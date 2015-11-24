/************************************************************/
/* ../linux-3.17/fs/lockd/clntlock.c */
/************************************************************/
/*
 * linux/fs/lockd/clntlock.c
 *
 * Lock handling for the client side NLM implementation
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/nfs_fs.h>
#include <linux/sunrpc/addr.h>
#include <linux/sunrpc/svc.h>
#include <linux/lockd/lockd.h>
#include <linux/kthread.h>

#define NLMDBG_FACILITY		NLMDBG_CLIENT

/*
 * Local function prototypes
 */
static int			reclaimer(void *ptr);

/*
 * The following functions handle blocking and granting from the
 * client perspective.
 */

/*
 * This is the representation of a blocked client lock.
 */
struct nlm_wait {
	struct list_head	b_list;		/* linked list */
	wait_queue_head_t	b_wait;		/* where to wait on */
	struct nlm_host *	b_host;
	struct file_lock *	b_lock;		/* local file lock */
	unsigned short		b_reclaim;	/* got to reclaim lock */
	__be32			b_status;	/* grant callback status */
};

static LIST_HEAD_clntlock_c(nlm_blocked);
static DEFINE_SPINLOCK(nlm_blocked_lock);

/**
 * nlmclnt_init - Set up per-NFS mount point lockd data structures
 * @nlm_init: pointer to arguments structure
 *
 * Returns pointer to an appropriate nlm_host struct,
 * or an ERR_PTR value.
 */
struct nlm_host *nlmclnt_init(const struct nlmclnt_initdata *nlm_init)
{
	struct nlm_host *host;
	u32 nlm_version = (nlm_init->nfs_version == 2) ? 1 : 4;
	int status;

	status = lockd_up(nlm_init->net);
	if (status < 0)
		return ERR_PTR(status);

	host = nlmclnt_lookup_host(nlm_init->address, nlm_init->addrlen,
				   nlm_init->protocol, nlm_version,
				   nlm_init->hostname, nlm_init->noresvport,
				   nlm_init->net);
	if (host == NULL)
		goto out_nohost;
	if (host->h_rpcclnt == NULL && nlm_bind_host(host) == NULL)
		goto out_nobind;

	return host;
out_nobind:
	nlmclnt_release_host(host);
out_nohost:
	lockd_down(nlm_init->net);
	return ERR_PTR(-ENOLCK);
}
EXPORT_SYMBOL_GPL(nlmclnt_init);

/**
 * nlmclnt_done - Release resources allocated by nlmclnt_init()
 * @host: nlm_host structure reserved by nlmclnt_init()
 *
 */
void nlmclnt_done(struct nlm_host *host)
{
	struct net *net = host->net;

	nlmclnt_release_host(host);
	lockd_down(net);
}
EXPORT_SYMBOL_GPL(nlmclnt_done);

/*
 * Queue up a lock for blocking so that the GRANTED request can see it
 */
struct nlm_wait *nlmclnt_prepare_block(struct nlm_host *host, struct file_lock *fl)
{
	struct nlm_wait *block;

	block = kmalloc(sizeof(*block), GFP_KERNEL);
	if (block != NULL) {
		block->b_host = host;
		block->b_lock = fl;
		init_waitqueue_head(&block->b_wait);
		block->b_status = nlm_lck_blocked;

		spin_lock(&nlm_blocked_lock);
		list_add(&block->b_list, &nlm_blocked);
		spin_unlock(&nlm_blocked_lock);
	}
	return block;
}

void nlmclnt_finish_block(struct nlm_wait *block)
{
	if (block == NULL)
		return;
	spin_lock(&nlm_blocked_lock);
	list_del(&block->b_list);
	spin_unlock(&nlm_blocked_lock);
	kfree(block);
}

/*
 * Block on a lock
 */
int nlmclnt_block(struct nlm_wait *block, struct nlm_rqst *req, long timeout)
{
	long ret;

	/* A borken server might ask us to block even if we didn't
	 * request it. Just say no!
	 */
	if (block == NULL)
		return -EAGAIN;

	/* Go to sleep waiting for GRANT callback. Some servers seem
	 * to lose callbacks, however, so we're going to poll from
	 * time to time just to make sure.
	 *
	 * For now, the retry frequency is pretty high; normally
	 * a 1 minute timeout would do. See the comment before
	 * nlmclnt_lock for an explanation.
	 */
	ret = wait_event_interruptible_timeout(block->b_wait,
			block->b_status != nlm_lck_blocked,
			timeout);
	if (ret < 0)
		return -ERESTARTSYS;
	/* Reset the lock status after a server reboot so we resend */
	if (block->b_status == nlm_lck_denied_grace_period)
		block->b_status = nlm_lck_blocked;
	req->a_res.status = block->b_status;
	return 0;
}

/*
 * The server lockd has called us back to tell us the lock was granted
 */
__be32 nlmclnt_grant(const struct sockaddr *addr, const struct nlm_lock *lock)
{
	const struct file_lock *fl = &lock->fl;
	const struct nfs_fh *fh = &lock->fh;
	struct nlm_wait	*block;
	__be32 res = nlm_lck_denied;

	/*
	 * Look up blocked request based on arguments.
	 * Warning: must not use cookie to match it!
	 */
	spin_lock(&nlm_blocked_lock);
	list_for_each_entry(block, &nlm_blocked, b_list) {
		struct file_lock *fl_blocked = block->b_lock;

		if (fl_blocked->fl_start != fl->fl_start)
			continue;
		if (fl_blocked->fl_end != fl->fl_end)
			continue;
		/*
		 * Careful! The NLM server will return the 32-bit "pid" that
		 * we put on the wire: in this case the lockowner "pid".
		 */
		if (fl_blocked->fl_u.nfs_fl.owner->pid != lock->svid)
			continue;
		if (!rpc_cmp_addr(nlm_addr(block->b_host), addr))
			continue;
		if (nfs_compare_fh(NFS_FH(file_inode(fl_blocked->fl_file)) ,fh) != 0)
			continue;
		/* Alright, we found a lock. Set the return status
		 * and wake up the caller
		 */
		block->b_status = nlm_granted;
		wake_up(&block->b_wait);
		res = nlm_granted;
	}
	spin_unlock(&nlm_blocked_lock);
	return res;
}

/*
 * The following procedures deal with the recovery of locks after a
 * server crash.
 */

/*
 * Reclaim all locks on server host. We do this by spawning a separate
 * reclaimer thread.
 */
void
nlmclnt_recovery(struct nlm_host *host)
{
	struct task_struct *task;

	if (!host->h_reclaiming++) {
		nlm_get_host(host);
		task = kthread_run(reclaimer, host, "%s-reclaim", host->h_name);
		if (IS_ERR(task))
			printk(KERN_ERR "lockd: unable to spawn reclaimer "
				"thread. Locks for %s won't be reclaimed! "
				"(%ld)\n", host->h_name, PTR_ERR(task));
	}
}

static int
reclaimer(void *ptr)
{
	struct nlm_host	  *host = (struct nlm_host *) ptr;
	struct nlm_wait	  *block;
	struct nlm_rqst   *req;
	struct file_lock *fl, *next;
	u32 nsmstate;
	struct net *net = host->net;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		printk(KERN_ERR "lockd: reclaimer unable to alloc memory."
				" Locks for %s won't be reclaimed!\n",
				host->h_name);
		return 0;
	}

	allow_signal(SIGKILL);

	down_write(&host->h_rwsem);
	lockd_up(net);	/* note: this cannot fail as lockd is already running */

	dprintk("lockd: reclaiming locks for host %s\n", host->h_name);

restart:
	nsmstate = host->h_nsmstate;

	/* Force a portmap getport - the peer's lockd will
	 * most likely end up on a different port.
	 */
	host->h_nextrebind = jiffies;
	nlm_rebind_host(host);

	/* First, reclaim all locks that have been granted. */
	list_splice_init(&host->h_granted, &host->h_reclaim);
	list_for_each_entry_safe(fl, next, &host->h_reclaim, fl_u.nfs_fl.list) {
		list_del_init(&fl->fl_u.nfs_fl.list);

		/*
		 * sending this thread a SIGKILL will result in any unreclaimed
		 * locks being removed from the h_granted list. This means that
		 * the kernel will not attempt to reclaim them again if a new
		 * reclaimer thread is spawned for this host.
		 */
		if (signalled())
			continue;
		if (nlmclnt_reclaim(host, fl, req) != 0)
			continue;
		list_add_tail(&fl->fl_u.nfs_fl.list, &host->h_granted);
		if (host->h_nsmstate != nsmstate) {
			/* Argh! The server rebooted again! */
			goto restart;
		}
	}

	host->h_reclaiming = 0;
	up_write(&host->h_rwsem);
	dprintk("NLM: done reclaiming locks for host %s\n", host->h_name);

	/* Now, wake up all processes that sleep on a blocked lock */
	spin_lock(&nlm_blocked_lock);
	list_for_each_entry(block, &nlm_blocked, b_list) {
		if (block->b_host == host) {
			block->b_status = nlm_lck_denied_grace_period;
			wake_up(&block->b_wait);
		}
	}
	spin_unlock(&nlm_blocked_lock);

	/* Release host handle after use */
	nlmclnt_release_host(host);
	lockd_down(net);
	kfree(req);
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/lockd/clntproc.c */
/************************************************************/
/*
 * linux/fs/lockd/clntproc.c
 *
 * RPC procedures for the client side NLM implementation
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/module.h>
// #include <linux/slab.h>
// #include <linux/types.h>
#include <linux/errno.h>
#include <linux/fs.h>
// #include <linux/nfs_fs.h>
#include <linux/utsname.h>
#include <linux/freezer.h>
#include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/svc.h>
// #include <linux/lockd/lockd.h>

#define NLMDBG_FACILITY		NLMDBG_CLIENT
#define NLMCLNT_GRACE_WAIT	(5*HZ)
#define NLMCLNT_POLL_TIMEOUT	(30*HZ)
#define NLMCLNT_MAX_RETRIES	3

static int	nlmclnt_test(struct nlm_rqst *, struct file_lock *);
static int	nlmclnt_lock(struct nlm_rqst *, struct file_lock *);
static int	nlmclnt_unlock(struct nlm_rqst *, struct file_lock *);
static int	nlm_stat_to_errno(__be32 stat);
static void	nlmclnt_locks_init_private(struct file_lock *fl, struct nlm_host *host);
static int	nlmclnt_cancel(struct nlm_host *, int , struct file_lock *);

static const struct rpc_call_ops nlmclnt_unlock_ops;
static const struct rpc_call_ops nlmclnt_cancel_ops;

/*
 * Cookie counter for NLM requests
 */
static atomic_t	nlm_cookie = ATOMIC_INIT(0x1234);

void nlmclnt_next_cookie(struct nlm_cookie *c)
{
	u32	cookie = atomic_inc_return(&nlm_cookie);

	memcpy(c->data, &cookie, 4);
	c->len=4;
}

static struct nlm_lockowner *nlm_get_lockowner(struct nlm_lockowner *lockowner)
{
	atomic_inc(&lockowner->count);
	return lockowner;
}

static void nlm_put_lockowner(struct nlm_lockowner *lockowner)
{
	if (!atomic_dec_and_lock(&lockowner->count, &lockowner->host->h_lock))
		return;
	list_del(&lockowner->list);
	spin_unlock(&lockowner->host->h_lock);
	nlmclnt_release_host(lockowner->host);
	kfree(lockowner);
}

static inline int nlm_pidbusy(struct nlm_host *host, uint32_t pid)
{
	struct nlm_lockowner *lockowner;
	list_for_each_entry(lockowner, &host->h_lockowners, list) {
		if (lockowner->pid == pid)
			return -EBUSY;
	}
	return 0;
}

static inline uint32_t __nlm_alloc_pid(struct nlm_host *host)
{
	uint32_t res;
	do {
		res = host->h_pidcount++;
	} while (nlm_pidbusy(host, res) < 0);
	return res;
}

static struct nlm_lockowner *__nlm_find_lockowner(struct nlm_host *host, fl_owner_t owner)
{
	struct nlm_lockowner *lockowner;
	list_for_each_entry(lockowner, &host->h_lockowners, list) {
		if (lockowner->owner != owner)
			continue;
		return nlm_get_lockowner(lockowner);
	}
	return NULL;
}

static struct nlm_lockowner *nlm_find_lockowner(struct nlm_host *host, fl_owner_t owner)
{
	struct nlm_lockowner *res, *new = NULL;

	spin_lock(&host->h_lock);
	res = __nlm_find_lockowner(host, owner);
	if (res == NULL) {
		spin_unlock(&host->h_lock);
		new = kmalloc(sizeof(*new), GFP_KERNEL);
		spin_lock(&host->h_lock);
		res = __nlm_find_lockowner(host, owner);
		if (res == NULL && new != NULL) {
			res = new;
			atomic_set(&new->count, 1);
			new->owner = owner;
			new->pid = __nlm_alloc_pid(host);
			new->host = nlm_get_host(host);
			list_add(&new->list, &host->h_lockowners);
			new = NULL;
		}
	}
	spin_unlock(&host->h_lock);
	kfree(new);
	return res;
}

/*
 * Initialize arguments for TEST/LOCK/UNLOCK/CANCEL calls
 */
static void nlmclnt_setlockargs(struct nlm_rqst *req, struct file_lock *fl)
{
	struct nlm_args	*argp = &req->a_args;
	struct nlm_lock	*lock = &argp->lock;
	char *nodename = req->a_host->h_rpcclnt->cl_nodename;

	nlmclnt_next_cookie(&argp->cookie);
	memcpy(&lock->fh, NFS_FH(file_inode(fl->fl_file)), sizeof(struct nfs_fh));
	lock->caller  = nodename;
	lock->oh.data = req->a_owner;
	lock->oh.len  = snprintf(req->a_owner, sizeof(req->a_owner), "%u@%s",
				(unsigned int)fl->fl_u.nfs_fl.owner->pid,
				nodename);
	lock->svid = fl->fl_u.nfs_fl.owner->pid;
	lock->fl.fl_start = fl->fl_start;
	lock->fl.fl_end = fl->fl_end;
	lock->fl.fl_type = fl->fl_type;
}

static void nlmclnt_release_lockargs(struct nlm_rqst *req)
{
	WARN_ON_ONCE(req->a_args.lock.fl.fl_ops != NULL);
}

/**
 * nlmclnt_proc - Perform a single client-side lock request
 * @host: address of a valid nlm_host context representing the NLM server
 * @cmd: fcntl-style file lock operation to perform
 * @fl: address of arguments for the lock operation
 *
 */
int nlmclnt_proc(struct nlm_host *host, int cmd, struct file_lock *fl)
{
	struct nlm_rqst		*call;
	int			status;

	call = nlm_alloc_call(host);
	if (call == NULL)
		return -ENOMEM;

	nlmclnt_locks_init_private(fl, host);
	if (!fl->fl_u.nfs_fl.owner) {
		/* lockowner allocation has failed */
		nlmclnt_release_call(call);
		return -ENOMEM;
	}
	/* Set up the argument struct */
	nlmclnt_setlockargs(call, fl);

	if (IS_SETLK(cmd) || IS_SETLKW(cmd)) {
		if (fl->fl_type != F_UNLCK) {
			call->a_args.block = IS_SETLKW(cmd) ? 1 : 0;
			status = nlmclnt_lock(call, fl);
		} else
			status = nlmclnt_unlock(call, fl);
	} else if (IS_GETLK(cmd))
		status = nlmclnt_test(call, fl);
	else
		status = -EINVAL;
	fl->fl_ops->fl_release_private(fl);
	fl->fl_ops = NULL;

	dprintk("lockd: clnt proc returns %d\n", status);
	return status;
}
EXPORT_SYMBOL_GPL(nlmclnt_proc);

/*
 * Allocate an NLM RPC call struct
 */
struct nlm_rqst *nlm_alloc_call(struct nlm_host *host)
{
	struct nlm_rqst	*call;

	for(;;) {
		call = kzalloc(sizeof(*call), GFP_KERNEL);
		if (call != NULL) {
			atomic_set(&call->a_count, 1);
			locks_init_lock(&call->a_args.lock.fl);
			locks_init_lock(&call->a_res.lock.fl);
			call->a_host = nlm_get_host(host);
			return call;
		}
		if (signalled())
			break;
		printk("nlm_alloc_call: failed, waiting for memory\n");
		schedule_timeout_interruptible(5*HZ);
	}
	return NULL;
}

void nlmclnt_release_call(struct nlm_rqst *call)
{
	if (!atomic_dec_and_test(&call->a_count))
		return;
	nlmclnt_release_host(call->a_host);
	nlmclnt_release_lockargs(call);
	kfree(call);
}

static void nlmclnt_rpc_release(void *data)
{
	nlmclnt_release_call(data);
}

static int nlm_wait_on_grace(wait_queue_head_t *queue)
{
	DEFINE_WAIT(wait);
	int status = -EINTR;

	prepare_to_wait(queue, &wait, TASK_INTERRUPTIBLE);
	if (!signalled ()) {
		schedule_timeout(NLMCLNT_GRACE_WAIT);
		try_to_freeze();
		if (!signalled ())
			status = 0;
	}
	finish_wait(queue, &wait);
	return status;
}

/*
 * Generic NLM call
 */
static int
nlmclnt_call(struct rpc_cred *cred, struct nlm_rqst *req, u32 proc)
{
	struct nlm_host	*host = req->a_host;
	struct rpc_clnt	*clnt;
	struct nlm_args	*argp = &req->a_args;
	struct nlm_res	*resp = &req->a_res;
	struct rpc_message msg = {
		.rpc_argp	= argp,
		.rpc_resp	= resp,
		.rpc_cred	= cred,
	};
	int		status;

	dprintk("lockd: call procedure %d on %s\n",
			(int)proc, host->h_name);

	do {
		if (host->h_reclaiming && !argp->reclaim)
			goto in_grace_period;

		/* If we have no RPC client yet, create one. */
		if ((clnt = nlm_bind_host(host)) == NULL)
			return -ENOLCK;
		msg.rpc_proc = &clnt->cl_procinfo[proc];

		/* Perform the RPC call. If an error occurs, try again */
		if ((status = rpc_call_sync(clnt, &msg, 0)) < 0) {
			dprintk("lockd: rpc_call returned error %d\n", -status);
			switch (status) {
			case -EPROTONOSUPPORT:
				status = -EINVAL;
				break;
			case -ECONNREFUSED:
			case -ETIMEDOUT:
			case -ENOTCONN:
				nlm_rebind_host(host);
				status = -EAGAIN;
				break;
			case -ERESTARTSYS:
				return signalled () ? -EINTR : status;
			default:
				break;
			}
			break;
		} else
		if (resp->status == nlm_lck_denied_grace_period) {
			dprintk("lockd: server in grace period\n");
			if (argp->reclaim) {
				printk(KERN_WARNING
				     "lockd: spurious grace period reject?!\n");
				return -ENOLCK;
			}
		} else {
			if (!argp->reclaim) {
				/* We appear to be out of the grace period */
				wake_up_all(&host->h_gracewait);
			}
			dprintk("lockd: server returns status %d\n",
				ntohl(resp->status));
			return 0;	/* Okay, call complete */
		}

in_grace_period:
		/*
		 * The server has rebooted and appears to be in the grace
		 * period during which locks are only allowed to be
		 * reclaimed.
		 * We can only back off and try again later.
		 */
		status = nlm_wait_on_grace(&host->h_gracewait);
	} while (status == 0);

	return status;
}

/*
 * Generic NLM call, async version.
 */
static struct rpc_task *__nlm_async_call(struct nlm_rqst *req, u32 proc, struct rpc_message *msg, const struct rpc_call_ops *tk_ops)
{
	struct nlm_host	*host = req->a_host;
	struct rpc_clnt	*clnt;
	struct rpc_task_setup task_setup_data = {
		.rpc_message = msg,
		.callback_ops = tk_ops,
		.callback_data = req,
		.flags = RPC_TASK_ASYNC,
	};

	dprintk("lockd: call procedure %d on %s (async)\n",
			(int)proc, host->h_name);

	/* If we have no RPC client yet, create one. */
	clnt = nlm_bind_host(host);
	if (clnt == NULL)
		goto out_err;
	msg->rpc_proc = &clnt->cl_procinfo[proc];
	task_setup_data.rpc_client = clnt;

        /* bootstrap and kick off the async RPC call */
	return rpc_run_task(&task_setup_data);
out_err:
	tk_ops->rpc_release(req);
	return ERR_PTR(-ENOLCK);
}

static int nlm_do_async_call(struct nlm_rqst *req, u32 proc, struct rpc_message *msg, const struct rpc_call_ops *tk_ops)
{
	struct rpc_task *task;

	task = __nlm_async_call(req, proc, msg, tk_ops);
	if (IS_ERR(task))
		return PTR_ERR(task);
	rpc_put_task(task);
	return 0;
}

/*
 * NLM asynchronous call.
 */
int nlm_async_call(struct nlm_rqst *req, u32 proc, const struct rpc_call_ops *tk_ops)
{
	struct rpc_message msg = {
		.rpc_argp	= &req->a_args,
		.rpc_resp	= &req->a_res,
	};
	return nlm_do_async_call(req, proc, &msg, tk_ops);
}

int nlm_async_reply(struct nlm_rqst *req, u32 proc, const struct rpc_call_ops *tk_ops)
{
	struct rpc_message msg = {
		.rpc_argp	= &req->a_res,
	};
	return nlm_do_async_call(req, proc, &msg, tk_ops);
}

/*
 * NLM client asynchronous call.
 *
 * Note that although the calls are asynchronous, and are therefore
 *      guaranteed to complete, we still always attempt to wait for
 *      completion in order to be able to correctly track the lock
 *      state.
 */
static int nlmclnt_async_call(struct rpc_cred *cred, struct nlm_rqst *req, u32 proc, const struct rpc_call_ops *tk_ops)
{
	struct rpc_message msg = {
		.rpc_argp	= &req->a_args,
		.rpc_resp	= &req->a_res,
		.rpc_cred	= cred,
	};
	struct rpc_task *task;
	int err;

	task = __nlm_async_call(req, proc, &msg, tk_ops);
	if (IS_ERR(task))
		return PTR_ERR(task);
	err = rpc_wait_for_completion_task(task);
	rpc_put_task(task);
	return err;
}

/*
 * TEST for the presence of a conflicting lock
 */
static int
nlmclnt_test(struct nlm_rqst *req, struct file_lock *fl)
{
	int	status;

	status = nlmclnt_call(nfs_file_cred(fl->fl_file), req, NLMPROC_TEST);
	if (status < 0)
		goto out;

	switch (req->a_res.status) {
		case nlm_granted:
			fl->fl_type = F_UNLCK;
			break;
		case nlm_lck_denied:
			/*
			 * Report the conflicting lock back to the application.
			 */
			fl->fl_start = req->a_res.lock.fl.fl_start;
			fl->fl_end = req->a_res.lock.fl.fl_end;
			fl->fl_type = req->a_res.lock.fl.fl_type;
			fl->fl_pid = 0;
			break;
		default:
			status = nlm_stat_to_errno(req->a_res.status);
	}
out:
	nlmclnt_release_call(req);
	return status;
}

static void nlmclnt_locks_copy_lock(struct file_lock *new, struct file_lock *fl)
{
	spin_lock(&fl->fl_u.nfs_fl.owner->host->h_lock);
	new->fl_u.nfs_fl.state = fl->fl_u.nfs_fl.state;
	new->fl_u.nfs_fl.owner = nlm_get_lockowner(fl->fl_u.nfs_fl.owner);
	list_add_tail(&new->fl_u.nfs_fl.list, &fl->fl_u.nfs_fl.owner->host->h_granted);
	spin_unlock(&fl->fl_u.nfs_fl.owner->host->h_lock);
}

static void nlmclnt_locks_release_private(struct file_lock *fl)
{
	spin_lock(&fl->fl_u.nfs_fl.owner->host->h_lock);
	list_del(&fl->fl_u.nfs_fl.list);
	spin_unlock(&fl->fl_u.nfs_fl.owner->host->h_lock);
	nlm_put_lockowner(fl->fl_u.nfs_fl.owner);
}

static const struct file_lock_operations nlmclnt_lock_ops = {
	.fl_copy_lock = nlmclnt_locks_copy_lock,
	.fl_release_private = nlmclnt_locks_release_private,
};

static void nlmclnt_locks_init_private(struct file_lock *fl, struct nlm_host *host)
{
	fl->fl_u.nfs_fl.state = 0;
	fl->fl_u.nfs_fl.owner = nlm_find_lockowner(host, fl->fl_owner);
	INIT_LIST_HEAD(&fl->fl_u.nfs_fl.list);
	fl->fl_ops = &nlmclnt_lock_ops;
}

static int do_vfs_lock(struct file_lock *fl)
{
	int res = 0;
	switch (fl->fl_flags & (FL_POSIX|FL_FLOCK)) {
		case FL_POSIX:
			res = posix_lock_file_wait(fl->fl_file, fl);
			break;
		case FL_FLOCK:
			res = flock_lock_file_wait(fl->fl_file, fl);
			break;
		default:
			BUG();
	}
	return res;
}

/*
 * LOCK: Try to create a lock
 *
 *			Programmer Harassment Alert
 *
 * When given a blocking lock request in a sync RPC call, the HPUX lockd
 * will faithfully return LCK_BLOCKED but never cares to notify us when
 * the lock could be granted. This way, our local process could hang
 * around forever waiting for the callback.
 *
 *  Solution A:	Implement busy-waiting
 *  Solution B: Use the async version of the call (NLM_LOCK_{MSG,RES})
 *
 * For now I am implementing solution A, because I hate the idea of
 * re-implementing lockd for a third time in two months. The async
 * calls shouldn't be too hard to do, however.
 *
 * This is one of the lovely things about standards in the NFS area:
 * they're so soft and squishy you can't really blame HP for doing this.
 */
static int
nlmclnt_lock(struct nlm_rqst *req, struct file_lock *fl)
{
	struct rpc_cred *cred = nfs_file_cred(fl->fl_file);
	struct nlm_host	*host = req->a_host;
	struct nlm_res	*resp = &req->a_res;
	struct nlm_wait *block = NULL;
	unsigned char fl_flags = fl->fl_flags;
	unsigned char fl_type;
	int status = -ENOLCK;

	if (nsm_monitor(host) < 0)
		goto out;
	req->a_args.state = nsm_local_state;

	fl->fl_flags |= FL_ACCESS;
	status = do_vfs_lock(fl);
	fl->fl_flags = fl_flags;
	if (status < 0)
		goto out;

	block = nlmclnt_prepare_block(host, fl);
again:
	/*
	 * Initialise resp->status to a valid non-zero value,
	 * since 0 == nlm_lck_granted
	 */
	resp->status = nlm_lck_blocked;
	for(;;) {
		/* Reboot protection */
		fl->fl_u.nfs_fl.state = host->h_state;
		status = nlmclnt_call(cred, req, NLMPROC_LOCK);
		if (status < 0)
			break;
		/* Did a reclaimer thread notify us of a server reboot? */
		if (resp->status ==  nlm_lck_denied_grace_period)
			continue;
		if (resp->status != nlm_lck_blocked)
			break;
		/* Wait on an NLM blocking lock */
		status = nlmclnt_block(block, req, NLMCLNT_POLL_TIMEOUT);
		if (status < 0)
			break;
		if (resp->status != nlm_lck_blocked)
			break;
	}

	/* if we were interrupted while blocking, then cancel the lock request
	 * and exit
	 */
	if (resp->status == nlm_lck_blocked) {
		if (!req->a_args.block)
			goto out_unlock;
		if (nlmclnt_cancel(host, req->a_args.block, fl) == 0)
			goto out_unblock;
	}

	if (resp->status == nlm_granted) {
		down_read(&host->h_rwsem);
		/* Check whether or not the server has rebooted */
		if (fl->fl_u.nfs_fl.state != host->h_state) {
			up_read(&host->h_rwsem);
			goto again;
		}
		/* Ensure the resulting lock will get added to granted list */
		fl->fl_flags |= FL_SLEEP;
		if (do_vfs_lock(fl) < 0)
			printk(KERN_WARNING "%s: VFS is out of sync with lock manager!\n", __func__);
		up_read(&host->h_rwsem);
		fl->fl_flags = fl_flags;
		status = 0;
	}
	if (status < 0)
		goto out_unlock;
	/*
	 * EAGAIN doesn't make sense for sleeping locks, and in some
	 * cases NLM_LCK_DENIED is returned for a permanent error.  So
	 * turn it into an ENOLCK.
	 */
	if (resp->status == nlm_lck_denied && (fl_flags & FL_SLEEP))
		status = -ENOLCK;
	else
		status = nlm_stat_to_errno(resp->status);
out_unblock:
	nlmclnt_finish_block(block);
out:
	nlmclnt_release_call(req);
	return status;
out_unlock:
	/* Fatal error: ensure that we remove the lock altogether */
	dprintk("lockd: lock attempt ended in fatal error.\n"
		"       Attempting to unlock.\n");
	nlmclnt_finish_block(block);
	fl_type = fl->fl_type;
	fl->fl_type = F_UNLCK;
	down_read(&host->h_rwsem);
	do_vfs_lock(fl);
	up_read(&host->h_rwsem);
	fl->fl_type = fl_type;
	fl->fl_flags = fl_flags;
	nlmclnt_async_call(cred, req, NLMPROC_UNLOCK, &nlmclnt_unlock_ops);
	return status;
}

/*
 * RECLAIM: Try to reclaim a lock
 */
int
nlmclnt_reclaim(struct nlm_host *host, struct file_lock *fl,
		struct nlm_rqst *req)
{
	int		status;

	memset(req, 0, sizeof(*req));
	locks_init_lock(&req->a_args.lock.fl);
	locks_init_lock(&req->a_res.lock.fl);
	req->a_host  = host;

	/* Set up the argument struct */
	nlmclnt_setlockargs(req, fl);
	req->a_args.reclaim = 1;

	status = nlmclnt_call(nfs_file_cred(fl->fl_file), req, NLMPROC_LOCK);
	if (status >= 0 && req->a_res.status == nlm_granted)
		return 0;

	printk(KERN_WARNING "lockd: failed to reclaim lock for pid %d "
				"(errno %d, status %d)\n", fl->fl_pid,
				status, ntohl(req->a_res.status));

	/*
	 * FIXME: This is a serious failure. We can
	 *
	 *  a.	Ignore the problem
	 *  b.	Send the owning process some signal (Linux doesn't have
	 *	SIGLOST, though...)
	 *  c.	Retry the operation
	 *
	 * Until someone comes up with a simple implementation
	 * for b or c, I'll choose option a.
	 */

	return -ENOLCK;
}

/*
 * UNLOCK: remove an existing lock
 */
static int
nlmclnt_unlock(struct nlm_rqst *req, struct file_lock *fl)
{
	struct nlm_host	*host = req->a_host;
	struct nlm_res	*resp = &req->a_res;
	int status;
	unsigned char fl_flags = fl->fl_flags;

	/*
	 * Note: the server is supposed to either grant us the unlock
	 * request, or to deny it with NLM_LCK_DENIED_GRACE_PERIOD. In either
	 * case, we want to unlock.
	 */
	fl->fl_flags |= FL_EXISTS;
	down_read(&host->h_rwsem);
	status = do_vfs_lock(fl);
	up_read(&host->h_rwsem);
	fl->fl_flags = fl_flags;
	if (status == -ENOENT) {
		status = 0;
		goto out;
	}

	atomic_inc(&req->a_count);
	status = nlmclnt_async_call(nfs_file_cred(fl->fl_file), req,
			NLMPROC_UNLOCK, &nlmclnt_unlock_ops);
	if (status < 0)
		goto out;

	if (resp->status == nlm_granted)
		goto out;

	if (resp->status != nlm_lck_denied_nolocks)
		printk("lockd: unexpected unlock status: %d\n",
			ntohl(resp->status));
	/* What to do now? I'm out of my depth... */
	status = -ENOLCK;
out:
	nlmclnt_release_call(req);
	return status;
}

static void nlmclnt_unlock_callback(struct rpc_task *task, void *data)
{
	struct nlm_rqst	*req = data;
	u32 status = ntohl(req->a_res.status);

	if (RPC_ASSASSINATED(task))
		goto die;

	if (task->tk_status < 0) {
		dprintk("lockd: unlock failed (err = %d)\n", -task->tk_status);
		switch (task->tk_status) {
		case -EACCES:
		case -EIO:
			goto die;
		default:
			goto retry_rebind;
		}
	}
	if (status == NLM_LCK_DENIED_GRACE_PERIOD) {
		rpc_delay(task, NLMCLNT_GRACE_WAIT);
		goto retry_unlock;
	}
	if (status != NLM_LCK_GRANTED)
		printk(KERN_WARNING "lockd: unexpected unlock status: %d\n", status);
die:
	return;
 retry_rebind:
	nlm_rebind_host(req->a_host);
 retry_unlock:
	rpc_restart_call(task);
}

static const struct rpc_call_ops nlmclnt_unlock_ops = {
	.rpc_call_done = nlmclnt_unlock_callback,
	.rpc_release = nlmclnt_rpc_release,
};

/*
 * Cancel a blocked lock request.
 * We always use an async RPC call for this in order not to hang a
 * process that has been Ctrl-C'ed.
 */
static int nlmclnt_cancel(struct nlm_host *host, int block, struct file_lock *fl)
{
	struct nlm_rqst	*req;
	int status;

	dprintk("lockd: blocking lock attempt was interrupted by a signal.\n"
		"       Attempting to cancel lock.\n");

	req = nlm_alloc_call(host);
	if (!req)
		return -ENOMEM;
	req->a_flags = RPC_TASK_ASYNC;

	nlmclnt_setlockargs(req, fl);
	req->a_args.block = block;

	atomic_inc(&req->a_count);
	status = nlmclnt_async_call(nfs_file_cred(fl->fl_file), req,
			NLMPROC_CANCEL, &nlmclnt_cancel_ops);
	if (status == 0 && req->a_res.status == nlm_lck_denied)
		status = -ENOLCK;
	nlmclnt_release_call(req);
	return status;
}

static void nlmclnt_cancel_callback(struct rpc_task *task, void *data)
{
	struct nlm_rqst	*req = data;
	u32 status = ntohl(req->a_res.status);

	if (RPC_ASSASSINATED(task))
		goto die;

	if (task->tk_status < 0) {
		dprintk("lockd: CANCEL call error %d, retrying.\n",
					task->tk_status);
		goto retry_cancel;
	}

	dprintk("lockd: cancel status %u (task %u)\n",
			status, task->tk_pid);

	switch (status) {
	case NLM_LCK_GRANTED:
	case NLM_LCK_DENIED_GRACE_PERIOD:
	case NLM_LCK_DENIED:
		/* Everything's good */
		break;
	case NLM_LCK_DENIED_NOLOCKS:
		dprintk("lockd: CANCEL failed (server has no locks)\n");
		goto retry_cancel;
	default:
		printk(KERN_NOTICE "lockd: weird return %d for CANCEL call\n",
			status);
	}

die:
	return;

retry_cancel:
	/* Don't ever retry more than 3 times */
	if (req->a_retries++ >= NLMCLNT_MAX_RETRIES)
		goto die;
	nlm_rebind_host(req->a_host);
	rpc_restart_call(task);
	rpc_delay(task, 30 * HZ);
}

static const struct rpc_call_ops nlmclnt_cancel_ops = {
	.rpc_call_done = nlmclnt_cancel_callback,
	.rpc_release = nlmclnt_rpc_release,
};

/*
 * Convert an NLM status code to a generic kernel errno
 */
static int
nlm_stat_to_errno(__be32 status)
{
	switch(ntohl(status)) {
	case NLM_LCK_GRANTED:
		return 0;
	case NLM_LCK_DENIED:
		return -EAGAIN;
	case NLM_LCK_DENIED_NOLOCKS:
	case NLM_LCK_DENIED_GRACE_PERIOD:
		return -ENOLCK;
	case NLM_LCK_BLOCKED:
		printk(KERN_NOTICE "lockd: unexpected status NLM_BLOCKED\n");
		return -ENOLCK;
#ifdef CONFIG_LOCKD_V4
	case NLM_DEADLCK:
		return -EDEADLK;
	case NLM_ROFS:
		return -EROFS;
	case NLM_STALE_FH:
		return -ESTALE;
	case NLM_FBIG:
		return -EOVERFLOW;
	case NLM_FAILED:
		return -ENOLCK;
#endif
	}
	printk(KERN_NOTICE "lockd: unexpected server status %d\n",
		 ntohl(status));
	return -ENOLCK;
}
/************************************************************/
/* ../linux-3.17/fs/lockd/clntxdr.c */
/************************************************************/
/*
 * linux/fs/lockd/clntxdr.c
 *
 * XDR functions to encode/decode NLM version 3 RPC arguments and results.
 * NLM version 3 is backwards compatible with NLM versions 1 and 2.
 *
 * NLM client-side only.
 *
 * Copyright (C) 2010, Oracle.  All rights reserved.
 */

// #include <linux/types.h>
#include <linux/sunrpc/xdr.h>
// #include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/stats.h>
// #include <linux/lockd/lockd.h>

#include <uapi/linux/nfs2.h>

#define NLMDBG_FACILITY		NLMDBG_XDR

#if (NLMCLNT_OHSIZE > XDR_MAX_NETOBJ)
#  error "NLM host name cannot be larger than XDR_MAX_NETOBJ!"
#endif

/*
 * Declare the space requirements for NLM arguments and replies as
 * number of 32bit-words
 */
#define NLM_cookie_sz		(1+(NLM_MAXCOOKIELEN>>2))
#define NLM_caller_sz		(1+(NLMCLNT_OHSIZE>>2))
#define NLM_owner_sz		(1+(NLMCLNT_OHSIZE>>2))
#define NLM_fhandle_sz		(1+(NFS2_FHSIZE>>2))
#define NLM_lock_sz		(3+NLM_caller_sz+NLM_owner_sz+NLM_fhandle_sz)
#define NLM_holder_sz		(4+NLM_owner_sz)

#define NLM_testargs_sz		(NLM_cookie_sz+1+NLM_lock_sz)
#define NLM_lockargs_sz		(NLM_cookie_sz+4+NLM_lock_sz)
#define NLM_cancargs_sz		(NLM_cookie_sz+2+NLM_lock_sz)
#define NLM_unlockargs_sz	(NLM_cookie_sz+NLM_lock_sz)

#define NLM_testres_sz		(NLM_cookie_sz+1+NLM_holder_sz)
#define NLM_res_sz		(NLM_cookie_sz+1)
#define NLM_norep_sz		(0)


static s32 loff_t_to_s32(loff_t offset)
{
	s32 res;

	if (offset >= NLM_OFFSET_MAX)
		res = NLM_OFFSET_MAX;
	else if (offset <= -NLM_OFFSET_MAX)
		res = -NLM_OFFSET_MAX;
	else
		res = offset;
	return res;
}

static void nlm_compute_offsets(const struct nlm_lock *lock,
				u32 *l_offset, u32 *l_len)
{
	const struct file_lock *fl = &lock->fl;

	*l_offset = loff_t_to_s32(fl->fl_start);
	if (fl->fl_end == OFFSET_MAX)
		*l_len = 0;
	else
		*l_len = loff_t_to_s32(fl->fl_end - fl->fl_start + 1);
}

/*
 * Handle decode buffer overflows out-of-line.
 */
static void print_overflow_msg(const char *func, const struct xdr_stream *xdr)
{
	dprintk("lockd: %s prematurely hit the end of our receive buffer. "
		"Remaining buffer length is %tu words.\n",
		func, xdr->end - xdr->p);
}


/*
 * Encode/decode NLMv3 basic data types
 *
 * Basic NLMv3 data types are not defined in an IETF standards
 * document.  X/Open has a description of these data types that
 * is useful.  See Chapter 10 of "Protocols for Interworking:
 * XNFS, Version 3W".
 *
 * Not all basic data types have their own encoding and decoding
 * functions.  For run-time efficiency, some data types are encoded
 * or decoded inline.
 */

static void encode_bool(struct xdr_stream *xdr, const int value)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 4);
	*p = value ? xdr_one : xdr_zero;
}

static void encode_int32(struct xdr_stream *xdr, const s32 value)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 4);
	*p = cpu_to_be32(value);
}

/*
 *	typedef opaque netobj<MAXNETOBJ_SZ>
 */
static void encode_netobj(struct xdr_stream *xdr,
			  const u8 *data, const unsigned int length)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 4 + length);
	xdr_encode_opaque(p, data, length);
}

static int decode_netobj(struct xdr_stream *xdr,
			 struct xdr_netobj *obj)
{
	u32 length;
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	length = be32_to_cpup(p++);
	if (unlikely(length > XDR_MAX_NETOBJ))
		goto out_size;
	obj->len = length;
	obj->data = (u8 *)p;
	return 0;
out_size:
	dprintk("NFS: returned netobj was too long: %u\n", length);
	return -EIO;
out_overflow:
	print_overflow_msg(__func__, xdr);
	return -EIO;
}

/*
 *	netobj cookie;
 */
static void encode_cookie(struct xdr_stream *xdr,
			  const struct nlm_cookie *cookie)
{
	encode_netobj(xdr, (u8 *)&cookie->data, cookie->len);
}

static int decode_cookie(struct xdr_stream *xdr,
			 struct nlm_cookie *cookie)
{
	u32 length;
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	length = be32_to_cpup(p++);
	/* apparently HPUX can return empty cookies */
	if (length == 0)
		goto out_hpux;
	if (length > NLM_MAXCOOKIELEN)
		goto out_size;
	p = xdr_inline_decode(xdr, length);
	if (unlikely(p == NULL))
		goto out_overflow;
	cookie->len = length;
	memcpy(cookie->data, p, length);
	return 0;
out_hpux:
	cookie->len = 4;
	memset(cookie->data, 0, 4);
	return 0;
out_size:
	dprintk("NFS: returned cookie was too long: %u\n", length);
	return -EIO;
out_overflow:
	print_overflow_msg(__func__, xdr);
	return -EIO;
}

/*
 *	netobj fh;
 */
static void encode_fh(struct xdr_stream *xdr, const struct nfs_fh *fh)
{
	encode_netobj(xdr, (u8 *)&fh->data, NFS2_FHSIZE);
}

/*
 *	enum nlm_stats {
 *		LCK_GRANTED = 0,
 *		LCK_DENIED = 1,
 *		LCK_DENIED_NOLOCKS = 2,
 *		LCK_BLOCKED = 3,
 *		LCK_DENIED_GRACE_PERIOD = 4
 *	};
 *
 *
 *	struct nlm_stat {
 *		nlm_stats stat;
 *	};
 *
 * NB: we don't swap bytes for the NLM status values.  The upper
 * layers deal directly with the status value in network byte
 * order.
 */

static void encode_nlm_stat(struct xdr_stream *xdr,
			    const __be32 stat)
{
	__be32 *p;

	WARN_ON_ONCE(be32_to_cpu(stat) > NLM_LCK_DENIED_GRACE_PERIOD);
	p = xdr_reserve_space(xdr, 4);
	*p = stat;
}

static int decode_nlm_stat(struct xdr_stream *xdr,
			   __be32 *stat)
{
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	if (unlikely(ntohl(*p) > ntohl(nlm_lck_denied_grace_period)))
		goto out_enum;
	*stat = *p;
	return 0;
out_enum:
	dprintk("%s: server returned invalid nlm_stats value: %u\n",
		__func__, be32_to_cpup(p));
	return -EIO;
out_overflow:
	print_overflow_msg(__func__, xdr);
	return -EIO;
}

/*
 *	struct nlm_holder {
 *		bool exclusive;
 *		int uppid;
 *		netobj oh;
 *		unsigned l_offset;
 *		unsigned l_len;
 *	};
 */
static void encode_nlm_holder(struct xdr_stream *xdr,
			      const struct nlm_res *result)
{
	const struct nlm_lock *lock = &result->lock;
	u32 l_offset, l_len;
	__be32 *p;

	encode_bool(xdr, lock->fl.fl_type == F_RDLCK);
	encode_int32(xdr, lock->svid);
	encode_netobj(xdr, lock->oh.data, lock->oh.len);

	p = xdr_reserve_space(xdr, 4 + 4);
	nlm_compute_offsets(lock, &l_offset, &l_len);
	*p++ = cpu_to_be32(l_offset);
	*p   = cpu_to_be32(l_len);
}

static int decode_nlm_holder(struct xdr_stream *xdr, struct nlm_res *result)
{
	struct nlm_lock *lock = &result->lock;
	struct file_lock *fl = &lock->fl;
	u32 exclusive, l_offset, l_len;
	int error;
	__be32 *p;
	s32 end;

	memset(lock, 0, sizeof(*lock));
	locks_init_lock(fl);

	p = xdr_inline_decode(xdr, 4 + 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	exclusive = be32_to_cpup(p++);
	lock->svid = be32_to_cpup(p);
	fl->fl_pid = (pid_t)lock->svid;

	error = decode_netobj(xdr, &lock->oh);
	if (unlikely(error))
		goto out;

	p = xdr_inline_decode(xdr, 4 + 4);
	if (unlikely(p == NULL))
		goto out_overflow;

	fl->fl_flags = FL_POSIX;
	fl->fl_type  = exclusive != 0 ? F_WRLCK : F_RDLCK;
	l_offset = be32_to_cpup(p++);
	l_len = be32_to_cpup(p);
	end = l_offset + l_len - 1;

	fl->fl_start = (loff_t)l_offset;
	if (l_len == 0 || end < 0)
		fl->fl_end = OFFSET_MAX;
	else
		fl->fl_end = (loff_t)end;
	error = 0;
out:
	return error;
out_overflow:
	print_overflow_msg(__func__, xdr);
	return -EIO;
}

/*
 *	string caller_name<LM_MAXSTRLEN>;
 */
static void encode_caller_name(struct xdr_stream *xdr, const char *name)
{
	/* NB: client-side does not set lock->len */
	u32 length = strlen(name);
	__be32 *p;

	p = xdr_reserve_space(xdr, 4 + length);
	xdr_encode_opaque(p, name, length);
}

/*
 *	struct nlm_lock {
 *		string caller_name<LM_MAXSTRLEN>;
 *		netobj fh;
 *		netobj oh;
 *		int uppid;
 *		unsigned l_offset;
 *		unsigned l_len;
 *	};
 */
static void encode_nlm_lock(struct xdr_stream *xdr,
			    const struct nlm_lock *lock)
{
	u32 l_offset, l_len;
	__be32 *p;

	encode_caller_name(xdr, lock->caller);
	encode_fh(xdr, &lock->fh);
	encode_netobj(xdr, lock->oh.data, lock->oh.len);

	p = xdr_reserve_space(xdr, 4 + 4 + 4);
	*p++ = cpu_to_be32(lock->svid);

	nlm_compute_offsets(lock, &l_offset, &l_len);
	*p++ = cpu_to_be32(l_offset);
	*p   = cpu_to_be32(l_len);
}


/*
 * NLMv3 XDR encode functions
 *
 * NLMv3 argument types are defined in Chapter 10 of The Open Group's
 * "Protocols for Interworking: XNFS, Version 3W".
 */

/*
 *	struct nlm_testargs {
 *		netobj cookie;
 *		bool exclusive;
 *		struct nlm_lock alock;
 *	};
 */
static void nlm_xdr_enc_testargs(struct rpc_rqst *req,
				 struct xdr_stream *xdr,
				 const struct nlm_args *args)
{
	const struct nlm_lock *lock = &args->lock;

	encode_cookie(xdr, &args->cookie);
	encode_bool(xdr, lock->fl.fl_type == F_WRLCK);
	encode_nlm_lock(xdr, lock);
}

/*
 *	struct nlm_lockargs {
 *		netobj cookie;
 *		bool block;
 *		bool exclusive;
 *		struct nlm_lock alock;
 *		bool reclaim;
 *		int state;
 *	};
 */
static void nlm_xdr_enc_lockargs(struct rpc_rqst *req,
				 struct xdr_stream *xdr,
				 const struct nlm_args *args)
{
	const struct nlm_lock *lock = &args->lock;

	encode_cookie(xdr, &args->cookie);
	encode_bool(xdr, args->block);
	encode_bool(xdr, lock->fl.fl_type == F_WRLCK);
	encode_nlm_lock(xdr, lock);
	encode_bool(xdr, args->reclaim);
	encode_int32(xdr, args->state);
}

/*
 *	struct nlm_cancargs {
 *		netobj cookie;
 *		bool block;
 *		bool exclusive;
 *		struct nlm_lock alock;
 *	};
 */
static void nlm_xdr_enc_cancargs(struct rpc_rqst *req,
				 struct xdr_stream *xdr,
				 const struct nlm_args *args)
{
	const struct nlm_lock *lock = &args->lock;

	encode_cookie(xdr, &args->cookie);
	encode_bool(xdr, args->block);
	encode_bool(xdr, lock->fl.fl_type == F_WRLCK);
	encode_nlm_lock(xdr, lock);
}

/*
 *	struct nlm_unlockargs {
 *		netobj cookie;
 *		struct nlm_lock alock;
 *	};
 */
static void nlm_xdr_enc_unlockargs(struct rpc_rqst *req,
				   struct xdr_stream *xdr,
				   const struct nlm_args *args)
{
	const struct nlm_lock *lock = &args->lock;

	encode_cookie(xdr, &args->cookie);
	encode_nlm_lock(xdr, lock);
}

/*
 *	struct nlm_res {
 *		netobj cookie;
 *		nlm_stat stat;
 *	};
 */
static void nlm_xdr_enc_res(struct rpc_rqst *req,
			    struct xdr_stream *xdr,
			    const struct nlm_res *result)
{
	encode_cookie(xdr, &result->cookie);
	encode_nlm_stat(xdr, result->status);
}

/*
 *	union nlm_testrply switch (nlm_stats stat) {
 *	case LCK_DENIED:
 *		struct nlm_holder holder;
 *	default:
 *		void;
 *	};
 *
 *	struct nlm_testres {
 *		netobj cookie;
 *		nlm_testrply test_stat;
 *	};
 */
static void encode_nlm_testrply(struct xdr_stream *xdr,
				const struct nlm_res *result)
{
	if (result->status == nlm_lck_denied)
		encode_nlm_holder(xdr, result);
}

static void nlm_xdr_enc_testres(struct rpc_rqst *req,
				struct xdr_stream *xdr,
				const struct nlm_res *result)
{
	encode_cookie(xdr, &result->cookie);
	encode_nlm_stat(xdr, result->status);
	encode_nlm_testrply(xdr, result);
}


/*
 * NLMv3 XDR decode functions
 *
 * NLMv3 result types are defined in Chapter 10 of The Open Group's
 * "Protocols for Interworking: XNFS, Version 3W".
 */

/*
 *	union nlm_testrply switch (nlm_stats stat) {
 *	case LCK_DENIED:
 *		struct nlm_holder holder;
 *	default:
 *		void;
 *	};
 *
 *	struct nlm_testres {
 *		netobj cookie;
 *		nlm_testrply test_stat;
 *	};
 */
static int decode_nlm_testrply(struct xdr_stream *xdr,
			       struct nlm_res *result)
{
	int error;

	error = decode_nlm_stat(xdr, &result->status);
	if (unlikely(error))
		goto out;
	if (result->status == nlm_lck_denied)
		error = decode_nlm_holder(xdr, result);
out:
	return error;
}

static int nlm_xdr_dec_testres(struct rpc_rqst *req,
			       struct xdr_stream *xdr,
			       struct nlm_res *result)
{
	int error;

	error = decode_cookie(xdr, &result->cookie);
	if (unlikely(error))
		goto out;
	error = decode_nlm_testrply(xdr, result);
out:
	return error;
}

/*
 *	struct nlm_res {
 *		netobj cookie;
 *		nlm_stat stat;
 *	};
 */
static int nlm_xdr_dec_res(struct rpc_rqst *req,
			   struct xdr_stream *xdr,
			   struct nlm_res *result)
{
	int error;

	error = decode_cookie(xdr, &result->cookie);
	if (unlikely(error))
		goto out;
	error = decode_nlm_stat(xdr, &result->status);
out:
	return error;
}


/*
 * For NLM, a void procedure really returns nothing
 */
#define nlm_xdr_dec_norep	NULL

#define PROC(proc, argtype, restype)	\
[NLMPROC_##proc] = {							\
	.p_proc      = NLMPROC_##proc,					\
	.p_encode    = (kxdreproc_t)nlm_xdr_enc_##argtype,		\
	.p_decode    = (kxdrdproc_t)nlm_xdr_dec_##restype,		\
	.p_arglen    = NLM_##argtype##_sz,				\
	.p_replen    = NLM_##restype##_sz,				\
	.p_statidx   = NLMPROC_##proc,					\
	.p_name      = #proc,						\
	}

static struct rpc_procinfo	nlm_procedures[] = {
	PROC(TEST,		testargs,	testres),
	PROC(LOCK,		lockargs,	res),
	PROC(CANCEL,		cancargs,	res),
	PROC(UNLOCK,		unlockargs,	res),
	PROC(GRANTED,		testargs,	res),
	PROC(TEST_MSG,		testargs,	norep),
	PROC(LOCK_MSG,		lockargs,	norep),
	PROC(CANCEL_MSG,	cancargs,	norep),
	PROC(UNLOCK_MSG,	unlockargs,	norep),
	PROC(GRANTED_MSG,	testargs,	norep),
	PROC(TEST_RES,		testres,	norep),
	PROC(LOCK_RES,		res,		norep),
	PROC(CANCEL_RES,	res,		norep),
	PROC(UNLOCK_RES,	res,		norep),
	PROC(GRANTED_RES,	res,		norep),
};

static const struct rpc_version	nlm_version1 = {
		.number		= 1,
		.nrprocs	= ARRAY_SIZE(nlm_procedures),
		.procs		= nlm_procedures,
};

static const struct rpc_version	nlm_version3 = {
		.number		= 3,
		.nrprocs	= ARRAY_SIZE(nlm_procedures),
		.procs		= nlm_procedures,
};

static const struct rpc_version	*nlm_versions[] = {
	[1] = &nlm_version1,
	[3] = &nlm_version3,
#ifdef CONFIG_LOCKD_V4
	[4] = &nlm_version4,
#endif
};

static struct rpc_stat		nlm_rpc_stats;

const struct rpc_program	nlm_program = {
		.name		= "lockd",
		.number		= NLM_PROGRAM,
		.nrvers		= ARRAY_SIZE(nlm_versions),
		.version	= nlm_versions,
		.stats		= &nlm_rpc_stats,
};
/************************************************************/
/* ../linux-3.17/fs/lockd/host.c */
/************************************************************/
/*
 * linux/fs/lockd/host.c
 *
 * Management for NLM peer hosts. The nlm_host struct is shared
 * between client and server implementation. The only reason to
 * do so is to reduce code bloat.
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/types.h>
// #include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/addr.h>
// #include <linux/sunrpc/svc.h>
// #include <linux/lockd/lockd.h>
#include <linux/mutex.h>

#include <linux/sunrpc/svc_xprt.h>

#include <net/ipv6.h>

#include "netns.h"

#define NLMDBG_FACILITY		NLMDBG_HOSTCACHE
#define NLM_HOST_NRHASH		32
#define NLM_HOST_REBIND		(60 * HZ)
#define NLM_HOST_EXPIRE		(300 * HZ)
#define NLM_HOST_COLLECT	(120 * HZ)

static struct hlist_head	nlm_server_hosts[NLM_HOST_NRHASH];
static struct hlist_head	nlm_client_hosts[NLM_HOST_NRHASH];

#define for_each_host(host, chain, table) \
	for ((chain) = (table); \
	     (chain) < (table) + NLM_HOST_NRHASH; ++(chain)) \
		hlist_for_each_entry((host), (chain), h_hash)

#define for_each_host_safe(host, next, chain, table) \
	for ((chain) = (table); \
	     (chain) < (table) + NLM_HOST_NRHASH; ++(chain)) \
		hlist_for_each_entry_safe((host), (next), \
						(chain), h_hash)

static unsigned long		nrhosts;
static DEFINE_MUTEX(nlm_host_mutex);

static void			nlm_gc_hosts(struct net *net);

struct nlm_lookup_host_info {
	const int		server;		/* search for server|client */
	const struct sockaddr	*sap;		/* address to search for */
	const size_t		salen;		/* it's length */
	const unsigned short	protocol;	/* transport to search for*/
	const u32		version;	/* NLM version to search for */
	const char		*hostname;	/* remote's hostname */
	const size_t		hostname_len;	/* it's length */
	const int		noresvport;	/* use non-priv port */
	struct net		*net;		/* network namespace to bind */
};

/*
 * Hash function must work well on big- and little-endian platforms
 */
static unsigned int __nlm_hash32(const __be32 n)
{
	unsigned int hash = (__force u32)n ^ ((__force u32)n >> 16);
	return hash ^ (hash >> 8);
}

static unsigned int __nlm_hash_addr4(const struct sockaddr *sap)
{
	const struct sockaddr_in *sin = (struct sockaddr_in *)sap;
	return __nlm_hash32(sin->sin_addr.s_addr);
}

static unsigned int __nlm_hash_addr6(const struct sockaddr *sap)
{
	const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sap;
	const struct in6_addr addr = sin6->sin6_addr;
	return __nlm_hash32(addr.s6_addr32[0]) ^
	       __nlm_hash32(addr.s6_addr32[1]) ^
	       __nlm_hash32(addr.s6_addr32[2]) ^
	       __nlm_hash32(addr.s6_addr32[3]);
}

static unsigned int nlm_hash_address(const struct sockaddr *sap)
{
	unsigned int hash;

	switch (sap->sa_family) {
	case AF_INET:
		hash = __nlm_hash_addr4(sap);
		break;
	case AF_INET6:
		hash = __nlm_hash_addr6(sap);
		break;
	default:
		hash = 0;
	}
	return hash & (NLM_HOST_NRHASH - 1);
}

/*
 * Allocate and initialize an nlm_host.  Common to both client and server.
 */
static struct nlm_host *nlm_alloc_host(struct nlm_lookup_host_info *ni,
				       struct nsm_handle *nsm)
{
	struct nlm_host *host = NULL;
	unsigned long now = jiffies;

	if (nsm != NULL)
		atomic_inc(&nsm->sm_count);
	else {
		host = NULL;
		nsm = nsm_get_handle(ni->sap, ni->salen,
					ni->hostname, ni->hostname_len);
		if (unlikely(nsm == NULL)) {
			dprintk("lockd: %s failed; no nsm handle\n",
				__func__);
			goto out;
		}
	}

	host = kmalloc(sizeof(*host), GFP_KERNEL);
	if (unlikely(host == NULL)) {
		dprintk("lockd: %s failed; no memory\n", __func__);
		nsm_release(nsm);
		goto out;
	}

	memcpy(nlm_addr(host), ni->sap, ni->salen);
	host->h_addrlen    = ni->salen;
	rpc_set_port(nlm_addr(host), 0);
	host->h_srcaddrlen = 0;

	host->h_rpcclnt    = NULL;
	host->h_name	   = nsm->sm_name;
	host->h_version    = ni->version;
	host->h_proto      = ni->protocol;
	host->h_reclaiming = 0;
	host->h_server     = ni->server;
	host->h_noresvport = ni->noresvport;
	host->h_inuse      = 0;
	init_waitqueue_head(&host->h_gracewait);
	init_rwsem(&host->h_rwsem);
	host->h_state      = 0;
	host->h_nsmstate   = 0;
	host->h_pidcount   = 0;
	atomic_set(&host->h_count, 1);
	mutex_init(&host->h_mutex);
	host->h_nextrebind = now + NLM_HOST_REBIND;
	host->h_expires    = now + NLM_HOST_EXPIRE;
	INIT_LIST_HEAD(&host->h_lockowners);
	spin_lock_init(&host->h_lock);
	INIT_LIST_HEAD(&host->h_granted);
	INIT_LIST_HEAD(&host->h_reclaim);
	host->h_nsmhandle  = nsm;
	host->h_addrbuf    = nsm->sm_addrbuf;
	host->net	   = ni->net;

out:
	return host;
}

/*
 * Destroy an nlm_host and free associated resources
 *
 * Caller must hold nlm_host_mutex.
 */
static void nlm_destroy_host_locked(struct nlm_host *host)
{
	struct rpc_clnt	*clnt;
	struct lockd_net *ln = net_generic(host->net, lockd_net_id);

	dprintk("lockd: destroy host %s\n", host->h_name);

	hlist_del_init(&host->h_hash);

	nsm_unmonitor(host);
	nsm_release(host->h_nsmhandle);

	clnt = host->h_rpcclnt;
	if (clnt != NULL)
		rpc_shutdown_client(clnt);
	kfree(host);

	ln->nrhosts--;
	nrhosts--;
}

/**
 * nlmclnt_lookup_host - Find an NLM host handle matching a remote server
 * @sap: network address of server
 * @salen: length of server address
 * @protocol: transport protocol to use
 * @version: NLM protocol version
 * @hostname: '\0'-terminated hostname of server
 * @noresvport: 1 if non-privileged port should be used
 *
 * Returns an nlm_host structure that matches the passed-in
 * [server address, transport protocol, NLM version, server hostname].
 * If one doesn't already exist in the host cache, a new handle is
 * created and returned.
 */
struct nlm_host *nlmclnt_lookup_host(const struct sockaddr *sap,
				     const size_t salen,
				     const unsigned short protocol,
				     const u32 version,
				     const char *hostname,
				     int noresvport,
				     struct net *net)
{
	struct nlm_lookup_host_info ni = {
		.server		= 0,
		.sap		= sap,
		.salen		= salen,
		.protocol	= protocol,
		.version	= version,
		.hostname	= hostname,
		.hostname_len	= strlen(hostname),
		.noresvport	= noresvport,
		.net		= net,
	};
	struct hlist_head *chain;
	struct nlm_host	*host;
	struct nsm_handle *nsm = NULL;
	struct lockd_net *ln = net_generic(net, lockd_net_id);

	dprintk("lockd: %s(host='%s', vers=%u, proto=%s)\n", __func__,
			(hostname ? hostname : "<none>"), version,
			(protocol == IPPROTO_UDP ? "udp" : "tcp"));

	mutex_lock(&nlm_host_mutex);

	chain = &nlm_client_hosts[nlm_hash_address(sap)];
	hlist_for_each_entry(host, chain, h_hash) {
		if (host->net != net)
			continue;
		if (!rpc_cmp_addr(nlm_addr(host), sap))
			continue;

		/* Same address. Share an NSM handle if we already have one */
		if (nsm == NULL)
			nsm = host->h_nsmhandle;

		if (host->h_proto != protocol)
			continue;
		if (host->h_version != version)
			continue;

		nlm_get_host(host);
		dprintk("lockd: %s found host %s (%s)\n", __func__,
			host->h_name, host->h_addrbuf);
		goto out;
	}

	host = nlm_alloc_host(&ni, nsm);
	if (unlikely(host == NULL))
		goto out;

	hlist_add_head(&host->h_hash, chain);
	ln->nrhosts++;
	nrhosts++;

	dprintk("lockd: %s created host %s (%s)\n", __func__,
		host->h_name, host->h_addrbuf);

out:
	mutex_unlock(&nlm_host_mutex);
	return host;
}

/**
 * nlmclnt_release_host - release client nlm_host
 * @host: nlm_host to release
 *
 */
void nlmclnt_release_host(struct nlm_host *host)
{
	if (host == NULL)
		return;

	dprintk("lockd: release client host %s\n", host->h_name);

	WARN_ON_ONCE(host->h_server);

	if (atomic_dec_and_test(&host->h_count)) {
		WARN_ON_ONCE(!list_empty(&host->h_lockowners));
		WARN_ON_ONCE(!list_empty(&host->h_granted));
		WARN_ON_ONCE(!list_empty(&host->h_reclaim));

		mutex_lock(&nlm_host_mutex);
		nlm_destroy_host_locked(host);
		mutex_unlock(&nlm_host_mutex);
	}
}

/**
 * nlmsvc_lookup_host - Find an NLM host handle matching a remote client
 * @rqstp: incoming NLM request
 * @hostname: name of client host
 * @hostname_len: length of client hostname
 *
 * Returns an nlm_host structure that matches the [client address,
 * transport protocol, NLM version, client hostname] of the passed-in
 * NLM request.  If one doesn't already exist in the host cache, a
 * new handle is created and returned.
 *
 * Before possibly creating a new nlm_host, construct a sockaddr
 * for a specific source address in case the local system has
 * multiple network addresses.  The family of the address in
 * rq_daddr is guaranteed to be the same as the family of the
 * address in rq_addr, so it's safe to use the same family for
 * the source address.
 */
struct nlm_host *nlmsvc_lookup_host(const struct svc_rqst *rqstp,
				    const char *hostname,
				    const size_t hostname_len)
{
	struct hlist_head *chain;
	struct nlm_host	*host = NULL;
	struct nsm_handle *nsm = NULL;
	struct sockaddr *src_sap = svc_daddr(rqstp);
	size_t src_len = rqstp->rq_daddrlen;
	struct net *net = SVC_NET(rqstp);
	struct nlm_lookup_host_info ni = {
		.server		= 1,
		.sap		= svc_addr(rqstp),
		.salen		= rqstp->rq_addrlen,
		.protocol	= rqstp->rq_prot,
		.version	= rqstp->rq_vers,
		.hostname	= hostname,
		.hostname_len	= hostname_len,
		.net		= net,
	};
	struct lockd_net *ln = net_generic(net, lockd_net_id);

	dprintk("lockd: %s(host='%*s', vers=%u, proto=%s)\n", __func__,
			(int)hostname_len, hostname, rqstp->rq_vers,
			(rqstp->rq_prot == IPPROTO_UDP ? "udp" : "tcp"));

	mutex_lock(&nlm_host_mutex);

	if (time_after_eq(jiffies, ln->next_gc))
		nlm_gc_hosts(net);

	chain = &nlm_server_hosts[nlm_hash_address(ni.sap)];
	hlist_for_each_entry(host, chain, h_hash) {
		if (host->net != net)
			continue;
		if (!rpc_cmp_addr(nlm_addr(host), ni.sap))
			continue;

		/* Same address. Share an NSM handle if we already have one */
		if (nsm == NULL)
			nsm = host->h_nsmhandle;

		if (host->h_proto != ni.protocol)
			continue;
		if (host->h_version != ni.version)
			continue;
		if (!rpc_cmp_addr(nlm_srcaddr(host), src_sap))
			continue;

		/* Move to head of hash chain. */
		hlist_del(&host->h_hash);
		hlist_add_head(&host->h_hash, chain);

		nlm_get_host(host);
		dprintk("lockd: %s found host %s (%s)\n",
			__func__, host->h_name, host->h_addrbuf);
		goto out;
	}

	host = nlm_alloc_host(&ni, nsm);
	if (unlikely(host == NULL))
		goto out;

	memcpy(nlm_srcaddr(host), src_sap, src_len);
	host->h_srcaddrlen = src_len;
	hlist_add_head(&host->h_hash, chain);
	ln->nrhosts++;
	nrhosts++;

	dprintk("lockd: %s created host %s (%s)\n",
		__func__, host->h_name, host->h_addrbuf);

out:
	mutex_unlock(&nlm_host_mutex);
	return host;
}

/**
 * nlmsvc_release_host - release server nlm_host
 * @host: nlm_host to release
 *
 * Host is destroyed later in nlm_gc_host().
 */
void nlmsvc_release_host(struct nlm_host *host)
{
	if (host == NULL)
		return;

	dprintk("lockd: release server host %s\n", host->h_name);

	WARN_ON_ONCE(!host->h_server);
	atomic_dec(&host->h_count);
}

/*
 * Create the NLM RPC client for an NLM peer
 */
struct rpc_clnt *
nlm_bind_host(struct nlm_host *host)
{
	struct rpc_clnt	*clnt;

	dprintk("lockd: nlm_bind_host %s (%s)\n",
			host->h_name, host->h_addrbuf);

	/* Lock host handle */
	mutex_lock(&host->h_mutex);

	/* If we've already created an RPC client, check whether
	 * RPC rebind is required
	 */
	if ((clnt = host->h_rpcclnt) != NULL) {
		if (time_after_eq(jiffies, host->h_nextrebind)) {
			rpc_force_rebind(clnt);
			host->h_nextrebind = jiffies + NLM_HOST_REBIND;
			dprintk("lockd: next rebind in %lu jiffies\n",
					host->h_nextrebind - jiffies);
		}
	} else {
		unsigned long increment = nlmsvc_timeout;
		struct rpc_timeout timeparms = {
			.to_initval	= increment,
			.to_increment	= increment,
			.to_maxval	= increment * 6UL,
			.to_retries	= 5U,
		};
		struct rpc_create_args args = {
			.net		= host->net,
			.protocol	= host->h_proto,
			.address	= nlm_addr(host),
			.addrsize	= host->h_addrlen,
			.timeout	= &timeparms,
			.servername	= host->h_name,
			.program	= &nlm_program,
			.version	= host->h_version,
			.authflavor	= RPC_AUTH_UNIX,
			.flags		= (RPC_CLNT_CREATE_NOPING |
					   RPC_CLNT_CREATE_AUTOBIND),
		};

		/*
		 * lockd retries server side blocks automatically so we want
		 * those to be soft RPC calls. Client side calls need to be
		 * hard RPC tasks.
		 */
		if (!host->h_server)
			args.flags |= RPC_CLNT_CREATE_HARDRTRY;
		if (host->h_noresvport)
			args.flags |= RPC_CLNT_CREATE_NONPRIVPORT;
		if (host->h_srcaddrlen)
			args.saddress = nlm_srcaddr(host);

		clnt = rpc_create(&args);
		if (!IS_ERR(clnt))
			host->h_rpcclnt = clnt;
		else {
			printk("lockd: couldn't create RPC handle for %s\n", host->h_name);
			clnt = NULL;
		}
	}

	mutex_unlock(&host->h_mutex);
	return clnt;
}

/*
 * Force a portmap lookup of the remote lockd port
 */
void
nlm_rebind_host(struct nlm_host *host)
{
	dprintk("lockd: rebind host %s\n", host->h_name);
	if (host->h_rpcclnt && time_after_eq(jiffies, host->h_nextrebind)) {
		rpc_force_rebind(host->h_rpcclnt);
		host->h_nextrebind = jiffies + NLM_HOST_REBIND;
	}
}

/*
 * Increment NLM host count
 */
struct nlm_host * nlm_get_host(struct nlm_host *host)
{
	if (host) {
		dprintk("lockd: get host %s\n", host->h_name);
		atomic_inc(&host->h_count);
		host->h_expires = jiffies + NLM_HOST_EXPIRE;
	}
	return host;
}

static struct nlm_host *next_host_state(struct hlist_head *cache,
					struct nsm_handle *nsm,
					const struct nlm_reboot *info)
{
	struct nlm_host *host;
	struct hlist_head *chain;

	mutex_lock(&nlm_host_mutex);
	for_each_host(host, chain, cache) {
		if (host->h_nsmhandle == nsm
		    && host->h_nsmstate != info->state) {
			host->h_nsmstate = info->state;
			host->h_state++;

			nlm_get_host(host);
			mutex_unlock(&nlm_host_mutex);
			return host;
		}
	}

	mutex_unlock(&nlm_host_mutex);
	return NULL;
}

/**
 * nlm_host_rebooted - Release all resources held by rebooted host
 * @info: pointer to decoded results of NLM_SM_NOTIFY call
 *
 * We were notified that the specified host has rebooted.  Release
 * all resources held by that peer.
 */
void nlm_host_rebooted(const struct nlm_reboot *info)
{
	struct nsm_handle *nsm;
	struct nlm_host	*host;

	nsm = nsm_reboot_lookup(info);
	if (unlikely(nsm == NULL))
		return;

	/* Mark all hosts tied to this NSM state as having rebooted.
	 * We run the loop repeatedly, because we drop the host table
	 * lock for this.
	 * To avoid processing a host several times, we match the nsmstate.
	 */
	while ((host = next_host_state(nlm_server_hosts, nsm, info)) != NULL) {
		nlmsvc_free_host_resources(host);
		nlmsvc_release_host(host);
	}
	while ((host = next_host_state(nlm_client_hosts, nsm, info)) != NULL) {
		nlmclnt_recovery(host);
		nlmclnt_release_host(host);
	}

	nsm_release(nsm);
}

static void nlm_complain_hosts(struct net *net)
{
	struct hlist_head *chain;
	struct nlm_host	*host;

	if (net) {
		struct lockd_net *ln = net_generic(net, lockd_net_id);

		if (ln->nrhosts == 0)
			return;
		printk(KERN_WARNING "lockd: couldn't shutdown host module for net %p!\n", net);
		dprintk("lockd: %lu hosts left in net %p:\n", ln->nrhosts, net);
	} else {
		if (nrhosts == 0)
			return;
		printk(KERN_WARNING "lockd: couldn't shutdown host module!\n");
		dprintk("lockd: %lu hosts left:\n", nrhosts);
	}

	for_each_host(host, chain, nlm_server_hosts) {
		if (net && host->net != net)
			continue;
		dprintk("       %s (cnt %d use %d exp %ld net %p)\n",
			host->h_name, atomic_read(&host->h_count),
			host->h_inuse, host->h_expires, host->net);
	}
}

void
nlm_shutdown_hosts_net(struct net *net)
{
	struct hlist_head *chain;
	struct nlm_host	*host;

	mutex_lock(&nlm_host_mutex);

	/* First, make all hosts eligible for gc */
	dprintk("lockd: nuking all hosts in net %p...\n", net);
	for_each_host(host, chain, nlm_server_hosts) {
		if (net && host->net != net)
			continue;
		host->h_expires = jiffies - 1;
		if (host->h_rpcclnt) {
			rpc_shutdown_client(host->h_rpcclnt);
			host->h_rpcclnt = NULL;
		}
	}

	/* Then, perform a garbage collection pass */
	nlm_gc_hosts(net);
	mutex_unlock(&nlm_host_mutex);

	nlm_complain_hosts(net);
}

/*
 * Shut down the hosts module.
 * Note that this routine is called only at server shutdown time.
 */
void
nlm_shutdown_hosts(void)
{
	dprintk("lockd: shutting down host module\n");
	nlm_shutdown_hosts_net(NULL);
}

/*
 * Garbage collect any unused NLM hosts.
 * This GC combines reference counting for async operations with
 * mark & sweep for resources held by remote clients.
 */
static void
nlm_gc_hosts(struct net *net)
{
	struct hlist_head *chain;
	struct hlist_node *next;
	struct nlm_host	*host;

	dprintk("lockd: host garbage collection for net %p\n", net);
	for_each_host(host, chain, nlm_server_hosts) {
		if (net && host->net != net)
			continue;
		host->h_inuse = 0;
	}

	/* Mark all hosts that hold locks, blocks or shares */
	nlmsvc_mark_resources(net);

	for_each_host_safe(host, next, chain, nlm_server_hosts) {
		if (net && host->net != net)
			continue;
		if (atomic_read(&host->h_count) || host->h_inuse
		 || time_before(jiffies, host->h_expires)) {
			dprintk("nlm_gc_hosts skipping %s "
				"(cnt %d use %d exp %ld net %p)\n",
				host->h_name, atomic_read(&host->h_count),
				host->h_inuse, host->h_expires, host->net);
			continue;
		}
		nlm_destroy_host_locked(host);
	}

	if (net) {
		struct lockd_net *ln = net_generic(net, lockd_net_id);

		ln->next_gc = jiffies + NLM_HOST_COLLECT;
	}
}
/************************************************************/
/* ../linux-3.17/fs/lockd/svc.c */
/************************************************************/
/*
 * linux/fs/lockd/svc.c
 *
 * This is the central lockd service.
 *
 * FIXME: Separate the lockd NFS server functionality from the lockd NFS
 * 	  client functionality. Oh why didn't Sun create two separate
 *	  services in the first place?
 *
 * Authors:	Olaf Kirch (okir@monad.swb.de)
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/module.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/moduleparam.h>

#include <linux/sched.h>
// #include <linux/errno.h>
// #include <linux/in.h>
#include <linux/uio.h>
#include <linux/smp.h>
// #include <linux/mutex.h>
// #include <linux/kthread.h>
// #include <linux/freezer.h>

#include <linux/sunrpc/types.h>
// #include <linux/sunrpc/stats.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/svc.h>
#include <linux/sunrpc/svcsock.h>
#include <net/ip.h>
// #include <linux/lockd/lockd.h>
#include <linux/nfs.h>

// #include "netns.h"

#define NLMDBG_FACILITY		NLMDBG_SVC
#define LOCKD_BUFSIZE		(1024 + NLMSVC_XDRSIZE)
#define ALLOWED_SIGS		(sigmask(SIGKILL))

static struct svc_program	nlmsvc_program;

struct nlmsvc_binding *		nlmsvc_ops;
EXPORT_SYMBOL_GPL(nlmsvc_ops);

static DEFINE_MUTEX(nlmsvc_mutex);
static unsigned int		nlmsvc_users;
static struct task_struct	*nlmsvc_task;
static struct svc_rqst		*nlmsvc_rqst;
unsigned long			nlmsvc_timeout;

int lockd_net_id;

/*
 * These can be set at insmod time (useful for NFS as root filesystem),
 * and also changed through the sysctl interface.  -- Jamie Lokier, Aug 2003
 */
static unsigned long		nlm_grace_period;
static unsigned long		nlm_timeout = LOCKD_DFLT_TIMEO;
static int			nlm_udpport, nlm_tcpport;

/* RLIM_NOFILE defaults to 1024. That seems like a reasonable default here. */
static unsigned int		nlm_max_connections = 1024;

/*
 * Constants needed for the sysctl interface.
 */
static const unsigned long	nlm_grace_period_min = 0;
static const unsigned long	nlm_grace_period_max = 240;
static const unsigned long	nlm_timeout_min = 3;
static const unsigned long	nlm_timeout_max = 20;
static const int		nlm_port_min = 0, nlm_port_max = 65535;

#ifdef CONFIG_SYSCTL
static struct ctl_table_header * nlm_sysctl_table;
#endif

static unsigned long get_lockd_grace_period(void)
{
	/* Note: nlm_timeout should always be nonzero */
	if (nlm_grace_period)
		return roundup(nlm_grace_period, nlm_timeout) * HZ;
	else
		return nlm_timeout * 5 * HZ;
}

static void grace_ender(struct work_struct *grace)
{
	struct delayed_work *dwork = container_of(grace, struct delayed_work,
						  work);
	struct lockd_net *ln = container_of(dwork, struct lockd_net,
					    grace_period_end);

	locks_end_grace(&ln->lockd_manager);
}

static void set_grace_period(struct net *net)
{
	unsigned long grace_period = get_lockd_grace_period();
	struct lockd_net *ln = net_generic(net, lockd_net_id);

	locks_start_grace(net, &ln->lockd_manager);
	cancel_delayed_work_sync(&ln->grace_period_end);
	schedule_delayed_work(&ln->grace_period_end, grace_period);
}

static void restart_grace(void)
{
	if (nlmsvc_ops) {
		struct net *net = &init_net;
		struct lockd_net *ln = net_generic(net, lockd_net_id);

		cancel_delayed_work_sync(&ln->grace_period_end);
		locks_end_grace(&ln->lockd_manager);
		nlmsvc_invalidate_all();
		set_grace_period(net);
	}
}

/*
 * This is the lockd kernel thread
 */
static int
lockd(void *vrqstp)
{
	int		err = 0;
	struct svc_rqst *rqstp = vrqstp;

	/* try_to_freeze() is called from svc_recv() */
	set_freezable();

	/* Allow SIGKILL to tell lockd to drop all of its locks */
	allow_signal(SIGKILL);

	dprintk("NFS locking service started (ver " LOCKD_VERSION ").\n");

	if (!nlm_timeout)
		nlm_timeout = LOCKD_DFLT_TIMEO;
	nlmsvc_timeout = nlm_timeout * HZ;

	/*
	 * The main request loop. We don't terminate until the last
	 * NFS mount or NFS daemon has gone away.
	 */
	while (!kthread_should_stop()) {
		long timeout = MAX_SCHEDULE_TIMEOUT;
		RPC_IFDEBUG(char buf[RPC_MAX_ADDRBUFLEN]);

		/* update sv_maxconn if it has changed */
		rqstp->rq_server->sv_maxconn = nlm_max_connections;

		if (signalled()) {
			flush_signals(current);
			restart_grace();
			continue;
		}

		timeout = nlmsvc_retry_blocked();

		/*
		 * Find a socket with data available and call its
		 * recvfrom routine.
		 */
		err = svc_recv(rqstp, timeout);
		if (err == -EAGAIN || err == -EINTR)
			continue;
		dprintk("lockd: request from %s\n",
				svc_print_addr(rqstp, buf, sizeof(buf)));

		svc_process(rqstp);
	}
	flush_signals(current);
	if (nlmsvc_ops)
		nlmsvc_invalidate_all();
	nlm_shutdown_hosts();
	return 0;
}

static int create_lockd_listener(struct svc_serv *serv, const char *name,
				 struct net *net, const int family,
				 const unsigned short port)
{
	struct svc_xprt *xprt;

	xprt = svc_find_xprt(serv, name, net, family, 0);
	if (xprt == NULL)
		return svc_create_xprt(serv, name, net, family, port,
						SVC_SOCK_DEFAULTS);
	svc_xprt_put(xprt);
	return 0;
}

static int create_lockd_family(struct svc_serv *serv, struct net *net,
			       const int family)
{
	int err;

	err = create_lockd_listener(serv, "udp", net, family, nlm_udpport);
	if (err < 0)
		return err;

	return create_lockd_listener(serv, "tcp", net, family, nlm_tcpport);
}

/*
 * Ensure there are active UDP and TCP listeners for lockd.
 *
 * Even if we have only TCP NFS mounts and/or TCP NFSDs, some
 * local services (such as rpc.statd) still require UDP, and
 * some NFS servers do not yet support NLM over TCP.
 *
 * Returns zero if all listeners are available; otherwise a
 * negative errno value is returned.
 */
static int make_socks(struct svc_serv *serv, struct net *net)
{
	static int warned;
	int err;

	err = create_lockd_family(serv, net, PF_INET);
	if (err < 0)
		goto out_err;

	err = create_lockd_family(serv, net, PF_INET6);
	if (err < 0 && err != -EAFNOSUPPORT)
		goto out_err;

	warned = 0;
	return 0;

out_err:
	if (warned++ == 0)
		printk(KERN_WARNING
			"lockd_up: makesock failed, error=%d\n", err);
	svc_shutdown_net(serv, net);
	return err;
}

static int lockd_up_net(struct svc_serv *serv, struct net *net)
{
	struct lockd_net *ln = net_generic(net, lockd_net_id);
	int error;

	if (ln->nlmsvc_users++)
		return 0;

	error = svc_bind(serv, net);
	if (error)
		goto err_bind;

	error = make_socks(serv, net);
	if (error < 0)
		goto err_socks;
	set_grace_period(net);
	dprintk("lockd_up_net: per-net data created; net=%p\n", net);
	return 0;

err_socks:
	svc_rpcb_cleanup(serv, net);
err_bind:
	ln->nlmsvc_users--;
	return error;
}

static void lockd_down_net(struct svc_serv *serv, struct net *net)
{
	struct lockd_net *ln = net_generic(net, lockd_net_id);

	if (ln->nlmsvc_users) {
		if (--ln->nlmsvc_users == 0) {
			nlm_shutdown_hosts_net(net);
			cancel_delayed_work_sync(&ln->grace_period_end);
			locks_end_grace(&ln->lockd_manager);
			svc_shutdown_net(serv, net);
			dprintk("lockd_down_net: per-net data destroyed; net=%p\n", net);
		}
	} else {
		printk(KERN_ERR "lockd_down_net: no users! task=%p, net=%p\n",
				nlmsvc_task, net);
		BUG();
	}
}

static int lockd_start_svc(struct svc_serv *serv)
{
	int error;

	if (nlmsvc_rqst)
		return 0;

	/*
	 * Create the kernel thread and wait for it to start.
	 */
	nlmsvc_rqst = svc_prepare_thread(serv, &serv->sv_pools[0], NUMA_NO_NODE);
	if (IS_ERR(nlmsvc_rqst)) {
		error = PTR_ERR(nlmsvc_rqst);
		printk(KERN_WARNING
			"lockd_up: svc_rqst allocation failed, error=%d\n",
			error);
		goto out_rqst;
	}

	svc_sock_update_bufs(serv);
	serv->sv_maxconn = nlm_max_connections;

	nlmsvc_task = kthread_run(lockd, nlmsvc_rqst, "%s", serv->sv_name);
	if (IS_ERR(nlmsvc_task)) {
		error = PTR_ERR(nlmsvc_task);
		printk(KERN_WARNING
			"lockd_up: kthread_run failed, error=%d\n", error);
		goto out_task;
	}
	dprintk("lockd_up: service started\n");
	return 0;

out_task:
	svc_exit_thread(nlmsvc_rqst);
	nlmsvc_task = NULL;
out_rqst:
	nlmsvc_rqst = NULL;
	return error;
}

static struct svc_serv *lockd_create_svc(void)
{
	struct svc_serv *serv;

	/*
	 * Check whether we're already up and running.
	 */
	if (nlmsvc_rqst) {
		/*
		 * Note: increase service usage, because later in case of error
		 * svc_destroy() will be called.
		 */
		svc_get(nlmsvc_rqst->rq_server);
		return nlmsvc_rqst->rq_server;
	}

	/*
	 * Sanity check: if there's no pid,
	 * we should be the first user ...
	 */
	if (nlmsvc_users)
		printk(KERN_WARNING
			"lockd_up: no pid, %d users??\n", nlmsvc_users);

	serv = svc_create(&nlmsvc_program, LOCKD_BUFSIZE, NULL);
	if (!serv) {
		printk(KERN_WARNING "lockd_up: create service failed\n");
		return ERR_PTR(-ENOMEM);
	}
	dprintk("lockd_up: service created\n");
	return serv;
}

/*
 * Bring up the lockd process if it's not already up.
 */
int lockd_up(struct net *net)
{
	struct svc_serv *serv;
	int error;

	mutex_lock(&nlmsvc_mutex);

	serv = lockd_create_svc();
	if (IS_ERR(serv)) {
		error = PTR_ERR(serv);
		goto err_create;
	}

	error = lockd_up_net(serv, net);
	if (error < 0)
		goto err_net;

	error = lockd_start_svc(serv);
	if (error < 0)
		goto err_start;

	nlmsvc_users++;
	/*
	 * Note: svc_serv structures have an initial use count of 1,
	 * so we exit through here on both success and failure.
	 */
err_net:
	svc_destroy(serv);
err_create:
	mutex_unlock(&nlmsvc_mutex);
	return error;

err_start:
	lockd_down_net(serv, net);
	goto err_net;
}
EXPORT_SYMBOL_GPL(lockd_up);

/*
 * Decrement the user count and bring down lockd if we're the last.
 */
void
lockd_down(struct net *net)
{
	mutex_lock(&nlmsvc_mutex);
	lockd_down_net(nlmsvc_rqst->rq_server, net);
	if (nlmsvc_users) {
		if (--nlmsvc_users)
			goto out;
	} else {
		printk(KERN_ERR "lockd_down: no users! task=%p\n",
			nlmsvc_task);
		BUG();
	}

	if (!nlmsvc_task) {
		printk(KERN_ERR "lockd_down: no lockd running.\n");
		BUG();
	}
	kthread_stop(nlmsvc_task);
	dprintk("lockd_down: service stopped\n");
	svc_exit_thread(nlmsvc_rqst);
	dprintk("lockd_down: service destroyed\n");
	nlmsvc_task = NULL;
	nlmsvc_rqst = NULL;
out:
	mutex_unlock(&nlmsvc_mutex);
}
EXPORT_SYMBOL_GPL(lockd_down);

#ifdef CONFIG_SYSCTL

/*
 * Sysctl parameters (same as module parameters, different interface).
 */

static struct ctl_table nlm_sysctls[] = {
	{
		.procname	= "nlm_grace_period",
		.data		= &nlm_grace_period,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= (unsigned long *) &nlm_grace_period_min,
		.extra2		= (unsigned long *) &nlm_grace_period_max,
	},
	{
		.procname	= "nlm_timeout",
		.data		= &nlm_timeout,
		.maxlen		= sizeof(unsigned long),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= (unsigned long *) &nlm_timeout_min,
		.extra2		= (unsigned long *) &nlm_timeout_max,
	},
	{
		.procname	= "nlm_udpport",
		.data		= &nlm_udpport,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= (int *) &nlm_port_min,
		.extra2		= (int *) &nlm_port_max,
	},
	{
		.procname	= "nlm_tcpport",
		.data		= &nlm_tcpport,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= (int *) &nlm_port_min,
		.extra2		= (int *) &nlm_port_max,
	},
	{
		.procname	= "nsm_use_hostnames",
		.data		= &nsm_use_hostnames,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "nsm_local_state",
		.data		= &nsm_local_state,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static struct ctl_table nlm_sysctl_dir[] = {
	{
		.procname	= "nfs",
		.mode		= 0555,
		.child		= nlm_sysctls,
	},
	{ }
};

static struct ctl_table nlm_sysctl_root[] = {
	{
		.procname	= "fs",
		.mode		= 0555,
		.child		= nlm_sysctl_dir,
	},
	{ }
};

#endif	/* CONFIG_SYSCTL */

/*
 * Module (and sysfs) parameters.
 */

#define param_set_min_max(name, type, which_strtol, min, max)		\
static int param_set_##name(const char *val, struct kernel_param *kp)	\
{									\
	char *endp;							\
	__typeof__(type) num = which_strtol(val, &endp, 0);		\
	if (endp == val || *endp || num < (min) || num > (max))		\
		return -EINVAL;						\
	*((type *) kp->arg) = num;					\
	return 0;							\
}

static inline int is_callback(u32 proc)
{
	return proc == NLMPROC_GRANTED
		|| proc == NLMPROC_GRANTED_MSG
		|| proc == NLMPROC_TEST_RES
		|| proc == NLMPROC_LOCK_RES
		|| proc == NLMPROC_CANCEL_RES
		|| proc == NLMPROC_UNLOCK_RES
		|| proc == NLMPROC_NSM_NOTIFY;
}


static int lockd_authenticate(struct svc_rqst *rqstp)
{
	rqstp->rq_client = NULL;
	switch (rqstp->rq_authop->flavour) {
		case RPC_AUTH_NULL:
		case RPC_AUTH_UNIX:
			if (rqstp->rq_proc == 0)
				return SVC_OK;
			if (is_callback(rqstp->rq_proc)) {
				/* Leave it to individual procedures to
				 * call nlmsvc_lookup_host(rqstp)
				 */
				return SVC_OK;
			}
			return svc_set_client(rqstp);
	}
	return SVC_DENIED;
}


param_set_min_max(port, int, simple_strtol, 0, 65535)
param_set_min_max(grace_period, unsigned long, simple_strtoul,
		  nlm_grace_period_min, nlm_grace_period_max)
param_set_min_max(timeout, unsigned long, simple_strtoul,
		  nlm_timeout_min, nlm_timeout_max)

MODULE_AUTHOR("Olaf Kirch <okir@monad.swb.de>");
MODULE_DESCRIPTION("NFS file locking service version " LOCKD_VERSION ".");
MODULE_LICENSE("GPL");

module_param_call(nlm_grace_period, param_set_grace_period, param_get_ulong,
		  &nlm_grace_period, 0644);
module_param_call(nlm_timeout, param_set_timeout, param_get_ulong,
		  &nlm_timeout, 0644);
module_param_call(nlm_udpport, param_set_port, param_get_int,
		  &nlm_udpport, 0644);
module_param_call(nlm_tcpport, param_set_port, param_get_int,
		  &nlm_tcpport, 0644);
module_param(nsm_use_hostnames, bool, 0644);
module_param(nlm_max_connections, uint, 0644);

static int lockd_init_net(struct net *net)
{
	struct lockd_net *ln = net_generic(net, lockd_net_id);

	INIT_DELAYED_WORK(&ln->grace_period_end, grace_ender);
	INIT_LIST_HEAD(&ln->grace_list);
	spin_lock_init(&ln->nsm_clnt_lock);
	return 0;
}

static void lockd_exit_net(struct net *net)
{
}

static struct pernet_operations lockd_net_ops = {
	.init = lockd_init_net,
	.exit = lockd_exit_net,
	.id = &lockd_net_id,
	.size = sizeof(struct lockd_net),
};


/*
 * Initialising and terminating the module.
 */

static int __init init_nlm(void)
{
	int err;

#ifdef CONFIG_SYSCTL
	err = -ENOMEM;
	nlm_sysctl_table = register_sysctl_table(nlm_sysctl_root);
	if (nlm_sysctl_table == NULL)
		goto err_sysctl;
#endif
	err = register_pernet_subsys(&lockd_net_ops);
	if (err)
		goto err_pernet;
	return 0;

err_pernet:
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(nlm_sysctl_table);
err_sysctl:
#endif
	return err;
}

static void __exit exit_nlm(void)
{
	/* FIXME: delete all NLM clients */
	nlm_shutdown_hosts();
	unregister_pernet_subsys(&lockd_net_ops);
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(nlm_sysctl_table);
#endif
}

module_init(init_nlm);
module_exit(exit_nlm);

/*
 * Define NLM program and procedures
 */
static struct svc_version	nlmsvc_version1 = {
		.vs_vers	= 1,
		.vs_nproc	= 17,
		.vs_proc	= nlmsvc_procedures,
		.vs_xdrsize	= NLMSVC_XDRSIZE,
};
static struct svc_version	nlmsvc_version3 = {
		.vs_vers	= 3,
		.vs_nproc	= 24,
		.vs_proc	= nlmsvc_procedures,
		.vs_xdrsize	= NLMSVC_XDRSIZE,
};
#ifdef CONFIG_LOCKD_V4
static struct svc_version	nlmsvc_version4 = {
		.vs_vers	= 4,
		.vs_nproc	= 24,
		.vs_proc	= nlmsvc_procedures4,
		.vs_xdrsize	= NLMSVC_XDRSIZE,
};
#endif
static struct svc_version *	nlmsvc_version[] = {
	[1] = &nlmsvc_version1,
	[3] = &nlmsvc_version3,
#ifdef CONFIG_LOCKD_V4
	[4] = &nlmsvc_version4,
#endif
};

static struct svc_stat		nlmsvc_stats;

#define NLM_NRVERS	ARRAY_SIZE(nlmsvc_version)
static struct svc_program	nlmsvc_program = {
	.pg_prog		= NLM_PROGRAM,		/* program number */
	.pg_nvers		= NLM_NRVERS,		/* number of entries in nlmsvc_version */
	.pg_vers		= nlmsvc_version,	/* version table */
	.pg_name		= "lockd",		/* service name */
	.pg_class		= "nfsd",		/* share authentication with nfsd */
	.pg_stats		= &nlmsvc_stats,	/* stats table */
	.pg_authenticate = &lockd_authenticate	/* export authentication */
};
/************************************************************/
/* ../linux-3.17/fs/lockd/svclock.c */
/************************************************************/
/*
 * linux/fs/lockd/svclock.c
 *
 * Handling of server-side locks, mostly of the blocked variety.
 * This is the ugliest part of lockd because we tread on very thin ice.
 * GRANT and CANCEL calls may get stuck, meet in mid-flight, etc.
 * IMNSHO introducing the grant callback into the NLM protocol was one
 * of the worst ideas Sun ever had. Except maybe for the idea of doing
 * NFS file locking at all.
 *
 * I'm trying hard to avoid race conditions by protecting most accesses
 * to a file's list of blocked locks through a semaphore. The global
 * list of blocked locks is not protected in this fashion however.
 * Therefore, some functions (such as the RPC callback for the async grant
 * call) move blocked locks towards the head of the list *while some other
 * process might be traversing it*. This should not be a problem in
 * practice, because this will only cause functions traversing the list
 * to visit some blocks twice.
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/types.h>
// #include <linux/slab.h>
// #include <linux/errno.h>
#include <linux/kernel.h>
// #include <linux/sched.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/svc_xprt.h>
#include <linux/lockd/nlm.h>
// #include <linux/lockd/lockd.h>
// #include <linux/kthread.h>

#define NLMDBG_FACILITY		NLMDBG_SVCLOCK

#ifdef CONFIG_LOCKD_V4
#define nlm_deadlock	nlm4_deadlock
#else
#define nlm_deadlock	nlm_lck_denied
#endif

static void nlmsvc_release_block(struct nlm_block *block);
static void	nlmsvc_insert_block(struct nlm_block *block, unsigned long);
static void	nlmsvc_remove_block(struct nlm_block *block);

static int nlmsvc_setgrantargs(struct nlm_rqst *call, struct nlm_lock *lock);
static void nlmsvc_freegrantargs(struct nlm_rqst *call);
static const struct rpc_call_ops nlmsvc_grant_ops;

/*
 * The list of blocked locks to retry
 */
static LIST_HEAD_svclock_c(nlm_blocked);
static DEFINE_SPINLOCK(nlm_blocked_lock);

#ifdef LOCKD_DEBUG
static const char *nlmdbg_cookie2a(const struct nlm_cookie *cookie)
{
	/*
	 * We can get away with a static buffer because we're only
	 * called with BKL held.
	 */
	static char buf[2*NLM_MAXCOOKIELEN+1];
	unsigned int i, len = sizeof(buf);
	char *p = buf;

	len--;	/* allow for trailing \0 */
	if (len < 3)
		return "???";
	for (i = 0 ; i < cookie->len ; i++) {
		if (len < 2) {
			strcpy(p-3, "...");
			break;
		}
		sprintf(p, "%02x", cookie->data[i]);
		p += 2;
		len -= 2;
	}
	*p = '\0';

	return buf;
}
#endif

/*
 * Insert a blocked lock into the global list
 */
static void
nlmsvc_insert_block_locked(struct nlm_block *block, unsigned long when)
{
	struct nlm_block *b;
	struct list_head *pos;

	dprintk("lockd: nlmsvc_insert_block(%p, %ld)\n", block, when);
	if (list_empty(&block->b_list)) {
		kref_get(&block->b_count);
	} else {
		list_del_init(&block->b_list);
	}

	pos = &nlm_blocked;
	if (when != NLM_NEVER) {
		if ((when += jiffies) == NLM_NEVER)
			when ++;
		list_for_each(pos, &nlm_blocked) {
			b = list_entry(pos, struct nlm_block, b_list);
			if (time_after(b->b_when,when) || b->b_when == NLM_NEVER)
				break;
		}
		/* On normal exit from the loop, pos == &nlm_blocked,
		 * so we will be adding to the end of the list - good
		 */
	}

	list_add_tail(&block->b_list, pos);
	block->b_when = when;
}

static void nlmsvc_insert_block(struct nlm_block *block, unsigned long when)
{
	spin_lock(&nlm_blocked_lock);
	nlmsvc_insert_block_locked(block, when);
	spin_unlock(&nlm_blocked_lock);
}

/*
 * Remove a block from the global list
 */
static inline void
nlmsvc_remove_block(struct nlm_block *block)
{
	if (!list_empty(&block->b_list)) {
		spin_lock(&nlm_blocked_lock);
		list_del_init(&block->b_list);
		spin_unlock(&nlm_blocked_lock);
		nlmsvc_release_block(block);
	}
}

/*
 * Find a block for a given lock
 */
static struct nlm_block *
nlmsvc_lookup_block(struct nlm_file *file, struct nlm_lock *lock)
{
	struct nlm_block	*block;
	struct file_lock	*fl;

	dprintk("lockd: nlmsvc_lookup_block f=%p pd=%d %Ld-%Ld ty=%d\n",
				file, lock->fl.fl_pid,
				(long long)lock->fl.fl_start,
				(long long)lock->fl.fl_end, lock->fl.fl_type);
	list_for_each_entry(block, &nlm_blocked, b_list) {
		fl = &block->b_call->a_args.lock.fl;
		dprintk("lockd: check f=%p pd=%d %Ld-%Ld ty=%d cookie=%s\n",
				block->b_file, fl->fl_pid,
				(long long)fl->fl_start,
				(long long)fl->fl_end, fl->fl_type,
				nlmdbg_cookie2a(&block->b_call->a_args.cookie));
		if (block->b_file == file && nlm_compare_locks(fl, &lock->fl)) {
			kref_get(&block->b_count);
			return block;
		}
	}

	return NULL;
}

static inline int nlm_cookie_match(struct nlm_cookie *a, struct nlm_cookie *b)
{
	if (a->len != b->len)
		return 0;
	if (memcmp(a->data, b->data, a->len))
		return 0;
	return 1;
}

/*
 * Find a block with a given NLM cookie.
 */
static inline struct nlm_block *
nlmsvc_find_block(struct nlm_cookie *cookie)
{
	struct nlm_block *block;

	list_for_each_entry(block, &nlm_blocked, b_list) {
		if (nlm_cookie_match(&block->b_call->a_args.cookie,cookie))
			goto found;
	}

	return NULL;

found:
	dprintk("nlmsvc_find_block(%s): block=%p\n", nlmdbg_cookie2a(cookie), block);
	kref_get(&block->b_count);
	return block;
}

/*
 * Create a block and initialize it.
 *
 * Note: we explicitly set the cookie of the grant reply to that of
 * the blocked lock request. The spec explicitly mentions that the client
 * should _not_ rely on the callback containing the same cookie as the
 * request, but (as I found out later) that's because some implementations
 * do just this. Never mind the standards comittees, they support our
 * logging industries.
 *
 * 10 years later: I hope we can safely ignore these old and broken
 * clients by now. Let's fix this so we can uniquely identify an incoming
 * GRANTED_RES message by cookie, without having to rely on the client's IP
 * address. --okir
 */
static struct nlm_block *
nlmsvc_create_block(struct svc_rqst *rqstp, struct nlm_host *host,
		    struct nlm_file *file, struct nlm_lock *lock,
		    struct nlm_cookie *cookie)
{
	struct nlm_block	*block;
	struct nlm_rqst		*call = NULL;

	call = nlm_alloc_call(host);
	if (call == NULL)
		return NULL;

	/* Allocate memory for block, and initialize arguments */
	block = kzalloc(sizeof(*block), GFP_KERNEL);
	if (block == NULL)
		goto failed;
	kref_init(&block->b_count);
	INIT_LIST_HEAD(&block->b_list);
	INIT_LIST_HEAD(&block->b_flist);

	if (!nlmsvc_setgrantargs(call, lock))
		goto failed_free;

	/* Set notifier function for VFS, and init args */
	call->a_args.lock.fl.fl_flags |= FL_SLEEP;
	call->a_args.lock.fl.fl_lmops = &nlmsvc_lock_operations;
	nlmclnt_next_cookie(&call->a_args.cookie);

	dprintk("lockd: created block %p...\n", block);

	/* Create and initialize the block */
	block->b_daemon = rqstp->rq_server;
	block->b_host   = host;
	block->b_file   = file;
	block->b_fl = NULL;
	file->f_count++;

	/* Add to file's list of blocks */
	list_add(&block->b_flist, &file->f_blocks);

	/* Set up RPC arguments for callback */
	block->b_call = call;
	call->a_flags   = RPC_TASK_ASYNC;
	call->a_block = block;

	return block;

failed_free:
	kfree(block);
failed:
	nlmsvc_release_call(call);
	return NULL;
}

/*
 * Delete a block.
 * It is the caller's responsibility to check whether the file
 * can be closed hereafter.
 */
static int nlmsvc_unlink_block(struct nlm_block *block)
{
	int status;
	dprintk("lockd: unlinking block %p...\n", block);

	/* Remove block from list */
	status = posix_unblock_lock(&block->b_call->a_args.lock.fl);
	nlmsvc_remove_block(block);
	return status;
}

static void nlmsvc_free_block(struct kref *kref)
{
	struct nlm_block *block = container_of(kref, struct nlm_block, b_count);
	struct nlm_file		*file = block->b_file;

	dprintk("lockd: freeing block %p...\n", block);

	/* Remove block from file's list of blocks */
	list_del_init(&block->b_flist);
	mutex_unlock(&file->f_mutex);

	nlmsvc_freegrantargs(block->b_call);
	nlmsvc_release_call(block->b_call);
	nlm_release_file(block->b_file);
	kfree(block->b_fl);
	kfree(block);
}

static void nlmsvc_release_block(struct nlm_block *block)
{
	if (block != NULL)
		kref_put_mutex(&block->b_count, nlmsvc_free_block, &block->b_file->f_mutex);
}

/*
 * Loop over all blocks and delete blocks held by
 * a matching host.
 */
void nlmsvc_traverse_blocks(struct nlm_host *host,
			struct nlm_file *file,
			nlm_host_match_fn_t match)
{
	struct nlm_block *block, *next;

restart:
	mutex_lock(&file->f_mutex);
	list_for_each_entry_safe(block, next, &file->f_blocks, b_flist) {
		if (!match(block->b_host, host))
			continue;
		/* Do not destroy blocks that are not on
		 * the global retry list - why? */
		if (list_empty(&block->b_list))
			continue;
		kref_get(&block->b_count);
		mutex_unlock(&file->f_mutex);
		nlmsvc_unlink_block(block);
		nlmsvc_release_block(block);
		goto restart;
	}
	mutex_unlock(&file->f_mutex);
}

/*
 * Initialize arguments for GRANTED call. The nlm_rqst structure
 * has been cleared already.
 */
static int nlmsvc_setgrantargs(struct nlm_rqst *call, struct nlm_lock *lock)
{
	locks_copy_lock(&call->a_args.lock.fl, &lock->fl);
	memcpy(&call->a_args.lock.fh, &lock->fh, sizeof(call->a_args.lock.fh));
	call->a_args.lock.caller = utsname()->nodename;
	call->a_args.lock.oh.len = lock->oh.len;

	/* set default data area */
	call->a_args.lock.oh.data = call->a_owner;
	call->a_args.lock.svid = lock->fl.fl_pid;

	if (lock->oh.len > NLMCLNT_OHSIZE) {
		void *data = kmalloc(lock->oh.len, GFP_KERNEL);
		if (!data)
			return 0;
		call->a_args.lock.oh.data = (u8 *) data;
	}

	memcpy(call->a_args.lock.oh.data, lock->oh.data, lock->oh.len);
	return 1;
}

static void nlmsvc_freegrantargs(struct nlm_rqst *call)
{
	if (call->a_args.lock.oh.data != call->a_owner)
		kfree(call->a_args.lock.oh.data);

	locks_release_private(&call->a_args.lock.fl);
}

/*
 * Deferred lock request handling for non-blocking lock
 */
static __be32
nlmsvc_defer_lock_rqst(struct svc_rqst *rqstp, struct nlm_block *block)
{
	__be32 status = nlm_lck_denied_nolocks;

	block->b_flags |= B_QUEUED;

	nlmsvc_insert_block(block, NLM_TIMEOUT);

	block->b_cache_req = &rqstp->rq_chandle;
	if (rqstp->rq_chandle.defer) {
		block->b_deferred_req =
			rqstp->rq_chandle.defer(block->b_cache_req);
		if (block->b_deferred_req != NULL)
			status = nlm_drop_reply;
	}
	dprintk("lockd: nlmsvc_defer_lock_rqst block %p flags %d status %d\n",
		block, block->b_flags, ntohl(status));

	return status;
}

/*
 * Attempt to establish a lock, and if it can't be granted, block it
 * if required.
 */
__be32
nlmsvc_lock(struct svc_rqst *rqstp, struct nlm_file *file,
	    struct nlm_host *host, struct nlm_lock *lock, int wait,
	    struct nlm_cookie *cookie, int reclaim)
{
	struct nlm_block	*block = NULL;
	int			error;
	__be32			ret;

	dprintk("lockd: nlmsvc_lock(%s/%ld, ty=%d, pi=%d, %Ld-%Ld, bl=%d)\n",
				file_inode(file->f_file)->i_sb->s_id,
				file_inode(file->f_file)->i_ino,
				lock->fl.fl_type, lock->fl.fl_pid,
				(long long)lock->fl.fl_start,
				(long long)lock->fl.fl_end,
				wait);

	/* Lock file against concurrent access */
	mutex_lock(&file->f_mutex);
	/* Get existing block (in case client is busy-waiting)
	 * or create new block
	 */
	block = nlmsvc_lookup_block(file, lock);
	if (block == NULL) {
		block = nlmsvc_create_block(rqstp, host, file, lock, cookie);
		ret = nlm_lck_denied_nolocks;
		if (block == NULL)
			goto out;
		lock = &block->b_call->a_args.lock;
	} else
		lock->fl.fl_flags &= ~FL_SLEEP;

	if (block->b_flags & B_QUEUED) {
		dprintk("lockd: nlmsvc_lock deferred block %p flags %d\n",
							block, block->b_flags);
		if (block->b_granted) {
			nlmsvc_unlink_block(block);
			ret = nlm_granted;
			goto out;
		}
		if (block->b_flags & B_TIMED_OUT) {
			nlmsvc_unlink_block(block);
			ret = nlm_lck_denied;
			goto out;
		}
		ret = nlm_drop_reply;
		goto out;
	}

	if (locks_in_grace(SVC_NET(rqstp)) && !reclaim) {
		ret = nlm_lck_denied_grace_period;
		goto out;
	}
	if (reclaim && !locks_in_grace(SVC_NET(rqstp))) {
		ret = nlm_lck_denied_grace_period;
		goto out;
	}

	if (!wait)
		lock->fl.fl_flags &= ~FL_SLEEP;
	error = vfs_lock_file(file->f_file, F_SETLK, &lock->fl, NULL);
	lock->fl.fl_flags &= ~FL_SLEEP;

	dprintk("lockd: vfs_lock_file returned %d\n", error);
	switch (error) {
		case 0:
			ret = nlm_granted;
			goto out;
		case -EAGAIN:
			/*
			 * If this is a blocking request for an
			 * already pending lock request then we need
			 * to put it back on lockd's block list
			 */
			if (wait)
				break;
			ret = nlm_lck_denied;
			goto out;
		case FILE_LOCK_DEFERRED:
			if (wait)
				break;
			/* Filesystem lock operation is in progress
			   Add it to the queue waiting for callback */
			ret = nlmsvc_defer_lock_rqst(rqstp, block);
			goto out;
		case -EDEADLK:
			ret = nlm_deadlock;
			goto out;
		default:			/* includes ENOLCK */
			ret = nlm_lck_denied_nolocks;
			goto out;
	}

	ret = nlm_lck_blocked;

	/* Append to list of blocked */
	nlmsvc_insert_block(block, NLM_NEVER);
out:
	mutex_unlock(&file->f_mutex);
	nlmsvc_release_block(block);
	dprintk("lockd: nlmsvc_lock returned %u\n", ret);
	return ret;
}

/*
 * Test for presence of a conflicting lock.
 */
__be32
nlmsvc_testlock(struct svc_rqst *rqstp, struct nlm_file *file,
		struct nlm_host *host, struct nlm_lock *lock,
		struct nlm_lock *conflock, struct nlm_cookie *cookie)
{
	struct nlm_block 	*block = NULL;
	int			error;
	__be32			ret;

	dprintk("lockd: nlmsvc_testlock(%s/%ld, ty=%d, %Ld-%Ld)\n",
				file_inode(file->f_file)->i_sb->s_id,
				file_inode(file->f_file)->i_ino,
				lock->fl.fl_type,
				(long long)lock->fl.fl_start,
				(long long)lock->fl.fl_end);

	/* Get existing block (in case client is busy-waiting) */
	block = nlmsvc_lookup_block(file, lock);

	if (block == NULL) {
		struct file_lock *conf = kzalloc(sizeof(*conf), GFP_KERNEL);

		if (conf == NULL)
			return nlm_granted;
		block = nlmsvc_create_block(rqstp, host, file, lock, cookie);
		if (block == NULL) {
			kfree(conf);
			return nlm_granted;
		}
		block->b_fl = conf;
	}
	if (block->b_flags & B_QUEUED) {
		dprintk("lockd: nlmsvc_testlock deferred block %p flags %d fl %p\n",
			block, block->b_flags, block->b_fl);
		if (block->b_flags & B_TIMED_OUT) {
			nlmsvc_unlink_block(block);
			ret = nlm_lck_denied;
			goto out;
		}
		if (block->b_flags & B_GOT_CALLBACK) {
			nlmsvc_unlink_block(block);
			if (block->b_fl != NULL
					&& block->b_fl->fl_type != F_UNLCK) {
				lock->fl = *block->b_fl;
				goto conf_lock;
			} else {
				ret = nlm_granted;
				goto out;
			}
		}
		ret = nlm_drop_reply;
		goto out;
	}

	if (locks_in_grace(SVC_NET(rqstp))) {
		ret = nlm_lck_denied_grace_period;
		goto out;
	}
	error = vfs_test_lock(file->f_file, &lock->fl);
	if (error == FILE_LOCK_DEFERRED) {
		ret = nlmsvc_defer_lock_rqst(rqstp, block);
		goto out;
	}
	if (error) {
		ret = nlm_lck_denied_nolocks;
		goto out;
	}
	if (lock->fl.fl_type == F_UNLCK) {
		ret = nlm_granted;
		goto out;
	}

conf_lock:
	dprintk("lockd: conflicting lock(ty=%d, %Ld-%Ld)\n",
		lock->fl.fl_type, (long long)lock->fl.fl_start,
		(long long)lock->fl.fl_end);
	conflock->caller = "somehost";	/* FIXME */
	conflock->len = strlen(conflock->caller);
	conflock->oh.len = 0;		/* don't return OH info */
	conflock->svid = lock->fl.fl_pid;
	conflock->fl.fl_type = lock->fl.fl_type;
	conflock->fl.fl_start = lock->fl.fl_start;
	conflock->fl.fl_end = lock->fl.fl_end;
	ret = nlm_lck_denied;
out:
	if (block)
		nlmsvc_release_block(block);
	return ret;
}

/*
 * Remove a lock.
 * This implies a CANCEL call: We send a GRANT_MSG, the client replies
 * with a GRANT_RES call which gets lost, and calls UNLOCK immediately
 * afterwards. In this case the block will still be there, and hence
 * must be removed.
 */
__be32
nlmsvc_unlock(struct net *net, struct nlm_file *file, struct nlm_lock *lock)
{
	int	error;

	dprintk("lockd: nlmsvc_unlock(%s/%ld, pi=%d, %Ld-%Ld)\n",
				file_inode(file->f_file)->i_sb->s_id,
				file_inode(file->f_file)->i_ino,
				lock->fl.fl_pid,
				(long long)lock->fl.fl_start,
				(long long)lock->fl.fl_end);

	/* First, cancel any lock that might be there */
	nlmsvc_cancel_blocked(net, file, lock);

	lock->fl.fl_type = F_UNLCK;
	error = vfs_lock_file(file->f_file, F_SETLK, &lock->fl, NULL);

	return (error < 0)? nlm_lck_denied_nolocks : nlm_granted;
}

/*
 * Cancel a previously blocked request.
 *
 * A cancel request always overrides any grant that may currently
 * be in progress.
 * The calling procedure must check whether the file can be closed.
 */
__be32
nlmsvc_cancel_blocked(struct net *net, struct nlm_file *file, struct nlm_lock *lock)
{
	struct nlm_block	*block;
	int status = 0;

	dprintk("lockd: nlmsvc_cancel(%s/%ld, pi=%d, %Ld-%Ld)\n",
				file_inode(file->f_file)->i_sb->s_id,
				file_inode(file->f_file)->i_ino,
				lock->fl.fl_pid,
				(long long)lock->fl.fl_start,
				(long long)lock->fl.fl_end);

	if (locks_in_grace(net))
		return nlm_lck_denied_grace_period;

	mutex_lock(&file->f_mutex);
	block = nlmsvc_lookup_block(file, lock);
	mutex_unlock(&file->f_mutex);
	if (block != NULL) {
		vfs_cancel_lock(block->b_file->f_file,
				&block->b_call->a_args.lock.fl);
		status = nlmsvc_unlink_block(block);
		nlmsvc_release_block(block);
	}
	return status ? nlm_lck_denied : nlm_granted;
}

/*
 * This is a callback from the filesystem for VFS file lock requests.
 * It will be used if lm_grant is defined and the filesystem can not
 * respond to the request immediately.
 * For GETLK request it will copy the reply to the nlm_block.
 * For SETLK or SETLKW request it will get the local posix lock.
 * In all cases it will move the block to the head of nlm_blocked q where
 * nlmsvc_retry_blocked() can send back a reply for SETLKW or revisit the
 * deferred rpc for GETLK and SETLK.
 */
static void
nlmsvc_update_deferred_block(struct nlm_block *block, struct file_lock *conf,
			     int result)
{
	block->b_flags |= B_GOT_CALLBACK;
	if (result == 0)
		block->b_granted = 1;
	else
		block->b_flags |= B_TIMED_OUT;
	if (conf) {
		if (block->b_fl)
			__locks_copy_lock(block->b_fl, conf);
	}
}

static int nlmsvc_grant_deferred(struct file_lock *fl, struct file_lock *conf,
					int result)
{
	struct nlm_block *block;
	int rc = -ENOENT;

	spin_lock(&nlm_blocked_lock);
	list_for_each_entry(block, &nlm_blocked, b_list) {
		if (nlm_compare_locks(&block->b_call->a_args.lock.fl, fl)) {
			dprintk("lockd: nlmsvc_notify_blocked block %p flags %d\n",
							block, block->b_flags);
			if (block->b_flags & B_QUEUED) {
				if (block->b_flags & B_TIMED_OUT) {
					rc = -ENOLCK;
					break;
				}
				nlmsvc_update_deferred_block(block, conf, result);
			} else if (result == 0)
				block->b_granted = 1;

			nlmsvc_insert_block_locked(block, 0);
			svc_wake_up(block->b_daemon);
			rc = 0;
			break;
		}
	}
	spin_unlock(&nlm_blocked_lock);
	if (rc == -ENOENT)
		printk(KERN_WARNING "lockd: grant for unknown block\n");
	return rc;
}

/*
 * Unblock a blocked lock request. This is a callback invoked from the
 * VFS layer when a lock on which we blocked is removed.
 *
 * This function doesn't grant the blocked lock instantly, but rather moves
 * the block to the head of nlm_blocked where it can be picked up by lockd.
 */
static void
nlmsvc_notify_blocked(struct file_lock *fl)
{
	struct nlm_block	*block;

	dprintk("lockd: VFS unblock notification for block %p\n", fl);
	spin_lock(&nlm_blocked_lock);
	list_for_each_entry(block, &nlm_blocked, b_list) {
		if (nlm_compare_locks(&block->b_call->a_args.lock.fl, fl)) {
			nlmsvc_insert_block_locked(block, 0);
			spin_unlock(&nlm_blocked_lock);
			svc_wake_up(block->b_daemon);
			return;
		}
	}
	spin_unlock(&nlm_blocked_lock);
	printk(KERN_WARNING "lockd: notification for unknown block!\n");
}

static int nlmsvc_same_owner(struct file_lock *fl1, struct file_lock *fl2)
{
	return fl1->fl_owner == fl2->fl_owner && fl1->fl_pid == fl2->fl_pid;
}

/*
 * Since NLM uses two "keys" for tracking locks, we need to hash them down
 * to one for the blocked_hash. Here, we're just xor'ing the host address
 * with the pid in order to create a key value for picking a hash bucket.
 */
static unsigned long
nlmsvc_owner_key(struct file_lock *fl)
{
	return (unsigned long)fl->fl_owner ^ (unsigned long)fl->fl_pid;
}

const struct lock_manager_operations nlmsvc_lock_operations = {
	.lm_compare_owner = nlmsvc_same_owner,
	.lm_owner_key = nlmsvc_owner_key,
	.lm_notify = nlmsvc_notify_blocked,
	.lm_grant = nlmsvc_grant_deferred,
};

/*
 * Try to claim a lock that was previously blocked.
 *
 * Note that we use both the RPC_GRANTED_MSG call _and_ an async
 * RPC thread when notifying the client. This seems like overkill...
 * Here's why:
 *  -	we don't want to use a synchronous RPC thread, otherwise
 *	we might find ourselves hanging on a dead portmapper.
 *  -	Some lockd implementations (e.g. HP) don't react to
 *	RPC_GRANTED calls; they seem to insist on RPC_GRANTED_MSG calls.
 */
static void
nlmsvc_grant_blocked(struct nlm_block *block)
{
	struct nlm_file		*file = block->b_file;
	struct nlm_lock		*lock = &block->b_call->a_args.lock;
	int			error;
	loff_t			fl_start, fl_end;

	dprintk("lockd: grant blocked lock %p\n", block);

	kref_get(&block->b_count);

	/* Unlink block request from list */
	nlmsvc_unlink_block(block);

	/* If b_granted is true this means we've been here before.
	 * Just retry the grant callback, possibly refreshing the RPC
	 * binding */
	if (block->b_granted) {
		nlm_rebind_host(block->b_host);
		goto callback;
	}

	/* Try the lock operation again */
	/* vfs_lock_file() can mangle fl_start and fl_end, but we need
	 * them unchanged for the GRANT_MSG
	 */
	lock->fl.fl_flags |= FL_SLEEP;
	fl_start = lock->fl.fl_start;
	fl_end = lock->fl.fl_end;
	error = vfs_lock_file(file->f_file, F_SETLK, &lock->fl, NULL);
	lock->fl.fl_flags &= ~FL_SLEEP;
	lock->fl.fl_start = fl_start;
	lock->fl.fl_end = fl_end;

	switch (error) {
	case 0:
		break;
	case FILE_LOCK_DEFERRED:
		dprintk("lockd: lock still blocked error %d\n", error);
		nlmsvc_insert_block(block, NLM_NEVER);
		nlmsvc_release_block(block);
		return;
	default:
		printk(KERN_WARNING "lockd: unexpected error %d in %s!\n",
				-error, __func__);
		nlmsvc_insert_block(block, 10 * HZ);
		nlmsvc_release_block(block);
		return;
	}

callback:
	/* Lock was granted by VFS. */
	dprintk("lockd: GRANTing blocked lock.\n");
	block->b_granted = 1;

	/* keep block on the list, but don't reattempt until the RPC
	 * completes or the submission fails
	 */
	nlmsvc_insert_block(block, NLM_NEVER);

	/* Call the client -- use a soft RPC task since nlmsvc_retry_blocked
	 * will queue up a new one if this one times out
	 */
	error = nlm_async_call(block->b_call, NLMPROC_GRANTED_MSG,
				&nlmsvc_grant_ops);

	/* RPC submission failed, wait a bit and retry */
	if (error < 0)
		nlmsvc_insert_block(block, 10 * HZ);
}

/*
 * This is the callback from the RPC layer when the NLM_GRANTED_MSG
 * RPC call has succeeded or timed out.
 * Like all RPC callbacks, it is invoked by the rpciod process, so it
 * better not sleep. Therefore, we put the blocked lock on the nlm_blocked
 * chain once more in order to have it removed by lockd itself (which can
 * then sleep on the file semaphore without disrupting e.g. the nfs client).
 */
static void nlmsvc_grant_callback(struct rpc_task *task, void *data)
{
	struct nlm_rqst		*call = data;
	struct nlm_block	*block = call->a_block;
	unsigned long		timeout;

	dprintk("lockd: GRANT_MSG RPC callback\n");

	spin_lock(&nlm_blocked_lock);
	/* if the block is not on a list at this point then it has
	 * been invalidated. Don't try to requeue it.
	 *
	 * FIXME: it's possible that the block is removed from the list
	 * after this check but before the nlmsvc_insert_block. In that
	 * case it will be added back. Perhaps we need better locking
	 * for nlm_blocked?
	 */
	if (list_empty(&block->b_list))
		goto out;

	/* Technically, we should down the file semaphore here. Since we
	 * move the block towards the head of the queue only, no harm
	 * can be done, though. */
	if (task->tk_status < 0) {
		/* RPC error: Re-insert for retransmission */
		timeout = 10 * HZ;
	} else {
		/* Call was successful, now wait for client callback */
		timeout = 60 * HZ;
	}
	nlmsvc_insert_block_locked(block, timeout);
	svc_wake_up(block->b_daemon);
out:
	spin_unlock(&nlm_blocked_lock);
}

/*
 * FIXME: nlmsvc_release_block() grabs a mutex.  This is not allowed for an
 * .rpc_release rpc_call_op
 */
static void nlmsvc_grant_release(void *data)
{
	struct nlm_rqst		*call = data;
	nlmsvc_release_block(call->a_block);
}

static const struct rpc_call_ops nlmsvc_grant_ops = {
	.rpc_call_done = nlmsvc_grant_callback,
	.rpc_release = nlmsvc_grant_release,
};

/*
 * We received a GRANT_RES callback. Try to find the corresponding
 * block.
 */
void
nlmsvc_grant_reply(struct nlm_cookie *cookie, __be32 status)
{
	struct nlm_block	*block;

	dprintk("grant_reply: looking for cookie %x, s=%d \n",
		*(unsigned int *)(cookie->data), status);
	if (!(block = nlmsvc_find_block(cookie)))
		return;

	if (block) {
		if (status == nlm_lck_denied_grace_period) {
			/* Try again in a couple of seconds */
			nlmsvc_insert_block(block, 10 * HZ);
		} else {
			/* Lock is now held by client, or has been rejected.
			 * In both cases, the block should be removed. */
			nlmsvc_unlink_block(block);
		}
	}
	nlmsvc_release_block(block);
}

/* Helper function to handle retry of a deferred block.
 * If it is a blocking lock, call grant_blocked.
 * For a non-blocking lock or test lock, revisit the request.
 */
static void
retry_deferred_block(struct nlm_block *block)
{
	if (!(block->b_flags & B_GOT_CALLBACK))
		block->b_flags |= B_TIMED_OUT;
	nlmsvc_insert_block(block, NLM_TIMEOUT);
	dprintk("revisit block %p flags %d\n",	block, block->b_flags);
	if (block->b_deferred_req) {
		block->b_deferred_req->revisit(block->b_deferred_req, 0);
		block->b_deferred_req = NULL;
	}
}

/*
 * Retry all blocked locks that have been notified. This is where lockd
 * picks up locks that can be granted, or grant notifications that must
 * be retransmitted.
 */
unsigned long
nlmsvc_retry_blocked(void)
{
	unsigned long	timeout = MAX_SCHEDULE_TIMEOUT;
	struct nlm_block *block;

	spin_lock(&nlm_blocked_lock);
	while (!list_empty(&nlm_blocked) && !kthread_should_stop()) {
		block = list_entry(nlm_blocked.next, struct nlm_block, b_list);

		if (block->b_when == NLM_NEVER)
			break;
		if (time_after(block->b_when, jiffies)) {
			timeout = block->b_when - jiffies;
			break;
		}
		spin_unlock(&nlm_blocked_lock);

		dprintk("nlmsvc_retry_blocked(%p, when=%ld)\n",
			block, block->b_when);
		if (block->b_flags & B_QUEUED) {
			dprintk("nlmsvc_retry_blocked delete block (%p, granted=%d, flags=%d)\n",
				block, block->b_granted, block->b_flags);
			retry_deferred_block(block);
		} else
			nlmsvc_grant_blocked(block);
		spin_lock(&nlm_blocked_lock);
	}
	spin_unlock(&nlm_blocked_lock);

	return timeout;
}
/************************************************************/
/* ../linux-3.17/fs/lockd/svcshare.c */
/************************************************************/
/*
 * linux/fs/lockd/svcshare.c
 *
 * Management of DOS shares.
 *
 * Copyright (C) 1996 Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/time.h>
#include <linux/unistd.h>
#include <linux/string.h>
// #include <linux/slab.h>

// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/svc.h>
// #include <linux/lockd/lockd.h>
#include <linux/lockd/share.h>

static inline int
nlm_cmp_owner(struct nlm_share *share, struct xdr_netobj *oh)
{
	return share->s_owner.len == oh->len
	    && !memcmp(share->s_owner.data, oh->data, oh->len);
}

__be32
nlmsvc_share_file(struct nlm_host *host, struct nlm_file *file,
			struct nlm_args *argp)
{
	struct nlm_share	*share;
	struct xdr_netobj	*oh = &argp->lock.oh;
	u8			*ohdata;

	for (share = file->f_shares; share; share = share->s_next) {
		if (share->s_host == host && nlm_cmp_owner(share, oh))
			goto update;
		if ((argp->fsm_access & share->s_mode)
		 || (argp->fsm_mode   & share->s_access ))
			return nlm_lck_denied;
	}

	share = kmalloc(sizeof(*share) + oh->len,
						GFP_KERNEL);
	if (share == NULL)
		return nlm_lck_denied_nolocks;

	/* Copy owner handle */
	ohdata = (u8 *) (share + 1);
	memcpy(ohdata, oh->data, oh->len);

	share->s_file	    = file;
	share->s_host       = host;
	share->s_owner.data = ohdata;
	share->s_owner.len  = oh->len;
	share->s_next       = file->f_shares;
	file->f_shares      = share;

update:
	share->s_access = argp->fsm_access;
	share->s_mode   = argp->fsm_mode;
	return nlm_granted;
}

/*
 * Delete a share.
 */
__be32
nlmsvc_unshare_file(struct nlm_host *host, struct nlm_file *file,
			struct nlm_args *argp)
{
	struct nlm_share	*share, **shpp;
	struct xdr_netobj	*oh = &argp->lock.oh;

	for (shpp = &file->f_shares; (share = *shpp) != NULL;
					shpp = &share->s_next) {
		if (share->s_host == host && nlm_cmp_owner(share, oh)) {
			*shpp = share->s_next;
			kfree(share);
			return nlm_granted;
		}
	}

	/* X/Open spec says return success even if there was no
	 * corresponding share. */
	return nlm_granted;
}

/*
 * Traverse all shares for a given file, and delete
 * those owned by the given (type of) host
 */
void nlmsvc_traverse_shares(struct nlm_host *host, struct nlm_file *file,
		nlm_host_match_fn_t match)
{
	struct nlm_share	*share, **shpp;

	shpp = &file->f_shares;
	while ((share = *shpp) !=  NULL) {
		if (match(share->s_host, host)) {
			*shpp = share->s_next;
			kfree(share);
			continue;
		}
		shpp = &share->s_next;
	}
}
/************************************************************/
/* ../linux-3.17/fs/lockd/svcproc.c */
/************************************************************/
/*
 * linux/fs/lockd/svcproc.c
 *
 * Lockd server procedures. We don't implement the NLM_*_RES
 * procedures because we don't use the async procedures.
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/types.h>
// #include <linux/time.h>
// #include <linux/lockd/lockd.h>
// #include <linux/lockd/share.h>
// #include <linux/sunrpc/svc_xprt.h>

#define NLMDBG_FACILITY		NLMDBG_CLIENT

#ifdef CONFIG_LOCKD_V4
static __be32
cast_to_nlm(__be32 status, u32 vers)
{
	/* Note: status is assumed to be in network byte order !!! */
	if (vers != 4){
		switch (status) {
		case nlm_granted:
		case nlm_lck_denied:
		case nlm_lck_denied_nolocks:
		case nlm_lck_blocked:
		case nlm_lck_denied_grace_period:
		case nlm_drop_reply:
			break;
		case nlm4_deadlock:
			status = nlm_lck_denied;
			break;
		default:
			status = nlm_lck_denied_nolocks;
		}
	}

	return (status);
}
#define	cast_status(status) (cast_to_nlm(status, rqstp->rq_vers))
#else
#define cast_status(status) (status)
#endif

/*
 * Obtain client and file from arguments
 */
static __be32
nlmsvc_retrieve_args(struct svc_rqst *rqstp, struct nlm_args *argp,
			struct nlm_host **hostp, struct nlm_file **filp)
{
	struct nlm_host		*host = NULL;
	struct nlm_file		*file = NULL;
	struct nlm_lock		*lock = &argp->lock;
	__be32			error = 0;

	/* nfsd callbacks must have been installed for this procedure */
	if (!nlmsvc_ops)
		return nlm_lck_denied_nolocks;

	/* Obtain host handle */
	if (!(host = nlmsvc_lookup_host(rqstp, lock->caller, lock->len))
	 || (argp->monitor && nsm_monitor(host) < 0))
		goto no_locks;
	*hostp = host;

	/* Obtain file pointer. Not used by FREE_ALL call. */
	if (filp != NULL) {
		error = cast_status(nlm_lookup_file(rqstp, &file, &lock->fh));
		if (error != 0)
			goto no_locks;
		*filp = file;

		/* Set up the missing parts of the file_lock structure */
		lock->fl.fl_file  = file->f_file;
		lock->fl.fl_owner = (fl_owner_t) host;
		lock->fl.fl_lmops = &nlmsvc_lock_operations;
	}

	return 0;

no_locks:
	nlmsvc_release_host(host);
	if (error)
		return error;
	return nlm_lck_denied_nolocks;
}

/*
 * NULL: Test for presence of service
 */
static __be32
nlmsvc_proc_null(struct svc_rqst *rqstp, void *argp, void *resp)
{
	dprintk("lockd: NULL          called\n");
	return rpc_success;
}

/*
 * TEST: Check for conflicting lock
 */
static __be32
nlmsvc_proc_test(struct svc_rqst *rqstp, struct nlm_args *argp,
				         struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;
	__be32 rc = rpc_success;

	dprintk("lockd: TEST          called\n");
	resp->cookie = argp->cookie;

	/* Obtain client and file */
	if ((resp->status = nlmsvc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Now check for conflicting locks */
	resp->status = cast_status(nlmsvc_testlock(rqstp, file, host, &argp->lock, &resp->lock, &resp->cookie));
	if (resp->status == nlm_drop_reply)
		rc = rpc_drop_reply;
	else
		dprintk("lockd: TEST          status %d vers %d\n",
			ntohl(resp->status), rqstp->rq_vers);

	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rc;
}

static __be32
nlmsvc_proc_lock(struct svc_rqst *rqstp, struct nlm_args *argp,
				         struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;
	__be32 rc = rpc_success;

	dprintk("lockd: LOCK          called\n");

	resp->cookie = argp->cookie;

	/* Obtain client and file */
	if ((resp->status = nlmsvc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

#if 0
	/* If supplied state doesn't match current state, we assume it's
	 * an old request that time-warped somehow. Any error return would
	 * do in this case because it's irrelevant anyway.
	 *
	 * NB: We don't retrieve the remote host's state yet.
	 */
	if (host->h_nsmstate && host->h_nsmstate != argp->state) {
		resp->status = nlm_lck_denied_nolocks;
	} else
#endif

	/* Now try to lock the file */
	resp->status = cast_status(nlmsvc_lock(rqstp, file, host, &argp->lock,
					       argp->block, &argp->cookie,
					       argp->reclaim));
	if (resp->status == nlm_drop_reply)
		rc = rpc_drop_reply;
	else
		dprintk("lockd: LOCK         status %d\n", ntohl(resp->status));

	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rc;
}

static __be32
nlmsvc_proc_cancel(struct svc_rqst *rqstp, struct nlm_args *argp,
				           struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;
	struct net *net = SVC_NET(rqstp);

	dprintk("lockd: CANCEL        called\n");

	resp->cookie = argp->cookie;

	/* Don't accept requests during grace period */
	if (locks_in_grace(net)) {
		resp->status = nlm_lck_denied_grace_period;
		return rpc_success;
	}

	/* Obtain client and file */
	if ((resp->status = nlmsvc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Try to cancel request. */
	resp->status = cast_status(nlmsvc_cancel_blocked(net, file, &argp->lock));

	dprintk("lockd: CANCEL        status %d\n", ntohl(resp->status));
	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rpc_success;
}

/*
 * UNLOCK: release a lock
 */
static __be32
nlmsvc_proc_unlock(struct svc_rqst *rqstp, struct nlm_args *argp,
				           struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;
	struct net *net = SVC_NET(rqstp);

	dprintk("lockd: UNLOCK        called\n");

	resp->cookie = argp->cookie;

	/* Don't accept new lock requests during grace period */
	if (locks_in_grace(net)) {
		resp->status = nlm_lck_denied_grace_period;
		return rpc_success;
	}

	/* Obtain client and file */
	if ((resp->status = nlmsvc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Now try to remove the lock */
	resp->status = cast_status(nlmsvc_unlock(net, file, &argp->lock));

	dprintk("lockd: UNLOCK        status %d\n", ntohl(resp->status));
	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rpc_success;
}

/*
 * GRANTED: A server calls us to tell that a process' lock request
 * was granted
 */
static __be32
nlmsvc_proc_granted(struct svc_rqst *rqstp, struct nlm_args *argp,
				            struct nlm_res  *resp)
{
	resp->cookie = argp->cookie;

	dprintk("lockd: GRANTED       called\n");
	resp->status = nlmclnt_grant(svc_addr(rqstp), &argp->lock);
	dprintk("lockd: GRANTED       status %d\n", ntohl(resp->status));
	return rpc_success;
}

/*
 * This is the generic lockd callback for async RPC calls
 */
static void nlmsvc_callback_exit(struct rpc_task *task, void *data)
{
	dprintk("lockd: %5u callback returned %d\n", task->tk_pid,
			-task->tk_status);
}

void nlmsvc_release_call(struct nlm_rqst *call)
{
	if (!atomic_dec_and_test(&call->a_count))
		return;
	nlmsvc_release_host(call->a_host);
	kfree(call);
}

static void nlmsvc_callback_release(void *data)
{
	nlmsvc_release_call(data);
}

static const struct rpc_call_ops nlmsvc_callback_ops = {
	.rpc_call_done = nlmsvc_callback_exit,
	.rpc_release = nlmsvc_callback_release,
};

/*
 * `Async' versions of the above service routines. They aren't really,
 * because we send the callback before the reply proper. I hope this
 * doesn't break any clients.
 */
static __be32 nlmsvc_callback(struct svc_rqst *rqstp, u32 proc, struct nlm_args *argp,
		__be32 (*func)(struct svc_rqst *, struct nlm_args *, struct nlm_res  *))
{
	struct nlm_host	*host;
	struct nlm_rqst	*call;
	__be32 stat;

	host = nlmsvc_lookup_host(rqstp,
				  argp->lock.caller,
				  argp->lock.len);
	if (host == NULL)
		return rpc_system_err;

	call = nlm_alloc_call(host);
	nlmsvc_release_host(host);
	if (call == NULL)
		return rpc_system_err;

	stat = func(rqstp, argp, &call->a_res);
	if (stat != 0) {
		nlmsvc_release_call(call);
		return stat;
	}

	call->a_flags = RPC_TASK_ASYNC;
	if (nlm_async_reply(call, proc, &nlmsvc_callback_ops) < 0)
		return rpc_system_err;
	return rpc_success;
}

static __be32 nlmsvc_proc_test_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
					     void	     *resp)
{
	dprintk("lockd: TEST_MSG      called\n");
	return nlmsvc_callback(rqstp, NLMPROC_TEST_RES, argp, nlmsvc_proc_test);
}

static __be32 nlmsvc_proc_lock_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
					     void	     *resp)
{
	dprintk("lockd: LOCK_MSG      called\n");
	return nlmsvc_callback(rqstp, NLMPROC_LOCK_RES, argp, nlmsvc_proc_lock);
}

static __be32 nlmsvc_proc_cancel_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
					       void	       *resp)
{
	dprintk("lockd: CANCEL_MSG    called\n");
	return nlmsvc_callback(rqstp, NLMPROC_CANCEL_RES, argp, nlmsvc_proc_cancel);
}

static __be32
nlmsvc_proc_unlock_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
                                               void            *resp)
{
	dprintk("lockd: UNLOCK_MSG    called\n");
	return nlmsvc_callback(rqstp, NLMPROC_UNLOCK_RES, argp, nlmsvc_proc_unlock);
}

static __be32
nlmsvc_proc_granted_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
                                                void            *resp)
{
	dprintk("lockd: GRANTED_MSG   called\n");
	return nlmsvc_callback(rqstp, NLMPROC_GRANTED_RES, argp, nlmsvc_proc_granted);
}

/*
 * SHARE: create a DOS share or alter existing share.
 */
static __be32
nlmsvc_proc_share(struct svc_rqst *rqstp, struct nlm_args *argp,
				          struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;

	dprintk("lockd: SHARE         called\n");

	resp->cookie = argp->cookie;

	/* Don't accept new lock requests during grace period */
	if (locks_in_grace(SVC_NET(rqstp)) && !argp->reclaim) {
		resp->status = nlm_lck_denied_grace_period;
		return rpc_success;
	}

	/* Obtain client and file */
	if ((resp->status = nlmsvc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Now try to create the share */
	resp->status = cast_status(nlmsvc_share_file(host, file, argp));

	dprintk("lockd: SHARE         status %d\n", ntohl(resp->status));
	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rpc_success;
}

/*
 * UNSHARE: Release a DOS share.
 */
static __be32
nlmsvc_proc_unshare(struct svc_rqst *rqstp, struct nlm_args *argp,
				            struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;

	dprintk("lockd: UNSHARE       called\n");

	resp->cookie = argp->cookie;

	/* Don't accept requests during grace period */
	if (locks_in_grace(SVC_NET(rqstp))) {
		resp->status = nlm_lck_denied_grace_period;
		return rpc_success;
	}

	/* Obtain client and file */
	if ((resp->status = nlmsvc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Now try to unshare the file */
	resp->status = cast_status(nlmsvc_unshare_file(host, file, argp));

	dprintk("lockd: UNSHARE       status %d\n", ntohl(resp->status));
	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rpc_success;
}

/*
 * NM_LOCK: Create an unmonitored lock
 */
static __be32
nlmsvc_proc_nm_lock(struct svc_rqst *rqstp, struct nlm_args *argp,
				            struct nlm_res  *resp)
{
	dprintk("lockd: NM_LOCK       called\n");

	argp->monitor = 0;		/* just clean the monitor flag */
	return nlmsvc_proc_lock(rqstp, argp, resp);
}

/*
 * FREE_ALL: Release all locks and shares held by client
 */
static __be32
nlmsvc_proc_free_all(struct svc_rqst *rqstp, struct nlm_args *argp,
					     void            *resp)
{
	struct nlm_host	*host;

	/* Obtain client */
	if (nlmsvc_retrieve_args(rqstp, argp, &host, NULL))
		return rpc_success;

	nlmsvc_free_host_resources(host);
	nlmsvc_release_host(host);
	return rpc_success;
}

/*
 * SM_NOTIFY: private callback from statd (not part of official NLM proto)
 */
static __be32
nlmsvc_proc_sm_notify(struct svc_rqst *rqstp, struct nlm_reboot *argp,
					      void	        *resp)
{
	dprintk("lockd: SM_NOTIFY     called\n");

	if (!nlm_privileged_requester(rqstp)) {
		char buf[RPC_MAX_ADDRBUFLEN];
		printk(KERN_WARNING "lockd: rejected NSM callback from %s\n",
				svc_print_addr(rqstp, buf, sizeof(buf)));
		return rpc_system_err;
	}

	nlm_host_rebooted(argp);
	return rpc_success;
}

/*
 * client sent a GRANTED_RES, let's remove the associated block
 */
static __be32
nlmsvc_proc_granted_res(struct svc_rqst *rqstp, struct nlm_res  *argp,
                                                void            *resp)
{
	if (!nlmsvc_ops)
		return rpc_success;

	dprintk("lockd: GRANTED_RES   called\n");

	nlmsvc_grant_reply(&argp->cookie, argp->status);
	return rpc_success;
}

/*
 * NLM Server procedures.
 */

#define nlmsvc_encode_norep	nlmsvc_encode_void
#define nlmsvc_decode_norep	nlmsvc_decode_void
#define nlmsvc_decode_testres	nlmsvc_decode_void
#define nlmsvc_decode_lockres	nlmsvc_decode_void
#define nlmsvc_decode_unlockres	nlmsvc_decode_void
#define nlmsvc_decode_cancelres	nlmsvc_decode_void
#define nlmsvc_decode_grantedres	nlmsvc_decode_void

#define nlmsvc_proc_none	nlmsvc_proc_null
#define nlmsvc_proc_test_res	nlmsvc_proc_null
#define nlmsvc_proc_lock_res	nlmsvc_proc_null
#define nlmsvc_proc_cancel_res	nlmsvc_proc_null
#define nlmsvc_proc_unlock_res	nlmsvc_proc_null

struct nlm_void_svcproc_c			{ int dummy; };

#define PROC(name, xargt, xrest, argt, rest, respsize)	\
 { .pc_func	= (svc_procfunc) nlmsvc_proc_##name,	\
   .pc_decode	= (kxdrproc_t) nlmsvc_decode_##xargt,	\
   .pc_encode	= (kxdrproc_t) nlmsvc_encode_##xrest,	\
   .pc_release	= NULL,					\
   .pc_argsize	= sizeof(struct nlm_##argt),		\
   .pc_ressize	= sizeof(struct nlm_##rest),		\
   .pc_xdrressize = respsize,				\
 }

#define	Ck	(1+XDR_QUADLEN(NLM_MAXCOOKIELEN))	/* cookie */
#define	St	1				/* status */
#define	No	(1+1024/4)			/* Net Obj */
#define	Rg	2				/* range - offset + size */

struct svc_procedure		nlmsvc_procedures[] = {
  PROC(null,		void,		void,		void,	void, 1),
  PROC(test,		testargs,	testres,	args,	res, Ck+St+2+No+Rg),
  PROC(lock,		lockargs,	res,		args,	res, Ck+St),
  PROC(cancel,		cancargs,	res,		args,	res, Ck+St),
  PROC(unlock,		unlockargs,	res,		args,	res, Ck+St),
  PROC(granted,		testargs,	res,		args,	res, Ck+St),
  PROC(test_msg,	testargs,	norep,		args,	void, 1),
  PROC(lock_msg,	lockargs,	norep,		args,	void, 1),
  PROC(cancel_msg,	cancargs,	norep,		args,	void, 1),
  PROC(unlock_msg,	unlockargs,	norep,		args,	void, 1),
  PROC(granted_msg,	testargs,	norep,		args,	void, 1),
  PROC(test_res,	testres,	norep,		res,	void, 1),
  PROC(lock_res,	lockres,	norep,		res,	void, 1),
  PROC(cancel_res,	cancelres,	norep,		res,	void, 1),
  PROC(unlock_res,	unlockres,	norep,		res,	void, 1),
  PROC(granted_res,	res,		norep,		res,	void, 1),
  /* statd callback */
  PROC(sm_notify,	reboot,		void,		reboot,	void, 1),
  PROC(none,		void,		void,		void,	void, 1),
  PROC(none,		void,		void,		void,	void, 1),
  PROC(none,		void,		void,		void,	void, 1),
  PROC(share,		shareargs,	shareres,	args,	res, Ck+St+1),
  PROC(unshare,		shareargs,	shareres,	args,	res, Ck+St+1),
  PROC(nm_lock,		lockargs,	res,		args,	res, Ck+St),
  PROC(free_all,	notify,		void,		args,	void, 0),

};
/************************************************************/
/* ../linux-3.17/fs/lockd/svcsubs.c */
/************************************************************/
/*
 * linux/fs/lockd/svcsubs.c
 *
 * Various support routines for the NLM server.
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/types.h>
// #include <linux/string.h>
// #include <linux/time.h>
// #include <linux/in.h>
// #include <linux/slab.h>
// #include <linux/mutex.h>
// #include <linux/sunrpc/svc.h>
// #include <linux/sunrpc/addr.h>
// #include <linux/lockd/lockd.h>
// #include <linux/lockd/share.h>
// #include <linux/module.h>
#include <linux/mount.h>
// #include <uapi/linux/nfs2.h>

#define NLMDBG_FACILITY		NLMDBG_SVCSUBS


/*
 * Global file hash table
 */
#define FILE_HASH_BITS		7
#define FILE_NRHASH		(1<<FILE_HASH_BITS)
static struct hlist_head	nlm_files[FILE_NRHASH];
static DEFINE_MUTEX(nlm_file_mutex);

#ifdef NFSD_DEBUG
static inline void nlm_debug_print_fh(char *msg, struct nfs_fh *f)
{
	u32 *fhp = (u32*)f->data;

	/* print the first 32 bytes of the fh */
	dprintk("lockd: %s (%08x %08x %08x %08x %08x %08x %08x %08x)\n",
		msg, fhp[0], fhp[1], fhp[2], fhp[3],
		fhp[4], fhp[5], fhp[6], fhp[7]);
}

static inline void nlm_debug_print_file(char *msg, struct nlm_file *file)
{
	struct inode *inode = file_inode(file->f_file);

	dprintk("lockd: %s %s/%ld\n",
		msg, inode->i_sb->s_id, inode->i_ino);
}
#else
static inline void nlm_debug_print_fh(char *msg, struct nfs_fh *f)
{
	return;
}

static inline void nlm_debug_print_file(char *msg, struct nlm_file *file)
{
	return;
}
#endif

static inline unsigned int file_hash(struct nfs_fh *f)
{
	unsigned int tmp=0;
	int i;
	for (i=0; i<NFS2_FHSIZE;i++)
		tmp += f->data[i];
	return tmp & (FILE_NRHASH - 1);
}

/*
 * Lookup file info. If it doesn't exist, create a file info struct
 * and open a (VFS) file for the given inode.
 *
 * FIXME:
 * Note that we open the file O_RDONLY even when creating write locks.
 * This is not quite right, but for now, we assume the client performs
 * the proper R/W checking.
 */
__be32
nlm_lookup_file(struct svc_rqst *rqstp, struct nlm_file **result,
					struct nfs_fh *f)
{
	struct nlm_file	*file;
	unsigned int	hash;
	__be32		nfserr;

	nlm_debug_print_fh("nlm_lookup_file", f);

	hash = file_hash(f);

	/* Lock file table */
	mutex_lock(&nlm_file_mutex);

	hlist_for_each_entry(file, &nlm_files[hash], f_list)
		if (!nfs_compare_fh(&file->f_handle, f))
			goto found;

	nlm_debug_print_fh("creating file for", f);

	nfserr = nlm_lck_denied_nolocks;
	file = kzalloc(sizeof(*file), GFP_KERNEL);
	if (!file)
		goto out_unlock;

	memcpy(&file->f_handle, f, sizeof(struct nfs_fh));
	mutex_init(&file->f_mutex);
	INIT_HLIST_NODE(&file->f_list);
	INIT_LIST_HEAD(&file->f_blocks);

	/* Open the file. Note that this must not sleep for too long, else
	 * we would lock up lockd:-) So no NFS re-exports, folks.
	 *
	 * We have to make sure we have the right credential to open
	 * the file.
	 */
	if ((nfserr = nlmsvc_ops->fopen(rqstp, f, &file->f_file)) != 0) {
		dprintk("lockd: open failed (error %d)\n", nfserr);
		goto out_free;
	}

	hlist_add_head(&file->f_list, &nlm_files[hash]);

found:
	dprintk("lockd: found file %p (count %d)\n", file, file->f_count);
	*result = file;
	file->f_count++;
	nfserr = 0;

out_unlock:
	mutex_unlock(&nlm_file_mutex);
	return nfserr;

out_free:
	kfree(file);
	goto out_unlock;
}

/*
 * Delete a file after having released all locks, blocks and shares
 */
static inline void
nlm_delete_file(struct nlm_file *file)
{
	nlm_debug_print_file("closing file", file);
	if (!hlist_unhashed(&file->f_list)) {
		hlist_del(&file->f_list);
		nlmsvc_ops->fclose(file->f_file);
		kfree(file);
	} else {
		printk(KERN_WARNING "lockd: attempt to release unknown file!\n");
	}
}

/*
 * Loop over all locks on the given file and perform the specified
 * action.
 */
static int
nlm_traverse_locks(struct nlm_host *host, struct nlm_file *file,
			nlm_host_match_fn_t match)
{
	struct inode	 *inode = nlmsvc_file_inode(file);
	struct file_lock *fl;
	struct nlm_host	 *lockhost;

again:
	file->f_locks = 0;
	spin_lock(&inode->i_lock);
	for (fl = inode->i_flock; fl; fl = fl->fl_next) {
		if (fl->fl_lmops != &nlmsvc_lock_operations)
			continue;

		/* update current lock count */
		file->f_locks++;

		lockhost = (struct nlm_host *) fl->fl_owner;
		if (match(lockhost, host)) {
			struct file_lock lock = *fl;

			spin_unlock(&inode->i_lock);
			lock.fl_type  = F_UNLCK;
			lock.fl_start = 0;
			lock.fl_end   = OFFSET_MAX;
			if (vfs_lock_file(file->f_file, F_SETLK, &lock, NULL) < 0) {
				printk("lockd: unlock failure in %s:%d\n",
						__FILE__, __LINE__);
				return 1;
			}
			goto again;
		}
	}
	spin_unlock(&inode->i_lock);

	return 0;
}

static int
nlmsvc_always_match(void *dummy1, struct nlm_host *dummy2)
{
	return 1;
}

/*
 * Inspect a single file
 */
static inline int
nlm_inspect_file(struct nlm_host *host, struct nlm_file *file, nlm_host_match_fn_t match)
{
	nlmsvc_traverse_blocks(host, file, match);
	nlmsvc_traverse_shares(host, file, match);
	return nlm_traverse_locks(host, file, match);
}

/*
 * Quick check whether there are still any locks, blocks or
 * shares on a given file.
 */
static inline int
nlm_file_inuse(struct nlm_file *file)
{
	struct inode	 *inode = nlmsvc_file_inode(file);
	struct file_lock *fl;

	if (file->f_count || !list_empty(&file->f_blocks) || file->f_shares)
		return 1;

	spin_lock(&inode->i_lock);
	for (fl = inode->i_flock; fl; fl = fl->fl_next) {
		if (fl->fl_lmops == &nlmsvc_lock_operations) {
			spin_unlock(&inode->i_lock);
			return 1;
		}
	}
	spin_unlock(&inode->i_lock);
	file->f_locks = 0;
	return 0;
}

/*
 * Loop over all files in the file table.
 */
static int
nlm_traverse_files(void *data, nlm_host_match_fn_t match,
		int (*is_failover_file)(void *data, struct nlm_file *file))
{
	struct hlist_node *next;
	struct nlm_file	*file;
	int i, ret = 0;

	mutex_lock(&nlm_file_mutex);
	for (i = 0; i < FILE_NRHASH; i++) {
		hlist_for_each_entry_safe(file, next, &nlm_files[i], f_list) {
			if (is_failover_file && !is_failover_file(data, file))
				continue;
			file->f_count++;
			mutex_unlock(&nlm_file_mutex);

			/* Traverse locks, blocks and shares of this file
			 * and update file->f_locks count */
			if (nlm_inspect_file(data, file, match))
				ret = 1;

			mutex_lock(&nlm_file_mutex);
			file->f_count--;
			/* No more references to this file. Let go of it. */
			if (list_empty(&file->f_blocks) && !file->f_locks
			 && !file->f_shares && !file->f_count) {
				hlist_del(&file->f_list);
				nlmsvc_ops->fclose(file->f_file);
				kfree(file);
			}
		}
	}
	mutex_unlock(&nlm_file_mutex);
	return ret;
}

/*
 * Release file. If there are no more remote locks on this file,
 * close it and free the handle.
 *
 * Note that we can't do proper reference counting without major
 * contortions because the code in fs/locks.c creates, deletes and
 * splits locks without notification. Our only way is to walk the
 * entire lock list each time we remove a lock.
 */
void
nlm_release_file(struct nlm_file *file)
{
	dprintk("lockd: nlm_release_file(%p, ct = %d)\n",
				file, file->f_count);

	/* Lock file table */
	mutex_lock(&nlm_file_mutex);

	/* If there are no more locks etc, delete the file */
	if (--file->f_count == 0 && !nlm_file_inuse(file))
		nlm_delete_file(file);

	mutex_unlock(&nlm_file_mutex);
}

/*
 * Helpers function for resource traversal
 *
 * nlmsvc_mark_host:
 *	used by the garbage collector; simply sets h_inuse only for those
 *	hosts, which passed network check.
 *	Always returns 0.
 *
 * nlmsvc_same_host:
 *	returns 1 iff the two hosts match. Used to release
 *	all resources bound to a specific host.
 *
 * nlmsvc_is_client:
 *	returns 1 iff the host is a client.
 *	Used by nlmsvc_invalidate_all
 */

static int
nlmsvc_mark_host(void *data, struct nlm_host *hint)
{
	struct nlm_host *host = data;

	if ((hint->net == NULL) ||
	    (host->net == hint->net))
		host->h_inuse = 1;
	return 0;
}

static int
nlmsvc_same_host(void *data, struct nlm_host *other)
{
	struct nlm_host *host = data;

	return host == other;
}

static int
nlmsvc_is_client(void *data, struct nlm_host *dummy)
{
	struct nlm_host *host = data;

	if (host->h_server) {
		/* we are destroying locks even though the client
		 * hasn't asked us too, so don't unmonitor the
		 * client
		 */
		if (host->h_nsmhandle)
			host->h_nsmhandle->sm_sticky = 1;
		return 1;
	} else
		return 0;
}

/*
 * Mark all hosts that still hold resources
 */
void
nlmsvc_mark_resources(struct net *net)
{
	struct nlm_host hint;

	dprintk("lockd: nlmsvc_mark_resources for net %p\n", net);
	hint.net = net;
	nlm_traverse_files(&hint, nlmsvc_mark_host, NULL);
}

/*
 * Release all resources held by the given client
 */
void
nlmsvc_free_host_resources(struct nlm_host *host)
{
	dprintk("lockd: nlmsvc_free_host_resources\n");

	if (nlm_traverse_files(host, nlmsvc_same_host, NULL)) {
		printk(KERN_WARNING
			"lockd: couldn't remove all locks held by %s\n",
			host->h_name);
		BUG();
	}
}

/**
 * nlmsvc_invalidate_all - remove all locks held for clients
 *
 * Release all locks held by NFS clients.
 *
 */
void
nlmsvc_invalidate_all(void)
{
	/*
	 * Previously, the code would call
	 * nlmsvc_free_host_resources for each client in
	 * turn, which is about as inefficient as it gets.
	 * Now we just do it once in nlm_traverse_files.
	 */
	nlm_traverse_files(NULL, nlmsvc_is_client, NULL);
}

static int
nlmsvc_match_sb(void *datap, struct nlm_file *file)
{
	struct super_block *sb = datap;

	return sb == file->f_file->f_path.dentry->d_sb;
}

/**
 * nlmsvc_unlock_all_by_sb - release locks held on this file system
 * @sb: super block
 *
 * Release all locks held by clients accessing this file system.
 */
int
nlmsvc_unlock_all_by_sb(struct super_block *sb)
{
	int ret;

	ret = nlm_traverse_files(sb, nlmsvc_always_match, nlmsvc_match_sb);
	return ret ? -EIO : 0;
}
EXPORT_SYMBOL_GPL(nlmsvc_unlock_all_by_sb);

static int
nlmsvc_match_ip(void *datap, struct nlm_host *host)
{
	return rpc_cmp_addr(nlm_srcaddr(host), datap);
}

/**
 * nlmsvc_unlock_all_by_ip - release local locks by IP address
 * @server_addr: server's IP address as seen by clients
 *
 * Release all locks held by clients accessing this host
 * via the passed in IP address.
 */
int
nlmsvc_unlock_all_by_ip(struct sockaddr *server_addr)
{
	int ret;

	ret = nlm_traverse_files(server_addr, nlmsvc_match_ip, NULL);
	return ret ? -EIO : 0;
}
EXPORT_SYMBOL_GPL(nlmsvc_unlock_all_by_ip);
/************************************************************/
/* ../linux-3.17/fs/lockd/mon.c */
/************************************************************/
/*
 * linux/fs/lockd/mon.c
 *
 * The kernel statd client.
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/types.h>
// #include <linux/kernel.h>
#include <linux/ktime.h>
// #include <linux/slab.h>

// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/addr.h>
#include <linux/sunrpc/xprtsock.h>
// #include <linux/sunrpc/svc.h>
// #include <linux/lockd/lockd.h>

#include <asm/unaligned.h>

// #include "netns.h"

#define NLMDBG_FACILITY		NLMDBG_MONITOR
#define NSM_PROGRAM		100024
#define NSM_VERSION		1

enum {
	NSMPROC_NULL,
	NSMPROC_STAT,
	NSMPROC_MON,
	NSMPROC_UNMON,
	NSMPROC_UNMON_ALL,
	NSMPROC_SIMU_CRASH,
	NSMPROC_NOTIFY,
};

struct nsm_args {
	struct nsm_private	*priv;
	u32			prog;		/* RPC callback info */
	u32			vers;
	u32			proc;

	char			*mon_name;
	char			*nodename;
};

struct nsm_res {
	u32			status;
	u32			state;
};

static const struct rpc_program	nsm_program;
static				LIST_HEAD(nsm_handles);
static				DEFINE_SPINLOCK(nsm_lock);

/*
 * Local NSM state
 */
u32	__read_mostly		nsm_local_state;
bool	__read_mostly		nsm_use_hostnames;

static inline struct sockaddr *nsm_addr(const struct nsm_handle *nsm)
{
	return (struct sockaddr *)&nsm->sm_addr;
}

static struct rpc_clnt *nsm_create(struct net *net)
{
	struct sockaddr_in sin = {
		.sin_family		= AF_INET,
		.sin_addr.s_addr	= htonl(INADDR_LOOPBACK),
	};
	struct rpc_create_args args = {
		.net			= net,
		.protocol		= XPRT_TRANSPORT_TCP,
		.address		= (struct sockaddr *)&sin,
		.addrsize		= sizeof(sin),
		.servername		= "rpc.statd",
		.program		= &nsm_program,
		.version		= NSM_VERSION,
		.authflavor		= RPC_AUTH_NULL,
		.flags			= RPC_CLNT_CREATE_NOPING,
	};

	return rpc_create(&args);
}

static struct rpc_clnt *nsm_client_set(struct lockd_net *ln,
		struct rpc_clnt *clnt)
{
	spin_lock(&ln->nsm_clnt_lock);
	if (ln->nsm_users == 0) {
		if (clnt == NULL)
			goto out;
		ln->nsm_clnt = clnt;
	}
	clnt = ln->nsm_clnt;
	ln->nsm_users++;
out:
	spin_unlock(&ln->nsm_clnt_lock);
	return clnt;
}

static struct rpc_clnt *nsm_client_get(struct net *net)
{
	struct rpc_clnt	*clnt, *new;
	struct lockd_net *ln = net_generic(net, lockd_net_id);

	clnt = nsm_client_set(ln, NULL);
	if (clnt != NULL)
		goto out;

	clnt = new = nsm_create(net);
	if (IS_ERR(clnt))
		goto out;

	clnt = nsm_client_set(ln, new);
	if (clnt != new)
		rpc_shutdown_client(new);
out:
	return clnt;
}

static void nsm_client_put(struct net *net)
{
	struct lockd_net *ln = net_generic(net, lockd_net_id);
	struct rpc_clnt	*clnt = NULL;

	spin_lock(&ln->nsm_clnt_lock);
	ln->nsm_users--;
	if (ln->nsm_users == 0) {
		clnt = ln->nsm_clnt;
		ln->nsm_clnt = NULL;
	}
	spin_unlock(&ln->nsm_clnt_lock);
	if (clnt != NULL)
		rpc_shutdown_client(clnt);
}

static int nsm_mon_unmon(struct nsm_handle *nsm, u32 proc, struct nsm_res *res,
			 struct rpc_clnt *clnt)
{
	int		status;
	struct nsm_args args = {
		.priv		= &nsm->sm_priv,
		.prog		= NLM_PROGRAM,
		.vers		= 3,
		.proc		= NLMPROC_NSM_NOTIFY,
		.mon_name	= nsm->sm_mon_name,
		.nodename	= clnt->cl_nodename,
	};
	struct rpc_message msg = {
		.rpc_argp	= &args,
		.rpc_resp	= res,
	};

	memset(res, 0, sizeof(*res));

	msg.rpc_proc = &clnt->cl_procinfo[proc];
	status = rpc_call_sync(clnt, &msg, RPC_TASK_SOFTCONN);
	if (status < 0)
		dprintk("lockd: NSM upcall RPC failed, status=%d\n",
				status);
	else
		status = 0;
	return status;
}

/**
 * nsm_monitor - Notify a peer in case we reboot
 * @host: pointer to nlm_host of peer to notify
 *
 * If this peer is not already monitored, this function sends an
 * upcall to the local rpc.statd to record the name/address of
 * the peer to notify in case we reboot.
 *
 * Returns zero if the peer is monitored by the local rpc.statd;
 * otherwise a negative errno value is returned.
 */
int nsm_monitor(const struct nlm_host *host)
{
	struct nsm_handle *nsm = host->h_nsmhandle;
	struct nsm_res	res;
	int		status;
	struct rpc_clnt *clnt;

	dprintk("lockd: nsm_monitor(%s)\n", nsm->sm_name);

	if (nsm->sm_monitored)
		return 0;

	/*
	 * Choose whether to record the caller_name or IP address of
	 * this peer in the local rpc.statd's database.
	 */
	nsm->sm_mon_name = nsm_use_hostnames ? nsm->sm_name : nsm->sm_addrbuf;

	clnt = nsm_client_get(host->net);
	if (IS_ERR(clnt)) {
		status = PTR_ERR(clnt);
		dprintk("lockd: failed to create NSM upcall transport, "
				"status=%d, net=%p\n", status, host->net);
		return status;
	}

	status = nsm_mon_unmon(nsm, NSMPROC_MON, &res, clnt);
	if (unlikely(res.status != 0))
		status = -EIO;
	if (unlikely(status < 0)) {
		printk(KERN_NOTICE "lockd: cannot monitor %s\n", nsm->sm_name);
		return status;
	}

	nsm->sm_monitored = 1;
	if (unlikely(nsm_local_state != res.state)) {
		nsm_local_state = res.state;
		dprintk("lockd: NSM state changed to %d\n", nsm_local_state);
	}
	return 0;
}

/**
 * nsm_unmonitor - Unregister peer notification
 * @host: pointer to nlm_host of peer to stop monitoring
 *
 * If this peer is monitored, this function sends an upcall to
 * tell the local rpc.statd not to send this peer a notification
 * when we reboot.
 */
void nsm_unmonitor(const struct nlm_host *host)
{
	struct nsm_handle *nsm = host->h_nsmhandle;
	struct nsm_res	res;
	int status;

	if (atomic_read(&nsm->sm_count) == 1
	 && nsm->sm_monitored && !nsm->sm_sticky) {
		struct lockd_net *ln = net_generic(host->net, lockd_net_id);

		dprintk("lockd: nsm_unmonitor(%s)\n", nsm->sm_name);

		status = nsm_mon_unmon(nsm, NSMPROC_UNMON, &res, ln->nsm_clnt);
		if (res.status != 0)
			status = -EIO;
		if (status < 0)
			printk(KERN_NOTICE "lockd: cannot unmonitor %s\n",
					nsm->sm_name);
		else
			nsm->sm_monitored = 0;

		nsm_client_put(host->net);
	}
}

static struct nsm_handle *nsm_lookup_hostname(const char *hostname,
					      const size_t len)
{
	struct nsm_handle *nsm;

	list_for_each_entry(nsm, &nsm_handles, sm_link)
		if (strlen(nsm->sm_name) == len &&
		    memcmp(nsm->sm_name, hostname, len) == 0)
			return nsm;
	return NULL;
}

static struct nsm_handle *nsm_lookup_addr(const struct sockaddr *sap)
{
	struct nsm_handle *nsm;

	list_for_each_entry(nsm, &nsm_handles, sm_link)
		if (rpc_cmp_addr(nsm_addr(nsm), sap))
			return nsm;
	return NULL;
}

static struct nsm_handle *nsm_lookup_priv(const struct nsm_private *priv)
{
	struct nsm_handle *nsm;

	list_for_each_entry(nsm, &nsm_handles, sm_link)
		if (memcmp(nsm->sm_priv.data, priv->data,
					sizeof(priv->data)) == 0)
			return nsm;
	return NULL;
}

/*
 * Construct a unique cookie to match this nsm_handle to this monitored
 * host.  It is passed to the local rpc.statd via NSMPROC_MON, and
 * returned via NLMPROC_SM_NOTIFY, in the "priv" field of these
 * requests.
 *
 * The NSM protocol requires that these cookies be unique while the
 * system is running.  We prefer a stronger requirement of making them
 * unique across reboots.  If user space bugs cause a stale cookie to
 * be sent to the kernel, it could cause the wrong host to lose its
 * lock state if cookies were not unique across reboots.
 *
 * The cookies are exposed only to local user space via loopback.  They
 * do not appear on the physical network.  If we want greater security
 * for some reason, nsm_init_private() could perform a one-way hash to
 * obscure the contents of the cookie.
 */
static void nsm_init_private(struct nsm_handle *nsm)
{
	u64 *p = (u64 *)&nsm->sm_priv.data;
	s64 ns;

	ns = ktime_get_ns();
	put_unaligned(ns, p);
	put_unaligned((unsigned long)nsm, p + 1);
}

static struct nsm_handle *nsm_create_handle(const struct sockaddr *sap,
					    const size_t salen,
					    const char *hostname,
					    const size_t hostname_len)
{
	struct nsm_handle *new;

	new = kzalloc(sizeof(*new) + hostname_len + 1, GFP_KERNEL);
	if (unlikely(new == NULL))
		return NULL;

	atomic_set(&new->sm_count, 1);
	new->sm_name = (char *)(new + 1);
	memcpy(nsm_addr(new), sap, salen);
	new->sm_addrlen = salen;
	nsm_init_private(new);

	if (rpc_ntop(nsm_addr(new), new->sm_addrbuf,
					sizeof(new->sm_addrbuf)) == 0)
		(void)snprintf(new->sm_addrbuf, sizeof(new->sm_addrbuf),
				"unsupported address family");
	memcpy(new->sm_name, hostname, hostname_len);
	new->sm_name[hostname_len] = '\0';

	return new;
}

/**
 * nsm_get_handle - Find or create a cached nsm_handle
 * @sap: pointer to socket address of handle to find
 * @salen: length of socket address
 * @hostname: pointer to C string containing hostname to find
 * @hostname_len: length of C string
 *
 * Behavior is modulated by the global nsm_use_hostnames variable.
 *
 * Returns a cached nsm_handle after bumping its ref count, or
 * returns a fresh nsm_handle if a handle that matches @sap and/or
 * @hostname cannot be found in the handle cache.  Returns NULL if
 * an error occurs.
 */
struct nsm_handle *nsm_get_handle(const struct sockaddr *sap,
				  const size_t salen, const char *hostname,
				  const size_t hostname_len)
{
	struct nsm_handle *cached, *new = NULL;

	if (hostname && memchr(hostname, '/', hostname_len) != NULL) {
		if (printk_ratelimit()) {
			printk(KERN_WARNING "Invalid hostname \"%.*s\" "
					    "in NFS lock request\n",
				(int)hostname_len, hostname);
		}
		return NULL;
	}

retry:
	spin_lock(&nsm_lock);

	if (nsm_use_hostnames && hostname != NULL)
		cached = nsm_lookup_hostname(hostname, hostname_len);
	else
		cached = nsm_lookup_addr(sap);

	if (cached != NULL) {
		atomic_inc(&cached->sm_count);
		spin_unlock(&nsm_lock);
		kfree(new);
		dprintk("lockd: found nsm_handle for %s (%s), "
				"cnt %d\n", cached->sm_name,
				cached->sm_addrbuf,
				atomic_read(&cached->sm_count));
		return cached;
	}

	if (new != NULL) {
		list_add(&new->sm_link, &nsm_handles);
		spin_unlock(&nsm_lock);
		dprintk("lockd: created nsm_handle for %s (%s)\n",
				new->sm_name, new->sm_addrbuf);
		return new;
	}

	spin_unlock(&nsm_lock);

	new = nsm_create_handle(sap, salen, hostname, hostname_len);
	if (unlikely(new == NULL))
		return NULL;
	goto retry;
}

/**
 * nsm_reboot_lookup - match NLMPROC_SM_NOTIFY arguments to an nsm_handle
 * @info: pointer to NLMPROC_SM_NOTIFY arguments
 *
 * Returns a matching nsm_handle if found in the nsm cache. The returned
 * nsm_handle's reference count is bumped. Otherwise returns NULL if some
 * error occurred.
 */
struct nsm_handle *nsm_reboot_lookup(const struct nlm_reboot *info)
{
	struct nsm_handle *cached;

	spin_lock(&nsm_lock);

	cached = nsm_lookup_priv(&info->priv);
	if (unlikely(cached == NULL)) {
		spin_unlock(&nsm_lock);
		dprintk("lockd: never saw rebooted peer '%.*s' before\n",
				info->len, info->mon);
		return cached;
	}

	atomic_inc(&cached->sm_count);
	spin_unlock(&nsm_lock);

	dprintk("lockd: host %s (%s) rebooted, cnt %d\n",
			cached->sm_name, cached->sm_addrbuf,
			atomic_read(&cached->sm_count));
	return cached;
}

/**
 * nsm_release - Release an NSM handle
 * @nsm: pointer to handle to be released
 *
 */
void nsm_release(struct nsm_handle *nsm)
{
	if (atomic_dec_and_lock(&nsm->sm_count, &nsm_lock)) {
		list_del(&nsm->sm_link);
		spin_unlock(&nsm_lock);
		dprintk("lockd: destroyed nsm_handle for %s (%s)\n",
				nsm->sm_name, nsm->sm_addrbuf);
		kfree(nsm);
	}
}

/*
 * XDR functions for NSM.
 *
 * See http://www.opengroup.org/ for details on the Network
 * Status Monitor wire protocol.
 */

static void encode_nsm_string(struct xdr_stream *xdr, const char *string)
{
	const u32 len = strlen(string);
	__be32 *p;

	p = xdr_reserve_space(xdr, 4 + len);
	xdr_encode_opaque(p, string, len);
}

/*
 * "mon_name" specifies the host to be monitored.
 */
static void encode_mon_name(struct xdr_stream *xdr, const struct nsm_args *argp)
{
	encode_nsm_string(xdr, argp->mon_name);
}

/*
 * The "my_id" argument specifies the hostname and RPC procedure
 * to be called when the status manager receives notification
 * (via the NLMPROC_SM_NOTIFY call) that the state of host "mon_name"
 * has changed.
 */
static void encode_my_id(struct xdr_stream *xdr, const struct nsm_args *argp)
{
	__be32 *p;

	encode_nsm_string(xdr, argp->nodename);
	p = xdr_reserve_space(xdr, 4 + 4 + 4);
	*p++ = cpu_to_be32(argp->prog);
	*p++ = cpu_to_be32(argp->vers);
	*p = cpu_to_be32(argp->proc);
}

/*
 * The "mon_id" argument specifies the non-private arguments
 * of an NSMPROC_MON or NSMPROC_UNMON call.
 */
static void encode_mon_id(struct xdr_stream *xdr, const struct nsm_args *argp)
{
	encode_mon_name(xdr, argp);
	encode_my_id(xdr, argp);
}

/*
 * The "priv" argument may contain private information required
 * by the NSMPROC_MON call. This information will be supplied in the
 * NLMPROC_SM_NOTIFY call.
 */
static void encode_priv(struct xdr_stream *xdr, const struct nsm_args *argp)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, SM_PRIV_SIZE);
	xdr_encode_opaque_fixed(p, argp->priv->data, SM_PRIV_SIZE);
}

static void nsm_xdr_enc_mon(struct rpc_rqst *req, struct xdr_stream *xdr,
			    const struct nsm_args *argp)
{
	encode_mon_id(xdr, argp);
	encode_priv(xdr, argp);
}

static void nsm_xdr_enc_unmon(struct rpc_rqst *req, struct xdr_stream *xdr,
			      const struct nsm_args *argp)
{
	encode_mon_id(xdr, argp);
}

static int nsm_xdr_dec_stat_res(struct rpc_rqst *rqstp,
				struct xdr_stream *xdr,
				struct nsm_res *resp)
{
	__be32 *p;

	p = xdr_inline_decode(xdr, 4 + 4);
	if (unlikely(p == NULL))
		return -EIO;
	resp->status = be32_to_cpup(p++);
	resp->state = be32_to_cpup(p);

	dprintk("lockd: %s status %d state %d\n",
		__func__, resp->status, resp->state);
	return 0;
}

static int nsm_xdr_dec_stat(struct rpc_rqst *rqstp,
			    struct xdr_stream *xdr,
			    struct nsm_res *resp)
{
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		return -EIO;
	resp->state = be32_to_cpup(p);

	dprintk("lockd: %s state %d\n", __func__, resp->state);
	return 0;
}

#define SM_my_name_sz	(1+XDR_QUADLEN(SM_MAXSTRLEN))
#define SM_my_id_sz	(SM_my_name_sz+3)
#define SM_mon_name_sz	(1+XDR_QUADLEN(SM_MAXSTRLEN))
#define SM_mon_id_sz	(SM_mon_name_sz+SM_my_id_sz)
#define SM_priv_sz	(XDR_QUADLEN(SM_PRIV_SIZE))
#define SM_mon_sz	(SM_mon_id_sz+SM_priv_sz)
#define SM_monres_sz	2
#define SM_unmonres_sz	1

static struct rpc_procinfo	nsm_procedures[] = {
[NSMPROC_MON] = {
		.p_proc		= NSMPROC_MON,
		.p_encode	= (kxdreproc_t)nsm_xdr_enc_mon,
		.p_decode	= (kxdrdproc_t)nsm_xdr_dec_stat_res,
		.p_arglen	= SM_mon_sz,
		.p_replen	= SM_monres_sz,
		.p_statidx	= NSMPROC_MON,
		.p_name		= "MONITOR",
	},
[NSMPROC_UNMON] = {
		.p_proc		= NSMPROC_UNMON,
		.p_encode	= (kxdreproc_t)nsm_xdr_enc_unmon,
		.p_decode	= (kxdrdproc_t)nsm_xdr_dec_stat,
		.p_arglen	= SM_mon_id_sz,
		.p_replen	= SM_unmonres_sz,
		.p_statidx	= NSMPROC_UNMON,
		.p_name		= "UNMONITOR",
	},
};

static const struct rpc_version nsm_version1 = {
		.number		= 1,
		.nrprocs	= ARRAY_SIZE(nsm_procedures),
		.procs		= nsm_procedures
};

static const struct rpc_version *nsm_version[] = {
	[1] = &nsm_version1,
};

static struct rpc_stat		nsm_stats;

static const struct rpc_program nsm_program = {
		.name		= "statd",
		.number		= NSM_PROGRAM,
		.nrvers		= ARRAY_SIZE(nsm_version),
		.version	= nsm_version,
		.stats		= &nsm_stats
};
/************************************************************/
/* ../linux-3.17/fs/lockd/xdr.c */
/************************************************************/
/*
 * linux/fs/lockd/xdr.c
 *
 * XDR support for lockd and the lock client.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/types.h>
// #include <linux/sched.h>
// #include <linux/nfs.h>

// #include <linux/sunrpc/xdr.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/svc.h>
// #include <linux/sunrpc/stats.h>
// #include <linux/lockd/lockd.h>

// #include <uapi/linux/nfs2.h>

#define NLMDBG_FACILITY		NLMDBG_XDR


static inline loff_t
s32_to_loff_t(__s32 offset)
{
	return (loff_t)offset;
}

static inline __s32
loff_t_to_s32_xdr_c(loff_t offset)
{
	__s32 res;
	if (offset >= NLM_OFFSET_MAX)
		res = NLM_OFFSET_MAX;
	else if (offset <= -NLM_OFFSET_MAX)
		res = -NLM_OFFSET_MAX;
	else
		res = offset;
	return res;
}

/*
 * XDR functions for basic NLM types
 */
static __be32 *nlm_decode_cookie(__be32 *p, struct nlm_cookie *c)
{
	unsigned int	len;

	len = ntohl(*p++);

	if(len==0)
	{
		c->len=4;
		memset(c->data, 0, 4);	/* hockeypux brain damage */
	}
	else if(len<=NLM_MAXCOOKIELEN)
	{
		c->len=len;
		memcpy(c->data, p, len);
		p+=XDR_QUADLEN(len);
	}
	else
	{
		dprintk("lockd: bad cookie size %d (only cookies under "
			"%d bytes are supported.)\n",
				len, NLM_MAXCOOKIELEN);
		return NULL;
	}
	return p;
}

static inline __be32 *
nlm_encode_cookie(__be32 *p, struct nlm_cookie *c)
{
	*p++ = htonl(c->len);
	memcpy(p, c->data, c->len);
	p+=XDR_QUADLEN(c->len);
	return p;
}

static __be32 *
nlm_decode_fh(__be32 *p, struct nfs_fh *f)
{
	unsigned int	len;

	if ((len = ntohl(*p++)) != NFS2_FHSIZE) {
		dprintk("lockd: bad fhandle size %d (should be %d)\n",
			len, NFS2_FHSIZE);
		return NULL;
	}
	f->size = NFS2_FHSIZE;
	memset(f->data, 0, sizeof(f->data));
	memcpy(f->data, p, NFS2_FHSIZE);
	return p + XDR_QUADLEN(NFS2_FHSIZE);
}

static inline __be32 *
nlm_encode_fh(__be32 *p, struct nfs_fh *f)
{
	*p++ = htonl(NFS2_FHSIZE);
	memcpy(p, f->data, NFS2_FHSIZE);
	return p + XDR_QUADLEN(NFS2_FHSIZE);
}

/*
 * Encode and decode owner handle
 */
static inline __be32 *
nlm_decode_oh(__be32 *p, struct xdr_netobj *oh)
{
	return xdr_decode_netobj(p, oh);
}

static inline __be32 *
nlm_encode_oh(__be32 *p, struct xdr_netobj *oh)
{
	return xdr_encode_netobj(p, oh);
}

static __be32 *
nlm_decode_lock(__be32 *p, struct nlm_lock *lock)
{
	struct file_lock	*fl = &lock->fl;
	s32			start, len, end;

	if (!(p = xdr_decode_string_inplace(p, &lock->caller,
					    &lock->len,
					    NLM_MAXSTRLEN))
	 || !(p = nlm_decode_fh(p, &lock->fh))
	 || !(p = nlm_decode_oh(p, &lock->oh)))
		return NULL;
	lock->svid  = ntohl(*p++);

	locks_init_lock(fl);
	fl->fl_owner = current->files;
	fl->fl_pid   = (pid_t)lock->svid;
	fl->fl_flags = FL_POSIX;
	fl->fl_type  = F_RDLCK;		/* as good as anything else */
	start = ntohl(*p++);
	len = ntohl(*p++);
	end = start + len - 1;

	fl->fl_start = s32_to_loff_t(start);

	if (len == 0 || end < 0)
		fl->fl_end = OFFSET_MAX;
	else
		fl->fl_end = s32_to_loff_t(end);
	return p;
}

/*
 * Encode result of a TEST/TEST_MSG call
 */
static __be32 *
nlm_encode_testres(__be32 *p, struct nlm_res *resp)
{
	s32		start, len;

	if (!(p = nlm_encode_cookie(p, &resp->cookie)))
		return NULL;
	*p++ = resp->status;

	if (resp->status == nlm_lck_denied) {
		struct file_lock	*fl = &resp->lock.fl;

		*p++ = (fl->fl_type == F_RDLCK)? xdr_zero : xdr_one;
		*p++ = htonl(resp->lock.svid);

		/* Encode owner handle. */
		if (!(p = xdr_encode_netobj(p, &resp->lock.oh)))
			return NULL;

		start = loff_t_to_s32_xdr_c(fl->fl_start);
		if (fl->fl_end == OFFSET_MAX)
			len = 0;
		else
			len = loff_t_to_s32_xdr_c(fl->fl_end - fl->fl_start + 1);

		*p++ = htonl(start);
		*p++ = htonl(len);
	}

	return p;
}


/*
 * First, the server side XDR functions
 */
int
nlmsvc_decode_testargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	u32	exclusive;

	if (!(p = nlm_decode_cookie(p, &argp->cookie)))
		return 0;

	exclusive = ntohl(*p++);
	if (!(p = nlm_decode_lock(p, &argp->lock)))
		return 0;
	if (exclusive)
		argp->lock.fl.fl_type = F_WRLCK;

	return xdr_argsize_check(rqstp, p);
}

int
nlmsvc_encode_testres(struct svc_rqst *rqstp, __be32 *p, struct nlm_res *resp)
{
	if (!(p = nlm_encode_testres(p, resp)))
		return 0;
	return xdr_ressize_check(rqstp, p);
}

int
nlmsvc_decode_lockargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	u32	exclusive;

	if (!(p = nlm_decode_cookie(p, &argp->cookie)))
		return 0;
	argp->block  = ntohl(*p++);
	exclusive    = ntohl(*p++);
	if (!(p = nlm_decode_lock(p, &argp->lock)))
		return 0;
	if (exclusive)
		argp->lock.fl.fl_type = F_WRLCK;
	argp->reclaim = ntohl(*p++);
	argp->state   = ntohl(*p++);
	argp->monitor = 1;		/* monitor client by default */

	return xdr_argsize_check(rqstp, p);
}

int
nlmsvc_decode_cancargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	u32	exclusive;

	if (!(p = nlm_decode_cookie(p, &argp->cookie)))
		return 0;
	argp->block = ntohl(*p++);
	exclusive = ntohl(*p++);
	if (!(p = nlm_decode_lock(p, &argp->lock)))
		return 0;
	if (exclusive)
		argp->lock.fl.fl_type = F_WRLCK;
	return xdr_argsize_check(rqstp, p);
}

int
nlmsvc_decode_unlockargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	if (!(p = nlm_decode_cookie(p, &argp->cookie))
	 || !(p = nlm_decode_lock(p, &argp->lock)))
		return 0;
	argp->lock.fl.fl_type = F_UNLCK;
	return xdr_argsize_check(rqstp, p);
}

int
nlmsvc_decode_shareargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	struct nlm_lock	*lock = &argp->lock;

	memset(lock, 0, sizeof(*lock));
	locks_init_lock(&lock->fl);
	lock->svid = ~(u32) 0;
	lock->fl.fl_pid = (pid_t)lock->svid;

	if (!(p = nlm_decode_cookie(p, &argp->cookie))
	 || !(p = xdr_decode_string_inplace(p, &lock->caller,
					    &lock->len, NLM_MAXSTRLEN))
	 || !(p = nlm_decode_fh(p, &lock->fh))
	 || !(p = nlm_decode_oh(p, &lock->oh)))
		return 0;
	argp->fsm_mode = ntohl(*p++);
	argp->fsm_access = ntohl(*p++);
	return xdr_argsize_check(rqstp, p);
}

int
nlmsvc_encode_shareres(struct svc_rqst *rqstp, __be32 *p, struct nlm_res *resp)
{
	if (!(p = nlm_encode_cookie(p, &resp->cookie)))
		return 0;
	*p++ = resp->status;
	*p++ = xdr_zero;		/* sequence argument */
	return xdr_ressize_check(rqstp, p);
}

int
nlmsvc_encode_res(struct svc_rqst *rqstp, __be32 *p, struct nlm_res *resp)
{
	if (!(p = nlm_encode_cookie(p, &resp->cookie)))
		return 0;
	*p++ = resp->status;
	return xdr_ressize_check(rqstp, p);
}

int
nlmsvc_decode_notify(struct svc_rqst *rqstp, __be32 *p, struct nlm_args *argp)
{
	struct nlm_lock	*lock = &argp->lock;

	if (!(p = xdr_decode_string_inplace(p, &lock->caller,
					    &lock->len, NLM_MAXSTRLEN)))
		return 0;
	argp->state = ntohl(*p++);
	return xdr_argsize_check(rqstp, p);
}

int
nlmsvc_decode_reboot(struct svc_rqst *rqstp, __be32 *p, struct nlm_reboot *argp)
{
	if (!(p = xdr_decode_string_inplace(p, &argp->mon, &argp->len, SM_MAXSTRLEN)))
		return 0;
	argp->state = ntohl(*p++);
	memcpy(&argp->priv.data, p, sizeof(argp->priv.data));
	p += XDR_QUADLEN(SM_PRIV_SIZE);
	return xdr_argsize_check(rqstp, p);
}

int
nlmsvc_decode_res(struct svc_rqst *rqstp, __be32 *p, struct nlm_res *resp)
{
	if (!(p = nlm_decode_cookie(p, &resp->cookie)))
		return 0;
	resp->status = *p++;
	return xdr_argsize_check(rqstp, p);
}

int
nlmsvc_decode_void(struct svc_rqst *rqstp, __be32 *p, void *dummy)
{
	return xdr_argsize_check(rqstp, p);
}

int
nlmsvc_encode_void(struct svc_rqst *rqstp, __be32 *p, void *dummy)
{
	return xdr_ressize_check(rqstp, p);
}
/************************************************************/
/* ../linux-3.17/fs/lockd/grace.c */
/************************************************************/
/*
 * Common code for control of lockd and nfsv4 grace periods.
 */

// #include <linux/module.h>
#include <linux/lockd/bind.h>
#include <net/net_namespace.h>

// #include "netns.h"

static DEFINE_SPINLOCK(grace_lock);

/**
 * locks_start_grace
 * @lm: who this grace period is for
 *
 * A grace period is a period during which locks should not be given
 * out.  Currently grace periods are only enforced by the two lock
 * managers (lockd and nfsd), using the locks_in_grace() function to
 * check when they are in a grace period.
 *
 * This function is called to start a grace period.
 */
void locks_start_grace(struct net *net, struct lock_manager *lm)
{
	struct lockd_net *ln = net_generic(net, lockd_net_id);

	spin_lock(&grace_lock);
	list_add(&lm->list, &ln->grace_list);
	spin_unlock(&grace_lock);
}
EXPORT_SYMBOL_GPL(locks_start_grace);

/**
 * locks_end_grace
 * @lm: who this grace period is for
 *
 * Call this function to state that the given lock manager is ready to
 * resume regular locking.  The grace period will not end until all lock
 * managers that called locks_start_grace() also call locks_end_grace().
 * Note that callers count on it being safe to call this more than once,
 * and the second call should be a no-op.
 */
void locks_end_grace(struct lock_manager *lm)
{
	spin_lock(&grace_lock);
	list_del_init(&lm->list);
	spin_unlock(&grace_lock);
}
EXPORT_SYMBOL_GPL(locks_end_grace);

/**
 * locks_in_grace
 *
 * Lock managers call this function to determine when it is OK for them
 * to answer ordinary lock requests, and when they should accept only
 * lock reclaims.
 */
int locks_in_grace(struct net *net)
{
	struct lockd_net *ln = net_generic(net, lockd_net_id);

	return !list_empty(&ln->grace_list);
}
EXPORT_SYMBOL_GPL(locks_in_grace);
/************************************************************/
/* ../linux-3.17/fs/lockd/clnt4xdr.c */
/************************************************************/
/*
 * linux/fs/lockd/clnt4xdr.c
 *
 * XDR functions to encode/decode NLM version 4 RPC arguments and results.
 *
 * NLM client-side only.
 *
 * Copyright (C) 2010, Oracle.  All rights reserved.
 */

// #include <linux/types.h>
// #include <linux/sunrpc/xdr.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/stats.h>
// #include <linux/lockd/lockd.h>

#include <uapi/linux/nfs3.h>

#define NLMDBG_FACILITY		NLMDBG_XDR

#if (NLMCLNT_OHSIZE > XDR_MAX_NETOBJ)
#  error "NLM host name cannot be larger than XDR_MAX_NETOBJ!"
#endif

#if (NLMCLNT_OHSIZE > NLM_MAXSTRLEN)
#  error "NLM host name cannot be larger than NLM's maximum string length!"
#endif

/*
 * Declare the space requirements for NLM arguments and replies as
 * number of 32bit-words
 */
#define NLM4_void_sz		(0)
#define NLM4_cookie_sz		(1+(NLM_MAXCOOKIELEN>>2))
#define NLM4_caller_sz		(1+(NLMCLNT_OHSIZE>>2))
#define NLM4_owner_sz		(1+(NLMCLNT_OHSIZE>>2))
#define NLM4_fhandle_sz		(1+(NFS3_FHSIZE>>2))
#define NLM4_lock_sz		(5+NLM4_caller_sz+NLM4_owner_sz+NLM4_fhandle_sz)
#define NLM4_holder_sz		(6+NLM4_owner_sz)

#define NLM4_testargs_sz	(NLM4_cookie_sz+1+NLM4_lock_sz)
#define NLM4_lockargs_sz	(NLM4_cookie_sz+4+NLM4_lock_sz)
#define NLM4_cancargs_sz	(NLM4_cookie_sz+2+NLM4_lock_sz)
#define NLM4_unlockargs_sz	(NLM4_cookie_sz+NLM4_lock_sz)

#define NLM4_testres_sz		(NLM4_cookie_sz+1+NLM4_holder_sz)
#define NLM4_res_sz		(NLM4_cookie_sz+1)
#define NLM4_norep_sz		(0)


static s64 loff_t_to_s64(loff_t offset)
{
	s64 res;

	if (offset >= NLM4_OFFSET_MAX)
		res = NLM4_OFFSET_MAX;
	else if (offset <= -NLM4_OFFSET_MAX)
		res = -NLM4_OFFSET_MAX;
	else
		res = offset;
	return res;
}

static void nlm4_compute_offsets(const struct nlm_lock *lock,
				 u64 *l_offset, u64 *l_len)
{
	const struct file_lock *fl = &lock->fl;

	*l_offset = loff_t_to_s64(fl->fl_start);
	if (fl->fl_end == OFFSET_MAX)
		*l_len = 0;
	else
		*l_len = loff_t_to_s64(fl->fl_end - fl->fl_start + 1);
}

/*
 * Handle decode buffer overflows out-of-line.
 */
static void print_overflow_msg_clnt4xdr_c(const char *func, const struct xdr_stream *xdr)
{
	dprintk("lockd: %s prematurely hit the end of our receive buffer. "
		"Remaining buffer length is %tu words.\n",
		func, xdr->end - xdr->p);
}


/*
 * Encode/decode NLMv4 basic data types
 *
 * Basic NLMv4 data types are defined in Appendix II, section 6.1.4
 * of RFC 1813: "NFS Version 3 Protocol Specification" and in Chapter
 * 10 of X/Open's "Protocols for Interworking: XNFS, Version 3W".
 *
 * Not all basic data types have their own encoding and decoding
 * functions.  For run-time efficiency, some data types are encoded
 * or decoded inline.
 */

static void encode_bool_clnt4xdr_c(struct xdr_stream *xdr, const int value)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 4);
	*p = value ? xdr_one : xdr_zero;
}

static void encode_int32_clnt4xdr_c(struct xdr_stream *xdr, const s32 value)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 4);
	*p = cpu_to_be32(value);
}

/*
 *	typedef opaque netobj<MAXNETOBJ_SZ>
 */
static void encode_netobj_clnt4xdr_c(struct xdr_stream *xdr,
			  const u8 *data, const unsigned int length)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 4 + length);
	xdr_encode_opaque(p, data, length);
}

static int decode_netobj_clnt4xdr_c(struct xdr_stream *xdr,
			 struct xdr_netobj *obj)
{
	u32 length;
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	length = be32_to_cpup(p++);
	if (unlikely(length > XDR_MAX_NETOBJ))
		goto out_size;
	obj->len = length;
	obj->data = (u8 *)p;
	return 0;
out_size:
	dprintk("NFS: returned netobj was too long: %u\n", length);
	return -EIO;
out_overflow:
	print_overflow_msg_clnt4xdr_c(__func__, xdr);
	return -EIO;
}

/*
 *	netobj cookie;
 */
static void encode_cookie_clnt4xdr_c(struct xdr_stream *xdr,
			  const struct nlm_cookie *cookie)
{
	encode_netobj_clnt4xdr_c(xdr, (u8 *)&cookie->data, cookie->len);
}

static int decode_cookie_clnt4xdr_c(struct xdr_stream *xdr,
			     struct nlm_cookie *cookie)
{
	u32 length;
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	length = be32_to_cpup(p++);
	/* apparently HPUX can return empty cookies */
	if (length == 0)
		goto out_hpux;
	if (length > NLM_MAXCOOKIELEN)
		goto out_size;
	p = xdr_inline_decode(xdr, length);
	if (unlikely(p == NULL))
		goto out_overflow;
	cookie->len = length;
	memcpy(cookie->data, p, length);
	return 0;
out_hpux:
	cookie->len = 4;
	memset(cookie->data, 0, 4);
	return 0;
out_size:
	dprintk("NFS: returned cookie was too long: %u\n", length);
	return -EIO;
out_overflow:
	print_overflow_msg_clnt4xdr_c(__func__, xdr);
	return -EIO;
}

/*
 *	netobj fh;
 */
static void encode_fh_clnt4xdr_c(struct xdr_stream *xdr, const struct nfs_fh *fh)
{
	encode_netobj_clnt4xdr_c(xdr, (u8 *)&fh->data, fh->size);
}

/*
 *	enum nlm4_stats {
 *		NLM4_GRANTED = 0,
 *		NLM4_DENIED = 1,
 *		NLM4_DENIED_NOLOCKS = 2,
 *		NLM4_BLOCKED = 3,
 *		NLM4_DENIED_GRACE_PERIOD = 4,
 *		NLM4_DEADLCK = 5,
 *		NLM4_ROFS = 6,
 *		NLM4_STALE_FH = 7,
 *		NLM4_FBIG = 8,
 *		NLM4_FAILED = 9
 *	};
 *
 *	struct nlm4_stat {
 *		nlm4_stats stat;
 *	};
 *
 * NB: we don't swap bytes for the NLM status values.  The upper
 * layers deal directly with the status value in network byte
 * order.
 */
static void encode_nlm4_stat(struct xdr_stream *xdr,
			     const __be32 stat)
{
	__be32 *p;

	BUG_ON(be32_to_cpu(stat) > NLM_FAILED);
	p = xdr_reserve_space(xdr, 4);
	*p = stat;
}

static int decode_nlm4_stat(struct xdr_stream *xdr, __be32 *stat)
{
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	if (unlikely(ntohl(*p) > ntohl(nlm4_failed)))
		goto out_bad_xdr;
	*stat = *p;
	return 0;
out_bad_xdr:
	dprintk("%s: server returned invalid nlm4_stats value: %u\n",
			__func__, be32_to_cpup(p));
	return -EIO;
out_overflow:
	print_overflow_msg_clnt4xdr_c(__func__, xdr);
	return -EIO;
}

/*
 *	struct nlm4_holder {
 *		bool	exclusive;
 *		int32	svid;
 *		netobj	oh;
 *		uint64	l_offset;
 *		uint64	l_len;
 *	};
 */
static void encode_nlm4_holder(struct xdr_stream *xdr,
			       const struct nlm_res *result)
{
	const struct nlm_lock *lock = &result->lock;
	u64 l_offset, l_len;
	__be32 *p;

	encode_bool_clnt4xdr_c(xdr, lock->fl.fl_type == F_RDLCK);
	encode_int32_clnt4xdr_c(xdr, lock->svid);
	encode_netobj_clnt4xdr_c(xdr, lock->oh.data, lock->oh.len);

	p = xdr_reserve_space(xdr, 4 + 4);
	nlm4_compute_offsets(lock, &l_offset, &l_len);
	p = xdr_encode_hyper(p, l_offset);
	xdr_encode_hyper(p, l_len);
}

static int decode_nlm4_holder(struct xdr_stream *xdr, struct nlm_res *result)
{
	struct nlm_lock *lock = &result->lock;
	struct file_lock *fl = &lock->fl;
	u64 l_offset, l_len;
	u32 exclusive;
	int error;
	__be32 *p;
	s32 end;

	memset(lock, 0, sizeof(*lock));
	locks_init_lock(fl);

	p = xdr_inline_decode(xdr, 4 + 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	exclusive = be32_to_cpup(p++);
	lock->svid = be32_to_cpup(p);
	fl->fl_pid = (pid_t)lock->svid;

	error = decode_netobj_clnt4xdr_c(xdr, &lock->oh);
	if (unlikely(error))
		goto out;

	p = xdr_inline_decode(xdr, 8 + 8);
	if (unlikely(p == NULL))
		goto out_overflow;

	fl->fl_flags = FL_POSIX;
	fl->fl_type  = exclusive != 0 ? F_WRLCK : F_RDLCK;
	p = xdr_decode_hyper(p, &l_offset);
	xdr_decode_hyper(p, &l_len);
	end = l_offset + l_len - 1;

	fl->fl_start = (loff_t)l_offset;
	if (l_len == 0 || end < 0)
		fl->fl_end = OFFSET_MAX;
	else
		fl->fl_end = (loff_t)end;
	error = 0;
out:
	return error;
out_overflow:
	print_overflow_msg_clnt4xdr_c(__func__, xdr);
	return -EIO;
}

/*
 *	string caller_name<LM_MAXSTRLEN>;
 */
static void encode_caller_name_clnt4xdr_c(struct xdr_stream *xdr, const char *name)
{
	/* NB: client-side does not set lock->len */
	u32 length = strlen(name);
	__be32 *p;

	p = xdr_reserve_space(xdr, 4 + length);
	xdr_encode_opaque(p, name, length);
}

/*
 *	struct nlm4_lock {
 *		string	caller_name<LM_MAXSTRLEN>;
 *		netobj	fh;
 *		netobj	oh;
 *		int32	svid;
 *		uint64	l_offset;
 *		uint64	l_len;
 *	};
 */
static void encode_nlm4_lock(struct xdr_stream *xdr,
			     const struct nlm_lock *lock)
{
	u64 l_offset, l_len;
	__be32 *p;

	encode_caller_name_clnt4xdr_c(xdr, lock->caller);
	encode_fh_clnt4xdr_c(xdr, &lock->fh);
	encode_netobj_clnt4xdr_c(xdr, lock->oh.data, lock->oh.len);

	p = xdr_reserve_space(xdr, 4 + 8 + 8);
	*p++ = cpu_to_be32(lock->svid);

	nlm4_compute_offsets(lock, &l_offset, &l_len);
	p = xdr_encode_hyper(p, l_offset);
	xdr_encode_hyper(p, l_len);
}


/*
 * NLMv4 XDR encode functions
 *
 * NLMv4 argument types are defined in Appendix II of RFC 1813:
 * "NFS Version 3 Protocol Specification" and Chapter 10 of X/Open's
 * "Protocols for Interworking: XNFS, Version 3W".
 */

/*
 *	struct nlm4_testargs {
 *		netobj cookie;
 *		bool exclusive;
 *		struct nlm4_lock alock;
 *	};
 */
static void nlm4_xdr_enc_testargs(struct rpc_rqst *req,
				  struct xdr_stream *xdr,
				  const struct nlm_args *args)
{
	const struct nlm_lock *lock = &args->lock;

	encode_cookie_clnt4xdr_c(xdr, &args->cookie);
	encode_bool_clnt4xdr_c(xdr, lock->fl.fl_type == F_WRLCK);
	encode_nlm4_lock(xdr, lock);
}

/*
 *	struct nlm4_lockargs {
 *		netobj cookie;
 *		bool block;
 *		bool exclusive;
 *		struct nlm4_lock alock;
 *		bool reclaim;
 *		int state;
 *	};
 */
static void nlm4_xdr_enc_lockargs(struct rpc_rqst *req,
				  struct xdr_stream *xdr,
				  const struct nlm_args *args)
{
	const struct nlm_lock *lock = &args->lock;

	encode_cookie_clnt4xdr_c(xdr, &args->cookie);
	encode_bool_clnt4xdr_c(xdr, args->block);
	encode_bool_clnt4xdr_c(xdr, lock->fl.fl_type == F_WRLCK);
	encode_nlm4_lock(xdr, lock);
	encode_bool_clnt4xdr_c(xdr, args->reclaim);
	encode_int32_clnt4xdr_c(xdr, args->state);
}

/*
 *	struct nlm4_cancargs {
 *		netobj cookie;
 *		bool block;
 *		bool exclusive;
 *		struct nlm4_lock alock;
 *	};
 */
static void nlm4_xdr_enc_cancargs(struct rpc_rqst *req,
				  struct xdr_stream *xdr,
				  const struct nlm_args *args)
{
	const struct nlm_lock *lock = &args->lock;

	encode_cookie_clnt4xdr_c(xdr, &args->cookie);
	encode_bool_clnt4xdr_c(xdr, args->block);
	encode_bool_clnt4xdr_c(xdr, lock->fl.fl_type == F_WRLCK);
	encode_nlm4_lock(xdr, lock);
}

/*
 *	struct nlm4_unlockargs {
 *		netobj cookie;
 *		struct nlm4_lock alock;
 *	};
 */
static void nlm4_xdr_enc_unlockargs(struct rpc_rqst *req,
				    struct xdr_stream *xdr,
				    const struct nlm_args *args)
{
	const struct nlm_lock *lock = &args->lock;

	encode_cookie_clnt4xdr_c(xdr, &args->cookie);
	encode_nlm4_lock(xdr, lock);
}

/*
 *	struct nlm4_res {
 *		netobj cookie;
 *		nlm4_stat stat;
 *	};
 */
static void nlm4_xdr_enc_res(struct rpc_rqst *req,
			     struct xdr_stream *xdr,
			     const struct nlm_res *result)
{
	encode_cookie_clnt4xdr_c(xdr, &result->cookie);
	encode_nlm4_stat(xdr, result->status);
}

/*
 *	union nlm4_testrply switch (nlm4_stats stat) {
 *	case NLM4_DENIED:
 *		struct nlm4_holder holder;
 *	default:
 *		void;
 *	};
 *
 *	struct nlm4_testres {
 *		netobj cookie;
 *		nlm4_testrply test_stat;
 *	};
 */
static void nlm4_xdr_enc_testres(struct rpc_rqst *req,
				 struct xdr_stream *xdr,
				 const struct nlm_res *result)
{
	encode_cookie_clnt4xdr_c(xdr, &result->cookie);
	encode_nlm4_stat(xdr, result->status);
	if (result->status == nlm_lck_denied)
		encode_nlm4_holder(xdr, result);
}


/*
 * NLMv4 XDR decode functions
 *
 * NLMv4 argument types are defined in Appendix II of RFC 1813:
 * "NFS Version 3 Protocol Specification" and Chapter 10 of X/Open's
 * "Protocols for Interworking: XNFS, Version 3W".
 */

/*
 *	union nlm4_testrply switch (nlm4_stats stat) {
 *	case NLM4_DENIED:
 *		struct nlm4_holder holder;
 *	default:
 *		void;
 *	};
 *
 *	struct nlm4_testres {
 *		netobj cookie;
 *		nlm4_testrply test_stat;
 *	};
 */
static int decode_nlm4_testrply(struct xdr_stream *xdr,
				struct nlm_res *result)
{
	int error;

	error = decode_nlm4_stat(xdr, &result->status);
	if (unlikely(error))
		goto out;
	if (result->status == nlm_lck_denied)
		error = decode_nlm4_holder(xdr, result);
out:
	return error;
}

static int nlm4_xdr_dec_testres(struct rpc_rqst *req,
				struct xdr_stream *xdr,
				struct nlm_res *result)
{
	int error;

	error = decode_cookie_clnt4xdr_c(xdr, &result->cookie);
	if (unlikely(error))
		goto out;
	error = decode_nlm4_testrply(xdr, result);
out:
	return error;
}

/*
 *	struct nlm4_res {
 *		netobj cookie;
 *		nlm4_stat stat;
 *	};
 */
static int nlm4_xdr_dec_res(struct rpc_rqst *req,
			    struct xdr_stream *xdr,
			    struct nlm_res *result)
{
	int error;

	error = decode_cookie_clnt4xdr_c(xdr, &result->cookie);
	if (unlikely(error))
		goto out;
	error = decode_nlm4_stat(xdr, &result->status);
out:
	return error;
}


/*
 * For NLM, a void procedure really returns nothing
 */
#define nlm4_xdr_dec_norep	NULL

#define PROC(proc, argtype, restype)					\
[NLMPROC_##proc] = {							\
	.p_proc      = NLMPROC_##proc,					\
	.p_encode    = (kxdreproc_t)nlm4_xdr_enc_##argtype,		\
	.p_decode    = (kxdrdproc_t)nlm4_xdr_dec_##restype,		\
	.p_arglen    = NLM4_##argtype##_sz,				\
	.p_replen    = NLM4_##restype##_sz,				\
	.p_statidx   = NLMPROC_##proc,					\
	.p_name      = #proc,						\
	}

static struct rpc_procinfo	nlm4_procedures[] = {
	PROC(TEST,		testargs,	testres),
	PROC(LOCK,		lockargs,	res),
	PROC(CANCEL,		cancargs,	res),
	PROC(UNLOCK,		unlockargs,	res),
	PROC(GRANTED,		testargs,	res),
	PROC(TEST_MSG,		testargs,	norep),
	PROC(LOCK_MSG,		lockargs,	norep),
	PROC(CANCEL_MSG,	cancargs,	norep),
	PROC(UNLOCK_MSG,	unlockargs,	norep),
	PROC(GRANTED_MSG,	testargs,	norep),
	PROC(TEST_RES,		testres,	norep),
	PROC(LOCK_RES,		res,		norep),
	PROC(CANCEL_RES,	res,		norep),
	PROC(UNLOCK_RES,	res,		norep),
	PROC(GRANTED_RES,	res,		norep),
};

const struct rpc_version nlm_version4 = {
	.number		= 4,
	.nrprocs	= ARRAY_SIZE(nlm4_procedures),
	.procs		= nlm4_procedures,
};
/************************************************************/
/* ../linux-3.17/fs/lockd/xdr4.c */
/************************************************************/
/*
 * linux/fs/lockd/xdr4.c
 *
 * XDR support for lockd and the lock client.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 * Copyright (C) 1999, Trond Myklebust <trond.myklebust@fys.uio.no>
 */

// #include <linux/types.h>
// #include <linux/sched.h>
// #include <linux/nfs.h>

// #include <linux/sunrpc/xdr.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/svc.h>
// #include <linux/sunrpc/stats.h>
// #include <linux/lockd/lockd.h>

#define NLMDBG_FACILITY		NLMDBG_XDR

static inline loff_t
s64_to_loff_t(__s64 offset)
{
	return (loff_t)offset;
}


static inline s64
loff_t_to_s64_xdr4_c(loff_t offset)
{
	s64 res;
	if (offset > NLM4_OFFSET_MAX)
		res = NLM4_OFFSET_MAX;
	else if (offset < -NLM4_OFFSET_MAX)
		res = -NLM4_OFFSET_MAX;
	else
		res = offset;
	return res;
}

/*
 * XDR functions for basic NLM types
 */
static __be32 *
nlm4_decode_cookie(__be32 *p, struct nlm_cookie *c)
{
	unsigned int	len;

	len = ntohl(*p++);

	if(len==0)
	{
		c->len=4;
		memset(c->data, 0, 4);	/* hockeypux brain damage */
	}
	else if(len<=NLM_MAXCOOKIELEN)
	{
		c->len=len;
		memcpy(c->data, p, len);
		p+=XDR_QUADLEN(len);
	}
	else
	{
		dprintk("lockd: bad cookie size %d (only cookies under "
			"%d bytes are supported.)\n",
				len, NLM_MAXCOOKIELEN);
		return NULL;
	}
	return p;
}

static __be32 *
nlm4_encode_cookie(__be32 *p, struct nlm_cookie *c)
{
	*p++ = htonl(c->len);
	memcpy(p, c->data, c->len);
	p+=XDR_QUADLEN(c->len);
	return p;
}

static __be32 *
nlm4_decode_fh(__be32 *p, struct nfs_fh *f)
{
	memset(f->data, 0, sizeof(f->data));
	f->size = ntohl(*p++);
	if (f->size > NFS_MAXFHSIZE) {
		dprintk("lockd: bad fhandle size %d (should be <=%d)\n",
			f->size, NFS_MAXFHSIZE);
		return NULL;
	}
      	memcpy(f->data, p, f->size);
	return p + XDR_QUADLEN(f->size);
}

/*
 * Encode and decode owner handle
 */
static __be32 *
nlm4_decode_oh(__be32 *p, struct xdr_netobj *oh)
{
	return xdr_decode_netobj(p, oh);
}

static __be32 *
nlm4_decode_lock(__be32 *p, struct nlm_lock *lock)
{
	struct file_lock	*fl = &lock->fl;
	__u64			len, start;
	__s64			end;

	if (!(p = xdr_decode_string_inplace(p, &lock->caller,
					    &lock->len, NLM_MAXSTRLEN))
	 || !(p = nlm4_decode_fh(p, &lock->fh))
	 || !(p = nlm4_decode_oh(p, &lock->oh)))
		return NULL;
	lock->svid  = ntohl(*p++);

	locks_init_lock(fl);
	fl->fl_owner = current->files;
	fl->fl_pid   = (pid_t)lock->svid;
	fl->fl_flags = FL_POSIX;
	fl->fl_type  = F_RDLCK;		/* as good as anything else */
	p = xdr_decode_hyper(p, &start);
	p = xdr_decode_hyper(p, &len);
	end = start + len - 1;

	fl->fl_start = s64_to_loff_t(start);

	if (len == 0 || end < 0)
		fl->fl_end = OFFSET_MAX;
	else
		fl->fl_end = s64_to_loff_t(end);
	return p;
}

/*
 * Encode result of a TEST/TEST_MSG call
 */
static __be32 *
nlm4_encode_testres(__be32 *p, struct nlm_res *resp)
{
	s64		start, len;

	dprintk("xdr: before encode_testres (p %p resp %p)\n", p, resp);
	if (!(p = nlm4_encode_cookie(p, &resp->cookie)))
		return NULL;
	*p++ = resp->status;

	if (resp->status == nlm_lck_denied) {
		struct file_lock	*fl = &resp->lock.fl;

		*p++ = (fl->fl_type == F_RDLCK)? xdr_zero : xdr_one;
		*p++ = htonl(resp->lock.svid);

		/* Encode owner handle. */
		if (!(p = xdr_encode_netobj(p, &resp->lock.oh)))
			return NULL;

		start = loff_t_to_s64_xdr4_c(fl->fl_start);
		if (fl->fl_end == OFFSET_MAX)
			len = 0;
		else
			len = loff_t_to_s64_xdr4_c(fl->fl_end - fl->fl_start + 1);

		p = xdr_encode_hyper(p, start);
		p = xdr_encode_hyper(p, len);
		dprintk("xdr: encode_testres (status %u pid %d type %d start %Ld end %Ld)\n",
			resp->status, (int)resp->lock.svid, fl->fl_type,
			(long long)fl->fl_start,  (long long)fl->fl_end);
	}

	dprintk("xdr: after encode_testres (p %p resp %p)\n", p, resp);
	return p;
}


/*
 * First, the server side XDR functions
 */
int
nlm4svc_decode_testargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	u32	exclusive;

	if (!(p = nlm4_decode_cookie(p, &argp->cookie)))
		return 0;

	exclusive = ntohl(*p++);
	if (!(p = nlm4_decode_lock(p, &argp->lock)))
		return 0;
	if (exclusive)
		argp->lock.fl.fl_type = F_WRLCK;

	return xdr_argsize_check(rqstp, p);
}

int
nlm4svc_encode_testres(struct svc_rqst *rqstp, __be32 *p, struct nlm_res *resp)
{
	if (!(p = nlm4_encode_testres(p, resp)))
		return 0;
	return xdr_ressize_check(rqstp, p);
}

int
nlm4svc_decode_lockargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	u32	exclusive;

	if (!(p = nlm4_decode_cookie(p, &argp->cookie)))
		return 0;
	argp->block  = ntohl(*p++);
	exclusive    = ntohl(*p++);
	if (!(p = nlm4_decode_lock(p, &argp->lock)))
		return 0;
	if (exclusive)
		argp->lock.fl.fl_type = F_WRLCK;
	argp->reclaim = ntohl(*p++);
	argp->state   = ntohl(*p++);
	argp->monitor = 1;		/* monitor client by default */

	return xdr_argsize_check(rqstp, p);
}

int
nlm4svc_decode_cancargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	u32	exclusive;

	if (!(p = nlm4_decode_cookie(p, &argp->cookie)))
		return 0;
	argp->block = ntohl(*p++);
	exclusive = ntohl(*p++);
	if (!(p = nlm4_decode_lock(p, &argp->lock)))
		return 0;
	if (exclusive)
		argp->lock.fl.fl_type = F_WRLCK;
	return xdr_argsize_check(rqstp, p);
}

int
nlm4svc_decode_unlockargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	if (!(p = nlm4_decode_cookie(p, &argp->cookie))
	 || !(p = nlm4_decode_lock(p, &argp->lock)))
		return 0;
	argp->lock.fl.fl_type = F_UNLCK;
	return xdr_argsize_check(rqstp, p);
}

int
nlm4svc_decode_shareargs(struct svc_rqst *rqstp, __be32 *p, nlm_args *argp)
{
	struct nlm_lock	*lock = &argp->lock;

	memset(lock, 0, sizeof(*lock));
	locks_init_lock(&lock->fl);
	lock->svid = ~(u32) 0;
	lock->fl.fl_pid = (pid_t)lock->svid;

	if (!(p = nlm4_decode_cookie(p, &argp->cookie))
	 || !(p = xdr_decode_string_inplace(p, &lock->caller,
					    &lock->len, NLM_MAXSTRLEN))
	 || !(p = nlm4_decode_fh(p, &lock->fh))
	 || !(p = nlm4_decode_oh(p, &lock->oh)))
		return 0;
	argp->fsm_mode = ntohl(*p++);
	argp->fsm_access = ntohl(*p++);
	return xdr_argsize_check(rqstp, p);
}

int
nlm4svc_encode_shareres(struct svc_rqst *rqstp, __be32 *p, struct nlm_res *resp)
{
	if (!(p = nlm4_encode_cookie(p, &resp->cookie)))
		return 0;
	*p++ = resp->status;
	*p++ = xdr_zero;		/* sequence argument */
	return xdr_ressize_check(rqstp, p);
}

int
nlm4svc_encode_res(struct svc_rqst *rqstp, __be32 *p, struct nlm_res *resp)
{
	if (!(p = nlm4_encode_cookie(p, &resp->cookie)))
		return 0;
	*p++ = resp->status;
	return xdr_ressize_check(rqstp, p);
}

int
nlm4svc_decode_notify(struct svc_rqst *rqstp, __be32 *p, struct nlm_args *argp)
{
	struct nlm_lock	*lock = &argp->lock;

	if (!(p = xdr_decode_string_inplace(p, &lock->caller,
					    &lock->len, NLM_MAXSTRLEN)))
		return 0;
	argp->state = ntohl(*p++);
	return xdr_argsize_check(rqstp, p);
}

int
nlm4svc_decode_reboot(struct svc_rqst *rqstp, __be32 *p, struct nlm_reboot *argp)
{
	if (!(p = xdr_decode_string_inplace(p, &argp->mon, &argp->len, SM_MAXSTRLEN)))
		return 0;
	argp->state = ntohl(*p++);
	memcpy(&argp->priv.data, p, sizeof(argp->priv.data));
	p += XDR_QUADLEN(SM_PRIV_SIZE);
	return xdr_argsize_check(rqstp, p);
}

int
nlm4svc_decode_res(struct svc_rqst *rqstp, __be32 *p, struct nlm_res *resp)
{
	if (!(p = nlm4_decode_cookie(p, &resp->cookie)))
		return 0;
	resp->status = *p++;
	return xdr_argsize_check(rqstp, p);
}

int
nlm4svc_decode_void(struct svc_rqst *rqstp, __be32 *p, void *dummy)
{
	return xdr_argsize_check(rqstp, p);
}

int
nlm4svc_encode_void(struct svc_rqst *rqstp, __be32 *p, void *dummy)
{
	return xdr_ressize_check(rqstp, p);
}
/************************************************************/
/* ../linux-3.17/fs/lockd/svc4proc.c */
/************************************************************/
/*
 * linux/fs/lockd/svc4proc.c
 *
 * Lockd server procedures. We don't implement the NLM_*_RES
 * procedures because we don't use the async procedures.
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/types.h>
// #include <linux/time.h>
// #include <linux/lockd/lockd.h>
// #include <linux/lockd/share.h>
// #include <linux/sunrpc/svc_xprt.h>

#define NLMDBG_FACILITY		NLMDBG_CLIENT

/*
 * Obtain client and file from arguments
 */
static __be32
nlm4svc_retrieve_args(struct svc_rqst *rqstp, struct nlm_args *argp,
			struct nlm_host **hostp, struct nlm_file **filp)
{
	struct nlm_host		*host = NULL;
	struct nlm_file		*file = NULL;
	struct nlm_lock		*lock = &argp->lock;
	__be32			error = 0;

	/* nfsd callbacks must have been installed for this procedure */
	if (!nlmsvc_ops)
		return nlm_lck_denied_nolocks;

	/* Obtain host handle */
	if (!(host = nlmsvc_lookup_host(rqstp, lock->caller, lock->len))
	 || (argp->monitor && nsm_monitor(host) < 0))
		goto no_locks;
	*hostp = host;

	/* Obtain file pointer. Not used by FREE_ALL call. */
	if (filp != NULL) {
		if ((error = nlm_lookup_file(rqstp, &file, &lock->fh)) != 0)
			goto no_locks;
		*filp = file;

		/* Set up the missing parts of the file_lock structure */
		lock->fl.fl_file  = file->f_file;
		lock->fl.fl_owner = (fl_owner_t) host;
		lock->fl.fl_lmops = &nlmsvc_lock_operations;
	}

	return 0;

no_locks:
	nlmsvc_release_host(host);
 	if (error)
		return error;
	return nlm_lck_denied_nolocks;
}

/*
 * NULL: Test for presence of service
 */
static __be32
nlm4svc_proc_null(struct svc_rqst *rqstp, void *argp, void *resp)
{
	dprintk("lockd: NULL          called\n");
	return rpc_success;
}

/*
 * TEST: Check for conflicting lock
 */
static __be32
nlm4svc_proc_test(struct svc_rqst *rqstp, struct nlm_args *argp,
				         struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;
	__be32 rc = rpc_success;

	dprintk("lockd: TEST4        called\n");
	resp->cookie = argp->cookie;

	/* Obtain client and file */
	if ((resp->status = nlm4svc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Now check for conflicting locks */
	resp->status = nlmsvc_testlock(rqstp, file, host, &argp->lock, &resp->lock, &resp->cookie);
	if (resp->status == nlm_drop_reply)
		rc = rpc_drop_reply;
	else
		dprintk("lockd: TEST4        status %d\n", ntohl(resp->status));

	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rc;
}

static __be32
nlm4svc_proc_lock(struct svc_rqst *rqstp, struct nlm_args *argp,
				         struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;
	__be32 rc = rpc_success;

	dprintk("lockd: LOCK          called\n");

	resp->cookie = argp->cookie;

	/* Obtain client and file */
	if ((resp->status = nlm4svc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

#if 0
	/* If supplied state doesn't match current state, we assume it's
	 * an old request that time-warped somehow. Any error return would
	 * do in this case because it's irrelevant anyway.
	 *
	 * NB: We don't retrieve the remote host's state yet.
	 */
	if (host->h_nsmstate && host->h_nsmstate != argp->state) {
		resp->status = nlm_lck_denied_nolocks;
	} else
#endif

	/* Now try to lock the file */
	resp->status = nlmsvc_lock(rqstp, file, host, &argp->lock,
					argp->block, &argp->cookie,
					argp->reclaim);
	if (resp->status == nlm_drop_reply)
		rc = rpc_drop_reply;
	else
		dprintk("lockd: LOCK         status %d\n", ntohl(resp->status));

	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rc;
}

static __be32
nlm4svc_proc_cancel(struct svc_rqst *rqstp, struct nlm_args *argp,
				           struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;

	dprintk("lockd: CANCEL        called\n");

	resp->cookie = argp->cookie;

	/* Don't accept requests during grace period */
	if (locks_in_grace(SVC_NET(rqstp))) {
		resp->status = nlm_lck_denied_grace_period;
		return rpc_success;
	}

	/* Obtain client and file */
	if ((resp->status = nlm4svc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Try to cancel request. */
	resp->status = nlmsvc_cancel_blocked(SVC_NET(rqstp), file, &argp->lock);

	dprintk("lockd: CANCEL        status %d\n", ntohl(resp->status));
	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rpc_success;
}

/*
 * UNLOCK: release a lock
 */
static __be32
nlm4svc_proc_unlock(struct svc_rqst *rqstp, struct nlm_args *argp,
				           struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;

	dprintk("lockd: UNLOCK        called\n");

	resp->cookie = argp->cookie;

	/* Don't accept new lock requests during grace period */
	if (locks_in_grace(SVC_NET(rqstp))) {
		resp->status = nlm_lck_denied_grace_period;
		return rpc_success;
	}

	/* Obtain client and file */
	if ((resp->status = nlm4svc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Now try to remove the lock */
	resp->status = nlmsvc_unlock(SVC_NET(rqstp), file, &argp->lock);

	dprintk("lockd: UNLOCK        status %d\n", ntohl(resp->status));
	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rpc_success;
}

/*
 * GRANTED: A server calls us to tell that a process' lock request
 * was granted
 */
static __be32
nlm4svc_proc_granted(struct svc_rqst *rqstp, struct nlm_args *argp,
				            struct nlm_res  *resp)
{
	resp->cookie = argp->cookie;

	dprintk("lockd: GRANTED       called\n");
	resp->status = nlmclnt_grant(svc_addr(rqstp), &argp->lock);
	dprintk("lockd: GRANTED       status %d\n", ntohl(resp->status));
	return rpc_success;
}

/*
 * This is the generic lockd callback for async RPC calls
 */
static void nlm4svc_callback_exit(struct rpc_task *task, void *data)
{
	dprintk("lockd: %5u callback returned %d\n", task->tk_pid,
			-task->tk_status);
}

static void nlm4svc_callback_release(void *data)
{
	nlmsvc_release_call(data);
}

static const struct rpc_call_ops nlm4svc_callback_ops = {
	.rpc_call_done = nlm4svc_callback_exit,
	.rpc_release = nlm4svc_callback_release,
};

/*
 * `Async' versions of the above service routines. They aren't really,
 * because we send the callback before the reply proper. I hope this
 * doesn't break any clients.
 */
static __be32 nlm4svc_callback(struct svc_rqst *rqstp, u32 proc, struct nlm_args *argp,
		__be32 (*func)(struct svc_rqst *, struct nlm_args *, struct nlm_res  *))
{
	struct nlm_host	*host;
	struct nlm_rqst	*call;
	__be32 stat;

	host = nlmsvc_lookup_host(rqstp,
				  argp->lock.caller,
				  argp->lock.len);
	if (host == NULL)
		return rpc_system_err;

	call = nlm_alloc_call(host);
	nlmsvc_release_host(host);
	if (call == NULL)
		return rpc_system_err;

	stat = func(rqstp, argp, &call->a_res);
	if (stat != 0) {
		nlmsvc_release_call(call);
		return stat;
	}

	call->a_flags = RPC_TASK_ASYNC;
	if (nlm_async_reply(call, proc, &nlm4svc_callback_ops) < 0)
		return rpc_system_err;
	return rpc_success;
}

static __be32 nlm4svc_proc_test_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
					     void	     *resp)
{
	dprintk("lockd: TEST_MSG      called\n");
	return nlm4svc_callback(rqstp, NLMPROC_TEST_RES, argp, nlm4svc_proc_test);
}

static __be32 nlm4svc_proc_lock_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
					     void	     *resp)
{
	dprintk("lockd: LOCK_MSG      called\n");
	return nlm4svc_callback(rqstp, NLMPROC_LOCK_RES, argp, nlm4svc_proc_lock);
}

static __be32 nlm4svc_proc_cancel_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
					       void	       *resp)
{
	dprintk("lockd: CANCEL_MSG    called\n");
	return nlm4svc_callback(rqstp, NLMPROC_CANCEL_RES, argp, nlm4svc_proc_cancel);
}

static __be32 nlm4svc_proc_unlock_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
                                               void            *resp)
{
	dprintk("lockd: UNLOCK_MSG    called\n");
	return nlm4svc_callback(rqstp, NLMPROC_UNLOCK_RES, argp, nlm4svc_proc_unlock);
}

static __be32 nlm4svc_proc_granted_msg(struct svc_rqst *rqstp, struct nlm_args *argp,
                                                void            *resp)
{
	dprintk("lockd: GRANTED_MSG   called\n");
	return nlm4svc_callback(rqstp, NLMPROC_GRANTED_RES, argp, nlm4svc_proc_granted);
}

/*
 * SHARE: create a DOS share or alter existing share.
 */
static __be32
nlm4svc_proc_share(struct svc_rqst *rqstp, struct nlm_args *argp,
				          struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;

	dprintk("lockd: SHARE         called\n");

	resp->cookie = argp->cookie;

	/* Don't accept new lock requests during grace period */
	if (locks_in_grace(SVC_NET(rqstp)) && !argp->reclaim) {
		resp->status = nlm_lck_denied_grace_period;
		return rpc_success;
	}

	/* Obtain client and file */
	if ((resp->status = nlm4svc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Now try to create the share */
	resp->status = nlmsvc_share_file(host, file, argp);

	dprintk("lockd: SHARE         status %d\n", ntohl(resp->status));
	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rpc_success;
}

/*
 * UNSHARE: Release a DOS share.
 */
static __be32
nlm4svc_proc_unshare(struct svc_rqst *rqstp, struct nlm_args *argp,
				            struct nlm_res  *resp)
{
	struct nlm_host	*host;
	struct nlm_file	*file;

	dprintk("lockd: UNSHARE       called\n");

	resp->cookie = argp->cookie;

	/* Don't accept requests during grace period */
	if (locks_in_grace(SVC_NET(rqstp))) {
		resp->status = nlm_lck_denied_grace_period;
		return rpc_success;
	}

	/* Obtain client and file */
	if ((resp->status = nlm4svc_retrieve_args(rqstp, argp, &host, &file)))
		return resp->status == nlm_drop_reply ? rpc_drop_reply :rpc_success;

	/* Now try to lock the file */
	resp->status = nlmsvc_unshare_file(host, file, argp);

	dprintk("lockd: UNSHARE       status %d\n", ntohl(resp->status));
	nlmsvc_release_host(host);
	nlm_release_file(file);
	return rpc_success;
}

/*
 * NM_LOCK: Create an unmonitored lock
 */
static __be32
nlm4svc_proc_nm_lock(struct svc_rqst *rqstp, struct nlm_args *argp,
				            struct nlm_res  *resp)
{
	dprintk("lockd: NM_LOCK       called\n");

	argp->monitor = 0;		/* just clean the monitor flag */
	return nlm4svc_proc_lock(rqstp, argp, resp);
}

/*
 * FREE_ALL: Release all locks and shares held by client
 */
static __be32
nlm4svc_proc_free_all(struct svc_rqst *rqstp, struct nlm_args *argp,
					     void            *resp)
{
	struct nlm_host	*host;

	/* Obtain client */
	if (nlm4svc_retrieve_args(rqstp, argp, &host, NULL))
		return rpc_success;

	nlmsvc_free_host_resources(host);
	nlmsvc_release_host(host);
	return rpc_success;
}

/*
 * SM_NOTIFY: private callback from statd (not part of official NLM proto)
 */
static __be32
nlm4svc_proc_sm_notify(struct svc_rqst *rqstp, struct nlm_reboot *argp,
					      void	        *resp)
{
	dprintk("lockd: SM_NOTIFY     called\n");

	if (!nlm_privileged_requester(rqstp)) {
		char buf[RPC_MAX_ADDRBUFLEN];
		printk(KERN_WARNING "lockd: rejected NSM callback from %s\n",
				svc_print_addr(rqstp, buf, sizeof(buf)));
		return rpc_system_err;
	}

	nlm_host_rebooted(argp);
	return rpc_success;
}

/*
 * client sent a GRANTED_RES, let's remove the associated block
 */
static __be32
nlm4svc_proc_granted_res(struct svc_rqst *rqstp, struct nlm_res  *argp,
                                                void            *resp)
{
        if (!nlmsvc_ops)
                return rpc_success;

        dprintk("lockd: GRANTED_RES   called\n");

        nlmsvc_grant_reply(&argp->cookie, argp->status);
        return rpc_success;
}


/*
 * NLM Server procedures.
 */

#define nlm4svc_encode_norep	nlm4svc_encode_void
#define nlm4svc_decode_norep	nlm4svc_decode_void
#define nlm4svc_decode_testres	nlm4svc_decode_void
#define nlm4svc_decode_lockres	nlm4svc_decode_void
#define nlm4svc_decode_unlockres	nlm4svc_decode_void
#define nlm4svc_decode_cancelres	nlm4svc_decode_void
#define nlm4svc_decode_grantedres	nlm4svc_decode_void

#define nlm4svc_proc_none	nlm4svc_proc_null
#define nlm4svc_proc_test_res	nlm4svc_proc_null
#define nlm4svc_proc_lock_res	nlm4svc_proc_null
#define nlm4svc_proc_cancel_res	nlm4svc_proc_null
#define nlm4svc_proc_unlock_res	nlm4svc_proc_null

struct nlm_void			{ int dummy; };

#define PROC(name, xargt, xrest, argt, rest, respsize)	\
 { .pc_func	= (svc_procfunc) nlm4svc_proc_##name,	\
   .pc_decode	= (kxdrproc_t) nlm4svc_decode_##xargt,	\
   .pc_encode	= (kxdrproc_t) nlm4svc_encode_##xrest,	\
   .pc_release	= NULL,					\
   .pc_argsize	= sizeof(struct nlm_##argt),		\
   .pc_ressize	= sizeof(struct nlm_##rest),		\
   .pc_xdrressize = respsize,				\
 }
#define	Ck	(1+XDR_QUADLEN(NLM_MAXCOOKIELEN))	/* cookie */
#define	No	(1+1024/4)				/* netobj */
#define	St	1					/* status */
#define	Rg	4					/* range (offset + length) */
struct svc_procedure		nlmsvc_procedures4[] = {
  PROC(null,		void,		void,		void,	void, 1),
  PROC(test,		testargs,	testres,	args,	res, Ck+St+2+No+Rg),
  PROC(lock,		lockargs,	res,		args,	res, Ck+St),
  PROC(cancel,		cancargs,	res,		args,	res, Ck+St),
  PROC(unlock,		unlockargs,	res,		args,	res, Ck+St),
  PROC(granted,		testargs,	res,		args,	res, Ck+St),
  PROC(test_msg,	testargs,	norep,		args,	void, 1),
  PROC(lock_msg,	lockargs,	norep,		args,	void, 1),
  PROC(cancel_msg,	cancargs,	norep,		args,	void, 1),
  PROC(unlock_msg,	unlockargs,	norep,		args,	void, 1),
  PROC(granted_msg,	testargs,	norep,		args,	void, 1),
  PROC(test_res,	testres,	norep,		res,	void, 1),
  PROC(lock_res,	lockres,	norep,		res,	void, 1),
  PROC(cancel_res,	cancelres,	norep,		res,	void, 1),
  PROC(unlock_res,	unlockres,	norep,		res,	void, 1),
  PROC(granted_res,	res,		norep,		res,	void, 1),
  /* statd callback */
  PROC(sm_notify,	reboot,		void,		reboot,	void, 1),
  PROC(none,		void,		void,		void,	void, 0),
  PROC(none,		void,		void,		void,	void, 0),
  PROC(none,		void,		void,		void,	void, 0),
  PROC(share,		shareargs,	shareres,	args,	res, Ck+St+1),
  PROC(unshare,		shareargs,	shareres,	args,	res, Ck+St+1),
  PROC(nm_lock,		lockargs,	res,		args,	res, Ck+St),
  PROC(free_all,	notify,		void,		args,	void, 1),

};
