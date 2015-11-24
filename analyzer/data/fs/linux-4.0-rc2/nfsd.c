#include "state.h"
#include "../../inc/__fss.h"

#define CREATE_TRACE_POINTS
#include "trace.h"
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/trace.c */
/************************************************************/
/*
 * Central processing for nfsd.
 *
 * Authors:	Olaf Kirch (okir@monad.swb.de)
 *
 * Copyright (C) 1995, 1996, 1997 Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/sched.h>
#include <linux/freezer.h>
#include <linux/module.h>
#include <linux/fs_struct.h>
#include <linux/swap.h>
#include "../../inc/__fss.h"

#include <linux/sunrpc/stats.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/lockd/bind.h>
#include <linux/nfsacl.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include "nfsd.h"
#include "cache.h"
#include "vfs.h"
#include "netns.h"
#include "../../inc/__fss.h"

#define NFSDDBG_FACILITY	NFSDDBG_SVC

extern struct svc_program	nfsd_program;
static int			nfsd(void *vrqstp);

/*
 * nfsd_mutex protects nn->nfsd_serv -- both the pointer itself and the members
 * of the svc_serv struct. In particular, ->sv_nrthreads but also to some
 * extent ->sv_temp_socks and ->sv_permsocks. It also protects nfsdstats.th_cnt
 *
 * If (out side the lock) nn->nfsd_serv is non-NULL, then it must point to a
 * properly initialised 'struct svc_serv' with ->sv_nrthreads > 0. That number
 * of nfsd threads must exist and each must listed in ->sp_all_threads in each
 * entry of ->sv_pools[].
 *
 * Transitions of the thread count between zero and non-zero are of particular
 * interest since the svc_serv needs to be created and initialized at that
 * point, or freed.
 *
 * Finally, the nfsd_mutex also protects some of the global variables that are
 * accessed when nfsd starts and that are settable via the write_* routines in
 * nfsctl.c. In particular:
 *
 *	user_recovery_dirname
 *	user_lease_time
 *	nfsd_versions
 */
DEFINE_MUTEX(nfsd_mutex);

/*
 * nfsd_drc_lock protects nfsd_drc_max_pages and nfsd_drc_pages_used.
 * nfsd_drc_max_pages limits the total amount of memory available for
 * version 4.1 DRC caches.
 * nfsd_drc_pages_used tracks the current version 4.1 DRC memory usage.
 */
spinlock_t	nfsd_drc_lock;
unsigned long	nfsd_drc_max_mem;
unsigned long	nfsd_drc_mem_used;

#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
static struct svc_stat	nfsd_acl_svcstats;
static struct svc_version *	nfsd_acl_version[] = {
	[2] = &nfsd_acl_version2,
	[3] = &nfsd_acl_version3,
};

#define NFSD_ACL_MINVERS            2
#define NFSD_ACL_NRVERS		ARRAY_SIZE(nfsd_acl_version)
static struct svc_version *nfsd_acl_versions[NFSD_ACL_NRVERS];

static struct svc_program	nfsd_acl_program = {
	.pg_prog		= NFS_ACL_PROGRAM,
	.pg_nvers		= NFSD_ACL_NRVERS,
	.pg_vers		= nfsd_acl_versions,
	.pg_name		= "nfsacl",
	.pg_class		= "nfsd",
	.pg_stats		= &nfsd_acl_svcstats,
	.pg_authenticate	= &svc_set_client,
};

static struct svc_stat	nfsd_acl_svcstats = {
	.program	= &nfsd_acl_program,
};
#endif /* defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL) */

static struct svc_version *	nfsd_version[] = {
	[2] = &nfsd_version2,
#if defined(CONFIG_NFSD_V3)
	[3] = &nfsd_version3,
#endif
#if defined(CONFIG_NFSD_V4)
	[4] = &nfsd_version4,
#endif
};

#define NFSD_MINVERS    	2
#define NFSD_NRVERS		ARRAY_SIZE(nfsd_version)
static struct svc_version *nfsd_versions[NFSD_NRVERS];

struct svc_program		nfsd_program = {
#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
	.pg_next		= &nfsd_acl_program,
#endif
	.pg_prog		= NFS_PROGRAM,		/* program number */
	.pg_nvers		= NFSD_NRVERS,		/* nr of entries in nfsd_version */
	.pg_vers		= nfsd_versions,	/* version table */
	.pg_name		= "nfsd",		/* program name */
	.pg_class		= "nfsd",		/* authentication class */
	.pg_stats		= &nfsd_svcstats,	/* version table */
	.pg_authenticate	= &svc_set_client,	/* export authentication */

};

static bool nfsd_supported_minorversions[NFSD_SUPPORTED_MINOR_VERSION + 1] = {
	[0] = 1,
	[1] = 1,
	[2] = 1,
};

int nfsd_vers(int vers, enum vers_op change)
{
	if (vers < NFSD_MINVERS || vers >= NFSD_NRVERS)
		return 0;
	switch(change) {
	case NFSD_SET:
		nfsd_versions[vers] = nfsd_version[vers];
#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
		if (vers < NFSD_ACL_NRVERS)
			nfsd_acl_versions[vers] = nfsd_acl_version[vers];
#endif
		break;
	case NFSD_CLEAR:
		nfsd_versions[vers] = NULL;
#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
		if (vers < NFSD_ACL_NRVERS)
			nfsd_acl_versions[vers] = NULL;
#endif
		break;
	case NFSD_TEST:
		return nfsd_versions[vers] != NULL;
	case NFSD_AVAIL:
		return nfsd_version[vers] != NULL;
	}
	return 0;
}

int nfsd_minorversion(u32 minorversion, enum vers_op change)
{
	if (minorversion > NFSD_SUPPORTED_MINOR_VERSION)
		return -1;
	switch(change) {
	case NFSD_SET:
		nfsd_supported_minorversions[minorversion] = true;
		break;
	case NFSD_CLEAR:
		nfsd_supported_minorversions[minorversion] = false;
		break;
	case NFSD_TEST:
		return nfsd_supported_minorversions[minorversion];
	case NFSD_AVAIL:
		return minorversion <= NFSD_SUPPORTED_MINOR_VERSION;
	}
	return 0;
}

/*
 * Maximum number of nfsd processes
 */
#define	NFSD_MAXSERVS		8192

int nfsd_nrthreads(struct net *net)
{
	int rv = 0;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	mutex_lock(&nfsd_mutex);
	if (nn->nfsd_serv)
		rv = nn->nfsd_serv->sv_nrthreads;
	mutex_unlock(&nfsd_mutex);
	return rv;
}

static int nfsd_init_socks(struct net *net)
{
	int error;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	if (!list_empty(&nn->nfsd_serv->sv_permsocks))
		return 0;

	error = svc_create_xprt(nn->nfsd_serv, "udp", net, PF_INET, NFS_PORT,
					SVC_SOCK_DEFAULTS);
	if (error < 0)
		return error;

	error = svc_create_xprt(nn->nfsd_serv, "tcp", net, PF_INET, NFS_PORT,
					SVC_SOCK_DEFAULTS);
	if (error < 0)
		return error;

	return 0;
}

static int nfsd_users = 0;

static int nfsd_startup_generic(int nrservs)
{
	int ret;

	if (nfsd_users++)
		return 0;

	/*
	 * Readahead param cache - will no-op if it already exists.
	 * (Note therefore results will be suboptimal if number of
	 * threads is modified after nfsd start.)
	 */
	ret = nfsd_racache_init(2*nrservs);
	if (ret)
		goto dec_users;

	ret = nfs4_state_start();
	if (ret)
		goto out_racache;
	return 0;

out_racache:
	nfsd_racache_shutdown();
dec_users:
	nfsd_users--;
	return ret;
}

static void nfsd_shutdown_generic(void)
{
	if (--nfsd_users)
		return;

	nfs4_state_shutdown();
	nfsd_racache_shutdown();
}

static bool nfsd_needs_lockd(void)
{
#if defined(CONFIG_NFSD_V3)
	return (nfsd_versions[2] != NULL) || (nfsd_versions[3] != NULL);
#else
	return (nfsd_versions[2] != NULL);
#endif
}

static int nfsd_startup_net(int nrservs, struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	int ret;

	if (nn->nfsd_net_up)
		return 0;

	ret = nfsd_startup_generic(nrservs);
	if (ret)
		return ret;
	ret = nfsd_init_socks(net);
	if (ret)
		goto out_socks;

	if (nfsd_needs_lockd() && !nn->lockd_up) {
		ret = lockd_up(net);
		if (ret)
			goto out_socks;
		nn->lockd_up = 1;
	}

	ret = nfs4_state_start_net(net);
	if (ret)
		goto out_lockd;

	nn->nfsd_net_up = true;
	return 0;

out_lockd:
	if (nn->lockd_up) {
		lockd_down(net);
		nn->lockd_up = 0;
	}
out_socks:
	nfsd_shutdown_generic();
	return ret;
}

static void nfsd_shutdown_net(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	nfs4_state_shutdown_net(net);
	if (nn->lockd_up) {
		lockd_down(net);
		nn->lockd_up = 0;
	}
	nn->nfsd_net_up = false;
	nfsd_shutdown_generic();
}

static void nfsd_last_thread(struct svc_serv *serv, struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	/*
	 * write_ports can create the server without actually starting
	 * any threads--if we get shut down before any threads are
	 * started, then nfsd_last_thread will be run before any of this
	 * other initialization has been done.
	 */
	if (!nn->nfsd_net_up)
		return;
	nfsd_shutdown_net(net);

	svc_rpcb_cleanup(serv, net);

	printk(KERN_WARNING "nfsd: last server has exited, flushing export "
			    "cache\n");
	nfsd_export_flush(net);
}

void nfsd_reset_versions(void)
{
	int found_one = 0;
	int i;

	for (i = NFSD_MINVERS; i < NFSD_NRVERS; i++) {
		if (nfsd_program.pg_vers[i])
			found_one = 1;
	}

	if (!found_one) {
		for (i = NFSD_MINVERS; i < NFSD_NRVERS; i++)
			nfsd_program.pg_vers[i] = nfsd_version[i];
#if defined(CONFIG_NFSD_V2_ACL) || defined(CONFIG_NFSD_V3_ACL)
		for (i = NFSD_ACL_MINVERS; i < NFSD_ACL_NRVERS; i++)
			nfsd_acl_program.pg_vers[i] =
				nfsd_acl_version[i];
#endif
	}
}

/*
 * Each session guarantees a negotiated per slot memory cache for replies
 * which in turn consumes memory beyond the v2/v3/v4.0 server. A dedicated
 * NFSv4.1 server might want to use more memory for a DRC than a machine
 * with mutiple services.
 *
 * Impose a hard limit on the number of pages for the DRC which varies
 * according to the machines free pages. This is of course only a default.
 *
 * For now this is a #defined shift which could be under admin control
 * in the future.
 */
static void set_max_drc(void)
{
	#define NFSD_DRC_SIZE_SHIFT	10
	nfsd_drc_max_mem = (nr_free_buffer_pages()
					>> NFSD_DRC_SIZE_SHIFT) * PAGE_SIZE;
	nfsd_drc_mem_used = 0;
	spin_lock_init(&nfsd_drc_lock);
	dprintk("%s nfsd_drc_max_mem %lu \n", __func__, nfsd_drc_max_mem);
}

static int nfsd_get_default_max_blksize(void)
{
	struct sysinfo i;
	unsigned long long target;
	unsigned long ret;

	si_meminfo(&i);
	target = (i.totalram - i.totalhigh) << PAGE_SHIFT;
	/*
	 * Aim for 1/4096 of memory per thread This gives 1MB on 4Gig
	 * machines, but only uses 32K on 128M machines.  Bottom out at
	 * 8K on 32M and smaller.  Of course, this is only a default.
	 */
	target >>= 12;

	ret = NFSSVC_MAXBLKSIZE;
	while (ret > target && ret >= 8*1024*2)
		ret /= 2;
	return ret;
}

int nfsd_create_serv(struct net *net)
{
	int error;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	WARN_ON(!mutex_is_locked(&nfsd_mutex));
	if (nn->nfsd_serv) {
		svc_get(nn->nfsd_serv);
		return 0;
	}
	if (nfsd_max_blksize == 0)
		nfsd_max_blksize = nfsd_get_default_max_blksize();
	nfsd_reset_versions();
	nn->nfsd_serv = svc_create_pooled(&nfsd_program, nfsd_max_blksize,
				      nfsd_last_thread, nfsd, THIS_MODULE);
	if (nn->nfsd_serv == NULL)
		return -ENOMEM;

	nn->nfsd_serv->sv_maxconn = nn->max_connections;
	error = svc_bind(nn->nfsd_serv, net);
	if (error < 0) {
		svc_destroy(nn->nfsd_serv);
		return error;
	}

	set_max_drc();
	do_gettimeofday(&nn->nfssvc_boot);		/* record boot time */
	return 0;
}

int nfsd_nrpools(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	if (nn->nfsd_serv == NULL)
		return 0;
	else
		return nn->nfsd_serv->sv_nrpools;
}

int nfsd_get_nrthreads(int n, int *nthreads, struct net *net)
{
	int i = 0;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	if (nn->nfsd_serv != NULL) {
		for (i = 0; i < nn->nfsd_serv->sv_nrpools && i < n; i++)
			nthreads[i] = nn->nfsd_serv->sv_pools[i].sp_nrthreads;
	}

	return 0;
}

void nfsd_destroy(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	int destroy = (nn->nfsd_serv->sv_nrthreads == 1);

	if (destroy)
		svc_shutdown_net(nn->nfsd_serv, net);
	svc_destroy(nn->nfsd_serv);
	if (destroy)
		nn->nfsd_serv = NULL;
}

int nfsd_set_nrthreads(int n, int *nthreads, struct net *net)
{
	int i = 0;
	int tot = 0;
	int err = 0;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	WARN_ON(!mutex_is_locked(&nfsd_mutex));

	if (nn->nfsd_serv == NULL || n <= 0)
		return 0;

	if (n > nn->nfsd_serv->sv_nrpools)
		n = nn->nfsd_serv->sv_nrpools;

	/* enforce a global maximum number of threads */
	tot = 0;
	for (i = 0; i < n; i++) {
		nthreads[i] = min(nthreads[i], NFSD_MAXSERVS);
		tot += nthreads[i];
	}
	if (tot > NFSD_MAXSERVS) {
		/* total too large: scale down requested numbers */
		for (i = 0; i < n && tot > 0; i++) {
		    	int new = nthreads[i] * NFSD_MAXSERVS / tot;
			tot -= (nthreads[i] - new);
			nthreads[i] = new;
		}
		for (i = 0; i < n && tot > 0; i++) {
			nthreads[i]--;
			tot--;
		}
	}

	/*
	 * There must always be a thread in pool 0; the admin
	 * can't shut down NFS completely using pool_threads.
	 */
	if (nthreads[0] == 0)
		nthreads[0] = 1;

	/* apply the new numbers */
	svc_get(nn->nfsd_serv);
	for (i = 0; i < n; i++) {
		err = svc_set_num_threads(nn->nfsd_serv, &nn->nfsd_serv->sv_pools[i],
				    	  nthreads[i]);
		if (err)
			break;
	}
	nfsd_destroy(net);
	return err;
}

/*
 * Adjust the number of threads and return the new number of threads.
 * This is also the function that starts the server if necessary, if
 * this is the first time nrservs is nonzero.
 */
int
nfsd_svc(int nrservs, struct net *net)
{
	int	error;
	bool	nfsd_up_before;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	mutex_lock(&nfsd_mutex);
	dprintk("nfsd: creating service\n");

	nrservs = max(nrservs, 0);
	nrservs = min(nrservs, NFSD_MAXSERVS);
	error = 0;

	if (nrservs == 0 && nn->nfsd_serv == NULL)
		goto out;

	error = nfsd_create_serv(net);
	if (error)
		goto out;

	nfsd_up_before = nn->nfsd_net_up;

	error = nfsd_startup_net(nrservs, net);
	if (error)
		goto out_destroy;
	error = svc_set_num_threads(nn->nfsd_serv, NULL, nrservs);
	if (error)
		goto out_shutdown;
	/* We are holding a reference to nn->nfsd_serv which
	 * we don't want to count in the return value,
	 * so subtract 1
	 */
	error = nn->nfsd_serv->sv_nrthreads - 1;
out_shutdown:
	if (error < 0 && !nfsd_up_before)
		nfsd_shutdown_net(net);
out_destroy:
	nfsd_destroy(net);		/* Release server */
out:
	mutex_unlock(&nfsd_mutex);
	return error;
}


/*
 * This is the NFS server kernel thread
 */
static int
nfsd(void *vrqstp)
{
	struct svc_rqst *rqstp = (struct svc_rqst *) vrqstp;
	struct svc_xprt *perm_sock = list_entry(rqstp->rq_server->sv_permsocks.next, typeof(struct svc_xprt), xpt_list);
	struct net *net = perm_sock->xpt_net;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	int err;

	/* Lock module and set up kernel thread */
	mutex_lock(&nfsd_mutex);

	/* At this point, the thread shares current->fs
	 * with the init process. We need to create files with a
	 * umask of 0 instead of init's umask. */
	if (unshare_fs_struct() < 0) {
		printk("Unable to start nfsd thread: out of memory\n");
		goto out;
	}

	current->fs->umask = 0;

	/*
	 * thread is spawned with all signals set to SIG_IGN, re-enable
	 * the ones that will bring down the thread
	 */
	allow_signal(SIGKILL);
	allow_signal(SIGHUP);
	allow_signal(SIGINT);
	allow_signal(SIGQUIT);

	nfsdstats.th_cnt++;
	mutex_unlock(&nfsd_mutex);

	set_freezable();

	/*
	 * The main request loop
	 */
	for (;;) {
		/* Update sv_maxconn if it has changed */
		rqstp->rq_server->sv_maxconn = nn->max_connections;

		/*
		 * Find a socket with data available and call its
		 * recvfrom routine.
		 */
		while ((err = svc_recv(rqstp, 60*60*HZ)) == -EAGAIN)
			;
		if (err == -EINTR)
			break;
		validate_process_creds();
		svc_process(rqstp);
		validate_process_creds();
	}

	/* Clear signals before calling svc_exit_thread() */
	flush_signals(current);

	mutex_lock(&nfsd_mutex);
	nfsdstats.th_cnt --;

out:
	rqstp->rq_server = NULL;

	/* Release the thread */
	svc_exit_thread(rqstp);

	nfsd_destroy(net);

	/* Release module */
	mutex_unlock(&nfsd_mutex);
	module_put_and_exit(0);
	return 0;
}

static __be32 map_new_errors(u32 vers, __be32 nfserr)
{
	if (nfserr == nfserr_jukebox && vers == 2)
		return nfserr_dropit;
	if (nfserr == nfserr_wrongsec && vers < 4)
		return nfserr_acces;
	return nfserr;
}

int
nfsd_dispatch(struct svc_rqst *rqstp, __be32 *statp)
{
	struct svc_procedure	*proc;
	kxdrproc_t		xdr;
	__be32			nfserr;
	__be32			*nfserrp;

	dprintk("nfsd_dispatch: vers %d proc %d\n",
				rqstp->rq_vers, rqstp->rq_proc);
	proc = rqstp->rq_procinfo;

	/*
	 * Give the xdr decoder a chance to change this if it wants
	 * (necessary in the NFSv4.0 compound case)
	 */
	rqstp->rq_cachetype = proc->pc_cachetype;
	/* Decode arguments */
	xdr = proc->pc_decode;
	if (xdr && !xdr(rqstp, (__be32*)rqstp->rq_arg.head[0].iov_base,
			rqstp->rq_argp)) {
		dprintk("nfsd: failed to decode arguments!\n");
		*statp = rpc_garbage_args;
		return 1;
	}

	/* Check whether we have this call in the cache. */
	switch (nfsd_cache_lookup(rqstp)) {
	case RC_DROPIT:
		return 0;
	case RC_REPLY:
		return 1;
	case RC_DOIT:;
		/* do it */
	}

	/* need to grab the location to store the status, as
	 * nfsv4 does some encoding while processing 
	 */
	nfserrp = rqstp->rq_res.head[0].iov_base
		+ rqstp->rq_res.head[0].iov_len;
	rqstp->rq_res.head[0].iov_len += sizeof(__be32);

	/* Now call the procedure handler, and encode NFS status. */
	nfserr = proc->pc_func(rqstp, rqstp->rq_argp, rqstp->rq_resp);
	nfserr = map_new_errors(rqstp->rq_vers, nfserr);
	if (nfserr == nfserr_dropit || test_bit(RQ_DROPME, &rqstp->rq_flags)) {
		dprintk("nfsd: Dropping request; may be revisited later\n");
		nfsd_cache_update(rqstp, RC_NOCACHE, NULL);
		return 0;
	}

	if (rqstp->rq_proc != 0)
		*nfserrp++ = nfserr;

	/* Encode result.
	 * For NFSv2, additional info is never returned in case of an error.
	 */
	if (!(nfserr && rqstp->rq_vers == 2)) {
		xdr = proc->pc_encode;
		if (xdr && !xdr(rqstp, nfserrp,
				rqstp->rq_resp)) {
			/* Failed to encode result. Release cache entry */
			dprintk("nfsd: failed to encode result!\n");
			nfsd_cache_update(rqstp, RC_NOCACHE, NULL);
			*statp = rpc_system_err;
			return 1;
		}
	}

	/* Store reply in cache. */
	nfsd_cache_update(rqstp, rqstp->rq_cachetype, statp + 1);
	return 1;
}

int nfsd_pool_stats_open(struct inode *inode, struct file *file)
{
	int ret;
	struct nfsd_net *nn = net_generic(inode->i_sb->s_fs_info, nfsd_net_id);

	mutex_lock(&nfsd_mutex);
	if (nn->nfsd_serv == NULL) {
		mutex_unlock(&nfsd_mutex);
		return -ENODEV;
	}
	/* bump up the psudo refcount while traversing */
	svc_get(nn->nfsd_serv);
	ret = svc_pool_stats_open(nn->nfsd_serv, file);
	mutex_unlock(&nfsd_mutex);
	return ret;
}

int nfsd_pool_stats_release(struct inode *inode, struct file *file)
{
	int ret = seq_release(inode, file);
	struct net *net = inode->i_sb->s_fs_info;

	mutex_lock(&nfsd_mutex);
	/* this function really, really should have been called svc_put() */
	nfsd_destroy(net);
	mutex_unlock(&nfsd_mutex);
	return ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfssvc.c */
/************************************************************/
/*
 * Syscall interface to knfsd.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/ctype.h>
#include "../../inc/__fss.h"

// #include <linux/sunrpc/svcsock.h>
#include <linux/lockd/lockd.h>
#include <linux/sunrpc/addr.h>
#include <linux/sunrpc/gss_api.h>
#include <linux/sunrpc/gss_krb5_enctypes.h>
#include <linux/sunrpc/rpc_pipe_fs.h>
// #include <linux/module.h>
#include "../../inc/__fss.h"

#include "idmap.h"
// #include "nfsd.h"
// #include "cache.h"
// #include "state.h"
// #include "netns.h"
#include "pnfs.h"
#include "../../inc/__fss.h"

/*
 *	We have a single directory with several nodes in it.
 */
enum {
	NFSD_Root = 1,
	NFSD_List,
	NFSD_Export_features,
	NFSD_Fh,
	NFSD_FO_UnlockIP,
	NFSD_FO_UnlockFS,
	NFSD_Threads,
	NFSD_Pool_Threads,
	NFSD_Pool_Stats,
	NFSD_Reply_Cache_Stats,
	NFSD_Versions,
	NFSD_Ports,
	NFSD_MaxBlkSize,
	NFSD_MaxConnections,
	NFSD_SupportedEnctypes,
	/*
	 * The below MUST come last.  Otherwise we leave a hole in nfsd_files[]
	 * with !CONFIG_NFSD_V4 and simple_fill_super() goes oops
	 */
#ifdef CONFIG_NFSD_V4
	NFSD_Leasetime,
	NFSD_Gracetime,
	NFSD_RecoveryDir,
	NFSD_V4EndGrace,
#endif
};

/*
 * write() for these nodes.
 */
static ssize_t write_filehandle(struct file *file, char *buf, size_t size);
static ssize_t write_unlock_ip(struct file *file, char *buf, size_t size);
static ssize_t write_unlock_fs(struct file *file, char *buf, size_t size);
static ssize_t write_threads(struct file *file, char *buf, size_t size);
static ssize_t write_pool_threads(struct file *file, char *buf, size_t size);
static ssize_t write_versions(struct file *file, char *buf, size_t size);
static ssize_t write_ports(struct file *file, char *buf, size_t size);
static ssize_t write_maxblksize(struct file *file, char *buf, size_t size);
static ssize_t write_maxconn(struct file *file, char *buf, size_t size);
#ifdef CONFIG_NFSD_V4
static ssize_t write_leasetime(struct file *file, char *buf, size_t size);
static ssize_t write_gracetime(struct file *file, char *buf, size_t size);
static ssize_t write_recoverydir(struct file *file, char *buf, size_t size);
static ssize_t write_v4_end_grace(struct file *file, char *buf, size_t size);
#endif

static ssize_t (*write_op[])(struct file *, char *, size_t) = {
	[NFSD_Fh] = write_filehandle,
	[NFSD_FO_UnlockIP] = write_unlock_ip,
	[NFSD_FO_UnlockFS] = write_unlock_fs,
	[NFSD_Threads] = write_threads,
	[NFSD_Pool_Threads] = write_pool_threads,
	[NFSD_Versions] = write_versions,
	[NFSD_Ports] = write_ports,
	[NFSD_MaxBlkSize] = write_maxblksize,
	[NFSD_MaxConnections] = write_maxconn,
#ifdef CONFIG_NFSD_V4
	[NFSD_Leasetime] = write_leasetime,
	[NFSD_Gracetime] = write_gracetime,
	[NFSD_RecoveryDir] = write_recoverydir,
	[NFSD_V4EndGrace] = write_v4_end_grace,
#endif
};

static ssize_t nfsctl_transaction_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	ino_t ino =  file_inode(file)->i_ino;
	char *data;
	ssize_t rv;

	if (ino >= ARRAY_SIZE(write_op) || !write_op[ino])
		return -EINVAL;

	data = simple_transaction_get(file, buf, size);
	if (IS_ERR(data))
		return PTR_ERR(data);

	rv =  write_op[ino](file, data, size);
	if (rv >= 0) {
		simple_transaction_set(file, rv);
		rv = size;
	}
	return rv;
}

static ssize_t nfsctl_transaction_read(struct file *file, char __user *buf, size_t size, loff_t *pos)
{
	if (! file->private_data) {
		/* An attempt to read a transaction file without writing
		 * causes a 0-byte write so that the file can return
		 * state information
		 */
		ssize_t rv = nfsctl_transaction_write(file, buf, 0, pos);
		if (rv < 0)
			return rv;
	}
	return simple_transaction_read(file, buf, size, pos);
}

static const struct file_operations transaction_ops = {
	.write		= nfsctl_transaction_write,
	.read		= nfsctl_transaction_read,
	.release	= simple_transaction_release,
	.llseek		= default_llseek,
};

static int exports_net_open(struct net *net, struct file *file)
{
	int err;
	struct seq_file *seq;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	err = seq_open(file, &nfs_exports_op);
	if (err)
		return err;

	seq = file->private_data;
	seq->private = nn->svc_export_cache;
	return 0;
}

static int exports_proc_open(struct inode *inode, struct file *file)
{
	return exports_net_open(current->nsproxy->net_ns, file);
}

static const struct file_operations exports_proc_operations = {
	.open		= exports_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
	.owner		= THIS_MODULE,
};

static int exports_nfsd_open(struct inode *inode, struct file *file)
{
	return exports_net_open(inode->i_sb->s_fs_info, file);
}

static const struct file_operations exports_nfsd_operations = {
	.open		= exports_nfsd_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
	.owner		= THIS_MODULE,
};

static int export_features_show(struct seq_file *m, void *v)
{
	seq_printf(m, "0x%x 0x%x\n", NFSEXP_ALLFLAGS, NFSEXP_SECINFO_FLAGS);
	return 0;
}

static int export_features_open(struct inode *inode, struct file *file)
{
	return single_open(file, export_features_show, NULL);
}

static const struct file_operations export_features_operations = {
	.open		= export_features_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#if defined(CONFIG_SUNRPC_GSS) || defined(CONFIG_SUNRPC_GSS_MODULE)
static int supported_enctypes_show(struct seq_file *m, void *v)
{
	seq_printf(m, KRB5_SUPPORTED_ENCTYPES);
	return 0;
}

static int supported_enctypes_open(struct inode *inode, struct file *file)
{
	return single_open(file, supported_enctypes_show, NULL);
}

static const struct file_operations supported_enctypes_ops = {
	.open		= supported_enctypes_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif /* CONFIG_SUNRPC_GSS or CONFIG_SUNRPC_GSS_MODULE */

static const struct file_operations pool_stats_operations = {
	.open		= nfsd_pool_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= nfsd_pool_stats_release,
	.owner		= THIS_MODULE,
};

static struct file_operations reply_cache_stats_operations = {
	.open		= nfsd_reply_cache_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*----------------------------------------------------------------------------*/
/*
 * payload - write methods
 */

static inline struct net *netns(struct file *file)
{
	return file_inode(file)->i_sb->s_fs_info;
}

/**
 * write_unlock_ip - Release all locks used by a client
 *
 * Experimental.
 *
 * Input:
 *			buf:	'\n'-terminated C string containing a
 *				presentation format IP address
 *			size:	length of C string in @buf
 * Output:
 *	On success:	returns zero if all specified locks were released;
 *			returns one if one or more locks were not released
 *	On error:	return code is negative errno value
 */
static ssize_t write_unlock_ip(struct file *file, char *buf, size_t size)
{
	struct sockaddr_storage address;
	struct sockaddr *sap = (struct sockaddr *)&address;
	size_t salen = sizeof(address);
	char *fo_path;
	struct net *net = netns(file);

	/* sanity check */
	if (size == 0)
		return -EINVAL;

	if (buf[size-1] != '\n')
		return -EINVAL;

	fo_path = buf;
	if (qword_get(&buf, fo_path, size) < 0)
		return -EINVAL;

	if (rpc_pton(net, fo_path, size, sap, salen) == 0)
		return -EINVAL;

	return nlmsvc_unlock_all_by_ip(sap);
}

/**
 * write_unlock_fs - Release all locks on a local file system
 *
 * Experimental.
 *
 * Input:
 *			buf:	'\n'-terminated C string containing the
 *				absolute pathname of a local file system
 *			size:	length of C string in @buf
 * Output:
 *	On success:	returns zero if all specified locks were released;
 *			returns one if one or more locks were not released
 *	On error:	return code is negative errno value
 */
static ssize_t write_unlock_fs(struct file *file, char *buf, size_t size)
{
	struct path path;
	char *fo_path;
	int error;

	/* sanity check */
	if (size == 0)
		return -EINVAL;

	if (buf[size-1] != '\n')
		return -EINVAL;

	fo_path = buf;
	if (qword_get(&buf, fo_path, size) < 0)
		return -EINVAL;

	error = kern_path(fo_path, 0, &path);
	if (error)
		return error;

	/*
	 * XXX: Needs better sanity checking.  Otherwise we could end up
	 * releasing locks on the wrong file system.
	 *
	 * For example:
	 * 1.  Does the path refer to a directory?
	 * 2.  Is that directory a mount point, or
	 * 3.  Is that directory the root of an exported file system?
	 */
	error = nlmsvc_unlock_all_by_sb(path.dentry->d_sb);

	path_put(&path);
	return error;
}

/**
 * write_filehandle - Get a variable-length NFS file handle by path
 *
 * On input, the buffer contains a '\n'-terminated C string comprised of
 * three alphanumeric words separated by whitespace.  The string may
 * contain escape sequences.
 *
 * Input:
 *			buf:
 *				domain:		client domain name
 *				path:		export pathname
 *				maxsize:	numeric maximum size of
 *						@buf
 *			size:	length of C string in @buf
 * Output:
 *	On success:	passed-in buffer filled with '\n'-terminated C
 *			string containing a ASCII hex text version
 *			of the NFS file handle;
 *			return code is the size in bytes of the string
 *	On error:	return code is negative errno value
 */
static ssize_t write_filehandle(struct file *file, char *buf, size_t size)
{
	char *dname, *path;
	int uninitialized_var(maxsize);
	char *mesg = buf;
	int len;
	struct auth_domain *dom;
	struct knfsd_fh fh;

	if (size == 0)
		return -EINVAL;

	if (buf[size-1] != '\n')
		return -EINVAL;
	buf[size-1] = 0;

	dname = mesg;
	len = qword_get(&mesg, dname, size);
	if (len <= 0)
		return -EINVAL;
	
	path = dname+len+1;
	len = qword_get(&mesg, path, size);
	if (len <= 0)
		return -EINVAL;

	len = get_int(&mesg, &maxsize);
	if (len)
		return len;

	if (maxsize < NFS_FHSIZE)
		return -EINVAL;
	maxsize = min(maxsize, NFS3_FHSIZE);

	if (qword_get(&mesg, mesg, size)>0)
		return -EINVAL;

	/* we have all the words, they are in buf.. */
	dom = unix_domain_find(dname);
	if (!dom)
		return -ENOMEM;

	len = exp_rootfh(netns(file), dom, path, &fh,  maxsize);
	auth_domain_put(dom);
	if (len)
		return len;
	
	mesg = buf;
	len = SIMPLE_TRANSACTION_LIMIT;
	qword_addhex(&mesg, &len, (char*)&fh.fh_base, fh.fh_size);
	mesg[-1] = '\n';
	return mesg - buf;	
}

/**
 * write_threads - Start NFSD, or report the current number of running threads
 *
 * Input:
 *			buf:		ignored
 *			size:		zero
 * Output:
 *	On success:	passed-in buffer filled with '\n'-terminated C
 *			string numeric value representing the number of
 *			running NFSD threads;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero
 *
 * OR
 *
 * Input:
 *			buf:		C string containing an unsigned
 *					integer value representing the
 *					number of NFSD threads to start
 *			size:		non-zero length of C string in @buf
 * Output:
 *	On success:	NFS service is started;
 *			passed-in buffer filled with '\n'-terminated C
 *			string numeric value representing the number of
 *			running NFSD threads;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero or a negative errno value
 */
static ssize_t write_threads(struct file *file, char *buf, size_t size)
{
	char *mesg = buf;
	int rv;
	struct net *net = netns(file);

	if (size > 0) {
		int newthreads;
		rv = get_int(&mesg, &newthreads);
		if (rv)
			return rv;
		if (newthreads < 0)
			return -EINVAL;
		rv = nfsd_svc(newthreads, net);
		if (rv < 0)
			return rv;
	} else
		rv = nfsd_nrthreads(net);

	return scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%d\n", rv);
}

/**
 * write_pool_threads - Set or report the current number of threads per pool
 *
 * Input:
 *			buf:		ignored
 *			size:		zero
 *
 * OR
 *
 * Input:
 * 			buf:		C string containing whitespace-
 * 					separated unsigned integer values
 *					representing the number of NFSD
 *					threads to start in each pool
 *			size:		non-zero length of C string in @buf
 * Output:
 *	On success:	passed-in buffer filled with '\n'-terminated C
 *			string containing integer values representing the
 *			number of NFSD threads in each pool;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero or a negative errno value
 */
static ssize_t write_pool_threads(struct file *file, char *buf, size_t size)
{
	/* if size > 0, look for an array of number of threads per node
	 * and apply them  then write out number of threads per node as reply
	 */
	char *mesg = buf;
	int i;
	int rv;
	int len;
	int npools;
	int *nthreads;
	struct net *net = netns(file);

	mutex_lock(&nfsd_mutex);
	npools = nfsd_nrpools(net);
	if (npools == 0) {
		/*
		 * NFS is shut down.  The admin can start it by
		 * writing to the threads file but NOT the pool_threads
		 * file, sorry.  Report zero threads.
		 */
		mutex_unlock(&nfsd_mutex);
		strcpy(buf, "0\n");
		return strlen(buf);
	}

	nthreads = kcalloc(npools, sizeof(int), GFP_KERNEL);
	rv = -ENOMEM;
	if (nthreads == NULL)
		goto out_free;

	if (size > 0) {
		for (i = 0; i < npools; i++) {
			rv = get_int(&mesg, &nthreads[i]);
			if (rv == -ENOENT)
				break;		/* fewer numbers than pools */
			if (rv)
				goto out_free;	/* syntax error */
			rv = -EINVAL;
			if (nthreads[i] < 0)
				goto out_free;
		}
		rv = nfsd_set_nrthreads(i, nthreads, net);
		if (rv)
			goto out_free;
	}

	rv = nfsd_get_nrthreads(npools, nthreads, net);
	if (rv)
		goto out_free;

	mesg = buf;
	size = SIMPLE_TRANSACTION_LIMIT;
	for (i = 0; i < npools && size > 0; i++) {
		snprintf(mesg, size, "%d%c", nthreads[i], (i == npools-1 ? '\n' : ' '));
		len = strlen(mesg);
		size -= len;
		mesg += len;
	}
	rv = mesg - buf;
out_free:
	kfree(nthreads);
	mutex_unlock(&nfsd_mutex);
	return rv;
}

static ssize_t __write_versions(struct file *file, char *buf, size_t size)
{
	char *mesg = buf;
	char *vers, *minorp, sign;
	int len, num, remaining;
	unsigned minor;
	ssize_t tlen = 0;
	char *sep;
	struct nfsd_net *nn = net_generic(netns(file), nfsd_net_id);

	if (size>0) {
		if (nn->nfsd_serv)
			/* Cannot change versions without updating
			 * nn->nfsd_serv->sv_xdrsize, and reallocing
			 * rq_argp and rq_resp
			 */
			return -EBUSY;
		if (buf[size-1] != '\n')
			return -EINVAL;
		buf[size-1] = 0;

		vers = mesg;
		len = qword_get(&mesg, vers, size);
		if (len <= 0) return -EINVAL;
		do {
			sign = *vers;
			if (sign == '+' || sign == '-')
				num = simple_strtol((vers+1), &minorp, 0);
			else
				num = simple_strtol(vers, &minorp, 0);
			if (*minorp == '.') {
				if (num != 4)
					return -EINVAL;
				minor = simple_strtoul(minorp+1, NULL, 0);
				if (minor == 0)
					return -EINVAL;
				if (nfsd_minorversion(minor, sign == '-' ?
						     NFSD_CLEAR : NFSD_SET) < 0)
					return -EINVAL;
				goto next;
			}
			switch(num) {
			case 2:
			case 3:
			case 4:
				nfsd_vers(num, sign == '-' ? NFSD_CLEAR : NFSD_SET);
				break;
			default:
				return -EINVAL;
			}
		next:
			vers += len + 1;
		} while ((len = qword_get(&mesg, vers, size)) > 0);
		/* If all get turned off, turn them back on, as
		 * having no versions is BAD
		 */
		nfsd_reset_versions();
	}

	/* Now write current state into reply buffer */
	len = 0;
	sep = "";
	remaining = SIMPLE_TRANSACTION_LIMIT;
	for (num=2 ; num <= 4 ; num++)
		if (nfsd_vers(num, NFSD_AVAIL)) {
			len = snprintf(buf, remaining, "%s%c%d", sep,
				       nfsd_vers(num, NFSD_TEST)?'+':'-',
				       num);
			sep = " ";

			if (len >= remaining)
				break;
			remaining -= len;
			buf += len;
			tlen += len;
		}
	if (nfsd_vers(4, NFSD_AVAIL))
		for (minor = 1; minor <= NFSD_SUPPORTED_MINOR_VERSION;
		     minor++) {
			len = snprintf(buf, remaining, " %c4.%u",
					(nfsd_vers(4, NFSD_TEST) &&
					 nfsd_minorversion(minor, NFSD_TEST)) ?
						'+' : '-',
					minor);

			if (len >= remaining)
				break;
			remaining -= len;
			buf += len;
			tlen += len;
		}

	len = snprintf(buf, remaining, "\n");
	if (len >= remaining)
		return -EINVAL;
	return tlen + len;
}

/**
 * write_versions - Set or report the available NFS protocol versions
 *
 * Input:
 *			buf:		ignored
 *			size:		zero
 * Output:
 *	On success:	passed-in buffer filled with '\n'-terminated C
 *			string containing positive or negative integer
 *			values representing the current status of each
 *			protocol version;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero or a negative errno value
 *
 * OR
 *
 * Input:
 * 			buf:		C string containing whitespace-
 * 					separated positive or negative
 * 					integer values representing NFS
 * 					protocol versions to enable ("+n")
 * 					or disable ("-n")
 *			size:		non-zero length of C string in @buf
 * Output:
 *	On success:	status of zero or more protocol versions has
 *			been updated; passed-in buffer filled with
 *			'\n'-terminated C string containing positive
 *			or negative integer values representing the
 *			current status of each protocol version;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero or a negative errno value
 */
static ssize_t write_versions(struct file *file, char *buf, size_t size)
{
	ssize_t rv;

	mutex_lock(&nfsd_mutex);
	rv = __write_versions(file, buf, size);
	mutex_unlock(&nfsd_mutex);
	return rv;
}

/*
 * Zero-length write.  Return a list of NFSD's current listener
 * transports.
 */
static ssize_t __write_ports_names(char *buf, struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	if (nn->nfsd_serv == NULL)
		return 0;
	return svc_xprt_names(nn->nfsd_serv, buf, SIMPLE_TRANSACTION_LIMIT);
}

/*
 * A single 'fd' number was written, in which case it must be for
 * a socket of a supported family/protocol, and we use it as an
 * nfsd listener.
 */
static ssize_t __write_ports_addfd(char *buf, struct net *net)
{
	char *mesg = buf;
	int fd, err;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	err = get_int(&mesg, &fd);
	if (err != 0 || fd < 0)
		return -EINVAL;

	if (svc_alien_sock(net, fd)) {
		printk(KERN_ERR "%s: socket net is different to NFSd's one\n", __func__);
		return -EINVAL;
	}

	err = nfsd_create_serv(net);
	if (err != 0)
		return err;

	err = svc_addsock(nn->nfsd_serv, fd, buf, SIMPLE_TRANSACTION_LIMIT);
	if (err < 0) {
		nfsd_destroy(net);
		return err;
	}

	/* Decrease the count, but don't shut down the service */
	nn->nfsd_serv->sv_nrthreads--;
	return err;
}

/*
 * A transport listener is added by writing it's transport name and
 * a port number.
 */
static ssize_t __write_ports_addxprt(char *buf, struct net *net)
{
	char transport[16];
	struct svc_xprt *xprt;
	int port, err;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	if (sscanf(buf, "%15s %5u", transport, &port) != 2)
		return -EINVAL;

	if (port < 1 || port > USHRT_MAX)
		return -EINVAL;

	err = nfsd_create_serv(net);
	if (err != 0)
		return err;

	err = svc_create_xprt(nn->nfsd_serv, transport, net,
				PF_INET, port, SVC_SOCK_ANONYMOUS);
	if (err < 0)
		goto out_err;

	err = svc_create_xprt(nn->nfsd_serv, transport, net,
				PF_INET6, port, SVC_SOCK_ANONYMOUS);
	if (err < 0 && err != -EAFNOSUPPORT)
		goto out_close;

	/* Decrease the count, but don't shut down the service */
	nn->nfsd_serv->sv_nrthreads--;
	return 0;
out_close:
	xprt = svc_find_xprt(nn->nfsd_serv, transport, net, PF_INET, port);
	if (xprt != NULL) {
		svc_close_xprt(xprt);
		svc_xprt_put(xprt);
	}
out_err:
	nfsd_destroy(net);
	return err;
}

static ssize_t __write_ports(struct file *file, char *buf, size_t size,
			     struct net *net)
{
	if (size == 0)
		return __write_ports_names(buf, net);

	if (isdigit(buf[0]))
		return __write_ports_addfd(buf, net);

	if (isalpha(buf[0]))
		return __write_ports_addxprt(buf, net);

	return -EINVAL;
}

/**
 * write_ports - Pass a socket file descriptor or transport name to listen on
 *
 * Input:
 *			buf:		ignored
 *			size:		zero
 * Output:
 *	On success:	passed-in buffer filled with a '\n'-terminated C
 *			string containing a whitespace-separated list of
 *			named NFSD listeners;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero or a negative errno value
 *
 * OR
 *
 * Input:
 *			buf:		C string containing an unsigned
 *					integer value representing a bound
 *					but unconnected socket that is to be
 *					used as an NFSD listener; listen(3)
 *					must be called for a SOCK_STREAM
 *					socket, otherwise it is ignored
 *			size:		non-zero length of C string in @buf
 * Output:
 *	On success:	NFS service is started;
 *			passed-in buffer filled with a '\n'-terminated C
 *			string containing a unique alphanumeric name of
 *			the listener;
 *			return code is the size in bytes of the string
 *	On error:	return code is a negative errno value
 *
 * OR
 *
 * Input:
 *			buf:		C string containing a transport
 *					name and an unsigned integer value
 *					representing the port to listen on,
 *					separated by whitespace
 *			size:		non-zero length of C string in @buf
 * Output:
 *	On success:	returns zero; NFS service is started
 *	On error:	return code is a negative errno value
 */
static ssize_t write_ports(struct file *file, char *buf, size_t size)
{
	ssize_t rv;

	mutex_lock(&nfsd_mutex);
	rv = __write_ports(file, buf, size, netns(file));
	mutex_unlock(&nfsd_mutex);
	return rv;
}


int nfsd_max_blksize;

/**
 * write_maxblksize - Set or report the current NFS blksize
 *
 * Input:
 *			buf:		ignored
 *			size:		zero
 *
 * OR
 *
 * Input:
 * 			buf:		C string containing an unsigned
 * 					integer value representing the new
 * 					NFS blksize
 *			size:		non-zero length of C string in @buf
 * Output:
 *	On success:	passed-in buffer filled with '\n'-terminated C string
 *			containing numeric value of the current NFS blksize
 *			setting;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero or a negative errno value
 */
static ssize_t write_maxblksize(struct file *file, char *buf, size_t size)
{
	char *mesg = buf;
	struct nfsd_net *nn = net_generic(netns(file), nfsd_net_id);

	if (size > 0) {
		int bsize;
		int rv = get_int(&mesg, &bsize);
		if (rv)
			return rv;
		/* force bsize into allowed range and
		 * required alignment.
		 */
		bsize = max_t(int, bsize, 1024);
		bsize = min_t(int, bsize, NFSSVC_MAXBLKSIZE);
		bsize &= ~(1024-1);
		mutex_lock(&nfsd_mutex);
		if (nn->nfsd_serv) {
			mutex_unlock(&nfsd_mutex);
			return -EBUSY;
		}
		nfsd_max_blksize = bsize;
		mutex_unlock(&nfsd_mutex);
	}

	return scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%d\n",
							nfsd_max_blksize);
}

/**
 * write_maxconn - Set or report the current max number of connections
 *
 * Input:
 *			buf:		ignored
 *			size:		zero
 * OR
 *
 * Input:
 * 			buf:		C string containing an unsigned
 * 					integer value representing the new
 * 					number of max connections
 *			size:		non-zero length of C string in @buf
 * Output:
 *	On success:	passed-in buffer filled with '\n'-terminated C string
 *			containing numeric value of max_connections setting
 *			for this net namespace;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero or a negative errno value
 */
static ssize_t write_maxconn(struct file *file, char *buf, size_t size)
{
	char *mesg = buf;
	struct nfsd_net *nn = net_generic(netns(file), nfsd_net_id);
	unsigned int maxconn = nn->max_connections;

	if (size > 0) {
		int rv = get_uint(&mesg, &maxconn);

		if (rv)
			return rv;
		nn->max_connections = maxconn;
	}

	return scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%u\n", maxconn);
}

#ifdef CONFIG_NFSD_V4
static ssize_t __nfsd4_write_time(struct file *file, char *buf, size_t size,
				  time_t *time, struct nfsd_net *nn)
{
	char *mesg = buf;
	int rv, i;

	if (size > 0) {
		if (nn->nfsd_serv)
			return -EBUSY;
		rv = get_int(&mesg, &i);
		if (rv)
			return rv;
		/*
		 * Some sanity checking.  We don't have a reason for
		 * these particular numbers, but problems with the
		 * extremes are:
		 *	- Too short: the briefest network outage may
		 *	  cause clients to lose all their locks.  Also,
		 *	  the frequent polling may be wasteful.
		 *	- Too long: do you really want reboot recovery
		 *	  to take more than an hour?  Or to make other
		 *	  clients wait an hour before being able to
		 *	  revoke a dead client's locks?
		 */
		if (i < 10 || i > 3600)
			return -EINVAL;
		*time = i;
	}

	return scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%ld\n", *time);
}

static ssize_t nfsd4_write_time(struct file *file, char *buf, size_t size,
				time_t *time, struct nfsd_net *nn)
{
	ssize_t rv;

	mutex_lock(&nfsd_mutex);
	rv = __nfsd4_write_time(file, buf, size, time, nn);
	mutex_unlock(&nfsd_mutex);
	return rv;
}

/**
 * write_leasetime - Set or report the current NFSv4 lease time
 *
 * Input:
 *			buf:		ignored
 *			size:		zero
 *
 * OR
 *
 * Input:
 *			buf:		C string containing an unsigned
 *					integer value representing the new
 *					NFSv4 lease expiry time
 *			size:		non-zero length of C string in @buf
 * Output:
 *	On success:	passed-in buffer filled with '\n'-terminated C
 *			string containing unsigned integer value of the
 *			current lease expiry time;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero or a negative errno value
 */
static ssize_t write_leasetime(struct file *file, char *buf, size_t size)
{
	struct nfsd_net *nn = net_generic(netns(file), nfsd_net_id);
	return nfsd4_write_time(file, buf, size, &nn->nfsd4_lease, nn);
}

/**
 * write_gracetime - Set or report current NFSv4 grace period time
 *
 * As above, but sets the time of the NFSv4 grace period.
 *
 * Note this should never be set to less than the *previous*
 * lease-period time, but we don't try to enforce this.  (In the common
 * case (a new boot), we don't know what the previous lease time was
 * anyway.)
 */
static ssize_t write_gracetime(struct file *file, char *buf, size_t size)
{
	struct nfsd_net *nn = net_generic(netns(file), nfsd_net_id);
	return nfsd4_write_time(file, buf, size, &nn->nfsd4_grace, nn);
}

static ssize_t __write_recoverydir(struct file *file, char *buf, size_t size,
				   struct nfsd_net *nn)
{
	char *mesg = buf;
	char *recdir;
	int len, status;

	if (size > 0) {
		if (nn->nfsd_serv)
			return -EBUSY;
		if (size > PATH_MAX || buf[size-1] != '\n')
			return -EINVAL;
		buf[size-1] = 0;

		recdir = mesg;
		len = qword_get(&mesg, recdir, size);
		if (len <= 0)
			return -EINVAL;

		status = nfs4_reset_recoverydir(recdir);
		if (status)
			return status;
	}

	return scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%s\n",
							nfs4_recoverydir());
}

/**
 * write_recoverydir - Set or report the pathname of the recovery directory
 *
 * Input:
 *			buf:		ignored
 *			size:		zero
 *
 * OR
 *
 * Input:
 *			buf:		C string containing the pathname
 *					of the directory on a local file
 *					system containing permanent NFSv4
 *					recovery data
 *			size:		non-zero length of C string in @buf
 * Output:
 *	On success:	passed-in buffer filled with '\n'-terminated C string
 *			containing the current recovery pathname setting;
 *			return code is the size in bytes of the string
 *	On error:	return code is zero or a negative errno value
 */
static ssize_t write_recoverydir(struct file *file, char *buf, size_t size)
{
	ssize_t rv;
	struct nfsd_net *nn = net_generic(netns(file), nfsd_net_id);

	mutex_lock(&nfsd_mutex);
	rv = __write_recoverydir(file, buf, size, nn);
	mutex_unlock(&nfsd_mutex);
	return rv;
}

/**
 * write_v4_end_grace - release grace period for nfsd's v4.x lock manager
 *
 * Input:
 *			buf:		ignored
 *			size:		zero
 * OR
 *
 * Input:
 * 			buf:		any value
 *			size:		non-zero length of C string in @buf
 * Output:
 *			passed-in buffer filled with "Y" or "N" with a newline
 *			and NULL-terminated C string. This indicates whether
 *			the grace period has ended in the current net
 *			namespace. Return code is the size in bytes of the
 *			string. Writing a string that starts with 'Y', 'y', or
 *			'1' to the file will end the grace period for nfsd's v4
 *			lock manager.
 */
static ssize_t write_v4_end_grace(struct file *file, char *buf, size_t size)
{
	struct nfsd_net *nn = net_generic(netns(file), nfsd_net_id);

	if (size > 0) {
		switch(buf[0]) {
		case 'Y':
		case 'y':
		case '1':
			nfsd4_end_grace(nn);
			break;
		default:
			return -EINVAL;
		}
	}

	return scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%c\n",
			 nn->grace_ended ? 'Y' : 'N');
}

#endif

/*----------------------------------------------------------------------------*/
/*
 *	populating the filesystem.
 */

static int nfsd_fill_super(struct super_block * sb, void * data, int silent)
{
	static struct tree_descr nfsd_files[] = {
		[NFSD_List] = {"exports", &exports_nfsd_operations, S_IRUGO},
		[NFSD_Export_features] = {"export_features",
					&export_features_operations, S_IRUGO},
		[NFSD_FO_UnlockIP] = {"unlock_ip",
					&transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_FO_UnlockFS] = {"unlock_filesystem",
					&transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Fh] = {"filehandle", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Threads] = {"threads", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Pool_Threads] = {"pool_threads", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Pool_Stats] = {"pool_stats", &pool_stats_operations, S_IRUGO},
		[NFSD_Reply_Cache_Stats] = {"reply_cache_stats", &reply_cache_stats_operations, S_IRUGO},
		[NFSD_Versions] = {"versions", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Ports] = {"portlist", &transaction_ops, S_IWUSR|S_IRUGO},
		[NFSD_MaxBlkSize] = {"max_block_size", &transaction_ops, S_IWUSR|S_IRUGO},
		[NFSD_MaxConnections] = {"max_connections", &transaction_ops, S_IWUSR|S_IRUGO},
#if defined(CONFIG_SUNRPC_GSS) || defined(CONFIG_SUNRPC_GSS_MODULE)
		[NFSD_SupportedEnctypes] = {"supported_krb5_enctypes", &supported_enctypes_ops, S_IRUGO},
#endif /* CONFIG_SUNRPC_GSS or CONFIG_SUNRPC_GSS_MODULE */
#ifdef CONFIG_NFSD_V4
		[NFSD_Leasetime] = {"nfsv4leasetime", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_Gracetime] = {"nfsv4gracetime", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_RecoveryDir] = {"nfsv4recoverydir", &transaction_ops, S_IWUSR|S_IRUSR},
		[NFSD_V4EndGrace] = {"v4_end_grace", &transaction_ops, S_IWUSR|S_IRUGO},
#endif
		/* last one */ {""}
	};
	struct net *net = data;
	int ret;

	ret = simple_fill_super(sb, 0x6e667364, nfsd_files);
	if (ret)
		return ret;
	sb->s_fs_info = get_net(net);
	return 0;
}

static struct dentry *nfsd_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_ns(fs_type, flags, current->nsproxy->net_ns, nfsd_fill_super);
}

static void nfsd_umount(struct super_block *sb)
{
	struct net *net = sb->s_fs_info;

	kill_litter_super(sb);
	put_net(net);
}

static struct file_system_type nfsd_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "nfsd",
	.mount		= nfsd_mount,
	.kill_sb	= nfsd_umount,
};
MODULE_ALIAS_FS("nfsd");

#ifdef CONFIG_PROC_FS
static int create_proc_exports_entry(void)
{
	struct proc_dir_entry *entry;

	entry = proc_mkdir("fs/nfs", NULL);
	if (!entry)
		return -ENOMEM;
	entry = proc_create("exports", 0, entry,
				 &exports_proc_operations);
	if (!entry) {
		remove_proc_entry("fs/nfs", NULL);
		return -ENOMEM;
	}
	return 0;
}
#else /* CONFIG_PROC_FS */
static int create_proc_exports_entry(void)
{
	return 0;
}
#endif

int nfsd_net_id;

static __net_init int nfsd_init_net(struct net *net)
{
	int retval;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	retval = nfsd_export_init(net);
	if (retval)
		goto out_export_error;
	retval = nfsd_idmap_init(net);
	if (retval)
		goto out_idmap_error;
	nn->nfsd4_lease = 90;	/* default lease time */
	nn->nfsd4_grace = 90;
	return 0;

out_idmap_error:
	nfsd_export_shutdown(net);
out_export_error:
	return retval;
}

static __net_exit void nfsd_exit_net(struct net *net)
{
	nfsd_idmap_shutdown(net);
	nfsd_export_shutdown(net);
}

static struct pernet_operations nfsd_net_ops = {
	.init = nfsd_init_net,
	.exit = nfsd_exit_net,
	.id   = &nfsd_net_id,
	.size = sizeof(struct nfsd_net),
};

static int __init init_nfsd(void)
{
	int retval;
	printk(KERN_INFO "Installing knfsd (copyright (C) 1996 okir@monad.swb.de).\n");

	retval = register_cld_notifier();
	if (retval)
		return retval;
	retval = register_pernet_subsys(&nfsd_net_ops);
	if (retval < 0)
		goto out_unregister_notifier;
	retval = nfsd4_init_slabs();
	if (retval)
		goto out_unregister_pernet;
	retval = nfsd4_init_pnfs();
	if (retval)
		goto out_free_slabs;
	retval = nfsd_fault_inject_init(); /* nfsd fault injection controls */
	if (retval)
		goto out_exit_pnfs;
	nfsd_stat_init();	/* Statistics */
	retval = nfsd_reply_cache_init();
	if (retval)
		goto out_free_stat;
	nfsd_lockd_init();	/* lockd->nfsd callbacks */
	retval = create_proc_exports_entry();
	if (retval)
		goto out_free_lockd;
	retval = register_filesystem(&nfsd_fs_type);
	if (retval)
		goto out_free_all;
	return 0;
out_free_all:
	remove_proc_entry("fs/nfs/exports", NULL);
	remove_proc_entry("fs/nfs", NULL);
out_free_lockd:
	nfsd_lockd_shutdown();
	nfsd_reply_cache_shutdown();
out_free_stat:
	nfsd_stat_shutdown();
	nfsd_fault_inject_cleanup();
out_exit_pnfs:
	nfsd4_exit_pnfs();
out_free_slabs:
	nfsd4_free_slabs();
out_unregister_pernet:
	unregister_pernet_subsys(&nfsd_net_ops);
out_unregister_notifier:
	unregister_cld_notifier();
	return retval;
}

static void __exit exit_nfsd(void)
{
	nfsd_reply_cache_shutdown();
	remove_proc_entry("fs/nfs/exports", NULL);
	remove_proc_entry("fs/nfs", NULL);
	nfsd_stat_shutdown();
	nfsd_lockd_shutdown();
	nfsd4_free_slabs();
	nfsd4_exit_pnfs();
	nfsd_fault_inject_cleanup();
	unregister_filesystem(&nfsd_fs_type);
	unregister_pernet_subsys(&nfsd_net_ops);
	unregister_cld_notifier();
}

MODULE_AUTHOR("Olaf Kirch <okir@monad.swb.de>");
MODULE_LICENSE("GPL");
module_init(init_nfsd)
module_exit(exit_nfsd)
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfsctl.c */
/************************************************************/
/*
 * Process version 2 NFS requests.
 *
 * Copyright (C) 1995-1997 Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/namei.h>

// #include "cache.h"
#include "xdr.h"
// #include "vfs.h"
#include "../../inc/__fss.h"

typedef struct svc_rqst	svc_rqst;
typedef struct svc_buf	svc_buf;

#define NFSDDBG_FACILITY		NFSDDBG_PROC


static __be32
nfsd_proc_null(struct svc_rqst *rqstp, void *argp, void *resp)
{
	return nfs_ok;
}

static __be32
nfsd_return_attrs(__be32 err, struct nfsd_attrstat *resp)
{
	if (err) return err;
	return fh_getattr(&resp->fh, &resp->stat);
}
static __be32
nfsd_return_dirop(__be32 err, struct nfsd_diropres *resp)
{
	if (err) return err;
	return fh_getattr(&resp->fh, &resp->stat);
}
/*
 * Get a file's attributes
 * N.B. After this call resp->fh needs an fh_put
 */
static __be32
nfsd_proc_getattr(struct svc_rqst *rqstp, struct nfsd_fhandle  *argp,
					  struct nfsd_attrstat *resp)
{
	__be32 nfserr;
	dprintk("nfsd: GETATTR  %s\n", SVCFH_fmt(&argp->fh));

	fh_copy(&resp->fh, &argp->fh);
	nfserr = fh_verify(rqstp, &resp->fh, 0,
			NFSD_MAY_NOP | NFSD_MAY_BYPASS_GSS_ON_ROOT);
	return nfsd_return_attrs(nfserr, resp);
}

/*
 * Set a file's attributes
 * N.B. After this call resp->fh needs an fh_put
 */
static __be32
nfsd_proc_setattr(struct svc_rqst *rqstp, struct nfsd_sattrargs *argp,
					  struct nfsd_attrstat  *resp)
{
	__be32 nfserr;
	dprintk("nfsd: SETATTR  %s, valid=%x, size=%ld\n",
		SVCFH_fmt(&argp->fh),
		argp->attrs.ia_valid, (long) argp->attrs.ia_size);

	fh_copy(&resp->fh, &argp->fh);
	nfserr = nfsd_setattr(rqstp, &resp->fh, &argp->attrs,0, (time_t)0);
	return nfsd_return_attrs(nfserr, resp);
}

/*
 * Look up a path name component
 * Note: the dentry in the resp->fh may be negative if the file
 * doesn't exist yet.
 * N.B. After this call resp->fh needs an fh_put
 */
static __be32
nfsd_proc_lookup(struct svc_rqst *rqstp, struct nfsd_diropargs *argp,
					 struct nfsd_diropres  *resp)
{
	__be32	nfserr;

	dprintk("nfsd: LOOKUP   %s %.*s\n",
		SVCFH_fmt(&argp->fh), argp->len, argp->name);

	fh_init(&resp->fh, NFS_FHSIZE);
	nfserr = nfsd_lookup(rqstp, &argp->fh, argp->name, argp->len,
				 &resp->fh);

	fh_put(&argp->fh);
	return nfsd_return_dirop(nfserr, resp);
}

/*
 * Read a symlink.
 */
static __be32
nfsd_proc_readlink(struct svc_rqst *rqstp, struct nfsd_readlinkargs *argp,
					   struct nfsd_readlinkres *resp)
{
	__be32	nfserr;

	dprintk("nfsd: READLINK %s\n", SVCFH_fmt(&argp->fh));

	/* Read the symlink. */
	resp->len = NFS_MAXPATHLEN;
	nfserr = nfsd_readlink(rqstp, &argp->fh, argp->buffer, &resp->len);

	fh_put(&argp->fh);
	return nfserr;
}

/*
 * Read a portion of a file.
 * N.B. After this call resp->fh needs an fh_put
 */
static __be32
nfsd_proc_read(struct svc_rqst *rqstp, struct nfsd_readargs *argp,
				       struct nfsd_readres  *resp)
{
	__be32	nfserr;

	dprintk("nfsd: READ    %s %d bytes at %d\n",
		SVCFH_fmt(&argp->fh),
		argp->count, argp->offset);

	/* Obtain buffer pointer for payload. 19 is 1 word for
	 * status, 17 words for fattr, and 1 word for the byte count.
	 */

	if (NFSSVC_MAXBLKSIZE_V2 < argp->count) {
		char buf[RPC_MAX_ADDRBUFLEN];
		printk(KERN_NOTICE
			"oversized read request from %s (%d bytes)\n",
				svc_print_addr(rqstp, buf, sizeof(buf)),
				argp->count);
		argp->count = NFSSVC_MAXBLKSIZE_V2;
	}
	svc_reserve_auth(rqstp, (19<<2) + argp->count + 4);

	resp->count = argp->count;
	nfserr = nfsd_read(rqstp, fh_copy(&resp->fh, &argp->fh),
				  argp->offset,
			   	  rqstp->rq_vec, argp->vlen,
				  &resp->count);

	if (nfserr) return nfserr;
	return fh_getattr(&resp->fh, &resp->stat);
}

/*
 * Write data to a file
 * N.B. After this call resp->fh needs an fh_put
 */
static __be32
nfsd_proc_write(struct svc_rqst *rqstp, struct nfsd_writeargs *argp,
					struct nfsd_attrstat  *resp)
{
	__be32	nfserr;
	int	stable = 1;
	unsigned long cnt = argp->len;

	dprintk("nfsd: WRITE    %s %d bytes at %d\n",
		SVCFH_fmt(&argp->fh),
		argp->len, argp->offset);

	nfserr = nfsd_write(rqstp, fh_copy(&resp->fh, &argp->fh), NULL,
				   argp->offset,
				   rqstp->rq_vec, argp->vlen,
			           &cnt,
				   &stable);
	return nfsd_return_attrs(nfserr, resp);
}

/*
 * CREATE processing is complicated. The keyword here is `overloaded.'
 * The parent directory is kept locked between the check for existence
 * and the actual create() call in compliance with VFS protocols.
 * N.B. After this call _both_ argp->fh and resp->fh need an fh_put
 */
static __be32
nfsd_proc_create(struct svc_rqst *rqstp, struct nfsd_createargs *argp,
					 struct nfsd_diropres   *resp)
{
	svc_fh		*dirfhp = &argp->fh;
	svc_fh		*newfhp = &resp->fh;
	struct iattr	*attr = &argp->attrs;
	struct inode	*inode;
	struct dentry	*dchild;
	int		type, mode;
	__be32		nfserr;
	int		hosterr;
	dev_t		rdev = 0, wanted = new_decode_dev(attr->ia_size);

	dprintk("nfsd: CREATE   %s %.*s\n",
		SVCFH_fmt(dirfhp), argp->len, argp->name);

	/* First verify the parent file handle */
	nfserr = fh_verify(rqstp, dirfhp, S_IFDIR, NFSD_MAY_EXEC);
	if (nfserr)
		goto done; /* must fh_put dirfhp even on error */

	/* Check for NFSD_MAY_WRITE in nfsd_create if necessary */

	nfserr = nfserr_acces;
	if (!argp->len)
		goto done;
	nfserr = nfserr_exist;
	if (isdotent(argp->name, argp->len))
		goto done;
	hosterr = fh_want_write(dirfhp);
	if (hosterr) {
		nfserr = nfserrno(hosterr);
		goto done;
	}

	fh_lock_nested(dirfhp, I_MUTEX_PARENT);
	dchild = lookup_one_len(argp->name, dirfhp->fh_dentry, argp->len);
	if (IS_ERR(dchild)) {
		nfserr = nfserrno(PTR_ERR(dchild));
		goto out_unlock;
	}
	fh_init(newfhp, NFS_FHSIZE);
	nfserr = fh_compose(newfhp, dirfhp->fh_export, dchild, dirfhp);
	if (!nfserr && !dchild->d_inode)
		nfserr = nfserr_noent;
	dput(dchild);
	if (nfserr) {
		if (nfserr != nfserr_noent)
			goto out_unlock;
		/*
		 * If the new file handle wasn't verified, we can't tell
		 * whether the file exists or not. Time to bail ...
		 */
		nfserr = nfserr_acces;
		if (!newfhp->fh_dentry) {
			printk(KERN_WARNING 
				"nfsd_proc_create: file handle not verified\n");
			goto out_unlock;
		}
	}

	inode = newfhp->fh_dentry->d_inode;

	/* Unfudge the mode bits */
	if (attr->ia_valid & ATTR_MODE) {
		type = attr->ia_mode & S_IFMT;
		mode = attr->ia_mode & ~S_IFMT;
		if (!type) {
			/* no type, so if target exists, assume same as that,
			 * else assume a file */
			if (inode) {
				type = inode->i_mode & S_IFMT;
				switch(type) {
				case S_IFCHR:
				case S_IFBLK:
					/* reserve rdev for later checking */
					rdev = inode->i_rdev;
					attr->ia_valid |= ATTR_SIZE;

					/* FALLTHROUGH */
				case S_IFIFO:
					/* this is probably a permission check..
					 * at least IRIX implements perm checking on
					 *   echo thing > device-special-file-or-pipe
					 * by doing a CREATE with type==0
					 */
					nfserr = nfsd_permission(rqstp,
								 newfhp->fh_export,
								 newfhp->fh_dentry,
								 NFSD_MAY_WRITE|NFSD_MAY_LOCAL_ACCESS);
					if (nfserr && nfserr != nfserr_rofs)
						goto out_unlock;
				}
			} else
				type = S_IFREG;
		}
	} else if (inode) {
		type = inode->i_mode & S_IFMT;
		mode = inode->i_mode & ~S_IFMT;
	} else {
		type = S_IFREG;
		mode = 0;	/* ??? */
	}

	attr->ia_valid |= ATTR_MODE;
	attr->ia_mode = mode;

	/* Special treatment for non-regular files according to the
	 * gospel of sun micro
	 */
	if (type != S_IFREG) {
		if (type != S_IFBLK && type != S_IFCHR) {
			rdev = 0;
		} else if (type == S_IFCHR && !(attr->ia_valid & ATTR_SIZE)) {
			/* If you think you've seen the worst, grok this. */
			type = S_IFIFO;
		} else {
			/* Okay, char or block special */
			if (!rdev)
				rdev = wanted;
		}

		/* we've used the SIZE information, so discard it */
		attr->ia_valid &= ~ATTR_SIZE;

		/* Make sure the type and device matches */
		nfserr = nfserr_exist;
		if (inode && type != (inode->i_mode & S_IFMT))
			goto out_unlock;
	}

	nfserr = 0;
	if (!inode) {
		/* File doesn't exist. Create it and set attrs */
		nfserr = nfsd_create(rqstp, dirfhp, argp->name, argp->len,
					attr, type, rdev, newfhp);
	} else if (type == S_IFREG) {
		dprintk("nfsd:   existing %s, valid=%x, size=%ld\n",
			argp->name, attr->ia_valid, (long) attr->ia_size);
		/* File already exists. We ignore all attributes except
		 * size, so that creat() behaves exactly like
		 * open(..., O_CREAT|O_TRUNC|O_WRONLY).
		 */
		attr->ia_valid &= ATTR_SIZE;
		if (attr->ia_valid)
			nfserr = nfsd_setattr(rqstp, newfhp, attr, 0, (time_t)0);
	}

out_unlock:
	/* We don't really need to unlock, as fh_put does it. */
	fh_unlock(dirfhp);
	fh_drop_write(dirfhp);
done:
	fh_put(dirfhp);
	return nfsd_return_dirop(nfserr, resp);
}

static __be32
nfsd_proc_remove(struct svc_rqst *rqstp, struct nfsd_diropargs *argp,
					 void		       *resp)
{
	__be32	nfserr;

	dprintk("nfsd: REMOVE   %s %.*s\n", SVCFH_fmt(&argp->fh),
		argp->len, argp->name);

	/* Unlink. -SIFDIR means file must not be a directory */
	nfserr = nfsd_unlink(rqstp, &argp->fh, -S_IFDIR, argp->name, argp->len);
	fh_put(&argp->fh);
	return nfserr;
}

static __be32
nfsd_proc_rename(struct svc_rqst *rqstp, struct nfsd_renameargs *argp,
				  	 void		        *resp)
{
	__be32	nfserr;

	dprintk("nfsd: RENAME   %s %.*s -> \n",
		SVCFH_fmt(&argp->ffh), argp->flen, argp->fname);
	dprintk("nfsd:        ->  %s %.*s\n",
		SVCFH_fmt(&argp->tfh), argp->tlen, argp->tname);

	nfserr = nfsd_rename(rqstp, &argp->ffh, argp->fname, argp->flen,
				    &argp->tfh, argp->tname, argp->tlen);
	fh_put(&argp->ffh);
	fh_put(&argp->tfh);
	return nfserr;
}

static __be32
nfsd_proc_link(struct svc_rqst *rqstp, struct nfsd_linkargs *argp,
				void			    *resp)
{
	__be32	nfserr;

	dprintk("nfsd: LINK     %s ->\n",
		SVCFH_fmt(&argp->ffh));
	dprintk("nfsd:    %s %.*s\n",
		SVCFH_fmt(&argp->tfh),
		argp->tlen,
		argp->tname);

	nfserr = nfsd_link(rqstp, &argp->tfh, argp->tname, argp->tlen,
				  &argp->ffh);
	fh_put(&argp->ffh);
	fh_put(&argp->tfh);
	return nfserr;
}

static __be32
nfsd_proc_symlink(struct svc_rqst *rqstp, struct nfsd_symlinkargs *argp,
				          void			  *resp)
{
	struct svc_fh	newfh;
	__be32		nfserr;

	dprintk("nfsd: SYMLINK  %s %.*s -> %.*s\n",
		SVCFH_fmt(&argp->ffh), argp->flen, argp->fname,
		argp->tlen, argp->tname);

	fh_init(&newfh, NFS_FHSIZE);
	/*
	 * Crazy hack: the request fits in a page, and already-decoded
	 * attributes follow argp->tname, so it's safe to just write a
	 * null to ensure it's null-terminated:
	 */
	argp->tname[argp->tlen] = '\0';
	nfserr = nfsd_symlink(rqstp, &argp->ffh, argp->fname, argp->flen,
						 argp->tname, &newfh);

	fh_put(&argp->ffh);
	fh_put(&newfh);
	return nfserr;
}

/*
 * Make directory. This operation is not idempotent.
 * N.B. After this call resp->fh needs an fh_put
 */
static __be32
nfsd_proc_mkdir(struct svc_rqst *rqstp, struct nfsd_createargs *argp,
					struct nfsd_diropres   *resp)
{
	__be32	nfserr;

	dprintk("nfsd: MKDIR    %s %.*s\n", SVCFH_fmt(&argp->fh), argp->len, argp->name);

	if (resp->fh.fh_dentry) {
		printk(KERN_WARNING
			"nfsd_proc_mkdir: response already verified??\n");
	}

	argp->attrs.ia_valid &= ~ATTR_SIZE;
	fh_init(&resp->fh, NFS_FHSIZE);
	nfserr = nfsd_create(rqstp, &argp->fh, argp->name, argp->len,
				    &argp->attrs, S_IFDIR, 0, &resp->fh);
	fh_put(&argp->fh);
	return nfsd_return_dirop(nfserr, resp);
}

/*
 * Remove a directory
 */
static __be32
nfsd_proc_rmdir(struct svc_rqst *rqstp, struct nfsd_diropargs *argp,
				 	void		      *resp)
{
	__be32	nfserr;

	dprintk("nfsd: RMDIR    %s %.*s\n", SVCFH_fmt(&argp->fh), argp->len, argp->name);

	nfserr = nfsd_unlink(rqstp, &argp->fh, S_IFDIR, argp->name, argp->len);
	fh_put(&argp->fh);
	return nfserr;
}

/*
 * Read a portion of a directory.
 */
static __be32
nfsd_proc_readdir(struct svc_rqst *rqstp, struct nfsd_readdirargs *argp,
					  struct nfsd_readdirres  *resp)
{
	int		count;
	__be32		nfserr;
	loff_t		offset;

	dprintk("nfsd: READDIR  %s %d bytes at %d\n",
		SVCFH_fmt(&argp->fh),		
		argp->count, argp->cookie);

	/* Shrink to the client read size */
	count = (argp->count >> 2) - 2;

	/* Make sure we've room for the NULL ptr & eof flag */
	count -= 2;
	if (count < 0)
		count = 0;

	resp->buffer = argp->buffer;
	resp->offset = NULL;
	resp->buflen = count;
	resp->common.err = nfs_ok;
	/* Read directory and encode entries on the fly */
	offset = argp->cookie;
	nfserr = nfsd_readdir(rqstp, &argp->fh, &offset, 
			      &resp->common, nfssvc_encode_entry);

	resp->count = resp->buffer - argp->buffer;
	if (resp->offset)
		*resp->offset = htonl(offset);

	fh_put(&argp->fh);
	return nfserr;
}

/*
 * Get file system info
 */
static __be32
nfsd_proc_statfs(struct svc_rqst * rqstp, struct nfsd_fhandle   *argp,
					  struct nfsd_statfsres *resp)
{
	__be32	nfserr;

	dprintk("nfsd: STATFS   %s\n", SVCFH_fmt(&argp->fh));

	nfserr = nfsd_statfs(rqstp, &argp->fh, &resp->stats,
			NFSD_MAY_BYPASS_GSS_ON_ROOT);
	fh_put(&argp->fh);
	return nfserr;
}

/*
 * NFSv2 Server procedures.
 * Only the results of non-idempotent operations are cached.
 */
struct nfsd_void { int dummy; };

#define ST 1		/* status */
#define FH 8		/* filehandle */
#define	AT 18		/* attributes */

static struct svc_procedure		nfsd_procedures2[18] = {
	[NFSPROC_NULL] = {
		.pc_func = (svc_procfunc) nfsd_proc_null,
		.pc_decode = (kxdrproc_t) nfssvc_decode_void,
		.pc_encode = (kxdrproc_t) nfssvc_encode_void,
		.pc_argsize = sizeof(struct nfsd_void),
		.pc_ressize = sizeof(struct nfsd_void),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST,
	},
	[NFSPROC_GETATTR] = {
		.pc_func = (svc_procfunc) nfsd_proc_getattr,
		.pc_decode = (kxdrproc_t) nfssvc_decode_fhandle,
		.pc_encode = (kxdrproc_t) nfssvc_encode_attrstat,
		.pc_release = (kxdrproc_t) nfssvc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd_fhandle),
		.pc_ressize = sizeof(struct nfsd_attrstat),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+AT,
	},
	[NFSPROC_SETATTR] = {
		.pc_func = (svc_procfunc) nfsd_proc_setattr,
		.pc_decode = (kxdrproc_t) nfssvc_decode_sattrargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_attrstat,
		.pc_release = (kxdrproc_t) nfssvc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd_sattrargs),
		.pc_ressize = sizeof(struct nfsd_attrstat),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+AT,
	},
	[NFSPROC_ROOT] = {
		.pc_decode = (kxdrproc_t) nfssvc_decode_void,
		.pc_encode = (kxdrproc_t) nfssvc_encode_void,
		.pc_argsize = sizeof(struct nfsd_void),
		.pc_ressize = sizeof(struct nfsd_void),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST,
	},
	[NFSPROC_LOOKUP] = {
		.pc_func = (svc_procfunc) nfsd_proc_lookup,
		.pc_decode = (kxdrproc_t) nfssvc_decode_diropargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_diropres,
		.pc_release = (kxdrproc_t) nfssvc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd_diropargs),
		.pc_ressize = sizeof(struct nfsd_diropres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+FH+AT,
	},
	[NFSPROC_READLINK] = {
		.pc_func = (svc_procfunc) nfsd_proc_readlink,
		.pc_decode = (kxdrproc_t) nfssvc_decode_readlinkargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_readlinkres,
		.pc_argsize = sizeof(struct nfsd_readlinkargs),
		.pc_ressize = sizeof(struct nfsd_readlinkres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+1+NFS_MAXPATHLEN/4,
	},
	[NFSPROC_READ] = {
		.pc_func = (svc_procfunc) nfsd_proc_read,
		.pc_decode = (kxdrproc_t) nfssvc_decode_readargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_readres,
		.pc_release = (kxdrproc_t) nfssvc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd_readargs),
		.pc_ressize = sizeof(struct nfsd_readres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+AT+1+NFSSVC_MAXBLKSIZE_V2/4,
	},
	[NFSPROC_WRITECACHE] = {
		.pc_decode = (kxdrproc_t) nfssvc_decode_void,
		.pc_encode = (kxdrproc_t) nfssvc_encode_void,
		.pc_argsize = sizeof(struct nfsd_void),
		.pc_ressize = sizeof(struct nfsd_void),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST,
	},
	[NFSPROC_WRITE] = {
		.pc_func = (svc_procfunc) nfsd_proc_write,
		.pc_decode = (kxdrproc_t) nfssvc_decode_writeargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_attrstat,
		.pc_release = (kxdrproc_t) nfssvc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd_writeargs),
		.pc_ressize = sizeof(struct nfsd_attrstat),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+AT,
	},
	[NFSPROC_CREATE] = {
		.pc_func = (svc_procfunc) nfsd_proc_create,
		.pc_decode = (kxdrproc_t) nfssvc_decode_createargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_diropres,
		.pc_release = (kxdrproc_t) nfssvc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd_createargs),
		.pc_ressize = sizeof(struct nfsd_diropres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+FH+AT,
	},
	[NFSPROC_REMOVE] = {
		.pc_func = (svc_procfunc) nfsd_proc_remove,
		.pc_decode = (kxdrproc_t) nfssvc_decode_diropargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_void,
		.pc_argsize = sizeof(struct nfsd_diropargs),
		.pc_ressize = sizeof(struct nfsd_void),
		.pc_cachetype = RC_REPLSTAT,
		.pc_xdrressize = ST,
	},
	[NFSPROC_RENAME] = {
		.pc_func = (svc_procfunc) nfsd_proc_rename,
		.pc_decode = (kxdrproc_t) nfssvc_decode_renameargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_void,
		.pc_argsize = sizeof(struct nfsd_renameargs),
		.pc_ressize = sizeof(struct nfsd_void),
		.pc_cachetype = RC_REPLSTAT,
		.pc_xdrressize = ST,
	},
	[NFSPROC_LINK] = {
		.pc_func = (svc_procfunc) nfsd_proc_link,
		.pc_decode = (kxdrproc_t) nfssvc_decode_linkargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_void,
		.pc_argsize = sizeof(struct nfsd_linkargs),
		.pc_ressize = sizeof(struct nfsd_void),
		.pc_cachetype = RC_REPLSTAT,
		.pc_xdrressize = ST,
	},
	[NFSPROC_SYMLINK] = {
		.pc_func = (svc_procfunc) nfsd_proc_symlink,
		.pc_decode = (kxdrproc_t) nfssvc_decode_symlinkargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_void,
		.pc_argsize = sizeof(struct nfsd_symlinkargs),
		.pc_ressize = sizeof(struct nfsd_void),
		.pc_cachetype = RC_REPLSTAT,
		.pc_xdrressize = ST,
	},
	[NFSPROC_MKDIR] = {
		.pc_func = (svc_procfunc) nfsd_proc_mkdir,
		.pc_decode = (kxdrproc_t) nfssvc_decode_createargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_diropres,
		.pc_release = (kxdrproc_t) nfssvc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd_createargs),
		.pc_ressize = sizeof(struct nfsd_diropres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+FH+AT,
	},
	[NFSPROC_RMDIR] = {
		.pc_func = (svc_procfunc) nfsd_proc_rmdir,
		.pc_decode = (kxdrproc_t) nfssvc_decode_diropargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_void,
		.pc_argsize = sizeof(struct nfsd_diropargs),
		.pc_ressize = sizeof(struct nfsd_void),
		.pc_cachetype = RC_REPLSTAT,
		.pc_xdrressize = ST,
	},
	[NFSPROC_READDIR] = {
		.pc_func = (svc_procfunc) nfsd_proc_readdir,
		.pc_decode = (kxdrproc_t) nfssvc_decode_readdirargs,
		.pc_encode = (kxdrproc_t) nfssvc_encode_readdirres,
		.pc_argsize = sizeof(struct nfsd_readdirargs),
		.pc_ressize = sizeof(struct nfsd_readdirres),
		.pc_cachetype = RC_NOCACHE,
	},
	[NFSPROC_STATFS] = {
		.pc_func = (svc_procfunc) nfsd_proc_statfs,
		.pc_decode = (kxdrproc_t) nfssvc_decode_fhandle,
		.pc_encode = (kxdrproc_t) nfssvc_encode_statfsres,
		.pc_argsize = sizeof(struct nfsd_fhandle),
		.pc_ressize = sizeof(struct nfsd_statfsres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+5,
	},
};


struct svc_version	nfsd_version2 = {
		.vs_vers	= 2,
		.vs_nproc	= 18,
		.vs_proc	= nfsd_procedures2,
		.vs_dispatch	= nfsd_dispatch,
		.vs_xdrsize	= NFS2_SVC_XDRSIZE,
};

/*
 * Map errnos to NFS errnos.
 */
__be32
nfserrno (int errno)
{
	static struct {
		__be32	nfserr;
		int	syserr;
	} nfs_errtbl[] = {
		{ nfs_ok, 0 },
		{ nfserr_perm, -EPERM },
		{ nfserr_noent, -ENOENT },
		{ nfserr_io, -EIO },
		{ nfserr_nxio, -ENXIO },
		{ nfserr_fbig, -E2BIG },
		{ nfserr_acces, -EACCES },
		{ nfserr_exist, -EEXIST },
		{ nfserr_xdev, -EXDEV },
		{ nfserr_mlink, -EMLINK },
		{ nfserr_nodev, -ENODEV },
		{ nfserr_notdir, -ENOTDIR },
		{ nfserr_isdir, -EISDIR },
		{ nfserr_inval, -EINVAL },
		{ nfserr_fbig, -EFBIG },
		{ nfserr_nospc, -ENOSPC },
		{ nfserr_rofs, -EROFS },
		{ nfserr_mlink, -EMLINK },
		{ nfserr_nametoolong, -ENAMETOOLONG },
		{ nfserr_notempty, -ENOTEMPTY },
#ifdef EDQUOT
		{ nfserr_dquot, -EDQUOT },
#endif
		{ nfserr_stale, -ESTALE },
		{ nfserr_jukebox, -ETIMEDOUT },
		{ nfserr_jukebox, -ERESTARTSYS },
		{ nfserr_jukebox, -EAGAIN },
		{ nfserr_jukebox, -EWOULDBLOCK },
		{ nfserr_jukebox, -ENOMEM },
		{ nfserr_io, -ETXTBSY },
		{ nfserr_notsupp, -EOPNOTSUPP },
		{ nfserr_toosmall, -ETOOSMALL },
		{ nfserr_serverfault, -ESERVERFAULT },
		{ nfserr_serverfault, -ENFILE },
	};
	int	i;

	for (i = 0; i < ARRAY_SIZE(nfs_errtbl); i++) {
		if (nfs_errtbl[i].syserr == errno)
			return nfs_errtbl[i].nfserr;
	}
	WARN(1, "nfsd: non-standard errno: %d\n", errno);
	return nfserr_io;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfsproc.c */
/************************************************************/
/*
 * NFS server file handle treatment.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 * Portions Copyright (C) 1999 G. Allen Morris III <gam3@acm.org>
 * Extensive rewrite by Neil Brown <neilb@cse.unsw.edu.au> Southern-Spring 1999
 * ... and again Southern-Winter 2001 to support export_operations
 */

#include <linux/exportfs.h>
#include "../../inc/__fss.h"

#include <linux/sunrpc/svcauth_gss.h>
// #include "nfsd.h"
// #include "vfs.h"
#include "auth.h"
#include "../../inc/__fss.h"

#define NFSDDBG_FACILITY		NFSDDBG_FH


/*
 * our acceptability function.
 * if NOSUBTREECHECK, accept anything
 * if not, require that we can walk up to exp->ex_dentry
 * doing some checks on the 'x' bits
 */
static int nfsd_acceptable(void *expv, struct dentry *dentry)
{
	struct svc_export *exp = expv;
	int rv;
	struct dentry *tdentry;
	struct dentry *parent;

	if (exp->ex_flags & NFSEXP_NOSUBTREECHECK)
		return 1;

	tdentry = dget(dentry);
	while (tdentry != exp->ex_path.dentry && !IS_ROOT(tdentry)) {
		/* make sure parents give x permission to user */
		int err;
		parent = dget_parent(tdentry);
		err = inode_permission(parent->d_inode, MAY_EXEC);
		if (err < 0) {
			dput(parent);
			break;
		}
		dput(tdentry);
		tdentry = parent;
	}
	if (tdentry != exp->ex_path.dentry)
		dprintk("nfsd_acceptable failed at %p %pd\n", tdentry, tdentry);
	rv = (tdentry == exp->ex_path.dentry);
	dput(tdentry);
	return rv;
}

/* Type check. The correct error return for type mismatches does not seem to be
 * generally agreed upon. SunOS seems to use EISDIR if file isn't S_IFREG; a
 * comment in the NFSv3 spec says this is incorrect (implementation notes for
 * the write call).
 */
static inline __be32
nfsd_mode_check(struct svc_rqst *rqstp, umode_t mode, umode_t requested)
{
	mode &= S_IFMT;

	if (requested == 0) /* the caller doesn't care */
		return nfs_ok;
	if (mode == requested)
		return nfs_ok;
	/*
	 * v4 has an error more specific than err_notdir which we should
	 * return in preference to err_notdir:
	 */
	if (rqstp->rq_vers == 4 && mode == S_IFLNK)
		return nfserr_symlink;
	if (requested == S_IFDIR)
		return nfserr_notdir;
	if (mode == S_IFDIR)
		return nfserr_isdir;
	return nfserr_inval;
}

static __be32 nfsd_setuser_and_check_port(struct svc_rqst *rqstp,
					  struct svc_export *exp)
{
	int flags = nfsexp_flags(rqstp, exp);

	/* Check if the request originated from a secure port. */
	if (!test_bit(RQ_SECURE, &rqstp->rq_flags) && !(flags & NFSEXP_INSECURE_PORT)) {
		RPC_IFDEBUG(char buf[RPC_MAX_ADDRBUFLEN]);
		dprintk("nfsd: request from insecure port %s!\n",
		        svc_print_addr(rqstp, buf, sizeof(buf)));
		return nfserr_perm;
	}

	/* Set user creds for this exportpoint */
	return nfserrno(nfsd_setuser(rqstp, exp));
}

static inline __be32 check_pseudo_root(struct svc_rqst *rqstp,
	struct dentry *dentry, struct svc_export *exp)
{
	if (!(exp->ex_flags & NFSEXP_V4ROOT))
		return nfs_ok;
	/*
	 * v2/v3 clients have no need for the V4ROOT export--they use
	 * the mount protocl instead; also, further V4ROOT checks may be
	 * in v4-specific code, in which case v2/v3 clients could bypass
	 * them.
	 */
	if (!nfsd_v4client(rqstp))
		return nfserr_stale;
	/*
	 * We're exposing only the directories and symlinks that have to be
	 * traversed on the way to real exports:
	 */
	if (unlikely(!d_is_dir(dentry) &&
		     !d_is_symlink(dentry)))
		return nfserr_stale;
	/*
	 * A pseudoroot export gives permission to access only one
	 * single directory; the kernel has to make another upcall
	 * before granting access to anything else under it:
	 */
	if (unlikely(dentry != exp->ex_path.dentry))
		return nfserr_stale;
	return nfs_ok;
}

/*
 * Use the given filehandle to look up the corresponding export and
 * dentry.  On success, the results are used to set fh_export and
 * fh_dentry.
 */
static __be32 nfsd_set_fh_dentry(struct svc_rqst *rqstp, struct svc_fh *fhp)
{
	struct knfsd_fh	*fh = &fhp->fh_handle;
	struct fid *fid = NULL, sfid;
	struct svc_export *exp;
	struct dentry *dentry;
	int fileid_type;
	int data_left = fh->fh_size/4;
	__be32 error;

	error = nfserr_stale;
	if (rqstp->rq_vers > 2)
		error = nfserr_badhandle;
	if (rqstp->rq_vers == 4 && fh->fh_size == 0)
		return nfserr_nofilehandle;

	if (fh->fh_version == 1) {
		int len;

		if (--data_left < 0)
			return error;
		if (fh->fh_auth_type != 0)
			return error;
		len = key_len(fh->fh_fsid_type) / 4;
		if (len == 0)
			return error;
		if  (fh->fh_fsid_type == FSID_MAJOR_MINOR) {
			/* deprecated, convert to type 3 */
			len = key_len(FSID_ENCODE_DEV)/4;
			fh->fh_fsid_type = FSID_ENCODE_DEV;
			/*
			 * struct knfsd_fh uses host-endian fields, which are
			 * sometimes used to hold net-endian values. This
			 * confuses sparse, so we must use __force here to
			 * keep it from complaining.
			 */
			fh->fh_fsid[0] = new_encode_dev(MKDEV(ntohl((__force __be32)fh->fh_fsid[0]),
							ntohl((__force __be32)fh->fh_fsid[1])));
			fh->fh_fsid[1] = fh->fh_fsid[2];
		}
		data_left -= len;
		if (data_left < 0)
			return error;
		exp = rqst_exp_find(rqstp, fh->fh_fsid_type, fh->fh_fsid);
		fid = (struct fid *)(fh->fh_fsid + len);
	} else {
		__u32 tfh[2];
		dev_t xdev;
		ino_t xino;

		if (fh->fh_size != NFS_FHSIZE)
			return error;
		/* assume old filehandle format */
		xdev = old_decode_dev(fh->ofh_xdev);
		xino = u32_to_ino_t(fh->ofh_xino);
		mk_fsid(FSID_DEV, tfh, xdev, xino, 0, NULL);
		exp = rqst_exp_find(rqstp, FSID_DEV, tfh);
	}

	error = nfserr_stale;
	if (PTR_ERR(exp) == -ENOENT)
		return error;

	if (IS_ERR(exp))
		return nfserrno(PTR_ERR(exp));

	if (exp->ex_flags & NFSEXP_NOSUBTREECHECK) {
		/* Elevate privileges so that the lack of 'r' or 'x'
		 * permission on some parent directory will
		 * not stop exportfs_decode_fh from being able
		 * to reconnect a directory into the dentry cache.
		 * The same problem can affect "SUBTREECHECK" exports,
		 * but as nfsd_acceptable depends on correct
		 * access control settings being in effect, we cannot
		 * fix that case easily.
		 */
		struct cred *new = prepare_creds();
		if (!new) {
			error =  nfserrno(-ENOMEM);
			goto out;
		}
		new->cap_effective =
			cap_raise_nfsd_set(new->cap_effective,
					   new->cap_permitted);
		put_cred(override_creds(new));
		put_cred(new);
	} else {
		error = nfsd_setuser_and_check_port(rqstp, exp);
		if (error)
			goto out;
	}

	/*
	 * Look up the dentry using the NFS file handle.
	 */
	error = nfserr_stale;
	if (rqstp->rq_vers > 2)
		error = nfserr_badhandle;

	if (fh->fh_version != 1) {
		sfid.i32.ino = fh->ofh_ino;
		sfid.i32.gen = fh->ofh_generation;
		sfid.i32.parent_ino = fh->ofh_dirino;
		fid = &sfid;
		data_left = 3;
		if (fh->ofh_dirino == 0)
			fileid_type = FILEID_INO32_GEN;
		else
			fileid_type = FILEID_INO32_GEN_PARENT;
	} else
		fileid_type = fh->fh_fileid_type;

	if (fileid_type == FILEID_ROOT)
		dentry = dget(exp->ex_path.dentry);
	else {
		dentry = exportfs_decode_fh(exp->ex_path.mnt, fid,
				data_left, fileid_type,
				nfsd_acceptable, exp);
	}
	if (dentry == NULL)
		goto out;
	if (IS_ERR(dentry)) {
		if (PTR_ERR(dentry) != -EINVAL)
			error = nfserrno(PTR_ERR(dentry));
		goto out;
	}

	if (d_is_dir(dentry) &&
			(dentry->d_flags & DCACHE_DISCONNECTED)) {
		printk("nfsd: find_fh_dentry returned a DISCONNECTED directory: %pd2\n",
				dentry);
	}

	fhp->fh_dentry = dentry;
	fhp->fh_export = exp;
	return 0;
out:
	exp_put(exp);
	return error;
}

/**
 * fh_verify - filehandle lookup and access checking
 * @rqstp: pointer to current rpc request
 * @fhp: filehandle to be verified
 * @type: expected type of object pointed to by filehandle
 * @access: type of access needed to object
 *
 * Look up a dentry from the on-the-wire filehandle, check the client's
 * access to the export, and set the current task's credentials.
 *
 * Regardless of success or failure of fh_verify(), fh_put() should be
 * called on @fhp when the caller is finished with the filehandle.
 *
 * fh_verify() may be called multiple times on a given filehandle, for
 * example, when processing an NFSv4 compound.  The first call will look
 * up a dentry using the on-the-wire filehandle.  Subsequent calls will
 * skip the lookup and just perform the other checks and possibly change
 * the current task's credentials.
 *
 * @type specifies the type of object expected using one of the S_IF*
 * constants defined in include/linux/stat.h.  The caller may use zero
 * to indicate that it doesn't care, or a negative integer to indicate
 * that it expects something not of the given type.
 *
 * @access is formed from the NFSD_MAY_* constants defined in
 * include/linux/nfsd/nfsd.h.
 */
__be32
fh_verify(struct svc_rqst *rqstp, struct svc_fh *fhp, umode_t type, int access)
{
	struct svc_export *exp;
	struct dentry	*dentry;
	__be32		error;

	dprintk("nfsd: fh_verify(%s)\n", SVCFH_fmt(fhp));

	if (!fhp->fh_dentry) {
		error = nfsd_set_fh_dentry(rqstp, fhp);
		if (error)
			goto out;
	}
	dentry = fhp->fh_dentry;
	exp = fhp->fh_export;
	/*
	 * We still have to do all these permission checks, even when
	 * fh_dentry is already set:
	 * 	- fh_verify may be called multiple times with different
	 * 	  "access" arguments (e.g. nfsd_proc_create calls
	 * 	  fh_verify(...,NFSD_MAY_EXEC) first, then later (in
	 * 	  nfsd_create) calls fh_verify(...,NFSD_MAY_CREATE).
	 *	- in the NFSv4 case, the filehandle may have been filled
	 *	  in by fh_compose, and given a dentry, but further
	 *	  compound operations performed with that filehandle
	 *	  still need permissions checks.  In the worst case, a
	 *	  mountpoint crossing may have changed the export
	 *	  options, and we may now need to use a different uid
	 *	  (for example, if different id-squashing options are in
	 *	  effect on the new filesystem).
	 */
	error = check_pseudo_root(rqstp, dentry, exp);
	if (error)
		goto out;

	error = nfsd_setuser_and_check_port(rqstp, exp);
	if (error)
		goto out;

	error = nfsd_mode_check(rqstp, dentry->d_inode->i_mode, type);
	if (error)
		goto out;

	/*
	 * pseudoflavor restrictions are not enforced on NLM,
	 * which clients virtually always use auth_sys for,
	 * even while using RPCSEC_GSS for NFS.
	 */
	if (access & NFSD_MAY_LOCK || access & NFSD_MAY_BYPASS_GSS)
		goto skip_pseudoflavor_check;
	/*
	 * Clients may expect to be able to use auth_sys during mount,
	 * even if they use gss for everything else; see section 2.3.2
	 * of rfc 2623.
	 */
	if (access & NFSD_MAY_BYPASS_GSS_ON_ROOT
			&& exp->ex_path.dentry == dentry)
		goto skip_pseudoflavor_check;

	error = check_nfsd_access(exp, rqstp);
	if (error)
		goto out;

skip_pseudoflavor_check:
	/* Finally, check access permissions. */
	error = nfsd_permission(rqstp, exp, dentry, access);

	if (error) {
		dprintk("fh_verify: %pd2 permission failure, "
			"acc=%x, error=%d\n",
			dentry,
			access, ntohl(error));
	}
out:
	if (error == nfserr_stale)
		nfsdstats.fh_stale++;
	return error;
}


/*
 * Compose a file handle for an NFS reply.
 *
 * Note that when first composed, the dentry may not yet have
 * an inode.  In this case a call to fh_update should be made
 * before the fh goes out on the wire ...
 */
static void _fh_update(struct svc_fh *fhp, struct svc_export *exp,
		struct dentry *dentry)
{
	if (dentry != exp->ex_path.dentry) {
		struct fid *fid = (struct fid *)
			(fhp->fh_handle.fh_fsid + fhp->fh_handle.fh_size/4 - 1);
		int maxsize = (fhp->fh_maxsize - fhp->fh_handle.fh_size)/4;
		int subtreecheck = !(exp->ex_flags & NFSEXP_NOSUBTREECHECK);

		fhp->fh_handle.fh_fileid_type =
			exportfs_encode_fh(dentry, fid, &maxsize, subtreecheck);
		fhp->fh_handle.fh_size += maxsize * 4;
	} else {
		fhp->fh_handle.fh_fileid_type = FILEID_ROOT;
	}
}

/*
 * for composing old style file handles
 */
static inline void _fh_update_old(struct dentry *dentry,
				  struct svc_export *exp,
				  struct knfsd_fh *fh)
{
	fh->ofh_ino = ino_t_to_u32(dentry->d_inode->i_ino);
	fh->ofh_generation = dentry->d_inode->i_generation;
	if (d_is_dir(dentry) ||
	    (exp->ex_flags & NFSEXP_NOSUBTREECHECK))
		fh->ofh_dirino = 0;
}

static bool is_root_export(struct svc_export *exp)
{
	return exp->ex_path.dentry == exp->ex_path.dentry->d_sb->s_root;
}

static struct super_block *exp_sb(struct svc_export *exp)
{
	return exp->ex_path.dentry->d_inode->i_sb;
}

static bool fsid_type_ok_for_exp(u8 fsid_type, struct svc_export *exp)
{
	switch (fsid_type) {
	case FSID_DEV:
		if (!old_valid_dev(exp_sb(exp)->s_dev))
			return 0;
		/* FALL THROUGH */
	case FSID_MAJOR_MINOR:
	case FSID_ENCODE_DEV:
		return exp_sb(exp)->s_type->fs_flags & FS_REQUIRES_DEV;
	case FSID_NUM:
		return exp->ex_flags & NFSEXP_FSID;
	case FSID_UUID8:
	case FSID_UUID16:
		if (!is_root_export(exp))
			return 0;
		/* fall through */
	case FSID_UUID4_INUM:
	case FSID_UUID16_INUM:
		return exp->ex_uuid != NULL;
	}
	return 1;
}


static void set_version_and_fsid_type(struct svc_fh *fhp, struct svc_export *exp, struct svc_fh *ref_fh)
{
	u8 version;
	u8 fsid_type;
retry:
	version = 1;
	if (ref_fh && ref_fh->fh_export == exp) {
		version = ref_fh->fh_handle.fh_version;
		fsid_type = ref_fh->fh_handle.fh_fsid_type;

		ref_fh = NULL;

		switch (version) {
		case 0xca:
			fsid_type = FSID_DEV;
			break;
		case 1:
			break;
		default:
			goto retry;
		}

		/*
		 * As the fsid -> filesystem mapping was guided by
		 * user-space, there is no guarantee that the filesystem
		 * actually supports that fsid type. If it doesn't we
		 * loop around again without ref_fh set.
		 */
		if (!fsid_type_ok_for_exp(fsid_type, exp))
			goto retry;
	} else if (exp->ex_flags & NFSEXP_FSID) {
		fsid_type = FSID_NUM;
	} else if (exp->ex_uuid) {
		if (fhp->fh_maxsize >= 64) {
			if (is_root_export(exp))
				fsid_type = FSID_UUID16;
			else
				fsid_type = FSID_UUID16_INUM;
		} else {
			if (is_root_export(exp))
				fsid_type = FSID_UUID8;
			else
				fsid_type = FSID_UUID4_INUM;
		}
	} else if (!old_valid_dev(exp_sb(exp)->s_dev))
		/* for newer device numbers, we must use a newer fsid format */
		fsid_type = FSID_ENCODE_DEV;
	else
		fsid_type = FSID_DEV;
	fhp->fh_handle.fh_version = version;
	if (version)
		fhp->fh_handle.fh_fsid_type = fsid_type;
}

__be32
fh_compose(struct svc_fh *fhp, struct svc_export *exp, struct dentry *dentry,
	   struct svc_fh *ref_fh)
{
	/* ref_fh is a reference file handle.
	 * if it is non-null and for the same filesystem, then we should compose
	 * a filehandle which is of the same version, where possible.
	 * Currently, that means that if ref_fh->fh_handle.fh_version == 0xca
	 * Then create a 32byte filehandle using nfs_fhbase_old
	 *
	 */

	struct inode * inode = dentry->d_inode;
	dev_t ex_dev = exp_sb(exp)->s_dev;

	dprintk("nfsd: fh_compose(exp %02x:%02x/%ld %pd2, ino=%ld)\n",
		MAJOR(ex_dev), MINOR(ex_dev),
		(long) exp->ex_path.dentry->d_inode->i_ino,
		dentry,
		(inode ? inode->i_ino : 0));

	/* Choose filehandle version and fsid type based on
	 * the reference filehandle (if it is in the same export)
	 * or the export options.
	 */
	 set_version_and_fsid_type(fhp, exp, ref_fh);

	if (ref_fh == fhp)
		fh_put(ref_fh);

	if (fhp->fh_locked || fhp->fh_dentry) {
		printk(KERN_ERR "fh_compose: fh %pd2 not initialized!\n",
		       dentry);
	}
	if (fhp->fh_maxsize < NFS_FHSIZE)
		printk(KERN_ERR "fh_compose: called with maxsize %d! %pd2\n",
		       fhp->fh_maxsize,
		       dentry);

	fhp->fh_dentry = dget(dentry); /* our internal copy */
	fhp->fh_export = exp_get(exp);

	if (fhp->fh_handle.fh_version == 0xca) {
		/* old style filehandle please */
		memset(&fhp->fh_handle.fh_base, 0, NFS_FHSIZE);
		fhp->fh_handle.fh_size = NFS_FHSIZE;
		fhp->fh_handle.ofh_dcookie = 0xfeebbaca;
		fhp->fh_handle.ofh_dev =  old_encode_dev(ex_dev);
		fhp->fh_handle.ofh_xdev = fhp->fh_handle.ofh_dev;
		fhp->fh_handle.ofh_xino =
			ino_t_to_u32(exp->ex_path.dentry->d_inode->i_ino);
		fhp->fh_handle.ofh_dirino = ino_t_to_u32(parent_ino(dentry));
		if (inode)
			_fh_update_old(dentry, exp, &fhp->fh_handle);
	} else {
		fhp->fh_handle.fh_size =
			key_len(fhp->fh_handle.fh_fsid_type) + 4;
		fhp->fh_handle.fh_auth_type = 0;

		mk_fsid(fhp->fh_handle.fh_fsid_type,
			fhp->fh_handle.fh_fsid,
			ex_dev,
			exp->ex_path.dentry->d_inode->i_ino,
			exp->ex_fsid, exp->ex_uuid);

		if (inode)
			_fh_update(fhp, exp, dentry);
		if (fhp->fh_handle.fh_fileid_type == FILEID_INVALID) {
			fh_put(fhp);
			return nfserr_opnotsupp;
		}
	}

	return 0;
}

/*
 * Update file handle information after changing a dentry.
 * This is only called by nfsd_create, nfsd_create_v3 and nfsd_proc_create
 */
__be32
fh_update(struct svc_fh *fhp)
{
	struct dentry *dentry;

	if (!fhp->fh_dentry)
		goto out_bad;

	dentry = fhp->fh_dentry;
	if (!dentry->d_inode)
		goto out_negative;
	if (fhp->fh_handle.fh_version != 1) {
		_fh_update_old(dentry, fhp->fh_export, &fhp->fh_handle);
	} else {
		if (fhp->fh_handle.fh_fileid_type != FILEID_ROOT)
			return 0;

		_fh_update(fhp, fhp->fh_export, dentry);
		if (fhp->fh_handle.fh_fileid_type == FILEID_INVALID)
			return nfserr_opnotsupp;
	}
	return 0;
out_bad:
	printk(KERN_ERR "fh_update: fh not verified!\n");
	return nfserr_serverfault;
out_negative:
	printk(KERN_ERR "fh_update: %pd2 still negative!\n",
		dentry);
	return nfserr_serverfault;
}

/*
 * Release a file handle.
 */
void
fh_put(struct svc_fh *fhp)
{
	struct dentry * dentry = fhp->fh_dentry;
	struct svc_export * exp = fhp->fh_export;
	if (dentry) {
		fh_unlock(fhp);
		fhp->fh_dentry = NULL;
		dput(dentry);
#ifdef CONFIG_NFSD_V3
		fhp->fh_pre_saved = 0;
		fhp->fh_post_saved = 0;
#endif
	}
	fh_drop_write(fhp);
	if (exp) {
		exp_put(exp);
		fhp->fh_export = NULL;
	}
	return;
}

/*
 * Shorthand for dprintk()'s
 */
char * SVCFH_fmt(struct svc_fh *fhp)
{
	struct knfsd_fh *fh = &fhp->fh_handle;

	static char buf[80];
	sprintf(buf, "%d: %08x %08x %08x %08x %08x %08x",
		fh->fh_size,
		fh->fh_base.fh_pad[0],
		fh->fh_base.fh_pad[1],
		fh->fh_base.fh_pad[2],
		fh->fh_base.fh_pad[3],
		fh->fh_base.fh_pad[4],
		fh->fh_base.fh_pad[5]);
	return buf;
}

enum fsid_source fsid_source(struct svc_fh *fhp)
{
	if (fhp->fh_handle.fh_version != 1)
		return FSIDSOURCE_DEV;
	switch(fhp->fh_handle.fh_fsid_type) {
	case FSID_DEV:
	case FSID_ENCODE_DEV:
	case FSID_MAJOR_MINOR:
		if (exp_sb(fhp->fh_export)->s_type->fs_flags & FS_REQUIRES_DEV)
			return FSIDSOURCE_DEV;
		break;
	case FSID_NUM:
		if (fhp->fh_export->ex_flags & NFSEXP_FSID)
			return FSIDSOURCE_FSID;
		break;
	default:
		break;
	}
	/* either a UUID type filehandle, or the filehandle doesn't
	 * match the export.
	 */
	if (fhp->fh_export->ex_flags & NFSEXP_FSID)
		return FSIDSOURCE_FSID;
	if (fhp->fh_export->ex_uuid)
		return FSIDSOURCE_UUID;
	return FSIDSOURCE_DEV;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfsfh.c */
/************************************************************/
/*
 * File operations used by nfsd. Some of these have been ripped from
 * other parts of the kernel because they weren't exported, others
 * are partial duplicates with added or changed functionality.
 *
 * Note that several functions dget() the dentry upon which they want
 * to act, most notably those that create directory entries. Response
 * dentry's are dput()'d if necessary in the release callback.
 * So if you notice code paths that apparently fail to dput() the
 * dentry, don't worry--they have been taken care of.
 *
 * Copyright (C) 1995-1999 Olaf Kirch <okir@monad.swb.de>
 * Zerocpy NFS support (C) 2002 Hirokazu Takahashi <taka@valinux.co.jp>
 */

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/splice.h>
#include <linux/falloc.h>
#include <linux/fcntl.h>
// #include <linux/namei.h>
#include <linux/delay.h>
#include <linux/fsnotify.h>
#include <linux/posix_acl_xattr.h>
#include <linux/xattr.h>
#include <linux/jhash.h>
#include <linux/ima.h>
// #include <linux/slab.h>
#include <asm/uaccess.h>
// #include <linux/exportfs.h>
#include <linux/writeback.h>
#include <linux/security.h>
#include "../../inc/__fss.h"

#ifdef CONFIG_NFSD_V3
#include "xdr3.h"
#include "../../inc/__fss.h"
#endif /* CONFIG_NFSD_V3 */

#ifdef CONFIG_NFSD_V4
#include "acl.h"
// #include "idmap.h"
#include "../../inc/__fss.h"
#endif /* CONFIG_NFSD_V4 */

// #include "nfsd.h"
// #include "vfs.h"

#define NFSDDBG_FACILITY		NFSDDBG_FILEOP


/*
 * This is a cache of readahead params that help us choose the proper
 * readahead strategy. Initially, we set all readahead parameters to 0
 * and let the VFS handle things.
 * If you increase the number of cached files very much, you'll need to
 * add a hash table here.
 */
struct raparms {
	struct raparms		*p_next;
	unsigned int		p_count;
	ino_t			p_ino;
	dev_t			p_dev;
	int			p_set;
	struct file_ra_state	p_ra;
	unsigned int		p_hindex;
};

struct raparm_hbucket {
	struct raparms		*pb_head;
	spinlock_t		pb_lock;
} ____cacheline_aligned_in_smp;

#define RAPARM_HASH_BITS	4
#define RAPARM_HASH_SIZE	(1<<RAPARM_HASH_BITS)
#define RAPARM_HASH_MASK	(RAPARM_HASH_SIZE-1)
static struct raparm_hbucket	raparm_hash[RAPARM_HASH_SIZE];

/* 
 * Called from nfsd_lookup and encode_dirent. Check if we have crossed 
 * a mount point.
 * Returns -EAGAIN or -ETIMEDOUT leaving *dpp and *expp unchanged,
 *  or nfs_ok having possibly changed *dpp and *expp
 */
int
nfsd_cross_mnt(struct svc_rqst *rqstp, struct dentry **dpp, 
		        struct svc_export **expp)
{
	struct svc_export *exp = *expp, *exp2 = NULL;
	struct dentry *dentry = *dpp;
	struct path path = {.mnt = mntget(exp->ex_path.mnt),
			    .dentry = dget(dentry)};
	int err = 0;

	err = follow_down(&path);
	if (err < 0)
		goto out;

	exp2 = rqst_exp_get_by_name(rqstp, &path);
	if (IS_ERR(exp2)) {
		err = PTR_ERR(exp2);
		/*
		 * We normally allow NFS clients to continue
		 * "underneath" a mountpoint that is not exported.
		 * The exception is V4ROOT, where no traversal is ever
		 * allowed without an explicit export of the new
		 * directory.
		 */
		if (err == -ENOENT && !(exp->ex_flags & NFSEXP_V4ROOT))
			err = 0;
		path_put(&path);
		goto out;
	}
	if (nfsd_v4client(rqstp) ||
		(exp->ex_flags & NFSEXP_CROSSMOUNT) || EX_NOHIDE(exp2)) {
		/* successfully crossed mount point */
		/*
		 * This is subtle: path.dentry is *not* on path.mnt
		 * at this point.  The only reason we are safe is that
		 * original mnt is pinned down by exp, so we should
		 * put path *before* putting exp
		 */
		*dpp = path.dentry;
		path.dentry = dentry;
		*expp = exp2;
		exp2 = exp;
	}
	path_put(&path);
	exp_put(exp2);
out:
	return err;
}

static void follow_to_parent(struct path *path)
{
	struct dentry *dp;

	while (path->dentry == path->mnt->mnt_root && follow_up(path))
		;
	dp = dget_parent(path->dentry);
	dput(path->dentry);
	path->dentry = dp;
}

static int nfsd_lookup_parent(struct svc_rqst *rqstp, struct dentry *dparent, struct svc_export **exp, struct dentry **dentryp)
{
	struct svc_export *exp2;
	struct path path = {.mnt = mntget((*exp)->ex_path.mnt),
			    .dentry = dget(dparent)};

	follow_to_parent(&path);

	exp2 = rqst_exp_parent(rqstp, &path);
	if (PTR_ERR(exp2) == -ENOENT) {
		*dentryp = dget(dparent);
	} else if (IS_ERR(exp2)) {
		path_put(&path);
		return PTR_ERR(exp2);
	} else {
		*dentryp = dget(path.dentry);
		exp_put(*exp);
		*exp = exp2;
	}
	path_put(&path);
	return 0;
}

/*
 * For nfsd purposes, we treat V4ROOT exports as though there was an
 * export at *every* directory.
 */
int nfsd_mountpoint(struct dentry *dentry, struct svc_export *exp)
{
	if (d_mountpoint(dentry))
		return 1;
	if (nfsd4_is_junction(dentry))
		return 1;
	if (!(exp->ex_flags & NFSEXP_V4ROOT))
		return 0;
	return dentry->d_inode != NULL;
}

__be32
nfsd_lookup_dentry(struct svc_rqst *rqstp, struct svc_fh *fhp,
		   const char *name, unsigned int len,
		   struct svc_export **exp_ret, struct dentry **dentry_ret)
{
	struct svc_export	*exp;
	struct dentry		*dparent;
	struct dentry		*dentry;
	int			host_err;

	dprintk("nfsd: nfsd_lookup(fh %s, %.*s)\n", SVCFH_fmt(fhp), len,name);

	dparent = fhp->fh_dentry;
	exp = exp_get(fhp->fh_export);

	/* Lookup the name, but don't follow links */
	if (isdotent(name, len)) {
		if (len==1)
			dentry = dget(dparent);
		else if (dparent != exp->ex_path.dentry)
			dentry = dget_parent(dparent);
		else if (!EX_NOHIDE(exp) && !nfsd_v4client(rqstp))
			dentry = dget(dparent); /* .. == . just like at / */
		else {
			/* checking mountpoint crossing is very different when stepping up */
			host_err = nfsd_lookup_parent(rqstp, dparent, &exp, &dentry);
			if (host_err)
				goto out_nfserr;
		}
	} else {
		/*
		 * In the nfsd4_open() case, this may be held across
		 * subsequent open and delegation acquisition which may
		 * need to take the child's i_mutex:
		 */
		fh_lock_nested(fhp, I_MUTEX_PARENT);
		dentry = lookup_one_len(name, dparent, len);
		host_err = PTR_ERR(dentry);
		if (IS_ERR(dentry))
			goto out_nfserr;
		/*
		 * check if we have crossed a mount point ...
		 */
		if (nfsd_mountpoint(dentry, exp)) {
			if ((host_err = nfsd_cross_mnt(rqstp, &dentry, &exp))) {
				dput(dentry);
				goto out_nfserr;
			}
		}
	}
	*dentry_ret = dentry;
	*exp_ret = exp;
	return 0;

out_nfserr:
	exp_put(exp);
	return nfserrno(host_err);
}

/*
 * Look up one component of a pathname.
 * N.B. After this call _both_ fhp and resfh need an fh_put
 *
 * If the lookup would cross a mountpoint, and the mounted filesystem
 * is exported to the client with NFSEXP_NOHIDE, then the lookup is
 * accepted as it stands and the mounted directory is
 * returned. Otherwise the covered directory is returned.
 * NOTE: this mountpoint crossing is not supported properly by all
 *   clients and is explicitly disallowed for NFSv3
 *      NeilBrown <neilb@cse.unsw.edu.au>
 */
__be32
nfsd_lookup(struct svc_rqst *rqstp, struct svc_fh *fhp, const char *name,
				unsigned int len, struct svc_fh *resfh)
{
	struct svc_export	*exp;
	struct dentry		*dentry;
	__be32 err;

	err = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_EXEC);
	if (err)
		return err;
	err = nfsd_lookup_dentry(rqstp, fhp, name, len, &exp, &dentry);
	if (err)
		return err;
	err = check_nfsd_access(exp, rqstp);
	if (err)
		goto out;
	/*
	 * Note: we compose the file handle now, but as the
	 * dentry may be negative, it may need to be updated.
	 */
	err = fh_compose(resfh, exp, dentry, fhp);
	if (!err && !dentry->d_inode)
		err = nfserr_noent;
out:
	dput(dentry);
	exp_put(exp);
	return err;
}

/*
 * Commit metadata changes to stable storage.
 */
static int
commit_metadata(struct svc_fh *fhp)
{
	struct inode *inode = fhp->fh_dentry->d_inode;
	const struct export_operations *export_ops = inode->i_sb->s_export_op;

	if (!EX_ISSYNC(fhp->fh_export))
		return 0;

	if (export_ops->commit_metadata)
		return export_ops->commit_metadata(inode);
	return sync_inode_metadata(inode, 1);
}

/*
 * Go over the attributes and take care of the small differences between
 * NFS semantics and what Linux expects.
 */
static void
nfsd_sanitize_attrs(struct inode *inode, struct iattr *iap)
{
	/*
	 * NFSv2 does not differentiate between "set-[ac]time-to-now"
	 * which only requires access, and "set-[ac]time-to-X" which
	 * requires ownership.
	 * So if it looks like it might be "set both to the same time which
	 * is close to now", and if inode_change_ok fails, then we
	 * convert to "set to now" instead of "set to explicit time"
	 *
	 * We only call inode_change_ok as the last test as technically
	 * it is not an interface that we should be using.
	 */
#define BOTH_TIME_SET (ATTR_ATIME_SET | ATTR_MTIME_SET)
#define	MAX_TOUCH_TIME_ERROR (30*60)
	if ((iap->ia_valid & BOTH_TIME_SET) == BOTH_TIME_SET &&
	    iap->ia_mtime.tv_sec == iap->ia_atime.tv_sec) {
		/*
		 * Looks probable.
		 *
		 * Now just make sure time is in the right ballpark.
		 * Solaris, at least, doesn't seem to care what the time
		 * request is.  We require it be within 30 minutes of now.
		 */
		time_t delta = iap->ia_atime.tv_sec - get_seconds();
		if (delta < 0)
			delta = -delta;
		if (delta < MAX_TOUCH_TIME_ERROR &&
		    inode_change_ok(inode, iap) != 0) {
			/*
			 * Turn off ATTR_[AM]TIME_SET but leave ATTR_[AM]TIME.
			 * This will cause notify_change to set these times
			 * to "now"
			 */
			iap->ia_valid &= ~BOTH_TIME_SET;
		}
	}

	/* sanitize the mode change */
	if (iap->ia_valid & ATTR_MODE) {
		iap->ia_mode &= S_IALLUGO;
		iap->ia_mode |= (inode->i_mode & ~S_IALLUGO);
	}

	/* Revoke setuid/setgid on chown */
	if (!S_ISDIR(inode->i_mode) &&
	    ((iap->ia_valid & ATTR_UID) || (iap->ia_valid & ATTR_GID))) {
		iap->ia_valid |= ATTR_KILL_PRIV;
		if (iap->ia_valid & ATTR_MODE) {
			/* we're setting mode too, just clear the s*id bits */
			iap->ia_mode &= ~S_ISUID;
			if (iap->ia_mode & S_IXGRP)
				iap->ia_mode &= ~S_ISGID;
		} else {
			/* set ATTR_KILL_* bits and let VFS handle it */
			iap->ia_valid |= (ATTR_KILL_SUID | ATTR_KILL_SGID);
		}
	}
}

static __be32
nfsd_get_write_access(struct svc_rqst *rqstp, struct svc_fh *fhp,
		struct iattr *iap)
{
	struct inode *inode = fhp->fh_dentry->d_inode;
	int host_err;

	if (iap->ia_size < inode->i_size) {
		__be32 err;

		err = nfsd_permission(rqstp, fhp->fh_export, fhp->fh_dentry,
				NFSD_MAY_TRUNC | NFSD_MAY_OWNER_OVERRIDE);
		if (err)
			return err;
	}

	host_err = get_write_access(inode);
	if (host_err)
		goto out_nfserrno;

	host_err = locks_verify_truncate(inode, NULL, iap->ia_size);
	if (host_err)
		goto out_put_write_access;
	return 0;

out_put_write_access:
	put_write_access(inode);
out_nfserrno:
	return nfserrno(host_err);
}

/*
 * Set various file attributes.  After this call fhp needs an fh_put.
 */
__be32
nfsd_setattr(struct svc_rqst *rqstp, struct svc_fh *fhp, struct iattr *iap,
	     int check_guard, time_t guardtime)
{
	struct dentry	*dentry;
	struct inode	*inode;
	int		accmode = NFSD_MAY_SATTR;
	umode_t		ftype = 0;
	__be32		err;
	int		host_err;
	bool		get_write_count;
	int		size_change = 0;

	if (iap->ia_valid & (ATTR_ATIME | ATTR_MTIME | ATTR_SIZE))
		accmode |= NFSD_MAY_WRITE|NFSD_MAY_OWNER_OVERRIDE;
	if (iap->ia_valid & ATTR_SIZE)
		ftype = S_IFREG;

	/* Callers that do fh_verify should do the fh_want_write: */
	get_write_count = !fhp->fh_dentry;

	/* Get inode */
	err = fh_verify(rqstp, fhp, ftype, accmode);
	if (err)
		goto out;
	if (get_write_count) {
		host_err = fh_want_write(fhp);
		if (host_err)
			return nfserrno(host_err);
	}

	dentry = fhp->fh_dentry;
	inode = dentry->d_inode;

	/* Ignore any mode updates on symlinks */
	if (S_ISLNK(inode->i_mode))
		iap->ia_valid &= ~ATTR_MODE;

	if (!iap->ia_valid)
		goto out;

	nfsd_sanitize_attrs(inode, iap);

	/*
	 * The size case is special, it changes the file in addition to the
	 * attributes.
	 */
	if (iap->ia_valid & ATTR_SIZE) {
		err = nfsd_get_write_access(rqstp, fhp, iap);
		if (err)
			goto out;
		size_change = 1;

		/*
		 * RFC5661, Section 18.30.4:
		 *   Changing the size of a file with SETATTR indirectly
		 *   changes the time_modify and change attributes.
		 *
		 * (and similar for the older RFCs)
		 */
		if (iap->ia_size != i_size_read(inode))
			iap->ia_valid |= ATTR_MTIME;
	}

	iap->ia_valid |= ATTR_CTIME;

	if (check_guard && guardtime != inode->i_ctime.tv_sec) {
		err = nfserr_notsync;
		goto out_put_write_access;
	}

	fh_lock(fhp);
	host_err = notify_change(dentry, iap, NULL);
	fh_unlock(fhp);
	err = nfserrno(host_err);

out_put_write_access:
	if (size_change)
		put_write_access(inode);
	if (!err)
		err = nfserrno(commit_metadata(fhp));
out:
	return err;
}

#if defined(CONFIG_NFSD_V4)
/*
 * NFS junction information is stored in an extended attribute.
 */
#define NFSD_JUNCTION_XATTR_NAME	XATTR_TRUSTED_PREFIX "junction.nfs"

/**
 * nfsd4_is_junction - Test if an object could be an NFS junction
 *
 * @dentry: object to test
 *
 * Returns 1 if "dentry" appears to contain NFS junction information.
 * Otherwise 0 is returned.
 */
int nfsd4_is_junction(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	if (inode == NULL)
		return 0;
	if (inode->i_mode & S_IXUGO)
		return 0;
	if (!(inode->i_mode & S_ISVTX))
		return 0;
	if (vfs_getxattr(dentry, NFSD_JUNCTION_XATTR_NAME, NULL, 0) <= 0)
		return 0;
	return 1;
}
#ifdef CONFIG_NFSD_V4_SECURITY_LABEL
__be32 nfsd4_set_nfs4_label(struct svc_rqst *rqstp, struct svc_fh *fhp,
		struct xdr_netobj *label)
{
	__be32 error;
	int host_error;
	struct dentry *dentry;

	error = fh_verify(rqstp, fhp, 0 /* S_IFREG */, NFSD_MAY_SATTR);
	if (error)
		return error;

	dentry = fhp->fh_dentry;

	mutex_lock(&dentry->d_inode->i_mutex);
	host_error = security_inode_setsecctx(dentry, label->data, label->len);
	mutex_unlock(&dentry->d_inode->i_mutex);
	return nfserrno(host_error);
}
#else
__be32 nfsd4_set_nfs4_label(struct svc_rqst *rqstp, struct svc_fh *fhp,
		struct xdr_netobj *label)
{
	return nfserr_notsupp;
}
#endif

__be32 nfsd4_vfs_fallocate(struct svc_rqst *rqstp, struct svc_fh *fhp,
			   struct file *file, loff_t offset, loff_t len,
			   int flags)
{
	__be32 err;
	int error;

	if (!S_ISREG(file_inode(file)->i_mode))
		return nfserr_inval;

	err = nfsd_permission(rqstp, fhp->fh_export, fhp->fh_dentry, NFSD_MAY_WRITE);
	if (err)
		return err;

	error = vfs_fallocate(file, flags, offset, len);
	if (!error)
		error = commit_metadata(fhp);

	return nfserrno(error);
}
#endif /* defined(CONFIG_NFSD_V4) */

#ifdef CONFIG_NFSD_V3
/*
 * Check server access rights to a file system object
 */
struct accessmap {
	u32		access;
	int		how;
};
static struct accessmap	nfs3_regaccess[] = {
    {	NFS3_ACCESS_READ,	NFSD_MAY_READ			},
    {	NFS3_ACCESS_EXECUTE,	NFSD_MAY_EXEC			},
    {	NFS3_ACCESS_MODIFY,	NFSD_MAY_WRITE|NFSD_MAY_TRUNC	},
    {	NFS3_ACCESS_EXTEND,	NFSD_MAY_WRITE			},

    {	0,			0				}
};

static struct accessmap	nfs3_diraccess[] = {
    {	NFS3_ACCESS_READ,	NFSD_MAY_READ			},
    {	NFS3_ACCESS_LOOKUP,	NFSD_MAY_EXEC			},
    {	NFS3_ACCESS_MODIFY,	NFSD_MAY_EXEC|NFSD_MAY_WRITE|NFSD_MAY_TRUNC},
    {	NFS3_ACCESS_EXTEND,	NFSD_MAY_EXEC|NFSD_MAY_WRITE	},
    {	NFS3_ACCESS_DELETE,	NFSD_MAY_REMOVE			},

    {	0,			0				}
};

static struct accessmap	nfs3_anyaccess[] = {
	/* Some clients - Solaris 2.6 at least, make an access call
	 * to the server to check for access for things like /dev/null
	 * (which really, the server doesn't care about).  So
	 * We provide simple access checking for them, looking
	 * mainly at mode bits, and we make sure to ignore read-only
	 * filesystem checks
	 */
    {	NFS3_ACCESS_READ,	NFSD_MAY_READ			},
    {	NFS3_ACCESS_EXECUTE,	NFSD_MAY_EXEC			},
    {	NFS3_ACCESS_MODIFY,	NFSD_MAY_WRITE|NFSD_MAY_LOCAL_ACCESS	},
    {	NFS3_ACCESS_EXTEND,	NFSD_MAY_WRITE|NFSD_MAY_LOCAL_ACCESS	},

    {	0,			0				}
};

__be32
nfsd_access(struct svc_rqst *rqstp, struct svc_fh *fhp, u32 *access, u32 *supported)
{
	struct accessmap	*map;
	struct svc_export	*export;
	struct dentry		*dentry;
	u32			query, result = 0, sresult = 0;
	__be32			error;

	error = fh_verify(rqstp, fhp, 0, NFSD_MAY_NOP);
	if (error)
		goto out;

	export = fhp->fh_export;
	dentry = fhp->fh_dentry;

	if (d_is_reg(dentry))
		map = nfs3_regaccess;
	else if (d_is_dir(dentry))
		map = nfs3_diraccess;
	else
		map = nfs3_anyaccess;


	query = *access;
	for  (; map->access; map++) {
		if (map->access & query) {
			__be32 err2;

			sresult |= map->access;

			err2 = nfsd_permission(rqstp, export, dentry, map->how);
			switch (err2) {
			case nfs_ok:
				result |= map->access;
				break;
				
			/* the following error codes just mean the access was not allowed,
			 * rather than an error occurred */
			case nfserr_rofs:
			case nfserr_acces:
			case nfserr_perm:
				/* simply don't "or" in the access bit. */
				break;
			default:
				error = err2;
				goto out;
			}
		}
	}
	*access = result;
	if (supported)
		*supported = sresult;

 out:
	return error;
}
#endif /* CONFIG_NFSD_V3 */

static int nfsd_open_break_lease(struct inode *inode, int access)
{
	unsigned int mode;

	if (access & NFSD_MAY_NOT_BREAK_LEASE)
		return 0;
	mode = (access & NFSD_MAY_WRITE) ? O_WRONLY : O_RDONLY;
	return break_lease(inode, mode | O_NONBLOCK);
}

/*
 * Open an existing file or directory.
 * The may_flags argument indicates the type of open (read/write/lock)
 * and additional flags.
 * N.B. After this call fhp needs an fh_put
 */
__be32
nfsd_open(struct svc_rqst *rqstp, struct svc_fh *fhp, umode_t type,
			int may_flags, struct file **filp)
{
	struct path	path;
	struct inode	*inode;
	struct file	*file;
	int		flags = O_RDONLY|O_LARGEFILE;
	__be32		err;
	int		host_err = 0;

	validate_process_creds();

	/*
	 * If we get here, then the client has already done an "open",
	 * and (hopefully) checked permission - so allow OWNER_OVERRIDE
	 * in case a chmod has now revoked permission.
	 *
	 * Arguably we should also allow the owner override for
	 * directories, but we never have and it doesn't seem to have
	 * caused anyone a problem.  If we were to change this, note
	 * also that our filldir callbacks would need a variant of
	 * lookup_one_len that doesn't check permissions.
	 */
	if (type == S_IFREG)
		may_flags |= NFSD_MAY_OWNER_OVERRIDE;
	err = fh_verify(rqstp, fhp, type, may_flags);
	if (err)
		goto out;

	path.mnt = fhp->fh_export->ex_path.mnt;
	path.dentry = fhp->fh_dentry;
	inode = path.dentry->d_inode;

	/* Disallow write access to files with the append-only bit set
	 * or any access when mandatory locking enabled
	 */
	err = nfserr_perm;
	if (IS_APPEND(inode) && (may_flags & NFSD_MAY_WRITE))
		goto out;
	/*
	 * We must ignore files (but only files) which might have mandatory
	 * locks on them because there is no way to know if the accesser has
	 * the lock.
	 */
	if (S_ISREG((inode)->i_mode) && mandatory_lock(inode))
		goto out;

	if (!inode->i_fop)
		goto out;

	host_err = nfsd_open_break_lease(inode, may_flags);
	if (host_err) /* NOMEM or WOULDBLOCK */
		goto out_nfserr;

	if (may_flags & NFSD_MAY_WRITE) {
		if (may_flags & NFSD_MAY_READ)
			flags = O_RDWR|O_LARGEFILE;
		else
			flags = O_WRONLY|O_LARGEFILE;
	}

	file = dentry_open(&path, flags, current_cred());
	if (IS_ERR(file)) {
		host_err = PTR_ERR(file);
		goto out_nfserr;
	}

	host_err = ima_file_check(file, may_flags, 0);
	if (host_err) {
		nfsd_close(file);
		goto out_nfserr;
	}

	if (may_flags & NFSD_MAY_64BIT_COOKIE)
		file->f_mode |= FMODE_64BITHASH;
	else
		file->f_mode |= FMODE_32BITHASH;

	*filp = file;
out_nfserr:
	err = nfserrno(host_err);
out:
	validate_process_creds();
	return err;
}

/*
 * Close a file.
 */
void
nfsd_close(struct file *filp)
{
	fput(filp);
}

/*
 * Obtain the readahead parameters for the file
 * specified by (dev, ino).
 */

static inline struct raparms *
nfsd_get_raparms(dev_t dev, ino_t ino)
{
	struct raparms	*ra, **rap, **frap = NULL;
	int depth = 0;
	unsigned int hash;
	struct raparm_hbucket *rab;

	hash = jhash_2words(dev, ino, 0xfeedbeef) & RAPARM_HASH_MASK;
	rab = &raparm_hash[hash];

	spin_lock(&rab->pb_lock);
	for (rap = &rab->pb_head; (ra = *rap); rap = &ra->p_next) {
		if (ra->p_ino == ino && ra->p_dev == dev)
			goto found;
		depth++;
		if (ra->p_count == 0)
			frap = rap;
	}
	depth = nfsdstats.ra_size;
	if (!frap) {	
		spin_unlock(&rab->pb_lock);
		return NULL;
	}
	rap = frap;
	ra = *frap;
	ra->p_dev = dev;
	ra->p_ino = ino;
	ra->p_set = 0;
	ra->p_hindex = hash;
found:
	if (rap != &rab->pb_head) {
		*rap = ra->p_next;
		ra->p_next   = rab->pb_head;
		rab->pb_head = ra;
	}
	ra->p_count++;
	nfsdstats.ra_depth[depth*10/nfsdstats.ra_size]++;
	spin_unlock(&rab->pb_lock);
	return ra;
}

/*
 * Grab and keep cached pages associated with a file in the svc_rqst
 * so that they can be passed to the network sendmsg/sendpage routines
 * directly. They will be released after the sending has completed.
 */
static int
nfsd_splice_actor(struct pipe_inode_info *pipe, struct pipe_buffer *buf,
		  struct splice_desc *sd)
{
	struct svc_rqst *rqstp = sd->u.data;
	struct page **pp = rqstp->rq_next_page;
	struct page *page = buf->page;
	size_t size;

	size = sd->len;

	if (rqstp->rq_res.page_len == 0) {
		get_page(page);
		put_page(*rqstp->rq_next_page);
		*(rqstp->rq_next_page++) = page;
		rqstp->rq_res.page_base = buf->offset;
		rqstp->rq_res.page_len = size;
	} else if (page != pp[-1]) {
		get_page(page);
		if (*rqstp->rq_next_page)
			put_page(*rqstp->rq_next_page);
		*(rqstp->rq_next_page++) = page;
		rqstp->rq_res.page_len += size;
	} else
		rqstp->rq_res.page_len += size;

	return size;
}

static int nfsd_direct_splice_actor(struct pipe_inode_info *pipe,
				    struct splice_desc *sd)
{
	return __splice_from_pipe(pipe, sd, nfsd_splice_actor);
}

static __be32
nfsd_finish_read(struct file *file, unsigned long *count, int host_err)
{
	if (host_err >= 0) {
		nfsdstats.io_read += host_err;
		*count = host_err;
		fsnotify_access(file);
		return 0;
	} else 
		return nfserrno(host_err);
}

__be32 nfsd_splice_read(struct svc_rqst *rqstp,
		     struct file *file, loff_t offset, unsigned long *count)
{
	struct splice_desc sd = {
		.len		= 0,
		.total_len	= *count,
		.pos		= offset,
		.u.data		= rqstp,
	};
	int host_err;

	rqstp->rq_next_page = rqstp->rq_respages + 1;
	host_err = splice_direct_to_actor(file, &sd, nfsd_direct_splice_actor);
	return nfsd_finish_read(file, count, host_err);
}

__be32 nfsd_readv(struct file *file, loff_t offset, struct kvec *vec, int vlen,
		unsigned long *count)
{
	mm_segment_t oldfs;
	int host_err;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	host_err = vfs_readv(file, (struct iovec __user *)vec, vlen, &offset);
	set_fs(oldfs);
	return nfsd_finish_read(file, count, host_err);
}

static __be32
nfsd_vfs_read(struct svc_rqst *rqstp, struct file *file,
	      loff_t offset, struct kvec *vec, int vlen, unsigned long *count)
{
	if (file->f_op->splice_read && test_bit(RQ_SPLICE_OK, &rqstp->rq_flags))
		return nfsd_splice_read(rqstp, file, offset, count);
	else
		return nfsd_readv(file, offset, vec, vlen, count);
}

/*
 * Gathered writes: If another process is currently writing to the file,
 * there's a high chance this is another nfsd (triggered by a bulk write
 * from a client's biod). Rather than syncing the file with each write
 * request, we sleep for 10 msec.
 *
 * I don't know if this roughly approximates C. Juszak's idea of
 * gathered writes, but it's a nice and simple solution (IMHO), and it
 * seems to work:-)
 *
 * Note: we do this only in the NFSv2 case, since v3 and higher have a
 * better tool (separate unstable writes and commits) for solving this
 * problem.
 */
static int wait_for_concurrent_writes(struct file *file)
{
	struct inode *inode = file_inode(file);
	static ino_t last_ino;
	static dev_t last_dev;
	int err = 0;

	if (atomic_read(&inode->i_writecount) > 1
	    || (last_ino == inode->i_ino && last_dev == inode->i_sb->s_dev)) {
		dprintk("nfsd: write defer %d\n", task_pid_nr(current));
		msleep(10);
		dprintk("nfsd: write resume %d\n", task_pid_nr(current));
	}

	if (inode->i_state & I_DIRTY) {
		dprintk("nfsd: write sync %d\n", task_pid_nr(current));
		err = vfs_fsync(file, 0);
	}
	last_ino = inode->i_ino;
	last_dev = inode->i_sb->s_dev;
	return err;
}

static __be32
nfsd_vfs_write(struct svc_rqst *rqstp, struct svc_fh *fhp, struct file *file,
				loff_t offset, struct kvec *vec, int vlen,
				unsigned long *cnt, int *stablep)
{
	struct svc_export	*exp;
	struct inode		*inode;
	mm_segment_t		oldfs;
	__be32			err = 0;
	int			host_err;
	int			stable = *stablep;
	int			use_wgather;
	loff_t			pos = offset;
	loff_t			end = LLONG_MAX;
	unsigned int		pflags = current->flags;

	if (test_bit(RQ_LOCAL, &rqstp->rq_flags))
		/*
		 * We want less throttling in balance_dirty_pages()
		 * and shrink_inactive_list() so that nfs to
		 * localhost doesn't cause nfsd to lock up due to all
		 * the client's dirty pages or its congested queue.
		 */
		current->flags |= PF_LESS_THROTTLE;

	inode = file_inode(file);
	exp   = fhp->fh_export;

	use_wgather = (rqstp->rq_vers == 2) && EX_WGATHER(exp);

	if (!EX_ISSYNC(exp))
		stable = 0;

	/* Write the data. */
	oldfs = get_fs(); set_fs(KERNEL_DS);
	host_err = vfs_writev(file, (struct iovec __user *)vec, vlen, &pos);
	set_fs(oldfs);
	if (host_err < 0)
		goto out_nfserr;
	*cnt = host_err;
	nfsdstats.io_write += host_err;
	fsnotify_modify(file);

	if (stable) {
		if (use_wgather) {
			host_err = wait_for_concurrent_writes(file);
		} else {
			if (*cnt)
				end = offset + *cnt - 1;
			host_err = vfs_fsync_range(file, offset, end, 0);
		}
	}

out_nfserr:
	dprintk("nfsd: write complete host_err=%d\n", host_err);
	if (host_err >= 0)
		err = 0;
	else
		err = nfserrno(host_err);
	if (test_bit(RQ_LOCAL, &rqstp->rq_flags))
		tsk_restore_flags(current, pflags, PF_LESS_THROTTLE);
	return err;
}

__be32 nfsd_get_tmp_read_open(struct svc_rqst *rqstp, struct svc_fh *fhp,
		struct file **file, struct raparms **ra)
{
	struct inode *inode;
	__be32 err;

	err = nfsd_open(rqstp, fhp, S_IFREG, NFSD_MAY_READ, file);
	if (err)
		return err;

	inode = file_inode(*file);

	/* Get readahead parameters */
	*ra = nfsd_get_raparms(inode->i_sb->s_dev, inode->i_ino);

	if (*ra && (*ra)->p_set)
		(*file)->f_ra = (*ra)->p_ra;
	return nfs_ok;
}

void nfsd_put_tmp_read_open(struct file *file, struct raparms *ra)
{
	/* Write back readahead params */
	if (ra) {
		struct raparm_hbucket *rab = &raparm_hash[ra->p_hindex];
		spin_lock(&rab->pb_lock);
		ra->p_ra = file->f_ra;
		ra->p_set = 1;
		ra->p_count--;
		spin_unlock(&rab->pb_lock);
	}
	nfsd_close(file);
}

/*
 * Read data from a file. count must contain the requested read count
 * on entry. On return, *count contains the number of bytes actually read.
 * N.B. After this call fhp needs an fh_put
 */
__be32 nfsd_read(struct svc_rqst *rqstp, struct svc_fh *fhp,
	loff_t offset, struct kvec *vec, int vlen, unsigned long *count)
{
	struct file *file;
	struct raparms	*ra;
	__be32 err;

	err = nfsd_get_tmp_read_open(rqstp, fhp, &file, &ra);
	if (err)
		return err;

	err = nfsd_vfs_read(rqstp, file, offset, vec, vlen, count);

	nfsd_put_tmp_read_open(file, ra);

	return err;
}

/*
 * Write data to a file.
 * The stable flag requests synchronous writes.
 * N.B. After this call fhp needs an fh_put
 */
__be32
nfsd_write(struct svc_rqst *rqstp, struct svc_fh *fhp, struct file *file,
		loff_t offset, struct kvec *vec, int vlen, unsigned long *cnt,
		int *stablep)
{
	__be32			err = 0;

	if (file) {
		err = nfsd_permission(rqstp, fhp->fh_export, fhp->fh_dentry,
				NFSD_MAY_WRITE|NFSD_MAY_OWNER_OVERRIDE);
		if (err)
			goto out;
		err = nfsd_vfs_write(rqstp, fhp, file, offset, vec, vlen, cnt,
				stablep);
	} else {
		err = nfsd_open(rqstp, fhp, S_IFREG, NFSD_MAY_WRITE, &file);
		if (err)
			goto out;

		if (cnt)
			err = nfsd_vfs_write(rqstp, fhp, file, offset, vec, vlen,
					     cnt, stablep);
		nfsd_close(file);
	}
out:
	return err;
}

#ifdef CONFIG_NFSD_V3
/*
 * Commit all pending writes to stable storage.
 *
 * Note: we only guarantee that data that lies within the range specified
 * by the 'offset' and 'count' parameters will be synced.
 *
 * Unfortunately we cannot lock the file to make sure we return full WCC
 * data to the client, as locking happens lower down in the filesystem.
 */
__be32
nfsd_commit(struct svc_rqst *rqstp, struct svc_fh *fhp,
               loff_t offset, unsigned long count)
{
	struct file	*file;
	loff_t		end = LLONG_MAX;
	__be32		err = nfserr_inval;

	if (offset < 0)
		goto out;
	if (count != 0) {
		end = offset + (loff_t)count - 1;
		if (end < offset)
			goto out;
	}

	err = nfsd_open(rqstp, fhp, S_IFREG,
			NFSD_MAY_WRITE|NFSD_MAY_NOT_BREAK_LEASE, &file);
	if (err)
		goto out;
	if (EX_ISSYNC(fhp->fh_export)) {
		int err2 = vfs_fsync_range(file, offset, end, 0);

		if (err2 != -EINVAL)
			err = nfserrno(err2);
		else
			err = nfserr_notsupp;
	}

	nfsd_close(file);
out:
	return err;
}
#endif /* CONFIG_NFSD_V3 */

static __be32
nfsd_create_setattr(struct svc_rqst *rqstp, struct svc_fh *resfhp,
			struct iattr *iap)
{
	/*
	 * Mode has already been set earlier in create:
	 */
	iap->ia_valid &= ~ATTR_MODE;
	/*
	 * Setting uid/gid works only for root.  Irix appears to
	 * send along the gid on create when it tries to implement
	 * setgid directories via NFS:
	 */
	if (!uid_eq(current_fsuid(), GLOBAL_ROOT_UID))
		iap->ia_valid &= ~(ATTR_UID|ATTR_GID);
	if (iap->ia_valid)
		return nfsd_setattr(rqstp, resfhp, iap, 0, (time_t)0);
	/* Callers expect file metadata to be committed here */
	return nfserrno(commit_metadata(resfhp));
}

/* HPUX client sometimes creates a file in mode 000, and sets size to 0.
 * setting size to 0 may fail for some specific file systems by the permission
 * checking which requires WRITE permission but the mode is 000.
 * we ignore the resizing(to 0) on the just new created file, since the size is
 * 0 after file created.
 *
 * call this only after vfs_create() is called.
 * */
static void
nfsd_check_ignore_resizing(struct iattr *iap)
{
	if ((iap->ia_valid & ATTR_SIZE) && (iap->ia_size == 0))
		iap->ia_valid &= ~ATTR_SIZE;
}

/*
 * Create a file (regular, directory, device, fifo); UNIX sockets 
 * not yet implemented.
 * If the response fh has been verified, the parent directory should
 * already be locked. Note that the parent directory is left locked.
 *
 * N.B. Every call to nfsd_create needs an fh_put for _both_ fhp and resfhp
 */
__be32
nfsd_create(struct svc_rqst *rqstp, struct svc_fh *fhp,
		char *fname, int flen, struct iattr *iap,
		int type, dev_t rdev, struct svc_fh *resfhp)
{
	struct dentry	*dentry, *dchild = NULL;
	struct inode	*dirp;
	__be32		err;
	__be32		err2;
	int		host_err;

	err = nfserr_perm;
	if (!flen)
		goto out;
	err = nfserr_exist;
	if (isdotent(fname, flen))
		goto out;

	err = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_CREATE);
	if (err)
		goto out;

	dentry = fhp->fh_dentry;
	dirp = dentry->d_inode;

	err = nfserr_notdir;
	if (!dirp->i_op->lookup)
		goto out;
	/*
	 * Check whether the response file handle has been verified yet.
	 * If it has, the parent directory should already be locked.
	 */
	if (!resfhp->fh_dentry) {
		host_err = fh_want_write(fhp);
		if (host_err)
			goto out_nfserr;

		/* called from nfsd_proc_mkdir, or possibly nfsd3_proc_create */
		fh_lock_nested(fhp, I_MUTEX_PARENT);
		dchild = lookup_one_len(fname, dentry, flen);
		host_err = PTR_ERR(dchild);
		if (IS_ERR(dchild))
			goto out_nfserr;
		err = fh_compose(resfhp, fhp->fh_export, dchild, fhp);
		if (err)
			goto out;
	} else {
		/* called from nfsd_proc_create */
		dchild = dget(resfhp->fh_dentry);
		if (!fhp->fh_locked) {
			/* not actually possible */
			printk(KERN_ERR
				"nfsd_create: parent %pd2 not locked!\n",
				dentry);
			err = nfserr_io;
			goto out;
		}
	}
	/*
	 * Make sure the child dentry is still negative ...
	 */
	err = nfserr_exist;
	if (dchild->d_inode) {
		dprintk("nfsd_create: dentry %pd/%pd not negative!\n",
			dentry, dchild);
		goto out; 
	}

	if (!(iap->ia_valid & ATTR_MODE))
		iap->ia_mode = 0;
	iap->ia_mode = (iap->ia_mode & S_IALLUGO) | type;

	err = nfserr_inval;
	if (!S_ISREG(type) && !S_ISDIR(type) && !special_file(type)) {
		printk(KERN_WARNING "nfsd: bad file type %o in nfsd_create\n",
		       type);
		goto out;
	}

	/*
	 * Get the dir op function pointer.
	 */
	err = 0;
	host_err = 0;
	switch (type) {
	case S_IFREG:
		host_err = vfs_create(dirp, dchild, iap->ia_mode, true);
		if (!host_err)
			nfsd_check_ignore_resizing(iap);
		break;
	case S_IFDIR:
		host_err = vfs_mkdir(dirp, dchild, iap->ia_mode);
		break;
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		host_err = vfs_mknod(dirp, dchild, iap->ia_mode, rdev);
		break;
	}
	if (host_err < 0)
		goto out_nfserr;

	err = nfsd_create_setattr(rqstp, resfhp, iap);

	/*
	 * nfsd_create_setattr already committed the child.  Transactional
	 * filesystems had a chance to commit changes for both parent and
	 * child * simultaneously making the following commit_metadata a
	 * noop.
	 */
	err2 = nfserrno(commit_metadata(fhp));
	if (err2)
		err = err2;
	/*
	 * Update the file handle to get the new inode info.
	 */
	if (!err)
		err = fh_update(resfhp);
out:
	if (dchild && !IS_ERR(dchild))
		dput(dchild);
	return err;

out_nfserr:
	err = nfserrno(host_err);
	goto out;
}

#ifdef CONFIG_NFSD_V3

static inline int nfsd_create_is_exclusive(int createmode)
{
	return createmode == NFS3_CREATE_EXCLUSIVE
	       || createmode == NFS4_CREATE_EXCLUSIVE4_1;
}

/*
 * NFSv3 and NFSv4 version of nfsd_create
 */
__be32
do_nfsd_create(struct svc_rqst *rqstp, struct svc_fh *fhp,
		char *fname, int flen, struct iattr *iap,
		struct svc_fh *resfhp, int createmode, u32 *verifier,
	        bool *truncp, bool *created)
{
	struct dentry	*dentry, *dchild = NULL;
	struct inode	*dirp;
	__be32		err;
	int		host_err;
	__u32		v_mtime=0, v_atime=0;

	err = nfserr_perm;
	if (!flen)
		goto out;
	err = nfserr_exist;
	if (isdotent(fname, flen))
		goto out;
	if (!(iap->ia_valid & ATTR_MODE))
		iap->ia_mode = 0;
	err = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_EXEC);
	if (err)
		goto out;

	dentry = fhp->fh_dentry;
	dirp = dentry->d_inode;

	/* Get all the sanity checks out of the way before
	 * we lock the parent. */
	err = nfserr_notdir;
	if (!dirp->i_op->lookup)
		goto out;

	host_err = fh_want_write(fhp);
	if (host_err)
		goto out_nfserr;

	fh_lock_nested(fhp, I_MUTEX_PARENT);

	/*
	 * Compose the response file handle.
	 */
	dchild = lookup_one_len(fname, dentry, flen);
	host_err = PTR_ERR(dchild);
	if (IS_ERR(dchild))
		goto out_nfserr;

	/* If file doesn't exist, check for permissions to create one */
	if (!dchild->d_inode) {
		err = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_CREATE);
		if (err)
			goto out;
	}

	err = fh_compose(resfhp, fhp->fh_export, dchild, fhp);
	if (err)
		goto out;

	if (nfsd_create_is_exclusive(createmode)) {
		/* solaris7 gets confused (bugid 4218508) if these have
		 * the high bit set, so just clear the high bits. If this is
		 * ever changed to use different attrs for storing the
		 * verifier, then do_open_lookup() will also need to be fixed
		 * accordingly.
		 */
		v_mtime = verifier[0]&0x7fffffff;
		v_atime = verifier[1]&0x7fffffff;
	}
	
	if (dchild->d_inode) {
		err = 0;

		switch (createmode) {
		case NFS3_CREATE_UNCHECKED:
			if (! d_is_reg(dchild))
				goto out;
			else if (truncp) {
				/* in nfsv4, we need to treat this case a little
				 * differently.  we don't want to truncate the
				 * file now; this would be wrong if the OPEN
				 * fails for some other reason.  furthermore,
				 * if the size is nonzero, we should ignore it
				 * according to spec!
				 */
				*truncp = (iap->ia_valid & ATTR_SIZE) && !iap->ia_size;
			}
			else {
				iap->ia_valid &= ATTR_SIZE;
				goto set_attr;
			}
			break;
		case NFS3_CREATE_EXCLUSIVE:
			if (   dchild->d_inode->i_mtime.tv_sec == v_mtime
			    && dchild->d_inode->i_atime.tv_sec == v_atime
			    && dchild->d_inode->i_size  == 0 ) {
				if (created)
					*created = 1;
				break;
			}
		case NFS4_CREATE_EXCLUSIVE4_1:
			if (   dchild->d_inode->i_mtime.tv_sec == v_mtime
			    && dchild->d_inode->i_atime.tv_sec == v_atime
			    && dchild->d_inode->i_size  == 0 ) {
				if (created)
					*created = 1;
				goto set_attr;
			}
			 /* fallthru */
		case NFS3_CREATE_GUARDED:
			err = nfserr_exist;
		}
		fh_drop_write(fhp);
		goto out;
	}

	host_err = vfs_create(dirp, dchild, iap->ia_mode, true);
	if (host_err < 0) {
		fh_drop_write(fhp);
		goto out_nfserr;
	}
	if (created)
		*created = 1;

	nfsd_check_ignore_resizing(iap);

	if (nfsd_create_is_exclusive(createmode)) {
		/* Cram the verifier into atime/mtime */
		iap->ia_valid = ATTR_MTIME|ATTR_ATIME
			| ATTR_MTIME_SET|ATTR_ATIME_SET;
		/* XXX someone who knows this better please fix it for nsec */ 
		iap->ia_mtime.tv_sec = v_mtime;
		iap->ia_atime.tv_sec = v_atime;
		iap->ia_mtime.tv_nsec = 0;
		iap->ia_atime.tv_nsec = 0;
	}

 set_attr:
	err = nfsd_create_setattr(rqstp, resfhp, iap);

	/*
	 * nfsd_create_setattr already committed the child
	 * (and possibly also the parent).
	 */
	if (!err)
		err = nfserrno(commit_metadata(fhp));

	/*
	 * Update the filehandle to get the new inode info.
	 */
	if (!err)
		err = fh_update(resfhp);

 out:
	fh_unlock(fhp);
	if (dchild && !IS_ERR(dchild))
		dput(dchild);
	fh_drop_write(fhp);
 	return err;
 
 out_nfserr:
	err = nfserrno(host_err);
	goto out;
}
#endif /* CONFIG_NFSD_V3 */

/*
 * Read a symlink. On entry, *lenp must contain the maximum path length that
 * fits into the buffer. On return, it contains the true length.
 * N.B. After this call fhp needs an fh_put
 */
__be32
nfsd_readlink(struct svc_rqst *rqstp, struct svc_fh *fhp, char *buf, int *lenp)
{
	struct inode	*inode;
	mm_segment_t	oldfs;
	__be32		err;
	int		host_err;
	struct path path;

	err = fh_verify(rqstp, fhp, S_IFLNK, NFSD_MAY_NOP);
	if (err)
		goto out;

	path.mnt = fhp->fh_export->ex_path.mnt;
	path.dentry = fhp->fh_dentry;
	inode = path.dentry->d_inode;

	err = nfserr_inval;
	if (!inode->i_op->readlink)
		goto out;

	touch_atime(&path);
	/* N.B. Why does this call need a get_fs()??
	 * Remove the set_fs and watch the fireworks:-) --okir
	 */

	oldfs = get_fs(); set_fs(KERNEL_DS);
	host_err = inode->i_op->readlink(path.dentry, (char __user *)buf, *lenp);
	set_fs(oldfs);

	if (host_err < 0)
		goto out_nfserr;
	*lenp = host_err;
	err = 0;
out:
	return err;

out_nfserr:
	err = nfserrno(host_err);
	goto out;
}

/*
 * Create a symlink and look up its inode
 * N.B. After this call _both_ fhp and resfhp need an fh_put
 */
__be32
nfsd_symlink(struct svc_rqst *rqstp, struct svc_fh *fhp,
				char *fname, int flen,
				char *path,
				struct svc_fh *resfhp)
{
	struct dentry	*dentry, *dnew;
	__be32		err, cerr;
	int		host_err;

	err = nfserr_noent;
	if (!flen || path[0] == '\0')
		goto out;
	err = nfserr_exist;
	if (isdotent(fname, flen))
		goto out;

	err = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_CREATE);
	if (err)
		goto out;

	host_err = fh_want_write(fhp);
	if (host_err)
		goto out_nfserr;

	fh_lock(fhp);
	dentry = fhp->fh_dentry;
	dnew = lookup_one_len(fname, dentry, flen);
	host_err = PTR_ERR(dnew);
	if (IS_ERR(dnew))
		goto out_nfserr;

	host_err = vfs_symlink(dentry->d_inode, dnew, path);
	err = nfserrno(host_err);
	if (!err)
		err = nfserrno(commit_metadata(fhp));
	fh_unlock(fhp);

	fh_drop_write(fhp);

	cerr = fh_compose(resfhp, fhp->fh_export, dnew, fhp);
	dput(dnew);
	if (err==0) err = cerr;
out:
	return err;

out_nfserr:
	err = nfserrno(host_err);
	goto out;
}

/*
 * Create a hardlink
 * N.B. After this call _both_ ffhp and tfhp need an fh_put
 */
__be32
nfsd_link(struct svc_rqst *rqstp, struct svc_fh *ffhp,
				char *name, int len, struct svc_fh *tfhp)
{
	struct dentry	*ddir, *dnew, *dold;
	struct inode	*dirp;
	__be32		err;
	int		host_err;

	err = fh_verify(rqstp, ffhp, S_IFDIR, NFSD_MAY_CREATE);
	if (err)
		goto out;
	err = fh_verify(rqstp, tfhp, 0, NFSD_MAY_NOP);
	if (err)
		goto out;
	err = nfserr_isdir;
	if (d_is_dir(tfhp->fh_dentry))
		goto out;
	err = nfserr_perm;
	if (!len)
		goto out;
	err = nfserr_exist;
	if (isdotent(name, len))
		goto out;

	host_err = fh_want_write(tfhp);
	if (host_err) {
		err = nfserrno(host_err);
		goto out;
	}

	fh_lock_nested(ffhp, I_MUTEX_PARENT);
	ddir = ffhp->fh_dentry;
	dirp = ddir->d_inode;

	dnew = lookup_one_len(name, ddir, len);
	host_err = PTR_ERR(dnew);
	if (IS_ERR(dnew))
		goto out_nfserr;

	dold = tfhp->fh_dentry;

	err = nfserr_noent;
	if (!dold->d_inode)
		goto out_dput;
	host_err = vfs_link(dold, dirp, dnew, NULL);
	if (!host_err) {
		err = nfserrno(commit_metadata(ffhp));
		if (!err)
			err = nfserrno(commit_metadata(tfhp));
	} else {
		if (host_err == -EXDEV && rqstp->rq_vers == 2)
			err = nfserr_acces;
		else
			err = nfserrno(host_err);
	}
out_dput:
	dput(dnew);
out_unlock:
	fh_unlock(ffhp);
	fh_drop_write(tfhp);
out:
	return err;

out_nfserr:
	err = nfserrno(host_err);
	goto out_unlock;
}

/*
 * Rename a file
 * N.B. After this call _both_ ffhp and tfhp need an fh_put
 */
__be32
nfsd_rename(struct svc_rqst *rqstp, struct svc_fh *ffhp, char *fname, int flen,
			    struct svc_fh *tfhp, char *tname, int tlen)
{
	struct dentry	*fdentry, *tdentry, *odentry, *ndentry, *trap;
	struct inode	*fdir, *tdir;
	__be32		err;
	int		host_err;

	err = fh_verify(rqstp, ffhp, S_IFDIR, NFSD_MAY_REMOVE);
	if (err)
		goto out;
	err = fh_verify(rqstp, tfhp, S_IFDIR, NFSD_MAY_CREATE);
	if (err)
		goto out;

	fdentry = ffhp->fh_dentry;
	fdir = fdentry->d_inode;

	tdentry = tfhp->fh_dentry;
	tdir = tdentry->d_inode;

	err = nfserr_perm;
	if (!flen || isdotent(fname, flen) || !tlen || isdotent(tname, tlen))
		goto out;

	host_err = fh_want_write(ffhp);
	if (host_err) {
		err = nfserrno(host_err);
		goto out;
	}

	/* cannot use fh_lock as we need deadlock protective ordering
	 * so do it by hand */
	trap = lock_rename(tdentry, fdentry);
	ffhp->fh_locked = tfhp->fh_locked = 1;
	fill_pre_wcc(ffhp);
	fill_pre_wcc(tfhp);

	odentry = lookup_one_len(fname, fdentry, flen);
	host_err = PTR_ERR(odentry);
	if (IS_ERR(odentry))
		goto out_nfserr;

	host_err = -ENOENT;
	if (!odentry->d_inode)
		goto out_dput_old;
	host_err = -EINVAL;
	if (odentry == trap)
		goto out_dput_old;

	ndentry = lookup_one_len(tname, tdentry, tlen);
	host_err = PTR_ERR(ndentry);
	if (IS_ERR(ndentry))
		goto out_dput_old;
	host_err = -ENOTEMPTY;
	if (ndentry == trap)
		goto out_dput_new;

	host_err = -EXDEV;
	if (ffhp->fh_export->ex_path.mnt != tfhp->fh_export->ex_path.mnt)
		goto out_dput_new;
	if (ffhp->fh_export->ex_path.dentry != tfhp->fh_export->ex_path.dentry)
		goto out_dput_new;

	host_err = vfs_rename(fdir, odentry, tdir, ndentry, NULL, 0);
	if (!host_err) {
		host_err = commit_metadata(tfhp);
		if (!host_err)
			host_err = commit_metadata(ffhp);
	}
 out_dput_new:
	dput(ndentry);
 out_dput_old:
	dput(odentry);
 out_nfserr:
	err = nfserrno(host_err);
	/*
	 * We cannot rely on fh_unlock on the two filehandles,
	 * as that would do the wrong thing if the two directories
	 * were the same, so again we do it by hand.
	 */
	fill_post_wcc(ffhp);
	fill_post_wcc(tfhp);
	unlock_rename(tdentry, fdentry);
	ffhp->fh_locked = tfhp->fh_locked = 0;
	fh_drop_write(ffhp);

out:
	return err;
}

/*
 * Unlink a file or directory
 * N.B. After this call fhp needs an fh_put
 */
__be32
nfsd_unlink(struct svc_rqst *rqstp, struct svc_fh *fhp, int type,
				char *fname, int flen)
{
	struct dentry	*dentry, *rdentry;
	struct inode	*dirp;
	__be32		err;
	int		host_err;

	err = nfserr_acces;
	if (!flen || isdotent(fname, flen))
		goto out;
	err = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_REMOVE);
	if (err)
		goto out;

	host_err = fh_want_write(fhp);
	if (host_err)
		goto out_nfserr;

	fh_lock_nested(fhp, I_MUTEX_PARENT);
	dentry = fhp->fh_dentry;
	dirp = dentry->d_inode;

	rdentry = lookup_one_len(fname, dentry, flen);
	host_err = PTR_ERR(rdentry);
	if (IS_ERR(rdentry))
		goto out_nfserr;

	if (!rdentry->d_inode) {
		dput(rdentry);
		err = nfserr_noent;
		goto out;
	}

	if (!type)
		type = rdentry->d_inode->i_mode & S_IFMT;

	if (type != S_IFDIR)
		host_err = vfs_unlink(dirp, rdentry, NULL);
	else
		host_err = vfs_rmdir(dirp, rdentry);
	if (!host_err)
		host_err = commit_metadata(fhp);
	dput(rdentry);

out_nfserr:
	err = nfserrno(host_err);
out:
	return err;
}

/*
 * We do this buffering because we must not call back into the file
 * system's ->lookup() method from the filldir callback. That may well
 * deadlock a number of file systems.
 *
 * This is based heavily on the implementation of same in XFS.
 */
struct buffered_dirent {
	u64		ino;
	loff_t		offset;
	int		namlen;
	unsigned int	d_type;
	char		name[];
};

struct readdir_data {
	struct dir_context ctx;
	char		*dirent;
	size_t		used;
	int		full;
};

static int nfsd_buffered_filldir(struct dir_context *ctx, const char *name,
				 int namlen, loff_t offset, u64 ino,
				 unsigned int d_type)
{
	struct readdir_data *buf =
		container_of(ctx, struct readdir_data, ctx);
	struct buffered_dirent *de = (void *)(buf->dirent + buf->used);
	unsigned int reclen;

	reclen = ALIGN(sizeof(struct buffered_dirent) + namlen, sizeof(u64));
	if (buf->used + reclen > PAGE_SIZE) {
		buf->full = 1;
		return -EINVAL;
	}

	de->namlen = namlen;
	de->offset = offset;
	de->ino = ino;
	de->d_type = d_type;
	memcpy(de->name, name, namlen);
	buf->used += reclen;

	return 0;
}

static __be32 nfsd_buffered_readdir(struct file *file, nfsd_filldir_t func,
				    struct readdir_cd *cdp, loff_t *offsetp)
{
	struct buffered_dirent *de;
	int host_err;
	int size;
	loff_t offset;
	struct readdir_data buf = {
		.ctx.actor = nfsd_buffered_filldir,
		.dirent = (void *)__get_free_page(GFP_KERNEL)
	};

	if (!buf.dirent)
		return nfserrno(-ENOMEM);

	offset = *offsetp;

	while (1) {
		struct inode *dir_inode = file_inode(file);
		unsigned int reclen;

		cdp->err = nfserr_eof; /* will be cleared on successful read */
		buf.used = 0;
		buf.full = 0;

		host_err = iterate_dir(file, &buf.ctx);
		if (buf.full)
			host_err = 0;

		if (host_err < 0)
			break;

		size = buf.used;

		if (!size)
			break;

		/*
		 * Various filldir functions may end up calling back into
		 * lookup_one_len() and the file system's ->lookup() method.
		 * These expect i_mutex to be held, as it would within readdir.
		 */
		host_err = mutex_lock_killable(&dir_inode->i_mutex);
		if (host_err)
			break;

		de = (struct buffered_dirent *)buf.dirent;
		while (size > 0) {
			offset = de->offset;

			if (func(cdp, de->name, de->namlen, de->offset,
				 de->ino, de->d_type))
				break;

			if (cdp->err != nfs_ok)
				break;

			reclen = ALIGN(sizeof(*de) + de->namlen,
				       sizeof(u64));
			size -= reclen;
			de = (struct buffered_dirent *)((char *)de + reclen);
		}
		mutex_unlock(&dir_inode->i_mutex);
		if (size > 0) /* We bailed out early */
			break;

		offset = vfs_llseek(file, 0, SEEK_CUR);
	}

	free_page((unsigned long)(buf.dirent));

	if (host_err)
		return nfserrno(host_err);

	*offsetp = offset;
	return cdp->err;
}

/*
 * Read entries from a directory.
 * The  NFSv3/4 verifier we ignore for now.
 */
__be32
nfsd_readdir(struct svc_rqst *rqstp, struct svc_fh *fhp, loff_t *offsetp, 
	     struct readdir_cd *cdp, nfsd_filldir_t func)
{
	__be32		err;
	struct file	*file;
	loff_t		offset = *offsetp;
	int             may_flags = NFSD_MAY_READ;

	/* NFSv2 only supports 32 bit cookies */
	if (rqstp->rq_vers > 2)
		may_flags |= NFSD_MAY_64BIT_COOKIE;

	err = nfsd_open(rqstp, fhp, S_IFDIR, may_flags, &file);
	if (err)
		goto out;

	offset = vfs_llseek(file, offset, SEEK_SET);
	if (offset < 0) {
		err = nfserrno((int)offset);
		goto out_close;
	}

	err = nfsd_buffered_readdir(file, func, cdp, offsetp);

	if (err == nfserr_eof || err == nfserr_toosmall)
		err = nfs_ok; /* can still be found in ->err */
out_close:
	nfsd_close(file);
out:
	return err;
}

/*
 * Get file system stats
 * N.B. After this call fhp needs an fh_put
 */
__be32
nfsd_statfs(struct svc_rqst *rqstp, struct svc_fh *fhp, struct kstatfs *stat, int access)
{
	__be32 err;

	err = fh_verify(rqstp, fhp, 0, NFSD_MAY_NOP | access);
	if (!err) {
		struct path path = {
			.mnt	= fhp->fh_export->ex_path.mnt,
			.dentry	= fhp->fh_dentry,
		};
		if (vfs_statfs(&path, stat))
			err = nfserr_io;
	}
	return err;
}

static int exp_rdonly(struct svc_rqst *rqstp, struct svc_export *exp)
{
	return nfsexp_flags(rqstp, exp) & NFSEXP_READONLY;
}

/*
 * Check for a user's access permissions to this inode.
 */
__be32
nfsd_permission(struct svc_rqst *rqstp, struct svc_export *exp,
					struct dentry *dentry, int acc)
{
	struct inode	*inode = dentry->d_inode;
	int		err;

	if ((acc & NFSD_MAY_MASK) == NFSD_MAY_NOP)
		return 0;
#if 0
	dprintk("nfsd: permission 0x%x%s%s%s%s%s%s%s mode 0%o%s%s%s\n",
		acc,
		(acc & NFSD_MAY_READ)?	" read"  : "",
		(acc & NFSD_MAY_WRITE)?	" write" : "",
		(acc & NFSD_MAY_EXEC)?	" exec"  : "",
		(acc & NFSD_MAY_SATTR)?	" sattr" : "",
		(acc & NFSD_MAY_TRUNC)?	" trunc" : "",
		(acc & NFSD_MAY_LOCK)?	" lock"  : "",
		(acc & NFSD_MAY_OWNER_OVERRIDE)? " owneroverride" : "",
		inode->i_mode,
		IS_IMMUTABLE(inode)?	" immut" : "",
		IS_APPEND(inode)?	" append" : "",
		__mnt_is_readonly(exp->ex_path.mnt)?	" ro" : "");
	dprintk("      owner %d/%d user %d/%d\n",
		inode->i_uid, inode->i_gid, current_fsuid(), current_fsgid());
#endif

	/* Normally we reject any write/sattr etc access on a read-only file
	 * system.  But if it is IRIX doing check on write-access for a 
	 * device special file, we ignore rofs.
	 */
	if (!(acc & NFSD_MAY_LOCAL_ACCESS))
		if (acc & (NFSD_MAY_WRITE | NFSD_MAY_SATTR | NFSD_MAY_TRUNC)) {
			if (exp_rdonly(rqstp, exp) ||
			    __mnt_is_readonly(exp->ex_path.mnt))
				return nfserr_rofs;
			if (/* (acc & NFSD_MAY_WRITE) && */ IS_IMMUTABLE(inode))
				return nfserr_perm;
		}
	if ((acc & NFSD_MAY_TRUNC) && IS_APPEND(inode))
		return nfserr_perm;

	if (acc & NFSD_MAY_LOCK) {
		/* If we cannot rely on authentication in NLM requests,
		 * just allow locks, otherwise require read permission, or
		 * ownership
		 */
		if (exp->ex_flags & NFSEXP_NOAUTHNLM)
			return 0;
		else
			acc = NFSD_MAY_READ | NFSD_MAY_OWNER_OVERRIDE;
	}
	/*
	 * The file owner always gets access permission for accesses that
	 * would normally be checked at open time. This is to make
	 * file access work even when the client has done a fchmod(fd, 0).
	 *
	 * However, `cp foo bar' should fail nevertheless when bar is
	 * readonly. A sensible way to do this might be to reject all
	 * attempts to truncate a read-only file, because a creat() call
	 * always implies file truncation.
	 * ... but this isn't really fair.  A process may reasonably call
	 * ftruncate on an open file descriptor on a file with perm 000.
	 * We must trust the client to do permission checking - using "ACCESS"
	 * with NFSv3.
	 */
	if ((acc & NFSD_MAY_OWNER_OVERRIDE) &&
	    uid_eq(inode->i_uid, current_fsuid()))
		return 0;

	/* This assumes  NFSD_MAY_{READ,WRITE,EXEC} == MAY_{READ,WRITE,EXEC} */
	err = inode_permission(inode, acc & (MAY_READ|MAY_WRITE|MAY_EXEC));

	/* Allow read access to binaries even when mode 111 */
	if (err == -EACCES && S_ISREG(inode->i_mode) &&
	     (acc == (NFSD_MAY_READ | NFSD_MAY_OWNER_OVERRIDE) ||
	      acc == (NFSD_MAY_READ | NFSD_MAY_READ_IF_EXEC)))
		err = inode_permission(inode, MAY_EXEC);

	return err? nfserrno(err) : 0;
}

void
nfsd_racache_shutdown(void)
{
	struct raparms *raparm, *last_raparm;
	unsigned int i;

	dprintk("nfsd: freeing readahead buffers.\n");

	for (i = 0; i < RAPARM_HASH_SIZE; i++) {
		raparm = raparm_hash[i].pb_head;
		while(raparm) {
			last_raparm = raparm;
			raparm = raparm->p_next;
			kfree(last_raparm);
		}
		raparm_hash[i].pb_head = NULL;
	}
}
/*
 * Initialize readahead param cache
 */
int
nfsd_racache_init(int cache_size)
{
	int	i;
	int	j = 0;
	int	nperbucket;
	struct raparms **raparm = NULL;


	if (raparm_hash[0].pb_head)
		return 0;
	nperbucket = DIV_ROUND_UP(cache_size, RAPARM_HASH_SIZE);
	nperbucket = max(2, nperbucket);
	cache_size = nperbucket * RAPARM_HASH_SIZE;

	dprintk("nfsd: allocating %d readahead buffers.\n", cache_size);

	for (i = 0; i < RAPARM_HASH_SIZE; i++) {
		spin_lock_init(&raparm_hash[i].pb_lock);

		raparm = &raparm_hash[i].pb_head;
		for (j = 0; j < nperbucket; j++) {
			*raparm = kzalloc(sizeof(struct raparms), GFP_KERNEL);
			if (!*raparm)
				goto out_nomem;
			raparm = &(*raparm)->p_next;
		}
		*raparm = NULL;
	}

	nfsdstats.ra_size = cache_size;
	return 0;

out_nomem:
	dprintk("nfsd: kmalloc failed, freeing readahead buffers\n");
	nfsd_racache_shutdown();
	return -ENOMEM;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/vfs.c */
/************************************************************/
/*
 * NFS exporting and validation.
 *
 * We maintain a list of clients, each of which has a list of
 * exports. To export an fs to a given client, you first have
 * to create the client entry with NFSCTL_ADDCLIENT, which
 * creates a client control block and adds it to the hash
 * table. Then, you call NFSCTL_EXPORT for each fs.
 *
 *
 * Copyright (C) 1995, 1996 Olaf Kirch, <okir@monad.swb.de>
 */

// #include <linux/slab.h>
// #include <linux/namei.h>
// #include <linux/module.h>
// #include <linux/exportfs.h>
#include <linux/sunrpc/svc_xprt.h>
#include "../../inc/__fss.h"

// #include "nfsd.h"
#include "nfsfh.h"
// #include "netns.h"
// #include "pnfs.h"
#include "../../inc/__fss.h"

#define NFSDDBG_FACILITY	NFSDDBG_EXPORT

/*
 * We have two caches.
 * One maps client+vfsmnt+dentry to export options - the export map
 * The other maps client+filehandle-fragment to export options. - the expkey map
 *
 * The export options are actually stored in the first map, and the
 * second map contains a reference to the entry in the first map.
 */

#define	EXPKEY_HASHBITS		8
#define	EXPKEY_HASHMAX		(1 << EXPKEY_HASHBITS)
#define	EXPKEY_HASHMASK		(EXPKEY_HASHMAX -1)

static void expkey_put(struct kref *ref)
{
	struct svc_expkey *key = container_of(ref, struct svc_expkey, h.ref);

	if (test_bit(CACHE_VALID, &key->h.flags) &&
	    !test_bit(CACHE_NEGATIVE, &key->h.flags))
		path_put(&key->ek_path);
	auth_domain_put(key->ek_client);
	kfree(key);
}

static void expkey_request(struct cache_detail *cd,
			   struct cache_head *h,
			   char **bpp, int *blen)
{
	/* client fsidtype \xfsid */
	struct svc_expkey *ek = container_of(h, struct svc_expkey, h);
	char type[5];

	qword_add(bpp, blen, ek->ek_client->name);
	snprintf(type, 5, "%d", ek->ek_fsidtype);
	qword_add(bpp, blen, type);
	qword_addhex(bpp, blen, (char*)ek->ek_fsid, key_len(ek->ek_fsidtype));
	(*bpp)[-1] = '\n';
}

static struct svc_expkey *svc_expkey_update(struct cache_detail *cd, struct svc_expkey *new,
					    struct svc_expkey *old);
static struct svc_expkey *svc_expkey_lookup(struct cache_detail *cd, struct svc_expkey *);

static int expkey_parse(struct cache_detail *cd, char *mesg, int mlen)
{
	/* client fsidtype fsid expiry [path] */
	char *buf;
	int len;
	struct auth_domain *dom = NULL;
	int err;
	int fsidtype;
	char *ep;
	struct svc_expkey key;
	struct svc_expkey *ek = NULL;

	if (mesg[mlen - 1] != '\n')
		return -EINVAL;
	mesg[mlen-1] = 0;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	err = -ENOMEM;
	if (!buf)
		goto out;

	err = -EINVAL;
	if ((len=qword_get(&mesg, buf, PAGE_SIZE)) <= 0)
		goto out;

	err = -ENOENT;
	dom = auth_domain_find(buf);
	if (!dom)
		goto out;
	dprintk("found domain %s\n", buf);

	err = -EINVAL;
	if ((len=qword_get(&mesg, buf, PAGE_SIZE)) <= 0)
		goto out;
	fsidtype = simple_strtoul(buf, &ep, 10);
	if (*ep)
		goto out;
	dprintk("found fsidtype %d\n", fsidtype);
	if (key_len(fsidtype)==0) /* invalid type */
		goto out;
	if ((len=qword_get(&mesg, buf, PAGE_SIZE)) <= 0)
		goto out;
	dprintk("found fsid length %d\n", len);
	if (len != key_len(fsidtype))
		goto out;

	/* OK, we seem to have a valid key */
	key.h.flags = 0;
	key.h.expiry_time = get_expiry(&mesg);
	if (key.h.expiry_time == 0)
		goto out;

	key.ek_client = dom;	
	key.ek_fsidtype = fsidtype;
	memcpy(key.ek_fsid, buf, len);

	ek = svc_expkey_lookup(cd, &key);
	err = -ENOMEM;
	if (!ek)
		goto out;

	/* now we want a pathname, or empty meaning NEGATIVE  */
	err = -EINVAL;
	len = qword_get(&mesg, buf, PAGE_SIZE);
	if (len < 0)
		goto out;
	dprintk("Path seems to be <%s>\n", buf);
	err = 0;
	if (len == 0) {
		set_bit(CACHE_NEGATIVE, &key.h.flags);
		ek = svc_expkey_update(cd, &key, ek);
		if (!ek)
			err = -ENOMEM;
	} else {
		err = kern_path(buf, 0, &key.ek_path);
		if (err)
			goto out;

		dprintk("Found the path %s\n", buf);

		ek = svc_expkey_update(cd, &key, ek);
		if (!ek)
			err = -ENOMEM;
		path_put(&key.ek_path);
	}
	cache_flush();
 out:
	if (ek)
		cache_put(&ek->h, cd);
	if (dom)
		auth_domain_put(dom);
	kfree(buf);
	return err;
}

static int expkey_show(struct seq_file *m,
		       struct cache_detail *cd,
		       struct cache_head *h)
{
	struct svc_expkey *ek ;
	int i;

	if (h ==NULL) {
		seq_puts(m, "#domain fsidtype fsid [path]\n");
		return 0;
	}
	ek = container_of(h, struct svc_expkey, h);
	seq_printf(m, "%s %d 0x", ek->ek_client->name,
		   ek->ek_fsidtype);
	for (i=0; i < key_len(ek->ek_fsidtype)/4; i++)
		seq_printf(m, "%08x", ek->ek_fsid[i]);
	if (test_bit(CACHE_VALID, &h->flags) && 
	    !test_bit(CACHE_NEGATIVE, &h->flags)) {
		seq_printf(m, " ");
		seq_path(m, &ek->ek_path, "\\ \t\n");
	}
	seq_printf(m, "\n");
	return 0;
}

static inline int expkey_match (struct cache_head *a, struct cache_head *b)
{
	struct svc_expkey *orig = container_of(a, struct svc_expkey, h);
	struct svc_expkey *new = container_of(b, struct svc_expkey, h);

	if (orig->ek_fsidtype != new->ek_fsidtype ||
	    orig->ek_client != new->ek_client ||
	    memcmp(orig->ek_fsid, new->ek_fsid, key_len(orig->ek_fsidtype)) != 0)
		return 0;
	return 1;
}

static inline void expkey_init(struct cache_head *cnew,
				   struct cache_head *citem)
{
	struct svc_expkey *new = container_of(cnew, struct svc_expkey, h);
	struct svc_expkey *item = container_of(citem, struct svc_expkey, h);

	kref_get(&item->ek_client->ref);
	new->ek_client = item->ek_client;
	new->ek_fsidtype = item->ek_fsidtype;

	memcpy(new->ek_fsid, item->ek_fsid, sizeof(new->ek_fsid));
}

static inline void expkey_update(struct cache_head *cnew,
				   struct cache_head *citem)
{
	struct svc_expkey *new = container_of(cnew, struct svc_expkey, h);
	struct svc_expkey *item = container_of(citem, struct svc_expkey, h);

	new->ek_path = item->ek_path;
	path_get(&item->ek_path);
}

static struct cache_head *expkey_alloc(void)
{
	struct svc_expkey *i = kmalloc(sizeof(*i), GFP_KERNEL);
	if (i)
		return &i->h;
	else
		return NULL;
}

static struct cache_detail svc_expkey_cache_template = {
	.owner		= THIS_MODULE,
	.hash_size	= EXPKEY_HASHMAX,
	.name		= "nfsd.fh",
	.cache_put	= expkey_put,
	.cache_request	= expkey_request,
	.cache_parse	= expkey_parse,
	.cache_show	= expkey_show,
	.match		= expkey_match,
	.init		= expkey_init,
	.update       	= expkey_update,
	.alloc		= expkey_alloc,
};

static int
svc_expkey_hash(struct svc_expkey *item)
{
	int hash = item->ek_fsidtype;
	char * cp = (char*)item->ek_fsid;
	int len = key_len(item->ek_fsidtype);

	hash ^= hash_mem(cp, len, EXPKEY_HASHBITS);
	hash ^= hash_ptr(item->ek_client, EXPKEY_HASHBITS);
	hash &= EXPKEY_HASHMASK;
	return hash;
}

static struct svc_expkey *
svc_expkey_lookup(struct cache_detail *cd, struct svc_expkey *item)
{
	struct cache_head *ch;
	int hash = svc_expkey_hash(item);

	ch = sunrpc_cache_lookup(cd, &item->h, hash);
	if (ch)
		return container_of(ch, struct svc_expkey, h);
	else
		return NULL;
}

static struct svc_expkey *
svc_expkey_update(struct cache_detail *cd, struct svc_expkey *new,
		  struct svc_expkey *old)
{
	struct cache_head *ch;
	int hash = svc_expkey_hash(new);

	ch = sunrpc_cache_update(cd, &new->h, &old->h, hash);
	if (ch)
		return container_of(ch, struct svc_expkey, h);
	else
		return NULL;
}


#define	EXPORT_HASHBITS		8
#define	EXPORT_HASHMAX		(1<< EXPORT_HASHBITS)

static void nfsd4_fslocs_free(struct nfsd4_fs_locations *fsloc)
{
	struct nfsd4_fs_location *locations = fsloc->locations;
	int i;

	if (!locations)
		return;

	for (i = 0; i < fsloc->locations_count; i++) {
		kfree(locations[i].path);
		kfree(locations[i].hosts);
	}

	kfree(locations);
	fsloc->locations = NULL;
}

static void svc_export_put(struct kref *ref)
{
	struct svc_export *exp = container_of(ref, struct svc_export, h.ref);
	path_put(&exp->ex_path);
	auth_domain_put(exp->ex_client);
	nfsd4_fslocs_free(&exp->ex_fslocs);
	kfree(exp->ex_uuid);
	kfree(exp);
}

static void svc_export_request(struct cache_detail *cd,
			       struct cache_head *h,
			       char **bpp, int *blen)
{
	/*  client path */
	struct svc_export *exp = container_of(h, struct svc_export, h);
	char *pth;

	qword_add(bpp, blen, exp->ex_client->name);
	pth = d_path(&exp->ex_path, *bpp, *blen);
	if (IS_ERR(pth)) {
		/* is this correct? */
		(*bpp)[0] = '\n';
		return;
	}
	qword_add(bpp, blen, pth);
	(*bpp)[-1] = '\n';
}

static struct svc_export *svc_export_update(struct svc_export *new,
					    struct svc_export *old);
static struct svc_export *svc_export_lookup(struct svc_export *);

static int check_export(struct inode *inode, int *flags, unsigned char *uuid)
{

	/*
	 * We currently export only dirs, regular files, and (for v4
	 * pseudoroot) symlinks.
	 */
	if (!S_ISDIR(inode->i_mode) &&
	    !S_ISLNK(inode->i_mode) &&
	    !S_ISREG(inode->i_mode))
		return -ENOTDIR;

	/*
	 * Mountd should never pass down a writeable V4ROOT export, but,
	 * just to make sure:
	 */
	if (*flags & NFSEXP_V4ROOT)
		*flags |= NFSEXP_READONLY;

	/* There are two requirements on a filesystem to be exportable.
	 * 1:  We must be able to identify the filesystem from a number.
	 *       either a device number (so FS_REQUIRES_DEV needed)
	 *       or an FSID number (so NFSEXP_FSID or ->uuid is needed).
	 * 2:  We must be able to find an inode from a filehandle.
	 *       This means that s_export_op must be set.
	 */
	if (!(inode->i_sb->s_type->fs_flags & FS_REQUIRES_DEV) &&
	    !(*flags & NFSEXP_FSID) &&
	    uuid == NULL) {
		dprintk("exp_export: export of non-dev fs without fsid\n");
		return -EINVAL;
	}

	if (!inode->i_sb->s_export_op ||
	    !inode->i_sb->s_export_op->fh_to_dentry) {
		dprintk("exp_export: export of invalid fs type.\n");
		return -EINVAL;
	}

	return 0;

}

#ifdef CONFIG_NFSD_V4

static int
fsloc_parse(char **mesg, char *buf, struct nfsd4_fs_locations *fsloc)
{
	int len;
	int migrated, i, err;

	/* more than one fsloc */
	if (fsloc->locations)
		return -EINVAL;

	/* listsize */
	err = get_uint(mesg, &fsloc->locations_count);
	if (err)
		return err;
	if (fsloc->locations_count > MAX_FS_LOCATIONS)
		return -EINVAL;
	if (fsloc->locations_count == 0)
		return 0;

	fsloc->locations = kzalloc(fsloc->locations_count
			* sizeof(struct nfsd4_fs_location), GFP_KERNEL);
	if (!fsloc->locations)
		return -ENOMEM;
	for (i=0; i < fsloc->locations_count; i++) {
		/* colon separated host list */
		err = -EINVAL;
		len = qword_get(mesg, buf, PAGE_SIZE);
		if (len <= 0)
			goto out_free_all;
		err = -ENOMEM;
		fsloc->locations[i].hosts = kstrdup(buf, GFP_KERNEL);
		if (!fsloc->locations[i].hosts)
			goto out_free_all;
		err = -EINVAL;
		/* slash separated path component list */
		len = qword_get(mesg, buf, PAGE_SIZE);
		if (len <= 0)
			goto out_free_all;
		err = -ENOMEM;
		fsloc->locations[i].path = kstrdup(buf, GFP_KERNEL);
		if (!fsloc->locations[i].path)
			goto out_free_all;
	}
	/* migrated */
	err = get_int(mesg, &migrated);
	if (err)
		goto out_free_all;
	err = -EINVAL;
	if (migrated < 0 || migrated > 1)
		goto out_free_all;
	fsloc->migrated = migrated;
	return 0;
out_free_all:
	nfsd4_fslocs_free(fsloc);
	return err;
}

static int secinfo_parse(char **mesg, char *buf, struct svc_export *exp)
{
	struct exp_flavor_info *f;
	u32 listsize;
	int err;

	/* more than one secinfo */
	if (exp->ex_nflavors)
		return -EINVAL;

	err = get_uint(mesg, &listsize);
	if (err)
		return err;
	if (listsize > MAX_SECINFO_LIST)
		return -EINVAL;

	for (f = exp->ex_flavors; f < exp->ex_flavors + listsize; f++) {
		err = get_uint(mesg, &f->pseudoflavor);
		if (err)
			return err;
		/*
		 * XXX: It would be nice to also check whether this
		 * pseudoflavor is supported, so we can discover the
		 * problem at export time instead of when a client fails
		 * to authenticate.
		 */
		err = get_uint(mesg, &f->flags);
		if (err)
			return err;
		/* Only some flags are allowed to differ between flavors: */
		if (~NFSEXP_SECINFO_FLAGS & (f->flags ^ exp->ex_flags))
			return -EINVAL;
	}
	exp->ex_nflavors = listsize;
	return 0;
}

#else /* CONFIG_NFSD_V4 */
static inline int
fsloc_parse(char **mesg, char *buf, struct nfsd4_fs_locations *fsloc){return 0;}
static inline int
secinfo_parse(char **mesg, char *buf, struct svc_export *exp) { return 0; }
#endif

static inline int
uuid_parse(char **mesg, char *buf, unsigned char **puuid)
{
	int len;

	/* more than one uuid */
	if (*puuid)
		return -EINVAL;

	/* expect a 16 byte uuid encoded as \xXXXX... */
	len = qword_get(mesg, buf, PAGE_SIZE);
	if (len != EX_UUID_LEN)
		return -EINVAL;

	*puuid = kmemdup(buf, EX_UUID_LEN, GFP_KERNEL);
	if (*puuid == NULL)
		return -ENOMEM;

	return 0;
}

static int svc_export_parse(struct cache_detail *cd, char *mesg, int mlen)
{
	/* client path expiry [flags anonuid anongid fsid] */
	char *buf;
	int len;
	int err;
	struct auth_domain *dom = NULL;
	struct svc_export exp = {}, *expp;
	int an_int;

	if (mesg[mlen-1] != '\n')
		return -EINVAL;
	mesg[mlen-1] = 0;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* client */
	err = -EINVAL;
	len = qword_get(&mesg, buf, PAGE_SIZE);
	if (len <= 0)
		goto out;

	err = -ENOENT;
	dom = auth_domain_find(buf);
	if (!dom)
		goto out;

	/* path */
	err = -EINVAL;
	if ((len = qword_get(&mesg, buf, PAGE_SIZE)) <= 0)
		goto out1;

	err = kern_path(buf, 0, &exp.ex_path);
	if (err)
		goto out1;

	exp.ex_client = dom;
	exp.cd = cd;
	exp.ex_devid_map = NULL;

	/* expiry */
	err = -EINVAL;
	exp.h.expiry_time = get_expiry(&mesg);
	if (exp.h.expiry_time == 0)
		goto out3;

	/* flags */
	err = get_int(&mesg, &an_int);
	if (err == -ENOENT) {
		err = 0;
		set_bit(CACHE_NEGATIVE, &exp.h.flags);
	} else {
		if (err || an_int < 0)
			goto out3;
		exp.ex_flags= an_int;
	
		/* anon uid */
		err = get_int(&mesg, &an_int);
		if (err)
			goto out3;
		exp.ex_anon_uid= make_kuid(&init_user_ns, an_int);

		/* anon gid */
		err = get_int(&mesg, &an_int);
		if (err)
			goto out3;
		exp.ex_anon_gid= make_kgid(&init_user_ns, an_int);

		/* fsid */
		err = get_int(&mesg, &an_int);
		if (err)
			goto out3;
		exp.ex_fsid = an_int;

		while ((len = qword_get(&mesg, buf, PAGE_SIZE)) > 0) {
			if (strcmp(buf, "fsloc") == 0)
				err = fsloc_parse(&mesg, buf, &exp.ex_fslocs);
			else if (strcmp(buf, "uuid") == 0)
				err = uuid_parse(&mesg, buf, &exp.ex_uuid);
			else if (strcmp(buf, "secinfo") == 0)
				err = secinfo_parse(&mesg, buf, &exp);
			else
				/* quietly ignore unknown words and anything
				 * following. Newer user-space can try to set
				 * new values, then see what the result was.
				 */
				break;
			if (err)
				goto out4;
		}

		err = check_export(exp.ex_path.dentry->d_inode, &exp.ex_flags,
				   exp.ex_uuid);
		if (err)
			goto out4;
		/*
		 * No point caching this if it would immediately expire.
		 * Also, this protects exportfs's dummy export from the
		 * anon_uid/anon_gid checks:
		 */
		if (exp.h.expiry_time < seconds_since_boot())
			goto out4;
		/*
		 * For some reason exportfs has been passing down an
		 * invalid (-1) uid & gid on the "dummy" export which it
		 * uses to test export support.  To make sure exportfs
		 * sees errors from check_export we therefore need to
		 * delay these checks till after check_export:
		 */
		err = -EINVAL;
		if (!uid_valid(exp.ex_anon_uid))
			goto out4;
		if (!gid_valid(exp.ex_anon_gid))
			goto out4;
		err = 0;

		nfsd4_setup_layout_type(&exp);
	}

	expp = svc_export_lookup(&exp);
	if (expp)
		expp = svc_export_update(&exp, expp);
	else
		err = -ENOMEM;
	cache_flush();
	if (expp == NULL)
		err = -ENOMEM;
	else
		exp_put(expp);
out4:
	nfsd4_fslocs_free(&exp.ex_fslocs);
	kfree(exp.ex_uuid);
out3:
	path_put(&exp.ex_path);
out1:
	auth_domain_put(dom);
out:
	kfree(buf);
	return err;
}

static void exp_flags(struct seq_file *m, int flag, int fsid,
		kuid_t anonu, kgid_t anong, struct nfsd4_fs_locations *fslocs);
static void show_secinfo(struct seq_file *m, struct svc_export *exp);

static int svc_export_show(struct seq_file *m,
			   struct cache_detail *cd,
			   struct cache_head *h)
{
	struct svc_export *exp ;

	if (h ==NULL) {
		seq_puts(m, "#path domain(flags)\n");
		return 0;
	}
	exp = container_of(h, struct svc_export, h);
	seq_path(m, &exp->ex_path, " \t\n\\");
	seq_putc(m, '\t');
	seq_escape(m, exp->ex_client->name, " \t\n\\");
	seq_putc(m, '(');
	if (test_bit(CACHE_VALID, &h->flags) && 
	    !test_bit(CACHE_NEGATIVE, &h->flags)) {
		exp_flags(m, exp->ex_flags, exp->ex_fsid,
			  exp->ex_anon_uid, exp->ex_anon_gid, &exp->ex_fslocs);
		if (exp->ex_uuid) {
			int i;
			seq_puts(m, ",uuid=");
			for (i = 0; i < EX_UUID_LEN; i++) {
				if ((i&3) == 0 && i)
					seq_putc(m, ':');
				seq_printf(m, "%02x", exp->ex_uuid[i]);
			}
		}
		show_secinfo(m, exp);
	}
	seq_puts(m, ")\n");
	return 0;
}
static int svc_export_match(struct cache_head *a, struct cache_head *b)
{
	struct svc_export *orig = container_of(a, struct svc_export, h);
	struct svc_export *new = container_of(b, struct svc_export, h);
	return orig->ex_client == new->ex_client &&
		orig->ex_path.dentry == new->ex_path.dentry &&
		orig->ex_path.mnt == new->ex_path.mnt;
}

static void svc_export_init(struct cache_head *cnew, struct cache_head *citem)
{
	struct svc_export *new = container_of(cnew, struct svc_export, h);
	struct svc_export *item = container_of(citem, struct svc_export, h);

	kref_get(&item->ex_client->ref);
	new->ex_client = item->ex_client;
	new->ex_path = item->ex_path;
	path_get(&item->ex_path);
	new->ex_fslocs.locations = NULL;
	new->ex_fslocs.locations_count = 0;
	new->ex_fslocs.migrated = 0;
	new->ex_layout_type = 0;
	new->ex_uuid = NULL;
	new->cd = item->cd;
}

static void export_update(struct cache_head *cnew, struct cache_head *citem)
{
	struct svc_export *new = container_of(cnew, struct svc_export, h);
	struct svc_export *item = container_of(citem, struct svc_export, h);
	int i;

	new->ex_flags = item->ex_flags;
	new->ex_anon_uid = item->ex_anon_uid;
	new->ex_anon_gid = item->ex_anon_gid;
	new->ex_fsid = item->ex_fsid;
	new->ex_devid_map = item->ex_devid_map;
	item->ex_devid_map = NULL;
	new->ex_uuid = item->ex_uuid;
	item->ex_uuid = NULL;
	new->ex_fslocs.locations = item->ex_fslocs.locations;
	item->ex_fslocs.locations = NULL;
	new->ex_fslocs.locations_count = item->ex_fslocs.locations_count;
	item->ex_fslocs.locations_count = 0;
	new->ex_fslocs.migrated = item->ex_fslocs.migrated;
	item->ex_fslocs.migrated = 0;
	new->ex_layout_type = item->ex_layout_type;
	new->ex_nflavors = item->ex_nflavors;
	for (i = 0; i < MAX_SECINFO_LIST; i++) {
		new->ex_flavors[i] = item->ex_flavors[i];
	}
}

static struct cache_head *svc_export_alloc(void)
{
	struct svc_export *i = kmalloc(sizeof(*i), GFP_KERNEL);
	if (i)
		return &i->h;
	else
		return NULL;
}

static struct cache_detail svc_export_cache_template = {
	.owner		= THIS_MODULE,
	.hash_size	= EXPORT_HASHMAX,
	.name		= "nfsd.export",
	.cache_put	= svc_export_put,
	.cache_request	= svc_export_request,
	.cache_parse	= svc_export_parse,
	.cache_show	= svc_export_show,
	.match		= svc_export_match,
	.init		= svc_export_init,
	.update		= export_update,
	.alloc		= svc_export_alloc,
};

static int
svc_export_hash(struct svc_export *exp)
{
	int hash;

	hash = hash_ptr(exp->ex_client, EXPORT_HASHBITS);
	hash ^= hash_ptr(exp->ex_path.dentry, EXPORT_HASHBITS);
	hash ^= hash_ptr(exp->ex_path.mnt, EXPORT_HASHBITS);
	return hash;
}

static struct svc_export *
svc_export_lookup(struct svc_export *exp)
{
	struct cache_head *ch;
	int hash = svc_export_hash(exp);

	ch = sunrpc_cache_lookup(exp->cd, &exp->h, hash);
	if (ch)
		return container_of(ch, struct svc_export, h);
	else
		return NULL;
}

static struct svc_export *
svc_export_update(struct svc_export *new, struct svc_export *old)
{
	struct cache_head *ch;
	int hash = svc_export_hash(old);

	ch = sunrpc_cache_update(old->cd, &new->h, &old->h, hash);
	if (ch)
		return container_of(ch, struct svc_export, h);
	else
		return NULL;
}


static struct svc_expkey *
exp_find_key(struct cache_detail *cd, struct auth_domain *clp, int fsid_type,
	     u32 *fsidv, struct cache_req *reqp)
{
	struct svc_expkey key, *ek;
	int err;
	
	if (!clp)
		return ERR_PTR(-ENOENT);

	key.ek_client = clp;
	key.ek_fsidtype = fsid_type;
	memcpy(key.ek_fsid, fsidv, key_len(fsid_type));

	ek = svc_expkey_lookup(cd, &key);
	if (ek == NULL)
		return ERR_PTR(-ENOMEM);
	err = cache_check(cd, &ek->h, reqp);
	if (err)
		return ERR_PTR(err);
	return ek;
}

static struct svc_export *
exp_get_by_name(struct cache_detail *cd, struct auth_domain *clp,
		const struct path *path, struct cache_req *reqp)
{
	struct svc_export *exp, key;
	int err;

	if (!clp)
		return ERR_PTR(-ENOENT);

	key.ex_client = clp;
	key.ex_path = *path;
	key.cd = cd;

	exp = svc_export_lookup(&key);
	if (exp == NULL)
		return ERR_PTR(-ENOMEM);
	err = cache_check(cd, &exp->h, reqp);
	if (err)
		return ERR_PTR(err);
	return exp;
}

/*
 * Find the export entry for a given dentry.
 */
static struct svc_export *
exp_parent(struct cache_detail *cd, struct auth_domain *clp, struct path *path)
{
	struct dentry *saved = dget(path->dentry);
	struct svc_export *exp = exp_get_by_name(cd, clp, path, NULL);

	while (PTR_ERR(exp) == -ENOENT && !IS_ROOT(path->dentry)) {
		struct dentry *parent = dget_parent(path->dentry);
		dput(path->dentry);
		path->dentry = parent;
		exp = exp_get_by_name(cd, clp, path, NULL);
	}
	dput(path->dentry);
	path->dentry = saved;
	return exp;
}



/*
 * Obtain the root fh on behalf of a client.
 * This could be done in user space, but I feel that it adds some safety
 * since its harder to fool a kernel module than a user space program.
 */
int
exp_rootfh(struct net *net, struct auth_domain *clp, char *name,
	   struct knfsd_fh *f, int maxsize)
{
	struct svc_export	*exp;
	struct path		path;
	struct inode		*inode;
	struct svc_fh		fh;
	int			err;
	struct nfsd_net		*nn = net_generic(net, nfsd_net_id);
	struct cache_detail	*cd = nn->svc_export_cache;

	err = -EPERM;
	/* NB: we probably ought to check that it's NUL-terminated */
	if (kern_path(name, 0, &path)) {
		printk("nfsd: exp_rootfh path not found %s", name);
		return err;
	}
	inode = path.dentry->d_inode;

	dprintk("nfsd: exp_rootfh(%s [%p] %s:%s/%ld)\n",
		 name, path.dentry, clp->name,
		 inode->i_sb->s_id, inode->i_ino);
	exp = exp_parent(cd, clp, &path);
	if (IS_ERR(exp)) {
		err = PTR_ERR(exp);
		goto out;
	}

	/*
	 * fh must be initialized before calling fh_compose
	 */
	fh_init(&fh, maxsize);
	if (fh_compose(&fh, exp, path.dentry, NULL))
		err = -EINVAL;
	else
		err = 0;
	memcpy(f, &fh.fh_handle, sizeof(struct knfsd_fh));
	fh_put(&fh);
	exp_put(exp);
out:
	path_put(&path);
	return err;
}

static struct svc_export *exp_find(struct cache_detail *cd,
				   struct auth_domain *clp, int fsid_type,
				   u32 *fsidv, struct cache_req *reqp)
{
	struct svc_export *exp;
	struct nfsd_net *nn = net_generic(cd->net, nfsd_net_id);
	struct svc_expkey *ek = exp_find_key(nn->svc_expkey_cache, clp, fsid_type, fsidv, reqp);
	if (IS_ERR(ek))
		return ERR_CAST(ek);

	exp = exp_get_by_name(cd, clp, &ek->ek_path, reqp);
	cache_put(&ek->h, nn->svc_expkey_cache);

	if (IS_ERR(exp))
		return ERR_CAST(exp);
	return exp;
}

__be32 check_nfsd_access(struct svc_export *exp, struct svc_rqst *rqstp)
{
	struct exp_flavor_info *f;
	struct exp_flavor_info *end = exp->ex_flavors + exp->ex_nflavors;

	/* legacy gss-only clients are always OK: */
	if (exp->ex_client == rqstp->rq_gssclient)
		return 0;
	/* ip-address based client; check sec= export option: */
	for (f = exp->ex_flavors; f < end; f++) {
		if (f->pseudoflavor == rqstp->rq_cred.cr_flavor)
			return 0;
	}
	/* defaults in absence of sec= options: */
	if (exp->ex_nflavors == 0) {
		if (rqstp->rq_cred.cr_flavor == RPC_AUTH_NULL ||
		    rqstp->rq_cred.cr_flavor == RPC_AUTH_UNIX)
			return 0;
	}
	return nfserr_wrongsec;
}

/*
 * Uses rq_client and rq_gssclient to find an export; uses rq_client (an
 * auth_unix client) if it's available and has secinfo information;
 * otherwise, will try to use rq_gssclient.
 *
 * Called from functions that handle requests; functions that do work on
 * behalf of mountd are passed a single client name to use, and should
 * use exp_get_by_name() or exp_find().
 */
struct svc_export *
rqst_exp_get_by_name(struct svc_rqst *rqstp, struct path *path)
{
	struct svc_export *gssexp, *exp = ERR_PTR(-ENOENT);
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);
	struct cache_detail *cd = nn->svc_export_cache;

	if (rqstp->rq_client == NULL)
		goto gss;

	/* First try the auth_unix client: */
	exp = exp_get_by_name(cd, rqstp->rq_client, path, &rqstp->rq_chandle);
	if (PTR_ERR(exp) == -ENOENT)
		goto gss;
	if (IS_ERR(exp))
		return exp;
	/* If it has secinfo, assume there are no gss/... clients */
	if (exp->ex_nflavors > 0)
		return exp;
gss:
	/* Otherwise, try falling back on gss client */
	if (rqstp->rq_gssclient == NULL)
		return exp;
	gssexp = exp_get_by_name(cd, rqstp->rq_gssclient, path, &rqstp->rq_chandle);
	if (PTR_ERR(gssexp) == -ENOENT)
		return exp;
	if (!IS_ERR(exp))
		exp_put(exp);
	return gssexp;
}

struct svc_export *
rqst_exp_find(struct svc_rqst *rqstp, int fsid_type, u32 *fsidv)
{
	struct svc_export *gssexp, *exp = ERR_PTR(-ENOENT);
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);
	struct cache_detail *cd = nn->svc_export_cache;

	if (rqstp->rq_client == NULL)
		goto gss;

	/* First try the auth_unix client: */
	exp = exp_find(cd, rqstp->rq_client, fsid_type,
		       fsidv, &rqstp->rq_chandle);
	if (PTR_ERR(exp) == -ENOENT)
		goto gss;
	if (IS_ERR(exp))
		return exp;
	/* If it has secinfo, assume there are no gss/... clients */
	if (exp->ex_nflavors > 0)
		return exp;
gss:
	/* Otherwise, try falling back on gss client */
	if (rqstp->rq_gssclient == NULL)
		return exp;
	gssexp = exp_find(cd, rqstp->rq_gssclient, fsid_type, fsidv,
						&rqstp->rq_chandle);
	if (PTR_ERR(gssexp) == -ENOENT)
		return exp;
	if (!IS_ERR(exp))
		exp_put(exp);
	return gssexp;
}

struct svc_export *
rqst_exp_parent(struct svc_rqst *rqstp, struct path *path)
{
	struct dentry *saved = dget(path->dentry);
	struct svc_export *exp = rqst_exp_get_by_name(rqstp, path);

	while (PTR_ERR(exp) == -ENOENT && !IS_ROOT(path->dentry)) {
		struct dentry *parent = dget_parent(path->dentry);
		dput(path->dentry);
		path->dentry = parent;
		exp = rqst_exp_get_by_name(rqstp, path);
	}
	dput(path->dentry);
	path->dentry = saved;
	return exp;
}

struct svc_export *rqst_find_fsidzero_export(struct svc_rqst *rqstp)
{
	u32 fsidv[2];

	mk_fsid(FSID_NUM, fsidv, 0, 0, 0, NULL);

	return rqst_exp_find(rqstp, FSID_NUM, fsidv);
}

/*
 * Called when we need the filehandle for the root of the pseudofs,
 * for a given NFSv4 client.   The root is defined to be the
 * export point with fsid==0
 */
__be32
exp_pseudoroot(struct svc_rqst *rqstp, struct svc_fh *fhp)
{
	struct svc_export *exp;
	__be32 rv;

	exp = rqst_find_fsidzero_export(rqstp);
	if (IS_ERR(exp))
		return nfserrno(PTR_ERR(exp));
	rv = fh_compose(fhp, exp, exp->ex_path.dentry, NULL);
	exp_put(exp);
	return rv;
}

/* Iterator */

static void *e_start(struct seq_file *m, loff_t *pos)
	__acquires(((struct cache_detail *)m->private)->hash_lock)
{
	loff_t n = *pos;
	unsigned hash, export;
	struct cache_head *ch;
	struct cache_detail *cd = m->private;
	struct cache_head **export_table = cd->hash_table;

	read_lock(&cd->hash_lock);
	if (!n--)
		return SEQ_START_TOKEN;
	hash = n >> 32;
	export = n & ((1LL<<32) - 1);

	
	for (ch=export_table[hash]; ch; ch=ch->next)
		if (!export--)
			return ch;
	n &= ~((1LL<<32) - 1);
	do {
		hash++;
		n += 1LL<<32;
	} while(hash < EXPORT_HASHMAX && export_table[hash]==NULL);
	if (hash >= EXPORT_HASHMAX)
		return NULL;
	*pos = n+1;
	return export_table[hash];
}

static void *e_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct cache_head *ch = p;
	int hash = (*pos >> 32);
	struct cache_detail *cd = m->private;
	struct cache_head **export_table = cd->hash_table;

	if (p == SEQ_START_TOKEN)
		hash = 0;
	else if (ch->next == NULL) {
		hash++;
		*pos += 1LL<<32;
	} else {
		++*pos;
		return ch->next;
	}
	*pos &= ~((1LL<<32) - 1);
	while (hash < EXPORT_HASHMAX && export_table[hash] == NULL) {
		hash++;
		*pos += 1LL<<32;
	}
	if (hash >= EXPORT_HASHMAX)
		return NULL;
	++*pos;
	return export_table[hash];
}

static void e_stop(struct seq_file *m, void *p)
	__releases(((struct cache_detail *)m->private)->hash_lock)
{
	struct cache_detail *cd = m->private;

	read_unlock(&cd->hash_lock);
}

static struct flags {
	int flag;
	char *name[2];
} expflags[] = {
	{ NFSEXP_READONLY, {"ro", "rw"}},
	{ NFSEXP_INSECURE_PORT, {"insecure", ""}},
	{ NFSEXP_ROOTSQUASH, {"root_squash", "no_root_squash"}},
	{ NFSEXP_ALLSQUASH, {"all_squash", ""}},
	{ NFSEXP_ASYNC, {"async", "sync"}},
	{ NFSEXP_GATHERED_WRITES, {"wdelay", "no_wdelay"}},
	{ NFSEXP_NOREADDIRPLUS, {"nordirplus", ""}},
	{ NFSEXP_NOHIDE, {"nohide", ""}},
	{ NFSEXP_CROSSMOUNT, {"crossmnt", ""}},
	{ NFSEXP_NOSUBTREECHECK, {"no_subtree_check", ""}},
	{ NFSEXP_NOAUTHNLM, {"insecure_locks", ""}},
	{ NFSEXP_V4ROOT, {"v4root", ""}},
	{ 0, {"", ""}}
};

static void show_expflags(struct seq_file *m, int flags, int mask)
{
	struct flags *flg;
	int state, first = 0;

	for (flg = expflags; flg->flag; flg++) {
		if (flg->flag & ~mask)
			continue;
		state = (flg->flag & flags) ? 0 : 1;
		if (*flg->name[state])
			seq_printf(m, "%s%s", first++?",":"", flg->name[state]);
	}
}

static void show_secinfo_flags(struct seq_file *m, int flags)
{
	seq_printf(m, ",");
	show_expflags(m, flags, NFSEXP_SECINFO_FLAGS);
}

static bool secinfo_flags_equal(int f, int g)
{
	f &= NFSEXP_SECINFO_FLAGS;
	g &= NFSEXP_SECINFO_FLAGS;
	return f == g;
}

static int show_secinfo_run(struct seq_file *m, struct exp_flavor_info **fp, struct exp_flavor_info *end)
{
	int flags;

	flags = (*fp)->flags;
	seq_printf(m, ",sec=%d", (*fp)->pseudoflavor);
	(*fp)++;
	while (*fp != end && secinfo_flags_equal(flags, (*fp)->flags)) {
		seq_printf(m, ":%d", (*fp)->pseudoflavor);
		(*fp)++;
	}
	return flags;
}

static void show_secinfo(struct seq_file *m, struct svc_export *exp)
{
	struct exp_flavor_info *f;
	struct exp_flavor_info *end = exp->ex_flavors + exp->ex_nflavors;
	int flags;

	if (exp->ex_nflavors == 0)
		return;
	f = exp->ex_flavors;
	flags = show_secinfo_run(m, &f, end);
	if (!secinfo_flags_equal(flags, exp->ex_flags))
		show_secinfo_flags(m, flags);
	while (f != end) {
		flags = show_secinfo_run(m, &f, end);
		show_secinfo_flags(m, flags);
	}
}

static void exp_flags(struct seq_file *m, int flag, int fsid,
		kuid_t anonu, kgid_t anong, struct nfsd4_fs_locations *fsloc)
{
	show_expflags(m, flag, NFSEXP_ALLFLAGS);
	if (flag & NFSEXP_FSID)
		seq_printf(m, ",fsid=%d", fsid);
	if (!uid_eq(anonu, make_kuid(&init_user_ns, (uid_t)-2)) &&
	    !uid_eq(anonu, make_kuid(&init_user_ns, 0x10000-2)))
		seq_printf(m, ",anonuid=%u", from_kuid(&init_user_ns, anonu));
	if (!gid_eq(anong, make_kgid(&init_user_ns, (gid_t)-2)) &&
	    !gid_eq(anong, make_kgid(&init_user_ns, 0x10000-2)))
		seq_printf(m, ",anongid=%u", from_kgid(&init_user_ns, anong));
	if (fsloc && fsloc->locations_count > 0) {
		char *loctype = (fsloc->migrated) ? "refer" : "replicas";
		int i;

		seq_printf(m, ",%s=", loctype);
		seq_escape(m, fsloc->locations[0].path, ",;@ \t\n\\");
		seq_putc(m, '@');
		seq_escape(m, fsloc->locations[0].hosts, ",;@ \t\n\\");
		for (i = 1; i < fsloc->locations_count; i++) {
			seq_putc(m, ';');
			seq_escape(m, fsloc->locations[i].path, ",;@ \t\n\\");
			seq_putc(m, '@');
			seq_escape(m, fsloc->locations[i].hosts, ",;@ \t\n\\");
		}
	}
}

static int e_show(struct seq_file *m, void *p)
{
	struct cache_head *cp = p;
	struct svc_export *exp = container_of(cp, struct svc_export, h);
	struct cache_detail *cd = m->private;

	if (p == SEQ_START_TOKEN) {
		seq_puts(m, "# Version 1.1\n");
		seq_puts(m, "# Path Client(Flags) # IPs\n");
		return 0;
	}

	exp_get(exp);
	if (cache_check(cd, &exp->h, NULL))
		return 0;
	exp_put(exp);
	return svc_export_show(m, cd, cp);
}

const struct seq_operations nfs_exports_op = {
	.start	= e_start,
	.next	= e_next,
	.stop	= e_stop,
	.show	= e_show,
};

/*
 * Initialize the exports module.
 */
int
nfsd_export_init(struct net *net)
{
	int rv;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	dprintk("nfsd: initializing export module (net: %p).\n", net);

	nn->svc_export_cache = cache_create_net(&svc_export_cache_template, net);
	if (IS_ERR(nn->svc_export_cache))
		return PTR_ERR(nn->svc_export_cache);
	rv = cache_register_net(nn->svc_export_cache, net);
	if (rv)
		goto destroy_export_cache;

	nn->svc_expkey_cache = cache_create_net(&svc_expkey_cache_template, net);
	if (IS_ERR(nn->svc_expkey_cache)) {
		rv = PTR_ERR(nn->svc_expkey_cache);
		goto unregister_export_cache;
	}
	rv = cache_register_net(nn->svc_expkey_cache, net);
	if (rv)
		goto destroy_expkey_cache;
	return 0;

destroy_expkey_cache:
	cache_destroy_net(nn->svc_expkey_cache, net);
unregister_export_cache:
	cache_unregister_net(nn->svc_export_cache, net);
destroy_export_cache:
	cache_destroy_net(nn->svc_export_cache, net);
	return rv;
}

/*
 * Flush exports table - called when last nfsd thread is killed
 */
void
nfsd_export_flush(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	cache_purge(nn->svc_expkey_cache);
	cache_purge(nn->svc_export_cache);
}

/*
 * Shutdown the exports module.
 */
void
nfsd_export_shutdown(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	dprintk("nfsd: shutting down export module (net: %p).\n", net);

	cache_unregister_net(nn->svc_expkey_cache, net);
	cache_unregister_net(nn->svc_export_cache, net);
	cache_destroy_net(nn->svc_expkey_cache, net);
	cache_destroy_net(nn->svc_export_cache, net);
	svcauth_unix_purge(net);

	dprintk("nfsd: export shutdown complete (net: %p).\n", net);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/export.c */
/************************************************************/
/* Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de> */

// #include <linux/sched.h>
// #include "nfsd.h"
// #include "auth.h"

int nfsexp_flags(struct svc_rqst *rqstp, struct svc_export *exp)
{
	struct exp_flavor_info *f;
	struct exp_flavor_info *end = exp->ex_flavors + exp->ex_nflavors;

	for (f = exp->ex_flavors; f < end; f++) {
		if (f->pseudoflavor == rqstp->rq_cred.cr_flavor)
			return f->flags;
	}
	return exp->ex_flags;

}

int nfsd_setuser(struct svc_rqst *rqstp, struct svc_export *exp)
{
	struct group_info *rqgi;
	struct group_info *gi;
	struct cred *new;
	int i;
	int flags = nfsexp_flags(rqstp, exp);

	validate_process_creds();

	/* discard any old override before preparing the new set */
	revert_creds(get_cred(current_real_cred()));
	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	new->fsuid = rqstp->rq_cred.cr_uid;
	new->fsgid = rqstp->rq_cred.cr_gid;

	rqgi = rqstp->rq_cred.cr_group_info;

	if (flags & NFSEXP_ALLSQUASH) {
		new->fsuid = exp->ex_anon_uid;
		new->fsgid = exp->ex_anon_gid;
		gi = groups_alloc(0);
		if (!gi)
			goto oom;
	} else if (flags & NFSEXP_ROOTSQUASH) {
		if (uid_eq(new->fsuid, GLOBAL_ROOT_UID))
			new->fsuid = exp->ex_anon_uid;
		if (gid_eq(new->fsgid, GLOBAL_ROOT_GID))
			new->fsgid = exp->ex_anon_gid;

		gi = groups_alloc(rqgi->ngroups);
		if (!gi)
			goto oom;

		for (i = 0; i < rqgi->ngroups; i++) {
			if (gid_eq(GLOBAL_ROOT_GID, GROUP_AT(rqgi, i)))
				GROUP_AT(gi, i) = exp->ex_anon_gid;
			else
				GROUP_AT(gi, i) = GROUP_AT(rqgi, i);
		}
	} else {
		gi = get_group_info(rqgi);
	}

	if (uid_eq(new->fsuid, INVALID_UID))
		new->fsuid = exp->ex_anon_uid;
	if (gid_eq(new->fsgid, INVALID_GID))
		new->fsgid = exp->ex_anon_gid;

	set_groups(new, gi);
	put_group_info(gi);

	if (!uid_eq(new->fsuid, GLOBAL_ROOT_UID))
		new->cap_effective = cap_drop_nfsd_set(new->cap_effective);
	else
		new->cap_effective = cap_raise_nfsd_set(new->cap_effective,
							new->cap_permitted);
	validate_process_creds();
	put_cred(override_creds(new));
	put_cred(new);
	validate_process_creds();
	return 0;

oom:
	abort_creds(new);
	return -ENOMEM;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/auth.c */
/************************************************************/
/*
 * This file contains all the stubs needed when communicating with lockd.
 * This level of indirection is necessary so we can run nfsd+lockd without
 * requiring the nfs client to be compiled in/loaded, and vice versa.
 *
 * Copyright (C) 1996, Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/file.h>
// #include <linux/lockd/bind.h>
// #include "nfsd.h"
// #include "vfs.h"

#define NFSDDBG_FACILITY		NFSDDBG_LOCKD

#ifdef CONFIG_LOCKD_V4
#define nlm_stale_fh	nlm4_stale_fh
#define nlm_failed	nlm4_failed
#else
#define nlm_stale_fh	nlm_lck_denied_nolocks
#define nlm_failed	nlm_lck_denied_nolocks
#endif
/*
 * Note: we hold the dentry use count while the file is open.
 */
static __be32
nlm_fopen(struct svc_rqst *rqstp, struct nfs_fh *f, struct file **filp)
{
	__be32		nfserr;
	struct svc_fh	fh;

	/* must initialize before using! but maxsize doesn't matter */
	fh_init(&fh,0);
	fh.fh_handle.fh_size = f->size;
	memcpy((char*)&fh.fh_handle.fh_base, f->data, f->size);
	fh.fh_export = NULL;

	nfserr = nfsd_open(rqstp, &fh, S_IFREG, NFSD_MAY_LOCK, filp);
	fh_put(&fh);
 	/* We return nlm error codes as nlm doesn't know
	 * about nfsd, but nfsd does know about nlm..
	 */
	switch (nfserr) {
	case nfs_ok:
		return 0;
	case nfserr_dropit:
		return nlm_drop_reply;
	case nfserr_stale:
		return nlm_stale_fh;
	default:
		return nlm_failed;
	}
}

static void
nlm_fclose(struct file *filp)
{
	fput(filp);
}

static struct nlmsvc_binding	nfsd_nlm_ops = {
	.fopen		= nlm_fopen,		/* open file for locking */
	.fclose		= nlm_fclose,		/* close file */
};

void
nfsd_lockd_init(void)
{
	dprintk("nfsd: initializing lockd\n");
	nlmsvc_ops = &nfsd_nlm_ops;
}

void
nfsd_lockd_shutdown(void)
{
	nlmsvc_ops = NULL;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/lockd.c */
/************************************************************/
/*
 * Request reply cache. This is currently a global cache, but this may
 * change in the future and be a per-client cache.
 *
 * This code is heavily inspired by the 44BSD implementation, although
 * it does things a bit differently.
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/slab.h>
// #include <linux/sunrpc/addr.h>
#include <linux/highmem.h>
#include <linux/log2.h>
#include <linux/hash.h>
#include <net/checksum.h>
#include "../../inc/__fss.h"

// #include "nfsd.h"
// #include "cache.h"

#define NFSDDBG_FACILITY	NFSDDBG_REPCACHE

/*
 * We use this value to determine the number of hash buckets from the max
 * cache size, the idea being that when the cache is at its maximum number
 * of entries, then this should be the average number of entries per bucket.
 */
#define TARGET_BUCKET_SIZE	64

struct nfsd_drc_bucket {
	struct list_head lru_head;
	spinlock_t cache_lock;
};

static struct nfsd_drc_bucket	*drc_hashtbl;
static struct kmem_cache	*drc_slab;

/* max number of entries allowed in the cache */
static unsigned int		max_drc_entries;

/* number of significant bits in the hash value */
static unsigned int		maskbits;
static unsigned int		drc_hashsize;

/*
 * Stats and other tracking of on the duplicate reply cache. All of these and
 * the "rc" fields in nfsdstats are protected by the cache_lock
 */

/* total number of entries */
static atomic_t			num_drc_entries;

/* cache misses due only to checksum comparison failures */
static unsigned int		payload_misses;

/* amount of memory (in bytes) currently consumed by the DRC */
static unsigned int		drc_mem_usage;

/* longest hash chain seen */
static unsigned int		longest_chain;

/* size of cache when we saw the longest hash chain */
static unsigned int		longest_chain_cachesize;

static int	nfsd_cache_append(struct svc_rqst *rqstp, struct kvec *vec);
static void	cache_cleaner_func(struct work_struct *unused);
static unsigned long nfsd_reply_cache_count(struct shrinker *shrink,
					    struct shrink_control *sc);
static unsigned long nfsd_reply_cache_scan(struct shrinker *shrink,
					   struct shrink_control *sc);

static struct shrinker nfsd_reply_cache_shrinker = {
	.scan_objects = nfsd_reply_cache_scan,
	.count_objects = nfsd_reply_cache_count,
	.seeks	= 1,
};

/*
 * locking for the reply cache:
 * A cache entry is "single use" if c_state == RC_INPROG
 * Otherwise, it when accessing _prev or _next, the lock must be held.
 */
static DECLARE_DELAYED_WORK(cache_cleaner, cache_cleaner_func);

/*
 * Put a cap on the size of the DRC based on the amount of available
 * low memory in the machine.
 *
 *  64MB:    8192
 * 128MB:   11585
 * 256MB:   16384
 * 512MB:   23170
 *   1GB:   32768
 *   2GB:   46340
 *   4GB:   65536
 *   8GB:   92681
 *  16GB:  131072
 *
 * ...with a hard cap of 256k entries. In the worst case, each entry will be
 * ~1k, so the above numbers should give a rough max of the amount of memory
 * used in k.
 */
static unsigned int
nfsd_cache_size_limit(void)
{
	unsigned int limit;
	unsigned long low_pages = totalram_pages - totalhigh_pages;

	limit = (16 * int_sqrt(low_pages)) << (PAGE_SHIFT-10);
	return min_t(unsigned int, limit, 256*1024);
}

/*
 * Compute the number of hash buckets we need. Divide the max cachesize by
 * the "target" max bucket size, and round up to next power of two.
 */
static unsigned int
nfsd_hashsize(unsigned int limit)
{
	return roundup_pow_of_two(limit / TARGET_BUCKET_SIZE);
}

static u32
nfsd_cache_hash(__be32 xid)
{
	return hash_32(be32_to_cpu(xid), maskbits);
}

static struct svc_cacherep *
nfsd_reply_cache_alloc(void)
{
	struct svc_cacherep	*rp;

	rp = kmem_cache_alloc(drc_slab, GFP_KERNEL);
	if (rp) {
		rp->c_state = RC_UNUSED;
		rp->c_type = RC_NOCACHE;
		INIT_LIST_HEAD(&rp->c_lru);
	}
	return rp;
}

static void
nfsd_reply_cache_free_locked(struct svc_cacherep *rp)
{
	if (rp->c_type == RC_REPLBUFF && rp->c_replvec.iov_base) {
		drc_mem_usage -= rp->c_replvec.iov_len;
		kfree(rp->c_replvec.iov_base);
	}
	list_del(&rp->c_lru);
	atomic_dec(&num_drc_entries);
	drc_mem_usage -= sizeof(*rp);
	kmem_cache_free(drc_slab, rp);
}

static void
nfsd_reply_cache_free(struct nfsd_drc_bucket *b, struct svc_cacherep *rp)
{
	spin_lock(&b->cache_lock);
	nfsd_reply_cache_free_locked(rp);
	spin_unlock(&b->cache_lock);
}

int nfsd_reply_cache_init(void)
{
	unsigned int hashsize;
	unsigned int i;

	max_drc_entries = nfsd_cache_size_limit();
	atomic_set(&num_drc_entries, 0);
	hashsize = nfsd_hashsize(max_drc_entries);
	maskbits = ilog2(hashsize);

	register_shrinker(&nfsd_reply_cache_shrinker);
	drc_slab = kmem_cache_create("nfsd_drc", sizeof(struct svc_cacherep),
					0, 0, NULL);
	if (!drc_slab)
		goto out_nomem;

	drc_hashtbl = kcalloc(hashsize, sizeof(*drc_hashtbl), GFP_KERNEL);
	if (!drc_hashtbl)
		goto out_nomem;
	for (i = 0; i < hashsize; i++) {
		INIT_LIST_HEAD(&drc_hashtbl[i].lru_head);
		spin_lock_init(&drc_hashtbl[i].cache_lock);
	}
	drc_hashsize = hashsize;

	return 0;
out_nomem:
	printk(KERN_ERR "nfsd: failed to allocate reply cache\n");
	nfsd_reply_cache_shutdown();
	return -ENOMEM;
}

void nfsd_reply_cache_shutdown(void)
{
	struct svc_cacherep	*rp;
	unsigned int i;

	unregister_shrinker(&nfsd_reply_cache_shrinker);
	cancel_delayed_work_sync(&cache_cleaner);

	for (i = 0; i < drc_hashsize; i++) {
		struct list_head *head = &drc_hashtbl[i].lru_head;
		while (!list_empty(head)) {
			rp = list_first_entry(head, struct svc_cacherep, c_lru);
			nfsd_reply_cache_free_locked(rp);
		}
	}

	kfree (drc_hashtbl);
	drc_hashtbl = NULL;
	drc_hashsize = 0;

	if (drc_slab) {
		kmem_cache_destroy(drc_slab);
		drc_slab = NULL;
	}
}

/*
 * Move cache entry to end of LRU list, and queue the cleaner to run if it's
 * not already scheduled.
 */
static void
lru_put_end(struct nfsd_drc_bucket *b, struct svc_cacherep *rp)
{
	rp->c_timestamp = jiffies;
	list_move_tail(&rp->c_lru, &b->lru_head);
	schedule_delayed_work(&cache_cleaner, RC_EXPIRE);
}

static long
prune_bucket(struct nfsd_drc_bucket *b)
{
	struct svc_cacherep *rp, *tmp;
	long freed = 0;

	list_for_each_entry_safe(rp, tmp, &b->lru_head, c_lru) {
		/*
		 * Don't free entries attached to calls that are still
		 * in-progress, but do keep scanning the list.
		 */
		if (rp->c_state == RC_INPROG)
			continue;
		if (atomic_read(&num_drc_entries) <= max_drc_entries &&
		    time_before(jiffies, rp->c_timestamp + RC_EXPIRE))
			break;
		nfsd_reply_cache_free_locked(rp);
		freed++;
	}
	return freed;
}

/*
 * Walk the LRU list and prune off entries that are older than RC_EXPIRE.
 * Also prune the oldest ones when the total exceeds the max number of entries.
 */
static long
prune_cache_entries(void)
{
	unsigned int i;
	long freed = 0;
	bool cancel = true;

	for (i = 0; i < drc_hashsize; i++) {
		struct nfsd_drc_bucket *b = &drc_hashtbl[i];

		if (list_empty(&b->lru_head))
			continue;
		spin_lock(&b->cache_lock);
		freed += prune_bucket(b);
		if (!list_empty(&b->lru_head))
			cancel = false;
		spin_unlock(&b->cache_lock);
	}

	/*
	 * Conditionally rearm the job to run in RC_EXPIRE since we just
	 * ran the pruner.
	 */
	if (!cancel)
		mod_delayed_work(system_wq, &cache_cleaner, RC_EXPIRE);
	return freed;
}

static void
cache_cleaner_func(struct work_struct *unused)
{
	prune_cache_entries();
}

static unsigned long
nfsd_reply_cache_count(struct shrinker *shrink, struct shrink_control *sc)
{
	return atomic_read(&num_drc_entries);
}

static unsigned long
nfsd_reply_cache_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	return prune_cache_entries();
}
/*
 * Walk an xdr_buf and get a CRC for at most the first RC_CSUMLEN bytes
 */
static __wsum
nfsd_cache_csum(struct svc_rqst *rqstp)
{
	int idx;
	unsigned int base;
	__wsum csum;
	struct xdr_buf *buf = &rqstp->rq_arg;
	const unsigned char *p = buf->head[0].iov_base;
	size_t csum_len = min_t(size_t, buf->head[0].iov_len + buf->page_len,
				RC_CSUMLEN);
	size_t len = min(buf->head[0].iov_len, csum_len);

	/* rq_arg.head first */
	csum = csum_partial(p, len, 0);
	csum_len -= len;

	/* Continue into page array */
	idx = buf->page_base / PAGE_SIZE;
	base = buf->page_base & ~PAGE_MASK;
	while (csum_len) {
		p = page_address(buf->pages[idx]) + base;
		len = min_t(size_t, PAGE_SIZE - base, csum_len);
		csum = csum_partial(p, len, csum);
		csum_len -= len;
		base = 0;
		++idx;
	}
	return csum;
}

static bool
nfsd_cache_match(struct svc_rqst *rqstp, __wsum csum, struct svc_cacherep *rp)
{
	/* Check RPC XID first */
	if (rqstp->rq_xid != rp->c_xid)
		return false;
	/* compare checksum of NFS data */
	if (csum != rp->c_csum) {
		++payload_misses;
		return false;
	}

	/* Other discriminators */
	if (rqstp->rq_proc != rp->c_proc ||
	    rqstp->rq_prot != rp->c_prot ||
	    rqstp->rq_vers != rp->c_vers ||
	    rqstp->rq_arg.len != rp->c_len ||
	    !rpc_cmp_addr(svc_addr(rqstp), (struct sockaddr *)&rp->c_addr) ||
	    rpc_get_port(svc_addr(rqstp)) != rpc_get_port((struct sockaddr *)&rp->c_addr))
		return false;

	return true;
}

/*
 * Search the request hash for an entry that matches the given rqstp.
 * Must be called with cache_lock held. Returns the found entry or
 * NULL on failure.
 */
static struct svc_cacherep *
nfsd_cache_search(struct nfsd_drc_bucket *b, struct svc_rqst *rqstp,
		__wsum csum)
{
	struct svc_cacherep	*rp, *ret = NULL;
	struct list_head 	*rh = &b->lru_head;
	unsigned int		entries = 0;

	list_for_each_entry(rp, rh, c_lru) {
		++entries;
		if (nfsd_cache_match(rqstp, csum, rp)) {
			ret = rp;
			break;
		}
	}

	/* tally hash chain length stats */
	if (entries > longest_chain) {
		longest_chain = entries;
		longest_chain_cachesize = atomic_read(&num_drc_entries);
	} else if (entries == longest_chain) {
		/* prefer to keep the smallest cachesize possible here */
		longest_chain_cachesize = min_t(unsigned int,
				longest_chain_cachesize,
				atomic_read(&num_drc_entries));
	}

	return ret;
}

/*
 * Try to find an entry matching the current call in the cache. When none
 * is found, we try to grab the oldest expired entry off the LRU list. If
 * a suitable one isn't there, then drop the cache_lock and allocate a
 * new one, then search again in case one got inserted while this thread
 * didn't hold the lock.
 */
int
nfsd_cache_lookup(struct svc_rqst *rqstp)
{
	struct svc_cacherep	*rp, *found;
	__be32			xid = rqstp->rq_xid;
	u32			proto =  rqstp->rq_prot,
				vers = rqstp->rq_vers,
				proc = rqstp->rq_proc;
	__wsum			csum;
	u32 hash = nfsd_cache_hash(xid);
	struct nfsd_drc_bucket *b = &drc_hashtbl[hash];
	unsigned long		age;
	int type = rqstp->rq_cachetype;
	int rtn = RC_DOIT;

	rqstp->rq_cacherep = NULL;
	if (type == RC_NOCACHE) {
		nfsdstats.rcnocache++;
		return rtn;
	}

	csum = nfsd_cache_csum(rqstp);

	/*
	 * Since the common case is a cache miss followed by an insert,
	 * preallocate an entry.
	 */
	rp = nfsd_reply_cache_alloc();
	spin_lock(&b->cache_lock);
	if (likely(rp)) {
		atomic_inc(&num_drc_entries);
		drc_mem_usage += sizeof(*rp);
	}

	/* go ahead and prune the cache */
	prune_bucket(b);

	found = nfsd_cache_search(b, rqstp, csum);
	if (found) {
		if (likely(rp))
			nfsd_reply_cache_free_locked(rp);
		rp = found;
		goto found_entry;
	}

	if (!rp) {
		dprintk("nfsd: unable to allocate DRC entry!\n");
		goto out;
	}

	nfsdstats.rcmisses++;
	rqstp->rq_cacherep = rp;
	rp->c_state = RC_INPROG;
	rp->c_xid = xid;
	rp->c_proc = proc;
	rpc_copy_addr((struct sockaddr *)&rp->c_addr, svc_addr(rqstp));
	rpc_set_port((struct sockaddr *)&rp->c_addr, rpc_get_port(svc_addr(rqstp)));
	rp->c_prot = proto;
	rp->c_vers = vers;
	rp->c_len = rqstp->rq_arg.len;
	rp->c_csum = csum;

	lru_put_end(b, rp);

	/* release any buffer */
	if (rp->c_type == RC_REPLBUFF) {
		drc_mem_usage -= rp->c_replvec.iov_len;
		kfree(rp->c_replvec.iov_base);
		rp->c_replvec.iov_base = NULL;
	}
	rp->c_type = RC_NOCACHE;
 out:
	spin_unlock(&b->cache_lock);
	return rtn;

found_entry:
	nfsdstats.rchits++;
	/* We found a matching entry which is either in progress or done. */
	age = jiffies - rp->c_timestamp;
	lru_put_end(b, rp);

	rtn = RC_DROPIT;
	/* Request being processed or excessive rexmits */
	if (rp->c_state == RC_INPROG || age < RC_DELAY)
		goto out;

	/* From the hall of fame of impractical attacks:
	 * Is this a user who tries to snoop on the cache? */
	rtn = RC_DOIT;
	if (!test_bit(RQ_SECURE, &rqstp->rq_flags) && rp->c_secure)
		goto out;

	/* Compose RPC reply header */
	switch (rp->c_type) {
	case RC_NOCACHE:
		break;
	case RC_REPLSTAT:
		svc_putu32(&rqstp->rq_res.head[0], rp->c_replstat);
		rtn = RC_REPLY;
		break;
	case RC_REPLBUFF:
		if (!nfsd_cache_append(rqstp, &rp->c_replvec))
			goto out;	/* should not happen */
		rtn = RC_REPLY;
		break;
	default:
		printk(KERN_WARNING "nfsd: bad repcache type %d\n", rp->c_type);
		nfsd_reply_cache_free_locked(rp);
	}

	goto out;
}

/*
 * Update a cache entry. This is called from nfsd_dispatch when
 * the procedure has been executed and the complete reply is in
 * rqstp->rq_res.
 *
 * We're copying around data here rather than swapping buffers because
 * the toplevel loop requires max-sized buffers, which would be a waste
 * of memory for a cache with a max reply size of 100 bytes (diropokres).
 *
 * If we should start to use different types of cache entries tailored
 * specifically for attrstat and fh's, we may save even more space.
 *
 * Also note that a cachetype of RC_NOCACHE can legally be passed when
 * nfsd failed to encode a reply that otherwise would have been cached.
 * In this case, nfsd_cache_update is called with statp == NULL.
 */
void
nfsd_cache_update(struct svc_rqst *rqstp, int cachetype, __be32 *statp)
{
	struct svc_cacherep *rp = rqstp->rq_cacherep;
	struct kvec	*resv = &rqstp->rq_res.head[0], *cachv;
	u32		hash;
	struct nfsd_drc_bucket *b;
	int		len;
	size_t		bufsize = 0;

	if (!rp)
		return;

	hash = nfsd_cache_hash(rp->c_xid);
	b = &drc_hashtbl[hash];

	len = resv->iov_len - ((char*)statp - (char*)resv->iov_base);
	len >>= 2;

	/* Don't cache excessive amounts of data and XDR failures */
	if (!statp || len > (256 >> 2)) {
		nfsd_reply_cache_free(b, rp);
		return;
	}

	switch (cachetype) {
	case RC_REPLSTAT:
		if (len != 1)
			printk("nfsd: RC_REPLSTAT/reply len %d!\n",len);
		rp->c_replstat = *statp;
		break;
	case RC_REPLBUFF:
		cachv = &rp->c_replvec;
		bufsize = len << 2;
		cachv->iov_base = kmalloc(bufsize, GFP_KERNEL);
		if (!cachv->iov_base) {
			nfsd_reply_cache_free(b, rp);
			return;
		}
		cachv->iov_len = bufsize;
		memcpy(cachv->iov_base, statp, bufsize);
		break;
	case RC_NOCACHE:
		nfsd_reply_cache_free(b, rp);
		return;
	}
	spin_lock(&b->cache_lock);
	drc_mem_usage += bufsize;
	lru_put_end(b, rp);
	rp->c_secure = test_bit(RQ_SECURE, &rqstp->rq_flags);
	rp->c_type = cachetype;
	rp->c_state = RC_DONE;
	spin_unlock(&b->cache_lock);
	return;
}

/*
 * Copy cached reply to current reply buffer. Should always fit.
 * FIXME as reply is in a page, we should just attach the page, and
 * keep a refcount....
 */
static int
nfsd_cache_append(struct svc_rqst *rqstp, struct kvec *data)
{
	struct kvec	*vec = &rqstp->rq_res.head[0];

	if (vec->iov_len + data->iov_len > PAGE_SIZE) {
		printk(KERN_WARNING "nfsd: cached reply too large (%Zd).\n",
				data->iov_len);
		return 0;
	}
	memcpy((char*)vec->iov_base + vec->iov_len, data->iov_base, data->iov_len);
	vec->iov_len += data->iov_len;
	return 1;
}

/*
 * Note that fields may be added, removed or reordered in the future. Programs
 * scraping this file for info should test the labels to ensure they're
 * getting the correct field.
 */
static int nfsd_reply_cache_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "max entries:           %u\n", max_drc_entries);
	seq_printf(m, "num entries:           %u\n",
			atomic_read(&num_drc_entries));
	seq_printf(m, "hash buckets:          %u\n", 1 << maskbits);
	seq_printf(m, "mem usage:             %u\n", drc_mem_usage);
	seq_printf(m, "cache hits:            %u\n", nfsdstats.rchits);
	seq_printf(m, "cache misses:          %u\n", nfsdstats.rcmisses);
	seq_printf(m, "not cached:            %u\n", nfsdstats.rcnocache);
	seq_printf(m, "payload misses:        %u\n", payload_misses);
	seq_printf(m, "longest chain len:     %u\n", longest_chain);
	seq_printf(m, "cachesize at longest:  %u\n", longest_chain_cachesize);
	return 0;
}

int nfsd_reply_cache_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, nfsd_reply_cache_stats_show, NULL);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfscache.c */
/************************************************************/
/*
 * XDR support for nfsd
 *
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

// #include "vfs.h"
// #include "xdr.h"
// #include "auth.h"

#define NFSDDBG_FACILITY		NFSDDBG_XDR

/*
 * Mapping of S_IF* types to NFS file types
 */
static u32	nfs_ftypes[] = {
	NFNON,  NFCHR,  NFCHR, NFBAD,
	NFDIR,  NFBAD,  NFBLK, NFBAD,
	NFREG,  NFBAD,  NFLNK, NFBAD,
	NFSOCK, NFBAD,  NFLNK, NFBAD,
};


/*
 * XDR functions for basic NFS types
 */
static __be32 *
decode_fh(__be32 *p, struct svc_fh *fhp)
{
	fh_init(fhp, NFS_FHSIZE);
	memcpy(&fhp->fh_handle.fh_base, p, NFS_FHSIZE);
	fhp->fh_handle.fh_size = NFS_FHSIZE;

	/* FIXME: Look up export pointer here and verify
	 * Sun Secure RPC if requested */
	return p + (NFS_FHSIZE >> 2);
}

/* Helper function for NFSv2 ACL code */
__be32 *nfs2svc_decode_fh(__be32 *p, struct svc_fh *fhp)
{
	return decode_fh(p, fhp);
}

static __be32 *
encode_fh(__be32 *p, struct svc_fh *fhp)
{
	memcpy(p, &fhp->fh_handle.fh_base, NFS_FHSIZE);
	return p + (NFS_FHSIZE>> 2);
}

/*
 * Decode a file name and make sure that the path contains
 * no slashes or null bytes.
 */
static __be32 *
decode_filename(__be32 *p, char **namp, unsigned int *lenp)
{
	char		*name;
	unsigned int	i;

	if ((p = xdr_decode_string_inplace(p, namp, lenp, NFS_MAXNAMLEN)) != NULL) {
		for (i = 0, name = *namp; i < *lenp; i++, name++) {
			if (*name == '\0' || *name == '/')
				return NULL;
		}
	}

	return p;
}

static __be32 *
decode_pathname(__be32 *p, char **namp, unsigned int *lenp)
{
	char		*name;
	unsigned int	i;

	if ((p = xdr_decode_string_inplace(p, namp, lenp, NFS_MAXPATHLEN)) != NULL) {
		for (i = 0, name = *namp; i < *lenp; i++, name++) {
			if (*name == '\0')
				return NULL;
		}
	}

	return p;
}

static __be32 *
decode_sattr(__be32 *p, struct iattr *iap)
{
	u32	tmp, tmp1;

	iap->ia_valid = 0;

	/* Sun client bug compatibility check: some sun clients seem to
	 * put 0xffff in the mode field when they mean 0xffffffff.
	 * Quoting the 4.4BSD nfs server code: Nah nah nah nah na nah.
	 */
	if ((tmp = ntohl(*p++)) != (u32)-1 && tmp != 0xffff) {
		iap->ia_valid |= ATTR_MODE;
		iap->ia_mode = tmp;
	}
	if ((tmp = ntohl(*p++)) != (u32)-1) {
		iap->ia_uid = make_kuid(&init_user_ns, tmp);
		if (uid_valid(iap->ia_uid))
			iap->ia_valid |= ATTR_UID;
	}
	if ((tmp = ntohl(*p++)) != (u32)-1) {
		iap->ia_gid = make_kgid(&init_user_ns, tmp);
		if (gid_valid(iap->ia_gid))
			iap->ia_valid |= ATTR_GID;
	}
	if ((tmp = ntohl(*p++)) != (u32)-1) {
		iap->ia_valid |= ATTR_SIZE;
		iap->ia_size = tmp;
	}
	tmp  = ntohl(*p++); tmp1 = ntohl(*p++);
	if (tmp != (u32)-1 && tmp1 != (u32)-1) {
		iap->ia_valid |= ATTR_ATIME | ATTR_ATIME_SET;
		iap->ia_atime.tv_sec = tmp;
		iap->ia_atime.tv_nsec = tmp1 * 1000; 
	}
	tmp  = ntohl(*p++); tmp1 = ntohl(*p++);
	if (tmp != (u32)-1 && tmp1 != (u32)-1) {
		iap->ia_valid |= ATTR_MTIME | ATTR_MTIME_SET;
		iap->ia_mtime.tv_sec = tmp;
		iap->ia_mtime.tv_nsec = tmp1 * 1000; 
		/*
		 * Passing the invalid value useconds=1000000 for mtime
		 * is a Sun convention for "set both mtime and atime to
		 * current server time".  It's needed to make permissions
		 * checks for the "touch" program across v2 mounts to
		 * Solaris and Irix boxes work correctly. See description of
		 * sattr in section 6.1 of "NFS Illustrated" by
		 * Brent Callaghan, Addison-Wesley, ISBN 0-201-32750-5
		 */
		if (tmp1 == 1000000)
			iap->ia_valid &= ~(ATTR_ATIME_SET|ATTR_MTIME_SET);
	}
	return p;
}

static __be32 *
encode_fattr(struct svc_rqst *rqstp, __be32 *p, struct svc_fh *fhp,
	     struct kstat *stat)
{
	struct dentry	*dentry = fhp->fh_dentry;
	int type;
	struct timespec time;
	u32 f;

	type = (stat->mode & S_IFMT);

	*p++ = htonl(nfs_ftypes[type >> 12]);
	*p++ = htonl((u32) stat->mode);
	*p++ = htonl((u32) stat->nlink);
	*p++ = htonl((u32) from_kuid(&init_user_ns, stat->uid));
	*p++ = htonl((u32) from_kgid(&init_user_ns, stat->gid));

	if (S_ISLNK(type) && stat->size > NFS_MAXPATHLEN) {
		*p++ = htonl(NFS_MAXPATHLEN);
	} else {
		*p++ = htonl((u32) stat->size);
	}
	*p++ = htonl((u32) stat->blksize);
	if (S_ISCHR(type) || S_ISBLK(type))
		*p++ = htonl(new_encode_dev(stat->rdev));
	else
		*p++ = htonl(0xffffffff);
	*p++ = htonl((u32) stat->blocks);
	switch (fsid_source(fhp)) {
	default:
	case FSIDSOURCE_DEV:
		*p++ = htonl(new_encode_dev(stat->dev));
		break;
	case FSIDSOURCE_FSID:
		*p++ = htonl((u32) fhp->fh_export->ex_fsid);
		break;
	case FSIDSOURCE_UUID:
		f = ((u32*)fhp->fh_export->ex_uuid)[0];
		f ^= ((u32*)fhp->fh_export->ex_uuid)[1];
		f ^= ((u32*)fhp->fh_export->ex_uuid)[2];
		f ^= ((u32*)fhp->fh_export->ex_uuid)[3];
		*p++ = htonl(f);
		break;
	}
	*p++ = htonl((u32) stat->ino);
	*p++ = htonl((u32) stat->atime.tv_sec);
	*p++ = htonl(stat->atime.tv_nsec ? stat->atime.tv_nsec / 1000 : 0);
	lease_get_mtime(dentry->d_inode, &time); 
	*p++ = htonl((u32) time.tv_sec);
	*p++ = htonl(time.tv_nsec ? time.tv_nsec / 1000 : 0); 
	*p++ = htonl((u32) stat->ctime.tv_sec);
	*p++ = htonl(stat->ctime.tv_nsec ? stat->ctime.tv_nsec / 1000 : 0);

	return p;
}

/* Helper function for NFSv2 ACL code */
__be32 *nfs2svc_encode_fattr(struct svc_rqst *rqstp, __be32 *p, struct svc_fh *fhp, struct kstat *stat)
{
	return encode_fattr(rqstp, p, fhp, stat);
}

/*
 * XDR decode functions
 */
int
nfssvc_decode_void(struct svc_rqst *rqstp, __be32 *p, void *dummy)
{
	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_fhandle(struct svc_rqst *rqstp, __be32 *p, struct nfsd_fhandle *args)
{
	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;
	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_sattrargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_sattrargs *args)
{
	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;
	p = decode_sattr(p, &args->attrs);

	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_diropargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_diropargs *args)
{
	if (!(p = decode_fh(p, &args->fh))
	 || !(p = decode_filename(p, &args->name, &args->len)))
		return 0;

	 return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_readargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_readargs *args)
{
	unsigned int len;
	int v;
	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;

	args->offset    = ntohl(*p++);
	len = args->count     = ntohl(*p++);
	p++; /* totalcount - unused */

	len = min_t(unsigned int, len, NFSSVC_MAXBLKSIZE_V2);

	/* set up somewhere to store response.
	 * We take pages, put them on reslist and include in iovec
	 */
	v=0;
	while (len > 0) {
		struct page *p = *(rqstp->rq_next_page++);

		rqstp->rq_vec[v].iov_base = page_address(p);
		rqstp->rq_vec[v].iov_len = min_t(unsigned int, len, PAGE_SIZE);
		len -= rqstp->rq_vec[v].iov_len;
		v++;
	}
	args->vlen = v;
	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_writeargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_writeargs *args)
{
	unsigned int len, hdr, dlen;
	int v;

	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;

	p++;				/* beginoffset */
	args->offset = ntohl(*p++);	/* offset */
	p++;				/* totalcount */
	len = args->len = ntohl(*p++);
	/*
	 * The protocol specifies a maximum of 8192 bytes.
	 */
	if (len > NFSSVC_MAXBLKSIZE_V2)
		return 0;

	/*
	 * Check to make sure that we got the right number of
	 * bytes.
	 */
	hdr = (void*)p - rqstp->rq_arg.head[0].iov_base;
	dlen = rqstp->rq_arg.head[0].iov_len + rqstp->rq_arg.page_len
		- hdr;

	/*
	 * Round the length of the data which was specified up to
	 * the next multiple of XDR units and then compare that
	 * against the length which was actually received.
	 * Note that when RPCSEC/GSS (for example) is used, the
	 * data buffer can be padded so dlen might be larger
	 * than required.  It must never be smaller.
	 */
	if (dlen < XDR_QUADLEN(len)*4)
		return 0;

	rqstp->rq_vec[0].iov_base = (void*)p;
	rqstp->rq_vec[0].iov_len = rqstp->rq_arg.head[0].iov_len - hdr;
	v = 0;
	while (len > rqstp->rq_vec[v].iov_len) {
		len -= rqstp->rq_vec[v].iov_len;
		v++;
		rqstp->rq_vec[v].iov_base = page_address(rqstp->rq_pages[v]);
		rqstp->rq_vec[v].iov_len = PAGE_SIZE;
	}
	rqstp->rq_vec[v].iov_len = len;
	args->vlen = v + 1;
	return 1;
}

int
nfssvc_decode_createargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_createargs *args)
{
	if (   !(p = decode_fh(p, &args->fh))
	    || !(p = decode_filename(p, &args->name, &args->len)))
		return 0;
	p = decode_sattr(p, &args->attrs);

	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_renameargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_renameargs *args)
{
	if (!(p = decode_fh(p, &args->ffh))
	 || !(p = decode_filename(p, &args->fname, &args->flen))
	 || !(p = decode_fh(p, &args->tfh))
	 || !(p = decode_filename(p, &args->tname, &args->tlen)))
		return 0;

	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_readlinkargs(struct svc_rqst *rqstp, __be32 *p, struct nfsd_readlinkargs *args)
{
	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;
	args->buffer = page_address(*(rqstp->rq_next_page++));

	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_linkargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_linkargs *args)
{
	if (!(p = decode_fh(p, &args->ffh))
	 || !(p = decode_fh(p, &args->tfh))
	 || !(p = decode_filename(p, &args->tname, &args->tlen)))
		return 0;

	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_symlinkargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_symlinkargs *args)
{
	if (   !(p = decode_fh(p, &args->ffh))
	    || !(p = decode_filename(p, &args->fname, &args->flen))
	    || !(p = decode_pathname(p, &args->tname, &args->tlen)))
		return 0;
	p = decode_sattr(p, &args->attrs);

	return xdr_argsize_check(rqstp, p);
}

int
nfssvc_decode_readdirargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_readdirargs *args)
{
	p = decode_fh(p, &args->fh);
	if (!p)
		return 0;
	args->cookie = ntohl(*p++);
	args->count  = ntohl(*p++);
	args->count  = min_t(u32, args->count, PAGE_SIZE);
	args->buffer = page_address(*(rqstp->rq_next_page++));

	return xdr_argsize_check(rqstp, p);
}

/*
 * XDR encode functions
 */
int
nfssvc_encode_void(struct svc_rqst *rqstp, __be32 *p, void *dummy)
{
	return xdr_ressize_check(rqstp, p);
}

int
nfssvc_encode_attrstat(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_attrstat *resp)
{
	p = encode_fattr(rqstp, p, &resp->fh, &resp->stat);
	return xdr_ressize_check(rqstp, p);
}

int
nfssvc_encode_diropres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_diropres *resp)
{
	p = encode_fh(p, &resp->fh);
	p = encode_fattr(rqstp, p, &resp->fh, &resp->stat);
	return xdr_ressize_check(rqstp, p);
}

int
nfssvc_encode_readlinkres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_readlinkres *resp)
{
	*p++ = htonl(resp->len);
	xdr_ressize_check(rqstp, p);
	rqstp->rq_res.page_len = resp->len;
	if (resp->len & 3) {
		/* need to pad the tail */
		rqstp->rq_res.tail[0].iov_base = p;
		*p = 0;
		rqstp->rq_res.tail[0].iov_len = 4 - (resp->len&3);
	}
	return 1;
}

int
nfssvc_encode_readres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_readres *resp)
{
	p = encode_fattr(rqstp, p, &resp->fh, &resp->stat);
	*p++ = htonl(resp->count);
	xdr_ressize_check(rqstp, p);

	/* now update rqstp->rq_res to reflect data as well */
	rqstp->rq_res.page_len = resp->count;
	if (resp->count & 3) {
		/* need to pad the tail */
		rqstp->rq_res.tail[0].iov_base = p;
		*p = 0;
		rqstp->rq_res.tail[0].iov_len = 4 - (resp->count&3);
	}
	return 1;
}

int
nfssvc_encode_readdirres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_readdirres *resp)
{
	xdr_ressize_check(rqstp, p);
	p = resp->buffer;
	*p++ = 0;			/* no more entries */
	*p++ = htonl((resp->common.err == nfserr_eof));
	rqstp->rq_res.page_len = (((unsigned long)p-1) & ~PAGE_MASK)+1;

	return 1;
}

int
nfssvc_encode_statfsres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_statfsres *resp)
{
	struct kstatfs	*stat = &resp->stats;

	*p++ = htonl(NFSSVC_MAXBLKSIZE_V2);	/* max transfer size */
	*p++ = htonl(stat->f_bsize);
	*p++ = htonl(stat->f_blocks);
	*p++ = htonl(stat->f_bfree);
	*p++ = htonl(stat->f_bavail);
	return xdr_ressize_check(rqstp, p);
}

int
nfssvc_encode_entry(void *ccdv, const char *name,
		    int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct readdir_cd *ccd = ccdv;
	struct nfsd_readdirres *cd = container_of(ccd, struct nfsd_readdirres, common);
	__be32	*p = cd->buffer;
	int	buflen, slen;

	/*
	dprintk("nfsd: entry(%.*s off %ld ino %ld)\n",
			namlen, name, offset, ino);
	 */

	if (offset > ~((u32) 0)) {
		cd->common.err = nfserr_fbig;
		return -EINVAL;
	}
	if (cd->offset)
		*cd->offset = htonl(offset);

	/* truncate filename */
	namlen = min(namlen, NFS2_MAXNAMLEN);
	slen = XDR_QUADLEN(namlen);

	if ((buflen = cd->buflen - slen - 4) < 0) {
		cd->common.err = nfserr_toosmall;
		return -EINVAL;
	}
	if (ino > ~((u32) 0)) {
		cd->common.err = nfserr_fbig;
		return -EINVAL;
	}
	*p++ = xdr_one;				/* mark entry present */
	*p++ = htonl((u32) ino);		/* file id */
	p    = xdr_encode_array(p, name, namlen);/* name length & name */
	cd->offset = p;			/* remember pointer */
	*p++ = htonl(~0U);		/* offset of next entry */

	cd->buflen = buflen;
	cd->buffer = p;
	cd->common.err = nfs_ok;
	return 0;
}

/*
 * XDR release functions
 */
int
nfssvc_release_fhandle(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd_fhandle *resp)
{
	fh_put(&resp->fh);
	return 1;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfsxdr.c */
/************************************************************/
/*
 * procfs-based user access to knfsd statistics
 *
 * /proc/net/rpc/nfsd
 *
 * Format:
 *	rc <hits> <misses> <nocache>
 *			Statistsics for the reply cache
 *	fh <stale> <total-lookups> <anonlookups> <dir-not-in-dcache> <nondir-not-in-dcache>
 *			statistics for filehandle lookup
 *	io <bytes-read> <bytes-written>
 *			statistics for IO throughput
 *	th <threads> <fullcnt> <10%-20%> <20%-30%> ... <90%-100%> <100%> 
 *			time (seconds) when nfsd thread usage above thresholds
 *			and number of times that all threads were in use
 *	ra cache-size  <10%  <20%  <30% ... <100% not-found
 *			number of times that read-ahead entry was found that deep in
 *			the cache.
 *	plus generic RPC stats (see net/sunrpc/stats.c)
 *
 * Copyright (C) 1995, 1996, 1997 Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/seq_file.h>
// #include <linux/module.h>
// #include <linux/sunrpc/stats.h>
// #include <net/net_namespace.h>

// #include "nfsd.h"

struct nfsd_stats	nfsdstats;
struct svc_stat		nfsd_svcstats = {
	.program	= &nfsd_program,
};

static int nfsd_proc_show(struct seq_file *seq, void *v)
{
	int i;

	seq_printf(seq, "rc %u %u %u\nfh %u %u %u %u %u\nio %u %u\n",
		      nfsdstats.rchits,
		      nfsdstats.rcmisses,
		      nfsdstats.rcnocache,
		      nfsdstats.fh_stale,
		      nfsdstats.fh_lookup,
		      nfsdstats.fh_anon,
		      nfsdstats.fh_nocache_dir,
		      nfsdstats.fh_nocache_nondir,
		      nfsdstats.io_read,
		      nfsdstats.io_write);
	/* thread usage: */
	seq_printf(seq, "th %u %u", nfsdstats.th_cnt, nfsdstats.th_fullcnt);
	for (i=0; i<10; i++) {
		unsigned int jifs = nfsdstats.th_usage[i];
		unsigned int sec = jifs / HZ, msec = (jifs % HZ)*1000/HZ;
		seq_printf(seq, " %u.%03u", sec, msec);
	}

	/* newline and ra-cache */
	seq_printf(seq, "\nra %u", nfsdstats.ra_size);
	for (i=0; i<11; i++)
		seq_printf(seq, " %u", nfsdstats.ra_depth[i]);
	seq_putc(seq, '\n');
	
	/* show my rpc info */
	svc_seq_show(seq, &nfsd_svcstats);

#ifdef CONFIG_NFSD_V4
	/* Show count for individual nfsv4 operations */
	/* Writing operation numbers 0 1 2 also for maintaining uniformity */
	seq_printf(seq,"proc4ops %u", LAST_NFS4_OP + 1);
	for (i = 0; i <= LAST_NFS4_OP; i++)
		seq_printf(seq, " %u", nfsdstats.nfs4_opcount[i]);

	seq_putc(seq, '\n');
#endif

	return 0;
}

static int nfsd_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, nfsd_proc_show, NULL);
}

static const struct file_operations nfsd_proc_fops = {
	.owner = THIS_MODULE,
	.open = nfsd_proc_open,
	.read  = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

void
nfsd_stat_init(void)
{
	svc_proc_register(&init_net, &nfsd_svcstats, &nfsd_proc_fops);
}

void
nfsd_stat_shutdown(void)
{
	svc_proc_unregister(&init_net, "nfsd");
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/stats.c */
/************************************************************/
/*
 * Process version 2 NFSACL requests.
 *
 * Copyright (C) 2002-2003 Andreas Gruenbacher <agruen@suse.de>
 */

// #include "nfsd.h"
/* FIXME: nfsacl.h is a broken header */
// #include <linux/nfsacl.h>
#include <linux/gfp.h>
// #include "cache.h"
// #include "xdr3.h"
// #include "vfs.h"
#include "../../inc/__fss.h"

#define NFSDDBG_FACILITY		NFSDDBG_PROC
#define RETURN_STATUS(st)	{ resp->status = (st); return (st); }

/*
 * NULL call.
 */
static __be32
nfsacld_proc_null(struct svc_rqst *rqstp, void *argp, void *resp)
{
	return nfs_ok;
}

/*
 * Get the Access and/or Default ACL of a file.
 */
static __be32 nfsacld_proc_getacl(struct svc_rqst * rqstp,
		struct nfsd3_getaclargs *argp, struct nfsd3_getaclres *resp)
{
	struct posix_acl *acl;
	struct inode *inode;
	svc_fh *fh;
	__be32 nfserr = 0;

	dprintk("nfsd: GETACL(2acl)   %s\n", SVCFH_fmt(&argp->fh));

	fh = fh_copy(&resp->fh, &argp->fh);
	nfserr = fh_verify(rqstp, &resp->fh, 0, NFSD_MAY_NOP);
	if (nfserr)
		RETURN_STATUS(nfserr);

	inode = fh->fh_dentry->d_inode;

	if (argp->mask & ~(NFS_ACL|NFS_ACLCNT|NFS_DFACL|NFS_DFACLCNT))
		RETURN_STATUS(nfserr_inval);
	resp->mask = argp->mask;

	nfserr = fh_getattr(fh, &resp->stat);
	if (nfserr)
		goto fail;

	if (resp->mask & (NFS_ACL|NFS_ACLCNT)) {
		acl = get_acl(inode, ACL_TYPE_ACCESS);
		if (acl == NULL) {
			/* Solaris returns the inode's minimum ACL. */
			acl = posix_acl_from_mode(inode->i_mode, GFP_KERNEL);
		}
		if (IS_ERR(acl)) {
			nfserr = nfserrno(PTR_ERR(acl));
			goto fail;
		}
		resp->acl_access = acl;
	}
	if (resp->mask & (NFS_DFACL|NFS_DFACLCNT)) {
		/* Check how Solaris handles requests for the Default ACL
		   of a non-directory! */
		acl = get_acl(inode, ACL_TYPE_DEFAULT);
		if (IS_ERR(acl)) {
			nfserr = nfserrno(PTR_ERR(acl));
			goto fail;
		}
		resp->acl_default = acl;
	}

	/* resp->acl_{access,default} are released in nfssvc_release_getacl. */
	RETURN_STATUS(0);

fail:
	posix_acl_release(resp->acl_access);
	posix_acl_release(resp->acl_default);
	RETURN_STATUS(nfserr);
}

/*
 * Set the Access and/or Default ACL of a file.
 */
static __be32 nfsacld_proc_setacl(struct svc_rqst * rqstp,
		struct nfsd3_setaclargs *argp,
		struct nfsd_attrstat *resp)
{
	struct inode *inode;
	svc_fh *fh;
	__be32 nfserr = 0;
	int error;

	dprintk("nfsd: SETACL(2acl)   %s\n", SVCFH_fmt(&argp->fh));

	fh = fh_copy(&resp->fh, &argp->fh);
	nfserr = fh_verify(rqstp, &resp->fh, 0, NFSD_MAY_SATTR);
	if (nfserr)
		goto out;

	inode = fh->fh_dentry->d_inode;
	if (!IS_POSIXACL(inode) || !inode->i_op->set_acl) {
		error = -EOPNOTSUPP;
		goto out_errno;
	}

	error = fh_want_write(fh);
	if (error)
		goto out_errno;

	error = inode->i_op->set_acl(inode, argp->acl_access, ACL_TYPE_ACCESS);
	if (error)
		goto out_drop_write;
	error = inode->i_op->set_acl(inode, argp->acl_default,
				     ACL_TYPE_DEFAULT);
	if (error)
		goto out_drop_write;

	fh_drop_write(fh);

	nfserr = fh_getattr(fh, &resp->stat);

out:
	/* argp->acl_{access,default} may have been allocated in
	   nfssvc_decode_setaclargs. */
	posix_acl_release(argp->acl_access);
	posix_acl_release(argp->acl_default);
	return nfserr;
out_drop_write:
	fh_drop_write(fh);
out_errno:
	nfserr = nfserrno(error);
	goto out;
}

/*
 * Check file attributes
 */
static __be32 nfsacld_proc_getattr(struct svc_rqst * rqstp,
		struct nfsd_fhandle *argp, struct nfsd_attrstat *resp)
{
	__be32 nfserr;
	dprintk("nfsd: GETATTR  %s\n", SVCFH_fmt(&argp->fh));

	fh_copy(&resp->fh, &argp->fh);
	nfserr = fh_verify(rqstp, &resp->fh, 0, NFSD_MAY_NOP);
	if (nfserr)
		return nfserr;
	nfserr = fh_getattr(&resp->fh, &resp->stat);
	return nfserr;
}

/*
 * Check file access
 */
static __be32 nfsacld_proc_access(struct svc_rqst *rqstp, struct nfsd3_accessargs *argp,
		struct nfsd3_accessres *resp)
{
	__be32 nfserr;

	dprintk("nfsd: ACCESS(2acl)   %s 0x%x\n",
			SVCFH_fmt(&argp->fh),
			argp->access);

	fh_copy(&resp->fh, &argp->fh);
	resp->access = argp->access;
	nfserr = nfsd_access(rqstp, &resp->fh, &resp->access, NULL);
	if (nfserr)
		return nfserr;
	nfserr = fh_getattr(&resp->fh, &resp->stat);
	return nfserr;
}

/*
 * XDR decode functions
 */
static int nfsaclsvc_decode_getaclargs(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_getaclargs *argp)
{
	p = nfs2svc_decode_fh(p, &argp->fh);
	if (!p)
		return 0;
	argp->mask = ntohl(*p); p++;

	return xdr_argsize_check(rqstp, p);
}


static int nfsaclsvc_decode_setaclargs(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_setaclargs *argp)
{
	struct kvec *head = rqstp->rq_arg.head;
	unsigned int base;
	int n;

	p = nfs2svc_decode_fh(p, &argp->fh);
	if (!p)
		return 0;
	argp->mask = ntohl(*p++);
	if (argp->mask & ~(NFS_ACL|NFS_ACLCNT|NFS_DFACL|NFS_DFACLCNT) ||
	    !xdr_argsize_check(rqstp, p))
		return 0;

	base = (char *)p - (char *)head->iov_base;
	n = nfsacl_decode(&rqstp->rq_arg, base, NULL,
			  (argp->mask & NFS_ACL) ?
			  &argp->acl_access : NULL);
	if (n > 0)
		n = nfsacl_decode(&rqstp->rq_arg, base + n, NULL,
				  (argp->mask & NFS_DFACL) ?
				  &argp->acl_default : NULL);
	return (n > 0);
}

static int nfsaclsvc_decode_fhandleargs(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd_fhandle *argp)
{
	p = nfs2svc_decode_fh(p, &argp->fh);
	if (!p)
		return 0;
	return xdr_argsize_check(rqstp, p);
}

static int nfsaclsvc_decode_accessargs(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_accessargs *argp)
{
	p = nfs2svc_decode_fh(p, &argp->fh);
	if (!p)
		return 0;
	argp->access = ntohl(*p++);

	return xdr_argsize_check(rqstp, p);
}

/*
 * XDR encode functions
 */

/*
 * There must be an encoding function for void results so svc_process
 * will work properly.
 */
static int nfsaclsvc_encode_voidres(struct svc_rqst *rqstp, __be32 *p, void *dummy)
{
	return xdr_ressize_check(rqstp, p);
}

/* GETACL */
static int nfsaclsvc_encode_getaclres(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_getaclres *resp)
{
	struct dentry *dentry = resp->fh.fh_dentry;
	struct inode *inode;
	struct kvec *head = rqstp->rq_res.head;
	unsigned int base;
	int n;
	int w;

	/*
	 * Since this is version 2, the check for nfserr in
	 * nfsd_dispatch actually ensures the following cannot happen.
	 * However, it seems fragile to depend on that.
	 */
	if (dentry == NULL || dentry->d_inode == NULL)
		return 0;
	inode = dentry->d_inode;

	p = nfs2svc_encode_fattr(rqstp, p, &resp->fh, &resp->stat);
	*p++ = htonl(resp->mask);
	if (!xdr_ressize_check(rqstp, p))
		return 0;
	base = (char *)p - (char *)head->iov_base;

	rqstp->rq_res.page_len = w = nfsacl_size(
		(resp->mask & NFS_ACL)   ? resp->acl_access  : NULL,
		(resp->mask & NFS_DFACL) ? resp->acl_default : NULL);
	while (w > 0) {
		if (!*(rqstp->rq_next_page++))
			return 0;
		w -= PAGE_SIZE;
	}

	n = nfsacl_encode(&rqstp->rq_res, base, inode,
			  resp->acl_access,
			  resp->mask & NFS_ACL, 0);
	if (n > 0)
		n = nfsacl_encode(&rqstp->rq_res, base + n, inode,
				  resp->acl_default,
				  resp->mask & NFS_DFACL,
				  NFS_ACL_DEFAULT);
	if (n <= 0)
		return 0;
	return 1;
}

static int nfsaclsvc_encode_attrstatres(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd_attrstat *resp)
{
	p = nfs2svc_encode_fattr(rqstp, p, &resp->fh, &resp->stat);
	return xdr_ressize_check(rqstp, p);
}

/* ACCESS */
static int nfsaclsvc_encode_accessres(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_accessres *resp)
{
	p = nfs2svc_encode_fattr(rqstp, p, &resp->fh, &resp->stat);
	*p++ = htonl(resp->access);
	return xdr_ressize_check(rqstp, p);
}

/*
 * XDR release functions
 */
static int nfsaclsvc_release_getacl(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_getaclres *resp)
{
	fh_put(&resp->fh);
	posix_acl_release(resp->acl_access);
	posix_acl_release(resp->acl_default);
	return 1;
}

static int nfsaclsvc_release_attrstat(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd_attrstat *resp)
{
	fh_put(&resp->fh);
	return 1;
}

static int nfsaclsvc_release_access(struct svc_rqst *rqstp, __be32 *p,
               struct nfsd3_accessres *resp)
{
       fh_put(&resp->fh);
       return 1;
}

#define nfsaclsvc_decode_voidargs	NULL
#define nfsaclsvc_release_void		NULL
#define nfsd3_fhandleargs	nfsd_fhandle
#define nfsd3_attrstatres	nfsd_attrstat
#define nfsd3_voidres		nfsd3_voidargs
struct nfsd3_voidargs { int dummy; };

#define PROC(name, argt, rest, relt, cache, respsize)	\
 { (svc_procfunc) nfsacld_proc_##name,		\
   (kxdrproc_t) nfsaclsvc_decode_##argt##args,	\
   (kxdrproc_t) nfsaclsvc_encode_##rest##res,	\
   (kxdrproc_t) nfsaclsvc_release_##relt,		\
   sizeof(struct nfsd3_##argt##args),		\
   sizeof(struct nfsd3_##rest##res),		\
   0,						\
   cache,					\
   respsize,					\
 }

#define ST 1		/* status*/
#define AT 21		/* attributes */
#define pAT (1+AT)	/* post attributes - conditional */
#define ACL (1+NFS_ACL_MAX_ENTRIES*3)  /* Access Control List */

static struct svc_procedure		nfsd_acl_procedures2[] = {
  PROC(null,	void,		void,		void,	  RC_NOCACHE, ST),
  PROC(getacl,	getacl,		getacl,		getacl,	  RC_NOCACHE, ST+1+2*(1+ACL)),
  PROC(setacl,	setacl,		attrstat,	attrstat, RC_NOCACHE, ST+AT),
  PROC(getattr, fhandle,	attrstat,	attrstat, RC_NOCACHE, ST+AT),
  PROC(access,	access,		access,		access,   RC_NOCACHE, ST+AT+1),
};

struct svc_version	nfsd_acl_version2 = {
		.vs_vers	= 2,
		.vs_nproc	= 5,
		.vs_proc	= nfsd_acl_procedures2,
		.vs_dispatch	= nfsd_dispatch,
		.vs_xdrsize	= NFS3_SVC_XDRSIZE,
		.vs_hidden	= 0,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs2acl.c */
/************************************************************/
/*
 * Process version 3 NFS requests.
 *
 * Copyright (C) 1996, 1997, 1998 Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/magic.h>
#include "../../inc/__fss.h"

// #include "cache.h"
// #include "xdr3.h"
// #include "vfs.h"

#define NFSDDBG_FACILITY		NFSDDBG_PROC

#define RETURN_STATUS(st)	{ resp->status = (st); return (st); }

static int	nfs3_ftypes[] = {
	0,			/* NF3NON */
	S_IFREG,		/* NF3REG */
	S_IFDIR,		/* NF3DIR */
	S_IFBLK,		/* NF3BLK */
	S_IFCHR,		/* NF3CHR */
	S_IFLNK,		/* NF3LNK */
	S_IFSOCK,		/* NF3SOCK */
	S_IFIFO,		/* NF3FIFO */
};

/*
 * NULL call.
 */
static __be32
nfsd3_proc_null(struct svc_rqst *rqstp, void *argp, void *resp)
{
	return nfs_ok;
}

/*
 * Get a file's attributes
 */
static __be32
nfsd3_proc_getattr(struct svc_rqst *rqstp, struct nfsd_fhandle  *argp,
					   struct nfsd3_attrstat *resp)
{
	__be32	nfserr;

	dprintk("nfsd: GETATTR(3)  %s\n",
		SVCFH_fmt(&argp->fh));

	fh_copy(&resp->fh, &argp->fh);
	nfserr = fh_verify(rqstp, &resp->fh, 0,
			NFSD_MAY_NOP | NFSD_MAY_BYPASS_GSS_ON_ROOT);
	if (nfserr)
		RETURN_STATUS(nfserr);

	nfserr = fh_getattr(&resp->fh, &resp->stat);

	RETURN_STATUS(nfserr);
}

/*
 * Set a file's attributes
 */
static __be32
nfsd3_proc_setattr(struct svc_rqst *rqstp, struct nfsd3_sattrargs *argp,
					   struct nfsd3_attrstat  *resp)
{
	__be32	nfserr;

	dprintk("nfsd: SETATTR(3)  %s\n",
				SVCFH_fmt(&argp->fh));

	fh_copy(&resp->fh, &argp->fh);
	nfserr = nfsd_setattr(rqstp, &resp->fh, &argp->attrs,
			      argp->check_guard, argp->guardtime);
	RETURN_STATUS(nfserr);
}

/*
 * Look up a path name component
 */
static __be32
nfsd3_proc_lookup(struct svc_rqst *rqstp, struct nfsd3_diropargs *argp,
					  struct nfsd3_diropres  *resp)
{
	__be32	nfserr;

	dprintk("nfsd: LOOKUP(3)   %s %.*s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				argp->name);

	fh_copy(&resp->dirfh, &argp->fh);
	fh_init(&resp->fh, NFS3_FHSIZE);

	nfserr = nfsd_lookup(rqstp, &resp->dirfh,
				    argp->name,
				    argp->len,
				    &resp->fh);
	RETURN_STATUS(nfserr);
}

/*
 * Check file access
 */
static __be32
nfsd3_proc_access(struct svc_rqst *rqstp, struct nfsd3_accessargs *argp,
					  struct nfsd3_accessres *resp)
{
	__be32	nfserr;

	dprintk("nfsd: ACCESS(3)   %s 0x%x\n",
				SVCFH_fmt(&argp->fh),
				argp->access);

	fh_copy(&resp->fh, &argp->fh);
	resp->access = argp->access;
	nfserr = nfsd_access(rqstp, &resp->fh, &resp->access, NULL);
	RETURN_STATUS(nfserr);
}

/*
 * Read a symlink.
 */
static __be32
nfsd3_proc_readlink(struct svc_rqst *rqstp, struct nfsd3_readlinkargs *argp,
					   struct nfsd3_readlinkres *resp)
{
	__be32 nfserr;

	dprintk("nfsd: READLINK(3) %s\n", SVCFH_fmt(&argp->fh));

	/* Read the symlink. */
	fh_copy(&resp->fh, &argp->fh);
	resp->len = NFS3_MAXPATHLEN;
	nfserr = nfsd_readlink(rqstp, &resp->fh, argp->buffer, &resp->len);
	RETURN_STATUS(nfserr);
}

/*
 * Read a portion of a file.
 */
static __be32
nfsd3_proc_read(struct svc_rqst *rqstp, struct nfsd3_readargs *argp,
				        struct nfsd3_readres  *resp)
{
	__be32	nfserr;
	u32	max_blocksize = svc_max_payload(rqstp);

	dprintk("nfsd: READ(3) %s %lu bytes at %Lu\n",
				SVCFH_fmt(&argp->fh),
				(unsigned long) argp->count,
				(unsigned long long) argp->offset);

	/* Obtain buffer pointer for payload.
	 * 1 (status) + 22 (post_op_attr) + 1 (count) + 1 (eof)
	 * + 1 (xdr opaque byte count) = 26
	 */
	resp->count = min(argp->count, max_blocksize);
	svc_reserve_auth(rqstp, ((1 + NFS3_POST_OP_ATTR_WORDS + 3)<<2) + resp->count +4);

	fh_copy(&resp->fh, &argp->fh);
	nfserr = nfsd_read(rqstp, &resp->fh,
				  argp->offset,
			   	  rqstp->rq_vec, argp->vlen,
				  &resp->count);
	if (nfserr == 0) {
		struct inode	*inode = resp->fh.fh_dentry->d_inode;

		resp->eof = (argp->offset + resp->count) >= inode->i_size;
	}

	RETURN_STATUS(nfserr);
}

/*
 * Write data to a file
 */
static __be32
nfsd3_proc_write(struct svc_rqst *rqstp, struct nfsd3_writeargs *argp,
					 struct nfsd3_writeres  *resp)
{
	__be32	nfserr;
	unsigned long cnt = argp->len;

	dprintk("nfsd: WRITE(3)    %s %d bytes at %Lu%s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				(unsigned long long) argp->offset,
				argp->stable? " stable" : "");

	fh_copy(&resp->fh, &argp->fh);
	resp->committed = argp->stable;
	nfserr = nfsd_write(rqstp, &resp->fh, NULL,
				   argp->offset,
				   rqstp->rq_vec, argp->vlen,
				   &cnt,
				   &resp->committed);
	resp->count = cnt;
	RETURN_STATUS(nfserr);
}

/*
 * With NFSv3, CREATE processing is a lot easier than with NFSv2.
 * At least in theory; we'll see how it fares in practice when the
 * first reports about SunOS compatibility problems start to pour in...
 */
static __be32
nfsd3_proc_create(struct svc_rqst *rqstp, struct nfsd3_createargs *argp,
					  struct nfsd3_diropres   *resp)
{
	svc_fh		*dirfhp, *newfhp = NULL;
	struct iattr	*attr;
	__be32		nfserr;

	dprintk("nfsd: CREATE(3)   %s %.*s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				argp->name);

	dirfhp = fh_copy(&resp->dirfh, &argp->fh);
	newfhp = fh_init(&resp->fh, NFS3_FHSIZE);
	attr   = &argp->attrs;

	/* Unfudge the mode bits */
	attr->ia_mode &= ~S_IFMT;
	if (!(attr->ia_valid & ATTR_MODE)) { 
		attr->ia_valid |= ATTR_MODE;
		attr->ia_mode = S_IFREG;
	} else {
		attr->ia_mode = (attr->ia_mode & ~S_IFMT) | S_IFREG;
	}

	/* Now create the file and set attributes */
	nfserr = do_nfsd_create(rqstp, dirfhp, argp->name, argp->len,
				attr, newfhp,
				argp->createmode, (u32 *)argp->verf, NULL, NULL);

	RETURN_STATUS(nfserr);
}

/*
 * Make directory. This operation is not idempotent.
 */
static __be32
nfsd3_proc_mkdir(struct svc_rqst *rqstp, struct nfsd3_createargs *argp,
					 struct nfsd3_diropres   *resp)
{
	__be32	nfserr;

	dprintk("nfsd: MKDIR(3)    %s %.*s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				argp->name);

	argp->attrs.ia_valid &= ~ATTR_SIZE;
	fh_copy(&resp->dirfh, &argp->fh);
	fh_init(&resp->fh, NFS3_FHSIZE);
	nfserr = nfsd_create(rqstp, &resp->dirfh, argp->name, argp->len,
				    &argp->attrs, S_IFDIR, 0, &resp->fh);
	fh_unlock(&resp->dirfh);
	RETURN_STATUS(nfserr);
}

static __be32
nfsd3_proc_symlink(struct svc_rqst *rqstp, struct nfsd3_symlinkargs *argp,
					   struct nfsd3_diropres    *resp)
{
	__be32	nfserr;

	dprintk("nfsd: SYMLINK(3)  %s %.*s -> %.*s\n",
				SVCFH_fmt(&argp->ffh),
				argp->flen, argp->fname,
				argp->tlen, argp->tname);

	fh_copy(&resp->dirfh, &argp->ffh);
	fh_init(&resp->fh, NFS3_FHSIZE);
	nfserr = nfsd_symlink(rqstp, &resp->dirfh, argp->fname, argp->flen,
						   argp->tname, &resp->fh);
	RETURN_STATUS(nfserr);
}

/*
 * Make socket/fifo/device.
 */
static __be32
nfsd3_proc_mknod(struct svc_rqst *rqstp, struct nfsd3_mknodargs *argp,
					 struct nfsd3_diropres  *resp)
{
	__be32	nfserr;
	int type;
	dev_t	rdev = 0;

	dprintk("nfsd: MKNOD(3)    %s %.*s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				argp->name);

	fh_copy(&resp->dirfh, &argp->fh);
	fh_init(&resp->fh, NFS3_FHSIZE);

	if (argp->ftype == 0 || argp->ftype >= NF3BAD)
		RETURN_STATUS(nfserr_inval);
	if (argp->ftype == NF3CHR || argp->ftype == NF3BLK) {
		rdev = MKDEV(argp->major, argp->minor);
		if (MAJOR(rdev) != argp->major ||
		    MINOR(rdev) != argp->minor)
			RETURN_STATUS(nfserr_inval);
	} else
		if (argp->ftype != NF3SOCK && argp->ftype != NF3FIFO)
			RETURN_STATUS(nfserr_inval);

	type = nfs3_ftypes[argp->ftype];
	nfserr = nfsd_create(rqstp, &resp->dirfh, argp->name, argp->len,
				    &argp->attrs, type, rdev, &resp->fh);
	fh_unlock(&resp->dirfh);
	RETURN_STATUS(nfserr);
}

/*
 * Remove file/fifo/socket etc.
 */
static __be32
nfsd3_proc_remove(struct svc_rqst *rqstp, struct nfsd3_diropargs *argp,
					  struct nfsd3_attrstat  *resp)
{
	__be32	nfserr;

	dprintk("nfsd: REMOVE(3)   %s %.*s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				argp->name);

	/* Unlink. -S_IFDIR means file must not be a directory */
	fh_copy(&resp->fh, &argp->fh);
	nfserr = nfsd_unlink(rqstp, &resp->fh, -S_IFDIR, argp->name, argp->len);
	fh_unlock(&resp->fh);
	RETURN_STATUS(nfserr);
}

/*
 * Remove a directory
 */
static __be32
nfsd3_proc_rmdir(struct svc_rqst *rqstp, struct nfsd3_diropargs *argp,
					 struct nfsd3_attrstat  *resp)
{
	__be32	nfserr;

	dprintk("nfsd: RMDIR(3)    %s %.*s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				argp->name);

	fh_copy(&resp->fh, &argp->fh);
	nfserr = nfsd_unlink(rqstp, &resp->fh, S_IFDIR, argp->name, argp->len);
	fh_unlock(&resp->fh);
	RETURN_STATUS(nfserr);
}

static __be32
nfsd3_proc_rename(struct svc_rqst *rqstp, struct nfsd3_renameargs *argp,
					  struct nfsd3_renameres  *resp)
{
	__be32	nfserr;

	dprintk("nfsd: RENAME(3)   %s %.*s ->\n",
				SVCFH_fmt(&argp->ffh),
				argp->flen,
				argp->fname);
	dprintk("nfsd: -> %s %.*s\n",
				SVCFH_fmt(&argp->tfh),
				argp->tlen,
				argp->tname);

	fh_copy(&resp->ffh, &argp->ffh);
	fh_copy(&resp->tfh, &argp->tfh);
	nfserr = nfsd_rename(rqstp, &resp->ffh, argp->fname, argp->flen,
				    &resp->tfh, argp->tname, argp->tlen);
	RETURN_STATUS(nfserr);
}

static __be32
nfsd3_proc_link(struct svc_rqst *rqstp, struct nfsd3_linkargs *argp,
					struct nfsd3_linkres  *resp)
{
	__be32	nfserr;

	dprintk("nfsd: LINK(3)     %s ->\n",
				SVCFH_fmt(&argp->ffh));
	dprintk("nfsd:   -> %s %.*s\n",
				SVCFH_fmt(&argp->tfh),
				argp->tlen,
				argp->tname);

	fh_copy(&resp->fh,  &argp->ffh);
	fh_copy(&resp->tfh, &argp->tfh);
	nfserr = nfsd_link(rqstp, &resp->tfh, argp->tname, argp->tlen,
				  &resp->fh);
	RETURN_STATUS(nfserr);
}

/*
 * Read a portion of a directory.
 */
static __be32
nfsd3_proc_readdir(struct svc_rqst *rqstp, struct nfsd3_readdirargs *argp,
					   struct nfsd3_readdirres  *resp)
{
	__be32		nfserr;
	int		count;

	dprintk("nfsd: READDIR(3)  %s %d bytes at %d\n",
				SVCFH_fmt(&argp->fh),
				argp->count, (u32) argp->cookie);

	/* Make sure we've room for the NULL ptr & eof flag, and shrink to
	 * client read size */
	count = (argp->count >> 2) - 2;

	/* Read directory and encode entries on the fly */
	fh_copy(&resp->fh, &argp->fh);

	resp->buflen = count;
	resp->common.err = nfs_ok;
	resp->buffer = argp->buffer;
	resp->rqstp = rqstp;
	nfserr = nfsd_readdir(rqstp, &resp->fh, (loff_t*) &argp->cookie, 
					&resp->common, nfs3svc_encode_entry);
	memcpy(resp->verf, argp->verf, 8);
	resp->count = resp->buffer - argp->buffer;
	if (resp->offset)
		xdr_encode_hyper(resp->offset, argp->cookie);

	RETURN_STATUS(nfserr);
}

/*
 * Read a portion of a directory, including file handles and attrs.
 * For now, we choose to ignore the dircount parameter.
 */
static __be32
nfsd3_proc_readdirplus(struct svc_rqst *rqstp, struct nfsd3_readdirargs *argp,
					       struct nfsd3_readdirres  *resp)
{
	__be32	nfserr;
	int	count = 0;
	loff_t	offset;
	struct page **p;
	caddr_t	page_addr = NULL;

	dprintk("nfsd: READDIR+(3) %s %d bytes at %d\n",
				SVCFH_fmt(&argp->fh),
				argp->count, (u32) argp->cookie);

	/* Convert byte count to number of words (i.e. >> 2),
	 * and reserve room for the NULL ptr & eof flag (-2 words) */
	resp->count = (argp->count >> 2) - 2;

	/* Read directory and encode entries on the fly */
	fh_copy(&resp->fh, &argp->fh);

	resp->common.err = nfs_ok;
	resp->buffer = argp->buffer;
	resp->buflen = resp->count;
	resp->rqstp = rqstp;
	offset = argp->cookie;

	nfserr = fh_verify(rqstp, &resp->fh, S_IFDIR, NFSD_MAY_NOP);
	if (nfserr)
		RETURN_STATUS(nfserr);

	if (resp->fh.fh_export->ex_flags & NFSEXP_NOREADDIRPLUS)
		RETURN_STATUS(nfserr_notsupp);

	nfserr = nfsd_readdir(rqstp, &resp->fh,
				     &offset,
				     &resp->common,
				     nfs3svc_encode_entry_plus);
	memcpy(resp->verf, argp->verf, 8);
	for (p = rqstp->rq_respages + 1; p < rqstp->rq_next_page; p++) {
		page_addr = page_address(*p);

		if (((caddr_t)resp->buffer >= page_addr) &&
		    ((caddr_t)resp->buffer < page_addr + PAGE_SIZE)) {
			count += (caddr_t)resp->buffer - page_addr;
			break;
		}
		count += PAGE_SIZE;
	}
	resp->count = count >> 2;
	if (resp->offset) {
		if (unlikely(resp->offset1)) {
			/* we ended up with offset on a page boundary */
			*resp->offset = htonl(offset >> 32);
			*resp->offset1 = htonl(offset & 0xffffffff);
			resp->offset1 = NULL;
		} else {
			xdr_encode_hyper(resp->offset, offset);
		}
	}

	RETURN_STATUS(nfserr);
}

/*
 * Get file system stats
 */
static __be32
nfsd3_proc_fsstat(struct svc_rqst * rqstp, struct nfsd_fhandle    *argp,
					   struct nfsd3_fsstatres *resp)
{
	__be32	nfserr;

	dprintk("nfsd: FSSTAT(3)   %s\n",
				SVCFH_fmt(&argp->fh));

	nfserr = nfsd_statfs(rqstp, &argp->fh, &resp->stats, 0);
	fh_put(&argp->fh);
	RETURN_STATUS(nfserr);
}

/*
 * Get file system info
 */
static __be32
nfsd3_proc_fsinfo(struct svc_rqst * rqstp, struct nfsd_fhandle    *argp,
					   struct nfsd3_fsinfores *resp)
{
	__be32	nfserr;
	u32	max_blocksize = svc_max_payload(rqstp);

	dprintk("nfsd: FSINFO(3)   %s\n",
				SVCFH_fmt(&argp->fh));

	resp->f_rtmax  = max_blocksize;
	resp->f_rtpref = max_blocksize;
	resp->f_rtmult = PAGE_SIZE;
	resp->f_wtmax  = max_blocksize;
	resp->f_wtpref = max_blocksize;
	resp->f_wtmult = PAGE_SIZE;
	resp->f_dtpref = PAGE_SIZE;
	resp->f_maxfilesize = ~(u32) 0;
	resp->f_properties = NFS3_FSF_DEFAULT;

	nfserr = fh_verify(rqstp, &argp->fh, 0,
			NFSD_MAY_NOP | NFSD_MAY_BYPASS_GSS_ON_ROOT);

	/* Check special features of the file system. May request
	 * different read/write sizes for file systems known to have
	 * problems with large blocks */
	if (nfserr == 0) {
		struct super_block *sb = argp->fh.fh_dentry->d_inode->i_sb;

		/* Note that we don't care for remote fs's here */
		if (sb->s_magic == MSDOS_SUPER_MAGIC) {
			resp->f_properties = NFS3_FSF_BILLYBOY;
		}
		resp->f_maxfilesize = sb->s_maxbytes;
	}

	fh_put(&argp->fh);
	RETURN_STATUS(nfserr);
}

/*
 * Get pathconf info for the specified file
 */
static __be32
nfsd3_proc_pathconf(struct svc_rqst * rqstp, struct nfsd_fhandle      *argp,
					     struct nfsd3_pathconfres *resp)
{
	__be32	nfserr;

	dprintk("nfsd: PATHCONF(3) %s\n",
				SVCFH_fmt(&argp->fh));

	/* Set default pathconf */
	resp->p_link_max = 255;		/* at least */
	resp->p_name_max = 255;		/* at least */
	resp->p_no_trunc = 0;
	resp->p_chown_restricted = 1;
	resp->p_case_insensitive = 0;
	resp->p_case_preserving = 1;

	nfserr = fh_verify(rqstp, &argp->fh, 0, NFSD_MAY_NOP);

	if (nfserr == 0) {
		struct super_block *sb = argp->fh.fh_dentry->d_inode->i_sb;

		/* Note that we don't care for remote fs's here */
		switch (sb->s_magic) {
		case EXT2_SUPER_MAGIC:
			resp->p_link_max = EXT2_LINK_MAX;
			resp->p_name_max = EXT2_NAME_LEN;
			break;
		case MSDOS_SUPER_MAGIC:
			resp->p_case_insensitive = 1;
			resp->p_case_preserving  = 0;
			break;
		}
	}

	fh_put(&argp->fh);
	RETURN_STATUS(nfserr);
}


/*
 * Commit a file (range) to stable storage.
 */
static __be32
nfsd3_proc_commit(struct svc_rqst * rqstp, struct nfsd3_commitargs *argp,
					   struct nfsd3_commitres  *resp)
{
	__be32	nfserr;

	dprintk("nfsd: COMMIT(3)   %s %u@%Lu\n",
				SVCFH_fmt(&argp->fh),
				argp->count,
				(unsigned long long) argp->offset);

	if (argp->offset > NFS_OFFSET_MAX)
		RETURN_STATUS(nfserr_inval);

	fh_copy(&resp->fh, &argp->fh);
	nfserr = nfsd_commit(rqstp, &resp->fh, argp->offset, argp->count);

	RETURN_STATUS(nfserr);
}


/*
 * NFSv3 Server procedures.
 * Only the results of non-idempotent operations are cached.
 */
#define nfs3svc_decode_fhandleargs	nfs3svc_decode_fhandle
#define nfs3svc_encode_attrstatres	nfs3svc_encode_attrstat
#define nfs3svc_encode_wccstatres	nfs3svc_encode_wccstat
#define nfsd3_mkdirargs			nfsd3_createargs
#define nfsd3_readdirplusargs		nfsd3_readdirargs
#define nfsd3_fhandleargs		nfsd_fhandle
#define nfsd3_fhandleres		nfsd3_attrstat
#define nfsd3_attrstatres		nfsd3_attrstat
#define nfsd3_wccstatres		nfsd3_attrstat
#define nfsd3_createres			nfsd3_diropres
#define nfsd3_voidres			nfsd3_voidargs_nfs3proc_c
struct nfsd3_voidargs_nfs3proc_c { int dummy; };

#define PROC(name, argt, rest, relt, cache, respsize)	\
 { (svc_procfunc) nfsd3_proc_##name,		\
   (kxdrproc_t) nfs3svc_decode_##argt##args,	\
   (kxdrproc_t) nfs3svc_encode_##rest##res,	\
   (kxdrproc_t) nfs3svc_release_##relt,		\
   sizeof(struct nfsd3_##argt##args),		\
   sizeof(struct nfsd3_##rest##res),		\
   0,						\
   cache,					\
   respsize,					\
 }

#define ST 1		/* status*/
#define FH 17		/* filehandle with length */
#define AT 21		/* attributes */
#define pAT (1+AT)	/* post attributes - conditional */
#define WC (7+pAT)	/* WCC attributes */

static struct svc_procedure		nfsd_procedures3[22] = {
	[NFS3PROC_NULL] = {
		.pc_func = (svc_procfunc) nfsd3_proc_null,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_voidres,
		.pc_argsize = sizeof(struct nfsd3_voidargs_nfs3proc_c),
		.pc_ressize = sizeof(struct nfsd3_voidres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST,
	},
	[NFS3PROC_GETATTR] = {
		.pc_func = (svc_procfunc) nfsd3_proc_getattr,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_fhandleargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_attrstatres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_attrstatres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+AT,
	},
	[NFS3PROC_SETATTR] = {
		.pc_func = (svc_procfunc) nfsd3_proc_setattr,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_sattrargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_wccstatres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_sattrargs),
		.pc_ressize = sizeof(struct nfsd3_wccstatres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC,
	},
	[NFS3PROC_LOOKUP] = {
		.pc_func = (svc_procfunc) nfsd3_proc_lookup,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_diropargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_diropres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_diropargs),
		.pc_ressize = sizeof(struct nfsd3_diropres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+FH+pAT+pAT,
	},
	[NFS3PROC_ACCESS] = {
		.pc_func = (svc_procfunc) nfsd3_proc_access,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_accessargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_accessres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_accessargs),
		.pc_ressize = sizeof(struct nfsd3_accessres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+1,
	},
	[NFS3PROC_READLINK] = {
		.pc_func = (svc_procfunc) nfsd3_proc_readlink,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_readlinkargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_readlinkres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_readlinkargs),
		.pc_ressize = sizeof(struct nfsd3_readlinkres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+1+NFS3_MAXPATHLEN/4,
	},
	[NFS3PROC_READ] = {
		.pc_func = (svc_procfunc) nfsd3_proc_read,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_readargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_readres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_readargs),
		.pc_ressize = sizeof(struct nfsd3_readres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+4+NFSSVC_MAXBLKSIZE/4,
	},
	[NFS3PROC_WRITE] = {
		.pc_func = (svc_procfunc) nfsd3_proc_write,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_writeargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_writeres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_writeargs),
		.pc_ressize = sizeof(struct nfsd3_writeres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC+4,
	},
	[NFS3PROC_CREATE] = {
		.pc_func = (svc_procfunc) nfsd3_proc_create,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_createargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_createres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_createargs),
		.pc_ressize = sizeof(struct nfsd3_createres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
	},
	[NFS3PROC_MKDIR] = {
		.pc_func = (svc_procfunc) nfsd3_proc_mkdir,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_mkdirargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_createres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_mkdirargs),
		.pc_ressize = sizeof(struct nfsd3_createres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
	},
	[NFS3PROC_SYMLINK] = {
		.pc_func = (svc_procfunc) nfsd3_proc_symlink,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_symlinkargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_createres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_symlinkargs),
		.pc_ressize = sizeof(struct nfsd3_createres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
	},
	[NFS3PROC_MKNOD] = {
		.pc_func = (svc_procfunc) nfsd3_proc_mknod,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_mknodargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_createres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_mknodargs),
		.pc_ressize = sizeof(struct nfsd3_createres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
	},
	[NFS3PROC_REMOVE] = {
		.pc_func = (svc_procfunc) nfsd3_proc_remove,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_diropargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_wccstatres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_diropargs),
		.pc_ressize = sizeof(struct nfsd3_wccstatres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC,
	},
	[NFS3PROC_RMDIR] = {
		.pc_func = (svc_procfunc) nfsd3_proc_rmdir,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_diropargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_wccstatres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_diropargs),
		.pc_ressize = sizeof(struct nfsd3_wccstatres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC,
	},
	[NFS3PROC_RENAME] = {
		.pc_func = (svc_procfunc) nfsd3_proc_rename,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_renameargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_renameres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_renameargs),
		.pc_ressize = sizeof(struct nfsd3_renameres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC+WC,
	},
	[NFS3PROC_LINK] = {
		.pc_func = (svc_procfunc) nfsd3_proc_link,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_linkargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_linkres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_linkargs),
		.pc_ressize = sizeof(struct nfsd3_linkres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+pAT+WC,
	},
	[NFS3PROC_READDIR] = {
		.pc_func = (svc_procfunc) nfsd3_proc_readdir,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_readdirargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_readdirres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_readdirargs),
		.pc_ressize = sizeof(struct nfsd3_readdirres),
		.pc_cachetype = RC_NOCACHE,
	},
	[NFS3PROC_READDIRPLUS] = {
		.pc_func = (svc_procfunc) nfsd3_proc_readdirplus,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_readdirplusargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_readdirres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_readdirplusargs),
		.pc_ressize = sizeof(struct nfsd3_readdirres),
		.pc_cachetype = RC_NOCACHE,
	},
	[NFS3PROC_FSSTAT] = {
		.pc_func = (svc_procfunc) nfsd3_proc_fsstat,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_fhandleargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_fsstatres,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_fsstatres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+2*6+1,
	},
	[NFS3PROC_FSINFO] = {
		.pc_func = (svc_procfunc) nfsd3_proc_fsinfo,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_fhandleargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_fsinfores,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_fsinfores),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+12,
	},
	[NFS3PROC_PATHCONF] = {
		.pc_func = (svc_procfunc) nfsd3_proc_pathconf,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_fhandleargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_pathconfres,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_pathconfres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+6,
	},
	[NFS3PROC_COMMIT] = {
		.pc_func = (svc_procfunc) nfsd3_proc_commit,
		.pc_decode = (kxdrproc_t) nfs3svc_decode_commitargs,
		.pc_encode = (kxdrproc_t) nfs3svc_encode_commitres,
		.pc_release = (kxdrproc_t) nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_commitargs),
		.pc_ressize = sizeof(struct nfsd3_commitres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+WC+2,
	},
};

struct svc_version	nfsd_version3 = {
		.vs_vers	= 3,
		.vs_nproc	= 22,
		.vs_proc	= nfsd_procedures3,
		.vs_dispatch	= nfsd_dispatch,
		.vs_xdrsize	= NFS3_SVC_XDRSIZE,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs3proc.c */
/************************************************************/
/*
 * XDR support for nfsd/protocol version 3.
 *
 * Copyright (C) 1995, 1996, 1997 Olaf Kirch <okir@monad.swb.de>
 *
 * 2003-08-09 Jamie Lokier: Use htonl() for nanoseconds, not htons()!
 */

// #include <linux/namei.h>
// #include <linux/sunrpc/svc_xprt.h>
// #include "xdr3.h"
// #include "auth.h"
// #include "netns.h"
// #include "vfs.h"

#define NFSDDBG_FACILITY		NFSDDBG_XDR


/*
 * Mapping of S_IF* types to NFS file types
 */
static u32	nfs3_ftypes[] = {
	NF3NON,  NF3FIFO, NF3CHR, NF3BAD,
	NF3DIR,  NF3BAD,  NF3BLK, NF3BAD,
	NF3REG,  NF3BAD,  NF3LNK, NF3BAD,
	NF3SOCK, NF3BAD,  NF3LNK, NF3BAD,
};

/*
 * XDR functions for basic NFS types
 */
static __be32 *
encode_time3(__be32 *p, struct timespec *time)
{
	*p++ = htonl((u32) time->tv_sec); *p++ = htonl(time->tv_nsec);
	return p;
}

static __be32 *
decode_time3(__be32 *p, struct timespec *time)
{
	time->tv_sec = ntohl(*p++);
	time->tv_nsec = ntohl(*p++);
	return p;
}

static __be32 *
decode_fh_nfs3xdr_c(__be32 *p, struct svc_fh *fhp)
{
	unsigned int size;
	fh_init(fhp, NFS3_FHSIZE);
	size = ntohl(*p++);
	if (size > NFS3_FHSIZE)
		return NULL;

	memcpy(&fhp->fh_handle.fh_base, p, size);
	fhp->fh_handle.fh_size = size;
	return p + XDR_QUADLEN(size);
}

/* Helper function for NFSv3 ACL code */
__be32 *nfs3svc_decode_fh(__be32 *p, struct svc_fh *fhp)
{
	return decode_fh_nfs3xdr_c(p, fhp);
}

static __be32 *
encode_fh_nfs3xdr_c(__be32 *p, struct svc_fh *fhp)
{
	unsigned int size = fhp->fh_handle.fh_size;
	*p++ = htonl(size);
	if (size) p[XDR_QUADLEN(size)-1]=0;
	memcpy(p, &fhp->fh_handle.fh_base, size);
	return p + XDR_QUADLEN(size);
}

/*
 * Decode a file name and make sure that the path contains
 * no slashes or null bytes.
 */
static __be32 *
decode_filename_nfs3xdr_c(__be32 *p, char **namp, unsigned int *lenp)
{
	char		*name;
	unsigned int	i;

	if ((p = xdr_decode_string_inplace(p, namp, lenp, NFS3_MAXNAMLEN)) != NULL) {
		for (i = 0, name = *namp; i < *lenp; i++, name++) {
			if (*name == '\0' || *name == '/')
				return NULL;
		}
	}

	return p;
}

static __be32 *
decode_sattr3(__be32 *p, struct iattr *iap)
{
	u32	tmp;

	iap->ia_valid = 0;

	if (*p++) {
		iap->ia_valid |= ATTR_MODE;
		iap->ia_mode = ntohl(*p++);
	}
	if (*p++) {
		iap->ia_uid = make_kuid(&init_user_ns, ntohl(*p++));
		if (uid_valid(iap->ia_uid))
			iap->ia_valid |= ATTR_UID;
	}
	if (*p++) {
		iap->ia_gid = make_kgid(&init_user_ns, ntohl(*p++));
		if (gid_valid(iap->ia_gid))
			iap->ia_valid |= ATTR_GID;
	}
	if (*p++) {
		u64	newsize;

		iap->ia_valid |= ATTR_SIZE;
		p = xdr_decode_hyper(p, &newsize);
		iap->ia_size = min_t(u64, newsize, NFS_OFFSET_MAX);
	}
	if ((tmp = ntohl(*p++)) == 1) {	/* set to server time */
		iap->ia_valid |= ATTR_ATIME;
	} else if (tmp == 2) {		/* set to client time */
		iap->ia_valid |= ATTR_ATIME | ATTR_ATIME_SET;
		iap->ia_atime.tv_sec = ntohl(*p++);
		iap->ia_atime.tv_nsec = ntohl(*p++);
	}
	if ((tmp = ntohl(*p++)) == 1) {	/* set to server time */
		iap->ia_valid |= ATTR_MTIME;
	} else if (tmp == 2) {		/* set to client time */
		iap->ia_valid |= ATTR_MTIME | ATTR_MTIME_SET;
		iap->ia_mtime.tv_sec = ntohl(*p++);
		iap->ia_mtime.tv_nsec = ntohl(*p++);
	}
	return p;
}

static __be32 *encode_fsid(__be32 *p, struct svc_fh *fhp)
{
	u64 f;
	switch(fsid_source(fhp)) {
	default:
	case FSIDSOURCE_DEV:
		p = xdr_encode_hyper(p, (u64)huge_encode_dev
				     (fhp->fh_dentry->d_inode->i_sb->s_dev));
		break;
	case FSIDSOURCE_FSID:
		p = xdr_encode_hyper(p, (u64) fhp->fh_export->ex_fsid);
		break;
	case FSIDSOURCE_UUID:
		f = ((u64*)fhp->fh_export->ex_uuid)[0];
		f ^= ((u64*)fhp->fh_export->ex_uuid)[1];
		p = xdr_encode_hyper(p, f);
		break;
	}
	return p;
}

static __be32 *
encode_fattr3(struct svc_rqst *rqstp, __be32 *p, struct svc_fh *fhp,
	      struct kstat *stat)
{
	*p++ = htonl(nfs3_ftypes[(stat->mode & S_IFMT) >> 12]);
	*p++ = htonl((u32) (stat->mode & S_IALLUGO));
	*p++ = htonl((u32) stat->nlink);
	*p++ = htonl((u32) from_kuid(&init_user_ns, stat->uid));
	*p++ = htonl((u32) from_kgid(&init_user_ns, stat->gid));
	if (S_ISLNK(stat->mode) && stat->size > NFS3_MAXPATHLEN) {
		p = xdr_encode_hyper(p, (u64) NFS3_MAXPATHLEN);
	} else {
		p = xdr_encode_hyper(p, (u64) stat->size);
	}
	p = xdr_encode_hyper(p, ((u64)stat->blocks) << 9);
	*p++ = htonl((u32) MAJOR(stat->rdev));
	*p++ = htonl((u32) MINOR(stat->rdev));
	p = encode_fsid(p, fhp);
	p = xdr_encode_hyper(p, stat->ino);
	p = encode_time3(p, &stat->atime);
	p = encode_time3(p, &stat->mtime);
	p = encode_time3(p, &stat->ctime);

	return p;
}

static __be32 *
encode_saved_post_attr(struct svc_rqst *rqstp, __be32 *p, struct svc_fh *fhp)
{
	/* Attributes to follow */
	*p++ = xdr_one;
	return encode_fattr3(rqstp, p, fhp, &fhp->fh_post_attr);
}

/*
 * Encode post-operation attributes.
 * The inode may be NULL if the call failed because of a stale file
 * handle. In this case, no attributes are returned.
 */
static __be32 *
encode_post_op_attr(struct svc_rqst *rqstp, __be32 *p, struct svc_fh *fhp)
{
	struct dentry *dentry = fhp->fh_dentry;
	if (dentry && dentry->d_inode) {
	        __be32 err;
		struct kstat stat;

		err = fh_getattr(fhp, &stat);
		if (!err) {
			*p++ = xdr_one;		/* attributes follow */
			lease_get_mtime(dentry->d_inode, &stat.mtime);
			return encode_fattr3(rqstp, p, fhp, &stat);
		}
	}
	*p++ = xdr_zero;
	return p;
}

/* Helper for NFSv3 ACLs */
__be32 *
nfs3svc_encode_post_op_attr(struct svc_rqst *rqstp, __be32 *p, struct svc_fh *fhp)
{
	return encode_post_op_attr(rqstp, p, fhp);
}

/*
 * Enocde weak cache consistency data
 */
static __be32 *
encode_wcc_data(struct svc_rqst *rqstp, __be32 *p, struct svc_fh *fhp)
{
	struct dentry	*dentry = fhp->fh_dentry;

	if (dentry && dentry->d_inode && fhp->fh_post_saved) {
		if (fhp->fh_pre_saved) {
			*p++ = xdr_one;
			p = xdr_encode_hyper(p, (u64) fhp->fh_pre_size);
			p = encode_time3(p, &fhp->fh_pre_mtime);
			p = encode_time3(p, &fhp->fh_pre_ctime);
		} else {
			*p++ = xdr_zero;
		}
		return encode_saved_post_attr(rqstp, p, fhp);
	}
	/* no pre- or post-attrs */
	*p++ = xdr_zero;
	return encode_post_op_attr(rqstp, p, fhp);
}

/*
 * Fill in the post_op attr for the wcc data
 */
void fill_post_wcc(struct svc_fh *fhp)
{
	__be32 err;

	if (fhp->fh_post_saved)
		printk("nfsd: inode locked twice during operation.\n");

	err = fh_getattr(fhp, &fhp->fh_post_attr);
	fhp->fh_post_change = fhp->fh_dentry->d_inode->i_version;
	if (err) {
		fhp->fh_post_saved = 0;
		/* Grab the ctime anyway - set_change_info might use it */
		fhp->fh_post_attr.ctime = fhp->fh_dentry->d_inode->i_ctime;
	} else
		fhp->fh_post_saved = 1;
}

/*
 * XDR decode functions
 */
int
nfs3svc_decode_fhandle(struct svc_rqst *rqstp, __be32 *p, struct nfsd_fhandle *args)
{
	p = decode_fh_nfs3xdr_c(p, &args->fh);
	if (!p)
		return 0;
	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_sattrargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_sattrargs *args)
{
	p = decode_fh_nfs3xdr_c(p, &args->fh);
	if (!p)
		return 0;
	p = decode_sattr3(p, &args->attrs);

	if ((args->check_guard = ntohl(*p++)) != 0) { 
		struct timespec time; 
		p = decode_time3(p, &time);
		args->guardtime = time.tv_sec;
	}

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_diropargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_diropargs *args)
{
	if (!(p = decode_fh_nfs3xdr_c(p, &args->fh))
	 || !(p = decode_filename_nfs3xdr_c(p, &args->name, &args->len)))
		return 0;

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_accessargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_accessargs *args)
{
	p = decode_fh_nfs3xdr_c(p, &args->fh);
	if (!p)
		return 0;
	args->access = ntohl(*p++);

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_readargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readargs *args)
{
	unsigned int len;
	int v;
	u32 max_blocksize = svc_max_payload(rqstp);

	p = decode_fh_nfs3xdr_c(p, &args->fh);
	if (!p)
		return 0;
	p = xdr_decode_hyper(p, &args->offset);

	args->count = ntohl(*p++);
	len = min(args->count, max_blocksize);

	/* set up the kvec */
	v=0;
	while (len > 0) {
		struct page *p = *(rqstp->rq_next_page++);

		rqstp->rq_vec[v].iov_base = page_address(p);
		rqstp->rq_vec[v].iov_len = min_t(unsigned int, len, PAGE_SIZE);
		len -= rqstp->rq_vec[v].iov_len;
		v++;
	}
	args->vlen = v;
	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_writeargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_writeargs *args)
{
	unsigned int len, v, hdr, dlen;
	u32 max_blocksize = svc_max_payload(rqstp);

	p = decode_fh_nfs3xdr_c(p, &args->fh);
	if (!p)
		return 0;
	p = xdr_decode_hyper(p, &args->offset);

	args->count = ntohl(*p++);
	args->stable = ntohl(*p++);
	len = args->len = ntohl(*p++);
	/*
	 * The count must equal the amount of data passed.
	 */
	if (args->count != args->len)
		return 0;

	/*
	 * Check to make sure that we got the right number of
	 * bytes.
	 */
	hdr = (void*)p - rqstp->rq_arg.head[0].iov_base;
	dlen = rqstp->rq_arg.head[0].iov_len + rqstp->rq_arg.page_len
		- hdr;
	/*
	 * Round the length of the data which was specified up to
	 * the next multiple of XDR units and then compare that
	 * against the length which was actually received.
	 * Note that when RPCSEC/GSS (for example) is used, the
	 * data buffer can be padded so dlen might be larger
	 * than required.  It must never be smaller.
	 */
	if (dlen < XDR_QUADLEN(len)*4)
		return 0;

	if (args->count > max_blocksize) {
		args->count = max_blocksize;
		len = args->len = max_blocksize;
	}
	rqstp->rq_vec[0].iov_base = (void*)p;
	rqstp->rq_vec[0].iov_len = rqstp->rq_arg.head[0].iov_len - hdr;
	v = 0;
	while (len > rqstp->rq_vec[v].iov_len) {
		len -= rqstp->rq_vec[v].iov_len;
		v++;
		rqstp->rq_vec[v].iov_base = page_address(rqstp->rq_pages[v]);
		rqstp->rq_vec[v].iov_len = PAGE_SIZE;
	}
	rqstp->rq_vec[v].iov_len = len;
	args->vlen = v + 1;
	return 1;
}

int
nfs3svc_decode_createargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_createargs *args)
{
	if (!(p = decode_fh_nfs3xdr_c(p, &args->fh))
	 || !(p = decode_filename_nfs3xdr_c(p, &args->name, &args->len)))
		return 0;

	switch (args->createmode = ntohl(*p++)) {
	case NFS3_CREATE_UNCHECKED:
	case NFS3_CREATE_GUARDED:
		p = decode_sattr3(p, &args->attrs);
		break;
	case NFS3_CREATE_EXCLUSIVE:
		args->verf = p;
		p += 2;
		break;
	default:
		return 0;
	}

	return xdr_argsize_check(rqstp, p);
}
int
nfs3svc_decode_mkdirargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_createargs *args)
{
	if (!(p = decode_fh_nfs3xdr_c(p, &args->fh)) ||
	    !(p = decode_filename_nfs3xdr_c(p, &args->name, &args->len)))
		return 0;
	p = decode_sattr3(p, &args->attrs);

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_symlinkargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_symlinkargs *args)
{
	unsigned int len, avail;
	char *old, *new;
	struct kvec *vec;

	if (!(p = decode_fh_nfs3xdr_c(p, &args->ffh)) ||
	    !(p = decode_filename_nfs3xdr_c(p, &args->fname, &args->flen))
		)
		return 0;
	p = decode_sattr3(p, &args->attrs);

	/* now decode the pathname, which might be larger than the first page.
	 * As we have to check for nul's anyway, we copy it into a new page
	 * This page appears in the rq_res.pages list, but as pages_len is always
	 * 0, it won't get in the way
	 */
	len = ntohl(*p++);
	if (len == 0 || len > NFS3_MAXPATHLEN || len >= PAGE_SIZE)
		return 0;
	args->tname = new = page_address(*(rqstp->rq_next_page++));
	args->tlen = len;
	/* first copy and check from the first page */
	old = (char*)p;
	vec = &rqstp->rq_arg.head[0];
	avail = vec->iov_len - (old - (char*)vec->iov_base);
	while (len && avail && *old) {
		*new++ = *old++;
		len--;
		avail--;
	}
	/* now copy next page if there is one */
	if (len && !avail && rqstp->rq_arg.page_len) {
		avail = min_t(unsigned int, rqstp->rq_arg.page_len, PAGE_SIZE);
		old = page_address(rqstp->rq_arg.pages[0]);
	}
	while (len && avail && *old) {
		*new++ = *old++;
		len--;
		avail--;
	}
	*new = '\0';
	if (len)
		return 0;

	return 1;
}

int
nfs3svc_decode_mknodargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_mknodargs *args)
{
	if (!(p = decode_fh_nfs3xdr_c(p, &args->fh))
	 || !(p = decode_filename_nfs3xdr_c(p, &args->name, &args->len)))
		return 0;

	args->ftype = ntohl(*p++);

	if (args->ftype == NF3BLK  || args->ftype == NF3CHR
	 || args->ftype == NF3SOCK || args->ftype == NF3FIFO)
		p = decode_sattr3(p, &args->attrs);

	if (args->ftype == NF3BLK || args->ftype == NF3CHR) {
		args->major = ntohl(*p++);
		args->minor = ntohl(*p++);
	}

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_renameargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_renameargs *args)
{
	if (!(p = decode_fh_nfs3xdr_c(p, &args->ffh))
	 || !(p = decode_filename_nfs3xdr_c(p, &args->fname, &args->flen))
	 || !(p = decode_fh_nfs3xdr_c(p, &args->tfh))
	 || !(p = decode_filename_nfs3xdr_c(p, &args->tname, &args->tlen)))
		return 0;

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_readlinkargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readlinkargs *args)
{
	p = decode_fh_nfs3xdr_c(p, &args->fh);
	if (!p)
		return 0;
	args->buffer = page_address(*(rqstp->rq_next_page++));

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_linkargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_linkargs *args)
{
	if (!(p = decode_fh_nfs3xdr_c(p, &args->ffh))
	 || !(p = decode_fh_nfs3xdr_c(p, &args->tfh))
	 || !(p = decode_filename_nfs3xdr_c(p, &args->tname, &args->tlen)))
		return 0;

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_readdirargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readdirargs *args)
{
	p = decode_fh_nfs3xdr_c(p, &args->fh);
	if (!p)
		return 0;
	p = xdr_decode_hyper(p, &args->cookie);
	args->verf   = p; p += 2;
	args->dircount = ~0;
	args->count  = ntohl(*p++);
	args->count  = min_t(u32, args->count, PAGE_SIZE);
	args->buffer = page_address(*(rqstp->rq_next_page++));

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_readdirplusargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readdirargs *args)
{
	int len;
	u32 max_blocksize = svc_max_payload(rqstp);

	p = decode_fh_nfs3xdr_c(p, &args->fh);
	if (!p)
		return 0;
	p = xdr_decode_hyper(p, &args->cookie);
	args->verf     = p; p += 2;
	args->dircount = ntohl(*p++);
	args->count    = ntohl(*p++);

	len = args->count = min(args->count, max_blocksize);
	while (len > 0) {
		struct page *p = *(rqstp->rq_next_page++);
		if (!args->buffer)
			args->buffer = page_address(p);
		len -= PAGE_SIZE;
	}

	return xdr_argsize_check(rqstp, p);
}

int
nfs3svc_decode_commitargs(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_commitargs *args)
{
	p = decode_fh_nfs3xdr_c(p, &args->fh);
	if (!p)
		return 0;
	p = xdr_decode_hyper(p, &args->offset);
	args->count = ntohl(*p++);

	return xdr_argsize_check(rqstp, p);
}

/*
 * XDR encode functions
 */
/*
 * There must be an encoding function for void results so svc_process
 * will work properly.
 */
int
nfs3svc_encode_voidres(struct svc_rqst *rqstp, __be32 *p, void *dummy)
{
	return xdr_ressize_check(rqstp, p);
}

/* GETATTR */
int
nfs3svc_encode_attrstat(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_attrstat *resp)
{
	if (resp->status == 0) {
		lease_get_mtime(resp->fh.fh_dentry->d_inode,
				&resp->stat.mtime);
		p = encode_fattr3(rqstp, p, &resp->fh, &resp->stat);
	}
	return xdr_ressize_check(rqstp, p);
}

/* SETATTR, REMOVE, RMDIR */
int
nfs3svc_encode_wccstat(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_attrstat *resp)
{
	p = encode_wcc_data(rqstp, p, &resp->fh);
	return xdr_ressize_check(rqstp, p);
}

/* LOOKUP */
int
nfs3svc_encode_diropres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_diropres *resp)
{
	if (resp->status == 0) {
		p = encode_fh_nfs3xdr_c(p, &resp->fh);
		p = encode_post_op_attr(rqstp, p, &resp->fh);
	}
	p = encode_post_op_attr(rqstp, p, &resp->dirfh);
	return xdr_ressize_check(rqstp, p);
}

/* ACCESS */
int
nfs3svc_encode_accessres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_accessres *resp)
{
	p = encode_post_op_attr(rqstp, p, &resp->fh);
	if (resp->status == 0)
		*p++ = htonl(resp->access);
	return xdr_ressize_check(rqstp, p);
}

/* READLINK */
int
nfs3svc_encode_readlinkres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readlinkres *resp)
{
	p = encode_post_op_attr(rqstp, p, &resp->fh);
	if (resp->status == 0) {
		*p++ = htonl(resp->len);
		xdr_ressize_check(rqstp, p);
		rqstp->rq_res.page_len = resp->len;
		if (resp->len & 3) {
			/* need to pad the tail */
			rqstp->rq_res.tail[0].iov_base = p;
			*p = 0;
			rqstp->rq_res.tail[0].iov_len = 4 - (resp->len&3);
		}
		return 1;
	} else
		return xdr_ressize_check(rqstp, p);
}

/* READ */
int
nfs3svc_encode_readres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readres *resp)
{
	p = encode_post_op_attr(rqstp, p, &resp->fh);
	if (resp->status == 0) {
		*p++ = htonl(resp->count);
		*p++ = htonl(resp->eof);
		*p++ = htonl(resp->count);	/* xdr opaque count */
		xdr_ressize_check(rqstp, p);
		/* now update rqstp->rq_res to reflect data as well */
		rqstp->rq_res.page_len = resp->count;
		if (resp->count & 3) {
			/* need to pad the tail */
			rqstp->rq_res.tail[0].iov_base = p;
			*p = 0;
			rqstp->rq_res.tail[0].iov_len = 4 - (resp->count & 3);
		}
		return 1;
	} else
		return xdr_ressize_check(rqstp, p);
}

/* WRITE */
int
nfs3svc_encode_writeres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_writeres *resp)
{
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	p = encode_wcc_data(rqstp, p, &resp->fh);
	if (resp->status == 0) {
		*p++ = htonl(resp->count);
		*p++ = htonl(resp->committed);
		*p++ = htonl(nn->nfssvc_boot.tv_sec);
		*p++ = htonl(nn->nfssvc_boot.tv_usec);
	}
	return xdr_ressize_check(rqstp, p);
}

/* CREATE, MKDIR, SYMLINK, MKNOD */
int
nfs3svc_encode_createres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_diropres *resp)
{
	if (resp->status == 0) {
		*p++ = xdr_one;
		p = encode_fh_nfs3xdr_c(p, &resp->fh);
		p = encode_post_op_attr(rqstp, p, &resp->fh);
	}
	p = encode_wcc_data(rqstp, p, &resp->dirfh);
	return xdr_ressize_check(rqstp, p);
}

/* RENAME */
int
nfs3svc_encode_renameres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_renameres *resp)
{
	p = encode_wcc_data(rqstp, p, &resp->ffh);
	p = encode_wcc_data(rqstp, p, &resp->tfh);
	return xdr_ressize_check(rqstp, p);
}

/* LINK */
int
nfs3svc_encode_linkres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_linkres *resp)
{
	p = encode_post_op_attr(rqstp, p, &resp->fh);
	p = encode_wcc_data(rqstp, p, &resp->tfh);
	return xdr_ressize_check(rqstp, p);
}

/* READDIR */
int
nfs3svc_encode_readdirres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_readdirres *resp)
{
	p = encode_post_op_attr(rqstp, p, &resp->fh);

	if (resp->status == 0) {
		/* stupid readdir cookie */
		memcpy(p, resp->verf, 8); p += 2;
		xdr_ressize_check(rqstp, p);
		if (rqstp->rq_res.head[0].iov_len + (2<<2) > PAGE_SIZE)
			return 1; /*No room for trailer */
		rqstp->rq_res.page_len = (resp->count) << 2;

		/* add the 'tail' to the end of the 'head' page - page 0. */
		rqstp->rq_res.tail[0].iov_base = p;
		*p++ = 0;		/* no more entries */
		*p++ = htonl(resp->common.err == nfserr_eof);
		rqstp->rq_res.tail[0].iov_len = 2<<2;
		return 1;
	} else
		return xdr_ressize_check(rqstp, p);
}

static __be32 *
encode_entry_baggage(struct nfsd3_readdirres *cd, __be32 *p, const char *name,
	     int namlen, u64 ino)
{
	*p++ = xdr_one;				 /* mark entry present */
	p    = xdr_encode_hyper(p, ino);	 /* file id */
	p    = xdr_encode_array(p, name, namlen);/* name length & name */

	cd->offset = p;				/* remember pointer */
	p = xdr_encode_hyper(p, NFS_OFFSET_MAX);/* offset of next entry */

	return p;
}

static __be32
compose_entry_fh(struct nfsd3_readdirres *cd, struct svc_fh *fhp,
		const char *name, int namlen)
{
	struct svc_export	*exp;
	struct dentry		*dparent, *dchild;
	__be32 rv = nfserr_noent;

	dparent = cd->fh.fh_dentry;
	exp  = cd->fh.fh_export;

	if (isdotent(name, namlen)) {
		if (namlen == 2) {
			dchild = dget_parent(dparent);
			/* filesystem root - cannot return filehandle for ".." */
			if (dchild == dparent)
				goto out;
		} else
			dchild = dget(dparent);
	} else
		dchild = lookup_one_len(name, dparent, namlen);
	if (IS_ERR(dchild))
		return rv;
	if (d_mountpoint(dchild))
		goto out;
	if (!dchild->d_inode)
		goto out;
	rv = fh_compose(fhp, exp, dchild, &cd->fh);
out:
	dput(dchild);
	return rv;
}

static __be32 *encode_entryplus_baggage(struct nfsd3_readdirres *cd, __be32 *p, const char *name, int namlen)
{
	struct svc_fh	*fh = &cd->scratch;
	__be32 err;

	fh_init(fh, NFS3_FHSIZE);
	err = compose_entry_fh(cd, fh, name, namlen);
	if (err) {
		*p++ = 0;
		*p++ = 0;
		goto out;
	}
	p = encode_post_op_attr(cd->rqstp, p, fh);
	*p++ = xdr_one;			/* yes, a file handle follows */
	p = encode_fh_nfs3xdr_c(p, fh);
out:
	fh_put(fh);
	return p;
}

/*
 * Encode a directory entry. This one works for both normal readdir
 * and readdirplus.
 * The normal readdir reply requires 2 (fileid) + 1 (stringlen)
 * + string + 2 (cookie) + 1 (next) words, i.e. 6 + strlen.
 * 
 * The readdirplus baggage is 1+21 words for post_op_attr, plus the
 * file handle.
 */

#define NFS3_ENTRY_BAGGAGE	(2 + 1 + 2 + 1)
#define NFS3_ENTRYPLUS_BAGGAGE	(1 + 21 + 1 + (NFS3_FHSIZE >> 2))
static int
encode_entry(struct readdir_cd *ccd, const char *name, int namlen,
	     loff_t offset, u64 ino, unsigned int d_type, int plus)
{
	struct nfsd3_readdirres *cd = container_of(ccd, struct nfsd3_readdirres,
		       					common);
	__be32		*p = cd->buffer;
	caddr_t		curr_page_addr = NULL;
	struct page **	page;
	int		slen;		/* string (name) length */
	int		elen;		/* estimated entry length in words */
	int		num_entry_words = 0;	/* actual number of words */

	if (cd->offset) {
		u64 offset64 = offset;

		if (unlikely(cd->offset1)) {
			/* we ended up with offset on a page boundary */
			*cd->offset = htonl(offset64 >> 32);
			*cd->offset1 = htonl(offset64 & 0xffffffff);
			cd->offset1 = NULL;
		} else {
			xdr_encode_hyper(cd->offset, offset64);
		}
	}

	/*
	dprintk("encode_entry(%.*s @%ld%s)\n",
		namlen, name, (long) offset, plus? " plus" : "");
	 */

	/* truncate filename if too long */
	namlen = min(namlen, NFS3_MAXNAMLEN);

	slen = XDR_QUADLEN(namlen);
	elen = slen + NFS3_ENTRY_BAGGAGE
		+ (plus? NFS3_ENTRYPLUS_BAGGAGE : 0);

	if (cd->buflen < elen) {
		cd->common.err = nfserr_toosmall;
		return -EINVAL;
	}

	/* determine which page in rq_respages[] we are currently filling */
	for (page = cd->rqstp->rq_respages + 1;
				page < cd->rqstp->rq_next_page; page++) {
		curr_page_addr = page_address(*page);

		if (((caddr_t)cd->buffer >= curr_page_addr) &&
		    ((caddr_t)cd->buffer <  curr_page_addr + PAGE_SIZE))
			break;
	}

	if ((caddr_t)(cd->buffer + elen) < (curr_page_addr + PAGE_SIZE)) {
		/* encode entry in current page */

		p = encode_entry_baggage(cd, p, name, namlen, ino);

		if (plus)
			p = encode_entryplus_baggage(cd, p, name, namlen);
		num_entry_words = p - cd->buffer;
	} else if (*(page+1) != NULL) {
		/* temporarily encode entry into next page, then move back to
		 * current and next page in rq_respages[] */
		__be32 *p1, *tmp;
		int len1, len2;

		/* grab next page for temporary storage of entry */
		p1 = tmp = page_address(*(page+1));

		p1 = encode_entry_baggage(cd, p1, name, namlen, ino);

		if (plus)
			p1 = encode_entryplus_baggage(cd, p1, name, namlen);

		/* determine entry word length and lengths to go in pages */
		num_entry_words = p1 - tmp;
		len1 = curr_page_addr + PAGE_SIZE - (caddr_t)cd->buffer;
		if ((num_entry_words << 2) < len1) {
			/* the actual number of words in the entry is less
			 * than elen and can still fit in the current page
			 */
			memmove(p, tmp, num_entry_words << 2);
			p += num_entry_words;

			/* update offset */
			cd->offset = cd->buffer + (cd->offset - tmp);
		} else {
			unsigned int offset_r = (cd->offset - tmp) << 2;

			/* update pointer to offset location.
			 * This is a 64bit quantity, so we need to
			 * deal with 3 cases:
			 *  -	entirely in first page
			 *  -	entirely in second page
			 *  -	4 bytes in each page
			 */
			if (offset_r + 8 <= len1) {
				cd->offset = p + (cd->offset - tmp);
			} else if (offset_r >= len1) {
				cd->offset -= len1 >> 2;
			} else {
				/* sitting on the fence */
				BUG_ON(offset_r != len1 - 4);
				cd->offset = p + (cd->offset - tmp);
				cd->offset1 = tmp;
			}

			len2 = (num_entry_words << 2) - len1;

			/* move from temp page to current and next pages */
			memmove(p, tmp, len1);
			memmove(tmp, (caddr_t)tmp+len1, len2);

			p = tmp + (len2 >> 2);
		}
	}
	else {
		cd->common.err = nfserr_toosmall;
		return -EINVAL;
	}

	cd->buflen -= num_entry_words;
	cd->buffer = p;
	cd->common.err = nfs_ok;
	return 0;

}

int
nfs3svc_encode_entry(void *cd, const char *name,
		     int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	return encode_entry(cd, name, namlen, offset, ino, d_type, 0);
}

int
nfs3svc_encode_entry_plus(void *cd, const char *name,
			  int namlen, loff_t offset, u64 ino,
			  unsigned int d_type)
{
	return encode_entry(cd, name, namlen, offset, ino, d_type, 1);
}

/* FSSTAT */
int
nfs3svc_encode_fsstatres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_fsstatres *resp)
{
	struct kstatfs	*s = &resp->stats;
	u64		bs = s->f_bsize;

	*p++ = xdr_zero;	/* no post_op_attr */

	if (resp->status == 0) {
		p = xdr_encode_hyper(p, bs * s->f_blocks);	/* total bytes */
		p = xdr_encode_hyper(p, bs * s->f_bfree);	/* free bytes */
		p = xdr_encode_hyper(p, bs * s->f_bavail);	/* user available bytes */
		p = xdr_encode_hyper(p, s->f_files);	/* total inodes */
		p = xdr_encode_hyper(p, s->f_ffree);	/* free inodes */
		p = xdr_encode_hyper(p, s->f_ffree);	/* user available inodes */
		*p++ = htonl(resp->invarsec);	/* mean unchanged time */
	}
	return xdr_ressize_check(rqstp, p);
}

/* FSINFO */
int
nfs3svc_encode_fsinfores(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_fsinfores *resp)
{
	*p++ = xdr_zero;	/* no post_op_attr */

	if (resp->status == 0) {
		*p++ = htonl(resp->f_rtmax);
		*p++ = htonl(resp->f_rtpref);
		*p++ = htonl(resp->f_rtmult);
		*p++ = htonl(resp->f_wtmax);
		*p++ = htonl(resp->f_wtpref);
		*p++ = htonl(resp->f_wtmult);
		*p++ = htonl(resp->f_dtpref);
		p = xdr_encode_hyper(p, resp->f_maxfilesize);
		*p++ = xdr_one;
		*p++ = xdr_zero;
		*p++ = htonl(resp->f_properties);
	}

	return xdr_ressize_check(rqstp, p);
}

/* PATHCONF */
int
nfs3svc_encode_pathconfres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_pathconfres *resp)
{
	*p++ = xdr_zero;	/* no post_op_attr */

	if (resp->status == 0) {
		*p++ = htonl(resp->p_link_max);
		*p++ = htonl(resp->p_name_max);
		*p++ = htonl(resp->p_no_trunc);
		*p++ = htonl(resp->p_chown_restricted);
		*p++ = htonl(resp->p_case_insensitive);
		*p++ = htonl(resp->p_case_preserving);
	}

	return xdr_ressize_check(rqstp, p);
}

/* COMMIT */
int
nfs3svc_encode_commitres(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_commitres *resp)
{
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	p = encode_wcc_data(rqstp, p, &resp->fh);
	/* Write verifier */
	if (resp->status == 0) {
		*p++ = htonl(nn->nfssvc_boot.tv_sec);
		*p++ = htonl(nn->nfssvc_boot.tv_usec);
	}
	return xdr_ressize_check(rqstp, p);
}

/*
 * XDR release functions
 */
int
nfs3svc_release_fhandle(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_attrstat *resp)
{
	fh_put(&resp->fh);
	return 1;
}

int
nfs3svc_release_fhandle2(struct svc_rqst *rqstp, __be32 *p,
					struct nfsd3_fhandle_pair *resp)
{
	fh_put(&resp->fh1);
	fh_put(&resp->fh2);
	return 1;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs3xdr.c */
/************************************************************/
/*
 * Process version 3 NFSACL requests.
 *
 * Copyright (C) 2002-2003 Andreas Gruenbacher <agruen@suse.de>
 */

// #include "nfsd.h"
/* FIXME: nfsacl.h is a broken header */
// #include <linux/nfsacl.h>
// #include <linux/gfp.h>
// #include "cache.h"
// #include "xdr3.h"
// #include "vfs.h"

#define RETURN_STATUS(st)	{ resp->status = (st); return (st); }

/*
 * NULL call.
 */
static __be32
nfsd3_proc_null_nfs3acl_c(struct svc_rqst *rqstp, void *argp, void *resp)
{
	return nfs_ok;
}

/*
 * Get the Access and/or Default ACL of a file.
 */
static __be32 nfsd3_proc_getacl(struct svc_rqst * rqstp,
		struct nfsd3_getaclargs *argp, struct nfsd3_getaclres *resp)
{
	struct posix_acl *acl;
	struct inode *inode;
	svc_fh *fh;
	__be32 nfserr = 0;

	fh = fh_copy(&resp->fh, &argp->fh);
	nfserr = fh_verify(rqstp, &resp->fh, 0, NFSD_MAY_NOP);
	if (nfserr)
		RETURN_STATUS(nfserr);

	inode = fh->fh_dentry->d_inode;

	if (argp->mask & ~(NFS_ACL|NFS_ACLCNT|NFS_DFACL|NFS_DFACLCNT))
		RETURN_STATUS(nfserr_inval);
	resp->mask = argp->mask;

	if (resp->mask & (NFS_ACL|NFS_ACLCNT)) {
		acl = get_acl(inode, ACL_TYPE_ACCESS);
		if (acl == NULL) {
			/* Solaris returns the inode's minimum ACL. */
			acl = posix_acl_from_mode(inode->i_mode, GFP_KERNEL);
		}
		if (IS_ERR(acl)) {
			nfserr = nfserrno(PTR_ERR(acl));
			goto fail;
		}
		resp->acl_access = acl;
	}
	if (resp->mask & (NFS_DFACL|NFS_DFACLCNT)) {
		/* Check how Solaris handles requests for the Default ACL
		   of a non-directory! */
		acl = get_acl(inode, ACL_TYPE_DEFAULT);
		if (IS_ERR(acl)) {
			nfserr = nfserrno(PTR_ERR(acl));
			goto fail;
		}
		resp->acl_default = acl;
	}

	/* resp->acl_{access,default} are released in nfs3svc_release_getacl. */
	RETURN_STATUS(0);

fail:
	posix_acl_release(resp->acl_access);
	posix_acl_release(resp->acl_default);
	RETURN_STATUS(nfserr);
}

/*
 * Set the Access and/or Default ACL of a file.
 */
static __be32 nfsd3_proc_setacl(struct svc_rqst * rqstp,
		struct nfsd3_setaclargs *argp,
		struct nfsd3_attrstat *resp)
{
	struct inode *inode;
	svc_fh *fh;
	__be32 nfserr = 0;
	int error;

	fh = fh_copy(&resp->fh, &argp->fh);
	nfserr = fh_verify(rqstp, &resp->fh, 0, NFSD_MAY_SATTR);
	if (nfserr)
		goto out;

	inode = fh->fh_dentry->d_inode;
	if (!IS_POSIXACL(inode) || !inode->i_op->set_acl) {
		error = -EOPNOTSUPP;
		goto out_errno;
	}

	error = fh_want_write(fh);
	if (error)
		goto out_errno;

	error = inode->i_op->set_acl(inode, argp->acl_access, ACL_TYPE_ACCESS);
	if (error)
		goto out_drop_write;
	error = inode->i_op->set_acl(inode, argp->acl_default,
				     ACL_TYPE_DEFAULT);

out_drop_write:
	fh_drop_write(fh);
out_errno:
	nfserr = nfserrno(error);
out:
	/* argp->acl_{access,default} may have been allocated in
	   nfs3svc_decode_setaclargs. */
	posix_acl_release(argp->acl_access);
	posix_acl_release(argp->acl_default);
	RETURN_STATUS(nfserr);
}

/*
 * XDR decode functions
 */
static int nfs3svc_decode_getaclargs(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_getaclargs *args)
{
	p = nfs3svc_decode_fh(p, &args->fh);
	if (!p)
		return 0;
	args->mask = ntohl(*p); p++;

	return xdr_argsize_check(rqstp, p);
}


static int nfs3svc_decode_setaclargs(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_setaclargs *args)
{
	struct kvec *head = rqstp->rq_arg.head;
	unsigned int base;
	int n;

	p = nfs3svc_decode_fh(p, &args->fh);
	if (!p)
		return 0;
	args->mask = ntohl(*p++);
	if (args->mask & ~(NFS_ACL|NFS_ACLCNT|NFS_DFACL|NFS_DFACLCNT) ||
	    !xdr_argsize_check(rqstp, p))
		return 0;

	base = (char *)p - (char *)head->iov_base;
	n = nfsacl_decode(&rqstp->rq_arg, base, NULL,
			  (args->mask & NFS_ACL) ?
			  &args->acl_access : NULL);
	if (n > 0)
		n = nfsacl_decode(&rqstp->rq_arg, base + n, NULL,
				  (args->mask & NFS_DFACL) ?
				  &args->acl_default : NULL);
	return (n > 0);
}

/*
 * XDR encode functions
 */

/* GETACL */
static int nfs3svc_encode_getaclres(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_getaclres *resp)
{
	struct dentry *dentry = resp->fh.fh_dentry;

	p = nfs3svc_encode_post_op_attr(rqstp, p, &resp->fh);
	if (resp->status == 0 && dentry && dentry->d_inode) {
		struct inode *inode = dentry->d_inode;
		struct kvec *head = rqstp->rq_res.head;
		unsigned int base;
		int n;
		int w;

		*p++ = htonl(resp->mask);
		if (!xdr_ressize_check(rqstp, p))
			return 0;
		base = (char *)p - (char *)head->iov_base;

		rqstp->rq_res.page_len = w = nfsacl_size(
			(resp->mask & NFS_ACL)   ? resp->acl_access  : NULL,
			(resp->mask & NFS_DFACL) ? resp->acl_default : NULL);
		while (w > 0) {
			if (!*(rqstp->rq_next_page++))
				return 0;
			w -= PAGE_SIZE;
		}

		n = nfsacl_encode(&rqstp->rq_res, base, inode,
				  resp->acl_access,
				  resp->mask & NFS_ACL, 0);
		if (n > 0)
			n = nfsacl_encode(&rqstp->rq_res, base + n, inode,
					  resp->acl_default,
					  resp->mask & NFS_DFACL,
					  NFS_ACL_DEFAULT);
		if (n <= 0)
			return 0;
	} else
		if (!xdr_ressize_check(rqstp, p))
			return 0;

	return 1;
}

/* SETACL */
static int nfs3svc_encode_setaclres(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_attrstat *resp)
{
	p = nfs3svc_encode_post_op_attr(rqstp, p, &resp->fh);

	return xdr_ressize_check(rqstp, p);
}

/*
 * XDR release functions
 */
static int nfs3svc_release_getacl(struct svc_rqst *rqstp, __be32 *p,
		struct nfsd3_getaclres *resp)
{
	fh_put(&resp->fh);
	posix_acl_release(resp->acl_access);
	posix_acl_release(resp->acl_default);
	return 1;
}

#define nfs3svc_decode_voidargs		NULL
#define nfs3svc_release_void		NULL
#define nfsd3_setaclres			nfsd3_attrstat
#define nfsd3_voidres			nfsd3_voidargs_nfs3acl_c
struct nfsd3_voidargs_nfs3acl_c { int dummy; };

#define PROC(name, argt, rest, relt, cache, respsize)	\
 { (svc_procfunc) nfsd3_proc_##name,		\
   (kxdrproc_t) nfs3svc_decode_##argt##args,	\
   (kxdrproc_t) nfs3svc_encode_##rest##res,	\
   (kxdrproc_t) nfs3svc_release_##relt,		\
   sizeof(struct nfsd3_##argt##args),		\
   sizeof(struct nfsd3_##rest##res),		\
   0,						\
   cache,					\
   respsize,					\
 }

#define ST 1		/* status*/
#define AT 21		/* attributes */
#define pAT (1+AT)	/* post attributes - conditional */
#define ACL (1+NFS_ACL_MAX_ENTRIES*3)  /* Access Control List */

static struct svc_procedure		nfsd_acl_procedures3[] = {
  PROC(null,	void,		void,		void,	  RC_NOCACHE, ST),
  PROC(getacl,	getacl,		getacl,		getacl,	  RC_NOCACHE, ST+1+2*(1+ACL)),
  PROC(setacl,	setacl,		setacl,		fhandle,  RC_NOCACHE, ST+pAT),
};

struct svc_version	nfsd_acl_version3 = {
		.vs_vers	= 3,
		.vs_nproc	= 3,
		.vs_proc	= nfsd_acl_procedures3,
		.vs_dispatch	= nfsd_dispatch,
		.vs_xdrsize	= NFS3_SVC_XDRSIZE,
		.vs_hidden	= 0,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs3acl.c */
/************************************************************/
/*
 *  Server-side procedures for NFSv4.
 *
 *  Copyright (c) 2002 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Kendrick Smith <kmsmith@umich.edu>
 *  Andy Adamson   <andros@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
// #include <linux/file.h>
// #include <linux/falloc.h>
// #include <linux/slab.h>

// #include "idmap.h"
// #include "cache.h"
#include "xdr4.h"
// #include "vfs.h"
#include "current_stateid.h"
// #include "netns.h"
// #include "acl.h"
// #include "pnfs.h"
// #include "trace.h"
#include "../../inc/__fss.h"

#ifdef CONFIG_NFSD_V4_SECURITY_LABEL
// #include <linux/security.h>

static inline void
nfsd4_security_inode_setsecctx(struct svc_fh *resfh, struct xdr_netobj *label, u32 *bmval)
{
	struct inode *inode = resfh->fh_dentry->d_inode;
	int status;

	mutex_lock(&inode->i_mutex);
	status = security_inode_setsecctx(resfh->fh_dentry,
		label->data, label->len);
	mutex_unlock(&inode->i_mutex);

	if (status)
		/*
		 * XXX: We should really fail the whole open, but we may
		 * already have created a new file, so it may be too
		 * late.  For now this seems the least of evils:
		 */
		bmval[2] &= ~FATTR4_WORD2_SECURITY_LABEL;

	return;
}
#else
static inline void
nfsd4_security_inode_setsecctx(struct svc_fh *resfh, struct xdr_netobj *label, u32 *bmval)
{ }
#endif

#define NFSDDBG_FACILITY		NFSDDBG_PROC

static u32 nfsd_attrmask[] = {
	NFSD_WRITEABLE_ATTRS_WORD0,
	NFSD_WRITEABLE_ATTRS_WORD1,
	NFSD_WRITEABLE_ATTRS_WORD2
};

static u32 nfsd41_ex_attrmask[] = {
	NFSD_SUPPATTR_EXCLCREAT_WORD0,
	NFSD_SUPPATTR_EXCLCREAT_WORD1,
	NFSD_SUPPATTR_EXCLCREAT_WORD2
};

static __be32
check_attr_support(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		   u32 *bmval, u32 *writable)
{
	struct dentry *dentry = cstate->current_fh.fh_dentry;

	/*
	 * Check about attributes are supported by the NFSv4 server or not.
	 * According to spec, unsupported attributes return ERR_ATTRNOTSUPP.
	 */
	if ((bmval[0] & ~nfsd_suppattrs0(cstate->minorversion)) ||
	    (bmval[1] & ~nfsd_suppattrs1(cstate->minorversion)) ||
	    (bmval[2] & ~nfsd_suppattrs2(cstate->minorversion)))
		return nfserr_attrnotsupp;

	/*
	 * Check FATTR4_WORD0_ACL can be supported
	 * in current environment or not.
	 */
	if (bmval[0] & FATTR4_WORD0_ACL) {
		if (!IS_POSIXACL(dentry->d_inode))
			return nfserr_attrnotsupp;
	}

	/*
	 * According to spec, read-only attributes return ERR_INVAL.
	 */
	if (writable) {
		if ((bmval[0] & ~writable[0]) || (bmval[1] & ~writable[1]) ||
		    (bmval[2] & ~writable[2]))
			return nfserr_inval;
	}

	return nfs_ok;
}

static __be32
nfsd4_check_open_attributes(struct svc_rqst *rqstp,
	struct nfsd4_compound_state *cstate, struct nfsd4_open *open)
{
	__be32 status = nfs_ok;

	if (open->op_create == NFS4_OPEN_CREATE) {
		if (open->op_createmode == NFS4_CREATE_UNCHECKED
		    || open->op_createmode == NFS4_CREATE_GUARDED)
			status = check_attr_support(rqstp, cstate,
					open->op_bmval, nfsd_attrmask);
		else if (open->op_createmode == NFS4_CREATE_EXCLUSIVE4_1)
			status = check_attr_support(rqstp, cstate,
					open->op_bmval, nfsd41_ex_attrmask);
	}

	return status;
}

static int
is_create_with_attrs(struct nfsd4_open *open)
{
	return open->op_create == NFS4_OPEN_CREATE
		&& (open->op_createmode == NFS4_CREATE_UNCHECKED
		    || open->op_createmode == NFS4_CREATE_GUARDED
		    || open->op_createmode == NFS4_CREATE_EXCLUSIVE4_1);
}

/*
 * if error occurs when setting the acl, just clear the acl bit
 * in the returned attr bitmap.
 */
static void
do_set_nfs4_acl(struct svc_rqst *rqstp, struct svc_fh *fhp,
		struct nfs4_acl *acl, u32 *bmval)
{
	__be32 status;

	status = nfsd4_set_nfs4_acl(rqstp, fhp, acl);
	if (status)
		/*
		 * We should probably fail the whole open at this point,
		 * but we've already created the file, so it's too late;
		 * So this seems the least of evils:
		 */
		bmval[0] &= ~FATTR4_WORD0_ACL;
}

static inline void
fh_dup2(struct svc_fh *dst, struct svc_fh *src)
{
	fh_put(dst);
	dget(src->fh_dentry);
	if (src->fh_export)
		exp_get(src->fh_export);
	*dst = *src;
}

static __be32
do_open_permission(struct svc_rqst *rqstp, struct svc_fh *current_fh, struct nfsd4_open *open, int accmode)
{
	__be32 status;

	if (open->op_truncate &&
		!(open->op_share_access & NFS4_SHARE_ACCESS_WRITE))
		return nfserr_inval;

	accmode |= NFSD_MAY_READ_IF_EXEC;

	if (open->op_share_access & NFS4_SHARE_ACCESS_READ)
		accmode |= NFSD_MAY_READ;
	if (open->op_share_access & NFS4_SHARE_ACCESS_WRITE)
		accmode |= (NFSD_MAY_WRITE | NFSD_MAY_TRUNC);
	if (open->op_share_deny & NFS4_SHARE_DENY_READ)
		accmode |= NFSD_MAY_WRITE;

	status = fh_verify(rqstp, current_fh, S_IFREG, accmode);

	return status;
}

static __be32 nfsd_check_obj_isreg(struct svc_fh *fh)
{
	umode_t mode = fh->fh_dentry->d_inode->i_mode;

	if (S_ISREG(mode))
		return nfs_ok;
	if (S_ISDIR(mode))
		return nfserr_isdir;
	/*
	 * Using err_symlink as our catch-all case may look odd; but
	 * there's no other obvious error for this case in 4.0, and we
	 * happen to know that it will cause the linux v4 client to do
	 * the right thing on attempts to open something other than a
	 * regular file.
	 */
	return nfserr_symlink;
}

static void nfsd4_set_open_owner_reply_cache(struct nfsd4_compound_state *cstate, struct nfsd4_open *open, struct svc_fh *resfh)
{
	if (nfsd4_has_session(cstate))
		return;
	fh_copy_shallow(&open->op_openowner->oo_owner.so_replay.rp_openfh,
			&resfh->fh_handle);
}

static __be32
do_open_lookup(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate, struct nfsd4_open *open, struct svc_fh **resfh)
{
	struct svc_fh *current_fh = &cstate->current_fh;
	int accmode;
	__be32 status;

	*resfh = kmalloc(sizeof(struct svc_fh), GFP_KERNEL);
	if (!*resfh)
		return nfserr_jukebox;
	fh_init(*resfh, NFS4_FHSIZE);
	open->op_truncate = 0;

	if (open->op_create) {
		/* FIXME: check session persistence and pnfs flags.
		 * The nfsv4.1 spec requires the following semantics:
		 *
		 * Persistent   | pNFS   | Server REQUIRED | Client Allowed
		 * Reply Cache  | server |                 |
		 * -------------+--------+-----------------+--------------------
		 * no           | no     | EXCLUSIVE4_1    | EXCLUSIVE4_1
		 *              |        |                 | (SHOULD)
		 *              |        | and EXCLUSIVE4  | or EXCLUSIVE4
		 *              |        |                 | (SHOULD NOT)
		 * no           | yes    | EXCLUSIVE4_1    | EXCLUSIVE4_1
		 * yes          | no     | GUARDED4        | GUARDED4
		 * yes          | yes    | GUARDED4        | GUARDED4
		 */

		/*
		 * Note: create modes (UNCHECKED,GUARDED...) are the same
		 * in NFSv4 as in v3 except EXCLUSIVE4_1.
		 */
		status = do_nfsd_create(rqstp, current_fh, open->op_fname.data,
					open->op_fname.len, &open->op_iattr,
					*resfh, open->op_createmode,
					(u32 *)open->op_verf.data,
					&open->op_truncate, &open->op_created);

		if (!status && open->op_label.len)
			nfsd4_security_inode_setsecctx(*resfh, &open->op_label, open->op_bmval);

		/*
		 * Following rfc 3530 14.2.16, use the returned bitmask
		 * to indicate which attributes we used to store the
		 * verifier:
		 */
		if (open->op_createmode == NFS4_CREATE_EXCLUSIVE && status == 0)
			open->op_bmval[1] = (FATTR4_WORD1_TIME_ACCESS |
							FATTR4_WORD1_TIME_MODIFY);
	} else
		/*
		 * Note this may exit with the parent still locked.
		 * We will hold the lock until nfsd4_open's final
		 * lookup, to prevent renames or unlinks until we've had
		 * a chance to an acquire a delegation if appropriate.
		 */
		status = nfsd_lookup(rqstp, current_fh,
				     open->op_fname.data, open->op_fname.len, *resfh);
	if (status)
		goto out;
	status = nfsd_check_obj_isreg(*resfh);
	if (status)
		goto out;

	if (is_create_with_attrs(open) && open->op_acl != NULL)
		do_set_nfs4_acl(rqstp, *resfh, open->op_acl, open->op_bmval);

	nfsd4_set_open_owner_reply_cache(cstate, open, *resfh);
	accmode = NFSD_MAY_NOP;
	if (open->op_created ||
			open->op_claim_type == NFS4_OPEN_CLAIM_DELEGATE_CUR)
		accmode |= NFSD_MAY_OWNER_OVERRIDE;
	status = do_open_permission(rqstp, *resfh, open, accmode);
	set_change_info(&open->op_cinfo, current_fh);
out:
	return status;
}

static __be32
do_open_fhandle(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate, struct nfsd4_open *open)
{
	struct svc_fh *current_fh = &cstate->current_fh;
	__be32 status;
	int accmode = 0;

	/* We don't know the target directory, and therefore can not
	* set the change info
	*/

	memset(&open->op_cinfo, 0, sizeof(struct nfsd4_change_info));

	nfsd4_set_open_owner_reply_cache(cstate, open, current_fh);

	open->op_truncate = (open->op_iattr.ia_valid & ATTR_SIZE) &&
		(open->op_iattr.ia_size == 0);
	/*
	 * In the delegation case, the client is telling us about an
	 * open that it *already* performed locally, some time ago.  We
	 * should let it succeed now if possible.
	 *
	 * In the case of a CLAIM_FH open, on the other hand, the client
	 * may be counting on us to enforce permissions (the Linux 4.1
	 * client uses this for normal opens, for example).
	 */
	if (open->op_claim_type == NFS4_OPEN_CLAIM_DELEG_CUR_FH)
		accmode = NFSD_MAY_OWNER_OVERRIDE;

	status = do_open_permission(rqstp, current_fh, open, accmode);

	return status;
}

static void
copy_clientid(clientid_t *clid, struct nfsd4_session *session)
{
	struct nfsd4_sessionid *sid =
			(struct nfsd4_sessionid *)session->se_sessionid.data;

	clid->cl_boot = sid->clientid.cl_boot;
	clid->cl_id = sid->clientid.cl_id;
}

static __be32
nfsd4_open(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	   struct nfsd4_open *open)
{
	__be32 status;
	struct svc_fh *resfh = NULL;
	struct nfsd4_compoundres *resp;
	struct net *net = SVC_NET(rqstp);
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	dprintk("NFSD: nfsd4_open filename %.*s op_openowner %p\n",
		(int)open->op_fname.len, open->op_fname.data,
		open->op_openowner);

	/* This check required by spec. */
	if (open->op_create && open->op_claim_type != NFS4_OPEN_CLAIM_NULL)
		return nfserr_inval;

	open->op_created = 0;
	/*
	 * RFC5661 18.51.3
	 * Before RECLAIM_COMPLETE done, server should deny new lock
	 */
	if (nfsd4_has_session(cstate) &&
	    !test_bit(NFSD4_CLIENT_RECLAIM_COMPLETE,
		      &cstate->session->se_client->cl_flags) &&
	    open->op_claim_type != NFS4_OPEN_CLAIM_PREVIOUS)
		return nfserr_grace;

	if (nfsd4_has_session(cstate))
		copy_clientid(&open->op_clientid, cstate->session);

	/* check seqid for replay. set nfs4_owner */
	resp = rqstp->rq_resp;
	status = nfsd4_process_open1(&resp->cstate, open, nn);
	if (status == nfserr_replay_me) {
		struct nfs4_replay *rp = &open->op_openowner->oo_owner.so_replay;
		fh_put(&cstate->current_fh);
		fh_copy_shallow(&cstate->current_fh.fh_handle,
				&rp->rp_openfh);
		status = fh_verify(rqstp, &cstate->current_fh, 0, NFSD_MAY_NOP);
		if (status)
			dprintk("nfsd4_open: replay failed"
				" restoring previous filehandle\n");
		else
			status = nfserr_replay_me;
	}
	if (status)
		goto out;
	if (open->op_xdr_error) {
		status = open->op_xdr_error;
		goto out;
	}

	status = nfsd4_check_open_attributes(rqstp, cstate, open);
	if (status)
		goto out;

	/* Openowner is now set, so sequence id will get bumped.  Now we need
	 * these checks before we do any creates: */
	status = nfserr_grace;
	if (locks_in_grace(net) && open->op_claim_type != NFS4_OPEN_CLAIM_PREVIOUS)
		goto out;
	status = nfserr_no_grace;
	if (!locks_in_grace(net) && open->op_claim_type == NFS4_OPEN_CLAIM_PREVIOUS)
		goto out;

	switch (open->op_claim_type) {
		case NFS4_OPEN_CLAIM_DELEGATE_CUR:
		case NFS4_OPEN_CLAIM_NULL:
			status = do_open_lookup(rqstp, cstate, open, &resfh);
			if (status)
				goto out;
			break;
		case NFS4_OPEN_CLAIM_PREVIOUS:
			status = nfs4_check_open_reclaim(&open->op_clientid,
							 cstate, nn);
			if (status)
				goto out;
			open->op_openowner->oo_flags |= NFS4_OO_CONFIRMED;
		case NFS4_OPEN_CLAIM_FH:
		case NFS4_OPEN_CLAIM_DELEG_CUR_FH:
			status = do_open_fhandle(rqstp, cstate, open);
			if (status)
				goto out;
			resfh = &cstate->current_fh;
			break;
		case NFS4_OPEN_CLAIM_DELEG_PREV_FH:
             	case NFS4_OPEN_CLAIM_DELEGATE_PREV:
			dprintk("NFSD: unsupported OPEN claim type %d\n",
				open->op_claim_type);
			status = nfserr_notsupp;
			goto out;
		default:
			dprintk("NFSD: Invalid OPEN claim type %d\n",
				open->op_claim_type);
			status = nfserr_inval;
			goto out;
	}
	/*
	 * nfsd4_process_open2() does the actual opening of the file.  If
	 * successful, it (1) truncates the file if open->op_truncate was
	 * set, (2) sets open->op_stateid, (3) sets open->op_delegation.
	 */
	status = nfsd4_process_open2(rqstp, resfh, open);
	WARN(status && open->op_created,
	     "nfsd4_process_open2 failed to open newly-created file! status=%u\n",
	     be32_to_cpu(status));
out:
	if (resfh && resfh != &cstate->current_fh) {
		fh_dup2(&cstate->current_fh, resfh);
		fh_put(resfh);
		kfree(resfh);
	}
	nfsd4_cleanup_open_state(cstate, open, status);
	nfsd4_bump_seqid(cstate, status);
	return status;
}

/*
 * OPEN is the only seqid-mutating operation whose decoding can fail
 * with a seqid-mutating error (specifically, decoding of user names in
 * the attributes).  Therefore we have to do some processing to look up
 * the stateowner so that we can bump the seqid.
 */
static __be32 nfsd4_open_omfg(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate, struct nfsd4_op *op)
{
	struct nfsd4_open *open = (struct nfsd4_open *)&op->u;

	if (!seqid_mutating_err(ntohl(op->status)))
		return op->status;
	if (nfsd4_has_session(cstate))
		return op->status;
	open->op_xdr_error = op->status;
	return nfsd4_open(rqstp, cstate, open);
}

/*
 * filehandle-manipulating ops.
 */
static __be32
nfsd4_getfh(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	    struct svc_fh **getfh)
{
	if (!cstate->current_fh.fh_dentry)
		return nfserr_nofilehandle;

	*getfh = &cstate->current_fh;
	return nfs_ok;
}

static __be32
nfsd4_putfh(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	    struct nfsd4_putfh *putfh)
{
	fh_put(&cstate->current_fh);
	cstate->current_fh.fh_handle.fh_size = putfh->pf_fhlen;
	memcpy(&cstate->current_fh.fh_handle.fh_base, putfh->pf_fhval,
	       putfh->pf_fhlen);
	return fh_verify(rqstp, &cstate->current_fh, 0, NFSD_MAY_BYPASS_GSS);
}

static __be32
nfsd4_putrootfh(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		void *arg)
{
	__be32 status;

	fh_put(&cstate->current_fh);
	status = exp_pseudoroot(rqstp, &cstate->current_fh);
	return status;
}

static __be32
nfsd4_restorefh(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		void *arg)
{
	if (!cstate->save_fh.fh_dentry)
		return nfserr_restorefh;

	fh_dup2(&cstate->current_fh, &cstate->save_fh);
	if (HAS_STATE_ID(cstate, SAVED_STATE_ID_FLAG)) {
		memcpy(&cstate->current_stateid, &cstate->save_stateid, sizeof(stateid_t));
		SET_STATE_ID(cstate, CURRENT_STATE_ID_FLAG);
	}
	return nfs_ok;
}

static __be32
nfsd4_savefh(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     void *arg)
{
	if (!cstate->current_fh.fh_dentry)
		return nfserr_nofilehandle;

	fh_dup2(&cstate->save_fh, &cstate->current_fh);
	if (HAS_STATE_ID(cstate, CURRENT_STATE_ID_FLAG)) {
		memcpy(&cstate->save_stateid, &cstate->current_stateid, sizeof(stateid_t));
		SET_STATE_ID(cstate, SAVED_STATE_ID_FLAG);
	}
	return nfs_ok;
}

/*
 * misc nfsv4 ops
 */
static __be32
nfsd4_access(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     struct nfsd4_access *access)
{
	if (access->ac_req_access & ~NFS3_ACCESS_FULL)
		return nfserr_inval;

	access->ac_resp_access = access->ac_req_access;
	return nfsd_access(rqstp, &cstate->current_fh, &access->ac_resp_access,
			   &access->ac_supported);
}

static void gen_boot_verifier(nfs4_verifier *verifier, struct net *net)
{
	__be32 verf[2];
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	/*
	 * This is opaque to client, so no need to byte-swap. Use
	 * __force to keep sparse happy
	 */
	verf[0] = (__force __be32)nn->nfssvc_boot.tv_sec;
	verf[1] = (__force __be32)nn->nfssvc_boot.tv_usec;
	memcpy(verifier->data, verf, sizeof(verifier->data));
}

static __be32
nfsd4_commit(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     struct nfsd4_commit *commit)
{
	gen_boot_verifier(&commit->co_verf, SVC_NET(rqstp));
	return nfsd_commit(rqstp, &cstate->current_fh, commit->co_offset,
			     commit->co_count);
}

static __be32
nfsd4_create(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     struct nfsd4_create *create)
{
	struct svc_fh resfh;
	__be32 status;
	dev_t rdev;

	fh_init(&resfh, NFS4_FHSIZE);

	status = fh_verify(rqstp, &cstate->current_fh, S_IFDIR,
			   NFSD_MAY_CREATE);
	if (status)
		return status;

	status = check_attr_support(rqstp, cstate, create->cr_bmval,
				    nfsd_attrmask);
	if (status)
		return status;

	switch (create->cr_type) {
	case NF4LNK:
		status = nfsd_symlink(rqstp, &cstate->current_fh,
				      create->cr_name, create->cr_namelen,
				      create->cr_data, &resfh);
		break;

	case NF4BLK:
		rdev = MKDEV(create->cr_specdata1, create->cr_specdata2);
		if (MAJOR(rdev) != create->cr_specdata1 ||
		    MINOR(rdev) != create->cr_specdata2)
			return nfserr_inval;
		status = nfsd_create(rqstp, &cstate->current_fh,
				     create->cr_name, create->cr_namelen,
				     &create->cr_iattr, S_IFBLK, rdev, &resfh);
		break;

	case NF4CHR:
		rdev = MKDEV(create->cr_specdata1, create->cr_specdata2);
		if (MAJOR(rdev) != create->cr_specdata1 ||
		    MINOR(rdev) != create->cr_specdata2)
			return nfserr_inval;
		status = nfsd_create(rqstp, &cstate->current_fh,
				     create->cr_name, create->cr_namelen,
				     &create->cr_iattr,S_IFCHR, rdev, &resfh);
		break;

	case NF4SOCK:
		status = nfsd_create(rqstp, &cstate->current_fh,
				     create->cr_name, create->cr_namelen,
				     &create->cr_iattr, S_IFSOCK, 0, &resfh);
		break;

	case NF4FIFO:
		status = nfsd_create(rqstp, &cstate->current_fh,
				     create->cr_name, create->cr_namelen,
				     &create->cr_iattr, S_IFIFO, 0, &resfh);
		break;

	case NF4DIR:
		create->cr_iattr.ia_valid &= ~ATTR_SIZE;
		status = nfsd_create(rqstp, &cstate->current_fh,
				     create->cr_name, create->cr_namelen,
				     &create->cr_iattr, S_IFDIR, 0, &resfh);
		break;

	default:
		status = nfserr_badtype;
	}

	if (status)
		goto out;

	if (create->cr_label.len)
		nfsd4_security_inode_setsecctx(&resfh, &create->cr_label, create->cr_bmval);

	if (create->cr_acl != NULL)
		do_set_nfs4_acl(rqstp, &resfh, create->cr_acl,
				create->cr_bmval);

	fh_unlock(&cstate->current_fh);
	set_change_info(&create->cr_cinfo, &cstate->current_fh);
	fh_dup2(&cstate->current_fh, &resfh);
out:
	fh_put(&resfh);
	return status;
}

static __be32
nfsd4_getattr(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	      struct nfsd4_getattr *getattr)
{
	__be32 status;

	status = fh_verify(rqstp, &cstate->current_fh, 0, NFSD_MAY_NOP);
	if (status)
		return status;

	if (getattr->ga_bmval[1] & NFSD_WRITEONLY_ATTRS_WORD1)
		return nfserr_inval;

	getattr->ga_bmval[0] &= nfsd_suppattrs0(cstate->minorversion);
	getattr->ga_bmval[1] &= nfsd_suppattrs1(cstate->minorversion);
	getattr->ga_bmval[2] &= nfsd_suppattrs2(cstate->minorversion);

	getattr->ga_fhp = &cstate->current_fh;
	return nfs_ok;
}

static __be32
nfsd4_link(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	   struct nfsd4_link *link)
{
	__be32 status = nfserr_nofilehandle;

	if (!cstate->save_fh.fh_dentry)
		return status;
	status = nfsd_link(rqstp, &cstate->current_fh,
			   link->li_name, link->li_namelen, &cstate->save_fh);
	if (!status)
		set_change_info(&link->li_cinfo, &cstate->current_fh);
	return status;
}

static __be32 nfsd4_do_lookupp(struct svc_rqst *rqstp, struct svc_fh *fh)
{
	struct svc_fh tmp_fh;
	__be32 ret;

	fh_init(&tmp_fh, NFS4_FHSIZE);
	ret = exp_pseudoroot(rqstp, &tmp_fh);
	if (ret)
		return ret;
	if (tmp_fh.fh_dentry == fh->fh_dentry) {
		fh_put(&tmp_fh);
		return nfserr_noent;
	}
	fh_put(&tmp_fh);
	return nfsd_lookup(rqstp, fh, "..", 2, fh);
}

static __be32
nfsd4_lookupp(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	      void *arg)
{
	return nfsd4_do_lookupp(rqstp, &cstate->current_fh);
}

static __be32
nfsd4_lookup(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     struct nfsd4_lookup *lookup)
{
	return nfsd_lookup(rqstp, &cstate->current_fh,
			   lookup->lo_name, lookup->lo_len,
			   &cstate->current_fh);
}

static __be32
nfsd4_read(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	   struct nfsd4_read *read)
{
	__be32 status;

	/* no need to check permission - this will be done in nfsd_read() */

	read->rd_filp = NULL;
	if (read->rd_offset >= OFFSET_MAX)
		return nfserr_inval;

	/*
	 * If we do a zero copy read, then a client will see read data
	 * that reflects the state of the file *after* performing the
	 * following compound.
	 *
	 * To ensure proper ordering, we therefore turn off zero copy if
	 * the client wants us to do more in this compound:
	 */
	if (!nfsd4_last_compound_op(rqstp))
		clear_bit(RQ_SPLICE_OK, &rqstp->rq_flags);

	/* check stateid */
	if ((status = nfs4_preprocess_stateid_op(SVC_NET(rqstp),
						 cstate, &read->rd_stateid,
						 RD_STATE, &read->rd_filp))) {
		dprintk("NFSD: nfsd4_read: couldn't process stateid!\n");
		goto out;
	}
	status = nfs_ok;
out:
	read->rd_rqstp = rqstp;
	read->rd_fhp = &cstate->current_fh;
	return status;
}

static __be32
nfsd4_readdir(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	      struct nfsd4_readdir *readdir)
{
	u64 cookie = readdir->rd_cookie;
	static const nfs4_verifier zeroverf;

	/* no need to check permission - this will be done in nfsd_readdir() */

	if (readdir->rd_bmval[1] & NFSD_WRITEONLY_ATTRS_WORD1)
		return nfserr_inval;

	readdir->rd_bmval[0] &= nfsd_suppattrs0(cstate->minorversion);
	readdir->rd_bmval[1] &= nfsd_suppattrs1(cstate->minorversion);
	readdir->rd_bmval[2] &= nfsd_suppattrs2(cstate->minorversion);

	if ((cookie == 1) || (cookie == 2) ||
	    (cookie == 0 && memcmp(readdir->rd_verf.data, zeroverf.data, NFS4_VERIFIER_SIZE)))
		return nfserr_bad_cookie;

	readdir->rd_rqstp = rqstp;
	readdir->rd_fhp = &cstate->current_fh;
	return nfs_ok;
}

static __be32
nfsd4_readlink(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	       struct nfsd4_readlink *readlink)
{
	readlink->rl_rqstp = rqstp;
	readlink->rl_fhp = &cstate->current_fh;
	return nfs_ok;
}

static __be32
nfsd4_remove(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     struct nfsd4_remove *remove)
{
	__be32 status;

	if (locks_in_grace(SVC_NET(rqstp)))
		return nfserr_grace;
	status = nfsd_unlink(rqstp, &cstate->current_fh, 0,
			     remove->rm_name, remove->rm_namelen);
	if (!status) {
		fh_unlock(&cstate->current_fh);
		set_change_info(&remove->rm_cinfo, &cstate->current_fh);
	}
	return status;
}

static __be32
nfsd4_rename(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     struct nfsd4_rename *rename)
{
	__be32 status = nfserr_nofilehandle;

	if (!cstate->save_fh.fh_dentry)
		return status;
	if (locks_in_grace(SVC_NET(rqstp)) &&
		!(cstate->save_fh.fh_export->ex_flags & NFSEXP_NOSUBTREECHECK))
		return nfserr_grace;
	status = nfsd_rename(rqstp, &cstate->save_fh, rename->rn_sname,
			     rename->rn_snamelen, &cstate->current_fh,
			     rename->rn_tname, rename->rn_tnamelen);
	if (status)
		return status;
	set_change_info(&rename->rn_sinfo, &cstate->current_fh);
	set_change_info(&rename->rn_tinfo, &cstate->save_fh);
	return nfs_ok;
}

static __be32
nfsd4_secinfo(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	      struct nfsd4_secinfo *secinfo)
{
	struct svc_fh resfh;
	struct svc_export *exp;
	struct dentry *dentry;
	__be32 err;

	fh_init(&resfh, NFS4_FHSIZE);
	err = fh_verify(rqstp, &cstate->current_fh, S_IFDIR, NFSD_MAY_EXEC);
	if (err)
		return err;
	err = nfsd_lookup_dentry(rqstp, &cstate->current_fh,
				    secinfo->si_name, secinfo->si_namelen,
				    &exp, &dentry);
	if (err)
		return err;
	if (dentry->d_inode == NULL) {
		exp_put(exp);
		err = nfserr_noent;
	} else
		secinfo->si_exp = exp;
	dput(dentry);
	if (cstate->minorversion)
		/* See rfc 5661 section 2.6.3.1.1.8 */
		fh_put(&cstate->current_fh);
	return err;
}

static __be32
nfsd4_secinfo_no_name(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	      struct nfsd4_secinfo_no_name *sin)
{
	__be32 err;

	switch (sin->sin_style) {
	case NFS4_SECINFO_STYLE4_CURRENT_FH:
		break;
	case NFS4_SECINFO_STYLE4_PARENT:
		err = nfsd4_do_lookupp(rqstp, &cstate->current_fh);
		if (err)
			return err;
		break;
	default:
		return nfserr_inval;
	}

	sin->sin_exp = exp_get(cstate->current_fh.fh_export);
	fh_put(&cstate->current_fh);
	return nfs_ok;
}

static __be32
nfsd4_setattr(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	      struct nfsd4_setattr *setattr)
{
	__be32 status = nfs_ok;
	int err;

	if (setattr->sa_iattr.ia_valid & ATTR_SIZE) {
		status = nfs4_preprocess_stateid_op(SVC_NET(rqstp), cstate,
			&setattr->sa_stateid, WR_STATE, NULL);
		if (status) {
			dprintk("NFSD: nfsd4_setattr: couldn't process stateid!\n");
			return status;
		}
	}
	err = fh_want_write(&cstate->current_fh);
	if (err)
		return nfserrno(err);
	status = nfs_ok;

	status = check_attr_support(rqstp, cstate, setattr->sa_bmval,
				    nfsd_attrmask);
	if (status)
		goto out;

	if (setattr->sa_acl != NULL)
		status = nfsd4_set_nfs4_acl(rqstp, &cstate->current_fh,
					    setattr->sa_acl);
	if (status)
		goto out;
	if (setattr->sa_label.len)
		status = nfsd4_set_nfs4_label(rqstp, &cstate->current_fh,
				&setattr->sa_label);
	if (status)
		goto out;
	status = nfsd_setattr(rqstp, &cstate->current_fh, &setattr->sa_iattr,
				0, (time_t)0);
out:
	fh_drop_write(&cstate->current_fh);
	return status;
}

static int fill_in_write_vector(struct kvec *vec, struct nfsd4_write *write)
{
        int i = 1;
        int buflen = write->wr_buflen;

        vec[0].iov_base = write->wr_head.iov_base;
        vec[0].iov_len = min_t(int, buflen, write->wr_head.iov_len);
        buflen -= vec[0].iov_len;

        while (buflen) {
                vec[i].iov_base = page_address(write->wr_pagelist[i - 1]);
                vec[i].iov_len = min_t(int, PAGE_SIZE, buflen);
                buflen -= vec[i].iov_len;
                i++;
        }
        return i;
}

static __be32
nfsd4_write(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	    struct nfsd4_write *write)
{
	stateid_t *stateid = &write->wr_stateid;
	struct file *filp = NULL;
	__be32 status = nfs_ok;
	unsigned long cnt;
	int nvecs;

	/* no need to check permission - this will be done in nfsd_write() */

	if (write->wr_offset >= OFFSET_MAX)
		return nfserr_inval;

	status = nfs4_preprocess_stateid_op(SVC_NET(rqstp),
					cstate, stateid, WR_STATE, &filp);
	if (status) {
		dprintk("NFSD: nfsd4_write: couldn't process stateid!\n");
		return status;
	}

	cnt = write->wr_buflen;
	write->wr_how_written = write->wr_stable_how;
	gen_boot_verifier(&write->wr_verifier, SVC_NET(rqstp));

	nvecs = fill_in_write_vector(rqstp->rq_vec, write);
	WARN_ON_ONCE(nvecs > ARRAY_SIZE(rqstp->rq_vec));

	status =  nfsd_write(rqstp, &cstate->current_fh, filp,
			     write->wr_offset, rqstp->rq_vec, nvecs,
			     &cnt, &write->wr_how_written);
	if (filp)
		fput(filp);

	write->wr_bytes_written = cnt;

	return status;
}

static __be32
nfsd4_fallocate(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		struct nfsd4_fallocate *fallocate, int flags)
{
	__be32 status = nfserr_notsupp;
	struct file *file;

	status = nfs4_preprocess_stateid_op(SVC_NET(rqstp), cstate,
					    &fallocate->falloc_stateid,
					    WR_STATE, &file);
	if (status != nfs_ok) {
		dprintk("NFSD: nfsd4_fallocate: couldn't process stateid!\n");
		return status;
	}

	status = nfsd4_vfs_fallocate(rqstp, &cstate->current_fh, file,
				     fallocate->falloc_offset,
				     fallocate->falloc_length,
				     flags);
	fput(file);
	return status;
}

static __be32
nfsd4_allocate(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	       struct nfsd4_fallocate *fallocate)
{
	return nfsd4_fallocate(rqstp, cstate, fallocate, 0);
}

static __be32
nfsd4_deallocate(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		 struct nfsd4_fallocate *fallocate)
{
	return nfsd4_fallocate(rqstp, cstate, fallocate,
			       FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE);
}

static __be32
nfsd4_seek(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		struct nfsd4_seek *seek)
{
	int whence;
	__be32 status;
	struct file *file;

	status = nfs4_preprocess_stateid_op(SVC_NET(rqstp), cstate,
					    &seek->seek_stateid,
					    RD_STATE, &file);
	if (status) {
		dprintk("NFSD: nfsd4_seek: couldn't process stateid!\n");
		return status;
	}

	switch (seek->seek_whence) {
	case NFS4_CONTENT_DATA:
		whence = SEEK_DATA;
		break;
	case NFS4_CONTENT_HOLE:
		whence = SEEK_HOLE;
		break;
	default:
		status = nfserr_union_notsupp;
		goto out;
	}

	/*
	 * Note:  This call does change file->f_pos, but nothing in NFSD
	 *        should ever file->f_pos.
	 */
	seek->seek_pos = vfs_llseek(file, seek->seek_offset, whence);
	if (seek->seek_pos < 0)
		status = nfserrno(seek->seek_pos);
	else if (seek->seek_pos >= i_size_read(file_inode(file)))
		seek->seek_eof = true;

out:
	fput(file);
	return status;
}

/* This routine never returns NFS_OK!  If there are no other errors, it
 * will return NFSERR_SAME or NFSERR_NOT_SAME depending on whether the
 * attributes matched.  VERIFY is implemented by mapping NFSERR_SAME
 * to NFS_OK after the call; NVERIFY by mapping NFSERR_NOT_SAME to NFS_OK.
 */
static __be32
_nfsd4_verify(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     struct nfsd4_verify *verify)
{
	__be32 *buf, *p;
	int count;
	__be32 status;

	status = fh_verify(rqstp, &cstate->current_fh, 0, NFSD_MAY_NOP);
	if (status)
		return status;

	status = check_attr_support(rqstp, cstate, verify->ve_bmval, NULL);
	if (status)
		return status;

	if ((verify->ve_bmval[0] & FATTR4_WORD0_RDATTR_ERROR)
	    || (verify->ve_bmval[1] & NFSD_WRITEONLY_ATTRS_WORD1))
		return nfserr_inval;
	if (verify->ve_attrlen & 3)
		return nfserr_inval;

	/* count in words:
	 *   bitmap_len(1) + bitmap(2) + attr_len(1) = 4
	 */
	count = 4 + (verify->ve_attrlen >> 2);
	buf = kmalloc(count << 2, GFP_KERNEL);
	if (!buf)
		return nfserr_jukebox;

	p = buf;
	status = nfsd4_encode_fattr_to_buf(&p, count, &cstate->current_fh,
				    cstate->current_fh.fh_export,
				    cstate->current_fh.fh_dentry,
				    verify->ve_bmval,
				    rqstp, 0);
	/*
	 * If nfsd4_encode_fattr() ran out of space, assume that's because
	 * the attributes are longer (hence different) than those given:
	 */
	if (status == nfserr_resource)
		status = nfserr_not_same;
	if (status)
		goto out_kfree;

	/* skip bitmap */
	p = buf + 1 + ntohl(buf[0]);
	status = nfserr_not_same;
	if (ntohl(*p++) != verify->ve_attrlen)
		goto out_kfree;
	if (!memcmp(p, verify->ve_attrval, verify->ve_attrlen))
		status = nfserr_same;

out_kfree:
	kfree(buf);
	return status;
}

static __be32
nfsd4_nverify(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	      struct nfsd4_verify *verify)
{
	__be32 status;

	status = _nfsd4_verify(rqstp, cstate, verify);
	return status == nfserr_not_same ? nfs_ok : status;
}

static __be32
nfsd4_verify(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	     struct nfsd4_verify *verify)
{
	__be32 status;

	status = _nfsd4_verify(rqstp, cstate, verify);
	return status == nfserr_same ? nfs_ok : status;
}

#ifdef CONFIG_NFSD_PNFS
static const struct nfsd4_layout_ops *
nfsd4_layout_verify(struct svc_export *exp, unsigned int layout_type)
{
	if (!exp->ex_layout_type) {
		dprintk("%s: export does not support pNFS\n", __func__);
		return NULL;
	}

	if (exp->ex_layout_type != layout_type) {
		dprintk("%s: layout type %d not supported\n",
			__func__, layout_type);
		return NULL;
	}

	return nfsd4_layout_ops[layout_type];
}

static __be32
nfsd4_getdeviceinfo(struct svc_rqst *rqstp,
		struct nfsd4_compound_state *cstate,
		struct nfsd4_getdeviceinfo *gdp)
{
	const struct nfsd4_layout_ops *ops;
	struct nfsd4_deviceid_map *map;
	struct svc_export *exp;
	__be32 nfserr;

	dprintk("%s: layout_type %u dev_id [0x%llx:0x%x] maxcnt %u\n",
	       __func__,
	       gdp->gd_layout_type,
	       gdp->gd_devid.fsid_idx, gdp->gd_devid.generation,
	       gdp->gd_maxcount);

	map = nfsd4_find_devid_map(gdp->gd_devid.fsid_idx);
	if (!map) {
		dprintk("%s: couldn't find device ID to export mapping!\n",
			__func__);
		return nfserr_noent;
	}

	exp = rqst_exp_find(rqstp, map->fsid_type, map->fsid);
	if (IS_ERR(exp)) {
		dprintk("%s: could not find device id\n", __func__);
		return nfserr_noent;
	}

	nfserr = nfserr_layoutunavailable;
	ops = nfsd4_layout_verify(exp, gdp->gd_layout_type);
	if (!ops)
		goto out;

	nfserr = nfs_ok;
	if (gdp->gd_maxcount != 0)
		nfserr = ops->proc_getdeviceinfo(exp->ex_path.mnt->mnt_sb, gdp);

	gdp->gd_notify_types &= ops->notify_types;
	exp_put(exp);
out:
	return nfserr;
}

static __be32
nfsd4_layoutget(struct svc_rqst *rqstp,
		struct nfsd4_compound_state *cstate,
		struct nfsd4_layoutget *lgp)
{
	struct svc_fh *current_fh = &cstate->current_fh;
	const struct nfsd4_layout_ops *ops;
	struct nfs4_layout_stateid *ls;
	__be32 nfserr;
	int accmode;

	switch (lgp->lg_seg.iomode) {
	case IOMODE_READ:
		accmode = NFSD_MAY_READ;
		break;
	case IOMODE_RW:
		accmode = NFSD_MAY_READ | NFSD_MAY_WRITE;
		break;
	default:
		dprintk("%s: invalid iomode %d\n",
			__func__, lgp->lg_seg.iomode);
		nfserr = nfserr_badiomode;
		goto out;
	}

	nfserr = fh_verify(rqstp, current_fh, 0, accmode);
	if (nfserr)
		goto out;

	nfserr = nfserr_layoutunavailable;
	ops = nfsd4_layout_verify(current_fh->fh_export, lgp->lg_layout_type);
	if (!ops)
		goto out;

	/*
	 * Verify minlength and range as per RFC5661:
	 *  o  If loga_length is less than loga_minlength,
	 *     the metadata server MUST return NFS4ERR_INVAL.
	 *  o  If the sum of loga_offset and loga_minlength exceeds
	 *     NFS4_UINT64_MAX, and loga_minlength is not
	 *     NFS4_UINT64_MAX, the error NFS4ERR_INVAL MUST result.
	 *  o  If the sum of loga_offset and loga_length exceeds
	 *     NFS4_UINT64_MAX, and loga_length is not NFS4_UINT64_MAX,
	 *     the error NFS4ERR_INVAL MUST result.
	 */
	nfserr = nfserr_inval;
	if (lgp->lg_seg.length < lgp->lg_minlength ||
	    (lgp->lg_minlength != NFS4_MAX_UINT64 &&
	     lgp->lg_minlength > NFS4_MAX_UINT64 - lgp->lg_seg.offset) ||
	    (lgp->lg_seg.length != NFS4_MAX_UINT64 &&
	     lgp->lg_seg.length > NFS4_MAX_UINT64 - lgp->lg_seg.offset))
		goto out;
	if (lgp->lg_seg.length == 0)
		goto out;

	nfserr = nfsd4_preprocess_layout_stateid(rqstp, cstate, &lgp->lg_sid,
						true, lgp->lg_layout_type, &ls);
	if (nfserr) {
		trace_layout_get_lookup_fail(&lgp->lg_sid);
		goto out;
	}

	nfserr = nfserr_recallconflict;
	if (atomic_read(&ls->ls_stid.sc_file->fi_lo_recalls))
		goto out_put_stid;

	nfserr = ops->proc_layoutget(current_fh->fh_dentry->d_inode,
				     current_fh, lgp);
	if (nfserr)
		goto out_put_stid;

	nfserr = nfsd4_insert_layout(lgp, ls);

out_put_stid:
	nfs4_put_stid(&ls->ls_stid);
out:
	return nfserr;
}

static __be32
nfsd4_layoutcommit(struct svc_rqst *rqstp,
		struct nfsd4_compound_state *cstate,
		struct nfsd4_layoutcommit *lcp)
{
	const struct nfsd4_layout_seg *seg = &lcp->lc_seg;
	struct svc_fh *current_fh = &cstate->current_fh;
	const struct nfsd4_layout_ops *ops;
	loff_t new_size = lcp->lc_last_wr + 1;
	struct inode *inode;
	struct nfs4_layout_stateid *ls;
	__be32 nfserr;

	nfserr = fh_verify(rqstp, current_fh, 0, NFSD_MAY_WRITE);
	if (nfserr)
		goto out;

	nfserr = nfserr_layoutunavailable;
	ops = nfsd4_layout_verify(current_fh->fh_export, lcp->lc_layout_type);
	if (!ops)
		goto out;
	inode = current_fh->fh_dentry->d_inode;

	nfserr = nfserr_inval;
	if (new_size <= seg->offset) {
		dprintk("pnfsd: last write before layout segment\n");
		goto out;
	}
	if (new_size > seg->offset + seg->length) {
		dprintk("pnfsd: last write beyond layout segment\n");
		goto out;
	}
	if (!lcp->lc_newoffset && new_size > i_size_read(inode)) {
		dprintk("pnfsd: layoutcommit beyond EOF\n");
		goto out;
	}

	nfserr = nfsd4_preprocess_layout_stateid(rqstp, cstate, &lcp->lc_sid,
						false, lcp->lc_layout_type,
						&ls);
	if (nfserr) {
		trace_layout_commit_lookup_fail(&lcp->lc_sid);
		/* fixup error code as per RFC5661 */
		if (nfserr == nfserr_bad_stateid)
			nfserr = nfserr_badlayout;
		goto out;
	}

	nfserr = ops->proc_layoutcommit(inode, lcp);
	if (nfserr)
		goto out_put_stid;

	if (new_size > i_size_read(inode)) {
		lcp->lc_size_chg = 1;
		lcp->lc_newsize = new_size;
	} else {
		lcp->lc_size_chg = 0;
	}

out_put_stid:
	nfs4_put_stid(&ls->ls_stid);
out:
	return nfserr;
}

static __be32
nfsd4_layoutreturn(struct svc_rqst *rqstp,
		struct nfsd4_compound_state *cstate,
		struct nfsd4_layoutreturn *lrp)
{
	struct svc_fh *current_fh = &cstate->current_fh;
	__be32 nfserr;

	nfserr = fh_verify(rqstp, current_fh, 0, NFSD_MAY_NOP);
	if (nfserr)
		goto out;

	nfserr = nfserr_layoutunavailable;
	if (!nfsd4_layout_verify(current_fh->fh_export, lrp->lr_layout_type))
		goto out;

	switch (lrp->lr_seg.iomode) {
	case IOMODE_READ:
	case IOMODE_RW:
	case IOMODE_ANY:
		break;
	default:
		dprintk("%s: invalid iomode %d\n", __func__,
			lrp->lr_seg.iomode);
		nfserr = nfserr_inval;
		goto out;
	}

	switch (lrp->lr_return_type) {
	case RETURN_FILE:
		nfserr = nfsd4_return_file_layouts(rqstp, cstate, lrp);
		break;
	case RETURN_FSID:
	case RETURN_ALL:
		nfserr = nfsd4_return_client_layouts(rqstp, cstate, lrp);
		break;
	default:
		dprintk("%s: invalid return_type %d\n", __func__,
			lrp->lr_return_type);
		nfserr = nfserr_inval;
		break;
	}
out:
	return nfserr;
}
#endif /* CONFIG_NFSD_PNFS */

/*
 * NULL call.
 */
static __be32
nfsd4_proc_null(struct svc_rqst *rqstp, void *argp, void *resp)
{
	return nfs_ok;
}

static inline void nfsd4_increment_op_stats(u32 opnum)
{
	if (opnum >= FIRST_NFS4_OP && opnum <= LAST_NFS4_OP)
		nfsdstats.nfs4_opcount[opnum]++;
}

typedef __be32(*nfsd4op_func)(struct svc_rqst *, struct nfsd4_compound_state *,
			      void *);
typedef u32(*nfsd4op_rsize)(struct svc_rqst *, struct nfsd4_op *op);
typedef void(*stateid_setter)(struct nfsd4_compound_state *, void *);
typedef void(*stateid_getter)(struct nfsd4_compound_state *, void *);

enum nfsd4_op_flags {
	ALLOWED_WITHOUT_FH = 1 << 0,	/* No current filehandle required */
	ALLOWED_ON_ABSENT_FS = 1 << 1,	/* ops processed on absent fs */
	ALLOWED_AS_FIRST_OP = 1 << 2,	/* ops reqired first in compound */
	/* For rfc 5661 section 2.6.3.1.1: */
	OP_HANDLES_WRONGSEC = 1 << 3,
	OP_IS_PUTFH_LIKE = 1 << 4,
	/*
	 * These are the ops whose result size we estimate before
	 * encoding, to avoid performing an op then not being able to
	 * respond or cache a response.  This includes writes and setattrs
	 * as well as the operations usually called "nonidempotent":
	 */
	OP_MODIFIES_SOMETHING = 1 << 5,
	/*
	 * Cache compounds containing these ops in the xid-based drc:
	 * We use the DRC for compounds containing non-idempotent
	 * operations, *except* those that are 4.1-specific (since
	 * sessions provide their own EOS), and except for stateful
	 * operations other than setclientid and setclientid_confirm
	 * (since sequence numbers provide EOS for open, lock, etc in
	 * the v4.0 case).
	 */
	OP_CACHEME = 1 << 6,
	/*
	 * These are ops which clear current state id.
	 */
	OP_CLEAR_STATEID = 1 << 7,
};

struct nfsd4_operation {
	nfsd4op_func op_func;
	u32 op_flags;
	char *op_name;
	/* Try to get response size before operation */
	nfsd4op_rsize op_rsize_bop;
	stateid_getter op_get_currentstateid;
	stateid_setter op_set_currentstateid;
};

static struct nfsd4_operation nfsd4_ops[];

static const char *nfsd4_op_name(unsigned opnum);

/*
 * Enforce NFSv4.1 COMPOUND ordering rules:
 *
 * Also note, enforced elsewhere:
 *	- SEQUENCE other than as first op results in
 *	  NFS4ERR_SEQUENCE_POS. (Enforced in nfsd4_sequence().)
 *	- BIND_CONN_TO_SESSION must be the only op in its compound.
 *	  (Enforced in nfsd4_bind_conn_to_session().)
 *	- DESTROY_SESSION must be the final operation in a compound, if
 *	  sessionid's in SEQUENCE and DESTROY_SESSION are the same.
 *	  (Enforced in nfsd4_destroy_session().)
 */
static __be32 nfs41_check_op_ordering(struct nfsd4_compoundargs *args)
{
	struct nfsd4_op *op = &args->ops[0];

	/* These ordering requirements don't apply to NFSv4.0: */
	if (args->minorversion == 0)
		return nfs_ok;
	/* This is weird, but OK, not our problem: */
	if (args->opcnt == 0)
		return nfs_ok;
	if (op->status == nfserr_op_illegal)
		return nfs_ok;
	if (!(nfsd4_ops[op->opnum].op_flags & ALLOWED_AS_FIRST_OP))
		return nfserr_op_not_in_session;
	if (op->opnum == OP_SEQUENCE)
		return nfs_ok;
	if (args->opcnt != 1)
		return nfserr_not_only_op;
	return nfs_ok;
}

static inline struct nfsd4_operation *OPDESC(struct nfsd4_op *op)
{
	return &nfsd4_ops[op->opnum];
}

bool nfsd4_cache_this_op(struct nfsd4_op *op)
{
	if (op->opnum == OP_ILLEGAL)
		return false;
	return OPDESC(op)->op_flags & OP_CACHEME;
}

static bool need_wrongsec_check(struct svc_rqst *rqstp)
{
	struct nfsd4_compoundres *resp = rqstp->rq_resp;
	struct nfsd4_compoundargs *argp = rqstp->rq_argp;
	struct nfsd4_op *this = &argp->ops[resp->opcnt - 1];
	struct nfsd4_op *next = &argp->ops[resp->opcnt];
	struct nfsd4_operation *thisd;
	struct nfsd4_operation *nextd;

	thisd = OPDESC(this);
	/*
	 * Most ops check wronsec on our own; only the putfh-like ops
	 * have special rules.
	 */
	if (!(thisd->op_flags & OP_IS_PUTFH_LIKE))
		return false;
	/*
	 * rfc 5661 2.6.3.1.1.6: don't bother erroring out a
	 * put-filehandle operation if we're not going to use the
	 * result:
	 */
	if (argp->opcnt == resp->opcnt)
		return false;
	if (next->opnum == OP_ILLEGAL)
		return false;
	nextd = OPDESC(next);
	/*
	 * Rest of 2.6.3.1.1: certain operations will return WRONGSEC
	 * errors themselves as necessary; others should check for them
	 * now:
	 */
	return !(nextd->op_flags & OP_HANDLES_WRONGSEC);
}

static void svcxdr_init_encode(struct svc_rqst *rqstp,
			       struct nfsd4_compoundres *resp)
{
	struct xdr_stream *xdr = &resp->xdr;
	struct xdr_buf *buf = &rqstp->rq_res;
	struct kvec *head = buf->head;

	xdr->buf = buf;
	xdr->iov = head;
	xdr->p   = head->iov_base + head->iov_len;
	xdr->end = head->iov_base + PAGE_SIZE - rqstp->rq_auth_slack;
	/* Tail and page_len should be zero at this point: */
	buf->len = buf->head[0].iov_len;
	xdr->scratch.iov_len = 0;
	xdr->page_ptr = buf->pages - 1;
	buf->buflen = PAGE_SIZE * (1 + rqstp->rq_page_end - buf->pages)
		- rqstp->rq_auth_slack;
}

/*
 * COMPOUND call.
 */
static __be32
nfsd4_proc_compound(struct svc_rqst *rqstp,
		    struct nfsd4_compoundargs *args,
		    struct nfsd4_compoundres *resp)
{
	struct nfsd4_op	*op;
	struct nfsd4_operation *opdesc;
	struct nfsd4_compound_state *cstate = &resp->cstate;
	struct svc_fh *current_fh = &cstate->current_fh;
	struct svc_fh *save_fh = &cstate->save_fh;
	__be32		status;

	svcxdr_init_encode(rqstp, resp);
	resp->tagp = resp->xdr.p;
	/* reserve space for: taglen, tag, and opcnt */
	xdr_reserve_space(&resp->xdr, 8 + args->taglen);
	resp->taglen = args->taglen;
	resp->tag = args->tag;
	resp->rqstp = rqstp;
	cstate->minorversion = args->minorversion;
	fh_init(current_fh, NFS4_FHSIZE);
	fh_init(save_fh, NFS4_FHSIZE);
	/*
	 * Don't use the deferral mechanism for NFSv4; compounds make it
	 * too hard to avoid non-idempotency problems.
	 */
	clear_bit(RQ_USEDEFERRAL, &rqstp->rq_flags);

	/*
	 * According to RFC3010, this takes precedence over all other errors.
	 */
	status = nfserr_minor_vers_mismatch;
	if (nfsd_minorversion(args->minorversion, NFSD_TEST) <= 0)
		goto out;

	status = nfs41_check_op_ordering(args);
	if (status) {
		op = &args->ops[0];
		op->status = status;
		goto encode_op;
	}

	while (!status && resp->opcnt < args->opcnt) {
		op = &args->ops[resp->opcnt++];

		dprintk("nfsv4 compound op #%d/%d: %d (%s)\n",
			resp->opcnt, args->opcnt, op->opnum,
			nfsd4_op_name(op->opnum));
		/*
		 * The XDR decode routines may have pre-set op->status;
		 * for example, if there is a miscellaneous XDR error
		 * it will be set to nfserr_bad_xdr.
		 */
		if (op->status) {
			if (op->opnum == OP_OPEN)
				op->status = nfsd4_open_omfg(rqstp, cstate, op);
			goto encode_op;
		}

		opdesc = OPDESC(op);

		if (!current_fh->fh_dentry) {
			if (!(opdesc->op_flags & ALLOWED_WITHOUT_FH)) {
				op->status = nfserr_nofilehandle;
				goto encode_op;
			}
		} else if (current_fh->fh_export->ex_fslocs.migrated &&
			  !(opdesc->op_flags & ALLOWED_ON_ABSENT_FS)) {
			op->status = nfserr_moved;
			goto encode_op;
		}

		fh_clear_wcc(current_fh);

		/* If op is non-idempotent */
		if (opdesc->op_flags & OP_MODIFIES_SOMETHING) {
			/*
			 * Don't execute this op if we couldn't encode a
			 * succesful reply:
			 */
			u32 plen = opdesc->op_rsize_bop(rqstp, op);
			/*
			 * Plus if there's another operation, make sure
			 * we'll have space to at least encode an error:
			 */
			if (resp->opcnt < args->opcnt)
				plen += COMPOUND_ERR_SLACK_SPACE;
			op->status = nfsd4_check_resp_size(resp, plen);
		}

		if (op->status)
			goto encode_op;

		if (opdesc->op_get_currentstateid)
			opdesc->op_get_currentstateid(cstate, &op->u);
		op->status = opdesc->op_func(rqstp, cstate, &op->u);

		if (!op->status) {
			if (opdesc->op_set_currentstateid)
				opdesc->op_set_currentstateid(cstate, &op->u);

			if (opdesc->op_flags & OP_CLEAR_STATEID)
				clear_current_stateid(cstate);

			if (need_wrongsec_check(rqstp))
				op->status = check_nfsd_access(current_fh->fh_export, rqstp);
		}

encode_op:
		/* Only from SEQUENCE */
		if (cstate->status == nfserr_replay_cache) {
			dprintk("%s NFS4.1 replay from cache\n", __func__);
			status = op->status;
			goto out;
		}
		if (op->status == nfserr_replay_me) {
			op->replay = &cstate->replay_owner->so_replay;
			nfsd4_encode_replay(&resp->xdr, op);
			status = op->status = op->replay->rp_status;
		} else {
			nfsd4_encode_operation(resp, op);
			status = op->status;
		}

		dprintk("nfsv4 compound op %p opcnt %d #%d: %d: status %d\n",
			args->ops, args->opcnt, resp->opcnt, op->opnum,
			be32_to_cpu(status));

		nfsd4_cstate_clear_replay(cstate);
		/* XXX Ugh, we need to get rid of this kind of special case: */
		if (op->opnum == OP_READ && op->u.read.rd_filp)
			fput(op->u.read.rd_filp);

		nfsd4_increment_op_stats(op->opnum);
	}

	cstate->status = status;
	fh_put(current_fh);
	fh_put(save_fh);
	BUG_ON(cstate->replay_owner);
out:
	/* Reset deferral mechanism for RPC deferrals */
	set_bit(RQ_USEDEFERRAL, &rqstp->rq_flags);
	dprintk("nfsv4 compound returned %d\n", ntohl(status));
	return status;
}

#define op_encode_hdr_size		(2)
#define op_encode_stateid_maxsz		(XDR_QUADLEN(NFS4_STATEID_SIZE))
#define op_encode_verifier_maxsz	(XDR_QUADLEN(NFS4_VERIFIER_SIZE))
#define op_encode_change_info_maxsz	(5)
#define nfs4_fattr_bitmap_maxsz		(4)

/* We'll fall back on returning no lockowner if run out of space: */
#define op_encode_lockowner_maxsz	(0)
#define op_encode_lock_denied_maxsz	(8 + op_encode_lockowner_maxsz)

#define nfs4_owner_maxsz		(1 + XDR_QUADLEN(IDMAP_NAMESZ))

#define op_encode_ace_maxsz		(3 + nfs4_owner_maxsz)
#define op_encode_delegation_maxsz	(1 + op_encode_stateid_maxsz + 1 + \
					 op_encode_ace_maxsz)

#define op_encode_channel_attrs_maxsz	(6 + 1 + 1)

static inline u32 nfsd4_only_status_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size) * sizeof(__be32);
}

static inline u32 nfsd4_status_stateid_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + op_encode_stateid_maxsz)* sizeof(__be32);
}

static inline u32 nfsd4_commit_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + op_encode_verifier_maxsz) * sizeof(__be32);
}

static inline u32 nfsd4_create_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + op_encode_change_info_maxsz
		+ nfs4_fattr_bitmap_maxsz) * sizeof(__be32);
}

/*
 * Note since this is an idempotent operation we won't insist on failing
 * the op prematurely if the estimate is too large.  We may turn off splice
 * reads unnecessarily.
 */
static inline u32 nfsd4_getattr_rsize(struct svc_rqst *rqstp,
				      struct nfsd4_op *op)
{
	u32 *bmap = op->u.getattr.ga_bmval;
	u32 bmap0 = bmap[0], bmap1 = bmap[1], bmap2 = bmap[2];
	u32 ret = 0;

	if (bmap0 & FATTR4_WORD0_ACL)
		return svc_max_payload(rqstp);
	if (bmap0 & FATTR4_WORD0_FS_LOCATIONS)
		return svc_max_payload(rqstp);

	if (bmap1 & FATTR4_WORD1_OWNER) {
		ret += IDMAP_NAMESZ + 4;
		bmap1 &= ~FATTR4_WORD1_OWNER;
	}
	if (bmap1 & FATTR4_WORD1_OWNER_GROUP) {
		ret += IDMAP_NAMESZ + 4;
		bmap1 &= ~FATTR4_WORD1_OWNER_GROUP;
	}
	if (bmap0 & FATTR4_WORD0_FILEHANDLE) {
		ret += NFS4_FHSIZE + 4;
		bmap0 &= ~FATTR4_WORD0_FILEHANDLE;
	}
	if (bmap2 & FATTR4_WORD2_SECURITY_LABEL) {
		ret += NFSD4_MAX_SEC_LABEL_LEN + 12;
		bmap2 &= ~FATTR4_WORD2_SECURITY_LABEL;
	}
	/*
	 * Largest of remaining attributes are 16 bytes (e.g.,
	 * supported_attributes)
	 */
	ret += 16 * (hweight32(bmap0) + hweight32(bmap1) + hweight32(bmap2));
	/* bitmask, length */
	ret += 20;
	return ret;
}

static inline u32 nfsd4_link_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + op_encode_change_info_maxsz)
		* sizeof(__be32);
}

static inline u32 nfsd4_lock_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + op_encode_lock_denied_maxsz)
		* sizeof(__be32);
}

static inline u32 nfsd4_open_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + op_encode_stateid_maxsz
		+ op_encode_change_info_maxsz + 1
		+ nfs4_fattr_bitmap_maxsz
		+ op_encode_delegation_maxsz) * sizeof(__be32);
}

static inline u32 nfsd4_read_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	u32 maxcount = 0, rlen = 0;

	maxcount = svc_max_payload(rqstp);
	rlen = min(op->u.read.rd_length, maxcount);

	return (op_encode_hdr_size + 2 + XDR_QUADLEN(rlen)) * sizeof(__be32);
}

static inline u32 nfsd4_readdir_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	u32 maxcount = 0, rlen = 0;

	maxcount = svc_max_payload(rqstp);
	rlen = min(op->u.readdir.rd_maxcount, maxcount);

	return (op_encode_hdr_size + op_encode_verifier_maxsz +
		XDR_QUADLEN(rlen)) * sizeof(__be32);
}

static inline u32 nfsd4_remove_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + op_encode_change_info_maxsz)
		* sizeof(__be32);
}

static inline u32 nfsd4_rename_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + op_encode_change_info_maxsz
		+ op_encode_change_info_maxsz) * sizeof(__be32);
}

static inline u32 nfsd4_sequence_rsize(struct svc_rqst *rqstp,
				       struct nfsd4_op *op)
{
	return (op_encode_hdr_size
		+ XDR_QUADLEN(NFS4_MAX_SESSIONID_LEN) + 5) * sizeof(__be32);
}

static inline u32 nfsd4_setattr_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + nfs4_fattr_bitmap_maxsz) * sizeof(__be32);
}

static inline u32 nfsd4_setclientid_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + 2 + XDR_QUADLEN(NFS4_VERIFIER_SIZE)) *
								sizeof(__be32);
}

static inline u32 nfsd4_write_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + 2 + op_encode_verifier_maxsz) * sizeof(__be32);
}

static inline u32 nfsd4_exchange_id_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + 2 + 1 + /* eir_clientid, eir_sequenceid */\
		1 + 1 + /* eir_flags, spr_how */\
		4 + /* spo_must_enforce & _allow with bitmap */\
		2 + /*eir_server_owner.so_minor_id */\
		/* eir_server_owner.so_major_id<> */\
		XDR_QUADLEN(NFS4_OPAQUE_LIMIT) + 1 +\
		/* eir_server_scope<> */\
		XDR_QUADLEN(NFS4_OPAQUE_LIMIT) + 1 +\
		1 + /* eir_server_impl_id array length */\
		0 /* ignored eir_server_impl_id contents */) * sizeof(__be32);
}

static inline u32 nfsd4_bind_conn_to_session_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + \
		XDR_QUADLEN(NFS4_MAX_SESSIONID_LEN) + /* bctsr_sessid */\
		2 /* bctsr_dir, use_conn_in_rdma_mode */) * sizeof(__be32);
}

static inline u32 nfsd4_create_session_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size + \
		XDR_QUADLEN(NFS4_MAX_SESSIONID_LEN) + /* sessionid */\
		2 + /* csr_sequence, csr_flags */\
		op_encode_channel_attrs_maxsz + \
		op_encode_channel_attrs_maxsz) * sizeof(__be32);
}

#ifdef CONFIG_NFSD_PNFS
/*
 * At this stage we don't really know what layout driver will handle the request,
 * so we need to define an arbitrary upper bound here.
 */
#define MAX_LAYOUT_SIZE		128
static inline u32 nfsd4_layoutget_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size +
		1 /* logr_return_on_close */ +
		op_encode_stateid_maxsz +
		1 /* nr of layouts */ +
		MAX_LAYOUT_SIZE) * sizeof(__be32);
}

static inline u32 nfsd4_layoutcommit_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size +
		1 /* locr_newsize */ +
		2 /* ns_size */) * sizeof(__be32);
}

static inline u32 nfsd4_layoutreturn_rsize(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	return (op_encode_hdr_size +
		1 /* lrs_stateid */ +
		op_encode_stateid_maxsz) * sizeof(__be32);
}
#endif /* CONFIG_NFSD_PNFS */

static struct nfsd4_operation nfsd4_ops[] = {
	[OP_ACCESS] = {
		.op_func = (nfsd4op_func)nfsd4_access,
		.op_name = "OP_ACCESS",
	},
	[OP_CLOSE] = {
		.op_func = (nfsd4op_func)nfsd4_close,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_CLOSE",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_status_stateid_rsize,
		.op_get_currentstateid = (stateid_getter)nfsd4_get_closestateid,
		.op_set_currentstateid = (stateid_setter)nfsd4_set_closestateid,
	},
	[OP_COMMIT] = {
		.op_func = (nfsd4op_func)nfsd4_commit,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_COMMIT",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_commit_rsize,
	},
	[OP_CREATE] = {
		.op_func = (nfsd4op_func)nfsd4_create,
		.op_flags = OP_MODIFIES_SOMETHING | OP_CACHEME | OP_CLEAR_STATEID,
		.op_name = "OP_CREATE",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_create_rsize,
	},
	[OP_DELEGRETURN] = {
		.op_func = (nfsd4op_func)nfsd4_delegreturn,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_DELEGRETURN",
		.op_rsize_bop = nfsd4_only_status_rsize,
		.op_get_currentstateid = (stateid_getter)nfsd4_get_delegreturnstateid,
	},
	[OP_GETATTR] = {
		.op_func = (nfsd4op_func)nfsd4_getattr,
		.op_flags = ALLOWED_ON_ABSENT_FS,
		.op_rsize_bop = nfsd4_getattr_rsize,
		.op_name = "OP_GETATTR",
	},
	[OP_GETFH] = {
		.op_func = (nfsd4op_func)nfsd4_getfh,
		.op_name = "OP_GETFH",
	},
	[OP_LINK] = {
		.op_func = (nfsd4op_func)nfsd4_link,
		.op_flags = ALLOWED_ON_ABSENT_FS | OP_MODIFIES_SOMETHING
				| OP_CACHEME,
		.op_name = "OP_LINK",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_link_rsize,
	},
	[OP_LOCK] = {
		.op_func = (nfsd4op_func)nfsd4_lock,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_LOCK",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_lock_rsize,
		.op_set_currentstateid = (stateid_setter)nfsd4_set_lockstateid,
	},
	[OP_LOCKT] = {
		.op_func = (nfsd4op_func)nfsd4_lockt,
		.op_name = "OP_LOCKT",
	},
	[OP_LOCKU] = {
		.op_func = (nfsd4op_func)nfsd4_locku,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_LOCKU",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_status_stateid_rsize,
		.op_get_currentstateid = (stateid_getter)nfsd4_get_lockustateid,
	},
	[OP_LOOKUP] = {
		.op_func = (nfsd4op_func)nfsd4_lookup,
		.op_flags = OP_HANDLES_WRONGSEC | OP_CLEAR_STATEID,
		.op_name = "OP_LOOKUP",
	},
	[OP_LOOKUPP] = {
		.op_func = (nfsd4op_func)nfsd4_lookupp,
		.op_flags = OP_HANDLES_WRONGSEC | OP_CLEAR_STATEID,
		.op_name = "OP_LOOKUPP",
	},
	[OP_NVERIFY] = {
		.op_func = (nfsd4op_func)nfsd4_nverify,
		.op_name = "OP_NVERIFY",
	},
	[OP_OPEN] = {
		.op_func = (nfsd4op_func)nfsd4_open,
		.op_flags = OP_HANDLES_WRONGSEC | OP_MODIFIES_SOMETHING,
		.op_name = "OP_OPEN",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_open_rsize,
		.op_set_currentstateid = (stateid_setter)nfsd4_set_openstateid,
	},
	[OP_OPEN_CONFIRM] = {
		.op_func = (nfsd4op_func)nfsd4_open_confirm,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_OPEN_CONFIRM",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_status_stateid_rsize,
	},
	[OP_OPEN_DOWNGRADE] = {
		.op_func = (nfsd4op_func)nfsd4_open_downgrade,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_OPEN_DOWNGRADE",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_status_stateid_rsize,
		.op_get_currentstateid = (stateid_getter)nfsd4_get_opendowngradestateid,
		.op_set_currentstateid = (stateid_setter)nfsd4_set_opendowngradestateid,
	},
	[OP_PUTFH] = {
		.op_func = (nfsd4op_func)nfsd4_putfh,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_ON_ABSENT_FS
				| OP_IS_PUTFH_LIKE | OP_CLEAR_STATEID,
		.op_name = "OP_PUTFH",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_PUTPUBFH] = {
		.op_func = (nfsd4op_func)nfsd4_putrootfh,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_ON_ABSENT_FS
				| OP_IS_PUTFH_LIKE | OP_CLEAR_STATEID,
		.op_name = "OP_PUTPUBFH",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_PUTROOTFH] = {
		.op_func = (nfsd4op_func)nfsd4_putrootfh,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_ON_ABSENT_FS
				| OP_IS_PUTFH_LIKE | OP_CLEAR_STATEID,
		.op_name = "OP_PUTROOTFH",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_READ] = {
		.op_func = (nfsd4op_func)nfsd4_read,
		.op_name = "OP_READ",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_read_rsize,
		.op_get_currentstateid = (stateid_getter)nfsd4_get_readstateid,
	},
	[OP_READDIR] = {
		.op_func = (nfsd4op_func)nfsd4_readdir,
		.op_name = "OP_READDIR",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_readdir_rsize,
	},
	[OP_READLINK] = {
		.op_func = (nfsd4op_func)nfsd4_readlink,
		.op_name = "OP_READLINK",
	},
	[OP_REMOVE] = {
		.op_func = (nfsd4op_func)nfsd4_remove,
		.op_flags = OP_MODIFIES_SOMETHING | OP_CACHEME,
		.op_name = "OP_REMOVE",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_remove_rsize,
	},
	[OP_RENAME] = {
		.op_func = (nfsd4op_func)nfsd4_rename,
		.op_flags = OP_MODIFIES_SOMETHING | OP_CACHEME,
		.op_name = "OP_RENAME",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_rename_rsize,
	},
	[OP_RENEW] = {
		.op_func = (nfsd4op_func)nfsd4_renew,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_ON_ABSENT_FS
				| OP_MODIFIES_SOMETHING,
		.op_name = "OP_RENEW",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,

	},
	[OP_RESTOREFH] = {
		.op_func = (nfsd4op_func)nfsd4_restorefh,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_ON_ABSENT_FS
				| OP_IS_PUTFH_LIKE | OP_MODIFIES_SOMETHING,
		.op_name = "OP_RESTOREFH",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_SAVEFH] = {
		.op_func = (nfsd4op_func)nfsd4_savefh,
		.op_flags = OP_HANDLES_WRONGSEC | OP_MODIFIES_SOMETHING,
		.op_name = "OP_SAVEFH",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_SECINFO] = {
		.op_func = (nfsd4op_func)nfsd4_secinfo,
		.op_flags = OP_HANDLES_WRONGSEC,
		.op_name = "OP_SECINFO",
	},
	[OP_SETATTR] = {
		.op_func = (nfsd4op_func)nfsd4_setattr,
		.op_name = "OP_SETATTR",
		.op_flags = OP_MODIFIES_SOMETHING | OP_CACHEME,
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_setattr_rsize,
		.op_get_currentstateid = (stateid_getter)nfsd4_get_setattrstateid,
	},
	[OP_SETCLIENTID] = {
		.op_func = (nfsd4op_func)nfsd4_setclientid,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_ON_ABSENT_FS
				| OP_MODIFIES_SOMETHING | OP_CACHEME,
		.op_name = "OP_SETCLIENTID",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_setclientid_rsize,
	},
	[OP_SETCLIENTID_CONFIRM] = {
		.op_func = (nfsd4op_func)nfsd4_setclientid_confirm,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_ON_ABSENT_FS
				| OP_MODIFIES_SOMETHING | OP_CACHEME,
		.op_name = "OP_SETCLIENTID_CONFIRM",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_VERIFY] = {
		.op_func = (nfsd4op_func)nfsd4_verify,
		.op_name = "OP_VERIFY",
	},
	[OP_WRITE] = {
		.op_func = (nfsd4op_func)nfsd4_write,
		.op_flags = OP_MODIFIES_SOMETHING | OP_CACHEME,
		.op_name = "OP_WRITE",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_write_rsize,
		.op_get_currentstateid = (stateid_getter)nfsd4_get_writestateid,
	},
	[OP_RELEASE_LOCKOWNER] = {
		.op_func = (nfsd4op_func)nfsd4_release_lockowner,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_ON_ABSENT_FS
				| OP_MODIFIES_SOMETHING,
		.op_name = "OP_RELEASE_LOCKOWNER",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},

	/* NFSv4.1 operations */
	[OP_EXCHANGE_ID] = {
		.op_func = (nfsd4op_func)nfsd4_exchange_id,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_AS_FIRST_OP
				| OP_MODIFIES_SOMETHING,
		.op_name = "OP_EXCHANGE_ID",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_exchange_id_rsize,
	},
	[OP_BACKCHANNEL_CTL] = {
		.op_func = (nfsd4op_func)nfsd4_backchannel_ctl,
		.op_flags = ALLOWED_WITHOUT_FH | OP_MODIFIES_SOMETHING,
		.op_name = "OP_BACKCHANNEL_CTL",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_BIND_CONN_TO_SESSION] = {
		.op_func = (nfsd4op_func)nfsd4_bind_conn_to_session,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_AS_FIRST_OP
				| OP_MODIFIES_SOMETHING,
		.op_name = "OP_BIND_CONN_TO_SESSION",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_bind_conn_to_session_rsize,
	},
	[OP_CREATE_SESSION] = {
		.op_func = (nfsd4op_func)nfsd4_create_session,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_AS_FIRST_OP
				| OP_MODIFIES_SOMETHING,
		.op_name = "OP_CREATE_SESSION",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_create_session_rsize,
	},
	[OP_DESTROY_SESSION] = {
		.op_func = (nfsd4op_func)nfsd4_destroy_session,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_AS_FIRST_OP
				| OP_MODIFIES_SOMETHING,
		.op_name = "OP_DESTROY_SESSION",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_SEQUENCE] = {
		.op_func = (nfsd4op_func)nfsd4_sequence,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_AS_FIRST_OP,
		.op_name = "OP_SEQUENCE",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_sequence_rsize,
	},
	[OP_DESTROY_CLIENTID] = {
		.op_func = (nfsd4op_func)nfsd4_destroy_clientid,
		.op_flags = ALLOWED_WITHOUT_FH | ALLOWED_AS_FIRST_OP
				| OP_MODIFIES_SOMETHING,
		.op_name = "OP_DESTROY_CLIENTID",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_RECLAIM_COMPLETE] = {
		.op_func = (nfsd4op_func)nfsd4_reclaim_complete,
		.op_flags = ALLOWED_WITHOUT_FH | OP_MODIFIES_SOMETHING,
		.op_name = "OP_RECLAIM_COMPLETE",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
	[OP_SECINFO_NO_NAME] = {
		.op_func = (nfsd4op_func)nfsd4_secinfo_no_name,
		.op_flags = OP_HANDLES_WRONGSEC,
		.op_name = "OP_SECINFO_NO_NAME",
	},
	[OP_TEST_STATEID] = {
		.op_func = (nfsd4op_func)nfsd4_test_stateid,
		.op_flags = ALLOWED_WITHOUT_FH,
		.op_name = "OP_TEST_STATEID",
	},
	[OP_FREE_STATEID] = {
		.op_func = (nfsd4op_func)nfsd4_free_stateid,
		.op_flags = ALLOWED_WITHOUT_FH | OP_MODIFIES_SOMETHING,
		.op_name = "OP_FREE_STATEID",
		.op_get_currentstateid = (stateid_getter)nfsd4_get_freestateid,
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_only_status_rsize,
	},
#ifdef CONFIG_NFSD_PNFS
	[OP_GETDEVICEINFO] = {
		.op_func = (nfsd4op_func)nfsd4_getdeviceinfo,
		.op_flags = ALLOWED_WITHOUT_FH,
		.op_name = "OP_GETDEVICEINFO",
	},
	[OP_LAYOUTGET] = {
		.op_func = (nfsd4op_func)nfsd4_layoutget,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_LAYOUTGET",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_layoutget_rsize,
	},
	[OP_LAYOUTCOMMIT] = {
		.op_func = (nfsd4op_func)nfsd4_layoutcommit,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_LAYOUTCOMMIT",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_layoutcommit_rsize,
	},
	[OP_LAYOUTRETURN] = {
		.op_func = (nfsd4op_func)nfsd4_layoutreturn,
		.op_flags = OP_MODIFIES_SOMETHING,
		.op_name = "OP_LAYOUTRETURN",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_layoutreturn_rsize,
	},
#endif /* CONFIG_NFSD_PNFS */

	/* NFSv4.2 operations */
	[OP_ALLOCATE] = {
		.op_func = (nfsd4op_func)nfsd4_allocate,
		.op_flags = OP_MODIFIES_SOMETHING | OP_CACHEME,
		.op_name = "OP_ALLOCATE",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_write_rsize,
	},
	[OP_DEALLOCATE] = {
		.op_func = (nfsd4op_func)nfsd4_deallocate,
		.op_flags = OP_MODIFIES_SOMETHING | OP_CACHEME,
		.op_name = "OP_DEALLOCATE",
		.op_rsize_bop = (nfsd4op_rsize)nfsd4_write_rsize,
	},
	[OP_SEEK] = {
		.op_func = (nfsd4op_func)nfsd4_seek,
		.op_name = "OP_SEEK",
	},
};

int nfsd4_max_reply(struct svc_rqst *rqstp, struct nfsd4_op *op)
{
	struct nfsd4_operation *opdesc;
	nfsd4op_rsize estimator;

	if (op->opnum == OP_ILLEGAL)
		return op_encode_hdr_size * sizeof(__be32);
	opdesc = OPDESC(op);
	estimator = opdesc->op_rsize_bop;
	return estimator ? estimator(rqstp, op) : PAGE_SIZE;
}

void warn_on_nonidempotent_op(struct nfsd4_op *op)
{
	if (OPDESC(op)->op_flags & OP_MODIFIES_SOMETHING) {
		pr_err("unable to encode reply to nonidempotent op %d (%s)\n",
			op->opnum, nfsd4_op_name(op->opnum));
		WARN_ON_ONCE(1);
	}
}

static const char *nfsd4_op_name(unsigned opnum)
{
	if (opnum < ARRAY_SIZE(nfsd4_ops))
		return nfsd4_ops[opnum].op_name;
	return "unknown_operation";
}

#define nfsd4_voidres			nfsd4_voidargs
struct nfsd4_voidargs { int dummy; };

static struct svc_procedure		nfsd_procedures4[2] = {
	[NFSPROC4_NULL] = {
		.pc_func = (svc_procfunc) nfsd4_proc_null,
		.pc_encode = (kxdrproc_t) nfs4svc_encode_voidres,
		.pc_argsize = sizeof(struct nfsd4_voidargs),
		.pc_ressize = sizeof(struct nfsd4_voidres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = 1,
	},
	[NFSPROC4_COMPOUND] = {
		.pc_func = (svc_procfunc) nfsd4_proc_compound,
		.pc_decode = (kxdrproc_t) nfs4svc_decode_compoundargs,
		.pc_encode = (kxdrproc_t) nfs4svc_encode_compoundres,
		.pc_argsize = sizeof(struct nfsd4_compoundargs),
		.pc_ressize = sizeof(struct nfsd4_compoundres),
		.pc_release = nfsd4_release_compoundargs,
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = NFSD_BUFSIZE/4,
	},
};

struct svc_version	nfsd_version4 = {
		.vs_vers	= 4,
		.vs_nproc	= 2,
		.vs_proc	= nfsd_procedures4,
		.vs_dispatch	= nfsd_dispatch,
		.vs_xdrsize	= NFS4_SVC_XDRSIZE,
		.vs_rpcb_optnl	= 1,
};

/*
 * Local variables:
 *  c-basic-offset: 8
 * End:
 */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs4proc.c */
/************************************************************/
/*
 *  Server-side XDR for NFSv4
 *
 *  Copyright (c) 2002 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Kendrick Smith <kmsmith@umich.edu>
 *  Andy Adamson   <andros@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// #include <linux/slab.h>
// #include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/utsname.h>
#include <linux/pagemap.h>
// #include <linux/sunrpc/svcauth_gss.h>
#include "../../inc/__fss.h"

// #include "idmap.h"
// #include "acl.h"
// #include "xdr4.h"
// #include "vfs.h"
// #include "state.h"
// #include "cache.h"
// #include "netns.h"
// #include "pnfs.h"

#ifdef CONFIG_NFSD_V4_SECURITY_LABEL
// #include <linux/security.h>
#endif


#define NFSDDBG_FACILITY		NFSDDBG_XDR

/*
 * As per referral draft, the fsid for a referral MUST be different from the fsid of the containing
 * directory in order to indicate to the client that a filesystem boundary is present
 * We use a fixed fsid for a referral
 */
#define NFS4_REFERRAL_FSID_MAJOR	0x8000000ULL
#define NFS4_REFERRAL_FSID_MINOR	0x8000000ULL

static __be32
check_filename(char *str, int len)
{
	int i;

	if (len == 0)
		return nfserr_inval;
	if (isdotent(str, len))
		return nfserr_badname;
	for (i = 0; i < len; i++)
		if (str[i] == '/')
			return nfserr_badname;
	return 0;
}

#define DECODE_HEAD				\
	__be32 *p;				\
	__be32 status
#define DECODE_TAIL				\
	status = 0;				\
out:						\
	return status;				\
xdr_error:					\
	dprintk("NFSD: xdr error (%s:%d)\n",	\
			__FILE__, __LINE__);	\
	status = nfserr_bad_xdr;		\
	goto out

#define READMEM(x,nbytes) do {			\
	x = (char *)p;				\
	p += XDR_QUADLEN(nbytes);		\
} while (0)
#define SAVEMEM(x,nbytes) do {			\
	if (!(x = (p==argp->tmp || p == argp->tmpp) ? \
 		savemem(argp, p, nbytes) :	\
 		(char *)p)) {			\
		dprintk("NFSD: xdr error (%s:%d)\n", \
				__FILE__, __LINE__); \
		goto xdr_error;			\
		}				\
	p += XDR_QUADLEN(nbytes);		\
} while (0)
#define COPYMEM(x,nbytes) do {			\
	memcpy((x), p, nbytes);			\
	p += XDR_QUADLEN(nbytes);		\
} while (0)

/* READ_BUF, read_buf(): nbytes must be <= PAGE_SIZE */
#define READ_BUF(nbytes)  do {			\
	if (nbytes <= (u32)((char *)argp->end - (char *)argp->p)) {	\
		p = argp->p;			\
		argp->p += XDR_QUADLEN(nbytes);	\
	} else if (!(p = read_buf(argp, nbytes))) { \
		dprintk("NFSD: xdr error (%s:%d)\n", \
				__FILE__, __LINE__); \
		goto xdr_error;			\
	}					\
} while (0)

static void next_decode_page(struct nfsd4_compoundargs *argp)
{
	argp->p = page_address(argp->pagelist[0]);
	argp->pagelist++;
	if (argp->pagelen < PAGE_SIZE) {
		argp->end = argp->p + (argp->pagelen>>2);
		argp->pagelen = 0;
	} else {
		argp->end = argp->p + (PAGE_SIZE>>2);
		argp->pagelen -= PAGE_SIZE;
	}
}

static __be32 *read_buf(struct nfsd4_compoundargs *argp, u32 nbytes)
{
	/* We want more bytes than seem to be available.
	 * Maybe we need a new page, maybe we have just run out
	 */
	unsigned int avail = (char *)argp->end - (char *)argp->p;
	__be32 *p;
	if (avail + argp->pagelen < nbytes)
		return NULL;
	if (avail + PAGE_SIZE < nbytes) /* need more than a page !! */
		return NULL;
	/* ok, we can do it with the current plus the next page */
	if (nbytes <= sizeof(argp->tmp))
		p = argp->tmp;
	else {
		kfree(argp->tmpp);
		p = argp->tmpp = kmalloc(nbytes, GFP_KERNEL);
		if (!p)
			return NULL;
		
	}
	/*
	 * The following memcpy is safe because read_buf is always
	 * called with nbytes > avail, and the two cases above both
	 * guarantee p points to at least nbytes bytes.
	 */
	memcpy(p, argp->p, avail);
	next_decode_page(argp);
	memcpy(((char*)p)+avail, argp->p, (nbytes - avail));
	argp->p += XDR_QUADLEN(nbytes - avail);
	return p;
}

static int zero_clientid(clientid_t *clid)
{
	return (clid->cl_boot == 0) && (clid->cl_id == 0);
}

/**
 * svcxdr_tmpalloc - allocate memory to be freed after compound processing
 * @argp: NFSv4 compound argument structure
 * @p: pointer to be freed (with kfree())
 *
 * Marks @p to be freed when processing the compound operation
 * described in @argp finishes.
 */
static void *
svcxdr_tmpalloc(struct nfsd4_compoundargs *argp, u32 len)
{
	struct svcxdr_tmpbuf *tb;

	tb = kmalloc(sizeof(*tb) + len, GFP_KERNEL);
	if (!tb)
		return NULL;
	tb->next = argp->to_free;
	argp->to_free = tb;
	return tb->buf;
}

/*
 * For xdr strings that need to be passed to other kernel api's
 * as null-terminated strings.
 *
 * Note null-terminating in place usually isn't safe since the
 * buffer might end on a page boundary.
 */
static char *
svcxdr_dupstr(struct nfsd4_compoundargs *argp, void *buf, u32 len)
{
	char *p = svcxdr_tmpalloc(argp, len + 1);

	if (!p)
		return NULL;
	memcpy(p, buf, len);
	p[len] = '\0';
	return p;
}

/**
 * savemem - duplicate a chunk of memory for later processing
 * @argp: NFSv4 compound argument structure to be freed with
 * @p: pointer to be duplicated
 * @nbytes: length to be duplicated
 *
 * Returns a pointer to a copy of @nbytes bytes of memory at @p
 * that are preserved until processing of the NFSv4 compound
 * operation described by @argp finishes.
 */
static char *savemem(struct nfsd4_compoundargs *argp, __be32 *p, int nbytes)
{
	void *ret;

	ret = svcxdr_tmpalloc(argp, nbytes);
	if (!ret)
		return NULL;
	memcpy(ret, p, nbytes);
	return ret;
}

/*
 * We require the high 32 bits of 'seconds' to be 0, and
 * we ignore all 32 bits of 'nseconds'.
 */
static __be32
nfsd4_decode_time(struct nfsd4_compoundargs *argp, struct timespec *tv)
{
	DECODE_HEAD;
	u64 sec;

	READ_BUF(12);
	p = xdr_decode_hyper(p, &sec);
	tv->tv_sec = sec;
	tv->tv_nsec = be32_to_cpup(p++);
	if (tv->tv_nsec >= (u32)1000000000)
		return nfserr_inval;

	DECODE_TAIL;
}

static __be32
nfsd4_decode_bitmap(struct nfsd4_compoundargs *argp, u32 *bmval)
{
	u32 bmlen;
	DECODE_HEAD;

	bmval[0] = 0;
	bmval[1] = 0;
	bmval[2] = 0;

	READ_BUF(4);
	bmlen = be32_to_cpup(p++);
	if (bmlen > 1000)
		goto xdr_error;

	READ_BUF(bmlen << 2);
	if (bmlen > 0)
		bmval[0] = be32_to_cpup(p++);
	if (bmlen > 1)
		bmval[1] = be32_to_cpup(p++);
	if (bmlen > 2)
		bmval[2] = be32_to_cpup(p++);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_fattr(struct nfsd4_compoundargs *argp, u32 *bmval,
		   struct iattr *iattr, struct nfs4_acl **acl,
		   struct xdr_netobj *label)
{
	int expected_len, len = 0;
	u32 dummy32;
	char *buf;

	DECODE_HEAD;
	iattr->ia_valid = 0;
	if ((status = nfsd4_decode_bitmap(argp, bmval)))
		return status;

	READ_BUF(4);
	expected_len = be32_to_cpup(p++);

	if (bmval[0] & FATTR4_WORD0_SIZE) {
		READ_BUF(8);
		len += 8;
		p = xdr_decode_hyper(p, &iattr->ia_size);
		iattr->ia_valid |= ATTR_SIZE;
	}
	if (bmval[0] & FATTR4_WORD0_ACL) {
		u32 nace;
		struct nfs4_ace *ace;

		READ_BUF(4); len += 4;
		nace = be32_to_cpup(p++);

		if (nace > NFS4_ACL_MAX)
			return nfserr_fbig;

		*acl = svcxdr_tmpalloc(argp, nfs4_acl_bytes(nace));
		if (*acl == NULL)
			return nfserr_jukebox;

		(*acl)->naces = nace;
		for (ace = (*acl)->aces; ace < (*acl)->aces + nace; ace++) {
			READ_BUF(16); len += 16;
			ace->type = be32_to_cpup(p++);
			ace->flag = be32_to_cpup(p++);
			ace->access_mask = be32_to_cpup(p++);
			dummy32 = be32_to_cpup(p++);
			READ_BUF(dummy32);
			len += XDR_QUADLEN(dummy32) << 2;
			READMEM(buf, dummy32);
			ace->whotype = nfs4_acl_get_whotype(buf, dummy32);
			status = nfs_ok;
			if (ace->whotype != NFS4_ACL_WHO_NAMED)
				;
			else if (ace->flag & NFS4_ACE_IDENTIFIER_GROUP)
				status = nfsd_map_name_to_gid(argp->rqstp,
						buf, dummy32, &ace->who_gid);
			else
				status = nfsd_map_name_to_uid(argp->rqstp,
						buf, dummy32, &ace->who_uid);
			if (status)
				return status;
		}
	} else
		*acl = NULL;
	if (bmval[1] & FATTR4_WORD1_MODE) {
		READ_BUF(4);
		len += 4;
		iattr->ia_mode = be32_to_cpup(p++);
		iattr->ia_mode &= (S_IFMT | S_IALLUGO);
		iattr->ia_valid |= ATTR_MODE;
	}
	if (bmval[1] & FATTR4_WORD1_OWNER) {
		READ_BUF(4);
		len += 4;
		dummy32 = be32_to_cpup(p++);
		READ_BUF(dummy32);
		len += (XDR_QUADLEN(dummy32) << 2);
		READMEM(buf, dummy32);
		if ((status = nfsd_map_name_to_uid(argp->rqstp, buf, dummy32, &iattr->ia_uid)))
			return status;
		iattr->ia_valid |= ATTR_UID;
	}
	if (bmval[1] & FATTR4_WORD1_OWNER_GROUP) {
		READ_BUF(4);
		len += 4;
		dummy32 = be32_to_cpup(p++);
		READ_BUF(dummy32);
		len += (XDR_QUADLEN(dummy32) << 2);
		READMEM(buf, dummy32);
		if ((status = nfsd_map_name_to_gid(argp->rqstp, buf, dummy32, &iattr->ia_gid)))
			return status;
		iattr->ia_valid |= ATTR_GID;
	}
	if (bmval[1] & FATTR4_WORD1_TIME_ACCESS_SET) {
		READ_BUF(4);
		len += 4;
		dummy32 = be32_to_cpup(p++);
		switch (dummy32) {
		case NFS4_SET_TO_CLIENT_TIME:
			len += 12;
			status = nfsd4_decode_time(argp, &iattr->ia_atime);
			if (status)
				return status;
			iattr->ia_valid |= (ATTR_ATIME | ATTR_ATIME_SET);
			break;
		case NFS4_SET_TO_SERVER_TIME:
			iattr->ia_valid |= ATTR_ATIME;
			break;
		default:
			goto xdr_error;
		}
	}
	if (bmval[1] & FATTR4_WORD1_TIME_MODIFY_SET) {
		READ_BUF(4);
		len += 4;
		dummy32 = be32_to_cpup(p++);
		switch (dummy32) {
		case NFS4_SET_TO_CLIENT_TIME:
			len += 12;
			status = nfsd4_decode_time(argp, &iattr->ia_mtime);
			if (status)
				return status;
			iattr->ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);
			break;
		case NFS4_SET_TO_SERVER_TIME:
			iattr->ia_valid |= ATTR_MTIME;
			break;
		default:
			goto xdr_error;
		}
	}

	label->len = 0;
#ifdef CONFIG_NFSD_V4_SECURITY_LABEL
	if (bmval[2] & FATTR4_WORD2_SECURITY_LABEL) {
		READ_BUF(4);
		len += 4;
		dummy32 = be32_to_cpup(p++); /* lfs: we don't use it */
		READ_BUF(4);
		len += 4;
		dummy32 = be32_to_cpup(p++); /* pi: we don't use it either */
		READ_BUF(4);
		len += 4;
		dummy32 = be32_to_cpup(p++);
		READ_BUF(dummy32);
		if (dummy32 > NFSD4_MAX_SEC_LABEL_LEN)
			return nfserr_badlabel;
		len += (XDR_QUADLEN(dummy32) << 2);
		READMEM(buf, dummy32);
		label->len = dummy32;
		label->data = svcxdr_dupstr(argp, buf, dummy32);
		if (!label->data)
			return nfserr_jukebox;
	}
#endif

	if (bmval[0] & ~NFSD_WRITEABLE_ATTRS_WORD0
	    || bmval[1] & ~NFSD_WRITEABLE_ATTRS_WORD1
	    || bmval[2] & ~NFSD_WRITEABLE_ATTRS_WORD2)
		READ_BUF(expected_len - len);
	else if (len != expected_len)
		goto xdr_error;

	DECODE_TAIL;
}

static __be32
nfsd4_decode_stateid(struct nfsd4_compoundargs *argp, stateid_t *sid)
{
	DECODE_HEAD;

	READ_BUF(sizeof(stateid_t));
	sid->si_generation = be32_to_cpup(p++);
	COPYMEM(&sid->si_opaque, sizeof(stateid_opaque_t));

	DECODE_TAIL;
}

static __be32
nfsd4_decode_access(struct nfsd4_compoundargs *argp, struct nfsd4_access *access)
{
	DECODE_HEAD;

	READ_BUF(4);
	access->ac_req_access = be32_to_cpup(p++);

	DECODE_TAIL;
}

static __be32 nfsd4_decode_cb_sec(struct nfsd4_compoundargs *argp, struct nfsd4_cb_sec *cbs)
{
	DECODE_HEAD;
	u32 dummy, uid, gid;
	char *machine_name;
	int i;
	int nr_secflavs;

	/* callback_sec_params4 */
	READ_BUF(4);
	nr_secflavs = be32_to_cpup(p++);
	if (nr_secflavs)
		cbs->flavor = (u32)(-1);
	else
		/* Is this legal? Be generous, take it to mean AUTH_NONE: */
		cbs->flavor = 0;
	for (i = 0; i < nr_secflavs; ++i) {
		READ_BUF(4);
		dummy = be32_to_cpup(p++);
		switch (dummy) {
		case RPC_AUTH_NULL:
			/* Nothing to read */
			if (cbs->flavor == (u32)(-1))
				cbs->flavor = RPC_AUTH_NULL;
			break;
		case RPC_AUTH_UNIX:
			READ_BUF(8);
			/* stamp */
			dummy = be32_to_cpup(p++);

			/* machine name */
			dummy = be32_to_cpup(p++);
			READ_BUF(dummy);
			SAVEMEM(machine_name, dummy);

			/* uid, gid */
			READ_BUF(8);
			uid = be32_to_cpup(p++);
			gid = be32_to_cpup(p++);

			/* more gids */
			READ_BUF(4);
			dummy = be32_to_cpup(p++);
			READ_BUF(dummy * 4);
			if (cbs->flavor == (u32)(-1)) {
				kuid_t kuid = make_kuid(&init_user_ns, uid);
				kgid_t kgid = make_kgid(&init_user_ns, gid);
				if (uid_valid(kuid) && gid_valid(kgid)) {
					cbs->uid = kuid;
					cbs->gid = kgid;
					cbs->flavor = RPC_AUTH_UNIX;
				} else {
					dprintk("RPC_AUTH_UNIX with invalid"
						"uid or gid ignoring!\n");
				}
			}
			break;
		case RPC_AUTH_GSS:
			dprintk("RPC_AUTH_GSS callback secflavor "
				"not supported!\n");
			READ_BUF(8);
			/* gcbp_service */
			dummy = be32_to_cpup(p++);
			/* gcbp_handle_from_server */
			dummy = be32_to_cpup(p++);
			READ_BUF(dummy);
			p += XDR_QUADLEN(dummy);
			/* gcbp_handle_from_client */
			READ_BUF(4);
			dummy = be32_to_cpup(p++);
			READ_BUF(dummy);
			break;
		default:
			dprintk("Illegal callback secflavor\n");
			return nfserr_inval;
		}
	}
	DECODE_TAIL;
}

static __be32 nfsd4_decode_backchannel_ctl(struct nfsd4_compoundargs *argp, struct nfsd4_backchannel_ctl *bc)
{
	DECODE_HEAD;

	READ_BUF(4);
	bc->bc_cb_program = be32_to_cpup(p++);
	nfsd4_decode_cb_sec(argp, &bc->bc_cb_sec);

	DECODE_TAIL;
}

static __be32 nfsd4_decode_bind_conn_to_session(struct nfsd4_compoundargs *argp, struct nfsd4_bind_conn_to_session *bcts)
{
	DECODE_HEAD;

	READ_BUF(NFS4_MAX_SESSIONID_LEN + 8);
	COPYMEM(bcts->sessionid.data, NFS4_MAX_SESSIONID_LEN);
	bcts->dir = be32_to_cpup(p++);
	/* XXX: skipping ctsa_use_conn_in_rdma_mode.  Perhaps Tom Tucker
	 * could help us figure out we should be using it. */
	DECODE_TAIL;
}

static __be32
nfsd4_decode_close(struct nfsd4_compoundargs *argp, struct nfsd4_close *close)
{
	DECODE_HEAD;

	READ_BUF(4);
	close->cl_seqid = be32_to_cpup(p++);
	return nfsd4_decode_stateid(argp, &close->cl_stateid);

	DECODE_TAIL;
}


static __be32
nfsd4_decode_commit(struct nfsd4_compoundargs *argp, struct nfsd4_commit *commit)
{
	DECODE_HEAD;

	READ_BUF(12);
	p = xdr_decode_hyper(p, &commit->co_offset);
	commit->co_count = be32_to_cpup(p++);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_create(struct nfsd4_compoundargs *argp, struct nfsd4_create *create)
{
	DECODE_HEAD;

	READ_BUF(4);
	create->cr_type = be32_to_cpup(p++);
	switch (create->cr_type) {
	case NF4LNK:
		READ_BUF(4);
		create->cr_datalen = be32_to_cpup(p++);
		READ_BUF(create->cr_datalen);
		create->cr_data = svcxdr_dupstr(argp, p, create->cr_datalen);
		if (!create->cr_data)
			return nfserr_jukebox;
		break;
	case NF4BLK:
	case NF4CHR:
		READ_BUF(8);
		create->cr_specdata1 = be32_to_cpup(p++);
		create->cr_specdata2 = be32_to_cpup(p++);
		break;
	case NF4SOCK:
	case NF4FIFO:
	case NF4DIR:
	default:
		break;
	}

	READ_BUF(4);
	create->cr_namelen = be32_to_cpup(p++);
	READ_BUF(create->cr_namelen);
	SAVEMEM(create->cr_name, create->cr_namelen);
	if ((status = check_filename(create->cr_name, create->cr_namelen)))
		return status;

	status = nfsd4_decode_fattr(argp, create->cr_bmval, &create->cr_iattr,
				    &create->cr_acl, &create->cr_label);
	if (status)
		goto out;

	DECODE_TAIL;
}

static inline __be32
nfsd4_decode_delegreturn(struct nfsd4_compoundargs *argp, struct nfsd4_delegreturn *dr)
{
	return nfsd4_decode_stateid(argp, &dr->dr_stateid);
}

static inline __be32
nfsd4_decode_getattr(struct nfsd4_compoundargs *argp, struct nfsd4_getattr *getattr)
{
	return nfsd4_decode_bitmap(argp, getattr->ga_bmval);
}

static __be32
nfsd4_decode_link(struct nfsd4_compoundargs *argp, struct nfsd4_link *link)
{
	DECODE_HEAD;

	READ_BUF(4);
	link->li_namelen = be32_to_cpup(p++);
	READ_BUF(link->li_namelen);
	SAVEMEM(link->li_name, link->li_namelen);
	if ((status = check_filename(link->li_name, link->li_namelen)))
		return status;

	DECODE_TAIL;
}

static __be32
nfsd4_decode_lock(struct nfsd4_compoundargs *argp, struct nfsd4_lock *lock)
{
	DECODE_HEAD;

	/*
	* type, reclaim(boolean), offset, length, new_lock_owner(boolean)
	*/
	READ_BUF(28);
	lock->lk_type = be32_to_cpup(p++);
	if ((lock->lk_type < NFS4_READ_LT) || (lock->lk_type > NFS4_WRITEW_LT))
		goto xdr_error;
	lock->lk_reclaim = be32_to_cpup(p++);
	p = xdr_decode_hyper(p, &lock->lk_offset);
	p = xdr_decode_hyper(p, &lock->lk_length);
	lock->lk_is_new = be32_to_cpup(p++);

	if (lock->lk_is_new) {
		READ_BUF(4);
		lock->lk_new_open_seqid = be32_to_cpup(p++);
		status = nfsd4_decode_stateid(argp, &lock->lk_new_open_stateid);
		if (status)
			return status;
		READ_BUF(8 + sizeof(clientid_t));
		lock->lk_new_lock_seqid = be32_to_cpup(p++);
		COPYMEM(&lock->lk_new_clientid, sizeof(clientid_t));
		lock->lk_new_owner.len = be32_to_cpup(p++);
		READ_BUF(lock->lk_new_owner.len);
		READMEM(lock->lk_new_owner.data, lock->lk_new_owner.len);
	} else {
		status = nfsd4_decode_stateid(argp, &lock->lk_old_lock_stateid);
		if (status)
			return status;
		READ_BUF(4);
		lock->lk_old_lock_seqid = be32_to_cpup(p++);
	}

	DECODE_TAIL;
}

static __be32
nfsd4_decode_lockt(struct nfsd4_compoundargs *argp, struct nfsd4_lockt *lockt)
{
	DECODE_HEAD;
		        
	READ_BUF(32);
	lockt->lt_type = be32_to_cpup(p++);
	if((lockt->lt_type < NFS4_READ_LT) || (lockt->lt_type > NFS4_WRITEW_LT))
		goto xdr_error;
	p = xdr_decode_hyper(p, &lockt->lt_offset);
	p = xdr_decode_hyper(p, &lockt->lt_length);
	COPYMEM(&lockt->lt_clientid, 8);
	lockt->lt_owner.len = be32_to_cpup(p++);
	READ_BUF(lockt->lt_owner.len);
	READMEM(lockt->lt_owner.data, lockt->lt_owner.len);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_locku(struct nfsd4_compoundargs *argp, struct nfsd4_locku *locku)
{
	DECODE_HEAD;

	READ_BUF(8);
	locku->lu_type = be32_to_cpup(p++);
	if ((locku->lu_type < NFS4_READ_LT) || (locku->lu_type > NFS4_WRITEW_LT))
		goto xdr_error;
	locku->lu_seqid = be32_to_cpup(p++);
	status = nfsd4_decode_stateid(argp, &locku->lu_stateid);
	if (status)
		return status;
	READ_BUF(16);
	p = xdr_decode_hyper(p, &locku->lu_offset);
	p = xdr_decode_hyper(p, &locku->lu_length);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_lookup(struct nfsd4_compoundargs *argp, struct nfsd4_lookup *lookup)
{
	DECODE_HEAD;

	READ_BUF(4);
	lookup->lo_len = be32_to_cpup(p++);
	READ_BUF(lookup->lo_len);
	SAVEMEM(lookup->lo_name, lookup->lo_len);
	if ((status = check_filename(lookup->lo_name, lookup->lo_len)))
		return status;

	DECODE_TAIL;
}

static __be32 nfsd4_decode_share_access(struct nfsd4_compoundargs *argp, u32 *share_access, u32 *deleg_want, u32 *deleg_when)
{
	__be32 *p;
	u32 w;

	READ_BUF(4);
	w = be32_to_cpup(p++);
	*share_access = w & NFS4_SHARE_ACCESS_MASK;
	*deleg_want = w & NFS4_SHARE_WANT_MASK;
	if (deleg_when)
		*deleg_when = w & NFS4_SHARE_WHEN_MASK;

	switch (w & NFS4_SHARE_ACCESS_MASK) {
	case NFS4_SHARE_ACCESS_READ:
	case NFS4_SHARE_ACCESS_WRITE:
	case NFS4_SHARE_ACCESS_BOTH:
		break;
	default:
		return nfserr_bad_xdr;
	}
	w &= ~NFS4_SHARE_ACCESS_MASK;
	if (!w)
		return nfs_ok;
	if (!argp->minorversion)
		return nfserr_bad_xdr;
	switch (w & NFS4_SHARE_WANT_MASK) {
	case NFS4_SHARE_WANT_NO_PREFERENCE:
	case NFS4_SHARE_WANT_READ_DELEG:
	case NFS4_SHARE_WANT_WRITE_DELEG:
	case NFS4_SHARE_WANT_ANY_DELEG:
	case NFS4_SHARE_WANT_NO_DELEG:
	case NFS4_SHARE_WANT_CANCEL:
		break;
	default:
		return nfserr_bad_xdr;
	}
	w &= ~NFS4_SHARE_WANT_MASK;
	if (!w)
		return nfs_ok;

	if (!deleg_when)	/* open_downgrade */
		return nfserr_inval;
	switch (w) {
	case NFS4_SHARE_SIGNAL_DELEG_WHEN_RESRC_AVAIL:
	case NFS4_SHARE_PUSH_DELEG_WHEN_UNCONTENDED:
	case (NFS4_SHARE_SIGNAL_DELEG_WHEN_RESRC_AVAIL |
	      NFS4_SHARE_PUSH_DELEG_WHEN_UNCONTENDED):
		return nfs_ok;
	}
xdr_error:
	return nfserr_bad_xdr;
}

static __be32 nfsd4_decode_share_deny(struct nfsd4_compoundargs *argp, u32 *x)
{
	__be32 *p;

	READ_BUF(4);
	*x = be32_to_cpup(p++);
	/* Note: unlinke access bits, deny bits may be zero. */
	if (*x & ~NFS4_SHARE_DENY_BOTH)
		return nfserr_bad_xdr;
	return nfs_ok;
xdr_error:
	return nfserr_bad_xdr;
}

static __be32 nfsd4_decode_opaque(struct nfsd4_compoundargs *argp, struct xdr_netobj *o)
{
	__be32 *p;

	READ_BUF(4);
	o->len = be32_to_cpup(p++);

	if (o->len == 0 || o->len > NFS4_OPAQUE_LIMIT)
		return nfserr_bad_xdr;

	READ_BUF(o->len);
	SAVEMEM(o->data, o->len);
	return nfs_ok;
xdr_error:
	return nfserr_bad_xdr;
}

static __be32
nfsd4_decode_open(struct nfsd4_compoundargs *argp, struct nfsd4_open *open)
{
	DECODE_HEAD;
	u32 dummy;

	memset(open->op_bmval, 0, sizeof(open->op_bmval));
	open->op_iattr.ia_valid = 0;
	open->op_openowner = NULL;

	open->op_xdr_error = 0;
	/* seqid, share_access, share_deny, clientid, ownerlen */
	READ_BUF(4);
	open->op_seqid = be32_to_cpup(p++);
	/* decode, yet ignore deleg_when until supported */
	status = nfsd4_decode_share_access(argp, &open->op_share_access,
					   &open->op_deleg_want, &dummy);
	if (status)
		goto xdr_error;
	status = nfsd4_decode_share_deny(argp, &open->op_share_deny);
	if (status)
		goto xdr_error;
	READ_BUF(sizeof(clientid_t));
	COPYMEM(&open->op_clientid, sizeof(clientid_t));
	status = nfsd4_decode_opaque(argp, &open->op_owner);
	if (status)
		goto xdr_error;
	READ_BUF(4);
	open->op_create = be32_to_cpup(p++);
	switch (open->op_create) {
	case NFS4_OPEN_NOCREATE:
		break;
	case NFS4_OPEN_CREATE:
		READ_BUF(4);
		open->op_createmode = be32_to_cpup(p++);
		switch (open->op_createmode) {
		case NFS4_CREATE_UNCHECKED:
		case NFS4_CREATE_GUARDED:
			status = nfsd4_decode_fattr(argp, open->op_bmval,
				&open->op_iattr, &open->op_acl, &open->op_label);
			if (status)
				goto out;
			break;
		case NFS4_CREATE_EXCLUSIVE:
			READ_BUF(NFS4_VERIFIER_SIZE);
			COPYMEM(open->op_verf.data, NFS4_VERIFIER_SIZE);
			break;
		case NFS4_CREATE_EXCLUSIVE4_1:
			if (argp->minorversion < 1)
				goto xdr_error;
			READ_BUF(NFS4_VERIFIER_SIZE);
			COPYMEM(open->op_verf.data, NFS4_VERIFIER_SIZE);
			status = nfsd4_decode_fattr(argp, open->op_bmval,
				&open->op_iattr, &open->op_acl, &open->op_label);
			if (status)
				goto out;
			break;
		default:
			goto xdr_error;
		}
		break;
	default:
		goto xdr_error;
	}

	/* open_claim */
	READ_BUF(4);
	open->op_claim_type = be32_to_cpup(p++);
	switch (open->op_claim_type) {
	case NFS4_OPEN_CLAIM_NULL:
	case NFS4_OPEN_CLAIM_DELEGATE_PREV:
		READ_BUF(4);
		open->op_fname.len = be32_to_cpup(p++);
		READ_BUF(open->op_fname.len);
		SAVEMEM(open->op_fname.data, open->op_fname.len);
		if ((status = check_filename(open->op_fname.data, open->op_fname.len)))
			return status;
		break;
	case NFS4_OPEN_CLAIM_PREVIOUS:
		READ_BUF(4);
		open->op_delegate_type = be32_to_cpup(p++);
		break;
	case NFS4_OPEN_CLAIM_DELEGATE_CUR:
		status = nfsd4_decode_stateid(argp, &open->op_delegate_stateid);
		if (status)
			return status;
		READ_BUF(4);
		open->op_fname.len = be32_to_cpup(p++);
		READ_BUF(open->op_fname.len);
		SAVEMEM(open->op_fname.data, open->op_fname.len);
		if ((status = check_filename(open->op_fname.data, open->op_fname.len)))
			return status;
		break;
	case NFS4_OPEN_CLAIM_FH:
	case NFS4_OPEN_CLAIM_DELEG_PREV_FH:
		if (argp->minorversion < 1)
			goto xdr_error;
		/* void */
		break;
	case NFS4_OPEN_CLAIM_DELEG_CUR_FH:
		if (argp->minorversion < 1)
			goto xdr_error;
		status = nfsd4_decode_stateid(argp, &open->op_delegate_stateid);
		if (status)
			return status;
		break;
	default:
		goto xdr_error;
	}

	DECODE_TAIL;
}

static __be32
nfsd4_decode_open_confirm(struct nfsd4_compoundargs *argp, struct nfsd4_open_confirm *open_conf)
{
	DECODE_HEAD;

	if (argp->minorversion >= 1)
		return nfserr_notsupp;

	status = nfsd4_decode_stateid(argp, &open_conf->oc_req_stateid);
	if (status)
		return status;
	READ_BUF(4);
	open_conf->oc_seqid = be32_to_cpup(p++);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_open_downgrade(struct nfsd4_compoundargs *argp, struct nfsd4_open_downgrade *open_down)
{
	DECODE_HEAD;
		    
	status = nfsd4_decode_stateid(argp, &open_down->od_stateid);
	if (status)
		return status;
	READ_BUF(4);
	open_down->od_seqid = be32_to_cpup(p++);
	status = nfsd4_decode_share_access(argp, &open_down->od_share_access,
					   &open_down->od_deleg_want, NULL);
	if (status)
		return status;
	status = nfsd4_decode_share_deny(argp, &open_down->od_share_deny);
	if (status)
		return status;
	DECODE_TAIL;
}

static __be32
nfsd4_decode_putfh(struct nfsd4_compoundargs *argp, struct nfsd4_putfh *putfh)
{
	DECODE_HEAD;

	READ_BUF(4);
	putfh->pf_fhlen = be32_to_cpup(p++);
	if (putfh->pf_fhlen > NFS4_FHSIZE)
		goto xdr_error;
	READ_BUF(putfh->pf_fhlen);
	SAVEMEM(putfh->pf_fhval, putfh->pf_fhlen);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_putpubfh(struct nfsd4_compoundargs *argp, void *p)
{
	if (argp->minorversion == 0)
		return nfs_ok;
	return nfserr_notsupp;
}

static __be32
nfsd4_decode_read(struct nfsd4_compoundargs *argp, struct nfsd4_read *read)
{
	DECODE_HEAD;

	status = nfsd4_decode_stateid(argp, &read->rd_stateid);
	if (status)
		return status;
	READ_BUF(12);
	p = xdr_decode_hyper(p, &read->rd_offset);
	read->rd_length = be32_to_cpup(p++);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_readdir(struct nfsd4_compoundargs *argp, struct nfsd4_readdir *readdir)
{
	DECODE_HEAD;

	READ_BUF(24);
	p = xdr_decode_hyper(p, &readdir->rd_cookie);
	COPYMEM(readdir->rd_verf.data, sizeof(readdir->rd_verf.data));
	readdir->rd_dircount = be32_to_cpup(p++);
	readdir->rd_maxcount = be32_to_cpup(p++);
	if ((status = nfsd4_decode_bitmap(argp, readdir->rd_bmval)))
		goto out;

	DECODE_TAIL;
}

static __be32
nfsd4_decode_remove(struct nfsd4_compoundargs *argp, struct nfsd4_remove *remove)
{
	DECODE_HEAD;

	READ_BUF(4);
	remove->rm_namelen = be32_to_cpup(p++);
	READ_BUF(remove->rm_namelen);
	SAVEMEM(remove->rm_name, remove->rm_namelen);
	if ((status = check_filename(remove->rm_name, remove->rm_namelen)))
		return status;

	DECODE_TAIL;
}

static __be32
nfsd4_decode_rename(struct nfsd4_compoundargs *argp, struct nfsd4_rename *rename)
{
	DECODE_HEAD;

	READ_BUF(4);
	rename->rn_snamelen = be32_to_cpup(p++);
	READ_BUF(rename->rn_snamelen + 4);
	SAVEMEM(rename->rn_sname, rename->rn_snamelen);
	rename->rn_tnamelen = be32_to_cpup(p++);
	READ_BUF(rename->rn_tnamelen);
	SAVEMEM(rename->rn_tname, rename->rn_tnamelen);
	if ((status = check_filename(rename->rn_sname, rename->rn_snamelen)))
		return status;
	if ((status = check_filename(rename->rn_tname, rename->rn_tnamelen)))
		return status;

	DECODE_TAIL;
}

static __be32
nfsd4_decode_renew(struct nfsd4_compoundargs *argp, clientid_t *clientid)
{
	DECODE_HEAD;

	if (argp->minorversion >= 1)
		return nfserr_notsupp;

	READ_BUF(sizeof(clientid_t));
	COPYMEM(clientid, sizeof(clientid_t));

	DECODE_TAIL;
}

static __be32
nfsd4_decode_secinfo(struct nfsd4_compoundargs *argp,
		     struct nfsd4_secinfo *secinfo)
{
	DECODE_HEAD;

	READ_BUF(4);
	secinfo->si_namelen = be32_to_cpup(p++);
	READ_BUF(secinfo->si_namelen);
	SAVEMEM(secinfo->si_name, secinfo->si_namelen);
	status = check_filename(secinfo->si_name, secinfo->si_namelen);
	if (status)
		return status;
	DECODE_TAIL;
}

static __be32
nfsd4_decode_secinfo_no_name(struct nfsd4_compoundargs *argp,
		     struct nfsd4_secinfo_no_name *sin)
{
	DECODE_HEAD;

	READ_BUF(4);
	sin->sin_style = be32_to_cpup(p++);
	DECODE_TAIL;
}

static __be32
nfsd4_decode_setattr(struct nfsd4_compoundargs *argp, struct nfsd4_setattr *setattr)
{
	__be32 status;

	status = nfsd4_decode_stateid(argp, &setattr->sa_stateid);
	if (status)
		return status;
	return nfsd4_decode_fattr(argp, setattr->sa_bmval, &setattr->sa_iattr,
				  &setattr->sa_acl, &setattr->sa_label);
}

static __be32
nfsd4_decode_setclientid(struct nfsd4_compoundargs *argp, struct nfsd4_setclientid *setclientid)
{
	DECODE_HEAD;

	if (argp->minorversion >= 1)
		return nfserr_notsupp;

	READ_BUF(NFS4_VERIFIER_SIZE);
	COPYMEM(setclientid->se_verf.data, NFS4_VERIFIER_SIZE);

	status = nfsd4_decode_opaque(argp, &setclientid->se_name);
	if (status)
		return nfserr_bad_xdr;
	READ_BUF(8);
	setclientid->se_callback_prog = be32_to_cpup(p++);
	setclientid->se_callback_netid_len = be32_to_cpup(p++);

	READ_BUF(setclientid->se_callback_netid_len + 4);
	SAVEMEM(setclientid->se_callback_netid_val, setclientid->se_callback_netid_len);
	setclientid->se_callback_addr_len = be32_to_cpup(p++);

	READ_BUF(setclientid->se_callback_addr_len + 4);
	SAVEMEM(setclientid->se_callback_addr_val, setclientid->se_callback_addr_len);
	setclientid->se_callback_ident = be32_to_cpup(p++);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_setclientid_confirm(struct nfsd4_compoundargs *argp, struct nfsd4_setclientid_confirm *scd_c)
{
	DECODE_HEAD;

	if (argp->minorversion >= 1)
		return nfserr_notsupp;

	READ_BUF(8 + NFS4_VERIFIER_SIZE);
	COPYMEM(&scd_c->sc_clientid, 8);
	COPYMEM(&scd_c->sc_confirm, NFS4_VERIFIER_SIZE);

	DECODE_TAIL;
}

/* Also used for NVERIFY */
static __be32
nfsd4_decode_verify(struct nfsd4_compoundargs *argp, struct nfsd4_verify *verify)
{
	DECODE_HEAD;

	if ((status = nfsd4_decode_bitmap(argp, verify->ve_bmval)))
		goto out;

	/* For convenience's sake, we compare raw xdr'd attributes in
	 * nfsd4_proc_verify */

	READ_BUF(4);
	verify->ve_attrlen = be32_to_cpup(p++);
	READ_BUF(verify->ve_attrlen);
	SAVEMEM(verify->ve_attrval, verify->ve_attrlen);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_write(struct nfsd4_compoundargs *argp, struct nfsd4_write *write)
{
	int avail;
	int len;
	DECODE_HEAD;

	status = nfsd4_decode_stateid(argp, &write->wr_stateid);
	if (status)
		return status;
	READ_BUF(16);
	p = xdr_decode_hyper(p, &write->wr_offset);
	write->wr_stable_how = be32_to_cpup(p++);
	if (write->wr_stable_how > 2)
		goto xdr_error;
	write->wr_buflen = be32_to_cpup(p++);

	/* Sorry .. no magic macros for this.. *
	 * READ_BUF(write->wr_buflen);
	 * SAVEMEM(write->wr_buf, write->wr_buflen);
	 */
	avail = (char*)argp->end - (char*)argp->p;
	if (avail + argp->pagelen < write->wr_buflen) {
		dprintk("NFSD: xdr error (%s:%d)\n",
				__FILE__, __LINE__);
		goto xdr_error;
	}
	write->wr_head.iov_base = p;
	write->wr_head.iov_len = avail;
	write->wr_pagelist = argp->pagelist;

	len = XDR_QUADLEN(write->wr_buflen) << 2;
	if (len >= avail) {
		int pages;

		len -= avail;

		pages = len >> PAGE_SHIFT;
		argp->pagelist += pages;
		argp->pagelen -= pages * PAGE_SIZE;
		len -= pages * PAGE_SIZE;

		argp->p = (__be32 *)page_address(argp->pagelist[0]);
		argp->pagelist++;
		argp->end = argp->p + XDR_QUADLEN(PAGE_SIZE);
	}
	argp->p += XDR_QUADLEN(len);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_release_lockowner(struct nfsd4_compoundargs *argp, struct nfsd4_release_lockowner *rlockowner)
{
	DECODE_HEAD;

	if (argp->minorversion >= 1)
		return nfserr_notsupp;

	READ_BUF(12);
	COPYMEM(&rlockowner->rl_clientid, sizeof(clientid_t));
	rlockowner->rl_owner.len = be32_to_cpup(p++);
	READ_BUF(rlockowner->rl_owner.len);
	READMEM(rlockowner->rl_owner.data, rlockowner->rl_owner.len);

	if (argp->minorversion && !zero_clientid(&rlockowner->rl_clientid))
		return nfserr_inval;
	DECODE_TAIL;
}

static __be32
nfsd4_decode_exchange_id(struct nfsd4_compoundargs *argp,
			 struct nfsd4_exchange_id *exid)
{
	int dummy, tmp;
	DECODE_HEAD;

	READ_BUF(NFS4_VERIFIER_SIZE);
	COPYMEM(exid->verifier.data, NFS4_VERIFIER_SIZE);

	status = nfsd4_decode_opaque(argp, &exid->clname);
	if (status)
		return nfserr_bad_xdr;

	READ_BUF(4);
	exid->flags = be32_to_cpup(p++);

	/* Ignore state_protect4_a */
	READ_BUF(4);
	exid->spa_how = be32_to_cpup(p++);
	switch (exid->spa_how) {
	case SP4_NONE:
		break;
	case SP4_MACH_CRED:
		/* spo_must_enforce */
		READ_BUF(4);
		dummy = be32_to_cpup(p++);
		READ_BUF(dummy * 4);
		p += dummy;

		/* spo_must_allow */
		READ_BUF(4);
		dummy = be32_to_cpup(p++);
		READ_BUF(dummy * 4);
		p += dummy;
		break;
	case SP4_SSV:
		/* ssp_ops */
		READ_BUF(4);
		dummy = be32_to_cpup(p++);
		READ_BUF(dummy * 4);
		p += dummy;

		READ_BUF(4);
		dummy = be32_to_cpup(p++);
		READ_BUF(dummy * 4);
		p += dummy;

		/* ssp_hash_algs<> */
		READ_BUF(4);
		tmp = be32_to_cpup(p++);
		while (tmp--) {
			READ_BUF(4);
			dummy = be32_to_cpup(p++);
			READ_BUF(dummy);
			p += XDR_QUADLEN(dummy);
		}

		/* ssp_encr_algs<> */
		READ_BUF(4);
		tmp = be32_to_cpup(p++);
		while (tmp--) {
			READ_BUF(4);
			dummy = be32_to_cpup(p++);
			READ_BUF(dummy);
			p += XDR_QUADLEN(dummy);
		}

		/* ssp_window and ssp_num_gss_handles */
		READ_BUF(8);
		dummy = be32_to_cpup(p++);
		dummy = be32_to_cpup(p++);
		break;
	default:
		goto xdr_error;
	}

	/* Ignore Implementation ID */
	READ_BUF(4);    /* nfs_impl_id4 array length */
	dummy = be32_to_cpup(p++);

	if (dummy > 1)
		goto xdr_error;

	if (dummy == 1) {
		/* nii_domain */
		READ_BUF(4);
		dummy = be32_to_cpup(p++);
		READ_BUF(dummy);
		p += XDR_QUADLEN(dummy);

		/* nii_name */
		READ_BUF(4);
		dummy = be32_to_cpup(p++);
		READ_BUF(dummy);
		p += XDR_QUADLEN(dummy);

		/* nii_date */
		READ_BUF(12);
		p += 3;
	}
	DECODE_TAIL;
}

static __be32
nfsd4_decode_create_session(struct nfsd4_compoundargs *argp,
			    struct nfsd4_create_session *sess)
{
	DECODE_HEAD;
	u32 dummy;

	READ_BUF(16);
	COPYMEM(&sess->clientid, 8);
	sess->seqid = be32_to_cpup(p++);
	sess->flags = be32_to_cpup(p++);

	/* Fore channel attrs */
	READ_BUF(28);
	dummy = be32_to_cpup(p++); /* headerpadsz is always 0 */
	sess->fore_channel.maxreq_sz = be32_to_cpup(p++);
	sess->fore_channel.maxresp_sz = be32_to_cpup(p++);
	sess->fore_channel.maxresp_cached = be32_to_cpup(p++);
	sess->fore_channel.maxops = be32_to_cpup(p++);
	sess->fore_channel.maxreqs = be32_to_cpup(p++);
	sess->fore_channel.nr_rdma_attrs = be32_to_cpup(p++);
	if (sess->fore_channel.nr_rdma_attrs == 1) {
		READ_BUF(4);
		sess->fore_channel.rdma_attrs = be32_to_cpup(p++);
	} else if (sess->fore_channel.nr_rdma_attrs > 1) {
		dprintk("Too many fore channel attr bitmaps!\n");
		goto xdr_error;
	}

	/* Back channel attrs */
	READ_BUF(28);
	dummy = be32_to_cpup(p++); /* headerpadsz is always 0 */
	sess->back_channel.maxreq_sz = be32_to_cpup(p++);
	sess->back_channel.maxresp_sz = be32_to_cpup(p++);
	sess->back_channel.maxresp_cached = be32_to_cpup(p++);
	sess->back_channel.maxops = be32_to_cpup(p++);
	sess->back_channel.maxreqs = be32_to_cpup(p++);
	sess->back_channel.nr_rdma_attrs = be32_to_cpup(p++);
	if (sess->back_channel.nr_rdma_attrs == 1) {
		READ_BUF(4);
		sess->back_channel.rdma_attrs = be32_to_cpup(p++);
	} else if (sess->back_channel.nr_rdma_attrs > 1) {
		dprintk("Too many back channel attr bitmaps!\n");
		goto xdr_error;
	}

	READ_BUF(4);
	sess->callback_prog = be32_to_cpup(p++);
	nfsd4_decode_cb_sec(argp, &sess->cb_sec);
	DECODE_TAIL;
}

static __be32
nfsd4_decode_destroy_session(struct nfsd4_compoundargs *argp,
			     struct nfsd4_destroy_session *destroy_session)
{
	DECODE_HEAD;
	READ_BUF(NFS4_MAX_SESSIONID_LEN);
	COPYMEM(destroy_session->sessionid.data, NFS4_MAX_SESSIONID_LEN);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_free_stateid(struct nfsd4_compoundargs *argp,
			  struct nfsd4_free_stateid *free_stateid)
{
	DECODE_HEAD;

	READ_BUF(sizeof(stateid_t));
	free_stateid->fr_stateid.si_generation = be32_to_cpup(p++);
	COPYMEM(&free_stateid->fr_stateid.si_opaque, sizeof(stateid_opaque_t));

	DECODE_TAIL;
}

static __be32
nfsd4_decode_sequence(struct nfsd4_compoundargs *argp,
		      struct nfsd4_sequence *seq)
{
	DECODE_HEAD;

	READ_BUF(NFS4_MAX_SESSIONID_LEN + 16);
	COPYMEM(seq->sessionid.data, NFS4_MAX_SESSIONID_LEN);
	seq->seqid = be32_to_cpup(p++);
	seq->slotid = be32_to_cpup(p++);
	seq->maxslots = be32_to_cpup(p++);
	seq->cachethis = be32_to_cpup(p++);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_test_stateid(struct nfsd4_compoundargs *argp, struct nfsd4_test_stateid *test_stateid)
{
	int i;
	__be32 *p, status;
	struct nfsd4_test_stateid_id *stateid;

	READ_BUF(4);
	test_stateid->ts_num_ids = ntohl(*p++);

	INIT_LIST_HEAD(&test_stateid->ts_stateid_list);

	for (i = 0; i < test_stateid->ts_num_ids; i++) {
		stateid = svcxdr_tmpalloc(argp, sizeof(*stateid));
		if (!stateid) {
			status = nfserrno(-ENOMEM);
			goto out;
		}

		INIT_LIST_HEAD(&stateid->ts_id_list);
		list_add_tail(&stateid->ts_id_list, &test_stateid->ts_stateid_list);

		status = nfsd4_decode_stateid(argp, &stateid->ts_id_stateid);
		if (status)
			goto out;
	}

	status = 0;
out:
	return status;
xdr_error:
	dprintk("NFSD: xdr error (%s:%d)\n", __FILE__, __LINE__);
	status = nfserr_bad_xdr;
	goto out;
}

static __be32 nfsd4_decode_destroy_clientid(struct nfsd4_compoundargs *argp, struct nfsd4_destroy_clientid *dc)
{
	DECODE_HEAD;

	READ_BUF(8);
	COPYMEM(&dc->clientid, 8);

	DECODE_TAIL;
}

static __be32 nfsd4_decode_reclaim_complete(struct nfsd4_compoundargs *argp, struct nfsd4_reclaim_complete *rc)
{
	DECODE_HEAD;

	READ_BUF(4);
	rc->rca_one_fs = be32_to_cpup(p++);

	DECODE_TAIL;
}

#ifdef CONFIG_NFSD_PNFS
static __be32
nfsd4_decode_getdeviceinfo(struct nfsd4_compoundargs *argp,
		struct nfsd4_getdeviceinfo *gdev)
{
	DECODE_HEAD;
	u32 num, i;

	READ_BUF(sizeof(struct nfsd4_deviceid) + 3 * 4);
	COPYMEM(&gdev->gd_devid, sizeof(struct nfsd4_deviceid));
	gdev->gd_layout_type = be32_to_cpup(p++);
	gdev->gd_maxcount = be32_to_cpup(p++);
	num = be32_to_cpup(p++);
	if (num) {
		READ_BUF(4 * num);
		gdev->gd_notify_types = be32_to_cpup(p++);
		for (i = 1; i < num; i++) {
			if (be32_to_cpup(p++)) {
				status = nfserr_inval;
				goto out;
			}
		}
	}
	DECODE_TAIL;
}

static __be32
nfsd4_decode_layoutget(struct nfsd4_compoundargs *argp,
		struct nfsd4_layoutget *lgp)
{
	DECODE_HEAD;

	READ_BUF(36);
	lgp->lg_signal = be32_to_cpup(p++);
	lgp->lg_layout_type = be32_to_cpup(p++);
	lgp->lg_seg.iomode = be32_to_cpup(p++);
	p = xdr_decode_hyper(p, &lgp->lg_seg.offset);
	p = xdr_decode_hyper(p, &lgp->lg_seg.length);
	p = xdr_decode_hyper(p, &lgp->lg_minlength);
	nfsd4_decode_stateid(argp, &lgp->lg_sid);
	READ_BUF(4);
	lgp->lg_maxcount = be32_to_cpup(p++);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_layoutcommit(struct nfsd4_compoundargs *argp,
		struct nfsd4_layoutcommit *lcp)
{
	DECODE_HEAD;
	u32 timechange;

	READ_BUF(20);
	p = xdr_decode_hyper(p, &lcp->lc_seg.offset);
	p = xdr_decode_hyper(p, &lcp->lc_seg.length);
	lcp->lc_reclaim = be32_to_cpup(p++);
	nfsd4_decode_stateid(argp, &lcp->lc_sid);
	READ_BUF(4);
	lcp->lc_newoffset = be32_to_cpup(p++);
	if (lcp->lc_newoffset) {
		READ_BUF(8);
		p = xdr_decode_hyper(p, &lcp->lc_last_wr);
	} else
		lcp->lc_last_wr = 0;
	READ_BUF(4);
	timechange = be32_to_cpup(p++);
	if (timechange) {
		status = nfsd4_decode_time(argp, &lcp->lc_mtime);
		if (status)
			return status;
	} else {
		lcp->lc_mtime.tv_nsec = UTIME_NOW;
	}
	READ_BUF(8);
	lcp->lc_layout_type = be32_to_cpup(p++);

	/*
	 * Save the layout update in XDR format and let the layout driver deal
	 * with it later.
	 */
	lcp->lc_up_len = be32_to_cpup(p++);
	if (lcp->lc_up_len > 0) {
		READ_BUF(lcp->lc_up_len);
		READMEM(lcp->lc_up_layout, lcp->lc_up_len);
	}

	DECODE_TAIL;
}

static __be32
nfsd4_decode_layoutreturn(struct nfsd4_compoundargs *argp,
		struct nfsd4_layoutreturn *lrp)
{
	DECODE_HEAD;

	READ_BUF(16);
	lrp->lr_reclaim = be32_to_cpup(p++);
	lrp->lr_layout_type = be32_to_cpup(p++);
	lrp->lr_seg.iomode = be32_to_cpup(p++);
	lrp->lr_return_type = be32_to_cpup(p++);
	if (lrp->lr_return_type == RETURN_FILE) {
		READ_BUF(16);
		p = xdr_decode_hyper(p, &lrp->lr_seg.offset);
		p = xdr_decode_hyper(p, &lrp->lr_seg.length);
		nfsd4_decode_stateid(argp, &lrp->lr_sid);
		READ_BUF(4);
		lrp->lrf_body_len = be32_to_cpup(p++);
		if (lrp->lrf_body_len > 0) {
			READ_BUF(lrp->lrf_body_len);
			READMEM(lrp->lrf_body, lrp->lrf_body_len);
		}
	} else {
		lrp->lr_seg.offset = 0;
		lrp->lr_seg.length = NFS4_MAX_UINT64;
	}

	DECODE_TAIL;
}
#endif /* CONFIG_NFSD_PNFS */

static __be32
nfsd4_decode_fallocate(struct nfsd4_compoundargs *argp,
		       struct nfsd4_fallocate *fallocate)
{
	DECODE_HEAD;

	status = nfsd4_decode_stateid(argp, &fallocate->falloc_stateid);
	if (status)
		return status;

	READ_BUF(16);
	p = xdr_decode_hyper(p, &fallocate->falloc_offset);
	xdr_decode_hyper(p, &fallocate->falloc_length);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_seek(struct nfsd4_compoundargs *argp, struct nfsd4_seek *seek)
{
	DECODE_HEAD;

	status = nfsd4_decode_stateid(argp, &seek->seek_stateid);
	if (status)
		return status;

	READ_BUF(8 + 4);
	p = xdr_decode_hyper(p, &seek->seek_offset);
	seek->seek_whence = be32_to_cpup(p);

	DECODE_TAIL;
}

static __be32
nfsd4_decode_noop(struct nfsd4_compoundargs *argp, void *p)
{
	return nfs_ok;
}

static __be32
nfsd4_decode_notsupp(struct nfsd4_compoundargs *argp, void *p)
{
	return nfserr_notsupp;
}

typedef __be32(*nfsd4_dec)(struct nfsd4_compoundargs *argp, void *);

static nfsd4_dec nfsd4_dec_ops[] = {
	[OP_ACCESS]		= (nfsd4_dec)nfsd4_decode_access,
	[OP_CLOSE]		= (nfsd4_dec)nfsd4_decode_close,
	[OP_COMMIT]		= (nfsd4_dec)nfsd4_decode_commit,
	[OP_CREATE]		= (nfsd4_dec)nfsd4_decode_create,
	[OP_DELEGPURGE]		= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_DELEGRETURN]	= (nfsd4_dec)nfsd4_decode_delegreturn,
	[OP_GETATTR]		= (nfsd4_dec)nfsd4_decode_getattr,
	[OP_GETFH]		= (nfsd4_dec)nfsd4_decode_noop,
	[OP_LINK]		= (nfsd4_dec)nfsd4_decode_link,
	[OP_LOCK]		= (nfsd4_dec)nfsd4_decode_lock,
	[OP_LOCKT]		= (nfsd4_dec)nfsd4_decode_lockt,
	[OP_LOCKU]		= (nfsd4_dec)nfsd4_decode_locku,
	[OP_LOOKUP]		= (nfsd4_dec)nfsd4_decode_lookup,
	[OP_LOOKUPP]		= (nfsd4_dec)nfsd4_decode_noop,
	[OP_NVERIFY]		= (nfsd4_dec)nfsd4_decode_verify,
	[OP_OPEN]		= (nfsd4_dec)nfsd4_decode_open,
	[OP_OPENATTR]		= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_OPEN_CONFIRM]	= (nfsd4_dec)nfsd4_decode_open_confirm,
	[OP_OPEN_DOWNGRADE]	= (nfsd4_dec)nfsd4_decode_open_downgrade,
	[OP_PUTFH]		= (nfsd4_dec)nfsd4_decode_putfh,
	[OP_PUTPUBFH]		= (nfsd4_dec)nfsd4_decode_putpubfh,
	[OP_PUTROOTFH]		= (nfsd4_dec)nfsd4_decode_noop,
	[OP_READ]		= (nfsd4_dec)nfsd4_decode_read,
	[OP_READDIR]		= (nfsd4_dec)nfsd4_decode_readdir,
	[OP_READLINK]		= (nfsd4_dec)nfsd4_decode_noop,
	[OP_REMOVE]		= (nfsd4_dec)nfsd4_decode_remove,
	[OP_RENAME]		= (nfsd4_dec)nfsd4_decode_rename,
	[OP_RENEW]		= (nfsd4_dec)nfsd4_decode_renew,
	[OP_RESTOREFH]		= (nfsd4_dec)nfsd4_decode_noop,
	[OP_SAVEFH]		= (nfsd4_dec)nfsd4_decode_noop,
	[OP_SECINFO]		= (nfsd4_dec)nfsd4_decode_secinfo,
	[OP_SETATTR]		= (nfsd4_dec)nfsd4_decode_setattr,
	[OP_SETCLIENTID]	= (nfsd4_dec)nfsd4_decode_setclientid,
	[OP_SETCLIENTID_CONFIRM] = (nfsd4_dec)nfsd4_decode_setclientid_confirm,
	[OP_VERIFY]		= (nfsd4_dec)nfsd4_decode_verify,
	[OP_WRITE]		= (nfsd4_dec)nfsd4_decode_write,
	[OP_RELEASE_LOCKOWNER]	= (nfsd4_dec)nfsd4_decode_release_lockowner,

	/* new operations for NFSv4.1 */
	[OP_BACKCHANNEL_CTL]	= (nfsd4_dec)nfsd4_decode_backchannel_ctl,
	[OP_BIND_CONN_TO_SESSION]= (nfsd4_dec)nfsd4_decode_bind_conn_to_session,
	[OP_EXCHANGE_ID]	= (nfsd4_dec)nfsd4_decode_exchange_id,
	[OP_CREATE_SESSION]	= (nfsd4_dec)nfsd4_decode_create_session,
	[OP_DESTROY_SESSION]	= (nfsd4_dec)nfsd4_decode_destroy_session,
	[OP_FREE_STATEID]	= (nfsd4_dec)nfsd4_decode_free_stateid,
	[OP_GET_DIR_DELEGATION]	= (nfsd4_dec)nfsd4_decode_notsupp,
#ifdef CONFIG_NFSD_PNFS
	[OP_GETDEVICEINFO]	= (nfsd4_dec)nfsd4_decode_getdeviceinfo,
	[OP_GETDEVICELIST]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_LAYOUTCOMMIT]	= (nfsd4_dec)nfsd4_decode_layoutcommit,
	[OP_LAYOUTGET]		= (nfsd4_dec)nfsd4_decode_layoutget,
	[OP_LAYOUTRETURN]	= (nfsd4_dec)nfsd4_decode_layoutreturn,
#else
	[OP_GETDEVICEINFO]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_GETDEVICELIST]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_LAYOUTCOMMIT]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_LAYOUTGET]		= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_LAYOUTRETURN]	= (nfsd4_dec)nfsd4_decode_notsupp,
#endif
	[OP_SECINFO_NO_NAME]	= (nfsd4_dec)nfsd4_decode_secinfo_no_name,
	[OP_SEQUENCE]		= (nfsd4_dec)nfsd4_decode_sequence,
	[OP_SET_SSV]		= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_TEST_STATEID]	= (nfsd4_dec)nfsd4_decode_test_stateid,
	[OP_WANT_DELEGATION]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_DESTROY_CLIENTID]	= (nfsd4_dec)nfsd4_decode_destroy_clientid,
	[OP_RECLAIM_COMPLETE]	= (nfsd4_dec)nfsd4_decode_reclaim_complete,

	/* new operations for NFSv4.2 */
	[OP_ALLOCATE]		= (nfsd4_dec)nfsd4_decode_fallocate,
	[OP_COPY]		= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_COPY_NOTIFY]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_DEALLOCATE]		= (nfsd4_dec)nfsd4_decode_fallocate,
	[OP_IO_ADVISE]		= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_LAYOUTERROR]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_LAYOUTSTATS]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_OFFLOAD_CANCEL]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_OFFLOAD_STATUS]	= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_READ_PLUS]		= (nfsd4_dec)nfsd4_decode_notsupp,
	[OP_SEEK]		= (nfsd4_dec)nfsd4_decode_seek,
	[OP_WRITE_SAME]		= (nfsd4_dec)nfsd4_decode_notsupp,
};

static inline bool
nfsd4_opnum_in_range(struct nfsd4_compoundargs *argp, struct nfsd4_op *op)
{
	if (op->opnum < FIRST_NFS4_OP)
		return false;
	else if (argp->minorversion == 0 && op->opnum > LAST_NFS40_OP)
		return false;
	else if (argp->minorversion == 1 && op->opnum > LAST_NFS41_OP)
		return false;
	else if (argp->minorversion == 2 && op->opnum > LAST_NFS42_OP)
		return false;
	return true;
}

static __be32
nfsd4_decode_compound(struct nfsd4_compoundargs *argp)
{
	DECODE_HEAD;
	struct nfsd4_op *op;
	bool cachethis = false;
	int auth_slack= argp->rqstp->rq_auth_slack;
	int max_reply = auth_slack + 8; /* opcnt, status */
	int readcount = 0;
	int readbytes = 0;
	int i;

	READ_BUF(4);
	argp->taglen = be32_to_cpup(p++);
	READ_BUF(argp->taglen + 8);
	SAVEMEM(argp->tag, argp->taglen);
	argp->minorversion = be32_to_cpup(p++);
	argp->opcnt = be32_to_cpup(p++);
	max_reply += 4 + (XDR_QUADLEN(argp->taglen) << 2);

	if (argp->taglen > NFSD4_MAX_TAGLEN)
		goto xdr_error;
	if (argp->opcnt > 100)
		goto xdr_error;

	if (argp->opcnt > ARRAY_SIZE(argp->iops)) {
		argp->ops = kzalloc(argp->opcnt * sizeof(*argp->ops), GFP_KERNEL);
		if (!argp->ops) {
			argp->ops = argp->iops;
			dprintk("nfsd: couldn't allocate room for COMPOUND\n");
			goto xdr_error;
		}
	}

	if (argp->minorversion > NFSD_SUPPORTED_MINOR_VERSION)
		argp->opcnt = 0;

	for (i = 0; i < argp->opcnt; i++) {
		op = &argp->ops[i];
		op->replay = NULL;

		READ_BUF(4);
		op->opnum = be32_to_cpup(p++);

		if (nfsd4_opnum_in_range(argp, op))
			op->status = nfsd4_dec_ops[op->opnum](argp, &op->u);
		else {
			op->opnum = OP_ILLEGAL;
			op->status = nfserr_op_illegal;
		}
		/*
		 * We'll try to cache the result in the DRC if any one
		 * op in the compound wants to be cached:
		 */
		cachethis |= nfsd4_cache_this_op(op);

		if (op->opnum == OP_READ) {
			readcount++;
			readbytes += nfsd4_max_reply(argp->rqstp, op);
		} else
			max_reply += nfsd4_max_reply(argp->rqstp, op);
		/*
		 * OP_LOCK may return a conflicting lock.  (Special case
		 * because it will just skip encoding this if it runs
		 * out of xdr buffer space, and it is the only operation
		 * that behaves this way.)
		 */
		if (op->opnum == OP_LOCK)
			max_reply += NFS4_OPAQUE_LIMIT;

		if (op->status) {
			argp->opcnt = i+1;
			break;
		}
	}
	/* Sessions make the DRC unnecessary: */
	if (argp->minorversion)
		cachethis = false;
	svc_reserve(argp->rqstp, max_reply + readbytes);
	argp->rqstp->rq_cachetype = cachethis ? RC_REPLBUFF : RC_NOCACHE;

	if (readcount > 1 || max_reply > PAGE_SIZE - auth_slack)
		clear_bit(RQ_SPLICE_OK, &argp->rqstp->rq_flags);

	DECODE_TAIL;
}

static __be32 *encode_change(__be32 *p, struct kstat *stat, struct inode *inode)
{
	if (IS_I_VERSION(inode)) {
		p = xdr_encode_hyper(p, inode->i_version);
	} else {
		*p++ = cpu_to_be32(stat->ctime.tv_sec);
		*p++ = cpu_to_be32(stat->ctime.tv_nsec);
	}
	return p;
}

static __be32 *encode_cinfo(__be32 *p, struct nfsd4_change_info *c)
{
	*p++ = cpu_to_be32(c->atomic);
	if (c->change_supported) {
		p = xdr_encode_hyper(p, c->before_change);
		p = xdr_encode_hyper(p, c->after_change);
	} else {
		*p++ = cpu_to_be32(c->before_ctime_sec);
		*p++ = cpu_to_be32(c->before_ctime_nsec);
		*p++ = cpu_to_be32(c->after_ctime_sec);
		*p++ = cpu_to_be32(c->after_ctime_nsec);
	}
	return p;
}

/* Encode as an array of strings the string given with components
 * separated @sep, escaped with esc_enter and esc_exit.
 */
static __be32 nfsd4_encode_components_esc(struct xdr_stream *xdr, char sep,
					  char *components, char esc_enter,
					  char esc_exit)
{
	__be32 *p;
	__be32 pathlen;
	int pathlen_offset;
	int strlen, count=0;
	char *str, *end, *next;

	dprintk("nfsd4_encode_components(%s)\n", components);

	pathlen_offset = xdr->buf->len;
	p = xdr_reserve_space(xdr, 4);
	if (!p)
		return nfserr_resource;
	p++; /* We will fill this in with @count later */

	end = str = components;
	while (*end) {
		bool found_esc = false;

		/* try to parse as esc_start, ..., esc_end, sep */
		if (*str == esc_enter) {
			for (; *end && (*end != esc_exit); end++)
				/* find esc_exit or end of string */;
			next = end + 1;
			if (*end && (!*next || *next == sep)) {
				str++;
				found_esc = true;
			}
		}

		if (!found_esc)
			for (; *end && (*end != sep); end++)
				/* find sep or end of string */;

		strlen = end - str;
		if (strlen) {
			p = xdr_reserve_space(xdr, strlen + 4);
			if (!p)
				return nfserr_resource;
			p = xdr_encode_opaque(p, str, strlen);
			count++;
		}
		else
			end++;
		if (found_esc)
			end = next;

		str = end;
	}
	pathlen = htonl(count);
	write_bytes_to_xdr_buf(xdr->buf, pathlen_offset, &pathlen, 4);
	return 0;
}

/* Encode as an array of strings the string given with components
 * separated @sep.
 */
static __be32 nfsd4_encode_components(struct xdr_stream *xdr, char sep,
				      char *components)
{
	return nfsd4_encode_components_esc(xdr, sep, components, 0, 0);
}

/*
 * encode a location element of a fs_locations structure
 */
static __be32 nfsd4_encode_fs_location4(struct xdr_stream *xdr,
					struct nfsd4_fs_location *location)
{
	__be32 status;

	status = nfsd4_encode_components_esc(xdr, ':', location->hosts,
						'[', ']');
	if (status)
		return status;
	status = nfsd4_encode_components(xdr, '/', location->path);
	if (status)
		return status;
	return 0;
}

/*
 * Encode a path in RFC3530 'pathname4' format
 */
static __be32 nfsd4_encode_path(struct xdr_stream *xdr,
				const struct path *root,
				const struct path *path)
{
	struct path cur = *path;
	__be32 *p;
	struct dentry **components = NULL;
	unsigned int ncomponents = 0;
	__be32 err = nfserr_jukebox;

	dprintk("nfsd4_encode_components(");

	path_get(&cur);
	/* First walk the path up to the nfsd root, and store the
	 * dentries/path components in an array.
	 */
	for (;;) {
		if (cur.dentry == root->dentry && cur.mnt == root->mnt)
			break;
		if (cur.dentry == cur.mnt->mnt_root) {
			if (follow_up(&cur))
				continue;
			goto out_free;
		}
		if ((ncomponents & 15) == 0) {
			struct dentry **new;
			new = krealloc(components,
					sizeof(*new) * (ncomponents + 16),
					GFP_KERNEL);
			if (!new)
				goto out_free;
			components = new;
		}
		components[ncomponents++] = cur.dentry;
		cur.dentry = dget_parent(cur.dentry);
	}
	err = nfserr_resource;
	p = xdr_reserve_space(xdr, 4);
	if (!p)
		goto out_free;
	*p++ = cpu_to_be32(ncomponents);

	while (ncomponents) {
		struct dentry *dentry = components[ncomponents - 1];
		unsigned int len;

		spin_lock(&dentry->d_lock);
		len = dentry->d_name.len;
		p = xdr_reserve_space(xdr, len + 4);
		if (!p) {
			spin_unlock(&dentry->d_lock);
			goto out_free;
		}
		p = xdr_encode_opaque(p, dentry->d_name.name, len);
		dprintk("/%pd", dentry);
		spin_unlock(&dentry->d_lock);
		dput(dentry);
		ncomponents--;
	}

	err = 0;
out_free:
	dprintk(")\n");
	while (ncomponents)
		dput(components[--ncomponents]);
	kfree(components);
	path_put(&cur);
	return err;
}

static __be32 nfsd4_encode_fsloc_fsroot(struct xdr_stream *xdr,
			struct svc_rqst *rqstp, const struct path *path)
{
	struct svc_export *exp_ps;
	__be32 res;

	exp_ps = rqst_find_fsidzero_export(rqstp);
	if (IS_ERR(exp_ps))
		return nfserrno(PTR_ERR(exp_ps));
	res = nfsd4_encode_path(xdr, &exp_ps->ex_path, path);
	exp_put(exp_ps);
	return res;
}

/*
 *  encode a fs_locations structure
 */
static __be32 nfsd4_encode_fs_locations(struct xdr_stream *xdr,
			struct svc_rqst *rqstp, struct svc_export *exp)
{
	__be32 status;
	int i;
	__be32 *p;
	struct nfsd4_fs_locations *fslocs = &exp->ex_fslocs;

	status = nfsd4_encode_fsloc_fsroot(xdr, rqstp, &exp->ex_path);
	if (status)
		return status;
	p = xdr_reserve_space(xdr, 4);
	if (!p)
		return nfserr_resource;
	*p++ = cpu_to_be32(fslocs->locations_count);
	for (i=0; i<fslocs->locations_count; i++) {
		status = nfsd4_encode_fs_location4(xdr, &fslocs->locations[i]);
		if (status)
			return status;
	}
	return 0;
}

static u32 nfs4_file_type(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFIFO:	return NF4FIFO;
	case S_IFCHR:	return NF4CHR;
	case S_IFDIR:	return NF4DIR;
	case S_IFBLK:	return NF4BLK;
	case S_IFLNK:	return NF4LNK;
	case S_IFREG:	return NF4REG;
	case S_IFSOCK:	return NF4SOCK;
	default:	return NF4BAD;
	};
}

static inline __be32
nfsd4_encode_aclname(struct xdr_stream *xdr, struct svc_rqst *rqstp,
		     struct nfs4_ace *ace)
{
	if (ace->whotype != NFS4_ACL_WHO_NAMED)
		return nfs4_acl_write_who(xdr, ace->whotype);
	else if (ace->flag & NFS4_ACE_IDENTIFIER_GROUP)
		return nfsd4_encode_group(xdr, rqstp, ace->who_gid);
	else
		return nfsd4_encode_user(xdr, rqstp, ace->who_uid);
}

#define WORD0_ABSENT_FS_ATTRS (FATTR4_WORD0_FS_LOCATIONS | FATTR4_WORD0_FSID | \
			      FATTR4_WORD0_RDATTR_ERROR)
#define WORD1_ABSENT_FS_ATTRS FATTR4_WORD1_MOUNTED_ON_FILEID

#ifdef CONFIG_NFSD_V4_SECURITY_LABEL
static inline __be32
nfsd4_encode_security_label(struct xdr_stream *xdr, struct svc_rqst *rqstp,
			    void *context, int len)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, len + 4 + 4 + 4);
	if (!p)
		return nfserr_resource;

	/*
	 * For now we use a 0 here to indicate the null translation; in
	 * the future we may place a call to translation code here.
	 */
	*p++ = cpu_to_be32(0); /* lfs */
	*p++ = cpu_to_be32(0); /* pi */
	p = xdr_encode_opaque(p, context, len);
	return 0;
}
#else
static inline __be32
nfsd4_encode_security_label(struct xdr_stream *xdr, struct svc_rqst *rqstp,
			    void *context, int len)
{ return 0; }
#endif

static __be32 fattr_handle_absent_fs(u32 *bmval0, u32 *bmval1, u32 *rdattr_err)
{
	/* As per referral draft:  */
	if (*bmval0 & ~WORD0_ABSENT_FS_ATTRS ||
	    *bmval1 & ~WORD1_ABSENT_FS_ATTRS) {
		if (*bmval0 & FATTR4_WORD0_RDATTR_ERROR ||
	            *bmval0 & FATTR4_WORD0_FS_LOCATIONS)
			*rdattr_err = NFSERR_MOVED;
		else
			return nfserr_moved;
	}
	*bmval0 &= WORD0_ABSENT_FS_ATTRS;
	*bmval1 &= WORD1_ABSENT_FS_ATTRS;
	return 0;
}


static int get_parent_attributes(struct svc_export *exp, struct kstat *stat)
{
	struct path path = exp->ex_path;
	int err;

	path_get(&path);
	while (follow_up(&path)) {
		if (path.dentry != path.mnt->mnt_root)
			break;
	}
	err = vfs_getattr(&path, stat);
	path_put(&path);
	return err;
}

/*
 * Note: @fhp can be NULL; in this case, we might have to compose the filehandle
 * ourselves.
 */
static __be32
nfsd4_encode_fattr(struct xdr_stream *xdr, struct svc_fh *fhp,
		struct svc_export *exp,
		struct dentry *dentry, u32 *bmval,
		struct svc_rqst *rqstp, int ignore_crossmnt)
{
	u32 bmval0 = bmval[0];
	u32 bmval1 = bmval[1];
	u32 bmval2 = bmval[2];
	struct kstat stat;
	struct svc_fh *tempfh = NULL;
	struct kstatfs statfs;
	__be32 *p;
	int starting_len = xdr->buf->len;
	int attrlen_offset;
	__be32 attrlen;
	u32 dummy;
	u64 dummy64;
	u32 rdattr_err = 0;
	__be32 status;
	int err;
	int aclsupport = 0;
	struct nfs4_acl *acl = NULL;
	void *context = NULL;
	int contextlen;
	bool contextsupport = false;
	struct nfsd4_compoundres *resp = rqstp->rq_resp;
	u32 minorversion = resp->cstate.minorversion;
	struct path path = {
		.mnt	= exp->ex_path.mnt,
		.dentry	= dentry,
	};
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	BUG_ON(bmval1 & NFSD_WRITEONLY_ATTRS_WORD1);
	BUG_ON(bmval0 & ~nfsd_suppattrs0(minorversion));
	BUG_ON(bmval1 & ~nfsd_suppattrs1(minorversion));
	BUG_ON(bmval2 & ~nfsd_suppattrs2(minorversion));

	if (exp->ex_fslocs.migrated) {
		BUG_ON(bmval[2]);
		status = fattr_handle_absent_fs(&bmval0, &bmval1, &rdattr_err);
		if (status)
			goto out;
	}

	err = vfs_getattr(&path, &stat);
	if (err)
		goto out_nfserr;
	if ((bmval0 & (FATTR4_WORD0_FILES_AVAIL | FATTR4_WORD0_FILES_FREE |
			FATTR4_WORD0_FILES_TOTAL | FATTR4_WORD0_MAXNAME)) ||
	    (bmval1 & (FATTR4_WORD1_SPACE_AVAIL | FATTR4_WORD1_SPACE_FREE |
		       FATTR4_WORD1_SPACE_TOTAL))) {
		err = vfs_statfs(&path, &statfs);
		if (err)
			goto out_nfserr;
	}
	if ((bmval0 & (FATTR4_WORD0_FILEHANDLE | FATTR4_WORD0_FSID)) && !fhp) {
		tempfh = kmalloc(sizeof(struct svc_fh), GFP_KERNEL);
		status = nfserr_jukebox;
		if (!tempfh)
			goto out;
		fh_init(tempfh, NFS4_FHSIZE);
		status = fh_compose(tempfh, exp, dentry, NULL);
		if (status)
			goto out;
		fhp = tempfh;
	}
	if (bmval0 & (FATTR4_WORD0_ACL | FATTR4_WORD0_ACLSUPPORT
			| FATTR4_WORD0_SUPPORTED_ATTRS)) {
		err = nfsd4_get_nfs4_acl(rqstp, dentry, &acl);
		aclsupport = (err == 0);
		if (bmval0 & FATTR4_WORD0_ACL) {
			if (err == -EOPNOTSUPP)
				bmval0 &= ~FATTR4_WORD0_ACL;
			else if (err == -EINVAL) {
				status = nfserr_attrnotsupp;
				goto out;
			} else if (err != 0)
				goto out_nfserr;
		}
	}

#ifdef CONFIG_NFSD_V4_SECURITY_LABEL
	if ((bmval[2] & FATTR4_WORD2_SECURITY_LABEL) ||
			bmval[0] & FATTR4_WORD0_SUPPORTED_ATTRS) {
		err = security_inode_getsecctx(dentry->d_inode,
						&context, &contextlen);
		contextsupport = (err == 0);
		if (bmval2 & FATTR4_WORD2_SECURITY_LABEL) {
			if (err == -EOPNOTSUPP)
				bmval2 &= ~FATTR4_WORD2_SECURITY_LABEL;
			else if (err)
				goto out_nfserr;
		}
	}
#endif /* CONFIG_NFSD_V4_SECURITY_LABEL */

	if (bmval2) {
		p = xdr_reserve_space(xdr, 16);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(3);
		*p++ = cpu_to_be32(bmval0);
		*p++ = cpu_to_be32(bmval1);
		*p++ = cpu_to_be32(bmval2);
	} else if (bmval1) {
		p = xdr_reserve_space(xdr, 12);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(2);
		*p++ = cpu_to_be32(bmval0);
		*p++ = cpu_to_be32(bmval1);
	} else {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(1);
		*p++ = cpu_to_be32(bmval0);
	}

	attrlen_offset = xdr->buf->len;
	p = xdr_reserve_space(xdr, 4);
	if (!p)
		goto out_resource;
	p++;                /* to be backfilled later */

	if (bmval0 & FATTR4_WORD0_SUPPORTED_ATTRS) {
		u32 word0 = nfsd_suppattrs0(minorversion);
		u32 word1 = nfsd_suppattrs1(minorversion);
		u32 word2 = nfsd_suppattrs2(minorversion);

		if (!aclsupport)
			word0 &= ~FATTR4_WORD0_ACL;
		if (!contextsupport)
			word2 &= ~FATTR4_WORD2_SECURITY_LABEL;
		if (!word2) {
			p = xdr_reserve_space(xdr, 12);
			if (!p)
				goto out_resource;
			*p++ = cpu_to_be32(2);
			*p++ = cpu_to_be32(word0);
			*p++ = cpu_to_be32(word1);
		} else {
			p = xdr_reserve_space(xdr, 16);
			if (!p)
				goto out_resource;
			*p++ = cpu_to_be32(3);
			*p++ = cpu_to_be32(word0);
			*p++ = cpu_to_be32(word1);
			*p++ = cpu_to_be32(word2);
		}
	}
	if (bmval0 & FATTR4_WORD0_TYPE) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		dummy = nfs4_file_type(stat.mode);
		if (dummy == NF4BAD) {
			status = nfserr_serverfault;
			goto out;
		}
		*p++ = cpu_to_be32(dummy);
	}
	if (bmval0 & FATTR4_WORD0_FH_EXPIRE_TYPE) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		if (exp->ex_flags & NFSEXP_NOSUBTREECHECK)
			*p++ = cpu_to_be32(NFS4_FH_PERSISTENT);
		else
			*p++ = cpu_to_be32(NFS4_FH_PERSISTENT|
						NFS4_FH_VOL_RENAME);
	}
	if (bmval0 & FATTR4_WORD0_CHANGE) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		p = encode_change(p, &stat, dentry->d_inode);
	}
	if (bmval0 & FATTR4_WORD0_SIZE) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, stat.size);
	}
	if (bmval0 & FATTR4_WORD0_LINK_SUPPORT) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(1);
	}
	if (bmval0 & FATTR4_WORD0_SYMLINK_SUPPORT) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(1);
	}
	if (bmval0 & FATTR4_WORD0_NAMED_ATTR) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(0);
	}
	if (bmval0 & FATTR4_WORD0_FSID) {
		p = xdr_reserve_space(xdr, 16);
		if (!p)
			goto out_resource;
		if (exp->ex_fslocs.migrated) {
			p = xdr_encode_hyper(p, NFS4_REFERRAL_FSID_MAJOR);
			p = xdr_encode_hyper(p, NFS4_REFERRAL_FSID_MINOR);
		} else switch(fsid_source(fhp)) {
		case FSIDSOURCE_FSID:
			p = xdr_encode_hyper(p, (u64)exp->ex_fsid);
			p = xdr_encode_hyper(p, (u64)0);
			break;
		case FSIDSOURCE_DEV:
			*p++ = cpu_to_be32(0);
			*p++ = cpu_to_be32(MAJOR(stat.dev));
			*p++ = cpu_to_be32(0);
			*p++ = cpu_to_be32(MINOR(stat.dev));
			break;
		case FSIDSOURCE_UUID:
			p = xdr_encode_opaque_fixed(p, exp->ex_uuid,
								EX_UUID_LEN);
			break;
		}
	}
	if (bmval0 & FATTR4_WORD0_UNIQUE_HANDLES) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(0);
	}
	if (bmval0 & FATTR4_WORD0_LEASE_TIME) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(nn->nfsd4_lease);
	}
	if (bmval0 & FATTR4_WORD0_RDATTR_ERROR) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(rdattr_err);
	}
	if (bmval0 & FATTR4_WORD0_ACL) {
		struct nfs4_ace *ace;

		if (acl == NULL) {
			p = xdr_reserve_space(xdr, 4);
			if (!p)
				goto out_resource;

			*p++ = cpu_to_be32(0);
			goto out_acl;
		}
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(acl->naces);

		for (ace = acl->aces; ace < acl->aces + acl->naces; ace++) {
			p = xdr_reserve_space(xdr, 4*3);
			if (!p)
				goto out_resource;
			*p++ = cpu_to_be32(ace->type);
			*p++ = cpu_to_be32(ace->flag);
			*p++ = cpu_to_be32(ace->access_mask &
							NFS4_ACE_MASK_ALL);
			status = nfsd4_encode_aclname(xdr, rqstp, ace);
			if (status)
				goto out;
		}
	}
out_acl:
	if (bmval0 & FATTR4_WORD0_ACLSUPPORT) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(aclsupport ?
			ACL4_SUPPORT_ALLOW_ACL|ACL4_SUPPORT_DENY_ACL : 0);
	}
	if (bmval0 & FATTR4_WORD0_CANSETTIME) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(1);
	}
	if (bmval0 & FATTR4_WORD0_CASE_INSENSITIVE) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(0);
	}
	if (bmval0 & FATTR4_WORD0_CASE_PRESERVING) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(1);
	}
	if (bmval0 & FATTR4_WORD0_CHOWN_RESTRICTED) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(1);
	}
	if (bmval0 & FATTR4_WORD0_FILEHANDLE) {
		p = xdr_reserve_space(xdr, fhp->fh_handle.fh_size + 4);
		if (!p)
			goto out_resource;
		p = xdr_encode_opaque(p, &fhp->fh_handle.fh_base,
					fhp->fh_handle.fh_size);
	}
	if (bmval0 & FATTR4_WORD0_FILEID) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, stat.ino);
	}
	if (bmval0 & FATTR4_WORD0_FILES_AVAIL) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, (u64) statfs.f_ffree);
	}
	if (bmval0 & FATTR4_WORD0_FILES_FREE) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, (u64) statfs.f_ffree);
	}
	if (bmval0 & FATTR4_WORD0_FILES_TOTAL) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, (u64) statfs.f_files);
	}
	if (bmval0 & FATTR4_WORD0_FS_LOCATIONS) {
		status = nfsd4_encode_fs_locations(xdr, rqstp, exp);
		if (status)
			goto out;
	}
	if (bmval0 & FATTR4_WORD0_HOMOGENEOUS) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(1);
	}
	if (bmval0 & FATTR4_WORD0_MAXFILESIZE) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, exp->ex_path.mnt->mnt_sb->s_maxbytes);
	}
	if (bmval0 & FATTR4_WORD0_MAXLINK) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(255);
	}
	if (bmval0 & FATTR4_WORD0_MAXNAME) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(statfs.f_namelen);
	}
	if (bmval0 & FATTR4_WORD0_MAXREAD) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, (u64) svc_max_payload(rqstp));
	}
	if (bmval0 & FATTR4_WORD0_MAXWRITE) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, (u64) svc_max_payload(rqstp));
	}
	if (bmval1 & FATTR4_WORD1_MODE) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(stat.mode & S_IALLUGO);
	}
	if (bmval1 & FATTR4_WORD1_NO_TRUNC) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(1);
	}
	if (bmval1 & FATTR4_WORD1_NUMLINKS) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(stat.nlink);
	}
	if (bmval1 & FATTR4_WORD1_OWNER) {
		status = nfsd4_encode_user(xdr, rqstp, stat.uid);
		if (status)
			goto out;
	}
	if (bmval1 & FATTR4_WORD1_OWNER_GROUP) {
		status = nfsd4_encode_group(xdr, rqstp, stat.gid);
		if (status)
			goto out;
	}
	if (bmval1 & FATTR4_WORD1_RAWDEV) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32((u32) MAJOR(stat.rdev));
		*p++ = cpu_to_be32((u32) MINOR(stat.rdev));
	}
	if (bmval1 & FATTR4_WORD1_SPACE_AVAIL) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		dummy64 = (u64)statfs.f_bavail * (u64)statfs.f_bsize;
		p = xdr_encode_hyper(p, dummy64);
	}
	if (bmval1 & FATTR4_WORD1_SPACE_FREE) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		dummy64 = (u64)statfs.f_bfree * (u64)statfs.f_bsize;
		p = xdr_encode_hyper(p, dummy64);
	}
	if (bmval1 & FATTR4_WORD1_SPACE_TOTAL) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		dummy64 = (u64)statfs.f_blocks * (u64)statfs.f_bsize;
		p = xdr_encode_hyper(p, dummy64);
	}
	if (bmval1 & FATTR4_WORD1_SPACE_USED) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			goto out_resource;
		dummy64 = (u64)stat.blocks << 9;
		p = xdr_encode_hyper(p, dummy64);
	}
	if (bmval1 & FATTR4_WORD1_TIME_ACCESS) {
		p = xdr_reserve_space(xdr, 12);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, (s64)stat.atime.tv_sec);
		*p++ = cpu_to_be32(stat.atime.tv_nsec);
	}
	if (bmval1 & FATTR4_WORD1_TIME_DELTA) {
		p = xdr_reserve_space(xdr, 12);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(0);
		*p++ = cpu_to_be32(1);
		*p++ = cpu_to_be32(0);
	}
	if (bmval1 & FATTR4_WORD1_TIME_METADATA) {
		p = xdr_reserve_space(xdr, 12);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, (s64)stat.ctime.tv_sec);
		*p++ = cpu_to_be32(stat.ctime.tv_nsec);
	}
	if (bmval1 & FATTR4_WORD1_TIME_MODIFY) {
		p = xdr_reserve_space(xdr, 12);
		if (!p)
			goto out_resource;
		p = xdr_encode_hyper(p, (s64)stat.mtime.tv_sec);
		*p++ = cpu_to_be32(stat.mtime.tv_nsec);
	}
	if (bmval1 & FATTR4_WORD1_MOUNTED_ON_FILEID) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
                	goto out_resource;
		/*
		 * Get parent's attributes if not ignoring crossmount
		 * and this is the root of a cross-mounted filesystem.
		 */
		if (ignore_crossmnt == 0 &&
		    dentry == exp->ex_path.mnt->mnt_root)
			get_parent_attributes(exp, &stat);
		p = xdr_encode_hyper(p, stat.ino);
	}
#ifdef CONFIG_NFSD_PNFS
	if ((bmval1 & FATTR4_WORD1_FS_LAYOUT_TYPES) ||
	    (bmval2 & FATTR4_WORD2_LAYOUT_TYPES)) {
		if (exp->ex_layout_type) {
			p = xdr_reserve_space(xdr, 8);
			if (!p)
				goto out_resource;
			*p++ = cpu_to_be32(1);
			*p++ = cpu_to_be32(exp->ex_layout_type);
		} else {
			p = xdr_reserve_space(xdr, 4);
			if (!p)
				goto out_resource;
			*p++ = cpu_to_be32(0);
		}
	}

	if (bmval2 & FATTR4_WORD2_LAYOUT_BLKSIZE) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(stat.blksize);
	}
#endif /* CONFIG_NFSD_PNFS */
	if (bmval2 & FATTR4_WORD2_SECURITY_LABEL) {
		status = nfsd4_encode_security_label(xdr, rqstp, context,
								contextlen);
		if (status)
			goto out;
	}
	if (bmval2 & FATTR4_WORD2_SUPPATTR_EXCLCREAT) {
		p = xdr_reserve_space(xdr, 16);
		if (!p)
			goto out_resource;
		*p++ = cpu_to_be32(3);
		*p++ = cpu_to_be32(NFSD_SUPPATTR_EXCLCREAT_WORD0);
		*p++ = cpu_to_be32(NFSD_SUPPATTR_EXCLCREAT_WORD1);
		*p++ = cpu_to_be32(NFSD_SUPPATTR_EXCLCREAT_WORD2);
	}

	attrlen = htonl(xdr->buf->len - attrlen_offset - 4);
	write_bytes_to_xdr_buf(xdr->buf, attrlen_offset, &attrlen, 4);
	status = nfs_ok;

out:
#ifdef CONFIG_NFSD_V4_SECURITY_LABEL
	if (context)
		security_release_secctx(context, contextlen);
#endif /* CONFIG_NFSD_V4_SECURITY_LABEL */
	kfree(acl);
	if (tempfh) {
		fh_put(tempfh);
		kfree(tempfh);
	}
	if (status)
		xdr_truncate_encode(xdr, starting_len);
	return status;
out_nfserr:
	status = nfserrno(err);
	goto out;
out_resource:
	status = nfserr_resource;
	goto out;
}

static void svcxdr_init_encode_from_buffer(struct xdr_stream *xdr,
				struct xdr_buf *buf, __be32 *p, int bytes)
{
	xdr->scratch.iov_len = 0;
	memset(buf, 0, sizeof(struct xdr_buf));
	buf->head[0].iov_base = p;
	buf->head[0].iov_len = 0;
	buf->len = 0;
	xdr->buf = buf;
	xdr->iov = buf->head;
	xdr->p = p;
	xdr->end = (void *)p + bytes;
	buf->buflen = bytes;
}

__be32 nfsd4_encode_fattr_to_buf(__be32 **p, int words,
			struct svc_fh *fhp, struct svc_export *exp,
			struct dentry *dentry, u32 *bmval,
			struct svc_rqst *rqstp, int ignore_crossmnt)
{
	struct xdr_buf dummy;
	struct xdr_stream xdr;
	__be32 ret;

	svcxdr_init_encode_from_buffer(&xdr, &dummy, *p, words << 2);
	ret = nfsd4_encode_fattr(&xdr, fhp, exp, dentry, bmval, rqstp,
							ignore_crossmnt);
	*p = xdr.p;
	return ret;
}

static inline int attributes_need_mount(u32 *bmval)
{
	if (bmval[0] & ~(FATTR4_WORD0_RDATTR_ERROR | FATTR4_WORD0_LEASE_TIME))
		return 1;
	if (bmval[1] & ~FATTR4_WORD1_MOUNTED_ON_FILEID)
		return 1;
	return 0;
}

static __be32
nfsd4_encode_dirent_fattr(struct xdr_stream *xdr, struct nfsd4_readdir *cd,
			const char *name, int namlen)
{
	struct svc_export *exp = cd->rd_fhp->fh_export;
	struct dentry *dentry;
	__be32 nfserr;
	int ignore_crossmnt = 0;

	dentry = lookup_one_len(name, cd->rd_fhp->fh_dentry, namlen);
	if (IS_ERR(dentry))
		return nfserrno(PTR_ERR(dentry));
	if (!dentry->d_inode) {
		/*
		 * nfsd_buffered_readdir drops the i_mutex between
		 * readdir and calling this callback, leaving a window
		 * where this directory entry could have gone away.
		 */
		dput(dentry);
		return nfserr_noent;
	}

	exp_get(exp);
	/*
	 * In the case of a mountpoint, the client may be asking for
	 * attributes that are only properties of the underlying filesystem
	 * as opposed to the cross-mounted file system. In such a case,
	 * we will not follow the cross mount and will fill the attribtutes
	 * directly from the mountpoint dentry.
	 */
	if (nfsd_mountpoint(dentry, exp)) {
		int err;

		if (!(exp->ex_flags & NFSEXP_V4ROOT)
				&& !attributes_need_mount(cd->rd_bmval)) {
			ignore_crossmnt = 1;
			goto out_encode;
		}
		/*
		 * Why the heck aren't we just using nfsd_lookup??
		 * Different "."/".." handling?  Something else?
		 * At least, add a comment here to explain....
		 */
		err = nfsd_cross_mnt(cd->rd_rqstp, &dentry, &exp);
		if (err) {
			nfserr = nfserrno(err);
			goto out_put;
		}
		nfserr = check_nfsd_access(exp, cd->rd_rqstp);
		if (nfserr)
			goto out_put;

	}
out_encode:
	nfserr = nfsd4_encode_fattr(xdr, NULL, exp, dentry, cd->rd_bmval,
					cd->rd_rqstp, ignore_crossmnt);
out_put:
	dput(dentry);
	exp_put(exp);
	return nfserr;
}

static __be32 *
nfsd4_encode_rdattr_error(struct xdr_stream *xdr, __be32 nfserr)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 20);
	if (!p)
		return NULL;
	*p++ = htonl(2);
	*p++ = htonl(FATTR4_WORD0_RDATTR_ERROR); /* bmval0 */
	*p++ = htonl(0);			 /* bmval1 */

	*p++ = htonl(4);     /* attribute length */
	*p++ = nfserr;       /* no htonl */
	return p;
}

static int
nfsd4_encode_dirent(void *ccdv, const char *name, int namlen,
		    loff_t offset, u64 ino, unsigned int d_type)
{
	struct readdir_cd *ccd = ccdv;
	struct nfsd4_readdir *cd = container_of(ccd, struct nfsd4_readdir, common);
	struct xdr_stream *xdr = cd->xdr;
	int start_offset = xdr->buf->len;
	int cookie_offset;
	u32 name_and_cookie;
	int entry_bytes;
	__be32 nfserr = nfserr_toosmall;
	__be64 wire_offset;
	__be32 *p;

	/* In nfsv4, "." and ".." never make it onto the wire.. */
	if (name && isdotent(name, namlen)) {
		cd->common.err = nfs_ok;
		return 0;
	}

	if (cd->cookie_offset) {
		wire_offset = cpu_to_be64(offset);
		write_bytes_to_xdr_buf(xdr->buf, cd->cookie_offset,
							&wire_offset, 8);
	}

	p = xdr_reserve_space(xdr, 4);
	if (!p)
		goto fail;
	*p++ = xdr_one;                             /* mark entry present */
	cookie_offset = xdr->buf->len;
	p = xdr_reserve_space(xdr, 3*4 + namlen);
	if (!p)
		goto fail;
	p = xdr_encode_hyper(p, NFS_OFFSET_MAX);    /* offset of next entry */
	p = xdr_encode_array(p, name, namlen);      /* name length & name */

	nfserr = nfsd4_encode_dirent_fattr(xdr, cd, name, namlen);
	switch (nfserr) {
	case nfs_ok:
		break;
	case nfserr_resource:
		nfserr = nfserr_toosmall;
		goto fail;
	case nfserr_noent:
		xdr_truncate_encode(xdr, start_offset);
		goto skip_entry;
	default:
		/*
		 * If the client requested the RDATTR_ERROR attribute,
		 * we stuff the error code into this attribute
		 * and continue.  If this attribute was not requested,
		 * then in accordance with the spec, we fail the
		 * entire READDIR operation(!)
		 */
		if (!(cd->rd_bmval[0] & FATTR4_WORD0_RDATTR_ERROR))
			goto fail;
		p = nfsd4_encode_rdattr_error(xdr, nfserr);
		if (p == NULL) {
			nfserr = nfserr_toosmall;
			goto fail;
		}
	}
	nfserr = nfserr_toosmall;
	entry_bytes = xdr->buf->len - start_offset;
	if (entry_bytes > cd->rd_maxcount)
		goto fail;
	cd->rd_maxcount -= entry_bytes;
	/*
	 * RFC 3530 14.2.24 describes rd_dircount as only a "hint", so
	 * let's always let through the first entry, at least:
	 */
	if (!cd->rd_dircount)
		goto fail;
	name_and_cookie = 4 + 4 * XDR_QUADLEN(namlen) + 8;
	if (name_and_cookie > cd->rd_dircount && cd->cookie_offset)
		goto fail;
	cd->rd_dircount -= min(cd->rd_dircount, name_and_cookie);

	cd->cookie_offset = cookie_offset;
skip_entry:
	cd->common.err = nfs_ok;
	return 0;
fail:
	xdr_truncate_encode(xdr, start_offset);
	cd->common.err = nfserr;
	return -EINVAL;
}

static __be32
nfsd4_encode_stateid(struct xdr_stream *xdr, stateid_t *sid)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, sizeof(stateid_t));
	if (!p)
		return nfserr_resource;
	*p++ = cpu_to_be32(sid->si_generation);
	p = xdr_encode_opaque_fixed(p, &sid->si_opaque,
					sizeof(stateid_opaque_t));
	return 0;
}

static __be32
nfsd4_encode_access(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_access *access)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (!nfserr) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			return nfserr_resource;
		*p++ = cpu_to_be32(access->ac_supported);
		*p++ = cpu_to_be32(access->ac_resp_access);
	}
	return nfserr;
}

static __be32 nfsd4_encode_bind_conn_to_session(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_bind_conn_to_session *bcts)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (!nfserr) {
		p = xdr_reserve_space(xdr, NFS4_MAX_SESSIONID_LEN + 8);
		if (!p)
			return nfserr_resource;
		p = xdr_encode_opaque_fixed(p, bcts->sessionid.data,
						NFS4_MAX_SESSIONID_LEN);
		*p++ = cpu_to_be32(bcts->dir);
		/* Sorry, we do not yet support RDMA over 4.1: */
		*p++ = cpu_to_be32(0);
	}
	return nfserr;
}

static __be32
nfsd4_encode_close(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_close *close)
{
	struct xdr_stream *xdr = &resp->xdr;

	if (!nfserr)
		nfserr = nfsd4_encode_stateid(xdr, &close->cl_stateid);

	return nfserr;
}


static __be32
nfsd4_encode_commit(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_commit *commit)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (!nfserr) {
		p = xdr_reserve_space(xdr, NFS4_VERIFIER_SIZE);
		if (!p)
			return nfserr_resource;
		p = xdr_encode_opaque_fixed(p, commit->co_verf.data,
						NFS4_VERIFIER_SIZE);
	}
	return nfserr;
}

static __be32
nfsd4_encode_create(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_create *create)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (!nfserr) {
		p = xdr_reserve_space(xdr, 32);
		if (!p)
			return nfserr_resource;
		p = encode_cinfo(p, &create->cr_cinfo);
		*p++ = cpu_to_be32(2);
		*p++ = cpu_to_be32(create->cr_bmval[0]);
		*p++ = cpu_to_be32(create->cr_bmval[1]);
	}
	return nfserr;
}

static __be32
nfsd4_encode_getattr(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_getattr *getattr)
{
	struct svc_fh *fhp = getattr->ga_fhp;
	struct xdr_stream *xdr = &resp->xdr;

	if (nfserr)
		return nfserr;

	nfserr = nfsd4_encode_fattr(xdr, fhp, fhp->fh_export, fhp->fh_dentry,
				    getattr->ga_bmval,
				    resp->rqstp, 0);
	return nfserr;
}

static __be32
nfsd4_encode_getfh(struct nfsd4_compoundres *resp, __be32 nfserr, struct svc_fh **fhpp)
{
	struct xdr_stream *xdr = &resp->xdr;
	struct svc_fh *fhp = *fhpp;
	unsigned int len;
	__be32 *p;

	if (!nfserr) {
		len = fhp->fh_handle.fh_size;
		p = xdr_reserve_space(xdr, len + 4);
		if (!p)
			return nfserr_resource;
		p = xdr_encode_opaque(p, &fhp->fh_handle.fh_base, len);
	}
	return nfserr;
}

/*
* Including all fields other than the name, a LOCK4denied structure requires
*   8(clientid) + 4(namelen) + 8(offset) + 8(length) + 4(type) = 32 bytes.
*/
static __be32
nfsd4_encode_lock_denied(struct xdr_stream *xdr, struct nfsd4_lock_denied *ld)
{
	struct xdr_netobj *conf = &ld->ld_owner;
	__be32 *p;

again:
	p = xdr_reserve_space(xdr, 32 + XDR_LEN(conf->len));
	if (!p) {
		/*
		 * Don't fail to return the result just because we can't
		 * return the conflicting open:
		 */
		if (conf->len) {
			kfree(conf->data);
			conf->len = 0;
			conf->data = NULL;
			goto again;
		}
		return nfserr_resource;
	}
	p = xdr_encode_hyper(p, ld->ld_start);
	p = xdr_encode_hyper(p, ld->ld_length);
	*p++ = cpu_to_be32(ld->ld_type);
	if (conf->len) {
		p = xdr_encode_opaque_fixed(p, &ld->ld_clientid, 8);
		p = xdr_encode_opaque(p, conf->data, conf->len);
		kfree(conf->data);
	}  else {  /* non - nfsv4 lock in conflict, no clientid nor owner */
		p = xdr_encode_hyper(p, (u64)0); /* clientid */
		*p++ = cpu_to_be32(0); /* length of owner name */
	}
	return nfserr_denied;
}

static __be32
nfsd4_encode_lock(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_lock *lock)
{
	struct xdr_stream *xdr = &resp->xdr;

	if (!nfserr)
		nfserr = nfsd4_encode_stateid(xdr, &lock->lk_resp_stateid);
	else if (nfserr == nfserr_denied)
		nfserr = nfsd4_encode_lock_denied(xdr, &lock->lk_denied);

	return nfserr;
}

static __be32
nfsd4_encode_lockt(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_lockt *lockt)
{
	struct xdr_stream *xdr = &resp->xdr;

	if (nfserr == nfserr_denied)
		nfsd4_encode_lock_denied(xdr, &lockt->lt_denied);
	return nfserr;
}

static __be32
nfsd4_encode_locku(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_locku *locku)
{
	struct xdr_stream *xdr = &resp->xdr;

	if (!nfserr)
		nfserr = nfsd4_encode_stateid(xdr, &locku->lu_stateid);

	return nfserr;
}


static __be32
nfsd4_encode_link(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_link *link)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (!nfserr) {
		p = xdr_reserve_space(xdr, 20);
		if (!p)
			return nfserr_resource;
		p = encode_cinfo(p, &link->li_cinfo);
	}
	return nfserr;
}


static __be32
nfsd4_encode_open(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_open *open)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (nfserr)
		goto out;

	nfserr = nfsd4_encode_stateid(xdr, &open->op_stateid);
	if (nfserr)
		goto out;
	p = xdr_reserve_space(xdr, 40);
	if (!p)
		return nfserr_resource;
	p = encode_cinfo(p, &open->op_cinfo);
	*p++ = cpu_to_be32(open->op_rflags);
	*p++ = cpu_to_be32(2);
	*p++ = cpu_to_be32(open->op_bmval[0]);
	*p++ = cpu_to_be32(open->op_bmval[1]);
	*p++ = cpu_to_be32(open->op_delegate_type);

	switch (open->op_delegate_type) {
	case NFS4_OPEN_DELEGATE_NONE:
		break;
	case NFS4_OPEN_DELEGATE_READ:
		nfserr = nfsd4_encode_stateid(xdr, &open->op_delegate_stateid);
		if (nfserr)
			return nfserr;
		p = xdr_reserve_space(xdr, 20);
		if (!p)
			return nfserr_resource;
		*p++ = cpu_to_be32(open->op_recall);

		/*
		 * TODO: ACE's in delegations
		 */
		*p++ = cpu_to_be32(NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE);
		*p++ = cpu_to_be32(0);
		*p++ = cpu_to_be32(0);
		*p++ = cpu_to_be32(0);   /* XXX: is NULL principal ok? */
		break;
	case NFS4_OPEN_DELEGATE_WRITE:
		nfserr = nfsd4_encode_stateid(xdr, &open->op_delegate_stateid);
		if (nfserr)
			return nfserr;
		p = xdr_reserve_space(xdr, 32);
		if (!p)
			return nfserr_resource;
		*p++ = cpu_to_be32(0);

		/*
		 * TODO: space_limit's in delegations
		 */
		*p++ = cpu_to_be32(NFS4_LIMIT_SIZE);
		*p++ = cpu_to_be32(~(u32)0);
		*p++ = cpu_to_be32(~(u32)0);

		/*
		 * TODO: ACE's in delegations
		 */
		*p++ = cpu_to_be32(NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE);
		*p++ = cpu_to_be32(0);
		*p++ = cpu_to_be32(0);
		*p++ = cpu_to_be32(0);   /* XXX: is NULL principal ok? */
		break;
	case NFS4_OPEN_DELEGATE_NONE_EXT: /* 4.1 */
		switch (open->op_why_no_deleg) {
		case WND4_CONTENTION:
		case WND4_RESOURCE:
			p = xdr_reserve_space(xdr, 8);
			if (!p)
				return nfserr_resource;
			*p++ = cpu_to_be32(open->op_why_no_deleg);
			/* deleg signaling not supported yet: */
			*p++ = cpu_to_be32(0);
			break;
		default:
			p = xdr_reserve_space(xdr, 4);
			if (!p)
				return nfserr_resource;
			*p++ = cpu_to_be32(open->op_why_no_deleg);
		}
		break;
	default:
		BUG();
	}
	/* XXX save filehandle here */
out:
	return nfserr;
}

static __be32
nfsd4_encode_open_confirm(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_open_confirm *oc)
{
	struct xdr_stream *xdr = &resp->xdr;

	if (!nfserr)
		nfserr = nfsd4_encode_stateid(xdr, &oc->oc_resp_stateid);

	return nfserr;
}

static __be32
nfsd4_encode_open_downgrade(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_open_downgrade *od)
{
	struct xdr_stream *xdr = &resp->xdr;

	if (!nfserr)
		nfserr = nfsd4_encode_stateid(xdr, &od->od_stateid);

	return nfserr;
}

static __be32 nfsd4_encode_splice_read(
				struct nfsd4_compoundres *resp,
				struct nfsd4_read *read,
				struct file *file, unsigned long maxcount)
{
	struct xdr_stream *xdr = &resp->xdr;
	struct xdr_buf *buf = xdr->buf;
	u32 eof;
	int space_left;
	__be32 nfserr;
	__be32 *p = xdr->p - 2;

	/* Make sure there will be room for padding if needed */
	if (xdr->end - xdr->p < 1)
		return nfserr_resource;

	nfserr = nfsd_splice_read(read->rd_rqstp, file,
				  read->rd_offset, &maxcount);
	if (nfserr) {
		/*
		 * nfsd_splice_actor may have already messed with the
		 * page length; reset it so as not to confuse
		 * xdr_truncate_encode:
		 */
		buf->page_len = 0;
		return nfserr;
	}

	eof = (read->rd_offset + maxcount >=
	       read->rd_fhp->fh_dentry->d_inode->i_size);

	*(p++) = htonl(eof);
	*(p++) = htonl(maxcount);

	buf->page_len = maxcount;
	buf->len += maxcount;
	xdr->page_ptr += (buf->page_base + maxcount + PAGE_SIZE - 1)
							/ PAGE_SIZE;

	/* Use rest of head for padding and remaining ops: */
	buf->tail[0].iov_base = xdr->p;
	buf->tail[0].iov_len = 0;
	xdr->iov = buf->tail;
	if (maxcount&3) {
		int pad = 4 - (maxcount&3);

		*(xdr->p++) = 0;

		buf->tail[0].iov_base += maxcount&3;
		buf->tail[0].iov_len = pad;
		buf->len += pad;
	}

	space_left = min_t(int, (void *)xdr->end - (void *)xdr->p,
				buf->buflen - buf->len);
	buf->buflen = buf->len + space_left;
	xdr->end = (__be32 *)((void *)xdr->end + space_left);

	return 0;
}

static __be32 nfsd4_encode_readv(struct nfsd4_compoundres *resp,
				 struct nfsd4_read *read,
				 struct file *file, unsigned long maxcount)
{
	struct xdr_stream *xdr = &resp->xdr;
	u32 eof;
	int v;
	int starting_len = xdr->buf->len - 8;
	long len;
	int thislen;
	__be32 nfserr;
	__be32 tmp;
	__be32 *p;
	u32 zzz = 0;
	int pad;

	len = maxcount;
	v = 0;

	thislen = min_t(long, len, ((void *)xdr->end - (void *)xdr->p));
	p = xdr_reserve_space(xdr, (thislen+3)&~3);
	WARN_ON_ONCE(!p);
	resp->rqstp->rq_vec[v].iov_base = p;
	resp->rqstp->rq_vec[v].iov_len = thislen;
	v++;
	len -= thislen;

	while (len) {
		thislen = min_t(long, len, PAGE_SIZE);
		p = xdr_reserve_space(xdr, (thislen+3)&~3);
		WARN_ON_ONCE(!p);
		resp->rqstp->rq_vec[v].iov_base = p;
		resp->rqstp->rq_vec[v].iov_len = thislen;
		v++;
		len -= thislen;
	}
	read->rd_vlen = v;

	nfserr = nfsd_readv(file, read->rd_offset, resp->rqstp->rq_vec,
			read->rd_vlen, &maxcount);
	if (nfserr)
		return nfserr;
	xdr_truncate_encode(xdr, starting_len + 8 + ((maxcount+3)&~3));

	eof = (read->rd_offset + maxcount >=
	       read->rd_fhp->fh_dentry->d_inode->i_size);

	tmp = htonl(eof);
	write_bytes_to_xdr_buf(xdr->buf, starting_len    , &tmp, 4);
	tmp = htonl(maxcount);
	write_bytes_to_xdr_buf(xdr->buf, starting_len + 4, &tmp, 4);

	pad = (maxcount&3) ? 4 - (maxcount&3) : 0;
	write_bytes_to_xdr_buf(xdr->buf, starting_len + 8 + maxcount,
								&zzz, pad);
	return 0;

}

static __be32
nfsd4_encode_read(struct nfsd4_compoundres *resp, __be32 nfserr,
		  struct nfsd4_read *read)
{
	unsigned long maxcount;
	struct xdr_stream *xdr = &resp->xdr;
	struct file *file = read->rd_filp;
	int starting_len = xdr->buf->len;
	struct raparms *ra;
	__be32 *p;
	__be32 err;

	if (nfserr)
		return nfserr;

	p = xdr_reserve_space(xdr, 8); /* eof flag and byte count */
	if (!p) {
		WARN_ON_ONCE(test_bit(RQ_SPLICE_OK, &resp->rqstp->rq_flags));
		return nfserr_resource;
	}
	if (resp->xdr.buf->page_len && test_bit(RQ_SPLICE_OK, &resp->rqstp->rq_flags)) {
		WARN_ON_ONCE(1);
		return nfserr_resource;
	}
	xdr_commit_encode(xdr);

	maxcount = svc_max_payload(resp->rqstp);
	maxcount = min_t(unsigned long, maxcount, (xdr->buf->buflen - xdr->buf->len));
	maxcount = min_t(unsigned long, maxcount, read->rd_length);

	if (!read->rd_filp) {
		err = nfsd_get_tmp_read_open(resp->rqstp, read->rd_fhp,
						&file, &ra);
		if (err)
			goto err_truncate;
	}

	if (file->f_op->splice_read && test_bit(RQ_SPLICE_OK, &resp->rqstp->rq_flags))
		err = nfsd4_encode_splice_read(resp, read, file, maxcount);
	else
		err = nfsd4_encode_readv(resp, read, file, maxcount);

	if (!read->rd_filp)
		nfsd_put_tmp_read_open(file, ra);

err_truncate:
	if (err)
		xdr_truncate_encode(xdr, starting_len);
	return err;
}

static __be32
nfsd4_encode_readlink(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_readlink *readlink)
{
	int maxcount;
	__be32 wire_count;
	int zero = 0;
	struct xdr_stream *xdr = &resp->xdr;
	int length_offset = xdr->buf->len;
	__be32 *p;

	if (nfserr)
		return nfserr;

	p = xdr_reserve_space(xdr, 4);
	if (!p)
		return nfserr_resource;
	maxcount = PAGE_SIZE;

	p = xdr_reserve_space(xdr, maxcount);
	if (!p)
		return nfserr_resource;
	/*
	 * XXX: By default, the ->readlink() VFS op will truncate symlinks
	 * if they would overflow the buffer.  Is this kosher in NFSv4?  If
	 * not, one easy fix is: if ->readlink() precisely fills the buffer,
	 * assume that truncation occurred, and return NFS4ERR_RESOURCE.
	 */
	nfserr = nfsd_readlink(readlink->rl_rqstp, readlink->rl_fhp,
						(char *)p, &maxcount);
	if (nfserr == nfserr_isdir)
		nfserr = nfserr_inval;
	if (nfserr) {
		xdr_truncate_encode(xdr, length_offset);
		return nfserr;
	}

	wire_count = htonl(maxcount);
	write_bytes_to_xdr_buf(xdr->buf, length_offset, &wire_count, 4);
	xdr_truncate_encode(xdr, length_offset + 4 + ALIGN(maxcount, 4));
	if (maxcount & 3)
		write_bytes_to_xdr_buf(xdr->buf, length_offset + 4 + maxcount,
						&zero, 4 - (maxcount&3));
	return 0;
}

static __be32
nfsd4_encode_readdir(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_readdir *readdir)
{
	int maxcount;
	int bytes_left;
	loff_t offset;
	__be64 wire_offset;
	struct xdr_stream *xdr = &resp->xdr;
	int starting_len = xdr->buf->len;
	__be32 *p;

	if (nfserr)
		return nfserr;

	p = xdr_reserve_space(xdr, NFS4_VERIFIER_SIZE);
	if (!p)
		return nfserr_resource;

	/* XXX: Following NFSv3, we ignore the READDIR verifier for now. */
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(0);
	resp->xdr.buf->head[0].iov_len = ((char *)resp->xdr.p)
				- (char *)resp->xdr.buf->head[0].iov_base;

	/*
	 * Number of bytes left for directory entries allowing for the
	 * final 8 bytes of the readdir and a following failed op:
	 */
	bytes_left = xdr->buf->buflen - xdr->buf->len
			- COMPOUND_ERR_SLACK_SPACE - 8;
	if (bytes_left < 0) {
		nfserr = nfserr_resource;
		goto err_no_verf;
	}
	maxcount = min_t(u32, readdir->rd_maxcount, INT_MAX);
	/*
	 * Note the rfc defines rd_maxcount as the size of the
	 * READDIR4resok structure, which includes the verifier above
	 * and the 8 bytes encoded at the end of this function:
	 */
	if (maxcount < 16) {
		nfserr = nfserr_toosmall;
		goto err_no_verf;
	}
	maxcount = min_t(int, maxcount-16, bytes_left);

	/* RFC 3530 14.2.24 allows us to ignore dircount when it's 0: */
	if (!readdir->rd_dircount)
		readdir->rd_dircount = INT_MAX;

	readdir->xdr = xdr;
	readdir->rd_maxcount = maxcount;
	readdir->common.err = 0;
	readdir->cookie_offset = 0;

	offset = readdir->rd_cookie;
	nfserr = nfsd_readdir(readdir->rd_rqstp, readdir->rd_fhp,
			      &offset,
			      &readdir->common, nfsd4_encode_dirent);
	if (nfserr == nfs_ok &&
	    readdir->common.err == nfserr_toosmall &&
	    xdr->buf->len == starting_len + 8) {
		/* nothing encoded; which limit did we hit?: */
		if (maxcount - 16 < bytes_left)
			/* It was the fault of rd_maxcount: */
			nfserr = nfserr_toosmall;
		else
			/* We ran out of buffer space: */
			nfserr = nfserr_resource;
	}
	if (nfserr)
		goto err_no_verf;

	if (readdir->cookie_offset) {
		wire_offset = cpu_to_be64(offset);
		write_bytes_to_xdr_buf(xdr->buf, readdir->cookie_offset,
							&wire_offset, 8);
	}

	p = xdr_reserve_space(xdr, 8);
	if (!p) {
		WARN_ON_ONCE(1);
		goto err_no_verf;
	}
	*p++ = 0;	/* no more entries */
	*p++ = htonl(readdir->common.err == nfserr_eof);

	return 0;
err_no_verf:
	xdr_truncate_encode(xdr, starting_len);
	return nfserr;
}

static __be32
nfsd4_encode_remove(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_remove *remove)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (!nfserr) {
		p = xdr_reserve_space(xdr, 20);
		if (!p)
			return nfserr_resource;
		p = encode_cinfo(p, &remove->rm_cinfo);
	}
	return nfserr;
}

static __be32
nfsd4_encode_rename(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_rename *rename)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (!nfserr) {
		p = xdr_reserve_space(xdr, 40);
		if (!p)
			return nfserr_resource;
		p = encode_cinfo(p, &rename->rn_sinfo);
		p = encode_cinfo(p, &rename->rn_tinfo);
	}
	return nfserr;
}

static __be32
nfsd4_do_encode_secinfo(struct xdr_stream *xdr,
			 __be32 nfserr, struct svc_export *exp)
{
	u32 i, nflavs, supported;
	struct exp_flavor_info *flavs;
	struct exp_flavor_info def_flavs[2];
	__be32 *p, *flavorsp;
	static bool report = true;

	if (nfserr)
		goto out;
	nfserr = nfserr_resource;
	if (exp->ex_nflavors) {
		flavs = exp->ex_flavors;
		nflavs = exp->ex_nflavors;
	} else { /* Handling of some defaults in absence of real secinfo: */
		flavs = def_flavs;
		if (exp->ex_client->flavour->flavour == RPC_AUTH_UNIX) {
			nflavs = 2;
			flavs[0].pseudoflavor = RPC_AUTH_UNIX;
			flavs[1].pseudoflavor = RPC_AUTH_NULL;
		} else if (exp->ex_client->flavour->flavour == RPC_AUTH_GSS) {
			nflavs = 1;
			flavs[0].pseudoflavor
					= svcauth_gss_flavor(exp->ex_client);
		} else {
			nflavs = 1;
			flavs[0].pseudoflavor
					= exp->ex_client->flavour->flavour;
		}
	}

	supported = 0;
	p = xdr_reserve_space(xdr, 4);
	if (!p)
		goto out;
	flavorsp = p++;		/* to be backfilled later */

	for (i = 0; i < nflavs; i++) {
		rpc_authflavor_t pf = flavs[i].pseudoflavor;
		struct rpcsec_gss_info info;

		if (rpcauth_get_gssinfo(pf, &info) == 0) {
			supported++;
			p = xdr_reserve_space(xdr, 4 + 4 +
					      XDR_LEN(info.oid.len) + 4 + 4);
			if (!p)
				goto out;
			*p++ = cpu_to_be32(RPC_AUTH_GSS);
			p = xdr_encode_opaque(p,  info.oid.data, info.oid.len);
			*p++ = cpu_to_be32(info.qop);
			*p++ = cpu_to_be32(info.service);
		} else if (pf < RPC_AUTH_MAXFLAVOR) {
			supported++;
			p = xdr_reserve_space(xdr, 4);
			if (!p)
				goto out;
			*p++ = cpu_to_be32(pf);
		} else {
			if (report)
				pr_warn("NFS: SECINFO: security flavor %u "
					"is not supported\n", pf);
		}
	}

	if (nflavs != supported)
		report = false;
	*flavorsp = htonl(supported);
	nfserr = 0;
out:
	if (exp)
		exp_put(exp);
	return nfserr;
}

static __be32
nfsd4_encode_secinfo(struct nfsd4_compoundres *resp, __be32 nfserr,
		     struct nfsd4_secinfo *secinfo)
{
	struct xdr_stream *xdr = &resp->xdr;

	return nfsd4_do_encode_secinfo(xdr, nfserr, secinfo->si_exp);
}

static __be32
nfsd4_encode_secinfo_no_name(struct nfsd4_compoundres *resp, __be32 nfserr,
		     struct nfsd4_secinfo_no_name *secinfo)
{
	struct xdr_stream *xdr = &resp->xdr;

	return nfsd4_do_encode_secinfo(xdr, nfserr, secinfo->sin_exp);
}

/*
 * The SETATTR encode routine is special -- it always encodes a bitmap,
 * regardless of the error status.
 */
static __be32
nfsd4_encode_setattr(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_setattr *setattr)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	p = xdr_reserve_space(xdr, 16);
	if (!p)
		return nfserr_resource;
	if (nfserr) {
		*p++ = cpu_to_be32(3);
		*p++ = cpu_to_be32(0);
		*p++ = cpu_to_be32(0);
		*p++ = cpu_to_be32(0);
	}
	else {
		*p++ = cpu_to_be32(3);
		*p++ = cpu_to_be32(setattr->sa_bmval[0]);
		*p++ = cpu_to_be32(setattr->sa_bmval[1]);
		*p++ = cpu_to_be32(setattr->sa_bmval[2]);
	}
	return nfserr;
}

static __be32
nfsd4_encode_setclientid(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_setclientid *scd)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (!nfserr) {
		p = xdr_reserve_space(xdr, 8 + NFS4_VERIFIER_SIZE);
		if (!p)
			return nfserr_resource;
		p = xdr_encode_opaque_fixed(p, &scd->se_clientid, 8);
		p = xdr_encode_opaque_fixed(p, &scd->se_confirm,
						NFS4_VERIFIER_SIZE);
	}
	else if (nfserr == nfserr_clid_inuse) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			return nfserr_resource;
		*p++ = cpu_to_be32(0);
		*p++ = cpu_to_be32(0);
	}
	return nfserr;
}

static __be32
nfsd4_encode_write(struct nfsd4_compoundres *resp, __be32 nfserr, struct nfsd4_write *write)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (!nfserr) {
		p = xdr_reserve_space(xdr, 16);
		if (!p)
			return nfserr_resource;
		*p++ = cpu_to_be32(write->wr_bytes_written);
		*p++ = cpu_to_be32(write->wr_how_written);
		p = xdr_encode_opaque_fixed(p, write->wr_verifier.data,
							NFS4_VERIFIER_SIZE);
	}
	return nfserr;
}

static const u32 nfs4_minimal_spo_must_enforce[2] = {
	[1] = 1 << (OP_BIND_CONN_TO_SESSION - 32) |
	      1 << (OP_EXCHANGE_ID - 32) |
	      1 << (OP_CREATE_SESSION - 32) |
	      1 << (OP_DESTROY_SESSION - 32) |
	      1 << (OP_DESTROY_CLIENTID - 32)
};

static __be32
nfsd4_encode_exchange_id(struct nfsd4_compoundres *resp, __be32 nfserr,
			 struct nfsd4_exchange_id *exid)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;
	char *major_id;
	char *server_scope;
	int major_id_sz;
	int server_scope_sz;
	uint64_t minor_id = 0;

	if (nfserr)
		return nfserr;

	major_id = utsname()->nodename;
	major_id_sz = strlen(major_id);
	server_scope = utsname()->nodename;
	server_scope_sz = strlen(server_scope);

	p = xdr_reserve_space(xdr,
		8 /* eir_clientid */ +
		4 /* eir_sequenceid */ +
		4 /* eir_flags */ +
		4 /* spr_how */);
	if (!p)
		return nfserr_resource;

	p = xdr_encode_opaque_fixed(p, &exid->clientid, 8);
	*p++ = cpu_to_be32(exid->seqid);
	*p++ = cpu_to_be32(exid->flags);

	*p++ = cpu_to_be32(exid->spa_how);

	switch (exid->spa_how) {
	case SP4_NONE:
		break;
	case SP4_MACH_CRED:
		/* spo_must_enforce, spo_must_allow */
		p = xdr_reserve_space(xdr, 16);
		if (!p)
			return nfserr_resource;

		/* spo_must_enforce bitmap: */
		*p++ = cpu_to_be32(2);
		*p++ = cpu_to_be32(nfs4_minimal_spo_must_enforce[0]);
		*p++ = cpu_to_be32(nfs4_minimal_spo_must_enforce[1]);
		/* empty spo_must_allow bitmap: */
		*p++ = cpu_to_be32(0);

		break;
	default:
		WARN_ON_ONCE(1);
	}

	p = xdr_reserve_space(xdr,
		8 /* so_minor_id */ +
		4 /* so_major_id.len */ +
		(XDR_QUADLEN(major_id_sz) * 4) +
		4 /* eir_server_scope.len */ +
		(XDR_QUADLEN(server_scope_sz) * 4) +
		4 /* eir_server_impl_id.count (0) */);
	if (!p)
		return nfserr_resource;

	/* The server_owner struct */
	p = xdr_encode_hyper(p, minor_id);      /* Minor id */
	/* major id */
	p = xdr_encode_opaque(p, major_id, major_id_sz);

	/* Server scope */
	p = xdr_encode_opaque(p, server_scope, server_scope_sz);

	/* Implementation id */
	*p++ = cpu_to_be32(0);	/* zero length nfs_impl_id4 array */
	return 0;
}

static __be32
nfsd4_encode_create_session(struct nfsd4_compoundres *resp, __be32 nfserr,
			    struct nfsd4_create_session *sess)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (nfserr)
		return nfserr;

	p = xdr_reserve_space(xdr, 24);
	if (!p)
		return nfserr_resource;
	p = xdr_encode_opaque_fixed(p, sess->sessionid.data,
					NFS4_MAX_SESSIONID_LEN);
	*p++ = cpu_to_be32(sess->seqid);
	*p++ = cpu_to_be32(sess->flags);

	p = xdr_reserve_space(xdr, 28);
	if (!p)
		return nfserr_resource;
	*p++ = cpu_to_be32(0); /* headerpadsz */
	*p++ = cpu_to_be32(sess->fore_channel.maxreq_sz);
	*p++ = cpu_to_be32(sess->fore_channel.maxresp_sz);
	*p++ = cpu_to_be32(sess->fore_channel.maxresp_cached);
	*p++ = cpu_to_be32(sess->fore_channel.maxops);
	*p++ = cpu_to_be32(sess->fore_channel.maxreqs);
	*p++ = cpu_to_be32(sess->fore_channel.nr_rdma_attrs);

	if (sess->fore_channel.nr_rdma_attrs) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			return nfserr_resource;
		*p++ = cpu_to_be32(sess->fore_channel.rdma_attrs);
	}

	p = xdr_reserve_space(xdr, 28);
	if (!p)
		return nfserr_resource;
	*p++ = cpu_to_be32(0); /* headerpadsz */
	*p++ = cpu_to_be32(sess->back_channel.maxreq_sz);
	*p++ = cpu_to_be32(sess->back_channel.maxresp_sz);
	*p++ = cpu_to_be32(sess->back_channel.maxresp_cached);
	*p++ = cpu_to_be32(sess->back_channel.maxops);
	*p++ = cpu_to_be32(sess->back_channel.maxreqs);
	*p++ = cpu_to_be32(sess->back_channel.nr_rdma_attrs);

	if (sess->back_channel.nr_rdma_attrs) {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			return nfserr_resource;
		*p++ = cpu_to_be32(sess->back_channel.rdma_attrs);
	}
	return 0;
}

static __be32
nfsd4_encode_sequence(struct nfsd4_compoundres *resp, __be32 nfserr,
		      struct nfsd4_sequence *seq)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (nfserr)
		return nfserr;

	p = xdr_reserve_space(xdr, NFS4_MAX_SESSIONID_LEN + 20);
	if (!p)
		return nfserr_resource;
	p = xdr_encode_opaque_fixed(p, seq->sessionid.data,
					NFS4_MAX_SESSIONID_LEN);
	*p++ = cpu_to_be32(seq->seqid);
	*p++ = cpu_to_be32(seq->slotid);
	/* Note slotid's are numbered from zero: */
	*p++ = cpu_to_be32(seq->maxslots - 1); /* sr_highest_slotid */
	*p++ = cpu_to_be32(seq->maxslots - 1); /* sr_target_highest_slotid */
	*p++ = cpu_to_be32(seq->status_flags);

	resp->cstate.data_offset = xdr->buf->len; /* DRC cache data pointer */
	return 0;
}

static __be32
nfsd4_encode_test_stateid(struct nfsd4_compoundres *resp, __be32 nfserr,
			  struct nfsd4_test_stateid *test_stateid)
{
	struct xdr_stream *xdr = &resp->xdr;
	struct nfsd4_test_stateid_id *stateid, *next;
	__be32 *p;

	if (nfserr)
		return nfserr;

	p = xdr_reserve_space(xdr, 4 + (4 * test_stateid->ts_num_ids));
	if (!p)
		return nfserr_resource;
	*p++ = htonl(test_stateid->ts_num_ids);

	list_for_each_entry_safe(stateid, next, &test_stateid->ts_stateid_list, ts_id_list) {
		*p++ = stateid->ts_id_status;
	}

	return nfserr;
}

#ifdef CONFIG_NFSD_PNFS
static __be32
nfsd4_encode_getdeviceinfo(struct nfsd4_compoundres *resp, __be32 nfserr,
		struct nfsd4_getdeviceinfo *gdev)
{
	struct xdr_stream *xdr = &resp->xdr;
	const struct nfsd4_layout_ops *ops =
		nfsd4_layout_ops[gdev->gd_layout_type];
	u32 starting_len = xdr->buf->len, needed_len;
	__be32 *p;

	dprintk("%s: err %d\n", __func__, nfserr);
	if (nfserr)
		goto out;

	nfserr = nfserr_resource;
	p = xdr_reserve_space(xdr, 4);
	if (!p)
		goto out;

	*p++ = cpu_to_be32(gdev->gd_layout_type);

	/* If maxcount is 0 then just update notifications */
	if (gdev->gd_maxcount != 0) {
		nfserr = ops->encode_getdeviceinfo(xdr, gdev);
		if (nfserr) {
			/*
			 * We don't bother to burden the layout drivers with
			 * enforcing gd_maxcount, just tell the client to
			 * come back with a bigger buffer if it's not enough.
			 */
			if (xdr->buf->len + 4 > gdev->gd_maxcount)
				goto toosmall;
			goto out;
		}
	}

	nfserr = nfserr_resource;
	if (gdev->gd_notify_types) {
		p = xdr_reserve_space(xdr, 4 + 4);
		if (!p)
			goto out;
		*p++ = cpu_to_be32(1);			/* bitmap length */
		*p++ = cpu_to_be32(gdev->gd_notify_types);
	} else {
		p = xdr_reserve_space(xdr, 4);
		if (!p)
			goto out;
		*p++ = 0;
	}

	nfserr = 0;
out:
	kfree(gdev->gd_device);
	dprintk("%s: done: %d\n", __func__, be32_to_cpu(nfserr));
	return nfserr;

toosmall:
	dprintk("%s: maxcount too small\n", __func__);
	needed_len = xdr->buf->len + 4 /* notifications */;
	xdr_truncate_encode(xdr, starting_len);
	p = xdr_reserve_space(xdr, 4);
	if (!p) {
		nfserr = nfserr_resource;
	} else {
		*p++ = cpu_to_be32(needed_len);
		nfserr = nfserr_toosmall;
	}
	goto out;
}

static __be32
nfsd4_encode_layoutget(struct nfsd4_compoundres *resp, __be32 nfserr,
		struct nfsd4_layoutget *lgp)
{
	struct xdr_stream *xdr = &resp->xdr;
	const struct nfsd4_layout_ops *ops =
		nfsd4_layout_ops[lgp->lg_layout_type];
	__be32 *p;

	dprintk("%s: err %d\n", __func__, nfserr);
	if (nfserr)
		goto out;

	nfserr = nfserr_resource;
	p = xdr_reserve_space(xdr, 36 + sizeof(stateid_opaque_t));
	if (!p)
		goto out;

	*p++ = cpu_to_be32(1);	/* we always set return-on-close */
	*p++ = cpu_to_be32(lgp->lg_sid.si_generation);
	p = xdr_encode_opaque_fixed(p, &lgp->lg_sid.si_opaque,
				    sizeof(stateid_opaque_t));

	*p++ = cpu_to_be32(1);	/* we always return a single layout */
	p = xdr_encode_hyper(p, lgp->lg_seg.offset);
	p = xdr_encode_hyper(p, lgp->lg_seg.length);
	*p++ = cpu_to_be32(lgp->lg_seg.iomode);
	*p++ = cpu_to_be32(lgp->lg_layout_type);

	nfserr = ops->encode_layoutget(xdr, lgp);
out:
	kfree(lgp->lg_content);
	return nfserr;
}

static __be32
nfsd4_encode_layoutcommit(struct nfsd4_compoundres *resp, __be32 nfserr,
			  struct nfsd4_layoutcommit *lcp)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (nfserr)
		return nfserr;

	p = xdr_reserve_space(xdr, 4);
	if (!p)
		return nfserr_resource;
	*p++ = cpu_to_be32(lcp->lc_size_chg);
	if (lcp->lc_size_chg) {
		p = xdr_reserve_space(xdr, 8);
		if (!p)
			return nfserr_resource;
		p = xdr_encode_hyper(p, lcp->lc_newsize);
	}

	return nfs_ok;
}

static __be32
nfsd4_encode_layoutreturn(struct nfsd4_compoundres *resp, __be32 nfserr,
		struct nfsd4_layoutreturn *lrp)
{
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;

	if (nfserr)
		return nfserr;

	p = xdr_reserve_space(xdr, 4);
	if (!p)
		return nfserr_resource;
	*p++ = cpu_to_be32(lrp->lrs_present);
	if (lrp->lrs_present)
		nfsd4_encode_stateid(xdr, &lrp->lr_sid);
	return nfs_ok;
}
#endif /* CONFIG_NFSD_PNFS */

static __be32
nfsd4_encode_seek(struct nfsd4_compoundres *resp, __be32 nfserr,
		  struct nfsd4_seek *seek)
{
	__be32 *p;

	if (nfserr)
		return nfserr;

	p = xdr_reserve_space(&resp->xdr, 4 + 8);
	*p++ = cpu_to_be32(seek->seek_eof);
	p = xdr_encode_hyper(p, seek->seek_pos);

	return nfserr;
}

static __be32
nfsd4_encode_noop(struct nfsd4_compoundres *resp, __be32 nfserr, void *p)
{
	return nfserr;
}

typedef __be32(* nfsd4_enc)(struct nfsd4_compoundres *, __be32, void *);

/*
 * Note: nfsd4_enc_ops vector is shared for v4.0 and v4.1
 * since we don't need to filter out obsolete ops as this is
 * done in the decoding phase.
 */
static nfsd4_enc nfsd4_enc_ops[] = {
	[OP_ACCESS]		= (nfsd4_enc)nfsd4_encode_access,
	[OP_CLOSE]		= (nfsd4_enc)nfsd4_encode_close,
	[OP_COMMIT]		= (nfsd4_enc)nfsd4_encode_commit,
	[OP_CREATE]		= (nfsd4_enc)nfsd4_encode_create,
	[OP_DELEGPURGE]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_DELEGRETURN]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_GETATTR]		= (nfsd4_enc)nfsd4_encode_getattr,
	[OP_GETFH]		= (nfsd4_enc)nfsd4_encode_getfh,
	[OP_LINK]		= (nfsd4_enc)nfsd4_encode_link,
	[OP_LOCK]		= (nfsd4_enc)nfsd4_encode_lock,
	[OP_LOCKT]		= (nfsd4_enc)nfsd4_encode_lockt,
	[OP_LOCKU]		= (nfsd4_enc)nfsd4_encode_locku,
	[OP_LOOKUP]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_LOOKUPP]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_NVERIFY]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_OPEN]		= (nfsd4_enc)nfsd4_encode_open,
	[OP_OPENATTR]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_OPEN_CONFIRM]	= (nfsd4_enc)nfsd4_encode_open_confirm,
	[OP_OPEN_DOWNGRADE]	= (nfsd4_enc)nfsd4_encode_open_downgrade,
	[OP_PUTFH]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_PUTPUBFH]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_PUTROOTFH]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_READ]		= (nfsd4_enc)nfsd4_encode_read,
	[OP_READDIR]		= (nfsd4_enc)nfsd4_encode_readdir,
	[OP_READLINK]		= (nfsd4_enc)nfsd4_encode_readlink,
	[OP_REMOVE]		= (nfsd4_enc)nfsd4_encode_remove,
	[OP_RENAME]		= (nfsd4_enc)nfsd4_encode_rename,
	[OP_RENEW]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_RESTOREFH]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_SAVEFH]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_SECINFO]		= (nfsd4_enc)nfsd4_encode_secinfo,
	[OP_SETATTR]		= (nfsd4_enc)nfsd4_encode_setattr,
	[OP_SETCLIENTID]	= (nfsd4_enc)nfsd4_encode_setclientid,
	[OP_SETCLIENTID_CONFIRM] = (nfsd4_enc)nfsd4_encode_noop,
	[OP_VERIFY]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_WRITE]		= (nfsd4_enc)nfsd4_encode_write,
	[OP_RELEASE_LOCKOWNER]	= (nfsd4_enc)nfsd4_encode_noop,

	/* NFSv4.1 operations */
	[OP_BACKCHANNEL_CTL]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_BIND_CONN_TO_SESSION] = (nfsd4_enc)nfsd4_encode_bind_conn_to_session,
	[OP_EXCHANGE_ID]	= (nfsd4_enc)nfsd4_encode_exchange_id,
	[OP_CREATE_SESSION]	= (nfsd4_enc)nfsd4_encode_create_session,
	[OP_DESTROY_SESSION]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_FREE_STATEID]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_GET_DIR_DELEGATION]	= (nfsd4_enc)nfsd4_encode_noop,
#ifdef CONFIG_NFSD_PNFS
	[OP_GETDEVICEINFO]	= (nfsd4_enc)nfsd4_encode_getdeviceinfo,
	[OP_GETDEVICELIST]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_LAYOUTCOMMIT]	= (nfsd4_enc)nfsd4_encode_layoutcommit,
	[OP_LAYOUTGET]		= (nfsd4_enc)nfsd4_encode_layoutget,
	[OP_LAYOUTRETURN]	= (nfsd4_enc)nfsd4_encode_layoutreturn,
#else
	[OP_GETDEVICEINFO]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_GETDEVICELIST]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_LAYOUTCOMMIT]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_LAYOUTGET]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_LAYOUTRETURN]	= (nfsd4_enc)nfsd4_encode_noop,
#endif
	[OP_SECINFO_NO_NAME]	= (nfsd4_enc)nfsd4_encode_secinfo_no_name,
	[OP_SEQUENCE]		= (nfsd4_enc)nfsd4_encode_sequence,
	[OP_SET_SSV]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_TEST_STATEID]	= (nfsd4_enc)nfsd4_encode_test_stateid,
	[OP_WANT_DELEGATION]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_DESTROY_CLIENTID]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_RECLAIM_COMPLETE]	= (nfsd4_enc)nfsd4_encode_noop,

	/* NFSv4.2 operations */
	[OP_ALLOCATE]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_COPY]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_COPY_NOTIFY]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_DEALLOCATE]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_IO_ADVISE]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_LAYOUTERROR]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_LAYOUTSTATS]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_OFFLOAD_CANCEL]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_OFFLOAD_STATUS]	= (nfsd4_enc)nfsd4_encode_noop,
	[OP_READ_PLUS]		= (nfsd4_enc)nfsd4_encode_noop,
	[OP_SEEK]		= (nfsd4_enc)nfsd4_encode_seek,
	[OP_WRITE_SAME]		= (nfsd4_enc)nfsd4_encode_noop,
};

/*
 * Calculate whether we still have space to encode repsize bytes.
 * There are two considerations:
 *     - For NFS versions >=4.1, the size of the reply must stay within
 *       session limits
 *     - For all NFS versions, we must stay within limited preallocated
 *       buffer space.
 *
 * This is called before the operation is processed, so can only provide
 * an upper estimate.  For some nonidempotent operations (such as
 * getattr), it's not necessarily a problem if that estimate is wrong,
 * as we can fail it after processing without significant side effects.
 */
__be32 nfsd4_check_resp_size(struct nfsd4_compoundres *resp, u32 respsize)
{
	struct xdr_buf *buf = &resp->rqstp->rq_res;
	struct nfsd4_slot *slot = resp->cstate.slot;

	if (buf->len + respsize <= buf->buflen)
		return nfs_ok;
	if (!nfsd4_has_session(&resp->cstate))
		return nfserr_resource;
	if (slot->sl_flags & NFSD4_SLOT_CACHETHIS) {
		WARN_ON_ONCE(1);
		return nfserr_rep_too_big_to_cache;
	}
	return nfserr_rep_too_big;
}

void
nfsd4_encode_operation(struct nfsd4_compoundres *resp, struct nfsd4_op *op)
{
	struct xdr_stream *xdr = &resp->xdr;
	struct nfs4_stateowner *so = resp->cstate.replay_owner;
	struct svc_rqst *rqstp = resp->rqstp;
	int post_err_offset;
	nfsd4_enc encoder;
	__be32 *p;

	p = xdr_reserve_space(xdr, 8);
	if (!p) {
		WARN_ON_ONCE(1);
		return;
	}
	*p++ = cpu_to_be32(op->opnum);
	post_err_offset = xdr->buf->len;

	if (op->opnum == OP_ILLEGAL)
		goto status;
	BUG_ON(op->opnum < 0 || op->opnum >= ARRAY_SIZE(nfsd4_enc_ops) ||
	       !nfsd4_enc_ops[op->opnum]);
	encoder = nfsd4_enc_ops[op->opnum];
	op->status = encoder(resp, op->status, &op->u);
	xdr_commit_encode(xdr);

	/* nfsd4_check_resp_size guarantees enough room for error status */
	if (!op->status) {
		int space_needed = 0;
		if (!nfsd4_last_compound_op(rqstp))
			space_needed = COMPOUND_ERR_SLACK_SPACE;
		op->status = nfsd4_check_resp_size(resp, space_needed);
	}
	if (op->status == nfserr_resource && nfsd4_has_session(&resp->cstate)) {
		struct nfsd4_slot *slot = resp->cstate.slot;

		if (slot->sl_flags & NFSD4_SLOT_CACHETHIS)
			op->status = nfserr_rep_too_big_to_cache;
		else
			op->status = nfserr_rep_too_big;
	}
	if (op->status == nfserr_resource ||
	    op->status == nfserr_rep_too_big ||
	    op->status == nfserr_rep_too_big_to_cache) {
		/*
		 * The operation may have already been encoded or
		 * partially encoded.  No op returns anything additional
		 * in the case of one of these three errors, so we can
		 * just truncate back to after the status.  But it's a
		 * bug if we had to do this on a non-idempotent op:
		 */
		warn_on_nonidempotent_op(op);
		xdr_truncate_encode(xdr, post_err_offset);
	}
	if (so) {
		int len = xdr->buf->len - post_err_offset;

		so->so_replay.rp_status = op->status;
		so->so_replay.rp_buflen = len;
		read_bytes_from_xdr_buf(xdr->buf, post_err_offset,
						so->so_replay.rp_buf, len);
	}
status:
	/* Note that op->status is already in network byte order: */
	write_bytes_to_xdr_buf(xdr->buf, post_err_offset - 4, &op->status, 4);
}

/* 
 * Encode the reply stored in the stateowner reply cache 
 * 
 * XDR note: do not encode rp->rp_buflen: the buffer contains the
 * previously sent already encoded operation.
 */
void
nfsd4_encode_replay(struct xdr_stream *xdr, struct nfsd4_op *op)
{
	__be32 *p;
	struct nfs4_replay *rp = op->replay;

	BUG_ON(!rp);

	p = xdr_reserve_space(xdr, 8 + rp->rp_buflen);
	if (!p) {
		WARN_ON_ONCE(1);
		return;
	}
	*p++ = cpu_to_be32(op->opnum);
	*p++ = rp->rp_status;  /* already xdr'ed */

	p = xdr_encode_opaque_fixed(p, rp->rp_buf, rp->rp_buflen);
}

int
nfs4svc_encode_voidres(struct svc_rqst *rqstp, __be32 *p, void *dummy)
{
        return xdr_ressize_check(rqstp, p);
}

int nfsd4_release_compoundargs(void *rq, __be32 *p, void *resp)
{
	struct svc_rqst *rqstp = rq;
	struct nfsd4_compoundargs *args = rqstp->rq_argp;

	if (args->ops != args->iops) {
		kfree(args->ops);
		args->ops = args->iops;
	}
	kfree(args->tmpp);
	args->tmpp = NULL;
	while (args->to_free) {
		struct svcxdr_tmpbuf *tb = args->to_free;
		args->to_free = tb->next;
		kfree(tb);
	}
	return 1;
}

int
nfs4svc_decode_compoundargs(struct svc_rqst *rqstp, __be32 *p, struct nfsd4_compoundargs *args)
{
	if (rqstp->rq_arg.head[0].iov_len % 4) {
		/* client is nuts */
		dprintk("%s: compound not properly padded! (peeraddr=%pISc xid=0x%x)",
			__func__, svc_addr(rqstp), be32_to_cpu(rqstp->rq_xid));
		return 0;
	}
	args->p = p;
	args->end = rqstp->rq_arg.head[0].iov_base + rqstp->rq_arg.head[0].iov_len;
	args->pagelist = rqstp->rq_arg.pages;
	args->pagelen = rqstp->rq_arg.page_len;
	args->tmpp = NULL;
	args->to_free = NULL;
	args->ops = args->iops;
	args->rqstp = rqstp;

	return !nfsd4_decode_compound(args);
}

int
nfs4svc_encode_compoundres(struct svc_rqst *rqstp, __be32 *p, struct nfsd4_compoundres *resp)
{
	/*
	 * All that remains is to write the tag and operation count...
	 */
	struct xdr_buf *buf = resp->xdr.buf;

	WARN_ON_ONCE(buf->len != buf->head[0].iov_len + buf->page_len +
				 buf->tail[0].iov_len);

	rqstp->rq_next_page = resp->xdr.page_ptr + 1;

	p = resp->tagp;
	*p++ = htonl(resp->taglen);
	memcpy(p, resp->tag, resp->taglen);
	p += XDR_QUADLEN(resp->taglen);
	*p++ = htonl(resp->opcnt);

	nfsd4_sequence_done(resp);
	return 1;
}

/*
 * Local variables:
 *  c-basic-offset: 8
 * End:
 */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs4xdr.c */
/************************************************************/
/*
*  Copyright (c) 2001 The Regents of the University of Michigan.
*  All rights reserved.
*
*  Kendrick Smith <kmsmith@umich.edu>
*  Andy Adamson <kandros@umich.edu>
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions
*  are met:
*
*  1. Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*  2. Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in the
*     documentation and/or other materials provided with the distribution.
*  3. Neither the name of the University nor the names of its
*     contributors may be used to endorse or promote products derived
*     from this software without specific prior written permission.
*
*  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
*  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
*  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
*  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
*  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
*  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
*  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
*  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
*  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
*  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
*  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

// #include <linux/file.h>
// #include <linux/fs.h>
// #include <linux/slab.h>
// #include <linux/namei.h>
// #include <linux/swap.h>
// #include <linux/pagemap.h>
#include <linux/ratelimit.h>
// #include <linux/sunrpc/svcauth_gss.h>
// #include <linux/sunrpc/addr.h>
// #include <linux/jhash.h>
// #include "xdr4.h"
#include "xdr4cb.h"
// #include "vfs.h"
// #include "current_stateid.h"
#include "../../inc/__fss.h"

// #include "netns.h"
// #include "pnfs.h"

#define NFSDDBG_FACILITY                NFSDDBG_PROC

#define all_ones {{~0,~0},~0}
static const stateid_t one_stateid = {
	.si_generation = ~0,
	.si_opaque = all_ones,
};
static const stateid_t zero_stateid = {
	/* all fields zero */
};
static const stateid_t currentstateid = {
	.si_generation = 1,
};

static u64 current_sessionid = 1;

#define ZERO_STATEID(stateid) (!memcmp((stateid), &zero_stateid, sizeof(stateid_t)))
#define ONE_STATEID(stateid)  (!memcmp((stateid), &one_stateid, sizeof(stateid_t)))
#define CURRENT_STATEID(stateid) (!memcmp((stateid), &currentstateid, sizeof(stateid_t)))

/* forward declarations */
static bool check_for_locks(struct nfs4_file *fp, struct nfs4_lockowner *lowner);
static void nfs4_free_ol_stateid(struct nfs4_stid *stid);

/* Locking: */

/*
 * Currently used for the del_recall_lru and file hash table.  In an
 * effort to decrease the scope of the client_mutex, this spinlock may
 * eventually cover more:
 */
static DEFINE_SPINLOCK(state_lock);

/*
 * A waitqueue for all in-progress 4.0 CLOSE operations that are waiting for
 * the refcount on the open stateid to drop.
 */
static DECLARE_WAIT_QUEUE_HEAD(close_wq);

static struct kmem_cache *openowner_slab;
static struct kmem_cache *lockowner_slab;
static struct kmem_cache *file_slab;
static struct kmem_cache *stateid_slab;
static struct kmem_cache *deleg_slab;

static void free_session(struct nfsd4_session *);

static struct nfsd4_callback_ops nfsd4_cb_recall_ops;

static bool is_session_dead(struct nfsd4_session *ses)
{
	return ses->se_flags & NFS4_SESSION_DEAD;
}

static __be32 mark_session_dead_locked(struct nfsd4_session *ses, int ref_held_by_me)
{
	if (atomic_read(&ses->se_ref) > ref_held_by_me)
		return nfserr_jukebox;
	ses->se_flags |= NFS4_SESSION_DEAD;
	return nfs_ok;
}

static bool is_client_expired(struct nfs4_client *clp)
{
	return clp->cl_time == 0;
}

static __be32 get_client_locked(struct nfs4_client *clp)
{
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	lockdep_assert_held(&nn->client_lock);

	if (is_client_expired(clp))
		return nfserr_expired;
	atomic_inc(&clp->cl_refcount);
	return nfs_ok;
}

/* must be called under the client_lock */
static inline void
renew_client_locked(struct nfs4_client *clp)
{
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	if (is_client_expired(clp)) {
		WARN_ON(1);
		printk("%s: client (clientid %08x/%08x) already expired\n",
			__func__,
			clp->cl_clientid.cl_boot,
			clp->cl_clientid.cl_id);
		return;
	}

	dprintk("renewing client (clientid %08x/%08x)\n",
			clp->cl_clientid.cl_boot,
			clp->cl_clientid.cl_id);
	list_move_tail(&clp->cl_lru, &nn->client_lru);
	clp->cl_time = get_seconds();
}

static void put_client_renew_locked(struct nfs4_client *clp)
{
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	lockdep_assert_held(&nn->client_lock);

	if (!atomic_dec_and_test(&clp->cl_refcount))
		return;
	if (!is_client_expired(clp))
		renew_client_locked(clp);
}

static void put_client_renew(struct nfs4_client *clp)
{
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	if (!atomic_dec_and_lock(&clp->cl_refcount, &nn->client_lock))
		return;
	if (!is_client_expired(clp))
		renew_client_locked(clp);
	spin_unlock(&nn->client_lock);
}

static __be32 nfsd4_get_session_locked(struct nfsd4_session *ses)
{
	__be32 status;

	if (is_session_dead(ses))
		return nfserr_badsession;
	status = get_client_locked(ses->se_client);
	if (status)
		return status;
	atomic_inc(&ses->se_ref);
	return nfs_ok;
}

static void nfsd4_put_session_locked(struct nfsd4_session *ses)
{
	struct nfs4_client *clp = ses->se_client;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	lockdep_assert_held(&nn->client_lock);

	if (atomic_dec_and_test(&ses->se_ref) && is_session_dead(ses))
		free_session(ses);
	put_client_renew_locked(clp);
}

static void nfsd4_put_session(struct nfsd4_session *ses)
{
	struct nfs4_client *clp = ses->se_client;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	spin_lock(&nn->client_lock);
	nfsd4_put_session_locked(ses);
	spin_unlock(&nn->client_lock);
}

static inline struct nfs4_stateowner *
nfs4_get_stateowner(struct nfs4_stateowner *sop)
{
	atomic_inc(&sop->so_count);
	return sop;
}

static int
same_owner_str(struct nfs4_stateowner *sop, struct xdr_netobj *owner)
{
	return (sop->so_owner.len == owner->len) &&
		0 == memcmp(sop->so_owner.data, owner->data, owner->len);
}

static struct nfs4_openowner *
find_openstateowner_str_locked(unsigned int hashval, struct nfsd4_open *open,
			struct nfs4_client *clp)
{
	struct nfs4_stateowner *so;

	lockdep_assert_held(&clp->cl_lock);

	list_for_each_entry(so, &clp->cl_ownerstr_hashtbl[hashval],
			    so_strhash) {
		if (!so->so_is_open_owner)
			continue;
		if (same_owner_str(so, &open->op_owner))
			return openowner(nfs4_get_stateowner(so));
	}
	return NULL;
}

static struct nfs4_openowner *
find_openstateowner_str(unsigned int hashval, struct nfsd4_open *open,
			struct nfs4_client *clp)
{
	struct nfs4_openowner *oo;

	spin_lock(&clp->cl_lock);
	oo = find_openstateowner_str_locked(hashval, open, clp);
	spin_unlock(&clp->cl_lock);
	return oo;
}

static inline u32
opaque_hashval(const void *ptr, int nbytes)
{
	unsigned char *cptr = (unsigned char *) ptr;

	u32 x = 0;
	while (nbytes--) {
		x *= 37;
		x += *cptr++;
	}
	return x;
}

static void nfsd4_free_file_rcu(struct rcu_head *rcu)
{
	struct nfs4_file *fp = container_of(rcu, struct nfs4_file, fi_rcu);

	kmem_cache_free(file_slab, fp);
}

void
put_nfs4_file(struct nfs4_file *fi)
{
	might_lock(&state_lock);

	if (atomic_dec_and_lock(&fi->fi_ref, &state_lock)) {
		hlist_del_rcu(&fi->fi_hash);
		spin_unlock(&state_lock);
		WARN_ON_ONCE(!list_empty(&fi->fi_delegations));
		call_rcu(&fi->fi_rcu, nfsd4_free_file_rcu);
	}
}

static struct file *
__nfs4_get_fd(struct nfs4_file *f, int oflag)
{
	if (f->fi_fds[oflag])
		return get_file(f->fi_fds[oflag]);
	return NULL;
}

static struct file *
find_writeable_file_locked(struct nfs4_file *f)
{
	struct file *ret;

	lockdep_assert_held(&f->fi_lock);

	ret = __nfs4_get_fd(f, O_WRONLY);
	if (!ret)
		ret = __nfs4_get_fd(f, O_RDWR);
	return ret;
}

static struct file *
find_writeable_file(struct nfs4_file *f)
{
	struct file *ret;

	spin_lock(&f->fi_lock);
	ret = find_writeable_file_locked(f);
	spin_unlock(&f->fi_lock);

	return ret;
}

static struct file *find_readable_file_locked(struct nfs4_file *f)
{
	struct file *ret;

	lockdep_assert_held(&f->fi_lock);

	ret = __nfs4_get_fd(f, O_RDONLY);
	if (!ret)
		ret = __nfs4_get_fd(f, O_RDWR);
	return ret;
}

static struct file *
find_readable_file(struct nfs4_file *f)
{
	struct file *ret;

	spin_lock(&f->fi_lock);
	ret = find_readable_file_locked(f);
	spin_unlock(&f->fi_lock);

	return ret;
}

struct file *
find_any_file(struct nfs4_file *f)
{
	struct file *ret;

	spin_lock(&f->fi_lock);
	ret = __nfs4_get_fd(f, O_RDWR);
	if (!ret) {
		ret = __nfs4_get_fd(f, O_WRONLY);
		if (!ret)
			ret = __nfs4_get_fd(f, O_RDONLY);
	}
	spin_unlock(&f->fi_lock);
	return ret;
}

static atomic_long_t num_delegations;
unsigned long max_delegations;

/*
 * Open owner state (share locks)
 */

/* hash tables for lock and open owners */
#define OWNER_HASH_BITS              8
#define OWNER_HASH_SIZE             (1 << OWNER_HASH_BITS)
#define OWNER_HASH_MASK             (OWNER_HASH_SIZE - 1)

static unsigned int ownerstr_hashval(struct xdr_netobj *ownername)
{
	unsigned int ret;

	ret = opaque_hashval(ownername->data, ownername->len);
	return ret & OWNER_HASH_MASK;
}

/* hash table for nfs4_file */
#define FILE_HASH_BITS                   8
#define FILE_HASH_SIZE                  (1 << FILE_HASH_BITS)

static unsigned int nfsd_fh_hashval(struct knfsd_fh *fh)
{
	return jhash2(fh->fh_base.fh_pad, XDR_QUADLEN(fh->fh_size), 0);
}

static unsigned int file_hashval(struct knfsd_fh *fh)
{
	return nfsd_fh_hashval(fh) & (FILE_HASH_SIZE - 1);
}

static struct hlist_head file_hashtbl[FILE_HASH_SIZE];

static void
__nfs4_file_get_access(struct nfs4_file *fp, u32 access)
{
	lockdep_assert_held(&fp->fi_lock);

	if (access & NFS4_SHARE_ACCESS_WRITE)
		atomic_inc(&fp->fi_access[O_WRONLY]);
	if (access & NFS4_SHARE_ACCESS_READ)
		atomic_inc(&fp->fi_access[O_RDONLY]);
}

static __be32
nfs4_file_get_access(struct nfs4_file *fp, u32 access)
{
	lockdep_assert_held(&fp->fi_lock);

	/* Does this access mode make sense? */
	if (access & ~NFS4_SHARE_ACCESS_BOTH)
		return nfserr_inval;

	/* Does it conflict with a deny mode already set? */
	if ((access & fp->fi_share_deny) != 0)
		return nfserr_share_denied;

	__nfs4_file_get_access(fp, access);
	return nfs_ok;
}

static __be32 nfs4_file_check_deny(struct nfs4_file *fp, u32 deny)
{
	/* Common case is that there is no deny mode. */
	if (deny) {
		/* Does this deny mode make sense? */
		if (deny & ~NFS4_SHARE_DENY_BOTH)
			return nfserr_inval;

		if ((deny & NFS4_SHARE_DENY_READ) &&
		    atomic_read(&fp->fi_access[O_RDONLY]))
			return nfserr_share_denied;

		if ((deny & NFS4_SHARE_DENY_WRITE) &&
		    atomic_read(&fp->fi_access[O_WRONLY]))
			return nfserr_share_denied;
	}
	return nfs_ok;
}

static void __nfs4_file_put_access(struct nfs4_file *fp, int oflag)
{
	might_lock(&fp->fi_lock);

	if (atomic_dec_and_lock(&fp->fi_access[oflag], &fp->fi_lock)) {
		struct file *f1 = NULL;
		struct file *f2 = NULL;

		swap(f1, fp->fi_fds[oflag]);
		if (atomic_read(&fp->fi_access[1 - oflag]) == 0)
			swap(f2, fp->fi_fds[O_RDWR]);
		spin_unlock(&fp->fi_lock);
		if (f1)
			fput(f1);
		if (f2)
			fput(f2);
	}
}

static void nfs4_file_put_access(struct nfs4_file *fp, u32 access)
{
	WARN_ON_ONCE(access & ~NFS4_SHARE_ACCESS_BOTH);

	if (access & NFS4_SHARE_ACCESS_WRITE)
		__nfs4_file_put_access(fp, O_WRONLY);
	if (access & NFS4_SHARE_ACCESS_READ)
		__nfs4_file_put_access(fp, O_RDONLY);
}

struct nfs4_stid *nfs4_alloc_stid(struct nfs4_client *cl,
					 struct kmem_cache *slab)
{
	struct nfs4_stid *stid;
	int new_id;

	stid = kmem_cache_zalloc(slab, GFP_KERNEL);
	if (!stid)
		return NULL;

	idr_preload(GFP_KERNEL);
	spin_lock(&cl->cl_lock);
	new_id = idr_alloc_cyclic(&cl->cl_stateids, stid, 0, 0, GFP_NOWAIT);
	spin_unlock(&cl->cl_lock);
	idr_preload_end();
	if (new_id < 0)
		goto out_free;
	stid->sc_client = cl;
	stid->sc_stateid.si_opaque.so_id = new_id;
	stid->sc_stateid.si_opaque.so_clid = cl->cl_clientid;
	/* Will be incremented before return to client: */
	atomic_set(&stid->sc_count, 1);

	/*
	 * It shouldn't be a problem to reuse an opaque stateid value.
	 * I don't think it is for 4.1.  But with 4.0 I worry that, for
	 * example, a stray write retransmission could be accepted by
	 * the server when it should have been rejected.  Therefore,
	 * adopt a trick from the sctp code to attempt to maximize the
	 * amount of time until an id is reused, by ensuring they always
	 * "increase" (mod INT_MAX):
	 */
	return stid;
out_free:
	kmem_cache_free(slab, stid);
	return NULL;
}

static struct nfs4_ol_stateid * nfs4_alloc_open_stateid(struct nfs4_client *clp)
{
	struct nfs4_stid *stid;
	struct nfs4_ol_stateid *stp;

	stid = nfs4_alloc_stid(clp, stateid_slab);
	if (!stid)
		return NULL;

	stp = openlockstateid(stid);
	stp->st_stid.sc_free = nfs4_free_ol_stateid;
	return stp;
}

static void nfs4_free_deleg(struct nfs4_stid *stid)
{
	kmem_cache_free(deleg_slab, stid);
	atomic_long_dec(&num_delegations);
}

/*
 * When we recall a delegation, we should be careful not to hand it
 * out again straight away.
 * To ensure this we keep a pair of bloom filters ('new' and 'old')
 * in which the filehandles of recalled delegations are "stored".
 * If a filehandle appear in either filter, a delegation is blocked.
 * When a delegation is recalled, the filehandle is stored in the "new"
 * filter.
 * Every 30 seconds we swap the filters and clear the "new" one,
 * unless both are empty of course.
 *
 * Each filter is 256 bits.  We hash the filehandle to 32bit and use the
 * low 3 bytes as hash-table indices.
 *
 * 'blocked_delegations_lock', which is always taken in block_delegations(),
 * is used to manage concurrent access.  Testing does not need the lock
 * except when swapping the two filters.
 */
static DEFINE_SPINLOCK(blocked_delegations_lock);
static struct bloom_pair {
	int	entries, old_entries;
	time_t	swap_time;
	int	new; /* index into 'set' */
	DECLARE_BITMAP(set[2], 256);
} blocked_delegations;

static int delegation_blocked(struct knfsd_fh *fh)
{
	u32 hash;
	struct bloom_pair *bd = &blocked_delegations;

	if (bd->entries == 0)
		return 0;
	if (seconds_since_boot() - bd->swap_time > 30) {
		spin_lock(&blocked_delegations_lock);
		if (seconds_since_boot() - bd->swap_time > 30) {
			bd->entries -= bd->old_entries;
			bd->old_entries = bd->entries;
			memset(bd->set[bd->new], 0,
			       sizeof(bd->set[0]));
			bd->new = 1-bd->new;
			bd->swap_time = seconds_since_boot();
		}
		spin_unlock(&blocked_delegations_lock);
	}
	hash = jhash(&fh->fh_base, fh->fh_size, 0);
	if (test_bit(hash&255, bd->set[0]) &&
	    test_bit((hash>>8)&255, bd->set[0]) &&
	    test_bit((hash>>16)&255, bd->set[0]))
		return 1;

	if (test_bit(hash&255, bd->set[1]) &&
	    test_bit((hash>>8)&255, bd->set[1]) &&
	    test_bit((hash>>16)&255, bd->set[1]))
		return 1;

	return 0;
}

static void block_delegations(struct knfsd_fh *fh)
{
	u32 hash;
	struct bloom_pair *bd = &blocked_delegations;

	hash = jhash(&fh->fh_base, fh->fh_size, 0);

	spin_lock(&blocked_delegations_lock);
	__set_bit(hash&255, bd->set[bd->new]);
	__set_bit((hash>>8)&255, bd->set[bd->new]);
	__set_bit((hash>>16)&255, bd->set[bd->new]);
	if (bd->entries == 0)
		bd->swap_time = seconds_since_boot();
	bd->entries += 1;
	spin_unlock(&blocked_delegations_lock);
}

static struct nfs4_delegation *
alloc_init_deleg(struct nfs4_client *clp, struct svc_fh *current_fh)
{
	struct nfs4_delegation *dp;
	long n;

	dprintk("NFSD alloc_init_deleg\n");
	n = atomic_long_inc_return(&num_delegations);
	if (n < 0 || n > max_delegations)
		goto out_dec;
	if (delegation_blocked(&current_fh->fh_handle))
		goto out_dec;
	dp = delegstateid(nfs4_alloc_stid(clp, deleg_slab));
	if (dp == NULL)
		goto out_dec;

	dp->dl_stid.sc_free = nfs4_free_deleg;
	/*
	 * delegation seqid's are never incremented.  The 4.1 special
	 * meaning of seqid 0 isn't meaningful, really, but let's avoid
	 * 0 anyway just for consistency and use 1:
	 */
	dp->dl_stid.sc_stateid.si_generation = 1;
	INIT_LIST_HEAD(&dp->dl_perfile);
	INIT_LIST_HEAD(&dp->dl_perclnt);
	INIT_LIST_HEAD(&dp->dl_recall_lru);
	dp->dl_type = NFS4_OPEN_DELEGATE_READ;
	dp->dl_retries = 1;
	nfsd4_init_cb(&dp->dl_recall, dp->dl_stid.sc_client,
		      &nfsd4_cb_recall_ops, NFSPROC4_CLNT_CB_RECALL);
	return dp;
out_dec:
	atomic_long_dec(&num_delegations);
	return NULL;
}

void
nfs4_put_stid(struct nfs4_stid *s)
{
	struct nfs4_file *fp = s->sc_file;
	struct nfs4_client *clp = s->sc_client;

	might_lock(&clp->cl_lock);

	if (!atomic_dec_and_lock(&s->sc_count, &clp->cl_lock)) {
		wake_up_all(&close_wq);
		return;
	}
	idr_remove(&clp->cl_stateids, s->sc_stateid.si_opaque.so_id);
	spin_unlock(&clp->cl_lock);
	s->sc_free(s);
	if (fp)
		put_nfs4_file(fp);
}

static void nfs4_put_deleg_lease(struct nfs4_file *fp)
{
	struct file *filp = NULL;

	spin_lock(&fp->fi_lock);
	if (fp->fi_deleg_file && --fp->fi_delegees == 0)
		swap(filp, fp->fi_deleg_file);
	spin_unlock(&fp->fi_lock);

	if (filp) {
		vfs_setlease(filp, F_UNLCK, NULL, (void **)&fp);
		fput(filp);
	}
}

void nfs4_unhash_stid(struct nfs4_stid *s)
{
	s->sc_type = 0;
}

static void
hash_delegation_locked(struct nfs4_delegation *dp, struct nfs4_file *fp)
{
	lockdep_assert_held(&state_lock);
	lockdep_assert_held(&fp->fi_lock);

	atomic_inc(&dp->dl_stid.sc_count);
	dp->dl_stid.sc_type = NFS4_DELEG_STID;
	list_add(&dp->dl_perfile, &fp->fi_delegations);
	list_add(&dp->dl_perclnt, &dp->dl_stid.sc_client->cl_delegations);
}

static void
unhash_delegation_locked(struct nfs4_delegation *dp)
{
	struct nfs4_file *fp = dp->dl_stid.sc_file;

	lockdep_assert_held(&state_lock);

	dp->dl_stid.sc_type = NFS4_CLOSED_DELEG_STID;
	/* Ensure that deleg break won't try to requeue it */
	++dp->dl_time;
	spin_lock(&fp->fi_lock);
	list_del_init(&dp->dl_perclnt);
	list_del_init(&dp->dl_recall_lru);
	list_del_init(&dp->dl_perfile);
	spin_unlock(&fp->fi_lock);
}

static void destroy_delegation(struct nfs4_delegation *dp)
{
	spin_lock(&state_lock);
	unhash_delegation_locked(dp);
	spin_unlock(&state_lock);
	nfs4_put_deleg_lease(dp->dl_stid.sc_file);
	nfs4_put_stid(&dp->dl_stid);
}

static void revoke_delegation(struct nfs4_delegation *dp)
{
	struct nfs4_client *clp = dp->dl_stid.sc_client;

	WARN_ON(!list_empty(&dp->dl_recall_lru));

	nfs4_put_deleg_lease(dp->dl_stid.sc_file);

	if (clp->cl_minorversion == 0)
		nfs4_put_stid(&dp->dl_stid);
	else {
		dp->dl_stid.sc_type = NFS4_REVOKED_DELEG_STID;
		spin_lock(&clp->cl_lock);
		list_add(&dp->dl_recall_lru, &clp->cl_revoked);
		spin_unlock(&clp->cl_lock);
	}
}

/* 
 * SETCLIENTID state 
 */

static unsigned int clientid_hashval(u32 id)
{
	return id & CLIENT_HASH_MASK;
}

static unsigned int clientstr_hashval(const char *name)
{
	return opaque_hashval(name, 8) & CLIENT_HASH_MASK;
}

/*
 * We store the NONE, READ, WRITE, and BOTH bits separately in the
 * st_{access,deny}_bmap field of the stateid, in order to track not
 * only what share bits are currently in force, but also what
 * combinations of share bits previous opens have used.  This allows us
 * to enforce the recommendation of rfc 3530 14.2.19 that the server
 * return an error if the client attempt to downgrade to a combination
 * of share bits not explicable by closing some of its previous opens.
 *
 * XXX: This enforcement is actually incomplete, since we don't keep
 * track of access/deny bit combinations; so, e.g., we allow:
 *
 *	OPEN allow read, deny write
 *	OPEN allow both, deny none
 *	DOWNGRADE allow read, deny none
 *
 * which we should reject.
 */
static unsigned int
bmap_to_share_mode(unsigned long bmap) {
	int i;
	unsigned int access = 0;

	for (i = 1; i < 4; i++) {
		if (test_bit(i, &bmap))
			access |= i;
	}
	return access;
}

/* set share access for a given stateid */
static inline void
set_access(u32 access, struct nfs4_ol_stateid *stp)
{
	unsigned char mask = 1 << access;

	WARN_ON_ONCE(access > NFS4_SHARE_ACCESS_BOTH);
	stp->st_access_bmap |= mask;
}

/* clear share access for a given stateid */
static inline void
clear_access(u32 access, struct nfs4_ol_stateid *stp)
{
	unsigned char mask = 1 << access;

	WARN_ON_ONCE(access > NFS4_SHARE_ACCESS_BOTH);
	stp->st_access_bmap &= ~mask;
}

/* test whether a given stateid has access */
static inline bool
test_access(u32 access, struct nfs4_ol_stateid *stp)
{
	unsigned char mask = 1 << access;

	return (bool)(stp->st_access_bmap & mask);
}

/* set share deny for a given stateid */
static inline void
set_deny(u32 deny, struct nfs4_ol_stateid *stp)
{
	unsigned char mask = 1 << deny;

	WARN_ON_ONCE(deny > NFS4_SHARE_DENY_BOTH);
	stp->st_deny_bmap |= mask;
}

/* clear share deny for a given stateid */
static inline void
clear_deny(u32 deny, struct nfs4_ol_stateid *stp)
{
	unsigned char mask = 1 << deny;

	WARN_ON_ONCE(deny > NFS4_SHARE_DENY_BOTH);
	stp->st_deny_bmap &= ~mask;
}

/* test whether a given stateid is denying specific access */
static inline bool
test_deny(u32 deny, struct nfs4_ol_stateid *stp)
{
	unsigned char mask = 1 << deny;

	return (bool)(stp->st_deny_bmap & mask);
}

static int nfs4_access_to_omode(u32 access)
{
	switch (access & NFS4_SHARE_ACCESS_BOTH) {
	case NFS4_SHARE_ACCESS_READ:
		return O_RDONLY;
	case NFS4_SHARE_ACCESS_WRITE:
		return O_WRONLY;
	case NFS4_SHARE_ACCESS_BOTH:
		return O_RDWR;
	}
	WARN_ON_ONCE(1);
	return O_RDONLY;
}

/*
 * A stateid that had a deny mode associated with it is being released
 * or downgraded. Recalculate the deny mode on the file.
 */
static void
recalculate_deny_mode(struct nfs4_file *fp)
{
	struct nfs4_ol_stateid *stp;

	spin_lock(&fp->fi_lock);
	fp->fi_share_deny = 0;
	list_for_each_entry(stp, &fp->fi_stateids, st_perfile)
		fp->fi_share_deny |= bmap_to_share_mode(stp->st_deny_bmap);
	spin_unlock(&fp->fi_lock);
}

static void
reset_union_bmap_deny(u32 deny, struct nfs4_ol_stateid *stp)
{
	int i;
	bool change = false;

	for (i = 1; i < 4; i++) {
		if ((i & deny) != i) {
			change = true;
			clear_deny(i, stp);
		}
	}

	/* Recalculate per-file deny mode if there was a change */
	if (change)
		recalculate_deny_mode(stp->st_stid.sc_file);
}

/* release all access and file references for a given stateid */
static void
release_all_access(struct nfs4_ol_stateid *stp)
{
	int i;
	struct nfs4_file *fp = stp->st_stid.sc_file;

	if (fp && stp->st_deny_bmap != 0)
		recalculate_deny_mode(fp);

	for (i = 1; i < 4; i++) {
		if (test_access(i, stp))
			nfs4_file_put_access(stp->st_stid.sc_file, i);
		clear_access(i, stp);
	}
}

static void nfs4_put_stateowner(struct nfs4_stateowner *sop)
{
	struct nfs4_client *clp = sop->so_client;

	might_lock(&clp->cl_lock);

	if (!atomic_dec_and_lock(&sop->so_count, &clp->cl_lock))
		return;
	sop->so_ops->so_unhash(sop);
	spin_unlock(&clp->cl_lock);
	kfree(sop->so_owner.data);
	sop->so_ops->so_free(sop);
}

static void unhash_ol_stateid(struct nfs4_ol_stateid *stp)
{
	struct nfs4_file *fp = stp->st_stid.sc_file;

	lockdep_assert_held(&stp->st_stateowner->so_client->cl_lock);

	spin_lock(&fp->fi_lock);
	list_del(&stp->st_perfile);
	spin_unlock(&fp->fi_lock);
	list_del(&stp->st_perstateowner);
}

static void nfs4_free_ol_stateid(struct nfs4_stid *stid)
{
	struct nfs4_ol_stateid *stp = openlockstateid(stid);

	release_all_access(stp);
	if (stp->st_stateowner)
		nfs4_put_stateowner(stp->st_stateowner);
	kmem_cache_free(stateid_slab, stid);
}

static void nfs4_free_lock_stateid(struct nfs4_stid *stid)
{
	struct nfs4_ol_stateid *stp = openlockstateid(stid);
	struct nfs4_lockowner *lo = lockowner(stp->st_stateowner);
	struct file *file;

	file = find_any_file(stp->st_stid.sc_file);
	if (file)
		filp_close(file, (fl_owner_t)lo);
	nfs4_free_ol_stateid(stid);
}

/*
 * Put the persistent reference to an already unhashed generic stateid, while
 * holding the cl_lock. If it's the last reference, then put it onto the
 * reaplist for later destruction.
 */
static void put_ol_stateid_locked(struct nfs4_ol_stateid *stp,
				       struct list_head *reaplist)
{
	struct nfs4_stid *s = &stp->st_stid;
	struct nfs4_client *clp = s->sc_client;

	lockdep_assert_held(&clp->cl_lock);

	WARN_ON_ONCE(!list_empty(&stp->st_locks));

	if (!atomic_dec_and_test(&s->sc_count)) {
		wake_up_all(&close_wq);
		return;
	}

	idr_remove(&clp->cl_stateids, s->sc_stateid.si_opaque.so_id);
	list_add(&stp->st_locks, reaplist);
}

static void unhash_lock_stateid(struct nfs4_ol_stateid *stp)
{
	struct nfs4_openowner *oo = openowner(stp->st_openstp->st_stateowner);

	lockdep_assert_held(&oo->oo_owner.so_client->cl_lock);

	list_del_init(&stp->st_locks);
	unhash_ol_stateid(stp);
	nfs4_unhash_stid(&stp->st_stid);
}

static void release_lock_stateid(struct nfs4_ol_stateid *stp)
{
	struct nfs4_openowner *oo = openowner(stp->st_openstp->st_stateowner);

	spin_lock(&oo->oo_owner.so_client->cl_lock);
	unhash_lock_stateid(stp);
	spin_unlock(&oo->oo_owner.so_client->cl_lock);
	nfs4_put_stid(&stp->st_stid);
}

static void unhash_lockowner_locked(struct nfs4_lockowner *lo)
{
	struct nfs4_client *clp = lo->lo_owner.so_client;

	lockdep_assert_held(&clp->cl_lock);

	list_del_init(&lo->lo_owner.so_strhash);
}

/*
 * Free a list of generic stateids that were collected earlier after being
 * fully unhashed.
 */
static void
free_ol_stateid_reaplist(struct list_head *reaplist)
{
	struct nfs4_ol_stateid *stp;
	struct nfs4_file *fp;

	might_sleep();

	while (!list_empty(reaplist)) {
		stp = list_first_entry(reaplist, struct nfs4_ol_stateid,
				       st_locks);
		list_del(&stp->st_locks);
		fp = stp->st_stid.sc_file;
		stp->st_stid.sc_free(&stp->st_stid);
		if (fp)
			put_nfs4_file(fp);
	}
}

static void release_lockowner(struct nfs4_lockowner *lo)
{
	struct nfs4_client *clp = lo->lo_owner.so_client;
	struct nfs4_ol_stateid *stp;
	struct list_head reaplist;

	INIT_LIST_HEAD(&reaplist);

	spin_lock(&clp->cl_lock);
	unhash_lockowner_locked(lo);
	while (!list_empty(&lo->lo_owner.so_stateids)) {
		stp = list_first_entry(&lo->lo_owner.so_stateids,
				struct nfs4_ol_stateid, st_perstateowner);
		unhash_lock_stateid(stp);
		put_ol_stateid_locked(stp, &reaplist);
	}
	spin_unlock(&clp->cl_lock);
	free_ol_stateid_reaplist(&reaplist);
	nfs4_put_stateowner(&lo->lo_owner);
}

static void release_open_stateid_locks(struct nfs4_ol_stateid *open_stp,
				       struct list_head *reaplist)
{
	struct nfs4_ol_stateid *stp;

	while (!list_empty(&open_stp->st_locks)) {
		stp = list_entry(open_stp->st_locks.next,
				struct nfs4_ol_stateid, st_locks);
		unhash_lock_stateid(stp);
		put_ol_stateid_locked(stp, reaplist);
	}
}

static void unhash_open_stateid(struct nfs4_ol_stateid *stp,
				struct list_head *reaplist)
{
	lockdep_assert_held(&stp->st_stid.sc_client->cl_lock);

	unhash_ol_stateid(stp);
	release_open_stateid_locks(stp, reaplist);
}

static void release_open_stateid(struct nfs4_ol_stateid *stp)
{
	LIST_HEAD(reaplist);

	spin_lock(&stp->st_stid.sc_client->cl_lock);
	unhash_open_stateid(stp, &reaplist);
	put_ol_stateid_locked(stp, &reaplist);
	spin_unlock(&stp->st_stid.sc_client->cl_lock);
	free_ol_stateid_reaplist(&reaplist);
}

static void unhash_openowner_locked(struct nfs4_openowner *oo)
{
	struct nfs4_client *clp = oo->oo_owner.so_client;

	lockdep_assert_held(&clp->cl_lock);

	list_del_init(&oo->oo_owner.so_strhash);
	list_del_init(&oo->oo_perclient);
}

static void release_last_closed_stateid(struct nfs4_openowner *oo)
{
	struct nfsd_net *nn = net_generic(oo->oo_owner.so_client->net,
					  nfsd_net_id);
	struct nfs4_ol_stateid *s;

	spin_lock(&nn->client_lock);
	s = oo->oo_last_closed_stid;
	if (s) {
		list_del_init(&oo->oo_close_lru);
		oo->oo_last_closed_stid = NULL;
	}
	spin_unlock(&nn->client_lock);
	if (s)
		nfs4_put_stid(&s->st_stid);
}

static void release_openowner(struct nfs4_openowner *oo)
{
	struct nfs4_ol_stateid *stp;
	struct nfs4_client *clp = oo->oo_owner.so_client;
	struct list_head reaplist;

	INIT_LIST_HEAD(&reaplist);

	spin_lock(&clp->cl_lock);
	unhash_openowner_locked(oo);
	while (!list_empty(&oo->oo_owner.so_stateids)) {
		stp = list_first_entry(&oo->oo_owner.so_stateids,
				struct nfs4_ol_stateid, st_perstateowner);
		unhash_open_stateid(stp, &reaplist);
		put_ol_stateid_locked(stp, &reaplist);
	}
	spin_unlock(&clp->cl_lock);
	free_ol_stateid_reaplist(&reaplist);
	release_last_closed_stateid(oo);
	nfs4_put_stateowner(&oo->oo_owner);
}

static inline int
hash_sessionid(struct nfs4_sessionid *sessionid)
{
	struct nfsd4_sessionid *sid = (struct nfsd4_sessionid *)sessionid;

	return sid->sequence % SESSION_HASH_SIZE;
}

#ifdef NFSD_DEBUG
static inline void
dump_sessionid(const char *fn, struct nfs4_sessionid *sessionid)
{
	u32 *ptr = (u32 *)(&sessionid->data[0]);
	dprintk("%s: %u:%u:%u:%u\n", fn, ptr[0], ptr[1], ptr[2], ptr[3]);
}
#else
static inline void
dump_sessionid(const char *fn, struct nfs4_sessionid *sessionid)
{
}
#endif

/*
 * Bump the seqid on cstate->replay_owner, and clear replay_owner if it
 * won't be used for replay.
 */
void nfsd4_bump_seqid(struct nfsd4_compound_state *cstate, __be32 nfserr)
{
	struct nfs4_stateowner *so = cstate->replay_owner;

	if (nfserr == nfserr_replay_me)
		return;

	if (!seqid_mutating_err(ntohl(nfserr))) {
		nfsd4_cstate_clear_replay(cstate);
		return;
	}
	if (!so)
		return;
	if (so->so_is_open_owner)
		release_last_closed_stateid(openowner(so));
	so->so_seqid++;
	return;
}

static void
gen_sessionid(struct nfsd4_session *ses)
{
	struct nfs4_client *clp = ses->se_client;
	struct nfsd4_sessionid *sid;

	sid = (struct nfsd4_sessionid *)ses->se_sessionid.data;
	sid->clientid = clp->cl_clientid;
	sid->sequence = current_sessionid++;
	sid->reserved = 0;
}

/*
 * The protocol defines ca_maxresponssize_cached to include the size of
 * the rpc header, but all we need to cache is the data starting after
 * the end of the initial SEQUENCE operation--the rest we regenerate
 * each time.  Therefore we can advertise a ca_maxresponssize_cached
 * value that is the number of bytes in our cache plus a few additional
 * bytes.  In order to stay on the safe side, and not promise more than
 * we can cache, those additional bytes must be the minimum possible: 24
 * bytes of rpc header (xid through accept state, with AUTH_NULL
 * verifier), 12 for the compound header (with zero-length tag), and 44
 * for the SEQUENCE op response:
 */
#define NFSD_MIN_HDR_SEQ_SZ  (24 + 12 + 44)

static void
free_session_slots(struct nfsd4_session *ses)
{
	int i;

	for (i = 0; i < ses->se_fchannel.maxreqs; i++)
		kfree(ses->se_slots[i]);
}

/*
 * We don't actually need to cache the rpc and session headers, so we
 * can allocate a little less for each slot:
 */
static inline u32 slot_bytes(struct nfsd4_channel_attrs *ca)
{
	u32 size;

	if (ca->maxresp_cached < NFSD_MIN_HDR_SEQ_SZ)
		size = 0;
	else
		size = ca->maxresp_cached - NFSD_MIN_HDR_SEQ_SZ;
	return size + sizeof(struct nfsd4_slot);
}

/*
 * XXX: If we run out of reserved DRC memory we could (up to a point)
 * re-negotiate active sessions and reduce their slot usage to make
 * room for new connections. For now we just fail the create session.
 */
static u32 nfsd4_get_drc_mem(struct nfsd4_channel_attrs *ca)
{
	u32 slotsize = slot_bytes(ca);
	u32 num = ca->maxreqs;
	int avail;

	spin_lock(&nfsd_drc_lock);
	avail = min((unsigned long)NFSD_MAX_MEM_PER_SESSION,
		    nfsd_drc_max_mem - nfsd_drc_mem_used);
	num = min_t(int, num, avail / slotsize);
	nfsd_drc_mem_used += num * slotsize;
	spin_unlock(&nfsd_drc_lock);

	return num;
}

static void nfsd4_put_drc_mem(struct nfsd4_channel_attrs *ca)
{
	int slotsize = slot_bytes(ca);

	spin_lock(&nfsd_drc_lock);
	nfsd_drc_mem_used -= slotsize * ca->maxreqs;
	spin_unlock(&nfsd_drc_lock);
}

static struct nfsd4_session *alloc_session(struct nfsd4_channel_attrs *fattrs,
					   struct nfsd4_channel_attrs *battrs)
{
	int numslots = fattrs->maxreqs;
	int slotsize = slot_bytes(fattrs);
	struct nfsd4_session *new;
	int mem, i;

	BUILD_BUG_ON(NFSD_MAX_SLOTS_PER_SESSION * sizeof(struct nfsd4_slot *)
			+ sizeof(struct nfsd4_session) > PAGE_SIZE);
	mem = numslots * sizeof(struct nfsd4_slot *);

	new = kzalloc(sizeof(*new) + mem, GFP_KERNEL);
	if (!new)
		return NULL;
	/* allocate each struct nfsd4_slot and data cache in one piece */
	for (i = 0; i < numslots; i++) {
		new->se_slots[i] = kzalloc(slotsize, GFP_KERNEL);
		if (!new->se_slots[i])
			goto out_free;
	}

	memcpy(&new->se_fchannel, fattrs, sizeof(struct nfsd4_channel_attrs));
	memcpy(&new->se_bchannel, battrs, sizeof(struct nfsd4_channel_attrs));

	return new;
out_free:
	while (i--)
		kfree(new->se_slots[i]);
	kfree(new);
	return NULL;
}

static void free_conn(struct nfsd4_conn *c)
{
	svc_xprt_put(c->cn_xprt);
	kfree(c);
}

static void nfsd4_conn_lost(struct svc_xpt_user *u)
{
	struct nfsd4_conn *c = container_of(u, struct nfsd4_conn, cn_xpt_user);
	struct nfs4_client *clp = c->cn_session->se_client;

	spin_lock(&clp->cl_lock);
	if (!list_empty(&c->cn_persession)) {
		list_del(&c->cn_persession);
		free_conn(c);
	}
	nfsd4_probe_callback(clp);
	spin_unlock(&clp->cl_lock);
}

static struct nfsd4_conn *alloc_conn(struct svc_rqst *rqstp, u32 flags)
{
	struct nfsd4_conn *conn;

	conn = kmalloc(sizeof(struct nfsd4_conn), GFP_KERNEL);
	if (!conn)
		return NULL;
	svc_xprt_get(rqstp->rq_xprt);
	conn->cn_xprt = rqstp->rq_xprt;
	conn->cn_flags = flags;
	INIT_LIST_HEAD(&conn->cn_xpt_user.list);
	return conn;
}

static void __nfsd4_hash_conn(struct nfsd4_conn *conn, struct nfsd4_session *ses)
{
	conn->cn_session = ses;
	list_add(&conn->cn_persession, &ses->se_conns);
}

static void nfsd4_hash_conn(struct nfsd4_conn *conn, struct nfsd4_session *ses)
{
	struct nfs4_client *clp = ses->se_client;

	spin_lock(&clp->cl_lock);
	__nfsd4_hash_conn(conn, ses);
	spin_unlock(&clp->cl_lock);
}

static int nfsd4_register_conn(struct nfsd4_conn *conn)
{
	conn->cn_xpt_user.callback = nfsd4_conn_lost;
	return register_xpt_user(conn->cn_xprt, &conn->cn_xpt_user);
}

static void nfsd4_init_conn(struct svc_rqst *rqstp, struct nfsd4_conn *conn, struct nfsd4_session *ses)
{
	int ret;

	nfsd4_hash_conn(conn, ses);
	ret = nfsd4_register_conn(conn);
	if (ret)
		/* oops; xprt is already down: */
		nfsd4_conn_lost(&conn->cn_xpt_user);
	/* We may have gained or lost a callback channel: */
	nfsd4_probe_callback_sync(ses->se_client);
}

static struct nfsd4_conn *alloc_conn_from_crses(struct svc_rqst *rqstp, struct nfsd4_create_session *cses)
{
	u32 dir = NFS4_CDFC4_FORE;

	if (cses->flags & SESSION4_BACK_CHAN)
		dir |= NFS4_CDFC4_BACK;
	return alloc_conn(rqstp, dir);
}

/* must be called under client_lock */
static void nfsd4_del_conns(struct nfsd4_session *s)
{
	struct nfs4_client *clp = s->se_client;
	struct nfsd4_conn *c;

	spin_lock(&clp->cl_lock);
	while (!list_empty(&s->se_conns)) {
		c = list_first_entry(&s->se_conns, struct nfsd4_conn, cn_persession);
		list_del_init(&c->cn_persession);
		spin_unlock(&clp->cl_lock);

		unregister_xpt_user(c->cn_xprt, &c->cn_xpt_user);
		free_conn(c);

		spin_lock(&clp->cl_lock);
	}
	spin_unlock(&clp->cl_lock);
}

static void __free_session(struct nfsd4_session *ses)
{
	free_session_slots(ses);
	kfree(ses);
}

static void free_session(struct nfsd4_session *ses)
{
	nfsd4_del_conns(ses);
	nfsd4_put_drc_mem(&ses->se_fchannel);
	__free_session(ses);
}

static void init_session(struct svc_rqst *rqstp, struct nfsd4_session *new, struct nfs4_client *clp, struct nfsd4_create_session *cses)
{
	int idx;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	new->se_client = clp;
	gen_sessionid(new);

	INIT_LIST_HEAD(&new->se_conns);

	new->se_cb_seq_nr = 1;
	new->se_flags = cses->flags;
	new->se_cb_prog = cses->callback_prog;
	new->se_cb_sec = cses->cb_sec;
	atomic_set(&new->se_ref, 0);
	idx = hash_sessionid(&new->se_sessionid);
	list_add(&new->se_hash, &nn->sessionid_hashtbl[idx]);
	spin_lock(&clp->cl_lock);
	list_add(&new->se_perclnt, &clp->cl_sessions);
	spin_unlock(&clp->cl_lock);

	{
		struct sockaddr *sa = svc_addr(rqstp);
		/*
		 * This is a little silly; with sessions there's no real
		 * use for the callback address.  Use the peer address
		 * as a reasonable default for now, but consider fixing
		 * the rpc client not to require an address in the
		 * future:
		 */
		rpc_copy_addr((struct sockaddr *)&clp->cl_cb_conn.cb_addr, sa);
		clp->cl_cb_conn.cb_addrlen = svc_addr_len(sa);
	}
}

/* caller must hold client_lock */
static struct nfsd4_session *
__find_in_sessionid_hashtbl(struct nfs4_sessionid *sessionid, struct net *net)
{
	struct nfsd4_session *elem;
	int idx;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	lockdep_assert_held(&nn->client_lock);

	dump_sessionid(__func__, sessionid);
	idx = hash_sessionid(sessionid);
	/* Search in the appropriate list */
	list_for_each_entry(elem, &nn->sessionid_hashtbl[idx], se_hash) {
		if (!memcmp(elem->se_sessionid.data, sessionid->data,
			    NFS4_MAX_SESSIONID_LEN)) {
			return elem;
		}
	}

	dprintk("%s: session not found\n", __func__);
	return NULL;
}

static struct nfsd4_session *
find_in_sessionid_hashtbl(struct nfs4_sessionid *sessionid, struct net *net,
		__be32 *ret)
{
	struct nfsd4_session *session;
	__be32 status = nfserr_badsession;

	session = __find_in_sessionid_hashtbl(sessionid, net);
	if (!session)
		goto out;
	status = nfsd4_get_session_locked(session);
	if (status)
		session = NULL;
out:
	*ret = status;
	return session;
}

/* caller must hold client_lock */
static void
unhash_session(struct nfsd4_session *ses)
{
	struct nfs4_client *clp = ses->se_client;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	lockdep_assert_held(&nn->client_lock);

	list_del(&ses->se_hash);
	spin_lock(&ses->se_client->cl_lock);
	list_del(&ses->se_perclnt);
	spin_unlock(&ses->se_client->cl_lock);
}

/* SETCLIENTID and SETCLIENTID_CONFIRM Helper functions */
static int
STALE_CLIENTID(clientid_t *clid, struct nfsd_net *nn)
{
	/*
	 * We're assuming the clid was not given out from a boot
	 * precisely 2^32 (about 136 years) before this one.  That seems
	 * a safe assumption:
	 */
	if (clid->cl_boot == (u32)nn->boot_time)
		return 0;
	dprintk("NFSD stale clientid (%08x/%08x) boot_time %08lx\n",
		clid->cl_boot, clid->cl_id, nn->boot_time);
	return 1;
}

/* 
 * XXX Should we use a slab cache ?
 * This type of memory management is somewhat inefficient, but we use it
 * anyway since SETCLIENTID is not a common operation.
 */
static struct nfs4_client *alloc_client(struct xdr_netobj name)
{
	struct nfs4_client *clp;
	int i;

	clp = kzalloc(sizeof(struct nfs4_client), GFP_KERNEL);
	if (clp == NULL)
		return NULL;
	clp->cl_name.data = kmemdup(name.data, name.len, GFP_KERNEL);
	if (clp->cl_name.data == NULL)
		goto err_no_name;
	clp->cl_ownerstr_hashtbl = kmalloc(sizeof(struct list_head) *
			OWNER_HASH_SIZE, GFP_KERNEL);
	if (!clp->cl_ownerstr_hashtbl)
		goto err_no_hashtbl;
	for (i = 0; i < OWNER_HASH_SIZE; i++)
		INIT_LIST_HEAD(&clp->cl_ownerstr_hashtbl[i]);
	clp->cl_name.len = name.len;
	INIT_LIST_HEAD(&clp->cl_sessions);
	idr_init(&clp->cl_stateids);
	atomic_set(&clp->cl_refcount, 0);
	clp->cl_cb_state = NFSD4_CB_UNKNOWN;
	INIT_LIST_HEAD(&clp->cl_idhash);
	INIT_LIST_HEAD(&clp->cl_openowners);
	INIT_LIST_HEAD(&clp->cl_delegations);
	INIT_LIST_HEAD(&clp->cl_lru);
	INIT_LIST_HEAD(&clp->cl_callbacks);
	INIT_LIST_HEAD(&clp->cl_revoked);
#ifdef CONFIG_NFSD_PNFS
	INIT_LIST_HEAD(&clp->cl_lo_states);
#endif
	spin_lock_init(&clp->cl_lock);
	rpc_init_wait_queue(&clp->cl_cb_waitq, "Backchannel slot table");
	return clp;
err_no_hashtbl:
	kfree(clp->cl_name.data);
err_no_name:
	kfree(clp);
	return NULL;
}

static void
free_client(struct nfs4_client *clp)
{
	while (!list_empty(&clp->cl_sessions)) {
		struct nfsd4_session *ses;
		ses = list_entry(clp->cl_sessions.next, struct nfsd4_session,
				se_perclnt);
		list_del(&ses->se_perclnt);
		WARN_ON_ONCE(atomic_read(&ses->se_ref));
		free_session(ses);
	}
	rpc_destroy_wait_queue(&clp->cl_cb_waitq);
	free_svc_cred(&clp->cl_cred);
	kfree(clp->cl_ownerstr_hashtbl);
	kfree(clp->cl_name.data);
	idr_destroy(&clp->cl_stateids);
	kfree(clp);
}

/* must be called under the client_lock */
static void
unhash_client_locked(struct nfs4_client *clp)
{
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);
	struct nfsd4_session *ses;

	lockdep_assert_held(&nn->client_lock);

	/* Mark the client as expired! */
	clp->cl_time = 0;
	/* Make it invisible */
	if (!list_empty(&clp->cl_idhash)) {
		list_del_init(&clp->cl_idhash);
		if (test_bit(NFSD4_CLIENT_CONFIRMED, &clp->cl_flags))
			rb_erase(&clp->cl_namenode, &nn->conf_name_tree);
		else
			rb_erase(&clp->cl_namenode, &nn->unconf_name_tree);
	}
	list_del_init(&clp->cl_lru);
	spin_lock(&clp->cl_lock);
	list_for_each_entry(ses, &clp->cl_sessions, se_perclnt)
		list_del_init(&ses->se_hash);
	spin_unlock(&clp->cl_lock);
}

static void
unhash_client(struct nfs4_client *clp)
{
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	spin_lock(&nn->client_lock);
	unhash_client_locked(clp);
	spin_unlock(&nn->client_lock);
}

static __be32 mark_client_expired_locked(struct nfs4_client *clp)
{
	if (atomic_read(&clp->cl_refcount))
		return nfserr_jukebox;
	unhash_client_locked(clp);
	return nfs_ok;
}

static void
__destroy_client(struct nfs4_client *clp)
{
	struct nfs4_openowner *oo;
	struct nfs4_delegation *dp;
	struct list_head reaplist;

	INIT_LIST_HEAD(&reaplist);
	spin_lock(&state_lock);
	while (!list_empty(&clp->cl_delegations)) {
		dp = list_entry(clp->cl_delegations.next, struct nfs4_delegation, dl_perclnt);
		unhash_delegation_locked(dp);
		list_add(&dp->dl_recall_lru, &reaplist);
	}
	spin_unlock(&state_lock);
	while (!list_empty(&reaplist)) {
		dp = list_entry(reaplist.next, struct nfs4_delegation, dl_recall_lru);
		list_del_init(&dp->dl_recall_lru);
		nfs4_put_deleg_lease(dp->dl_stid.sc_file);
		nfs4_put_stid(&dp->dl_stid);
	}
	while (!list_empty(&clp->cl_revoked)) {
		dp = list_entry(reaplist.next, struct nfs4_delegation, dl_recall_lru);
		list_del_init(&dp->dl_recall_lru);
		nfs4_put_stid(&dp->dl_stid);
	}
	while (!list_empty(&clp->cl_openowners)) {
		oo = list_entry(clp->cl_openowners.next, struct nfs4_openowner, oo_perclient);
		nfs4_get_stateowner(&oo->oo_owner);
		release_openowner(oo);
	}
	nfsd4_return_all_client_layouts(clp);
	nfsd4_shutdown_callback(clp);
	if (clp->cl_cb_conn.cb_xprt)
		svc_xprt_put(clp->cl_cb_conn.cb_xprt);
	free_client(clp);
}

static void
destroy_client(struct nfs4_client *clp)
{
	unhash_client(clp);
	__destroy_client(clp);
}

static void expire_client(struct nfs4_client *clp)
{
	unhash_client(clp);
	nfsd4_client_record_remove(clp);
	__destroy_client(clp);
}

static void copy_verf(struct nfs4_client *target, nfs4_verifier *source)
{
	memcpy(target->cl_verifier.data, source->data,
			sizeof(target->cl_verifier.data));
}

static void copy_clid(struct nfs4_client *target, struct nfs4_client *source)
{
	target->cl_clientid.cl_boot = source->cl_clientid.cl_boot; 
	target->cl_clientid.cl_id = source->cl_clientid.cl_id; 
}

static int copy_cred(struct svc_cred *target, struct svc_cred *source)
{
	if (source->cr_principal) {
		target->cr_principal =
				kstrdup(source->cr_principal, GFP_KERNEL);
		if (target->cr_principal == NULL)
			return -ENOMEM;
	} else
		target->cr_principal = NULL;
	target->cr_flavor = source->cr_flavor;
	target->cr_uid = source->cr_uid;
	target->cr_gid = source->cr_gid;
	target->cr_group_info = source->cr_group_info;
	get_group_info(target->cr_group_info);
	target->cr_gss_mech = source->cr_gss_mech;
	if (source->cr_gss_mech)
		gss_mech_get(source->cr_gss_mech);
	return 0;
}

static int
compare_blob(const struct xdr_netobj *o1, const struct xdr_netobj *o2)
{
	if (o1->len < o2->len)
		return -1;
	if (o1->len > o2->len)
		return 1;
	return memcmp(o1->data, o2->data, o1->len);
}

static int same_name(const char *n1, const char *n2)
{
	return 0 == memcmp(n1, n2, HEXDIR_LEN);
}

static int
same_verf(nfs4_verifier *v1, nfs4_verifier *v2)
{
	return 0 == memcmp(v1->data, v2->data, sizeof(v1->data));
}

static int
same_clid(clientid_t *cl1, clientid_t *cl2)
{
	return (cl1->cl_boot == cl2->cl_boot) && (cl1->cl_id == cl2->cl_id);
}

static bool groups_equal(struct group_info *g1, struct group_info *g2)
{
	int i;

	if (g1->ngroups != g2->ngroups)
		return false;
	for (i=0; i<g1->ngroups; i++)
		if (!gid_eq(GROUP_AT(g1, i), GROUP_AT(g2, i)))
			return false;
	return true;
}

/*
 * RFC 3530 language requires clid_inuse be returned when the
 * "principal" associated with a requests differs from that previously
 * used.  We use uid, gid's, and gss principal string as our best
 * approximation.  We also don't want to allow non-gss use of a client
 * established using gss: in theory cr_principal should catch that
 * change, but in practice cr_principal can be null even in the gss case
 * since gssd doesn't always pass down a principal string.
 */
static bool is_gss_cred(struct svc_cred *cr)
{
	/* Is cr_flavor one of the gss "pseudoflavors"?: */
	return (cr->cr_flavor > RPC_AUTH_MAXFLAVOR);
}


static bool
same_creds(struct svc_cred *cr1, struct svc_cred *cr2)
{
	if ((is_gss_cred(cr1) != is_gss_cred(cr2))
		|| (!uid_eq(cr1->cr_uid, cr2->cr_uid))
		|| (!gid_eq(cr1->cr_gid, cr2->cr_gid))
		|| !groups_equal(cr1->cr_group_info, cr2->cr_group_info))
		return false;
	if (cr1->cr_principal == cr2->cr_principal)
		return true;
	if (!cr1->cr_principal || !cr2->cr_principal)
		return false;
	return 0 == strcmp(cr1->cr_principal, cr2->cr_principal);
}

static bool svc_rqst_integrity_protected(struct svc_rqst *rqstp)
{
	struct svc_cred *cr = &rqstp->rq_cred;
	u32 service;

	if (!cr->cr_gss_mech)
		return false;
	service = gss_pseudoflavor_to_service(cr->cr_gss_mech, cr->cr_flavor);
	return service == RPC_GSS_SVC_INTEGRITY ||
	       service == RPC_GSS_SVC_PRIVACY;
}

static bool mach_creds_match(struct nfs4_client *cl, struct svc_rqst *rqstp)
{
	struct svc_cred *cr = &rqstp->rq_cred;

	if (!cl->cl_mach_cred)
		return true;
	if (cl->cl_cred.cr_gss_mech != cr->cr_gss_mech)
		return false;
	if (!svc_rqst_integrity_protected(rqstp))
		return false;
	if (!cr->cr_principal)
		return false;
	return 0 == strcmp(cl->cl_cred.cr_principal, cr->cr_principal);
}

static void gen_confirm(struct nfs4_client *clp, struct nfsd_net *nn)
{
	__be32 verf[2];

	/*
	 * This is opaque to client, so no need to byte-swap. Use
	 * __force to keep sparse happy
	 */
	verf[0] = (__force __be32)get_seconds();
	verf[1] = (__force __be32)nn->clientid_counter;
	memcpy(clp->cl_confirm.data, verf, sizeof(clp->cl_confirm.data));
}

static void gen_clid(struct nfs4_client *clp, struct nfsd_net *nn)
{
	clp->cl_clientid.cl_boot = nn->boot_time;
	clp->cl_clientid.cl_id = nn->clientid_counter++;
	gen_confirm(clp, nn);
}

static struct nfs4_stid *
find_stateid_locked(struct nfs4_client *cl, stateid_t *t)
{
	struct nfs4_stid *ret;

	ret = idr_find(&cl->cl_stateids, t->si_opaque.so_id);
	if (!ret || !ret->sc_type)
		return NULL;
	return ret;
}

static struct nfs4_stid *
find_stateid_by_type(struct nfs4_client *cl, stateid_t *t, char typemask)
{
	struct nfs4_stid *s;

	spin_lock(&cl->cl_lock);
	s = find_stateid_locked(cl, t);
	if (s != NULL) {
		if (typemask & s->sc_type)
			atomic_inc(&s->sc_count);
		else
			s = NULL;
	}
	spin_unlock(&cl->cl_lock);
	return s;
}

static struct nfs4_client *create_client(struct xdr_netobj name,
		struct svc_rqst *rqstp, nfs4_verifier *verf)
{
	struct nfs4_client *clp;
	struct sockaddr *sa = svc_addr(rqstp);
	int ret;
	struct net *net = SVC_NET(rqstp);

	clp = alloc_client(name);
	if (clp == NULL)
		return NULL;

	ret = copy_cred(&clp->cl_cred, &rqstp->rq_cred);
	if (ret) {
		free_client(clp);
		return NULL;
	}
	nfsd4_init_cb(&clp->cl_cb_null, clp, NULL, NFSPROC4_CLNT_CB_NULL);
	clp->cl_time = get_seconds();
	clear_bit(0, &clp->cl_cb_slot_busy);
	copy_verf(clp, verf);
	rpc_copy_addr((struct sockaddr *) &clp->cl_addr, sa);
	clp->cl_cb_session = NULL;
	clp->net = net;
	return clp;
}

static void
add_clp_to_name_tree(struct nfs4_client *new_clp, struct rb_root *root)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct nfs4_client *clp;

	while (*new) {
		clp = rb_entry(*new, struct nfs4_client, cl_namenode);
		parent = *new;

		if (compare_blob(&clp->cl_name, &new_clp->cl_name) > 0)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&new_clp->cl_namenode, parent, new);
	rb_insert_color(&new_clp->cl_namenode, root);
}

static struct nfs4_client *
find_clp_in_name_tree(struct xdr_netobj *name, struct rb_root *root)
{
	int cmp;
	struct rb_node *node = root->rb_node;
	struct nfs4_client *clp;

	while (node) {
		clp = rb_entry(node, struct nfs4_client, cl_namenode);
		cmp = compare_blob(&clp->cl_name, name);
		if (cmp > 0)
			node = node->rb_left;
		else if (cmp < 0)
			node = node->rb_right;
		else
			return clp;
	}
	return NULL;
}

static void
add_to_unconfirmed(struct nfs4_client *clp)
{
	unsigned int idhashval;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	lockdep_assert_held(&nn->client_lock);

	clear_bit(NFSD4_CLIENT_CONFIRMED, &clp->cl_flags);
	add_clp_to_name_tree(clp, &nn->unconf_name_tree);
	idhashval = clientid_hashval(clp->cl_clientid.cl_id);
	list_add(&clp->cl_idhash, &nn->unconf_id_hashtbl[idhashval]);
	renew_client_locked(clp);
}

static void
move_to_confirmed(struct nfs4_client *clp)
{
	unsigned int idhashval = clientid_hashval(clp->cl_clientid.cl_id);
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	lockdep_assert_held(&nn->client_lock);

	dprintk("NFSD: move_to_confirm nfs4_client %p\n", clp);
	list_move(&clp->cl_idhash, &nn->conf_id_hashtbl[idhashval]);
	rb_erase(&clp->cl_namenode, &nn->unconf_name_tree);
	add_clp_to_name_tree(clp, &nn->conf_name_tree);
	set_bit(NFSD4_CLIENT_CONFIRMED, &clp->cl_flags);
	renew_client_locked(clp);
}

static struct nfs4_client *
find_client_in_id_table(struct list_head *tbl, clientid_t *clid, bool sessions)
{
	struct nfs4_client *clp;
	unsigned int idhashval = clientid_hashval(clid->cl_id);

	list_for_each_entry(clp, &tbl[idhashval], cl_idhash) {
		if (same_clid(&clp->cl_clientid, clid)) {
			if ((bool)clp->cl_minorversion != sessions)
				return NULL;
			renew_client_locked(clp);
			return clp;
		}
	}
	return NULL;
}

static struct nfs4_client *
find_confirmed_client(clientid_t *clid, bool sessions, struct nfsd_net *nn)
{
	struct list_head *tbl = nn->conf_id_hashtbl;

	lockdep_assert_held(&nn->client_lock);
	return find_client_in_id_table(tbl, clid, sessions);
}

static struct nfs4_client *
find_unconfirmed_client(clientid_t *clid, bool sessions, struct nfsd_net *nn)
{
	struct list_head *tbl = nn->unconf_id_hashtbl;

	lockdep_assert_held(&nn->client_lock);
	return find_client_in_id_table(tbl, clid, sessions);
}

static bool clp_used_exchangeid(struct nfs4_client *clp)
{
	return clp->cl_exchange_flags != 0;
} 

static struct nfs4_client *
find_confirmed_client_by_name(struct xdr_netobj *name, struct nfsd_net *nn)
{
	lockdep_assert_held(&nn->client_lock);
	return find_clp_in_name_tree(name, &nn->conf_name_tree);
}

static struct nfs4_client *
find_unconfirmed_client_by_name(struct xdr_netobj *name, struct nfsd_net *nn)
{
	lockdep_assert_held(&nn->client_lock);
	return find_clp_in_name_tree(name, &nn->unconf_name_tree);
}

static void
gen_callback(struct nfs4_client *clp, struct nfsd4_setclientid *se, struct svc_rqst *rqstp)
{
	struct nfs4_cb_conn *conn = &clp->cl_cb_conn;
	struct sockaddr	*sa = svc_addr(rqstp);
	u32 scopeid = rpc_get_scope_id(sa);
	unsigned short expected_family;

	/* Currently, we only support tcp and tcp6 for the callback channel */
	if (se->se_callback_netid_len == 3 &&
	    !memcmp(se->se_callback_netid_val, "tcp", 3))
		expected_family = AF_INET;
	else if (se->se_callback_netid_len == 4 &&
		 !memcmp(se->se_callback_netid_val, "tcp6", 4))
		expected_family = AF_INET6;
	else
		goto out_err;

	conn->cb_addrlen = rpc_uaddr2sockaddr(clp->net, se->se_callback_addr_val,
					    se->se_callback_addr_len,
					    (struct sockaddr *)&conn->cb_addr,
					    sizeof(conn->cb_addr));

	if (!conn->cb_addrlen || conn->cb_addr.ss_family != expected_family)
		goto out_err;

	if (conn->cb_addr.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&conn->cb_addr)->sin6_scope_id = scopeid;

	conn->cb_prog = se->se_callback_prog;
	conn->cb_ident = se->se_callback_ident;
	memcpy(&conn->cb_saddr, &rqstp->rq_daddr, rqstp->rq_daddrlen);
	return;
out_err:
	conn->cb_addr.ss_family = AF_UNSPEC;
	conn->cb_addrlen = 0;
	dprintk(KERN_INFO "NFSD: this client (clientid %08x/%08x) "
		"will not receive delegations\n",
		clp->cl_clientid.cl_boot, clp->cl_clientid.cl_id);

	return;
}

/*
 * Cache a reply. nfsd4_check_resp_size() has bounded the cache size.
 */
static void
nfsd4_store_cache_entry(struct nfsd4_compoundres *resp)
{
	struct xdr_buf *buf = resp->xdr.buf;
	struct nfsd4_slot *slot = resp->cstate.slot;
	unsigned int base;

	dprintk("--> %s slot %p\n", __func__, slot);

	slot->sl_opcnt = resp->opcnt;
	slot->sl_status = resp->cstate.status;

	slot->sl_flags |= NFSD4_SLOT_INITIALIZED;
	if (nfsd4_not_cached(resp)) {
		slot->sl_datalen = 0;
		return;
	}
	base = resp->cstate.data_offset;
	slot->sl_datalen = buf->len - base;
	if (read_bytes_from_xdr_buf(buf, base, slot->sl_data, slot->sl_datalen))
		WARN("%s: sessions DRC could not cache compound\n", __func__);
	return;
}

/*
 * Encode the replay sequence operation from the slot values.
 * If cachethis is FALSE encode the uncached rep error on the next
 * operation which sets resp->p and increments resp->opcnt for
 * nfs4svc_encode_compoundres.
 *
 */
static __be32
nfsd4_enc_sequence_replay(struct nfsd4_compoundargs *args,
			  struct nfsd4_compoundres *resp)
{
	struct nfsd4_op *op;
	struct nfsd4_slot *slot = resp->cstate.slot;

	/* Encode the replayed sequence operation */
	op = &args->ops[resp->opcnt - 1];
	nfsd4_encode_operation(resp, op);

	/* Return nfserr_retry_uncached_rep in next operation. */
	if (args->opcnt > 1 && !(slot->sl_flags & NFSD4_SLOT_CACHETHIS)) {
		op = &args->ops[resp->opcnt++];
		op->status = nfserr_retry_uncached_rep;
		nfsd4_encode_operation(resp, op);
	}
	return op->status;
}

/*
 * The sequence operation is not cached because we can use the slot and
 * session values.
 */
static __be32
nfsd4_replay_cache_entry(struct nfsd4_compoundres *resp,
			 struct nfsd4_sequence *seq)
{
	struct nfsd4_slot *slot = resp->cstate.slot;
	struct xdr_stream *xdr = &resp->xdr;
	__be32 *p;
	__be32 status;

	dprintk("--> %s slot %p\n", __func__, slot);

	status = nfsd4_enc_sequence_replay(resp->rqstp->rq_argp, resp);
	if (status)
		return status;

	p = xdr_reserve_space(xdr, slot->sl_datalen);
	if (!p) {
		WARN_ON_ONCE(1);
		return nfserr_serverfault;
	}
	xdr_encode_opaque_fixed(p, slot->sl_data, slot->sl_datalen);
	xdr_commit_encode(xdr);

	resp->opcnt = slot->sl_opcnt;
	return slot->sl_status;
}

/*
 * Set the exchange_id flags returned by the server.
 */
static void
nfsd4_set_ex_flags(struct nfs4_client *new, struct nfsd4_exchange_id *clid)
{
#ifdef CONFIG_NFSD_PNFS
	new->cl_exchange_flags |= EXCHGID4_FLAG_USE_PNFS_MDS;
#else
	new->cl_exchange_flags |= EXCHGID4_FLAG_USE_NON_PNFS;
#endif

	/* Referrals are supported, Migration is not. */
	new->cl_exchange_flags |= EXCHGID4_FLAG_SUPP_MOVED_REFER;

	/* set the wire flags to return to client. */
	clid->flags = new->cl_exchange_flags;
}

static bool client_has_state(struct nfs4_client *clp)
{
	/*
	 * Note clp->cl_openowners check isn't quite right: there's no
	 * need to count owners without stateid's.
	 *
	 * Also note we should probably be using this in 4.0 case too.
	 */
	return !list_empty(&clp->cl_openowners)
		|| !list_empty(&clp->cl_delegations)
		|| !list_empty(&clp->cl_sessions);
}

__be32
nfsd4_exchange_id(struct svc_rqst *rqstp,
		  struct nfsd4_compound_state *cstate,
		  struct nfsd4_exchange_id *exid)
{
	struct nfs4_client *conf, *new;
	struct nfs4_client *unconf = NULL;
	__be32 status;
	char			addr_str[INET6_ADDRSTRLEN];
	nfs4_verifier		verf = exid->verifier;
	struct sockaddr		*sa = svc_addr(rqstp);
	bool	update = exid->flags & EXCHGID4_FLAG_UPD_CONFIRMED_REC_A;
	struct nfsd_net		*nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	rpc_ntop(sa, addr_str, sizeof(addr_str));
	dprintk("%s rqstp=%p exid=%p clname.len=%u clname.data=%p "
		"ip_addr=%s flags %x, spa_how %d\n",
		__func__, rqstp, exid, exid->clname.len, exid->clname.data,
		addr_str, exid->flags, exid->spa_how);

	if (exid->flags & ~EXCHGID4_FLAG_MASK_A)
		return nfserr_inval;

	switch (exid->spa_how) {
	case SP4_MACH_CRED:
		if (!svc_rqst_integrity_protected(rqstp))
			return nfserr_inval;
	case SP4_NONE:
		break;
	default:				/* checked by xdr code */
		WARN_ON_ONCE(1);
	case SP4_SSV:
		return nfserr_encr_alg_unsupp;
	}

	new = create_client(exid->clname, rqstp, &verf);
	if (new == NULL)
		return nfserr_jukebox;

	/* Cases below refer to rfc 5661 section 18.35.4: */
	spin_lock(&nn->client_lock);
	conf = find_confirmed_client_by_name(&exid->clname, nn);
	if (conf) {
		bool creds_match = same_creds(&conf->cl_cred, &rqstp->rq_cred);
		bool verfs_match = same_verf(&verf, &conf->cl_verifier);

		if (update) {
			if (!clp_used_exchangeid(conf)) { /* buggy client */
				status = nfserr_inval;
				goto out;
			}
			if (!mach_creds_match(conf, rqstp)) {
				status = nfserr_wrong_cred;
				goto out;
			}
			if (!creds_match) { /* case 9 */
				status = nfserr_perm;
				goto out;
			}
			if (!verfs_match) { /* case 8 */
				status = nfserr_not_same;
				goto out;
			}
			/* case 6 */
			exid->flags |= EXCHGID4_FLAG_CONFIRMED_R;
			goto out_copy;
		}
		if (!creds_match) { /* case 3 */
			if (client_has_state(conf)) {
				status = nfserr_clid_inuse;
				goto out;
			}
			goto out_new;
		}
		if (verfs_match) { /* case 2 */
			conf->cl_exchange_flags |= EXCHGID4_FLAG_CONFIRMED_R;
			goto out_copy;
		}
		/* case 5, client reboot */
		conf = NULL;
		goto out_new;
	}

	if (update) { /* case 7 */
		status = nfserr_noent;
		goto out;
	}

	unconf  = find_unconfirmed_client_by_name(&exid->clname, nn);
	if (unconf) /* case 4, possible retry or client restart */
		unhash_client_locked(unconf);

	/* case 1 (normal case) */
out_new:
	if (conf) {
		status = mark_client_expired_locked(conf);
		if (status)
			goto out;
	}
	new->cl_minorversion = cstate->minorversion;
	new->cl_mach_cred = (exid->spa_how == SP4_MACH_CRED);

	gen_clid(new, nn);
	add_to_unconfirmed(new);
	swap(new, conf);
out_copy:
	exid->clientid.cl_boot = conf->cl_clientid.cl_boot;
	exid->clientid.cl_id = conf->cl_clientid.cl_id;

	exid->seqid = conf->cl_cs_slot.sl_seqid + 1;
	nfsd4_set_ex_flags(conf, exid);

	dprintk("nfsd4_exchange_id seqid %d flags %x\n",
		conf->cl_cs_slot.sl_seqid, conf->cl_exchange_flags);
	status = nfs_ok;

out:
	spin_unlock(&nn->client_lock);
	if (new)
		expire_client(new);
	if (unconf)
		expire_client(unconf);
	return status;
}

static __be32
check_slot_seqid(u32 seqid, u32 slot_seqid, int slot_inuse)
{
	dprintk("%s enter. seqid %d slot_seqid %d\n", __func__, seqid,
		slot_seqid);

	/* The slot is in use, and no response has been sent. */
	if (slot_inuse) {
		if (seqid == slot_seqid)
			return nfserr_jukebox;
		else
			return nfserr_seq_misordered;
	}
	/* Note unsigned 32-bit arithmetic handles wraparound: */
	if (likely(seqid == slot_seqid + 1))
		return nfs_ok;
	if (seqid == slot_seqid)
		return nfserr_replay_cache;
	return nfserr_seq_misordered;
}

/*
 * Cache the create session result into the create session single DRC
 * slot cache by saving the xdr structure. sl_seqid has been set.
 * Do this for solo or embedded create session operations.
 */
static void
nfsd4_cache_create_session(struct nfsd4_create_session *cr_ses,
			   struct nfsd4_clid_slot *slot, __be32 nfserr)
{
	slot->sl_status = nfserr;
	memcpy(&slot->sl_cr_ses, cr_ses, sizeof(*cr_ses));
}

static __be32
nfsd4_replay_create_session(struct nfsd4_create_session *cr_ses,
			    struct nfsd4_clid_slot *slot)
{
	memcpy(cr_ses, &slot->sl_cr_ses, sizeof(*cr_ses));
	return slot->sl_status;
}

#define NFSD_MIN_REQ_HDR_SEQ_SZ	((\
			2 * 2 + /* credential,verifier: AUTH_NULL, length 0 */ \
			1 +	/* MIN tag is length with zero, only length */ \
			3 +	/* version, opcount, opcode */ \
			XDR_QUADLEN(NFS4_MAX_SESSIONID_LEN) + \
				/* seqid, slotID, slotID, cache */ \
			4 ) * sizeof(__be32))

#define NFSD_MIN_RESP_HDR_SEQ_SZ ((\
			2 +	/* verifier: AUTH_NULL, length 0 */\
			1 +	/* status */ \
			1 +	/* MIN tag is length with zero, only length */ \
			3 +	/* opcount, opcode, opstatus*/ \
			XDR_QUADLEN(NFS4_MAX_SESSIONID_LEN) + \
				/* seqid, slotID, slotID, slotID, status */ \
			5 ) * sizeof(__be32))

static __be32 check_forechannel_attrs(struct nfsd4_channel_attrs *ca, struct nfsd_net *nn)
{
	u32 maxrpc = nn->nfsd_serv->sv_max_mesg;

	if (ca->maxreq_sz < NFSD_MIN_REQ_HDR_SEQ_SZ)
		return nfserr_toosmall;
	if (ca->maxresp_sz < NFSD_MIN_RESP_HDR_SEQ_SZ)
		return nfserr_toosmall;
	ca->headerpadsz = 0;
	ca->maxreq_sz = min_t(u32, ca->maxreq_sz, maxrpc);
	ca->maxresp_sz = min_t(u32, ca->maxresp_sz, maxrpc);
	ca->maxops = min_t(u32, ca->maxops, NFSD_MAX_OPS_PER_COMPOUND);
	ca->maxresp_cached = min_t(u32, ca->maxresp_cached,
			NFSD_SLOT_CACHE_SIZE + NFSD_MIN_HDR_SEQ_SZ);
	ca->maxreqs = min_t(u32, ca->maxreqs, NFSD_MAX_SLOTS_PER_SESSION);
	/*
	 * Note decreasing slot size below client's request may make it
	 * difficult for client to function correctly, whereas
	 * decreasing the number of slots will (just?) affect
	 * performance.  When short on memory we therefore prefer to
	 * decrease number of slots instead of their size.  Clients that
	 * request larger slots than they need will get poor results:
	 */
	ca->maxreqs = nfsd4_get_drc_mem(ca);
	if (!ca->maxreqs)
		return nfserr_jukebox;

	return nfs_ok;
}

#define NFSD_CB_MAX_REQ_SZ	((NFS4_enc_cb_recall_sz + \
				 RPC_MAX_HEADER_WITH_AUTH) * sizeof(__be32))
#define NFSD_CB_MAX_RESP_SZ	((NFS4_dec_cb_recall_sz + \
				 RPC_MAX_REPHEADER_WITH_AUTH) * sizeof(__be32))

static __be32 check_backchannel_attrs(struct nfsd4_channel_attrs *ca)
{
	ca->headerpadsz = 0;

	/*
	 * These RPC_MAX_HEADER macros are overkill, especially since we
	 * don't even do gss on the backchannel yet.  But this is still
	 * less than 1k.  Tighten up this estimate in the unlikely event
	 * it turns out to be a problem for some client:
	 */
	if (ca->maxreq_sz < NFSD_CB_MAX_REQ_SZ)
		return nfserr_toosmall;
	if (ca->maxresp_sz < NFSD_CB_MAX_RESP_SZ)
		return nfserr_toosmall;
	ca->maxresp_cached = 0;
	if (ca->maxops < 2)
		return nfserr_toosmall;

	return nfs_ok;
}

static __be32 nfsd4_check_cb_sec(struct nfsd4_cb_sec *cbs)
{
	switch (cbs->flavor) {
	case RPC_AUTH_NULL:
	case RPC_AUTH_UNIX:
		return nfs_ok;
	default:
		/*
		 * GSS case: the spec doesn't allow us to return this
		 * error.  But it also doesn't allow us not to support
		 * GSS.
		 * I'd rather this fail hard than return some error the
		 * client might think it can already handle:
		 */
		return nfserr_encr_alg_unsupp;
	}
}

__be32
nfsd4_create_session(struct svc_rqst *rqstp,
		     struct nfsd4_compound_state *cstate,
		     struct nfsd4_create_session *cr_ses)
{
	struct sockaddr *sa = svc_addr(rqstp);
	struct nfs4_client *conf, *unconf;
	struct nfs4_client *old = NULL;
	struct nfsd4_session *new;
	struct nfsd4_conn *conn;
	struct nfsd4_clid_slot *cs_slot = NULL;
	__be32 status = 0;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	if (cr_ses->flags & ~SESSION4_FLAG_MASK_A)
		return nfserr_inval;
	status = nfsd4_check_cb_sec(&cr_ses->cb_sec);
	if (status)
		return status;
	status = check_forechannel_attrs(&cr_ses->fore_channel, nn);
	if (status)
		return status;
	status = check_backchannel_attrs(&cr_ses->back_channel);
	if (status)
		goto out_release_drc_mem;
	status = nfserr_jukebox;
	new = alloc_session(&cr_ses->fore_channel, &cr_ses->back_channel);
	if (!new)
		goto out_release_drc_mem;
	conn = alloc_conn_from_crses(rqstp, cr_ses);
	if (!conn)
		goto out_free_session;

	spin_lock(&nn->client_lock);
	unconf = find_unconfirmed_client(&cr_ses->clientid, true, nn);
	conf = find_confirmed_client(&cr_ses->clientid, true, nn);
	WARN_ON_ONCE(conf && unconf);

	if (conf) {
		status = nfserr_wrong_cred;
		if (!mach_creds_match(conf, rqstp))
			goto out_free_conn;
		cs_slot = &conf->cl_cs_slot;
		status = check_slot_seqid(cr_ses->seqid, cs_slot->sl_seqid, 0);
		if (status == nfserr_replay_cache) {
			status = nfsd4_replay_create_session(cr_ses, cs_slot);
			goto out_free_conn;
		} else if (cr_ses->seqid != cs_slot->sl_seqid + 1) {
			status = nfserr_seq_misordered;
			goto out_free_conn;
		}
	} else if (unconf) {
		if (!same_creds(&unconf->cl_cred, &rqstp->rq_cred) ||
		    !rpc_cmp_addr(sa, (struct sockaddr *) &unconf->cl_addr)) {
			status = nfserr_clid_inuse;
			goto out_free_conn;
		}
		status = nfserr_wrong_cred;
		if (!mach_creds_match(unconf, rqstp))
			goto out_free_conn;
		cs_slot = &unconf->cl_cs_slot;
		status = check_slot_seqid(cr_ses->seqid, cs_slot->sl_seqid, 0);
		if (status) {
			/* an unconfirmed replay returns misordered */
			status = nfserr_seq_misordered;
			goto out_free_conn;
		}
		old = find_confirmed_client_by_name(&unconf->cl_name, nn);
		if (old) {
			status = mark_client_expired_locked(old);
			if (status) {
				old = NULL;
				goto out_free_conn;
			}
		}
		move_to_confirmed(unconf);
		conf = unconf;
	} else {
		status = nfserr_stale_clientid;
		goto out_free_conn;
	}
	status = nfs_ok;
	/*
	 * We do not support RDMA or persistent sessions
	 */
	cr_ses->flags &= ~SESSION4_PERSIST;
	cr_ses->flags &= ~SESSION4_RDMA;

	init_session(rqstp, new, conf, cr_ses);
	nfsd4_get_session_locked(new);

	memcpy(cr_ses->sessionid.data, new->se_sessionid.data,
	       NFS4_MAX_SESSIONID_LEN);
	cs_slot->sl_seqid++;
	cr_ses->seqid = cs_slot->sl_seqid;

	/* cache solo and embedded create sessions under the client_lock */
	nfsd4_cache_create_session(cr_ses, cs_slot, status);
	spin_unlock(&nn->client_lock);
	/* init connection and backchannel */
	nfsd4_init_conn(rqstp, conn, new);
	nfsd4_put_session(new);
	if (old)
		expire_client(old);
	return status;
out_free_conn:
	spin_unlock(&nn->client_lock);
	free_conn(conn);
	if (old)
		expire_client(old);
out_free_session:
	__free_session(new);
out_release_drc_mem:
	nfsd4_put_drc_mem(&cr_ses->fore_channel);
	return status;
}

static __be32 nfsd4_map_bcts_dir(u32 *dir)
{
	switch (*dir) {
	case NFS4_CDFC4_FORE:
	case NFS4_CDFC4_BACK:
		return nfs_ok;
	case NFS4_CDFC4_FORE_OR_BOTH:
	case NFS4_CDFC4_BACK_OR_BOTH:
		*dir = NFS4_CDFC4_BOTH;
		return nfs_ok;
	};
	return nfserr_inval;
}

__be32 nfsd4_backchannel_ctl(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate, struct nfsd4_backchannel_ctl *bc)
{
	struct nfsd4_session *session = cstate->session;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);
	__be32 status;

	status = nfsd4_check_cb_sec(&bc->bc_cb_sec);
	if (status)
		return status;
	spin_lock(&nn->client_lock);
	session->se_cb_prog = bc->bc_cb_program;
	session->se_cb_sec = bc->bc_cb_sec;
	spin_unlock(&nn->client_lock);

	nfsd4_probe_callback(session->se_client);

	return nfs_ok;
}

__be32 nfsd4_bind_conn_to_session(struct svc_rqst *rqstp,
		     struct nfsd4_compound_state *cstate,
		     struct nfsd4_bind_conn_to_session *bcts)
{
	__be32 status;
	struct nfsd4_conn *conn;
	struct nfsd4_session *session;
	struct net *net = SVC_NET(rqstp);
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	if (!nfsd4_last_compound_op(rqstp))
		return nfserr_not_only_op;
	spin_lock(&nn->client_lock);
	session = find_in_sessionid_hashtbl(&bcts->sessionid, net, &status);
	spin_unlock(&nn->client_lock);
	if (!session)
		goto out_no_session;
	status = nfserr_wrong_cred;
	if (!mach_creds_match(session->se_client, rqstp))
		goto out;
	status = nfsd4_map_bcts_dir(&bcts->dir);
	if (status)
		goto out;
	conn = alloc_conn(rqstp, bcts->dir);
	status = nfserr_jukebox;
	if (!conn)
		goto out;
	nfsd4_init_conn(rqstp, conn, session);
	status = nfs_ok;
out:
	nfsd4_put_session(session);
out_no_session:
	return status;
}

static bool nfsd4_compound_in_session(struct nfsd4_session *session, struct nfs4_sessionid *sid)
{
	if (!session)
		return 0;
	return !memcmp(sid, &session->se_sessionid, sizeof(*sid));
}

__be32
nfsd4_destroy_session(struct svc_rqst *r,
		      struct nfsd4_compound_state *cstate,
		      struct nfsd4_destroy_session *sessionid)
{
	struct nfsd4_session *ses;
	__be32 status;
	int ref_held_by_me = 0;
	struct net *net = SVC_NET(r);
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	status = nfserr_not_only_op;
	if (nfsd4_compound_in_session(cstate->session, &sessionid->sessionid)) {
		if (!nfsd4_last_compound_op(r))
			goto out;
		ref_held_by_me++;
	}
	dump_sessionid(__func__, &sessionid->sessionid);
	spin_lock(&nn->client_lock);
	ses = find_in_sessionid_hashtbl(&sessionid->sessionid, net, &status);
	if (!ses)
		goto out_client_lock;
	status = nfserr_wrong_cred;
	if (!mach_creds_match(ses->se_client, r))
		goto out_put_session;
	status = mark_session_dead_locked(ses, 1 + ref_held_by_me);
	if (status)
		goto out_put_session;
	unhash_session(ses);
	spin_unlock(&nn->client_lock);

	nfsd4_probe_callback_sync(ses->se_client);

	spin_lock(&nn->client_lock);
	status = nfs_ok;
out_put_session:
	nfsd4_put_session_locked(ses);
out_client_lock:
	spin_unlock(&nn->client_lock);
out:
	return status;
}

static struct nfsd4_conn *__nfsd4_find_conn(struct svc_xprt *xpt, struct nfsd4_session *s)
{
	struct nfsd4_conn *c;

	list_for_each_entry(c, &s->se_conns, cn_persession) {
		if (c->cn_xprt == xpt) {
			return c;
		}
	}
	return NULL;
}

static __be32 nfsd4_sequence_check_conn(struct nfsd4_conn *new, struct nfsd4_session *ses)
{
	struct nfs4_client *clp = ses->se_client;
	struct nfsd4_conn *c;
	__be32 status = nfs_ok;
	int ret;

	spin_lock(&clp->cl_lock);
	c = __nfsd4_find_conn(new->cn_xprt, ses);
	if (c)
		goto out_free;
	status = nfserr_conn_not_bound_to_session;
	if (clp->cl_mach_cred)
		goto out_free;
	__nfsd4_hash_conn(new, ses);
	spin_unlock(&clp->cl_lock);
	ret = nfsd4_register_conn(new);
	if (ret)
		/* oops; xprt is already down: */
		nfsd4_conn_lost(&new->cn_xpt_user);
	return nfs_ok;
out_free:
	spin_unlock(&clp->cl_lock);
	free_conn(new);
	return status;
}

static bool nfsd4_session_too_many_ops(struct svc_rqst *rqstp, struct nfsd4_session *session)
{
	struct nfsd4_compoundargs *args = rqstp->rq_argp;

	return args->opcnt > session->se_fchannel.maxops;
}

static bool nfsd4_request_too_big(struct svc_rqst *rqstp,
				  struct nfsd4_session *session)
{
	struct xdr_buf *xb = &rqstp->rq_arg;

	return xb->len > session->se_fchannel.maxreq_sz;
}

__be32
nfsd4_sequence(struct svc_rqst *rqstp,
	       struct nfsd4_compound_state *cstate,
	       struct nfsd4_sequence *seq)
{
	struct nfsd4_compoundres *resp = rqstp->rq_resp;
	struct xdr_stream *xdr = &resp->xdr;
	struct nfsd4_session *session;
	struct nfs4_client *clp;
	struct nfsd4_slot *slot;
	struct nfsd4_conn *conn;
	__be32 status;
	int buflen;
	struct net *net = SVC_NET(rqstp);
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	if (resp->opcnt != 1)
		return nfserr_sequence_pos;

	/*
	 * Will be either used or freed by nfsd4_sequence_check_conn
	 * below.
	 */
	conn = alloc_conn(rqstp, NFS4_CDFC4_FORE);
	if (!conn)
		return nfserr_jukebox;

	spin_lock(&nn->client_lock);
	session = find_in_sessionid_hashtbl(&seq->sessionid, net, &status);
	if (!session)
		goto out_no_session;
	clp = session->se_client;

	status = nfserr_too_many_ops;
	if (nfsd4_session_too_many_ops(rqstp, session))
		goto out_put_session;

	status = nfserr_req_too_big;
	if (nfsd4_request_too_big(rqstp, session))
		goto out_put_session;

	status = nfserr_badslot;
	if (seq->slotid >= session->se_fchannel.maxreqs)
		goto out_put_session;

	slot = session->se_slots[seq->slotid];
	dprintk("%s: slotid %d\n", __func__, seq->slotid);

	/* We do not negotiate the number of slots yet, so set the
	 * maxslots to the session maxreqs which is used to encode
	 * sr_highest_slotid and the sr_target_slot id to maxslots */
	seq->maxslots = session->se_fchannel.maxreqs;

	status = check_slot_seqid(seq->seqid, slot->sl_seqid,
					slot->sl_flags & NFSD4_SLOT_INUSE);
	if (status == nfserr_replay_cache) {
		status = nfserr_seq_misordered;
		if (!(slot->sl_flags & NFSD4_SLOT_INITIALIZED))
			goto out_put_session;
		cstate->slot = slot;
		cstate->session = session;
		cstate->clp = clp;
		/* Return the cached reply status and set cstate->status
		 * for nfsd4_proc_compound processing */
		status = nfsd4_replay_cache_entry(resp, seq);
		cstate->status = nfserr_replay_cache;
		goto out;
	}
	if (status)
		goto out_put_session;

	status = nfsd4_sequence_check_conn(conn, session);
	conn = NULL;
	if (status)
		goto out_put_session;

	buflen = (seq->cachethis) ?
			session->se_fchannel.maxresp_cached :
			session->se_fchannel.maxresp_sz;
	status = (seq->cachethis) ? nfserr_rep_too_big_to_cache :
				    nfserr_rep_too_big;
	if (xdr_restrict_buflen(xdr, buflen - rqstp->rq_auth_slack))
		goto out_put_session;
	svc_reserve(rqstp, buflen);

	status = nfs_ok;
	/* Success! bump slot seqid */
	slot->sl_seqid = seq->seqid;
	slot->sl_flags |= NFSD4_SLOT_INUSE;
	if (seq->cachethis)
		slot->sl_flags |= NFSD4_SLOT_CACHETHIS;
	else
		slot->sl_flags &= ~NFSD4_SLOT_CACHETHIS;

	cstate->slot = slot;
	cstate->session = session;
	cstate->clp = clp;

out:
	switch (clp->cl_cb_state) {
	case NFSD4_CB_DOWN:
		seq->status_flags = SEQ4_STATUS_CB_PATH_DOWN;
		break;
	case NFSD4_CB_FAULT:
		seq->status_flags = SEQ4_STATUS_BACKCHANNEL_FAULT;
		break;
	default:
		seq->status_flags = 0;
	}
	if (!list_empty(&clp->cl_revoked))
		seq->status_flags |= SEQ4_STATUS_RECALLABLE_STATE_REVOKED;
out_no_session:
	if (conn)
		free_conn(conn);
	spin_unlock(&nn->client_lock);
	return status;
out_put_session:
	nfsd4_put_session_locked(session);
	goto out_no_session;
}

void
nfsd4_sequence_done(struct nfsd4_compoundres *resp)
{
	struct nfsd4_compound_state *cs = &resp->cstate;

	if (nfsd4_has_session(cs)) {
		if (cs->status != nfserr_replay_cache) {
			nfsd4_store_cache_entry(resp);
			cs->slot->sl_flags &= ~NFSD4_SLOT_INUSE;
		}
		/* Drop session reference that was taken in nfsd4_sequence() */
		nfsd4_put_session(cs->session);
	} else if (cs->clp)
		put_client_renew(cs->clp);
}

__be32
nfsd4_destroy_clientid(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate, struct nfsd4_destroy_clientid *dc)
{
	struct nfs4_client *conf, *unconf;
	struct nfs4_client *clp = NULL;
	__be32 status = 0;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	spin_lock(&nn->client_lock);
	unconf = find_unconfirmed_client(&dc->clientid, true, nn);
	conf = find_confirmed_client(&dc->clientid, true, nn);
	WARN_ON_ONCE(conf && unconf);

	if (conf) {
		if (client_has_state(conf)) {
			status = nfserr_clientid_busy;
			goto out;
		}
		status = mark_client_expired_locked(conf);
		if (status)
			goto out;
		clp = conf;
	} else if (unconf)
		clp = unconf;
	else {
		status = nfserr_stale_clientid;
		goto out;
	}
	if (!mach_creds_match(clp, rqstp)) {
		clp = NULL;
		status = nfserr_wrong_cred;
		goto out;
	}
	unhash_client_locked(clp);
out:
	spin_unlock(&nn->client_lock);
	if (clp)
		expire_client(clp);
	return status;
}

__be32
nfsd4_reclaim_complete(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate, struct nfsd4_reclaim_complete *rc)
{
	__be32 status = 0;

	if (rc->rca_one_fs) {
		if (!cstate->current_fh.fh_dentry)
			return nfserr_nofilehandle;
		/*
		 * We don't take advantage of the rca_one_fs case.
		 * That's OK, it's optional, we can safely ignore it.
		 */
		 return nfs_ok;
	}

	status = nfserr_complete_already;
	if (test_and_set_bit(NFSD4_CLIENT_RECLAIM_COMPLETE,
			     &cstate->session->se_client->cl_flags))
		goto out;

	status = nfserr_stale_clientid;
	if (is_client_expired(cstate->session->se_client))
		/*
		 * The following error isn't really legal.
		 * But we only get here if the client just explicitly
		 * destroyed the client.  Surely it no longer cares what
		 * error it gets back on an operation for the dead
		 * client.
		 */
		goto out;

	status = nfs_ok;
	nfsd4_client_record_create(cstate->session->se_client);
out:
	return status;
}

__be32
nfsd4_setclientid(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		  struct nfsd4_setclientid *setclid)
{
	struct xdr_netobj 	clname = setclid->se_name;
	nfs4_verifier		clverifier = setclid->se_verf;
	struct nfs4_client	*conf, *new;
	struct nfs4_client	*unconf = NULL;
	__be32 			status;
	struct nfsd_net		*nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	new = create_client(clname, rqstp, &clverifier);
	if (new == NULL)
		return nfserr_jukebox;
	/* Cases below refer to rfc 3530 section 14.2.33: */
	spin_lock(&nn->client_lock);
	conf = find_confirmed_client_by_name(&clname, nn);
	if (conf) {
		/* case 0: */
		status = nfserr_clid_inuse;
		if (clp_used_exchangeid(conf))
			goto out;
		if (!same_creds(&conf->cl_cred, &rqstp->rq_cred)) {
			char addr_str[INET6_ADDRSTRLEN];
			rpc_ntop((struct sockaddr *) &conf->cl_addr, addr_str,
				 sizeof(addr_str));
			dprintk("NFSD: setclientid: string in use by client "
				"at %s\n", addr_str);
			goto out;
		}
	}
	unconf = find_unconfirmed_client_by_name(&clname, nn);
	if (unconf)
		unhash_client_locked(unconf);
	if (conf && same_verf(&conf->cl_verifier, &clverifier))
		/* case 1: probable callback update */
		copy_clid(new, conf);
	else /* case 4 (new client) or cases 2, 3 (client reboot): */
		gen_clid(new, nn);
	new->cl_minorversion = 0;
	gen_callback(new, setclid, rqstp);
	add_to_unconfirmed(new);
	setclid->se_clientid.cl_boot = new->cl_clientid.cl_boot;
	setclid->se_clientid.cl_id = new->cl_clientid.cl_id;
	memcpy(setclid->se_confirm.data, new->cl_confirm.data, sizeof(setclid->se_confirm.data));
	new = NULL;
	status = nfs_ok;
out:
	spin_unlock(&nn->client_lock);
	if (new)
		free_client(new);
	if (unconf)
		expire_client(unconf);
	return status;
}


__be32
nfsd4_setclientid_confirm(struct svc_rqst *rqstp,
			 struct nfsd4_compound_state *cstate,
			 struct nfsd4_setclientid_confirm *setclientid_confirm)
{
	struct nfs4_client *conf, *unconf;
	struct nfs4_client *old = NULL;
	nfs4_verifier confirm = setclientid_confirm->sc_confirm; 
	clientid_t * clid = &setclientid_confirm->sc_clientid;
	__be32 status;
	struct nfsd_net	*nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	if (STALE_CLIENTID(clid, nn))
		return nfserr_stale_clientid;

	spin_lock(&nn->client_lock);
	conf = find_confirmed_client(clid, false, nn);
	unconf = find_unconfirmed_client(clid, false, nn);
	/*
	 * We try hard to give out unique clientid's, so if we get an
	 * attempt to confirm the same clientid with a different cred,
	 * there's a bug somewhere.  Let's charitably assume it's our
	 * bug.
	 */
	status = nfserr_serverfault;
	if (unconf && !same_creds(&unconf->cl_cred, &rqstp->rq_cred))
		goto out;
	if (conf && !same_creds(&conf->cl_cred, &rqstp->rq_cred))
		goto out;
	/* cases below refer to rfc 3530 section 14.2.34: */
	if (!unconf || !same_verf(&confirm, &unconf->cl_confirm)) {
		if (conf && !unconf) /* case 2: probable retransmit */
			status = nfs_ok;
		else /* case 4: client hasn't noticed we rebooted yet? */
			status = nfserr_stale_clientid;
		goto out;
	}
	status = nfs_ok;
	if (conf) { /* case 1: callback update */
		old = unconf;
		unhash_client_locked(old);
		nfsd4_change_callback(conf, &unconf->cl_cb_conn);
	} else { /* case 3: normal case; new or rebooted client */
		old = find_confirmed_client_by_name(&unconf->cl_name, nn);
		if (old) {
			status = mark_client_expired_locked(old);
			if (status) {
				old = NULL;
				goto out;
			}
		}
		move_to_confirmed(unconf);
		conf = unconf;
	}
	get_client_locked(conf);
	spin_unlock(&nn->client_lock);
	nfsd4_probe_callback(conf);
	spin_lock(&nn->client_lock);
	put_client_renew_locked(conf);
out:
	spin_unlock(&nn->client_lock);
	if (old)
		expire_client(old);
	return status;
}

static struct nfs4_file *nfsd4_alloc_file(void)
{
	return kmem_cache_alloc(file_slab, GFP_KERNEL);
}

/* OPEN Share state helper functions */
static void nfsd4_init_file(struct knfsd_fh *fh, unsigned int hashval,
				struct nfs4_file *fp)
{
	lockdep_assert_held(&state_lock);

	atomic_set(&fp->fi_ref, 1);
	spin_lock_init(&fp->fi_lock);
	INIT_LIST_HEAD(&fp->fi_stateids);
	INIT_LIST_HEAD(&fp->fi_delegations);
	fh_copy_shallow(&fp->fi_fhandle, fh);
	fp->fi_deleg_file = NULL;
	fp->fi_had_conflict = false;
	fp->fi_share_deny = 0;
	memset(fp->fi_fds, 0, sizeof(fp->fi_fds));
	memset(fp->fi_access, 0, sizeof(fp->fi_access));
#ifdef CONFIG_NFSD_PNFS
	INIT_LIST_HEAD(&fp->fi_lo_states);
	atomic_set(&fp->fi_lo_recalls, 0);
#endif
	hlist_add_head_rcu(&fp->fi_hash, &file_hashtbl[hashval]);
}

void
nfsd4_free_slabs(void)
{
	kmem_cache_destroy(openowner_slab);
	kmem_cache_destroy(lockowner_slab);
	kmem_cache_destroy(file_slab);
	kmem_cache_destroy(stateid_slab);
	kmem_cache_destroy(deleg_slab);
}

int
nfsd4_init_slabs(void)
{
	openowner_slab = kmem_cache_create("nfsd4_openowners",
			sizeof(struct nfs4_openowner), 0, 0, NULL);
	if (openowner_slab == NULL)
		goto out;
	lockowner_slab = kmem_cache_create("nfsd4_lockowners",
			sizeof(struct nfs4_lockowner), 0, 0, NULL);
	if (lockowner_slab == NULL)
		goto out_free_openowner_slab;
	file_slab = kmem_cache_create("nfsd4_files",
			sizeof(struct nfs4_file), 0, 0, NULL);
	if (file_slab == NULL)
		goto out_free_lockowner_slab;
	stateid_slab = kmem_cache_create("nfsd4_stateids",
			sizeof(struct nfs4_ol_stateid), 0, 0, NULL);
	if (stateid_slab == NULL)
		goto out_free_file_slab;
	deleg_slab = kmem_cache_create("nfsd4_delegations",
			sizeof(struct nfs4_delegation), 0, 0, NULL);
	if (deleg_slab == NULL)
		goto out_free_stateid_slab;
	return 0;

out_free_stateid_slab:
	kmem_cache_destroy(stateid_slab);
out_free_file_slab:
	kmem_cache_destroy(file_slab);
out_free_lockowner_slab:
	kmem_cache_destroy(lockowner_slab);
out_free_openowner_slab:
	kmem_cache_destroy(openowner_slab);
out:
	dprintk("nfsd4: out of memory while initializing nfsv4\n");
	return -ENOMEM;
}

static void init_nfs4_replay(struct nfs4_replay *rp)
{
	rp->rp_status = nfserr_serverfault;
	rp->rp_buflen = 0;
	rp->rp_buf = rp->rp_ibuf;
	mutex_init(&rp->rp_mutex);
}

static void nfsd4_cstate_assign_replay(struct nfsd4_compound_state *cstate,
		struct nfs4_stateowner *so)
{
	if (!nfsd4_has_session(cstate)) {
		mutex_lock(&so->so_replay.rp_mutex);
		cstate->replay_owner = nfs4_get_stateowner(so);
	}
}

void nfsd4_cstate_clear_replay(struct nfsd4_compound_state *cstate)
{
	struct nfs4_stateowner *so = cstate->replay_owner;

	if (so != NULL) {
		cstate->replay_owner = NULL;
		mutex_unlock(&so->so_replay.rp_mutex);
		nfs4_put_stateowner(so);
	}
}

static inline void *alloc_stateowner(struct kmem_cache *slab, struct xdr_netobj *owner, struct nfs4_client *clp)
{
	struct nfs4_stateowner *sop;

	sop = kmem_cache_alloc(slab, GFP_KERNEL);
	if (!sop)
		return NULL;

	sop->so_owner.data = kmemdup(owner->data, owner->len, GFP_KERNEL);
	if (!sop->so_owner.data) {
		kmem_cache_free(slab, sop);
		return NULL;
	}
	sop->so_owner.len = owner->len;

	INIT_LIST_HEAD(&sop->so_stateids);
	sop->so_client = clp;
	init_nfs4_replay(&sop->so_replay);
	atomic_set(&sop->so_count, 1);
	return sop;
}

static void hash_openowner(struct nfs4_openowner *oo, struct nfs4_client *clp, unsigned int strhashval)
{
	lockdep_assert_held(&clp->cl_lock);

	list_add(&oo->oo_owner.so_strhash,
		 &clp->cl_ownerstr_hashtbl[strhashval]);
	list_add(&oo->oo_perclient, &clp->cl_openowners);
}

static void nfs4_unhash_openowner(struct nfs4_stateowner *so)
{
	unhash_openowner_locked(openowner(so));
}

static void nfs4_free_openowner(struct nfs4_stateowner *so)
{
	struct nfs4_openowner *oo = openowner(so);

	kmem_cache_free(openowner_slab, oo);
}

static const struct nfs4_stateowner_operations openowner_ops = {
	.so_unhash =	nfs4_unhash_openowner,
	.so_free =	nfs4_free_openowner,
};

static struct nfs4_openowner *
alloc_init_open_stateowner(unsigned int strhashval, struct nfsd4_open *open,
			   struct nfsd4_compound_state *cstate)
{
	struct nfs4_client *clp = cstate->clp;
	struct nfs4_openowner *oo, *ret;

	oo = alloc_stateowner(openowner_slab, &open->op_owner, clp);
	if (!oo)
		return NULL;
	oo->oo_owner.so_ops = &openowner_ops;
	oo->oo_owner.so_is_open_owner = 1;
	oo->oo_owner.so_seqid = open->op_seqid;
	oo->oo_flags = 0;
	if (nfsd4_has_session(cstate))
		oo->oo_flags |= NFS4_OO_CONFIRMED;
	oo->oo_time = 0;
	oo->oo_last_closed_stid = NULL;
	INIT_LIST_HEAD(&oo->oo_close_lru);
	spin_lock(&clp->cl_lock);
	ret = find_openstateowner_str_locked(strhashval, open, clp);
	if (ret == NULL) {
		hash_openowner(oo, clp, strhashval);
		ret = oo;
	} else
		nfs4_free_openowner(&oo->oo_owner);
	spin_unlock(&clp->cl_lock);
	return oo;
}

static void init_open_stateid(struct nfs4_ol_stateid *stp, struct nfs4_file *fp, struct nfsd4_open *open) {
	struct nfs4_openowner *oo = open->op_openowner;

	atomic_inc(&stp->st_stid.sc_count);
	stp->st_stid.sc_type = NFS4_OPEN_STID;
	INIT_LIST_HEAD(&stp->st_locks);
	stp->st_stateowner = nfs4_get_stateowner(&oo->oo_owner);
	get_nfs4_file(fp);
	stp->st_stid.sc_file = fp;
	stp->st_access_bmap = 0;
	stp->st_deny_bmap = 0;
	stp->st_openstp = NULL;
	spin_lock(&oo->oo_owner.so_client->cl_lock);
	list_add(&stp->st_perstateowner, &oo->oo_owner.so_stateids);
	spin_lock(&fp->fi_lock);
	list_add(&stp->st_perfile, &fp->fi_stateids);
	spin_unlock(&fp->fi_lock);
	spin_unlock(&oo->oo_owner.so_client->cl_lock);
}

/*
 * In the 4.0 case we need to keep the owners around a little while to handle
 * CLOSE replay. We still do need to release any file access that is held by
 * them before returning however.
 */
static void
move_to_close_lru(struct nfs4_ol_stateid *s, struct net *net)
{
	struct nfs4_ol_stateid *last;
	struct nfs4_openowner *oo = openowner(s->st_stateowner);
	struct nfsd_net *nn = net_generic(s->st_stid.sc_client->net,
						nfsd_net_id);

	dprintk("NFSD: move_to_close_lru nfs4_openowner %p\n", oo);

	/*
	 * We know that we hold one reference via nfsd4_close, and another
	 * "persistent" reference for the client. If the refcount is higher
	 * than 2, then there are still calls in progress that are using this
	 * stateid. We can't put the sc_file reference until they are finished.
	 * Wait for the refcount to drop to 2. Since it has been unhashed,
	 * there should be no danger of the refcount going back up again at
	 * this point.
	 */
	wait_event(close_wq, atomic_read(&s->st_stid.sc_count) == 2);

	release_all_access(s);
	if (s->st_stid.sc_file) {
		put_nfs4_file(s->st_stid.sc_file);
		s->st_stid.sc_file = NULL;
	}

	spin_lock(&nn->client_lock);
	last = oo->oo_last_closed_stid;
	oo->oo_last_closed_stid = s;
	list_move_tail(&oo->oo_close_lru, &nn->close_lru);
	oo->oo_time = get_seconds();
	spin_unlock(&nn->client_lock);
	if (last)
		nfs4_put_stid(&last->st_stid);
}

/* search file_hashtbl[] for file */
static struct nfs4_file *
find_file_locked(struct knfsd_fh *fh, unsigned int hashval)
{
	struct nfs4_file *fp;

	hlist_for_each_entry_rcu(fp, &file_hashtbl[hashval], fi_hash) {
		if (fh_match(&fp->fi_fhandle, fh)) {
			if (atomic_inc_not_zero(&fp->fi_ref))
				return fp;
		}
	}
	return NULL;
}

struct nfs4_file *
find_file(struct knfsd_fh *fh)
{
	struct nfs4_file *fp;
	unsigned int hashval = file_hashval(fh);

	rcu_read_lock();
	fp = find_file_locked(fh, hashval);
	rcu_read_unlock();
	return fp;
}

static struct nfs4_file *
find_or_add_file(struct nfs4_file *new, struct knfsd_fh *fh)
{
	struct nfs4_file *fp;
	unsigned int hashval = file_hashval(fh);

	rcu_read_lock();
	fp = find_file_locked(fh, hashval);
	rcu_read_unlock();
	if (fp)
		return fp;

	spin_lock(&state_lock);
	fp = find_file_locked(fh, hashval);
	if (likely(fp == NULL)) {
		nfsd4_init_file(fh, hashval, new);
		fp = new;
	}
	spin_unlock(&state_lock);

	return fp;
}

/*
 * Called to check deny when READ with all zero stateid or
 * WRITE with all zero or all one stateid
 */
static __be32
nfs4_share_conflict(struct svc_fh *current_fh, unsigned int deny_type)
{
	struct nfs4_file *fp;
	__be32 ret = nfs_ok;

	fp = find_file(&current_fh->fh_handle);
	if (!fp)
		return ret;
	/* Check for conflicting share reservations */
	spin_lock(&fp->fi_lock);
	if (fp->fi_share_deny & deny_type)
		ret = nfserr_locked;
	spin_unlock(&fp->fi_lock);
	put_nfs4_file(fp);
	return ret;
}

static void nfsd4_cb_recall_prepare(struct nfsd4_callback *cb)
{
	struct nfs4_delegation *dp = cb_to_delegation(cb);
	struct nfsd_net *nn = net_generic(dp->dl_stid.sc_client->net,
					  nfsd_net_id);

	block_delegations(&dp->dl_stid.sc_file->fi_fhandle);

	/*
	 * We can't do this in nfsd_break_deleg_cb because it is
	 * already holding inode->i_lock.
	 *
	 * If the dl_time != 0, then we know that it has already been
	 * queued for a lease break. Don't queue it again.
	 */
	spin_lock(&state_lock);
	if (dp->dl_time == 0) {
		dp->dl_time = get_seconds();
		list_add_tail(&dp->dl_recall_lru, &nn->del_recall_lru);
	}
	spin_unlock(&state_lock);
}

static int nfsd4_cb_recall_done(struct nfsd4_callback *cb,
		struct rpc_task *task)
{
	struct nfs4_delegation *dp = cb_to_delegation(cb);

	switch (task->tk_status) {
	case 0:
		return 1;
	case -EBADHANDLE:
	case -NFS4ERR_BAD_STATEID:
		/*
		 * Race: client probably got cb_recall before open reply
		 * granting delegation.
		 */
		if (dp->dl_retries--) {
			rpc_delay(task, 2 * HZ);
			return 0;
		}
		/*FALLTHRU*/
	default:
		return -1;
	}
}

static void nfsd4_cb_recall_release(struct nfsd4_callback *cb)
{
	struct nfs4_delegation *dp = cb_to_delegation(cb);

	nfs4_put_stid(&dp->dl_stid);
}

static struct nfsd4_callback_ops nfsd4_cb_recall_ops = {
	.prepare	= nfsd4_cb_recall_prepare,
	.done		= nfsd4_cb_recall_done,
	.release	= nfsd4_cb_recall_release,
};

static void nfsd_break_one_deleg(struct nfs4_delegation *dp)
{
	/*
	 * We're assuming the state code never drops its reference
	 * without first removing the lease.  Since we're in this lease
	 * callback (and since the lease code is serialized by the kernel
	 * lock) we know the server hasn't removed the lease yet, we know
	 * it's safe to take a reference.
	 */
	atomic_inc(&dp->dl_stid.sc_count);
	nfsd4_run_cb(&dp->dl_recall);
}

/* Called from break_lease() with i_lock held. */
static bool
nfsd_break_deleg_cb(struct file_lock *fl)
{
	bool ret = false;
	struct nfs4_file *fp = (struct nfs4_file *)fl->fl_owner;
	struct nfs4_delegation *dp;

	if (!fp) {
		WARN(1, "(%p)->fl_owner NULL\n", fl);
		return ret;
	}
	if (fp->fi_had_conflict) {
		WARN(1, "duplicate break on %p\n", fp);
		return ret;
	}
	/*
	 * We don't want the locks code to timeout the lease for us;
	 * we'll remove it ourself if a delegation isn't returned
	 * in time:
	 */
	fl->fl_break_time = 0;

	spin_lock(&fp->fi_lock);
	fp->fi_had_conflict = true;
	/*
	 * If there are no delegations on the list, then return true
	 * so that the lease code will go ahead and delete it.
	 */
	if (list_empty(&fp->fi_delegations))
		ret = true;
	else
		list_for_each_entry(dp, &fp->fi_delegations, dl_perfile)
			nfsd_break_one_deleg(dp);
	spin_unlock(&fp->fi_lock);
	return ret;
}

static int
nfsd_change_deleg_cb(struct file_lock *onlist, int arg,
		     struct list_head *dispose)
{
	if (arg & F_UNLCK)
		return lease_modify(onlist, arg, dispose);
	else
		return -EAGAIN;
}

static const struct lock_manager_operations nfsd_lease_mng_ops = {
	.lm_break = nfsd_break_deleg_cb,
	.lm_change = nfsd_change_deleg_cb,
};

static __be32 nfsd4_check_seqid(struct nfsd4_compound_state *cstate, struct nfs4_stateowner *so, u32 seqid)
{
	if (nfsd4_has_session(cstate))
		return nfs_ok;
	if (seqid == so->so_seqid - 1)
		return nfserr_replay_me;
	if (seqid == so->so_seqid)
		return nfs_ok;
	return nfserr_bad_seqid;
}

static __be32 lookup_clientid(clientid_t *clid,
		struct nfsd4_compound_state *cstate,
		struct nfsd_net *nn)
{
	struct nfs4_client *found;

	if (cstate->clp) {
		found = cstate->clp;
		if (!same_clid(&found->cl_clientid, clid))
			return nfserr_stale_clientid;
		return nfs_ok;
	}

	if (STALE_CLIENTID(clid, nn))
		return nfserr_stale_clientid;

	/*
	 * For v4.1+ we get the client in the SEQUENCE op. If we don't have one
	 * cached already then we know this is for is for v4.0 and "sessions"
	 * will be false.
	 */
	WARN_ON_ONCE(cstate->session);
	spin_lock(&nn->client_lock);
	found = find_confirmed_client(clid, false, nn);
	if (!found) {
		spin_unlock(&nn->client_lock);
		return nfserr_expired;
	}
	atomic_inc(&found->cl_refcount);
	spin_unlock(&nn->client_lock);

	/* Cache the nfs4_client in cstate! */
	cstate->clp = found;
	return nfs_ok;
}

__be32
nfsd4_process_open1(struct nfsd4_compound_state *cstate,
		    struct nfsd4_open *open, struct nfsd_net *nn)
{
	clientid_t *clientid = &open->op_clientid;
	struct nfs4_client *clp = NULL;
	unsigned int strhashval;
	struct nfs4_openowner *oo = NULL;
	__be32 status;

	if (STALE_CLIENTID(&open->op_clientid, nn))
		return nfserr_stale_clientid;
	/*
	 * In case we need it later, after we've already created the
	 * file and don't want to risk a further failure:
	 */
	open->op_file = nfsd4_alloc_file();
	if (open->op_file == NULL)
		return nfserr_jukebox;

	status = lookup_clientid(clientid, cstate, nn);
	if (status)
		return status;
	clp = cstate->clp;

	strhashval = ownerstr_hashval(&open->op_owner);
	oo = find_openstateowner_str(strhashval, open, clp);
	open->op_openowner = oo;
	if (!oo) {
		goto new_owner;
	}
	if (!(oo->oo_flags & NFS4_OO_CONFIRMED)) {
		/* Replace unconfirmed owners without checking for replay. */
		release_openowner(oo);
		open->op_openowner = NULL;
		goto new_owner;
	}
	status = nfsd4_check_seqid(cstate, &oo->oo_owner, open->op_seqid);
	if (status)
		return status;
	goto alloc_stateid;
new_owner:
	oo = alloc_init_open_stateowner(strhashval, open, cstate);
	if (oo == NULL)
		return nfserr_jukebox;
	open->op_openowner = oo;
alloc_stateid:
	open->op_stp = nfs4_alloc_open_stateid(clp);
	if (!open->op_stp)
		return nfserr_jukebox;
	return nfs_ok;
}

static inline __be32
nfs4_check_delegmode(struct nfs4_delegation *dp, int flags)
{
	if ((flags & WR_STATE) && (dp->dl_type == NFS4_OPEN_DELEGATE_READ))
		return nfserr_openmode;
	else
		return nfs_ok;
}

static int share_access_to_flags(u32 share_access)
{
	return share_access == NFS4_SHARE_ACCESS_READ ? RD_STATE : WR_STATE;
}

static struct nfs4_delegation *find_deleg_stateid(struct nfs4_client *cl, stateid_t *s)
{
	struct nfs4_stid *ret;

	ret = find_stateid_by_type(cl, s, NFS4_DELEG_STID);
	if (!ret)
		return NULL;
	return delegstateid(ret);
}

static bool nfsd4_is_deleg_cur(struct nfsd4_open *open)
{
	return open->op_claim_type == NFS4_OPEN_CLAIM_DELEGATE_CUR ||
	       open->op_claim_type == NFS4_OPEN_CLAIM_DELEG_CUR_FH;
}

static __be32
nfs4_check_deleg(struct nfs4_client *cl, struct nfsd4_open *open,
		struct nfs4_delegation **dp)
{
	int flags;
	__be32 status = nfserr_bad_stateid;
	struct nfs4_delegation *deleg;

	deleg = find_deleg_stateid(cl, &open->op_delegate_stateid);
	if (deleg == NULL)
		goto out;
	flags = share_access_to_flags(open->op_share_access);
	status = nfs4_check_delegmode(deleg, flags);
	if (status) {
		nfs4_put_stid(&deleg->dl_stid);
		goto out;
	}
	*dp = deleg;
out:
	if (!nfsd4_is_deleg_cur(open))
		return nfs_ok;
	if (status)
		return status;
	open->op_openowner->oo_flags |= NFS4_OO_CONFIRMED;
	return nfs_ok;
}

static struct nfs4_ol_stateid *
nfsd4_find_existing_open(struct nfs4_file *fp, struct nfsd4_open *open)
{
	struct nfs4_ol_stateid *local, *ret = NULL;
	struct nfs4_openowner *oo = open->op_openowner;

	spin_lock(&fp->fi_lock);
	list_for_each_entry(local, &fp->fi_stateids, st_perfile) {
		/* ignore lock owners */
		if (local->st_stateowner->so_is_open_owner == 0)
			continue;
		if (local->st_stateowner == &oo->oo_owner) {
			ret = local;
			atomic_inc(&ret->st_stid.sc_count);
			break;
		}
	}
	spin_unlock(&fp->fi_lock);
	return ret;
}

static inline int nfs4_access_to_access(u32 nfs4_access)
{
	int flags = 0;

	if (nfs4_access & NFS4_SHARE_ACCESS_READ)
		flags |= NFSD_MAY_READ;
	if (nfs4_access & NFS4_SHARE_ACCESS_WRITE)
		flags |= NFSD_MAY_WRITE;
	return flags;
}

static inline __be32
nfsd4_truncate(struct svc_rqst *rqstp, struct svc_fh *fh,
		struct nfsd4_open *open)
{
	struct iattr iattr = {
		.ia_valid = ATTR_SIZE,
		.ia_size = 0,
	};
	if (!open->op_truncate)
		return 0;
	if (!(open->op_share_access & NFS4_SHARE_ACCESS_WRITE))
		return nfserr_inval;
	return nfsd_setattr(rqstp, fh, &iattr, 0, (time_t)0);
}

static __be32 nfs4_get_vfs_file(struct svc_rqst *rqstp, struct nfs4_file *fp,
		struct svc_fh *cur_fh, struct nfs4_ol_stateid *stp,
		struct nfsd4_open *open)
{
	struct file *filp = NULL;
	__be32 status;
	int oflag = nfs4_access_to_omode(open->op_share_access);
	int access = nfs4_access_to_access(open->op_share_access);
	unsigned char old_access_bmap, old_deny_bmap;

	spin_lock(&fp->fi_lock);

	/*
	 * Are we trying to set a deny mode that would conflict with
	 * current access?
	 */
	status = nfs4_file_check_deny(fp, open->op_share_deny);
	if (status != nfs_ok) {
		spin_unlock(&fp->fi_lock);
		goto out;
	}

	/* set access to the file */
	status = nfs4_file_get_access(fp, open->op_share_access);
	if (status != nfs_ok) {
		spin_unlock(&fp->fi_lock);
		goto out;
	}

	/* Set access bits in stateid */
	old_access_bmap = stp->st_access_bmap;
	set_access(open->op_share_access, stp);

	/* Set new deny mask */
	old_deny_bmap = stp->st_deny_bmap;
	set_deny(open->op_share_deny, stp);
	fp->fi_share_deny |= (open->op_share_deny & NFS4_SHARE_DENY_BOTH);

	if (!fp->fi_fds[oflag]) {
		spin_unlock(&fp->fi_lock);
		status = nfsd_open(rqstp, cur_fh, S_IFREG, access, &filp);
		if (status)
			goto out_put_access;
		spin_lock(&fp->fi_lock);
		if (!fp->fi_fds[oflag]) {
			fp->fi_fds[oflag] = filp;
			filp = NULL;
		}
	}
	spin_unlock(&fp->fi_lock);
	if (filp)
		fput(filp);

	status = nfsd4_truncate(rqstp, cur_fh, open);
	if (status)
		goto out_put_access;
out:
	return status;
out_put_access:
	stp->st_access_bmap = old_access_bmap;
	nfs4_file_put_access(fp, open->op_share_access);
	reset_union_bmap_deny(bmap_to_share_mode(old_deny_bmap), stp);
	goto out;
}

static __be32
nfs4_upgrade_open(struct svc_rqst *rqstp, struct nfs4_file *fp, struct svc_fh *cur_fh, struct nfs4_ol_stateid *stp, struct nfsd4_open *open)
{
	__be32 status;
	unsigned char old_deny_bmap;

	if (!test_access(open->op_share_access, stp))
		return nfs4_get_vfs_file(rqstp, fp, cur_fh, stp, open);

	/* test and set deny mode */
	spin_lock(&fp->fi_lock);
	status = nfs4_file_check_deny(fp, open->op_share_deny);
	if (status == nfs_ok) {
		old_deny_bmap = stp->st_deny_bmap;
		set_deny(open->op_share_deny, stp);
		fp->fi_share_deny |=
				(open->op_share_deny & NFS4_SHARE_DENY_BOTH);
	}
	spin_unlock(&fp->fi_lock);

	if (status != nfs_ok)
		return status;

	status = nfsd4_truncate(rqstp, cur_fh, open);
	if (status != nfs_ok)
		reset_union_bmap_deny(old_deny_bmap, stp);
	return status;
}

static void
nfs4_set_claim_prev(struct nfsd4_open *open, bool has_session)
{
	open->op_openowner->oo_flags |= NFS4_OO_CONFIRMED;
}

/* Should we give out recallable state?: */
static bool nfsd4_cb_channel_good(struct nfs4_client *clp)
{
	if (clp->cl_cb_state == NFSD4_CB_UP)
		return true;
	/*
	 * In the sessions case, since we don't have to establish a
	 * separate connection for callbacks, we assume it's OK
	 * until we hear otherwise:
	 */
	return clp->cl_minorversion && clp->cl_cb_state == NFSD4_CB_UNKNOWN;
}

static struct file_lock *nfs4_alloc_init_lease(struct nfs4_file *fp, int flag)
{
	struct file_lock *fl;

	fl = locks_alloc_lock();
	if (!fl)
		return NULL;
	fl->fl_lmops = &nfsd_lease_mng_ops;
	fl->fl_flags = FL_DELEG;
	fl->fl_type = flag == NFS4_OPEN_DELEGATE_READ? F_RDLCK: F_WRLCK;
	fl->fl_end = OFFSET_MAX;
	fl->fl_owner = (fl_owner_t)fp;
	fl->fl_pid = current->tgid;
	return fl;
}

static int nfs4_setlease(struct nfs4_delegation *dp)
{
	struct nfs4_file *fp = dp->dl_stid.sc_file;
	struct file_lock *fl, *ret;
	struct file *filp;
	int status = 0;

	fl = nfs4_alloc_init_lease(fp, NFS4_OPEN_DELEGATE_READ);
	if (!fl)
		return -ENOMEM;
	filp = find_readable_file(fp);
	if (!filp) {
		/* We should always have a readable file here */
		WARN_ON_ONCE(1);
		return -EBADF;
	}
	fl->fl_file = filp;
	ret = fl;
	status = vfs_setlease(filp, fl->fl_type, &fl, NULL);
	if (fl)
		locks_free_lock(fl);
	if (status)
		goto out_fput;
	spin_lock(&state_lock);
	spin_lock(&fp->fi_lock);
	/* Did the lease get broken before we took the lock? */
	status = -EAGAIN;
	if (fp->fi_had_conflict)
		goto out_unlock;
	/* Race breaker */
	if (fp->fi_deleg_file) {
		status = 0;
		++fp->fi_delegees;
		hash_delegation_locked(dp, fp);
		goto out_unlock;
	}
	fp->fi_deleg_file = filp;
	fp->fi_delegees = 1;
	hash_delegation_locked(dp, fp);
	spin_unlock(&fp->fi_lock);
	spin_unlock(&state_lock);
	return 0;
out_unlock:
	spin_unlock(&fp->fi_lock);
	spin_unlock(&state_lock);
out_fput:
	fput(filp);
	return status;
}

static struct nfs4_delegation *
nfs4_set_delegation(struct nfs4_client *clp, struct svc_fh *fh,
		    struct nfs4_file *fp)
{
	int status;
	struct nfs4_delegation *dp;

	if (fp->fi_had_conflict)
		return ERR_PTR(-EAGAIN);

	dp = alloc_init_deleg(clp, fh);
	if (!dp)
		return ERR_PTR(-ENOMEM);

	get_nfs4_file(fp);
	spin_lock(&state_lock);
	spin_lock(&fp->fi_lock);
	dp->dl_stid.sc_file = fp;
	if (!fp->fi_deleg_file) {
		spin_unlock(&fp->fi_lock);
		spin_unlock(&state_lock);
		status = nfs4_setlease(dp);
		goto out;
	}
	if (fp->fi_had_conflict) {
		status = -EAGAIN;
		goto out_unlock;
	}
	++fp->fi_delegees;
	hash_delegation_locked(dp, fp);
	status = 0;
out_unlock:
	spin_unlock(&fp->fi_lock);
	spin_unlock(&state_lock);
out:
	if (status) {
		nfs4_put_stid(&dp->dl_stid);
		return ERR_PTR(status);
	}
	return dp;
}

static void nfsd4_open_deleg_none_ext(struct nfsd4_open *open, int status)
{
	open->op_delegate_type = NFS4_OPEN_DELEGATE_NONE_EXT;
	if (status == -EAGAIN)
		open->op_why_no_deleg = WND4_CONTENTION;
	else {
		open->op_why_no_deleg = WND4_RESOURCE;
		switch (open->op_deleg_want) {
		case NFS4_SHARE_WANT_READ_DELEG:
		case NFS4_SHARE_WANT_WRITE_DELEG:
		case NFS4_SHARE_WANT_ANY_DELEG:
			break;
		case NFS4_SHARE_WANT_CANCEL:
			open->op_why_no_deleg = WND4_CANCELLED;
			break;
		case NFS4_SHARE_WANT_NO_DELEG:
			WARN_ON_ONCE(1);
		}
	}
}

/*
 * Attempt to hand out a delegation.
 *
 * Note we don't support write delegations, and won't until the vfs has
 * proper support for them.
 */
static void
nfs4_open_delegation(struct svc_fh *fh, struct nfsd4_open *open,
			struct nfs4_ol_stateid *stp)
{
	struct nfs4_delegation *dp;
	struct nfs4_openowner *oo = openowner(stp->st_stateowner);
	struct nfs4_client *clp = stp->st_stid.sc_client;
	int cb_up;
	int status = 0;

	cb_up = nfsd4_cb_channel_good(oo->oo_owner.so_client);
	open->op_recall = 0;
	switch (open->op_claim_type) {
		case NFS4_OPEN_CLAIM_PREVIOUS:
			if (!cb_up)
				open->op_recall = 1;
			if (open->op_delegate_type != NFS4_OPEN_DELEGATE_READ)
				goto out_no_deleg;
			break;
		case NFS4_OPEN_CLAIM_NULL:
		case NFS4_OPEN_CLAIM_FH:
			/*
			 * Let's not give out any delegations till everyone's
			 * had the chance to reclaim theirs....
			 */
			if (locks_in_grace(clp->net))
				goto out_no_deleg;
			if (!cb_up || !(oo->oo_flags & NFS4_OO_CONFIRMED))
				goto out_no_deleg;
			/*
			 * Also, if the file was opened for write or
			 * create, there's a good chance the client's
			 * about to write to it, resulting in an
			 * immediate recall (since we don't support
			 * write delegations):
			 */
			if (open->op_share_access & NFS4_SHARE_ACCESS_WRITE)
				goto out_no_deleg;
			if (open->op_create == NFS4_OPEN_CREATE)
				goto out_no_deleg;
			break;
		default:
			goto out_no_deleg;
	}
	dp = nfs4_set_delegation(clp, fh, stp->st_stid.sc_file);
	if (IS_ERR(dp))
		goto out_no_deleg;

	memcpy(&open->op_delegate_stateid, &dp->dl_stid.sc_stateid, sizeof(dp->dl_stid.sc_stateid));

	dprintk("NFSD: delegation stateid=" STATEID_FMT "\n",
		STATEID_VAL(&dp->dl_stid.sc_stateid));
	open->op_delegate_type = NFS4_OPEN_DELEGATE_READ;
	nfs4_put_stid(&dp->dl_stid);
	return;
out_no_deleg:
	open->op_delegate_type = NFS4_OPEN_DELEGATE_NONE;
	if (open->op_claim_type == NFS4_OPEN_CLAIM_PREVIOUS &&
	    open->op_delegate_type != NFS4_OPEN_DELEGATE_NONE) {
		dprintk("NFSD: WARNING: refusing delegation reclaim\n");
		open->op_recall = 1;
	}

	/* 4.1 client asking for a delegation? */
	if (open->op_deleg_want)
		nfsd4_open_deleg_none_ext(open, status);
	return;
}

static void nfsd4_deleg_xgrade_none_ext(struct nfsd4_open *open,
					struct nfs4_delegation *dp)
{
	if (open->op_deleg_want == NFS4_SHARE_WANT_READ_DELEG &&
	    dp->dl_type == NFS4_OPEN_DELEGATE_WRITE) {
		open->op_delegate_type = NFS4_OPEN_DELEGATE_NONE_EXT;
		open->op_why_no_deleg = WND4_NOT_SUPP_DOWNGRADE;
	} else if (open->op_deleg_want == NFS4_SHARE_WANT_WRITE_DELEG &&
		   dp->dl_type == NFS4_OPEN_DELEGATE_WRITE) {
		open->op_delegate_type = NFS4_OPEN_DELEGATE_NONE_EXT;
		open->op_why_no_deleg = WND4_NOT_SUPP_UPGRADE;
	}
	/* Otherwise the client must be confused wanting a delegation
	 * it already has, therefore we don't return
	 * NFS4_OPEN_DELEGATE_NONE_EXT and reason.
	 */
}

__be32
nfsd4_process_open2(struct svc_rqst *rqstp, struct svc_fh *current_fh, struct nfsd4_open *open)
{
	struct nfsd4_compoundres *resp = rqstp->rq_resp;
	struct nfs4_client *cl = open->op_openowner->oo_owner.so_client;
	struct nfs4_file *fp = NULL;
	struct nfs4_ol_stateid *stp = NULL;
	struct nfs4_delegation *dp = NULL;
	__be32 status;

	/*
	 * Lookup file; if found, lookup stateid and check open request,
	 * and check for delegations in the process of being recalled.
	 * If not found, create the nfs4_file struct
	 */
	fp = find_or_add_file(open->op_file, &current_fh->fh_handle);
	if (fp != open->op_file) {
		status = nfs4_check_deleg(cl, open, &dp);
		if (status)
			goto out;
		stp = nfsd4_find_existing_open(fp, open);
	} else {
		open->op_file = NULL;
		status = nfserr_bad_stateid;
		if (nfsd4_is_deleg_cur(open))
			goto out;
		status = nfserr_jukebox;
	}

	/*
	 * OPEN the file, or upgrade an existing OPEN.
	 * If truncate fails, the OPEN fails.
	 */
	if (stp) {
		/* Stateid was found, this is an OPEN upgrade */
		status = nfs4_upgrade_open(rqstp, fp, current_fh, stp, open);
		if (status)
			goto out;
	} else {
		stp = open->op_stp;
		open->op_stp = NULL;
		init_open_stateid(stp, fp, open);
		status = nfs4_get_vfs_file(rqstp, fp, current_fh, stp, open);
		if (status) {
			release_open_stateid(stp);
			goto out;
		}
	}
	update_stateid(&stp->st_stid.sc_stateid);
	memcpy(&open->op_stateid, &stp->st_stid.sc_stateid, sizeof(stateid_t));

	if (nfsd4_has_session(&resp->cstate)) {
		if (open->op_deleg_want & NFS4_SHARE_WANT_NO_DELEG) {
			open->op_delegate_type = NFS4_OPEN_DELEGATE_NONE_EXT;
			open->op_why_no_deleg = WND4_NOT_WANTED;
			goto nodeleg;
		}
	}

	/*
	* Attempt to hand out a delegation. No error return, because the
	* OPEN succeeds even if we fail.
	*/
	nfs4_open_delegation(current_fh, open, stp);
nodeleg:
	status = nfs_ok;

	dprintk("%s: stateid=" STATEID_FMT "\n", __func__,
		STATEID_VAL(&stp->st_stid.sc_stateid));
out:
	/* 4.1 client trying to upgrade/downgrade delegation? */
	if (open->op_delegate_type == NFS4_OPEN_DELEGATE_NONE && dp &&
	    open->op_deleg_want)
		nfsd4_deleg_xgrade_none_ext(open, dp);

	if (fp)
		put_nfs4_file(fp);
	if (status == 0 && open->op_claim_type == NFS4_OPEN_CLAIM_PREVIOUS)
		nfs4_set_claim_prev(open, nfsd4_has_session(&resp->cstate));
	/*
	* To finish the open response, we just need to set the rflags.
	*/
	open->op_rflags = NFS4_OPEN_RESULT_LOCKTYPE_POSIX;
	if (!(open->op_openowner->oo_flags & NFS4_OO_CONFIRMED) &&
	    !nfsd4_has_session(&resp->cstate))
		open->op_rflags |= NFS4_OPEN_RESULT_CONFIRM;
	if (dp)
		nfs4_put_stid(&dp->dl_stid);
	if (stp)
		nfs4_put_stid(&stp->st_stid);

	return status;
}

void nfsd4_cleanup_open_state(struct nfsd4_compound_state *cstate,
			      struct nfsd4_open *open, __be32 status)
{
	if (open->op_openowner) {
		struct nfs4_stateowner *so = &open->op_openowner->oo_owner;

		nfsd4_cstate_assign_replay(cstate, so);
		nfs4_put_stateowner(so);
	}
	if (open->op_file)
		kmem_cache_free(file_slab, open->op_file);
	if (open->op_stp)
		nfs4_put_stid(&open->op_stp->st_stid);
}

__be32
nfsd4_renew(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	    clientid_t *clid)
{
	struct nfs4_client *clp;
	__be32 status;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	dprintk("process_renew(%08x/%08x): starting\n", 
			clid->cl_boot, clid->cl_id);
	status = lookup_clientid(clid, cstate, nn);
	if (status)
		goto out;
	clp = cstate->clp;
	status = nfserr_cb_path_down;
	if (!list_empty(&clp->cl_delegations)
			&& clp->cl_cb_state != NFSD4_CB_UP)
		goto out;
	status = nfs_ok;
out:
	return status;
}

void
nfsd4_end_grace(struct nfsd_net *nn)
{
	/* do nothing if grace period already ended */
	if (nn->grace_ended)
		return;

	dprintk("NFSD: end of grace period\n");
	nn->grace_ended = true;
	/*
	 * If the server goes down again right now, an NFSv4
	 * client will still be allowed to reclaim after it comes back up,
	 * even if it hasn't yet had a chance to reclaim state this time.
	 *
	 */
	nfsd4_record_grace_done(nn);
	/*
	 * At this point, NFSv4 clients can still reclaim.  But if the
	 * server crashes, any that have not yet reclaimed will be out
	 * of luck on the next boot.
	 *
	 * (NFSv4.1+ clients are considered to have reclaimed once they
	 * call RECLAIM_COMPLETE.  NFSv4.0 clients are considered to
	 * have reclaimed after their first OPEN.)
	 */
	locks_end_grace(&nn->nfsd4_manager);
	/*
	 * At this point, and once lockd and/or any other containers
	 * exit their grace period, further reclaims will fail and
	 * regular locking can resume.
	 */
}

static time_t
nfs4_laundromat(struct nfsd_net *nn)
{
	struct nfs4_client *clp;
	struct nfs4_openowner *oo;
	struct nfs4_delegation *dp;
	struct nfs4_ol_stateid *stp;
	struct list_head *pos, *next, reaplist;
	time_t cutoff = get_seconds() - nn->nfsd4_lease;
	time_t t, new_timeo = nn->nfsd4_lease;

	dprintk("NFSD: laundromat service - starting\n");
	nfsd4_end_grace(nn);
	INIT_LIST_HEAD(&reaplist);
	spin_lock(&nn->client_lock);
	list_for_each_safe(pos, next, &nn->client_lru) {
		clp = list_entry(pos, struct nfs4_client, cl_lru);
		if (time_after((unsigned long)clp->cl_time, (unsigned long)cutoff)) {
			t = clp->cl_time - cutoff;
			new_timeo = min(new_timeo, t);
			break;
		}
		if (mark_client_expired_locked(clp)) {
			dprintk("NFSD: client in use (clientid %08x)\n",
				clp->cl_clientid.cl_id);
			continue;
		}
		list_add(&clp->cl_lru, &reaplist);
	}
	spin_unlock(&nn->client_lock);
	list_for_each_safe(pos, next, &reaplist) {
		clp = list_entry(pos, struct nfs4_client, cl_lru);
		dprintk("NFSD: purging unused client (clientid %08x)\n",
			clp->cl_clientid.cl_id);
		list_del_init(&clp->cl_lru);
		expire_client(clp);
	}
	spin_lock(&state_lock);
	list_for_each_safe(pos, next, &nn->del_recall_lru) {
		dp = list_entry (pos, struct nfs4_delegation, dl_recall_lru);
		if (net_generic(dp->dl_stid.sc_client->net, nfsd_net_id) != nn)
			continue;
		if (time_after((unsigned long)dp->dl_time, (unsigned long)cutoff)) {
			t = dp->dl_time - cutoff;
			new_timeo = min(new_timeo, t);
			break;
		}
		unhash_delegation_locked(dp);
		list_add(&dp->dl_recall_lru, &reaplist);
	}
	spin_unlock(&state_lock);
	while (!list_empty(&reaplist)) {
		dp = list_first_entry(&reaplist, struct nfs4_delegation,
					dl_recall_lru);
		list_del_init(&dp->dl_recall_lru);
		revoke_delegation(dp);
	}

	spin_lock(&nn->client_lock);
	while (!list_empty(&nn->close_lru)) {
		oo = list_first_entry(&nn->close_lru, struct nfs4_openowner,
					oo_close_lru);
		if (time_after((unsigned long)oo->oo_time,
			       (unsigned long)cutoff)) {
			t = oo->oo_time - cutoff;
			new_timeo = min(new_timeo, t);
			break;
		}
		list_del_init(&oo->oo_close_lru);
		stp = oo->oo_last_closed_stid;
		oo->oo_last_closed_stid = NULL;
		spin_unlock(&nn->client_lock);
		nfs4_put_stid(&stp->st_stid);
		spin_lock(&nn->client_lock);
	}
	spin_unlock(&nn->client_lock);

	new_timeo = max_t(time_t, new_timeo, NFSD_LAUNDROMAT_MINTIMEOUT);
	return new_timeo;
}

static struct workqueue_struct *laundry_wq;
static void laundromat_main(struct work_struct *);

static void
laundromat_main(struct work_struct *laundry)
{
	time_t t;
	struct delayed_work *dwork = container_of(laundry, struct delayed_work,
						  work);
	struct nfsd_net *nn = container_of(dwork, struct nfsd_net,
					   laundromat_work);

	t = nfs4_laundromat(nn);
	dprintk("NFSD: laundromat_main - sleeping for %ld seconds\n", t);
	queue_delayed_work(laundry_wq, &nn->laundromat_work, t*HZ);
}

static inline __be32 nfs4_check_fh(struct svc_fh *fhp, struct nfs4_ol_stateid *stp)
{
	if (!fh_match(&fhp->fh_handle, &stp->st_stid.sc_file->fi_fhandle))
		return nfserr_bad_stateid;
	return nfs_ok;
}

static inline int
access_permit_read(struct nfs4_ol_stateid *stp)
{
	return test_access(NFS4_SHARE_ACCESS_READ, stp) ||
		test_access(NFS4_SHARE_ACCESS_BOTH, stp) ||
		test_access(NFS4_SHARE_ACCESS_WRITE, stp);
}

static inline int
access_permit_write(struct nfs4_ol_stateid *stp)
{
	return test_access(NFS4_SHARE_ACCESS_WRITE, stp) ||
		test_access(NFS4_SHARE_ACCESS_BOTH, stp);
}

static
__be32 nfs4_check_openmode(struct nfs4_ol_stateid *stp, int flags)
{
        __be32 status = nfserr_openmode;

	/* For lock stateid's, we test the parent open, not the lock: */
	if (stp->st_openstp)
		stp = stp->st_openstp;
	if ((flags & WR_STATE) && !access_permit_write(stp))
                goto out;
	if ((flags & RD_STATE) && !access_permit_read(stp))
                goto out;
	status = nfs_ok;
out:
	return status;
}

static inline __be32
check_special_stateids(struct net *net, svc_fh *current_fh, stateid_t *stateid, int flags)
{
	if (ONE_STATEID(stateid) && (flags & RD_STATE))
		return nfs_ok;
	else if (locks_in_grace(net)) {
		/* Answer in remaining cases depends on existence of
		 * conflicting state; so we must wait out the grace period. */
		return nfserr_grace;
	} else if (flags & WR_STATE)
		return nfs4_share_conflict(current_fh,
				NFS4_SHARE_DENY_WRITE);
	else /* (flags & RD_STATE) && ZERO_STATEID(stateid) */
		return nfs4_share_conflict(current_fh,
				NFS4_SHARE_DENY_READ);
}

/*
 * Allow READ/WRITE during grace period on recovered state only for files
 * that are not able to provide mandatory locking.
 */
static inline int
grace_disallows_io(struct net *net, struct inode *inode)
{
	return locks_in_grace(net) && mandatory_lock(inode);
}

/* Returns true iff a is later than b: */
static bool stateid_generation_after(stateid_t *a, stateid_t *b)
{
	return (s32)(a->si_generation - b->si_generation) > 0;
}

static __be32 check_stateid_generation(stateid_t *in, stateid_t *ref, bool has_session)
{
	/*
	 * When sessions are used the stateid generation number is ignored
	 * when it is zero.
	 */
	if (has_session && in->si_generation == 0)
		return nfs_ok;

	if (in->si_generation == ref->si_generation)
		return nfs_ok;

	/* If the client sends us a stateid from the future, it's buggy: */
	if (stateid_generation_after(in, ref))
		return nfserr_bad_stateid;
	/*
	 * However, we could see a stateid from the past, even from a
	 * non-buggy client.  For example, if the client sends a lock
	 * while some IO is outstanding, the lock may bump si_generation
	 * while the IO is still in flight.  The client could avoid that
	 * situation by waiting for responses on all the IO requests,
	 * but better performance may result in retrying IO that
	 * receives an old_stateid error if requests are rarely
	 * reordered in flight:
	 */
	return nfserr_old_stateid;
}

static __be32 nfsd4_validate_stateid(struct nfs4_client *cl, stateid_t *stateid)
{
	struct nfs4_stid *s;
	struct nfs4_ol_stateid *ols;
	__be32 status = nfserr_bad_stateid;

	if (ZERO_STATEID(stateid) || ONE_STATEID(stateid))
		return status;
	/* Client debugging aid. */
	if (!same_clid(&stateid->si_opaque.so_clid, &cl->cl_clientid)) {
		char addr_str[INET6_ADDRSTRLEN];
		rpc_ntop((struct sockaddr *)&cl->cl_addr, addr_str,
				 sizeof(addr_str));
		pr_warn_ratelimited("NFSD: client %s testing state ID "
					"with incorrect client ID\n", addr_str);
		return status;
	}
	spin_lock(&cl->cl_lock);
	s = find_stateid_locked(cl, stateid);
	if (!s)
		goto out_unlock;
	status = check_stateid_generation(stateid, &s->sc_stateid, 1);
	if (status)
		goto out_unlock;
	switch (s->sc_type) {
	case NFS4_DELEG_STID:
		status = nfs_ok;
		break;
	case NFS4_REVOKED_DELEG_STID:
		status = nfserr_deleg_revoked;
		break;
	case NFS4_OPEN_STID:
	case NFS4_LOCK_STID:
		ols = openlockstateid(s);
		if (ols->st_stateowner->so_is_open_owner
	    			&& !(openowner(ols->st_stateowner)->oo_flags
						& NFS4_OO_CONFIRMED))
			status = nfserr_bad_stateid;
		else
			status = nfs_ok;
		break;
	default:
		printk("unknown stateid type %x\n", s->sc_type);
		/* Fallthrough */
	case NFS4_CLOSED_STID:
	case NFS4_CLOSED_DELEG_STID:
		status = nfserr_bad_stateid;
	}
out_unlock:
	spin_unlock(&cl->cl_lock);
	return status;
}

__be32
nfsd4_lookup_stateid(struct nfsd4_compound_state *cstate,
		     stateid_t *stateid, unsigned char typemask,
		     struct nfs4_stid **s, struct nfsd_net *nn)
{
	__be32 status;

	if (ZERO_STATEID(stateid) || ONE_STATEID(stateid))
		return nfserr_bad_stateid;
	status = lookup_clientid(&stateid->si_opaque.so_clid, cstate, nn);
	if (status == nfserr_stale_clientid) {
		if (cstate->session)
			return nfserr_bad_stateid;
		return nfserr_stale_stateid;
	}
	if (status)
		return status;
	*s = find_stateid_by_type(cstate->clp, stateid, typemask);
	if (!*s)
		return nfserr_bad_stateid;
	return nfs_ok;
}

/*
* Checks for stateid operations
*/
__be32
nfs4_preprocess_stateid_op(struct net *net, struct nfsd4_compound_state *cstate,
			   stateid_t *stateid, int flags, struct file **filpp)
{
	struct nfs4_stid *s;
	struct nfs4_ol_stateid *stp = NULL;
	struct nfs4_delegation *dp = NULL;
	struct svc_fh *current_fh = &cstate->current_fh;
	struct inode *ino = current_fh->fh_dentry->d_inode;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	struct file *file = NULL;
	__be32 status;

	if (filpp)
		*filpp = NULL;

	if (grace_disallows_io(net, ino))
		return nfserr_grace;

	if (ZERO_STATEID(stateid) || ONE_STATEID(stateid))
		return check_special_stateids(net, current_fh, stateid, flags);

	status = nfsd4_lookup_stateid(cstate, stateid,
				NFS4_DELEG_STID|NFS4_OPEN_STID|NFS4_LOCK_STID,
				&s, nn);
	if (status)
		return status;
	status = check_stateid_generation(stateid, &s->sc_stateid, nfsd4_has_session(cstate));
	if (status)
		goto out;
	switch (s->sc_type) {
	case NFS4_DELEG_STID:
		dp = delegstateid(s);
		status = nfs4_check_delegmode(dp, flags);
		if (status)
			goto out;
		if (filpp) {
			file = dp->dl_stid.sc_file->fi_deleg_file;
			if (!file) {
				WARN_ON_ONCE(1);
				status = nfserr_serverfault;
				goto out;
			}
			get_file(file);
		}
		break;
	case NFS4_OPEN_STID:
	case NFS4_LOCK_STID:
		stp = openlockstateid(s);
		status = nfs4_check_fh(current_fh, stp);
		if (status)
			goto out;
		if (stp->st_stateowner->so_is_open_owner
		    && !(openowner(stp->st_stateowner)->oo_flags & NFS4_OO_CONFIRMED))
			goto out;
		status = nfs4_check_openmode(stp, flags);
		if (status)
			goto out;
		if (filpp) {
			struct nfs4_file *fp = stp->st_stid.sc_file;

			if (flags & RD_STATE)
				file = find_readable_file(fp);
			else
				file = find_writeable_file(fp);
		}
		break;
	default:
		status = nfserr_bad_stateid;
		goto out;
	}
	status = nfs_ok;
	if (file)
		*filpp = file;
out:
	nfs4_put_stid(s);
	return status;
}

/*
 * Test if the stateid is valid
 */
__be32
nfsd4_test_stateid(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		   struct nfsd4_test_stateid *test_stateid)
{
	struct nfsd4_test_stateid_id *stateid;
	struct nfs4_client *cl = cstate->session->se_client;

	list_for_each_entry(stateid, &test_stateid->ts_stateid_list, ts_id_list)
		stateid->ts_id_status =
			nfsd4_validate_stateid(cl, &stateid->ts_id_stateid);

	return nfs_ok;
}

__be32
nfsd4_free_stateid(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		   struct nfsd4_free_stateid *free_stateid)
{
	stateid_t *stateid = &free_stateid->fr_stateid;
	struct nfs4_stid *s;
	struct nfs4_delegation *dp;
	struct nfs4_ol_stateid *stp;
	struct nfs4_client *cl = cstate->session->se_client;
	__be32 ret = nfserr_bad_stateid;

	spin_lock(&cl->cl_lock);
	s = find_stateid_locked(cl, stateid);
	if (!s)
		goto out_unlock;
	switch (s->sc_type) {
	case NFS4_DELEG_STID:
		ret = nfserr_locks_held;
		break;
	case NFS4_OPEN_STID:
		ret = check_stateid_generation(stateid, &s->sc_stateid, 1);
		if (ret)
			break;
		ret = nfserr_locks_held;
		break;
	case NFS4_LOCK_STID:
		ret = check_stateid_generation(stateid, &s->sc_stateid, 1);
		if (ret)
			break;
		stp = openlockstateid(s);
		ret = nfserr_locks_held;
		if (check_for_locks(stp->st_stid.sc_file,
				    lockowner(stp->st_stateowner)))
			break;
		unhash_lock_stateid(stp);
		spin_unlock(&cl->cl_lock);
		nfs4_put_stid(s);
		ret = nfs_ok;
		goto out;
	case NFS4_REVOKED_DELEG_STID:
		dp = delegstateid(s);
		list_del_init(&dp->dl_recall_lru);
		spin_unlock(&cl->cl_lock);
		nfs4_put_stid(s);
		ret = nfs_ok;
		goto out;
	/* Default falls through and returns nfserr_bad_stateid */
	}
out_unlock:
	spin_unlock(&cl->cl_lock);
out:
	return ret;
}

static inline int
setlkflg (int type)
{
	return (type == NFS4_READW_LT || type == NFS4_READ_LT) ?
		RD_STATE : WR_STATE;
}

static __be32 nfs4_seqid_op_checks(struct nfsd4_compound_state *cstate, stateid_t *stateid, u32 seqid, struct nfs4_ol_stateid *stp)
{
	struct svc_fh *current_fh = &cstate->current_fh;
	struct nfs4_stateowner *sop = stp->st_stateowner;
	__be32 status;

	status = nfsd4_check_seqid(cstate, sop, seqid);
	if (status)
		return status;
	if (stp->st_stid.sc_type == NFS4_CLOSED_STID
		|| stp->st_stid.sc_type == NFS4_REVOKED_DELEG_STID)
		/*
		 * "Closed" stateid's exist *only* to return
		 * nfserr_replay_me from the previous step, and
		 * revoked delegations are kept only for free_stateid.
		 */
		return nfserr_bad_stateid;
	status = check_stateid_generation(stateid, &stp->st_stid.sc_stateid, nfsd4_has_session(cstate));
	if (status)
		return status;
	return nfs4_check_fh(current_fh, stp);
}

/* 
 * Checks for sequence id mutating operations. 
 */
static __be32
nfs4_preprocess_seqid_op(struct nfsd4_compound_state *cstate, u32 seqid,
			 stateid_t *stateid, char typemask,
			 struct nfs4_ol_stateid **stpp,
			 struct nfsd_net *nn)
{
	__be32 status;
	struct nfs4_stid *s;
	struct nfs4_ol_stateid *stp = NULL;

	dprintk("NFSD: %s: seqid=%d stateid = " STATEID_FMT "\n", __func__,
		seqid, STATEID_VAL(stateid));

	*stpp = NULL;
	status = nfsd4_lookup_stateid(cstate, stateid, typemask, &s, nn);
	if (status)
		return status;
	stp = openlockstateid(s);
	nfsd4_cstate_assign_replay(cstate, stp->st_stateowner);

	status = nfs4_seqid_op_checks(cstate, stateid, seqid, stp);
	if (!status)
		*stpp = stp;
	else
		nfs4_put_stid(&stp->st_stid);
	return status;
}

static __be32 nfs4_preprocess_confirmed_seqid_op(struct nfsd4_compound_state *cstate, u32 seqid,
						 stateid_t *stateid, struct nfs4_ol_stateid **stpp, struct nfsd_net *nn)
{
	__be32 status;
	struct nfs4_openowner *oo;
	struct nfs4_ol_stateid *stp;

	status = nfs4_preprocess_seqid_op(cstate, seqid, stateid,
						NFS4_OPEN_STID, &stp, nn);
	if (status)
		return status;
	oo = openowner(stp->st_stateowner);
	if (!(oo->oo_flags & NFS4_OO_CONFIRMED)) {
		nfs4_put_stid(&stp->st_stid);
		return nfserr_bad_stateid;
	}
	*stpp = stp;
	return nfs_ok;
}

__be32
nfsd4_open_confirm(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		   struct nfsd4_open_confirm *oc)
{
	__be32 status;
	struct nfs4_openowner *oo;
	struct nfs4_ol_stateid *stp;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	dprintk("NFSD: nfsd4_open_confirm on file %pd\n",
			cstate->current_fh.fh_dentry);

	status = fh_verify(rqstp, &cstate->current_fh, S_IFREG, 0);
	if (status)
		return status;

	status = nfs4_preprocess_seqid_op(cstate,
					oc->oc_seqid, &oc->oc_req_stateid,
					NFS4_OPEN_STID, &stp, nn);
	if (status)
		goto out;
	oo = openowner(stp->st_stateowner);
	status = nfserr_bad_stateid;
	if (oo->oo_flags & NFS4_OO_CONFIRMED)
		goto put_stateid;
	oo->oo_flags |= NFS4_OO_CONFIRMED;
	update_stateid(&stp->st_stid.sc_stateid);
	memcpy(&oc->oc_resp_stateid, &stp->st_stid.sc_stateid, sizeof(stateid_t));
	dprintk("NFSD: %s: success, seqid=%d stateid=" STATEID_FMT "\n",
		__func__, oc->oc_seqid, STATEID_VAL(&stp->st_stid.sc_stateid));

	nfsd4_client_record_create(oo->oo_owner.so_client);
	status = nfs_ok;
put_stateid:
	nfs4_put_stid(&stp->st_stid);
out:
	nfsd4_bump_seqid(cstate, status);
	return status;
}

static inline void nfs4_stateid_downgrade_bit(struct nfs4_ol_stateid *stp, u32 access)
{
	if (!test_access(access, stp))
		return;
	nfs4_file_put_access(stp->st_stid.sc_file, access);
	clear_access(access, stp);
}

static inline void nfs4_stateid_downgrade(struct nfs4_ol_stateid *stp, u32 to_access)
{
	switch (to_access) {
	case NFS4_SHARE_ACCESS_READ:
		nfs4_stateid_downgrade_bit(stp, NFS4_SHARE_ACCESS_WRITE);
		nfs4_stateid_downgrade_bit(stp, NFS4_SHARE_ACCESS_BOTH);
		break;
	case NFS4_SHARE_ACCESS_WRITE:
		nfs4_stateid_downgrade_bit(stp, NFS4_SHARE_ACCESS_READ);
		nfs4_stateid_downgrade_bit(stp, NFS4_SHARE_ACCESS_BOTH);
		break;
	case NFS4_SHARE_ACCESS_BOTH:
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

__be32
nfsd4_open_downgrade(struct svc_rqst *rqstp,
		     struct nfsd4_compound_state *cstate,
		     struct nfsd4_open_downgrade *od)
{
	__be32 status;
	struct nfs4_ol_stateid *stp;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	dprintk("NFSD: nfsd4_open_downgrade on file %pd\n", 
			cstate->current_fh.fh_dentry);

	/* We don't yet support WANT bits: */
	if (od->od_deleg_want)
		dprintk("NFSD: %s: od_deleg_want=0x%x ignored\n", __func__,
			od->od_deleg_want);

	status = nfs4_preprocess_confirmed_seqid_op(cstate, od->od_seqid,
					&od->od_stateid, &stp, nn);
	if (status)
		goto out; 
	status = nfserr_inval;
	if (!test_access(od->od_share_access, stp)) {
		dprintk("NFSD: access not a subset of current bitmap: 0x%hhx, input access=%08x\n",
			stp->st_access_bmap, od->od_share_access);
		goto put_stateid;
	}
	if (!test_deny(od->od_share_deny, stp)) {
		dprintk("NFSD: deny not a subset of current bitmap: 0x%hhx, input deny=%08x\n",
			stp->st_deny_bmap, od->od_share_deny);
		goto put_stateid;
	}
	nfs4_stateid_downgrade(stp, od->od_share_access);

	reset_union_bmap_deny(od->od_share_deny, stp);

	update_stateid(&stp->st_stid.sc_stateid);
	memcpy(&od->od_stateid, &stp->st_stid.sc_stateid, sizeof(stateid_t));
	status = nfs_ok;
put_stateid:
	nfs4_put_stid(&stp->st_stid);
out:
	nfsd4_bump_seqid(cstate, status);
	return status;
}

static void nfsd4_close_open_stateid(struct nfs4_ol_stateid *s)
{
	struct nfs4_client *clp = s->st_stid.sc_client;
	LIST_HEAD(reaplist);

	s->st_stid.sc_type = NFS4_CLOSED_STID;
	spin_lock(&clp->cl_lock);
	unhash_open_stateid(s, &reaplist);

	if (clp->cl_minorversion) {
		put_ol_stateid_locked(s, &reaplist);
		spin_unlock(&clp->cl_lock);
		free_ol_stateid_reaplist(&reaplist);
	} else {
		spin_unlock(&clp->cl_lock);
		free_ol_stateid_reaplist(&reaplist);
		move_to_close_lru(s, clp->net);
	}
}

/*
 * nfs4_unlock_state() called after encode
 */
__be32
nfsd4_close(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	    struct nfsd4_close *close)
{
	__be32 status;
	struct nfs4_ol_stateid *stp;
	struct net *net = SVC_NET(rqstp);
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	dprintk("NFSD: nfsd4_close on file %pd\n", 
			cstate->current_fh.fh_dentry);

	status = nfs4_preprocess_seqid_op(cstate, close->cl_seqid,
					&close->cl_stateid,
					NFS4_OPEN_STID|NFS4_CLOSED_STID,
					&stp, nn);
	nfsd4_bump_seqid(cstate, status);
	if (status)
		goto out; 
	update_stateid(&stp->st_stid.sc_stateid);
	memcpy(&close->cl_stateid, &stp->st_stid.sc_stateid, sizeof(stateid_t));

	nfsd4_return_all_file_layouts(stp->st_stateowner->so_client,
				      stp->st_stid.sc_file);

	nfsd4_close_open_stateid(stp);

	/* put reference from nfs4_preprocess_seqid_op */
	nfs4_put_stid(&stp->st_stid);
out:
	return status;
}

__be32
nfsd4_delegreturn(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
		  struct nfsd4_delegreturn *dr)
{
	struct nfs4_delegation *dp;
	stateid_t *stateid = &dr->dr_stateid;
	struct nfs4_stid *s;
	__be32 status;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	if ((status = fh_verify(rqstp, &cstate->current_fh, S_IFREG, 0)))
		return status;

	status = nfsd4_lookup_stateid(cstate, stateid, NFS4_DELEG_STID, &s, nn);
	if (status)
		goto out;
	dp = delegstateid(s);
	status = check_stateid_generation(stateid, &dp->dl_stid.sc_stateid, nfsd4_has_session(cstate));
	if (status)
		goto put_stateid;

	destroy_delegation(dp);
put_stateid:
	nfs4_put_stid(&dp->dl_stid);
out:
	return status;
}


#define LOFF_OVERFLOW(start, len)      ((u64)(len) > ~(u64)(start))

static inline u64
end_offset(u64 start, u64 len)
{
	u64 end;

	end = start + len;
	return end >= start ? end: NFS4_MAX_UINT64;
}

/* last octet in a range */
static inline u64
last_byte_offset(u64 start, u64 len)
{
	u64 end;

	WARN_ON_ONCE(!len);
	end = start + len;
	return end > start ? end - 1: NFS4_MAX_UINT64;
}

/*
 * TODO: Linux file offsets are _signed_ 64-bit quantities, which means that
 * we can't properly handle lock requests that go beyond the (2^63 - 1)-th
 * byte, because of sign extension problems.  Since NFSv4 calls for 64-bit
 * locking, this prevents us from being completely protocol-compliant.  The
 * real solution to this problem is to start using unsigned file offsets in
 * the VFS, but this is a very deep change!
 */
static inline void
nfs4_transform_lock_offset(struct file_lock *lock)
{
	if (lock->fl_start < 0)
		lock->fl_start = OFFSET_MAX;
	if (lock->fl_end < 0)
		lock->fl_end = OFFSET_MAX;
}

static void nfsd4_fl_get_owner(struct file_lock *dst, struct file_lock *src)
{
	struct nfs4_lockowner *lo = (struct nfs4_lockowner *)src->fl_owner;
	dst->fl_owner = (fl_owner_t)lockowner(nfs4_get_stateowner(&lo->lo_owner));
}

static void nfsd4_fl_put_owner(struct file_lock *fl)
{
	struct nfs4_lockowner *lo = (struct nfs4_lockowner *)fl->fl_owner;

	if (lo) {
		nfs4_put_stateowner(&lo->lo_owner);
		fl->fl_owner = NULL;
	}
}

static const struct lock_manager_operations nfsd_posix_mng_ops  = {
	.lm_get_owner = nfsd4_fl_get_owner,
	.lm_put_owner = nfsd4_fl_put_owner,
};

static inline void
nfs4_set_lock_denied(struct file_lock *fl, struct nfsd4_lock_denied *deny)
{
	struct nfs4_lockowner *lo;

	if (fl->fl_lmops == &nfsd_posix_mng_ops) {
		lo = (struct nfs4_lockowner *) fl->fl_owner;
		deny->ld_owner.data = kmemdup(lo->lo_owner.so_owner.data,
					lo->lo_owner.so_owner.len, GFP_KERNEL);
		if (!deny->ld_owner.data)
			/* We just don't care that much */
			goto nevermind;
		deny->ld_owner.len = lo->lo_owner.so_owner.len;
		deny->ld_clientid = lo->lo_owner.so_client->cl_clientid;
	} else {
nevermind:
		deny->ld_owner.len = 0;
		deny->ld_owner.data = NULL;
		deny->ld_clientid.cl_boot = 0;
		deny->ld_clientid.cl_id = 0;
	}
	deny->ld_start = fl->fl_start;
	deny->ld_length = NFS4_MAX_UINT64;
	if (fl->fl_end != NFS4_MAX_UINT64)
		deny->ld_length = fl->fl_end - fl->fl_start + 1;        
	deny->ld_type = NFS4_READ_LT;
	if (fl->fl_type != F_RDLCK)
		deny->ld_type = NFS4_WRITE_LT;
}

static struct nfs4_lockowner *
find_lockowner_str_locked(clientid_t *clid, struct xdr_netobj *owner,
		struct nfs4_client *clp)
{
	unsigned int strhashval = ownerstr_hashval(owner);
	struct nfs4_stateowner *so;

	lockdep_assert_held(&clp->cl_lock);

	list_for_each_entry(so, &clp->cl_ownerstr_hashtbl[strhashval],
			    so_strhash) {
		if (so->so_is_open_owner)
			continue;
		if (same_owner_str(so, owner))
			return lockowner(nfs4_get_stateowner(so));
	}
	return NULL;
}

static struct nfs4_lockowner *
find_lockowner_str(clientid_t *clid, struct xdr_netobj *owner,
		struct nfs4_client *clp)
{
	struct nfs4_lockowner *lo;

	spin_lock(&clp->cl_lock);
	lo = find_lockowner_str_locked(clid, owner, clp);
	spin_unlock(&clp->cl_lock);
	return lo;
}

static void nfs4_unhash_lockowner(struct nfs4_stateowner *sop)
{
	unhash_lockowner_locked(lockowner(sop));
}

static void nfs4_free_lockowner(struct nfs4_stateowner *sop)
{
	struct nfs4_lockowner *lo = lockowner(sop);

	kmem_cache_free(lockowner_slab, lo);
}

static const struct nfs4_stateowner_operations lockowner_ops = {
	.so_unhash =	nfs4_unhash_lockowner,
	.so_free =	nfs4_free_lockowner,
};

/*
 * Alloc a lock owner structure.
 * Called in nfsd4_lock - therefore, OPEN and OPEN_CONFIRM (if needed) has 
 * occurred. 
 *
 * strhashval = ownerstr_hashval
 */
static struct nfs4_lockowner *
alloc_init_lock_stateowner(unsigned int strhashval, struct nfs4_client *clp,
			   struct nfs4_ol_stateid *open_stp,
			   struct nfsd4_lock *lock)
{
	struct nfs4_lockowner *lo, *ret;

	lo = alloc_stateowner(lockowner_slab, &lock->lk_new_owner, clp);
	if (!lo)
		return NULL;
	INIT_LIST_HEAD(&lo->lo_owner.so_stateids);
	lo->lo_owner.so_is_open_owner = 0;
	lo->lo_owner.so_seqid = lock->lk_new_lock_seqid;
	lo->lo_owner.so_ops = &lockowner_ops;
	spin_lock(&clp->cl_lock);
	ret = find_lockowner_str_locked(&clp->cl_clientid,
			&lock->lk_new_owner, clp);
	if (ret == NULL) {
		list_add(&lo->lo_owner.so_strhash,
			 &clp->cl_ownerstr_hashtbl[strhashval]);
		ret = lo;
	} else
		nfs4_free_lockowner(&lo->lo_owner);
	spin_unlock(&clp->cl_lock);
	return lo;
}

static void
init_lock_stateid(struct nfs4_ol_stateid *stp, struct nfs4_lockowner *lo,
		  struct nfs4_file *fp, struct inode *inode,
		  struct nfs4_ol_stateid *open_stp)
{
	struct nfs4_client *clp = lo->lo_owner.so_client;

	lockdep_assert_held(&clp->cl_lock);

	atomic_inc(&stp->st_stid.sc_count);
	stp->st_stid.sc_type = NFS4_LOCK_STID;
	stp->st_stateowner = nfs4_get_stateowner(&lo->lo_owner);
	get_nfs4_file(fp);
	stp->st_stid.sc_file = fp;
	stp->st_stid.sc_free = nfs4_free_lock_stateid;
	stp->st_access_bmap = 0;
	stp->st_deny_bmap = open_stp->st_deny_bmap;
	stp->st_openstp = open_stp;
	list_add(&stp->st_locks, &open_stp->st_locks);
	list_add(&stp->st_perstateowner, &lo->lo_owner.so_stateids);
	spin_lock(&fp->fi_lock);
	list_add(&stp->st_perfile, &fp->fi_stateids);
	spin_unlock(&fp->fi_lock);
}

static struct nfs4_ol_stateid *
find_lock_stateid(struct nfs4_lockowner *lo, struct nfs4_file *fp)
{
	struct nfs4_ol_stateid *lst;
	struct nfs4_client *clp = lo->lo_owner.so_client;

	lockdep_assert_held(&clp->cl_lock);

	list_for_each_entry(lst, &lo->lo_owner.so_stateids, st_perstateowner) {
		if (lst->st_stid.sc_file == fp) {
			atomic_inc(&lst->st_stid.sc_count);
			return lst;
		}
	}
	return NULL;
}

static struct nfs4_ol_stateid *
find_or_create_lock_stateid(struct nfs4_lockowner *lo, struct nfs4_file *fi,
			    struct inode *inode, struct nfs4_ol_stateid *ost,
			    bool *new)
{
	struct nfs4_stid *ns = NULL;
	struct nfs4_ol_stateid *lst;
	struct nfs4_openowner *oo = openowner(ost->st_stateowner);
	struct nfs4_client *clp = oo->oo_owner.so_client;

	spin_lock(&clp->cl_lock);
	lst = find_lock_stateid(lo, fi);
	if (lst == NULL) {
		spin_unlock(&clp->cl_lock);
		ns = nfs4_alloc_stid(clp, stateid_slab);
		if (ns == NULL)
			return NULL;

		spin_lock(&clp->cl_lock);
		lst = find_lock_stateid(lo, fi);
		if (likely(!lst)) {
			lst = openlockstateid(ns);
			init_lock_stateid(lst, lo, fi, inode, ost);
			ns = NULL;
			*new = true;
		}
	}
	spin_unlock(&clp->cl_lock);
	if (ns)
		nfs4_put_stid(ns);
	return lst;
}

static int
check_lock_length(u64 offset, u64 length)
{
	return ((length == 0)  || ((length != NFS4_MAX_UINT64) &&
	     LOFF_OVERFLOW(offset, length)));
}

static void get_lock_access(struct nfs4_ol_stateid *lock_stp, u32 access)
{
	struct nfs4_file *fp = lock_stp->st_stid.sc_file;

	lockdep_assert_held(&fp->fi_lock);

	if (test_access(access, lock_stp))
		return;
	__nfs4_file_get_access(fp, access);
	set_access(access, lock_stp);
}

static __be32
lookup_or_create_lock_state(struct nfsd4_compound_state *cstate,
			    struct nfs4_ol_stateid *ost,
			    struct nfsd4_lock *lock,
			    struct nfs4_ol_stateid **lst, bool *new)
{
	__be32 status;
	struct nfs4_file *fi = ost->st_stid.sc_file;
	struct nfs4_openowner *oo = openowner(ost->st_stateowner);
	struct nfs4_client *cl = oo->oo_owner.so_client;
	struct inode *inode = cstate->current_fh.fh_dentry->d_inode;
	struct nfs4_lockowner *lo;
	unsigned int strhashval;

	lo = find_lockowner_str(&cl->cl_clientid, &lock->v.new.owner, cl);
	if (!lo) {
		strhashval = ownerstr_hashval(&lock->v.new.owner);
		lo = alloc_init_lock_stateowner(strhashval, cl, ost, lock);
		if (lo == NULL)
			return nfserr_jukebox;
	} else {
		/* with an existing lockowner, seqids must be the same */
		status = nfserr_bad_seqid;
		if (!cstate->minorversion &&
		    lock->lk_new_lock_seqid != lo->lo_owner.so_seqid)
			goto out;
	}

	*lst = find_or_create_lock_stateid(lo, fi, inode, ost, new);
	if (*lst == NULL) {
		status = nfserr_jukebox;
		goto out;
	}
	status = nfs_ok;
out:
	nfs4_put_stateowner(&lo->lo_owner);
	return status;
}

/*
 *  LOCK operation 
 */
__be32
nfsd4_lock(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	   struct nfsd4_lock *lock)
{
	struct nfs4_openowner *open_sop = NULL;
	struct nfs4_lockowner *lock_sop = NULL;
	struct nfs4_ol_stateid *lock_stp = NULL;
	struct nfs4_ol_stateid *open_stp = NULL;
	struct nfs4_file *fp;
	struct file *filp = NULL;
	struct file_lock *file_lock = NULL;
	struct file_lock *conflock = NULL;
	__be32 status = 0;
	int lkflg;
	int err;
	bool new = false;
	struct net *net = SVC_NET(rqstp);
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	dprintk("NFSD: nfsd4_lock: start=%Ld length=%Ld\n",
		(long long) lock->lk_offset,
		(long long) lock->lk_length);

	if (check_lock_length(lock->lk_offset, lock->lk_length))
		 return nfserr_inval;

	if ((status = fh_verify(rqstp, &cstate->current_fh,
				S_IFREG, NFSD_MAY_LOCK))) {
		dprintk("NFSD: nfsd4_lock: permission denied!\n");
		return status;
	}

	if (lock->lk_is_new) {
		if (nfsd4_has_session(cstate))
			/* See rfc 5661 18.10.3: given clientid is ignored: */
			memcpy(&lock->v.new.clientid,
				&cstate->session->se_client->cl_clientid,
				sizeof(clientid_t));

		status = nfserr_stale_clientid;
		if (STALE_CLIENTID(&lock->lk_new_clientid, nn))
			goto out;

		/* validate and update open stateid and open seqid */
		status = nfs4_preprocess_confirmed_seqid_op(cstate,
				        lock->lk_new_open_seqid,
		                        &lock->lk_new_open_stateid,
					&open_stp, nn);
		if (status)
			goto out;
		open_sop = openowner(open_stp->st_stateowner);
		status = nfserr_bad_stateid;
		if (!same_clid(&open_sop->oo_owner.so_client->cl_clientid,
						&lock->v.new.clientid))
			goto out;
		status = lookup_or_create_lock_state(cstate, open_stp, lock,
							&lock_stp, &new);
	} else {
		status = nfs4_preprocess_seqid_op(cstate,
				       lock->lk_old_lock_seqid,
				       &lock->lk_old_lock_stateid,
				       NFS4_LOCK_STID, &lock_stp, nn);
	}
	if (status)
		goto out;
	lock_sop = lockowner(lock_stp->st_stateowner);

	lkflg = setlkflg(lock->lk_type);
	status = nfs4_check_openmode(lock_stp, lkflg);
	if (status)
		goto out;

	status = nfserr_grace;
	if (locks_in_grace(net) && !lock->lk_reclaim)
		goto out;
	status = nfserr_no_grace;
	if (!locks_in_grace(net) && lock->lk_reclaim)
		goto out;

	file_lock = locks_alloc_lock();
	if (!file_lock) {
		dprintk("NFSD: %s: unable to allocate lock!\n", __func__);
		status = nfserr_jukebox;
		goto out;
	}

	fp = lock_stp->st_stid.sc_file;
	switch (lock->lk_type) {
		case NFS4_READ_LT:
		case NFS4_READW_LT:
			spin_lock(&fp->fi_lock);
			filp = find_readable_file_locked(fp);
			if (filp)
				get_lock_access(lock_stp, NFS4_SHARE_ACCESS_READ);
			spin_unlock(&fp->fi_lock);
			file_lock->fl_type = F_RDLCK;
			break;
		case NFS4_WRITE_LT:
		case NFS4_WRITEW_LT:
			spin_lock(&fp->fi_lock);
			filp = find_writeable_file_locked(fp);
			if (filp)
				get_lock_access(lock_stp, NFS4_SHARE_ACCESS_WRITE);
			spin_unlock(&fp->fi_lock);
			file_lock->fl_type = F_WRLCK;
			break;
		default:
			status = nfserr_inval;
		goto out;
	}
	if (!filp) {
		status = nfserr_openmode;
		goto out;
	}

	file_lock->fl_owner = (fl_owner_t)lockowner(nfs4_get_stateowner(&lock_sop->lo_owner));
	file_lock->fl_pid = current->tgid;
	file_lock->fl_file = filp;
	file_lock->fl_flags = FL_POSIX;
	file_lock->fl_lmops = &nfsd_posix_mng_ops;
	file_lock->fl_start = lock->lk_offset;
	file_lock->fl_end = last_byte_offset(lock->lk_offset, lock->lk_length);
	nfs4_transform_lock_offset(file_lock);

	conflock = locks_alloc_lock();
	if (!conflock) {
		dprintk("NFSD: %s: unable to allocate lock!\n", __func__);
		status = nfserr_jukebox;
		goto out;
	}

	err = vfs_lock_file(filp, F_SETLK, file_lock, conflock);
	switch (-err) {
	case 0: /* success! */
		update_stateid(&lock_stp->st_stid.sc_stateid);
		memcpy(&lock->lk_resp_stateid, &lock_stp->st_stid.sc_stateid, 
				sizeof(stateid_t));
		status = 0;
		break;
	case (EAGAIN):		/* conflock holds conflicting lock */
		status = nfserr_denied;
		dprintk("NFSD: nfsd4_lock: conflicting lock found!\n");
		nfs4_set_lock_denied(conflock, &lock->lk_denied);
		break;
	case (EDEADLK):
		status = nfserr_deadlock;
		break;
	default:
		dprintk("NFSD: nfsd4_lock: vfs_lock_file() failed! status %d\n",err);
		status = nfserrno(err);
		break;
	}
out:
	if (filp)
		fput(filp);
	if (lock_stp) {
		/* Bump seqid manually if the 4.0 replay owner is openowner */
		if (cstate->replay_owner &&
		    cstate->replay_owner != &lock_sop->lo_owner &&
		    seqid_mutating_err(ntohl(status)))
			lock_sop->lo_owner.so_seqid++;

		/*
		 * If this is a new, never-before-used stateid, and we are
		 * returning an error, then just go ahead and release it.
		 */
		if (status && new)
			release_lock_stateid(lock_stp);

		nfs4_put_stid(&lock_stp->st_stid);
	}
	if (open_stp)
		nfs4_put_stid(&open_stp->st_stid);
	nfsd4_bump_seqid(cstate, status);
	if (file_lock)
		locks_free_lock(file_lock);
	if (conflock)
		locks_free_lock(conflock);
	return status;
}

/*
 * The NFSv4 spec allows a client to do a LOCKT without holding an OPEN,
 * so we do a temporary open here just to get an open file to pass to
 * vfs_test_lock.  (Arguably perhaps test_lock should be done with an
 * inode operation.)
 */
static __be32 nfsd_test_lock(struct svc_rqst *rqstp, struct svc_fh *fhp, struct file_lock *lock)
{
	struct file *file;
	__be32 err = nfsd_open(rqstp, fhp, S_IFREG, NFSD_MAY_READ, &file);
	if (!err) {
		err = nfserrno(vfs_test_lock(file, lock));
		nfsd_close(file);
	}
	return err;
}

/*
 * LOCKT operation
 */
__be32
nfsd4_lockt(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	    struct nfsd4_lockt *lockt)
{
	struct file_lock *file_lock = NULL;
	struct nfs4_lockowner *lo = NULL;
	__be32 status;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	if (locks_in_grace(SVC_NET(rqstp)))
		return nfserr_grace;

	if (check_lock_length(lockt->lt_offset, lockt->lt_length))
		 return nfserr_inval;

	if (!nfsd4_has_session(cstate)) {
		status = lookup_clientid(&lockt->lt_clientid, cstate, nn);
		if (status)
			goto out;
	}

	if ((status = fh_verify(rqstp, &cstate->current_fh, S_IFREG, 0)))
		goto out;

	file_lock = locks_alloc_lock();
	if (!file_lock) {
		dprintk("NFSD: %s: unable to allocate lock!\n", __func__);
		status = nfserr_jukebox;
		goto out;
	}

	switch (lockt->lt_type) {
		case NFS4_READ_LT:
		case NFS4_READW_LT:
			file_lock->fl_type = F_RDLCK;
		break;
		case NFS4_WRITE_LT:
		case NFS4_WRITEW_LT:
			file_lock->fl_type = F_WRLCK;
		break;
		default:
			dprintk("NFSD: nfs4_lockt: bad lock type!\n");
			status = nfserr_inval;
		goto out;
	}

	lo = find_lockowner_str(&lockt->lt_clientid, &lockt->lt_owner,
				cstate->clp);
	if (lo)
		file_lock->fl_owner = (fl_owner_t)lo;
	file_lock->fl_pid = current->tgid;
	file_lock->fl_flags = FL_POSIX;

	file_lock->fl_start = lockt->lt_offset;
	file_lock->fl_end = last_byte_offset(lockt->lt_offset, lockt->lt_length);

	nfs4_transform_lock_offset(file_lock);

	status = nfsd_test_lock(rqstp, &cstate->current_fh, file_lock);
	if (status)
		goto out;

	if (file_lock->fl_type != F_UNLCK) {
		status = nfserr_denied;
		nfs4_set_lock_denied(file_lock, &lockt->lt_denied);
	}
out:
	if (lo)
		nfs4_put_stateowner(&lo->lo_owner);
	if (file_lock)
		locks_free_lock(file_lock);
	return status;
}

__be32
nfsd4_locku(struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,
	    struct nfsd4_locku *locku)
{
	struct nfs4_ol_stateid *stp;
	struct file *filp = NULL;
	struct file_lock *file_lock = NULL;
	__be32 status;
	int err;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	dprintk("NFSD: nfsd4_locku: start=%Ld length=%Ld\n",
		(long long) locku->lu_offset,
		(long long) locku->lu_length);

	if (check_lock_length(locku->lu_offset, locku->lu_length))
		 return nfserr_inval;

	status = nfs4_preprocess_seqid_op(cstate, locku->lu_seqid,
					&locku->lu_stateid, NFS4_LOCK_STID,
					&stp, nn);
	if (status)
		goto out;
	filp = find_any_file(stp->st_stid.sc_file);
	if (!filp) {
		status = nfserr_lock_range;
		goto put_stateid;
	}
	file_lock = locks_alloc_lock();
	if (!file_lock) {
		dprintk("NFSD: %s: unable to allocate lock!\n", __func__);
		status = nfserr_jukebox;
		goto fput;
	}

	file_lock->fl_type = F_UNLCK;
	file_lock->fl_owner = (fl_owner_t)lockowner(nfs4_get_stateowner(stp->st_stateowner));
	file_lock->fl_pid = current->tgid;
	file_lock->fl_file = filp;
	file_lock->fl_flags = FL_POSIX;
	file_lock->fl_lmops = &nfsd_posix_mng_ops;
	file_lock->fl_start = locku->lu_offset;

	file_lock->fl_end = last_byte_offset(locku->lu_offset,
						locku->lu_length);
	nfs4_transform_lock_offset(file_lock);

	err = vfs_lock_file(filp, F_SETLK, file_lock, NULL);
	if (err) {
		dprintk("NFSD: nfs4_locku: vfs_lock_file failed!\n");
		goto out_nfserr;
	}
	update_stateid(&stp->st_stid.sc_stateid);
	memcpy(&locku->lu_stateid, &stp->st_stid.sc_stateid, sizeof(stateid_t));
fput:
	fput(filp);
put_stateid:
	nfs4_put_stid(&stp->st_stid);
out:
	nfsd4_bump_seqid(cstate, status);
	if (file_lock)
		locks_free_lock(file_lock);
	return status;

out_nfserr:
	status = nfserrno(err);
	goto fput;
}

/*
 * returns
 * 	true:  locks held by lockowner
 * 	false: no locks held by lockowner
 */
static bool
check_for_locks(struct nfs4_file *fp, struct nfs4_lockowner *lowner)
{
	struct file_lock *fl;
	int status = false;
	struct file *filp = find_any_file(fp);
	struct inode *inode;
	struct file_lock_context *flctx;

	if (!filp) {
		/* Any valid lock stateid should have some sort of access */
		WARN_ON_ONCE(1);
		return status;
	}

	inode = file_inode(filp);
	flctx = inode->i_flctx;

	if (flctx && !list_empty_careful(&flctx->flc_posix)) {
		spin_lock(&flctx->flc_lock);
		list_for_each_entry(fl, &flctx->flc_posix, fl_list) {
			if (fl->fl_owner == (fl_owner_t)lowner) {
				status = true;
				break;
			}
		}
		spin_unlock(&flctx->flc_lock);
	}
	fput(filp);
	return status;
}

__be32
nfsd4_release_lockowner(struct svc_rqst *rqstp,
			struct nfsd4_compound_state *cstate,
			struct nfsd4_release_lockowner *rlockowner)
{
	clientid_t *clid = &rlockowner->rl_clientid;
	struct nfs4_stateowner *sop;
	struct nfs4_lockowner *lo = NULL;
	struct nfs4_ol_stateid *stp;
	struct xdr_netobj *owner = &rlockowner->rl_owner;
	unsigned int hashval = ownerstr_hashval(owner);
	__be32 status;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);
	struct nfs4_client *clp;

	dprintk("nfsd4_release_lockowner clientid: (%08x/%08x):\n",
		clid->cl_boot, clid->cl_id);

	status = lookup_clientid(clid, cstate, nn);
	if (status)
		return status;

	clp = cstate->clp;
	/* Find the matching lock stateowner */
	spin_lock(&clp->cl_lock);
	list_for_each_entry(sop, &clp->cl_ownerstr_hashtbl[hashval],
			    so_strhash) {

		if (sop->so_is_open_owner || !same_owner_str(sop, owner))
			continue;

		/* see if there are still any locks associated with it */
		lo = lockowner(sop);
		list_for_each_entry(stp, &sop->so_stateids, st_perstateowner) {
			if (check_for_locks(stp->st_stid.sc_file, lo)) {
				status = nfserr_locks_held;
				spin_unlock(&clp->cl_lock);
				return status;
			}
		}

		nfs4_get_stateowner(sop);
		break;
	}
	spin_unlock(&clp->cl_lock);
	if (lo)
		release_lockowner(lo);
	return status;
}

static inline struct nfs4_client_reclaim *
alloc_reclaim(void)
{
	return kmalloc(sizeof(struct nfs4_client_reclaim), GFP_KERNEL);
}

bool
nfs4_has_reclaimed_state(const char *name, struct nfsd_net *nn)
{
	struct nfs4_client_reclaim *crp;

	crp = nfsd4_find_reclaim_client(name, nn);
	return (crp && crp->cr_clp);
}

/*
 * failure => all reset bets are off, nfserr_no_grace...
 */
struct nfs4_client_reclaim *
nfs4_client_to_reclaim(const char *name, struct nfsd_net *nn)
{
	unsigned int strhashval;
	struct nfs4_client_reclaim *crp;

	dprintk("NFSD nfs4_client_to_reclaim NAME: %.*s\n", HEXDIR_LEN, name);
	crp = alloc_reclaim();
	if (crp) {
		strhashval = clientstr_hashval(name);
		INIT_LIST_HEAD(&crp->cr_strhash);
		list_add(&crp->cr_strhash, &nn->reclaim_str_hashtbl[strhashval]);
		memcpy(crp->cr_recdir, name, HEXDIR_LEN);
		crp->cr_clp = NULL;
		nn->reclaim_str_hashtbl_size++;
	}
	return crp;
}

void
nfs4_remove_reclaim_record(struct nfs4_client_reclaim *crp, struct nfsd_net *nn)
{
	list_del(&crp->cr_strhash);
	kfree(crp);
	nn->reclaim_str_hashtbl_size--;
}

void
nfs4_release_reclaim(struct nfsd_net *nn)
{
	struct nfs4_client_reclaim *crp = NULL;
	int i;

	for (i = 0; i < CLIENT_HASH_SIZE; i++) {
		while (!list_empty(&nn->reclaim_str_hashtbl[i])) {
			crp = list_entry(nn->reclaim_str_hashtbl[i].next,
			                struct nfs4_client_reclaim, cr_strhash);
			nfs4_remove_reclaim_record(crp, nn);
		}
	}
	WARN_ON_ONCE(nn->reclaim_str_hashtbl_size);
}

/*
 * called from OPEN, CLAIM_PREVIOUS with a new clientid. */
struct nfs4_client_reclaim *
nfsd4_find_reclaim_client(const char *recdir, struct nfsd_net *nn)
{
	unsigned int strhashval;
	struct nfs4_client_reclaim *crp = NULL;

	dprintk("NFSD: nfs4_find_reclaim_client for recdir %s\n", recdir);

	strhashval = clientstr_hashval(recdir);
	list_for_each_entry(crp, &nn->reclaim_str_hashtbl[strhashval], cr_strhash) {
		if (same_name(crp->cr_recdir, recdir)) {
			return crp;
		}
	}
	return NULL;
}

/*
* Called from OPEN. Look for clientid in reclaim list.
*/
__be32
nfs4_check_open_reclaim(clientid_t *clid,
		struct nfsd4_compound_state *cstate,
		struct nfsd_net *nn)
{
	__be32 status;

	/* find clientid in conf_id_hashtbl */
	status = lookup_clientid(clid, cstate, nn);
	if (status)
		return nfserr_reclaim_bad;

	if (test_bit(NFSD4_CLIENT_RECLAIM_COMPLETE, &cstate->clp->cl_flags))
		return nfserr_no_grace;

	if (nfsd4_client_record_check(cstate->clp))
		return nfserr_reclaim_bad;

	return nfs_ok;
}

#ifdef CONFIG_NFSD_FAULT_INJECTION
static inline void
put_client(struct nfs4_client *clp)
{
	atomic_dec(&clp->cl_refcount);
}

static struct nfs4_client *
nfsd_find_client(struct sockaddr_storage *addr, size_t addr_size)
{
	struct nfs4_client *clp;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
					  nfsd_net_id);

	if (!nfsd_netns_ready(nn))
		return NULL;

	list_for_each_entry(clp, &nn->client_lru, cl_lru) {
		if (memcmp(&clp->cl_addr, addr, addr_size) == 0)
			return clp;
	}
	return NULL;
}

u64
nfsd_inject_print_clients(void)
{
	struct nfs4_client *clp;
	u64 count = 0;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
					  nfsd_net_id);
	char buf[INET6_ADDRSTRLEN];

	if (!nfsd_netns_ready(nn))
		return 0;

	spin_lock(&nn->client_lock);
	list_for_each_entry(clp, &nn->client_lru, cl_lru) {
		rpc_ntop((struct sockaddr *)&clp->cl_addr, buf, sizeof(buf));
		pr_info("NFS Client: %s\n", buf);
		++count;
	}
	spin_unlock(&nn->client_lock);

	return count;
}

u64
nfsd_inject_forget_client(struct sockaddr_storage *addr, size_t addr_size)
{
	u64 count = 0;
	struct nfs4_client *clp;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
					  nfsd_net_id);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	clp = nfsd_find_client(addr, addr_size);
	if (clp) {
		if (mark_client_expired_locked(clp) == nfs_ok)
			++count;
		else
			clp = NULL;
	}
	spin_unlock(&nn->client_lock);

	if (clp)
		expire_client(clp);

	return count;
}

u64
nfsd_inject_forget_clients(u64 max)
{
	u64 count = 0;
	struct nfs4_client *clp, *next;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	LIST_HEAD(reaplist);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	list_for_each_entry_safe(clp, next, &nn->client_lru, cl_lru) {
		if (mark_client_expired_locked(clp) == nfs_ok) {
			list_add(&clp->cl_lru, &reaplist);
			if (max != 0 && ++count >= max)
				break;
		}
	}
	spin_unlock(&nn->client_lock);

	list_for_each_entry_safe(clp, next, &reaplist, cl_lru)
		expire_client(clp);

	return count;
}

static void nfsd_print_count(struct nfs4_client *clp, unsigned int count,
			     const char *type)
{
	char buf[INET6_ADDRSTRLEN];
	rpc_ntop((struct sockaddr *)&clp->cl_addr, buf, sizeof(buf));
	printk(KERN_INFO "NFS Client: %s has %u %s\n", buf, count, type);
}

static void
nfsd_inject_add_lock_to_list(struct nfs4_ol_stateid *lst,
			     struct list_head *collect)
{
	struct nfs4_client *clp = lst->st_stid.sc_client;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
					  nfsd_net_id);

	if (!collect)
		return;

	lockdep_assert_held(&nn->client_lock);
	atomic_inc(&clp->cl_refcount);
	list_add(&lst->st_locks, collect);
}

static u64 nfsd_foreach_client_lock(struct nfs4_client *clp, u64 max,
				    struct list_head *collect,
				    void (*func)(struct nfs4_ol_stateid *))
{
	struct nfs4_openowner *oop;
	struct nfs4_ol_stateid *stp, *st_next;
	struct nfs4_ol_stateid *lst, *lst_next;
	u64 count = 0;

	spin_lock(&clp->cl_lock);
	list_for_each_entry(oop, &clp->cl_openowners, oo_perclient) {
		list_for_each_entry_safe(stp, st_next,
				&oop->oo_owner.so_stateids, st_perstateowner) {
			list_for_each_entry_safe(lst, lst_next,
					&stp->st_locks, st_locks) {
				if (func) {
					func(lst);
					nfsd_inject_add_lock_to_list(lst,
								collect);
				}
				++count;
				/*
				 * Despite the fact that these functions deal
				 * with 64-bit integers for "count", we must
				 * ensure that it doesn't blow up the
				 * clp->cl_refcount. Throw a warning if we
				 * start to approach INT_MAX here.
				 */
				WARN_ON_ONCE(count == (INT_MAX / 2));
				if (count == max)
					goto out;
			}
		}
	}
out:
	spin_unlock(&clp->cl_lock);

	return count;
}

static u64
nfsd_collect_client_locks(struct nfs4_client *clp, struct list_head *collect,
			  u64 max)
{
	return nfsd_foreach_client_lock(clp, max, collect, unhash_lock_stateid);
}

static u64
nfsd_print_client_locks(struct nfs4_client *clp)
{
	u64 count = nfsd_foreach_client_lock(clp, 0, NULL, NULL);
	nfsd_print_count(clp, count, "locked files");
	return count;
}

u64
nfsd_inject_print_locks(void)
{
	struct nfs4_client *clp;
	u64 count = 0;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);

	if (!nfsd_netns_ready(nn))
		return 0;

	spin_lock(&nn->client_lock);
	list_for_each_entry(clp, &nn->client_lru, cl_lru)
		count += nfsd_print_client_locks(clp);
	spin_unlock(&nn->client_lock);

	return count;
}

static void
nfsd_reap_locks(struct list_head *reaplist)
{
	struct nfs4_client *clp;
	struct nfs4_ol_stateid *stp, *next;

	list_for_each_entry_safe(stp, next, reaplist, st_locks) {
		list_del_init(&stp->st_locks);
		clp = stp->st_stid.sc_client;
		nfs4_put_stid(&stp->st_stid);
		put_client(clp);
	}
}

u64
nfsd_inject_forget_client_locks(struct sockaddr_storage *addr, size_t addr_size)
{
	unsigned int count = 0;
	struct nfs4_client *clp;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	LIST_HEAD(reaplist);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	clp = nfsd_find_client(addr, addr_size);
	if (clp)
		count = nfsd_collect_client_locks(clp, &reaplist, 0);
	spin_unlock(&nn->client_lock);
	nfsd_reap_locks(&reaplist);
	return count;
}

u64
nfsd_inject_forget_locks(u64 max)
{
	u64 count = 0;
	struct nfs4_client *clp;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	LIST_HEAD(reaplist);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	list_for_each_entry(clp, &nn->client_lru, cl_lru) {
		count += nfsd_collect_client_locks(clp, &reaplist, max - count);
		if (max != 0 && count >= max)
			break;
	}
	spin_unlock(&nn->client_lock);
	nfsd_reap_locks(&reaplist);
	return count;
}

static u64
nfsd_foreach_client_openowner(struct nfs4_client *clp, u64 max,
			      struct list_head *collect,
			      void (*func)(struct nfs4_openowner *))
{
	struct nfs4_openowner *oop, *next;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	u64 count = 0;

	lockdep_assert_held(&nn->client_lock);

	spin_lock(&clp->cl_lock);
	list_for_each_entry_safe(oop, next, &clp->cl_openowners, oo_perclient) {
		if (func) {
			func(oop);
			if (collect) {
				atomic_inc(&clp->cl_refcount);
				list_add(&oop->oo_perclient, collect);
			}
		}
		++count;
		/*
		 * Despite the fact that these functions deal with
		 * 64-bit integers for "count", we must ensure that
		 * it doesn't blow up the clp->cl_refcount. Throw a
		 * warning if we start to approach INT_MAX here.
		 */
		WARN_ON_ONCE(count == (INT_MAX / 2));
		if (count == max)
			break;
	}
	spin_unlock(&clp->cl_lock);

	return count;
}

static u64
nfsd_print_client_openowners(struct nfs4_client *clp)
{
	u64 count = nfsd_foreach_client_openowner(clp, 0, NULL, NULL);

	nfsd_print_count(clp, count, "openowners");
	return count;
}

static u64
nfsd_collect_client_openowners(struct nfs4_client *clp,
			       struct list_head *collect, u64 max)
{
	return nfsd_foreach_client_openowner(clp, max, collect,
						unhash_openowner_locked);
}

u64
nfsd_inject_print_openowners(void)
{
	struct nfs4_client *clp;
	u64 count = 0;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);

	if (!nfsd_netns_ready(nn))
		return 0;

	spin_lock(&nn->client_lock);
	list_for_each_entry(clp, &nn->client_lru, cl_lru)
		count += nfsd_print_client_openowners(clp);
	spin_unlock(&nn->client_lock);

	return count;
}

static void
nfsd_reap_openowners(struct list_head *reaplist)
{
	struct nfs4_client *clp;
	struct nfs4_openowner *oop, *next;

	list_for_each_entry_safe(oop, next, reaplist, oo_perclient) {
		list_del_init(&oop->oo_perclient);
		clp = oop->oo_owner.so_client;
		release_openowner(oop);
		put_client(clp);
	}
}

u64
nfsd_inject_forget_client_openowners(struct sockaddr_storage *addr,
				     size_t addr_size)
{
	unsigned int count = 0;
	struct nfs4_client *clp;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	LIST_HEAD(reaplist);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	clp = nfsd_find_client(addr, addr_size);
	if (clp)
		count = nfsd_collect_client_openowners(clp, &reaplist, 0);
	spin_unlock(&nn->client_lock);
	nfsd_reap_openowners(&reaplist);
	return count;
}

u64
nfsd_inject_forget_openowners(u64 max)
{
	u64 count = 0;
	struct nfs4_client *clp;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	LIST_HEAD(reaplist);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	list_for_each_entry(clp, &nn->client_lru, cl_lru) {
		count += nfsd_collect_client_openowners(clp, &reaplist,
							max - count);
		if (max != 0 && count >= max)
			break;
	}
	spin_unlock(&nn->client_lock);
	nfsd_reap_openowners(&reaplist);
	return count;
}

static u64 nfsd_find_all_delegations(struct nfs4_client *clp, u64 max,
				     struct list_head *victims)
{
	struct nfs4_delegation *dp, *next;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	u64 count = 0;

	lockdep_assert_held(&nn->client_lock);

	spin_lock(&state_lock);
	list_for_each_entry_safe(dp, next, &clp->cl_delegations, dl_perclnt) {
		if (victims) {
			/*
			 * It's not safe to mess with delegations that have a
			 * non-zero dl_time. They might have already been broken
			 * and could be processed by the laundromat outside of
			 * the state_lock. Just leave them be.
			 */
			if (dp->dl_time != 0)
				continue;

			atomic_inc(&clp->cl_refcount);
			unhash_delegation_locked(dp);
			list_add(&dp->dl_recall_lru, victims);
		}
		++count;
		/*
		 * Despite the fact that these functions deal with
		 * 64-bit integers for "count", we must ensure that
		 * it doesn't blow up the clp->cl_refcount. Throw a
		 * warning if we start to approach INT_MAX here.
		 */
		WARN_ON_ONCE(count == (INT_MAX / 2));
		if (count == max)
			break;
	}
	spin_unlock(&state_lock);
	return count;
}

static u64
nfsd_print_client_delegations(struct nfs4_client *clp)
{
	u64 count = nfsd_find_all_delegations(clp, 0, NULL);

	nfsd_print_count(clp, count, "delegations");
	return count;
}

u64
nfsd_inject_print_delegations(void)
{
	struct nfs4_client *clp;
	u64 count = 0;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);

	if (!nfsd_netns_ready(nn))
		return 0;

	spin_lock(&nn->client_lock);
	list_for_each_entry(clp, &nn->client_lru, cl_lru)
		count += nfsd_print_client_delegations(clp);
	spin_unlock(&nn->client_lock);

	return count;
}

static void
nfsd_forget_delegations(struct list_head *reaplist)
{
	struct nfs4_client *clp;
	struct nfs4_delegation *dp, *next;

	list_for_each_entry_safe(dp, next, reaplist, dl_recall_lru) {
		list_del_init(&dp->dl_recall_lru);
		clp = dp->dl_stid.sc_client;
		revoke_delegation(dp);
		put_client(clp);
	}
}

u64
nfsd_inject_forget_client_delegations(struct sockaddr_storage *addr,
				      size_t addr_size)
{
	u64 count = 0;
	struct nfs4_client *clp;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	LIST_HEAD(reaplist);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	clp = nfsd_find_client(addr, addr_size);
	if (clp)
		count = nfsd_find_all_delegations(clp, 0, &reaplist);
	spin_unlock(&nn->client_lock);

	nfsd_forget_delegations(&reaplist);
	return count;
}

u64
nfsd_inject_forget_delegations(u64 max)
{
	u64 count = 0;
	struct nfs4_client *clp;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	LIST_HEAD(reaplist);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	list_for_each_entry(clp, &nn->client_lru, cl_lru) {
		count += nfsd_find_all_delegations(clp, max - count, &reaplist);
		if (max != 0 && count >= max)
			break;
	}
	spin_unlock(&nn->client_lock);
	nfsd_forget_delegations(&reaplist);
	return count;
}

static void
nfsd_recall_delegations(struct list_head *reaplist)
{
	struct nfs4_client *clp;
	struct nfs4_delegation *dp, *next;

	list_for_each_entry_safe(dp, next, reaplist, dl_recall_lru) {
		list_del_init(&dp->dl_recall_lru);
		clp = dp->dl_stid.sc_client;
		/*
		 * We skipped all entries that had a zero dl_time before,
		 * so we can now reset the dl_time back to 0. If a delegation
		 * break comes in now, then it won't make any difference since
		 * we're recalling it either way.
		 */
		spin_lock(&state_lock);
		dp->dl_time = 0;
		spin_unlock(&state_lock);
		nfsd_break_one_deleg(dp);
		put_client(clp);
	}
}

u64
nfsd_inject_recall_client_delegations(struct sockaddr_storage *addr,
				      size_t addr_size)
{
	u64 count = 0;
	struct nfs4_client *clp;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	LIST_HEAD(reaplist);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	clp = nfsd_find_client(addr, addr_size);
	if (clp)
		count = nfsd_find_all_delegations(clp, 0, &reaplist);
	spin_unlock(&nn->client_lock);

	nfsd_recall_delegations(&reaplist);
	return count;
}

u64
nfsd_inject_recall_delegations(u64 max)
{
	u64 count = 0;
	struct nfs4_client *clp, *next;
	struct nfsd_net *nn = net_generic(current->nsproxy->net_ns,
						nfsd_net_id);
	LIST_HEAD(reaplist);

	if (!nfsd_netns_ready(nn))
		return count;

	spin_lock(&nn->client_lock);
	list_for_each_entry_safe(clp, next, &nn->client_lru, cl_lru) {
		count += nfsd_find_all_delegations(clp, max - count, &reaplist);
		if (max != 0 && ++count >= max)
			break;
	}
	spin_unlock(&nn->client_lock);
	nfsd_recall_delegations(&reaplist);
	return count;
}
#endif /* CONFIG_NFSD_FAULT_INJECTION */

/*
 * Since the lifetime of a delegation isn't limited to that of an open, a
 * client may quite reasonably hang on to a delegation as long as it has
 * the inode cached.  This becomes an obvious problem the first time a
 * client's inode cache approaches the size of the server's total memory.
 *
 * For now we avoid this problem by imposing a hard limit on the number
 * of delegations, which varies according to the server's memory size.
 */
static void
set_max_delegations(void)
{
	/*
	 * Allow at most 4 delegations per megabyte of RAM.  Quick
	 * estimates suggest that in the worst case (where every delegation
	 * is for a different inode), a delegation could take about 1.5K,
	 * giving a worst case usage of about 6% of memory.
	 */
	max_delegations = nr_free_buffer_pages() >> (20 - 2 - PAGE_SHIFT);
}

static int nfs4_state_create_net(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	int i;

	nn->conf_id_hashtbl = kmalloc(sizeof(struct list_head) *
			CLIENT_HASH_SIZE, GFP_KERNEL);
	if (!nn->conf_id_hashtbl)
		goto err;
	nn->unconf_id_hashtbl = kmalloc(sizeof(struct list_head) *
			CLIENT_HASH_SIZE, GFP_KERNEL);
	if (!nn->unconf_id_hashtbl)
		goto err_unconf_id;
	nn->sessionid_hashtbl = kmalloc(sizeof(struct list_head) *
			SESSION_HASH_SIZE, GFP_KERNEL);
	if (!nn->sessionid_hashtbl)
		goto err_sessionid;

	for (i = 0; i < CLIENT_HASH_SIZE; i++) {
		INIT_LIST_HEAD(&nn->conf_id_hashtbl[i]);
		INIT_LIST_HEAD(&nn->unconf_id_hashtbl[i]);
	}
	for (i = 0; i < SESSION_HASH_SIZE; i++)
		INIT_LIST_HEAD(&nn->sessionid_hashtbl[i]);
	nn->conf_name_tree = RB_ROOT;
	nn->unconf_name_tree = RB_ROOT;
	INIT_LIST_HEAD(&nn->client_lru);
	INIT_LIST_HEAD(&nn->close_lru);
	INIT_LIST_HEAD(&nn->del_recall_lru);
	spin_lock_init(&nn->client_lock);

	INIT_DELAYED_WORK(&nn->laundromat_work, laundromat_main);
	get_net(net);

	return 0;

err_sessionid:
	kfree(nn->unconf_id_hashtbl);
err_unconf_id:
	kfree(nn->conf_id_hashtbl);
err:
	return -ENOMEM;
}

static void
nfs4_state_destroy_net(struct net *net)
{
	int i;
	struct nfs4_client *clp = NULL;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	for (i = 0; i < CLIENT_HASH_SIZE; i++) {
		while (!list_empty(&nn->conf_id_hashtbl[i])) {
			clp = list_entry(nn->conf_id_hashtbl[i].next, struct nfs4_client, cl_idhash);
			destroy_client(clp);
		}
	}

	for (i = 0; i < CLIENT_HASH_SIZE; i++) {
		while (!list_empty(&nn->unconf_id_hashtbl[i])) {
			clp = list_entry(nn->unconf_id_hashtbl[i].next, struct nfs4_client, cl_idhash);
			destroy_client(clp);
		}
	}

	kfree(nn->sessionid_hashtbl);
	kfree(nn->unconf_id_hashtbl);
	kfree(nn->conf_id_hashtbl);
	put_net(net);
}

int
nfs4_state_start_net(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	int ret;

	ret = nfs4_state_create_net(net);
	if (ret)
		return ret;
	nn->boot_time = get_seconds();
	nn->grace_ended = false;
	locks_start_grace(net, &nn->nfsd4_manager);
	nfsd4_client_tracking_init(net);
	printk(KERN_INFO "NFSD: starting %ld-second grace period (net %p)\n",
	       nn->nfsd4_grace, net);
	queue_delayed_work(laundry_wq, &nn->laundromat_work, nn->nfsd4_grace * HZ);
	return 0;
}

/* initialization to perform when the nfsd service is started: */

int
nfs4_state_start(void)
{
	int ret;

	ret = set_callback_cred();
	if (ret)
		return -ENOMEM;
	laundry_wq = create_singlethread_workqueue("nfsd4");
	if (laundry_wq == NULL) {
		ret = -ENOMEM;
		goto out_recovery;
	}
	ret = nfsd4_create_callback_queue();
	if (ret)
		goto out_free_laundry;

	set_max_delegations();

	return 0;

out_free_laundry:
	destroy_workqueue(laundry_wq);
out_recovery:
	return ret;
}

void
nfs4_state_shutdown_net(struct net *net)
{
	struct nfs4_delegation *dp = NULL;
	struct list_head *pos, *next, reaplist;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	cancel_delayed_work_sync(&nn->laundromat_work);
	locks_end_grace(&nn->nfsd4_manager);

	INIT_LIST_HEAD(&reaplist);
	spin_lock(&state_lock);
	list_for_each_safe(pos, next, &nn->del_recall_lru) {
		dp = list_entry (pos, struct nfs4_delegation, dl_recall_lru);
		unhash_delegation_locked(dp);
		list_add(&dp->dl_recall_lru, &reaplist);
	}
	spin_unlock(&state_lock);
	list_for_each_safe(pos, next, &reaplist) {
		dp = list_entry (pos, struct nfs4_delegation, dl_recall_lru);
		list_del_init(&dp->dl_recall_lru);
		nfs4_put_deleg_lease(dp->dl_stid.sc_file);
		nfs4_put_stid(&dp->dl_stid);
	}

	nfsd4_client_tracking_exit(net);
	nfs4_state_destroy_net(net);
}

void
nfs4_state_shutdown(void)
{
	destroy_workqueue(laundry_wq);
	nfsd4_destroy_callback_queue();
}

static void
get_stateid(struct nfsd4_compound_state *cstate, stateid_t *stateid)
{
	if (HAS_STATE_ID(cstate, CURRENT_STATE_ID_FLAG) && CURRENT_STATEID(stateid))
		memcpy(stateid, &cstate->current_stateid, sizeof(stateid_t));
}

static void
put_stateid(struct nfsd4_compound_state *cstate, stateid_t *stateid)
{
	if (cstate->minorversion) {
		memcpy(&cstate->current_stateid, stateid, sizeof(stateid_t));
		SET_STATE_ID(cstate, CURRENT_STATE_ID_FLAG);
	}
}

void
clear_current_stateid(struct nfsd4_compound_state *cstate)
{
	CLEAR_STATE_ID(cstate, CURRENT_STATE_ID_FLAG);
}

/*
 * functions to set current state id
 */
void
nfsd4_set_opendowngradestateid(struct nfsd4_compound_state *cstate, struct nfsd4_open_downgrade *odp)
{
	put_stateid(cstate, &odp->od_stateid);
}

void
nfsd4_set_openstateid(struct nfsd4_compound_state *cstate, struct nfsd4_open *open)
{
	put_stateid(cstate, &open->op_stateid);
}

void
nfsd4_set_closestateid(struct nfsd4_compound_state *cstate, struct nfsd4_close *close)
{
	put_stateid(cstate, &close->cl_stateid);
}

void
nfsd4_set_lockstateid(struct nfsd4_compound_state *cstate, struct nfsd4_lock *lock)
{
	put_stateid(cstate, &lock->lk_resp_stateid);
}

/*
 * functions to consume current state id
 */

void
nfsd4_get_opendowngradestateid(struct nfsd4_compound_state *cstate, struct nfsd4_open_downgrade *odp)
{
	get_stateid(cstate, &odp->od_stateid);
}

void
nfsd4_get_delegreturnstateid(struct nfsd4_compound_state *cstate, struct nfsd4_delegreturn *drp)
{
	get_stateid(cstate, &drp->dr_stateid);
}

void
nfsd4_get_freestateid(struct nfsd4_compound_state *cstate, struct nfsd4_free_stateid *fsp)
{
	get_stateid(cstate, &fsp->fr_stateid);
}

void
nfsd4_get_setattrstateid(struct nfsd4_compound_state *cstate, struct nfsd4_setattr *setattr)
{
	get_stateid(cstate, &setattr->sa_stateid);
}

void
nfsd4_get_closestateid(struct nfsd4_compound_state *cstate, struct nfsd4_close *close)
{
	get_stateid(cstate, &close->cl_stateid);
}

void
nfsd4_get_lockustateid(struct nfsd4_compound_state *cstate, struct nfsd4_locku *locku)
{
	get_stateid(cstate, &locku->lu_stateid);
}

void
nfsd4_get_readstateid(struct nfsd4_compound_state *cstate, struct nfsd4_read *read)
{
	get_stateid(cstate, &read->rd_stateid);
}

void
nfsd4_get_writestateid(struct nfsd4_compound_state *cstate, struct nfsd4_write *write)
{
	get_stateid(cstate, &write->wr_stateid);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs4state.c */
/************************************************************/
/*
 *  Mapping of UID/GIDs to name and vice versa.
 *
 *  Copyright (c) 2002, 2003 The Regents of the University of
 *  Michigan.  All rights reserved.
 *
 *  Marius Aamodt Eriksen <marius@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// #include <linux/module.h>
// #include <linux/seq_file.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/sunrpc/svc_xprt.h>
// #include <net/net_namespace.h>
// #include "idmap.h"
// #include "nfsd.h"
// #include "netns.h"

/*
 * Turn off idmapping when using AUTH_SYS.
 */
static bool nfs4_disable_idmapping = true;
module_param(nfs4_disable_idmapping, bool, 0644);
MODULE_PARM_DESC(nfs4_disable_idmapping,
		"Turn off server's NFSv4 idmapping when using 'sec=sys'");

/*
 * Cache entry
 */

/*
 * XXX we know that IDMAP_NAMESZ < PAGE_SIZE, but it's ugly to rely on
 * that.
 */

#define IDMAP_TYPE_USER  0
#define IDMAP_TYPE_GROUP 1

struct ent {
	struct cache_head h;
	int               type;		       /* User / Group */
	u32               id;
	char              name[IDMAP_NAMESZ];
	char              authname[IDMAP_NAMESZ];
};

/* Common entry handling */

#define ENT_HASHBITS          8
#define ENT_HASHMAX           (1 << ENT_HASHBITS)

static void
ent_init(struct cache_head *cnew, struct cache_head *citm)
{
	struct ent *new = container_of(cnew, struct ent, h);
	struct ent *itm = container_of(citm, struct ent, h);

	new->id = itm->id;
	new->type = itm->type;

	strlcpy(new->name, itm->name, sizeof(new->name));
	strlcpy(new->authname, itm->authname, sizeof(new->name));
}

static void
ent_put(struct kref *ref)
{
	struct ent *map = container_of(ref, struct ent, h.ref);
	kfree(map);
}

static struct cache_head *
ent_alloc(void)
{
	struct ent *e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (e)
		return &e->h;
	else
		return NULL;
}

/*
 * ID -> Name cache
 */

static uint32_t
idtoname_hash(struct ent *ent)
{
	uint32_t hash;

	hash = hash_str(ent->authname, ENT_HASHBITS);
	hash = hash_long(hash ^ ent->id, ENT_HASHBITS);

	/* Flip LSB for user/group */
	if (ent->type == IDMAP_TYPE_GROUP)
		hash ^= 1;

	return hash;
}

static void
idtoname_request(struct cache_detail *cd, struct cache_head *ch, char **bpp,
    int *blen)
{
 	struct ent *ent = container_of(ch, struct ent, h);
	char idstr[11];

	qword_add(bpp, blen, ent->authname);
	snprintf(idstr, sizeof(idstr), "%u", ent->id);
	qword_add(bpp, blen, ent->type == IDMAP_TYPE_GROUP ? "group" : "user");
	qword_add(bpp, blen, idstr);

	(*bpp)[-1] = '\n';
}

static int
idtoname_match(struct cache_head *ca, struct cache_head *cb)
{
	struct ent *a = container_of(ca, struct ent, h);
	struct ent *b = container_of(cb, struct ent, h);

	return (a->id == b->id && a->type == b->type &&
	    strcmp(a->authname, b->authname) == 0);
}

static int
idtoname_show(struct seq_file *m, struct cache_detail *cd, struct cache_head *h)
{
	struct ent *ent;

	if (h == NULL) {
		seq_puts(m, "#domain type id [name]\n");
		return 0;
	}
	ent = container_of(h, struct ent, h);
	seq_printf(m, "%s %s %u", ent->authname,
			ent->type == IDMAP_TYPE_GROUP ? "group" : "user",
			ent->id);
	if (test_bit(CACHE_VALID, &h->flags))
		seq_printf(m, " %s", ent->name);
	seq_printf(m, "\n");
	return 0;
}

static void
warn_no_idmapd(struct cache_detail *detail, int has_died)
{
	printk("nfsd: nfsv4 idmapping failing: has idmapd %s?\n",
			has_died ? "died" : "not been started");
}


static int         idtoname_parse(struct cache_detail *, char *, int);
static struct ent *idtoname_lookup(struct cache_detail *, struct ent *);
static struct ent *idtoname_update(struct cache_detail *, struct ent *,
				   struct ent *);

static struct cache_detail idtoname_cache_template = {
	.owner		= THIS_MODULE,
	.hash_size	= ENT_HASHMAX,
	.name		= "nfs4.idtoname",
	.cache_put	= ent_put,
	.cache_request	= idtoname_request,
	.cache_parse	= idtoname_parse,
	.cache_show	= idtoname_show,
	.warn_no_listener = warn_no_idmapd,
	.match		= idtoname_match,
	.init		= ent_init,
	.update		= ent_init,
	.alloc		= ent_alloc,
};

static int
idtoname_parse(struct cache_detail *cd, char *buf, int buflen)
{
	struct ent ent, *res;
	char *buf1, *bp;
	int len;
	int error = -EINVAL;

	if (buf[buflen - 1] != '\n')
		return (-EINVAL);
	buf[buflen - 1]= '\0';

	buf1 = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf1 == NULL)
		return (-ENOMEM);

	memset(&ent, 0, sizeof(ent));

	/* Authentication name */
	len = qword_get(&buf, buf1, PAGE_SIZE);
	if (len <= 0 || len >= IDMAP_NAMESZ)
		goto out;
	memcpy(ent.authname, buf1, sizeof(ent.authname));

	/* Type */
	if (qword_get(&buf, buf1, PAGE_SIZE) <= 0)
		goto out;
	ent.type = strcmp(buf1, "user") == 0 ?
		IDMAP_TYPE_USER : IDMAP_TYPE_GROUP;

	/* ID */
	if (qword_get(&buf, buf1, PAGE_SIZE) <= 0)
		goto out;
	ent.id = simple_strtoul(buf1, &bp, 10);
	if (bp == buf1)
		goto out;

	/* expiry */
	ent.h.expiry_time = get_expiry(&buf);
	if (ent.h.expiry_time == 0)
		goto out;

	error = -ENOMEM;
	res = idtoname_lookup(cd, &ent);
	if (!res)
		goto out;

	/* Name */
	error = -EINVAL;
	len = qword_get(&buf, buf1, PAGE_SIZE);
	if (len < 0 || len >= IDMAP_NAMESZ)
		goto out;
	if (len == 0)
		set_bit(CACHE_NEGATIVE, &ent.h.flags);
	else
		memcpy(ent.name, buf1, sizeof(ent.name));
	error = -ENOMEM;
	res = idtoname_update(cd, &ent, res);
	if (res == NULL)
		goto out;

	cache_put(&res->h, cd);
	error = 0;
out:
	kfree(buf1);
	return error;
}

static struct ent *
idtoname_lookup(struct cache_detail *cd, struct ent *item)
{
	struct cache_head *ch = sunrpc_cache_lookup(cd, &item->h,
						    idtoname_hash(item));
	if (ch)
		return container_of(ch, struct ent, h);
	else
		return NULL;
}

static struct ent *
idtoname_update(struct cache_detail *cd, struct ent *new, struct ent *old)
{
	struct cache_head *ch = sunrpc_cache_update(cd, &new->h, &old->h,
						    idtoname_hash(new));
	if (ch)
		return container_of(ch, struct ent, h);
	else
		return NULL;
}


/*
 * Name -> ID cache
 */

static inline int
nametoid_hash(struct ent *ent)
{
	return hash_str(ent->name, ENT_HASHBITS);
}

static void
nametoid_request(struct cache_detail *cd, struct cache_head *ch, char **bpp,
    int *blen)
{
 	struct ent *ent = container_of(ch, struct ent, h);

	qword_add(bpp, blen, ent->authname);
	qword_add(bpp, blen, ent->type == IDMAP_TYPE_GROUP ? "group" : "user");
	qword_add(bpp, blen, ent->name);

	(*bpp)[-1] = '\n';
}

static int
nametoid_match(struct cache_head *ca, struct cache_head *cb)
{
	struct ent *a = container_of(ca, struct ent, h);
	struct ent *b = container_of(cb, struct ent, h);

	return (a->type == b->type && strcmp(a->name, b->name) == 0 &&
	    strcmp(a->authname, b->authname) == 0);
}

static int
nametoid_show(struct seq_file *m, struct cache_detail *cd, struct cache_head *h)
{
	struct ent *ent;

	if (h == NULL) {
		seq_puts(m, "#domain type name [id]\n");
		return 0;
	}
	ent = container_of(h, struct ent, h);
	seq_printf(m, "%s %s %s", ent->authname,
			ent->type == IDMAP_TYPE_GROUP ? "group" : "user",
			ent->name);
	if (test_bit(CACHE_VALID, &h->flags))
		seq_printf(m, " %u", ent->id);
	seq_printf(m, "\n");
	return 0;
}

static struct ent *nametoid_lookup(struct cache_detail *, struct ent *);
static struct ent *nametoid_update(struct cache_detail *, struct ent *,
				   struct ent *);
static int         nametoid_parse(struct cache_detail *, char *, int);

static struct cache_detail nametoid_cache_template = {
	.owner		= THIS_MODULE,
	.hash_size	= ENT_HASHMAX,
	.name		= "nfs4.nametoid",
	.cache_put	= ent_put,
	.cache_request	= nametoid_request,
	.cache_parse	= nametoid_parse,
	.cache_show	= nametoid_show,
	.warn_no_listener = warn_no_idmapd,
	.match		= nametoid_match,
	.init		= ent_init,
	.update		= ent_init,
	.alloc		= ent_alloc,
};

static int
nametoid_parse(struct cache_detail *cd, char *buf, int buflen)
{
	struct ent ent, *res;
	char *buf1;
	int len, error = -EINVAL;

	if (buf[buflen - 1] != '\n')
		return (-EINVAL);
	buf[buflen - 1]= '\0';

	buf1 = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf1 == NULL)
		return (-ENOMEM);

	memset(&ent, 0, sizeof(ent));

	/* Authentication name */
	len = qword_get(&buf, buf1, PAGE_SIZE);
	if (len <= 0 || len >= IDMAP_NAMESZ)
		goto out;
	memcpy(ent.authname, buf1, sizeof(ent.authname));

	/* Type */
	if (qword_get(&buf, buf1, PAGE_SIZE) <= 0)
		goto out;
	ent.type = strcmp(buf1, "user") == 0 ?
		IDMAP_TYPE_USER : IDMAP_TYPE_GROUP;

	/* Name */
	len = qword_get(&buf, buf1, PAGE_SIZE);
	if (len <= 0 || len >= IDMAP_NAMESZ)
		goto out;
	memcpy(ent.name, buf1, sizeof(ent.name));

	/* expiry */
	ent.h.expiry_time = get_expiry(&buf);
	if (ent.h.expiry_time == 0)
		goto out;

	/* ID */
	error = get_int(&buf, &ent.id);
	if (error == -EINVAL)
		goto out;
	if (error == -ENOENT)
		set_bit(CACHE_NEGATIVE, &ent.h.flags);

	error = -ENOMEM;
	res = nametoid_lookup(cd, &ent);
	if (res == NULL)
		goto out;
	res = nametoid_update(cd, &ent, res);
	if (res == NULL)
		goto out;

	cache_put(&res->h, cd);
	error = 0;
out:
	kfree(buf1);
	return (error);
}


static struct ent *
nametoid_lookup(struct cache_detail *cd, struct ent *item)
{
	struct cache_head *ch = sunrpc_cache_lookup(cd, &item->h,
						    nametoid_hash(item));
	if (ch)
		return container_of(ch, struct ent, h);
	else
		return NULL;
}

static struct ent *
nametoid_update(struct cache_detail *cd, struct ent *new, struct ent *old)
{
	struct cache_head *ch = sunrpc_cache_update(cd, &new->h, &old->h,
						    nametoid_hash(new));
	if (ch)
		return container_of(ch, struct ent, h);
	else
		return NULL;
}

/*
 * Exported API
 */

int
nfsd_idmap_init(struct net *net)
{
	int rv;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	nn->idtoname_cache = cache_create_net(&idtoname_cache_template, net);
	if (IS_ERR(nn->idtoname_cache))
		return PTR_ERR(nn->idtoname_cache);
	rv = cache_register_net(nn->idtoname_cache, net);
	if (rv)
		goto destroy_idtoname_cache;
	nn->nametoid_cache = cache_create_net(&nametoid_cache_template, net);
	if (IS_ERR(nn->nametoid_cache)) {
		rv = PTR_ERR(nn->nametoid_cache);
		goto unregister_idtoname_cache;
	}
	rv = cache_register_net(nn->nametoid_cache, net);
	if (rv)
		goto destroy_nametoid_cache;
	return 0;

destroy_nametoid_cache:
	cache_destroy_net(nn->nametoid_cache, net);
unregister_idtoname_cache:
	cache_unregister_net(nn->idtoname_cache, net);
destroy_idtoname_cache:
	cache_destroy_net(nn->idtoname_cache, net);
	return rv;
}

void
nfsd_idmap_shutdown(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	cache_unregister_net(nn->idtoname_cache, net);
	cache_unregister_net(nn->nametoid_cache, net);
	cache_destroy_net(nn->idtoname_cache, net);
	cache_destroy_net(nn->nametoid_cache, net);
}

static int
idmap_lookup(struct svc_rqst *rqstp,
		struct ent *(*lookup_fn)(struct cache_detail *, struct ent *),
		struct ent *key, struct cache_detail *detail, struct ent **item)
{
	int ret;

	*item = lookup_fn(detail, key);
	if (!*item)
		return -ENOMEM;
 retry:
	ret = cache_check(detail, &(*item)->h, &rqstp->rq_chandle);

	if (ret == -ETIMEDOUT) {
		struct ent *prev_item = *item;
		*item = lookup_fn(detail, key);
		if (*item != prev_item)
			goto retry;
		cache_put(&(*item)->h, detail);
	}
	return ret;
}

static char *
rqst_authname(struct svc_rqst *rqstp)
{
	struct auth_domain *clp;

	clp = rqstp->rq_gssclient ? rqstp->rq_gssclient : rqstp->rq_client;
	return clp->name;
}

static __be32
idmap_name_to_id(struct svc_rqst *rqstp, int type, const char *name, u32 namelen,
		u32 *id)
{
	struct ent *item, key = {
		.type = type,
	};
	int ret;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	if (namelen + 1 > sizeof(key.name))
		return nfserr_badowner;
	memcpy(key.name, name, namelen);
	key.name[namelen] = '\0';
	strlcpy(key.authname, rqst_authname(rqstp), sizeof(key.authname));
	ret = idmap_lookup(rqstp, nametoid_lookup, &key, nn->nametoid_cache, &item);
	if (ret == -ENOENT)
		return nfserr_badowner;
	if (ret)
		return nfserrno(ret);
	*id = item->id;
	cache_put(&item->h, nn->nametoid_cache);
	return 0;
}

static __be32 encode_ascii_id(struct xdr_stream *xdr, u32 id)
{
	char buf[11];
	int len;
	__be32 *p;

	len = sprintf(buf, "%u", id);
	p = xdr_reserve_space(xdr, len + 4);
	if (!p)
		return nfserr_resource;
	p = xdr_encode_opaque(p, buf, len);
	return 0;
}

static __be32 idmap_id_to_name(struct xdr_stream *xdr,
			       struct svc_rqst *rqstp, int type, u32 id)
{
	struct ent *item, key = {
		.id = id,
		.type = type,
	};
	__be32 *p;
	int ret;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);

	strlcpy(key.authname, rqst_authname(rqstp), sizeof(key.authname));
	ret = idmap_lookup(rqstp, idtoname_lookup, &key, nn->idtoname_cache, &item);
	if (ret == -ENOENT)
		return encode_ascii_id(xdr, id);
	if (ret)
		return nfserrno(ret);
	ret = strlen(item->name);
	WARN_ON_ONCE(ret > IDMAP_NAMESZ);
	p = xdr_reserve_space(xdr, ret + 4);
	if (!p)
		return nfserr_resource;
	p = xdr_encode_opaque(p, item->name, ret);
	cache_put(&item->h, nn->idtoname_cache);
	return 0;
}

static bool
numeric_name_to_id(struct svc_rqst *rqstp, int type, const char *name, u32 namelen, u32 *id)
{
	int ret;
	char buf[11];

	if (namelen + 1 > sizeof(buf))
		/* too long to represent a 32-bit id: */
		return false;
	/* Just to make sure it's null-terminated: */
	memcpy(buf, name, namelen);
	buf[namelen] = '\0';
	ret = kstrtouint(buf, 10, id);
	return ret == 0;
}

static __be32
do_name_to_id(struct svc_rqst *rqstp, int type, const char *name, u32 namelen, u32 *id)
{
	if (nfs4_disable_idmapping && rqstp->rq_cred.cr_flavor < RPC_AUTH_GSS)
		if (numeric_name_to_id(rqstp, type, name, namelen, id))
			return 0;
		/*
		 * otherwise, fall through and try idmapping, for
		 * backwards compatibility with clients sending names:
		 */
	return idmap_name_to_id(rqstp, type, name, namelen, id);
}

static __be32 encode_name_from_id(struct xdr_stream *xdr,
				  struct svc_rqst *rqstp, int type, u32 id)
{
	if (nfs4_disable_idmapping && rqstp->rq_cred.cr_flavor < RPC_AUTH_GSS)
		return encode_ascii_id(xdr, id);
	return idmap_id_to_name(xdr, rqstp, type, id);
}

__be32
nfsd_map_name_to_uid(struct svc_rqst *rqstp, const char *name, size_t namelen,
		kuid_t *uid)
{
	__be32 status;
	u32 id = -1;
	status = do_name_to_id(rqstp, IDMAP_TYPE_USER, name, namelen, &id);
	*uid = make_kuid(&init_user_ns, id);
	if (!uid_valid(*uid))
		status = nfserr_badowner;
	return status;
}

__be32
nfsd_map_name_to_gid(struct svc_rqst *rqstp, const char *name, size_t namelen,
		kgid_t *gid)
{
	__be32 status;
	u32 id = -1;
	status = do_name_to_id(rqstp, IDMAP_TYPE_GROUP, name, namelen, &id);
	*gid = make_kgid(&init_user_ns, id);
	if (!gid_valid(*gid))
		status = nfserr_badowner;
	return status;
}

__be32 nfsd4_encode_user(struct xdr_stream *xdr, struct svc_rqst *rqstp,
			 kuid_t uid)
{
	u32 id = from_kuid(&init_user_ns, uid);
	return encode_name_from_id(xdr, rqstp, IDMAP_TYPE_USER, id);
}

__be32 nfsd4_encode_group(struct xdr_stream *xdr, struct svc_rqst *rqstp,
			  kgid_t gid)
{
	u32 id = from_kgid(&init_user_ns, gid);
	return encode_name_from_id(xdr, rqstp, IDMAP_TYPE_GROUP, id);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs4idmap.c */
/************************************************************/
/*
 *  Common NFSv4 ACL handling code.
 *
 *  Copyright (c) 2002, 2003 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Marius Aamodt Eriksen <marius@umich.edu>
 *  Jeff Sedlak <jsedlak@umich.edu>
 *  J. Bruce Fields <bfields@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// #include <linux/slab.h>
#include <linux/nfs_fs.h>
// #include "nfsfh.h"
// #include "nfsd.h"
// #include "acl.h"
// #include "vfs.h"
#include "../../inc/__fss.h"

#define NFS4_ACL_TYPE_DEFAULT	0x01
#define NFS4_ACL_DIR		0x02
#define NFS4_ACL_OWNER		0x04

/* mode bit translations: */
#define NFS4_READ_MODE (NFS4_ACE_READ_DATA)
#define NFS4_WRITE_MODE (NFS4_ACE_WRITE_DATA | NFS4_ACE_APPEND_DATA)
#define NFS4_EXECUTE_MODE NFS4_ACE_EXECUTE
#define NFS4_ANYONE_MODE (NFS4_ACE_READ_ATTRIBUTES | NFS4_ACE_READ_ACL | NFS4_ACE_SYNCHRONIZE)
#define NFS4_OWNER_MODE (NFS4_ACE_WRITE_ATTRIBUTES | NFS4_ACE_WRITE_ACL)

/* We don't support these bits; insist they be neither allowed nor denied */
#define NFS4_MASK_UNSUPP (NFS4_ACE_DELETE | NFS4_ACE_WRITE_OWNER \
		| NFS4_ACE_READ_NAMED_ATTRS | NFS4_ACE_WRITE_NAMED_ATTRS)

/* flags used to simulate posix default ACLs */
#define NFS4_INHERITANCE_FLAGS (NFS4_ACE_FILE_INHERIT_ACE \
		| NFS4_ACE_DIRECTORY_INHERIT_ACE)

#define NFS4_SUPPORTED_FLAGS (NFS4_INHERITANCE_FLAGS \
		| NFS4_ACE_INHERIT_ONLY_ACE \
		| NFS4_ACE_IDENTIFIER_GROUP)

#define MASK_EQUAL(mask1, mask2) \
	( ((mask1) & NFS4_ACE_MASK_ALL) == ((mask2) & NFS4_ACE_MASK_ALL) )

static u32
mask_from_posix(unsigned short perm, unsigned int flags)
{
	int mask = NFS4_ANYONE_MODE;

	if (flags & NFS4_ACL_OWNER)
		mask |= NFS4_OWNER_MODE;
	if (perm & ACL_READ)
		mask |= NFS4_READ_MODE;
	if (perm & ACL_WRITE)
		mask |= NFS4_WRITE_MODE;
	if ((perm & ACL_WRITE) && (flags & NFS4_ACL_DIR))
		mask |= NFS4_ACE_DELETE_CHILD;
	if (perm & ACL_EXECUTE)
		mask |= NFS4_EXECUTE_MODE;
	return mask;
}

static u32
deny_mask_from_posix(unsigned short perm, u32 flags)
{
	u32 mask = 0;

	if (perm & ACL_READ)
		mask |= NFS4_READ_MODE;
	if (perm & ACL_WRITE)
		mask |= NFS4_WRITE_MODE;
	if ((perm & ACL_WRITE) && (flags & NFS4_ACL_DIR))
		mask |= NFS4_ACE_DELETE_CHILD;
	if (perm & ACL_EXECUTE)
		mask |= NFS4_EXECUTE_MODE;
	return mask;
}

/* XXX: modify functions to return NFS errors; they're only ever
 * used by nfs code, after all.... */

/* We only map from NFSv4 to POSIX ACLs when setting ACLs, when we err on the
 * side of being more restrictive, so the mode bit mapping below is
 * pessimistic.  An optimistic version would be needed to handle DENY's,
 * but we espect to coalesce all ALLOWs and DENYs before mapping to mode
 * bits. */

static void
low_mode_from_nfs4(u32 perm, unsigned short *mode, unsigned int flags)
{
	u32 write_mode = NFS4_WRITE_MODE;

	if (flags & NFS4_ACL_DIR)
		write_mode |= NFS4_ACE_DELETE_CHILD;
	*mode = 0;
	if ((perm & NFS4_READ_MODE) == NFS4_READ_MODE)
		*mode |= ACL_READ;
	if ((perm & write_mode) == write_mode)
		*mode |= ACL_WRITE;
	if ((perm & NFS4_EXECUTE_MODE) == NFS4_EXECUTE_MODE)
		*mode |= ACL_EXECUTE;
}

struct ace_container {
	struct nfs4_ace  *ace;
	struct list_head  ace_l;
};

static short ace2type(struct nfs4_ace *);
static void _posix_to_nfsv4_one(struct posix_acl *, struct nfs4_acl *,
				unsigned int);

int
nfsd4_get_nfs4_acl(struct svc_rqst *rqstp, struct dentry *dentry,
		struct nfs4_acl **acl)
{
	struct inode *inode = dentry->d_inode;
	int error = 0;
	struct posix_acl *pacl = NULL, *dpacl = NULL;
	unsigned int flags = 0;
	int size = 0;

	pacl = get_acl(inode, ACL_TYPE_ACCESS);
	if (!pacl)
		pacl = posix_acl_from_mode(inode->i_mode, GFP_KERNEL);

	if (IS_ERR(pacl))
		return PTR_ERR(pacl);

	/* allocate for worst case: one (deny, allow) pair each: */
	size += 2 * pacl->a_count;

	if (S_ISDIR(inode->i_mode)) {
		flags = NFS4_ACL_DIR;
		dpacl = get_acl(inode, ACL_TYPE_DEFAULT);
		if (IS_ERR(dpacl)) {
			error = PTR_ERR(dpacl);
			goto rel_pacl;
		}

		if (dpacl)
			size += 2 * dpacl->a_count;
	}

	*acl = kmalloc(nfs4_acl_bytes(size), GFP_KERNEL);
	if (*acl == NULL) {
		error = -ENOMEM;
		goto out;
	}
	(*acl)->naces = 0;

	_posix_to_nfsv4_one(pacl, *acl, flags & ~NFS4_ACL_TYPE_DEFAULT);

	if (dpacl)
		_posix_to_nfsv4_one(dpacl, *acl, flags | NFS4_ACL_TYPE_DEFAULT);

out:
	posix_acl_release(dpacl);
rel_pacl:
	posix_acl_release(pacl);
	return error;
}

struct posix_acl_summary {
	unsigned short owner;
	unsigned short users;
	unsigned short group;
	unsigned short groups;
	unsigned short other;
	unsigned short mask;
};

static void
summarize_posix_acl(struct posix_acl *acl, struct posix_acl_summary *pas)
{
	struct posix_acl_entry *pa, *pe;

	/*
	 * Only pas.users and pas.groups need initialization; previous
	 * posix_acl_valid() calls ensure that the other fields will be
	 * initialized in the following loop.  But, just to placate gcc:
	 */
	memset(pas, 0, sizeof(*pas));
	pas->mask = 07;

	pe = acl->a_entries + acl->a_count;

	FOREACH_ACL_ENTRY(pa, acl, pe) {
		switch (pa->e_tag) {
			case ACL_USER_OBJ:
				pas->owner = pa->e_perm;
				break;
			case ACL_GROUP_OBJ:
				pas->group = pa->e_perm;
				break;
			case ACL_USER:
				pas->users |= pa->e_perm;
				break;
			case ACL_GROUP:
				pas->groups |= pa->e_perm;
				break;
			case ACL_OTHER:
				pas->other = pa->e_perm;
				break;
			case ACL_MASK:
				pas->mask = pa->e_perm;
				break;
		}
	}
	/* We'll only care about effective permissions: */
	pas->users &= pas->mask;
	pas->group &= pas->mask;
	pas->groups &= pas->mask;
}

/* We assume the acl has been verified with posix_acl_valid. */
static void
_posix_to_nfsv4_one(struct posix_acl *pacl, struct nfs4_acl *acl,
						unsigned int flags)
{
	struct posix_acl_entry *pa, *group_owner_entry;
	struct nfs4_ace *ace;
	struct posix_acl_summary pas;
	unsigned short deny;
	int eflag = ((flags & NFS4_ACL_TYPE_DEFAULT) ?
		NFS4_INHERITANCE_FLAGS | NFS4_ACE_INHERIT_ONLY_ACE : 0);

	BUG_ON(pacl->a_count < 3);
	summarize_posix_acl(pacl, &pas);

	pa = pacl->a_entries;
	ace = acl->aces + acl->naces;

	/* We could deny everything not granted by the owner: */
	deny = ~pas.owner;
	/*
	 * but it is equivalent (and simpler) to deny only what is not
	 * granted by later entries:
	 */
	deny &= pas.users | pas.group | pas.groups | pas.other;
	if (deny) {
		ace->type = NFS4_ACE_ACCESS_DENIED_ACE_TYPE;
		ace->flag = eflag;
		ace->access_mask = deny_mask_from_posix(deny, flags);
		ace->whotype = NFS4_ACL_WHO_OWNER;
		ace++;
		acl->naces++;
	}

	ace->type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE;
	ace->flag = eflag;
	ace->access_mask = mask_from_posix(pa->e_perm, flags | NFS4_ACL_OWNER);
	ace->whotype = NFS4_ACL_WHO_OWNER;
	ace++;
	acl->naces++;
	pa++;

	while (pa->e_tag == ACL_USER) {
		deny = ~(pa->e_perm & pas.mask);
		deny &= pas.groups | pas.group | pas.other;
		if (deny) {
			ace->type = NFS4_ACE_ACCESS_DENIED_ACE_TYPE;
			ace->flag = eflag;
			ace->access_mask = deny_mask_from_posix(deny, flags);
			ace->whotype = NFS4_ACL_WHO_NAMED;
			ace->who_uid = pa->e_uid;
			ace++;
			acl->naces++;
		}
		ace->type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->flag = eflag;
		ace->access_mask = mask_from_posix(pa->e_perm & pas.mask,
						   flags);
		ace->whotype = NFS4_ACL_WHO_NAMED;
		ace->who_uid = pa->e_uid;
		ace++;
		acl->naces++;
		pa++;
	}

	/* In the case of groups, we apply allow ACEs first, then deny ACEs,
	 * since a user can be in more than one group.  */

	/* allow ACEs */

	group_owner_entry = pa;

	ace->type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE;
	ace->flag = eflag;
	ace->access_mask = mask_from_posix(pas.group, flags);
	ace->whotype = NFS4_ACL_WHO_GROUP;
	ace++;
	acl->naces++;
	pa++;

	while (pa->e_tag == ACL_GROUP) {
		ace->type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->flag = eflag | NFS4_ACE_IDENTIFIER_GROUP;
		ace->access_mask = mask_from_posix(pa->e_perm & pas.mask,
						   flags);
		ace->whotype = NFS4_ACL_WHO_NAMED;
		ace->who_gid = pa->e_gid;
		ace++;
		acl->naces++;
		pa++;
	}

	/* deny ACEs */

	pa = group_owner_entry;

	deny = ~pas.group & pas.other;
	if (deny) {
		ace->type = NFS4_ACE_ACCESS_DENIED_ACE_TYPE;
		ace->flag = eflag;
		ace->access_mask = deny_mask_from_posix(deny, flags);
		ace->whotype = NFS4_ACL_WHO_GROUP;
		ace++;
		acl->naces++;
	}
	pa++;

	while (pa->e_tag == ACL_GROUP) {
		deny = ~(pa->e_perm & pas.mask);
		deny &= pas.other;
		if (deny) {
			ace->type = NFS4_ACE_ACCESS_DENIED_ACE_TYPE;
			ace->flag = eflag | NFS4_ACE_IDENTIFIER_GROUP;
			ace->access_mask = deny_mask_from_posix(deny, flags);
			ace->whotype = NFS4_ACL_WHO_NAMED;
			ace->who_gid = pa->e_gid;
			ace++;
			acl->naces++;
		}
		pa++;
	}

	if (pa->e_tag == ACL_MASK)
		pa++;
	ace->type = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE;
	ace->flag = eflag;
	ace->access_mask = mask_from_posix(pa->e_perm, flags);
	ace->whotype = NFS4_ACL_WHO_EVERYONE;
	acl->naces++;
}

static bool
pace_gt(struct posix_acl_entry *pace1, struct posix_acl_entry *pace2)
{
	if (pace1->e_tag != pace2->e_tag)
		return pace1->e_tag > pace2->e_tag;
	if (pace1->e_tag == ACL_USER)
		return uid_gt(pace1->e_uid, pace2->e_uid);
	if (pace1->e_tag == ACL_GROUP)
		return gid_gt(pace1->e_gid, pace2->e_gid);
	return false;
}

static void
sort_pacl_range(struct posix_acl *pacl, int start, int end) {
	int sorted = 0, i;
	struct posix_acl_entry tmp;

	/* We just do a bubble sort; easy to do in place, and we're not
	 * expecting acl's to be long enough to justify anything more. */
	while (!sorted) {
		sorted = 1;
		for (i = start; i < end; i++) {
			if (pace_gt(&pacl->a_entries[i],
				    &pacl->a_entries[i+1])) {
				sorted = 0;
				tmp = pacl->a_entries[i];
				pacl->a_entries[i] = pacl->a_entries[i+1];
				pacl->a_entries[i+1] = tmp;
			}
		}
	}
}

static void
sort_pacl(struct posix_acl *pacl)
{
	/* posix_acl_valid requires that users and groups be in order
	 * by uid/gid. */
	int i, j;

	/* no users or groups */
	if (!pacl || pacl->a_count <= 4)
		return;

	i = 1;
	while (pacl->a_entries[i].e_tag == ACL_USER)
		i++;
	sort_pacl_range(pacl, 1, i-1);

	BUG_ON(pacl->a_entries[i].e_tag != ACL_GROUP_OBJ);
	j = ++i;
	while (pacl->a_entries[j].e_tag == ACL_GROUP)
		j++;
	sort_pacl_range(pacl, i, j-1);
	return;
}

/*
 * While processing the NFSv4 ACE, this maintains bitmasks representing
 * which permission bits have been allowed and which denied to a given
 * entity: */
struct posix_ace_state {
	u32 allow;
	u32 deny;
};

struct posix_user_ace_state {
	union {
		kuid_t uid;
		kgid_t gid;
	};
	struct posix_ace_state perms;
};

struct posix_ace_state_array {
	int n;
	struct posix_user_ace_state aces[];
};

/*
 * While processing the NFSv4 ACE, this maintains the partial permissions
 * calculated so far: */

struct posix_acl_state {
	int empty;
	struct posix_ace_state owner;
	struct posix_ace_state group;
	struct posix_ace_state other;
	struct posix_ace_state everyone;
	struct posix_ace_state mask; /* Deny unused in this case */
	struct posix_ace_state_array *users;
	struct posix_ace_state_array *groups;
};

static int
init_state(struct posix_acl_state *state, int cnt)
{
	int alloc;

	memset(state, 0, sizeof(struct posix_acl_state));
	state->empty = 1;
	/*
	 * In the worst case, each individual acl could be for a distinct
	 * named user or group, but we don't no which, so we allocate
	 * enough space for either:
	 */
	alloc = sizeof(struct posix_ace_state_array)
		+ cnt*sizeof(struct posix_user_ace_state);
	state->users = kzalloc(alloc, GFP_KERNEL);
	if (!state->users)
		return -ENOMEM;
	state->groups = kzalloc(alloc, GFP_KERNEL);
	if (!state->groups) {
		kfree(state->users);
		return -ENOMEM;
	}
	return 0;
}

static void
free_state(struct posix_acl_state *state) {
	kfree(state->users);
	kfree(state->groups);
}

static inline void add_to_mask(struct posix_acl_state *state, struct posix_ace_state *astate)
{
	state->mask.allow |= astate->allow;
}

/*
 * Certain bits (SYNCHRONIZE, DELETE, WRITE_OWNER, READ/WRITE_NAMED_ATTRS,
 * READ_ATTRIBUTES, READ_ACL) are currently unenforceable and don't translate
 * to traditional read/write/execute permissions.
 *
 * It's problematic to reject acls that use certain mode bits, because it
 * places the burden on users to learn the rules about which bits one
 * particular server sets, without giving the user a lot of help--we return an
 * error that could mean any number of different things.  To make matters
 * worse, the problematic bits might be introduced by some application that's
 * automatically mapping from some other acl model.
 *
 * So wherever possible we accept anything, possibly erring on the side of
 * denying more permissions than necessary.
 *
 * However we do reject *explicit* DENY's of a few bits representing
 * permissions we could never deny:
 */

static inline int check_deny(u32 mask, int isowner)
{
	if (mask & (NFS4_ACE_READ_ATTRIBUTES | NFS4_ACE_READ_ACL))
		return -EINVAL;
	if (!isowner)
		return 0;
	if (mask & (NFS4_ACE_WRITE_ATTRIBUTES | NFS4_ACE_WRITE_ACL))
		return -EINVAL;
	return 0;
}

static struct posix_acl *
posix_state_to_acl(struct posix_acl_state *state, unsigned int flags)
{
	struct posix_acl_entry *pace;
	struct posix_acl *pacl;
	int nace;
	int i, error = 0;

	/*
	 * ACLs with no ACEs are treated differently in the inheritable
	 * and effective cases: when there are no inheritable ACEs,
	 * calls ->set_acl with a NULL ACL structure.
	 */
	if (state->empty && (flags & NFS4_ACL_TYPE_DEFAULT))
		return NULL;

	/*
	 * When there are no effective ACEs, the following will end
	 * up setting a 3-element effective posix ACL with all
	 * permissions zero.
	 */
	if (!state->users->n && !state->groups->n)
		nace = 3;
	else /* Note we also include a MASK ACE in this case: */
		nace = 4 + state->users->n + state->groups->n;
	pacl = posix_acl_alloc(nace, GFP_KERNEL);
	if (!pacl)
		return ERR_PTR(-ENOMEM);

	pace = pacl->a_entries;
	pace->e_tag = ACL_USER_OBJ;
	error = check_deny(state->owner.deny, 1);
	if (error)
		goto out_err;
	low_mode_from_nfs4(state->owner.allow, &pace->e_perm, flags);

	for (i=0; i < state->users->n; i++) {
		pace++;
		pace->e_tag = ACL_USER;
		error = check_deny(state->users->aces[i].perms.deny, 0);
		if (error)
			goto out_err;
		low_mode_from_nfs4(state->users->aces[i].perms.allow,
					&pace->e_perm, flags);
		pace->e_uid = state->users->aces[i].uid;
		add_to_mask(state, &state->users->aces[i].perms);
	}

	pace++;
	pace->e_tag = ACL_GROUP_OBJ;
	error = check_deny(state->group.deny, 0);
	if (error)
		goto out_err;
	low_mode_from_nfs4(state->group.allow, &pace->e_perm, flags);
	add_to_mask(state, &state->group);

	for (i=0; i < state->groups->n; i++) {
		pace++;
		pace->e_tag = ACL_GROUP;
		error = check_deny(state->groups->aces[i].perms.deny, 0);
		if (error)
			goto out_err;
		low_mode_from_nfs4(state->groups->aces[i].perms.allow,
					&pace->e_perm, flags);
		pace->e_gid = state->groups->aces[i].gid;
		add_to_mask(state, &state->groups->aces[i].perms);
	}

	if (state->users->n || state->groups->n) {
		pace++;
		pace->e_tag = ACL_MASK;
		low_mode_from_nfs4(state->mask.allow, &pace->e_perm, flags);
	}

	pace++;
	pace->e_tag = ACL_OTHER;
	error = check_deny(state->other.deny, 0);
	if (error)
		goto out_err;
	low_mode_from_nfs4(state->other.allow, &pace->e_perm, flags);

	return pacl;
out_err:
	posix_acl_release(pacl);
	return ERR_PTR(error);
}

static inline void allow_bits(struct posix_ace_state *astate, u32 mask)
{
	/* Allow all bits in the mask not already denied: */
	astate->allow |= mask & ~astate->deny;
}

static inline void deny_bits(struct posix_ace_state *astate, u32 mask)
{
	/* Deny all bits in the mask not already allowed: */
	astate->deny |= mask & ~astate->allow;
}

static int find_uid(struct posix_acl_state *state, kuid_t uid)
{
	struct posix_ace_state_array *a = state->users;
	int i;

	for (i = 0; i < a->n; i++)
		if (uid_eq(a->aces[i].uid, uid))
			return i;
	/* Not found: */
	a->n++;
	a->aces[i].uid = uid;
	a->aces[i].perms.allow = state->everyone.allow;
	a->aces[i].perms.deny  = state->everyone.deny;

	return i;
}

static int find_gid(struct posix_acl_state *state, kgid_t gid)
{
	struct posix_ace_state_array *a = state->groups;
	int i;

	for (i = 0; i < a->n; i++)
		if (gid_eq(a->aces[i].gid, gid))
			return i;
	/* Not found: */
	a->n++;
	a->aces[i].gid = gid;
	a->aces[i].perms.allow = state->everyone.allow;
	a->aces[i].perms.deny  = state->everyone.deny;

	return i;
}

static void deny_bits_array(struct posix_ace_state_array *a, u32 mask)
{
	int i;

	for (i=0; i < a->n; i++)
		deny_bits(&a->aces[i].perms, mask);
}

static void allow_bits_array(struct posix_ace_state_array *a, u32 mask)
{
	int i;

	for (i=0; i < a->n; i++)
		allow_bits(&a->aces[i].perms, mask);
}

static void process_one_v4_ace(struct posix_acl_state *state,
				struct nfs4_ace *ace)
{
	u32 mask = ace->access_mask;
	int i;

	state->empty = 0;

	switch (ace2type(ace)) {
	case ACL_USER_OBJ:
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->owner, mask);
		} else {
			deny_bits(&state->owner, mask);
		}
		break;
	case ACL_USER:
		i = find_uid(state, ace->who_uid);
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->users->aces[i].perms, mask);
		} else {
			deny_bits(&state->users->aces[i].perms, mask);
			mask = state->users->aces[i].perms.deny;
			deny_bits(&state->owner, mask);
		}
		break;
	case ACL_GROUP_OBJ:
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->group, mask);
		} else {
			deny_bits(&state->group, mask);
			mask = state->group.deny;
			deny_bits(&state->owner, mask);
			deny_bits(&state->everyone, mask);
			deny_bits_array(state->users, mask);
			deny_bits_array(state->groups, mask);
		}
		break;
	case ACL_GROUP:
		i = find_gid(state, ace->who_gid);
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->groups->aces[i].perms, mask);
		} else {
			deny_bits(&state->groups->aces[i].perms, mask);
			mask = state->groups->aces[i].perms.deny;
			deny_bits(&state->owner, mask);
			deny_bits(&state->group, mask);
			deny_bits(&state->everyone, mask);
			deny_bits_array(state->users, mask);
			deny_bits_array(state->groups, mask);
		}
		break;
	case ACL_OTHER:
		if (ace->type == NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE) {
			allow_bits(&state->owner, mask);
			allow_bits(&state->group, mask);
			allow_bits(&state->other, mask);
			allow_bits(&state->everyone, mask);
			allow_bits_array(state->users, mask);
			allow_bits_array(state->groups, mask);
		} else {
			deny_bits(&state->owner, mask);
			deny_bits(&state->group, mask);
			deny_bits(&state->other, mask);
			deny_bits(&state->everyone, mask);
			deny_bits_array(state->users, mask);
			deny_bits_array(state->groups, mask);
		}
	}
}

static int nfs4_acl_nfsv4_to_posix(struct nfs4_acl *acl,
		struct posix_acl **pacl, struct posix_acl **dpacl,
		unsigned int flags)
{
	struct posix_acl_state effective_acl_state, default_acl_state;
	struct nfs4_ace *ace;
	int ret;

	ret = init_state(&effective_acl_state, acl->naces);
	if (ret)
		return ret;
	ret = init_state(&default_acl_state, acl->naces);
	if (ret)
		goto out_estate;
	ret = -EINVAL;
	for (ace = acl->aces; ace < acl->aces + acl->naces; ace++) {
		if (ace->type != NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE &&
		    ace->type != NFS4_ACE_ACCESS_DENIED_ACE_TYPE)
			goto out_dstate;
		if (ace->flag & ~NFS4_SUPPORTED_FLAGS)
			goto out_dstate;
		if ((ace->flag & NFS4_INHERITANCE_FLAGS) == 0) {
			process_one_v4_ace(&effective_acl_state, ace);
			continue;
		}
		if (!(flags & NFS4_ACL_DIR))
			goto out_dstate;
		/*
		 * Note that when only one of FILE_INHERIT or DIRECTORY_INHERIT
		 * is set, we're effectively turning on the other.  That's OK,
		 * according to rfc 3530.
		 */
		process_one_v4_ace(&default_acl_state, ace);

		if (!(ace->flag & NFS4_ACE_INHERIT_ONLY_ACE))
			process_one_v4_ace(&effective_acl_state, ace);
	}
	*pacl = posix_state_to_acl(&effective_acl_state, flags);
	if (IS_ERR(*pacl)) {
		ret = PTR_ERR(*pacl);
		*pacl = NULL;
		goto out_dstate;
	}
	*dpacl = posix_state_to_acl(&default_acl_state,
						flags | NFS4_ACL_TYPE_DEFAULT);
	if (IS_ERR(*dpacl)) {
		ret = PTR_ERR(*dpacl);
		*dpacl = NULL;
		posix_acl_release(*pacl);
		*pacl = NULL;
		goto out_dstate;
	}
	sort_pacl(*pacl);
	sort_pacl(*dpacl);
	ret = 0;
out_dstate:
	free_state(&default_acl_state);
out_estate:
	free_state(&effective_acl_state);
	return ret;
}

__be32
nfsd4_set_nfs4_acl(struct svc_rqst *rqstp, struct svc_fh *fhp,
		struct nfs4_acl *acl)
{
	__be32 error;
	int host_error;
	struct dentry *dentry;
	struct inode *inode;
	struct posix_acl *pacl = NULL, *dpacl = NULL;
	unsigned int flags = 0;

	/* Get inode */
	error = fh_verify(rqstp, fhp, 0, NFSD_MAY_SATTR);
	if (error)
		return error;

	dentry = fhp->fh_dentry;
	inode = dentry->d_inode;

	if (!inode->i_op->set_acl || !IS_POSIXACL(inode))
		return nfserr_attrnotsupp;

	if (S_ISDIR(inode->i_mode))
		flags = NFS4_ACL_DIR;

	host_error = nfs4_acl_nfsv4_to_posix(acl, &pacl, &dpacl, flags);
	if (host_error == -EINVAL)
		return nfserr_attrnotsupp;
	if (host_error < 0)
		goto out_nfserr;

	host_error = inode->i_op->set_acl(inode, pacl, ACL_TYPE_ACCESS);
	if (host_error < 0)
		goto out_release;

	if (S_ISDIR(inode->i_mode)) {
		host_error = inode->i_op->set_acl(inode, dpacl,
						  ACL_TYPE_DEFAULT);
	}

out_release:
	posix_acl_release(pacl);
	posix_acl_release(dpacl);
out_nfserr:
	if (host_error == -EOPNOTSUPP)
		return nfserr_attrnotsupp;
	else
		return nfserrno(host_error);
}


static short
ace2type(struct nfs4_ace *ace)
{
	switch (ace->whotype) {
		case NFS4_ACL_WHO_NAMED:
			return (ace->flag & NFS4_ACE_IDENTIFIER_GROUP ?
					ACL_GROUP : ACL_USER);
		case NFS4_ACL_WHO_OWNER:
			return ACL_USER_OBJ;
		case NFS4_ACL_WHO_GROUP:
			return ACL_GROUP_OBJ;
		case NFS4_ACL_WHO_EVERYONE:
			return ACL_OTHER;
	}
	BUG();
	return -1;
}

/*
 * return the size of the struct nfs4_acl required to represent an acl
 * with @entries entries.
 */
int nfs4_acl_bytes(int entries)
{
	return sizeof(struct nfs4_acl) + entries * sizeof(struct nfs4_ace);
}

static struct {
	char *string;
	int   stringlen;
	int type;
} s2t_map[] = {
	{
		.string    = "OWNER@",
		.stringlen = sizeof("OWNER@") - 1,
		.type      = NFS4_ACL_WHO_OWNER,
	},
	{
		.string    = "GROUP@",
		.stringlen = sizeof("GROUP@") - 1,
		.type      = NFS4_ACL_WHO_GROUP,
	},
	{
		.string    = "EVERYONE@",
		.stringlen = sizeof("EVERYONE@") - 1,
		.type      = NFS4_ACL_WHO_EVERYONE,
	},
};

int
nfs4_acl_get_whotype(char *p, u32 len)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(s2t_map); i++) {
		if (s2t_map[i].stringlen == len &&
				0 == memcmp(s2t_map[i].string, p, len))
			return s2t_map[i].type;
	}
	return NFS4_ACL_WHO_NAMED;
}

__be32 nfs4_acl_write_who(struct xdr_stream *xdr, int who)
{
	__be32 *p;
	int i;

	for (i = 0; i < ARRAY_SIZE(s2t_map); i++) {
		if (s2t_map[i].type != who)
			continue;
		p = xdr_reserve_space(xdr, s2t_map[i].stringlen + 4);
		if (!p)
			return nfserr_resource;
		p = xdr_encode_opaque(p, s2t_map[i].string,
					s2t_map[i].stringlen);
		return 0;
	}
	WARN_ON_ONCE(1);
	return nfserr_serverfault;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs4acl.c */
/************************************************************/
/*
 *  Copyright (c) 2001 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Kendrick Smith <kmsmith@umich.edu>
 *  Andy Adamson <andros@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/xprt.h>
// #include <linux/sunrpc/svc_xprt.h>
// #include <linux/slab.h>
// #include "nfsd.h"
// #include "state.h"
// #include "netns.h"
// #include "xdr4cb.h"
#include "../../inc/__fss.h"

#define NFSDDBG_FACILITY                NFSDDBG_PROC

static void nfsd4_mark_cb_fault(struct nfs4_client *, int reason);

#define NFSPROC4_CB_NULL 0
#define NFSPROC4_CB_COMPOUND 1

/* Index of predefined Linux callback client operations */

struct nfs4_cb_compound_hdr {
	/* args */
	u32		ident;	/* minorversion 0 only */
	u32		nops;
	__be32		*nops_p;
	u32		minorversion;
	/* res */
	int		status;
};

/*
 * Handle decode buffer overflows out-of-line.
 */
static void print_overflow_msg(const char *func, const struct xdr_stream *xdr)
{
	dprintk("NFS: %s prematurely hit the end of our receive buffer. "
		"Remaining buffer length is %tu words.\n",
		func, xdr->end - xdr->p);
}

static __be32 *xdr_encode_empty_array(__be32 *p)
{
	*p++ = xdr_zero;
	return p;
}

/*
 * Encode/decode NFSv4 CB basic data types
 *
 * Basic NFSv4 callback data types are defined in section 15 of RFC
 * 3530: "Network File System (NFS) version 4 Protocol" and section
 * 20 of RFC 5661: "Network File System (NFS) Version 4 Minor Version
 * 1 Protocol"
 */

/*
 *	nfs_cb_opnum4
 *
 *	enum nfs_cb_opnum4 {
 *		OP_CB_GETATTR		= 3,
 *		  ...
 *	};
 */
enum nfs_cb_opnum4 {
	OP_CB_GETATTR			= 3,
	OP_CB_RECALL			= 4,
	OP_CB_LAYOUTRECALL		= 5,
	OP_CB_NOTIFY			= 6,
	OP_CB_PUSH_DELEG		= 7,
	OP_CB_RECALL_ANY		= 8,
	OP_CB_RECALLABLE_OBJ_AVAIL	= 9,
	OP_CB_RECALL_SLOT		= 10,
	OP_CB_SEQUENCE			= 11,
	OP_CB_WANTS_CANCELLED		= 12,
	OP_CB_NOTIFY_LOCK		= 13,
	OP_CB_NOTIFY_DEVICEID		= 14,
	OP_CB_ILLEGAL			= 10044
};

static void encode_nfs_cb_opnum4(struct xdr_stream *xdr, enum nfs_cb_opnum4 op)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, 4);
	*p = cpu_to_be32(op);
}

/*
 * nfs_fh4
 *
 *	typedef opaque nfs_fh4<NFS4_FHSIZE>;
 */
static void encode_nfs_fh4(struct xdr_stream *xdr, const struct knfsd_fh *fh)
{
	u32 length = fh->fh_size;
	__be32 *p;

	BUG_ON(length > NFS4_FHSIZE);
	p = xdr_reserve_space(xdr, 4 + length);
	xdr_encode_opaque(p, &fh->fh_base, length);
}

/*
 * stateid4
 *
 *	struct stateid4 {
 *		uint32_t	seqid;
 *		opaque		other[12];
 *	};
 */
static void encode_stateid4(struct xdr_stream *xdr, const stateid_t *sid)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, NFS4_STATEID_SIZE);
	*p++ = cpu_to_be32(sid->si_generation);
	xdr_encode_opaque_fixed(p, &sid->si_opaque, NFS4_STATEID_OTHER_SIZE);
}

/*
 * sessionid4
 *
 *	typedef opaque sessionid4[NFS4_SESSIONID_SIZE];
 */
static void encode_sessionid4(struct xdr_stream *xdr,
			      const struct nfsd4_session *session)
{
	__be32 *p;

	p = xdr_reserve_space(xdr, NFS4_MAX_SESSIONID_LEN);
	xdr_encode_opaque_fixed(p, session->se_sessionid.data,
					NFS4_MAX_SESSIONID_LEN);
}

/*
 * nfsstat4
 */
static const struct {
	int stat;
	int errno;
} nfs_cb_errtbl[] = {
	{ NFS4_OK,		0		},
	{ NFS4ERR_PERM,		-EPERM		},
	{ NFS4ERR_NOENT,	-ENOENT		},
	{ NFS4ERR_IO,		-EIO		},
	{ NFS4ERR_NXIO,		-ENXIO		},
	{ NFS4ERR_ACCESS,	-EACCES		},
	{ NFS4ERR_EXIST,	-EEXIST		},
	{ NFS4ERR_XDEV,		-EXDEV		},
	{ NFS4ERR_NOTDIR,	-ENOTDIR	},
	{ NFS4ERR_ISDIR,	-EISDIR		},
	{ NFS4ERR_INVAL,	-EINVAL		},
	{ NFS4ERR_FBIG,		-EFBIG		},
	{ NFS4ERR_NOSPC,	-ENOSPC		},
	{ NFS4ERR_ROFS,		-EROFS		},
	{ NFS4ERR_MLINK,	-EMLINK		},
	{ NFS4ERR_NAMETOOLONG,	-ENAMETOOLONG	},
	{ NFS4ERR_NOTEMPTY,	-ENOTEMPTY	},
	{ NFS4ERR_DQUOT,	-EDQUOT		},
	{ NFS4ERR_STALE,	-ESTALE		},
	{ NFS4ERR_BADHANDLE,	-EBADHANDLE	},
	{ NFS4ERR_BAD_COOKIE,	-EBADCOOKIE	},
	{ NFS4ERR_NOTSUPP,	-ENOTSUPP	},
	{ NFS4ERR_TOOSMALL,	-ETOOSMALL	},
	{ NFS4ERR_SERVERFAULT,	-ESERVERFAULT	},
	{ NFS4ERR_BADTYPE,	-EBADTYPE	},
	{ NFS4ERR_LOCKED,	-EAGAIN		},
	{ NFS4ERR_RESOURCE,	-EREMOTEIO	},
	{ NFS4ERR_SYMLINK,	-ELOOP		},
	{ NFS4ERR_OP_ILLEGAL,	-EOPNOTSUPP	},
	{ NFS4ERR_DEADLOCK,	-EDEADLK	},
	{ -1,			-EIO		}
};

/*
 * If we cannot translate the error, the recovery routines should
 * handle it.
 *
 * Note: remaining NFSv4 error codes have values > 10000, so should
 * not conflict with native Linux error codes.
 */
static int nfs_cb_stat_to_errno(int status)
{
	int i;

	for (i = 0; nfs_cb_errtbl[i].stat != -1; i++) {
		if (nfs_cb_errtbl[i].stat == status)
			return nfs_cb_errtbl[i].errno;
	}

	dprintk("NFSD: Unrecognized NFS CB status value: %u\n", status);
	return -status;
}

static int decode_cb_op_status(struct xdr_stream *xdr, enum nfs_opnum4 expected,
			       enum nfsstat4 *status)
{
	__be32 *p;
	u32 op;

	p = xdr_inline_decode(xdr, 4 + 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	op = be32_to_cpup(p++);
	if (unlikely(op != expected))
		goto out_unexpected;
	*status = be32_to_cpup(p);
	return 0;
out_overflow:
	print_overflow_msg(__func__, xdr);
	return -EIO;
out_unexpected:
	dprintk("NFSD: Callback server returned operation %d but "
		"we issued a request for %d\n", op, expected);
	return -EIO;
}

/*
 * CB_COMPOUND4args
 *
 *	struct CB_COMPOUND4args {
 *		utf8str_cs	tag;
 *		uint32_t	minorversion;
 *		uint32_t	callback_ident;
 *		nfs_cb_argop4	argarray<>;
 *	};
*/
static void encode_cb_compound4args(struct xdr_stream *xdr,
				    struct nfs4_cb_compound_hdr *hdr)
{
	__be32 * p;

	p = xdr_reserve_space(xdr, 4 + 4 + 4 + 4);
	p = xdr_encode_empty_array(p);		/* empty tag */
	*p++ = cpu_to_be32(hdr->minorversion);
	*p++ = cpu_to_be32(hdr->ident);

	hdr->nops_p = p;
	*p = cpu_to_be32(hdr->nops);		/* argarray element count */
}

/*
 * Update argarray element count
 */
static void encode_cb_nops(struct nfs4_cb_compound_hdr *hdr)
{
	BUG_ON(hdr->nops > NFS4_MAX_BACK_CHANNEL_OPS);
	*hdr->nops_p = cpu_to_be32(hdr->nops);
}

/*
 * CB_COMPOUND4res
 *
 *	struct CB_COMPOUND4res {
 *		nfsstat4	status;
 *		utf8str_cs	tag;
 *		nfs_cb_resop4	resarray<>;
 *	};
 */
static int decode_cb_compound4res(struct xdr_stream *xdr,
				  struct nfs4_cb_compound_hdr *hdr)
{
	u32 length;
	__be32 *p;

	p = xdr_inline_decode(xdr, 4 + 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	hdr->status = be32_to_cpup(p++);
	/* Ignore the tag */
	length = be32_to_cpup(p++);
	p = xdr_inline_decode(xdr, length + 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	hdr->nops = be32_to_cpup(p);
	return 0;
out_overflow:
	print_overflow_msg(__func__, xdr);
	return -EIO;
}

/*
 * CB_RECALL4args
 *
 *	struct CB_RECALL4args {
 *		stateid4	stateid;
 *		bool		truncate;
 *		nfs_fh4		fh;
 *	};
 */
static void encode_cb_recall4args(struct xdr_stream *xdr,
				  const struct nfs4_delegation *dp,
				  struct nfs4_cb_compound_hdr *hdr)
{
	__be32 *p;

	encode_nfs_cb_opnum4(xdr, OP_CB_RECALL);
	encode_stateid4(xdr, &dp->dl_stid.sc_stateid);

	p = xdr_reserve_space(xdr, 4);
	*p++ = xdr_zero;			/* truncate */

	encode_nfs_fh4(xdr, &dp->dl_stid.sc_file->fi_fhandle);

	hdr->nops++;
}

/*
 * CB_SEQUENCE4args
 *
 *	struct CB_SEQUENCE4args {
 *		sessionid4		csa_sessionid;
 *		sequenceid4		csa_sequenceid;
 *		slotid4			csa_slotid;
 *		slotid4			csa_highest_slotid;
 *		bool			csa_cachethis;
 *		referring_call_list4	csa_referring_call_lists<>;
 *	};
 */
static void encode_cb_sequence4args(struct xdr_stream *xdr,
				    const struct nfsd4_callback *cb,
				    struct nfs4_cb_compound_hdr *hdr)
{
	struct nfsd4_session *session = cb->cb_clp->cl_cb_session;
	__be32 *p;

	if (hdr->minorversion == 0)
		return;

	encode_nfs_cb_opnum4(xdr, OP_CB_SEQUENCE);
	encode_sessionid4(xdr, session);

	p = xdr_reserve_space(xdr, 4 + 4 + 4 + 4 + 4);
	*p++ = cpu_to_be32(session->se_cb_seq_nr);	/* csa_sequenceid */
	*p++ = xdr_zero;			/* csa_slotid */
	*p++ = xdr_zero;			/* csa_highest_slotid */
	*p++ = xdr_zero;			/* csa_cachethis */
	xdr_encode_empty_array(p);		/* csa_referring_call_lists */

	hdr->nops++;
}

/*
 * CB_SEQUENCE4resok
 *
 *	struct CB_SEQUENCE4resok {
 *		sessionid4	csr_sessionid;
 *		sequenceid4	csr_sequenceid;
 *		slotid4		csr_slotid;
 *		slotid4		csr_highest_slotid;
 *		slotid4		csr_target_highest_slotid;
 *	};
 *
 *	union CB_SEQUENCE4res switch (nfsstat4 csr_status) {
 *	case NFS4_OK:
 *		CB_SEQUENCE4resok	csr_resok4;
 *	default:
 *		void;
 *	};
 *
 * Our current back channel implmentation supports a single backchannel
 * with a single slot.
 */
static int decode_cb_sequence4resok(struct xdr_stream *xdr,
				    struct nfsd4_callback *cb)
{
	struct nfsd4_session *session = cb->cb_clp->cl_cb_session;
	struct nfs4_sessionid id;
	int status;
	__be32 *p;
	u32 dummy;

	status = -ESERVERFAULT;

	/*
	 * If the server returns different values for sessionID, slotID or
	 * sequence number, the server is looney tunes.
	 */
	p = xdr_inline_decode(xdr, NFS4_MAX_SESSIONID_LEN + 4 + 4 + 4 + 4);
	if (unlikely(p == NULL))
		goto out_overflow;
	memcpy(id.data, p, NFS4_MAX_SESSIONID_LEN);
	if (memcmp(id.data, session->se_sessionid.data,
					NFS4_MAX_SESSIONID_LEN) != 0) {
		dprintk("NFS: %s Invalid session id\n", __func__);
		goto out;
	}
	p += XDR_QUADLEN(NFS4_MAX_SESSIONID_LEN);

	dummy = be32_to_cpup(p++);
	if (dummy != session->se_cb_seq_nr) {
		dprintk("NFS: %s Invalid sequence number\n", __func__);
		goto out;
	}

	dummy = be32_to_cpup(p++);
	if (dummy != 0) {
		dprintk("NFS: %s Invalid slotid\n", __func__);
		goto out;
	}

	/*
	 * FIXME: process highest slotid and target highest slotid
	 */
	status = 0;
out:
	if (status)
		nfsd4_mark_cb_fault(cb->cb_clp, status);
	return status;
out_overflow:
	print_overflow_msg(__func__, xdr);
	return -EIO;
}

static int decode_cb_sequence4res(struct xdr_stream *xdr,
				  struct nfsd4_callback *cb)
{
	enum nfsstat4 nfserr;
	int status;

	if (cb->cb_minorversion == 0)
		return 0;

	status = decode_cb_op_status(xdr, OP_CB_SEQUENCE, &nfserr);
	if (unlikely(status))
		goto out;
	if (unlikely(nfserr != NFS4_OK))
		goto out_default;
	status = decode_cb_sequence4resok(xdr, cb);
out:
	return status;
out_default:
	return nfs_cb_stat_to_errno(nfserr);
}

/*
 * NFSv4.0 and NFSv4.1 XDR encode functions
 *
 * NFSv4.0 callback argument types are defined in section 15 of RFC
 * 3530: "Network File System (NFS) version 4 Protocol" and section 20
 * of RFC 5661:  "Network File System (NFS) Version 4 Minor Version 1
 * Protocol".
 */

/*
 * NB: Without this zero space reservation, callbacks over krb5p fail
 */
static void nfs4_xdr_enc_cb_null(struct rpc_rqst *req, struct xdr_stream *xdr,
				 void *__unused)
{
	xdr_reserve_space(xdr, 0);
}

/*
 * 20.2. Operation 4: CB_RECALL - Recall a Delegation
 */
static void nfs4_xdr_enc_cb_recall(struct rpc_rqst *req, struct xdr_stream *xdr,
				   const struct nfsd4_callback *cb)
{
	const struct nfs4_delegation *dp = cb_to_delegation(cb);
	struct nfs4_cb_compound_hdr hdr = {
		.ident = cb->cb_clp->cl_cb_ident,
		.minorversion = cb->cb_minorversion,
	};

	encode_cb_compound4args(xdr, &hdr);
	encode_cb_sequence4args(xdr, cb, &hdr);
	encode_cb_recall4args(xdr, dp, &hdr);
	encode_cb_nops(&hdr);
}


/*
 * NFSv4.0 and NFSv4.1 XDR decode functions
 *
 * NFSv4.0 callback result types are defined in section 15 of RFC
 * 3530: "Network File System (NFS) version 4 Protocol" and section 20
 * of RFC 5661:  "Network File System (NFS) Version 4 Minor Version 1
 * Protocol".
 */

static int nfs4_xdr_dec_cb_null(struct rpc_rqst *req, struct xdr_stream *xdr,
				void *__unused)
{
	return 0;
}

/*
 * 20.2. Operation 4: CB_RECALL - Recall a Delegation
 */
static int nfs4_xdr_dec_cb_recall(struct rpc_rqst *rqstp,
				  struct xdr_stream *xdr,
				  struct nfsd4_callback *cb)
{
	struct nfs4_cb_compound_hdr hdr;
	enum nfsstat4 nfserr;
	int status;

	status = decode_cb_compound4res(xdr, &hdr);
	if (unlikely(status))
		goto out;

	if (cb != NULL) {
		status = decode_cb_sequence4res(xdr, cb);
		if (unlikely(status))
			goto out;
	}

	status = decode_cb_op_status(xdr, OP_CB_RECALL, &nfserr);
	if (unlikely(status))
		goto out;
	if (unlikely(nfserr != NFS4_OK))
		status = nfs_cb_stat_to_errno(nfserr);
out:
	return status;
}

#ifdef CONFIG_NFSD_PNFS
/*
 * CB_LAYOUTRECALL4args
 *
 *	struct layoutrecall_file4 {
 *		nfs_fh4         lor_fh;
 *		offset4         lor_offset;
 *		length4         lor_length;
 *		stateid4        lor_stateid;
 *	};
 *
 *	union layoutrecall4 switch(layoutrecall_type4 lor_recalltype) {
 *	case LAYOUTRECALL4_FILE:
 *		layoutrecall_file4 lor_layout;
 *	case LAYOUTRECALL4_FSID:
 *		fsid4              lor_fsid;
 *	case LAYOUTRECALL4_ALL:
 *		void;
 *	};
 *
 *	struct CB_LAYOUTRECALL4args {
 *		layouttype4             clora_type;
 *		layoutiomode4           clora_iomode;
 *		bool                    clora_changed;
 *		layoutrecall4           clora_recall;
 *	};
 */
static void encode_cb_layout4args(struct xdr_stream *xdr,
				  const struct nfs4_layout_stateid *ls,
				  struct nfs4_cb_compound_hdr *hdr)
{
	__be32 *p;

	BUG_ON(hdr->minorversion == 0);

	p = xdr_reserve_space(xdr, 5 * 4);
	*p++ = cpu_to_be32(OP_CB_LAYOUTRECALL);
	*p++ = cpu_to_be32(ls->ls_layout_type);
	*p++ = cpu_to_be32(IOMODE_ANY);
	*p++ = cpu_to_be32(1);
	*p = cpu_to_be32(RETURN_FILE);

	encode_nfs_fh4(xdr, &ls->ls_stid.sc_file->fi_fhandle);

	p = xdr_reserve_space(xdr, 2 * 8);
	p = xdr_encode_hyper(p, 0);
	xdr_encode_hyper(p, NFS4_MAX_UINT64);

	encode_stateid4(xdr, &ls->ls_recall_sid);

	hdr->nops++;
}

static void nfs4_xdr_enc_cb_layout(struct rpc_rqst *req,
				   struct xdr_stream *xdr,
				   const struct nfsd4_callback *cb)
{
	const struct nfs4_layout_stateid *ls =
		container_of(cb, struct nfs4_layout_stateid, ls_recall);
	struct nfs4_cb_compound_hdr hdr = {
		.ident = 0,
		.minorversion = cb->cb_minorversion,
	};

	encode_cb_compound4args(xdr, &hdr);
	encode_cb_sequence4args(xdr, cb, &hdr);
	encode_cb_layout4args(xdr, ls, &hdr);
	encode_cb_nops(&hdr);
}

static int nfs4_xdr_dec_cb_layout(struct rpc_rqst *rqstp,
				  struct xdr_stream *xdr,
				  struct nfsd4_callback *cb)
{
	struct nfs4_cb_compound_hdr hdr;
	enum nfsstat4 nfserr;
	int status;

	status = decode_cb_compound4res(xdr, &hdr);
	if (unlikely(status))
		goto out;
	if (cb) {
		status = decode_cb_sequence4res(xdr, cb);
		if (unlikely(status))
			goto out;
	}
	status = decode_cb_op_status(xdr, OP_CB_LAYOUTRECALL, &nfserr);
	if (unlikely(status))
		goto out;
	if (unlikely(nfserr != NFS4_OK))
		status = nfs_cb_stat_to_errno(nfserr);
out:
	return status;
}
#endif /* CONFIG_NFSD_PNFS */

/*
 * RPC procedure tables
 */
#define PROC(proc, call, argtype, restype)				\
[NFSPROC4_CLNT_##proc] = {						\
	.p_proc    = NFSPROC4_CB_##call,				\
	.p_encode  = (kxdreproc_t)nfs4_xdr_enc_##argtype,		\
	.p_decode  = (kxdrdproc_t)nfs4_xdr_dec_##restype,		\
	.p_arglen  = NFS4_enc_##argtype##_sz,				\
	.p_replen  = NFS4_dec_##restype##_sz,				\
	.p_statidx = NFSPROC4_CB_##call,				\
	.p_name    = #proc,						\
}

static struct rpc_procinfo nfs4_cb_procedures[] = {
	PROC(CB_NULL,	NULL,		cb_null,	cb_null),
	PROC(CB_RECALL,	COMPOUND,	cb_recall,	cb_recall),
#ifdef CONFIG_NFSD_PNFS
	PROC(CB_LAYOUT,	COMPOUND,	cb_layout,	cb_layout),
#endif
};

static struct rpc_version nfs_cb_version4 = {
/*
 * Note on the callback rpc program version number: despite language in rfc
 * 5661 section 18.36.3 requiring servers to use 4 in this field, the
 * official xdr descriptions for both 4.0 and 4.1 specify version 1, and
 * in practice that appears to be what implementations use.  The section
 * 18.36.3 language is expected to be fixed in an erratum.
 */
	.number			= 1,
	.nrprocs		= ARRAY_SIZE(nfs4_cb_procedures),
	.procs			= nfs4_cb_procedures
};

static const struct rpc_version *nfs_cb_version[] = {
	&nfs_cb_version4,
};

static const struct rpc_program cb_program;

static struct rpc_stat cb_stats = {
	.program		= &cb_program
};

#define NFS4_CALLBACK 0x40000000
static const struct rpc_program cb_program = {
	.name			= "nfs4_cb",
	.number			= NFS4_CALLBACK,
	.nrvers			= ARRAY_SIZE(nfs_cb_version),
	.version		= nfs_cb_version,
	.stats			= &cb_stats,
	.pipe_dir_name		= "nfsd4_cb",
};

static int max_cb_time(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	return max(nn->nfsd4_lease/10, (time_t)1) * HZ;
}

static struct rpc_cred *callback_cred;

int set_callback_cred(void)
{
	if (callback_cred)
		return 0;
	callback_cred = rpc_lookup_machine_cred("nfs");
	if (!callback_cred)
		return -ENOMEM;
	return 0;
}

static struct rpc_cred *get_backchannel_cred(struct nfs4_client *clp, struct rpc_clnt *client, struct nfsd4_session *ses)
{
	if (clp->cl_minorversion == 0) {
		return get_rpccred(callback_cred);
	} else {
		struct rpc_auth *auth = client->cl_auth;
		struct auth_cred acred = {};

		acred.uid = ses->se_cb_sec.uid;
		acred.gid = ses->se_cb_sec.gid;
		return auth->au_ops->lookup_cred(client->cl_auth, &acred, 0);
	}
}

static struct rpc_clnt *create_backchannel_client(struct rpc_create_args *args)
{
	struct rpc_xprt *xprt;

	if (args->protocol != XPRT_TRANSPORT_BC_TCP)
		return rpc_create(args);

	xprt = args->bc_xprt->xpt_bc_xprt;
	if (xprt) {
		xprt_get(xprt);
		return rpc_create_xprt(args, xprt);
	}

	return rpc_create(args);
}

static int setup_callback_client(struct nfs4_client *clp, struct nfs4_cb_conn *conn, struct nfsd4_session *ses)
{
	int maxtime = max_cb_time(clp->net);
	struct rpc_timeout	timeparms = {
		.to_initval	= maxtime,
		.to_retries	= 0,
		.to_maxval	= maxtime,
	};
	struct rpc_create_args args = {
		.net		= clp->net,
		.address	= (struct sockaddr *) &conn->cb_addr,
		.addrsize	= conn->cb_addrlen,
		.saddress	= (struct sockaddr *) &conn->cb_saddr,
		.timeout	= &timeparms,
		.program	= &cb_program,
		.version	= 0,
		.flags		= (RPC_CLNT_CREATE_NOPING | RPC_CLNT_CREATE_QUIET),
	};
	struct rpc_clnt *client;
	struct rpc_cred *cred;

	if (clp->cl_minorversion == 0) {
		if (!clp->cl_cred.cr_principal &&
				(clp->cl_cred.cr_flavor >= RPC_AUTH_GSS_KRB5))
			return -EINVAL;
		args.client_name = clp->cl_cred.cr_principal;
		args.prognumber	= conn->cb_prog;
		args.protocol = XPRT_TRANSPORT_TCP;
		args.authflavor = clp->cl_cred.cr_flavor;
		clp->cl_cb_ident = conn->cb_ident;
	} else {
		if (!conn->cb_xprt)
			return -EINVAL;
		clp->cl_cb_conn.cb_xprt = conn->cb_xprt;
		clp->cl_cb_session = ses;
		args.bc_xprt = conn->cb_xprt;
		args.prognumber = clp->cl_cb_session->se_cb_prog;
		args.protocol = conn->cb_xprt->xpt_class->xcl_ident |
				XPRT_TRANSPORT_BC;
		args.authflavor = ses->se_cb_sec.flavor;
	}
	/* Create RPC client */
	client = create_backchannel_client(&args);
	if (IS_ERR(client)) {
		dprintk("NFSD: couldn't create callback client: %ld\n",
			PTR_ERR(client));
		return PTR_ERR(client);
	}
	cred = get_backchannel_cred(clp, client, ses);
	if (IS_ERR(cred)) {
		rpc_shutdown_client(client);
		return PTR_ERR(cred);
	}
	clp->cl_cb_client = client;
	clp->cl_cb_cred = cred;
	return 0;
}

static void warn_no_callback_path(struct nfs4_client *clp, int reason)
{
	dprintk("NFSD: warning: no callback path to client %.*s: error %d\n",
		(int)clp->cl_name.len, clp->cl_name.data, reason);
}

static void nfsd4_mark_cb_down(struct nfs4_client *clp, int reason)
{
	clp->cl_cb_state = NFSD4_CB_DOWN;
	warn_no_callback_path(clp, reason);
}

static void nfsd4_mark_cb_fault(struct nfs4_client *clp, int reason)
{
	clp->cl_cb_state = NFSD4_CB_FAULT;
	warn_no_callback_path(clp, reason);
}

static void nfsd4_cb_probe_done(struct rpc_task *task, void *calldata)
{
	struct nfs4_client *clp = container_of(calldata, struct nfs4_client, cl_cb_null);

	if (task->tk_status)
		nfsd4_mark_cb_down(clp, task->tk_status);
	else
		clp->cl_cb_state = NFSD4_CB_UP;
}

static const struct rpc_call_ops nfsd4_cb_probe_ops = {
	/* XXX: release method to ensure we set the cb channel down if
	 * necessary on early failure? */
	.rpc_call_done = nfsd4_cb_probe_done,
};

static struct workqueue_struct *callback_wq;

/*
 * Poke the callback thread to process any updates to the callback
 * parameters, and send a null probe.
 */
void nfsd4_probe_callback(struct nfs4_client *clp)
{
	clp->cl_cb_state = NFSD4_CB_UNKNOWN;
	set_bit(NFSD4_CLIENT_CB_UPDATE, &clp->cl_flags);
	nfsd4_run_cb(&clp->cl_cb_null);
}

void nfsd4_probe_callback_sync(struct nfs4_client *clp)
{
	nfsd4_probe_callback(clp);
	flush_workqueue(callback_wq);
}

void nfsd4_change_callback(struct nfs4_client *clp, struct nfs4_cb_conn *conn)
{
	clp->cl_cb_state = NFSD4_CB_UNKNOWN;
	spin_lock(&clp->cl_lock);
	memcpy(&clp->cl_cb_conn, conn, sizeof(struct nfs4_cb_conn));
	spin_unlock(&clp->cl_lock);
}

/*
 * There's currently a single callback channel slot.
 * If the slot is available, then mark it busy.  Otherwise, set the
 * thread for sleeping on the callback RPC wait queue.
 */
static bool nfsd41_cb_get_slot(struct nfs4_client *clp, struct rpc_task *task)
{
	if (test_and_set_bit(0, &clp->cl_cb_slot_busy) != 0) {
		rpc_sleep_on(&clp->cl_cb_waitq, task, NULL);
		/* Race breaker */
		if (test_and_set_bit(0, &clp->cl_cb_slot_busy) != 0) {
			dprintk("%s slot is busy\n", __func__);
			return false;
		}
		rpc_wake_up_queued_task(&clp->cl_cb_waitq, task);
	}
	return true;
}

/*
 * TODO: cb_sequence should support referring call lists, cachethis, multiple
 * slots, and mark callback channel down on communication errors.
 */
static void nfsd4_cb_prepare(struct rpc_task *task, void *calldata)
{
	struct nfsd4_callback *cb = calldata;
	struct nfs4_client *clp = cb->cb_clp;
	u32 minorversion = clp->cl_minorversion;

	cb->cb_minorversion = minorversion;
	if (minorversion) {
		if (!nfsd41_cb_get_slot(clp, task))
			return;
	}
	spin_lock(&clp->cl_lock);
	if (list_empty(&cb->cb_per_client)) {
		/* This is the first call, not a restart */
		cb->cb_done = false;
		list_add(&cb->cb_per_client, &clp->cl_callbacks);
	}
	spin_unlock(&clp->cl_lock);
	rpc_call_start(task);
}

static void nfsd4_cb_done(struct rpc_task *task, void *calldata)
{
	struct nfsd4_callback *cb = calldata;
	struct nfs4_client *clp = cb->cb_clp;

	dprintk("%s: minorversion=%d\n", __func__,
		clp->cl_minorversion);

	if (clp->cl_minorversion) {
		/* No need for lock, access serialized in nfsd4_cb_prepare */
		++clp->cl_cb_session->se_cb_seq_nr;
		clear_bit(0, &clp->cl_cb_slot_busy);
		rpc_wake_up_next(&clp->cl_cb_waitq);
		dprintk("%s: freed slot, new seqid=%d\n", __func__,
			clp->cl_cb_session->se_cb_seq_nr);
	}

	if (clp->cl_cb_client != task->tk_client) {
		/* We're shutting down or changing cl_cb_client; leave
		 * it to nfsd4_process_cb_update to restart the call if
		 * necessary. */
		return;
	}

	if (cb->cb_done)
		return;

	switch (cb->cb_ops->done(cb, task)) {
	case 0:
		task->tk_status = 0;
		rpc_restart_call_prepare(task);
		return;
	case 1:
		break;
	case -1:
		/* Network partition? */
		nfsd4_mark_cb_down(clp, task->tk_status);
		break;
	default:
		BUG();
	}
	cb->cb_done = true;
}

static void nfsd4_cb_release(void *calldata)
{
	struct nfsd4_callback *cb = calldata;
	struct nfs4_client *clp = cb->cb_clp;

	if (cb->cb_done) {
		spin_lock(&clp->cl_lock);
		list_del(&cb->cb_per_client);
		spin_unlock(&clp->cl_lock);

		cb->cb_ops->release(cb);
	}
}

static const struct rpc_call_ops nfsd4_cb_ops = {
	.rpc_call_prepare = nfsd4_cb_prepare,
	.rpc_call_done = nfsd4_cb_done,
	.rpc_release = nfsd4_cb_release,
};

int nfsd4_create_callback_queue(void)
{
	callback_wq = create_singlethread_workqueue("nfsd4_callbacks");
	if (!callback_wq)
		return -ENOMEM;
	return 0;
}

void nfsd4_destroy_callback_queue(void)
{
	destroy_workqueue(callback_wq);
}

/* must be called under the state lock */
void nfsd4_shutdown_callback(struct nfs4_client *clp)
{
	set_bit(NFSD4_CLIENT_CB_KILL, &clp->cl_flags);
	/*
	 * Note this won't actually result in a null callback;
	 * instead, nfsd4_run_cb_null() will detect the killed
	 * client, destroy the rpc client, and stop:
	 */
	nfsd4_run_cb(&clp->cl_cb_null);
	flush_workqueue(callback_wq);
}

/* requires cl_lock: */
static struct nfsd4_conn * __nfsd4_find_backchannel(struct nfs4_client *clp)
{
	struct nfsd4_session *s;
	struct nfsd4_conn *c;

	list_for_each_entry(s, &clp->cl_sessions, se_perclnt) {
		list_for_each_entry(c, &s->se_conns, cn_persession) {
			if (c->cn_flags & NFS4_CDFC4_BACK)
				return c;
		}
	}
	return NULL;
}

static void nfsd4_process_cb_update(struct nfsd4_callback *cb)
{
	struct nfs4_cb_conn conn;
	struct nfs4_client *clp = cb->cb_clp;
	struct nfsd4_session *ses = NULL;
	struct nfsd4_conn *c;
	int err;

	/*
	 * This is either an update, or the client dying; in either case,
	 * kill the old client:
	 */
	if (clp->cl_cb_client) {
		rpc_shutdown_client(clp->cl_cb_client);
		clp->cl_cb_client = NULL;
		put_rpccred(clp->cl_cb_cred);
		clp->cl_cb_cred = NULL;
	}
	if (clp->cl_cb_conn.cb_xprt) {
		svc_xprt_put(clp->cl_cb_conn.cb_xprt);
		clp->cl_cb_conn.cb_xprt = NULL;
	}
	if (test_bit(NFSD4_CLIENT_CB_KILL, &clp->cl_flags))
		return;
	spin_lock(&clp->cl_lock);
	/*
	 * Only serialized callback code is allowed to clear these
	 * flags; main nfsd code can only set them:
	 */
	BUG_ON(!(clp->cl_flags & NFSD4_CLIENT_CB_FLAG_MASK));
	clear_bit(NFSD4_CLIENT_CB_UPDATE, &clp->cl_flags);
	memcpy(&conn, &cb->cb_clp->cl_cb_conn, sizeof(struct nfs4_cb_conn));
	c = __nfsd4_find_backchannel(clp);
	if (c) {
		svc_xprt_get(c->cn_xprt);
		conn.cb_xprt = c->cn_xprt;
		ses = c->cn_session;
	}
	spin_unlock(&clp->cl_lock);

	err = setup_callback_client(clp, &conn, ses);
	if (err) {
		nfsd4_mark_cb_down(clp, err);
		return;
	}
	/* Yay, the callback channel's back! Restart any callbacks: */
	list_for_each_entry(cb, &clp->cl_callbacks, cb_per_client)
		queue_work(callback_wq, &cb->cb_work);
}

static void
nfsd4_run_cb_work(struct work_struct *work)
{
	struct nfsd4_callback *cb =
		container_of(work, struct nfsd4_callback, cb_work);
	struct nfs4_client *clp = cb->cb_clp;
	struct rpc_clnt *clnt;

	if (cb->cb_ops && cb->cb_ops->prepare)
		cb->cb_ops->prepare(cb);

	if (clp->cl_flags & NFSD4_CLIENT_CB_FLAG_MASK)
		nfsd4_process_cb_update(cb);

	clnt = clp->cl_cb_client;
	if (!clnt) {
		/* Callback channel broken, or client killed; give up: */
		if (cb->cb_ops && cb->cb_ops->release)
			cb->cb_ops->release(cb);
		return;
	}
	cb->cb_msg.rpc_cred = clp->cl_cb_cred;
	rpc_call_async(clnt, &cb->cb_msg, RPC_TASK_SOFT | RPC_TASK_SOFTCONN,
			cb->cb_ops ? &nfsd4_cb_ops : &nfsd4_cb_probe_ops, cb);
}

void nfsd4_init_cb(struct nfsd4_callback *cb, struct nfs4_client *clp,
		struct nfsd4_callback_ops *ops, enum nfsd4_cb_op op)
{
	cb->cb_clp = clp;
	cb->cb_msg.rpc_proc = &nfs4_cb_procedures[op];
	cb->cb_msg.rpc_argp = cb;
	cb->cb_msg.rpc_resp = cb;
	cb->cb_ops = ops;
	INIT_WORK(&cb->cb_work, nfsd4_run_cb_work);
	INIT_LIST_HEAD(&cb->cb_per_client);
	cb->cb_done = true;
}

void nfsd4_run_cb(struct nfsd4_callback *cb)
{
	queue_work(callback_wq, &cb->cb_work);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs4callback.c */
/************************************************************/
/*
*  Copyright (c) 2004 The Regents of the University of Michigan.
*  Copyright (c) 2012 Jeff Layton <jlayton@redhat.com>
*  All rights reserved.
*
*  Andy Adamson <andros@citi.umich.edu>
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions
*  are met:
*
*  1. Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*  2. Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in the
*     documentation and/or other materials provided with the distribution.
*  3. Neither the name of the University nor the names of its
*     contributors may be used to endorse or promote products derived
*     from this software without specific prior written permission.
*
*  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
*  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
*  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
*  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
*  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
*  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
*  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
*  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
*  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
*  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
*  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

// #include <linux/file.h>
// #include <linux/slab.h>
// #include <linux/namei.h>
#include <linux/crypto.h>
// #include <linux/sched.h>
// #include <linux/fs.h>
// #include <linux/module.h>
// #include <net/net_namespace.h>
// #include <linux/sunrpc/rpc_pipe_fs.h>
// #include <linux/sunrpc/clnt.h>
#include <linux/nfsd/cld.h>
#include "../../inc/__fss.h"

// #include "nfsd.h"
// #include "state.h"
// #include "vfs.h"
// #include "netns.h"

#define NFSDDBG_FACILITY                NFSDDBG_PROC

/* Declarations */
struct nfsd4_client_tracking_ops {
	int (*init)(struct net *);
	void (*exit)(struct net *);
	void (*create)(struct nfs4_client *);
	void (*remove)(struct nfs4_client *);
	int (*check)(struct nfs4_client *);
	void (*grace_done)(struct nfsd_net *);
};

/* Globals */
static char user_recovery_dirname[PATH_MAX] = "/var/lib/nfs/v4recovery";

static int
nfs4_save_creds(const struct cred **original_creds)
{
	struct cred *new;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	new->fsuid = GLOBAL_ROOT_UID;
	new->fsgid = GLOBAL_ROOT_GID;
	*original_creds = override_creds(new);
	put_cred(new);
	return 0;
}

static void
nfs4_reset_creds(const struct cred *original)
{
	revert_creds(original);
}

static void
md5_to_hex(char *out, char *md5)
{
	int i;

	for (i=0; i<16; i++) {
		unsigned char c = md5[i];

		*out++ = '0' + ((c&0xf0)>>4) + (c>=0xa0)*('a'-'9'-1);
		*out++ = '0' + (c&0x0f) + ((c&0x0f)>=0x0a)*('a'-'9'-1);
	}
	*out = '\0';
}

static int
nfs4_make_rec_clidname(char *dname, const struct xdr_netobj *clname)
{
	struct xdr_netobj cksum;
	struct hash_desc desc;
	struct scatterlist sg;
	int status;

	dprintk("NFSD: nfs4_make_rec_clidname for %.*s\n",
			clname->len, clname->data);
	desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(desc.tfm)) {
		status = PTR_ERR(desc.tfm);
		goto out_no_tfm;
	}

	cksum.len = crypto_hash_digestsize(desc.tfm);
	cksum.data = kmalloc(cksum.len, GFP_KERNEL);
	if (cksum.data == NULL) {
		status = -ENOMEM;
 		goto out;
	}

	sg_init_one(&sg, clname->data, clname->len);

	status = crypto_hash_digest(&desc, &sg, sg.length, cksum.data);
	if (status)
		goto out;

	md5_to_hex(dname, cksum.data);

	status = 0;
out:
	kfree(cksum.data);
	crypto_free_hash(desc.tfm);
out_no_tfm:
	return status;
}

/*
 * If we had an error generating the recdir name for the legacy tracker
 * then warn the admin. If the error doesn't appear to be transient,
 * then disable recovery tracking.
 */
static void
legacy_recdir_name_error(struct nfs4_client *clp, int error)
{
	printk(KERN_ERR "NFSD: unable to generate recoverydir "
			"name (%d).\n", error);

	/*
	 * if the algorithm just doesn't exist, then disable the recovery
	 * tracker altogether. The crypto libs will generally return this if
	 * FIPS is enabled as well.
	 */
	if (error == -ENOENT) {
		printk(KERN_ERR "NFSD: disabling legacy clientid tracking. "
			"Reboot recovery will not function correctly!\n");
		nfsd4_client_tracking_exit(clp->net);
	}
}

static void
nfsd4_create_clid_dir(struct nfs4_client *clp)
{
	const struct cred *original_cred;
	char dname[HEXDIR_LEN];
	struct dentry *dir, *dentry;
	struct nfs4_client_reclaim *crp;
	int status;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	if (test_and_set_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags))
		return;
	if (!nn->rec_file)
		return;

	status = nfs4_make_rec_clidname(dname, &clp->cl_name);
	if (status)
		return legacy_recdir_name_error(clp, status);

	status = nfs4_save_creds(&original_cred);
	if (status < 0)
		return;

	status = mnt_want_write_file(nn->rec_file);
	if (status)
		goto out_creds;

	dir = nn->rec_file->f_path.dentry;
	/* lock the parent */
	mutex_lock(&dir->d_inode->i_mutex);

	dentry = lookup_one_len(dname, dir, HEXDIR_LEN-1);
	if (IS_ERR(dentry)) {
		status = PTR_ERR(dentry);
		goto out_unlock;
	}
	if (dentry->d_inode)
		/*
		 * In the 4.1 case, where we're called from
		 * reclaim_complete(), records from the previous reboot
		 * may still be left, so this is OK.
		 *
		 * In the 4.0 case, we should never get here; but we may
		 * as well be forgiving and just succeed silently.
		 */
		goto out_put;
	status = vfs_mkdir(dir->d_inode, dentry, S_IRWXU);
out_put:
	dput(dentry);
out_unlock:
	mutex_unlock(&dir->d_inode->i_mutex);
	if (status == 0) {
		if (nn->in_grace) {
			crp = nfs4_client_to_reclaim(dname, nn);
			if (crp)
				crp->cr_clp = clp;
		}
		vfs_fsync(nn->rec_file, 0);
	} else {
		printk(KERN_ERR "NFSD: failed to write recovery record"
				" (err %d); please check that %s exists"
				" and is writeable", status,
				user_recovery_dirname);
	}
	mnt_drop_write_file(nn->rec_file);
out_creds:
	nfs4_reset_creds(original_cred);
}

typedef int (recdir_func)(struct dentry *, struct dentry *, struct nfsd_net *);

struct name_list {
	char name[HEXDIR_LEN];
	struct list_head list;
};

struct nfs4_dir_ctx {
	struct dir_context ctx;
	struct list_head names;
};

static int
nfsd4_build_namelist(struct dir_context *__ctx, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned int d_type)
{
	struct nfs4_dir_ctx *ctx =
		container_of(__ctx, struct nfs4_dir_ctx, ctx);
	struct name_list *entry;

	if (namlen != HEXDIR_LEN - 1)
		return 0;
	entry = kmalloc(sizeof(struct name_list), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;
	memcpy(entry->name, name, HEXDIR_LEN - 1);
	entry->name[HEXDIR_LEN - 1] = '\0';
	list_add(&entry->list, &ctx->names);
	return 0;
}

static int
nfsd4_list_rec_dir(recdir_func *f, struct nfsd_net *nn)
{
	const struct cred *original_cred;
	struct dentry *dir = nn->rec_file->f_path.dentry;
	struct nfs4_dir_ctx ctx = {
		.ctx.actor = nfsd4_build_namelist,
		.names = LIST_HEAD_INIT(ctx.names)
	};
	int status;

	status = nfs4_save_creds(&original_cred);
	if (status < 0)
		return status;

	status = vfs_llseek(nn->rec_file, 0, SEEK_SET);
	if (status < 0) {
		nfs4_reset_creds(original_cred);
		return status;
	}

	status = iterate_dir(nn->rec_file, &ctx.ctx);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	while (!list_empty(&ctx.names)) {
		struct name_list *entry;
		entry = list_entry(ctx.names.next, struct name_list, list);
		if (!status) {
			struct dentry *dentry;
			dentry = lookup_one_len(entry->name, dir, HEXDIR_LEN-1);
			if (IS_ERR(dentry)) {
				status = PTR_ERR(dentry);
				break;
			}
			status = f(dir, dentry, nn);
			dput(dentry);
		}
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&dir->d_inode->i_mutex);
	nfs4_reset_creds(original_cred);
	return status;
}

static int
nfsd4_unlink_clid_dir(char *name, int namlen, struct nfsd_net *nn)
{
	struct dentry *dir, *dentry;
	int status;

	dprintk("NFSD: nfsd4_unlink_clid_dir. name %.*s\n", namlen, name);

	dir = nn->rec_file->f_path.dentry;
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	dentry = lookup_one_len(name, dir, namlen);
	if (IS_ERR(dentry)) {
		status = PTR_ERR(dentry);
		goto out_unlock;
	}
	status = -ENOENT;
	if (!dentry->d_inode)
		goto out;
	status = vfs_rmdir(dir->d_inode, dentry);
out:
	dput(dentry);
out_unlock:
	mutex_unlock(&dir->d_inode->i_mutex);
	return status;
}

static void
nfsd4_remove_clid_dir(struct nfs4_client *clp)
{
	const struct cred *original_cred;
	struct nfs4_client_reclaim *crp;
	char dname[HEXDIR_LEN];
	int status;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	if (!nn->rec_file || !test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags))
		return;

	status = nfs4_make_rec_clidname(dname, &clp->cl_name);
	if (status)
		return legacy_recdir_name_error(clp, status);

	status = mnt_want_write_file(nn->rec_file);
	if (status)
		goto out;
	clear_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags);

	status = nfs4_save_creds(&original_cred);
	if (status < 0)
		goto out_drop_write;

	status = nfsd4_unlink_clid_dir(dname, HEXDIR_LEN-1, nn);
	nfs4_reset_creds(original_cred);
	if (status == 0) {
		vfs_fsync(nn->rec_file, 0);
		if (nn->in_grace) {
			/* remove reclaim record */
			crp = nfsd4_find_reclaim_client(dname, nn);
			if (crp)
				nfs4_remove_reclaim_record(crp, nn);
		}
	}
out_drop_write:
	mnt_drop_write_file(nn->rec_file);
out:
	if (status)
		printk("NFSD: Failed to remove expired client state directory"
				" %.*s\n", HEXDIR_LEN, dname);
}

static int
purge_old(struct dentry *parent, struct dentry *child, struct nfsd_net *nn)
{
	int status;

	if (nfs4_has_reclaimed_state(child->d_name.name, nn))
		return 0;

	status = vfs_rmdir(parent->d_inode, child);
	if (status)
		printk("failed to remove client recovery directory %pd\n",
				child);
	/* Keep trying, success or failure: */
	return 0;
}

static void
nfsd4_recdir_purge_old(struct nfsd_net *nn)
{
	int status;

	nn->in_grace = false;
	if (!nn->rec_file)
		return;
	status = mnt_want_write_file(nn->rec_file);
	if (status)
		goto out;
	status = nfsd4_list_rec_dir(purge_old, nn);
	if (status == 0)
		vfs_fsync(nn->rec_file, 0);
	mnt_drop_write_file(nn->rec_file);
out:
	nfs4_release_reclaim(nn);
	if (status)
		printk("nfsd4: failed to purge old clients from recovery"
			" directory %pD\n", nn->rec_file);
}

static int
load_recdir(struct dentry *parent, struct dentry *child, struct nfsd_net *nn)
{
	if (child->d_name.len != HEXDIR_LEN - 1) {
		printk("nfsd4: illegal name %pd in recovery directory\n",
				child);
		/* Keep trying; maybe the others are OK: */
		return 0;
	}
	nfs4_client_to_reclaim(child->d_name.name, nn);
	return 0;
}

static int
nfsd4_recdir_load(struct net *net) {
	int status;
	struct nfsd_net *nn =  net_generic(net, nfsd_net_id);

	if (!nn->rec_file)
		return 0;

	status = nfsd4_list_rec_dir(load_recdir, nn);
	if (status)
		printk("nfsd4: failed loading clients from recovery"
			" directory %pD\n", nn->rec_file);
	return status;
}

/*
 * Hold reference to the recovery directory.
 */

static int
nfsd4_init_recdir(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	const struct cred *original_cred;
	int status;

	printk("NFSD: Using %s as the NFSv4 state recovery directory\n",
			user_recovery_dirname);

	BUG_ON(nn->rec_file);

	status = nfs4_save_creds(&original_cred);
	if (status < 0) {
		printk("NFSD: Unable to change credentials to find recovery"
		       " directory: error %d\n",
		       status);
		return status;
	}

	nn->rec_file = filp_open(user_recovery_dirname, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(nn->rec_file)) {
		printk("NFSD: unable to find recovery directory %s\n",
				user_recovery_dirname);
		status = PTR_ERR(nn->rec_file);
		nn->rec_file = NULL;
	}

	nfs4_reset_creds(original_cred);
	if (!status)
		nn->in_grace = true;
	return status;
}

static void
nfsd4_shutdown_recdir(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	if (!nn->rec_file)
		return;
	fput(nn->rec_file);
	nn->rec_file = NULL;
}

static int
nfs4_legacy_state_init(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	int i;

	nn->reclaim_str_hashtbl = kmalloc(sizeof(struct list_head) *
					  CLIENT_HASH_SIZE, GFP_KERNEL);
	if (!nn->reclaim_str_hashtbl)
		return -ENOMEM;

	for (i = 0; i < CLIENT_HASH_SIZE; i++)
		INIT_LIST_HEAD(&nn->reclaim_str_hashtbl[i]);
	nn->reclaim_str_hashtbl_size = 0;

	return 0;
}

static void
nfs4_legacy_state_shutdown(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	kfree(nn->reclaim_str_hashtbl);
}

static int
nfsd4_load_reboot_recovery_data(struct net *net)
{
	int status;

	status = nfsd4_init_recdir(net);
	if (status)
		return status;

	status = nfsd4_recdir_load(net);
	if (status)
		nfsd4_shutdown_recdir(net);

	return status;
}

static int
nfsd4_legacy_tracking_init(struct net *net)
{
	int status;

	/* XXX: The legacy code won't work in a container */
	if (net != &init_net) {
		WARN(1, KERN_ERR "NFSD: attempt to initialize legacy client "
			"tracking in a container!\n");
		return -EINVAL;
	}

	status = nfs4_legacy_state_init(net);
	if (status)
		return status;

	status = nfsd4_load_reboot_recovery_data(net);
	if (status)
		goto err;
	return 0;

err:
	nfs4_legacy_state_shutdown(net);
	return status;
}

static void
nfsd4_legacy_tracking_exit(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	nfs4_release_reclaim(nn);
	nfsd4_shutdown_recdir(net);
	nfs4_legacy_state_shutdown(net);
}

/*
 * Change the NFSv4 recovery directory to recdir.
 */
int
nfs4_reset_recoverydir(char *recdir)
{
	int status;
	struct path path;

	status = kern_path(recdir, LOOKUP_FOLLOW, &path);
	if (status)
		return status;
	status = -ENOTDIR;
	if (d_is_dir(path.dentry)) {
		strcpy(user_recovery_dirname, recdir);
		status = 0;
	}
	path_put(&path);
	return status;
}

char *
nfs4_recoverydir(void)
{
	return user_recovery_dirname;
}

static int
nfsd4_check_legacy_client(struct nfs4_client *clp)
{
	int status;
	char dname[HEXDIR_LEN];
	struct nfs4_client_reclaim *crp;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	/* did we already find that this client is stable? */
	if (test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags))
		return 0;

	status = nfs4_make_rec_clidname(dname, &clp->cl_name);
	if (status) {
		legacy_recdir_name_error(clp, status);
		return status;
	}

	/* look for it in the reclaim hashtable otherwise */
	crp = nfsd4_find_reclaim_client(dname, nn);
	if (crp) {
		set_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags);
		crp->cr_clp = clp;
		return 0;
	}

	return -ENOENT;
}

static struct nfsd4_client_tracking_ops nfsd4_legacy_tracking_ops = {
	.init		= nfsd4_legacy_tracking_init,
	.exit		= nfsd4_legacy_tracking_exit,
	.create		= nfsd4_create_clid_dir,
	.remove		= nfsd4_remove_clid_dir,
	.check		= nfsd4_check_legacy_client,
	.grace_done	= nfsd4_recdir_purge_old,
};

/* Globals */
#define NFSD_PIPE_DIR		"nfsd"
#define NFSD_CLD_PIPE		"cld"

/* per-net-ns structure for holding cld upcall info */
struct cld_net {
	struct rpc_pipe		*cn_pipe;
	spinlock_t		 cn_lock;
	struct list_head	 cn_list;
	unsigned int		 cn_xid;
};

struct cld_upcall {
	struct list_head	 cu_list;
	struct cld_net		*cu_net;
	struct task_struct	*cu_task;
	struct cld_msg		 cu_msg;
};

static int
__cld_pipe_upcall(struct rpc_pipe *pipe, struct cld_msg *cmsg)
{
	int ret;
	struct rpc_pipe_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.data = cmsg;
	msg.len = sizeof(*cmsg);

	/*
	 * Set task state before we queue the upcall. That prevents
	 * wake_up_process in the downcall from racing with schedule.
	 */
	set_current_state(TASK_UNINTERRUPTIBLE);
	ret = rpc_queue_upcall(pipe, &msg);
	if (ret < 0) {
		set_current_state(TASK_RUNNING);
		goto out;
	}

	schedule();

	if (msg.errno < 0)
		ret = msg.errno;
out:
	return ret;
}

static int
cld_pipe_upcall(struct rpc_pipe *pipe, struct cld_msg *cmsg)
{
	int ret;

	/*
	 * -EAGAIN occurs when pipe is closed and reopened while there are
	 *  upcalls queued.
	 */
	do {
		ret = __cld_pipe_upcall(pipe, cmsg);
	} while (ret == -EAGAIN);

	return ret;
}

static ssize_t
cld_pipe_downcall(struct file *filp, const char __user *src, size_t mlen)
{
	struct cld_upcall *tmp, *cup;
	struct cld_msg __user *cmsg = (struct cld_msg __user *)src;
	uint32_t xid;
	struct nfsd_net *nn = net_generic(file_inode(filp)->i_sb->s_fs_info,
						nfsd_net_id);
	struct cld_net *cn = nn->cld_net;

	if (mlen != sizeof(*cmsg)) {
		dprintk("%s: got %zu bytes, expected %zu\n", __func__, mlen,
			sizeof(*cmsg));
		return -EINVAL;
	}

	/* copy just the xid so we can try to find that */
	if (copy_from_user(&xid, &cmsg->cm_xid, sizeof(xid)) != 0) {
		dprintk("%s: error when copying xid from userspace", __func__);
		return -EFAULT;
	}

	/* walk the list and find corresponding xid */
	cup = NULL;
	spin_lock(&cn->cn_lock);
	list_for_each_entry(tmp, &cn->cn_list, cu_list) {
		if (get_unaligned(&tmp->cu_msg.cm_xid) == xid) {
			cup = tmp;
			list_del_init(&cup->cu_list);
			break;
		}
	}
	spin_unlock(&cn->cn_lock);

	/* couldn't find upcall? */
	if (!cup) {
		dprintk("%s: couldn't find upcall -- xid=%u\n", __func__, xid);
		return -EINVAL;
	}

	if (copy_from_user(&cup->cu_msg, src, mlen) != 0)
		return -EFAULT;

	wake_up_process(cup->cu_task);
	return mlen;
}

static void
cld_pipe_destroy_msg(struct rpc_pipe_msg *msg)
{
	struct cld_msg *cmsg = msg->data;
	struct cld_upcall *cup = container_of(cmsg, struct cld_upcall,
						 cu_msg);

	/* errno >= 0 means we got a downcall */
	if (msg->errno >= 0)
		return;

	wake_up_process(cup->cu_task);
}

static const struct rpc_pipe_ops cld_upcall_ops = {
	.upcall		= rpc_pipe_generic_upcall,
	.downcall	= cld_pipe_downcall,
	.destroy_msg	= cld_pipe_destroy_msg,
};

static struct dentry *
nfsd4_cld_register_sb(struct super_block *sb, struct rpc_pipe *pipe)
{
	struct dentry *dir, *dentry;

	dir = rpc_d_lookup_sb(sb, NFSD_PIPE_DIR);
	if (dir == NULL)
		return ERR_PTR(-ENOENT);
	dentry = rpc_mkpipe_dentry(dir, NFSD_CLD_PIPE, NULL, pipe);
	dput(dir);
	return dentry;
}

static void
nfsd4_cld_unregister_sb(struct rpc_pipe *pipe)
{
	if (pipe->dentry)
		rpc_unlink(pipe->dentry);
}

static struct dentry *
nfsd4_cld_register_net(struct net *net, struct rpc_pipe *pipe)
{
	struct super_block *sb;
	struct dentry *dentry;

	sb = rpc_get_sb_net(net);
	if (!sb)
		return NULL;
	dentry = nfsd4_cld_register_sb(sb, pipe);
	rpc_put_sb_net(net);
	return dentry;
}

static void
nfsd4_cld_unregister_net(struct net *net, struct rpc_pipe *pipe)
{
	struct super_block *sb;

	sb = rpc_get_sb_net(net);
	if (sb) {
		nfsd4_cld_unregister_sb(pipe);
		rpc_put_sb_net(net);
	}
}

/* Initialize rpc_pipefs pipe for communication with client tracking daemon */
static int
nfsd4_init_cld_pipe(struct net *net)
{
	int ret;
	struct dentry *dentry;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	struct cld_net *cn;

	if (nn->cld_net)
		return 0;

	cn = kzalloc(sizeof(*cn), GFP_KERNEL);
	if (!cn) {
		ret = -ENOMEM;
		goto err;
	}

	cn->cn_pipe = rpc_mkpipe_data(&cld_upcall_ops, RPC_PIPE_WAIT_FOR_OPEN);
	if (IS_ERR(cn->cn_pipe)) {
		ret = PTR_ERR(cn->cn_pipe);
		goto err;
	}
	spin_lock_init(&cn->cn_lock);
	INIT_LIST_HEAD(&cn->cn_list);

	dentry = nfsd4_cld_register_net(net, cn->cn_pipe);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto err_destroy_data;
	}

	cn->cn_pipe->dentry = dentry;
	nn->cld_net = cn;
	return 0;

err_destroy_data:
	rpc_destroy_pipe_data(cn->cn_pipe);
err:
	kfree(cn);
	printk(KERN_ERR "NFSD: unable to create nfsdcld upcall pipe (%d)\n",
			ret);
	return ret;
}

static void
nfsd4_remove_cld_pipe(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	struct cld_net *cn = nn->cld_net;

	nfsd4_cld_unregister_net(net, cn->cn_pipe);
	rpc_destroy_pipe_data(cn->cn_pipe);
	kfree(nn->cld_net);
	nn->cld_net = NULL;
}

static struct cld_upcall *
alloc_cld_upcall(struct cld_net *cn)
{
	struct cld_upcall *new, *tmp;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return new;

	/* FIXME: hard cap on number in flight? */
restart_search:
	spin_lock(&cn->cn_lock);
	list_for_each_entry(tmp, &cn->cn_list, cu_list) {
		if (tmp->cu_msg.cm_xid == cn->cn_xid) {
			cn->cn_xid++;
			spin_unlock(&cn->cn_lock);
			goto restart_search;
		}
	}
	new->cu_task = current;
	new->cu_msg.cm_vers = CLD_UPCALL_VERSION;
	put_unaligned(cn->cn_xid++, &new->cu_msg.cm_xid);
	new->cu_net = cn;
	list_add(&new->cu_list, &cn->cn_list);
	spin_unlock(&cn->cn_lock);

	dprintk("%s: allocated xid %u\n", __func__, new->cu_msg.cm_xid);

	return new;
}

static void
free_cld_upcall(struct cld_upcall *victim)
{
	struct cld_net *cn = victim->cu_net;

	spin_lock(&cn->cn_lock);
	list_del(&victim->cu_list);
	spin_unlock(&cn->cn_lock);
	kfree(victim);
}

/* Ask daemon to create a new record */
static void
nfsd4_cld_create(struct nfs4_client *clp)
{
	int ret;
	struct cld_upcall *cup;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);
	struct cld_net *cn = nn->cld_net;

	/* Don't upcall if it's already stored */
	if (test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags))
		return;

	cup = alloc_cld_upcall(cn);
	if (!cup) {
		ret = -ENOMEM;
		goto out_err;
	}

	cup->cu_msg.cm_cmd = Cld_Create;
	cup->cu_msg.cm_u.cm_name.cn_len = clp->cl_name.len;
	memcpy(cup->cu_msg.cm_u.cm_name.cn_id, clp->cl_name.data,
			clp->cl_name.len);

	ret = cld_pipe_upcall(cn->cn_pipe, &cup->cu_msg);
	if (!ret) {
		ret = cup->cu_msg.cm_status;
		set_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags);
	}

	free_cld_upcall(cup);
out_err:
	if (ret)
		printk(KERN_ERR "NFSD: Unable to create client "
				"record on stable storage: %d\n", ret);
}

/* Ask daemon to create a new record */
static void
nfsd4_cld_remove(struct nfs4_client *clp)
{
	int ret;
	struct cld_upcall *cup;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);
	struct cld_net *cn = nn->cld_net;

	/* Don't upcall if it's already removed */
	if (!test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags))
		return;

	cup = alloc_cld_upcall(cn);
	if (!cup) {
		ret = -ENOMEM;
		goto out_err;
	}

	cup->cu_msg.cm_cmd = Cld_Remove;
	cup->cu_msg.cm_u.cm_name.cn_len = clp->cl_name.len;
	memcpy(cup->cu_msg.cm_u.cm_name.cn_id, clp->cl_name.data,
			clp->cl_name.len);

	ret = cld_pipe_upcall(cn->cn_pipe, &cup->cu_msg);
	if (!ret) {
		ret = cup->cu_msg.cm_status;
		clear_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags);
	}

	free_cld_upcall(cup);
out_err:
	if (ret)
		printk(KERN_ERR "NFSD: Unable to remove client "
				"record from stable storage: %d\n", ret);
}

/* Check for presence of a record, and update its timestamp */
static int
nfsd4_cld_check(struct nfs4_client *clp)
{
	int ret;
	struct cld_upcall *cup;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);
	struct cld_net *cn = nn->cld_net;

	/* Don't upcall if one was already stored during this grace pd */
	if (test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags))
		return 0;

	cup = alloc_cld_upcall(cn);
	if (!cup) {
		printk(KERN_ERR "NFSD: Unable to check client record on "
				"stable storage: %d\n", -ENOMEM);
		return -ENOMEM;
	}

	cup->cu_msg.cm_cmd = Cld_Check;
	cup->cu_msg.cm_u.cm_name.cn_len = clp->cl_name.len;
	memcpy(cup->cu_msg.cm_u.cm_name.cn_id, clp->cl_name.data,
			clp->cl_name.len);

	ret = cld_pipe_upcall(cn->cn_pipe, &cup->cu_msg);
	if (!ret) {
		ret = cup->cu_msg.cm_status;
		set_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags);
	}

	free_cld_upcall(cup);
	return ret;
}

static void
nfsd4_cld_grace_done(struct nfsd_net *nn)
{
	int ret;
	struct cld_upcall *cup;
	struct cld_net *cn = nn->cld_net;

	cup = alloc_cld_upcall(cn);
	if (!cup) {
		ret = -ENOMEM;
		goto out_err;
	}

	cup->cu_msg.cm_cmd = Cld_GraceDone;
	cup->cu_msg.cm_u.cm_gracetime = (int64_t)nn->boot_time;
	ret = cld_pipe_upcall(cn->cn_pipe, &cup->cu_msg);
	if (!ret)
		ret = cup->cu_msg.cm_status;

	free_cld_upcall(cup);
out_err:
	if (ret)
		printk(KERN_ERR "NFSD: Unable to end grace period: %d\n", ret);
}

static struct nfsd4_client_tracking_ops nfsd4_cld_tracking_ops = {
	.init		= nfsd4_init_cld_pipe,
	.exit		= nfsd4_remove_cld_pipe,
	.create		= nfsd4_cld_create,
	.remove		= nfsd4_cld_remove,
	.check		= nfsd4_cld_check,
	.grace_done	= nfsd4_cld_grace_done,
};

/* upcall via usermodehelper */
static char cltrack_prog[PATH_MAX] = "/sbin/nfsdcltrack";
module_param_string(cltrack_prog, cltrack_prog, sizeof(cltrack_prog),
			S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(cltrack_prog, "Path to the nfsdcltrack upcall program");

static bool cltrack_legacy_disable;
module_param(cltrack_legacy_disable, bool, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(cltrack_legacy_disable,
		"Disable legacy recoverydir conversion. Default: false");

#define LEGACY_TOPDIR_ENV_PREFIX "NFSDCLTRACK_LEGACY_TOPDIR="
#define LEGACY_RECDIR_ENV_PREFIX "NFSDCLTRACK_LEGACY_RECDIR="
#define HAS_SESSION_ENV_PREFIX "NFSDCLTRACK_CLIENT_HAS_SESSION="
#define GRACE_START_ENV_PREFIX "NFSDCLTRACK_GRACE_START="

static char *
nfsd4_cltrack_legacy_topdir(void)
{
	int copied;
	size_t len;
	char *result;

	if (cltrack_legacy_disable)
		return NULL;

	len = strlen(LEGACY_TOPDIR_ENV_PREFIX) +
		strlen(nfs4_recoverydir()) + 1;

	result = kmalloc(len, GFP_KERNEL);
	if (!result)
		return result;

	copied = snprintf(result, len, LEGACY_TOPDIR_ENV_PREFIX "%s",
				nfs4_recoverydir());
	if (copied >= len) {
		/* just return nothing if output was truncated */
		kfree(result);
		return NULL;
	}

	return result;
}

static char *
nfsd4_cltrack_legacy_recdir(const struct xdr_netobj *name)
{
	int copied;
	size_t len;
	char *result;

	if (cltrack_legacy_disable)
		return NULL;

	/* +1 is for '/' between "topdir" and "recdir" */
	len = strlen(LEGACY_RECDIR_ENV_PREFIX) +
		strlen(nfs4_recoverydir()) + 1 + HEXDIR_LEN;

	result = kmalloc(len, GFP_KERNEL);
	if (!result)
		return result;

	copied = snprintf(result, len, LEGACY_RECDIR_ENV_PREFIX "%s/",
				nfs4_recoverydir());
	if (copied > (len - HEXDIR_LEN)) {
		/* just return nothing if output will be truncated */
		kfree(result);
		return NULL;
	}

	copied = nfs4_make_rec_clidname(result + copied, name);
	if (copied) {
		kfree(result);
		return NULL;
	}

	return result;
}

static char *
nfsd4_cltrack_client_has_session(struct nfs4_client *clp)
{
	int copied;
	size_t len;
	char *result;

	/* prefix + Y/N character + terminating NULL */
	len = strlen(HAS_SESSION_ENV_PREFIX) + 1 + 1;

	result = kmalloc(len, GFP_KERNEL);
	if (!result)
		return result;

	copied = snprintf(result, len, HAS_SESSION_ENV_PREFIX "%c",
				clp->cl_minorversion ? 'Y' : 'N');
	if (copied >= len) {
		/* just return nothing if output was truncated */
		kfree(result);
		return NULL;
	}

	return result;
}

static char *
nfsd4_cltrack_grace_start(time_t grace_start)
{
	int copied;
	size_t len;
	char *result;

	/* prefix + max width of int64_t string + terminating NULL */
	len = strlen(GRACE_START_ENV_PREFIX) + 22 + 1;

	result = kmalloc(len, GFP_KERNEL);
	if (!result)
		return result;

	copied = snprintf(result, len, GRACE_START_ENV_PREFIX "%ld",
				grace_start);
	if (copied >= len) {
		/* just return nothing if output was truncated */
		kfree(result);
		return NULL;
	}

	return result;
}

static int
nfsd4_umh_cltrack_upcall(char *cmd, char *arg, char *env0, char *env1)
{
	char *envp[3];
	char *argv[4];
	int ret;

	if (unlikely(!cltrack_prog[0])) {
		dprintk("%s: cltrack_prog is disabled\n", __func__);
		return -EACCES;
	}

	dprintk("%s: cmd: %s\n", __func__, cmd);
	dprintk("%s: arg: %s\n", __func__, arg ? arg : "(null)");
	dprintk("%s: env0: %s\n", __func__, env0 ? env0 : "(null)");
	dprintk("%s: env1: %s\n", __func__, env1 ? env1 : "(null)");

	envp[0] = env0;
	envp[1] = env1;
	envp[2] = NULL;

	argv[0] = (char *)cltrack_prog;
	argv[1] = cmd;
	argv[2] = arg;
	argv[3] = NULL;

	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	/*
	 * Disable the upcall mechanism if we're getting an ENOENT or EACCES
	 * error. The admin can re-enable it on the fly by using sysfs
	 * once the problem has been fixed.
	 */
	if (ret == -ENOENT || ret == -EACCES) {
		dprintk("NFSD: %s was not found or isn't executable (%d). "
			"Setting cltrack_prog to blank string!",
			cltrack_prog, ret);
		cltrack_prog[0] = '\0';
	}
	dprintk("%s: %s return value: %d\n", __func__, cltrack_prog, ret);

	return ret;
}

static char *
bin_to_hex_dup(const unsigned char *src, int srclen)
{
	int i;
	char *buf, *hex;

	/* +1 for terminating NULL */
	buf = kmalloc((srclen * 2) + 1, GFP_KERNEL);
	if (!buf)
		return buf;

	hex = buf;
	for (i = 0; i < srclen; i++) {
		sprintf(hex, "%2.2x", *src++);
		hex += 2;
	}
	return buf;
}

static int
nfsd4_umh_cltrack_init(struct net *net)
{
	int ret;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	char *grace_start = nfsd4_cltrack_grace_start(nn->boot_time);

	/* XXX: The usermode helper s not working in container yet. */
	if (net != &init_net) {
		WARN(1, KERN_ERR "NFSD: attempt to initialize umh client "
			"tracking in a container!\n");
		return -EINVAL;
	}

	ret = nfsd4_umh_cltrack_upcall("init", NULL, grace_start, NULL);
	kfree(grace_start);
	return ret;
}

static void
nfsd4_cltrack_upcall_lock(struct nfs4_client *clp)
{
	wait_on_bit_lock(&clp->cl_flags, NFSD4_CLIENT_UPCALL_LOCK,
			 TASK_UNINTERRUPTIBLE);
}

static void
nfsd4_cltrack_upcall_unlock(struct nfs4_client *clp)
{
	smp_mb__before_atomic();
	clear_bit(NFSD4_CLIENT_UPCALL_LOCK, &clp->cl_flags);
	smp_mb__after_atomic();
	wake_up_bit(&clp->cl_flags, NFSD4_CLIENT_UPCALL_LOCK);
}

static void
nfsd4_umh_cltrack_create(struct nfs4_client *clp)
{
	char *hexid, *has_session, *grace_start;
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	/*
	 * With v4.0 clients, there's little difference in outcome between a
	 * create and check operation, and we can end up calling into this
	 * function multiple times per client (once for each openowner). So,
	 * for v4.0 clients skip upcalling once the client has been recorded
	 * on stable storage.
	 *
	 * For v4.1+ clients, the outcome of the two operations is different,
	 * so we must ensure that we upcall for the create operation. v4.1+
	 * clients call this on RECLAIM_COMPLETE though, so we should only end
	 * up doing a single create upcall per client.
	 */
	if (clp->cl_minorversion == 0 &&
	    test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags))
		return;

	hexid = bin_to_hex_dup(clp->cl_name.data, clp->cl_name.len);
	if (!hexid) {
		dprintk("%s: can't allocate memory for upcall!\n", __func__);
		return;
	}

	has_session = nfsd4_cltrack_client_has_session(clp);
	grace_start = nfsd4_cltrack_grace_start(nn->boot_time);

	nfsd4_cltrack_upcall_lock(clp);
	if (!nfsd4_umh_cltrack_upcall("create", hexid, has_session, grace_start))
		set_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags);
	nfsd4_cltrack_upcall_unlock(clp);

	kfree(has_session);
	kfree(grace_start);
	kfree(hexid);
}

static void
nfsd4_umh_cltrack_remove(struct nfs4_client *clp)
{
	char *hexid;

	if (!test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags))
		return;

	hexid = bin_to_hex_dup(clp->cl_name.data, clp->cl_name.len);
	if (!hexid) {
		dprintk("%s: can't allocate memory for upcall!\n", __func__);
		return;
	}

	nfsd4_cltrack_upcall_lock(clp);
	if (test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags) &&
	    nfsd4_umh_cltrack_upcall("remove", hexid, NULL, NULL) == 0)
		clear_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags);
	nfsd4_cltrack_upcall_unlock(clp);

	kfree(hexid);
}

static int
nfsd4_umh_cltrack_check(struct nfs4_client *clp)
{
	int ret;
	char *hexid, *has_session, *legacy;

	if (test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags))
		return 0;

	hexid = bin_to_hex_dup(clp->cl_name.data, clp->cl_name.len);
	if (!hexid) {
		dprintk("%s: can't allocate memory for upcall!\n", __func__);
		return -ENOMEM;
	}

	has_session = nfsd4_cltrack_client_has_session(clp);
	legacy = nfsd4_cltrack_legacy_recdir(&clp->cl_name);

	nfsd4_cltrack_upcall_lock(clp);
	if (test_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags)) {
		ret = 0;
	} else {
		ret = nfsd4_umh_cltrack_upcall("check", hexid, has_session, legacy);
		if (ret == 0)
			set_bit(NFSD4_CLIENT_STABLE, &clp->cl_flags);
	}
	nfsd4_cltrack_upcall_unlock(clp);
	kfree(has_session);
	kfree(legacy);
	kfree(hexid);

	return ret;
}

static void
nfsd4_umh_cltrack_grace_done(struct nfsd_net *nn)
{
	char *legacy;
	char timestr[22]; /* FIXME: better way to determine max size? */

	sprintf(timestr, "%ld", nn->boot_time);
	legacy = nfsd4_cltrack_legacy_topdir();
	nfsd4_umh_cltrack_upcall("gracedone", timestr, legacy, NULL);
	kfree(legacy);
}

static struct nfsd4_client_tracking_ops nfsd4_umh_tracking_ops = {
	.init		= nfsd4_umh_cltrack_init,
	.exit		= NULL,
	.create		= nfsd4_umh_cltrack_create,
	.remove		= nfsd4_umh_cltrack_remove,
	.check		= nfsd4_umh_cltrack_check,
	.grace_done	= nfsd4_umh_cltrack_grace_done,
};

int
nfsd4_client_tracking_init(struct net *net)
{
	int status;
	struct path path;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	/* just run the init if it the method is already decided */
	if (nn->client_tracking_ops)
		goto do_init;

	/*
	 * First, try a UMH upcall. It should succeed or fail quickly, so
	 * there's little harm in trying that first.
	 */
	nn->client_tracking_ops = &nfsd4_umh_tracking_ops;
	status = nn->client_tracking_ops->init(net);
	if (!status)
		return status;

	/*
	 * See if the recoverydir exists and is a directory. If it is,
	 * then use the legacy ops.
	 */
	nn->client_tracking_ops = &nfsd4_legacy_tracking_ops;
	status = kern_path(nfs4_recoverydir(), LOOKUP_FOLLOW, &path);
	if (!status) {
		status = d_is_dir(path.dentry);
		path_put(&path);
		if (status)
			goto do_init;
	}

	/* Finally, try to use nfsdcld */
	nn->client_tracking_ops = &nfsd4_cld_tracking_ops;
	printk(KERN_WARNING "NFSD: the nfsdcld client tracking upcall will be "
			"removed in 3.10. Please transition to using "
			"nfsdcltrack.\n");
do_init:
	status = nn->client_tracking_ops->init(net);
	if (status) {
		printk(KERN_WARNING "NFSD: Unable to initialize client "
				    "recovery tracking! (%d)\n", status);
		nn->client_tracking_ops = NULL;
	}
	return status;
}

void
nfsd4_client_tracking_exit(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);

	if (nn->client_tracking_ops) {
		if (nn->client_tracking_ops->exit)
			nn->client_tracking_ops->exit(net);
		nn->client_tracking_ops = NULL;
	}
}

void
nfsd4_client_record_create(struct nfs4_client *clp)
{
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	if (nn->client_tracking_ops)
		nn->client_tracking_ops->create(clp);
}

void
nfsd4_client_record_remove(struct nfs4_client *clp)
{
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	if (nn->client_tracking_ops)
		nn->client_tracking_ops->remove(clp);
}

int
nfsd4_client_record_check(struct nfs4_client *clp)
{
	struct nfsd_net *nn = net_generic(clp->net, nfsd_net_id);

	if (nn->client_tracking_ops)
		return nn->client_tracking_ops->check(clp);

	return -EOPNOTSUPP;
}

void
nfsd4_record_grace_done(struct nfsd_net *nn)
{
	if (nn->client_tracking_ops)
		nn->client_tracking_ops->grace_done(nn);
}

static int
rpc_pipefs_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct super_block *sb = ptr;
	struct net *net = sb->s_fs_info;
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	struct cld_net *cn = nn->cld_net;
	struct dentry *dentry;
	int ret = 0;

	if (!try_module_get(THIS_MODULE))
		return 0;

	if (!cn) {
		module_put(THIS_MODULE);
		return 0;
	}

	switch (event) {
	case RPC_PIPEFS_MOUNT:
		dentry = nfsd4_cld_register_sb(sb, cn->cn_pipe);
		if (IS_ERR(dentry)) {
			ret = PTR_ERR(dentry);
			break;
		}
		cn->cn_pipe->dentry = dentry;
		break;
	case RPC_PIPEFS_UMOUNT:
		if (cn->cn_pipe->dentry)
			nfsd4_cld_unregister_sb(cn->cn_pipe);
		break;
	default:
		ret = -ENOTSUPP;
		break;
	}
	module_put(THIS_MODULE);
	return ret;
}

static struct notifier_block nfsd4_cld_block = {
	.notifier_call = rpc_pipefs_event,
};

int
register_cld_notifier(void)
{
	return rpc_pipefs_notifier_register(&nfsd4_cld_block);
}

void
unregister_cld_notifier(void)
{
	rpc_pipefs_notifier_unregister(&nfsd4_cld_block);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/nfsd/nfs4recover.c */
/************************************************************/
