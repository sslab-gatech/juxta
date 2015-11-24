/*
 * Copyright (c) 2002, 2007 Red Hat, Inc. All rights reserved.
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>
 *          David Howells <dhowells@redhat.com>
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/circ_buf.h>
#include <linux/sched.h>
#include "internal.h"
#include "../../inc/__fss.h"

#if 0
unsigned afs_vnode_update_timeout = 10;
#endif  /*  0  */

#define afs_breakring_space(server) \
	CIRC_SPACE((server)->cb_break_head, (server)->cb_break_tail,	\
		   ARRAY_SIZE((server)->cb_break))

//static void afs_callback_updater(struct work_struct *);

static struct workqueue_struct *afs_callback_update_worker;

/*
 * allow the fileserver to request callback state (re-)initialisation
 */
void afs_init_callback_state(struct afs_server *server)
{
	struct afs_vnode *vnode;

	_enter("{%p}", server);

	spin_lock(&server->cb_lock);

	/* kill all the promises on record from this server */
	while (!RB_EMPTY_ROOT(&server->cb_promises)) {
		vnode = rb_entry(server->cb_promises.rb_node,
				 struct afs_vnode, cb_promise);
		_debug("UNPROMISE { vid=%x:%u uq=%u}",
		       vnode->fid.vid, vnode->fid.vnode, vnode->fid.unique);
		rb_erase(&vnode->cb_promise, &server->cb_promises);
		vnode->cb_promised = false;
	}

	spin_unlock(&server->cb_lock);
	_leave("");
}

/*
 * handle the data invalidation side of a callback being broken
 */
void afs_broken_callback_work(struct work_struct *work)
{
	struct afs_vnode *vnode =
		container_of(work, struct afs_vnode, cb_broken_work);

	_enter("");

	if (test_bit(AFS_VNODE_DELETED, &vnode->flags))
		return;

	/* we're only interested in dealing with a broken callback on *this*
	 * vnode and only if no-one else has dealt with it yet */
	if (!mutex_trylock(&vnode->validate_lock))
		return; /* someone else is dealing with it */

	if (test_bit(AFS_VNODE_CB_BROKEN, &vnode->flags)) {
		if (S_ISDIR(vnode->vfs_inode.i_mode))
			afs_clear_permits(vnode);

		if (afs_vnode_fetch_status(vnode, NULL, NULL) < 0)
			goto out;

		if (test_bit(AFS_VNODE_DELETED, &vnode->flags))
			goto out;

		/* if the vnode's data version number changed then its contents
		 * are different */
		if (test_and_clear_bit(AFS_VNODE_ZAP_DATA, &vnode->flags))
			afs_zap_data(vnode);
	}

out:
	mutex_unlock(&vnode->validate_lock);

	/* avoid the potential race whereby the mutex_trylock() in this
	 * function happens again between the clear_bit() and the
	 * mutex_unlock() */
	if (test_bit(AFS_VNODE_CB_BROKEN, &vnode->flags)) {
		_debug("requeue");
		queue_work(afs_callback_update_worker, &vnode->cb_broken_work);
	}
	_leave("");
}

/*
 * actually break a callback
 */
static void afs_break_callback(struct afs_server *server,
			       struct afs_vnode *vnode)
{
	_enter("");

	set_bit(AFS_VNODE_CB_BROKEN, &vnode->flags);

	if (vnode->cb_promised) {
		spin_lock(&vnode->lock);

		_debug("break callback");

		spin_lock(&server->cb_lock);
		if (vnode->cb_promised) {
			rb_erase(&vnode->cb_promise, &server->cb_promises);
			vnode->cb_promised = false;
		}
		spin_unlock(&server->cb_lock);

		queue_work(afs_callback_update_worker, &vnode->cb_broken_work);
		if (list_empty(&vnode->granted_locks) &&
		    !list_empty(&vnode->pending_locks))
			afs_lock_may_be_available(vnode);
		spin_unlock(&vnode->lock);
	}
}

/*
 * allow the fileserver to explicitly break one callback
 * - happens when
 *   - the backing file is changed
 *   - a lock is released
 */
static void afs_break_one_callback(struct afs_server *server,
				   struct afs_fid *fid)
{
	struct afs_vnode *vnode;
	struct rb_node *p;

	_debug("find");
	spin_lock(&server->fs_lock);
	p = server->fs_vnodes.rb_node;
	while (p) {
		vnode = rb_entry(p, struct afs_vnode, server_rb);
		if (fid->vid < vnode->fid.vid)
			p = p->rb_left;
		else if (fid->vid > vnode->fid.vid)
			p = p->rb_right;
		else if (fid->vnode < vnode->fid.vnode)
			p = p->rb_left;
		else if (fid->vnode > vnode->fid.vnode)
			p = p->rb_right;
		else if (fid->unique < vnode->fid.unique)
			p = p->rb_left;
		else if (fid->unique > vnode->fid.unique)
			p = p->rb_right;
		else
			goto found;
	}

	/* not found so we just ignore it (it may have moved to another
	 * server) */
not_available:
	_debug("not avail");
	spin_unlock(&server->fs_lock);
	_leave("");
	return;

found:
	_debug("found");
	ASSERTCMP(server, ==, vnode->server);

	if (!igrab(AFS_VNODE_TO_I(vnode)))
		goto not_available;
	spin_unlock(&server->fs_lock);

	afs_break_callback(server, vnode);
	iput(&vnode->vfs_inode);
	_leave("");
}

/*
 * allow the fileserver to break callback promises
 */
void afs_break_callbacks(struct afs_server *server, size_t count,
			 struct afs_callback callbacks[])
{
	_enter("%p,%zu,", server, count);

	ASSERT(server != NULL);
	ASSERTCMP(count, <=, AFSCBMAX);

	for (; count > 0; callbacks++, count--) {
		_debug("- Fid { vl=%08x n=%u u=%u }  CB { v=%u x=%u t=%u }",
		       callbacks->fid.vid,
		       callbacks->fid.vnode,
		       callbacks->fid.unique,
		       callbacks->version,
		       callbacks->expiry,
		       callbacks->type
		       );
		afs_break_one_callback(server, &callbacks->fid);
	}

	_leave("");
	return;
}

/*
 * record the callback for breaking
 * - the caller must hold server->cb_lock
 */
static void afs_do_give_up_callback(struct afs_server *server,
				    struct afs_vnode *vnode)
{
	struct afs_callback *cb;

	_enter("%p,%p", server, vnode);

	cb = &server->cb_break[server->cb_break_head];
	cb->fid		= vnode->fid;
	cb->version	= vnode->cb_version;
	cb->expiry	= vnode->cb_expiry;
	cb->type	= vnode->cb_type;
	smp_wmb();
	server->cb_break_head =
		(server->cb_break_head + 1) &
		(ARRAY_SIZE(server->cb_break) - 1);

	/* defer the breaking of callbacks to try and collect as many as
	 * possible to ship in one operation */
	switch (atomic_inc_return(&server->cb_break_n)) {
	case 1 ... AFSCBMAX - 1:
		queue_delayed_work(afs_callback_update_worker,
				   &server->cb_break_work, HZ * 2);
		break;
	case AFSCBMAX:
		afs_flush_callback_breaks(server);
		break;
	default:
		break;
	}

	ASSERT(server->cb_promises.rb_node != NULL);
	rb_erase(&vnode->cb_promise, &server->cb_promises);
	vnode->cb_promised = false;
	_leave("");
}

/*
 * discard the callback on a deleted item
 */
void afs_discard_callback_on_delete(struct afs_vnode *vnode)
{
	struct afs_server *server = vnode->server;

	_enter("%d", vnode->cb_promised);

	if (!vnode->cb_promised) {
		_leave(" [not promised]");
		return;
	}

	ASSERT(server != NULL);

	spin_lock(&server->cb_lock);
	if (vnode->cb_promised) {
		ASSERT(server->cb_promises.rb_node != NULL);
		rb_erase(&vnode->cb_promise, &server->cb_promises);
		vnode->cb_promised = false;
	}
	spin_unlock(&server->cb_lock);
	_leave("");
}

/*
 * give up the callback registered for a vnode on the file server when the
 * inode is being cleared
 */
void afs_give_up_callback(struct afs_vnode *vnode)
{
	struct afs_server *server = vnode->server;

	DECLARE_WAITQUEUE(myself, current);

	_enter("%d", vnode->cb_promised);

	_debug("GIVE UP INODE %p", &vnode->vfs_inode);

	if (!vnode->cb_promised) {
		_leave(" [not promised]");
		return;
	}

	ASSERT(server != NULL);

	spin_lock(&server->cb_lock);
	if (vnode->cb_promised && afs_breakring_space(server) == 0) {
		add_wait_queue(&server->cb_break_waitq, &myself);
		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (!vnode->cb_promised ||
			    afs_breakring_space(server) != 0)
				break;
			spin_unlock(&server->cb_lock);
			schedule();
			spin_lock(&server->cb_lock);
		}
		remove_wait_queue(&server->cb_break_waitq, &myself);
		__set_current_state(TASK_RUNNING);
	}

	/* of course, it's always possible for the server to break this vnode's
	 * callback first... */
	if (vnode->cb_promised)
		afs_do_give_up_callback(server, vnode);

	spin_unlock(&server->cb_lock);
	_leave("");
}

/*
 * dispatch a deferred give up callbacks operation
 */
void afs_dispatch_give_up_callbacks(struct work_struct *work)
{
	struct afs_server *server =
		container_of(work, struct afs_server, cb_break_work.work);

	_enter("");

	/* tell the fileserver to discard the callback promises it has
	 * - in the event of ENOMEM or some other error, we just forget that we
	 *   had callbacks entirely, and the server will call us later to break
	 *   them
	 */
	afs_fs_give_up_callbacks(server, &afs_async_call);
}

/*
 * flush the outstanding callback breaks on a server
 */
void afs_flush_callback_breaks(struct afs_server *server)
{
	mod_delayed_work(afs_callback_update_worker, &server->cb_break_work, 0);
}

#if 0
/*
 * update a bunch of callbacks
 */
static void afs_callback_updater(struct work_struct *work)
{
	struct afs_server *server;
	struct afs_vnode *vnode, *xvnode;
	time_t now;
	long timeout;
	int ret;

	server = container_of(work, struct afs_server, updater);

	_enter("");

	now = get_seconds();

	/* find the first vnode to update */
	spin_lock(&server->cb_lock);
	for (;;) {
		if (RB_EMPTY_ROOT(&server->cb_promises)) {
			spin_unlock(&server->cb_lock);
			_leave(" [nothing]");
			return;
		}

		vnode = rb_entry(rb_first(&server->cb_promises),
				 struct afs_vnode, cb_promise);
		if (atomic_read(&vnode->usage) > 0)
			break;
		rb_erase(&vnode->cb_promise, &server->cb_promises);
		vnode->cb_promised = false;
	}

	timeout = vnode->update_at - now;
	if (timeout > 0) {
		queue_delayed_work(afs_vnode_update_worker,
				   &afs_vnode_update, timeout * HZ);
		spin_unlock(&server->cb_lock);
		_leave(" [nothing]");
		return;
	}

	list_del_init(&vnode->update);
	atomic_inc(&vnode->usage);
	spin_unlock(&server->cb_lock);

	/* we can now perform the update */
	_debug("update %s", vnode->vldb.name);
	vnode->state = AFS_VL_UPDATING;
	vnode->upd_rej_cnt = 0;
	vnode->upd_busy_cnt = 0;

	ret = afs_vnode_update_record(vl, &vldb);
	switch (ret) {
	case 0:
		afs_vnode_apply_update(vl, &vldb);
		vnode->state = AFS_VL_UPDATING;
		break;
	case -ENOMEDIUM:
		vnode->state = AFS_VL_VOLUME_DELETED;
		break;
	default:
		vnode->state = AFS_VL_UNCERTAIN;
		break;
	}

	/* and then reschedule */
	_debug("reschedule");
	vnode->update_at = get_seconds() + afs_vnode_update_timeout;

	spin_lock(&server->cb_lock);

	if (!list_empty(&server->cb_promises)) {
		/* next update in 10 minutes, but wait at least 1 second more
		 * than the newest record already queued so that we don't spam
		 * the VL server suddenly with lots of requests
		 */
		xvnode = list_entry(server->cb_promises.prev,
				    struct afs_vnode, update);
		if (vnode->update_at <= xvnode->update_at)
			vnode->update_at = xvnode->update_at + 1;
		xvnode = list_entry(server->cb_promises.next,
				    struct afs_vnode, update);
		timeout = xvnode->update_at - now;
		if (timeout < 0)
			timeout = 0;
	} else {
		timeout = afs_vnode_update_timeout;
	}

	list_add_tail(&vnode->update, &server->cb_promises);

	_debug("timeout %ld", timeout);
	queue_delayed_work(afs_vnode_update_worker,
			   &afs_vnode_update, timeout * HZ);
	spin_unlock(&server->cb_lock);
	afs_put_vnode(vl);
}
#endif

/*
 * initialise the callback update process
 */
int __init afs_callback_update_init(void)
{
	afs_callback_update_worker =
		create_singlethread_workqueue("kafs_callbackd");
	return afs_callback_update_worker ? 0 : -ENOMEM;
}

/*
 * shut down the callback update process
 */
void afs_callback_update_kill(void)
{
	destroy_workqueue(afs_callback_update_worker);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/callback.c */
/************************************************************/
/* AFS cell and server record management
 *
 * Copyright (C) 2002 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/module.h>
#include <linux/slab.h>
#include <linux/key.h>
#include <linux/ctype.h>
#include <linux/dns_resolver.h>
// #include <linux/sched.h>
#include <keys/rxrpc-type.h>
// #include "internal.h"
#include "../../inc/__fss.h"

DECLARE_RWSEM(afs_proc_cells_sem);
LIST_HEAD(afs_proc_cells);

static LIST_HEAD(afs_cells);
static DEFINE_RWLOCK(afs_cells_lock);
static DECLARE_RWSEM(afs_cells_sem); /* add/remove serialisation */
static DECLARE_WAIT_QUEUE_HEAD(afs_cells_freeable_wq);
static struct afs_cell *afs_cell_root;

/*
 * allocate a cell record and fill in its name, VL server address list and
 * allocate an anonymous key
 */
static struct afs_cell *afs_cell_alloc(const char *name, unsigned namelen,
				       char *vllist)
{
	struct afs_cell *cell;
	struct key *key;
	char keyname[4 + AFS_MAXCELLNAME + 1], *cp, *dp, *next;
	char  *dvllist = NULL, *_vllist = NULL;
	char  delimiter = ':';
	int ret;

	_enter("%*.*s,%s", namelen, namelen, name ?: "", vllist);

	BUG_ON(!name); /* TODO: want to look up "this cell" in the cache */

	if (namelen > AFS_MAXCELLNAME) {
		_leave(" = -ENAMETOOLONG");
		return ERR_PTR(-ENAMETOOLONG);
	}

	/* allocate and initialise a cell record */
	cell = kzalloc(sizeof(struct afs_cell) + namelen + 1, GFP_KERNEL);
	if (!cell) {
		_leave(" = -ENOMEM");
		return ERR_PTR(-ENOMEM);
	}

	memcpy(cell->name, name, namelen);
	cell->name[namelen] = 0;

	atomic_set(&cell->usage, 1);
	INIT_LIST_HEAD(&cell->link);
	rwlock_init(&cell->servers_lock);
	INIT_LIST_HEAD(&cell->servers);
	init_rwsem(&cell->vl_sem);
	INIT_LIST_HEAD(&cell->vl_list);
	spin_lock_init(&cell->vl_lock);

	/* if the ip address is invalid, try dns query */
	if (!vllist || strlen(vllist) < 7) {
		ret = dns_query("afsdb", name, namelen, "ipv4", &dvllist, NULL);
		if (ret < 0) {
			if (ret == -ENODATA || ret == -EAGAIN || ret == -ENOKEY)
				/* translate these errors into something
				 * userspace might understand */
				ret = -EDESTADDRREQ;
			_leave(" = %d", ret);
			return ERR_PTR(ret);
		}
		_vllist = dvllist;

		/* change the delimiter for user-space reply */
		delimiter = ',';

	} else {
		_vllist = vllist;
	}

	/* fill in the VL server list from the rest of the string */
	do {
		unsigned a, b, c, d;

		next = strchr(_vllist, delimiter);
		if (next)
			*next++ = 0;

		if (sscanf(_vllist, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
			goto bad_address;

		if (a > 255 || b > 255 || c > 255 || d > 255)
			goto bad_address;

		cell->vl_addrs[cell->vl_naddrs++].s_addr =
			htonl((a << 24) | (b << 16) | (c << 8) | d);

	} while (cell->vl_naddrs < AFS_CELL_MAX_ADDRS && (_vllist = next));

	/* create a key to represent an anonymous user */
	memcpy(keyname, "afs@", 4);
	dp = keyname + 4;
	cp = cell->name;
	do {
		*dp++ = toupper(*cp);
	} while (*cp++);

	key = rxrpc_get_null_key(keyname);
	if (IS_ERR(key)) {
		_debug("no key");
		ret = PTR_ERR(key);
		goto error;
	}
	cell->anonymous_key = key;

	_debug("anon key %p{%x}",
	       cell->anonymous_key, key_serial(cell->anonymous_key));

	_leave(" = %p", cell);
	return cell;

bad_address:
	printk(KERN_ERR "kAFS: bad VL server IP address\n");
	ret = -EINVAL;
error:
	key_put(cell->anonymous_key);
	kfree(dvllist);
	kfree(cell);
	_leave(" = %d", ret);
	return ERR_PTR(ret);
}

/*
 * afs_cell_crate() - create a cell record
 * @name:	is the name of the cell.
 * @namsesz:	is the strlen of the cell name.
 * @vllist:	is a colon separated list of IP addresses in "a.b.c.d" format.
 * @retref:	is T to return the cell reference when the cell exists.
 */
struct afs_cell *afs_cell_create(const char *name, unsigned namesz,
				 char *vllist, bool retref)
{
	struct afs_cell *cell;
	int ret;

	_enter("%*.*s,%s", namesz, namesz, name ?: "", vllist);

	down_write(&afs_cells_sem);
	read_lock(&afs_cells_lock);
	list_for_each_entry(cell, &afs_cells, link) {
		if (strncasecmp(cell->name, name, namesz) == 0)
			goto duplicate_name;
	}
	read_unlock(&afs_cells_lock);

	cell = afs_cell_alloc(name, namesz, vllist);
	if (IS_ERR(cell)) {
		_leave(" = %ld", PTR_ERR(cell));
		up_write(&afs_cells_sem);
		return cell;
	}

	/* add a proc directory for this cell */
	ret = afs_proc_cell_setup(cell);
	if (ret < 0)
		goto error;

#ifdef CONFIG_AFS_FSCACHE
	/* put it up for caching (this never returns an error) */
	cell->cache = fscache_acquire_cookie(afs_cache_netfs.primary_index,
					     &afs_cell_cache_index_def,
					     cell, true);
#endif

	/* add to the cell lists */
	write_lock(&afs_cells_lock);
	list_add_tail(&cell->link, &afs_cells);
	write_unlock(&afs_cells_lock);

	down_write(&afs_proc_cells_sem);
	list_add_tail(&cell->proc_link, &afs_proc_cells);
	up_write(&afs_proc_cells_sem);
	up_write(&afs_cells_sem);

	_leave(" = %p", cell);
	return cell;

error:
	up_write(&afs_cells_sem);
	key_put(cell->anonymous_key);
	kfree(cell);
	_leave(" = %d", ret);
	return ERR_PTR(ret);

duplicate_name:
	if (retref && !IS_ERR(cell))
		afs_get_cell(cell);

	read_unlock(&afs_cells_lock);
	up_write(&afs_cells_sem);

	if (retref) {
		_leave(" = %p", cell);
		return cell;
	}

	_leave(" = -EEXIST");
	return ERR_PTR(-EEXIST);
}

/*
 * set the root cell information
 * - can be called with a module parameter string
 * - can be called from a write to /proc/fs/afs/rootcell
 */
int afs_cell_init(char *rootcell)
{
	struct afs_cell *old_root, *new_root;
	char *cp;

	_enter("");

	if (!rootcell) {
		/* module is loaded with no parameters, or built statically.
		 * - in the future we might initialize cell DB here.
		 */
		_leave(" = 0 [no root]");
		return 0;
	}

	cp = strchr(rootcell, ':');
	if (!cp)
		_debug("kAFS: no VL server IP addresses specified");
	else
		*cp++ = 0;

	/* allocate a cell record for the root cell */
	new_root = afs_cell_create(rootcell, strlen(rootcell), cp, false);
	if (IS_ERR(new_root)) {
		_leave(" = %ld", PTR_ERR(new_root));
		return PTR_ERR(new_root);
	}

	/* install the new cell */
	write_lock(&afs_cells_lock);
	old_root = afs_cell_root;
	afs_cell_root = new_root;
	write_unlock(&afs_cells_lock);
	afs_put_cell(old_root);

	_leave(" = 0");
	return 0;
}

/*
 * lookup a cell record
 */
struct afs_cell *afs_cell_lookup(const char *name, unsigned namesz,
				 bool dns_cell)
{
	struct afs_cell *cell;

	_enter("\"%*.*s\",", namesz, namesz, name ?: "");

	down_read(&afs_cells_sem);
	read_lock(&afs_cells_lock);

	if (name) {
		/* if the cell was named, look for it in the cell record list */
		list_for_each_entry(cell, &afs_cells, link) {
			if (strncmp(cell->name, name, namesz) == 0) {
				afs_get_cell(cell);
				goto found;
			}
		}
		cell = ERR_PTR(-ENOENT);
		if (dns_cell)
			goto create_cell;
	found:
		;
	} else {
		cell = afs_cell_root;
		if (!cell) {
			/* this should not happen unless user tries to mount
			 * when root cell is not set. Return an impossibly
			 * bizarre errno to alert the user. Things like
			 * ENOENT might be "more appropriate" but they happen
			 * for other reasons.
			 */
			cell = ERR_PTR(-EDESTADDRREQ);
		} else {
			afs_get_cell(cell);
		}

	}

	read_unlock(&afs_cells_lock);
	up_read(&afs_cells_sem);
	_leave(" = %p", cell);
	return cell;

create_cell:
	read_unlock(&afs_cells_lock);
	up_read(&afs_cells_sem);

	cell = afs_cell_create(name, namesz, NULL, true);

	_leave(" = %p", cell);
	return cell;
}

#if 0
/*
 * try and get a cell record
 */
struct afs_cell *afs_get_cell_maybe(struct afs_cell *cell)
{
	write_lock(&afs_cells_lock);

	if (cell && !list_empty(&cell->link))
		afs_get_cell(cell);
	else
		cell = NULL;

	write_unlock(&afs_cells_lock);
	return cell;
}
#endif  /*  0  */

/*
 * destroy a cell record
 */
void afs_put_cell(struct afs_cell *cell)
{
	if (!cell)
		return;

	_enter("%p{%d,%s}", cell, atomic_read(&cell->usage), cell->name);

	ASSERTCMP(atomic_read(&cell->usage), >, 0);

	/* to prevent a race, the decrement and the dequeue must be effectively
	 * atomic */
	write_lock(&afs_cells_lock);

	if (likely(!atomic_dec_and_test(&cell->usage))) {
		write_unlock(&afs_cells_lock);
		_leave("");
		return;
	}

	ASSERT(list_empty(&cell->servers));
	ASSERT(list_empty(&cell->vl_list));

	write_unlock(&afs_cells_lock);

	wake_up(&afs_cells_freeable_wq);

	_leave(" [unused]");
}

/*
 * destroy a cell record
 * - must be called with the afs_cells_sem write-locked
 * - cell->link should have been broken by the caller
 */
static void afs_cell_destroy(struct afs_cell *cell)
{
	_enter("%p{%d,%s}", cell, atomic_read(&cell->usage), cell->name);

	ASSERTCMP(atomic_read(&cell->usage), >=, 0);
	ASSERT(list_empty(&cell->link));

	/* wait for everyone to stop using the cell */
	if (atomic_read(&cell->usage) > 0) {
		DECLARE_WAITQUEUE(myself, current);

		_debug("wait for cell %s", cell->name);
		set_current_state(TASK_UNINTERRUPTIBLE);
		add_wait_queue(&afs_cells_freeable_wq, &myself);

		while (atomic_read(&cell->usage) > 0) {
			schedule();
			set_current_state(TASK_UNINTERRUPTIBLE);
		}

		remove_wait_queue(&afs_cells_freeable_wq, &myself);
		set_current_state(TASK_RUNNING);
	}

	_debug("cell dead");
	ASSERTCMP(atomic_read(&cell->usage), ==, 0);
	ASSERT(list_empty(&cell->servers));
	ASSERT(list_empty(&cell->vl_list));

	afs_proc_cell_remove(cell);

	down_write(&afs_proc_cells_sem);
	list_del_init(&cell->proc_link);
	up_write(&afs_proc_cells_sem);

#ifdef CONFIG_AFS_FSCACHE
	fscache_relinquish_cookie(cell->cache, 0);
#endif
	key_put(cell->anonymous_key);
	kfree(cell);

	_leave(" [destroyed]");
}

/*
 * purge in-memory cell database on module unload or afs_init() failure
 * - the timeout daemon is stopped before calling this
 */
void afs_cell_purge(void)
{
	struct afs_cell *cell;

	_enter("");

	afs_put_cell(afs_cell_root);

	down_write(&afs_cells_sem);

	while (!list_empty(&afs_cells)) {
		cell = NULL;

		/* remove the next cell from the front of the list */
		write_lock(&afs_cells_lock);

		if (!list_empty(&afs_cells)) {
			cell = list_entry(afs_cells.next,
					  struct afs_cell, link);
			list_del_init(&cell->link);
		}

		write_unlock(&afs_cells_lock);

		if (cell) {
			_debug("PURGING CELL %s (%d)",
			       cell->name, atomic_read(&cell->usage));

			/* now the cell should be left with no references */
			afs_cell_destroy(cell);
		}
	}

	up_write(&afs_cells_sem);
	_leave("");
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/cell.c */
/************************************************************/
/* AFS Cache Manager Service
 *
 * Copyright (C) 2002 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/module.h>
// #include <linux/init.h>
// #include <linux/slab.h>
// #include <linux/sched.h>
#include <linux/ip.h>
// #include "internal.h"
#include "afs_cm.h"
#include "../../inc/__fss.h"

#if 0
struct workqueue_struct *afs_cm_workqueue;
#endif  /*  0  */

static int afs_deliver_cb_init_call_back_state(struct afs_call *,
					       struct sk_buff *, bool);
static int afs_deliver_cb_init_call_back_state3(struct afs_call *,
						struct sk_buff *, bool);
static int afs_deliver_cb_probe(struct afs_call *, struct sk_buff *, bool);
static int afs_deliver_cb_callback(struct afs_call *, struct sk_buff *, bool);
static int afs_deliver_cb_probe_uuid(struct afs_call *, struct sk_buff *, bool);
static int afs_deliver_cb_tell_me_about_yourself(struct afs_call *,
						 struct sk_buff *, bool);
static void afs_cm_destructor(struct afs_call *);

/*
 * CB.CallBack operation type
 */
static const struct afs_call_type afs_SRXCBCallBack = {
	.name		= "CB.CallBack",
	.deliver	= afs_deliver_cb_callback,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_cm_destructor,
};

/*
 * CB.InitCallBackState operation type
 */
static const struct afs_call_type afs_SRXCBInitCallBackState = {
	.name		= "CB.InitCallBackState",
	.deliver	= afs_deliver_cb_init_call_back_state,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_cm_destructor,
};

/*
 * CB.InitCallBackState3 operation type
 */
static const struct afs_call_type afs_SRXCBInitCallBackState3 = {
	.name		= "CB.InitCallBackState3",
	.deliver	= afs_deliver_cb_init_call_back_state3,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_cm_destructor,
};

/*
 * CB.Probe operation type
 */
static const struct afs_call_type afs_SRXCBProbe = {
	.name		= "CB.Probe",
	.deliver	= afs_deliver_cb_probe,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_cm_destructor,
};

/*
 * CB.ProbeUuid operation type
 */
static const struct afs_call_type afs_SRXCBProbeUuid = {
	.name		= "CB.ProbeUuid",
	.deliver	= afs_deliver_cb_probe_uuid,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_cm_destructor,
};

/*
 * CB.TellMeAboutYourself operation type
 */
static const struct afs_call_type afs_SRXCBTellMeAboutYourself = {
	.name		= "CB.TellMeAboutYourself",
	.deliver	= afs_deliver_cb_tell_me_about_yourself,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_cm_destructor,
};

/*
 * route an incoming cache manager call
 * - return T if supported, F if not
 */
bool afs_cm_incoming_call(struct afs_call *call)
{
	u32 operation_id = ntohl(call->operation_ID);

	_enter("{CB.OP %u}", operation_id);

	switch (operation_id) {
	case CBCallBack:
		call->type = &afs_SRXCBCallBack;
		return true;
	case CBInitCallBackState:
		call->type = &afs_SRXCBInitCallBackState;
		return true;
	case CBInitCallBackState3:
		call->type = &afs_SRXCBInitCallBackState3;
		return true;
	case CBProbe:
		call->type = &afs_SRXCBProbe;
		return true;
	case CBTellMeAboutYourself:
		call->type = &afs_SRXCBTellMeAboutYourself;
		return true;
	default:
		return false;
	}
}

/*
 * clean up a cache manager call
 */
static void afs_cm_destructor(struct afs_call *call)
{
	_enter("");

	/* Break the callbacks here so that we do it after the final ACK is
	 * received.  The step number here must match the final number in
	 * afs_deliver_cb_callback().
	 */
	if (call->unmarshall == 6) {
		ASSERT(call->server && call->count && call->request);
		afs_break_callbacks(call->server, call->count, call->request);
	}

	afs_put_server(call->server);
	call->server = NULL;
	kfree(call->buffer);
	call->buffer = NULL;
}

/*
 * allow the fileserver to see if the cache manager is still alive
 */
static void SRXAFSCB_CallBack(struct work_struct *work)
{
	struct afs_call *call = container_of(work, struct afs_call, work);

	_enter("");

	/* be sure to send the reply *before* attempting to spam the AFS server
	 * with FSFetchStatus requests on the vnodes with broken callbacks lest
	 * the AFS server get into a vicious cycle of trying to break further
	 * callbacks because it hadn't received completion of the CBCallBack op
	 * yet */
	afs_send_empty_reply(call);

	afs_break_callbacks(call->server, call->count, call->request);
	_leave("");
}

/*
 * deliver request data to a CB.CallBack call
 */
static int afs_deliver_cb_callback(struct afs_call *call, struct sk_buff *skb,
				   bool last)
{
	struct afs_callback *cb;
	struct afs_server *server;
	struct in_addr addr;
	__be32 *bp;
	u32 tmp;
	int ret, loop;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	switch (call->unmarshall) {
	case 0:
		call->offset = 0;
		call->unmarshall++;

		/* extract the FID array and its count in two steps */
	case 1:
		_debug("extract FID count");
		ret = afs_extract_data(call, skb, last, &call->tmp, 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->count = ntohl(call->tmp);
		_debug("FID count: %u", call->count);
		if (call->count > AFSCBMAX)
			return -EBADMSG;

		call->buffer = kmalloc(call->count * 3 * 4, GFP_KERNEL);
		if (!call->buffer)
			return -ENOMEM;
		call->offset = 0;
		call->unmarshall++;

	case 2:
		_debug("extract FID array");
		ret = afs_extract_data(call, skb, last, call->buffer,
				       call->count * 3 * 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		_debug("unmarshall FID array");
		call->request = kcalloc(call->count,
					sizeof(struct afs_callback),
					GFP_KERNEL);
		if (!call->request)
			return -ENOMEM;

		cb = call->request;
		bp = call->buffer;
		for (loop = call->count; loop > 0; loop--, cb++) {
			cb->fid.vid	= ntohl(*bp++);
			cb->fid.vnode	= ntohl(*bp++);
			cb->fid.unique	= ntohl(*bp++);
			cb->type	= AFSCM_CB_UNTYPED;
		}

		call->offset = 0;
		call->unmarshall++;

		/* extract the callback array and its count in two steps */
	case 3:
		_debug("extract CB count");
		ret = afs_extract_data(call, skb, last, &call->tmp, 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		tmp = ntohl(call->tmp);
		_debug("CB count: %u", tmp);
		if (tmp != call->count && tmp != 0)
			return -EBADMSG;
		call->offset = 0;
		call->unmarshall++;
		if (tmp == 0)
			goto empty_cb_array;

	case 4:
		_debug("extract CB array");
		ret = afs_extract_data(call, skb, last, call->request,
				       call->count * 3 * 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		_debug("unmarshall CB array");
		cb = call->request;
		bp = call->buffer;
		for (loop = call->count; loop > 0; loop--, cb++) {
			cb->version	= ntohl(*bp++);
			cb->expiry	= ntohl(*bp++);
			cb->type	= ntohl(*bp++);
		}

	empty_cb_array:
		call->offset = 0;
		call->unmarshall++;

	case 5:
		_debug("trailer");
		if (skb->len != 0)
			return -EBADMSG;

		/* Record that the message was unmarshalled successfully so
		 * that the call destructor can know do the callback breaking
		 * work, even if the final ACK isn't received.
		 *
		 * If the step number changes, then afs_cm_destructor() must be
		 * updated also.
		 */
		call->unmarshall++;
	case 6:
		break;
	}

	if (!last)
		return 0;

	call->state = AFS_CALL_REPLYING;

	/* we'll need the file server record as that tells us which set of
	 * vnodes to operate upon */
	memcpy(&addr, &ip_hdr(skb)->saddr, 4);
	server = afs_find_server(&addr);
	if (!server)
		return -ENOTCONN;
	call->server = server;

	INIT_WORK(&call->work, SRXAFSCB_CallBack);
	queue_work(afs_wq, &call->work);
	return 0;
}

/*
 * allow the fileserver to request callback state (re-)initialisation
 */
static void SRXAFSCB_InitCallBackState(struct work_struct *work)
{
	struct afs_call *call = container_of(work, struct afs_call, work);

	_enter("{%p}", call->server);

	afs_init_callback_state(call->server);
	afs_send_empty_reply(call);
	_leave("");
}

/*
 * deliver request data to a CB.InitCallBackState call
 */
static int afs_deliver_cb_init_call_back_state(struct afs_call *call,
					       struct sk_buff *skb,
					       bool last)
{
	struct afs_server *server;
	struct in_addr addr;

	_enter(",{%u},%d", skb->len, last);

	if (skb->len > 0)
		return -EBADMSG;
	if (!last)
		return 0;

	/* no unmarshalling required */
	call->state = AFS_CALL_REPLYING;

	/* we'll need the file server record as that tells us which set of
	 * vnodes to operate upon */
	memcpy(&addr, &ip_hdr(skb)->saddr, 4);
	server = afs_find_server(&addr);
	if (!server)
		return -ENOTCONN;
	call->server = server;

	INIT_WORK(&call->work, SRXAFSCB_InitCallBackState);
	queue_work(afs_wq, &call->work);
	return 0;
}

/*
 * deliver request data to a CB.InitCallBackState3 call
 */
static int afs_deliver_cb_init_call_back_state3(struct afs_call *call,
						struct sk_buff *skb,
						bool last)
{
	struct afs_server *server;
	struct in_addr addr;

	_enter(",{%u},%d", skb->len, last);

	if (!last)
		return 0;

	/* no unmarshalling required */
	call->state = AFS_CALL_REPLYING;

	/* we'll need the file server record as that tells us which set of
	 * vnodes to operate upon */
	memcpy(&addr, &ip_hdr(skb)->saddr, 4);
	server = afs_find_server(&addr);
	if (!server)
		return -ENOTCONN;
	call->server = server;

	INIT_WORK(&call->work, SRXAFSCB_InitCallBackState);
	queue_work(afs_wq, &call->work);
	return 0;
}

/*
 * allow the fileserver to see if the cache manager is still alive
 */
static void SRXAFSCB_Probe(struct work_struct *work)
{
	struct afs_call *call = container_of(work, struct afs_call, work);

	_enter("");
	afs_send_empty_reply(call);
	_leave("");
}

/*
 * deliver request data to a CB.Probe call
 */
static int afs_deliver_cb_probe(struct afs_call *call, struct sk_buff *skb,
				bool last)
{
	_enter(",{%u},%d", skb->len, last);

	if (skb->len > 0)
		return -EBADMSG;
	if (!last)
		return 0;

	/* no unmarshalling required */
	call->state = AFS_CALL_REPLYING;

	INIT_WORK(&call->work, SRXAFSCB_Probe);
	queue_work(afs_wq, &call->work);
	return 0;
}

/*
 * allow the fileserver to quickly find out if the fileserver has been rebooted
 */
static void SRXAFSCB_ProbeUuid(struct work_struct *work)
{
	struct afs_call *call = container_of(work, struct afs_call, work);
	struct afs_uuid *r = call->request;

	struct {
		__be32	match;
	} reply;

	_enter("");


	if (memcmp(r, &afs_uuid, sizeof(afs_uuid)) == 0)
		reply.match = htonl(0);
	else
		reply.match = htonl(1);

	afs_send_simple_reply(call, &reply, sizeof(reply));
	_leave("");
}

/*
 * deliver request data to a CB.ProbeUuid call
 */
static int afs_deliver_cb_probe_uuid(struct afs_call *call, struct sk_buff *skb,
				     bool last)
{
	struct afs_uuid *r;
	unsigned loop;
	__be32 *b;
	int ret;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	if (skb->len > 0)
		return -EBADMSG;
	if (!last)
		return 0;

	switch (call->unmarshall) {
	case 0:
		call->offset = 0;
		call->buffer = kmalloc(11 * sizeof(__be32), GFP_KERNEL);
		if (!call->buffer)
			return -ENOMEM;
		call->unmarshall++;

	case 1:
		_debug("extract UUID");
		ret = afs_extract_data(call, skb, last, call->buffer,
				       11 * sizeof(__be32));
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		_debug("unmarshall UUID");
		call->request = kmalloc(sizeof(struct afs_uuid), GFP_KERNEL);
		if (!call->request)
			return -ENOMEM;

		b = call->buffer;
		r = call->request;
		r->time_low			= ntohl(b[0]);
		r->time_mid			= ntohl(b[1]);
		r->time_hi_and_version		= ntohl(b[2]);
		r->clock_seq_hi_and_reserved 	= ntohl(b[3]);
		r->clock_seq_low		= ntohl(b[4]);

		for (loop = 0; loop < 6; loop++)
			r->node[loop] = ntohl(b[loop + 5]);

		call->offset = 0;
		call->unmarshall++;

	case 2:
		_debug("trailer");
		if (skb->len != 0)
			return -EBADMSG;
		break;
	}

	if (!last)
		return 0;

	call->state = AFS_CALL_REPLYING;

	INIT_WORK(&call->work, SRXAFSCB_ProbeUuid);
	queue_work(afs_wq, &call->work);
	return 0;
}

/*
 * allow the fileserver to ask about the cache manager's capabilities
 */
static void SRXAFSCB_TellMeAboutYourself(struct work_struct *work)
{
	struct afs_interface *ifs;
	struct afs_call *call = container_of(work, struct afs_call, work);
	int loop, nifs;

	struct {
		struct /* InterfaceAddr */ {
			__be32 nifs;
			__be32 uuid[11];
			__be32 ifaddr[32];
			__be32 netmask[32];
			__be32 mtu[32];
		} ia;
		struct /* Capabilities */ {
			__be32 capcount;
			__be32 caps[1];
		} cap;
	} reply;

	_enter("");

	nifs = 0;
	ifs = kcalloc(32, sizeof(*ifs), GFP_KERNEL);
	if (ifs) {
		nifs = afs_get_ipv4_interfaces(ifs, 32, false);
		if (nifs < 0) {
			kfree(ifs);
			ifs = NULL;
			nifs = 0;
		}
	}

	memset(&reply, 0, sizeof(reply));
	reply.ia.nifs = htonl(nifs);

	reply.ia.uuid[0] = htonl(afs_uuid.time_low);
	reply.ia.uuid[1] = htonl(afs_uuid.time_mid);
	reply.ia.uuid[2] = htonl(afs_uuid.time_hi_and_version);
	reply.ia.uuid[3] = htonl((s8) afs_uuid.clock_seq_hi_and_reserved);
	reply.ia.uuid[4] = htonl((s8) afs_uuid.clock_seq_low);
	for (loop = 0; loop < 6; loop++)
		reply.ia.uuid[loop + 5] = htonl((s8) afs_uuid.node[loop]);

	if (ifs) {
		for (loop = 0; loop < nifs; loop++) {
			reply.ia.ifaddr[loop] = ifs[loop].address.s_addr;
			reply.ia.netmask[loop] = ifs[loop].netmask.s_addr;
			reply.ia.mtu[loop] = htonl(ifs[loop].mtu);
		}
		kfree(ifs);
	}

	reply.cap.capcount = htonl(1);
	reply.cap.caps[0] = htonl(AFS_CAP_ERROR_TRANSLATION);
	afs_send_simple_reply(call, &reply, sizeof(reply));

	_leave("");
}

/*
 * deliver request data to a CB.TellMeAboutYourself call
 */
static int afs_deliver_cb_tell_me_about_yourself(struct afs_call *call,
						 struct sk_buff *skb, bool last)
{
	_enter(",{%u},%d", skb->len, last);

	if (skb->len > 0)
		return -EBADMSG;
	if (!last)
		return 0;

	/* no unmarshalling required */
	call->state = AFS_CALL_REPLYING;

	INIT_WORK(&call->work, SRXAFSCB_TellMeAboutYourself);
	queue_work(afs_wq, &call->work);
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/cmservice.c */
/************************************************************/
/* dir.c: AFS filesystem directory handling
 *
 * Copyright (C) 2002 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/init.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
// #include <linux/ctype.h>
// #include <linux/sched.h>
// #include "internal.h"
#include "../../inc/__fss.h"

static struct dentry *afs_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags);
static int afs_dir_open(struct inode *inode, struct file *file);
static int afs_readdir(struct file *file, struct dir_context *ctx);
static int afs_d_revalidate(struct dentry *dentry, unsigned int flags);
static int afs_d_delete(const struct dentry *dentry);
static void afs_d_release(struct dentry *dentry);
static int afs_lookup_filldir(struct dir_context *ctx, const char *name, int nlen,
				  loff_t fpos, u64 ino, unsigned dtype);
static int afs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		      bool excl);
static int afs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode);
static int afs_rmdir(struct inode *dir, struct dentry *dentry);
static int afs_unlink(struct inode *dir, struct dentry *dentry);
static int afs_link(struct dentry *from, struct inode *dir,
		    struct dentry *dentry);
static int afs_symlink(struct inode *dir, struct dentry *dentry,
		       const char *content);
static int afs_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry);

const struct file_operations afs_dir_file_operations = {
	.open		= afs_dir_open,
	.release	= afs_release,
	.iterate	= afs_readdir,
	.lock		= afs_lock,
	.llseek		= generic_file_llseek,
};

const struct inode_operations afs_dir_inode_operations = {
	.create		= afs_create,
	.lookup		= afs_lookup,
	.link		= afs_link,
	.unlink		= afs_unlink,
	.symlink	= afs_symlink,
	.mkdir		= afs_mkdir,
	.rmdir		= afs_rmdir,
	.rename		= afs_rename,
	.permission	= afs_permission,
	.getattr	= afs_getattr,
	.setattr	= afs_setattr,
};

const struct dentry_operations afs_fs_dentry_operations = {
	.d_revalidate	= afs_d_revalidate,
	.d_delete	= afs_d_delete,
	.d_release	= afs_d_release,
	.d_automount	= afs_d_automount,
};

#define AFS_DIR_HASHTBL_SIZE	128
#define AFS_DIR_DIRENT_SIZE	32
#define AFS_DIRENT_PER_BLOCK	64

union afs_dirent {
	struct {
		uint8_t		valid;
		uint8_t		unused[1];
		__be16		hash_next;
		__be32		vnode;
		__be32		unique;
		uint8_t		name[16];
		uint8_t		overflow[4];	/* if any char of the name (inc
						 * NUL) reaches here, consume
						 * the next dirent too */
	} u;
	uint8_t	extended_name[32];
};

/* AFS directory page header (one at the beginning of every 2048-byte chunk) */
struct afs_dir_pagehdr {
	__be16		npages;
	__be16		magic;
#define AFS_DIR_MAGIC htons(1234)
	uint8_t		nentries;
	uint8_t		bitmap[8];
	uint8_t		pad[19];
};

/* directory block layout */
union afs_dir_block {

	struct afs_dir_pagehdr pagehdr;

	struct {
		struct afs_dir_pagehdr	pagehdr;
		uint8_t			alloc_ctrs[128];
		/* dir hash table */
		uint16_t		hashtable[AFS_DIR_HASHTBL_SIZE];
	} hdr;

	union afs_dirent dirents[AFS_DIRENT_PER_BLOCK];
};

/* layout on a linux VM page */
struct afs_dir_page {
	union afs_dir_block blocks[PAGE_SIZE / sizeof(union afs_dir_block)];
};

struct afs_lookup_cookie {
	struct dir_context ctx;
	struct afs_fid	fid;
	struct qstr name;
	int		found;
};

/*
 * check that a directory page is valid
 */
static inline void afs_dir_check_page(struct inode *dir, struct page *page)
{
	struct afs_dir_page *dbuf;
	loff_t latter;
	int tmp, qty;

#if 0
	/* check the page count */
	qty = desc.size / sizeof(dbuf->blocks[0]);
	if (qty == 0)
		goto error;

	if (page->index == 0 && qty != ntohs(dbuf->blocks[0].pagehdr.npages)) {
		printk("kAFS: %s(%lu): wrong number of dir blocks %d!=%hu\n",
		       __func__, dir->i_ino, qty,
		       ntohs(dbuf->blocks[0].pagehdr.npages));
		goto error;
	}
#endif

	/* determine how many magic numbers there should be in this page */
	latter = dir->i_size - page_offset(page);
	if (latter >= PAGE_SIZE)
		qty = PAGE_SIZE;
	else
		qty = latter;
	qty /= sizeof(union afs_dir_block);

	/* check them */
	dbuf = page_address(page);
	for (tmp = 0; tmp < qty; tmp++) {
		if (dbuf->blocks[tmp].pagehdr.magic != AFS_DIR_MAGIC) {
			printk("kAFS: %s(%lu): bad magic %d/%d is %04hx\n",
			       __func__, dir->i_ino, tmp, qty,
			       ntohs(dbuf->blocks[tmp].pagehdr.magic));
			goto error;
		}
	}

	SetPageChecked(page);
	return;

error:
	SetPageChecked(page);
	SetPageError(page);
}

/*
 * discard a page cached in the pagecache
 */
static inline void afs_dir_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

/*
 * get a page into the pagecache
 */
static struct page *afs_dir_get_page(struct inode *dir, unsigned long index,
				     struct key *key)
{
	struct page *page;
	_enter("{%lu},%lu", dir->i_ino, index);

	page = read_cache_page(dir->i_mapping, index, afs_page_filler, key);
	if (!IS_ERR(page)) {
		kmap(page);
		if (!PageChecked(page))
			afs_dir_check_page(dir, page);
		if (PageError(page))
			goto fail;
	}
	return page;

fail:
	afs_dir_put_page(page);
	_leave(" = -EIO");
	return ERR_PTR(-EIO);
}

/*
 * open an AFS directory file
 */
static int afs_dir_open(struct inode *inode, struct file *file)
{
	_enter("{%lu}", inode->i_ino);

	BUILD_BUG_ON(sizeof(union afs_dir_block) != 2048);
	BUILD_BUG_ON(sizeof(union afs_dirent) != 32);

	if (test_bit(AFS_VNODE_DELETED, &AFS_FS_I(inode)->flags))
		return -ENOENT;

	return afs_open(inode, file);
}

/*
 * deal with one block in an AFS directory
 */
static int afs_dir_iterate_block(struct dir_context *ctx,
				 union afs_dir_block *block,
				 unsigned blkoff)
{
	union afs_dirent *dire;
	unsigned offset, next, curr;
	size_t nlen;
	int tmp;

	_enter("%u,%x,%p,,",(unsigned)ctx->pos,blkoff,block);

	curr = (ctx->pos - blkoff) / sizeof(union afs_dirent);

	/* walk through the block, an entry at a time */
	for (offset = AFS_DIRENT_PER_BLOCK - block->pagehdr.nentries;
	     offset < AFS_DIRENT_PER_BLOCK;
	     offset = next
	     ) {
		next = offset + 1;

		/* skip entries marked unused in the bitmap */
		if (!(block->pagehdr.bitmap[offset / 8] &
		      (1 << (offset % 8)))) {
			_debug("ENT[%Zu.%u]: unused",
			       blkoff / sizeof(union afs_dir_block), offset);
			if (offset >= curr)
				ctx->pos = blkoff +
					next * sizeof(union afs_dirent);
			continue;
		}

		/* got a valid entry */
		dire = &block->dirents[offset];
		nlen = strnlen(dire->u.name,
			       sizeof(*block) -
			       offset * sizeof(union afs_dirent));

		_debug("ENT[%Zu.%u]: %s %Zu \"%s\"",
		       blkoff / sizeof(union afs_dir_block), offset,
		       (offset < curr ? "skip" : "fill"),
		       nlen, dire->u.name);

		/* work out where the next possible entry is */
		for (tmp = nlen; tmp > 15; tmp -= sizeof(union afs_dirent)) {
			if (next >= AFS_DIRENT_PER_BLOCK) {
				_debug("ENT[%Zu.%u]:"
				       " %u travelled beyond end dir block"
				       " (len %u/%Zu)",
				       blkoff / sizeof(union afs_dir_block),
				       offset, next, tmp, nlen);
				return -EIO;
			}
			if (!(block->pagehdr.bitmap[next / 8] &
			      (1 << (next % 8)))) {
				_debug("ENT[%Zu.%u]:"
				       " %u unmarked extension (len %u/%Zu)",
				       blkoff / sizeof(union afs_dir_block),
				       offset, next, tmp, nlen);
				return -EIO;
			}

			_debug("ENT[%Zu.%u]: ext %u/%Zu",
			       blkoff / sizeof(union afs_dir_block),
			       next, tmp, nlen);
			next++;
		}

		/* skip if starts before the current position */
		if (offset < curr)
			continue;

		/* found the next entry */
		if (!dir_emit(ctx, dire->u.name, nlen,
			      ntohl(dire->u.vnode),
			      ctx->actor == afs_lookup_filldir ?
			      ntohl(dire->u.unique) : DT_UNKNOWN)) {
			_leave(" = 0 [full]");
			return 0;
		}

		ctx->pos = blkoff + next * sizeof(union afs_dirent);
	}

	_leave(" = 1 [more]");
	return 1;
}

/*
 * iterate through the data blob that lists the contents of an AFS directory
 */
static int afs_dir_iterate(struct inode *dir, struct dir_context *ctx,
			   struct key *key)
{
	union afs_dir_block *dblock;
	struct afs_dir_page *dbuf;
	struct page *page;
	unsigned blkoff, limit;
	int ret;

	_enter("{%lu},%u,,", dir->i_ino, (unsigned)ctx->pos);

	if (test_bit(AFS_VNODE_DELETED, &AFS_FS_I(dir)->flags)) {
		_leave(" = -ESTALE");
		return -ESTALE;
	}

	/* round the file position up to the next entry boundary */
	ctx->pos += sizeof(union afs_dirent) - 1;
	ctx->pos &= ~(sizeof(union afs_dirent) - 1);

	/* walk through the blocks in sequence */
	ret = 0;
	while (ctx->pos < dir->i_size) {
		blkoff = ctx->pos & ~(sizeof(union afs_dir_block) - 1);

		/* fetch the appropriate page from the directory */
		page = afs_dir_get_page(dir, blkoff / PAGE_SIZE, key);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			break;
		}

		limit = blkoff & ~(PAGE_SIZE - 1);

		dbuf = page_address(page);

		/* deal with the individual blocks stashed on this page */
		do {
			dblock = &dbuf->blocks[(blkoff % PAGE_SIZE) /
					       sizeof(union afs_dir_block)];
			ret = afs_dir_iterate_block(ctx, dblock, blkoff);
			if (ret != 1) {
				afs_dir_put_page(page);
				goto out;
			}

			blkoff += sizeof(union afs_dir_block);

		} while (ctx->pos < dir->i_size && blkoff < limit);

		afs_dir_put_page(page);
		ret = 0;
	}

out:
	_leave(" = %d", ret);
	return ret;
}

/*
 * read an AFS directory
 */
static int afs_readdir(struct file *file, struct dir_context *ctx)
{
	return afs_dir_iterate(file_inode(file), 
			      ctx, file->private_data);
}

/*
 * search the directory for a name
 * - if afs_dir_iterate_block() spots this function, it'll pass the FID
 *   uniquifier through dtype
 */
static int afs_lookup_filldir(struct dir_context *ctx, const char *name,
			      int nlen, loff_t fpos, u64 ino, unsigned dtype)
{
	struct afs_lookup_cookie *cookie =
		container_of(ctx, struct afs_lookup_cookie, ctx);

	_enter("{%s,%u},%s,%u,,%llu,%u",
	       cookie->name.name, cookie->name.len, name, nlen,
	       (unsigned long long) ino, dtype);

	/* insanity checks first */
	BUILD_BUG_ON(sizeof(union afs_dir_block) != 2048);
	BUILD_BUG_ON(sizeof(union afs_dirent) != 32);

	if (cookie->name.len != nlen ||
	    memcmp(cookie->name.name, name, nlen) != 0) {
		_leave(" = 0 [no]");
		return 0;
	}

	cookie->fid.vnode = ino;
	cookie->fid.unique = dtype;
	cookie->found = 1;

	_leave(" = -1 [found]");
	return -1;
}

/*
 * do a lookup in a directory
 * - just returns the FID the dentry name maps to if found
 */
static int afs_do_lookup(struct inode *dir, struct dentry *dentry,
			 struct afs_fid *fid, struct key *key)
{
	struct afs_super_info *as = dir->i_sb->s_fs_info;
	struct afs_lookup_cookie cookie = {
		.ctx.actor = afs_lookup_filldir,
		.name = dentry->d_name,
		.fid.vid = as->volume->vid
	};
	int ret;

	_enter("{%lu},%p{%pd},", dir->i_ino, dentry, dentry);

	/* search the directory */
	ret = afs_dir_iterate(dir, &cookie.ctx, key);
	if (ret < 0) {
		_leave(" = %d [iter]", ret);
		return ret;
	}

	ret = -ENOENT;
	if (!cookie.found) {
		_leave(" = -ENOENT [not found]");
		return -ENOENT;
	}

	*fid = cookie.fid;
	_leave(" = 0 { vn=%u u=%u }", fid->vnode, fid->unique);
	return 0;
}

/*
 * Try to auto mount the mountpoint with pseudo directory, if the autocell
 * operation is setted.
 */
static struct inode *afs_try_auto_mntpt(
	int ret, struct dentry *dentry, struct inode *dir, struct key *key,
	struct afs_fid *fid)
{
	const char *devname = dentry->d_name.name;
	struct afs_vnode *vnode = AFS_FS_I(dir);
	struct inode *inode;

	_enter("%d, %p{%pd}, {%x:%u}, %p",
	       ret, dentry, dentry, vnode->fid.vid, vnode->fid.vnode, key);

	if (ret != -ENOENT ||
	    !test_bit(AFS_VNODE_AUTOCELL, &vnode->flags))
		goto out;

	inode = afs_iget_autocell(dir, devname, strlen(devname), key);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	*fid = AFS_FS_I(inode)->fid;
	_leave("= %p", inode);
	return inode;

out:
	_leave("= %d", ret);
	return ERR_PTR(ret);
}

/*
 * look up an entry in a directory
 */
static struct dentry *afs_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	struct afs_vnode *vnode;
	struct afs_fid fid;
	struct inode *inode;
	struct key *key;
	int ret;

	vnode = AFS_FS_I(dir);

	_enter("{%x:%u},%p{%pd},",
	       vnode->fid.vid, vnode->fid.vnode, dentry, dentry);

	ASSERTCMP(dentry->d_inode, ==, NULL);

	if (dentry->d_name.len >= AFSNAMEMAX) {
		_leave(" = -ENAMETOOLONG");
		return ERR_PTR(-ENAMETOOLONG);
	}

	if (test_bit(AFS_VNODE_DELETED, &vnode->flags)) {
		_leave(" = -ESTALE");
		return ERR_PTR(-ESTALE);
	}

	key = afs_request_key(vnode->volume->cell);
	if (IS_ERR(key)) {
		_leave(" = %ld [key]", PTR_ERR(key));
		return ERR_CAST(key);
	}

	ret = afs_validate(vnode, key);
	if (ret < 0) {
		key_put(key);
		_leave(" = %d [val]", ret);
		return ERR_PTR(ret);
	}

	ret = afs_do_lookup(dir, dentry, &fid, key);
	if (ret < 0) {
		inode = afs_try_auto_mntpt(ret, dentry, dir, key, &fid);
		if (!IS_ERR(inode)) {
			key_put(key);
			goto success;
		}

		ret = PTR_ERR(inode);
		key_put(key);
		if (ret == -ENOENT) {
			d_add(dentry, NULL);
			_leave(" = NULL [negative]");
			return NULL;
		}
		_leave(" = %d [do]", ret);
		return ERR_PTR(ret);
	}
	dentry->d_fsdata = (void *)(unsigned long) vnode->status.data_version;

	/* instantiate the dentry */
	inode = afs_iget(dir->i_sb, key, &fid, NULL, NULL);
	key_put(key);
	if (IS_ERR(inode)) {
		_leave(" = %ld", PTR_ERR(inode));
		return ERR_CAST(inode);
	}

success:
	d_add(dentry, inode);
	_leave(" = 0 { vn=%u u=%u } -> { ino=%lu v=%u }",
	       fid.vnode,
	       fid.unique,
	       dentry->d_inode->i_ino,
	       dentry->d_inode->i_generation);

	return NULL;
}

/*
 * check that a dentry lookup hit has found a valid entry
 * - NOTE! the hit can be a negative hit too, so we can't assume we have an
 *   inode
 */
static int afs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct afs_vnode *vnode, *dir;
	struct afs_fid uninitialized_var(fid);
	struct dentry *parent;
	struct key *key;
	void *dir_version;
	int ret;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	vnode = AFS_FS_I(dentry->d_inode);

	if (dentry->d_inode)
		_enter("{v={%x:%u} n=%pd fl=%lx},",
		       vnode->fid.vid, vnode->fid.vnode, dentry,
		       vnode->flags);
	else
		_enter("{neg n=%pd}", dentry);

	key = afs_request_key(AFS_FS_S(dentry->d_sb)->volume->cell);
	if (IS_ERR(key))
		key = NULL;

	/* lock down the parent dentry so we can peer at it */
	parent = dget_parent(dentry);
	dir = AFS_FS_I(parent->d_inode);

	/* validate the parent directory */
	if (test_bit(AFS_VNODE_MODIFIED, &dir->flags))
		afs_validate(dir, key);

	if (test_bit(AFS_VNODE_DELETED, &dir->flags)) {
		_debug("%pd: parent dir deleted", dentry);
		goto out_bad;
	}

	dir_version = (void *) (unsigned long) dir->status.data_version;
	if (dentry->d_fsdata == dir_version)
		goto out_valid; /* the dir contents are unchanged */

	_debug("dir modified");

	/* search the directory for this vnode */
	ret = afs_do_lookup(&dir->vfs_inode, dentry, &fid, key);
	switch (ret) {
	case 0:
		/* the filename maps to something */
		if (!dentry->d_inode)
			goto out_bad;
		if (is_bad_inode(dentry->d_inode)) {
			printk("kAFS: afs_d_revalidate: %pd2 has bad inode\n",
			       dentry);
			goto out_bad;
		}

		/* if the vnode ID has changed, then the dirent points to a
		 * different file */
		if (fid.vnode != vnode->fid.vnode) {
			_debug("%pd: dirent changed [%u != %u]",
			       dentry, fid.vnode,
			       vnode->fid.vnode);
			goto not_found;
		}

		/* if the vnode ID uniqifier has changed, then the file has
		 * been deleted and replaced, and the original vnode ID has
		 * been reused */
		if (fid.unique != vnode->fid.unique) {
			_debug("%pd: file deleted (uq %u -> %u I:%u)",
			       dentry, fid.unique,
			       vnode->fid.unique,
			       dentry->d_inode->i_generation);
			spin_lock(&vnode->lock);
			set_bit(AFS_VNODE_DELETED, &vnode->flags);
			spin_unlock(&vnode->lock);
			goto not_found;
		}
		goto out_valid;

	case -ENOENT:
		/* the filename is unknown */
		_debug("%pd: dirent not found", dentry);
		if (dentry->d_inode)
			goto not_found;
		goto out_valid;

	default:
		_debug("failed to iterate dir %pd: %d",
		       parent, ret);
		goto out_bad;
	}

out_valid:
	dentry->d_fsdata = dir_version;
	dput(parent);
	key_put(key);
	_leave(" = 1 [valid]");
	return 1;

	/* the dirent, if it exists, now points to a different vnode */
not_found:
	spin_lock(&dentry->d_lock);
	dentry->d_flags |= DCACHE_NFSFS_RENAMED;
	spin_unlock(&dentry->d_lock);

out_bad:
	_debug("dropping dentry %pd2", dentry);
	dput(parent);
	key_put(key);

	_leave(" = 0 [bad]");
	return 0;
}

/*
 * allow the VFS to enquire as to whether a dentry should be unhashed (mustn't
 * sleep)
 * - called from dput() when d_count is going to 0.
 * - return 1 to request dentry be unhashed, 0 otherwise
 */
static int afs_d_delete(const struct dentry *dentry)
{
	_enter("%pd", dentry);

	if (dentry->d_flags & DCACHE_NFSFS_RENAMED)
		goto zap;

	if (dentry->d_inode &&
	    (test_bit(AFS_VNODE_DELETED,   &AFS_FS_I(dentry->d_inode)->flags) ||
	     test_bit(AFS_VNODE_PSEUDODIR, &AFS_FS_I(dentry->d_inode)->flags)))
		goto zap;

	_leave(" = 0 [keep]");
	return 0;

zap:
	_leave(" = 1 [zap]");
	return 1;
}

/*
 * handle dentry release
 */
static void afs_d_release(struct dentry *dentry)
{
	_enter("%pd", dentry);
}

/*
 * create a directory on an AFS filesystem
 */
static int afs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct afs_file_status status;
	struct afs_callback cb;
	struct afs_server *server;
	struct afs_vnode *dvnode, *vnode;
	struct afs_fid fid;
	struct inode *inode;
	struct key *key;
	int ret;

	dvnode = AFS_FS_I(dir);

	_enter("{%x:%u},{%pd},%ho",
	       dvnode->fid.vid, dvnode->fid.vnode, dentry, mode);

	key = afs_request_key(dvnode->volume->cell);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto error;
	}

	mode |= S_IFDIR;
	ret = afs_vnode_create(dvnode, key, dentry->d_name.name,
			       mode, &fid, &status, &cb, &server);
	if (ret < 0)
		goto mkdir_error;

	inode = afs_iget(dir->i_sb, key, &fid, &status, &cb);
	if (IS_ERR(inode)) {
		/* ENOMEM at a really inconvenient time - just abandon the new
		 * directory on the server */
		ret = PTR_ERR(inode);
		goto iget_error;
	}

	/* apply the status report we've got for the new vnode */
	vnode = AFS_FS_I(inode);
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);
	afs_vnode_finalise_status_update(vnode, server);
	afs_put_server(server);

	d_instantiate(dentry, inode);
	if (d_unhashed(dentry)) {
		_debug("not hashed");
		d_rehash(dentry);
	}
	key_put(key);
	_leave(" = 0");
	return 0;

iget_error:
	afs_put_server(server);
mkdir_error:
	key_put(key);
error:
	d_drop(dentry);
	_leave(" = %d", ret);
	return ret;
}

/*
 * remove a directory from an AFS filesystem
 */
static int afs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct afs_vnode *dvnode, *vnode;
	struct key *key;
	int ret;

	dvnode = AFS_FS_I(dir);

	_enter("{%x:%u},{%pd}",
	       dvnode->fid.vid, dvnode->fid.vnode, dentry);

	key = afs_request_key(dvnode->volume->cell);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto error;
	}

	ret = afs_vnode_remove(dvnode, key, dentry->d_name.name, true);
	if (ret < 0)
		goto rmdir_error;

	if (dentry->d_inode) {
		vnode = AFS_FS_I(dentry->d_inode);
		clear_nlink(&vnode->vfs_inode);
		set_bit(AFS_VNODE_DELETED, &vnode->flags);
		afs_discard_callback_on_delete(vnode);
	}

	key_put(key);
	_leave(" = 0");
	return 0;

rmdir_error:
	key_put(key);
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * remove a file from an AFS filesystem
 */
static int afs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct afs_vnode *dvnode, *vnode;
	struct key *key;
	int ret;

	dvnode = AFS_FS_I(dir);

	_enter("{%x:%u},{%pd}",
	       dvnode->fid.vid, dvnode->fid.vnode, dentry);

	ret = -ENAMETOOLONG;
	if (dentry->d_name.len >= AFSNAMEMAX)
		goto error;

	key = afs_request_key(dvnode->volume->cell);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto error;
	}

	if (dentry->d_inode) {
		vnode = AFS_FS_I(dentry->d_inode);

		/* make sure we have a callback promise on the victim */
		ret = afs_validate(vnode, key);
		if (ret < 0)
			goto error;
	}

	ret = afs_vnode_remove(dvnode, key, dentry->d_name.name, false);
	if (ret < 0)
		goto remove_error;

	if (dentry->d_inode) {
		/* if the file wasn't deleted due to excess hard links, the
		 * fileserver will break the callback promise on the file - if
		 * it had one - before it returns to us, and if it was deleted,
		 * it won't
		 *
		 * however, if we didn't have a callback promise outstanding,
		 * or it was outstanding on a different server, then it won't
		 * break it either...
		 */
		vnode = AFS_FS_I(dentry->d_inode);
		if (test_bit(AFS_VNODE_DELETED, &vnode->flags))
			_debug("AFS_VNODE_DELETED");
		if (test_bit(AFS_VNODE_CB_BROKEN, &vnode->flags))
			_debug("AFS_VNODE_CB_BROKEN");
		set_bit(AFS_VNODE_CB_BROKEN, &vnode->flags);
		ret = afs_validate(vnode, key);
		_debug("nlink %d [val %d]", vnode->vfs_inode.i_nlink, ret);
	}

	key_put(key);
	_leave(" = 0");
	return 0;

remove_error:
	key_put(key);
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * create a regular file on an AFS filesystem
 */
static int afs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		      bool excl)
{
	struct afs_file_status status;
	struct afs_callback cb;
	struct afs_server *server;
	struct afs_vnode *dvnode, *vnode;
	struct afs_fid fid;
	struct inode *inode;
	struct key *key;
	int ret;

	dvnode = AFS_FS_I(dir);

	_enter("{%x:%u},{%pd},%ho,",
	       dvnode->fid.vid, dvnode->fid.vnode, dentry, mode);

	key = afs_request_key(dvnode->volume->cell);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto error;
	}

	mode |= S_IFREG;
	ret = afs_vnode_create(dvnode, key, dentry->d_name.name,
			       mode, &fid, &status, &cb, &server);
	if (ret < 0)
		goto create_error;

	inode = afs_iget(dir->i_sb, key, &fid, &status, &cb);
	if (IS_ERR(inode)) {
		/* ENOMEM at a really inconvenient time - just abandon the new
		 * directory on the server */
		ret = PTR_ERR(inode);
		goto iget_error;
	}

	/* apply the status report we've got for the new vnode */
	vnode = AFS_FS_I(inode);
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);
	afs_vnode_finalise_status_update(vnode, server);
	afs_put_server(server);

	d_instantiate(dentry, inode);
	if (d_unhashed(dentry)) {
		_debug("not hashed");
		d_rehash(dentry);
	}
	key_put(key);
	_leave(" = 0");
	return 0;

iget_error:
	afs_put_server(server);
create_error:
	key_put(key);
error:
	d_drop(dentry);
	_leave(" = %d", ret);
	return ret;
}

/*
 * create a hard link between files in an AFS filesystem
 */
static int afs_link(struct dentry *from, struct inode *dir,
		    struct dentry *dentry)
{
	struct afs_vnode *dvnode, *vnode;
	struct key *key;
	int ret;

	vnode = AFS_FS_I(from->d_inode);
	dvnode = AFS_FS_I(dir);

	_enter("{%x:%u},{%x:%u},{%pd}",
	       vnode->fid.vid, vnode->fid.vnode,
	       dvnode->fid.vid, dvnode->fid.vnode,
	       dentry);

	key = afs_request_key(dvnode->volume->cell);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto error;
	}

	ret = afs_vnode_link(dvnode, vnode, key, dentry->d_name.name);
	if (ret < 0)
		goto link_error;

	ihold(&vnode->vfs_inode);
	d_instantiate(dentry, &vnode->vfs_inode);
	key_put(key);
	_leave(" = 0");
	return 0;

link_error:
	key_put(key);
error:
	d_drop(dentry);
	_leave(" = %d", ret);
	return ret;
}

/*
 * create a symlink in an AFS filesystem
 */
static int afs_symlink(struct inode *dir, struct dentry *dentry,
		       const char *content)
{
	struct afs_file_status status;
	struct afs_server *server;
	struct afs_vnode *dvnode, *vnode;
	struct afs_fid fid;
	struct inode *inode;
	struct key *key;
	int ret;

	dvnode = AFS_FS_I(dir);

	_enter("{%x:%u},{%pd},%s",
	       dvnode->fid.vid, dvnode->fid.vnode, dentry,
	       content);

	ret = -EINVAL;
	if (strlen(content) >= AFSPATHMAX)
		goto error;

	key = afs_request_key(dvnode->volume->cell);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto error;
	}

	ret = afs_vnode_symlink(dvnode, key, dentry->d_name.name, content,
				&fid, &status, &server);
	if (ret < 0)
		goto create_error;

	inode = afs_iget(dir->i_sb, key, &fid, &status, NULL);
	if (IS_ERR(inode)) {
		/* ENOMEM at a really inconvenient time - just abandon the new
		 * directory on the server */
		ret = PTR_ERR(inode);
		goto iget_error;
	}

	/* apply the status report we've got for the new vnode */
	vnode = AFS_FS_I(inode);
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);
	afs_vnode_finalise_status_update(vnode, server);
	afs_put_server(server);

	d_instantiate(dentry, inode);
	if (d_unhashed(dentry)) {
		_debug("not hashed");
		d_rehash(dentry);
	}
	key_put(key);
	_leave(" = 0");
	return 0;

iget_error:
	afs_put_server(server);
create_error:
	key_put(key);
error:
	d_drop(dentry);
	_leave(" = %d", ret);
	return ret;
}

/*
 * rename a file in an AFS filesystem and/or move it between directories
 */
static int afs_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	struct afs_vnode *orig_dvnode, *new_dvnode, *vnode;
	struct key *key;
	int ret;

	vnode = AFS_FS_I(old_dentry->d_inode);
	orig_dvnode = AFS_FS_I(old_dir);
	new_dvnode = AFS_FS_I(new_dir);

	_enter("{%x:%u},{%x:%u},{%x:%u},{%pd}",
	       orig_dvnode->fid.vid, orig_dvnode->fid.vnode,
	       vnode->fid.vid, vnode->fid.vnode,
	       new_dvnode->fid.vid, new_dvnode->fid.vnode,
	       new_dentry);

	key = afs_request_key(orig_dvnode->volume->cell);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto error;
	}

	ret = afs_vnode_rename(orig_dvnode, new_dvnode, key,
			       old_dentry->d_name.name,
			       new_dentry->d_name.name);
	if (ret < 0)
		goto rename_error;
	key_put(key);
	_leave(" = 0");
	return 0;

rename_error:
	key_put(key);
error:
	d_drop(new_dentry);
	_leave(" = %d", ret);
	return ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/dir.c */
/************************************************************/
/* AFS filesystem file handling
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/init.h>
// #include <linux/fs.h>
// #include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/gfp.h>
// #include "internal.h"
#include "../../inc/__fss.h"

static int afs_readpage(struct file *file, struct page *page);
static void afs_invalidatepage(struct page *page, unsigned int offset,
			       unsigned int length);
static int afs_releasepage(struct page *page, gfp_t gfp_flags);
static int afs_launder_page(struct page *page);

static int afs_readpages(struct file *filp, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages);

const struct file_operations afs_file_operations = {
	.open		= afs_open,
	.release	= afs_release,
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.write		= new_sync_write,
	.read_iter	= generic_file_read_iter,
	.write_iter	= afs_file_write,
	.mmap		= generic_file_readonly_mmap,
	.splice_read	= generic_file_splice_read,
	.fsync		= afs_fsync,
	.lock		= afs_lock,
	.flock		= afs_flock,
};

const struct inode_operations afs_file_inode_operations = {
	.getattr	= afs_getattr,
	.setattr	= afs_setattr,
	.permission	= afs_permission,
};

const struct address_space_operations afs_fs_aops = {
	.readpage	= afs_readpage,
	.readpages	= afs_readpages,
	.set_page_dirty	= afs_set_page_dirty,
	.launder_page	= afs_launder_page,
	.releasepage	= afs_releasepage,
	.invalidatepage	= afs_invalidatepage,
	.write_begin	= afs_write_begin,
	.write_end	= afs_write_end,
	.writepage	= afs_writepage,
	.writepages	= afs_writepages,
};

/*
 * open an AFS file or directory and attach a key to it
 */
int afs_open(struct inode *inode, struct file *file)
{
	struct afs_vnode *vnode = AFS_FS_I(inode);
	struct key *key;
	int ret;

	_enter("{%x:%u},", vnode->fid.vid, vnode->fid.vnode);

	key = afs_request_key(vnode->volume->cell);
	if (IS_ERR(key)) {
		_leave(" = %ld [key]", PTR_ERR(key));
		return PTR_ERR(key);
	}

	ret = afs_validate(vnode, key);
	if (ret < 0) {
		_leave(" = %d [val]", ret);
		return ret;
	}

	file->private_data = key;
	_leave(" = 0");
	return 0;
}

/*
 * release an AFS file or directory and discard its key
 */
int afs_release(struct inode *inode, struct file *file)
{
	struct afs_vnode *vnode = AFS_FS_I(inode);

	_enter("{%x:%u},", vnode->fid.vid, vnode->fid.vnode);

	key_put(file->private_data);
	_leave(" = 0");
	return 0;
}

#ifdef CONFIG_AFS_FSCACHE
/*
 * deal with notification that a page was read from the cache
 */
static void afs_file_readpage_read_complete(struct page *page,
					    void *data,
					    int error)
{
	_enter("%p,%p,%d", page, data, error);

	/* if the read completes with an error, we just unlock the page and let
	 * the VM reissue the readpage */
	if (!error)
		SetPageUptodate(page);
	unlock_page(page);
}
#endif

/*
 * read page from file, directory or symlink, given a key to use
 */
int afs_page_filler(void *data, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct afs_vnode *vnode = AFS_FS_I(inode);
	struct key *key = data;
	size_t len;
	off_t offset;
	int ret;

	_enter("{%x},{%lu},{%lu}", key_serial(key), inode->i_ino, page->index);

	BUG_ON(!PageLocked(page));

	ret = -ESTALE;
	if (test_bit(AFS_VNODE_DELETED, &vnode->flags))
		goto error;

	/* is it cached? */
#ifdef CONFIG_AFS_FSCACHE
	ret = fscache_read_or_alloc_page(vnode->cache,
					 page,
					 afs_file_readpage_read_complete,
					 NULL,
					 GFP_KERNEL);
#else
	ret = -ENOBUFS;
#endif
	switch (ret) {
		/* read BIO submitted (page in cache) */
	case 0:
		break;

		/* page not yet cached */
	case -ENODATA:
		_debug("cache said ENODATA");
		goto go_on;

		/* page will not be cached */
	case -ENOBUFS:
		_debug("cache said ENOBUFS");
	default:
	go_on:
		offset = page->index << PAGE_CACHE_SHIFT;
		len = min_t(size_t, i_size_read(inode) - offset, PAGE_SIZE);

		/* read the contents of the file from the server into the
		 * page */
		ret = afs_vnode_fetch_data(vnode, key, offset, len, page);
		if (ret < 0) {
			if (ret == -ENOENT) {
				_debug("got NOENT from server"
				       " - marking file deleted and stale");
				set_bit(AFS_VNODE_DELETED, &vnode->flags);
				ret = -ESTALE;
			}

#ifdef CONFIG_AFS_FSCACHE
			fscache_uncache_page(vnode->cache, page);
#endif
			BUG_ON(PageFsCache(page));
			goto error;
		}

		SetPageUptodate(page);

		/* send the page to the cache */
#ifdef CONFIG_AFS_FSCACHE
		if (PageFsCache(page) &&
		    fscache_write_page(vnode->cache, page, GFP_KERNEL) != 0) {
			fscache_uncache_page(vnode->cache, page);
			BUG_ON(PageFsCache(page));
		}
#endif
		unlock_page(page);
	}

	_leave(" = 0");
	return 0;

error:
	SetPageError(page);
	unlock_page(page);
	_leave(" = %d", ret);
	return ret;
}

/*
 * read page from file, directory or symlink, given a file to nominate the key
 * to be used
 */
static int afs_readpage(struct file *file, struct page *page)
{
	struct key *key;
	int ret;

	if (file) {
		key = file->private_data;
		ASSERT(key != NULL);
		ret = afs_page_filler(key, page);
	} else {
		struct inode *inode = page->mapping->host;
		key = afs_request_key(AFS_FS_S(inode->i_sb)->volume->cell);
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
		} else {
			ret = afs_page_filler(key, page);
			key_put(key);
		}
	}
	return ret;
}

/*
 * read a set of pages
 */
static int afs_readpages(struct file *file, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages)
{
	struct key *key = file->private_data;
	struct afs_vnode *vnode;
	int ret = 0;

	_enter("{%d},{%lu},,%d",
	       key_serial(key), mapping->host->i_ino, nr_pages);

	ASSERT(key != NULL);

	vnode = AFS_FS_I(mapping->host);
	if (test_bit(AFS_VNODE_DELETED, &vnode->flags)) {
		_leave(" = -ESTALE");
		return -ESTALE;
	}

	/* attempt to read as many of the pages as possible */
#ifdef CONFIG_AFS_FSCACHE
	ret = fscache_read_or_alloc_pages(vnode->cache,
					  mapping,
					  pages,
					  &nr_pages,
					  afs_file_readpage_read_complete,
					  NULL,
					  mapping_gfp_mask(mapping));
#else
	ret = -ENOBUFS;
#endif

	switch (ret) {
		/* all pages are being read from the cache */
	case 0:
		BUG_ON(!list_empty(pages));
		BUG_ON(nr_pages != 0);
		_leave(" = 0 [reading all]");
		return 0;

		/* there were pages that couldn't be read from the cache */
	case -ENODATA:
	case -ENOBUFS:
		break;

		/* other error */
	default:
		_leave(" = %d", ret);
		return ret;
	}

	/* load the missing pages from the network */
	ret = read_cache_pages(mapping, pages, afs_page_filler, key);

	_leave(" = %d [netting]", ret);
	return ret;
}

/*
 * write back a dirty page
 */
static int afs_launder_page(struct page *page)
{
	_enter("{%lu}", page->index);

	return 0;
}

/*
 * invalidate part or all of a page
 * - release a page and clean up its private data if offset is 0 (indicating
 *   the entire page)
 */
static void afs_invalidatepage(struct page *page, unsigned int offset,
			       unsigned int length)
{
	struct afs_writeback *wb = (struct afs_writeback *) page_private(page);

	_enter("{%lu},%u,%u", page->index, offset, length);

	BUG_ON(!PageLocked(page));

	/* we clean up only if the entire page is being invalidated */
	if (offset == 0 && length == PAGE_CACHE_SIZE) {
#ifdef CONFIG_AFS_FSCACHE
		if (PageFsCache(page)) {
			struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);
			fscache_wait_on_page_write(vnode->cache, page);
			fscache_uncache_page(vnode->cache, page);
		}
#endif

		if (PagePrivate(page)) {
			if (wb && !PageWriteback(page)) {
				set_page_private(page, 0);
				afs_put_writeback(wb);
			}

			if (!page_private(page))
				ClearPagePrivate(page);
		}
	}

	_leave("");
}

/*
 * release a page and clean up its private state if it's not busy
 * - return true if the page can now be released, false if not
 */
static int afs_releasepage(struct page *page, gfp_t gfp_flags)
{
	struct afs_writeback *wb = (struct afs_writeback *) page_private(page);
	struct afs_vnode *vnode = AFS_FS_I(page->mapping->host);

	_enter("{{%x:%u}[%lu],%lx},%x",
	       vnode->fid.vid, vnode->fid.vnode, page->index, page->flags,
	       gfp_flags);

	/* deny if page is being written to the cache and the caller hasn't
	 * elected to wait */
#ifdef CONFIG_AFS_FSCACHE
	if (!fscache_maybe_release_page(vnode->cache, page, gfp_flags)) {
		_leave(" = F [cache busy]");
		return 0;
	}
#endif

	if (PagePrivate(page)) {
		if (wb) {
			set_page_private(page, 0);
			afs_put_writeback(wb);
		}
		ClearPagePrivate(page);
	}

	/* indicate that the page can be released */
	_leave(" = T");
	return 1;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/file.c */
/************************************************************/
/* AFS file locking support
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include "internal.h"

#define AFS_LOCK_GRANTED	0
#define AFS_LOCK_PENDING	1

static void afs_fl_copy_lock(struct file_lock *new, struct file_lock *fl);
static void afs_fl_release_private(struct file_lock *fl);

static struct workqueue_struct *afs_lock_manager;
static DEFINE_MUTEX(afs_lock_manager_mutex);

static const struct file_lock_operations afs_lock_ops = {
	.fl_copy_lock		= afs_fl_copy_lock,
	.fl_release_private	= afs_fl_release_private,
};

/*
 * initialise the lock manager thread if it isn't already running
 */
static int afs_init_lock_manager(void)
{
	int ret;

	ret = 0;
	if (!afs_lock_manager) {
		mutex_lock(&afs_lock_manager_mutex);
		if (!afs_lock_manager) {
			afs_lock_manager =
				create_singlethread_workqueue("kafs_lockd");
			if (!afs_lock_manager)
				ret = -ENOMEM;
		}
		mutex_unlock(&afs_lock_manager_mutex);
	}
	return ret;
}

/*
 * destroy the lock manager thread if it's running
 */
void __exit afs_kill_lock_manager(void)
{
	if (afs_lock_manager)
		destroy_workqueue(afs_lock_manager);
}

/*
 * if the callback is broken on this vnode, then the lock may now be available
 */
void afs_lock_may_be_available(struct afs_vnode *vnode)
{
	_enter("{%x:%u}", vnode->fid.vid, vnode->fid.vnode);

	queue_delayed_work(afs_lock_manager, &vnode->lock_work, 0);
}

/*
 * the lock will time out in 5 minutes unless we extend it, so schedule
 * extension in a bit less than that time
 */
static void afs_schedule_lock_extension(struct afs_vnode *vnode)
{
	queue_delayed_work(afs_lock_manager, &vnode->lock_work,
			   AFS_LOCKWAIT * HZ / 2);
}

/*
 * grant one or more locks (readlocks are allowed to jump the queue if the
 * first lock in the queue is itself a readlock)
 * - the caller must hold the vnode lock
 */
static void afs_grant_locks(struct afs_vnode *vnode, struct file_lock *fl)
{
	struct file_lock *p, *_p;

	list_move_tail(&fl->fl_u.afs.link, &vnode->granted_locks);
	if (fl->fl_type == F_RDLCK) {
		list_for_each_entry_safe(p, _p, &vnode->pending_locks,
					 fl_u.afs.link) {
			if (p->fl_type == F_RDLCK) {
				p->fl_u.afs.state = AFS_LOCK_GRANTED;
				list_move_tail(&p->fl_u.afs.link,
					       &vnode->granted_locks);
				wake_up(&p->fl_wait);
			}
		}
	}
}

/*
 * do work for a lock, including:
 * - probing for a lock we're waiting on but didn't get immediately
 * - extending a lock that's close to timing out
 */
void afs_lock_work(struct work_struct *work)
{
	struct afs_vnode *vnode =
		container_of(work, struct afs_vnode, lock_work.work);
	struct file_lock *fl;
	afs_lock_type_t type;
	struct key *key;
	int ret;

	_enter("{%x:%u}", vnode->fid.vid, vnode->fid.vnode);

	spin_lock(&vnode->lock);

	if (test_bit(AFS_VNODE_UNLOCKING, &vnode->flags)) {
		_debug("unlock");
		spin_unlock(&vnode->lock);

		/* attempt to release the server lock; if it fails, we just
		 * wait 5 minutes and it'll time out anyway */
		ret = afs_vnode_release_lock(vnode, vnode->unlock_key);
		if (ret < 0)
			printk(KERN_WARNING "AFS:"
			       " Failed to release lock on {%x:%x} error %d\n",
			       vnode->fid.vid, vnode->fid.vnode, ret);

		spin_lock(&vnode->lock);
		key_put(vnode->unlock_key);
		vnode->unlock_key = NULL;
		clear_bit(AFS_VNODE_UNLOCKING, &vnode->flags);
	}

	/* if we've got a lock, then it must be time to extend that lock as AFS
	 * locks time out after 5 minutes */
	if (!list_empty(&vnode->granted_locks)) {
		_debug("extend");

		if (test_and_set_bit(AFS_VNODE_LOCKING, &vnode->flags))
			BUG();
		fl = list_entry(vnode->granted_locks.next,
				struct file_lock, fl_u.afs.link);
		key = key_get(fl->fl_file->private_data);
		spin_unlock(&vnode->lock);

		ret = afs_vnode_extend_lock(vnode, key);
		clear_bit(AFS_VNODE_LOCKING, &vnode->flags);
		key_put(key);
		switch (ret) {
		case 0:
			afs_schedule_lock_extension(vnode);
			break;
		default:
			/* ummm... we failed to extend the lock - retry
			 * extension shortly */
			printk(KERN_WARNING "AFS:"
			       " Failed to extend lock on {%x:%x} error %d\n",
			       vnode->fid.vid, vnode->fid.vnode, ret);
			queue_delayed_work(afs_lock_manager, &vnode->lock_work,
					   HZ * 10);
			break;
		}
		_leave(" [extend]");
		return;
	}

	/* if we don't have a granted lock, then we must've been called back by
	 * the server, and so if might be possible to get a lock we're
	 * currently waiting for */
	if (!list_empty(&vnode->pending_locks)) {
		_debug("get");

		if (test_and_set_bit(AFS_VNODE_LOCKING, &vnode->flags))
			BUG();
		fl = list_entry(vnode->pending_locks.next,
				struct file_lock, fl_u.afs.link);
		key = key_get(fl->fl_file->private_data);
		type = (fl->fl_type == F_RDLCK) ?
			AFS_LOCK_READ : AFS_LOCK_WRITE;
		spin_unlock(&vnode->lock);

		ret = afs_vnode_set_lock(vnode, key, type);
		clear_bit(AFS_VNODE_LOCKING, &vnode->flags);
		switch (ret) {
		case -EWOULDBLOCK:
			_debug("blocked");
			break;
		case 0:
			_debug("acquired");
			if (type == AFS_LOCK_READ)
				set_bit(AFS_VNODE_READLOCKED, &vnode->flags);
			else
				set_bit(AFS_VNODE_WRITELOCKED, &vnode->flags);
			ret = AFS_LOCK_GRANTED;
		default:
			spin_lock(&vnode->lock);
			/* the pending lock may have been withdrawn due to a
			 * signal */
			if (list_entry(vnode->pending_locks.next,
				       struct file_lock, fl_u.afs.link) == fl) {
				fl->fl_u.afs.state = ret;
				if (ret == AFS_LOCK_GRANTED)
					afs_grant_locks(vnode, fl);
				else
					list_del_init(&fl->fl_u.afs.link);
				wake_up(&fl->fl_wait);
				spin_unlock(&vnode->lock);
			} else {
				_debug("withdrawn");
				clear_bit(AFS_VNODE_READLOCKED, &vnode->flags);
				clear_bit(AFS_VNODE_WRITELOCKED, &vnode->flags);
				spin_unlock(&vnode->lock);
				afs_vnode_release_lock(vnode, key);
				if (!list_empty(&vnode->pending_locks))
					afs_lock_may_be_available(vnode);
			}
			break;
		}
		key_put(key);
		_leave(" [pend]");
		return;
	}

	/* looks like the lock request was withdrawn on a signal */
	spin_unlock(&vnode->lock);
	_leave(" [no locks]");
}

/*
 * pass responsibility for the unlocking of a vnode on the server to the
 * manager thread, lest a pending signal in the calling thread interrupt
 * AF_RXRPC
 * - the caller must hold the vnode lock
 */
static void afs_defer_unlock(struct afs_vnode *vnode, struct key *key)
{
	cancel_delayed_work(&vnode->lock_work);
	if (!test_and_clear_bit(AFS_VNODE_READLOCKED, &vnode->flags) &&
	    !test_and_clear_bit(AFS_VNODE_WRITELOCKED, &vnode->flags))
		BUG();
	if (test_and_set_bit(AFS_VNODE_UNLOCKING, &vnode->flags))
		BUG();
	vnode->unlock_key = key_get(key);
	afs_lock_may_be_available(vnode);
}

/*
 * request a lock on a file on the server
 */
static int afs_do_setlk(struct file *file, struct file_lock *fl)
{
	struct inode *inode = file_inode(file);
	struct afs_vnode *vnode = AFS_FS_I(inode);
	afs_lock_type_t type;
	struct key *key = file->private_data;
	int ret;

	_enter("{%x:%u},%u", vnode->fid.vid, vnode->fid.vnode, fl->fl_type);

	/* only whole-file locks are supported */
	if (fl->fl_start != 0 || fl->fl_end != OFFSET_MAX)
		return -EINVAL;

	ret = afs_init_lock_manager();
	if (ret < 0)
		return ret;

	fl->fl_ops = &afs_lock_ops;
	INIT_LIST_HEAD(&fl->fl_u.afs.link);
	fl->fl_u.afs.state = AFS_LOCK_PENDING;

	type = (fl->fl_type == F_RDLCK) ? AFS_LOCK_READ : AFS_LOCK_WRITE;

	spin_lock(&inode->i_lock);

	/* make sure we've got a callback on this file and that our view of the
	 * data version is up to date */
	ret = afs_vnode_fetch_status(vnode, NULL, key);
	if (ret < 0)
		goto error;

	if (vnode->status.lock_count != 0 && !(fl->fl_flags & FL_SLEEP)) {
		ret = -EAGAIN;
		goto error;
	}

	spin_lock(&vnode->lock);

	/* if we've already got a readlock on the server then we can instantly
	 * grant another readlock, irrespective of whether there are any
	 * pending writelocks */
	if (type == AFS_LOCK_READ &&
	    vnode->flags & (1 << AFS_VNODE_READLOCKED)) {
		_debug("instant readlock");
		ASSERTCMP(vnode->flags &
			  ((1 << AFS_VNODE_LOCKING) |
			   (1 << AFS_VNODE_WRITELOCKED)), ==, 0);
		ASSERT(!list_empty(&vnode->granted_locks));
		goto sharing_existing_lock;
	}

	/* if there's no-one else with a lock on this vnode, then we need to
	 * ask the server for a lock */
	if (list_empty(&vnode->pending_locks) &&
	    list_empty(&vnode->granted_locks)) {
		_debug("not locked");
		ASSERTCMP(vnode->flags &
			  ((1 << AFS_VNODE_LOCKING) |
			   (1 << AFS_VNODE_READLOCKED) |
			   (1 << AFS_VNODE_WRITELOCKED)), ==, 0);
		list_add_tail(&fl->fl_u.afs.link, &vnode->pending_locks);
		set_bit(AFS_VNODE_LOCKING, &vnode->flags);
		spin_unlock(&vnode->lock);

		ret = afs_vnode_set_lock(vnode, key, type);
		clear_bit(AFS_VNODE_LOCKING, &vnode->flags);
		switch (ret) {
		case 0:
			_debug("acquired");
			goto acquired_server_lock;
		case -EWOULDBLOCK:
			_debug("would block");
			spin_lock(&vnode->lock);
			ASSERT(list_empty(&vnode->granted_locks));
			ASSERTCMP(vnode->pending_locks.next, ==,
				  &fl->fl_u.afs.link);
			goto wait;
		default:
			spin_lock(&vnode->lock);
			list_del_init(&fl->fl_u.afs.link);
			spin_unlock(&vnode->lock);
			goto error;
		}
	}

	/* otherwise, we need to wait for a local lock to become available */
	_debug("wait local");
	list_add_tail(&fl->fl_u.afs.link, &vnode->pending_locks);
wait:
	if (!(fl->fl_flags & FL_SLEEP)) {
		_debug("noblock");
		ret = -EAGAIN;
		goto abort_attempt;
	}
	spin_unlock(&vnode->lock);

	/* now we need to sleep and wait for the lock manager thread to get the
	 * lock from the server */
	_debug("sleep");
	ret = wait_event_interruptible(fl->fl_wait,
				       fl->fl_u.afs.state <= AFS_LOCK_GRANTED);
	if (fl->fl_u.afs.state <= AFS_LOCK_GRANTED) {
		ret = fl->fl_u.afs.state;
		if (ret < 0)
			goto error;
		spin_lock(&vnode->lock);
		goto given_lock;
	}

	/* we were interrupted, but someone may still be in the throes of
	 * giving us the lock */
	_debug("intr");
	ASSERTCMP(ret, ==, -ERESTARTSYS);

	spin_lock(&vnode->lock);
	if (fl->fl_u.afs.state <= AFS_LOCK_GRANTED) {
		ret = fl->fl_u.afs.state;
		if (ret < 0) {
			spin_unlock(&vnode->lock);
			goto error;
		}
		goto given_lock;
	}

abort_attempt:
	/* we aren't going to get the lock, either because we're unwilling to
	 * wait, or because some signal happened */
	_debug("abort");
	if (list_empty(&vnode->granted_locks) &&
	    vnode->pending_locks.next == &fl->fl_u.afs.link) {
		if (vnode->pending_locks.prev != &fl->fl_u.afs.link) {
			/* kick the next pending lock into having a go */
			list_del_init(&fl->fl_u.afs.link);
			afs_lock_may_be_available(vnode);
		}
	} else {
		list_del_init(&fl->fl_u.afs.link);
	}
	spin_unlock(&vnode->lock);
	goto error;

acquired_server_lock:
	/* we've acquired a server lock, but it needs to be renewed after 5
	 * mins */
	spin_lock(&vnode->lock);
	afs_schedule_lock_extension(vnode);
	if (type == AFS_LOCK_READ)
		set_bit(AFS_VNODE_READLOCKED, &vnode->flags);
	else
		set_bit(AFS_VNODE_WRITELOCKED, &vnode->flags);
sharing_existing_lock:
	/* the lock has been granted as far as we're concerned... */
	fl->fl_u.afs.state = AFS_LOCK_GRANTED;
	list_move_tail(&fl->fl_u.afs.link, &vnode->granted_locks);
given_lock:
	/* ... but we do still need to get the VFS's blessing */
	ASSERT(!(vnode->flags & (1 << AFS_VNODE_LOCKING)));
	ASSERT((vnode->flags & ((1 << AFS_VNODE_READLOCKED) |
				(1 << AFS_VNODE_WRITELOCKED))) != 0);
	ret = posix_lock_file(file, fl, NULL);
	if (ret < 0)
		goto vfs_rejected_lock;
	spin_unlock(&vnode->lock);

	/* again, make sure we've got a callback on this file and, again, make
	 * sure that our view of the data version is up to date (we ignore
	 * errors incurred here and deal with the consequences elsewhere) */
	afs_vnode_fetch_status(vnode, NULL, key);

error:
	spin_unlock(&inode->i_lock);
	_leave(" = %d", ret);
	return ret;

vfs_rejected_lock:
	/* the VFS rejected the lock we just obtained, so we have to discard
	 * what we just got */
	_debug("vfs refused %d", ret);
	list_del_init(&fl->fl_u.afs.link);
	if (list_empty(&vnode->granted_locks))
		afs_defer_unlock(vnode, key);
	goto abort_attempt;
}

/*
 * unlock on a file on the server
 */
static int afs_do_unlk(struct file *file, struct file_lock *fl)
{
	struct afs_vnode *vnode = AFS_FS_I(file->f_mapping->host);
	struct key *key = file->private_data;
	int ret;

	_enter("{%x:%u},%u", vnode->fid.vid, vnode->fid.vnode, fl->fl_type);

	/* only whole-file unlocks are supported */
	if (fl->fl_start != 0 || fl->fl_end != OFFSET_MAX)
		return -EINVAL;

	fl->fl_ops = &afs_lock_ops;
	INIT_LIST_HEAD(&fl->fl_u.afs.link);
	fl->fl_u.afs.state = AFS_LOCK_PENDING;

	spin_lock(&vnode->lock);
	ret = posix_lock_file(file, fl, NULL);
	if (ret < 0) {
		spin_unlock(&vnode->lock);
		_leave(" = %d [vfs]", ret);
		return ret;
	}

	/* discard the server lock only if all granted locks are gone */
	if (list_empty(&vnode->granted_locks))
		afs_defer_unlock(vnode, key);
	spin_unlock(&vnode->lock);
	_leave(" = 0");
	return 0;
}

/*
 * return information about a lock we currently hold, if indeed we hold one
 */
static int afs_do_getlk(struct file *file, struct file_lock *fl)
{
	struct afs_vnode *vnode = AFS_FS_I(file->f_mapping->host);
	struct key *key = file->private_data;
	int ret, lock_count;

	_enter("");

	fl->fl_type = F_UNLCK;

	mutex_lock(&vnode->vfs_inode.i_mutex);

	/* check local lock records first */
	ret = 0;
	posix_test_lock(file, fl);
	if (fl->fl_type == F_UNLCK) {
		/* no local locks; consult the server */
		ret = afs_vnode_fetch_status(vnode, NULL, key);
		if (ret < 0)
			goto error;
		lock_count = vnode->status.lock_count;
		if (lock_count) {
			if (lock_count > 0)
				fl->fl_type = F_RDLCK;
			else
				fl->fl_type = F_WRLCK;
			fl->fl_start = 0;
			fl->fl_end = OFFSET_MAX;
		}
	}

error:
	mutex_unlock(&vnode->vfs_inode.i_mutex);
	_leave(" = %d [%hd]", ret, fl->fl_type);
	return ret;
}

/*
 * manage POSIX locks on a file
 */
int afs_lock(struct file *file, int cmd, struct file_lock *fl)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));

	_enter("{%x:%u},%d,{t=%x,fl=%x,r=%Ld:%Ld}",
	       vnode->fid.vid, vnode->fid.vnode, cmd,
	       fl->fl_type, fl->fl_flags,
	       (long long) fl->fl_start, (long long) fl->fl_end);

	/* AFS doesn't support mandatory locks */
	if (__mandatory_lock(&vnode->vfs_inode) && fl->fl_type != F_UNLCK)
		return -ENOLCK;

	if (IS_GETLK(cmd))
		return afs_do_getlk(file, fl);
	if (fl->fl_type == F_UNLCK)
		return afs_do_unlk(file, fl);
	return afs_do_setlk(file, fl);
}

/*
 * manage FLOCK locks on a file
 */
int afs_flock(struct file *file, int cmd, struct file_lock *fl)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));

	_enter("{%x:%u},%d,{t=%x,fl=%x}",
	       vnode->fid.vid, vnode->fid.vnode, cmd,
	       fl->fl_type, fl->fl_flags);

	/*
	 * No BSD flocks over NFS allowed.
	 * Note: we could try to fake a POSIX lock request here by
	 * using ((u32) filp | 0x80000000) or some such as the pid.
	 * Not sure whether that would be unique, though, or whether
	 * that would break in other places.
	 */
	if (!(fl->fl_flags & FL_FLOCK))
		return -ENOLCK;

	/* we're simulating flock() locks using posix locks on the server */
	if (fl->fl_type == F_UNLCK)
		return afs_do_unlk(file, fl);
	return afs_do_setlk(file, fl);
}

/*
 * the POSIX lock management core VFS code copies the lock record and adds the
 * copy into its own list, so we need to add that copy to the vnode's lock
 * queue in the same place as the original (which will be deleted shortly
 * after)
 */
static void afs_fl_copy_lock(struct file_lock *new, struct file_lock *fl)
{
	_enter("");

	list_add(&new->fl_u.afs.link, &fl->fl_u.afs.link);
}

/*
 * need to remove this lock from the vnode queue when it's removed from the
 * VFS's list
 */
static void afs_fl_release_private(struct file_lock *fl)
{
	_enter("");

	list_del_init(&fl->fl_u.afs.link);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/flock.c */
/************************************************************/
/* AFS File Server client stubs
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/init.h>
// #include <linux/slab.h>
// #include <linux/sched.h>
// #include <linux/circ_buf.h>
// #include "internal.h"
#include "afs_fs.h"
#include "../../inc/__fss.h"

/*
 * decode an AFSFid block
 */
static void xdr_decode_AFSFid(const __be32 **_bp, struct afs_fid *fid)
{
	const __be32 *bp = *_bp;

	fid->vid		= ntohl(*bp++);
	fid->vnode		= ntohl(*bp++);
	fid->unique		= ntohl(*bp++);
	*_bp = bp;
}

/*
 * decode an AFSFetchStatus block
 */
static void xdr_decode_AFSFetchStatus(const __be32 **_bp,
				      struct afs_file_status *status,
				      struct afs_vnode *vnode,
				      afs_dataversion_t *store_version)
{
	afs_dataversion_t expected_version;
	const __be32 *bp = *_bp;
	umode_t mode;
	u64 data_version, size;
	u32 changed = 0; /* becomes non-zero if ctime-type changes seen */
	kuid_t owner;
	kgid_t group;

#define EXTRACT(DST)				\
	do {					\
		u32 x = ntohl(*bp++);		\
		changed |= DST - x;		\
		DST = x;			\
	} while (0)

	status->if_version = ntohl(*bp++);
	EXTRACT(status->type);
	EXTRACT(status->nlink);
	size = ntohl(*bp++);
	data_version = ntohl(*bp++);
	EXTRACT(status->author);
	owner = make_kuid(&init_user_ns, ntohl(*bp++));
	changed |= !uid_eq(owner, status->owner);
	status->owner = owner;
	EXTRACT(status->caller_access); /* call ticket dependent */
	EXTRACT(status->anon_access);
	EXTRACT(status->mode);
	EXTRACT(status->parent.vnode);
	EXTRACT(status->parent.unique);
	bp++; /* seg size */
	status->mtime_client = ntohl(*bp++);
	status->mtime_server = ntohl(*bp++);
	group = make_kgid(&init_user_ns, ntohl(*bp++));
	changed |= !gid_eq(group, status->group);
	status->group = group;
	bp++; /* sync counter */
	data_version |= (u64) ntohl(*bp++) << 32;
	EXTRACT(status->lock_count);
	size |= (u64) ntohl(*bp++) << 32;
	bp++; /* spare 4 */
	*_bp = bp;

	if (size != status->size) {
		status->size = size;
		changed |= true;
	}
	status->mode &= S_IALLUGO;

	_debug("vnode time %lx, %lx",
	       status->mtime_client, status->mtime_server);

	if (vnode) {
		status->parent.vid = vnode->fid.vid;
		if (changed && !test_bit(AFS_VNODE_UNSET, &vnode->flags)) {
			_debug("vnode changed");
			i_size_write(&vnode->vfs_inode, size);
			vnode->vfs_inode.i_uid = status->owner;
			vnode->vfs_inode.i_gid = status->group;
			vnode->vfs_inode.i_generation = vnode->fid.unique;
			set_nlink(&vnode->vfs_inode, status->nlink);

			mode = vnode->vfs_inode.i_mode;
			mode &= ~S_IALLUGO;
			mode |= status->mode;
			barrier();
			vnode->vfs_inode.i_mode = mode;
		}

		vnode->vfs_inode.i_ctime.tv_sec	= status->mtime_server;
		vnode->vfs_inode.i_mtime	= vnode->vfs_inode.i_ctime;
		vnode->vfs_inode.i_atime	= vnode->vfs_inode.i_ctime;
		vnode->vfs_inode.i_version	= data_version;
	}

	expected_version = status->data_version;
	if (store_version)
		expected_version = *store_version;

	if (expected_version != data_version) {
		status->data_version = data_version;
		if (vnode && !test_bit(AFS_VNODE_UNSET, &vnode->flags)) {
			_debug("vnode modified %llx on {%x:%u}",
			       (unsigned long long) data_version,
			       vnode->fid.vid, vnode->fid.vnode);
			set_bit(AFS_VNODE_MODIFIED, &vnode->flags);
			set_bit(AFS_VNODE_ZAP_DATA, &vnode->flags);
		}
	} else if (store_version) {
		status->data_version = data_version;
	}
}

/*
 * decode an AFSCallBack block
 */
static void xdr_decode_AFSCallBack(const __be32 **_bp, struct afs_vnode *vnode)
{
	const __be32 *bp = *_bp;

	vnode->cb_version	= ntohl(*bp++);
	vnode->cb_expiry	= ntohl(*bp++);
	vnode->cb_type		= ntohl(*bp++);
	vnode->cb_expires	= vnode->cb_expiry + get_seconds();
	*_bp = bp;
}

static void xdr_decode_AFSCallBack_raw(const __be32 **_bp,
				       struct afs_callback *cb)
{
	const __be32 *bp = *_bp;

	cb->version	= ntohl(*bp++);
	cb->expiry	= ntohl(*bp++);
	cb->type	= ntohl(*bp++);
	*_bp = bp;
}

/*
 * decode an AFSVolSync block
 */
static void xdr_decode_AFSVolSync(const __be32 **_bp,
				  struct afs_volsync *volsync)
{
	const __be32 *bp = *_bp;

	volsync->creation = ntohl(*bp++);
	bp++; /* spare2 */
	bp++; /* spare3 */
	bp++; /* spare4 */
	bp++; /* spare5 */
	bp++; /* spare6 */
	*_bp = bp;
}

/*
 * encode the requested attributes into an AFSStoreStatus block
 */
static void xdr_encode_AFS_StoreStatus(__be32 **_bp, struct iattr *attr)
{
	__be32 *bp = *_bp;
	u32 mask = 0, mtime = 0, owner = 0, group = 0, mode = 0;

	mask = 0;
	if (attr->ia_valid & ATTR_MTIME) {
		mask |= AFS_SET_MTIME;
		mtime = attr->ia_mtime.tv_sec;
	}

	if (attr->ia_valid & ATTR_UID) {
		mask |= AFS_SET_OWNER;
		owner = from_kuid(&init_user_ns, attr->ia_uid);
	}

	if (attr->ia_valid & ATTR_GID) {
		mask |= AFS_SET_GROUP;
		group = from_kgid(&init_user_ns, attr->ia_gid);
	}

	if (attr->ia_valid & ATTR_MODE) {
		mask |= AFS_SET_MODE;
		mode = attr->ia_mode & S_IALLUGO;
	}

	*bp++ = htonl(mask);
	*bp++ = htonl(mtime);
	*bp++ = htonl(owner);
	*bp++ = htonl(group);
	*bp++ = htonl(mode);
	*bp++ = 0;		/* segment size */
	*_bp = bp;
}

/*
 * decode an AFSFetchVolumeStatus block
 */
static void xdr_decode_AFSFetchVolumeStatus(const __be32 **_bp,
					    struct afs_volume_status *vs)
{
	const __be32 *bp = *_bp;

	vs->vid			= ntohl(*bp++);
	vs->parent_id		= ntohl(*bp++);
	vs->online		= ntohl(*bp++);
	vs->in_service		= ntohl(*bp++);
	vs->blessed		= ntohl(*bp++);
	vs->needs_salvage	= ntohl(*bp++);
	vs->type		= ntohl(*bp++);
	vs->min_quota		= ntohl(*bp++);
	vs->max_quota		= ntohl(*bp++);
	vs->blocks_in_use	= ntohl(*bp++);
	vs->part_blocks_avail	= ntohl(*bp++);
	vs->part_max_blocks	= ntohl(*bp++);
	*_bp = bp;
}

/*
 * deliver reply data to an FS.FetchStatus
 */
static int afs_deliver_fs_fetch_status(struct afs_call *call,
				       struct sk_buff *skb, bool last)
{
	struct afs_vnode *vnode = call->reply;
	const __be32 *bp;

	_enter(",,%u", last);

	afs_transfer_reply(call, skb);
	if (!last)
		return 0;

	if (call->reply_size != call->reply_max)
		return -EBADMSG;

	/* unmarshall the reply once we've received all of it */
	bp = call->buffer;
	xdr_decode_AFSFetchStatus(&bp, &vnode->status, vnode, NULL);
	xdr_decode_AFSCallBack(&bp, vnode);
	if (call->reply2)
		xdr_decode_AFSVolSync(&bp, call->reply2);

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.FetchStatus operation type
 */
static const struct afs_call_type afs_RXFSFetchStatus = {
	.name		= "FS.FetchStatus",
	.deliver	= afs_deliver_fs_fetch_status,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * fetch the status information for a file
 */
int afs_fs_fetch_file_status(struct afs_server *server,
			     struct key *key,
			     struct afs_vnode *vnode,
			     struct afs_volsync *volsync,
			     const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	_enter(",%x,{%x:%u},,",
	       key_serial(key), vnode->fid.vid, vnode->fid.vnode);

	call = afs_alloc_flat_call(&afs_RXFSFetchStatus, 16, (21 + 3 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->reply2 = volsync;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	bp[0] = htonl(FSFETCHSTATUS);
	bp[1] = htonl(vnode->fid.vid);
	bp[2] = htonl(vnode->fid.vnode);
	bp[3] = htonl(vnode->fid.unique);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.FetchData
 */
static int afs_deliver_fs_fetch_data(struct afs_call *call,
				     struct sk_buff *skb, bool last)
{
	struct afs_vnode *vnode = call->reply;
	const __be32 *bp;
	struct page *page;
	void *buffer;
	int ret;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	switch (call->unmarshall) {
	case 0:
		call->offset = 0;
		call->unmarshall++;
		if (call->operation_ID != FSFETCHDATA64) {
			call->unmarshall++;
			goto no_msw;
		}

		/* extract the upper part of the returned data length of an
		 * FSFETCHDATA64 op (which should always be 0 using this
		 * client) */
	case 1:
		_debug("extract data length (MSW)");
		ret = afs_extract_data(call, skb, last, &call->tmp, 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->count = ntohl(call->tmp);
		_debug("DATA length MSW: %u", call->count);
		if (call->count > 0)
			return -EBADMSG;
		call->offset = 0;
		call->unmarshall++;

	no_msw:
		/* extract the returned data length */
	case 2:
		_debug("extract data length");
		ret = afs_extract_data(call, skb, last, &call->tmp, 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->count = ntohl(call->tmp);
		_debug("DATA length: %u", call->count);
		if (call->count > PAGE_SIZE)
			return -EBADMSG;
		call->offset = 0;
		call->unmarshall++;

		/* extract the returned data */
	case 3:
		_debug("extract data");
		if (call->count > 0) {
			page = call->reply3;
			buffer = kmap_atomic(page);
			ret = afs_extract_data(call, skb, last, buffer,
					       call->count);
			kunmap_atomic(buffer);
			switch (ret) {
			case 0:		break;
			case -EAGAIN:	return 0;
			default:	return ret;
			}
		}

		call->offset = 0;
		call->unmarshall++;

		/* extract the metadata */
	case 4:
		ret = afs_extract_data(call, skb, last, call->buffer,
				       (21 + 3 + 6) * 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		bp = call->buffer;
		xdr_decode_AFSFetchStatus(&bp, &vnode->status, vnode, NULL);
		xdr_decode_AFSCallBack(&bp, vnode);
		if (call->reply2)
			xdr_decode_AFSVolSync(&bp, call->reply2);

		call->offset = 0;
		call->unmarshall++;

	case 5:
		_debug("trailer");
		if (skb->len != 0)
			return -EBADMSG;
		break;
	}

	if (!last)
		return 0;

	if (call->count < PAGE_SIZE) {
		_debug("clear");
		page = call->reply3;
		buffer = kmap_atomic(page);
		memset(buffer + call->count, 0, PAGE_SIZE - call->count);
		kunmap_atomic(buffer);
	}

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.FetchData operation type
 */
static const struct afs_call_type afs_RXFSFetchData = {
	.name		= "FS.FetchData",
	.deliver	= afs_deliver_fs_fetch_data,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

static const struct afs_call_type afs_RXFSFetchData64 = {
	.name		= "FS.FetchData64",
	.deliver	= afs_deliver_fs_fetch_data,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * fetch data from a very large file
 */
static int afs_fs_fetch_data64(struct afs_server *server,
			       struct key *key,
			       struct afs_vnode *vnode,
			       off_t offset, size_t length,
			       struct page *buffer,
			       const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	_enter("");

	ASSERTCMP(length, <, ULONG_MAX);

	call = afs_alloc_flat_call(&afs_RXFSFetchData64, 32, (21 + 3 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->reply2 = NULL; /* volsync */
	call->reply3 = buffer;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);
	call->operation_ID = FSFETCHDATA64;

	/* marshall the parameters */
	bp = call->request;
	bp[0] = htonl(FSFETCHDATA64);
	bp[1] = htonl(vnode->fid.vid);
	bp[2] = htonl(vnode->fid.vnode);
	bp[3] = htonl(vnode->fid.unique);
	bp[4] = htonl(upper_32_bits(offset));
	bp[5] = htonl((u32) offset);
	bp[6] = 0;
	bp[7] = htonl((u32) length);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * fetch data from a file
 */
int afs_fs_fetch_data(struct afs_server *server,
		      struct key *key,
		      struct afs_vnode *vnode,
		      off_t offset, size_t length,
		      struct page *buffer,
		      const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	if (upper_32_bits(offset) || upper_32_bits(offset + length))
		return afs_fs_fetch_data64(server, key, vnode, offset, length,
					   buffer, wait_mode);

	_enter("");

	call = afs_alloc_flat_call(&afs_RXFSFetchData, 24, (21 + 3 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->reply2 = NULL; /* volsync */
	call->reply3 = buffer;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);
	call->operation_ID = FSFETCHDATA;

	/* marshall the parameters */
	bp = call->request;
	bp[0] = htonl(FSFETCHDATA);
	bp[1] = htonl(vnode->fid.vid);
	bp[2] = htonl(vnode->fid.vnode);
	bp[3] = htonl(vnode->fid.unique);
	bp[4] = htonl(offset);
	bp[5] = htonl(length);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.GiveUpCallBacks
 */
static int afs_deliver_fs_give_up_callbacks(struct afs_call *call,
					    struct sk_buff *skb, bool last)
{
	_enter(",{%u},%d", skb->len, last);

	if (skb->len > 0)
		return -EBADMSG; /* shouldn't be any reply data */
	return 0;
}

/*
 * FS.GiveUpCallBacks operation type
 */
static const struct afs_call_type afs_RXFSGiveUpCallBacks = {
	.name		= "FS.GiveUpCallBacks",
	.deliver	= afs_deliver_fs_give_up_callbacks,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * give up a set of callbacks
 * - the callbacks are held in the server->cb_break ring
 */
int afs_fs_give_up_callbacks(struct afs_server *server,
			     const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	size_t ncallbacks;
	__be32 *bp, *tp;
	int loop;

	ncallbacks = CIRC_CNT(server->cb_break_head, server->cb_break_tail,
			      ARRAY_SIZE(server->cb_break));

	_enter("{%zu},", ncallbacks);

	if (ncallbacks == 0)
		return 0;
	if (ncallbacks > AFSCBMAX)
		ncallbacks = AFSCBMAX;

	_debug("break %zu callbacks", ncallbacks);

	call = afs_alloc_flat_call(&afs_RXFSGiveUpCallBacks,
				   12 + ncallbacks * 6 * 4, 0);
	if (!call)
		return -ENOMEM;

	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	tp = bp + 2 + ncallbacks * 3;
	*bp++ = htonl(FSGIVEUPCALLBACKS);
	*bp++ = htonl(ncallbacks);
	*tp++ = htonl(ncallbacks);

	atomic_sub(ncallbacks, &server->cb_break_n);
	for (loop = ncallbacks; loop > 0; loop--) {
		struct afs_callback *cb =
			&server->cb_break[server->cb_break_tail];

		*bp++ = htonl(cb->fid.vid);
		*bp++ = htonl(cb->fid.vnode);
		*bp++ = htonl(cb->fid.unique);
		*tp++ = htonl(cb->version);
		*tp++ = htonl(cb->expiry);
		*tp++ = htonl(cb->type);
		smp_mb();
		server->cb_break_tail =
			(server->cb_break_tail + 1) &
			(ARRAY_SIZE(server->cb_break) - 1);
	}

	ASSERT(ncallbacks > 0);
	wake_up_nr(&server->cb_break_waitq, ncallbacks);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.CreateFile or an FS.MakeDir
 */
static int afs_deliver_fs_create_vnode(struct afs_call *call,
				       struct sk_buff *skb, bool last)
{
	struct afs_vnode *vnode = call->reply;
	const __be32 *bp;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	afs_transfer_reply(call, skb);
	if (!last)
		return 0;

	if (call->reply_size != call->reply_max)
		return -EBADMSG;

	/* unmarshall the reply once we've received all of it */
	bp = call->buffer;
	xdr_decode_AFSFid(&bp, call->reply2);
	xdr_decode_AFSFetchStatus(&bp, call->reply3, NULL, NULL);
	xdr_decode_AFSFetchStatus(&bp, &vnode->status, vnode, NULL);
	xdr_decode_AFSCallBack_raw(&bp, call->reply4);
	/* xdr_decode_AFSVolSync(&bp, call->replyX); */

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.CreateFile and FS.MakeDir operation type
 */
static const struct afs_call_type afs_RXFSCreateXXXX = {
	.name		= "FS.CreateXXXX",
	.deliver	= afs_deliver_fs_create_vnode,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * create a file or make a directory
 */
int afs_fs_create(struct afs_server *server,
		  struct key *key,
		  struct afs_vnode *vnode,
		  const char *name,
		  umode_t mode,
		  struct afs_fid *newfid,
		  struct afs_file_status *newstatus,
		  struct afs_callback *newcb,
		  const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	size_t namesz, reqsz, padsz;
	__be32 *bp;

	_enter("");

	namesz = strlen(name);
	padsz = (4 - (namesz & 3)) & 3;
	reqsz = (5 * 4) + namesz + padsz + (6 * 4);

	call = afs_alloc_flat_call(&afs_RXFSCreateXXXX, reqsz,
				   (3 + 21 + 21 + 3 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->reply2 = newfid;
	call->reply3 = newstatus;
	call->reply4 = newcb;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(S_ISDIR(mode) ? FSMAKEDIR : FSCREATEFILE);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);
	*bp++ = htonl(namesz);
	memcpy(bp, name, namesz);
	bp = (void *) bp + namesz;
	if (padsz > 0) {
		memset(bp, 0, padsz);
		bp = (void *) bp + padsz;
	}
	*bp++ = htonl(AFS_SET_MODE);
	*bp++ = 0; /* mtime */
	*bp++ = 0; /* owner */
	*bp++ = 0; /* group */
	*bp++ = htonl(mode & S_IALLUGO); /* unix mode */
	*bp++ = 0; /* segment size */

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.RemoveFile or FS.RemoveDir
 */
static int afs_deliver_fs_remove(struct afs_call *call,
				 struct sk_buff *skb, bool last)
{
	struct afs_vnode *vnode = call->reply;
	const __be32 *bp;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	afs_transfer_reply(call, skb);
	if (!last)
		return 0;

	if (call->reply_size != call->reply_max)
		return -EBADMSG;

	/* unmarshall the reply once we've received all of it */
	bp = call->buffer;
	xdr_decode_AFSFetchStatus(&bp, &vnode->status, vnode, NULL);
	/* xdr_decode_AFSVolSync(&bp, call->replyX); */

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.RemoveDir/FS.RemoveFile operation type
 */
static const struct afs_call_type afs_RXFSRemoveXXXX = {
	.name		= "FS.RemoveXXXX",
	.deliver	= afs_deliver_fs_remove,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * remove a file or directory
 */
int afs_fs_remove(struct afs_server *server,
		  struct key *key,
		  struct afs_vnode *vnode,
		  const char *name,
		  bool isdir,
		  const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	size_t namesz, reqsz, padsz;
	__be32 *bp;

	_enter("");

	namesz = strlen(name);
	padsz = (4 - (namesz & 3)) & 3;
	reqsz = (5 * 4) + namesz + padsz;

	call = afs_alloc_flat_call(&afs_RXFSRemoveXXXX, reqsz, (21 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(isdir ? FSREMOVEDIR : FSREMOVEFILE);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);
	*bp++ = htonl(namesz);
	memcpy(bp, name, namesz);
	bp = (void *) bp + namesz;
	if (padsz > 0) {
		memset(bp, 0, padsz);
		bp = (void *) bp + padsz;
	}

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.Link
 */
static int afs_deliver_fs_link(struct afs_call *call,
			       struct sk_buff *skb, bool last)
{
	struct afs_vnode *dvnode = call->reply, *vnode = call->reply2;
	const __be32 *bp;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	afs_transfer_reply(call, skb);
	if (!last)
		return 0;

	if (call->reply_size != call->reply_max)
		return -EBADMSG;

	/* unmarshall the reply once we've received all of it */
	bp = call->buffer;
	xdr_decode_AFSFetchStatus(&bp, &vnode->status, vnode, NULL);
	xdr_decode_AFSFetchStatus(&bp, &dvnode->status, dvnode, NULL);
	/* xdr_decode_AFSVolSync(&bp, call->replyX); */

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.Link operation type
 */
static const struct afs_call_type afs_RXFSLink = {
	.name		= "FS.Link",
	.deliver	= afs_deliver_fs_link,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * make a hard link
 */
int afs_fs_link(struct afs_server *server,
		struct key *key,
		struct afs_vnode *dvnode,
		struct afs_vnode *vnode,
		const char *name,
		const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	size_t namesz, reqsz, padsz;
	__be32 *bp;

	_enter("");

	namesz = strlen(name);
	padsz = (4 - (namesz & 3)) & 3;
	reqsz = (5 * 4) + namesz + padsz + (3 * 4);

	call = afs_alloc_flat_call(&afs_RXFSLink, reqsz, (21 + 21 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = dvnode;
	call->reply2 = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSLINK);
	*bp++ = htonl(dvnode->fid.vid);
	*bp++ = htonl(dvnode->fid.vnode);
	*bp++ = htonl(dvnode->fid.unique);
	*bp++ = htonl(namesz);
	memcpy(bp, name, namesz);
	bp = (void *) bp + namesz;
	if (padsz > 0) {
		memset(bp, 0, padsz);
		bp = (void *) bp + padsz;
	}
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.Symlink
 */
static int afs_deliver_fs_symlink(struct afs_call *call,
				  struct sk_buff *skb, bool last)
{
	struct afs_vnode *vnode = call->reply;
	const __be32 *bp;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	afs_transfer_reply(call, skb);
	if (!last)
		return 0;

	if (call->reply_size != call->reply_max)
		return -EBADMSG;

	/* unmarshall the reply once we've received all of it */
	bp = call->buffer;
	xdr_decode_AFSFid(&bp, call->reply2);
	xdr_decode_AFSFetchStatus(&bp, call->reply3, NULL, NULL);
	xdr_decode_AFSFetchStatus(&bp, &vnode->status, vnode, NULL);
	/* xdr_decode_AFSVolSync(&bp, call->replyX); */

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.Symlink operation type
 */
static const struct afs_call_type afs_RXFSSymlink = {
	.name		= "FS.Symlink",
	.deliver	= afs_deliver_fs_symlink,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * create a symbolic link
 */
int afs_fs_symlink(struct afs_server *server,
		   struct key *key,
		   struct afs_vnode *vnode,
		   const char *name,
		   const char *contents,
		   struct afs_fid *newfid,
		   struct afs_file_status *newstatus,
		   const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	size_t namesz, reqsz, padsz, c_namesz, c_padsz;
	__be32 *bp;

	_enter("");

	namesz = strlen(name);
	padsz = (4 - (namesz & 3)) & 3;

	c_namesz = strlen(contents);
	c_padsz = (4 - (c_namesz & 3)) & 3;

	reqsz = (6 * 4) + namesz + padsz + c_namesz + c_padsz + (6 * 4);

	call = afs_alloc_flat_call(&afs_RXFSSymlink, reqsz,
				   (3 + 21 + 21 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->reply2 = newfid;
	call->reply3 = newstatus;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSSYMLINK);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);
	*bp++ = htonl(namesz);
	memcpy(bp, name, namesz);
	bp = (void *) bp + namesz;
	if (padsz > 0) {
		memset(bp, 0, padsz);
		bp = (void *) bp + padsz;
	}
	*bp++ = htonl(c_namesz);
	memcpy(bp, contents, c_namesz);
	bp = (void *) bp + c_namesz;
	if (c_padsz > 0) {
		memset(bp, 0, c_padsz);
		bp = (void *) bp + c_padsz;
	}
	*bp++ = htonl(AFS_SET_MODE);
	*bp++ = 0; /* mtime */
	*bp++ = 0; /* owner */
	*bp++ = 0; /* group */
	*bp++ = htonl(S_IRWXUGO); /* unix mode */
	*bp++ = 0; /* segment size */

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.Rename
 */
static int afs_deliver_fs_rename(struct afs_call *call,
				  struct sk_buff *skb, bool last)
{
	struct afs_vnode *orig_dvnode = call->reply, *new_dvnode = call->reply2;
	const __be32 *bp;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	afs_transfer_reply(call, skb);
	if (!last)
		return 0;

	if (call->reply_size != call->reply_max)
		return -EBADMSG;

	/* unmarshall the reply once we've received all of it */
	bp = call->buffer;
	xdr_decode_AFSFetchStatus(&bp, &orig_dvnode->status, orig_dvnode, NULL);
	if (new_dvnode != orig_dvnode)
		xdr_decode_AFSFetchStatus(&bp, &new_dvnode->status, new_dvnode,
					  NULL);
	/* xdr_decode_AFSVolSync(&bp, call->replyX); */

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.Rename operation type
 */
static const struct afs_call_type afs_RXFSRename = {
	.name		= "FS.Rename",
	.deliver	= afs_deliver_fs_rename,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * create a symbolic link
 */
int afs_fs_rename(struct afs_server *server,
		  struct key *key,
		  struct afs_vnode *orig_dvnode,
		  const char *orig_name,
		  struct afs_vnode *new_dvnode,
		  const char *new_name,
		  const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	size_t reqsz, o_namesz, o_padsz, n_namesz, n_padsz;
	__be32 *bp;

	_enter("");

	o_namesz = strlen(orig_name);
	o_padsz = (4 - (o_namesz & 3)) & 3;

	n_namesz = strlen(new_name);
	n_padsz = (4 - (n_namesz & 3)) & 3;

	reqsz = (4 * 4) +
		4 + o_namesz + o_padsz +
		(3 * 4) +
		4 + n_namesz + n_padsz;

	call = afs_alloc_flat_call(&afs_RXFSRename, reqsz, (21 + 21 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = orig_dvnode;
	call->reply2 = new_dvnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSRENAME);
	*bp++ = htonl(orig_dvnode->fid.vid);
	*bp++ = htonl(orig_dvnode->fid.vnode);
	*bp++ = htonl(orig_dvnode->fid.unique);
	*bp++ = htonl(o_namesz);
	memcpy(bp, orig_name, o_namesz);
	bp = (void *) bp + o_namesz;
	if (o_padsz > 0) {
		memset(bp, 0, o_padsz);
		bp = (void *) bp + o_padsz;
	}

	*bp++ = htonl(new_dvnode->fid.vid);
	*bp++ = htonl(new_dvnode->fid.vnode);
	*bp++ = htonl(new_dvnode->fid.unique);
	*bp++ = htonl(n_namesz);
	memcpy(bp, new_name, n_namesz);
	bp = (void *) bp + n_namesz;
	if (n_padsz > 0) {
		memset(bp, 0, n_padsz);
		bp = (void *) bp + n_padsz;
	}

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.StoreData
 */
static int afs_deliver_fs_store_data(struct afs_call *call,
				     struct sk_buff *skb, bool last)
{
	struct afs_vnode *vnode = call->reply;
	const __be32 *bp;

	_enter(",,%u", last);

	afs_transfer_reply(call, skb);
	if (!last) {
		_leave(" = 0 [more]");
		return 0;
	}

	if (call->reply_size != call->reply_max) {
		_leave(" = -EBADMSG [%u != %u]",
		       call->reply_size, call->reply_max);
		return -EBADMSG;
	}

	/* unmarshall the reply once we've received all of it */
	bp = call->buffer;
	xdr_decode_AFSFetchStatus(&bp, &vnode->status, vnode,
				  &call->store_version);
	/* xdr_decode_AFSVolSync(&bp, call->replyX); */

	afs_pages_written_back(vnode, call);

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.StoreData operation type
 */
static const struct afs_call_type afs_RXFSStoreData = {
	.name		= "FS.StoreData",
	.deliver	= afs_deliver_fs_store_data,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

static const struct afs_call_type afs_RXFSStoreData64 = {
	.name		= "FS.StoreData64",
	.deliver	= afs_deliver_fs_store_data,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * store a set of pages to a very large file
 */
static int afs_fs_store_data64(struct afs_server *server,
			       struct afs_writeback *wb,
			       pgoff_t first, pgoff_t last,
			       unsigned offset, unsigned to,
			       loff_t size, loff_t pos, loff_t i_size,
			       const struct afs_wait_mode *wait_mode)
{
	struct afs_vnode *vnode = wb->vnode;
	struct afs_call *call;
	__be32 *bp;

	_enter(",%x,{%x:%u},,",
	       key_serial(wb->key), vnode->fid.vid, vnode->fid.vnode);

	call = afs_alloc_flat_call(&afs_RXFSStoreData64,
				   (4 + 6 + 3 * 2) * 4,
				   (21 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->wb = wb;
	call->key = wb->key;
	call->reply = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);
	call->mapping = vnode->vfs_inode.i_mapping;
	call->first = first;
	call->last = last;
	call->first_offset = offset;
	call->last_to = to;
	call->send_pages = true;
	call->store_version = vnode->status.data_version + 1;

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSSTOREDATA64);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);

	*bp++ = 0; /* mask */
	*bp++ = 0; /* mtime */
	*bp++ = 0; /* owner */
	*bp++ = 0; /* group */
	*bp++ = 0; /* unix mode */
	*bp++ = 0; /* segment size */

	*bp++ = htonl(pos >> 32);
	*bp++ = htonl((u32) pos);
	*bp++ = htonl(size >> 32);
	*bp++ = htonl((u32) size);
	*bp++ = htonl(i_size >> 32);
	*bp++ = htonl((u32) i_size);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * store a set of pages
 */
int afs_fs_store_data(struct afs_server *server, struct afs_writeback *wb,
		      pgoff_t first, pgoff_t last,
		      unsigned offset, unsigned to,
		      const struct afs_wait_mode *wait_mode)
{
	struct afs_vnode *vnode = wb->vnode;
	struct afs_call *call;
	loff_t size, pos, i_size;
	__be32 *bp;

	_enter(",%x,{%x:%u},,",
	       key_serial(wb->key), vnode->fid.vid, vnode->fid.vnode);

	size = to - offset;
	if (first != last)
		size += (loff_t)(last - first) << PAGE_SHIFT;
	pos = (loff_t)first << PAGE_SHIFT;
	pos += offset;

	i_size = i_size_read(&vnode->vfs_inode);
	if (pos + size > i_size)
		i_size = size + pos;

	_debug("size %llx, at %llx, i_size %llx",
	       (unsigned long long) size, (unsigned long long) pos,
	       (unsigned long long) i_size);

	if (pos >> 32 || i_size >> 32 || size >> 32 || (pos + size) >> 32)
		return afs_fs_store_data64(server, wb, first, last, offset, to,
					   size, pos, i_size, wait_mode);

	call = afs_alloc_flat_call(&afs_RXFSStoreData,
				   (4 + 6 + 3) * 4,
				   (21 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->wb = wb;
	call->key = wb->key;
	call->reply = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);
	call->mapping = vnode->vfs_inode.i_mapping;
	call->first = first;
	call->last = last;
	call->first_offset = offset;
	call->last_to = to;
	call->send_pages = true;
	call->store_version = vnode->status.data_version + 1;

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSSTOREDATA);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);

	*bp++ = 0; /* mask */
	*bp++ = 0; /* mtime */
	*bp++ = 0; /* owner */
	*bp++ = 0; /* group */
	*bp++ = 0; /* unix mode */
	*bp++ = 0; /* segment size */

	*bp++ = htonl(pos);
	*bp++ = htonl(size);
	*bp++ = htonl(i_size);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.StoreStatus
 */
static int afs_deliver_fs_store_status(struct afs_call *call,
				       struct sk_buff *skb, bool last)
{
	afs_dataversion_t *store_version;
	struct afs_vnode *vnode = call->reply;
	const __be32 *bp;

	_enter(",,%u", last);

	afs_transfer_reply(call, skb);
	if (!last) {
		_leave(" = 0 [more]");
		return 0;
	}

	if (call->reply_size != call->reply_max) {
		_leave(" = -EBADMSG [%u != %u]",
		       call->reply_size, call->reply_max);
		return -EBADMSG;
	}

	/* unmarshall the reply once we've received all of it */
	store_version = NULL;
	if (call->operation_ID == FSSTOREDATA)
		store_version = &call->store_version;

	bp = call->buffer;
	xdr_decode_AFSFetchStatus(&bp, &vnode->status, vnode, store_version);
	/* xdr_decode_AFSVolSync(&bp, call->replyX); */

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.StoreStatus operation type
 */
static const struct afs_call_type afs_RXFSStoreStatus = {
	.name		= "FS.StoreStatus",
	.deliver	= afs_deliver_fs_store_status,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

static const struct afs_call_type afs_RXFSStoreData_as_Status = {
	.name		= "FS.StoreData",
	.deliver	= afs_deliver_fs_store_status,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

static const struct afs_call_type afs_RXFSStoreData64_as_Status = {
	.name		= "FS.StoreData64",
	.deliver	= afs_deliver_fs_store_status,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * set the attributes on a very large file, using FS.StoreData rather than
 * FS.StoreStatus so as to alter the file size also
 */
static int afs_fs_setattr_size64(struct afs_server *server, struct key *key,
				 struct afs_vnode *vnode, struct iattr *attr,
				 const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	_enter(",%x,{%x:%u},,",
	       key_serial(key), vnode->fid.vid, vnode->fid.vnode);

	ASSERT(attr->ia_valid & ATTR_SIZE);

	call = afs_alloc_flat_call(&afs_RXFSStoreData64_as_Status,
				   (4 + 6 + 3 * 2) * 4,
				   (21 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);
	call->store_version = vnode->status.data_version + 1;
	call->operation_ID = FSSTOREDATA;

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSSTOREDATA64);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);

	xdr_encode_AFS_StoreStatus(&bp, attr);

	*bp++ = 0;				/* position of start of write */
	*bp++ = 0;
	*bp++ = 0;				/* size of write */
	*bp++ = 0;
	*bp++ = htonl(attr->ia_size >> 32);	/* new file length */
	*bp++ = htonl((u32) attr->ia_size);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * set the attributes on a file, using FS.StoreData rather than FS.StoreStatus
 * so as to alter the file size also
 */
static int afs_fs_setattr_size(struct afs_server *server, struct key *key,
			       struct afs_vnode *vnode, struct iattr *attr,
			       const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	_enter(",%x,{%x:%u},,",
	       key_serial(key), vnode->fid.vid, vnode->fid.vnode);

	ASSERT(attr->ia_valid & ATTR_SIZE);
	if (attr->ia_size >> 32)
		return afs_fs_setattr_size64(server, key, vnode, attr,
					     wait_mode);

	call = afs_alloc_flat_call(&afs_RXFSStoreData_as_Status,
				   (4 + 6 + 3) * 4,
				   (21 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);
	call->store_version = vnode->status.data_version + 1;
	call->operation_ID = FSSTOREDATA;

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSSTOREDATA);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);

	xdr_encode_AFS_StoreStatus(&bp, attr);

	*bp++ = 0;				/* position of start of write */
	*bp++ = 0;				/* size of write */
	*bp++ = htonl(attr->ia_size);		/* new file length */

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * set the attributes on a file, using FS.StoreData if there's a change in file
 * size, and FS.StoreStatus otherwise
 */
int afs_fs_setattr(struct afs_server *server, struct key *key,
		   struct afs_vnode *vnode, struct iattr *attr,
		   const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	if (attr->ia_valid & ATTR_SIZE)
		return afs_fs_setattr_size(server, key, vnode, attr,
					   wait_mode);

	_enter(",%x,{%x:%u},,",
	       key_serial(key), vnode->fid.vid, vnode->fid.vnode);

	call = afs_alloc_flat_call(&afs_RXFSStoreStatus,
				   (4 + 6) * 4,
				   (21 + 6) * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);
	call->operation_ID = FSSTORESTATUS;

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSSTORESTATUS);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);

	xdr_encode_AFS_StoreStatus(&bp, attr);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.GetVolumeStatus
 */
static int afs_deliver_fs_get_volume_status(struct afs_call *call,
					    struct sk_buff *skb, bool last)
{
	const __be32 *bp;
	char *p;
	int ret;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	switch (call->unmarshall) {
	case 0:
		call->offset = 0;
		call->unmarshall++;

		/* extract the returned status record */
	case 1:
		_debug("extract status");
		ret = afs_extract_data(call, skb, last, call->buffer,
				       12 * 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		bp = call->buffer;
		xdr_decode_AFSFetchVolumeStatus(&bp, call->reply2);
		call->offset = 0;
		call->unmarshall++;

		/* extract the volume name length */
	case 2:
		ret = afs_extract_data(call, skb, last, &call->tmp, 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->count = ntohl(call->tmp);
		_debug("volname length: %u", call->count);
		if (call->count >= AFSNAMEMAX)
			return -EBADMSG;
		call->offset = 0;
		call->unmarshall++;

		/* extract the volume name */
	case 3:
		_debug("extract volname");
		if (call->count > 0) {
			ret = afs_extract_data(call, skb, last, call->reply3,
					       call->count);
			switch (ret) {
			case 0:		break;
			case -EAGAIN:	return 0;
			default:	return ret;
			}
		}

		p = call->reply3;
		p[call->count] = 0;
		_debug("volname '%s'", p);

		call->offset = 0;
		call->unmarshall++;

		/* extract the volume name padding */
		if ((call->count & 3) == 0) {
			call->unmarshall++;
			goto no_volname_padding;
		}
		call->count = 4 - (call->count & 3);

	case 4:
		ret = afs_extract_data(call, skb, last, call->buffer,
				       call->count);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->offset = 0;
		call->unmarshall++;
	no_volname_padding:

		/* extract the offline message length */
	case 5:
		ret = afs_extract_data(call, skb, last, &call->tmp, 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->count = ntohl(call->tmp);
		_debug("offline msg length: %u", call->count);
		if (call->count >= AFSNAMEMAX)
			return -EBADMSG;
		call->offset = 0;
		call->unmarshall++;

		/* extract the offline message */
	case 6:
		_debug("extract offline");
		if (call->count > 0) {
			ret = afs_extract_data(call, skb, last, call->reply3,
					       call->count);
			switch (ret) {
			case 0:		break;
			case -EAGAIN:	return 0;
			default:	return ret;
			}
		}

		p = call->reply3;
		p[call->count] = 0;
		_debug("offline '%s'", p);

		call->offset = 0;
		call->unmarshall++;

		/* extract the offline message padding */
		if ((call->count & 3) == 0) {
			call->unmarshall++;
			goto no_offline_padding;
		}
		call->count = 4 - (call->count & 3);

	case 7:
		ret = afs_extract_data(call, skb, last, call->buffer,
				       call->count);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->offset = 0;
		call->unmarshall++;
	no_offline_padding:

		/* extract the message of the day length */
	case 8:
		ret = afs_extract_data(call, skb, last, &call->tmp, 4);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->count = ntohl(call->tmp);
		_debug("motd length: %u", call->count);
		if (call->count >= AFSNAMEMAX)
			return -EBADMSG;
		call->offset = 0;
		call->unmarshall++;

		/* extract the message of the day */
	case 9:
		_debug("extract motd");
		if (call->count > 0) {
			ret = afs_extract_data(call, skb, last, call->reply3,
					       call->count);
			switch (ret) {
			case 0:		break;
			case -EAGAIN:	return 0;
			default:	return ret;
			}
		}

		p = call->reply3;
		p[call->count] = 0;
		_debug("motd '%s'", p);

		call->offset = 0;
		call->unmarshall++;

		/* extract the message of the day padding */
		if ((call->count & 3) == 0) {
			call->unmarshall++;
			goto no_motd_padding;
		}
		call->count = 4 - (call->count & 3);

	case 10:
		ret = afs_extract_data(call, skb, last, call->buffer,
				       call->count);
		switch (ret) {
		case 0:		break;
		case -EAGAIN:	return 0;
		default:	return ret;
		}

		call->offset = 0;
		call->unmarshall++;
	no_motd_padding:

	case 11:
		_debug("trailer %d", skb->len);
		if (skb->len != 0)
			return -EBADMSG;
		break;
	}

	if (!last)
		return 0;

	_leave(" = 0 [done]");
	return 0;
}

/*
 * destroy an FS.GetVolumeStatus call
 */
static void afs_get_volume_status_call_destructor(struct afs_call *call)
{
	kfree(call->reply3);
	call->reply3 = NULL;
	afs_flat_call_destructor(call);
}

/*
 * FS.GetVolumeStatus operation type
 */
static const struct afs_call_type afs_RXFSGetVolumeStatus = {
	.name		= "FS.GetVolumeStatus",
	.deliver	= afs_deliver_fs_get_volume_status,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_get_volume_status_call_destructor,
};

/*
 * fetch the status of a volume
 */
int afs_fs_get_volume_status(struct afs_server *server,
			     struct key *key,
			     struct afs_vnode *vnode,
			     struct afs_volume_status *vs,
			     const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;
	void *tmpbuf;

	_enter("");

	tmpbuf = kmalloc(AFSOPAQUEMAX, GFP_KERNEL);
	if (!tmpbuf)
		return -ENOMEM;

	call = afs_alloc_flat_call(&afs_RXFSGetVolumeStatus, 2 * 4, 12 * 4);
	if (!call) {
		kfree(tmpbuf);
		return -ENOMEM;
	}

	call->key = key;
	call->reply = vnode;
	call->reply2 = vs;
	call->reply3 = tmpbuf;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	bp[0] = htonl(FSGETVOLUMESTATUS);
	bp[1] = htonl(vnode->fid.vid);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * deliver reply data to an FS.SetLock, FS.ExtendLock or FS.ReleaseLock
 */
static int afs_deliver_fs_xxxx_lock(struct afs_call *call,
				    struct sk_buff *skb, bool last)
{
	const __be32 *bp;

	_enter("{%u},{%u},%d", call->unmarshall, skb->len, last);

	afs_transfer_reply(call, skb);
	if (!last)
		return 0;

	if (call->reply_size != call->reply_max)
		return -EBADMSG;

	/* unmarshall the reply once we've received all of it */
	bp = call->buffer;
	/* xdr_decode_AFSVolSync(&bp, call->replyX); */

	_leave(" = 0 [done]");
	return 0;
}

/*
 * FS.SetLock operation type
 */
static const struct afs_call_type afs_RXFSSetLock = {
	.name		= "FS.SetLock",
	.deliver	= afs_deliver_fs_xxxx_lock,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * FS.ExtendLock operation type
 */
static const struct afs_call_type afs_RXFSExtendLock = {
	.name		= "FS.ExtendLock",
	.deliver	= afs_deliver_fs_xxxx_lock,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * FS.ReleaseLock operation type
 */
static const struct afs_call_type afs_RXFSReleaseLock = {
	.name		= "FS.ReleaseLock",
	.deliver	= afs_deliver_fs_xxxx_lock,
	.abort_to_error	= afs_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * get a lock on a file
 */
int afs_fs_set_lock(struct afs_server *server,
		    struct key *key,
		    struct afs_vnode *vnode,
		    afs_lock_type_t type,
		    const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	_enter("");

	call = afs_alloc_flat_call(&afs_RXFSSetLock, 5 * 4, 6 * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSSETLOCK);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);
	*bp++ = htonl(type);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * extend a lock on a file
 */
int afs_fs_extend_lock(struct afs_server *server,
		       struct key *key,
		       struct afs_vnode *vnode,
		       const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	_enter("");

	call = afs_alloc_flat_call(&afs_RXFSExtendLock, 4 * 4, 6 * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSEXTENDLOCK);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}

/*
 * release a lock on a file
 */
int afs_fs_release_lock(struct afs_server *server,
			struct key *key,
			struct afs_vnode *vnode,
			const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	_enter("");

	call = afs_alloc_flat_call(&afs_RXFSReleaseLock, 4 * 4, 6 * 4);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = vnode;
	call->service_id = FS_SERVICE;
	call->port = htons(AFS_FS_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(FSRELEASELOCK);
	*bp++ = htonl(vnode->fid.vid);
	*bp++ = htonl(vnode->fid.vnode);
	*bp++ = htonl(vnode->fid.unique);

	return afs_make_call(&server->addr, call, GFP_NOFS, wait_mode);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/fsclient.c */
/************************************************************/
/*
 * Copyright (c) 2002 Red Hat, Inc. All rights reserved.
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>
 *          David Howells <dhowells@redhat.com>
 *
 */

// #include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/init.h>
// #include <linux/fs.h>
// #include <linux/pagemap.h>
// #include <linux/sched.h>
#include <linux/mount.h>
// #include <linux/namei.h>
// #include "internal.h"
#include "../../inc/__fss.h"

struct afs_iget_data {
	struct afs_fid		fid;
	struct afs_volume	*volume;	/* volume on which resides */
};

/*
 * map the AFS file status to the inode member variables
 */
static int afs_inode_map_status(struct afs_vnode *vnode, struct key *key)
{
	struct inode *inode = AFS_VNODE_TO_I(vnode);

	_debug("FS: ft=%d lk=%d sz=%llu ver=%Lu mod=%hu",
	       vnode->status.type,
	       vnode->status.nlink,
	       (unsigned long long) vnode->status.size,
	       vnode->status.data_version,
	       vnode->status.mode);

	switch (vnode->status.type) {
	case AFS_FTYPE_FILE:
		inode->i_mode	= S_IFREG | vnode->status.mode;
		inode->i_op	= &afs_file_inode_operations;
		inode->i_fop	= &afs_file_operations;
		break;
	case AFS_FTYPE_DIR:
		inode->i_mode	= S_IFDIR | vnode->status.mode;
		inode->i_op	= &afs_dir_inode_operations;
		inode->i_fop	= &afs_dir_file_operations;
		break;
	case AFS_FTYPE_SYMLINK:
		inode->i_mode	= S_IFLNK | vnode->status.mode;
		inode->i_op	= &page_symlink_inode_operations;
		break;
	default:
		printk("kAFS: AFS vnode with undefined type\n");
		return -EBADMSG;
	}

#ifdef CONFIG_AFS_FSCACHE
	if (vnode->status.size != inode->i_size)
		fscache_attr_changed(vnode->cache);
#endif

	set_nlink(inode, vnode->status.nlink);
	inode->i_uid		= vnode->status.owner;
	inode->i_gid		= GLOBAL_ROOT_GID;
	inode->i_size		= vnode->status.size;
	inode->i_ctime.tv_sec	= vnode->status.mtime_server;
	inode->i_ctime.tv_nsec	= 0;
	inode->i_atime		= inode->i_mtime = inode->i_ctime;
	inode->i_blocks		= 0;
	inode->i_generation	= vnode->fid.unique;
	inode->i_version	= vnode->status.data_version;
	inode->i_mapping->a_ops	= &afs_fs_aops;

	/* check to see whether a symbolic link is really a mountpoint */
	if (vnode->status.type == AFS_FTYPE_SYMLINK) {
		afs_mntpt_check_symlink(vnode, key);

		if (test_bit(AFS_VNODE_MOUNTPOINT, &vnode->flags)) {
			inode->i_mode	= S_IFDIR | vnode->status.mode;
			inode->i_op	= &afs_mntpt_inode_operations;
			inode->i_fop	= &afs_mntpt_file_operations;
		}
	}

	return 0;
}

/*
 * iget5() comparator
 */
static int afs_iget5_test(struct inode *inode, void *opaque)
{
	struct afs_iget_data *data = opaque;

	return inode->i_ino == data->fid.vnode &&
		inode->i_generation == data->fid.unique;
}

/*
 * iget5() comparator for inode created by autocell operations
 *
 * These pseudo inodes don't match anything.
 */
static int afs_iget5_autocell_test(struct inode *inode, void *opaque)
{
	return 0;
}

/*
 * iget5() inode initialiser
 */
static int afs_iget5_set(struct inode *inode, void *opaque)
{
	struct afs_iget_data *data = opaque;
	struct afs_vnode *vnode = AFS_FS_I(inode);

	inode->i_ino = data->fid.vnode;
	inode->i_generation = data->fid.unique;
	vnode->fid = data->fid;
	vnode->volume = data->volume;

	return 0;
}

/*
 * inode retrieval for autocell
 */
struct inode *afs_iget_autocell(struct inode *dir, const char *dev_name,
				int namesz, struct key *key)
{
	struct afs_iget_data data;
	struct afs_super_info *as;
	struct afs_vnode *vnode;
	struct super_block *sb;
	struct inode *inode;
	static atomic_t afs_autocell_ino;

	_enter("{%x:%u},%*.*s,",
	       AFS_FS_I(dir)->fid.vid, AFS_FS_I(dir)->fid.vnode,
	       namesz, namesz, dev_name ?: "");

	sb = dir->i_sb;
	as = sb->s_fs_info;
	data.volume = as->volume;
	data.fid.vid = as->volume->vid;
	data.fid.unique = 0;
	data.fid.vnode = 0;

	inode = iget5_locked(sb, atomic_inc_return(&afs_autocell_ino),
			     afs_iget5_autocell_test, afs_iget5_set,
			     &data);
	if (!inode) {
		_leave(" = -ENOMEM");
		return ERR_PTR(-ENOMEM);
	}

	_debug("GOT INODE %p { ino=%lu, vl=%x, vn=%x, u=%x }",
	       inode, inode->i_ino, data.fid.vid, data.fid.vnode,
	       data.fid.unique);

	vnode = AFS_FS_I(inode);

	/* there shouldn't be an existing inode */
	BUG_ON(!(inode->i_state & I_NEW));

	inode->i_size		= 0;
	inode->i_mode		= S_IFDIR | S_IRUGO | S_IXUGO;
	inode->i_op		= &afs_autocell_inode_operations;
	set_nlink(inode, 2);
	inode->i_uid		= GLOBAL_ROOT_UID;
	inode->i_gid		= GLOBAL_ROOT_GID;
	inode->i_ctime.tv_sec	= get_seconds();
	inode->i_ctime.tv_nsec	= 0;
	inode->i_atime		= inode->i_mtime = inode->i_ctime;
	inode->i_blocks		= 0;
	inode->i_version	= 0;
	inode->i_generation	= 0;

	set_bit(AFS_VNODE_PSEUDODIR, &vnode->flags);
	set_bit(AFS_VNODE_MOUNTPOINT, &vnode->flags);
	inode->i_flags |= S_AUTOMOUNT | S_NOATIME;
	unlock_new_inode(inode);
	_leave(" = %p", inode);
	return inode;
}

/*
 * inode retrieval
 */
struct inode *afs_iget(struct super_block *sb, struct key *key,
		       struct afs_fid *fid, struct afs_file_status *status,
		       struct afs_callback *cb)
{
	struct afs_iget_data data = { .fid = *fid };
	struct afs_super_info *as;
	struct afs_vnode *vnode;
	struct inode *inode;
	int ret;

	_enter(",{%x:%u.%u},,", fid->vid, fid->vnode, fid->unique);

	as = sb->s_fs_info;
	data.volume = as->volume;

	inode = iget5_locked(sb, fid->vnode, afs_iget5_test, afs_iget5_set,
			     &data);
	if (!inode) {
		_leave(" = -ENOMEM");
		return ERR_PTR(-ENOMEM);
	}

	_debug("GOT INODE %p { vl=%x vn=%x, u=%x }",
	       inode, fid->vid, fid->vnode, fid->unique);

	vnode = AFS_FS_I(inode);

	/* deal with an existing inode */
	if (!(inode->i_state & I_NEW)) {
		_leave(" = %p", inode);
		return inode;
	}

	if (!status) {
		/* it's a remotely extant inode */
		set_bit(AFS_VNODE_CB_BROKEN, &vnode->flags);
		ret = afs_vnode_fetch_status(vnode, NULL, key);
		if (ret < 0)
			goto bad_inode;
	} else {
		/* it's an inode we just created */
		memcpy(&vnode->status, status, sizeof(vnode->status));

		if (!cb) {
			/* it's a symlink we just created (the fileserver
			 * didn't give us a callback) */
			vnode->cb_version = 0;
			vnode->cb_expiry = 0;
			vnode->cb_type = 0;
			vnode->cb_expires = get_seconds();
		} else {
			vnode->cb_version = cb->version;
			vnode->cb_expiry = cb->expiry;
			vnode->cb_type = cb->type;
			vnode->cb_expires = vnode->cb_expiry + get_seconds();
		}
	}

	/* set up caching before mapping the status, as map-status reads the
	 * first page of symlinks to see if they're really mountpoints */
	inode->i_size = vnode->status.size;
#ifdef CONFIG_AFS_FSCACHE
	vnode->cache = fscache_acquire_cookie(vnode->volume->cache,
					      &afs_vnode_cache_index_def,
					      vnode, true);
#endif

	ret = afs_inode_map_status(vnode, key);
	if (ret < 0)
		goto bad_inode;

	/* success */
	clear_bit(AFS_VNODE_UNSET, &vnode->flags);
	inode->i_flags |= S_NOATIME;
	unlock_new_inode(inode);
	_leave(" = %p [CB { v=%u t=%u }]", inode, vnode->cb_version, vnode->cb_type);
	return inode;

	/* failure */
bad_inode:
#ifdef CONFIG_AFS_FSCACHE
	fscache_relinquish_cookie(vnode->cache, 0);
	vnode->cache = NULL;
#endif
	iget_failed(inode);
	_leave(" = %d [bad]", ret);
	return ERR_PTR(ret);
}

/*
 * mark the data attached to an inode as obsolete due to a write on the server
 * - might also want to ditch all the outstanding writes and dirty pages
 */
void afs_zap_data(struct afs_vnode *vnode)
{
	_enter("{%x:%u}", vnode->fid.vid, vnode->fid.vnode);

	/* nuke all the non-dirty pages that aren't locked, mapped or being
	 * written back in a regular file and completely discard the pages in a
	 * directory or symlink */
	if (S_ISREG(vnode->vfs_inode.i_mode))
		invalidate_remote_inode(&vnode->vfs_inode);
	else
		invalidate_inode_pages2(vnode->vfs_inode.i_mapping);
}

/*
 * validate a vnode/inode
 * - there are several things we need to check
 *   - parent dir data changes (rm, rmdir, rename, mkdir, create, link,
 *     symlink)
 *   - parent dir metadata changed (security changes)
 *   - dentry data changed (write, truncate)
 *   - dentry metadata changed (security changes)
 */
int afs_validate(struct afs_vnode *vnode, struct key *key)
{
	int ret;

	_enter("{v={%x:%u} fl=%lx},%x",
	       vnode->fid.vid, vnode->fid.vnode, vnode->flags,
	       key_serial(key));

	if (vnode->cb_promised &&
	    !test_bit(AFS_VNODE_CB_BROKEN, &vnode->flags) &&
	    !test_bit(AFS_VNODE_MODIFIED, &vnode->flags) &&
	    !test_bit(AFS_VNODE_ZAP_DATA, &vnode->flags)) {
		if (vnode->cb_expires < get_seconds() + 10) {
			_debug("callback expired");
			set_bit(AFS_VNODE_CB_BROKEN, &vnode->flags);
		} else {
			goto valid;
		}
	}

	if (test_bit(AFS_VNODE_DELETED, &vnode->flags))
		goto valid;

	mutex_lock(&vnode->validate_lock);

	/* if the promise has expired, we need to check the server again to get
	 * a new promise - note that if the (parent) directory's metadata was
	 * changed then the security may be different and we may no longer have
	 * access */
	if (!vnode->cb_promised ||
	    test_bit(AFS_VNODE_CB_BROKEN, &vnode->flags)) {
		_debug("not promised");
		ret = afs_vnode_fetch_status(vnode, NULL, key);
		if (ret < 0)
			goto error_unlock;
		_debug("new promise [fl=%lx]", vnode->flags);
	}

	if (test_bit(AFS_VNODE_DELETED, &vnode->flags)) {
		_debug("file already deleted");
		ret = -ESTALE;
		goto error_unlock;
	}

	/* if the vnode's data version number changed then its contents are
	 * different */
	if (test_and_clear_bit(AFS_VNODE_ZAP_DATA, &vnode->flags))
		afs_zap_data(vnode);

	clear_bit(AFS_VNODE_MODIFIED, &vnode->flags);
	mutex_unlock(&vnode->validate_lock);
valid:
	_leave(" = 0");
	return 0;

error_unlock:
	mutex_unlock(&vnode->validate_lock);
	_leave(" = %d", ret);
	return ret;
}

/*
 * read the attributes of an inode
 */
int afs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		      struct kstat *stat)
{
	struct inode *inode;

	inode = dentry->d_inode;

	_enter("{ ino=%lu v=%u }", inode->i_ino, inode->i_generation);

	generic_fillattr(inode, stat);
	return 0;
}

/*
 * discard an AFS inode
 */
int afs_drop_inode(struct inode *inode)
{
	_enter("");

	if (test_bit(AFS_VNODE_PSEUDODIR, &AFS_FS_I(inode)->flags))
		return generic_delete_inode(inode);
	else
		return generic_drop_inode(inode);
}

/*
 * clear an AFS inode
 */
void afs_evict_inode(struct inode *inode)
{
	struct afs_permits *permits;
	struct afs_vnode *vnode;

	vnode = AFS_FS_I(inode);

	_enter("{%x:%u.%d} v=%u x=%u t=%u }",
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       vnode->cb_version,
	       vnode->cb_expiry,
	       vnode->cb_type);

	_debug("CLEAR INODE %p", inode);

	ASSERTCMP(inode->i_ino, ==, vnode->fid.vnode);

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	afs_give_up_callback(vnode);

	if (vnode->server) {
		spin_lock(&vnode->server->fs_lock);
		rb_erase(&vnode->server_rb, &vnode->server->fs_vnodes);
		spin_unlock(&vnode->server->fs_lock);
		afs_put_server(vnode->server);
		vnode->server = NULL;
	}

	ASSERT(list_empty(&vnode->writebacks));
	ASSERT(!vnode->cb_promised);

#ifdef CONFIG_AFS_FSCACHE
	fscache_relinquish_cookie(vnode->cache, 0);
	vnode->cache = NULL;
#endif

	mutex_lock(&vnode->permits_lock);
	permits = vnode->permits;
	rcu_assign_pointer(vnode->permits, NULL);
	mutex_unlock(&vnode->permits_lock);
	if (permits)
		call_rcu(&permits->rcu, afs_zap_permits);

	_leave("");
}

/*
 * set the attributes of an inode
 */
int afs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct afs_vnode *vnode = AFS_FS_I(dentry->d_inode);
	struct key *key;
	int ret;

	_enter("{%x:%u},{n=%pd},%x",
	       vnode->fid.vid, vnode->fid.vnode, dentry,
	       attr->ia_valid);

	if (!(attr->ia_valid & (ATTR_SIZE | ATTR_MODE | ATTR_UID | ATTR_GID |
				ATTR_MTIME))) {
		_leave(" = 0 [unsupported]");
		return 0;
	}

	/* flush any dirty data outstanding on a regular file */
	if (S_ISREG(vnode->vfs_inode.i_mode)) {
		filemap_write_and_wait(vnode->vfs_inode.i_mapping);
		afs_writeback_all(vnode);
	}

	if (attr->ia_valid & ATTR_FILE) {
		key = attr->ia_file->private_data;
	} else {
		key = afs_request_key(vnode->volume->cell);
		if (IS_ERR(key)) {
			ret = PTR_ERR(key);
			goto error;
		}
	}

	ret = afs_vnode_setattr(vnode, key, attr);
	if (!(attr->ia_valid & ATTR_FILE))
		key_put(key);

error:
	_leave(" = %d", ret);
	return ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/inode.c */
/************************************************************/
/* AFS client file system
 *
 * Copyright (C) 2002,5 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/module.h>
#include <linux/moduleparam.h>
// #include <linux/init.h>
#include <linux/completion.h>
// #include <linux/sched.h>
// #include "internal.h"
#include "../../inc/__fss.h"

MODULE_DESCRIPTION("AFS Client File System");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

unsigned afs_debug;
module_param_named(debug, afs_debug, uint, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(debug, "AFS debugging mask");

static char *rootcell;

module_param(rootcell, charp, 0);
MODULE_PARM_DESC(rootcell, "root AFS cell name and VL server IP addr list");

struct afs_uuid afs_uuid;
struct workqueue_struct *afs_wq;

/*
 * get a client UUID
 */
static int __init afs_get_client_UUID(void)
{
	struct timespec ts;
	u64 uuidtime;
	u16 clockseq;
	int ret;

	/* read the MAC address of one of the external interfaces and construct
	 * a UUID from it */
	ret = afs_get_MAC_address(afs_uuid.node, sizeof(afs_uuid.node));
	if (ret < 0)
		return ret;

	getnstimeofday(&ts);
	uuidtime = (u64) ts.tv_sec * 1000 * 1000 * 10;
	uuidtime += ts.tv_nsec / 100;
	uuidtime += AFS_UUID_TO_UNIX_TIME;
	afs_uuid.time_low = uuidtime;
	afs_uuid.time_mid = uuidtime >> 32;
	afs_uuid.time_hi_and_version = (uuidtime >> 48) & AFS_UUID_TIMEHI_MASK;
	afs_uuid.time_hi_and_version |= AFS_UUID_VERSION_TIME;

	get_random_bytes(&clockseq, 2);
	afs_uuid.clock_seq_low = clockseq;
	afs_uuid.clock_seq_hi_and_reserved =
		(clockseq >> 8) & AFS_UUID_CLOCKHI_MASK;
	afs_uuid.clock_seq_hi_and_reserved |= AFS_UUID_VARIANT_STD;

	_debug("AFS UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	       afs_uuid.time_low,
	       afs_uuid.time_mid,
	       afs_uuid.time_hi_and_version,
	       afs_uuid.clock_seq_hi_and_reserved,
	       afs_uuid.clock_seq_low,
	       afs_uuid.node[0], afs_uuid.node[1], afs_uuid.node[2],
	       afs_uuid.node[3], afs_uuid.node[4], afs_uuid.node[5]);

	return 0;
}

/*
 * initialise the AFS client FS module
 */
static int __init afs_init(void)
{
	int ret;

	printk(KERN_INFO "kAFS: Red Hat AFS client v0.1 registering.\n");

	ret = afs_get_client_UUID();
	if (ret < 0)
		return ret;

	/* create workqueue */
	ret = -ENOMEM;
	afs_wq = alloc_workqueue("afs", 0, 0);
	if (!afs_wq)
		return ret;

	/* register the /proc stuff */
	ret = afs_proc_init();
	if (ret < 0)
		goto error_proc;

#ifdef CONFIG_AFS_FSCACHE
	/* we want to be able to cache */
	ret = fscache_register_netfs(&afs_cache_netfs);
	if (ret < 0)
		goto error_cache;
#endif

	/* initialise the cell DB */
	ret = afs_cell_init(rootcell);
	if (ret < 0)
		goto error_cell_init;

	/* initialise the VL update process */
	ret = afs_vlocation_update_init();
	if (ret < 0)
		goto error_vl_update_init;

	/* initialise the callback update process */
	ret = afs_callback_update_init();
	if (ret < 0)
		goto error_callback_update_init;

	/* create the RxRPC transport */
	ret = afs_open_socket();
	if (ret < 0)
		goto error_open_socket;

	/* register the filesystems */
	ret = afs_fs_init();
	if (ret < 0)
		goto error_fs;

	return ret;

error_fs:
	afs_close_socket();
error_open_socket:
	afs_callback_update_kill();
error_callback_update_init:
	afs_vlocation_purge();
error_vl_update_init:
	afs_cell_purge();
error_cell_init:
#ifdef CONFIG_AFS_FSCACHE
	fscache_unregister_netfs(&afs_cache_netfs);
error_cache:
#endif
	afs_proc_cleanup();
error_proc:
	destroy_workqueue(afs_wq);
	rcu_barrier();
	printk(KERN_ERR "kAFS: failed to register: %d\n", ret);
	return ret;
}

/* XXX late_initcall is kludgy, but the only alternative seems to create
 * a transport upon the first mount, which is worse. Or is it?
 */
late_initcall(afs_init);	/* must be called after net/ to create socket */

/*
 * clean up on module removal
 */
static void __exit afs_exit(void)
{
	printk(KERN_INFO "kAFS: Red Hat AFS client v0.1 unregistering.\n");

	afs_fs_exit();
	afs_kill_lock_manager();
	afs_close_socket();
	afs_purge_servers();
	afs_callback_update_kill();
	afs_vlocation_purge();
	destroy_workqueue(afs_wq);
	afs_cell_purge();
#ifdef CONFIG_AFS_FSCACHE
	fscache_unregister_netfs(&afs_cache_netfs);
#endif
	afs_proc_cleanup();
	rcu_barrier();
}

module_exit(afs_exit);
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/main.c */
/************************************************************/
/* miscellaneous bits
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/kernel.h>
// #include <linux/module.h>
#include <linux/errno.h>
#include <rxrpc/packet.h>
// #include "internal.h"
// #include "afs_fs.h"
#include "../../inc/__fss.h"

/*
 * convert an AFS abort code to a Linux error number
 */
int afs_abort_to_error(u32 abort_code)
{
	switch (abort_code) {
	case 13:		return -EACCES;
	case 27:		return -EFBIG;
	case 30:		return -EROFS;
	case VSALVAGE:		return -EIO;
	case VNOVNODE:		return -ENOENT;
	case VNOVOL:		return -ENOMEDIUM;
	case VVOLEXISTS:	return -EEXIST;
	case VNOSERVICE:	return -EIO;
	case VOFFLINE:		return -ENOENT;
	case VONLINE:		return -EEXIST;
	case VDISKFULL:		return -ENOSPC;
	case VOVERQUOTA:	return -EDQUOT;
	case VBUSY:		return -EBUSY;
	case VMOVED:		return -ENXIO;
	case 0x2f6df0a:		return -EWOULDBLOCK;
	case 0x2f6df0c:		return -EACCES;
	case 0x2f6df0f:		return -EBUSY;
	case 0x2f6df10:		return -EEXIST;
	case 0x2f6df11:		return -EXDEV;
	case 0x2f6df13:		return -ENOTDIR;
	case 0x2f6df14:		return -EISDIR;
	case 0x2f6df15:		return -EINVAL;
	case 0x2f6df1a:		return -EFBIG;
	case 0x2f6df1b:		return -ENOSPC;
	case 0x2f6df1d:		return -EROFS;
	case 0x2f6df1e:		return -EMLINK;
	case 0x2f6df20:		return -EDOM;
	case 0x2f6df21:		return -ERANGE;
	case 0x2f6df22:		return -EDEADLK;
	case 0x2f6df23:		return -ENAMETOOLONG;
	case 0x2f6df24:		return -ENOLCK;
	case 0x2f6df26:		return -ENOTEMPTY;
	case 0x2f6df78:		return -EDQUOT;

	case RXKADINCONSISTENCY: return -EPROTO;
	case RXKADPACKETSHORT:	return -EPROTO;
	case RXKADLEVELFAIL:	return -EKEYREJECTED;
	case RXKADTICKETLEN:	return -EKEYREJECTED;
	case RXKADOUTOFSEQUENCE: return -EPROTO;
	case RXKADNOAUTH:	return -EKEYREJECTED;
	case RXKADBADKEY:	return -EKEYREJECTED;
	case RXKADBADTICKET:	return -EKEYREJECTED;
	case RXKADUNKNOWNKEY:	return -EKEYREJECTED;
	case RXKADEXPIRED:	return -EKEYEXPIRED;
	case RXKADSEALEDINCON:	return -EKEYREJECTED;
	case RXKADDATALEN:	return -EKEYREJECTED;
	case RXKADILLEGALLEVEL:	return -EKEYREJECTED;

	default:		return -EREMOTEIO;
	}
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/misc.c */
/************************************************************/
/* mountpoint management
 *
 * Copyright (C) 2002 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/init.h>
// #include <linux/fs.h>
// #include <linux/pagemap.h>
// #include <linux/mount.h>
// #include <linux/namei.h>
// #include <linux/gfp.h>
// #include "internal.h"


static struct dentry *afs_mntpt_lookup(struct inode *dir,
				       struct dentry *dentry,
				       unsigned int flags);
static int afs_mntpt_open(struct inode *inode, struct file *file);
static void afs_mntpt_expiry_timed_out(struct work_struct *work);

const struct file_operations afs_mntpt_file_operations = {
	.open		= afs_mntpt_open,
	.llseek		= noop_llseek,
};

const struct inode_operations afs_mntpt_inode_operations = {
	.lookup		= afs_mntpt_lookup,
	.readlink	= page_readlink,
	.getattr	= afs_getattr,
};

const struct inode_operations afs_autocell_inode_operations = {
	.getattr	= afs_getattr,
};

static LIST_HEAD(afs_vfsmounts);
static DECLARE_DELAYED_WORK_mntpt_c(afs_mntpt_expiry_timer, afs_mntpt_expiry_timed_out);

static unsigned long afs_mntpt_expiry_timeout = 10 * 60;

/*
 * check a symbolic link to see whether it actually encodes a mountpoint
 * - sets the AFS_VNODE_MOUNTPOINT flag on the vnode appropriately
 */
int afs_mntpt_check_symlink(struct afs_vnode *vnode, struct key *key)
{
	struct page *page;
	size_t size;
	char *buf;
	int ret;

	_enter("{%x:%u,%u}",
	       vnode->fid.vid, vnode->fid.vnode, vnode->fid.unique);

	/* read the contents of the symlink into the pagecache */
	page = read_cache_page(AFS_VNODE_TO_I(vnode)->i_mapping, 0,
			       afs_page_filler, key);
	if (IS_ERR(page)) {
		ret = PTR_ERR(page);
		goto out;
	}

	ret = -EIO;
	if (PageError(page))
		goto out_free;

	buf = kmap(page);

	/* examine the symlink's contents */
	size = vnode->status.size;
	_debug("symlink to %*.*s", (int) size, (int) size, buf);

	if (size > 2 &&
	    (buf[0] == '%' || buf[0] == '#') &&
	    buf[size - 1] == '.'
	    ) {
		_debug("symlink is a mountpoint");
		spin_lock(&vnode->lock);
		set_bit(AFS_VNODE_MOUNTPOINT, &vnode->flags);
		vnode->vfs_inode.i_flags |= S_AUTOMOUNT;
		spin_unlock(&vnode->lock);
	}

	ret = 0;

	kunmap(page);
out_free:
	page_cache_release(page);
out:
	_leave(" = %d", ret);
	return ret;
}

/*
 * no valid lookup procedure on this sort of dir
 */
static struct dentry *afs_mntpt_lookup(struct inode *dir,
				       struct dentry *dentry,
				       unsigned int flags)
{
	_enter("%p,%p{%pd2}", dir, dentry, dentry);
	return ERR_PTR(-EREMOTE);
}

/*
 * no valid open procedure on this sort of dir
 */
static int afs_mntpt_open(struct inode *inode, struct file *file)
{
	_enter("%p,%p{%pD2}", inode, file, file);
	return -EREMOTE;
}

/*
 * create a vfsmount to be automounted
 */
static struct vfsmount *afs_mntpt_do_automount(struct dentry *mntpt)
{
	struct afs_super_info *super;
	struct vfsmount *mnt;
	struct afs_vnode *vnode;
	struct page *page;
	char *devname, *options;
	bool rwpath = false;
	int ret;

	_enter("{%pd}", mntpt);

	BUG_ON(!mntpt->d_inode);

	ret = -ENOMEM;
	devname = (char *) get_zeroed_page(GFP_KERNEL);
	if (!devname)
		goto error_no_devname;

	options = (char *) get_zeroed_page(GFP_KERNEL);
	if (!options)
		goto error_no_options;

	vnode = AFS_FS_I(mntpt->d_inode);
	if (test_bit(AFS_VNODE_PSEUDODIR, &vnode->flags)) {
		/* if the directory is a pseudo directory, use the d_name */
		static const char afs_root_cell[] = ":root.cell.";
		unsigned size = mntpt->d_name.len;

		ret = -ENOENT;
		if (size < 2 || size > AFS_MAXCELLNAME)
			goto error_no_page;

		if (mntpt->d_name.name[0] == '.') {
			devname[0] = '#';
			memcpy(devname + 1, mntpt->d_name.name, size - 1);
			memcpy(devname + size, afs_root_cell,
			       sizeof(afs_root_cell));
			rwpath = true;
		} else {
			devname[0] = '%';
			memcpy(devname + 1, mntpt->d_name.name, size);
			memcpy(devname + size + 1, afs_root_cell,
			       sizeof(afs_root_cell));
		}
	} else {
		/* read the contents of the AFS special symlink */
		loff_t size = i_size_read(mntpt->d_inode);
		char *buf;

		ret = -EINVAL;
		if (size > PAGE_SIZE - 1)
			goto error_no_page;

		page = read_mapping_page(mntpt->d_inode->i_mapping, 0, NULL);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			goto error_no_page;
		}

		ret = -EIO;
		if (PageError(page))
			goto error;

		buf = kmap_atomic(page);
		memcpy(devname, buf, size);
		kunmap_atomic(buf);
		page_cache_release(page);
		page = NULL;
	}

	/* work out what options we want */
	super = AFS_FS_S(mntpt->d_sb);
	memcpy(options, "cell=", 5);
	strcpy(options + 5, super->volume->cell->name);
	if (super->volume->type == AFSVL_RWVOL || rwpath)
		strcat(options, ",rwpath");

	/* try and do the mount */
	_debug("--- attempting mount %s -o %s ---", devname, options);
	mnt = vfs_kern_mount(&afs_fs_type, 0, devname, options);
	_debug("--- mount result %p ---", mnt);

	free_page((unsigned long) devname);
	free_page((unsigned long) options);
	_leave(" = %p", mnt);
	return mnt;

error:
	page_cache_release(page);
error_no_page:
	free_page((unsigned long) options);
error_no_options:
	free_page((unsigned long) devname);
error_no_devname:
	_leave(" = %d", ret);
	return ERR_PTR(ret);
}

/*
 * handle an automount point
 */
struct vfsmount *afs_d_automount(struct path *path)
{
	struct vfsmount *newmnt;

	_enter("{%pd}", path->dentry);

	newmnt = afs_mntpt_do_automount(path->dentry);
	if (IS_ERR(newmnt))
		return newmnt;

	mntget(newmnt); /* prevent immediate expiration */
	mnt_set_expiry(newmnt, &afs_vfsmounts);
	queue_delayed_work(afs_wq, &afs_mntpt_expiry_timer,
			   afs_mntpt_expiry_timeout * HZ);
	_leave(" = %p", newmnt);
	return newmnt;
}

/*
 * handle mountpoint expiry timer going off
 */
static void afs_mntpt_expiry_timed_out(struct work_struct *work)
{
	_enter("");

	if (!list_empty(&afs_vfsmounts)) {
		mark_mounts_for_expiry(&afs_vfsmounts);
		queue_delayed_work(afs_wq, &afs_mntpt_expiry_timer,
				   afs_mntpt_expiry_timeout * HZ);
	}

	_leave("");
}

/*
 * kill the AFS mountpoint timer if it's still running
 */
void afs_mntpt_kill_timer(void)
{
	_enter("");

	ASSERT(list_empty(&afs_vfsmounts));
	cancel_delayed_work_sync(&afs_mntpt_expiry_timer);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/mntpt.c */
/************************************************************/
/* /proc interface for AFS
 *
 * Copyright (C) 2002 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/slab.h>
// #include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
// #include <linux/sched.h>
#include <asm/uaccess.h>
// #include "internal.h"
#include "../../inc/__fss.h"

static struct proc_dir_entry *proc_afs;


static int afs_proc_cells_open(struct inode *inode, struct file *file);
static void *afs_proc_cells_start(struct seq_file *p, loff_t *pos);
static void *afs_proc_cells_next(struct seq_file *p, void *v, loff_t *pos);
static void afs_proc_cells_stop(struct seq_file *p, void *v);
static int afs_proc_cells_show(struct seq_file *m, void *v);
static ssize_t afs_proc_cells_write(struct file *file, const char __user *buf,
				    size_t size, loff_t *_pos);

static const struct seq_operations afs_proc_cells_ops = {
	.start	= afs_proc_cells_start,
	.next	= afs_proc_cells_next,
	.stop	= afs_proc_cells_stop,
	.show	= afs_proc_cells_show,
};

static const struct file_operations afs_proc_cells_fops = {
	.open		= afs_proc_cells_open,
	.read		= seq_read,
	.write		= afs_proc_cells_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static ssize_t afs_proc_rootcell_read(struct file *file, char __user *buf,
				      size_t size, loff_t *_pos);
static ssize_t afs_proc_rootcell_write(struct file *file,
				       const char __user *buf,
				       size_t size, loff_t *_pos);

static const struct file_operations afs_proc_rootcell_fops = {
	.read		= afs_proc_rootcell_read,
	.write		= afs_proc_rootcell_write,
	.llseek		= no_llseek,
};

static int afs_proc_cell_volumes_open(struct inode *inode, struct file *file);
static void *afs_proc_cell_volumes_start(struct seq_file *p, loff_t *pos);
static void *afs_proc_cell_volumes_next(struct seq_file *p, void *v,
					loff_t *pos);
static void afs_proc_cell_volumes_stop(struct seq_file *p, void *v);
static int afs_proc_cell_volumes_show(struct seq_file *m, void *v);

static const struct seq_operations afs_proc_cell_volumes_ops = {
	.start	= afs_proc_cell_volumes_start,
	.next	= afs_proc_cell_volumes_next,
	.stop	= afs_proc_cell_volumes_stop,
	.show	= afs_proc_cell_volumes_show,
};

static const struct file_operations afs_proc_cell_volumes_fops = {
	.open		= afs_proc_cell_volumes_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int afs_proc_cell_vlservers_open(struct inode *inode,
					struct file *file);
static void *afs_proc_cell_vlservers_start(struct seq_file *p, loff_t *pos);
static void *afs_proc_cell_vlservers_next(struct seq_file *p, void *v,
					  loff_t *pos);
static void afs_proc_cell_vlservers_stop(struct seq_file *p, void *v);
static int afs_proc_cell_vlservers_show(struct seq_file *m, void *v);

static const struct seq_operations afs_proc_cell_vlservers_ops = {
	.start	= afs_proc_cell_vlservers_start,
	.next	= afs_proc_cell_vlservers_next,
	.stop	= afs_proc_cell_vlservers_stop,
	.show	= afs_proc_cell_vlservers_show,
};

static const struct file_operations afs_proc_cell_vlservers_fops = {
	.open		= afs_proc_cell_vlservers_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int afs_proc_cell_servers_open(struct inode *inode, struct file *file);
static void *afs_proc_cell_servers_start(struct seq_file *p, loff_t *pos);
static void *afs_proc_cell_servers_next(struct seq_file *p, void *v,
					loff_t *pos);
static void afs_proc_cell_servers_stop(struct seq_file *p, void *v);
static int afs_proc_cell_servers_show(struct seq_file *m, void *v);

static const struct seq_operations afs_proc_cell_servers_ops = {
	.start	= afs_proc_cell_servers_start,
	.next	= afs_proc_cell_servers_next,
	.stop	= afs_proc_cell_servers_stop,
	.show	= afs_proc_cell_servers_show,
};

static const struct file_operations afs_proc_cell_servers_fops = {
	.open		= afs_proc_cell_servers_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/*
 * initialise the /proc/fs/afs/ directory
 */
int afs_proc_init(void)
{
	_enter("");

	proc_afs = proc_mkdir("fs/afs", NULL);
	if (!proc_afs)
		goto error_dir;

	if (!proc_create("cells", 0644, proc_afs, &afs_proc_cells_fops) ||
	    !proc_create("rootcell", 0644, proc_afs, &afs_proc_rootcell_fops))
		goto error_tree;

	_leave(" = 0");
	return 0;

error_tree:
	remove_proc_subtree("fs/afs", NULL);
error_dir:
	_leave(" = -ENOMEM");
	return -ENOMEM;
}

/*
 * clean up the /proc/fs/afs/ directory
 */
void afs_proc_cleanup(void)
{
	remove_proc_subtree("fs/afs", NULL);
}

/*
 * open "/proc/fs/afs/cells" which provides a summary of extant cells
 */
static int afs_proc_cells_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = seq_open(file, &afs_proc_cells_ops);
	if (ret < 0)
		return ret;

	m = file->private_data;
	m->private = PDE_DATA(inode);

	return 0;
}

/*
 * set up the iterator to start reading from the cells list and return the
 * first item
 */
static void *afs_proc_cells_start(struct seq_file *m, loff_t *_pos)
{
	/* lock the list against modification */
	down_read(&afs_proc_cells_sem);
	return seq_list_start_head(&afs_proc_cells, *_pos);
}

/*
 * move to next cell in cells list
 */
static void *afs_proc_cells_next(struct seq_file *p, void *v, loff_t *pos)
{
	return seq_list_next(v, &afs_proc_cells, pos);
}

/*
 * clean up after reading from the cells list
 */
static void afs_proc_cells_stop(struct seq_file *p, void *v)
{
	up_read(&afs_proc_cells_sem);
}

/*
 * display a header line followed by a load of cell lines
 */
static int afs_proc_cells_show(struct seq_file *m, void *v)
{
	struct afs_cell *cell = list_entry(v, struct afs_cell, proc_link);

	if (v == &afs_proc_cells) {
		/* display header on line 1 */
		seq_puts(m, "USE NAME\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	seq_printf(m, "%3d %s\n",
		   atomic_read(&cell->usage), cell->name);
	return 0;
}

/*
 * handle writes to /proc/fs/afs/cells
 * - to add cells: echo "add <cellname> <IP>[:<IP>][:<IP>]"
 */
static ssize_t afs_proc_cells_write(struct file *file, const char __user *buf,
				    size_t size, loff_t *_pos)
{
	char *kbuf, *name, *args;
	int ret;

	/* start by dragging the command into memory */
	if (size <= 1 || size >= PAGE_SIZE)
		return -EINVAL;

	kbuf = kmalloc(size + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = -EFAULT;
	if (copy_from_user(kbuf, buf, size) != 0)
		goto done;
	kbuf[size] = 0;

	/* trim to first NL */
	name = memchr(kbuf, '\n', size);
	if (name)
		*name = 0;

	/* split into command, name and argslist */
	name = strchr(kbuf, ' ');
	if (!name)
		goto inval;
	do {
		*name++ = 0;
	} while(*name == ' ');
	if (!*name)
		goto inval;

	args = strchr(name, ' ');
	if (!args)
		goto inval;
	do {
		*args++ = 0;
	} while(*args == ' ');
	if (!*args)
		goto inval;

	/* determine command to perform */
	_debug("cmd=%s name=%s args=%s", kbuf, name, args);

	if (strcmp(kbuf, "add") == 0) {
		struct afs_cell *cell;

		cell = afs_cell_create(name, strlen(name), args, false);
		if (IS_ERR(cell)) {
			ret = PTR_ERR(cell);
			goto done;
		}

		afs_put_cell(cell);
		printk("kAFS: Added new cell '%s'\n", name);
	} else {
		goto inval;
	}

	ret = size;

done:
	kfree(kbuf);
	_leave(" = %d", ret);
	return ret;

inval:
	ret = -EINVAL;
	printk("kAFS: Invalid Command on /proc/fs/afs/cells file\n");
	goto done;
}

static ssize_t afs_proc_rootcell_read(struct file *file, char __user *buf,
				      size_t size, loff_t *_pos)
{
	return 0;
}

/*
 * handle writes to /proc/fs/afs/rootcell
 * - to initialize rootcell: echo "cell.name:192.168.231.14"
 */
static ssize_t afs_proc_rootcell_write(struct file *file,
				       const char __user *buf,
				       size_t size, loff_t *_pos)
{
	char *kbuf, *s;
	int ret;

	/* start by dragging the command into memory */
	if (size <= 1 || size >= PAGE_SIZE)
		return -EINVAL;

	ret = -ENOMEM;
	kbuf = kmalloc(size + 1, GFP_KERNEL);
	if (!kbuf)
		goto nomem;

	ret = -EFAULT;
	if (copy_from_user(kbuf, buf, size) != 0)
		goto infault;
	kbuf[size] = 0;

	/* trim to first NL */
	s = memchr(kbuf, '\n', size);
	if (s)
		*s = 0;

	/* determine command to perform */
	_debug("rootcell=%s", kbuf);

	ret = afs_cell_init(kbuf);
	if (ret >= 0)
		ret = size;	/* consume everything, always */

infault:
	kfree(kbuf);
nomem:
	_leave(" = %d", ret);
	return ret;
}

/*
 * initialise /proc/fs/afs/<cell>/
 */
int afs_proc_cell_setup(struct afs_cell *cell)
{
	struct proc_dir_entry *dir;

	_enter("%p{%s}", cell, cell->name);

	dir = proc_mkdir(cell->name, proc_afs);
	if (!dir)
		goto error_dir;

	if (!proc_create_data("servers", 0, dir,
			     &afs_proc_cell_servers_fops, cell) ||
	    !proc_create_data("vlservers", 0, dir,
			     &afs_proc_cell_vlservers_fops, cell) ||
	    !proc_create_data("volumes", 0, dir,
			     &afs_proc_cell_volumes_fops, cell))
		goto error_tree;

	_leave(" = 0");
	return 0;

error_tree:
	remove_proc_subtree(cell->name, proc_afs);
error_dir:
	_leave(" = -ENOMEM");
	return -ENOMEM;
}

/*
 * remove /proc/fs/afs/<cell>/
 */
void afs_proc_cell_remove(struct afs_cell *cell)
{
	_enter("");

	remove_proc_subtree(cell->name, proc_afs);

	_leave("");
}

/*
 * open "/proc/fs/afs/<cell>/volumes" which provides a summary of extant cells
 */
static int afs_proc_cell_volumes_open(struct inode *inode, struct file *file)
{
	struct afs_cell *cell;
	struct seq_file *m;
	int ret;

	cell = PDE_DATA(inode);
	if (!cell)
		return -ENOENT;

	ret = seq_open(file, &afs_proc_cell_volumes_ops);
	if (ret < 0)
		return ret;

	m = file->private_data;
	m->private = cell;

	return 0;
}

/*
 * set up the iterator to start reading from the cells list and return the
 * first item
 */
static void *afs_proc_cell_volumes_start(struct seq_file *m, loff_t *_pos)
{
	struct afs_cell *cell = m->private;

	_enter("cell=%p pos=%Ld", cell, *_pos);

	/* lock the list against modification */
	down_read(&cell->vl_sem);
	return seq_list_start_head(&cell->vl_list, *_pos);
}

/*
 * move to next cell in cells list
 */
static void *afs_proc_cell_volumes_next(struct seq_file *p, void *v,
					loff_t *_pos)
{
	struct afs_cell *cell = p->private;

	_enter("cell=%p pos=%Ld", cell, *_pos);
	return seq_list_next(v, &cell->vl_list, _pos);
}

/*
 * clean up after reading from the cells list
 */
static void afs_proc_cell_volumes_stop(struct seq_file *p, void *v)
{
	struct afs_cell *cell = p->private;

	up_read(&cell->vl_sem);
}

static const char afs_vlocation_states[][4] = {
	[AFS_VL_NEW]			= "New",
	[AFS_VL_CREATING]		= "Crt",
	[AFS_VL_VALID]			= "Val",
	[AFS_VL_NO_VOLUME]		= "NoV",
	[AFS_VL_UPDATING]		= "Upd",
	[AFS_VL_VOLUME_DELETED]		= "Del",
	[AFS_VL_UNCERTAIN]		= "Unc",
};

/*
 * display a header line followed by a load of volume lines
 */
static int afs_proc_cell_volumes_show(struct seq_file *m, void *v)
{
	struct afs_cell *cell = m->private;
	struct afs_vlocation *vlocation =
		list_entry(v, struct afs_vlocation, link);

	/* display header on line 1 */
	if (v == &cell->vl_list) {
		seq_puts(m, "USE STT VLID[0]  VLID[1]  VLID[2]  NAME\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	seq_printf(m, "%3d %s %08x %08x %08x %s\n",
		   atomic_read(&vlocation->usage),
		   afs_vlocation_states[vlocation->state],
		   vlocation->vldb.vid[0],
		   vlocation->vldb.vid[1],
		   vlocation->vldb.vid[2],
		   vlocation->vldb.name);

	return 0;
}

/*
 * open "/proc/fs/afs/<cell>/vlservers" which provides a list of volume
 * location server
 */
static int afs_proc_cell_vlservers_open(struct inode *inode, struct file *file)
{
	struct afs_cell *cell;
	struct seq_file *m;
	int ret;

	cell = PDE_DATA(inode);
	if (!cell)
		return -ENOENT;

	ret = seq_open(file, &afs_proc_cell_vlservers_ops);
	if (ret<0)
		return ret;

	m = file->private_data;
	m->private = cell;

	return 0;
}

/*
 * set up the iterator to start reading from the cells list and return the
 * first item
 */
static void *afs_proc_cell_vlservers_start(struct seq_file *m, loff_t *_pos)
{
	struct afs_cell *cell = m->private;
	loff_t pos = *_pos;

	_enter("cell=%p pos=%Ld", cell, *_pos);

	/* lock the list against modification */
	down_read(&cell->vl_sem);

	/* allow for the header line */
	if (!pos)
		return (void *) 1;
	pos--;

	if (pos >= cell->vl_naddrs)
		return NULL;

	return &cell->vl_addrs[pos];
}

/*
 * move to next cell in cells list
 */
static void *afs_proc_cell_vlservers_next(struct seq_file *p, void *v,
					  loff_t *_pos)
{
	struct afs_cell *cell = p->private;
	loff_t pos;

	_enter("cell=%p{nad=%u} pos=%Ld", cell, cell->vl_naddrs, *_pos);

	pos = *_pos;
	(*_pos)++;
	if (pos >= cell->vl_naddrs)
		return NULL;

	return &cell->vl_addrs[pos];
}

/*
 * clean up after reading from the cells list
 */
static void afs_proc_cell_vlservers_stop(struct seq_file *p, void *v)
{
	struct afs_cell *cell = p->private;

	up_read(&cell->vl_sem);
}

/*
 * display a header line followed by a load of volume lines
 */
static int afs_proc_cell_vlservers_show(struct seq_file *m, void *v)
{
	struct in_addr *addr = v;

	/* display header on line 1 */
	if (v == (struct in_addr *) 1) {
		seq_puts(m, "ADDRESS\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	seq_printf(m, "%pI4\n", &addr->s_addr);
	return 0;
}

/*
 * open "/proc/fs/afs/<cell>/servers" which provides a summary of active
 * servers
 */
static int afs_proc_cell_servers_open(struct inode *inode, struct file *file)
{
	struct afs_cell *cell;
	struct seq_file *m;
	int ret;

	cell = PDE_DATA(inode);
	if (!cell)
		return -ENOENT;

	ret = seq_open(file, &afs_proc_cell_servers_ops);
	if (ret < 0)
		return ret;

	m = file->private_data;
	m->private = cell;
	return 0;
}

/*
 * set up the iterator to start reading from the cells list and return the
 * first item
 */
static void *afs_proc_cell_servers_start(struct seq_file *m, loff_t *_pos)
	__acquires(m->private->servers_lock)
{
	struct afs_cell *cell = m->private;

	_enter("cell=%p pos=%Ld", cell, *_pos);

	/* lock the list against modification */
	read_lock(&cell->servers_lock);
	return seq_list_start_head(&cell->servers, *_pos);
}

/*
 * move to next cell in cells list
 */
static void *afs_proc_cell_servers_next(struct seq_file *p, void *v,
					loff_t *_pos)
{
	struct afs_cell *cell = p->private;

	_enter("cell=%p pos=%Ld", cell, *_pos);
	return seq_list_next(v, &cell->servers, _pos);
}

/*
 * clean up after reading from the cells list
 */
static void afs_proc_cell_servers_stop(struct seq_file *p, void *v)
	__releases(p->private->servers_lock)
{
	struct afs_cell *cell = p->private;

	read_unlock(&cell->servers_lock);
}

/*
 * display a header line followed by a load of volume lines
 */
static int afs_proc_cell_servers_show(struct seq_file *m, void *v)
{
	struct afs_cell *cell = m->private;
	struct afs_server *server = list_entry(v, struct afs_server, link);
	char ipaddr[20];

	/* display header on line 1 */
	if (v == &cell->servers) {
		seq_puts(m, "USE ADDR            STATE\n");
		return 0;
	}

	/* display one cell per line on subsequent lines */
	sprintf(ipaddr, "%pI4", &server->addr);
	seq_printf(m, "%3d %-15.15s %5d\n",
		   atomic_read(&server->usage), ipaddr, server->fs_state);

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/proc.c */
/************************************************************/
/* Maintain an RxRPC server socket to do AFS communications through
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/slab.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
// #include <rxrpc/packet.h>
// #include "internal.h"
// #include "afs_cm.h"
#include "../../inc/__fss.h"

static struct socket *afs_socket; /* my RxRPC socket */
static struct workqueue_struct *afs_async_calls;
static atomic_t afs_outstanding_calls;
static atomic_t afs_outstanding_skbs;

static void afs_wake_up_call_waiter(struct afs_call *);
static int afs_wait_for_call_to_complete(struct afs_call *);
static void afs_wake_up_async_call(struct afs_call *);
static int afs_dont_wait_for_call_to_complete(struct afs_call *);
static void afs_process_async_call(struct afs_call *);
static void afs_rx_interceptor(struct sock *, unsigned long, struct sk_buff *);
static int afs_deliver_cm_op_id(struct afs_call *, struct sk_buff *, bool);

/* synchronous call management */
const struct afs_wait_mode afs_sync_call = {
	.rx_wakeup	= afs_wake_up_call_waiter,
	.wait		= afs_wait_for_call_to_complete,
};

/* asynchronous call management */
const struct afs_wait_mode afs_async_call = {
	.rx_wakeup	= afs_wake_up_async_call,
	.wait		= afs_dont_wait_for_call_to_complete,
};

/* asynchronous incoming call management */
static const struct afs_wait_mode afs_async_incoming_call = {
	.rx_wakeup	= afs_wake_up_async_call,
};

/* asynchronous incoming call initial processing */
static const struct afs_call_type afs_RXCMxxxx = {
	.name		= "CB.xxxx",
	.deliver	= afs_deliver_cm_op_id,
	.abort_to_error	= afs_abort_to_error,
};

static void afs_collect_incoming_call(struct work_struct *);

static struct sk_buff_head afs_incoming_calls;
static DECLARE_WORK(afs_collect_incoming_call_work, afs_collect_incoming_call);

static void afs_async_workfn(struct work_struct *work)
{
	struct afs_call *call = container_of(work, struct afs_call, async_work);

	call->async_workfn(call);
}

/*
 * open an RxRPC socket and bind it to be a server for callback notifications
 * - the socket is left in blocking mode and non-blocking ops use MSG_DONTWAIT
 */
int afs_open_socket(void)
{
	struct sockaddr_rxrpc srx;
	struct socket *socket;
	int ret;

	_enter("");

	skb_queue_head_init(&afs_incoming_calls);

	afs_async_calls = create_singlethread_workqueue("kafsd");
	if (!afs_async_calls) {
		_leave(" = -ENOMEM [wq]");
		return -ENOMEM;
	}

	ret = sock_create_kern(AF_RXRPC, SOCK_DGRAM, PF_INET, &socket);
	if (ret < 0) {
		destroy_workqueue(afs_async_calls);
		_leave(" = %d [socket]", ret);
		return ret;
	}

	socket->sk->sk_allocation = GFP_NOFS;

	/* bind the callback manager's address to make this a server socket */
	srx.srx_family			= AF_RXRPC;
	srx.srx_service			= CM_SERVICE;
	srx.transport_type		= SOCK_DGRAM;
	srx.transport_len		= sizeof(srx.transport.sin);
	srx.transport.sin.sin_family	= AF_INET;
	srx.transport.sin.sin_port	= htons(AFS_CM_PORT);
	memset(&srx.transport.sin.sin_addr, 0,
	       sizeof(srx.transport.sin.sin_addr));

	ret = kernel_bind(socket, (struct sockaddr *) &srx, sizeof(srx));
	if (ret < 0) {
		sock_release(socket);
		destroy_workqueue(afs_async_calls);
		_leave(" = %d [bind]", ret);
		return ret;
	}

	rxrpc_kernel_intercept_rx_messages(socket, afs_rx_interceptor);

	afs_socket = socket;
	_leave(" = 0");
	return 0;
}

/*
 * close the RxRPC socket AFS was using
 */
void afs_close_socket(void)
{
	_enter("");

	sock_release(afs_socket);

	_debug("dework");
	destroy_workqueue(afs_async_calls);

	ASSERTCMP(atomic_read(&afs_outstanding_skbs), ==, 0);
	ASSERTCMP(atomic_read(&afs_outstanding_calls), ==, 0);
	_leave("");
}

/*
 * note that the data in a socket buffer is now delivered and that the buffer
 * should be freed
 */
static void afs_data_delivered(struct sk_buff *skb)
{
	if (!skb) {
		_debug("DLVR NULL [%d]", atomic_read(&afs_outstanding_skbs));
		dump_stack();
	} else {
		_debug("DLVR %p{%u} [%d]",
		       skb, skb->mark, atomic_read(&afs_outstanding_skbs));
		if (atomic_dec_return(&afs_outstanding_skbs) == -1)
			BUG();
		rxrpc_kernel_data_delivered(skb);
	}
}

/*
 * free a socket buffer
 */
static void afs_free_skb(struct sk_buff *skb)
{
	if (!skb) {
		_debug("FREE NULL [%d]", atomic_read(&afs_outstanding_skbs));
		dump_stack();
	} else {
		_debug("FREE %p{%u} [%d]",
		       skb, skb->mark, atomic_read(&afs_outstanding_skbs));
		if (atomic_dec_return(&afs_outstanding_skbs) == -1)
			BUG();
		rxrpc_kernel_free_skb(skb);
	}
}

/*
 * free a call
 */
static void afs_free_call(struct afs_call *call)
{
	_debug("DONE %p{%s} [%d]",
	       call, call->type->name, atomic_read(&afs_outstanding_calls));
	if (atomic_dec_return(&afs_outstanding_calls) == -1)
		BUG();

	ASSERTCMP(call->rxcall, ==, NULL);
	ASSERT(!work_pending(&call->async_work));
	ASSERT(skb_queue_empty(&call->rx_queue));
	ASSERT(call->type->name != NULL);

	kfree(call->request);
	kfree(call);
}

/*
 * End a call but do not free it
 */
static void afs_end_call_nofree(struct afs_call *call)
{
	if (call->rxcall) {
		rxrpc_kernel_end_call(call->rxcall);
		call->rxcall = NULL;
	}
	if (call->type->destructor)
		call->type->destructor(call);
}

/*
 * End a call and free it
 */
static void afs_end_call(struct afs_call *call)
{
	afs_end_call_nofree(call);
	afs_free_call(call);
}

/*
 * allocate a call with flat request and reply buffers
 */
struct afs_call *afs_alloc_flat_call(const struct afs_call_type *type,
				     size_t request_size, size_t reply_size)
{
	struct afs_call *call;

	call = kzalloc(sizeof(*call), GFP_NOFS);
	if (!call)
		goto nomem_call;

	_debug("CALL %p{%s} [%d]",
	       call, type->name, atomic_read(&afs_outstanding_calls));
	atomic_inc(&afs_outstanding_calls);

	call->type = type;
	call->request_size = request_size;
	call->reply_max = reply_size;

	if (request_size) {
		call->request = kmalloc(request_size, GFP_NOFS);
		if (!call->request)
			goto nomem_free;
	}

	if (reply_size) {
		call->buffer = kmalloc(reply_size, GFP_NOFS);
		if (!call->buffer)
			goto nomem_free;
	}

	init_waitqueue_head(&call->waitq);
	skb_queue_head_init(&call->rx_queue);
	return call;

nomem_free:
	afs_free_call(call);
nomem_call:
	return NULL;
}

/*
 * clean up a call with flat buffer
 */
void afs_flat_call_destructor(struct afs_call *call)
{
	_enter("");

	kfree(call->request);
	call->request = NULL;
	kfree(call->buffer);
	call->buffer = NULL;
}

/*
 * attach the data from a bunch of pages on an inode to a call
 */
static int afs_send_pages(struct afs_call *call, struct msghdr *msg,
			  struct kvec *iov)
{
	struct page *pages[8];
	unsigned count, n, loop, offset, to;
	pgoff_t first = call->first, last = call->last;
	int ret;

	_enter("");

	offset = call->first_offset;
	call->first_offset = 0;

	do {
		_debug("attach %lx-%lx", first, last);

		count = last - first + 1;
		if (count > ARRAY_SIZE(pages))
			count = ARRAY_SIZE(pages);
		n = find_get_pages_contig(call->mapping, first, count, pages);
		ASSERTCMP(n, ==, count);

		loop = 0;
		do {
			msg->msg_flags = 0;
			to = PAGE_SIZE;
			if (first + loop >= last)
				to = call->last_to;
			else
				msg->msg_flags = MSG_MORE;
			iov->iov_base = kmap(pages[loop]) + offset;
			iov->iov_len = to - offset;
			offset = 0;

			_debug("- range %u-%u%s",
			       offset, to, msg->msg_flags ? " [more]" : "");
			iov_iter_kvec(&msg->msg_iter, WRITE | ITER_KVEC,
				      iov, 1, to - offset);

			/* have to change the state *before* sending the last
			 * packet as RxRPC might give us the reply before it
			 * returns from sending the request */
			if (first + loop >= last)
				call->state = AFS_CALL_AWAIT_REPLY;
			ret = rxrpc_kernel_send_data(call->rxcall, msg,
						     to - offset);
			kunmap(pages[loop]);
			if (ret < 0)
				break;
		} while (++loop < count);
		first += count;

		for (loop = 0; loop < count; loop++)
			put_page(pages[loop]);
		if (ret < 0)
			break;
	} while (first <= last);

	_leave(" = %d", ret);
	return ret;
}

/*
 * initiate a call
 */
int afs_make_call(struct in_addr *addr, struct afs_call *call, gfp_t gfp,
		  const struct afs_wait_mode *wait_mode)
{
	struct sockaddr_rxrpc srx;
	struct rxrpc_call *rxcall;
	struct msghdr msg;
	struct kvec iov[1];
	int ret;
	struct sk_buff *skb;

	_enter("%x,{%d},", addr->s_addr, ntohs(call->port));

	ASSERT(call->type != NULL);
	ASSERT(call->type->name != NULL);

	_debug("____MAKE %p{%s,%x} [%d]____",
	       call, call->type->name, key_serial(call->key),
	       atomic_read(&afs_outstanding_calls));

	call->wait_mode = wait_mode;
	call->async_workfn = afs_process_async_call;
	INIT_WORK(&call->async_work, afs_async_workfn);

	memset(&srx, 0, sizeof(srx));
	srx.srx_family = AF_RXRPC;
	srx.srx_service = call->service_id;
	srx.transport_type = SOCK_DGRAM;
	srx.transport_len = sizeof(srx.transport.sin);
	srx.transport.sin.sin_family = AF_INET;
	srx.transport.sin.sin_port = call->port;
	memcpy(&srx.transport.sin.sin_addr, addr, 4);

	/* create a call */
	rxcall = rxrpc_kernel_begin_call(afs_socket, &srx, call->key,
					 (unsigned long) call, gfp);
	call->key = NULL;
	if (IS_ERR(rxcall)) {
		ret = PTR_ERR(rxcall);
		goto error_kill_call;
	}

	call->rxcall = rxcall;

	/* send the request */
	iov[0].iov_base	= call->request;
	iov[0].iov_len	= call->request_size;

	msg.msg_name		= NULL;
	msg.msg_namelen		= 0;
	iov_iter_kvec(&msg.msg_iter, WRITE | ITER_KVEC, iov, 1,
		      call->request_size);
	msg.msg_control		= NULL;
	msg.msg_controllen	= 0;
	msg.msg_flags		= (call->send_pages ? MSG_MORE : 0);

	/* have to change the state *before* sending the last packet as RxRPC
	 * might give us the reply before it returns from sending the
	 * request */
	if (!call->send_pages)
		call->state = AFS_CALL_AWAIT_REPLY;
	ret = rxrpc_kernel_send_data(rxcall, &msg, call->request_size);
	if (ret < 0)
		goto error_do_abort;

	if (call->send_pages) {
		ret = afs_send_pages(call, &msg, iov);
		if (ret < 0)
			goto error_do_abort;
	}

	/* at this point, an async call may no longer exist as it may have
	 * already completed */
	return wait_mode->wait(call);

error_do_abort:
	rxrpc_kernel_abort_call(rxcall, RX_USER_ABORT);
	while ((skb = skb_dequeue(&call->rx_queue)))
		afs_free_skb(skb);
error_kill_call:
	afs_end_call(call);
	_leave(" = %d", ret);
	return ret;
}

/*
 * handles intercepted messages that were arriving in the socket's Rx queue
 * - called with the socket receive queue lock held to ensure message ordering
 * - called with softirqs disabled
 */
static void afs_rx_interceptor(struct sock *sk, unsigned long user_call_ID,
			       struct sk_buff *skb)
{
	struct afs_call *call = (struct afs_call *) user_call_ID;

	_enter("%p,,%u", call, skb->mark);

	_debug("ICPT %p{%u} [%d]",
	       skb, skb->mark, atomic_read(&afs_outstanding_skbs));

	ASSERTCMP(sk, ==, afs_socket->sk);
	atomic_inc(&afs_outstanding_skbs);

	if (!call) {
		/* its an incoming call for our callback service */
		skb_queue_tail(&afs_incoming_calls, skb);
		queue_work(afs_wq, &afs_collect_incoming_call_work);
	} else {
		/* route the messages directly to the appropriate call */
		skb_queue_tail(&call->rx_queue, skb);
		call->wait_mode->rx_wakeup(call);
	}

	_leave("");
}

/*
 * deliver messages to a call
 */
static void afs_deliver_to_call(struct afs_call *call)
{
	struct sk_buff *skb;
	bool last;
	u32 abort_code;
	int ret;

	_enter("");

	while ((call->state == AFS_CALL_AWAIT_REPLY ||
		call->state == AFS_CALL_AWAIT_OP_ID ||
		call->state == AFS_CALL_AWAIT_REQUEST ||
		call->state == AFS_CALL_AWAIT_ACK) &&
	       (skb = skb_dequeue(&call->rx_queue))) {
		switch (skb->mark) {
		case RXRPC_SKB_MARK_DATA:
			_debug("Rcv DATA");
			last = rxrpc_kernel_is_data_last(skb);
			ret = call->type->deliver(call, skb, last);
			switch (ret) {
			case 0:
				if (last &&
				    call->state == AFS_CALL_AWAIT_REPLY)
					call->state = AFS_CALL_COMPLETE;
				break;
			case -ENOTCONN:
				abort_code = RX_CALL_DEAD;
				goto do_abort;
			case -ENOTSUPP:
				abort_code = RX_INVALID_OPERATION;
				goto do_abort;
			default:
				abort_code = RXGEN_CC_UNMARSHAL;
				if (call->state != AFS_CALL_AWAIT_REPLY)
					abort_code = RXGEN_SS_UNMARSHAL;
			do_abort:
				rxrpc_kernel_abort_call(call->rxcall,
							abort_code);
				call->error = ret;
				call->state = AFS_CALL_ERROR;
				break;
			}
			afs_data_delivered(skb);
			skb = NULL;
			continue;
		case RXRPC_SKB_MARK_FINAL_ACK:
			_debug("Rcv ACK");
			call->state = AFS_CALL_COMPLETE;
			break;
		case RXRPC_SKB_MARK_BUSY:
			_debug("Rcv BUSY");
			call->error = -EBUSY;
			call->state = AFS_CALL_BUSY;
			break;
		case RXRPC_SKB_MARK_REMOTE_ABORT:
			abort_code = rxrpc_kernel_get_abort_code(skb);
			call->error = call->type->abort_to_error(abort_code);
			call->state = AFS_CALL_ABORTED;
			_debug("Rcv ABORT %u -> %d", abort_code, call->error);
			break;
		case RXRPC_SKB_MARK_NET_ERROR:
			call->error = -rxrpc_kernel_get_error_number(skb);
			call->state = AFS_CALL_ERROR;
			_debug("Rcv NET ERROR %d", call->error);
			break;
		case RXRPC_SKB_MARK_LOCAL_ERROR:
			call->error = -rxrpc_kernel_get_error_number(skb);
			call->state = AFS_CALL_ERROR;
			_debug("Rcv LOCAL ERROR %d", call->error);
			break;
		default:
			BUG();
			break;
		}

		afs_free_skb(skb);
	}

	/* make sure the queue is empty if the call is done with (we might have
	 * aborted the call early because of an unmarshalling error) */
	if (call->state >= AFS_CALL_COMPLETE) {
		while ((skb = skb_dequeue(&call->rx_queue)))
			afs_free_skb(skb);
		if (call->incoming)
			afs_end_call(call);
	}

	_leave("");
}

/*
 * wait synchronously for a call to complete
 */
static int afs_wait_for_call_to_complete(struct afs_call *call)
{
	struct sk_buff *skb;
	int ret;

	DECLARE_WAITQUEUE(myself, current);

	_enter("");

	add_wait_queue(&call->waitq, &myself);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);

		/* deliver any messages that are in the queue */
		if (!skb_queue_empty(&call->rx_queue)) {
			__set_current_state(TASK_RUNNING);
			afs_deliver_to_call(call);
			continue;
		}

		ret = call->error;
		if (call->state >= AFS_CALL_COMPLETE)
			break;
		ret = -EINTR;
		if (signal_pending(current))
			break;
		schedule();
	}

	remove_wait_queue(&call->waitq, &myself);
	__set_current_state(TASK_RUNNING);

	/* kill the call */
	if (call->state < AFS_CALL_COMPLETE) {
		_debug("call incomplete");
		rxrpc_kernel_abort_call(call->rxcall, RX_CALL_DEAD);
		while ((skb = skb_dequeue(&call->rx_queue)))
			afs_free_skb(skb);
	}

	_debug("call complete");
	afs_end_call(call);
	_leave(" = %d", ret);
	return ret;
}

/*
 * wake up a waiting call
 */
static void afs_wake_up_call_waiter(struct afs_call *call)
{
	wake_up(&call->waitq);
}

/*
 * wake up an asynchronous call
 */
static void afs_wake_up_async_call(struct afs_call *call)
{
	_enter("");
	queue_work(afs_async_calls, &call->async_work);
}

/*
 * put a call into asynchronous mode
 * - mustn't touch the call descriptor as the call my have completed by the
 *   time we get here
 */
static int afs_dont_wait_for_call_to_complete(struct afs_call *call)
{
	_enter("");
	return -EINPROGRESS;
}

/*
 * delete an asynchronous call
 */
static void afs_delete_async_call(struct afs_call *call)
{
	_enter("");

	afs_free_call(call);

	_leave("");
}

/*
 * perform processing on an asynchronous call
 * - on a multiple-thread workqueue this work item may try to run on several
 *   CPUs at the same time
 */
static void afs_process_async_call(struct afs_call *call)
{
	_enter("");

	if (!skb_queue_empty(&call->rx_queue))
		afs_deliver_to_call(call);

	if (call->state >= AFS_CALL_COMPLETE && call->wait_mode) {
		if (call->wait_mode->async_complete)
			call->wait_mode->async_complete(call->reply,
							call->error);
		call->reply = NULL;

		/* kill the call */
		afs_end_call_nofree(call);

		/* we can't just delete the call because the work item may be
		 * queued */
		call->async_workfn = afs_delete_async_call;
		queue_work(afs_async_calls, &call->async_work);
	}

	_leave("");
}

/*
 * empty a socket buffer into a flat reply buffer
 */
void afs_transfer_reply(struct afs_call *call, struct sk_buff *skb)
{
	size_t len = skb->len;

	if (skb_copy_bits(skb, 0, call->buffer + call->reply_size, len) < 0)
		BUG();
	call->reply_size += len;
}

/*
 * accept the backlog of incoming calls
 */
static void afs_collect_incoming_call(struct work_struct *work)
{
	struct rxrpc_call *rxcall;
	struct afs_call *call = NULL;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&afs_incoming_calls))) {
		_debug("new call");

		/* don't need the notification */
		afs_free_skb(skb);

		if (!call) {
			call = kzalloc(sizeof(struct afs_call), GFP_KERNEL);
			if (!call) {
				rxrpc_kernel_reject_call(afs_socket);
				return;
			}

			call->async_workfn = afs_process_async_call;
			INIT_WORK(&call->async_work, afs_async_workfn);
			call->wait_mode = &afs_async_incoming_call;
			call->type = &afs_RXCMxxxx;
			init_waitqueue_head(&call->waitq);
			skb_queue_head_init(&call->rx_queue);
			call->state = AFS_CALL_AWAIT_OP_ID;

			_debug("CALL %p{%s} [%d]",
			       call, call->type->name,
			       atomic_read(&afs_outstanding_calls));
			atomic_inc(&afs_outstanding_calls);
		}

		rxcall = rxrpc_kernel_accept_call(afs_socket,
						  (unsigned long) call);
		if (!IS_ERR(rxcall)) {
			call->rxcall = rxcall;
			call = NULL;
		}
	}

	if (call)
		afs_free_call(call);
}

/*
 * grab the operation ID from an incoming cache manager call
 */
static int afs_deliver_cm_op_id(struct afs_call *call, struct sk_buff *skb,
				bool last)
{
	size_t len = skb->len;
	void *oibuf = (void *) &call->operation_ID;

	_enter("{%u},{%zu},%d", call->offset, len, last);

	ASSERTCMP(call->offset, <, 4);

	/* the operation ID forms the first four bytes of the request data */
	len = min_t(size_t, len, 4 - call->offset);
	if (skb_copy_bits(skb, 0, oibuf + call->offset, len) < 0)
		BUG();
	if (!pskb_pull(skb, len))
		BUG();
	call->offset += len;

	if (call->offset < 4) {
		if (last) {
			_leave(" = -EBADMSG [op ID short]");
			return -EBADMSG;
		}
		_leave(" = 0 [incomplete]");
		return 0;
	}

	call->state = AFS_CALL_AWAIT_REQUEST;

	/* ask the cache manager to route the call (it'll change the call type
	 * if successful) */
	if (!afs_cm_incoming_call(call))
		return -ENOTSUPP;

	/* pass responsibility for the remainer of this message off to the
	 * cache manager op */
	return call->type->deliver(call, skb, last);
}

/*
 * send an empty reply
 */
void afs_send_empty_reply(struct afs_call *call)
{
	struct msghdr msg;
	struct kvec iov[1];

	_enter("");

	iov[0].iov_base		= NULL;
	iov[0].iov_len		= 0;
	msg.msg_name		= NULL;
	msg.msg_namelen		= 0;
	iov_iter_kvec(&msg.msg_iter, WRITE | ITER_KVEC, iov, 0, 0);	/* WTF? */
	msg.msg_control		= NULL;
	msg.msg_controllen	= 0;
	msg.msg_flags		= 0;

	call->state = AFS_CALL_AWAIT_ACK;
	switch (rxrpc_kernel_send_data(call->rxcall, &msg, 0)) {
	case 0:
		_leave(" [replied]");
		return;

	case -ENOMEM:
		_debug("oom");
		rxrpc_kernel_abort_call(call->rxcall, RX_USER_ABORT);
	default:
		afs_end_call(call);
		_leave(" [error]");
		return;
	}
}

/*
 * send a simple reply
 */
void afs_send_simple_reply(struct afs_call *call, const void *buf, size_t len)
{
	struct msghdr msg;
	struct kvec iov[1];
	int n;

	_enter("");

	iov[0].iov_base		= (void *) buf;
	iov[0].iov_len		= len;
	msg.msg_name		= NULL;
	msg.msg_namelen		= 0;
	iov_iter_kvec(&msg.msg_iter, WRITE | ITER_KVEC, iov, 1, len);
	msg.msg_control		= NULL;
	msg.msg_controllen	= 0;
	msg.msg_flags		= 0;

	call->state = AFS_CALL_AWAIT_ACK;
	n = rxrpc_kernel_send_data(call->rxcall, &msg, len);
	if (n >= 0) {
		/* Success */
		_leave(" [replied]");
		return;
	}

	if (n == -ENOMEM) {
		_debug("oom");
		rxrpc_kernel_abort_call(call->rxcall, RX_USER_ABORT);
	}
	afs_end_call(call);
	_leave(" [error]");
}

/*
 * extract a piece of data from the received data socket buffers
 */
int afs_extract_data(struct afs_call *call, struct sk_buff *skb,
		     bool last, void *buf, size_t count)
{
	size_t len = skb->len;

	_enter("{%u},{%zu},%d,,%zu", call->offset, len, last, count);

	ASSERTCMP(call->offset, <, count);

	len = min_t(size_t, len, count - call->offset);
	if (skb_copy_bits(skb, 0, buf + call->offset, len) < 0 ||
	    !pskb_pull(skb, len))
		BUG();
	call->offset += len;

	if (call->offset < count) {
		if (last) {
			_leave(" = -EBADMSG [%d < %zu]", call->offset, count);
			return -EBADMSG;
		}
		_leave(" = -EAGAIN");
		return -EAGAIN;
	}
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/rxrpc.c */
/************************************************************/
/* AFS security handling
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/init.h>
// #include <linux/slab.h>
// #include <linux/fs.h>
// #include <linux/ctype.h>
// #include <linux/sched.h>
// #include <keys/rxrpc-type.h>
// #include "internal.h"

/*
 * get a key
 */
struct key *afs_request_key(struct afs_cell *cell)
{
	struct key *key;

	_enter("{%x}", key_serial(cell->anonymous_key));

	_debug("key %s", cell->anonymous_key->description);
	key = request_key(&key_type_rxrpc, cell->anonymous_key->description,
			  NULL);
	if (IS_ERR(key)) {
		if (PTR_ERR(key) != -ENOKEY) {
			_leave(" = %ld", PTR_ERR(key));
			return key;
		}

		/* act as anonymous user */
		_leave(" = {%x} [anon]", key_serial(cell->anonymous_key));
		return key_get(cell->anonymous_key);
	} else {
		/* act as authorised user */
		_leave(" = {%x} [auth]", key_serial(key));
		return key;
	}
}

/*
 * dispose of a permits list
 */
void afs_zap_permits(struct rcu_head *rcu)
{
	struct afs_permits *permits =
		container_of(rcu, struct afs_permits, rcu);
	int loop;

	_enter("{%d}", permits->count);

	for (loop = permits->count - 1; loop >= 0; loop--)
		key_put(permits->permits[loop].key);
	kfree(permits);
}

/*
 * dispose of a permits list in which all the key pointers have been copied
 */
static void afs_dispose_of_permits(struct rcu_head *rcu)
{
	struct afs_permits *permits =
		container_of(rcu, struct afs_permits, rcu);

	_enter("{%d}", permits->count);

	kfree(permits);
}

/*
 * get the authorising vnode - this is the specified inode itself if it's a
 * directory or it's the parent directory if the specified inode is a file or
 * symlink
 * - the caller must release the ref on the inode
 */
static struct afs_vnode *afs_get_auth_inode(struct afs_vnode *vnode,
					    struct key *key)
{
	struct afs_vnode *auth_vnode;
	struct inode *auth_inode;

	_enter("");

	if (S_ISDIR(vnode->vfs_inode.i_mode)) {
		auth_inode = igrab(&vnode->vfs_inode);
		ASSERT(auth_inode != NULL);
	} else {
		auth_inode = afs_iget(vnode->vfs_inode.i_sb, key,
				      &vnode->status.parent, NULL, NULL);
		if (IS_ERR(auth_inode))
			return ERR_CAST(auth_inode);
	}

	auth_vnode = AFS_FS_I(auth_inode);
	_leave(" = {%x}", auth_vnode->fid.vnode);
	return auth_vnode;
}

/*
 * clear the permit cache on a directory vnode
 */
void afs_clear_permits(struct afs_vnode *vnode)
{
	struct afs_permits *permits;

	_enter("{%x:%u}", vnode->fid.vid, vnode->fid.vnode);

	mutex_lock(&vnode->permits_lock);
	permits = vnode->permits;
	rcu_assign_pointer(vnode->permits, NULL);
	mutex_unlock(&vnode->permits_lock);

	if (permits)
		call_rcu(&permits->rcu, afs_zap_permits);
	_leave("");
}

/*
 * add the result obtained for a vnode to its or its parent directory's cache
 * for the key used to access it
 */
void afs_cache_permit(struct afs_vnode *vnode, struct key *key, long acl_order)
{
	struct afs_permits *permits, *xpermits;
	struct afs_permit *permit;
	struct afs_vnode *auth_vnode;
	int count, loop;

	_enter("{%x:%u},%x,%lx",
	       vnode->fid.vid, vnode->fid.vnode, key_serial(key), acl_order);

	auth_vnode = afs_get_auth_inode(vnode, key);
	if (IS_ERR(auth_vnode)) {
		_leave(" [get error %ld]", PTR_ERR(auth_vnode));
		return;
	}

	mutex_lock(&auth_vnode->permits_lock);

	/* guard against a rename being detected whilst we waited for the
	 * lock */
	if (memcmp(&auth_vnode->fid, &vnode->status.parent,
		   sizeof(struct afs_fid)) != 0) {
		_debug("renamed");
		goto out_unlock;
	}

	/* have to be careful as the directory's callback may be broken between
	 * us receiving the status we're trying to cache and us getting the
	 * lock to update the cache for the status */
	if (auth_vnode->acl_order - acl_order > 0) {
		_debug("ACL changed?");
		goto out_unlock;
	}

	/* always update the anonymous mask */
	_debug("anon access %x", vnode->status.anon_access);
	auth_vnode->status.anon_access = vnode->status.anon_access;
	if (key == vnode->volume->cell->anonymous_key)
		goto out_unlock;

	xpermits = auth_vnode->permits;
	count = 0;
	if (xpermits) {
		/* see if the permit is already in the list
		 * - if it is then we just amend the list
		 */
		count = xpermits->count;
		permit = xpermits->permits;
		for (loop = count; loop > 0; loop--) {
			if (permit->key == key) {
				permit->access_mask =
					vnode->status.caller_access;
				goto out_unlock;
			}
			permit++;
		}
	}

	permits = kmalloc(sizeof(*permits) + sizeof(*permit) * (count + 1),
			  GFP_NOFS);
	if (!permits)
		goto out_unlock;

	if (xpermits)
		memcpy(permits->permits, xpermits->permits,
			count * sizeof(struct afs_permit));

	_debug("key %x access %x",
	       key_serial(key), vnode->status.caller_access);
	permits->permits[count].access_mask = vnode->status.caller_access;
	permits->permits[count].key = key_get(key);
	permits->count = count + 1;

	rcu_assign_pointer(auth_vnode->permits, permits);
	if (xpermits)
		call_rcu(&xpermits->rcu, afs_dispose_of_permits);

out_unlock:
	mutex_unlock(&auth_vnode->permits_lock);
	iput(&auth_vnode->vfs_inode);
	_leave("");
}

/*
 * check with the fileserver to see if the directory or parent directory is
 * permitted to be accessed with this authorisation, and if so, what access it
 * is granted
 */
static int afs_check_permit(struct afs_vnode *vnode, struct key *key,
			    afs_access_t *_access)
{
	struct afs_permits *permits;
	struct afs_permit *permit;
	struct afs_vnode *auth_vnode;
	bool valid;
	int loop, ret;

	_enter("{%x:%u},%x",
	       vnode->fid.vid, vnode->fid.vnode, key_serial(key));

	auth_vnode = afs_get_auth_inode(vnode, key);
	if (IS_ERR(auth_vnode)) {
		*_access = 0;
		_leave(" = %ld", PTR_ERR(auth_vnode));
		return PTR_ERR(auth_vnode);
	}

	ASSERT(S_ISDIR(auth_vnode->vfs_inode.i_mode));

	/* check the permits to see if we've got one yet */
	if (key == auth_vnode->volume->cell->anonymous_key) {
		_debug("anon");
		*_access = auth_vnode->status.anon_access;
		valid = true;
	} else {
		valid = false;
		rcu_read_lock();
		permits = rcu_dereference(auth_vnode->permits);
		if (permits) {
			permit = permits->permits;
			for (loop = permits->count; loop > 0; loop--) {
				if (permit->key == key) {
					_debug("found in cache");
					*_access = permit->access_mask;
					valid = true;
					break;
				}
				permit++;
			}
		}
		rcu_read_unlock();
	}

	if (!valid) {
		/* check the status on the file we're actually interested in
		 * (the post-processing will cache the result on auth_vnode) */
		_debug("no valid permit");

		set_bit(AFS_VNODE_CB_BROKEN, &vnode->flags);
		ret = afs_vnode_fetch_status(vnode, auth_vnode, key);
		if (ret < 0) {
			iput(&auth_vnode->vfs_inode);
			*_access = 0;
			_leave(" = %d", ret);
			return ret;
		}
		*_access = vnode->status.caller_access;
	}

	iput(&auth_vnode->vfs_inode);
	_leave(" = 0 [access %x]", *_access);
	return 0;
}

/*
 * check the permissions on an AFS file
 * - AFS ACLs are attached to directories only, and a file is controlled by its
 *   parent directory's ACL
 */
int afs_permission(struct inode *inode, int mask)
{
	struct afs_vnode *vnode = AFS_FS_I(inode);
	afs_access_t uninitialized_var(access);
	struct key *key;
	int ret;

	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	_enter("{{%x:%u},%lx},%x,",
	       vnode->fid.vid, vnode->fid.vnode, vnode->flags, mask);

	key = afs_request_key(vnode->volume->cell);
	if (IS_ERR(key)) {
		_leave(" = %ld [key]", PTR_ERR(key));
		return PTR_ERR(key);
	}

	/* if the promise has expired, we need to check the server again */
	if (!vnode->cb_promised) {
		_debug("not promised");
		ret = afs_vnode_fetch_status(vnode, NULL, key);
		if (ret < 0)
			goto error;
		_debug("new promise [fl=%lx]", vnode->flags);
	}

	/* check the permits to see if we've got one yet */
	ret = afs_check_permit(vnode, key, &access);
	if (ret < 0)
		goto error;

	/* interpret the access mask */
	_debug("REQ %x ACC %x on %s",
	       mask, access, S_ISDIR(inode->i_mode) ? "dir" : "file");

	if (S_ISDIR(inode->i_mode)) {
		if (mask & MAY_EXEC) {
			if (!(access & AFS_ACE_LOOKUP))
				goto permission_denied;
		} else if (mask & MAY_READ) {
			if (!(access & AFS_ACE_READ))
				goto permission_denied;
		} else if (mask & MAY_WRITE) {
			if (!(access & (AFS_ACE_DELETE | /* rmdir, unlink, rename from */
					AFS_ACE_INSERT | /* create, mkdir, symlink, rename to */
					AFS_ACE_WRITE))) /* chmod */
				goto permission_denied;
		} else {
			BUG();
		}
	} else {
		if (!(access & AFS_ACE_LOOKUP))
			goto permission_denied;
		if (mask & (MAY_EXEC | MAY_READ)) {
			if (!(access & AFS_ACE_READ))
				goto permission_denied;
		} else if (mask & MAY_WRITE) {
			if (!(access & AFS_ACE_WRITE))
				goto permission_denied;
		}
	}

	key_put(key);
	ret = generic_permission(inode, mask);
	_leave(" = %d", ret);
	return ret;

permission_denied:
	ret = -EACCES;
error:
	key_put(key);
	_leave(" = %d", ret);
	return ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/security.c */
/************************************************************/
/* AFS server record management
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include "internal.h"

static unsigned afs_server_timeout = 10;	/* server timeout in seconds */

static void afs_reap_server(struct work_struct *);

/* tree of all the servers, indexed by IP address */
static struct rb_root afs_servers = RB_ROOT;
static DEFINE_RWLOCK(afs_servers_lock);

/* LRU list of all the servers not currently in use */
static LIST_HEAD(afs_server_graveyard);
static DEFINE_SPINLOCK(afs_server_graveyard_lock);
static DECLARE_DELAYED_WORK(afs_server_reaper, afs_reap_server);

/*
 * install a server record in the master tree
 */
static int afs_install_server(struct afs_server *server)
{
	struct afs_server *xserver;
	struct rb_node **pp, *p;
	int ret;

	_enter("%p", server);

	write_lock(&afs_servers_lock);

	ret = -EEXIST;
	pp = &afs_servers.rb_node;
	p = NULL;
	while (*pp) {
		p = *pp;
		_debug("- consider %p", p);
		xserver = rb_entry(p, struct afs_server, master_rb);
		if (server->addr.s_addr < xserver->addr.s_addr)
			pp = &(*pp)->rb_left;
		else if (server->addr.s_addr > xserver->addr.s_addr)
			pp = &(*pp)->rb_right;
		else
			goto error;
	}

	rb_link_node(&server->master_rb, p, pp);
	rb_insert_color(&server->master_rb, &afs_servers);
	ret = 0;

error:
	write_unlock(&afs_servers_lock);
	return ret;
}

/*
 * allocate a new server record
 */
static struct afs_server *afs_alloc_server(struct afs_cell *cell,
					   const struct in_addr *addr)
{
	struct afs_server *server;

	_enter("");

	server = kzalloc(sizeof(struct afs_server), GFP_KERNEL);
	if (server) {
		atomic_set(&server->usage, 1);
		server->cell = cell;

		INIT_LIST_HEAD(&server->link);
		INIT_LIST_HEAD(&server->grave);
		init_rwsem(&server->sem);
		spin_lock_init(&server->fs_lock);
		server->fs_vnodes = RB_ROOT;
		server->cb_promises = RB_ROOT;
		spin_lock_init(&server->cb_lock);
		init_waitqueue_head(&server->cb_break_waitq);
		INIT_DELAYED_WORK(&server->cb_break_work,
				  afs_dispatch_give_up_callbacks);

		memcpy(&server->addr, addr, sizeof(struct in_addr));
		server->addr.s_addr = addr->s_addr;
		_leave(" = %p{%d}", server, atomic_read(&server->usage));
	} else {
		_leave(" = NULL [nomem]");
	}
	return server;
}

/*
 * get an FS-server record for a cell
 */
struct afs_server *afs_lookup_server(struct afs_cell *cell,
				     const struct in_addr *addr)
{
	struct afs_server *server, *candidate;

	_enter("%p,%pI4", cell, &addr->s_addr);

	/* quick scan of the list to see if we already have the server */
	read_lock(&cell->servers_lock);

	list_for_each_entry(server, &cell->servers, link) {
		if (server->addr.s_addr == addr->s_addr)
			goto found_server_quickly;
	}
	read_unlock(&cell->servers_lock);

	candidate = afs_alloc_server(cell, addr);
	if (!candidate) {
		_leave(" = -ENOMEM");
		return ERR_PTR(-ENOMEM);
	}

	write_lock(&cell->servers_lock);

	/* check the cell's server list again */
	list_for_each_entry(server, &cell->servers, link) {
		if (server->addr.s_addr == addr->s_addr)
			goto found_server;
	}

	_debug("new");
	server = candidate;
	if (afs_install_server(server) < 0)
		goto server_in_two_cells;

	afs_get_cell(cell);
	list_add_tail(&server->link, &cell->servers);

	write_unlock(&cell->servers_lock);
	_leave(" = %p{%d}", server, atomic_read(&server->usage));
	return server;

	/* found a matching server quickly */
found_server_quickly:
	_debug("found quickly");
	afs_get_server(server);
	read_unlock(&cell->servers_lock);
no_longer_unused:
	if (!list_empty(&server->grave)) {
		spin_lock(&afs_server_graveyard_lock);
		list_del_init(&server->grave);
		spin_unlock(&afs_server_graveyard_lock);
	}
	_leave(" = %p{%d}", server, atomic_read(&server->usage));
	return server;

	/* found a matching server on the second pass */
found_server:
	_debug("found");
	afs_get_server(server);
	write_unlock(&cell->servers_lock);
	kfree(candidate);
	goto no_longer_unused;

	/* found a server that seems to be in two cells */
server_in_two_cells:
	write_unlock(&cell->servers_lock);
	kfree(candidate);
	printk(KERN_NOTICE "kAFS: Server %pI4 appears to be in two cells\n",
	       addr);
	_leave(" = -EEXIST");
	return ERR_PTR(-EEXIST);
}

/*
 * look up a server by its IP address
 */
struct afs_server *afs_find_server(const struct in_addr *_addr)
{
	struct afs_server *server = NULL;
	struct rb_node *p;
	struct in_addr addr = *_addr;

	_enter("%pI4", &addr.s_addr);

	read_lock(&afs_servers_lock);

	p = afs_servers.rb_node;
	while (p) {
		server = rb_entry(p, struct afs_server, master_rb);

		_debug("- consider %p", p);

		if (addr.s_addr < server->addr.s_addr) {
			p = p->rb_left;
		} else if (addr.s_addr > server->addr.s_addr) {
			p = p->rb_right;
		} else {
			afs_get_server(server);
			goto found;
		}
	}

	server = NULL;
found:
	read_unlock(&afs_servers_lock);
	ASSERTIFCMP(server, server->addr.s_addr, ==, addr.s_addr);
	_leave(" = %p", server);
	return server;
}

/*
 * destroy a server record
 * - removes from the cell list
 */
void afs_put_server(struct afs_server *server)
{
	if (!server)
		return;

	_enter("%p{%d}", server, atomic_read(&server->usage));

	_debug("PUT SERVER %d", atomic_read(&server->usage));

	ASSERTCMP(atomic_read(&server->usage), >, 0);

	if (likely(!atomic_dec_and_test(&server->usage))) {
		_leave("");
		return;
	}

	afs_flush_callback_breaks(server);

	spin_lock(&afs_server_graveyard_lock);
	if (atomic_read(&server->usage) == 0) {
		list_move_tail(&server->grave, &afs_server_graveyard);
		server->time_of_death = get_seconds();
		queue_delayed_work(afs_wq, &afs_server_reaper,
				   afs_server_timeout * HZ);
	}
	spin_unlock(&afs_server_graveyard_lock);
	_leave(" [dead]");
}

/*
 * destroy a dead server
 */
static void afs_destroy_server(struct afs_server *server)
{
	_enter("%p", server);

	ASSERTIF(server->cb_break_head != server->cb_break_tail,
		 delayed_work_pending(&server->cb_break_work));

	ASSERTCMP(server->fs_vnodes.rb_node, ==, NULL);
	ASSERTCMP(server->cb_promises.rb_node, ==, NULL);
	ASSERTCMP(server->cb_break_head, ==, server->cb_break_tail);
	ASSERTCMP(atomic_read(&server->cb_break_n), ==, 0);

	afs_put_cell(server->cell);
	kfree(server);
}

/*
 * reap dead server records
 */
static void afs_reap_server(struct work_struct *work)
{
	LIST_HEAD(corpses);
	struct afs_server *server;
	unsigned long delay, expiry;
	time_t now;

	now = get_seconds();
	spin_lock(&afs_server_graveyard_lock);

	while (!list_empty(&afs_server_graveyard)) {
		server = list_entry(afs_server_graveyard.next,
				    struct afs_server, grave);

		/* the queue is ordered most dead first */
		expiry = server->time_of_death + afs_server_timeout;
		if (expiry > now) {
			delay = (expiry - now) * HZ;
			mod_delayed_work(afs_wq, &afs_server_reaper, delay);
			break;
		}

		write_lock(&server->cell->servers_lock);
		write_lock(&afs_servers_lock);
		if (atomic_read(&server->usage) > 0) {
			list_del_init(&server->grave);
		} else {
			list_move_tail(&server->grave, &corpses);
			list_del_init(&server->link);
			rb_erase(&server->master_rb, &afs_servers);
		}
		write_unlock(&afs_servers_lock);
		write_unlock(&server->cell->servers_lock);
	}

	spin_unlock(&afs_server_graveyard_lock);

	/* now reap the corpses we've extracted */
	while (!list_empty(&corpses)) {
		server = list_entry(corpses.next, struct afs_server, grave);
		list_del(&server->grave);
		afs_destroy_server(server);
	}
}

/*
 * discard all the server records for rmmod
 */
void __exit afs_purge_servers(void)
{
	afs_server_timeout = 0;
	mod_delayed_work(afs_wq, &afs_server_reaper, 0);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/server.c */
/************************************************************/
/* AFS superblock handling
 *
 * Copyright (c) 2002, 2007 Red Hat, Inc. All rights reserved.
 *
 * This software may be freely redistributed under the terms of the
 * GNU General Public License.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors: David Howells <dhowells@redhat.com>
 *          David Woodhouse <dwmw2@infradead.org>
 *
 */

// #include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/mount.h>
// #include <linux/init.h>
// #include <linux/slab.h>
// #include <linux/fs.h>
// #include <linux/pagemap.h>
#include <linux/parser.h>
#include <linux/statfs.h>
// #include <linux/sched.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
// #include "internal.h"
#include "../../inc/__fss.h"

#define AFS_FS_MAGIC 0x6B414653 /* 'kAFS' */

static void afs_i_init_once(void *foo);
static struct dentry *afs_mount(struct file_system_type *fs_type,
		      int flags, const char *dev_name, void *data);
static void afs_kill_super(struct super_block *sb);
static struct inode *afs_alloc_inode(struct super_block *sb);
static void afs_destroy_inode(struct inode *inode);
static int afs_statfs(struct dentry *dentry, struct kstatfs *buf);

struct file_system_type afs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "afs",
	.mount		= afs_mount,
	.kill_sb	= afs_kill_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS("afs");

static const struct super_operations afs_super_ops = {
	.statfs		= afs_statfs,
	.alloc_inode	= afs_alloc_inode,
	.drop_inode	= afs_drop_inode,
	.destroy_inode	= afs_destroy_inode,
	.evict_inode	= afs_evict_inode,
	.show_options	= generic_show_options,
};

static struct kmem_cache *afs_inode_cachep;
static atomic_t afs_count_active_inodes;

enum {
	afs_no_opt,
	afs_opt_cell,
	afs_opt_rwpath,
	afs_opt_vol,
	afs_opt_autocell,
};

static const match_table_t afs_options_list = {
	{ afs_opt_cell,		"cell=%s"	},
	{ afs_opt_rwpath,	"rwpath"	},
	{ afs_opt_vol,		"vol=%s"	},
	{ afs_opt_autocell,	"autocell"	},
	{ afs_no_opt,		NULL		},
};

/*
 * initialise the filesystem
 */
int __init afs_fs_init(void)
{
	int ret;

	_enter("");

	/* create ourselves an inode cache */
	atomic_set(&afs_count_active_inodes, 0);

	ret = -ENOMEM;
	afs_inode_cachep = kmem_cache_create("afs_inode_cache",
					     sizeof(struct afs_vnode),
					     0,
					     SLAB_HWCACHE_ALIGN,
					     afs_i_init_once);
	if (!afs_inode_cachep) {
		printk(KERN_NOTICE "kAFS: Failed to allocate inode cache\n");
		return ret;
	}

	/* now export our filesystem to lesser mortals */
	ret = register_filesystem(&afs_fs_type);
	if (ret < 0) {
		kmem_cache_destroy(afs_inode_cachep);
		_leave(" = %d", ret);
		return ret;
	}

	_leave(" = 0");
	return 0;
}

/*
 * clean up the filesystem
 */
void __exit afs_fs_exit(void)
{
	_enter("");

	afs_mntpt_kill_timer();
	unregister_filesystem(&afs_fs_type);

	if (atomic_read(&afs_count_active_inodes) != 0) {
		printk("kAFS: %d active inode objects still present\n",
		       atomic_read(&afs_count_active_inodes));
		BUG();
	}

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(afs_inode_cachep);
	_leave("");
}

/*
 * parse the mount options
 * - this function has been shamelessly adapted from the ext3 fs which
 *   shamelessly adapted it from the msdos fs
 */
static int afs_parse_options(struct afs_mount_params *params,
			     char *options, const char **devname)
{
	struct afs_cell *cell;
	substring_t args[MAX_OPT_ARGS];
	char *p;
	int token;

	_enter("%s", options);

	options[PAGE_SIZE - 1] = 0;

	while ((p = strsep(&options, ","))) {
		if (!*p)
			continue;

		token = match_token(p, afs_options_list, args);
		switch (token) {
		case afs_opt_cell:
			cell = afs_cell_lookup(args[0].from,
					       args[0].to - args[0].from,
					       false);
			if (IS_ERR(cell))
				return PTR_ERR(cell);
			afs_put_cell(params->cell);
			params->cell = cell;
			break;

		case afs_opt_rwpath:
			params->rwpath = 1;
			break;

		case afs_opt_vol:
			*devname = args[0].from;
			break;

		case afs_opt_autocell:
			params->autocell = 1;
			break;

		default:
			printk(KERN_ERR "kAFS:"
			       " Unknown or invalid mount option: '%s'\n", p);
			return -EINVAL;
		}
	}

	_leave(" = 0");
	return 0;
}

/*
 * parse a device name to get cell name, volume name, volume type and R/W
 * selector
 * - this can be one of the following:
 *	"%[cell:]volume[.]"		R/W volume
 *	"#[cell:]volume[.]"		R/O or R/W volume (rwpath=0),
 *					 or R/W (rwpath=1) volume
 *	"%[cell:]volume.readonly"	R/O volume
 *	"#[cell:]volume.readonly"	R/O volume
 *	"%[cell:]volume.backup"		Backup volume
 *	"#[cell:]volume.backup"		Backup volume
 */
static int afs_parse_device_name(struct afs_mount_params *params,
				 const char *name)
{
	struct afs_cell *cell;
	const char *cellname, *suffix;
	int cellnamesz;

	_enter(",%s", name);

	if (!name) {
		printk(KERN_ERR "kAFS: no volume name specified\n");
		return -EINVAL;
	}

	if ((name[0] != '%' && name[0] != '#') || !name[1]) {
		printk(KERN_ERR "kAFS: unparsable volume name\n");
		return -EINVAL;
	}

	/* determine the type of volume we're looking for */
	params->type = AFSVL_ROVOL;
	params->force = false;
	if (params->rwpath || name[0] == '%') {
		params->type = AFSVL_RWVOL;
		params->force = true;
	}
	name++;

	/* split the cell name out if there is one */
	params->volname = strchr(name, ':');
	if (params->volname) {
		cellname = name;
		cellnamesz = params->volname - name;
		params->volname++;
	} else {
		params->volname = name;
		cellname = NULL;
		cellnamesz = 0;
	}

	/* the volume type is further affected by a possible suffix */
	suffix = strrchr(params->volname, '.');
	if (suffix) {
		if (strcmp(suffix, ".readonly") == 0) {
			params->type = AFSVL_ROVOL;
			params->force = true;
		} else if (strcmp(suffix, ".backup") == 0) {
			params->type = AFSVL_BACKVOL;
			params->force = true;
		} else if (suffix[1] == 0) {
		} else {
			suffix = NULL;
		}
	}

	params->volnamesz = suffix ?
		suffix - params->volname : strlen(params->volname);

	_debug("cell %*.*s [%p]",
	       cellnamesz, cellnamesz, cellname ?: "", params->cell);

	/* lookup the cell record */
	if (cellname || !params->cell) {
		cell = afs_cell_lookup(cellname, cellnamesz, true);
		if (IS_ERR(cell)) {
			printk(KERN_ERR "kAFS: unable to lookup cell '%*.*s'\n",
			       cellnamesz, cellnamesz, cellname ?: "");
			return PTR_ERR(cell);
		}
		afs_put_cell(params->cell);
		params->cell = cell;
	}

	_debug("CELL:%s [%p] VOLUME:%*.*s SUFFIX:%s TYPE:%d%s",
	       params->cell->name, params->cell,
	       params->volnamesz, params->volnamesz, params->volname,
	       suffix ?: "-", params->type, params->force ? " FORCE" : "");

	return 0;
}

/*
 * check a superblock to see if it's the one we're looking for
 */
static int afs_test_super(struct super_block *sb, void *data)
{
	struct afs_super_info *as1 = data;
	struct afs_super_info *as = sb->s_fs_info;

	return as->volume == as1->volume;
}

static int afs_set_super(struct super_block *sb, void *data)
{
	sb->s_fs_info = data;
	return set_anon_super(sb, NULL);
}

/*
 * fill in the superblock
 */
static int afs_fill_super(struct super_block *sb,
			  struct afs_mount_params *params)
{
	struct afs_super_info *as = sb->s_fs_info;
	struct afs_fid fid;
	struct inode *inode = NULL;
	int ret;

	_enter("");

	/* fill in the superblock */
	sb->s_blocksize		= PAGE_CACHE_SIZE;
	sb->s_blocksize_bits	= PAGE_CACHE_SHIFT;
	sb->s_magic		= AFS_FS_MAGIC;
	sb->s_op		= &afs_super_ops;
	sb->s_bdi		= &as->volume->bdi;
	strlcpy(sb->s_id, as->volume->vlocation->vldb.name, sizeof(sb->s_id));

	/* allocate the root inode and dentry */
	fid.vid		= as->volume->vid;
	fid.vnode	= 1;
	fid.unique	= 1;
	inode = afs_iget(sb, params->key, &fid, NULL, NULL);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (params->autocell)
		set_bit(AFS_VNODE_AUTOCELL, &AFS_FS_I(inode)->flags);

	ret = -ENOMEM;
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		goto error;

	sb->s_d_op = &afs_fs_dentry_operations;

	_leave(" = 0");
	return 0;

error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * get an AFS superblock
 */
static struct dentry *afs_mount(struct file_system_type *fs_type,
		      int flags, const char *dev_name, void *options)
{
	struct afs_mount_params params;
	struct super_block *sb;
	struct afs_volume *vol;
	struct key *key;
	char *new_opts = kstrdup(options, GFP_KERNEL);
	struct afs_super_info *as;
	int ret;

	_enter(",,%s,%p", dev_name, options);

	memset(&params, 0, sizeof(params));

	ret = -EINVAL;
	if (current->nsproxy->net_ns != &init_net)
		goto error;

	/* parse the options and device name */
	if (options) {
		ret = afs_parse_options(&params, options, &dev_name);
		if (ret < 0)
			goto error;
	}

	ret = afs_parse_device_name(&params, dev_name);
	if (ret < 0)
		goto error;

	/* try and do the mount securely */
	key = afs_request_key(params.cell);
	if (IS_ERR(key)) {
		_leave(" = %ld [key]", PTR_ERR(key));
		ret = PTR_ERR(key);
		goto error;
	}
	params.key = key;

	/* parse the device name */
	vol = afs_volume_lookup(&params);
	if (IS_ERR(vol)) {
		ret = PTR_ERR(vol);
		goto error;
	}

	/* allocate a superblock info record */
	as = kzalloc(sizeof(struct afs_super_info), GFP_KERNEL);
	if (!as) {
		ret = -ENOMEM;
		afs_put_volume(vol);
		goto error;
	}
	as->volume = vol;

	/* allocate a deviceless superblock */
	sb = sget(fs_type, afs_test_super, afs_set_super, flags, as);
	if (IS_ERR(sb)) {
		ret = PTR_ERR(sb);
		afs_put_volume(vol);
		kfree(as);
		goto error;
	}

	if (!sb->s_root) {
		/* initial superblock/root creation */
		_debug("create");
		ret = afs_fill_super(sb, &params);
		if (ret < 0) {
			deactivate_locked_super(sb);
			goto error;
		}
		save_mount_options(sb, new_opts);
		sb->s_flags |= MS_ACTIVE;
	} else {
		_debug("reuse");
		ASSERTCMP(sb->s_flags, &, MS_ACTIVE);
		afs_put_volume(vol);
		kfree(as);
	}

	afs_put_cell(params.cell);
	kfree(new_opts);
	_leave(" = 0 [%p]", sb);
	return dget(sb->s_root);

error:
	afs_put_cell(params.cell);
	key_put(params.key);
	kfree(new_opts);
	_leave(" = %d", ret);
	return ERR_PTR(ret);
}

static void afs_kill_super(struct super_block *sb)
{
	struct afs_super_info *as = sb->s_fs_info;
	kill_anon_super(sb);
	afs_put_volume(as->volume);
	kfree(as);
}

/*
 * initialise an inode cache slab element prior to any use
 */
static void afs_i_init_once(void *_vnode)
{
	struct afs_vnode *vnode = _vnode;

	memset(vnode, 0, sizeof(*vnode));
	inode_init_once(&vnode->vfs_inode);
	init_waitqueue_head(&vnode->update_waitq);
	mutex_init(&vnode->permits_lock);
	mutex_init(&vnode->validate_lock);
	spin_lock_init(&vnode->writeback_lock);
	spin_lock_init(&vnode->lock);
	INIT_LIST_HEAD(&vnode->writebacks);
	INIT_LIST_HEAD(&vnode->pending_locks);
	INIT_LIST_HEAD(&vnode->granted_locks);
	INIT_DELAYED_WORK(&vnode->lock_work, afs_lock_work);
	INIT_WORK(&vnode->cb_broken_work, afs_broken_callback_work);
}

/*
 * allocate an AFS inode struct from our slab cache
 */
static struct inode *afs_alloc_inode(struct super_block *sb)
{
	struct afs_vnode *vnode;

	vnode = kmem_cache_alloc(afs_inode_cachep, GFP_KERNEL);
	if (!vnode)
		return NULL;

	atomic_inc(&afs_count_active_inodes);

	memset(&vnode->fid, 0, sizeof(vnode->fid));
	memset(&vnode->status, 0, sizeof(vnode->status));

	vnode->volume		= NULL;
	vnode->update_cnt	= 0;
	vnode->flags		= 1 << AFS_VNODE_UNSET;
	vnode->cb_promised	= false;

	_leave(" = %p", &vnode->vfs_inode);
	return &vnode->vfs_inode;
}

static void afs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct afs_vnode *vnode = AFS_FS_I(inode);
	kmem_cache_free(afs_inode_cachep, vnode);
}

/*
 * destroy an AFS inode struct
 */
static void afs_destroy_inode(struct inode *inode)
{
	struct afs_vnode *vnode = AFS_FS_I(inode);

	_enter("%p{%x:%u}", inode, vnode->fid.vid, vnode->fid.vnode);

	_debug("DESTROY INODE %p", inode);

	ASSERTCMP(vnode->server, ==, NULL);

	call_rcu(&inode->i_rcu, afs_i_callback);
	atomic_dec(&afs_count_active_inodes);
}

/*
 * return information about an AFS volume
 */
static int afs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct afs_volume_status vs;
	struct afs_vnode *vnode = AFS_FS_I(dentry->d_inode);
	struct key *key;
	int ret;

	key = afs_request_key(vnode->volume->cell);
	if (IS_ERR(key))
		return PTR_ERR(key);

	ret = afs_vnode_get_volume_status(vnode, key, &vs);
	key_put(key);
	if (ret < 0) {
		_leave(" = %d", ret);
		return ret;
	}

	buf->f_type	= dentry->d_sb->s_magic;
	buf->f_bsize	= AFS_BLOCK_SIZE;
	buf->f_namelen	= AFSNAMEMAX - 1;

	if (vs.max_quota == 0)
		buf->f_blocks = vs.part_max_blocks;
	else
		buf->f_blocks = vs.max_quota;
	buf->f_bavail = buf->f_bfree = buf->f_blocks - vs.blocks_in_use;
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/super.c */
/************************************************************/
/* AFS network device helpers
 *
 * Copyright (c) 2007 Patrick McHardy <kaber@trash.net>
 */

#include <linux/string.h>
#include <linux/rtnetlink.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
// #include <net/net_namespace.h>
// #include "internal.h"
#include "../../inc/__fss.h"

/*
 * get a MAC address from a random ethernet interface that has a real one
 * - the buffer will normally be 6 bytes in size
 */
int afs_get_MAC_address(u8 *mac, size_t maclen)
{
	struct net_device *dev;
	int ret = -ENODEV;

	BUG_ON(maclen != ETH_ALEN);

	rtnl_lock();
	dev = __dev_getfirstbyhwtype(&init_net, ARPHRD_ETHER);
	if (dev) {
		memcpy(mac, dev->dev_addr, maclen);
		ret = 0;
	}
	rtnl_unlock();
	return ret;
}

/*
 * get a list of this system's interface IPv4 addresses, netmasks and MTUs
 * - maxbufs must be at least 1
 * - returns the number of interface records in the buffer
 */
int afs_get_ipv4_interfaces(struct afs_interface *bufs, size_t maxbufs,
			    bool wantloopback)
{
	struct net_device *dev;
	struct in_device *idev;
	int n = 0;

	ASSERT(maxbufs > 0);

	rtnl_lock();
	for_each_netdev(&init_net, dev) {
		if (dev->type == ARPHRD_LOOPBACK && !wantloopback)
			continue;
		idev = __in_dev_get_rtnl(dev);
		if (!idev)
			continue;
		for_primary_ifa(idev) {
			bufs[n].address.s_addr = ifa->ifa_address;
			bufs[n].netmask.s_addr = ifa->ifa_mask;
			bufs[n].mtu = dev->mtu;
			n++;
			if (n >= maxbufs)
				goto out;
		} endfor_ifa(idev);
	}
out:
	rtnl_unlock();
	return n;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/netdevices.c */
/************************************************************/
/* AFS Volume Location Service client
 *
 * Copyright (C) 2002 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/gfp.h>
// #include <linux/init.h>
// #include <linux/sched.h>
// #include "internal.h"

/*
 * map volume locator abort codes to error codes
 */
static int afs_vl_abort_to_error(u32 abort_code)
{
	_enter("%u", abort_code);

	switch (abort_code) {
	case AFSVL_IDEXIST:		return -EEXIST;
	case AFSVL_IO:			return -EREMOTEIO;
	case AFSVL_NAMEEXIST:		return -EEXIST;
	case AFSVL_CREATEFAIL:		return -EREMOTEIO;
	case AFSVL_NOENT:		return -ENOMEDIUM;
	case AFSVL_EMPTY:		return -ENOMEDIUM;
	case AFSVL_ENTDELETED:		return -ENOMEDIUM;
	case AFSVL_BADNAME:		return -EINVAL;
	case AFSVL_BADINDEX:		return -EINVAL;
	case AFSVL_BADVOLTYPE:		return -EINVAL;
	case AFSVL_BADSERVER:		return -EINVAL;
	case AFSVL_BADPARTITION:	return -EINVAL;
	case AFSVL_REPSFULL:		return -EFBIG;
	case AFSVL_NOREPSERVER:		return -ENOENT;
	case AFSVL_DUPREPSERVER:	return -EEXIST;
	case AFSVL_RWNOTFOUND:		return -ENOENT;
	case AFSVL_BADREFCOUNT:		return -EINVAL;
	case AFSVL_SIZEEXCEEDED:	return -EINVAL;
	case AFSVL_BADENTRY:		return -EINVAL;
	case AFSVL_BADVOLIDBUMP:	return -EINVAL;
	case AFSVL_IDALREADYHASHED:	return -EINVAL;
	case AFSVL_ENTRYLOCKED:		return -EBUSY;
	case AFSVL_BADVOLOPER:		return -EBADRQC;
	case AFSVL_BADRELLOCKTYPE:	return -EINVAL;
	case AFSVL_RERELEASE:		return -EREMOTEIO;
	case AFSVL_BADSERVERFLAG:	return -EINVAL;
	case AFSVL_PERM:		return -EACCES;
	case AFSVL_NOMEM:		return -EREMOTEIO;
	default:
		return afs_abort_to_error(abort_code);
	}
}

/*
 * deliver reply data to a VL.GetEntryByXXX call
 */
static int afs_deliver_vl_get_entry_by_xxx(struct afs_call *call,
					   struct sk_buff *skb, bool last)
{
	struct afs_cache_vlocation *entry;
	__be32 *bp;
	u32 tmp;
	int loop;

	_enter(",,%u", last);

	afs_transfer_reply(call, skb);
	if (!last)
		return 0;

	if (call->reply_size != call->reply_max)
		return -EBADMSG;

	/* unmarshall the reply once we've received all of it */
	entry = call->reply;
	bp = call->buffer;

	for (loop = 0; loop < 64; loop++)
		entry->name[loop] = ntohl(*bp++);
	entry->name[loop] = 0;
	bp++; /* final NUL */

	bp++; /* type */
	entry->nservers = ntohl(*bp++);

	for (loop = 0; loop < 8; loop++)
		entry->servers[loop].s_addr = *bp++;

	bp += 8; /* partition IDs */

	for (loop = 0; loop < 8; loop++) {
		tmp = ntohl(*bp++);
		entry->srvtmask[loop] = 0;
		if (tmp & AFS_VLSF_RWVOL)
			entry->srvtmask[loop] |= AFS_VOL_VTM_RW;
		if (tmp & AFS_VLSF_ROVOL)
			entry->srvtmask[loop] |= AFS_VOL_VTM_RO;
		if (tmp & AFS_VLSF_BACKVOL)
			entry->srvtmask[loop] |= AFS_VOL_VTM_BAK;
	}

	entry->vid[0] = ntohl(*bp++);
	entry->vid[1] = ntohl(*bp++);
	entry->vid[2] = ntohl(*bp++);

	bp++; /* clone ID */

	tmp = ntohl(*bp++); /* flags */
	entry->vidmask = 0;
	if (tmp & AFS_VLF_RWEXISTS)
		entry->vidmask |= AFS_VOL_VTM_RW;
	if (tmp & AFS_VLF_ROEXISTS)
		entry->vidmask |= AFS_VOL_VTM_RO;
	if (tmp & AFS_VLF_BACKEXISTS)
		entry->vidmask |= AFS_VOL_VTM_BAK;
	if (!entry->vidmask)
		return -EBADMSG;

	_leave(" = 0 [done]");
	return 0;
}

/*
 * VL.GetEntryByName operation type
 */
static const struct afs_call_type afs_RXVLGetEntryByName = {
	.name		= "VL.GetEntryByName",
	.deliver	= afs_deliver_vl_get_entry_by_xxx,
	.abort_to_error	= afs_vl_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * VL.GetEntryById operation type
 */
static const struct afs_call_type afs_RXVLGetEntryById = {
	.name		= "VL.GetEntryById",
	.deliver	= afs_deliver_vl_get_entry_by_xxx,
	.abort_to_error	= afs_vl_abort_to_error,
	.destructor	= afs_flat_call_destructor,
};

/*
 * dispatch a get volume entry by name operation
 */
int afs_vl_get_entry_by_name(struct in_addr *addr,
			     struct key *key,
			     const char *volname,
			     struct afs_cache_vlocation *entry,
			     const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	size_t volnamesz, reqsz, padsz;
	__be32 *bp;

	_enter("");

	volnamesz = strlen(volname);
	padsz = (4 - (volnamesz & 3)) & 3;
	reqsz = 8 + volnamesz + padsz;

	call = afs_alloc_flat_call(&afs_RXVLGetEntryByName, reqsz, 384);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = entry;
	call->service_id = VL_SERVICE;
	call->port = htons(AFS_VL_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(VLGETENTRYBYNAME);
	*bp++ = htonl(volnamesz);
	memcpy(bp, volname, volnamesz);
	if (padsz > 0)
		memset((void *) bp + volnamesz, 0, padsz);

	/* initiate the call */
	return afs_make_call(addr, call, GFP_KERNEL, wait_mode);
}

/*
 * dispatch a get volume entry by ID operation
 */
int afs_vl_get_entry_by_id(struct in_addr *addr,
			   struct key *key,
			   afs_volid_t volid,
			   afs_voltype_t voltype,
			   struct afs_cache_vlocation *entry,
			   const struct afs_wait_mode *wait_mode)
{
	struct afs_call *call;
	__be32 *bp;

	_enter("");

	call = afs_alloc_flat_call(&afs_RXVLGetEntryById, 12, 384);
	if (!call)
		return -ENOMEM;

	call->key = key;
	call->reply = entry;
	call->service_id = VL_SERVICE;
	call->port = htons(AFS_VL_PORT);

	/* marshall the parameters */
	bp = call->request;
	*bp++ = htonl(VLGETENTRYBYID);
	*bp++ = htonl(volid);
	*bp   = htonl(voltype);

	/* initiate the call */
	return afs_make_call(addr, call, GFP_KERNEL, wait_mode);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/vlclient.c */
/************************************************************/
/* AFS volume location management
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/slab.h>
// #include <linux/init.h>
// #include <linux/sched.h>
// #include "internal.h"

static unsigned afs_vlocation_timeout = 10;	/* volume location timeout in seconds */
static unsigned afs_vlocation_update_timeout = 10 * 60;

static void afs_vlocation_reaper(struct work_struct *);
static void afs_vlocation_updater(struct work_struct *);

static LIST_HEAD(afs_vlocation_updates);
static LIST_HEAD(afs_vlocation_graveyard);
static DEFINE_SPINLOCK(afs_vlocation_updates_lock);
static DEFINE_SPINLOCK(afs_vlocation_graveyard_lock);
static DECLARE_DELAYED_WORK_vlocation_c(afs_vlocation_reap, afs_vlocation_reaper);
static DECLARE_DELAYED_WORK_vlocation_c(afs_vlocation_update, afs_vlocation_updater);
static struct workqueue_struct *afs_vlocation_update_worker;

/*
 * iterate through the VL servers in a cell until one of them admits knowing
 * about the volume in question
 */
static int afs_vlocation_access_vl_by_name(struct afs_vlocation *vl,
					   struct key *key,
					   struct afs_cache_vlocation *vldb)
{
	struct afs_cell *cell = vl->cell;
	struct in_addr addr;
	int count, ret;

	_enter("%s,%s", cell->name, vl->vldb.name);

	down_write(&vl->cell->vl_sem);
	ret = -ENOMEDIUM;
	for (count = cell->vl_naddrs; count > 0; count--) {
		addr = cell->vl_addrs[cell->vl_curr_svix];

		_debug("CellServ[%hu]: %08x", cell->vl_curr_svix, addr.s_addr);

		/* attempt to access the VL server */
		ret = afs_vl_get_entry_by_name(&addr, key, vl->vldb.name, vldb,
					       &afs_sync_call);
		switch (ret) {
		case 0:
			goto out;
		case -ENOMEM:
		case -ENONET:
		case -ENETUNREACH:
		case -EHOSTUNREACH:
		case -ECONNREFUSED:
			if (ret == -ENOMEM || ret == -ENONET)
				goto out;
			goto rotate;
		case -ENOMEDIUM:
		case -EKEYREJECTED:
		case -EKEYEXPIRED:
			goto out;
		default:
			ret = -EIO;
			goto rotate;
		}

		/* rotate the server records upon lookup failure */
	rotate:
		cell->vl_curr_svix++;
		cell->vl_curr_svix %= cell->vl_naddrs;
	}

out:
	up_write(&vl->cell->vl_sem);
	_leave(" = %d", ret);
	return ret;
}

/*
 * iterate through the VL servers in a cell until one of them admits knowing
 * about the volume in question
 */
static int afs_vlocation_access_vl_by_id(struct afs_vlocation *vl,
					 struct key *key,
					 afs_volid_t volid,
					 afs_voltype_t voltype,
					 struct afs_cache_vlocation *vldb)
{
	struct afs_cell *cell = vl->cell;
	struct in_addr addr;
	int count, ret;

	_enter("%s,%x,%d,", cell->name, volid, voltype);

	down_write(&vl->cell->vl_sem);
	ret = -ENOMEDIUM;
	for (count = cell->vl_naddrs; count > 0; count--) {
		addr = cell->vl_addrs[cell->vl_curr_svix];

		_debug("CellServ[%hu]: %08x", cell->vl_curr_svix, addr.s_addr);

		/* attempt to access the VL server */
		ret = afs_vl_get_entry_by_id(&addr, key, volid, voltype, vldb,
					     &afs_sync_call);
		switch (ret) {
		case 0:
			goto out;
		case -ENOMEM:
		case -ENONET:
		case -ENETUNREACH:
		case -EHOSTUNREACH:
		case -ECONNREFUSED:
			if (ret == -ENOMEM || ret == -ENONET)
				goto out;
			goto rotate;
		case -EBUSY:
			vl->upd_busy_cnt++;
			if (vl->upd_busy_cnt <= 3) {
				if (vl->upd_busy_cnt > 1) {
					/* second+ BUSY - sleep a little bit */
					set_current_state(TASK_UNINTERRUPTIBLE);
					schedule_timeout(1);
				}
				continue;
			}
			break;
		case -ENOMEDIUM:
			vl->upd_rej_cnt++;
			goto rotate;
		default:
			ret = -EIO;
			goto rotate;
		}

		/* rotate the server records upon lookup failure */
	rotate:
		cell->vl_curr_svix++;
		cell->vl_curr_svix %= cell->vl_naddrs;
		vl->upd_busy_cnt = 0;
	}

out:
	if (ret < 0 && vl->upd_rej_cnt > 0) {
		printk(KERN_NOTICE "kAFS:"
		       " Active volume no longer valid '%s'\n",
		       vl->vldb.name);
		vl->valid = 0;
		ret = -ENOMEDIUM;
	}

	up_write(&vl->cell->vl_sem);
	_leave(" = %d", ret);
	return ret;
}

/*
 * allocate a volume location record
 */
static struct afs_vlocation *afs_vlocation_alloc(struct afs_cell *cell,
						 const char *name,
						 size_t namesz)
{
	struct afs_vlocation *vl;

	vl = kzalloc(sizeof(struct afs_vlocation), GFP_KERNEL);
	if (vl) {
		vl->cell = cell;
		vl->state = AFS_VL_NEW;
		atomic_set(&vl->usage, 1);
		INIT_LIST_HEAD(&vl->link);
		INIT_LIST_HEAD(&vl->grave);
		INIT_LIST_HEAD(&vl->update);
		init_waitqueue_head(&vl->waitq);
		spin_lock_init(&vl->lock);
		memcpy(vl->vldb.name, name, namesz);
	}

	_leave(" = %p", vl);
	return vl;
}

/*
 * update record if we found it in the cache
 */
static int afs_vlocation_update_record(struct afs_vlocation *vl,
				       struct key *key,
				       struct afs_cache_vlocation *vldb)
{
	afs_voltype_t voltype;
	afs_volid_t vid;
	int ret;

	/* try to look up a cached volume in the cell VL databases by ID */
	_debug("Locally Cached: %s %02x { %08x(%x) %08x(%x) %08x(%x) }",
	       vl->vldb.name,
	       vl->vldb.vidmask,
	       ntohl(vl->vldb.servers[0].s_addr),
	       vl->vldb.srvtmask[0],
	       ntohl(vl->vldb.servers[1].s_addr),
	       vl->vldb.srvtmask[1],
	       ntohl(vl->vldb.servers[2].s_addr),
	       vl->vldb.srvtmask[2]);

	_debug("Vids: %08x %08x %08x",
	       vl->vldb.vid[0],
	       vl->vldb.vid[1],
	       vl->vldb.vid[2]);

	if (vl->vldb.vidmask & AFS_VOL_VTM_RW) {
		vid = vl->vldb.vid[0];
		voltype = AFSVL_RWVOL;
	} else if (vl->vldb.vidmask & AFS_VOL_VTM_RO) {
		vid = vl->vldb.vid[1];
		voltype = AFSVL_ROVOL;
	} else if (vl->vldb.vidmask & AFS_VOL_VTM_BAK) {
		vid = vl->vldb.vid[2];
		voltype = AFSVL_BACKVOL;
	} else {
		BUG();
		vid = 0;
		voltype = 0;
	}

	/* contact the server to make sure the volume is still available
	 * - TODO: need to handle disconnected operation here
	 */
	ret = afs_vlocation_access_vl_by_id(vl, key, vid, voltype, vldb);
	switch (ret) {
		/* net error */
	default:
		printk(KERN_WARNING "kAFS:"
		       " failed to update volume '%s' (%x) up in '%s': %d\n",
		       vl->vldb.name, vid, vl->cell->name, ret);
		_leave(" = %d", ret);
		return ret;

		/* pulled from local cache into memory */
	case 0:
		_leave(" = 0");
		return 0;

		/* uh oh... looks like the volume got deleted */
	case -ENOMEDIUM:
		printk(KERN_ERR "kAFS:"
		       " volume '%s' (%x) does not exist '%s'\n",
		       vl->vldb.name, vid, vl->cell->name);

		/* TODO: make existing record unavailable */
		_leave(" = %d", ret);
		return ret;
	}
}

/*
 * apply the update to a VL record
 */
static void afs_vlocation_apply_update(struct afs_vlocation *vl,
				       struct afs_cache_vlocation *vldb)
{
	_debug("Done VL Lookup: %s %02x { %08x(%x) %08x(%x) %08x(%x) }",
	       vldb->name, vldb->vidmask,
	       ntohl(vldb->servers[0].s_addr), vldb->srvtmask[0],
	       ntohl(vldb->servers[1].s_addr), vldb->srvtmask[1],
	       ntohl(vldb->servers[2].s_addr), vldb->srvtmask[2]);

	_debug("Vids: %08x %08x %08x",
	       vldb->vid[0], vldb->vid[1], vldb->vid[2]);

	if (strcmp(vldb->name, vl->vldb.name) != 0)
		printk(KERN_NOTICE "kAFS:"
		       " name of volume '%s' changed to '%s' on server\n",
		       vl->vldb.name, vldb->name);

	vl->vldb = *vldb;

#ifdef CONFIG_AFS_FSCACHE
	fscache_update_cookie(vl->cache);
#endif
}

/*
 * fill in a volume location record, consulting the cache and the VL server
 * both
 */
static int afs_vlocation_fill_in_record(struct afs_vlocation *vl,
					struct key *key)
{
	struct afs_cache_vlocation vldb;
	int ret;

	_enter("");

	ASSERTCMP(vl->valid, ==, 0);

	memset(&vldb, 0, sizeof(vldb));

	/* see if we have an in-cache copy (will set vl->valid if there is) */
#ifdef CONFIG_AFS_FSCACHE
	vl->cache = fscache_acquire_cookie(vl->cell->cache,
					   &afs_vlocation_cache_index_def, vl,
					   true);
#endif

	if (vl->valid) {
		/* try to update a known volume in the cell VL databases by
		 * ID as the name may have changed */
		_debug("found in cache");
		ret = afs_vlocation_update_record(vl, key, &vldb);
	} else {
		/* try to look up an unknown volume in the cell VL databases by
		 * name */
		ret = afs_vlocation_access_vl_by_name(vl, key, &vldb);
		if (ret < 0) {
			printk("kAFS: failed to locate '%s' in cell '%s'\n",
			       vl->vldb.name, vl->cell->name);
			return ret;
		}
	}

	afs_vlocation_apply_update(vl, &vldb);
	_leave(" = 0");
	return 0;
}

/*
 * queue a vlocation record for updates
 */
static void afs_vlocation_queue_for_updates(struct afs_vlocation *vl)
{
	struct afs_vlocation *xvl;

	/* wait at least 10 minutes before updating... */
	vl->update_at = get_seconds() + afs_vlocation_update_timeout;

	spin_lock(&afs_vlocation_updates_lock);

	if (!list_empty(&afs_vlocation_updates)) {
		/* ... but wait at least 1 second more than the newest record
		 * already queued so that we don't spam the VL server suddenly
		 * with lots of requests
		 */
		xvl = list_entry(afs_vlocation_updates.prev,
				 struct afs_vlocation, update);
		if (vl->update_at <= xvl->update_at)
			vl->update_at = xvl->update_at + 1;
	} else {
		queue_delayed_work(afs_vlocation_update_worker,
				   &afs_vlocation_update,
				   afs_vlocation_update_timeout * HZ);
	}

	list_add_tail(&vl->update, &afs_vlocation_updates);
	spin_unlock(&afs_vlocation_updates_lock);
}

/*
 * lookup volume location
 * - iterate through the VL servers in a cell until one of them admits knowing
 *   about the volume in question
 * - lookup in the local cache if not able to find on the VL server
 * - insert/update in the local cache if did get a VL response
 */
struct afs_vlocation *afs_vlocation_lookup(struct afs_cell *cell,
					   struct key *key,
					   const char *name,
					   size_t namesz)
{
	struct afs_vlocation *vl;
	int ret;

	_enter("{%s},{%x},%*.*s,%zu",
	       cell->name, key_serial(key),
	       (int) namesz, (int) namesz, name, namesz);

	if (namesz >= sizeof(vl->vldb.name)) {
		_leave(" = -ENAMETOOLONG");
		return ERR_PTR(-ENAMETOOLONG);
	}

	/* see if we have an in-memory copy first */
	down_write(&cell->vl_sem);
	spin_lock(&cell->vl_lock);
	list_for_each_entry(vl, &cell->vl_list, link) {
		if (vl->vldb.name[namesz] != '\0')
			continue;
		if (memcmp(vl->vldb.name, name, namesz) == 0)
			goto found_in_memory;
	}
	spin_unlock(&cell->vl_lock);

	/* not in the cell's in-memory lists - create a new record */
	vl = afs_vlocation_alloc(cell, name, namesz);
	if (!vl) {
		up_write(&cell->vl_sem);
		return ERR_PTR(-ENOMEM);
	}

	afs_get_cell(cell);

	list_add_tail(&vl->link, &cell->vl_list);
	vl->state = AFS_VL_CREATING;
	up_write(&cell->vl_sem);

fill_in_record:
	ret = afs_vlocation_fill_in_record(vl, key);
	if (ret < 0)
		goto error_abandon;
	spin_lock(&vl->lock);
	vl->state = AFS_VL_VALID;
	spin_unlock(&vl->lock);
	wake_up(&vl->waitq);

	/* update volume entry in local cache */
#ifdef CONFIG_AFS_FSCACHE
	fscache_update_cookie(vl->cache);
#endif

	/* schedule for regular updates */
	afs_vlocation_queue_for_updates(vl);
	goto success;

found_in_memory:
	/* found in memory */
	_debug("found in memory");
	atomic_inc(&vl->usage);
	spin_unlock(&cell->vl_lock);
	if (!list_empty(&vl->grave)) {
		spin_lock(&afs_vlocation_graveyard_lock);
		list_del_init(&vl->grave);
		spin_unlock(&afs_vlocation_graveyard_lock);
	}
	up_write(&cell->vl_sem);

	/* see if it was an abandoned record that we might try filling in */
	spin_lock(&vl->lock);
	while (vl->state != AFS_VL_VALID) {
		afs_vlocation_state_t state = vl->state;

		_debug("invalid [state %d]", state);

		if (state == AFS_VL_NEW || state == AFS_VL_NO_VOLUME) {
			vl->state = AFS_VL_CREATING;
			spin_unlock(&vl->lock);
			goto fill_in_record;
		}

		/* must now wait for creation or update by someone else to
		 * complete */
		_debug("wait");

		spin_unlock(&vl->lock);
		ret = wait_event_interruptible(vl->waitq,
					       vl->state == AFS_VL_NEW ||
					       vl->state == AFS_VL_VALID ||
					       vl->state == AFS_VL_NO_VOLUME);
		if (ret < 0)
			goto error;
		spin_lock(&vl->lock);
	}
	spin_unlock(&vl->lock);

success:
	_leave(" = %p", vl);
	return vl;

error_abandon:
	spin_lock(&vl->lock);
	vl->state = AFS_VL_NEW;
	spin_unlock(&vl->lock);
	wake_up(&vl->waitq);
error:
	ASSERT(vl != NULL);
	afs_put_vlocation(vl);
	_leave(" = %d", ret);
	return ERR_PTR(ret);
}

/*
 * finish using a volume location record
 */
void afs_put_vlocation(struct afs_vlocation *vl)
{
	if (!vl)
		return;

	_enter("%s", vl->vldb.name);

	ASSERTCMP(atomic_read(&vl->usage), >, 0);

	if (likely(!atomic_dec_and_test(&vl->usage))) {
		_leave("");
		return;
	}

	spin_lock(&afs_vlocation_graveyard_lock);
	if (atomic_read(&vl->usage) == 0) {
		_debug("buried");
		list_move_tail(&vl->grave, &afs_vlocation_graveyard);
		vl->time_of_death = get_seconds();
		queue_delayed_work(afs_wq, &afs_vlocation_reap,
				   afs_vlocation_timeout * HZ);

		/* suspend updates on this record */
		if (!list_empty(&vl->update)) {
			spin_lock(&afs_vlocation_updates_lock);
			list_del_init(&vl->update);
			spin_unlock(&afs_vlocation_updates_lock);
		}
	}
	spin_unlock(&afs_vlocation_graveyard_lock);
	_leave(" [killed?]");
}

/*
 * destroy a dead volume location record
 */
static void afs_vlocation_destroy(struct afs_vlocation *vl)
{
	_enter("%p", vl);

#ifdef CONFIG_AFS_FSCACHE
	fscache_relinquish_cookie(vl->cache, 0);
#endif
	afs_put_cell(vl->cell);
	kfree(vl);
}

/*
 * reap dead volume location records
 */
static void afs_vlocation_reaper(struct work_struct *work)
{
	LIST_HEAD(corpses);
	struct afs_vlocation *vl;
	unsigned long delay, expiry;
	time_t now;

	_enter("");

	now = get_seconds();
	spin_lock(&afs_vlocation_graveyard_lock);

	while (!list_empty(&afs_vlocation_graveyard)) {
		vl = list_entry(afs_vlocation_graveyard.next,
				struct afs_vlocation, grave);

		_debug("check %p", vl);

		/* the queue is ordered most dead first */
		expiry = vl->time_of_death + afs_vlocation_timeout;
		if (expiry > now) {
			delay = (expiry - now) * HZ;
			_debug("delay %lu", delay);
			mod_delayed_work(afs_wq, &afs_vlocation_reap, delay);
			break;
		}

		spin_lock(&vl->cell->vl_lock);
		if (atomic_read(&vl->usage) > 0) {
			_debug("no reap");
			list_del_init(&vl->grave);
		} else {
			_debug("reap");
			list_move_tail(&vl->grave, &corpses);
			list_del_init(&vl->link);
		}
		spin_unlock(&vl->cell->vl_lock);
	}

	spin_unlock(&afs_vlocation_graveyard_lock);

	/* now reap the corpses we've extracted */
	while (!list_empty(&corpses)) {
		vl = list_entry(corpses.next, struct afs_vlocation, grave);
		list_del(&vl->grave);
		afs_vlocation_destroy(vl);
	}

	_leave("");
}

/*
 * initialise the VL update process
 */
int __init afs_vlocation_update_init(void)
{
	afs_vlocation_update_worker =
		create_singlethread_workqueue("kafs_vlupdated");
	return afs_vlocation_update_worker ? 0 : -ENOMEM;
}

/*
 * discard all the volume location records for rmmod
 */
void afs_vlocation_purge(void)
{
	afs_vlocation_timeout = 0;

	spin_lock(&afs_vlocation_updates_lock);
	list_del_init(&afs_vlocation_updates);
	spin_unlock(&afs_vlocation_updates_lock);
	mod_delayed_work(afs_vlocation_update_worker, &afs_vlocation_update, 0);
	destroy_workqueue(afs_vlocation_update_worker);

	mod_delayed_work(afs_wq, &afs_vlocation_reap, 0);
}

/*
 * update a volume location
 */
static void afs_vlocation_updater(struct work_struct *work)
{
	struct afs_cache_vlocation vldb;
	struct afs_vlocation *vl, *xvl;
	time_t now;
	long timeout;
	int ret;

	_enter("");

	now = get_seconds();

	/* find a record to update */
	spin_lock(&afs_vlocation_updates_lock);
	for (;;) {
		if (list_empty(&afs_vlocation_updates)) {
			spin_unlock(&afs_vlocation_updates_lock);
			_leave(" [nothing]");
			return;
		}

		vl = list_entry(afs_vlocation_updates.next,
				struct afs_vlocation, update);
		if (atomic_read(&vl->usage) > 0)
			break;
		list_del_init(&vl->update);
	}

	timeout = vl->update_at - now;
	if (timeout > 0) {
		queue_delayed_work(afs_vlocation_update_worker,
				   &afs_vlocation_update, timeout * HZ);
		spin_unlock(&afs_vlocation_updates_lock);
		_leave(" [nothing]");
		return;
	}

	list_del_init(&vl->update);
	atomic_inc(&vl->usage);
	spin_unlock(&afs_vlocation_updates_lock);

	/* we can now perform the update */
	_debug("update %s", vl->vldb.name);
	vl->state = AFS_VL_UPDATING;
	vl->upd_rej_cnt = 0;
	vl->upd_busy_cnt = 0;

	ret = afs_vlocation_update_record(vl, NULL, &vldb);
	spin_lock(&vl->lock);
	switch (ret) {
	case 0:
		afs_vlocation_apply_update(vl, &vldb);
		vl->state = AFS_VL_VALID;
		break;
	case -ENOMEDIUM:
		vl->state = AFS_VL_VOLUME_DELETED;
		break;
	default:
		vl->state = AFS_VL_UNCERTAIN;
		break;
	}
	spin_unlock(&vl->lock);
	wake_up(&vl->waitq);

	/* and then reschedule */
	_debug("reschedule");
	vl->update_at = get_seconds() + afs_vlocation_update_timeout;

	spin_lock(&afs_vlocation_updates_lock);

	if (!list_empty(&afs_vlocation_updates)) {
		/* next update in 10 minutes, but wait at least 1 second more
		 * than the newest record already queued so that we don't spam
		 * the VL server suddenly with lots of requests
		 */
		xvl = list_entry(afs_vlocation_updates.prev,
				 struct afs_vlocation, update);
		if (vl->update_at <= xvl->update_at)
			vl->update_at = xvl->update_at + 1;
		xvl = list_entry(afs_vlocation_updates.next,
				 struct afs_vlocation, update);
		timeout = xvl->update_at - now;
		if (timeout < 0)
			timeout = 0;
	} else {
		timeout = afs_vlocation_update_timeout;
	}

	ASSERT(list_empty(&vl->update));

	list_add_tail(&vl->update, &afs_vlocation_updates);

	_debug("timeout %ld", timeout);
	queue_delayed_work(afs_vlocation_update_worker,
			   &afs_vlocation_update, timeout * HZ);
	spin_unlock(&afs_vlocation_updates_lock);
	afs_put_vlocation(vl);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/vlocation.c */
/************************************************************/
/* AFS vnode management
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/init.h>
// #include <linux/fs.h>
// #include <linux/sched.h>
// #include "internal.h"

#if 0
static noinline bool dump_tree_aux(struct rb_node *node, struct rb_node *parent,
				   int depth, char lr)
{
	struct afs_vnode *vnode;
	bool bad = false;

	if (!node)
		return false;

	if (node->rb_left)
		bad = dump_tree_aux(node->rb_left, node, depth + 2, '/');

	vnode = rb_entry(node, struct afs_vnode, cb_promise);
	_debug("%c %*.*s%c%p {%d}",
	       rb_is_red(node) ? 'R' : 'B',
	       depth, depth, "", lr,
	       vnode, vnode->cb_expires_at);
	if (rb_parent(node) != parent) {
		printk("BAD: %p != %p\n", rb_parent(node), parent);
		bad = true;
	}

	if (node->rb_right)
		bad |= dump_tree_aux(node->rb_right, node, depth + 2, '\\');

	return bad;
}

static noinline void dump_tree(const char *name, struct afs_server *server)
{
	_enter("%s", name);
	if (dump_tree_aux(server->cb_promises.rb_node, NULL, 0, '-'))
		BUG();
}
#endif

/*
 * insert a vnode into the backing server's vnode tree
 */
static void afs_install_vnode(struct afs_vnode *vnode,
			      struct afs_server *server)
{
	struct afs_server *old_server = vnode->server;
	struct afs_vnode *xvnode;
	struct rb_node *parent, **p;

	_enter("%p,%p", vnode, server);

	if (old_server) {
		spin_lock(&old_server->fs_lock);
		rb_erase(&vnode->server_rb, &old_server->fs_vnodes);
		spin_unlock(&old_server->fs_lock);
	}

	afs_get_server(server);
	vnode->server = server;
	afs_put_server(old_server);

	/* insert into the server's vnode tree in FID order */
	spin_lock(&server->fs_lock);

	parent = NULL;
	p = &server->fs_vnodes.rb_node;
	while (*p) {
		parent = *p;
		xvnode = rb_entry(parent, struct afs_vnode, server_rb);
		if (vnode->fid.vid < xvnode->fid.vid)
			p = &(*p)->rb_left;
		else if (vnode->fid.vid > xvnode->fid.vid)
			p = &(*p)->rb_right;
		else if (vnode->fid.vnode < xvnode->fid.vnode)
			p = &(*p)->rb_left;
		else if (vnode->fid.vnode > xvnode->fid.vnode)
			p = &(*p)->rb_right;
		else if (vnode->fid.unique < xvnode->fid.unique)
			p = &(*p)->rb_left;
		else if (vnode->fid.unique > xvnode->fid.unique)
			p = &(*p)->rb_right;
		else
			BUG(); /* can't happen unless afs_iget() malfunctions */
	}

	rb_link_node(&vnode->server_rb, parent, p);
	rb_insert_color(&vnode->server_rb, &server->fs_vnodes);

	spin_unlock(&server->fs_lock);
	_leave("");
}

/*
 * insert a vnode into the promising server's update/expiration tree
 * - caller must hold vnode->lock
 */
static void afs_vnode_note_promise(struct afs_vnode *vnode,
				   struct afs_server *server)
{
	struct afs_server *old_server;
	struct afs_vnode *xvnode;
	struct rb_node *parent, **p;

	_enter("%p,%p", vnode, server);

	ASSERT(server != NULL);

	old_server = vnode->server;
	if (vnode->cb_promised) {
		if (server == old_server &&
		    vnode->cb_expires == vnode->cb_expires_at) {
			_leave(" [no change]");
			return;
		}

		spin_lock(&old_server->cb_lock);
		if (vnode->cb_promised) {
			_debug("delete");
			rb_erase(&vnode->cb_promise, &old_server->cb_promises);
			vnode->cb_promised = false;
		}
		spin_unlock(&old_server->cb_lock);
	}

	if (vnode->server != server)
		afs_install_vnode(vnode, server);

	vnode->cb_expires_at = vnode->cb_expires;
	_debug("PROMISE on %p {%lu}",
	       vnode, (unsigned long) vnode->cb_expires_at);

	/* abuse an RB-tree to hold the expiration order (we may have multiple
	 * items with the same expiration time) */
	spin_lock(&server->cb_lock);

	parent = NULL;
	p = &server->cb_promises.rb_node;
	while (*p) {
		parent = *p;
		xvnode = rb_entry(parent, struct afs_vnode, cb_promise);
		if (vnode->cb_expires_at < xvnode->cb_expires_at)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&vnode->cb_promise, parent, p);
	rb_insert_color(&vnode->cb_promise, &server->cb_promises);
	vnode->cb_promised = true;

	spin_unlock(&server->cb_lock);
	_leave("");
}

/*
 * handle remote file deletion by discarding the callback promise
 */
static void afs_vnode_deleted_remotely(struct afs_vnode *vnode)
{
	struct afs_server *server;

	_enter("{%p}", vnode->server);

	set_bit(AFS_VNODE_DELETED, &vnode->flags);

	server = vnode->server;
	if (server) {
		if (vnode->cb_promised) {
			spin_lock(&server->cb_lock);
			if (vnode->cb_promised) {
				rb_erase(&vnode->cb_promise,
					 &server->cb_promises);
				vnode->cb_promised = false;
			}
			spin_unlock(&server->cb_lock);
		}

		spin_lock(&server->fs_lock);
		rb_erase(&vnode->server_rb, &server->fs_vnodes);
		spin_unlock(&server->fs_lock);

		vnode->server = NULL;
		afs_put_server(server);
	} else {
		ASSERT(!vnode->cb_promised);
	}

	_leave("");
}

/*
 * finish off updating the recorded status of a file after a successful
 * operation completion
 * - starts callback expiry timer
 * - adds to server's callback list
 */
void afs_vnode_finalise_status_update(struct afs_vnode *vnode,
				      struct afs_server *server)
{
	struct afs_server *oldserver = NULL;

	_enter("%p,%p", vnode, server);

	spin_lock(&vnode->lock);
	clear_bit(AFS_VNODE_CB_BROKEN, &vnode->flags);
	afs_vnode_note_promise(vnode, server);
	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);

	wake_up_all(&vnode->update_waitq);
	afs_put_server(oldserver);
	_leave("");
}

/*
 * finish off updating the recorded status of a file after an operation failed
 */
static void afs_vnode_status_update_failed(struct afs_vnode *vnode, int ret)
{
	_enter("{%x:%u},%d", vnode->fid.vid, vnode->fid.vnode, ret);

	spin_lock(&vnode->lock);

	clear_bit(AFS_VNODE_CB_BROKEN, &vnode->flags);

	if (ret == -ENOENT) {
		/* the file was deleted on the server */
		_debug("got NOENT from server - marking file deleted");
		afs_vnode_deleted_remotely(vnode);
	}

	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);

	wake_up_all(&vnode->update_waitq);
	_leave("");
}

/*
 * fetch file status from the volume
 * - don't issue a fetch if:
 *   - the changed bit is not set and there's a valid callback
 *   - there are any outstanding ops that will fetch the status
 * - TODO implement local caching
 */
int afs_vnode_fetch_status(struct afs_vnode *vnode,
			   struct afs_vnode *auth_vnode, struct key *key)
{
	struct afs_server *server;
	unsigned long acl_order;
	int ret;

	DECLARE_WAITQUEUE(myself, current);

	_enter("%s,{%x:%u.%u}",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid, vnode->fid.vnode, vnode->fid.unique);

	if (!test_bit(AFS_VNODE_CB_BROKEN, &vnode->flags) &&
	    vnode->cb_promised) {
		_leave(" [unchanged]");
		return 0;
	}

	if (test_bit(AFS_VNODE_DELETED, &vnode->flags)) {
		_leave(" [deleted]");
		return -ENOENT;
	}

	acl_order = 0;
	if (auth_vnode)
		acl_order = auth_vnode->acl_order;

	spin_lock(&vnode->lock);

	if (!test_bit(AFS_VNODE_CB_BROKEN, &vnode->flags) &&
	    vnode->cb_promised) {
		spin_unlock(&vnode->lock);
		_leave(" [unchanged]");
		return 0;
	}

	ASSERTCMP(vnode->update_cnt, >=, 0);

	if (vnode->update_cnt > 0) {
		/* someone else started a fetch */
		_debug("wait on fetch %d", vnode->update_cnt);

		set_current_state(TASK_UNINTERRUPTIBLE);
		ASSERT(myself.func != NULL);
		add_wait_queue(&vnode->update_waitq, &myself);

		/* wait for the status to be updated */
		for (;;) {
			if (!test_bit(AFS_VNODE_CB_BROKEN, &vnode->flags))
				break;
			if (test_bit(AFS_VNODE_DELETED, &vnode->flags))
				break;

			/* check to see if it got updated and invalidated all
			 * before we saw it */
			if (vnode->update_cnt == 0) {
				remove_wait_queue(&vnode->update_waitq,
						  &myself);
				set_current_state(TASK_RUNNING);
				goto get_anyway;
			}

			spin_unlock(&vnode->lock);

			schedule();
			set_current_state(TASK_UNINTERRUPTIBLE);

			spin_lock(&vnode->lock);
		}

		remove_wait_queue(&vnode->update_waitq, &myself);
		spin_unlock(&vnode->lock);
		set_current_state(TASK_RUNNING);

		return test_bit(AFS_VNODE_DELETED, &vnode->flags) ?
			-ENOENT : 0;
	}

get_anyway:
	/* okay... we're going to have to initiate the op */
	vnode->update_cnt++;

	spin_unlock(&vnode->lock);

	/* merge AFS status fetches and clear outstanding callback on this
	 * vnode */
	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %p{%08x}",
		       server, ntohl(server->addr.s_addr));

		ret = afs_fs_fetch_file_status(server, key, vnode, NULL,
					       &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0) {
		_debug("adjust");
		if (auth_vnode)
			afs_cache_permit(vnode, key, acl_order);
		afs_vnode_finalise_status_update(vnode, server);
		afs_put_server(server);
	} else {
		_debug("failed [%d]", ret);
		afs_vnode_status_update_failed(vnode, ret);
	}

	ASSERTCMP(vnode->update_cnt, >=, 0);

	_leave(" = %d [cnt %d]", ret, vnode->update_cnt);
	return ret;

no_server:
	spin_lock(&vnode->lock);
	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);
	_leave(" = %ld [cnt %d]", PTR_ERR(server), vnode->update_cnt);
	return PTR_ERR(server);
}

/*
 * fetch file data from the volume
 * - TODO implement caching
 */
int afs_vnode_fetch_data(struct afs_vnode *vnode, struct key *key,
			 off_t offset, size_t length, struct page *page)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%x,,,",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key));

	/* this op will fetch the status */
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);

	/* merge in AFS status fetches and clear outstanding callback on this
	 * vnode */
	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_fetch_data(server, key, vnode, offset, length,
					page, &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0) {
		afs_vnode_finalise_status_update(vnode, server);
		afs_put_server(server);
	} else {
		afs_vnode_status_update_failed(vnode, ret);
	}

	_leave(" = %d", ret);
	return ret;

no_server:
	spin_lock(&vnode->lock);
	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);
	return PTR_ERR(server);
}

/*
 * make a file or a directory
 */
int afs_vnode_create(struct afs_vnode *vnode, struct key *key,
		     const char *name, umode_t mode, struct afs_fid *newfid,
		     struct afs_file_status *newstatus,
		     struct afs_callback *newcb, struct afs_server **_server)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%x,%s,,",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key),
	       name);

	/* this op will fetch the status on the directory we're creating in */
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_create(server, key, vnode, name, mode, newfid,
				    newstatus, newcb, &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0) {
		afs_vnode_finalise_status_update(vnode, server);
		*_server = server;
	} else {
		afs_vnode_status_update_failed(vnode, ret);
		*_server = NULL;
	}

	_leave(" = %d [cnt %d]", ret, vnode->update_cnt);
	return ret;

no_server:
	spin_lock(&vnode->lock);
	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);
	_leave(" = %ld [cnt %d]", PTR_ERR(server), vnode->update_cnt);
	return PTR_ERR(server);
}

/*
 * remove a file or directory
 */
int afs_vnode_remove(struct afs_vnode *vnode, struct key *key, const char *name,
		     bool isdir)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%x,%s",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key),
	       name);

	/* this op will fetch the status on the directory we're removing from */
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_remove(server, key, vnode, name, isdir,
				    &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0) {
		afs_vnode_finalise_status_update(vnode, server);
		afs_put_server(server);
	} else {
		afs_vnode_status_update_failed(vnode, ret);
	}

	_leave(" = %d [cnt %d]", ret, vnode->update_cnt);
	return ret;

no_server:
	spin_lock(&vnode->lock);
	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);
	_leave(" = %ld [cnt %d]", PTR_ERR(server), vnode->update_cnt);
	return PTR_ERR(server);
}

/*
 * create a hard link
 */
int afs_vnode_link(struct afs_vnode *dvnode, struct afs_vnode *vnode,
			  struct key *key, const char *name)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%s{%x:%u.%u},%x,%s",
	       dvnode->volume->vlocation->vldb.name,
	       dvnode->fid.vid,
	       dvnode->fid.vnode,
	       dvnode->fid.unique,
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key),
	       name);

	/* this op will fetch the status on the directory we're removing from */
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);
	spin_lock(&dvnode->lock);
	dvnode->update_cnt++;
	spin_unlock(&dvnode->lock);

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(dvnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_link(server, key, dvnode, vnode, name,
				  &afs_sync_call);

	} while (!afs_volume_release_fileserver(dvnode, server, ret));

	/* adjust the flags */
	if (ret == 0) {
		afs_vnode_finalise_status_update(vnode, server);
		afs_vnode_finalise_status_update(dvnode, server);
		afs_put_server(server);
	} else {
		afs_vnode_status_update_failed(vnode, ret);
		afs_vnode_status_update_failed(dvnode, ret);
	}

	_leave(" = %d [cnt %d]", ret, vnode->update_cnt);
	return ret;

no_server:
	spin_lock(&vnode->lock);
	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);
	spin_lock(&dvnode->lock);
	dvnode->update_cnt--;
	ASSERTCMP(dvnode->update_cnt, >=, 0);
	spin_unlock(&dvnode->lock);
	_leave(" = %ld [cnt %d]", PTR_ERR(server), vnode->update_cnt);
	return PTR_ERR(server);
}

/*
 * create a symbolic link
 */
int afs_vnode_symlink(struct afs_vnode *vnode, struct key *key,
		      const char *name, const char *content,
		      struct afs_fid *newfid,
		      struct afs_file_status *newstatus,
		      struct afs_server **_server)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%x,%s,%s,,,",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key),
	       name, content);

	/* this op will fetch the status on the directory we're creating in */
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_symlink(server, key, vnode, name, content,
				     newfid, newstatus, &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0) {
		afs_vnode_finalise_status_update(vnode, server);
		*_server = server;
	} else {
		afs_vnode_status_update_failed(vnode, ret);
		*_server = NULL;
	}

	_leave(" = %d [cnt %d]", ret, vnode->update_cnt);
	return ret;

no_server:
	spin_lock(&vnode->lock);
	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);
	_leave(" = %ld [cnt %d]", PTR_ERR(server), vnode->update_cnt);
	return PTR_ERR(server);
}

/*
 * rename a file
 */
int afs_vnode_rename(struct afs_vnode *orig_dvnode,
		     struct afs_vnode *new_dvnode,
		     struct key *key,
		     const char *orig_name,
		     const char *new_name)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%s{%u,%u,%u},%x,%s,%s",
	       orig_dvnode->volume->vlocation->vldb.name,
	       orig_dvnode->fid.vid,
	       orig_dvnode->fid.vnode,
	       orig_dvnode->fid.unique,
	       new_dvnode->volume->vlocation->vldb.name,
	       new_dvnode->fid.vid,
	       new_dvnode->fid.vnode,
	       new_dvnode->fid.unique,
	       key_serial(key),
	       orig_name,
	       new_name);

	/* this op will fetch the status on both the directories we're dealing
	 * with */
	spin_lock(&orig_dvnode->lock);
	orig_dvnode->update_cnt++;
	spin_unlock(&orig_dvnode->lock);
	if (new_dvnode != orig_dvnode) {
		spin_lock(&new_dvnode->lock);
		new_dvnode->update_cnt++;
		spin_unlock(&new_dvnode->lock);
	}

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(orig_dvnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_rename(server, key, orig_dvnode, orig_name,
				    new_dvnode, new_name, &afs_sync_call);

	} while (!afs_volume_release_fileserver(orig_dvnode, server, ret));

	/* adjust the flags */
	if (ret == 0) {
		afs_vnode_finalise_status_update(orig_dvnode, server);
		if (new_dvnode != orig_dvnode)
			afs_vnode_finalise_status_update(new_dvnode, server);
		afs_put_server(server);
	} else {
		afs_vnode_status_update_failed(orig_dvnode, ret);
		if (new_dvnode != orig_dvnode)
			afs_vnode_status_update_failed(new_dvnode, ret);
	}

	_leave(" = %d [cnt %d]", ret, orig_dvnode->update_cnt);
	return ret;

no_server:
	spin_lock(&orig_dvnode->lock);
	orig_dvnode->update_cnt--;
	ASSERTCMP(orig_dvnode->update_cnt, >=, 0);
	spin_unlock(&orig_dvnode->lock);
	if (new_dvnode != orig_dvnode) {
		spin_lock(&new_dvnode->lock);
		new_dvnode->update_cnt--;
		ASSERTCMP(new_dvnode->update_cnt, >=, 0);
		spin_unlock(&new_dvnode->lock);
	}
	_leave(" = %ld [cnt %d]", PTR_ERR(server), orig_dvnode->update_cnt);
	return PTR_ERR(server);
}

/*
 * write to a file
 */
int afs_vnode_store_data(struct afs_writeback *wb, pgoff_t first, pgoff_t last,
			 unsigned offset, unsigned to)
{
	struct afs_server *server;
	struct afs_vnode *vnode = wb->vnode;
	int ret;

	_enter("%s{%x:%u.%u},%x,%lx,%lx,%x,%x",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(wb->key),
	       first, last, offset, to);

	/* this op will fetch the status */
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_store_data(server, wb, first, last, offset, to,
					&afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0) {
		afs_vnode_finalise_status_update(vnode, server);
		afs_put_server(server);
	} else {
		afs_vnode_status_update_failed(vnode, ret);
	}

	_leave(" = %d", ret);
	return ret;

no_server:
	spin_lock(&vnode->lock);
	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);
	return PTR_ERR(server);
}

/*
 * set the attributes on a file
 */
int afs_vnode_setattr(struct afs_vnode *vnode, struct key *key,
		      struct iattr *attr)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%x",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key));

	/* this op will fetch the status */
	spin_lock(&vnode->lock);
	vnode->update_cnt++;
	spin_unlock(&vnode->lock);

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_setattr(server, key, vnode, attr, &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0) {
		afs_vnode_finalise_status_update(vnode, server);
		afs_put_server(server);
	} else {
		afs_vnode_status_update_failed(vnode, ret);
	}

	_leave(" = %d", ret);
	return ret;

no_server:
	spin_lock(&vnode->lock);
	vnode->update_cnt--;
	ASSERTCMP(vnode->update_cnt, >=, 0);
	spin_unlock(&vnode->lock);
	return PTR_ERR(server);
}

/*
 * get the status of a volume
 */
int afs_vnode_get_volume_status(struct afs_vnode *vnode, struct key *key,
				struct afs_volume_status *vs)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%x,",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key));

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_get_volume_status(server, key, vnode, vs, &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0)
		afs_put_server(server);

	_leave(" = %d", ret);
	return ret;

no_server:
	return PTR_ERR(server);
}

/*
 * get a lock on a file
 */
int afs_vnode_set_lock(struct afs_vnode *vnode, struct key *key,
		       afs_lock_type_t type)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%x,%u",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key), type);

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_set_lock(server, key, vnode, type, &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0)
		afs_put_server(server);

	_leave(" = %d", ret);
	return ret;

no_server:
	return PTR_ERR(server);
}

/*
 * extend a lock on a file
 */
int afs_vnode_extend_lock(struct afs_vnode *vnode, struct key *key)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%x",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key));

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_extend_lock(server, key, vnode, &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0)
		afs_put_server(server);

	_leave(" = %d", ret);
	return ret;

no_server:
	return PTR_ERR(server);
}

/*
 * release a lock on a file
 */
int afs_vnode_release_lock(struct afs_vnode *vnode, struct key *key)
{
	struct afs_server *server;
	int ret;

	_enter("%s{%x:%u.%u},%x",
	       vnode->volume->vlocation->vldb.name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       key_serial(key));

	do {
		/* pick a server to query */
		server = afs_volume_pick_fileserver(vnode);
		if (IS_ERR(server))
			goto no_server;

		_debug("USING SERVER: %08x\n", ntohl(server->addr.s_addr));

		ret = afs_fs_release_lock(server, key, vnode, &afs_sync_call);

	} while (!afs_volume_release_fileserver(vnode, server, ret));

	/* adjust the flags */
	if (ret == 0)
		afs_put_server(server);

	_leave(" = %d", ret);
	return ret;

no_server:
	return PTR_ERR(server);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/vnode.c */
/************************************************************/
/* AFS volume management
 *
 * Copyright (C) 2002, 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/kernel.h>
// #include <linux/module.h>
// #include <linux/init.h>
// #include <linux/slab.h>
// #include <linux/fs.h>
// #include <linux/pagemap.h>
// #include <linux/sched.h>
// #include "internal.h"

static const char *afs_voltypes[] = { "R/W", "R/O", "BAK" };

/*
 * lookup a volume by name
 * - this can be one of the following:
 *	"%[cell:]volume[.]"		R/W volume
 *	"#[cell:]volume[.]"		R/O or R/W volume (rwparent=0),
 *					 or R/W (rwparent=1) volume
 *	"%[cell:]volume.readonly"	R/O volume
 *	"#[cell:]volume.readonly"	R/O volume
 *	"%[cell:]volume.backup"		Backup volume
 *	"#[cell:]volume.backup"		Backup volume
 *
 * The cell name is optional, and defaults to the current cell.
 *
 * See "The Rules of Mount Point Traversal" in Chapter 5 of the AFS SysAdmin
 * Guide
 * - Rule 1: Explicit type suffix forces access of that type or nothing
 *           (no suffix, then use Rule 2 & 3)
 * - Rule 2: If parent volume is R/O, then mount R/O volume by preference, R/W
 *           if not available
 * - Rule 3: If parent volume is R/W, then only mount R/W volume unless
 *           explicitly told otherwise
 */
struct afs_volume *afs_volume_lookup(struct afs_mount_params *params)
{
	struct afs_vlocation *vlocation = NULL;
	struct afs_volume *volume = NULL;
	struct afs_server *server = NULL;
	char srvtmask;
	int ret, loop;

	_enter("{%*.*s,%d}",
	       params->volnamesz, params->volnamesz, params->volname, params->rwpath);

	/* lookup the volume location record */
	vlocation = afs_vlocation_lookup(params->cell, params->key,
					 params->volname, params->volnamesz);
	if (IS_ERR(vlocation)) {
		ret = PTR_ERR(vlocation);
		vlocation = NULL;
		goto error;
	}

	/* make the final decision on the type we want */
	ret = -ENOMEDIUM;
	if (params->force && !(vlocation->vldb.vidmask & (1 << params->type)))
		goto error;

	srvtmask = 0;
	for (loop = 0; loop < vlocation->vldb.nservers; loop++)
		srvtmask |= vlocation->vldb.srvtmask[loop];

	if (params->force) {
		if (!(srvtmask & (1 << params->type)))
			goto error;
	} else if (srvtmask & AFS_VOL_VTM_RO) {
		params->type = AFSVL_ROVOL;
	} else if (srvtmask & AFS_VOL_VTM_RW) {
		params->type = AFSVL_RWVOL;
	} else {
		goto error;
	}

	down_write(&params->cell->vl_sem);

	/* is the volume already active? */
	if (vlocation->vols[params->type]) {
		/* yes - re-use it */
		volume = vlocation->vols[params->type];
		afs_get_volume(volume);
		goto success;
	}

	/* create a new volume record */
	_debug("creating new volume record");

	ret = -ENOMEM;
	volume = kzalloc(sizeof(struct afs_volume), GFP_KERNEL);
	if (!volume)
		goto error_up;

	atomic_set(&volume->usage, 1);
	volume->type		= params->type;
	volume->type_force	= params->force;
	volume->cell		= params->cell;
	volume->vid		= vlocation->vldb.vid[params->type];

	ret = bdi_setup_and_register(&volume->bdi, "afs");
	if (ret)
		goto error_bdi;

	init_rwsem(&volume->server_sem);

	/* look up all the applicable server records */
	for (loop = 0; loop < 8; loop++) {
		if (vlocation->vldb.srvtmask[loop] & (1 << volume->type)) {
			server = afs_lookup_server(
			       volume->cell, &vlocation->vldb.servers[loop]);
			if (IS_ERR(server)) {
				ret = PTR_ERR(server);
				goto error_discard;
			}

			volume->servers[volume->nservers] = server;
			volume->nservers++;
		}
	}

	/* attach the cache and volume location */
#ifdef CONFIG_AFS_FSCACHE
	volume->cache = fscache_acquire_cookie(vlocation->cache,
					       &afs_volume_cache_index_def,
					       volume, true);
#endif
	afs_get_vlocation(vlocation);
	volume->vlocation = vlocation;

	vlocation->vols[volume->type] = volume;

success:
	_debug("kAFS selected %s volume %08x",
	       afs_voltypes[volume->type], volume->vid);
	up_write(&params->cell->vl_sem);
	afs_put_vlocation(vlocation);
	_leave(" = %p", volume);
	return volume;

	/* clean up */
error_up:
	up_write(&params->cell->vl_sem);
error:
	afs_put_vlocation(vlocation);
	_leave(" = %d", ret);
	return ERR_PTR(ret);

error_discard:
	bdi_destroy(&volume->bdi);
error_bdi:
	up_write(&params->cell->vl_sem);

	for (loop = volume->nservers - 1; loop >= 0; loop--)
		afs_put_server(volume->servers[loop]);

	kfree(volume);
	goto error;
}

/*
 * destroy a volume record
 */
void afs_put_volume(struct afs_volume *volume)
{
	struct afs_vlocation *vlocation;
	int loop;

	if (!volume)
		return;

	_enter("%p", volume);

	ASSERTCMP(atomic_read(&volume->usage), >, 0);

	vlocation = volume->vlocation;

	/* to prevent a race, the decrement and the dequeue must be effectively
	 * atomic */
	down_write(&vlocation->cell->vl_sem);

	if (likely(!atomic_dec_and_test(&volume->usage))) {
		up_write(&vlocation->cell->vl_sem);
		_leave("");
		return;
	}

	vlocation->vols[volume->type] = NULL;

	up_write(&vlocation->cell->vl_sem);

	/* finish cleaning up the volume */
#ifdef CONFIG_AFS_FSCACHE
	fscache_relinquish_cookie(volume->cache, 0);
#endif
	afs_put_vlocation(vlocation);

	for (loop = volume->nservers - 1; loop >= 0; loop--)
		afs_put_server(volume->servers[loop]);

	bdi_destroy(&volume->bdi);
	kfree(volume);

	_leave(" [destroyed]");
}

/*
 * pick a server to use to try accessing this volume
 * - returns with an elevated usage count on the server chosen
 */
struct afs_server *afs_volume_pick_fileserver(struct afs_vnode *vnode)
{
	struct afs_volume *volume = vnode->volume;
	struct afs_server *server;
	int ret, state, loop;

	_enter("%s", volume->vlocation->vldb.name);

	/* stick with the server we're already using if we can */
	if (vnode->server && vnode->server->fs_state == 0) {
		afs_get_server(vnode->server);
		_leave(" = %p [current]", vnode->server);
		return vnode->server;
	}

	down_read(&volume->server_sem);

	/* handle the no-server case */
	if (volume->nservers == 0) {
		ret = volume->rjservers ? -ENOMEDIUM : -ESTALE;
		up_read(&volume->server_sem);
		_leave(" = %d [no servers]", ret);
		return ERR_PTR(ret);
	}

	/* basically, just search the list for the first live server and use
	 * that */
	ret = 0;
	for (loop = 0; loop < volume->nservers; loop++) {
		server = volume->servers[loop];
		state = server->fs_state;

		_debug("consider %d [%d]", loop, state);

		switch (state) {
			/* found an apparently healthy server */
		case 0:
			afs_get_server(server);
			up_read(&volume->server_sem);
			_leave(" = %p (picked %08x)",
			       server, ntohl(server->addr.s_addr));
			return server;

		case -ENETUNREACH:
			if (ret == 0)
				ret = state;
			break;

		case -EHOSTUNREACH:
			if (ret == 0 ||
			    ret == -ENETUNREACH)
				ret = state;
			break;

		case -ECONNREFUSED:
			if (ret == 0 ||
			    ret == -ENETUNREACH ||
			    ret == -EHOSTUNREACH)
				ret = state;
			break;

		default:
		case -EREMOTEIO:
			if (ret == 0 ||
			    ret == -ENETUNREACH ||
			    ret == -EHOSTUNREACH ||
			    ret == -ECONNREFUSED)
				ret = state;
			break;
		}
	}

	/* no available servers
	 * - TODO: handle the no active servers case better
	 */
	up_read(&volume->server_sem);
	_leave(" = %d", ret);
	return ERR_PTR(ret);
}

/*
 * release a server after use
 * - releases the ref on the server struct that was acquired by picking
 * - records result of using a particular server to access a volume
 * - return 0 to try again, 1 if okay or to issue error
 * - the caller must release the server struct if result was 0
 */
int afs_volume_release_fileserver(struct afs_vnode *vnode,
				  struct afs_server *server,
				  int result)
{
	struct afs_volume *volume = vnode->volume;
	unsigned loop;

	_enter("%s,%08x,%d",
	       volume->vlocation->vldb.name, ntohl(server->addr.s_addr),
	       result);

	switch (result) {
		/* success */
	case 0:
		server->fs_act_jif = jiffies;
		server->fs_state = 0;
		_leave("");
		return 1;

		/* the fileserver denied all knowledge of the volume */
	case -ENOMEDIUM:
		server->fs_act_jif = jiffies;
		down_write(&volume->server_sem);

		/* firstly, find where the server is in the active list (if it
		 * is) */
		for (loop = 0; loop < volume->nservers; loop++)
			if (volume->servers[loop] == server)
				goto present;

		/* no longer there - may have been discarded by another op */
		goto try_next_server_upw;

	present:
		volume->nservers--;
		memmove(&volume->servers[loop],
			&volume->servers[loop + 1],
			sizeof(volume->servers[loop]) *
			(volume->nservers - loop));
		volume->servers[volume->nservers] = NULL;
		afs_put_server(server);
		volume->rjservers++;

		if (volume->nservers > 0)
			/* another server might acknowledge its existence */
			goto try_next_server_upw;

		/* handle the case where all the fileservers have rejected the
		 * volume
		 * - TODO: try asking the fileservers for volume information
		 * - TODO: contact the VL server again to see if the volume is
		 *         no longer registered
		 */
		up_write(&volume->server_sem);
		afs_put_server(server);
		_leave(" [completely rejected]");
		return 1;

		/* problem reaching the server */
	case -ENETUNREACH:
	case -EHOSTUNREACH:
	case -ECONNREFUSED:
	case -ETIME:
	case -ETIMEDOUT:
	case -EREMOTEIO:
		/* mark the server as dead
		 * TODO: vary dead timeout depending on error
		 */
		spin_lock(&server->fs_lock);
		if (!server->fs_state) {
			server->fs_dead_jif = jiffies + HZ * 10;
			server->fs_state = result;
			printk("kAFS: SERVER DEAD state=%d\n", result);
		}
		spin_unlock(&server->fs_lock);
		goto try_next_server;

		/* miscellaneous error */
	default:
		server->fs_act_jif = jiffies;
	case -ENOMEM:
	case -ENONET:
		/* tell the caller to accept the result */
		afs_put_server(server);
		_leave(" [local failure]");
		return 1;
	}

	/* tell the caller to loop around and try the next server */
try_next_server_upw:
	up_write(&volume->server_sem);
try_next_server:
	afs_put_server(server);
	_leave(" [try next server]");
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/volume.c */
/************************************************************/
/* handling of writes to regular files and writing back to the server
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <linux/backing-dev.h>
// #include <linux/slab.h>
// #include <linux/fs.h>
// #include <linux/pagemap.h>
// #include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/aio.h>
// #include "internal.h"
#include "../../inc/__fss.h"

static int afs_write_back_from_locked_page(struct afs_writeback *wb,
					   struct page *page);

/*
 * mark a page as having been made dirty and thus needing writeback
 */
int afs_set_page_dirty(struct page *page)
{
	_enter("");
	return __set_page_dirty_nobuffers(page);
}

/*
 * unlink a writeback record because its usage has reached zero
 * - must be called with the wb->vnode->writeback_lock held
 */
static void afs_unlink_writeback(struct afs_writeback *wb)
{
	struct afs_writeback *front;
	struct afs_vnode *vnode = wb->vnode;

	list_del_init(&wb->link);
	if (!list_empty(&vnode->writebacks)) {
		/* if an fsync rises to the front of the queue then wake it
		 * up */
		front = list_entry(vnode->writebacks.next,
				   struct afs_writeback, link);
		if (front->state == AFS_WBACK_SYNCING) {
			_debug("wake up sync");
			front->state = AFS_WBACK_COMPLETE;
			wake_up(&front->waitq);
		}
	}
}

/*
 * free a writeback record
 */
static void afs_free_writeback(struct afs_writeback *wb)
{
	_enter("");
	key_put(wb->key);
	kfree(wb);
}

/*
 * dispose of a reference to a writeback record
 */
void afs_put_writeback(struct afs_writeback *wb)
{
	struct afs_vnode *vnode = wb->vnode;

	_enter("{%d}", wb->usage);

	spin_lock(&vnode->writeback_lock);
	if (--wb->usage == 0)
		afs_unlink_writeback(wb);
	else
		wb = NULL;
	spin_unlock(&vnode->writeback_lock);
	if (wb)
		afs_free_writeback(wb);
}

/*
 * partly or wholly fill a page that's under preparation for writing
 */
static int afs_fill_page(struct afs_vnode *vnode, struct key *key,
			 loff_t pos, struct page *page)
{
	loff_t i_size;
	int ret;
	int len;

	_enter(",,%llu", (unsigned long long)pos);

	i_size = i_size_read(&vnode->vfs_inode);
	if (pos + PAGE_CACHE_SIZE > i_size)
		len = i_size - pos;
	else
		len = PAGE_CACHE_SIZE;

	ret = afs_vnode_fetch_data(vnode, key, pos, len, page);
	if (ret < 0) {
		if (ret == -ENOENT) {
			_debug("got NOENT from server"
			       " - marking file deleted and stale");
			set_bit(AFS_VNODE_DELETED, &vnode->flags);
			ret = -ESTALE;
		}
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * prepare to perform part of a write to a page
 */
int afs_write_begin(struct file *file, struct address_space *mapping,
		    loff_t pos, unsigned len, unsigned flags,
		    struct page **pagep, void **fsdata)
{
	struct afs_writeback *candidate, *wb;
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	struct page *page;
	struct key *key = file->private_data;
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + len;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	int ret;

	_enter("{%x:%u},{%lx},%u,%u",
	       vnode->fid.vid, vnode->fid.vnode, index, from, to);

	candidate = kzalloc(sizeof(*candidate), GFP_KERNEL);
	if (!candidate)
		return -ENOMEM;
	candidate->vnode = vnode;
	candidate->first = candidate->last = index;
	candidate->offset_first = from;
	candidate->to_last = to;
	INIT_LIST_HEAD(&candidate->link);
	candidate->usage = 1;
	candidate->state = AFS_WBACK_PENDING;
	init_waitqueue_head(&candidate->waitq);

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		kfree(candidate);
		return -ENOMEM;
	}
	*pagep = page;
	/* page won't leak in error case: it eventually gets cleaned off LRU */

	if (!PageUptodate(page) && len != PAGE_CACHE_SIZE) {
		ret = afs_fill_page(vnode, key, index << PAGE_CACHE_SHIFT, page);
		if (ret < 0) {
			kfree(candidate);
			_leave(" = %d [prep]", ret);
			return ret;
		}
		SetPageUptodate(page);
	}

try_again:
	spin_lock(&vnode->writeback_lock);

	/* see if this page is already pending a writeback under a suitable key
	 * - if so we can just join onto that one */
	wb = (struct afs_writeback *) page_private(page);
	if (wb) {
		if (wb->key == key && wb->state == AFS_WBACK_PENDING)
			goto subsume_in_current_wb;
		goto flush_conflicting_wb;
	}

	if (index > 0) {
		/* see if we can find an already pending writeback that we can
		 * append this page to */
		list_for_each_entry(wb, &vnode->writebacks, link) {
			if (wb->last == index - 1 && wb->key == key &&
			    wb->state == AFS_WBACK_PENDING)
				goto append_to_previous_wb;
		}
	}

	list_add_tail(&candidate->link, &vnode->writebacks);
	candidate->key = key_get(key);
	spin_unlock(&vnode->writeback_lock);
	SetPagePrivate(page);
	set_page_private(page, (unsigned long) candidate);
	_leave(" = 0 [new]");
	return 0;

subsume_in_current_wb:
	_debug("subsume");
	ASSERTRANGE(wb->first, <=, index, <=, wb->last);
	if (index == wb->first && from < wb->offset_first)
		wb->offset_first = from;
	if (index == wb->last && to > wb->to_last)
		wb->to_last = to;
	spin_unlock(&vnode->writeback_lock);
	kfree(candidate);
	_leave(" = 0 [sub]");
	return 0;

append_to_previous_wb:
	_debug("append into %lx-%lx", wb->first, wb->last);
	wb->usage++;
	wb->last++;
	wb->to_last = to;
	spin_unlock(&vnode->writeback_lock);
	SetPagePrivate(page);
	set_page_private(page, (unsigned long) wb);
	kfree(candidate);
	_leave(" = 0 [app]");
	return 0;

	/* the page is currently bound to another context, so if it's dirty we
	 * need to flush it before we can use the new context */
flush_conflicting_wb:
	_debug("flush conflict");
	if (wb->state == AFS_WBACK_PENDING)
		wb->state = AFS_WBACK_CONFLICTING;
	spin_unlock(&vnode->writeback_lock);
	if (PageDirty(page)) {
		ret = afs_write_back_from_locked_page(wb, page);
		if (ret < 0) {
			afs_put_writeback(candidate);
			_leave(" = %d", ret);
			return ret;
		}
	}

	/* the page holds a ref on the writeback record */
	afs_put_writeback(wb);
	set_page_private(page, 0);
	ClearPagePrivate(page);
	goto try_again;
}

/*
 * finalise part of a write to a page
 */
int afs_write_end(struct file *file, struct address_space *mapping,
		  loff_t pos, unsigned len, unsigned copied,
		  struct page *page, void *fsdata)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	loff_t i_size, maybe_i_size;

	_enter("{%x:%u},{%lx}",
	       vnode->fid.vid, vnode->fid.vnode, page->index);

	maybe_i_size = pos + copied;

	i_size = i_size_read(&vnode->vfs_inode);
	if (maybe_i_size > i_size) {
		spin_lock(&vnode->writeback_lock);
		i_size = i_size_read(&vnode->vfs_inode);
		if (maybe_i_size > i_size)
			i_size_write(&vnode->vfs_inode, maybe_i_size);
		spin_unlock(&vnode->writeback_lock);
	}

	set_page_dirty(page);
	if (PageDirty(page))
		_debug("dirtied");
	unlock_page(page);
	page_cache_release(page);

	return copied;
}

/*
 * kill all the pages in the given range
 */
static void afs_kill_pages(struct afs_vnode *vnode, bool error,
			   pgoff_t first, pgoff_t last)
{
	struct pagevec pv;
	unsigned count, loop;

	_enter("{%x:%u},%lx-%lx",
	       vnode->fid.vid, vnode->fid.vnode, first, last);

	pagevec_init(&pv, 0);

	do {
		_debug("kill %lx-%lx", first, last);

		count = last - first + 1;
		if (count > PAGEVEC_SIZE)
			count = PAGEVEC_SIZE;
		pv.nr = find_get_pages_contig(vnode->vfs_inode.i_mapping,
					      first, count, pv.pages);
		ASSERTCMP(pv.nr, ==, count);

		for (loop = 0; loop < count; loop++) {
			ClearPageUptodate(pv.pages[loop]);
			if (error)
				SetPageError(pv.pages[loop]);
			end_page_writeback(pv.pages[loop]);
		}

		__pagevec_release(&pv);
	} while (first < last);

	_leave("");
}

/*
 * synchronously write back the locked page and any subsequent non-locked dirty
 * pages also covered by the same writeback record
 */
static int afs_write_back_from_locked_page(struct afs_writeback *wb,
					   struct page *primary_page)
{
	struct page *pages[8], *page;
	unsigned long count;
	unsigned n, offset, to;
	pgoff_t start, first, last;
	int loop, ret;

	_enter(",%lx", primary_page->index);

	count = 1;
	if (!clear_page_dirty_for_io(primary_page))
		BUG();
	if (test_set_page_writeback(primary_page))
		BUG();

	/* find all consecutive lockable dirty pages, stopping when we find a
	 * page that is not immediately lockable, is not dirty or is missing,
	 * or we reach the end of the range */
	start = primary_page->index;
	if (start >= wb->last)
		goto no_more;
	start++;
	do {
		_debug("more %lx [%lx]", start, count);
		n = wb->last - start + 1;
		if (n > ARRAY_SIZE(pages))
			n = ARRAY_SIZE(pages);
		n = find_get_pages_contig(wb->vnode->vfs_inode.i_mapping,
					  start, n, pages);
		_debug("fgpc %u", n);
		if (n == 0)
			goto no_more;
		if (pages[0]->index != start) {
			do {
				put_page(pages[--n]);
			} while (n > 0);
			goto no_more;
		}

		for (loop = 0; loop < n; loop++) {
			page = pages[loop];
			if (page->index > wb->last)
				break;
			if (!trylock_page(page))
				break;
			if (!PageDirty(page) ||
			    page_private(page) != (unsigned long) wb) {
				unlock_page(page);
				break;
			}
			if (!clear_page_dirty_for_io(page))
				BUG();
			if (test_set_page_writeback(page))
				BUG();
			unlock_page(page);
			put_page(page);
		}
		count += loop;
		if (loop < n) {
			for (; loop < n; loop++)
				put_page(pages[loop]);
			goto no_more;
		}

		start += loop;
	} while (start <= wb->last && count < 65536);

no_more:
	/* we now have a contiguous set of dirty pages, each with writeback set
	 * and the dirty mark cleared; the first page is locked and must remain
	 * so, all the rest are unlocked */
	first = primary_page->index;
	last = first + count - 1;

	offset = (first == wb->first) ? wb->offset_first : 0;
	to = (last == wb->last) ? wb->to_last : PAGE_SIZE;

	_debug("write back %lx[%u..] to %lx[..%u]", first, offset, last, to);

	ret = afs_vnode_store_data(wb, first, last, offset, to);
	if (ret < 0) {
		switch (ret) {
		case -EDQUOT:
		case -ENOSPC:
			set_bit(AS_ENOSPC,
				&wb->vnode->vfs_inode.i_mapping->flags);
			break;
		case -EROFS:
		case -EIO:
		case -EREMOTEIO:
		case -EFBIG:
		case -ENOENT:
		case -ENOMEDIUM:
		case -ENXIO:
			afs_kill_pages(wb->vnode, true, first, last);
			set_bit(AS_EIO, &wb->vnode->vfs_inode.i_mapping->flags);
			break;
		case -EACCES:
		case -EPERM:
		case -ENOKEY:
		case -EKEYEXPIRED:
		case -EKEYREJECTED:
		case -EKEYREVOKED:
			afs_kill_pages(wb->vnode, false, first, last);
			break;
		default:
			break;
		}
	} else {
		ret = count;
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * write a page back to the server
 * - the caller locked the page for us
 */
int afs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct afs_writeback *wb;
	int ret;

	_enter("{%lx},", page->index);

	wb = (struct afs_writeback *) page_private(page);
	ASSERT(wb != NULL);

	ret = afs_write_back_from_locked_page(wb, page);
	unlock_page(page);
	if (ret < 0) {
		_leave(" = %d", ret);
		return 0;
	}

	wbc->nr_to_write -= ret;

	_leave(" = 0");
	return 0;
}

/*
 * write a region of pages back to the server
 */
static int afs_writepages_region(struct address_space *mapping,
				 struct writeback_control *wbc,
				 pgoff_t index, pgoff_t end, pgoff_t *_next)
{
	struct afs_writeback *wb;
	struct page *page;
	int ret, n;

	_enter(",,%lx,%lx,", index, end);

	do {
		n = find_get_pages_tag(mapping, &index, PAGECACHE_TAG_DIRTY,
				       1, &page);
		if (!n)
			break;

		_debug("wback %lx", page->index);

		if (page->index > end) {
			*_next = index;
			page_cache_release(page);
			_leave(" = 0 [%lx]", *_next);
			return 0;
		}

		/* at this point we hold neither mapping->tree_lock nor lock on
		 * the page itself: the page may be truncated or invalidated
		 * (changing page->mapping to NULL), or even swizzled back from
		 * swapper_space to tmpfs file mapping
		 */
		lock_page(page);

		if (page->mapping != mapping) {
			unlock_page(page);
			page_cache_release(page);
			continue;
		}

		if (wbc->sync_mode != WB_SYNC_NONE)
			wait_on_page_writeback(page);

		if (PageWriteback(page) || !PageDirty(page)) {
			unlock_page(page);
			continue;
		}

		wb = (struct afs_writeback *) page_private(page);
		ASSERT(wb != NULL);

		spin_lock(&wb->vnode->writeback_lock);
		wb->state = AFS_WBACK_WRITING;
		spin_unlock(&wb->vnode->writeback_lock);

		ret = afs_write_back_from_locked_page(wb, page);
		unlock_page(page);
		page_cache_release(page);
		if (ret < 0) {
			_leave(" = %d", ret);
			return ret;
		}

		wbc->nr_to_write -= ret;

		cond_resched();
	} while (index < end && wbc->nr_to_write > 0);

	*_next = index;
	_leave(" = 0 [%lx]", *_next);
	return 0;
}

/*
 * write some of the pending data back to the server
 */
int afs_writepages(struct address_space *mapping,
		   struct writeback_control *wbc)
{
	pgoff_t start, end, next;
	int ret;

	_enter("");

	if (wbc->range_cyclic) {
		start = mapping->writeback_index;
		end = -1;
		ret = afs_writepages_region(mapping, wbc, start, end, &next);
		if (start > 0 && wbc->nr_to_write > 0 && ret == 0)
			ret = afs_writepages_region(mapping, wbc, 0, start,
						    &next);
		mapping->writeback_index = next;
	} else if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX) {
		end = (pgoff_t)(LLONG_MAX >> PAGE_CACHE_SHIFT);
		ret = afs_writepages_region(mapping, wbc, 0, end, &next);
		if (wbc->nr_to_write > 0)
			mapping->writeback_index = next;
	} else {
		start = wbc->range_start >> PAGE_CACHE_SHIFT;
		end = wbc->range_end >> PAGE_CACHE_SHIFT;
		ret = afs_writepages_region(mapping, wbc, start, end, &next);
	}

	_leave(" = %d", ret);
	return ret;
}

/*
 * completion of write to server
 */
void afs_pages_written_back(struct afs_vnode *vnode, struct afs_call *call)
{
	struct afs_writeback *wb = call->wb;
	struct pagevec pv;
	unsigned count, loop;
	pgoff_t first = call->first, last = call->last;
	bool free_wb;

	_enter("{%x:%u},{%lx-%lx}",
	       vnode->fid.vid, vnode->fid.vnode, first, last);

	ASSERT(wb != NULL);

	pagevec_init(&pv, 0);

	do {
		_debug("done %lx-%lx", first, last);

		count = last - first + 1;
		if (count > PAGEVEC_SIZE)
			count = PAGEVEC_SIZE;
		pv.nr = find_get_pages_contig(call->mapping, first, count,
					      pv.pages);
		ASSERTCMP(pv.nr, ==, count);

		spin_lock(&vnode->writeback_lock);
		for (loop = 0; loop < count; loop++) {
			struct page *page = pv.pages[loop];
			end_page_writeback(page);
			if (page_private(page) == (unsigned long) wb) {
				set_page_private(page, 0);
				ClearPagePrivate(page);
				wb->usage--;
			}
		}
		free_wb = false;
		if (wb->usage == 0) {
			afs_unlink_writeback(wb);
			free_wb = true;
		}
		spin_unlock(&vnode->writeback_lock);
		first += count;
		if (free_wb) {
			afs_free_writeback(wb);
			wb = NULL;
		}

		__pagevec_release(&pv);
	} while (first <= last);

	_leave("");
}

/*
 * write to an AFS file
 */
ssize_t afs_file_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(iocb->ki_filp));
	ssize_t result;
	size_t count = iov_iter_count(from);

	_enter("{%x.%u},{%zu},",
	       vnode->fid.vid, vnode->fid.vnode, count);

	if (IS_SWAPFILE(&vnode->vfs_inode)) {
		printk(KERN_INFO
		       "AFS: Attempt to write to active swap file!\n");
		return -EBUSY;
	}

	if (!count)
		return 0;

	result = generic_file_write_iter(iocb, from);
	if (IS_ERR_VALUE(result)) {
		_leave(" = %zd", result);
		return result;
	}

	_leave(" = %zd", result);
	return result;
}

/*
 * flush the vnode to the fileserver
 */
int afs_writeback_all(struct afs_vnode *vnode)
{
	struct address_space *mapping = vnode->vfs_inode.i_mapping;
	struct writeback_control wbc = {
		.sync_mode	= WB_SYNC_ALL,
		.nr_to_write	= LONG_MAX,
		.range_cyclic	= 1,
	};
	int ret;

	_enter("");

	ret = mapping->a_ops->writepages(mapping, &wbc);
	__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);

	_leave(" = %d", ret);
	return ret;
}

/*
 * flush any dirty pages for this process, and check for write errors.
 * - the return status from this call provides a reliable indication of
 *   whether any write errors occurred for this process.
 */
int afs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file_inode(file);
	struct afs_writeback *wb, *xwb;
	struct afs_vnode *vnode = AFS_FS_I(inode);
	int ret;

	_enter("{%x:%u},{n=%pD},%d",
	       vnode->fid.vid, vnode->fid.vnode, file,
	       datasync);

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;
	mutex_lock(&inode->i_mutex);

	/* use a writeback record as a marker in the queue - when this reaches
	 * the front of the queue, all the outstanding writes are either
	 * completed or rejected */
	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (!wb) {
		ret = -ENOMEM;
		goto out;
	}
	wb->vnode = vnode;
	wb->first = 0;
	wb->last = -1;
	wb->offset_first = 0;
	wb->to_last = PAGE_SIZE;
	wb->usage = 1;
	wb->state = AFS_WBACK_SYNCING;
	init_waitqueue_head(&wb->waitq);

	spin_lock(&vnode->writeback_lock);
	list_for_each_entry(xwb, &vnode->writebacks, link) {
		if (xwb->state == AFS_WBACK_PENDING)
			xwb->state = AFS_WBACK_CONFLICTING;
	}
	list_add_tail(&wb->link, &vnode->writebacks);
	spin_unlock(&vnode->writeback_lock);

	/* push all the outstanding writebacks to the server */
	ret = afs_writeback_all(vnode);
	if (ret < 0) {
		afs_put_writeback(wb);
		_leave(" = %d [wb]", ret);
		goto out;
	}

	/* wait for the preceding writes to actually complete */
	ret = wait_event_interruptible(wb->waitq,
				       wb->state == AFS_WBACK_COMPLETE ||
				       vnode->writebacks.next == &wb->link);
	afs_put_writeback(wb);
	_leave(" = %d", ret);
out:
	mutex_unlock(&inode->i_mutex);
	return ret;
}

/*
 * notification that a previously read-only page is about to become writable
 * - if it returns an error, the caller will deliver a bus error signal
 */
int afs_page_mkwrite(struct vm_area_struct *vma, struct page *page)
{
	struct afs_vnode *vnode = AFS_FS_I(vma->vm_file->f_mapping->host);

	_enter("{{%x:%u}},{%lx}",
	       vnode->fid.vid, vnode->fid.vnode, page->index);

	/* wait for the page to be written to the cache before we allow it to
	 * be modified */
#ifdef CONFIG_AFS_FSCACHE
	fscache_wait_on_page_write(vnode->cache, page);
#endif

	_leave(" = 0");
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/afs/write.c */
/************************************************************/
