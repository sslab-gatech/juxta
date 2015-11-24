/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2010 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

#include "dlm_internal.h"
#include "lock.h"
#include "user.h"
#include "ast.h"
#include "../../inc/__fss.h"

static uint64_t dlm_cb_seq;
static DEFINE_SPINLOCK(dlm_cb_seq_spin);

static void dlm_dump_lkb_callbacks(struct dlm_lkb *lkb)
{
	int i;

	log_print("last_bast %x %llu flags %x mode %d sb %d %x",
		  lkb->lkb_id,
		  (unsigned long long)lkb->lkb_last_bast.seq,
		  lkb->lkb_last_bast.flags,
		  lkb->lkb_last_bast.mode,
		  lkb->lkb_last_bast.sb_status,
		  lkb->lkb_last_bast.sb_flags);

	log_print("last_cast %x %llu flags %x mode %d sb %d %x",
		  lkb->lkb_id,
		  (unsigned long long)lkb->lkb_last_cast.seq,
		  lkb->lkb_last_cast.flags,
		  lkb->lkb_last_cast.mode,
		  lkb->lkb_last_cast.sb_status,
		  lkb->lkb_last_cast.sb_flags);

	for (i = 0; i < DLM_CALLBACKS_SIZE; i++) {
		log_print("cb %x %llu flags %x mode %d sb %d %x",
			  lkb->lkb_id,
			  (unsigned long long)lkb->lkb_callbacks[i].seq,
			  lkb->lkb_callbacks[i].flags,
			  lkb->lkb_callbacks[i].mode,
			  lkb->lkb_callbacks[i].sb_status,
			  lkb->lkb_callbacks[i].sb_flags);
	}
}

int dlm_add_lkb_callback(struct dlm_lkb *lkb, uint32_t flags, int mode,
			 int status, uint32_t sbflags, uint64_t seq)
{
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;
	uint64_t prev_seq;
	int prev_mode;
	int i, rv;

	for (i = 0; i < DLM_CALLBACKS_SIZE; i++) {
		if (lkb->lkb_callbacks[i].seq)
			continue;

		/*
		 * Suppress some redundant basts here, do more on removal.
		 * Don't even add a bast if the callback just before it
		 * is a bast for the same mode or a more restrictive mode.
		 * (the addional > PR check is needed for PR/CW inversion)
		 */

		if ((i > 0) && (flags & DLM_CB_BAST) &&
		    (lkb->lkb_callbacks[i-1].flags & DLM_CB_BAST)) {

			prev_seq = lkb->lkb_callbacks[i-1].seq;
			prev_mode = lkb->lkb_callbacks[i-1].mode;

			if ((prev_mode == mode) ||
			    (prev_mode > mode && prev_mode > DLM_LOCK_PR)) {

				log_debug(ls, "skip %x add bast %llu mode %d "
					  "for bast %llu mode %d",
					  lkb->lkb_id,
					  (unsigned long long)seq,
					  mode,
					  (unsigned long long)prev_seq,
					  prev_mode);
				rv = 0;
				goto out;
			}
		}

		lkb->lkb_callbacks[i].seq = seq;
		lkb->lkb_callbacks[i].flags = flags;
		lkb->lkb_callbacks[i].mode = mode;
		lkb->lkb_callbacks[i].sb_status = status;
		lkb->lkb_callbacks[i].sb_flags = (sbflags & 0x000000FF);
		rv = 0;
		break;
	}

	if (i == DLM_CALLBACKS_SIZE) {
		log_error(ls, "no callbacks %x %llu flags %x mode %d sb %d %x",
			  lkb->lkb_id, (unsigned long long)seq,
			  flags, mode, status, sbflags);
		dlm_dump_lkb_callbacks(lkb);
		rv = -1;
		goto out;
	}
 out:
	return rv;
}

int dlm_rem_lkb_callback(struct dlm_ls *ls, struct dlm_lkb *lkb,
			 struct dlm_callback *cb, int *resid)
{
	int i, rv;

	*resid = 0;

	if (!lkb->lkb_callbacks[0].seq) {
		rv = -ENOENT;
		goto out;
	}

	/* oldest undelivered cb is callbacks[0] */

	memcpy(cb, &lkb->lkb_callbacks[0], sizeof(struct dlm_callback));
	memset(&lkb->lkb_callbacks[0], 0, sizeof(struct dlm_callback));

	/* shift others down */

	for (i = 1; i < DLM_CALLBACKS_SIZE; i++) {
		if (!lkb->lkb_callbacks[i].seq)
			break;
		memcpy(&lkb->lkb_callbacks[i-1], &lkb->lkb_callbacks[i],
		       sizeof(struct dlm_callback));
		memset(&lkb->lkb_callbacks[i], 0, sizeof(struct dlm_callback));
		(*resid)++;
	}

	/* if cb is a bast, it should be skipped if the blocking mode is
	   compatible with the last granted mode */

	if ((cb->flags & DLM_CB_BAST) && lkb->lkb_last_cast.seq) {
		if (dlm_modes_compat(cb->mode, lkb->lkb_last_cast.mode)) {
			cb->flags |= DLM_CB_SKIP;

			log_debug(ls, "skip %x bast %llu mode %d "
				  "for cast %llu mode %d",
				  lkb->lkb_id,
				  (unsigned long long)cb->seq,
				  cb->mode,
				  (unsigned long long)lkb->lkb_last_cast.seq,
				  lkb->lkb_last_cast.mode);
			rv = 0;
			goto out;
		}
	}

	if (cb->flags & DLM_CB_CAST) {
		memcpy(&lkb->lkb_last_cast, cb, sizeof(struct dlm_callback));
		lkb->lkb_last_cast_time = ktime_get();
	}

	if (cb->flags & DLM_CB_BAST) {
		memcpy(&lkb->lkb_last_bast, cb, sizeof(struct dlm_callback));
		lkb->lkb_last_bast_time = ktime_get();
	}
	rv = 0;
 out:
	return rv;
}

void dlm_add_cb(struct dlm_lkb *lkb, uint32_t flags, int mode, int status,
		uint32_t sbflags)
{
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;
	uint64_t new_seq, prev_seq;
	int rv;

	spin_lock(&dlm_cb_seq_spin);
	new_seq = ++dlm_cb_seq;
	spin_unlock(&dlm_cb_seq_spin);

	if (lkb->lkb_flags & DLM_IFL_USER) {
		dlm_user_add_ast(lkb, flags, mode, status, sbflags, new_seq);
		return;
	}

	mutex_lock(&lkb->lkb_cb_mutex);
	prev_seq = lkb->lkb_callbacks[0].seq;

	rv = dlm_add_lkb_callback(lkb, flags, mode, status, sbflags, new_seq);
	if (rv < 0)
		goto out;

	if (!prev_seq) {
		kref_get(&lkb->lkb_ref);

		if (test_bit(LSFL_CB_DELAY, &ls->ls_flags)) {
			mutex_lock(&ls->ls_cb_mutex);
			list_add(&lkb->lkb_cb_list, &ls->ls_cb_delay);
			mutex_unlock(&ls->ls_cb_mutex);
		} else {
			queue_work(ls->ls_callback_wq, &lkb->lkb_cb_work);
		}
	}
 out:
	mutex_unlock(&lkb->lkb_cb_mutex);
}

void dlm_callback_work(struct work_struct *work)
{
	struct dlm_lkb *lkb = container_of(work, struct dlm_lkb, lkb_cb_work);
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;
	void (*castfn) (void *astparam);
	void (*bastfn) (void *astparam, int mode);
	struct dlm_callback callbacks[DLM_CALLBACKS_SIZE];
	int i, rv, resid;

	memset(&callbacks, 0, sizeof(callbacks));

	mutex_lock(&lkb->lkb_cb_mutex);
	if (!lkb->lkb_callbacks[0].seq) {
		/* no callback work exists, shouldn't happen */
		log_error(ls, "dlm_callback_work %x no work", lkb->lkb_id);
		dlm_print_lkb(lkb);
		dlm_dump_lkb_callbacks(lkb);
	}

	for (i = 0; i < DLM_CALLBACKS_SIZE; i++) {
		rv = dlm_rem_lkb_callback(ls, lkb, &callbacks[i], &resid);
		if (rv < 0)
			break;
	}

	if (resid) {
		/* cbs remain, loop should have removed all, shouldn't happen */
		log_error(ls, "dlm_callback_work %x resid %d", lkb->lkb_id,
			  resid);
		dlm_print_lkb(lkb);
		dlm_dump_lkb_callbacks(lkb);
	}
	mutex_unlock(&lkb->lkb_cb_mutex);

	castfn = lkb->lkb_astfn;
	bastfn = lkb->lkb_bastfn;

	for (i = 0; i < DLM_CALLBACKS_SIZE; i++) {
		if (!callbacks[i].seq)
			break;
		if (callbacks[i].flags & DLM_CB_SKIP) {
			continue;
		} else if (callbacks[i].flags & DLM_CB_BAST) {
			bastfn(lkb->lkb_astparam, callbacks[i].mode);
		} else if (callbacks[i].flags & DLM_CB_CAST) {
			lkb->lkb_lksb->sb_status = callbacks[i].sb_status;
			lkb->lkb_lksb->sb_flags = callbacks[i].sb_flags;
			castfn(lkb->lkb_astparam);
		}
	}

	/* undo kref_get from dlm_add_callback, may cause lkb to be freed */
	dlm_put_lkb(lkb);
}

int dlm_callback_start(struct dlm_ls *ls)
{
	ls->ls_callback_wq = alloc_workqueue("dlm_callback",
					     WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!ls->ls_callback_wq) {
		log_print("can't start dlm_callback workqueue");
		return -ENOMEM;
	}
	return 0;
}

void dlm_callback_stop(struct dlm_ls *ls)
{
	if (ls->ls_callback_wq)
		destroy_workqueue(ls->ls_callback_wq);
}

void dlm_callback_suspend(struct dlm_ls *ls)
{
	set_bit(LSFL_CB_DELAY, &ls->ls_flags);

	if (ls->ls_callback_wq)
		flush_workqueue(ls->ls_callback_wq);
}

void dlm_callback_resume(struct dlm_ls *ls)
{
	struct dlm_lkb *lkb, *safe;
	int count = 0;

	clear_bit(LSFL_CB_DELAY, &ls->ls_flags);

	if (!ls->ls_callback_wq)
		return;

	mutex_lock(&ls->ls_cb_mutex);
	list_for_each_entry_safe(lkb, safe, &ls->ls_cb_delay, lkb_cb_list) {
		list_del_init(&lkb->lkb_cb_list);
		queue_work(ls->ls_callback_wq, &lkb->lkb_cb_work);
		count++;
	}
	mutex_unlock(&ls->ls_cb_mutex);

	if (count)
		log_rinfo(ls, "dlm_callback_resume %d", count);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/ast.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2011 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/configfs.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/dlmconstants.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include "../../inc/__fss.h"

#include "config.h"
#include "lowcomms.h"
#include "../../inc/__fss.h"

/*
 * /config/dlm/<cluster>/spaces/<space>/nodes/<node>/nodeid
 * /config/dlm/<cluster>/spaces/<space>/nodes/<node>/weight
 * /config/dlm/<cluster>/comms/<comm>/nodeid
 * /config/dlm/<cluster>/comms/<comm>/local
 * /config/dlm/<cluster>/comms/<comm>/addr      (write only)
 * /config/dlm/<cluster>/comms/<comm>/addr_list (read only)
 * The <cluster> level is useless, but I haven't figured out how to avoid it.
 */

static struct config_group *space_list;
static struct config_group *comm_list;
static struct dlm_comm *local_comm;
static uint32_t dlm_comm_count;

struct dlm_clusters;
struct dlm_cluster;
struct dlm_spaces;
struct dlm_space;
struct dlm_comms;
struct dlm_comm;
struct dlm_nodes;
struct dlm_node;

static struct config_group *make_cluster(struct config_group *, const char *);
static void drop_cluster(struct config_group *, struct config_item *);
static void release_cluster(struct config_item *);
static struct config_group *make_space(struct config_group *, const char *);
static void drop_space(struct config_group *, struct config_item *);
static void release_space(struct config_item *);
static struct config_item *make_comm(struct config_group *, const char *);
static void drop_comm(struct config_group *, struct config_item *);
static void release_comm(struct config_item *);
static struct config_item *make_node(struct config_group *, const char *);
static void drop_node(struct config_group *, struct config_item *);
static void release_node(struct config_item *);

static ssize_t show_cluster(struct config_item *i, struct configfs_attribute *a,
			    char *buf);
static ssize_t store_cluster(struct config_item *i,
			     struct configfs_attribute *a,
			     const char *buf, size_t len);
static ssize_t show_comm(struct config_item *i, struct configfs_attribute *a,
			 char *buf);
static ssize_t store_comm(struct config_item *i, struct configfs_attribute *a,
			  const char *buf, size_t len);
static ssize_t show_node(struct config_item *i, struct configfs_attribute *a,
			 char *buf);
static ssize_t store_node(struct config_item *i, struct configfs_attribute *a,
			  const char *buf, size_t len);

static ssize_t comm_nodeid_read(struct dlm_comm *cm, char *buf);
static ssize_t comm_nodeid_write(struct dlm_comm *cm, const char *buf,
				size_t len);
static ssize_t comm_local_read(struct dlm_comm *cm, char *buf);
static ssize_t comm_local_write(struct dlm_comm *cm, const char *buf,
				size_t len);
static ssize_t comm_addr_write(struct dlm_comm *cm, const char *buf,
				size_t len);
static ssize_t comm_addr_list_read(struct dlm_comm *cm, char *buf);
static ssize_t node_nodeid_read(struct dlm_node *nd, char *buf);
static ssize_t node_nodeid_write(struct dlm_node *nd, const char *buf,
				size_t len);
static ssize_t node_weight_read(struct dlm_node *nd, char *buf);
static ssize_t node_weight_write(struct dlm_node *nd, const char *buf,
				size_t len);

struct dlm_cluster {
	struct config_group group;
	unsigned int cl_tcp_port;
	unsigned int cl_buffer_size;
	unsigned int cl_rsbtbl_size;
	unsigned int cl_recover_timer;
	unsigned int cl_toss_secs;
	unsigned int cl_scan_secs;
	unsigned int cl_log_debug;
	unsigned int cl_protocol;
	unsigned int cl_timewarn_cs;
	unsigned int cl_waitwarn_us;
	unsigned int cl_new_rsb_count;
	unsigned int cl_recover_callbacks;
	char cl_cluster_name[DLM_LOCKSPACE_LEN];
};

enum {
	CLUSTER_ATTR_TCP_PORT = 0,
	CLUSTER_ATTR_BUFFER_SIZE,
	CLUSTER_ATTR_RSBTBL_SIZE,
	CLUSTER_ATTR_RECOVER_TIMER,
	CLUSTER_ATTR_TOSS_SECS,
	CLUSTER_ATTR_SCAN_SECS,
	CLUSTER_ATTR_LOG_DEBUG,
	CLUSTER_ATTR_PROTOCOL,
	CLUSTER_ATTR_TIMEWARN_CS,
	CLUSTER_ATTR_WAITWARN_US,
	CLUSTER_ATTR_NEW_RSB_COUNT,
	CLUSTER_ATTR_RECOVER_CALLBACKS,
	CLUSTER_ATTR_CLUSTER_NAME,
};

struct cluster_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(struct dlm_cluster *, char *);
	ssize_t (*store)(struct dlm_cluster *, const char *, size_t);
};

static ssize_t cluster_cluster_name_read(struct dlm_cluster *cl, char *buf)
{
	return sprintf(buf, "%s\n", cl->cl_cluster_name);
}

static ssize_t cluster_cluster_name_write(struct dlm_cluster *cl,
					  const char *buf, size_t len)
{
	strlcpy(dlm_config.ci_cluster_name, buf,
				sizeof(dlm_config.ci_cluster_name));
	strlcpy(cl->cl_cluster_name, buf, sizeof(cl->cl_cluster_name));
	return len;
}

static struct cluster_attribute cluster_attr_cluster_name = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "cluster_name",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.show   = cluster_cluster_name_read,
	.store  = cluster_cluster_name_write,
};

static ssize_t cluster_set(struct dlm_cluster *cl, unsigned int *cl_field,
			   int *info_field, int check_zero,
			   const char *buf, size_t len)
{
	unsigned int x;
	int rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	rc = kstrtouint(buf, 0, &x);
	if (rc)
		return rc;

	if (check_zero && !x)
		return -EINVAL;

	*cl_field = x;
	*info_field = x;

	return len;
}

#define CLUSTER_ATTR(name, check_zero)                                        \
static ssize_t name##_write(struct dlm_cluster *cl, const char *buf, size_t len) \
{                                                                             \
	return cluster_set(cl, &cl->cl_##name, &dlm_config.ci_##name,         \
			   check_zero, buf, len);                             \
}                                                                             \
static ssize_t name##_read(struct dlm_cluster *cl, char *buf)                 \
{                                                                             \
	return snprintf(buf, PAGE_SIZE, "%u\n", cl->cl_##name);               \
}                                                                             \
static struct cluster_attribute cluster_attr_##name =                         \
__CONFIGFS_ATTR(name, 0644, name##_read, name##_write)

CLUSTER_ATTR(tcp_port, 1);
CLUSTER_ATTR(buffer_size, 1);
CLUSTER_ATTR(rsbtbl_size, 1);
CLUSTER_ATTR(recover_timer, 1);
CLUSTER_ATTR(toss_secs, 1);
CLUSTER_ATTR(scan_secs, 1);
CLUSTER_ATTR(log_debug, 0);
CLUSTER_ATTR(protocol, 0);
CLUSTER_ATTR(timewarn_cs, 1);
CLUSTER_ATTR(waitwarn_us, 0);
CLUSTER_ATTR(new_rsb_count, 0);
CLUSTER_ATTR(recover_callbacks, 0);

static struct configfs_attribute *cluster_attrs[] = {
	[CLUSTER_ATTR_TCP_PORT] = &cluster_attr_tcp_port.attr,
	[CLUSTER_ATTR_BUFFER_SIZE] = &cluster_attr_buffer_size.attr,
	[CLUSTER_ATTR_RSBTBL_SIZE] = &cluster_attr_rsbtbl_size.attr,
	[CLUSTER_ATTR_RECOVER_TIMER] = &cluster_attr_recover_timer.attr,
	[CLUSTER_ATTR_TOSS_SECS] = &cluster_attr_toss_secs.attr,
	[CLUSTER_ATTR_SCAN_SECS] = &cluster_attr_scan_secs.attr,
	[CLUSTER_ATTR_LOG_DEBUG] = &cluster_attr_log_debug.attr,
	[CLUSTER_ATTR_PROTOCOL] = &cluster_attr_protocol.attr,
	[CLUSTER_ATTR_TIMEWARN_CS] = &cluster_attr_timewarn_cs.attr,
	[CLUSTER_ATTR_WAITWARN_US] = &cluster_attr_waitwarn_us.attr,
	[CLUSTER_ATTR_NEW_RSB_COUNT] = &cluster_attr_new_rsb_count.attr,
	[CLUSTER_ATTR_RECOVER_CALLBACKS] = &cluster_attr_recover_callbacks.attr,
	[CLUSTER_ATTR_CLUSTER_NAME] = &cluster_attr_cluster_name.attr,
	NULL,
};

enum {
	COMM_ATTR_NODEID = 0,
	COMM_ATTR_LOCAL,
	COMM_ATTR_ADDR,
	COMM_ATTR_ADDR_LIST,
};

struct comm_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(struct dlm_comm *, char *);
	ssize_t (*store)(struct dlm_comm *, const char *, size_t);
};

static struct comm_attribute comm_attr_nodeid = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "nodeid",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.show   = comm_nodeid_read,
	.store  = comm_nodeid_write,
};

static struct comm_attribute comm_attr_local = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "local",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.show   = comm_local_read,
	.store  = comm_local_write,
};

static struct comm_attribute comm_attr_addr = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "addr",
                    .ca_mode = S_IWUSR },
	.store  = comm_addr_write,
};

static struct comm_attribute comm_attr_addr_list = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "addr_list",
                    .ca_mode = S_IRUGO },
	.show   = comm_addr_list_read,
};

static struct configfs_attribute *comm_attrs[] = {
	[COMM_ATTR_NODEID] = &comm_attr_nodeid.attr,
	[COMM_ATTR_LOCAL] = &comm_attr_local.attr,
	[COMM_ATTR_ADDR] = &comm_attr_addr.attr,
	[COMM_ATTR_ADDR_LIST] = &comm_attr_addr_list.attr,
	NULL,
};

enum {
	NODE_ATTR_NODEID = 0,
	NODE_ATTR_WEIGHT,
};

struct node_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(struct dlm_node *, char *);
	ssize_t (*store)(struct dlm_node *, const char *, size_t);
};

static struct node_attribute node_attr_nodeid = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "nodeid",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.show   = node_nodeid_read,
	.store  = node_nodeid_write,
};

static struct node_attribute node_attr_weight = {
	.attr   = { .ca_owner = THIS_MODULE,
                    .ca_name = "weight",
                    .ca_mode = S_IRUGO | S_IWUSR },
	.show   = node_weight_read,
	.store  = node_weight_write,
};

static struct configfs_attribute *node_attrs[] = {
	[NODE_ATTR_NODEID] = &node_attr_nodeid.attr,
	[NODE_ATTR_WEIGHT] = &node_attr_weight.attr,
	NULL,
};

struct dlm_clusters {
	struct configfs_subsystem subsys;
};

struct dlm_spaces {
	struct config_group ss_group;
};

struct dlm_space {
	struct config_group group;
	struct list_head members;
	struct mutex members_lock;
	int members_count;
};

struct dlm_comms {
	struct config_group cs_group;
};

struct dlm_comm {
	struct config_item item;
	int seq;
	int nodeid;
	int local;
	int addr_count;
	struct sockaddr_storage *addr[DLM_MAX_ADDR_COUNT];
};

struct dlm_nodes {
	struct config_group ns_group;
};

struct dlm_node {
	struct config_item item;
	struct list_head list; /* space->members */
	int nodeid;
	int weight;
	int new;
	int comm_seq; /* copy of cm->seq when nd->nodeid is set */
};

static struct configfs_group_operations clusters_ops = {
	.make_group = make_cluster,
	.drop_item = drop_cluster,
};

static struct configfs_item_operations cluster_ops = {
	.release = release_cluster,
	.show_attribute = show_cluster,
	.store_attribute = store_cluster,
};

static struct configfs_group_operations spaces_ops = {
	.make_group = make_space,
	.drop_item = drop_space,
};

static struct configfs_item_operations space_ops = {
	.release = release_space,
};

static struct configfs_group_operations comms_ops = {
	.make_item = make_comm,
	.drop_item = drop_comm,
};

static struct configfs_item_operations comm_ops = {
	.release = release_comm,
	.show_attribute = show_comm,
	.store_attribute = store_comm,
};

static struct configfs_group_operations nodes_ops = {
	.make_item = make_node,
	.drop_item = drop_node,
};

static struct configfs_item_operations node_ops = {
	.release = release_node,
	.show_attribute = show_node,
	.store_attribute = store_node,
};

static struct config_item_type clusters_type = {
	.ct_group_ops = &clusters_ops,
	.ct_owner = THIS_MODULE,
};

static struct config_item_type cluster_type = {
	.ct_item_ops = &cluster_ops,
	.ct_attrs = cluster_attrs,
	.ct_owner = THIS_MODULE,
};

static struct config_item_type spaces_type = {
	.ct_group_ops = &spaces_ops,
	.ct_owner = THIS_MODULE,
};

static struct config_item_type space_type = {
	.ct_item_ops = &space_ops,
	.ct_owner = THIS_MODULE,
};

static struct config_item_type comms_type = {
	.ct_group_ops = &comms_ops,
	.ct_owner = THIS_MODULE,
};

static struct config_item_type comm_type = {
	.ct_item_ops = &comm_ops,
	.ct_attrs = comm_attrs,
	.ct_owner = THIS_MODULE,
};

static struct config_item_type nodes_type = {
	.ct_group_ops = &nodes_ops,
	.ct_owner = THIS_MODULE,
};

static struct config_item_type node_type = {
	.ct_item_ops = &node_ops,
	.ct_attrs = node_attrs,
	.ct_owner = THIS_MODULE,
};

static struct dlm_cluster *config_item_to_cluster(struct config_item *i)
{
	return i ? container_of(to_config_group(i), struct dlm_cluster, group) :
		   NULL;
}

static struct dlm_space *config_item_to_space(struct config_item *i)
{
	return i ? container_of(to_config_group(i), struct dlm_space, group) :
		   NULL;
}

static struct dlm_comm *config_item_to_comm(struct config_item *i)
{
	return i ? container_of(i, struct dlm_comm, item) : NULL;
}

static struct dlm_node *config_item_to_node(struct config_item *i)
{
	return i ? container_of(i, struct dlm_node, item) : NULL;
}

static struct config_group *make_cluster(struct config_group *g,
					 const char *name)
{
	struct dlm_cluster *cl = NULL;
	struct dlm_spaces *sps = NULL;
	struct dlm_comms *cms = NULL;
	void *gps = NULL;

	cl = kzalloc(sizeof(struct dlm_cluster), GFP_NOFS);
	gps = kcalloc(3, sizeof(struct config_group *), GFP_NOFS);
	sps = kzalloc(sizeof(struct dlm_spaces), GFP_NOFS);
	cms = kzalloc(sizeof(struct dlm_comms), GFP_NOFS);

	if (!cl || !gps || !sps || !cms)
		goto fail;

	config_group_init_type_name(&cl->group, name, &cluster_type);
	config_group_init_type_name(&sps->ss_group, "spaces", &spaces_type);
	config_group_init_type_name(&cms->cs_group, "comms", &comms_type);

	cl->group.default_groups = gps;
	cl->group.default_groups[0] = &sps->ss_group;
	cl->group.default_groups[1] = &cms->cs_group;
	cl->group.default_groups[2] = NULL;

	cl->cl_tcp_port = dlm_config.ci_tcp_port;
	cl->cl_buffer_size = dlm_config.ci_buffer_size;
	cl->cl_rsbtbl_size = dlm_config.ci_rsbtbl_size;
	cl->cl_recover_timer = dlm_config.ci_recover_timer;
	cl->cl_toss_secs = dlm_config.ci_toss_secs;
	cl->cl_scan_secs = dlm_config.ci_scan_secs;
	cl->cl_log_debug = dlm_config.ci_log_debug;
	cl->cl_protocol = dlm_config.ci_protocol;
	cl->cl_timewarn_cs = dlm_config.ci_timewarn_cs;
	cl->cl_waitwarn_us = dlm_config.ci_waitwarn_us;
	cl->cl_new_rsb_count = dlm_config.ci_new_rsb_count;
	cl->cl_recover_callbacks = dlm_config.ci_recover_callbacks;
	memcpy(cl->cl_cluster_name, dlm_config.ci_cluster_name,
	       DLM_LOCKSPACE_LEN);

	space_list = &sps->ss_group;
	comm_list = &cms->cs_group;
	return &cl->group;

 fail:
	kfree(cl);
	kfree(gps);
	kfree(sps);
	kfree(cms);
	return ERR_PTR(-ENOMEM);
}

static void drop_cluster(struct config_group *g, struct config_item *i)
{
	struct dlm_cluster *cl = config_item_to_cluster(i);
	struct config_item *tmp;
	int j;

	for (j = 0; cl->group.default_groups[j]; j++) {
		tmp = &cl->group.default_groups[j]->cg_item;
		cl->group.default_groups[j] = NULL;
		config_item_put(tmp);
	}

	space_list = NULL;
	comm_list = NULL;

	config_item_put(i);
}

static void release_cluster(struct config_item *i)
{
	struct dlm_cluster *cl = config_item_to_cluster(i);
	kfree(cl->group.default_groups);
	kfree(cl);
}

static struct config_group *make_space(struct config_group *g, const char *name)
{
	struct dlm_space *sp = NULL;
	struct dlm_nodes *nds = NULL;
	void *gps = NULL;

	sp = kzalloc(sizeof(struct dlm_space), GFP_NOFS);
	gps = kcalloc(2, sizeof(struct config_group *), GFP_NOFS);
	nds = kzalloc(sizeof(struct dlm_nodes), GFP_NOFS);

	if (!sp || !gps || !nds)
		goto fail;

	config_group_init_type_name(&sp->group, name, &space_type);
	config_group_init_type_name(&nds->ns_group, "nodes", &nodes_type);

	sp->group.default_groups = gps;
	sp->group.default_groups[0] = &nds->ns_group;
	sp->group.default_groups[1] = NULL;

	INIT_LIST_HEAD(&sp->members);
	mutex_init(&sp->members_lock);
	sp->members_count = 0;
	return &sp->group;

 fail:
	kfree(sp);
	kfree(gps);
	kfree(nds);
	return ERR_PTR(-ENOMEM);
}

static void drop_space(struct config_group *g, struct config_item *i)
{
	struct dlm_space *sp = config_item_to_space(i);
	struct config_item *tmp;
	int j;

	/* assert list_empty(&sp->members) */

	for (j = 0; sp->group.default_groups[j]; j++) {
		tmp = &sp->group.default_groups[j]->cg_item;
		sp->group.default_groups[j] = NULL;
		config_item_put(tmp);
	}

	config_item_put(i);
}

static void release_space(struct config_item *i)
{
	struct dlm_space *sp = config_item_to_space(i);
	kfree(sp->group.default_groups);
	kfree(sp);
}

static struct config_item *make_comm(struct config_group *g, const char *name)
{
	struct dlm_comm *cm;

	cm = kzalloc(sizeof(struct dlm_comm), GFP_NOFS);
	if (!cm)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&cm->item, name, &comm_type);

	cm->seq = dlm_comm_count++;
	if (!cm->seq)
		cm->seq = dlm_comm_count++;

	cm->nodeid = -1;
	cm->local = 0;
	cm->addr_count = 0;
	return &cm->item;
}

static void drop_comm(struct config_group *g, struct config_item *i)
{
	struct dlm_comm *cm = config_item_to_comm(i);
	if (local_comm == cm)
		local_comm = NULL;
	dlm_lowcomms_close(cm->nodeid);
	while (cm->addr_count--)
		kfree(cm->addr[cm->addr_count]);
	config_item_put(i);
}

static void release_comm(struct config_item *i)
{
	struct dlm_comm *cm = config_item_to_comm(i);
	kfree(cm);
}

static struct config_item *make_node(struct config_group *g, const char *name)
{
	struct dlm_space *sp = config_item_to_space(g->cg_item.ci_parent);
	struct dlm_node *nd;

	nd = kzalloc(sizeof(struct dlm_node), GFP_NOFS);
	if (!nd)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&nd->item, name, &node_type);
	nd->nodeid = -1;
	nd->weight = 1;  /* default weight of 1 if none is set */
	nd->new = 1;     /* set to 0 once it's been read by dlm_nodeid_list() */

	mutex_lock(&sp->members_lock);
	list_add(&nd->list, &sp->members);
	sp->members_count++;
	mutex_unlock(&sp->members_lock);

	return &nd->item;
}

static void drop_node(struct config_group *g, struct config_item *i)
{
	struct dlm_space *sp = config_item_to_space(g->cg_item.ci_parent);
	struct dlm_node *nd = config_item_to_node(i);

	mutex_lock(&sp->members_lock);
	list_del(&nd->list);
	sp->members_count--;
	mutex_unlock(&sp->members_lock);

	config_item_put(i);
}

static void release_node(struct config_item *i)
{
	struct dlm_node *nd = config_item_to_node(i);
	kfree(nd);
}

static struct dlm_clusters clusters_root = {
	.subsys = {
		.su_group = {
			.cg_item = {
				.ci_namebuf = "dlm",
				.ci_type = &clusters_type,
			},
		},
	},
};

int __init dlm_config_init(void)
{
	config_group_init(&clusters_root.subsys.su_group);
	mutex_init(&clusters_root.subsys.su_mutex);
	return configfs_register_subsystem(&clusters_root.subsys);
}

void dlm_config_exit(void)
{
	configfs_unregister_subsystem(&clusters_root.subsys);
}

/*
 * Functions for user space to read/write attributes
 */

static ssize_t show_cluster(struct config_item *i, struct configfs_attribute *a,
			    char *buf)
{
	struct dlm_cluster *cl = config_item_to_cluster(i);
	struct cluster_attribute *cla =
			container_of(a, struct cluster_attribute, attr);
	return cla->show ? cla->show(cl, buf) : 0;
}

static ssize_t store_cluster(struct config_item *i,
			     struct configfs_attribute *a,
			     const char *buf, size_t len)
{
	struct dlm_cluster *cl = config_item_to_cluster(i);
	struct cluster_attribute *cla =
		container_of(a, struct cluster_attribute, attr);
	return cla->store ? cla->store(cl, buf, len) : -EINVAL;
}

static ssize_t show_comm(struct config_item *i, struct configfs_attribute *a,
			 char *buf)
{
	struct dlm_comm *cm = config_item_to_comm(i);
	struct comm_attribute *cma =
			container_of(a, struct comm_attribute, attr);
	return cma->show ? cma->show(cm, buf) : 0;
}

static ssize_t store_comm(struct config_item *i, struct configfs_attribute *a,
			  const char *buf, size_t len)
{
	struct dlm_comm *cm = config_item_to_comm(i);
	struct comm_attribute *cma =
		container_of(a, struct comm_attribute, attr);
	return cma->store ? cma->store(cm, buf, len) : -EINVAL;
}

static ssize_t comm_nodeid_read(struct dlm_comm *cm, char *buf)
{
	return sprintf(buf, "%d\n", cm->nodeid);
}

static ssize_t comm_nodeid_write(struct dlm_comm *cm, const char *buf,
				 size_t len)
{
	int rc = kstrtoint(buf, 0, &cm->nodeid);

	if (rc)
		return rc;
	return len;
}

static ssize_t comm_local_read(struct dlm_comm *cm, char *buf)
{
	return sprintf(buf, "%d\n", cm->local);
}

static ssize_t comm_local_write(struct dlm_comm *cm, const char *buf,
				size_t len)
{
	int rc = kstrtoint(buf, 0, &cm->local);

	if (rc)
		return rc;
	if (cm->local && !local_comm)
		local_comm = cm;
	return len;
}

static ssize_t comm_addr_write(struct dlm_comm *cm, const char *buf, size_t len)
{
	struct sockaddr_storage *addr;
	int rv;

	if (len != sizeof(struct sockaddr_storage))
		return -EINVAL;

	if (cm->addr_count >= DLM_MAX_ADDR_COUNT)
		return -ENOSPC;

	addr = kzalloc(sizeof(*addr), GFP_NOFS);
	if (!addr)
		return -ENOMEM;

	memcpy(addr, buf, len);

	rv = dlm_lowcomms_addr(cm->nodeid, addr, len);
	if (rv) {
		kfree(addr);
		return rv;
	}

	cm->addr[cm->addr_count++] = addr;
	return len;
}

static ssize_t comm_addr_list_read(struct dlm_comm *cm, char *buf)
{
	ssize_t s;
	ssize_t allowance;
	int i;
	struct sockaddr_storage *addr;
	struct sockaddr_in *addr_in;
	struct sockaddr_in6 *addr_in6;
	
	/* Taken from ip6_addr_string() defined in lib/vsprintf.c */
	char buf0[sizeof("AF_INET6	xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255\n")];
	

	/* Derived from SIMPLE_ATTR_SIZE of fs/configfs/file.c */
	allowance = 4096;
	buf[0] = '\0';

	for (i = 0; i < cm->addr_count; i++) {
		addr = cm->addr[i];

		switch(addr->ss_family) {
		case AF_INET:
			addr_in = (struct sockaddr_in *)addr;
			s = sprintf(buf0, "AF_INET	%pI4\n", &addr_in->sin_addr.s_addr);
			break;
		case AF_INET6:
			addr_in6 = (struct sockaddr_in6 *)addr;
			s = sprintf(buf0, "AF_INET6	%pI6\n", &addr_in6->sin6_addr);
			break;
		default:
			s = sprintf(buf0, "%s\n", "<UNKNOWN>");
			break;
		}
		allowance -= s;
		if (allowance >= 0)
			strcat(buf, buf0);
		else {
			allowance += s;
			break;
		}
	}
	return 4096 - allowance;
}

static ssize_t show_node(struct config_item *i, struct configfs_attribute *a,
			 char *buf)
{
	struct dlm_node *nd = config_item_to_node(i);
	struct node_attribute *nda =
			container_of(a, struct node_attribute, attr);
	return nda->show ? nda->show(nd, buf) : 0;
}

static ssize_t store_node(struct config_item *i, struct configfs_attribute *a,
			  const char *buf, size_t len)
{
	struct dlm_node *nd = config_item_to_node(i);
	struct node_attribute *nda =
		container_of(a, struct node_attribute, attr);
	return nda->store ? nda->store(nd, buf, len) : -EINVAL;
}

static ssize_t node_nodeid_read(struct dlm_node *nd, char *buf)
{
	return sprintf(buf, "%d\n", nd->nodeid);
}

static ssize_t node_nodeid_write(struct dlm_node *nd, const char *buf,
				 size_t len)
{
	uint32_t seq = 0;
	int rc = kstrtoint(buf, 0, &nd->nodeid);

	if (rc)
		return rc;
	dlm_comm_seq(nd->nodeid, &seq);
	nd->comm_seq = seq;
	return len;
}

static ssize_t node_weight_read(struct dlm_node *nd, char *buf)
{
	return sprintf(buf, "%d\n", nd->weight);
}

static ssize_t node_weight_write(struct dlm_node *nd, const char *buf,
				 size_t len)
{
	int rc = kstrtoint(buf, 0, &nd->weight);

	if (rc)
		return rc;
	return len;
}

/*
 * Functions for the dlm to get the info that's been configured
 */

static struct dlm_space *get_space(char *name)
{
	struct config_item *i;

	if (!space_list)
		return NULL;

	mutex_lock(&space_list->cg_subsys->su_mutex);
	i = config_group_find_item(space_list, name);
	mutex_unlock(&space_list->cg_subsys->su_mutex);

	return config_item_to_space(i);
}

static void put_space(struct dlm_space *sp)
{
	config_item_put(&sp->group.cg_item);
}

static struct dlm_comm *get_comm(int nodeid)
{
	struct config_item *i;
	struct dlm_comm *cm = NULL;
	int found = 0;

	if (!comm_list)
		return NULL;

	mutex_lock(&clusters_root.subsys.su_mutex);

	list_for_each_entry(i, &comm_list->cg_children, ci_entry) {
		cm = config_item_to_comm(i);

		if (cm->nodeid != nodeid)
			continue;
		found = 1;
		config_item_get(i);
		break;
	}
	mutex_unlock(&clusters_root.subsys.su_mutex);

	if (!found)
		cm = NULL;
	return cm;
}

static void put_comm(struct dlm_comm *cm)
{
	config_item_put(&cm->item);
}

/* caller must free mem */
int dlm_config_nodes(char *lsname, struct dlm_config_node **nodes_out,
		     int *count_out)
{
	struct dlm_space *sp;
	struct dlm_node *nd;
	struct dlm_config_node *nodes, *node;
	int rv, count;

	sp = get_space(lsname);
	if (!sp)
		return -EEXIST;

	mutex_lock(&sp->members_lock);
	if (!sp->members_count) {
		rv = -EINVAL;
		printk(KERN_ERR "dlm: zero members_count\n");
		goto out;
	}

	count = sp->members_count;

	nodes = kcalloc(count, sizeof(struct dlm_config_node), GFP_NOFS);
	if (!nodes) {
		rv = -ENOMEM;
		goto out;
	}

	node = nodes;
	list_for_each_entry(nd, &sp->members, list) {
		node->nodeid = nd->nodeid;
		node->weight = nd->weight;
		node->new = nd->new;
		node->comm_seq = nd->comm_seq;
		node++;

		nd->new = 0;
	}

	*count_out = count;
	*nodes_out = nodes;
	rv = 0;
 out:
	mutex_unlock(&sp->members_lock);
	put_space(sp);
	return rv;
}

int dlm_comm_seq(int nodeid, uint32_t *seq)
{
	struct dlm_comm *cm = get_comm(nodeid);
	if (!cm)
		return -EEXIST;
	*seq = cm->seq;
	put_comm(cm);
	return 0;
}

int dlm_our_nodeid(void)
{
	return local_comm ? local_comm->nodeid : 0;
}

/* num 0 is first addr, num 1 is second addr */
int dlm_our_addr(struct sockaddr_storage *addr, int num)
{
	if (!local_comm)
		return -1;
	if (num + 1 > local_comm->addr_count)
		return -1;
	memcpy(addr, local_comm->addr[num], sizeof(*addr));
	return 0;
}

/* Config file defaults */
#define DEFAULT_TCP_PORT       21064
#define DEFAULT_BUFFER_SIZE     4096
#define DEFAULT_RSBTBL_SIZE     1024
#define DEFAULT_RECOVER_TIMER      5
#define DEFAULT_TOSS_SECS         10
#define DEFAULT_SCAN_SECS          5
#define DEFAULT_LOG_DEBUG          0
#define DEFAULT_PROTOCOL           0
#define DEFAULT_TIMEWARN_CS      500 /* 5 sec = 500 centiseconds */
#define DEFAULT_WAITWARN_US	   0
#define DEFAULT_NEW_RSB_COUNT    128
#define DEFAULT_RECOVER_CALLBACKS  0
#define DEFAULT_CLUSTER_NAME      ""

struct dlm_config_info dlm_config = {
	.ci_tcp_port = DEFAULT_TCP_PORT,
	.ci_buffer_size = DEFAULT_BUFFER_SIZE,
	.ci_rsbtbl_size = DEFAULT_RSBTBL_SIZE,
	.ci_recover_timer = DEFAULT_RECOVER_TIMER,
	.ci_toss_secs = DEFAULT_TOSS_SECS,
	.ci_scan_secs = DEFAULT_SCAN_SECS,
	.ci_log_debug = DEFAULT_LOG_DEBUG,
	.ci_protocol = DEFAULT_PROTOCOL,
	.ci_timewarn_cs = DEFAULT_TIMEWARN_CS,
	.ci_waitwarn_us = DEFAULT_WAITWARN_US,
	.ci_new_rsb_count = DEFAULT_NEW_RSB_COUNT,
	.ci_recover_callbacks = DEFAULT_RECOVER_CALLBACKS,
	.ci_cluster_name = DEFAULT_CLUSTER_NAME
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/config.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2005 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
#include "lockspace.h"
#include "member.h"
// #include "lowcomms.h"
#include "rcom.h"
// #include "config.h"
#include "memory.h"
#include "recover.h"
#include "util.h"
// #include "lock.h"
#include "dir.h"
#include "../../inc/__fss.h"

/*
 * We use the upper 16 bits of the hash value to select the directory node.
 * Low bits are used for distribution of rsb's among hash buckets on each node.
 *
 * To give the exact range wanted (0 to num_nodes-1), we apply a modulus of
 * num_nodes to the hash value.  This value in the desired range is used as an
 * offset into the sorted list of nodeid's to give the particular nodeid.
 */

int dlm_hash2nodeid(struct dlm_ls *ls, uint32_t hash)
{
	uint32_t node;

	if (ls->ls_num_nodes == 1)
		return dlm_our_nodeid();
	else {
		node = (hash >> 16) % ls->ls_total_weight;
		return ls->ls_node_array[node];
	}
}

int dlm_dir_nodeid(struct dlm_rsb *r)
{
	return r->res_dir_nodeid;
}

void dlm_recover_dir_nodeid(struct dlm_ls *ls)
{
	struct dlm_rsb *r;

	down_read(&ls->ls_root_sem);
	list_for_each_entry(r, &ls->ls_root_list, res_root_list) {
		r->res_dir_nodeid = dlm_hash2nodeid(ls, r->res_hash);
	}
	up_read(&ls->ls_root_sem);
}

int dlm_recover_directory(struct dlm_ls *ls)
{
	struct dlm_member *memb;
	char *b, *last_name = NULL;
	int error = -ENOMEM, last_len, nodeid, result;
	uint16_t namelen;
	unsigned int count = 0, count_match = 0, count_bad = 0, count_add = 0;

	log_rinfo(ls, "dlm_recover_directory");

	if (dlm_no_directory(ls))
		goto out_status;

	last_name = kmalloc(DLM_RESNAME_MAXLEN, GFP_NOFS);
	if (!last_name)
		goto out;

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		if (memb->nodeid == dlm_our_nodeid())
			continue;

		memset(last_name, 0, DLM_RESNAME_MAXLEN);
		last_len = 0;

		for (;;) {
			int left;
			error = dlm_recovery_stopped(ls);
			if (error)
				goto out_free;

			error = dlm_rcom_names(ls, memb->nodeid,
					       last_name, last_len);
			if (error)
				goto out_free;

			cond_resched();

			/*
			 * pick namelen/name pairs out of received buffer
			 */

			b = ls->ls_recover_buf->rc_buf;
			left = ls->ls_recover_buf->rc_header.h_length;
			left -= sizeof(struct dlm_rcom);

			for (;;) {
				__be16 v;

				error = -EINVAL;
				if (left < sizeof(__be16))
					goto out_free;

				memcpy(&v, b, sizeof(__be16));
				namelen = be16_to_cpu(v);
				b += sizeof(__be16);
				left -= sizeof(__be16);

				/* namelen of 0xFFFFF marks end of names for
				   this node; namelen of 0 marks end of the
				   buffer */

				if (namelen == 0xFFFF)
					goto done;
				if (!namelen)
					break;

				if (namelen > left)
					goto out_free;

				if (namelen > DLM_RESNAME_MAXLEN)
					goto out_free;

				error = dlm_master_lookup(ls, memb->nodeid,
							  b, namelen,
							  DLM_LU_RECOVER_DIR,
							  &nodeid, &result);
				if (error) {
					log_error(ls, "recover_dir lookup %d",
						  error);
					goto out_free;
				}

				/* The name was found in rsbtbl, but the
				 * master nodeid is different from
				 * memb->nodeid which says it is the master.
				 * This should not happen. */

				if (result == DLM_LU_MATCH &&
				    nodeid != memb->nodeid) {
					count_bad++;
					log_error(ls, "recover_dir lookup %d "
						  "nodeid %d memb %d bad %u",
						  result, nodeid, memb->nodeid,
						  count_bad);
					print_hex_dump_bytes("dlm_recover_dir ",
							     DUMP_PREFIX_NONE,
							     b, namelen);
				}

				/* The name was found in rsbtbl, and the
				 * master nodeid matches memb->nodeid. */

				if (result == DLM_LU_MATCH &&
				    nodeid == memb->nodeid) {
					count_match++;
				}

				/* The name was not found in rsbtbl and was
				 * added with memb->nodeid as the master. */

				if (result == DLM_LU_ADD) {
					count_add++;
				}

				last_len = namelen;
				memcpy(last_name, b, namelen);
				b += namelen;
				left -= namelen;
				count++;
			}
		}
	 done:
		;
	}

 out_status:
	error = 0;
	dlm_set_recover_status(ls, DLM_RS_DIR);

	log_rinfo(ls, "dlm_recover_directory %u in %u new",
		  count, count_add);
 out_free:
	kfree(last_name);
 out:
	return error;
}

static struct dlm_rsb *find_rsb_root(struct dlm_ls *ls, char *name, int len)
{
	struct dlm_rsb *r;
	uint32_t hash, bucket;
	int rv;

	hash = jhash(name, len, 0);
	bucket = hash & (ls->ls_rsbtbl_size - 1);

	spin_lock(&ls->ls_rsbtbl[bucket].lock);
	rv = dlm_search_rsb_tree(&ls->ls_rsbtbl[bucket].keep, name, len, &r);
	if (rv)
		rv = dlm_search_rsb_tree(&ls->ls_rsbtbl[bucket].toss,
					 name, len, &r);
	spin_unlock(&ls->ls_rsbtbl[bucket].lock);

	if (!rv)
		return r;

	down_read(&ls->ls_root_sem);
	list_for_each_entry(r, &ls->ls_root_list, res_root_list) {
		if (len == r->res_length && !memcmp(name, r->res_name, len)) {
			up_read(&ls->ls_root_sem);
			log_debug(ls, "find_rsb_root revert to root_list %s",
				  r->res_name);
			return r;
		}
	}
	up_read(&ls->ls_root_sem);
	return NULL;
}

/* Find the rsb where we left off (or start again), then send rsb names
   for rsb's we're master of and whose directory node matches the requesting
   node.  inbuf is the rsb name last sent, inlen is the name's length */

void dlm_copy_master_names(struct dlm_ls *ls, char *inbuf, int inlen,
 			   char *outbuf, int outlen, int nodeid)
{
	struct list_head *list;
	struct dlm_rsb *r;
	int offset = 0, dir_nodeid;
	__be16 be_namelen;

	down_read(&ls->ls_root_sem);

	if (inlen > 1) {
		r = find_rsb_root(ls, inbuf, inlen);
		if (!r) {
			inbuf[inlen - 1] = '\0';
			log_error(ls, "copy_master_names from %d start %d %s",
				  nodeid, inlen, inbuf);
			goto out;
		}
		list = r->res_root_list.next;
	} else {
		list = ls->ls_root_list.next;
	}

	for (offset = 0; list != &ls->ls_root_list; list = list->next) {
		r = list_entry(list, struct dlm_rsb, res_root_list);
		if (r->res_nodeid)
			continue;

		dir_nodeid = dlm_dir_nodeid(r);
		if (dir_nodeid != nodeid)
			continue;

		/*
		 * The block ends when we can't fit the following in the
		 * remaining buffer space:
		 * namelen (uint16_t) +
		 * name (r->res_length) +
		 * end-of-block record 0x0000 (uint16_t)
		 */

		if (offset + sizeof(uint16_t)*2 + r->res_length > outlen) {
			/* Write end-of-block record */
			be_namelen = cpu_to_be16(0);
			memcpy(outbuf + offset, &be_namelen, sizeof(__be16));
			offset += sizeof(__be16);
			ls->ls_recover_dir_sent_msg++;
			goto out;
		}

		be_namelen = cpu_to_be16(r->res_length);
		memcpy(outbuf + offset, &be_namelen, sizeof(__be16));
		offset += sizeof(__be16);
		memcpy(outbuf + offset, r->res_name, r->res_length);
		offset += r->res_length;
		ls->ls_recover_dir_sent_res++;
	}

	/*
	 * If we've reached the end of the list (and there's room) write a
	 * terminating record.
	 */

	if ((list == &ls->ls_root_list) &&
	    (offset + sizeof(uint16_t) <= outlen)) {
		be_namelen = cpu_to_be16(0xFFFF);
		memcpy(outbuf + offset, &be_namelen, sizeof(__be16));
		offset += sizeof(__be16);
		ls->ls_recover_dir_sent_msg++;
	}
 out:
	up_read(&ls->ls_root_sem);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/dir.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) 2005-2010 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

/* Central locking logic has four stages:

   dlm_lock()
   dlm_unlock()

   request_lock(ls, lkb)
   convert_lock(ls, lkb)
   unlock_lock(ls, lkb)
   cancel_lock(ls, lkb)

   _request_lock(r, lkb)
   _convert_lock(r, lkb)
   _unlock_lock(r, lkb)
   _cancel_lock(r, lkb)

   do_request(r, lkb)
   do_convert(r, lkb)
   do_unlock(r, lkb)
   do_cancel(r, lkb)

   Stage 1 (lock, unlock) is mainly about checking input args and
   splitting into one of the four main operations:

       dlm_lock          = request_lock
       dlm_lock+CONVERT  = convert_lock
       dlm_unlock        = unlock_lock
       dlm_unlock+CANCEL = cancel_lock

   Stage 2, xxxx_lock(), just finds and locks the relevant rsb which is
   provided to the next stage.

   Stage 3, _xxxx_lock(), determines if the operation is local or remote.
   When remote, it calls send_xxxx(), when local it calls do_xxxx().

   Stage 4, do_xxxx(), is the guts of the operation.  It manipulates the
   given rsb and lkb and queues callbacks.

   For remote operations, send_xxxx() results in the corresponding do_xxxx()
   function being executed on the remote node.  The connecting send/receive
   calls on local (L) and remote (R) nodes:

   L: send_xxxx()              ->  R: receive_xxxx()
                                   R: do_xxxx()
   L: receive_xxxx_reply()     <-  R: send_xxxx_reply()
*/
#include <linux/types.h>
#include <linux/rbtree.h>
// #include <linux/slab.h>
// #include "dlm_internal.h"
#include <linux/dlm_device.h>
// #include "memory.h"
// #include "lowcomms.h"
#include "requestqueue.h"
// #include "util.h"
// #include "dir.h"
// #include "member.h"
// #include "lockspace.h"
// #include "ast.h"
// #include "lock.h"
// #include "rcom.h"
// #include "recover.h"
#include "lvb_table.h"
// #include "user.h"
// #include "config.h"
#include "../../inc/__fss.h"

static int send_request(struct dlm_rsb *r, struct dlm_lkb *lkb);
static int send_convert(struct dlm_rsb *r, struct dlm_lkb *lkb);
static int send_unlock(struct dlm_rsb *r, struct dlm_lkb *lkb);
static int send_cancel(struct dlm_rsb *r, struct dlm_lkb *lkb);
static int send_grant(struct dlm_rsb *r, struct dlm_lkb *lkb);
static int send_bast(struct dlm_rsb *r, struct dlm_lkb *lkb, int mode);
static int send_lookup(struct dlm_rsb *r, struct dlm_lkb *lkb);
static int send_remove(struct dlm_rsb *r);
static int _request_lock(struct dlm_rsb *r, struct dlm_lkb *lkb);
static int _cancel_lock(struct dlm_rsb *r, struct dlm_lkb *lkb);
static void __receive_convert_reply(struct dlm_rsb *r, struct dlm_lkb *lkb,
				    struct dlm_message *ms);
static int receive_extralen(struct dlm_message *ms);
static void do_purge(struct dlm_ls *ls, int nodeid, int pid);
static void del_timeout(struct dlm_lkb *lkb);
static void toss_rsb(struct kref *kref);

/*
 * Lock compatibilty matrix - thanks Steve
 * UN = Unlocked state. Not really a state, used as a flag
 * PD = Padding. Used to make the matrix a nice power of two in size
 * Other states are the same as the VMS DLM.
 * Usage: matrix[grmode+1][rqmode+1]  (although m[rq+1][gr+1] is the same)
 */

static const int __dlm_compat_matrix[8][8] = {
      /* UN NL CR CW PR PW EX PD */
        {1, 1, 1, 1, 1, 1, 1, 0},       /* UN */
        {1, 1, 1, 1, 1, 1, 1, 0},       /* NL */
        {1, 1, 1, 1, 1, 1, 0, 0},       /* CR */
        {1, 1, 1, 1, 0, 0, 0, 0},       /* CW */
        {1, 1, 1, 0, 1, 0, 0, 0},       /* PR */
        {1, 1, 1, 0, 0, 0, 0, 0},       /* PW */
        {1, 1, 0, 0, 0, 0, 0, 0},       /* EX */
        {0, 0, 0, 0, 0, 0, 0, 0}        /* PD */
};

/*
 * This defines the direction of transfer of LVB data.
 * Granted mode is the row; requested mode is the column.
 * Usage: matrix[grmode+1][rqmode+1]
 * 1 = LVB is returned to the caller
 * 0 = LVB is written to the resource
 * -1 = nothing happens to the LVB
 */

const int dlm_lvb_operations[8][8] = {
        /* UN   NL  CR  CW  PR  PW  EX  PD*/
        {  -1,  1,  1,  1,  1,  1,  1, -1 }, /* UN */
        {  -1,  1,  1,  1,  1,  1,  1,  0 }, /* NL */
        {  -1, -1,  1,  1,  1,  1,  1,  0 }, /* CR */
        {  -1, -1, -1,  1,  1,  1,  1,  0 }, /* CW */
        {  -1, -1, -1, -1,  1,  1,  1,  0 }, /* PR */
        {  -1,  0,  0,  0,  0,  0,  1,  0 }, /* PW */
        {  -1,  0,  0,  0,  0,  0,  0,  0 }, /* EX */
        {  -1,  0,  0,  0,  0,  0,  0,  0 }  /* PD */
};

#define modes_compat(gr, rq) \
	__dlm_compat_matrix[(gr)->lkb_grmode + 1][(rq)->lkb_rqmode + 1]

int dlm_modes_compat(int mode1, int mode2)
{
	return __dlm_compat_matrix[mode1 + 1][mode2 + 1];
}

/*
 * Compatibility matrix for conversions with QUECVT set.
 * Granted mode is the row; requested mode is the column.
 * Usage: matrix[grmode+1][rqmode+1]
 */

static const int __quecvt_compat_matrix[8][8] = {
      /* UN NL CR CW PR PW EX PD */
        {0, 0, 0, 0, 0, 0, 0, 0},       /* UN */
        {0, 0, 1, 1, 1, 1, 1, 0},       /* NL */
        {0, 0, 0, 1, 1, 1, 1, 0},       /* CR */
        {0, 0, 0, 0, 1, 1, 1, 0},       /* CW */
        {0, 0, 0, 1, 0, 1, 1, 0},       /* PR */
        {0, 0, 0, 0, 0, 0, 1, 0},       /* PW */
        {0, 0, 0, 0, 0, 0, 0, 0},       /* EX */
        {0, 0, 0, 0, 0, 0, 0, 0}        /* PD */
};

void dlm_print_lkb(struct dlm_lkb *lkb)
{
	printk(KERN_ERR "lkb: nodeid %d id %x remid %x exflags %x flags %x "
	       "sts %d rq %d gr %d wait_type %d wait_nodeid %d seq %llu\n",
	       lkb->lkb_nodeid, lkb->lkb_id, lkb->lkb_remid, lkb->lkb_exflags,
	       lkb->lkb_flags, lkb->lkb_status, lkb->lkb_rqmode,
	       lkb->lkb_grmode, lkb->lkb_wait_type, lkb->lkb_wait_nodeid,
	       (unsigned long long)lkb->lkb_recover_seq);
}

static void dlm_print_rsb(struct dlm_rsb *r)
{
	printk(KERN_ERR "rsb: nodeid %d master %d dir %d flags %lx first %x "
	       "rlc %d name %s\n",
	       r->res_nodeid, r->res_master_nodeid, r->res_dir_nodeid,
	       r->res_flags, r->res_first_lkid, r->res_recover_locks_count,
	       r->res_name);
}

void dlm_dump_rsb(struct dlm_rsb *r)
{
	struct dlm_lkb *lkb;

	dlm_print_rsb(r);

	printk(KERN_ERR "rsb: root_list empty %d recover_list empty %d\n",
	       list_empty(&r->res_root_list), list_empty(&r->res_recover_list));
	printk(KERN_ERR "rsb lookup list\n");
	list_for_each_entry(lkb, &r->res_lookup, lkb_rsb_lookup)
		dlm_print_lkb(lkb);
	printk(KERN_ERR "rsb grant queue:\n");
	list_for_each_entry(lkb, &r->res_grantqueue, lkb_statequeue)
		dlm_print_lkb(lkb);
	printk(KERN_ERR "rsb convert queue:\n");
	list_for_each_entry(lkb, &r->res_convertqueue, lkb_statequeue)
		dlm_print_lkb(lkb);
	printk(KERN_ERR "rsb wait queue:\n");
	list_for_each_entry(lkb, &r->res_waitqueue, lkb_statequeue)
		dlm_print_lkb(lkb);
}

/* Threads cannot use the lockspace while it's being recovered */

static inline void dlm_lock_recovery(struct dlm_ls *ls)
{
	down_read(&ls->ls_in_recovery);
}

void dlm_unlock_recovery(struct dlm_ls *ls)
{
	up_read(&ls->ls_in_recovery);
}

int dlm_lock_recovery_try(struct dlm_ls *ls)
{
	return down_read_trylock(&ls->ls_in_recovery);
}

static inline int can_be_queued(struct dlm_lkb *lkb)
{
	return !(lkb->lkb_exflags & DLM_LKF_NOQUEUE);
}

static inline int force_blocking_asts(struct dlm_lkb *lkb)
{
	return (lkb->lkb_exflags & DLM_LKF_NOQUEUEBAST);
}

static inline int is_demoted(struct dlm_lkb *lkb)
{
	return (lkb->lkb_sbflags & DLM_SBF_DEMOTED);
}

static inline int is_altmode(struct dlm_lkb *lkb)
{
	return (lkb->lkb_sbflags & DLM_SBF_ALTMODE);
}

static inline int is_granted(struct dlm_lkb *lkb)
{
	return (lkb->lkb_status == DLM_LKSTS_GRANTED);
}

static inline int is_remote(struct dlm_rsb *r)
{
	DLM_ASSERT(r->res_nodeid >= 0, dlm_print_rsb(r););
	return !!r->res_nodeid;
}

static inline int is_process_copy(struct dlm_lkb *lkb)
{
	return (lkb->lkb_nodeid && !(lkb->lkb_flags & DLM_IFL_MSTCPY));
}

static inline int is_master_copy(struct dlm_lkb *lkb)
{
	return (lkb->lkb_flags & DLM_IFL_MSTCPY) ? 1 : 0;
}

static inline int middle_conversion(struct dlm_lkb *lkb)
{
	if ((lkb->lkb_grmode==DLM_LOCK_PR && lkb->lkb_rqmode==DLM_LOCK_CW) ||
	    (lkb->lkb_rqmode==DLM_LOCK_PR && lkb->lkb_grmode==DLM_LOCK_CW))
		return 1;
	return 0;
}

static inline int down_conversion(struct dlm_lkb *lkb)
{
	return (!middle_conversion(lkb) && lkb->lkb_rqmode < lkb->lkb_grmode);
}

static inline int is_overlap_unlock(struct dlm_lkb *lkb)
{
	return lkb->lkb_flags & DLM_IFL_OVERLAP_UNLOCK;
}

static inline int is_overlap_cancel(struct dlm_lkb *lkb)
{
	return lkb->lkb_flags & DLM_IFL_OVERLAP_CANCEL;
}

static inline int is_overlap(struct dlm_lkb *lkb)
{
	return (lkb->lkb_flags & (DLM_IFL_OVERLAP_UNLOCK |
				  DLM_IFL_OVERLAP_CANCEL));
}

static void queue_cast(struct dlm_rsb *r, struct dlm_lkb *lkb, int rv)
{
	if (is_master_copy(lkb))
		return;

	del_timeout(lkb);

	DLM_ASSERT(lkb->lkb_lksb, dlm_print_lkb(lkb););

	/* if the operation was a cancel, then return -DLM_ECANCEL, if a
	   timeout caused the cancel then return -ETIMEDOUT */
	if (rv == -DLM_ECANCEL && (lkb->lkb_flags & DLM_IFL_TIMEOUT_CANCEL)) {
		lkb->lkb_flags &= ~DLM_IFL_TIMEOUT_CANCEL;
		rv = -ETIMEDOUT;
	}

	if (rv == -DLM_ECANCEL && (lkb->lkb_flags & DLM_IFL_DEADLOCK_CANCEL)) {
		lkb->lkb_flags &= ~DLM_IFL_DEADLOCK_CANCEL;
		rv = -EDEADLK;
	}

	dlm_add_cb(lkb, DLM_CB_CAST, lkb->lkb_grmode, rv, lkb->lkb_sbflags);
}

static inline void queue_cast_overlap(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	queue_cast(r, lkb,
		   is_overlap_unlock(lkb) ? -DLM_EUNLOCK : -DLM_ECANCEL);
}

static void queue_bast(struct dlm_rsb *r, struct dlm_lkb *lkb, int rqmode)
{
	if (is_master_copy(lkb)) {
		send_bast(r, lkb, rqmode);
	} else {
		dlm_add_cb(lkb, DLM_CB_BAST, rqmode, 0, 0);
	}
}

/*
 * Basic operations on rsb's and lkb's
 */

/* This is only called to add a reference when the code already holds
   a valid reference to the rsb, so there's no need for locking. */

static inline void hold_rsb(struct dlm_rsb *r)
{
	kref_get(&r->res_ref);
}

void dlm_hold_rsb(struct dlm_rsb *r)
{
	hold_rsb(r);
}

/* When all references to the rsb are gone it's transferred to
   the tossed list for later disposal. */

static void put_rsb(struct dlm_rsb *r)
{
	struct dlm_ls *ls = r->res_ls;
	uint32_t bucket = r->res_bucket;

	spin_lock(&ls->ls_rsbtbl[bucket].lock);
	kref_put(&r->res_ref, toss_rsb);
	spin_unlock(&ls->ls_rsbtbl[bucket].lock);
}

void dlm_put_rsb(struct dlm_rsb *r)
{
	put_rsb(r);
}

static int pre_rsb_struct(struct dlm_ls *ls)
{
	struct dlm_rsb *r1, *r2;
	int count = 0;

	spin_lock(&ls->ls_new_rsb_spin);
	if (ls->ls_new_rsb_count > dlm_config.ci_new_rsb_count / 2) {
		spin_unlock(&ls->ls_new_rsb_spin);
		return 0;
	}
	spin_unlock(&ls->ls_new_rsb_spin);

	r1 = dlm_allocate_rsb(ls);
	r2 = dlm_allocate_rsb(ls);

	spin_lock(&ls->ls_new_rsb_spin);
	if (r1) {
		list_add(&r1->res_hashchain, &ls->ls_new_rsb);
		ls->ls_new_rsb_count++;
	}
	if (r2) {
		list_add(&r2->res_hashchain, &ls->ls_new_rsb);
		ls->ls_new_rsb_count++;
	}
	count = ls->ls_new_rsb_count;
	spin_unlock(&ls->ls_new_rsb_spin);

	if (!count)
		return -ENOMEM;
	return 0;
}

/* If ls->ls_new_rsb is empty, return -EAGAIN, so the caller can
   unlock any spinlocks, go back and call pre_rsb_struct again.
   Otherwise, take an rsb off the list and return it. */

static int get_rsb_struct(struct dlm_ls *ls, char *name, int len,
			  struct dlm_rsb **r_ret)
{
	struct dlm_rsb *r;
	int count;

	spin_lock(&ls->ls_new_rsb_spin);
	if (list_empty(&ls->ls_new_rsb)) {
		count = ls->ls_new_rsb_count;
		spin_unlock(&ls->ls_new_rsb_spin);
		log_debug(ls, "find_rsb retry %d %d %s",
			  count, dlm_config.ci_new_rsb_count, name);
		return -EAGAIN;
	}

	r = list_first_entry(&ls->ls_new_rsb, struct dlm_rsb, res_hashchain);
	list_del(&r->res_hashchain);
	/* Convert the empty list_head to a NULL rb_node for tree usage: */
	memset(&r->res_hashnode, 0, sizeof(struct rb_node));
	ls->ls_new_rsb_count--;
	spin_unlock(&ls->ls_new_rsb_spin);

	r->res_ls = ls;
	r->res_length = len;
	memcpy(r->res_name, name, len);
	mutex_init(&r->res_mutex);

	INIT_LIST_HEAD(&r->res_lookup);
	INIT_LIST_HEAD(&r->res_grantqueue);
	INIT_LIST_HEAD(&r->res_convertqueue);
	INIT_LIST_HEAD(&r->res_waitqueue);
	INIT_LIST_HEAD(&r->res_root_list);
	INIT_LIST_HEAD(&r->res_recover_list);

	*r_ret = r;
	return 0;
}

static int rsb_cmp(struct dlm_rsb *r, const char *name, int nlen)
{
	char maxname[DLM_RESNAME_MAXLEN];

	memset(maxname, 0, DLM_RESNAME_MAXLEN);
	memcpy(maxname, name, nlen);
	return memcmp(r->res_name, maxname, DLM_RESNAME_MAXLEN);
}

int dlm_search_rsb_tree(struct rb_root *tree, char *name, int len,
			struct dlm_rsb **r_ret)
{
	struct rb_node *node = tree->rb_node;
	struct dlm_rsb *r;
	int rc;

	while (node) {
		r = rb_entry(node, struct dlm_rsb, res_hashnode);
		rc = rsb_cmp(r, name, len);
		if (rc < 0)
			node = node->rb_left;
		else if (rc > 0)
			node = node->rb_right;
		else
			goto found;
	}
	*r_ret = NULL;
	return -EBADR;

 found:
	*r_ret = r;
	return 0;
}

static int rsb_insert(struct dlm_rsb *rsb, struct rb_root *tree)
{
	struct rb_node **newn = &tree->rb_node;
	struct rb_node *parent = NULL;
	int rc;

	while (*newn) {
		struct dlm_rsb *cur = rb_entry(*newn, struct dlm_rsb,
					       res_hashnode);

		parent = *newn;
		rc = rsb_cmp(cur, rsb->res_name, rsb->res_length);
		if (rc < 0)
			newn = &parent->rb_left;
		else if (rc > 0)
			newn = &parent->rb_right;
		else {
			log_print("rsb_insert match");
			dlm_dump_rsb(rsb);
			dlm_dump_rsb(cur);
			return -EEXIST;
		}
	}

	rb_link_node(&rsb->res_hashnode, parent, newn);
	rb_insert_color(&rsb->res_hashnode, tree);
	return 0;
}

/*
 * Find rsb in rsbtbl and potentially create/add one
 *
 * Delaying the release of rsb's has a similar benefit to applications keeping
 * NL locks on an rsb, but without the guarantee that the cached master value
 * will still be valid when the rsb is reused.  Apps aren't always smart enough
 * to keep NL locks on an rsb that they may lock again shortly; this can lead
 * to excessive master lookups and removals if we don't delay the release.
 *
 * Searching for an rsb means looking through both the normal list and toss
 * list.  When found on the toss list the rsb is moved to the normal list with
 * ref count of 1; when found on normal list the ref count is incremented.
 *
 * rsb's on the keep list are being used locally and refcounted.
 * rsb's on the toss list are not being used locally, and are not refcounted.
 *
 * The toss list rsb's were either
 * - previously used locally but not any more (were on keep list, then
 *   moved to toss list when last refcount dropped)
 * - created and put on toss list as a directory record for a lookup
 *   (we are the dir node for the res, but are not using the res right now,
 *   but some other node is)
 *
 * The purpose of find_rsb() is to return a refcounted rsb for local use.
 * So, if the given rsb is on the toss list, it is moved to the keep list
 * before being returned.
 *
 * toss_rsb() happens when all local usage of the rsb is done, i.e. no
 * more refcounts exist, so the rsb is moved from the keep list to the
 * toss list.
 *
 * rsb's on both keep and toss lists are used for doing a name to master
 * lookups.  rsb's that are in use locally (and being refcounted) are on
 * the keep list, rsb's that are not in use locally (not refcounted) and
 * only exist for name/master lookups are on the toss list.
 *
 * rsb's on the toss list who's dir_nodeid is not local can have stale
 * name/master mappings.  So, remote requests on such rsb's can potentially
 * return with an error, which means the mapping is stale and needs to
 * be updated with a new lookup.  (The idea behind MASTER UNCERTAIN and
 * first_lkid is to keep only a single outstanding request on an rsb
 * while that rsb has a potentially stale master.)
 */

static int find_rsb_dir(struct dlm_ls *ls, char *name, int len,
			uint32_t hash, uint32_t b,
			int dir_nodeid, int from_nodeid,
			unsigned int flags, struct dlm_rsb **r_ret)
{
	struct dlm_rsb *r = NULL;
	int our_nodeid = dlm_our_nodeid();
	int from_local = 0;
	int from_other = 0;
	int from_dir = 0;
	int create = 0;
	int error;

	if (flags & R_RECEIVE_REQUEST) {
		if (from_nodeid == dir_nodeid)
			from_dir = 1;
		else
			from_other = 1;
	} else if (flags & R_REQUEST) {
		from_local = 1;
	}

	/*
	 * flags & R_RECEIVE_RECOVER is from dlm_recover_master_copy, so
	 * from_nodeid has sent us a lock in dlm_recover_locks, believing
	 * we're the new master.  Our local recovery may not have set
	 * res_master_nodeid to our_nodeid yet, so allow either.  Don't
	 * create the rsb; dlm_recover_process_copy() will handle EBADR
	 * by resending.
	 *
	 * If someone sends us a request, we are the dir node, and we do
	 * not find the rsb anywhere, then recreate it.  This happens if
	 * someone sends us a request after we have removed/freed an rsb
	 * from our toss list.  (They sent a request instead of lookup
	 * because they are using an rsb from their toss list.)
	 */

	if (from_local || from_dir ||
	    (from_other && (dir_nodeid == our_nodeid))) {
		create = 1;
	}

 retry:
	if (create) {
		error = pre_rsb_struct(ls);
		if (error < 0)
			goto out;
	}

	spin_lock(&ls->ls_rsbtbl[b].lock);

	error = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].keep, name, len, &r);
	if (error)
		goto do_toss;
	
	/*
	 * rsb is active, so we can't check master_nodeid without lock_rsb.
	 */

	kref_get(&r->res_ref);
	error = 0;
	goto out_unlock;


 do_toss:
	error = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].toss, name, len, &r);
	if (error)
		goto do_new;

	/*
	 * rsb found inactive (master_nodeid may be out of date unless
	 * we are the dir_nodeid or were the master)  No other thread
	 * is using this rsb because it's on the toss list, so we can
	 * look at or update res_master_nodeid without lock_rsb.
	 */

	if ((r->res_master_nodeid != our_nodeid) && from_other) {
		/* our rsb was not master, and another node (not the dir node)
		   has sent us a request */
		log_debug(ls, "find_rsb toss from_other %d master %d dir %d %s",
			  from_nodeid, r->res_master_nodeid, dir_nodeid,
			  r->res_name);
		error = -ENOTBLK;
		goto out_unlock;
	}

	if ((r->res_master_nodeid != our_nodeid) && from_dir) {
		/* don't think this should ever happen */
		log_error(ls, "find_rsb toss from_dir %d master %d",
			  from_nodeid, r->res_master_nodeid);
		dlm_print_rsb(r);
		/* fix it and go on */
		r->res_master_nodeid = our_nodeid;
		r->res_nodeid = 0;
		rsb_clear_flag(r, RSB_MASTER_UNCERTAIN);
		r->res_first_lkid = 0;
	}

	if (from_local && (r->res_master_nodeid != our_nodeid)) {
		/* Because we have held no locks on this rsb,
		   res_master_nodeid could have become stale. */
		rsb_set_flag(r, RSB_MASTER_UNCERTAIN);
		r->res_first_lkid = 0;
	}

	rb_erase(&r->res_hashnode, &ls->ls_rsbtbl[b].toss);
	error = rsb_insert(r, &ls->ls_rsbtbl[b].keep);
	goto out_unlock;


 do_new:
	/*
	 * rsb not found
	 */

	if (error == -EBADR && !create)
		goto out_unlock;

	error = get_rsb_struct(ls, name, len, &r);
	if (error == -EAGAIN) {
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		goto retry;
	}
	if (error)
		goto out_unlock;

	r->res_hash = hash;
	r->res_bucket = b;
	r->res_dir_nodeid = dir_nodeid;
	kref_init(&r->res_ref);

	if (from_dir) {
		/* want to see how often this happens */
		log_debug(ls, "find_rsb new from_dir %d recreate %s",
			  from_nodeid, r->res_name);
		r->res_master_nodeid = our_nodeid;
		r->res_nodeid = 0;
		goto out_add;
	}

	if (from_other && (dir_nodeid != our_nodeid)) {
		/* should never happen */
		log_error(ls, "find_rsb new from_other %d dir %d our %d %s",
			  from_nodeid, dir_nodeid, our_nodeid, r->res_name);
		dlm_free_rsb(r);
		r = NULL;
		error = -ENOTBLK;
		goto out_unlock;
	}

	if (from_other) {
		log_debug(ls, "find_rsb new from_other %d dir %d %s",
			  from_nodeid, dir_nodeid, r->res_name);
	}

	if (dir_nodeid == our_nodeid) {
		/* When we are the dir nodeid, we can set the master
		   node immediately */
		r->res_master_nodeid = our_nodeid;
		r->res_nodeid = 0;
	} else {
		/* set_master will send_lookup to dir_nodeid */
		r->res_master_nodeid = 0;
		r->res_nodeid = -1;
	}

 out_add:
	error = rsb_insert(r, &ls->ls_rsbtbl[b].keep);
 out_unlock:
	spin_unlock(&ls->ls_rsbtbl[b].lock);
 out:
	*r_ret = r;
	return error;
}

/* During recovery, other nodes can send us new MSTCPY locks (from
   dlm_recover_locks) before we've made ourself master (in
   dlm_recover_masters). */

static int find_rsb_nodir(struct dlm_ls *ls, char *name, int len,
			  uint32_t hash, uint32_t b,
			  int dir_nodeid, int from_nodeid,
			  unsigned int flags, struct dlm_rsb **r_ret)
{
	struct dlm_rsb *r = NULL;
	int our_nodeid = dlm_our_nodeid();
	int recover = (flags & R_RECEIVE_RECOVER);
	int error;

 retry:
	error = pre_rsb_struct(ls);
	if (error < 0)
		goto out;

	spin_lock(&ls->ls_rsbtbl[b].lock);

	error = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].keep, name, len, &r);
	if (error)
		goto do_toss;

	/*
	 * rsb is active, so we can't check master_nodeid without lock_rsb.
	 */

	kref_get(&r->res_ref);
	goto out_unlock;


 do_toss:
	error = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].toss, name, len, &r);
	if (error)
		goto do_new;

	/*
	 * rsb found inactive. No other thread is using this rsb because
	 * it's on the toss list, so we can look at or update
	 * res_master_nodeid without lock_rsb.
	 */

	if (!recover && (r->res_master_nodeid != our_nodeid) && from_nodeid) {
		/* our rsb is not master, and another node has sent us a
		   request; this should never happen */
		log_error(ls, "find_rsb toss from_nodeid %d master %d dir %d",
			  from_nodeid, r->res_master_nodeid, dir_nodeid);
		dlm_print_rsb(r);
		error = -ENOTBLK;
		goto out_unlock;
	}

	if (!recover && (r->res_master_nodeid != our_nodeid) &&
	    (dir_nodeid == our_nodeid)) {
		/* our rsb is not master, and we are dir; may as well fix it;
		   this should never happen */
		log_error(ls, "find_rsb toss our %d master %d dir %d",
			  our_nodeid, r->res_master_nodeid, dir_nodeid);
		dlm_print_rsb(r);
		r->res_master_nodeid = our_nodeid;
		r->res_nodeid = 0;
	}

	rb_erase(&r->res_hashnode, &ls->ls_rsbtbl[b].toss);
	error = rsb_insert(r, &ls->ls_rsbtbl[b].keep);
	goto out_unlock;


 do_new:
	/*
	 * rsb not found
	 */

	error = get_rsb_struct(ls, name, len, &r);
	if (error == -EAGAIN) {
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		goto retry;
	}
	if (error)
		goto out_unlock;

	r->res_hash = hash;
	r->res_bucket = b;
	r->res_dir_nodeid = dir_nodeid;
	r->res_master_nodeid = dir_nodeid;
	r->res_nodeid = (dir_nodeid == our_nodeid) ? 0 : dir_nodeid;
	kref_init(&r->res_ref);

	error = rsb_insert(r, &ls->ls_rsbtbl[b].keep);
 out_unlock:
	spin_unlock(&ls->ls_rsbtbl[b].lock);
 out:
	*r_ret = r;
	return error;
}

static int find_rsb(struct dlm_ls *ls, char *name, int len, int from_nodeid,
		    unsigned int flags, struct dlm_rsb **r_ret)
{
	uint32_t hash, b;
	int dir_nodeid;

	if (len > DLM_RESNAME_MAXLEN)
		return -EINVAL;

	hash = jhash(name, len, 0);
	b = hash & (ls->ls_rsbtbl_size - 1);

	dir_nodeid = dlm_hash2nodeid(ls, hash);

	if (dlm_no_directory(ls))
		return find_rsb_nodir(ls, name, len, hash, b, dir_nodeid,
				      from_nodeid, flags, r_ret);
	else
		return find_rsb_dir(ls, name, len, hash, b, dir_nodeid,
				      from_nodeid, flags, r_ret);
}

/* we have received a request and found that res_master_nodeid != our_nodeid,
   so we need to return an error or make ourself the master */

static int validate_master_nodeid(struct dlm_ls *ls, struct dlm_rsb *r,
				  int from_nodeid)
{
	if (dlm_no_directory(ls)) {
		log_error(ls, "find_rsb keep from_nodeid %d master %d dir %d",
			  from_nodeid, r->res_master_nodeid,
			  r->res_dir_nodeid);
		dlm_print_rsb(r);
		return -ENOTBLK;
	}

	if (from_nodeid != r->res_dir_nodeid) {
		/* our rsb is not master, and another node (not the dir node)
	   	   has sent us a request.  this is much more common when our
	   	   master_nodeid is zero, so limit debug to non-zero.  */

		if (r->res_master_nodeid) {
			log_debug(ls, "validate master from_other %d master %d "
				  "dir %d first %x %s", from_nodeid,
				  r->res_master_nodeid, r->res_dir_nodeid,
				  r->res_first_lkid, r->res_name);
		}
		return -ENOTBLK;
	} else {
		/* our rsb is not master, but the dir nodeid has sent us a
	   	   request; this could happen with master 0 / res_nodeid -1 */

		if (r->res_master_nodeid) {
			log_error(ls, "validate master from_dir %d master %d "
				  "first %x %s",
				  from_nodeid, r->res_master_nodeid,
				  r->res_first_lkid, r->res_name);
		}

		r->res_master_nodeid = dlm_our_nodeid();
		r->res_nodeid = 0;
		return 0;
	}
}

/*
 * We're the dir node for this res and another node wants to know the
 * master nodeid.  During normal operation (non recovery) this is only
 * called from receive_lookup(); master lookups when the local node is
 * the dir node are done by find_rsb().
 *
 * normal operation, we are the dir node for a resource
 * . _request_lock
 * . set_master
 * . send_lookup
 * . receive_lookup
 * . dlm_master_lookup flags 0
 *
 * recover directory, we are rebuilding dir for all resources
 * . dlm_recover_directory
 * . dlm_rcom_names
 *   remote node sends back the rsb names it is master of and we are dir of
 * . dlm_master_lookup RECOVER_DIR (fix_master 0, from_master 1)
 *   we either create new rsb setting remote node as master, or find existing
 *   rsb and set master to be the remote node.
 *
 * recover masters, we are finding the new master for resources
 * . dlm_recover_masters
 * . recover_master
 * . dlm_send_rcom_lookup
 * . receive_rcom_lookup
 * . dlm_master_lookup RECOVER_MASTER (fix_master 1, from_master 0)
 */

int dlm_master_lookup(struct dlm_ls *ls, int from_nodeid, char *name, int len,
		      unsigned int flags, int *r_nodeid, int *result)
{
	struct dlm_rsb *r = NULL;
	uint32_t hash, b;
	int from_master = (flags & DLM_LU_RECOVER_DIR);
	int fix_master = (flags & DLM_LU_RECOVER_MASTER);
	int our_nodeid = dlm_our_nodeid();
	int dir_nodeid, error, toss_list = 0;

	if (len > DLM_RESNAME_MAXLEN)
		return -EINVAL;

	if (from_nodeid == our_nodeid) {
		log_error(ls, "dlm_master_lookup from our_nodeid %d flags %x",
			  our_nodeid, flags);
		return -EINVAL;
	}

	hash = jhash(name, len, 0);
	b = hash & (ls->ls_rsbtbl_size - 1);

	dir_nodeid = dlm_hash2nodeid(ls, hash);
	if (dir_nodeid != our_nodeid) {
		log_error(ls, "dlm_master_lookup from %d dir %d our %d h %x %d",
			  from_nodeid, dir_nodeid, our_nodeid, hash,
			  ls->ls_num_nodes);
		*r_nodeid = -1;
		return -EINVAL;
	}

 retry:
	error = pre_rsb_struct(ls);
	if (error < 0)
		return error;

	spin_lock(&ls->ls_rsbtbl[b].lock);
	error = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].keep, name, len, &r);
	if (!error) {
		/* because the rsb is active, we need to lock_rsb before
		   checking/changing re_master_nodeid */

		hold_rsb(r);
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		lock_rsb(r);
		goto found;
	}

	error = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].toss, name, len, &r);
	if (error)
		goto not_found;

	/* because the rsb is inactive (on toss list), it's not refcounted
	   and lock_rsb is not used, but is protected by the rsbtbl lock */

	toss_list = 1;
 found:
	if (r->res_dir_nodeid != our_nodeid) {
		/* should not happen, but may as well fix it and carry on */
		log_error(ls, "dlm_master_lookup res_dir %d our %d %s",
			  r->res_dir_nodeid, our_nodeid, r->res_name);
		r->res_dir_nodeid = our_nodeid;
	}

	if (fix_master && dlm_is_removed(ls, r->res_master_nodeid)) {
		/* Recovery uses this function to set a new master when
		   the previous master failed.  Setting NEW_MASTER will
		   force dlm_recover_masters to call recover_master on this
		   rsb even though the res_nodeid is no longer removed. */

		r->res_master_nodeid = from_nodeid;
		r->res_nodeid = from_nodeid;
		rsb_set_flag(r, RSB_NEW_MASTER);

		if (toss_list) {
			/* I don't think we should ever find it on toss list. */
			log_error(ls, "dlm_master_lookup fix_master on toss");
			dlm_dump_rsb(r);
		}
	}

	if (from_master && (r->res_master_nodeid != from_nodeid)) {
		/* this will happen if from_nodeid became master during
		   a previous recovery cycle, and we aborted the previous
		   cycle before recovering this master value */

		log_limit(ls, "dlm_master_lookup from_master %d "
			  "master_nodeid %d res_nodeid %d first %x %s",
			  from_nodeid, r->res_master_nodeid, r->res_nodeid,
			  r->res_first_lkid, r->res_name);

		if (r->res_master_nodeid == our_nodeid) {
			log_error(ls, "from_master %d our_master", from_nodeid);
			dlm_dump_rsb(r);
			dlm_send_rcom_lookup_dump(r, from_nodeid);
			goto out_found;
		}

		r->res_master_nodeid = from_nodeid;
		r->res_nodeid = from_nodeid;
		rsb_set_flag(r, RSB_NEW_MASTER);
	}

	if (!r->res_master_nodeid) {
		/* this will happen if recovery happens while we're looking
		   up the master for this rsb */

		log_debug(ls, "dlm_master_lookup master 0 to %d first %x %s",
			  from_nodeid, r->res_first_lkid, r->res_name);
		r->res_master_nodeid = from_nodeid;
		r->res_nodeid = from_nodeid;
	}

	if (!from_master && !fix_master &&
	    (r->res_master_nodeid == from_nodeid)) {
		/* this can happen when the master sends remove, the dir node
		   finds the rsb on the keep list and ignores the remove,
		   and the former master sends a lookup */

		log_limit(ls, "dlm_master_lookup from master %d flags %x "
			  "first %x %s", from_nodeid, flags,
			  r->res_first_lkid, r->res_name);
	}

 out_found:
	*r_nodeid = r->res_master_nodeid;
	if (result)
		*result = DLM_LU_MATCH;

	if (toss_list) {
		r->res_toss_time = jiffies;
		/* the rsb was inactive (on toss list) */
		spin_unlock(&ls->ls_rsbtbl[b].lock);
	} else {
		/* the rsb was active */
		unlock_rsb(r);
		put_rsb(r);
	}
	return 0;

 not_found:
	error = get_rsb_struct(ls, name, len, &r);
	if (error == -EAGAIN) {
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		goto retry;
	}
	if (error)
		goto out_unlock;

	r->res_hash = hash;
	r->res_bucket = b;
	r->res_dir_nodeid = our_nodeid;
	r->res_master_nodeid = from_nodeid;
	r->res_nodeid = from_nodeid;
	kref_init(&r->res_ref);
	r->res_toss_time = jiffies;

	error = rsb_insert(r, &ls->ls_rsbtbl[b].toss);
	if (error) {
		/* should never happen */
		dlm_free_rsb(r);
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		goto retry;
	}

	if (result)
		*result = DLM_LU_ADD;
	*r_nodeid = from_nodeid;
	error = 0;
 out_unlock:
	spin_unlock(&ls->ls_rsbtbl[b].lock);
	return error;
}

static void dlm_dump_rsb_hash(struct dlm_ls *ls, uint32_t hash)
{
	struct rb_node *n;
	struct dlm_rsb *r;
	int i;

	for (i = 0; i < ls->ls_rsbtbl_size; i++) {
		spin_lock(&ls->ls_rsbtbl[i].lock);
		for (n = rb_first(&ls->ls_rsbtbl[i].keep); n; n = rb_next(n)) {
			r = rb_entry(n, struct dlm_rsb, res_hashnode);
			if (r->res_hash == hash)
				dlm_dump_rsb(r);
		}
		spin_unlock(&ls->ls_rsbtbl[i].lock);
	}
}

void dlm_dump_rsb_name(struct dlm_ls *ls, char *name, int len)
{
	struct dlm_rsb *r = NULL;
	uint32_t hash, b;
	int error;

	hash = jhash(name, len, 0);
	b = hash & (ls->ls_rsbtbl_size - 1);

	spin_lock(&ls->ls_rsbtbl[b].lock);
	error = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].keep, name, len, &r);
	if (!error)
		goto out_dump;

	error = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].toss, name, len, &r);
	if (error)
		goto out;
 out_dump:
	dlm_dump_rsb(r);
 out:
	spin_unlock(&ls->ls_rsbtbl[b].lock);
}

static void toss_rsb(struct kref *kref)
{
	struct dlm_rsb *r = container_of(kref, struct dlm_rsb, res_ref);
	struct dlm_ls *ls = r->res_ls;

	DLM_ASSERT(list_empty(&r->res_root_list), dlm_print_rsb(r););
	kref_init(&r->res_ref);
	rb_erase(&r->res_hashnode, &ls->ls_rsbtbl[r->res_bucket].keep);
	rsb_insert(r, &ls->ls_rsbtbl[r->res_bucket].toss);
	r->res_toss_time = jiffies;
	ls->ls_rsbtbl[r->res_bucket].flags |= DLM_RTF_SHRINK;
	if (r->res_lvbptr) {
		dlm_free_lvb(r->res_lvbptr);
		r->res_lvbptr = NULL;
	}
}

/* See comment for unhold_lkb */

static void unhold_rsb(struct dlm_rsb *r)
{
	int rv;
	rv = kref_put(&r->res_ref, toss_rsb);
	DLM_ASSERT(!rv, dlm_dump_rsb(r););
}

static void kill_rsb(struct kref *kref)
{
	struct dlm_rsb *r = container_of(kref, struct dlm_rsb, res_ref);

	/* All work is done after the return from kref_put() so we
	   can release the write_lock before the remove and free. */

	DLM_ASSERT(list_empty(&r->res_lookup), dlm_dump_rsb(r););
	DLM_ASSERT(list_empty(&r->res_grantqueue), dlm_dump_rsb(r););
	DLM_ASSERT(list_empty(&r->res_convertqueue), dlm_dump_rsb(r););
	DLM_ASSERT(list_empty(&r->res_waitqueue), dlm_dump_rsb(r););
	DLM_ASSERT(list_empty(&r->res_root_list), dlm_dump_rsb(r););
	DLM_ASSERT(list_empty(&r->res_recover_list), dlm_dump_rsb(r););
}

/* Attaching/detaching lkb's from rsb's is for rsb reference counting.
   The rsb must exist as long as any lkb's for it do. */

static void attach_lkb(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	hold_rsb(r);
	lkb->lkb_resource = r;
}

static void detach_lkb(struct dlm_lkb *lkb)
{
	if (lkb->lkb_resource) {
		put_rsb(lkb->lkb_resource);
		lkb->lkb_resource = NULL;
	}
}

static int create_lkb(struct dlm_ls *ls, struct dlm_lkb **lkb_ret)
{
	struct dlm_lkb *lkb;
	int rv;

	lkb = dlm_allocate_lkb(ls);
	if (!lkb)
		return -ENOMEM;

	lkb->lkb_nodeid = -1;
	lkb->lkb_grmode = DLM_LOCK_IV;
	kref_init(&lkb->lkb_ref);
	INIT_LIST_HEAD(&lkb->lkb_ownqueue);
	INIT_LIST_HEAD(&lkb->lkb_rsb_lookup);
	INIT_LIST_HEAD(&lkb->lkb_time_list);
	INIT_LIST_HEAD(&lkb->lkb_cb_list);
	mutex_init(&lkb->lkb_cb_mutex);
	INIT_WORK(&lkb->lkb_cb_work, dlm_callback_work);

	idr_preload(GFP_NOFS);
	spin_lock(&ls->ls_lkbidr_spin);
	rv = idr_alloc(&ls->ls_lkbidr, lkb, 1, 0, GFP_NOWAIT);
	if (rv >= 0)
		lkb->lkb_id = rv;
	spin_unlock(&ls->ls_lkbidr_spin);
	idr_preload_end();

	if (rv < 0) {
		log_error(ls, "create_lkb idr error %d", rv);
		return rv;
	}

	*lkb_ret = lkb;
	return 0;
}

static int find_lkb(struct dlm_ls *ls, uint32_t lkid, struct dlm_lkb **lkb_ret)
{
	struct dlm_lkb *lkb;

	spin_lock(&ls->ls_lkbidr_spin);
	lkb = idr_find(&ls->ls_lkbidr, lkid);
	if (lkb)
		kref_get(&lkb->lkb_ref);
	spin_unlock(&ls->ls_lkbidr_spin);

	*lkb_ret = lkb;
	return lkb ? 0 : -ENOENT;
}

static void kill_lkb(struct kref *kref)
{
	struct dlm_lkb *lkb = container_of(kref, struct dlm_lkb, lkb_ref);

	/* All work is done after the return from kref_put() so we
	   can release the write_lock before the detach_lkb */

	DLM_ASSERT(!lkb->lkb_status, dlm_print_lkb(lkb););
}

/* __put_lkb() is used when an lkb may not have an rsb attached to
   it so we need to provide the lockspace explicitly */

static int __put_lkb(struct dlm_ls *ls, struct dlm_lkb *lkb)
{
	uint32_t lkid = lkb->lkb_id;

	spin_lock(&ls->ls_lkbidr_spin);
	if (kref_put(&lkb->lkb_ref, kill_lkb)) {
		idr_remove(&ls->ls_lkbidr, lkid);
		spin_unlock(&ls->ls_lkbidr_spin);

		detach_lkb(lkb);

		/* for local/process lkbs, lvbptr points to caller's lksb */
		if (lkb->lkb_lvbptr && is_master_copy(lkb))
			dlm_free_lvb(lkb->lkb_lvbptr);
		dlm_free_lkb(lkb);
		return 1;
	} else {
		spin_unlock(&ls->ls_lkbidr_spin);
		return 0;
	}
}

int dlm_put_lkb(struct dlm_lkb *lkb)
{
	struct dlm_ls *ls;

	DLM_ASSERT(lkb->lkb_resource, dlm_print_lkb(lkb););
	DLM_ASSERT(lkb->lkb_resource->res_ls, dlm_print_lkb(lkb););

	ls = lkb->lkb_resource->res_ls;
	return __put_lkb(ls, lkb);
}

/* This is only called to add a reference when the code already holds
   a valid reference to the lkb, so there's no need for locking. */

static inline void hold_lkb(struct dlm_lkb *lkb)
{
	kref_get(&lkb->lkb_ref);
}

/* This is called when we need to remove a reference and are certain
   it's not the last ref.  e.g. del_lkb is always called between a
   find_lkb/put_lkb and is always the inverse of a previous add_lkb.
   put_lkb would work fine, but would involve unnecessary locking */

static inline void unhold_lkb(struct dlm_lkb *lkb)
{
	int rv;
	rv = kref_put(&lkb->lkb_ref, kill_lkb);
	DLM_ASSERT(!rv, dlm_print_lkb(lkb););
}

static void lkb_add_ordered(struct list_head *new, struct list_head *head,
			    int mode)
{
	struct dlm_lkb *lkb = NULL;

	list_for_each_entry(lkb, head, lkb_statequeue)
		if (lkb->lkb_rqmode < mode)
			break;

	__list_add(new, lkb->lkb_statequeue.prev, &lkb->lkb_statequeue);
}

/* add/remove lkb to rsb's grant/convert/wait queue */

static void add_lkb(struct dlm_rsb *r, struct dlm_lkb *lkb, int status)
{
	kref_get(&lkb->lkb_ref);

	DLM_ASSERT(!lkb->lkb_status, dlm_print_lkb(lkb););

	lkb->lkb_timestamp = ktime_get();

	lkb->lkb_status = status;

	switch (status) {
	case DLM_LKSTS_WAITING:
		if (lkb->lkb_exflags & DLM_LKF_HEADQUE)
			list_add(&lkb->lkb_statequeue, &r->res_waitqueue);
		else
			list_add_tail(&lkb->lkb_statequeue, &r->res_waitqueue);
		break;
	case DLM_LKSTS_GRANTED:
		/* convention says granted locks kept in order of grmode */
		lkb_add_ordered(&lkb->lkb_statequeue, &r->res_grantqueue,
				lkb->lkb_grmode);
		break;
	case DLM_LKSTS_CONVERT:
		if (lkb->lkb_exflags & DLM_LKF_HEADQUE)
			list_add(&lkb->lkb_statequeue, &r->res_convertqueue);
		else
			list_add_tail(&lkb->lkb_statequeue,
				      &r->res_convertqueue);
		break;
	default:
		DLM_ASSERT(0, dlm_print_lkb(lkb); printk("sts=%d\n", status););
	}
}

static void del_lkb(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	lkb->lkb_status = 0;
	list_del(&lkb->lkb_statequeue);
	unhold_lkb(lkb);
}

static void move_lkb(struct dlm_rsb *r, struct dlm_lkb *lkb, int sts)
{
	hold_lkb(lkb);
	del_lkb(r, lkb);
	add_lkb(r, lkb, sts);
	unhold_lkb(lkb);
}

static int msg_reply_type(int mstype)
{
	switch (mstype) {
	case DLM_MSG_REQUEST:
		return DLM_MSG_REQUEST_REPLY;
	case DLM_MSG_CONVERT:
		return DLM_MSG_CONVERT_REPLY;
	case DLM_MSG_UNLOCK:
		return DLM_MSG_UNLOCK_REPLY;
	case DLM_MSG_CANCEL:
		return DLM_MSG_CANCEL_REPLY;
	case DLM_MSG_LOOKUP:
		return DLM_MSG_LOOKUP_REPLY;
	}
	return -1;
}

static int nodeid_warned(int nodeid, int num_nodes, int *warned)
{
	int i;

	for (i = 0; i < num_nodes; i++) {
		if (!warned[i]) {
			warned[i] = nodeid;
			return 0;
		}
		if (warned[i] == nodeid)
			return 1;
	}
	return 0;
}

void dlm_scan_waiters(struct dlm_ls *ls)
{
	struct dlm_lkb *lkb;
	ktime_t zero = ktime_set(0, 0);
	s64 us;
	s64 debug_maxus = 0;
	u32 debug_scanned = 0;
	u32 debug_expired = 0;
	int num_nodes = 0;
	int *warned = NULL;

	if (!dlm_config.ci_waitwarn_us)
		return;

	mutex_lock(&ls->ls_waiters_mutex);

	list_for_each_entry(lkb, &ls->ls_waiters, lkb_wait_reply) {
		if (ktime_equal(lkb->lkb_wait_time, zero))
			continue;

		debug_scanned++;

		us = ktime_to_us(ktime_sub(ktime_get(), lkb->lkb_wait_time));

		if (us < dlm_config.ci_waitwarn_us)
			continue;

		lkb->lkb_wait_time = zero;

		debug_expired++;
		if (us > debug_maxus)
			debug_maxus = us;

		if (!num_nodes) {
			num_nodes = ls->ls_num_nodes;
			warned = kzalloc(num_nodes * sizeof(int), GFP_KERNEL);
		}
		if (!warned)
			continue;
		if (nodeid_warned(lkb->lkb_wait_nodeid, num_nodes, warned))
			continue;

		log_error(ls, "waitwarn %x %lld %d us check connection to "
			  "node %d", lkb->lkb_id, (long long)us,
			  dlm_config.ci_waitwarn_us, lkb->lkb_wait_nodeid);
	}
	mutex_unlock(&ls->ls_waiters_mutex);
	kfree(warned);

	if (debug_expired)
		log_debug(ls, "scan_waiters %u warn %u over %d us max %lld us",
			  debug_scanned, debug_expired,
			  dlm_config.ci_waitwarn_us, (long long)debug_maxus);
}

/* add/remove lkb from global waiters list of lkb's waiting for
   a reply from a remote node */

static int add_to_waiters(struct dlm_lkb *lkb, int mstype, int to_nodeid)
{
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;
	int error = 0;

	mutex_lock(&ls->ls_waiters_mutex);

	if (is_overlap_unlock(lkb) ||
	    (is_overlap_cancel(lkb) && (mstype == DLM_MSG_CANCEL))) {
		error = -EINVAL;
		goto out;
	}

	if (lkb->lkb_wait_type || is_overlap_cancel(lkb)) {
		switch (mstype) {
		case DLM_MSG_UNLOCK:
			lkb->lkb_flags |= DLM_IFL_OVERLAP_UNLOCK;
			break;
		case DLM_MSG_CANCEL:
			lkb->lkb_flags |= DLM_IFL_OVERLAP_CANCEL;
			break;
		default:
			error = -EBUSY;
			goto out;
		}
		lkb->lkb_wait_count++;
		hold_lkb(lkb);

		log_debug(ls, "addwait %x cur %d overlap %d count %d f %x",
			  lkb->lkb_id, lkb->lkb_wait_type, mstype,
			  lkb->lkb_wait_count, lkb->lkb_flags);
		goto out;
	}

	DLM_ASSERT(!lkb->lkb_wait_count,
		   dlm_print_lkb(lkb);
		   printk("wait_count %d\n", lkb->lkb_wait_count););

	lkb->lkb_wait_count++;
	lkb->lkb_wait_type = mstype;
	lkb->lkb_wait_time = ktime_get();
	lkb->lkb_wait_nodeid = to_nodeid; /* for debugging */
	hold_lkb(lkb);
	list_add(&lkb->lkb_wait_reply, &ls->ls_waiters);
 out:
	if (error)
		log_error(ls, "addwait error %x %d flags %x %d %d %s",
			  lkb->lkb_id, error, lkb->lkb_flags, mstype,
			  lkb->lkb_wait_type, lkb->lkb_resource->res_name);
	mutex_unlock(&ls->ls_waiters_mutex);
	return error;
}

/* We clear the RESEND flag because we might be taking an lkb off the waiters
   list as part of process_requestqueue (e.g. a lookup that has an optimized
   request reply on the requestqueue) between dlm_recover_waiters_pre() which
   set RESEND and dlm_recover_waiters_post() */

static int _remove_from_waiters(struct dlm_lkb *lkb, int mstype,
				struct dlm_message *ms)
{
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;
	int overlap_done = 0;

	if (is_overlap_unlock(lkb) && (mstype == DLM_MSG_UNLOCK_REPLY)) {
		log_debug(ls, "remwait %x unlock_reply overlap", lkb->lkb_id);
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_UNLOCK;
		overlap_done = 1;
		goto out_del;
	}

	if (is_overlap_cancel(lkb) && (mstype == DLM_MSG_CANCEL_REPLY)) {
		log_debug(ls, "remwait %x cancel_reply overlap", lkb->lkb_id);
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_CANCEL;
		overlap_done = 1;
		goto out_del;
	}

	/* Cancel state was preemptively cleared by a successful convert,
	   see next comment, nothing to do. */

	if ((mstype == DLM_MSG_CANCEL_REPLY) &&
	    (lkb->lkb_wait_type != DLM_MSG_CANCEL)) {
		log_debug(ls, "remwait %x cancel_reply wait_type %d",
			  lkb->lkb_id, lkb->lkb_wait_type);
		return -1;
	}

	/* Remove for the convert reply, and premptively remove for the
	   cancel reply.  A convert has been granted while there's still
	   an outstanding cancel on it (the cancel is moot and the result
	   in the cancel reply should be 0).  We preempt the cancel reply
	   because the app gets the convert result and then can follow up
	   with another op, like convert.  This subsequent op would see the
	   lingering state of the cancel and fail with -EBUSY. */

	if ((mstype == DLM_MSG_CONVERT_REPLY) &&
	    (lkb->lkb_wait_type == DLM_MSG_CONVERT) &&
	    is_overlap_cancel(lkb) && ms && !ms->m_result) {
		log_debug(ls, "remwait %x convert_reply zap overlap_cancel",
			  lkb->lkb_id);
		lkb->lkb_wait_type = 0;
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_CANCEL;
		lkb->lkb_wait_count--;
		goto out_del;
	}

	/* N.B. type of reply may not always correspond to type of original
	   msg due to lookup->request optimization, verify others? */

	if (lkb->lkb_wait_type) {
		lkb->lkb_wait_type = 0;
		goto out_del;
	}

	log_error(ls, "remwait error %x remote %d %x msg %d flags %x no wait",
		  lkb->lkb_id, ms ? ms->m_header.h_nodeid : 0, lkb->lkb_remid,
		  mstype, lkb->lkb_flags);
	return -1;

 out_del:
	/* the force-unlock/cancel has completed and we haven't recvd a reply
	   to the op that was in progress prior to the unlock/cancel; we
	   give up on any reply to the earlier op.  FIXME: not sure when/how
	   this would happen */

	if (overlap_done && lkb->lkb_wait_type) {
		log_error(ls, "remwait error %x reply %d wait_type %d overlap",
			  lkb->lkb_id, mstype, lkb->lkb_wait_type);
		lkb->lkb_wait_count--;
		lkb->lkb_wait_type = 0;
	}

	DLM_ASSERT(lkb->lkb_wait_count, dlm_print_lkb(lkb););

	lkb->lkb_flags &= ~DLM_IFL_RESEND;
	lkb->lkb_wait_count--;
	if (!lkb->lkb_wait_count)
		list_del_init(&lkb->lkb_wait_reply);
	unhold_lkb(lkb);
	return 0;
}

static int remove_from_waiters(struct dlm_lkb *lkb, int mstype)
{
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;
	int error;

	mutex_lock(&ls->ls_waiters_mutex);
	error = _remove_from_waiters(lkb, mstype, NULL);
	mutex_unlock(&ls->ls_waiters_mutex);
	return error;
}

/* Handles situations where we might be processing a "fake" or "stub" reply in
   which we can't try to take waiters_mutex again. */

static int remove_from_waiters_ms(struct dlm_lkb *lkb, struct dlm_message *ms)
{
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;
	int error;

	if (ms->m_flags != DLM_IFL_STUB_MS)
		mutex_lock(&ls->ls_waiters_mutex);
	error = _remove_from_waiters(lkb, ms->m_type, ms);
	if (ms->m_flags != DLM_IFL_STUB_MS)
		mutex_unlock(&ls->ls_waiters_mutex);
	return error;
}

/* If there's an rsb for the same resource being removed, ensure
   that the remove message is sent before the new lookup message.
   It should be rare to need a delay here, but if not, then it may
   be worthwhile to add a proper wait mechanism rather than a delay. */

static void wait_pending_remove(struct dlm_rsb *r)
{
	struct dlm_ls *ls = r->res_ls;
 restart:
	spin_lock(&ls->ls_remove_spin);
	if (ls->ls_remove_len &&
	    !rsb_cmp(r, ls->ls_remove_name, ls->ls_remove_len)) {
		log_debug(ls, "delay lookup for remove dir %d %s",
		  	  r->res_dir_nodeid, r->res_name);
		spin_unlock(&ls->ls_remove_spin);
		msleep(1);
		goto restart;
	}
	spin_unlock(&ls->ls_remove_spin);
}

/*
 * ls_remove_spin protects ls_remove_name and ls_remove_len which are
 * read by other threads in wait_pending_remove.  ls_remove_names
 * and ls_remove_lens are only used by the scan thread, so they do
 * not need protection.
 */

static void shrink_bucket(struct dlm_ls *ls, int b)
{
	struct rb_node *n, *next;
	struct dlm_rsb *r;
	char *name;
	int our_nodeid = dlm_our_nodeid();
	int remote_count = 0;
	int need_shrink = 0;
	int i, len, rv;

	memset(&ls->ls_remove_lens, 0, sizeof(int) * DLM_REMOVE_NAMES_MAX);

	spin_lock(&ls->ls_rsbtbl[b].lock);

	if (!(ls->ls_rsbtbl[b].flags & DLM_RTF_SHRINK)) {
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		return;
	}

	for (n = rb_first(&ls->ls_rsbtbl[b].toss); n; n = next) {
		next = rb_next(n);
		r = rb_entry(n, struct dlm_rsb, res_hashnode);

		/* If we're the directory record for this rsb, and
		   we're not the master of it, then we need to wait
		   for the master node to send us a dir remove for
		   before removing the dir record. */

		if (!dlm_no_directory(ls) &&
		    (r->res_master_nodeid != our_nodeid) &&
		    (dlm_dir_nodeid(r) == our_nodeid)) {
			continue;
		}

		need_shrink = 1;

		if (!time_after_eq(jiffies, r->res_toss_time +
				   dlm_config.ci_toss_secs * HZ)) {
			continue;
		}

		if (!dlm_no_directory(ls) &&
		    (r->res_master_nodeid == our_nodeid) &&
		    (dlm_dir_nodeid(r) != our_nodeid)) {

			/* We're the master of this rsb but we're not
			   the directory record, so we need to tell the
			   dir node to remove the dir record. */

			ls->ls_remove_lens[remote_count] = r->res_length;
			memcpy(ls->ls_remove_names[remote_count], r->res_name,
			       DLM_RESNAME_MAXLEN);
			remote_count++;

			if (remote_count >= DLM_REMOVE_NAMES_MAX)
				break;
			continue;
		}

		if (!kref_put(&r->res_ref, kill_rsb)) {
			log_error(ls, "tossed rsb in use %s", r->res_name);
			continue;
		}

		rb_erase(&r->res_hashnode, &ls->ls_rsbtbl[b].toss);
		dlm_free_rsb(r);
	}

	if (need_shrink)
		ls->ls_rsbtbl[b].flags |= DLM_RTF_SHRINK;
	else
		ls->ls_rsbtbl[b].flags &= ~DLM_RTF_SHRINK;
	spin_unlock(&ls->ls_rsbtbl[b].lock);

	/*
	 * While searching for rsb's to free, we found some that require
	 * remote removal.  We leave them in place and find them again here
	 * so there is a very small gap between removing them from the toss
	 * list and sending the removal.  Keeping this gap small is
	 * important to keep us (the master node) from being out of sync
	 * with the remote dir node for very long.
	 *
	 * From the time the rsb is removed from toss until just after
	 * send_remove, the rsb name is saved in ls_remove_name.  A new
	 * lookup checks this to ensure that a new lookup message for the
	 * same resource name is not sent just before the remove message.
	 */

	for (i = 0; i < remote_count; i++) {
		name = ls->ls_remove_names[i];
		len = ls->ls_remove_lens[i];

		spin_lock(&ls->ls_rsbtbl[b].lock);
		rv = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].toss, name, len, &r);
		if (rv) {
			spin_unlock(&ls->ls_rsbtbl[b].lock);
			log_debug(ls, "remove_name not toss %s", name);
			continue;
		}

		if (r->res_master_nodeid != our_nodeid) {
			spin_unlock(&ls->ls_rsbtbl[b].lock);
			log_debug(ls, "remove_name master %d dir %d our %d %s",
				  r->res_master_nodeid, r->res_dir_nodeid,
				  our_nodeid, name);
			continue;
		}

		if (r->res_dir_nodeid == our_nodeid) {
			/* should never happen */
			spin_unlock(&ls->ls_rsbtbl[b].lock);
			log_error(ls, "remove_name dir %d master %d our %d %s",
				  r->res_dir_nodeid, r->res_master_nodeid,
				  our_nodeid, name);
			continue;
		}

		if (!time_after_eq(jiffies, r->res_toss_time +
				   dlm_config.ci_toss_secs * HZ)) {
			spin_unlock(&ls->ls_rsbtbl[b].lock);
			log_debug(ls, "remove_name toss_time %lu now %lu %s",
				  r->res_toss_time, jiffies, name);
			continue;
		}

		if (!kref_put(&r->res_ref, kill_rsb)) {
			spin_unlock(&ls->ls_rsbtbl[b].lock);
			log_error(ls, "remove_name in use %s", name);
			continue;
		}

		rb_erase(&r->res_hashnode, &ls->ls_rsbtbl[b].toss);

		/* block lookup of same name until we've sent remove */
		spin_lock(&ls->ls_remove_spin);
		ls->ls_remove_len = len;
		memcpy(ls->ls_remove_name, name, DLM_RESNAME_MAXLEN);
		spin_unlock(&ls->ls_remove_spin);
		spin_unlock(&ls->ls_rsbtbl[b].lock);

		send_remove(r);

		/* allow lookup of name again */
		spin_lock(&ls->ls_remove_spin);
		ls->ls_remove_len = 0;
		memset(ls->ls_remove_name, 0, DLM_RESNAME_MAXLEN);
		spin_unlock(&ls->ls_remove_spin);

		dlm_free_rsb(r);
	}
}

void dlm_scan_rsbs(struct dlm_ls *ls)
{
	int i;

	for (i = 0; i < ls->ls_rsbtbl_size; i++) {
		shrink_bucket(ls, i);
		if (dlm_locking_stopped(ls))
			break;
		cond_resched();
	}
}

static void add_timeout(struct dlm_lkb *lkb)
{
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;

	if (is_master_copy(lkb))
		return;

	if (test_bit(LSFL_TIMEWARN, &ls->ls_flags) &&
	    !(lkb->lkb_exflags & DLM_LKF_NODLCKWT)) {
		lkb->lkb_flags |= DLM_IFL_WATCH_TIMEWARN;
		goto add_it;
	}
	if (lkb->lkb_exflags & DLM_LKF_TIMEOUT)
		goto add_it;
	return;

 add_it:
	DLM_ASSERT(list_empty(&lkb->lkb_time_list), dlm_print_lkb(lkb););
	mutex_lock(&ls->ls_timeout_mutex);
	hold_lkb(lkb);
	list_add_tail(&lkb->lkb_time_list, &ls->ls_timeout);
	mutex_unlock(&ls->ls_timeout_mutex);
}

static void del_timeout(struct dlm_lkb *lkb)
{
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;

	mutex_lock(&ls->ls_timeout_mutex);
	if (!list_empty(&lkb->lkb_time_list)) {
		list_del_init(&lkb->lkb_time_list);
		unhold_lkb(lkb);
	}
	mutex_unlock(&ls->ls_timeout_mutex);
}

/* FIXME: is it safe to look at lkb_exflags, lkb_flags, lkb_timestamp, and
   lkb_lksb_timeout without lock_rsb?  Note: we can't lock timeout_mutex
   and then lock rsb because of lock ordering in add_timeout.  We may need
   to specify some special timeout-related bits in the lkb that are just to
   be accessed under the timeout_mutex. */

void dlm_scan_timeout(struct dlm_ls *ls)
{
	struct dlm_rsb *r;
	struct dlm_lkb *lkb;
	int do_cancel, do_warn;
	s64 wait_us;

	for (;;) {
		if (dlm_locking_stopped(ls))
			break;

		do_cancel = 0;
		do_warn = 0;
		mutex_lock(&ls->ls_timeout_mutex);
		list_for_each_entry(lkb, &ls->ls_timeout, lkb_time_list) {

			wait_us = ktime_to_us(ktime_sub(ktime_get(),
					      		lkb->lkb_timestamp));

			if ((lkb->lkb_exflags & DLM_LKF_TIMEOUT) &&
			    wait_us >= (lkb->lkb_timeout_cs * 10000))
				do_cancel = 1;

			if ((lkb->lkb_flags & DLM_IFL_WATCH_TIMEWARN) &&
			    wait_us >= dlm_config.ci_timewarn_cs * 10000)
				do_warn = 1;

			if (!do_cancel && !do_warn)
				continue;
			hold_lkb(lkb);
			break;
		}
		mutex_unlock(&ls->ls_timeout_mutex);

		if (!do_cancel && !do_warn)
			break;

		r = lkb->lkb_resource;
		hold_rsb(r);
		lock_rsb(r);

		if (do_warn) {
			/* clear flag so we only warn once */
			lkb->lkb_flags &= ~DLM_IFL_WATCH_TIMEWARN;
			if (!(lkb->lkb_exflags & DLM_LKF_TIMEOUT))
				del_timeout(lkb);
			dlm_timeout_warn(lkb);
		}

		if (do_cancel) {
			log_debug(ls, "timeout cancel %x node %d %s",
				  lkb->lkb_id, lkb->lkb_nodeid, r->res_name);
			lkb->lkb_flags &= ~DLM_IFL_WATCH_TIMEWARN;
			lkb->lkb_flags |= DLM_IFL_TIMEOUT_CANCEL;
			del_timeout(lkb);
			_cancel_lock(r, lkb);
		}

		unlock_rsb(r);
		unhold_rsb(r);
		dlm_put_lkb(lkb);
	}
}

/* This is only called by dlm_recoverd, and we rely on dlm_ls_stop() stopping
   dlm_recoverd before checking/setting ls_recover_begin. */

void dlm_adjust_timeouts(struct dlm_ls *ls)
{
	struct dlm_lkb *lkb;
	u64 adj_us = jiffies_to_usecs(jiffies - ls->ls_recover_begin);

	ls->ls_recover_begin = 0;
	mutex_lock(&ls->ls_timeout_mutex);
	list_for_each_entry(lkb, &ls->ls_timeout, lkb_time_list)
		lkb->lkb_timestamp = ktime_add_us(lkb->lkb_timestamp, adj_us);
	mutex_unlock(&ls->ls_timeout_mutex);

	if (!dlm_config.ci_waitwarn_us)
		return;

	mutex_lock(&ls->ls_waiters_mutex);
	list_for_each_entry(lkb, &ls->ls_waiters, lkb_wait_reply) {
		if (ktime_to_us(lkb->lkb_wait_time))
			lkb->lkb_wait_time = ktime_get();
	}
	mutex_unlock(&ls->ls_waiters_mutex);
}

/* lkb is master or local copy */

static void set_lvb_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int b, len = r->res_ls->ls_lvblen;

	/* b=1 lvb returned to caller
	   b=0 lvb written to rsb or invalidated
	   b=-1 do nothing */

	b =  dlm_lvb_operations[lkb->lkb_grmode + 1][lkb->lkb_rqmode + 1];

	if (b == 1) {
		if (!lkb->lkb_lvbptr)
			return;

		if (!(lkb->lkb_exflags & DLM_LKF_VALBLK))
			return;

		if (!r->res_lvbptr)
			return;

		memcpy(lkb->lkb_lvbptr, r->res_lvbptr, len);
		lkb->lkb_lvbseq = r->res_lvbseq;

	} else if (b == 0) {
		if (lkb->lkb_exflags & DLM_LKF_IVVALBLK) {
			rsb_set_flag(r, RSB_VALNOTVALID);
			return;
		}

		if (!lkb->lkb_lvbptr)
			return;

		if (!(lkb->lkb_exflags & DLM_LKF_VALBLK))
			return;

		if (!r->res_lvbptr)
			r->res_lvbptr = dlm_allocate_lvb(r->res_ls);

		if (!r->res_lvbptr)
			return;

		memcpy(r->res_lvbptr, lkb->lkb_lvbptr, len);
		r->res_lvbseq++;
		lkb->lkb_lvbseq = r->res_lvbseq;
		rsb_clear_flag(r, RSB_VALNOTVALID);
	}

	if (rsb_flag(r, RSB_VALNOTVALID))
		lkb->lkb_sbflags |= DLM_SBF_VALNOTVALID;
}

static void set_lvb_unlock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	if (lkb->lkb_grmode < DLM_LOCK_PW)
		return;

	if (lkb->lkb_exflags & DLM_LKF_IVVALBLK) {
		rsb_set_flag(r, RSB_VALNOTVALID);
		return;
	}

	if (!lkb->lkb_lvbptr)
		return;

	if (!(lkb->lkb_exflags & DLM_LKF_VALBLK))
		return;

	if (!r->res_lvbptr)
		r->res_lvbptr = dlm_allocate_lvb(r->res_ls);

	if (!r->res_lvbptr)
		return;

	memcpy(r->res_lvbptr, lkb->lkb_lvbptr, r->res_ls->ls_lvblen);
	r->res_lvbseq++;
	rsb_clear_flag(r, RSB_VALNOTVALID);
}

/* lkb is process copy (pc) */

static void set_lvb_lock_pc(struct dlm_rsb *r, struct dlm_lkb *lkb,
			    struct dlm_message *ms)
{
	int b;

	if (!lkb->lkb_lvbptr)
		return;

	if (!(lkb->lkb_exflags & DLM_LKF_VALBLK))
		return;

	b = dlm_lvb_operations[lkb->lkb_grmode + 1][lkb->lkb_rqmode + 1];
	if (b == 1) {
		int len = receive_extralen(ms);
		if (len > r->res_ls->ls_lvblen)
			len = r->res_ls->ls_lvblen;
		memcpy(lkb->lkb_lvbptr, ms->m_extra, len);
		lkb->lkb_lvbseq = ms->m_lvbseq;
	}
}

/* Manipulate lkb's on rsb's convert/granted/waiting queues
   remove_lock -- used for unlock, removes lkb from granted
   revert_lock -- used for cancel, moves lkb from convert to granted
   grant_lock  -- used for request and convert, adds lkb to granted or
                  moves lkb from convert or waiting to granted

   Each of these is used for master or local copy lkb's.  There is
   also a _pc() variation used to make the corresponding change on
   a process copy (pc) lkb. */

static void _remove_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	del_lkb(r, lkb);
	lkb->lkb_grmode = DLM_LOCK_IV;
	/* this unhold undoes the original ref from create_lkb()
	   so this leads to the lkb being freed */
	unhold_lkb(lkb);
}

static void remove_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	set_lvb_unlock(r, lkb);
	_remove_lock(r, lkb);
}

static void remove_lock_pc(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	_remove_lock(r, lkb);
}

/* returns: 0 did nothing
	    1 moved lock to granted
	   -1 removed lock */

static int revert_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int rv = 0;

	lkb->lkb_rqmode = DLM_LOCK_IV;

	switch (lkb->lkb_status) {
	case DLM_LKSTS_GRANTED:
		break;
	case DLM_LKSTS_CONVERT:
		move_lkb(r, lkb, DLM_LKSTS_GRANTED);
		rv = 1;
		break;
	case DLM_LKSTS_WAITING:
		del_lkb(r, lkb);
		lkb->lkb_grmode = DLM_LOCK_IV;
		/* this unhold undoes the original ref from create_lkb()
		   so this leads to the lkb being freed */
		unhold_lkb(lkb);
		rv = -1;
		break;
	default:
		log_print("invalid status for revert %d", lkb->lkb_status);
	}
	return rv;
}

static int revert_lock_pc(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	return revert_lock(r, lkb);
}

static void _grant_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	if (lkb->lkb_grmode != lkb->lkb_rqmode) {
		lkb->lkb_grmode = lkb->lkb_rqmode;
		if (lkb->lkb_status)
			move_lkb(r, lkb, DLM_LKSTS_GRANTED);
		else
			add_lkb(r, lkb, DLM_LKSTS_GRANTED);
	}

	lkb->lkb_rqmode = DLM_LOCK_IV;
	lkb->lkb_highbast = 0;
}

static void grant_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	set_lvb_lock(r, lkb);
	_grant_lock(r, lkb);
}

static void grant_lock_pc(struct dlm_rsb *r, struct dlm_lkb *lkb,
			  struct dlm_message *ms)
{
	set_lvb_lock_pc(r, lkb, ms);
	_grant_lock(r, lkb);
}

/* called by grant_pending_locks() which means an async grant message must
   be sent to the requesting node in addition to granting the lock if the
   lkb belongs to a remote node. */

static void grant_lock_pending(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	grant_lock(r, lkb);
	if (is_master_copy(lkb))
		send_grant(r, lkb);
	else
		queue_cast(r, lkb, 0);
}

/* The special CONVDEADLK, ALTPR and ALTCW flags allow the master to
   change the granted/requested modes.  We're munging things accordingly in
   the process copy.
   CONVDEADLK: our grmode may have been forced down to NL to resolve a
   conversion deadlock
   ALTPR/ALTCW: our rqmode may have been changed to PR or CW to become
   compatible with other granted locks */

static void munge_demoted(struct dlm_lkb *lkb)
{
	if (lkb->lkb_rqmode == DLM_LOCK_IV || lkb->lkb_grmode == DLM_LOCK_IV) {
		log_print("munge_demoted %x invalid modes gr %d rq %d",
			  lkb->lkb_id, lkb->lkb_grmode, lkb->lkb_rqmode);
		return;
	}

	lkb->lkb_grmode = DLM_LOCK_NL;
}

static void munge_altmode(struct dlm_lkb *lkb, struct dlm_message *ms)
{
	if (ms->m_type != DLM_MSG_REQUEST_REPLY &&
	    ms->m_type != DLM_MSG_GRANT) {
		log_print("munge_altmode %x invalid reply type %d",
			  lkb->lkb_id, ms->m_type);
		return;
	}

	if (lkb->lkb_exflags & DLM_LKF_ALTPR)
		lkb->lkb_rqmode = DLM_LOCK_PR;
	else if (lkb->lkb_exflags & DLM_LKF_ALTCW)
		lkb->lkb_rqmode = DLM_LOCK_CW;
	else {
		log_print("munge_altmode invalid exflags %x", lkb->lkb_exflags);
		dlm_print_lkb(lkb);
	}
}

static inline int first_in_list(struct dlm_lkb *lkb, struct list_head *head)
{
	struct dlm_lkb *first = list_entry(head->next, struct dlm_lkb,
					   lkb_statequeue);
	if (lkb->lkb_id == first->lkb_id)
		return 1;

	return 0;
}

/* Check if the given lkb conflicts with another lkb on the queue. */

static int queue_conflict(struct list_head *head, struct dlm_lkb *lkb)
{
	struct dlm_lkb *this;

	list_for_each_entry(this, head, lkb_statequeue) {
		if (this == lkb)
			continue;
		if (!modes_compat(this, lkb))
			return 1;
	}
	return 0;
}

/*
 * "A conversion deadlock arises with a pair of lock requests in the converting
 * queue for one resource.  The granted mode of each lock blocks the requested
 * mode of the other lock."
 *
 * Part 2: if the granted mode of lkb is preventing an earlier lkb in the
 * convert queue from being granted, then deadlk/demote lkb.
 *
 * Example:
 * Granted Queue: empty
 * Convert Queue: NL->EX (first lock)
 *                PR->EX (second lock)
 *
 * The first lock can't be granted because of the granted mode of the second
 * lock and the second lock can't be granted because it's not first in the
 * list.  We either cancel lkb's conversion (PR->EX) and return EDEADLK, or we
 * demote the granted mode of lkb (from PR to NL) if it has the CONVDEADLK
 * flag set and return DEMOTED in the lksb flags.
 *
 * Originally, this function detected conv-deadlk in a more limited scope:
 * - if !modes_compat(lkb1, lkb2) && !modes_compat(lkb2, lkb1), or
 * - if lkb1 was the first entry in the queue (not just earlier), and was
 *   blocked by the granted mode of lkb2, and there was nothing on the
 *   granted queue preventing lkb1 from being granted immediately, i.e.
 *   lkb2 was the only thing preventing lkb1 from being granted.
 *
 * That second condition meant we'd only say there was conv-deadlk if
 * resolving it (by demotion) would lead to the first lock on the convert
 * queue being granted right away.  It allowed conversion deadlocks to exist
 * between locks on the convert queue while they couldn't be granted anyway.
 *
 * Now, we detect and take action on conversion deadlocks immediately when
 * they're created, even if they may not be immediately consequential.  If
 * lkb1 exists anywhere in the convert queue and lkb2 comes in with a granted
 * mode that would prevent lkb1's conversion from being granted, we do a
 * deadlk/demote on lkb2 right away and don't let it onto the convert queue.
 * I think this means that the lkb_is_ahead condition below should always
 * be zero, i.e. there will never be conv-deadlk between two locks that are
 * both already on the convert queue.
 */

static int conversion_deadlock_detect(struct dlm_rsb *r, struct dlm_lkb *lkb2)
{
	struct dlm_lkb *lkb1;
	int lkb_is_ahead = 0;

	list_for_each_entry(lkb1, &r->res_convertqueue, lkb_statequeue) {
		if (lkb1 == lkb2) {
			lkb_is_ahead = 1;
			continue;
		}

		if (!lkb_is_ahead) {
			if (!modes_compat(lkb2, lkb1))
				return 1;
		} else {
			if (!modes_compat(lkb2, lkb1) &&
			    !modes_compat(lkb1, lkb2))
				return 1;
		}
	}
	return 0;
}

/*
 * Return 1 if the lock can be granted, 0 otherwise.
 * Also detect and resolve conversion deadlocks.
 *
 * lkb is the lock to be granted
 *
 * now is 1 if the function is being called in the context of the
 * immediate request, it is 0 if called later, after the lock has been
 * queued.
 *
 * recover is 1 if dlm_recover_grant() is trying to grant conversions
 * after recovery.
 *
 * References are from chapter 6 of "VAXcluster Principles" by Roy Davis
 */

static int _can_be_granted(struct dlm_rsb *r, struct dlm_lkb *lkb, int now,
			   int recover)
{
	int8_t conv = (lkb->lkb_grmode != DLM_LOCK_IV);

	/*
	 * 6-10: Version 5.4 introduced an option to address the phenomenon of
	 * a new request for a NL mode lock being blocked.
	 *
	 * 6-11: If the optional EXPEDITE flag is used with the new NL mode
	 * request, then it would be granted.  In essence, the use of this flag
	 * tells the Lock Manager to expedite theis request by not considering
	 * what may be in the CONVERTING or WAITING queues...  As of this
	 * writing, the EXPEDITE flag can be used only with new requests for NL
	 * mode locks.  This flag is not valid for conversion requests.
	 *
	 * A shortcut.  Earlier checks return an error if EXPEDITE is used in a
	 * conversion or used with a non-NL requested mode.  We also know an
	 * EXPEDITE request is always granted immediately, so now must always
	 * be 1.  The full condition to grant an expedite request: (now &&
	 * !conv && lkb->rqmode == DLM_LOCK_NL && (flags & EXPEDITE)) can
	 * therefore be shortened to just checking the flag.
	 */

	if (lkb->lkb_exflags & DLM_LKF_EXPEDITE)
		return 1;

	/*
	 * A shortcut. Without this, !queue_conflict(grantqueue, lkb) would be
	 * added to the remaining conditions.
	 */

	if (queue_conflict(&r->res_grantqueue, lkb))
		return 0;

	/*
	 * 6-3: By default, a conversion request is immediately granted if the
	 * requested mode is compatible with the modes of all other granted
	 * locks
	 */

	if (queue_conflict(&r->res_convertqueue, lkb))
		return 0;

	/*
	 * The RECOVER_GRANT flag means dlm_recover_grant() is granting
	 * locks for a recovered rsb, on which lkb's have been rebuilt.
	 * The lkb's may have been rebuilt on the queues in a different
	 * order than they were in on the previous master.  So, granting
	 * queued conversions in order after recovery doesn't make sense
	 * since the order hasn't been preserved anyway.  The new order
	 * could also have created a new "in place" conversion deadlock.
	 * (e.g. old, failed master held granted EX, with PR->EX, NL->EX.
	 * After recovery, there would be no granted locks, and possibly
	 * NL->EX, PR->EX, an in-place conversion deadlock.)  So, after
	 * recovery, grant conversions without considering order.
	 */

	if (conv && recover)
		return 1;

	/*
	 * 6-5: But the default algorithm for deciding whether to grant or
	 * queue conversion requests does not by itself guarantee that such
	 * requests are serviced on a "first come first serve" basis.  This, in
	 * turn, can lead to a phenomenon known as "indefinate postponement".
	 *
	 * 6-7: This issue is dealt with by using the optional QUECVT flag with
	 * the system service employed to request a lock conversion.  This flag
	 * forces certain conversion requests to be queued, even if they are
	 * compatible with the granted modes of other locks on the same
	 * resource.  Thus, the use of this flag results in conversion requests
	 * being ordered on a "first come first servce" basis.
	 *
	 * DCT: This condition is all about new conversions being able to occur
	 * "in place" while the lock remains on the granted queue (assuming
	 * nothing else conflicts.)  IOW if QUECVT isn't set, a conversion
	 * doesn't _have_ to go onto the convert queue where it's processed in
	 * order.  The "now" variable is necessary to distinguish converts
	 * being received and processed for the first time now, because once a
	 * convert is moved to the conversion queue the condition below applies
	 * requiring fifo granting.
	 */

	if (now && conv && !(lkb->lkb_exflags & DLM_LKF_QUECVT))
		return 1;

	/*
	 * Even if the convert is compat with all granted locks,
	 * QUECVT forces it behind other locks on the convert queue.
	 */

	if (now && conv && (lkb->lkb_exflags & DLM_LKF_QUECVT)) {
		if (list_empty(&r->res_convertqueue))
			return 1;
		else
			return 0;
	}

	/*
	 * The NOORDER flag is set to avoid the standard vms rules on grant
	 * order.
	 */

	if (lkb->lkb_exflags & DLM_LKF_NOORDER)
		return 1;

	/*
	 * 6-3: Once in that queue [CONVERTING], a conversion request cannot be
	 * granted until all other conversion requests ahead of it are granted
	 * and/or canceled.
	 */

	if (!now && conv && first_in_list(lkb, &r->res_convertqueue))
		return 1;

	/*
	 * 6-4: By default, a new request is immediately granted only if all
	 * three of the following conditions are satisfied when the request is
	 * issued:
	 * - The queue of ungranted conversion requests for the resource is
	 *   empty.
	 * - The queue of ungranted new requests for the resource is empty.
	 * - The mode of the new request is compatible with the most
	 *   restrictive mode of all granted locks on the resource.
	 */

	if (now && !conv && list_empty(&r->res_convertqueue) &&
	    list_empty(&r->res_waitqueue))
		return 1;

	/*
	 * 6-4: Once a lock request is in the queue of ungranted new requests,
	 * it cannot be granted until the queue of ungranted conversion
	 * requests is empty, all ungranted new requests ahead of it are
	 * granted and/or canceled, and it is compatible with the granted mode
	 * of the most restrictive lock granted on the resource.
	 */

	if (!now && !conv && list_empty(&r->res_convertqueue) &&
	    first_in_list(lkb, &r->res_waitqueue))
		return 1;

	return 0;
}

static int can_be_granted(struct dlm_rsb *r, struct dlm_lkb *lkb, int now,
			  int recover, int *err)
{
	int rv;
	int8_t alt = 0, rqmode = lkb->lkb_rqmode;
	int8_t is_convert = (lkb->lkb_grmode != DLM_LOCK_IV);

	if (err)
		*err = 0;

	rv = _can_be_granted(r, lkb, now, recover);
	if (rv)
		goto out;

	/*
	 * The CONVDEADLK flag is non-standard and tells the dlm to resolve
	 * conversion deadlocks by demoting grmode to NL, otherwise the dlm
	 * cancels one of the locks.
	 */

	if (is_convert && can_be_queued(lkb) &&
	    conversion_deadlock_detect(r, lkb)) {
		if (lkb->lkb_exflags & DLM_LKF_CONVDEADLK) {
			lkb->lkb_grmode = DLM_LOCK_NL;
			lkb->lkb_sbflags |= DLM_SBF_DEMOTED;
		} else if (!(lkb->lkb_exflags & DLM_LKF_NODLCKWT)) {
			if (err)
				*err = -EDEADLK;
			else {
				log_print("can_be_granted deadlock %x now %d",
					  lkb->lkb_id, now);
				dlm_dump_rsb(r);
			}
		}
		goto out;
	}

	/*
	 * The ALTPR and ALTCW flags are non-standard and tell the dlm to try
	 * to grant a request in a mode other than the normal rqmode.  It's a
	 * simple way to provide a big optimization to applications that can
	 * use them.
	 */

	if (rqmode != DLM_LOCK_PR && (lkb->lkb_exflags & DLM_LKF_ALTPR))
		alt = DLM_LOCK_PR;
	else if (rqmode != DLM_LOCK_CW && (lkb->lkb_exflags & DLM_LKF_ALTCW))
		alt = DLM_LOCK_CW;

	if (alt) {
		lkb->lkb_rqmode = alt;
		rv = _can_be_granted(r, lkb, now, 0);
		if (rv)
			lkb->lkb_sbflags |= DLM_SBF_ALTMODE;
		else
			lkb->lkb_rqmode = rqmode;
	}
 out:
	return rv;
}

/* FIXME: I don't think that can_be_granted() can/will demote or find deadlock
   for locks pending on the convert list.  Once verified (watch for these
   log_prints), we should be able to just call _can_be_granted() and not
   bother with the demote/deadlk cases here (and there's no easy way to deal
   with a deadlk here, we'd have to generate something like grant_lock with
   the deadlk error.) */

/* Returns the highest requested mode of all blocked conversions; sets
   cw if there's a blocked conversion to DLM_LOCK_CW. */

static int grant_pending_convert(struct dlm_rsb *r, int high, int *cw,
				 unsigned int *count)
{
	struct dlm_lkb *lkb, *s;
	int recover = rsb_flag(r, RSB_RECOVER_GRANT);
	int hi, demoted, quit, grant_restart, demote_restart;
	int deadlk;

	quit = 0;
 restart:
	grant_restart = 0;
	demote_restart = 0;
	hi = DLM_LOCK_IV;

	list_for_each_entry_safe(lkb, s, &r->res_convertqueue, lkb_statequeue) {
		demoted = is_demoted(lkb);
		deadlk = 0;

		if (can_be_granted(r, lkb, 0, recover, &deadlk)) {
			grant_lock_pending(r, lkb);
			grant_restart = 1;
			if (count)
				(*count)++;
			continue;
		}

		if (!demoted && is_demoted(lkb)) {
			log_print("WARN: pending demoted %x node %d %s",
				  lkb->lkb_id, lkb->lkb_nodeid, r->res_name);
			demote_restart = 1;
			continue;
		}

		if (deadlk) {
			log_print("WARN: pending deadlock %x node %d %s",
				  lkb->lkb_id, lkb->lkb_nodeid, r->res_name);
			dlm_dump_rsb(r);
			continue;
		}

		hi = max_t(int, lkb->lkb_rqmode, hi);

		if (cw && lkb->lkb_rqmode == DLM_LOCK_CW)
			*cw = 1;
	}

	if (grant_restart)
		goto restart;
	if (demote_restart && !quit) {
		quit = 1;
		goto restart;
	}

	return max_t(int, high, hi);
}

static int grant_pending_wait(struct dlm_rsb *r, int high, int *cw,
			      unsigned int *count)
{
	struct dlm_lkb *lkb, *s;

	list_for_each_entry_safe(lkb, s, &r->res_waitqueue, lkb_statequeue) {
		if (can_be_granted(r, lkb, 0, 0, NULL)) {
			grant_lock_pending(r, lkb);
			if (count)
				(*count)++;
		} else {
			high = max_t(int, lkb->lkb_rqmode, high);
			if (lkb->lkb_rqmode == DLM_LOCK_CW)
				*cw = 1;
		}
	}

	return high;
}

/* cw of 1 means there's a lock with a rqmode of DLM_LOCK_CW that's blocked
   on either the convert or waiting queue.
   high is the largest rqmode of all locks blocked on the convert or
   waiting queue. */

static int lock_requires_bast(struct dlm_lkb *gr, int high, int cw)
{
	if (gr->lkb_grmode == DLM_LOCK_PR && cw) {
		if (gr->lkb_highbast < DLM_LOCK_EX)
			return 1;
		return 0;
	}

	if (gr->lkb_highbast < high &&
	    !__dlm_compat_matrix[gr->lkb_grmode+1][high+1])
		return 1;
	return 0;
}

static void grant_pending_locks(struct dlm_rsb *r, unsigned int *count)
{
	struct dlm_lkb *lkb, *s;
	int high = DLM_LOCK_IV;
	int cw = 0;

	if (!is_master(r)) {
		log_print("grant_pending_locks r nodeid %d", r->res_nodeid);
		dlm_dump_rsb(r);
		return;
	}

	high = grant_pending_convert(r, high, &cw, count);
	high = grant_pending_wait(r, high, &cw, count);

	if (high == DLM_LOCK_IV)
		return;

	/*
	 * If there are locks left on the wait/convert queue then send blocking
	 * ASTs to granted locks based on the largest requested mode (high)
	 * found above.
	 */

	list_for_each_entry_safe(lkb, s, &r->res_grantqueue, lkb_statequeue) {
		if (lkb->lkb_bastfn && lock_requires_bast(lkb, high, cw)) {
			if (cw && high == DLM_LOCK_PR &&
			    lkb->lkb_grmode == DLM_LOCK_PR)
				queue_bast(r, lkb, DLM_LOCK_CW);
			else
				queue_bast(r, lkb, high);
			lkb->lkb_highbast = high;
		}
	}
}

static int modes_require_bast(struct dlm_lkb *gr, struct dlm_lkb *rq)
{
	if ((gr->lkb_grmode == DLM_LOCK_PR && rq->lkb_rqmode == DLM_LOCK_CW) ||
	    (gr->lkb_grmode == DLM_LOCK_CW && rq->lkb_rqmode == DLM_LOCK_PR)) {
		if (gr->lkb_highbast < DLM_LOCK_EX)
			return 1;
		return 0;
	}

	if (gr->lkb_highbast < rq->lkb_rqmode && !modes_compat(gr, rq))
		return 1;
	return 0;
}

static void send_bast_queue(struct dlm_rsb *r, struct list_head *head,
			    struct dlm_lkb *lkb)
{
	struct dlm_lkb *gr;

	list_for_each_entry(gr, head, lkb_statequeue) {
		/* skip self when sending basts to convertqueue */
		if (gr == lkb)
			continue;
		if (gr->lkb_bastfn && modes_require_bast(gr, lkb)) {
			queue_bast(r, gr, lkb->lkb_rqmode);
			gr->lkb_highbast = lkb->lkb_rqmode;
		}
	}
}

static void send_blocking_asts(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	send_bast_queue(r, &r->res_grantqueue, lkb);
}

static void send_blocking_asts_all(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	send_bast_queue(r, &r->res_grantqueue, lkb);
	send_bast_queue(r, &r->res_convertqueue, lkb);
}

/* set_master(r, lkb) -- set the master nodeid of a resource

   The purpose of this function is to set the nodeid field in the given
   lkb using the nodeid field in the given rsb.  If the rsb's nodeid is
   known, it can just be copied to the lkb and the function will return
   0.  If the rsb's nodeid is _not_ known, it needs to be looked up
   before it can be copied to the lkb.

   When the rsb nodeid is being looked up remotely, the initial lkb
   causing the lookup is kept on the ls_waiters list waiting for the
   lookup reply.  Other lkb's waiting for the same rsb lookup are kept
   on the rsb's res_lookup list until the master is verified.

   Return values:
   0: nodeid is set in rsb/lkb and the caller should go ahead and use it
   1: the rsb master is not available and the lkb has been placed on
      a wait queue
*/

static int set_master(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int our_nodeid = dlm_our_nodeid();

	if (rsb_flag(r, RSB_MASTER_UNCERTAIN)) {
		rsb_clear_flag(r, RSB_MASTER_UNCERTAIN);
		r->res_first_lkid = lkb->lkb_id;
		lkb->lkb_nodeid = r->res_nodeid;
		return 0;
	}

	if (r->res_first_lkid && r->res_first_lkid != lkb->lkb_id) {
		list_add_tail(&lkb->lkb_rsb_lookup, &r->res_lookup);
		return 1;
	}

	if (r->res_master_nodeid == our_nodeid) {
		lkb->lkb_nodeid = 0;
		return 0;
	}

	if (r->res_master_nodeid) {
		lkb->lkb_nodeid = r->res_master_nodeid;
		return 0;
	}

	if (dlm_dir_nodeid(r) == our_nodeid) {
		/* This is a somewhat unusual case; find_rsb will usually
		   have set res_master_nodeid when dir nodeid is local, but
		   there are cases where we become the dir node after we've
		   past find_rsb and go through _request_lock again.
		   confirm_master() or process_lookup_list() needs to be
		   called after this. */
		log_debug(r->res_ls, "set_master %x self master %d dir %d %s",
			  lkb->lkb_id, r->res_master_nodeid, r->res_dir_nodeid,
			  r->res_name);
		r->res_master_nodeid = our_nodeid;
		r->res_nodeid = 0;
		lkb->lkb_nodeid = 0;
		return 0;
	}

	wait_pending_remove(r);

	r->res_first_lkid = lkb->lkb_id;
	send_lookup(r, lkb);
	return 1;
}

static void process_lookup_list(struct dlm_rsb *r)
{
	struct dlm_lkb *lkb, *safe;

	list_for_each_entry_safe(lkb, safe, &r->res_lookup, lkb_rsb_lookup) {
		list_del_init(&lkb->lkb_rsb_lookup);
		_request_lock(r, lkb);
		schedule();
	}
}

/* confirm_master -- confirm (or deny) an rsb's master nodeid */

static void confirm_master(struct dlm_rsb *r, int error)
{
	struct dlm_lkb *lkb;

	if (!r->res_first_lkid)
		return;

	switch (error) {
	case 0:
	case -EINPROGRESS:
		r->res_first_lkid = 0;
		process_lookup_list(r);
		break;

	case -EAGAIN:
	case -EBADR:
	case -ENOTBLK:
		/* the remote request failed and won't be retried (it was
		   a NOQUEUE, or has been canceled/unlocked); make a waiting
		   lkb the first_lkid */

		r->res_first_lkid = 0;

		if (!list_empty(&r->res_lookup)) {
			lkb = list_entry(r->res_lookup.next, struct dlm_lkb,
					 lkb_rsb_lookup);
			list_del_init(&lkb->lkb_rsb_lookup);
			r->res_first_lkid = lkb->lkb_id;
			_request_lock(r, lkb);
		}
		break;

	default:
		log_error(r->res_ls, "confirm_master unknown error %d", error);
	}
}

static int set_lock_args(int mode, struct dlm_lksb *lksb, uint32_t flags,
			 int namelen, unsigned long timeout_cs,
			 void (*ast) (void *astparam),
			 void *astparam,
			 void (*bast) (void *astparam, int mode),
			 struct dlm_args *args)
{
	int rv = -EINVAL;

	/* check for invalid arg usage */

	if (mode < 0 || mode > DLM_LOCK_EX)
		goto out;

	if (!(flags & DLM_LKF_CONVERT) && (namelen > DLM_RESNAME_MAXLEN))
		goto out;

	if (flags & DLM_LKF_CANCEL)
		goto out;

	if (flags & DLM_LKF_QUECVT && !(flags & DLM_LKF_CONVERT))
		goto out;

	if (flags & DLM_LKF_CONVDEADLK && !(flags & DLM_LKF_CONVERT))
		goto out;

	if (flags & DLM_LKF_CONVDEADLK && flags & DLM_LKF_NOQUEUE)
		goto out;

	if (flags & DLM_LKF_EXPEDITE && flags & DLM_LKF_CONVERT)
		goto out;

	if (flags & DLM_LKF_EXPEDITE && flags & DLM_LKF_QUECVT)
		goto out;

	if (flags & DLM_LKF_EXPEDITE && flags & DLM_LKF_NOQUEUE)
		goto out;

	if (flags & DLM_LKF_EXPEDITE && mode != DLM_LOCK_NL)
		goto out;

	if (!ast || !lksb)
		goto out;

	if (flags & DLM_LKF_VALBLK && !lksb->sb_lvbptr)
		goto out;

	if (flags & DLM_LKF_CONVERT && !lksb->sb_lkid)
		goto out;

	/* these args will be copied to the lkb in validate_lock_args,
	   it cannot be done now because when converting locks, fields in
	   an active lkb cannot be modified before locking the rsb */

	args->flags = flags;
	args->astfn = ast;
	args->astparam = astparam;
	args->bastfn = bast;
	args->timeout = timeout_cs;
	args->mode = mode;
	args->lksb = lksb;
	rv = 0;
 out:
	return rv;
}

static int set_unlock_args(uint32_t flags, void *astarg, struct dlm_args *args)
{
	if (flags & ~(DLM_LKF_CANCEL | DLM_LKF_VALBLK | DLM_LKF_IVVALBLK |
 		      DLM_LKF_FORCEUNLOCK))
		return -EINVAL;

	if (flags & DLM_LKF_CANCEL && flags & DLM_LKF_FORCEUNLOCK)
		return -EINVAL;

	args->flags = flags;
	args->astparam = astarg;
	return 0;
}

static int validate_lock_args(struct dlm_ls *ls, struct dlm_lkb *lkb,
			      struct dlm_args *args)
{
	int rv = -EINVAL;

	if (args->flags & DLM_LKF_CONVERT) {
		if (lkb->lkb_flags & DLM_IFL_MSTCPY)
			goto out;

		if (args->flags & DLM_LKF_QUECVT &&
		    !__quecvt_compat_matrix[lkb->lkb_grmode+1][args->mode+1])
			goto out;

		rv = -EBUSY;
		if (lkb->lkb_status != DLM_LKSTS_GRANTED)
			goto out;

		if (lkb->lkb_wait_type)
			goto out;

		if (is_overlap(lkb))
			goto out;
	}

	lkb->lkb_exflags = args->flags;
	lkb->lkb_sbflags = 0;
	lkb->lkb_astfn = args->astfn;
	lkb->lkb_astparam = args->astparam;
	lkb->lkb_bastfn = args->bastfn;
	lkb->lkb_rqmode = args->mode;
	lkb->lkb_lksb = args->lksb;
	lkb->lkb_lvbptr = args->lksb->sb_lvbptr;
	lkb->lkb_ownpid = (int) current->pid;
	lkb->lkb_timeout_cs = args->timeout;
	rv = 0;
 out:
	if (rv)
		log_debug(ls, "validate_lock_args %d %x %x %x %d %d %s",
			  rv, lkb->lkb_id, lkb->lkb_flags, args->flags,
			  lkb->lkb_status, lkb->lkb_wait_type,
			  lkb->lkb_resource->res_name);
	return rv;
}

/* when dlm_unlock() sees -EBUSY with CANCEL/FORCEUNLOCK it returns 0
   for success */

/* note: it's valid for lkb_nodeid/res_nodeid to be -1 when we get here
   because there may be a lookup in progress and it's valid to do
   cancel/unlockf on it */

static int validate_unlock_args(struct dlm_lkb *lkb, struct dlm_args *args)
{
	struct dlm_ls *ls = lkb->lkb_resource->res_ls;
	int rv = -EINVAL;

	if (lkb->lkb_flags & DLM_IFL_MSTCPY) {
		log_error(ls, "unlock on MSTCPY %x", lkb->lkb_id);
		dlm_print_lkb(lkb);
		goto out;
	}

	/* an lkb may still exist even though the lock is EOL'ed due to a
	   cancel, unlock or failed noqueue request; an app can't use these
	   locks; return same error as if the lkid had not been found at all */

	if (lkb->lkb_flags & DLM_IFL_ENDOFLIFE) {
		log_debug(ls, "unlock on ENDOFLIFE %x", lkb->lkb_id);
		rv = -ENOENT;
		goto out;
	}

	/* an lkb may be waiting for an rsb lookup to complete where the
	   lookup was initiated by another lock */

	if (!list_empty(&lkb->lkb_rsb_lookup)) {
		if (args->flags & (DLM_LKF_CANCEL | DLM_LKF_FORCEUNLOCK)) {
			log_debug(ls, "unlock on rsb_lookup %x", lkb->lkb_id);
			list_del_init(&lkb->lkb_rsb_lookup);
			queue_cast(lkb->lkb_resource, lkb,
				   args->flags & DLM_LKF_CANCEL ?
				   -DLM_ECANCEL : -DLM_EUNLOCK);
			unhold_lkb(lkb); /* undoes create_lkb() */
		}
		/* caller changes -EBUSY to 0 for CANCEL and FORCEUNLOCK */
		rv = -EBUSY;
		goto out;
	}

	/* cancel not allowed with another cancel/unlock in progress */

	if (args->flags & DLM_LKF_CANCEL) {
		if (lkb->lkb_exflags & DLM_LKF_CANCEL)
			goto out;

		if (is_overlap(lkb))
			goto out;

		/* don't let scand try to do a cancel */
		del_timeout(lkb);

		if (lkb->lkb_flags & DLM_IFL_RESEND) {
			lkb->lkb_flags |= DLM_IFL_OVERLAP_CANCEL;
			rv = -EBUSY;
			goto out;
		}

		/* there's nothing to cancel */
		if (lkb->lkb_status == DLM_LKSTS_GRANTED &&
		    !lkb->lkb_wait_type) {
			rv = -EBUSY;
			goto out;
		}

		switch (lkb->lkb_wait_type) {
		case DLM_MSG_LOOKUP:
		case DLM_MSG_REQUEST:
			lkb->lkb_flags |= DLM_IFL_OVERLAP_CANCEL;
			rv = -EBUSY;
			goto out;
		case DLM_MSG_UNLOCK:
		case DLM_MSG_CANCEL:
			goto out;
		}
		/* add_to_waiters() will set OVERLAP_CANCEL */
		goto out_ok;
	}

	/* do we need to allow a force-unlock if there's a normal unlock
	   already in progress?  in what conditions could the normal unlock
	   fail such that we'd want to send a force-unlock to be sure? */

	if (args->flags & DLM_LKF_FORCEUNLOCK) {
		if (lkb->lkb_exflags & DLM_LKF_FORCEUNLOCK)
			goto out;

		if (is_overlap_unlock(lkb))
			goto out;

		/* don't let scand try to do a cancel */
		del_timeout(lkb);

		if (lkb->lkb_flags & DLM_IFL_RESEND) {
			lkb->lkb_flags |= DLM_IFL_OVERLAP_UNLOCK;
			rv = -EBUSY;
			goto out;
		}

		switch (lkb->lkb_wait_type) {
		case DLM_MSG_LOOKUP:
		case DLM_MSG_REQUEST:
			lkb->lkb_flags |= DLM_IFL_OVERLAP_UNLOCK;
			rv = -EBUSY;
			goto out;
		case DLM_MSG_UNLOCK:
			goto out;
		}
		/* add_to_waiters() will set OVERLAP_UNLOCK */
		goto out_ok;
	}

	/* normal unlock not allowed if there's any op in progress */
	rv = -EBUSY;
	if (lkb->lkb_wait_type || lkb->lkb_wait_count)
		goto out;

 out_ok:
	/* an overlapping op shouldn't blow away exflags from other op */
	lkb->lkb_exflags |= args->flags;
	lkb->lkb_sbflags = 0;
	lkb->lkb_astparam = args->astparam;
	rv = 0;
 out:
	if (rv)
		log_debug(ls, "validate_unlock_args %d %x %x %x %x %d %s", rv,
			  lkb->lkb_id, lkb->lkb_flags, lkb->lkb_exflags,
			  args->flags, lkb->lkb_wait_type,
			  lkb->lkb_resource->res_name);
	return rv;
}

/*
 * Four stage 4 varieties:
 * do_request(), do_convert(), do_unlock(), do_cancel()
 * These are called on the master node for the given lock and
 * from the central locking logic.
 */

static int do_request(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int error = 0;

	if (can_be_granted(r, lkb, 1, 0, NULL)) {
		grant_lock(r, lkb);
		queue_cast(r, lkb, 0);
		goto out;
	}

	if (can_be_queued(lkb)) {
		error = -EINPROGRESS;
		add_lkb(r, lkb, DLM_LKSTS_WAITING);
		add_timeout(lkb);
		goto out;
	}

	error = -EAGAIN;
	queue_cast(r, lkb, -EAGAIN);
 out:
	return error;
}

static void do_request_effects(struct dlm_rsb *r, struct dlm_lkb *lkb,
			       int error)
{
	switch (error) {
	case -EAGAIN:
		if (force_blocking_asts(lkb))
			send_blocking_asts_all(r, lkb);
		break;
	case -EINPROGRESS:
		send_blocking_asts(r, lkb);
		break;
	}
}

static int do_convert(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int error = 0;
	int deadlk = 0;

	/* changing an existing lock may allow others to be granted */

	if (can_be_granted(r, lkb, 1, 0, &deadlk)) {
		grant_lock(r, lkb);
		queue_cast(r, lkb, 0);
		goto out;
	}

	/* can_be_granted() detected that this lock would block in a conversion
	   deadlock, so we leave it on the granted queue and return EDEADLK in
	   the ast for the convert. */

	if (deadlk) {
		/* it's left on the granted queue */
		revert_lock(r, lkb);
		queue_cast(r, lkb, -EDEADLK);
		error = -EDEADLK;
		goto out;
	}

	/* is_demoted() means the can_be_granted() above set the grmode
	   to NL, and left us on the granted queue.  This auto-demotion
	   (due to CONVDEADLK) might mean other locks, and/or this lock, are
	   now grantable.  We have to try to grant other converting locks
	   before we try again to grant this one. */

	if (is_demoted(lkb)) {
		grant_pending_convert(r, DLM_LOCK_IV, NULL, NULL);
		if (_can_be_granted(r, lkb, 1, 0)) {
			grant_lock(r, lkb);
			queue_cast(r, lkb, 0);
			goto out;
		}
		/* else fall through and move to convert queue */
	}

	if (can_be_queued(lkb)) {
		error = -EINPROGRESS;
		del_lkb(r, lkb);
		add_lkb(r, lkb, DLM_LKSTS_CONVERT);
		add_timeout(lkb);
		goto out;
	}

	error = -EAGAIN;
	queue_cast(r, lkb, -EAGAIN);
 out:
	return error;
}

static void do_convert_effects(struct dlm_rsb *r, struct dlm_lkb *lkb,
			       int error)
{
	switch (error) {
	case 0:
		grant_pending_locks(r, NULL);
		/* grant_pending_locks also sends basts */
		break;
	case -EAGAIN:
		if (force_blocking_asts(lkb))
			send_blocking_asts_all(r, lkb);
		break;
	case -EINPROGRESS:
		send_blocking_asts(r, lkb);
		break;
	}
}

static int do_unlock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	remove_lock(r, lkb);
	queue_cast(r, lkb, -DLM_EUNLOCK);
	return -DLM_EUNLOCK;
}

static void do_unlock_effects(struct dlm_rsb *r, struct dlm_lkb *lkb,
			      int error)
{
	grant_pending_locks(r, NULL);
}

/* returns: 0 did nothing, -DLM_ECANCEL canceled lock */

static int do_cancel(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int error;

	error = revert_lock(r, lkb);
	if (error) {
		queue_cast(r, lkb, -DLM_ECANCEL);
		return -DLM_ECANCEL;
	}
	return 0;
}

static void do_cancel_effects(struct dlm_rsb *r, struct dlm_lkb *lkb,
			      int error)
{
	if (error)
		grant_pending_locks(r, NULL);
}

/*
 * Four stage 3 varieties:
 * _request_lock(), _convert_lock(), _unlock_lock(), _cancel_lock()
 */

/* add a new lkb to a possibly new rsb, called by requesting process */

static int _request_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int error;

	/* set_master: sets lkb nodeid from r */

	error = set_master(r, lkb);
	if (error < 0)
		goto out;
	if (error) {
		error = 0;
		goto out;
	}

	if (is_remote(r)) {
		/* receive_request() calls do_request() on remote node */
		error = send_request(r, lkb);
	} else {
		error = do_request(r, lkb);
		/* for remote locks the request_reply is sent
		   between do_request and do_request_effects */
		do_request_effects(r, lkb, error);
	}
 out:
	return error;
}

/* change some property of an existing lkb, e.g. mode */

static int _convert_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int error;

	if (is_remote(r)) {
		/* receive_convert() calls do_convert() on remote node */
		error = send_convert(r, lkb);
	} else {
		error = do_convert(r, lkb);
		/* for remote locks the convert_reply is sent
		   between do_convert and do_convert_effects */
		do_convert_effects(r, lkb, error);
	}

	return error;
}

/* remove an existing lkb from the granted queue */

static int _unlock_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int error;

	if (is_remote(r)) {
		/* receive_unlock() calls do_unlock() on remote node */
		error = send_unlock(r, lkb);
	} else {
		error = do_unlock(r, lkb);
		/* for remote locks the unlock_reply is sent
		   between do_unlock and do_unlock_effects */
		do_unlock_effects(r, lkb, error);
	}

	return error;
}

/* remove an existing lkb from the convert or wait queue */

static int _cancel_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int error;

	if (is_remote(r)) {
		/* receive_cancel() calls do_cancel() on remote node */
		error = send_cancel(r, lkb);
	} else {
		error = do_cancel(r, lkb);
		/* for remote locks the cancel_reply is sent
		   between do_cancel and do_cancel_effects */
		do_cancel_effects(r, lkb, error);
	}

	return error;
}

/*
 * Four stage 2 varieties:
 * request_lock(), convert_lock(), unlock_lock(), cancel_lock()
 */

static int request_lock(struct dlm_ls *ls, struct dlm_lkb *lkb, char *name,
			int len, struct dlm_args *args)
{
	struct dlm_rsb *r;
	int error;

	error = validate_lock_args(ls, lkb, args);
	if (error)
		return error;

	error = find_rsb(ls, name, len, 0, R_REQUEST, &r);
	if (error)
		return error;

	lock_rsb(r);

	attach_lkb(r, lkb);
	lkb->lkb_lksb->sb_lkid = lkb->lkb_id;

	error = _request_lock(r, lkb);

	unlock_rsb(r);
	put_rsb(r);
	return error;
}

static int convert_lock(struct dlm_ls *ls, struct dlm_lkb *lkb,
			struct dlm_args *args)
{
	struct dlm_rsb *r;
	int error;

	r = lkb->lkb_resource;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_lock_args(ls, lkb, args);
	if (error)
		goto out;

	error = _convert_lock(r, lkb);
 out:
	unlock_rsb(r);
	put_rsb(r);
	return error;
}

static int unlock_lock(struct dlm_ls *ls, struct dlm_lkb *lkb,
		       struct dlm_args *args)
{
	struct dlm_rsb *r;
	int error;

	r = lkb->lkb_resource;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_unlock_args(lkb, args);
	if (error)
		goto out;

	error = _unlock_lock(r, lkb);
 out:
	unlock_rsb(r);
	put_rsb(r);
	return error;
}

static int cancel_lock(struct dlm_ls *ls, struct dlm_lkb *lkb,
		       struct dlm_args *args)
{
	struct dlm_rsb *r;
	int error;

	r = lkb->lkb_resource;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_unlock_args(lkb, args);
	if (error)
		goto out;

	error = _cancel_lock(r, lkb);
 out:
	unlock_rsb(r);
	put_rsb(r);
	return error;
}

/*
 * Two stage 1 varieties:  dlm_lock() and dlm_unlock()
 */

int dlm_lock(dlm_lockspace_t *lockspace,
	     int mode,
	     struct dlm_lksb *lksb,
	     uint32_t flags,
	     void *name,
	     unsigned int namelen,
	     uint32_t parent_lkid,
	     void (*ast) (void *astarg),
	     void *astarg,
	     void (*bast) (void *astarg, int mode))
{
	struct dlm_ls *ls;
	struct dlm_lkb *lkb;
	struct dlm_args args;
	int error, convert = flags & DLM_LKF_CONVERT;

	ls = dlm_find_lockspace_local(lockspace);
	if (!ls)
		return -EINVAL;

	dlm_lock_recovery(ls);

	if (convert)
		error = find_lkb(ls, lksb->sb_lkid, &lkb);
	else
		error = create_lkb(ls, &lkb);

	if (error)
		goto out;

	error = set_lock_args(mode, lksb, flags, namelen, 0, ast,
			      astarg, bast, &args);
	if (error)
		goto out_put;

	if (convert)
		error = convert_lock(ls, lkb, &args);
	else
		error = request_lock(ls, lkb, name, namelen, &args);

	if (error == -EINPROGRESS)
		error = 0;
 out_put:
	if (convert || error)
		__put_lkb(ls, lkb);
	if (error == -EAGAIN || error == -EDEADLK)
		error = 0;
 out:
	dlm_unlock_recovery(ls);
	dlm_put_lockspace(ls);
	return error;
}

int dlm_unlock(dlm_lockspace_t *lockspace,
	       uint32_t lkid,
	       uint32_t flags,
	       struct dlm_lksb *lksb,
	       void *astarg)
{
	struct dlm_ls *ls;
	struct dlm_lkb *lkb;
	struct dlm_args args;
	int error;

	ls = dlm_find_lockspace_local(lockspace);
	if (!ls)
		return -EINVAL;

	dlm_lock_recovery(ls);

	error = find_lkb(ls, lkid, &lkb);
	if (error)
		goto out;

	error = set_unlock_args(flags, astarg, &args);
	if (error)
		goto out_put;

	if (flags & DLM_LKF_CANCEL)
		error = cancel_lock(ls, lkb, &args);
	else
		error = unlock_lock(ls, lkb, &args);

	if (error == -DLM_EUNLOCK || error == -DLM_ECANCEL)
		error = 0;
	if (error == -EBUSY && (flags & (DLM_LKF_CANCEL | DLM_LKF_FORCEUNLOCK)))
		error = 0;
 out_put:
	dlm_put_lkb(lkb);
 out:
	dlm_unlock_recovery(ls);
	dlm_put_lockspace(ls);
	return error;
}

/*
 * send/receive routines for remote operations and replies
 *
 * send_args
 * send_common
 * send_request			receive_request
 * send_convert			receive_convert
 * send_unlock			receive_unlock
 * send_cancel			receive_cancel
 * send_grant			receive_grant
 * send_bast			receive_bast
 * send_lookup			receive_lookup
 * send_remove			receive_remove
 *
 * 				send_common_reply
 * receive_request_reply	send_request_reply
 * receive_convert_reply	send_convert_reply
 * receive_unlock_reply		send_unlock_reply
 * receive_cancel_reply		send_cancel_reply
 * receive_lookup_reply		send_lookup_reply
 */

static int _create_message(struct dlm_ls *ls, int mb_len,
			   int to_nodeid, int mstype,
			   struct dlm_message **ms_ret,
			   struct dlm_mhandle **mh_ret)
{
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	char *mb;

	/* get_buffer gives us a message handle (mh) that we need to
	   pass into lowcomms_commit and a message buffer (mb) that we
	   write our data into */

	mh = dlm_lowcomms_get_buffer(to_nodeid, mb_len, GFP_NOFS, &mb);
	if (!mh)
		return -ENOBUFS;

	memset(mb, 0, mb_len);

	ms = (struct dlm_message *) mb;

	ms->m_header.h_version = (DLM_HEADER_MAJOR | DLM_HEADER_MINOR);
	ms->m_header.h_lockspace = ls->ls_global_id;
	ms->m_header.h_nodeid = dlm_our_nodeid();
	ms->m_header.h_length = mb_len;
	ms->m_header.h_cmd = DLM_MSG;

	ms->m_type = mstype;

	*mh_ret = mh;
	*ms_ret = ms;
	return 0;
}

static int create_message(struct dlm_rsb *r, struct dlm_lkb *lkb,
			  int to_nodeid, int mstype,
			  struct dlm_message **ms_ret,
			  struct dlm_mhandle **mh_ret)
{
	int mb_len = sizeof(struct dlm_message);

	switch (mstype) {
	case DLM_MSG_REQUEST:
	case DLM_MSG_LOOKUP:
	case DLM_MSG_REMOVE:
		mb_len += r->res_length;
		break;
	case DLM_MSG_CONVERT:
	case DLM_MSG_UNLOCK:
	case DLM_MSG_REQUEST_REPLY:
	case DLM_MSG_CONVERT_REPLY:
	case DLM_MSG_GRANT:
		if (lkb && lkb->lkb_lvbptr)
			mb_len += r->res_ls->ls_lvblen;
		break;
	}

	return _create_message(r->res_ls, mb_len, to_nodeid, mstype,
			       ms_ret, mh_ret);
}

/* further lowcomms enhancements or alternate implementations may make
   the return value from this function useful at some point */

static int send_message(struct dlm_mhandle *mh, struct dlm_message *ms)
{
	dlm_message_out(ms);
	dlm_lowcomms_commit_buffer(mh);
	return 0;
}

static void send_args(struct dlm_rsb *r, struct dlm_lkb *lkb,
		      struct dlm_message *ms)
{
	ms->m_nodeid   = lkb->lkb_nodeid;
	ms->m_pid      = lkb->lkb_ownpid;
	ms->m_lkid     = lkb->lkb_id;
	ms->m_remid    = lkb->lkb_remid;
	ms->m_exflags  = lkb->lkb_exflags;
	ms->m_sbflags  = lkb->lkb_sbflags;
	ms->m_flags    = lkb->lkb_flags;
	ms->m_lvbseq   = lkb->lkb_lvbseq;
	ms->m_status   = lkb->lkb_status;
	ms->m_grmode   = lkb->lkb_grmode;
	ms->m_rqmode   = lkb->lkb_rqmode;
	ms->m_hash     = r->res_hash;

	/* m_result and m_bastmode are set from function args,
	   not from lkb fields */

	if (lkb->lkb_bastfn)
		ms->m_asts |= DLM_CB_BAST;
	if (lkb->lkb_astfn)
		ms->m_asts |= DLM_CB_CAST;

	/* compare with switch in create_message; send_remove() doesn't
	   use send_args() */

	switch (ms->m_type) {
	case DLM_MSG_REQUEST:
	case DLM_MSG_LOOKUP:
		memcpy(ms->m_extra, r->res_name, r->res_length);
		break;
	case DLM_MSG_CONVERT:
	case DLM_MSG_UNLOCK:
	case DLM_MSG_REQUEST_REPLY:
	case DLM_MSG_CONVERT_REPLY:
	case DLM_MSG_GRANT:
		if (!lkb->lkb_lvbptr)
			break;
		memcpy(ms->m_extra, lkb->lkb_lvbptr, r->res_ls->ls_lvblen);
		break;
	}
}

static int send_common(struct dlm_rsb *r, struct dlm_lkb *lkb, int mstype)
{
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	int to_nodeid, error;

	to_nodeid = r->res_nodeid;

	error = add_to_waiters(lkb, mstype, to_nodeid);
	if (error)
		return error;

	error = create_message(r, lkb, to_nodeid, mstype, &ms, &mh);
	if (error)
		goto fail;

	send_args(r, lkb, ms);

	error = send_message(mh, ms);
	if (error)
		goto fail;
	return 0;

 fail:
	remove_from_waiters(lkb, msg_reply_type(mstype));
	return error;
}

static int send_request(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	return send_common(r, lkb, DLM_MSG_REQUEST);
}

static int send_convert(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	int error;

	error = send_common(r, lkb, DLM_MSG_CONVERT);

	/* down conversions go without a reply from the master */
	if (!error && down_conversion(lkb)) {
		remove_from_waiters(lkb, DLM_MSG_CONVERT_REPLY);
		r->res_ls->ls_stub_ms.m_flags = DLM_IFL_STUB_MS;
		r->res_ls->ls_stub_ms.m_type = DLM_MSG_CONVERT_REPLY;
		r->res_ls->ls_stub_ms.m_result = 0;
		__receive_convert_reply(r, lkb, &r->res_ls->ls_stub_ms);
	}

	return error;
}

/* FIXME: if this lkb is the only lock we hold on the rsb, then set
   MASTER_UNCERTAIN to force the next request on the rsb to confirm
   that the master is still correct. */

static int send_unlock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	return send_common(r, lkb, DLM_MSG_UNLOCK);
}

static int send_cancel(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	return send_common(r, lkb, DLM_MSG_CANCEL);
}

static int send_grant(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	int to_nodeid, error;

	to_nodeid = lkb->lkb_nodeid;

	error = create_message(r, lkb, to_nodeid, DLM_MSG_GRANT, &ms, &mh);
	if (error)
		goto out;

	send_args(r, lkb, ms);

	ms->m_result = 0;

	error = send_message(mh, ms);
 out:
	return error;
}

static int send_bast(struct dlm_rsb *r, struct dlm_lkb *lkb, int mode)
{
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	int to_nodeid, error;

	to_nodeid = lkb->lkb_nodeid;

	error = create_message(r, NULL, to_nodeid, DLM_MSG_BAST, &ms, &mh);
	if (error)
		goto out;

	send_args(r, lkb, ms);

	ms->m_bastmode = mode;

	error = send_message(mh, ms);
 out:
	return error;
}

static int send_lookup(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	int to_nodeid, error;

	to_nodeid = dlm_dir_nodeid(r);

	error = add_to_waiters(lkb, DLM_MSG_LOOKUP, to_nodeid);
	if (error)
		return error;

	error = create_message(r, NULL, to_nodeid, DLM_MSG_LOOKUP, &ms, &mh);
	if (error)
		goto fail;

	send_args(r, lkb, ms);

	error = send_message(mh, ms);
	if (error)
		goto fail;
	return 0;

 fail:
	remove_from_waiters(lkb, DLM_MSG_LOOKUP_REPLY);
	return error;
}

static int send_remove(struct dlm_rsb *r)
{
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	int to_nodeid, error;

	to_nodeid = dlm_dir_nodeid(r);

	error = create_message(r, NULL, to_nodeid, DLM_MSG_REMOVE, &ms, &mh);
	if (error)
		goto out;

	memcpy(ms->m_extra, r->res_name, r->res_length);
	ms->m_hash = r->res_hash;

	error = send_message(mh, ms);
 out:
	return error;
}

static int send_common_reply(struct dlm_rsb *r, struct dlm_lkb *lkb,
			     int mstype, int rv)
{
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	int to_nodeid, error;

	to_nodeid = lkb->lkb_nodeid;

	error = create_message(r, lkb, to_nodeid, mstype, &ms, &mh);
	if (error)
		goto out;

	send_args(r, lkb, ms);

	ms->m_result = rv;

	error = send_message(mh, ms);
 out:
	return error;
}

static int send_request_reply(struct dlm_rsb *r, struct dlm_lkb *lkb, int rv)
{
	return send_common_reply(r, lkb, DLM_MSG_REQUEST_REPLY, rv);
}

static int send_convert_reply(struct dlm_rsb *r, struct dlm_lkb *lkb, int rv)
{
	return send_common_reply(r, lkb, DLM_MSG_CONVERT_REPLY, rv);
}

static int send_unlock_reply(struct dlm_rsb *r, struct dlm_lkb *lkb, int rv)
{
	return send_common_reply(r, lkb, DLM_MSG_UNLOCK_REPLY, rv);
}

static int send_cancel_reply(struct dlm_rsb *r, struct dlm_lkb *lkb, int rv)
{
	return send_common_reply(r, lkb, DLM_MSG_CANCEL_REPLY, rv);
}

static int send_lookup_reply(struct dlm_ls *ls, struct dlm_message *ms_in,
			     int ret_nodeid, int rv)
{
	struct dlm_rsb *r = &ls->ls_stub_rsb;
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	int error, nodeid = ms_in->m_header.h_nodeid;

	error = create_message(r, NULL, nodeid, DLM_MSG_LOOKUP_REPLY, &ms, &mh);
	if (error)
		goto out;

	ms->m_lkid = ms_in->m_lkid;
	ms->m_result = rv;
	ms->m_nodeid = ret_nodeid;

	error = send_message(mh, ms);
 out:
	return error;
}

/* which args we save from a received message depends heavily on the type
   of message, unlike the send side where we can safely send everything about
   the lkb for any type of message */

static void receive_flags(struct dlm_lkb *lkb, struct dlm_message *ms)
{
	lkb->lkb_exflags = ms->m_exflags;
	lkb->lkb_sbflags = ms->m_sbflags;
	lkb->lkb_flags = (lkb->lkb_flags & 0xFFFF0000) |
		         (ms->m_flags & 0x0000FFFF);
}

static void receive_flags_reply(struct dlm_lkb *lkb, struct dlm_message *ms)
{
	if (ms->m_flags == DLM_IFL_STUB_MS)
		return;

	lkb->lkb_sbflags = ms->m_sbflags;
	lkb->lkb_flags = (lkb->lkb_flags & 0xFFFF0000) |
		         (ms->m_flags & 0x0000FFFF);
}

static int receive_extralen(struct dlm_message *ms)
{
	return (ms->m_header.h_length - sizeof(struct dlm_message));
}

static int receive_lvb(struct dlm_ls *ls, struct dlm_lkb *lkb,
		       struct dlm_message *ms)
{
	int len;

	if (lkb->lkb_exflags & DLM_LKF_VALBLK) {
		if (!lkb->lkb_lvbptr)
			lkb->lkb_lvbptr = dlm_allocate_lvb(ls);
		if (!lkb->lkb_lvbptr)
			return -ENOMEM;
		len = receive_extralen(ms);
		if (len > ls->ls_lvblen)
			len = ls->ls_lvblen;
		memcpy(lkb->lkb_lvbptr, ms->m_extra, len);
	}
	return 0;
}

static void fake_bastfn(void *astparam, int mode)
{
	log_print("fake_bastfn should not be called");
}

static void fake_astfn(void *astparam)
{
	log_print("fake_astfn should not be called");
}

static int receive_request_args(struct dlm_ls *ls, struct dlm_lkb *lkb,
				struct dlm_message *ms)
{
	lkb->lkb_nodeid = ms->m_header.h_nodeid;
	lkb->lkb_ownpid = ms->m_pid;
	lkb->lkb_remid = ms->m_lkid;
	lkb->lkb_grmode = DLM_LOCK_IV;
	lkb->lkb_rqmode = ms->m_rqmode;

	lkb->lkb_bastfn = (ms->m_asts & DLM_CB_BAST) ? &fake_bastfn : NULL;
	lkb->lkb_astfn = (ms->m_asts & DLM_CB_CAST) ? &fake_astfn : NULL;

	if (lkb->lkb_exflags & DLM_LKF_VALBLK) {
		/* lkb was just created so there won't be an lvb yet */
		lkb->lkb_lvbptr = dlm_allocate_lvb(ls);
		if (!lkb->lkb_lvbptr)
			return -ENOMEM;
	}

	return 0;
}

static int receive_convert_args(struct dlm_ls *ls, struct dlm_lkb *lkb,
				struct dlm_message *ms)
{
	if (lkb->lkb_status != DLM_LKSTS_GRANTED)
		return -EBUSY;

	if (receive_lvb(ls, lkb, ms))
		return -ENOMEM;

	lkb->lkb_rqmode = ms->m_rqmode;
	lkb->lkb_lvbseq = ms->m_lvbseq;

	return 0;
}

static int receive_unlock_args(struct dlm_ls *ls, struct dlm_lkb *lkb,
			       struct dlm_message *ms)
{
	if (receive_lvb(ls, lkb, ms))
		return -ENOMEM;
	return 0;
}

/* We fill in the stub-lkb fields with the info that send_xxxx_reply()
   uses to send a reply and that the remote end uses to process the reply. */

static void setup_stub_lkb(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb = &ls->ls_stub_lkb;
	lkb->lkb_nodeid = ms->m_header.h_nodeid;
	lkb->lkb_remid = ms->m_lkid;
}

/* This is called after the rsb is locked so that we can safely inspect
   fields in the lkb. */

static int validate_message(struct dlm_lkb *lkb, struct dlm_message *ms)
{
	int from = ms->m_header.h_nodeid;
	int error = 0;

	switch (ms->m_type) {
	case DLM_MSG_CONVERT:
	case DLM_MSG_UNLOCK:
	case DLM_MSG_CANCEL:
		if (!is_master_copy(lkb) || lkb->lkb_nodeid != from)
			error = -EINVAL;
		break;

	case DLM_MSG_CONVERT_REPLY:
	case DLM_MSG_UNLOCK_REPLY:
	case DLM_MSG_CANCEL_REPLY:
	case DLM_MSG_GRANT:
	case DLM_MSG_BAST:
		if (!is_process_copy(lkb) || lkb->lkb_nodeid != from)
			error = -EINVAL;
		break;

	case DLM_MSG_REQUEST_REPLY:
		if (!is_process_copy(lkb))
			error = -EINVAL;
		else if (lkb->lkb_nodeid != -1 && lkb->lkb_nodeid != from)
			error = -EINVAL;
		break;

	default:
		error = -EINVAL;
	}

	if (error)
		log_error(lkb->lkb_resource->res_ls,
			  "ignore invalid message %d from %d %x %x %x %d",
			  ms->m_type, from, lkb->lkb_id, lkb->lkb_remid,
			  lkb->lkb_flags, lkb->lkb_nodeid);
	return error;
}

static void send_repeat_remove(struct dlm_ls *ls, char *ms_name, int len)
{
	char name[DLM_RESNAME_MAXLEN + 1];
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	struct dlm_rsb *r;
	uint32_t hash, b;
	int rv, dir_nodeid;

	memset(name, 0, sizeof(name));
	memcpy(name, ms_name, len);

	hash = jhash(name, len, 0);
	b = hash & (ls->ls_rsbtbl_size - 1);

	dir_nodeid = dlm_hash2nodeid(ls, hash);

	log_error(ls, "send_repeat_remove dir %d %s", dir_nodeid, name);

	spin_lock(&ls->ls_rsbtbl[b].lock);
	rv = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].keep, name, len, &r);
	if (!rv) {
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		log_error(ls, "repeat_remove on keep %s", name);
		return;
	}

	rv = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].toss, name, len, &r);
	if (!rv) {
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		log_error(ls, "repeat_remove on toss %s", name);
		return;
	}

	/* use ls->remove_name2 to avoid conflict with shrink? */

	spin_lock(&ls->ls_remove_spin);
	ls->ls_remove_len = len;
	memcpy(ls->ls_remove_name, name, DLM_RESNAME_MAXLEN);
	spin_unlock(&ls->ls_remove_spin);
	spin_unlock(&ls->ls_rsbtbl[b].lock);

	rv = _create_message(ls, sizeof(struct dlm_message) + len,
			     dir_nodeid, DLM_MSG_REMOVE, &ms, &mh);
	if (rv)
		return;

	memcpy(ms->m_extra, name, len);
	ms->m_hash = hash;

	send_message(mh, ms);

	spin_lock(&ls->ls_remove_spin);
	ls->ls_remove_len = 0;
	memset(ls->ls_remove_name, 0, DLM_RESNAME_MAXLEN);
	spin_unlock(&ls->ls_remove_spin);
}

static int receive_request(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	struct dlm_rsb *r;
	int from_nodeid;
	int error, namelen = 0;

	from_nodeid = ms->m_header.h_nodeid;

	error = create_lkb(ls, &lkb);
	if (error)
		goto fail;

	receive_flags(lkb, ms);
	lkb->lkb_flags |= DLM_IFL_MSTCPY;
	error = receive_request_args(ls, lkb, ms);
	if (error) {
		__put_lkb(ls, lkb);
		goto fail;
	}

	/* The dir node is the authority on whether we are the master
	   for this rsb or not, so if the master sends us a request, we should
	   recreate the rsb if we've destroyed it.   This race happens when we
	   send a remove message to the dir node at the same time that the dir
	   node sends us a request for the rsb. */

	namelen = receive_extralen(ms);

	error = find_rsb(ls, ms->m_extra, namelen, from_nodeid,
			 R_RECEIVE_REQUEST, &r);
	if (error) {
		__put_lkb(ls, lkb);
		goto fail;
	}

	lock_rsb(r);

	if (r->res_master_nodeid != dlm_our_nodeid()) {
		error = validate_master_nodeid(ls, r, from_nodeid);
		if (error) {
			unlock_rsb(r);
			put_rsb(r);
			__put_lkb(ls, lkb);
			goto fail;
		}
	}

	attach_lkb(r, lkb);
	error = do_request(r, lkb);
	send_request_reply(r, lkb, error);
	do_request_effects(r, lkb, error);

	unlock_rsb(r);
	put_rsb(r);

	if (error == -EINPROGRESS)
		error = 0;
	if (error)
		dlm_put_lkb(lkb);
	return 0;

 fail:
	/* TODO: instead of returning ENOTBLK, add the lkb to res_lookup
	   and do this receive_request again from process_lookup_list once
	   we get the lookup reply.  This would avoid a many repeated
	   ENOTBLK request failures when the lookup reply designating us
	   as master is delayed. */

	/* We could repeatedly return -EBADR here if our send_remove() is
	   delayed in being sent/arriving/being processed on the dir node.
	   Another node would repeatedly lookup up the master, and the dir
	   node would continue returning our nodeid until our send_remove
	   took effect.

	   We send another remove message in case our previous send_remove
	   was lost/ignored/missed somehow. */

	if (error != -ENOTBLK) {
		log_limit(ls, "receive_request %x from %d %d",
			  ms->m_lkid, from_nodeid, error);
	}

	if (namelen && error == -EBADR) {
		send_repeat_remove(ls, ms->m_extra, namelen);
		msleep(1000);
	}

	setup_stub_lkb(ls, ms);
	send_request_reply(&ls->ls_stub_rsb, &ls->ls_stub_lkb, error);
	return error;
}

static int receive_convert(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	struct dlm_rsb *r;
	int error, reply = 1;

	error = find_lkb(ls, ms->m_remid, &lkb);
	if (error)
		goto fail;

	if (lkb->lkb_remid != ms->m_lkid) {
		log_error(ls, "receive_convert %x remid %x recover_seq %llu "
			  "remote %d %x", lkb->lkb_id, lkb->lkb_remid,
			  (unsigned long long)lkb->lkb_recover_seq,
			  ms->m_header.h_nodeid, ms->m_lkid);
		error = -ENOENT;
		goto fail;
	}

	r = lkb->lkb_resource;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_message(lkb, ms);
	if (error)
		goto out;

	receive_flags(lkb, ms);

	error = receive_convert_args(ls, lkb, ms);
	if (error) {
		send_convert_reply(r, lkb, error);
		goto out;
	}

	reply = !down_conversion(lkb);

	error = do_convert(r, lkb);
	if (reply)
		send_convert_reply(r, lkb, error);
	do_convert_effects(r, lkb, error);
 out:
	unlock_rsb(r);
	put_rsb(r);
	dlm_put_lkb(lkb);
	return 0;

 fail:
	setup_stub_lkb(ls, ms);
	send_convert_reply(&ls->ls_stub_rsb, &ls->ls_stub_lkb, error);
	return error;
}

static int receive_unlock(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	struct dlm_rsb *r;
	int error;

	error = find_lkb(ls, ms->m_remid, &lkb);
	if (error)
		goto fail;

	if (lkb->lkb_remid != ms->m_lkid) {
		log_error(ls, "receive_unlock %x remid %x remote %d %x",
			  lkb->lkb_id, lkb->lkb_remid,
			  ms->m_header.h_nodeid, ms->m_lkid);
		error = -ENOENT;
		goto fail;
	}

	r = lkb->lkb_resource;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_message(lkb, ms);
	if (error)
		goto out;

	receive_flags(lkb, ms);

	error = receive_unlock_args(ls, lkb, ms);
	if (error) {
		send_unlock_reply(r, lkb, error);
		goto out;
	}

	error = do_unlock(r, lkb);
	send_unlock_reply(r, lkb, error);
	do_unlock_effects(r, lkb, error);
 out:
	unlock_rsb(r);
	put_rsb(r);
	dlm_put_lkb(lkb);
	return 0;

 fail:
	setup_stub_lkb(ls, ms);
	send_unlock_reply(&ls->ls_stub_rsb, &ls->ls_stub_lkb, error);
	return error;
}

static int receive_cancel(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	struct dlm_rsb *r;
	int error;

	error = find_lkb(ls, ms->m_remid, &lkb);
	if (error)
		goto fail;

	receive_flags(lkb, ms);

	r = lkb->lkb_resource;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_message(lkb, ms);
	if (error)
		goto out;

	error = do_cancel(r, lkb);
	send_cancel_reply(r, lkb, error);
	do_cancel_effects(r, lkb, error);
 out:
	unlock_rsb(r);
	put_rsb(r);
	dlm_put_lkb(lkb);
	return 0;

 fail:
	setup_stub_lkb(ls, ms);
	send_cancel_reply(&ls->ls_stub_rsb, &ls->ls_stub_lkb, error);
	return error;
}

static int receive_grant(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	struct dlm_rsb *r;
	int error;

	error = find_lkb(ls, ms->m_remid, &lkb);
	if (error)
		return error;

	r = lkb->lkb_resource;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_message(lkb, ms);
	if (error)
		goto out;

	receive_flags_reply(lkb, ms);
	if (is_altmode(lkb))
		munge_altmode(lkb, ms);
	grant_lock_pc(r, lkb, ms);
	queue_cast(r, lkb, 0);
 out:
	unlock_rsb(r);
	put_rsb(r);
	dlm_put_lkb(lkb);
	return 0;
}

static int receive_bast(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	struct dlm_rsb *r;
	int error;

	error = find_lkb(ls, ms->m_remid, &lkb);
	if (error)
		return error;

	r = lkb->lkb_resource;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_message(lkb, ms);
	if (error)
		goto out;

	queue_bast(r, lkb, ms->m_bastmode);
	lkb->lkb_highbast = ms->m_bastmode;
 out:
	unlock_rsb(r);
	put_rsb(r);
	dlm_put_lkb(lkb);
	return 0;
}

static void receive_lookup(struct dlm_ls *ls, struct dlm_message *ms)
{
	int len, error, ret_nodeid, from_nodeid, our_nodeid;

	from_nodeid = ms->m_header.h_nodeid;
	our_nodeid = dlm_our_nodeid();

	len = receive_extralen(ms);

	error = dlm_master_lookup(ls, from_nodeid, ms->m_extra, len, 0,
				  &ret_nodeid, NULL);

	/* Optimization: we're master so treat lookup as a request */
	if (!error && ret_nodeid == our_nodeid) {
		receive_request(ls, ms);
		return;
	}
	send_lookup_reply(ls, ms, ret_nodeid, error);
}

static void receive_remove(struct dlm_ls *ls, struct dlm_message *ms)
{
	char name[DLM_RESNAME_MAXLEN+1];
	struct dlm_rsb *r;
	uint32_t hash, b;
	int rv, len, dir_nodeid, from_nodeid;

	from_nodeid = ms->m_header.h_nodeid;

	len = receive_extralen(ms);

	if (len > DLM_RESNAME_MAXLEN) {
		log_error(ls, "receive_remove from %d bad len %d",
			  from_nodeid, len);
		return;
	}

	dir_nodeid = dlm_hash2nodeid(ls, ms->m_hash);
	if (dir_nodeid != dlm_our_nodeid()) {
		log_error(ls, "receive_remove from %d bad nodeid %d",
			  from_nodeid, dir_nodeid);
		return;
	}

	/* Look for name on rsbtbl.toss, if it's there, kill it.
	   If it's on rsbtbl.keep, it's being used, and we should ignore this
	   message.  This is an expected race between the dir node sending a
	   request to the master node at the same time as the master node sends
	   a remove to the dir node.  The resolution to that race is for the
	   dir node to ignore the remove message, and the master node to
	   recreate the master rsb when it gets a request from the dir node for
	   an rsb it doesn't have. */

	memset(name, 0, sizeof(name));
	memcpy(name, ms->m_extra, len);

	hash = jhash(name, len, 0);
	b = hash & (ls->ls_rsbtbl_size - 1);

	spin_lock(&ls->ls_rsbtbl[b].lock);

	rv = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].toss, name, len, &r);
	if (rv) {
		/* verify the rsb is on keep list per comment above */
		rv = dlm_search_rsb_tree(&ls->ls_rsbtbl[b].keep, name, len, &r);
		if (rv) {
			/* should not happen */
			log_error(ls, "receive_remove from %d not found %s",
				  from_nodeid, name);
			spin_unlock(&ls->ls_rsbtbl[b].lock);
			return;
		}
		if (r->res_master_nodeid != from_nodeid) {
			/* should not happen */
			log_error(ls, "receive_remove keep from %d master %d",
				  from_nodeid, r->res_master_nodeid);
			dlm_print_rsb(r);
			spin_unlock(&ls->ls_rsbtbl[b].lock);
			return;
		}

		log_debug(ls, "receive_remove from %d master %d first %x %s",
			  from_nodeid, r->res_master_nodeid, r->res_first_lkid,
			  name);
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		return;
	}

	if (r->res_master_nodeid != from_nodeid) {
		log_error(ls, "receive_remove toss from %d master %d",
			  from_nodeid, r->res_master_nodeid);
		dlm_print_rsb(r);
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		return;
	}

	if (kref_put(&r->res_ref, kill_rsb)) {
		rb_erase(&r->res_hashnode, &ls->ls_rsbtbl[b].toss);
		spin_unlock(&ls->ls_rsbtbl[b].lock);
		dlm_free_rsb(r);
	} else {
		log_error(ls, "receive_remove from %d rsb ref error",
			  from_nodeid);
		dlm_print_rsb(r);
		spin_unlock(&ls->ls_rsbtbl[b].lock);
	}
}

static void receive_purge(struct dlm_ls *ls, struct dlm_message *ms)
{
	do_purge(ls, ms->m_nodeid, ms->m_pid);
}

static int receive_request_reply(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	struct dlm_rsb *r;
	int error, mstype, result;
	int from_nodeid = ms->m_header.h_nodeid;

	error = find_lkb(ls, ms->m_remid, &lkb);
	if (error)
		return error;

	r = lkb->lkb_resource;
	hold_rsb(r);
	lock_rsb(r);

	error = validate_message(lkb, ms);
	if (error)
		goto out;

	mstype = lkb->lkb_wait_type;
	error = remove_from_waiters(lkb, DLM_MSG_REQUEST_REPLY);
	if (error) {
		log_error(ls, "receive_request_reply %x remote %d %x result %d",
			  lkb->lkb_id, from_nodeid, ms->m_lkid, ms->m_result);
		dlm_dump_rsb(r);
		goto out;
	}

	/* Optimization: the dir node was also the master, so it took our
	   lookup as a request and sent request reply instead of lookup reply */
	if (mstype == DLM_MSG_LOOKUP) {
		r->res_master_nodeid = from_nodeid;
		r->res_nodeid = from_nodeid;
		lkb->lkb_nodeid = from_nodeid;
	}

	/* this is the value returned from do_request() on the master */
	result = ms->m_result;

	switch (result) {
	case -EAGAIN:
		/* request would block (be queued) on remote master */
		queue_cast(r, lkb, -EAGAIN);
		confirm_master(r, -EAGAIN);
		unhold_lkb(lkb); /* undoes create_lkb() */
		break;

	case -EINPROGRESS:
	case 0:
		/* request was queued or granted on remote master */
		receive_flags_reply(lkb, ms);
		lkb->lkb_remid = ms->m_lkid;
		if (is_altmode(lkb))
			munge_altmode(lkb, ms);
		if (result) {
			add_lkb(r, lkb, DLM_LKSTS_WAITING);
			add_timeout(lkb);
		} else {
			grant_lock_pc(r, lkb, ms);
			queue_cast(r, lkb, 0);
		}
		confirm_master(r, result);
		break;

	case -EBADR:
	case -ENOTBLK:
		/* find_rsb failed to find rsb or rsb wasn't master */
		log_limit(ls, "receive_request_reply %x from %d %d "
			  "master %d dir %d first %x %s", lkb->lkb_id,
			  from_nodeid, result, r->res_master_nodeid,
			  r->res_dir_nodeid, r->res_first_lkid, r->res_name);

		if (r->res_dir_nodeid != dlm_our_nodeid() &&
		    r->res_master_nodeid != dlm_our_nodeid()) {
			/* cause _request_lock->set_master->send_lookup */
			r->res_master_nodeid = 0;
			r->res_nodeid = -1;
			lkb->lkb_nodeid = -1;
		}

		if (is_overlap(lkb)) {
			/* we'll ignore error in cancel/unlock reply */
			queue_cast_overlap(r, lkb);
			confirm_master(r, result);
			unhold_lkb(lkb); /* undoes create_lkb() */
		} else {
			_request_lock(r, lkb);

			if (r->res_master_nodeid == dlm_our_nodeid())
				confirm_master(r, 0);
		}
		break;

	default:
		log_error(ls, "receive_request_reply %x error %d",
			  lkb->lkb_id, result);
	}

	if (is_overlap_unlock(lkb) && (result == 0 || result == -EINPROGRESS)) {
		log_debug(ls, "receive_request_reply %x result %d unlock",
			  lkb->lkb_id, result);
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_UNLOCK;
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_CANCEL;
		send_unlock(r, lkb);
	} else if (is_overlap_cancel(lkb) && (result == -EINPROGRESS)) {
		log_debug(ls, "receive_request_reply %x cancel", lkb->lkb_id);
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_UNLOCK;
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_CANCEL;
		send_cancel(r, lkb);
	} else {
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_CANCEL;
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_UNLOCK;
	}
 out:
	unlock_rsb(r);
	put_rsb(r);
	dlm_put_lkb(lkb);
	return 0;
}

static void __receive_convert_reply(struct dlm_rsb *r, struct dlm_lkb *lkb,
				    struct dlm_message *ms)
{
	/* this is the value returned from do_convert() on the master */
	switch (ms->m_result) {
	case -EAGAIN:
		/* convert would block (be queued) on remote master */
		queue_cast(r, lkb, -EAGAIN);
		break;

	case -EDEADLK:
		receive_flags_reply(lkb, ms);
		revert_lock_pc(r, lkb);
		queue_cast(r, lkb, -EDEADLK);
		break;

	case -EINPROGRESS:
		/* convert was queued on remote master */
		receive_flags_reply(lkb, ms);
		if (is_demoted(lkb))
			munge_demoted(lkb);
		del_lkb(r, lkb);
		add_lkb(r, lkb, DLM_LKSTS_CONVERT);
		add_timeout(lkb);
		break;

	case 0:
		/* convert was granted on remote master */
		receive_flags_reply(lkb, ms);
		if (is_demoted(lkb))
			munge_demoted(lkb);
		grant_lock_pc(r, lkb, ms);
		queue_cast(r, lkb, 0);
		break;

	default:
		log_error(r->res_ls, "receive_convert_reply %x remote %d %x %d",
			  lkb->lkb_id, ms->m_header.h_nodeid, ms->m_lkid,
			  ms->m_result);
		dlm_print_rsb(r);
		dlm_print_lkb(lkb);
	}
}

static void _receive_convert_reply(struct dlm_lkb *lkb, struct dlm_message *ms)
{
	struct dlm_rsb *r = lkb->lkb_resource;
	int error;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_message(lkb, ms);
	if (error)
		goto out;

	/* stub reply can happen with waiters_mutex held */
	error = remove_from_waiters_ms(lkb, ms);
	if (error)
		goto out;

	__receive_convert_reply(r, lkb, ms);
 out:
	unlock_rsb(r);
	put_rsb(r);
}

static int receive_convert_reply(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	int error;

	error = find_lkb(ls, ms->m_remid, &lkb);
	if (error)
		return error;

	_receive_convert_reply(lkb, ms);
	dlm_put_lkb(lkb);
	return 0;
}

static void _receive_unlock_reply(struct dlm_lkb *lkb, struct dlm_message *ms)
{
	struct dlm_rsb *r = lkb->lkb_resource;
	int error;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_message(lkb, ms);
	if (error)
		goto out;

	/* stub reply can happen with waiters_mutex held */
	error = remove_from_waiters_ms(lkb, ms);
	if (error)
		goto out;

	/* this is the value returned from do_unlock() on the master */

	switch (ms->m_result) {
	case -DLM_EUNLOCK:
		receive_flags_reply(lkb, ms);
		remove_lock_pc(r, lkb);
		queue_cast(r, lkb, -DLM_EUNLOCK);
		break;
	case -ENOENT:
		break;
	default:
		log_error(r->res_ls, "receive_unlock_reply %x error %d",
			  lkb->lkb_id, ms->m_result);
	}
 out:
	unlock_rsb(r);
	put_rsb(r);
}

static int receive_unlock_reply(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	int error;

	error = find_lkb(ls, ms->m_remid, &lkb);
	if (error)
		return error;

	_receive_unlock_reply(lkb, ms);
	dlm_put_lkb(lkb);
	return 0;
}

static void _receive_cancel_reply(struct dlm_lkb *lkb, struct dlm_message *ms)
{
	struct dlm_rsb *r = lkb->lkb_resource;
	int error;

	hold_rsb(r);
	lock_rsb(r);

	error = validate_message(lkb, ms);
	if (error)
		goto out;

	/* stub reply can happen with waiters_mutex held */
	error = remove_from_waiters_ms(lkb, ms);
	if (error)
		goto out;

	/* this is the value returned from do_cancel() on the master */

	switch (ms->m_result) {
	case -DLM_ECANCEL:
		receive_flags_reply(lkb, ms);
		revert_lock_pc(r, lkb);
		queue_cast(r, lkb, -DLM_ECANCEL);
		break;
	case 0:
		break;
	default:
		log_error(r->res_ls, "receive_cancel_reply %x error %d",
			  lkb->lkb_id, ms->m_result);
	}
 out:
	unlock_rsb(r);
	put_rsb(r);
}

static int receive_cancel_reply(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	int error;

	error = find_lkb(ls, ms->m_remid, &lkb);
	if (error)
		return error;

	_receive_cancel_reply(lkb, ms);
	dlm_put_lkb(lkb);
	return 0;
}

static void receive_lookup_reply(struct dlm_ls *ls, struct dlm_message *ms)
{
	struct dlm_lkb *lkb;
	struct dlm_rsb *r;
	int error, ret_nodeid;
	int do_lookup_list = 0;

	error = find_lkb(ls, ms->m_lkid, &lkb);
	if (error) {
		log_error(ls, "receive_lookup_reply no lkid %x", ms->m_lkid);
		return;
	}

	/* ms->m_result is the value returned by dlm_master_lookup on dir node
	   FIXME: will a non-zero error ever be returned? */

	r = lkb->lkb_resource;
	hold_rsb(r);
	lock_rsb(r);

	error = remove_from_waiters(lkb, DLM_MSG_LOOKUP_REPLY);
	if (error)
		goto out;

	ret_nodeid = ms->m_nodeid;

	/* We sometimes receive a request from the dir node for this
	   rsb before we've received the dir node's loookup_reply for it.
	   The request from the dir node implies we're the master, so we set
	   ourself as master in receive_request_reply, and verify here that
	   we are indeed the master. */

	if (r->res_master_nodeid && (r->res_master_nodeid != ret_nodeid)) {
		/* This should never happen */
		log_error(ls, "receive_lookup_reply %x from %d ret %d "
			  "master %d dir %d our %d first %x %s",
			  lkb->lkb_id, ms->m_header.h_nodeid, ret_nodeid,
			  r->res_master_nodeid, r->res_dir_nodeid,
			  dlm_our_nodeid(), r->res_first_lkid, r->res_name);
	}

	if (ret_nodeid == dlm_our_nodeid()) {
		r->res_master_nodeid = ret_nodeid;
		r->res_nodeid = 0;
		do_lookup_list = 1;
		r->res_first_lkid = 0;
	} else if (ret_nodeid == -1) {
		/* the remote node doesn't believe it's the dir node */
		log_error(ls, "receive_lookup_reply %x from %d bad ret_nodeid",
			  lkb->lkb_id, ms->m_header.h_nodeid);
		r->res_master_nodeid = 0;
		r->res_nodeid = -1;
		lkb->lkb_nodeid = -1;
	} else {
		/* set_master() will set lkb_nodeid from r */
		r->res_master_nodeid = ret_nodeid;
		r->res_nodeid = ret_nodeid;
	}

	if (is_overlap(lkb)) {
		log_debug(ls, "receive_lookup_reply %x unlock %x",
			  lkb->lkb_id, lkb->lkb_flags);
		queue_cast_overlap(r, lkb);
		unhold_lkb(lkb); /* undoes create_lkb() */
		goto out_list;
	}

	_request_lock(r, lkb);

 out_list:
	if (do_lookup_list)
		process_lookup_list(r);
 out:
	unlock_rsb(r);
	put_rsb(r);
	dlm_put_lkb(lkb);
}

static void _receive_message(struct dlm_ls *ls, struct dlm_message *ms,
			     uint32_t saved_seq)
{
	int error = 0, noent = 0;

	if (!dlm_is_member(ls, ms->m_header.h_nodeid)) {
		log_limit(ls, "receive %d from non-member %d %x %x %d",
			  ms->m_type, ms->m_header.h_nodeid, ms->m_lkid,
			  ms->m_remid, ms->m_result);
		return;
	}

	switch (ms->m_type) {

	/* messages sent to a master node */

	case DLM_MSG_REQUEST:
		error = receive_request(ls, ms);
		break;

	case DLM_MSG_CONVERT:
		error = receive_convert(ls, ms);
		break;

	case DLM_MSG_UNLOCK:
		error = receive_unlock(ls, ms);
		break;

	case DLM_MSG_CANCEL:
		noent = 1;
		error = receive_cancel(ls, ms);
		break;

	/* messages sent from a master node (replies to above) */

	case DLM_MSG_REQUEST_REPLY:
		error = receive_request_reply(ls, ms);
		break;

	case DLM_MSG_CONVERT_REPLY:
		error = receive_convert_reply(ls, ms);
		break;

	case DLM_MSG_UNLOCK_REPLY:
		error = receive_unlock_reply(ls, ms);
		break;

	case DLM_MSG_CANCEL_REPLY:
		error = receive_cancel_reply(ls, ms);
		break;

	/* messages sent from a master node (only two types of async msg) */

	case DLM_MSG_GRANT:
		noent = 1;
		error = receive_grant(ls, ms);
		break;

	case DLM_MSG_BAST:
		noent = 1;
		error = receive_bast(ls, ms);
		break;

	/* messages sent to a dir node */

	case DLM_MSG_LOOKUP:
		receive_lookup(ls, ms);
		break;

	case DLM_MSG_REMOVE:
		receive_remove(ls, ms);
		break;

	/* messages sent from a dir node (remove has no reply) */

	case DLM_MSG_LOOKUP_REPLY:
		receive_lookup_reply(ls, ms);
		break;

	/* other messages */

	case DLM_MSG_PURGE:
		receive_purge(ls, ms);
		break;

	default:
		log_error(ls, "unknown message type %d", ms->m_type);
	}

	/*
	 * When checking for ENOENT, we're checking the result of
	 * find_lkb(m_remid):
	 *
	 * The lock id referenced in the message wasn't found.  This may
	 * happen in normal usage for the async messages and cancel, so
	 * only use log_debug for them.
	 *
	 * Some errors are expected and normal.
	 */

	if (error == -ENOENT && noent) {
		log_debug(ls, "receive %d no %x remote %d %x saved_seq %u",
			  ms->m_type, ms->m_remid, ms->m_header.h_nodeid,
			  ms->m_lkid, saved_seq);
	} else if (error == -ENOENT) {
		log_error(ls, "receive %d no %x remote %d %x saved_seq %u",
			  ms->m_type, ms->m_remid, ms->m_header.h_nodeid,
			  ms->m_lkid, saved_seq);

		if (ms->m_type == DLM_MSG_CONVERT)
			dlm_dump_rsb_hash(ls, ms->m_hash);
	}

	if (error == -EINVAL) {
		log_error(ls, "receive %d inval from %d lkid %x remid %x "
			  "saved_seq %u",
			  ms->m_type, ms->m_header.h_nodeid,
			  ms->m_lkid, ms->m_remid, saved_seq);
	}
}

/* If the lockspace is in recovery mode (locking stopped), then normal
   messages are saved on the requestqueue for processing after recovery is
   done.  When not in recovery mode, we wait for dlm_recoverd to drain saved
   messages off the requestqueue before we process new ones. This occurs right
   after recovery completes when we transition from saving all messages on
   requestqueue, to processing all the saved messages, to processing new
   messages as they arrive. */

static void dlm_receive_message(struct dlm_ls *ls, struct dlm_message *ms,
				int nodeid)
{
	if (dlm_locking_stopped(ls)) {
		/* If we were a member of this lockspace, left, and rejoined,
		   other nodes may still be sending us messages from the
		   lockspace generation before we left. */
		if (!ls->ls_generation) {
			log_limit(ls, "receive %d from %d ignore old gen",
				  ms->m_type, nodeid);
			return;
		}

		dlm_add_requestqueue(ls, nodeid, ms);
	} else {
		dlm_wait_requestqueue(ls);
		_receive_message(ls, ms, 0);
	}
}

/* This is called by dlm_recoverd to process messages that were saved on
   the requestqueue. */

void dlm_receive_message_saved(struct dlm_ls *ls, struct dlm_message *ms,
			       uint32_t saved_seq)
{
	_receive_message(ls, ms, saved_seq);
}

/* This is called by the midcomms layer when something is received for
   the lockspace.  It could be either a MSG (normal message sent as part of
   standard locking activity) or an RCOM (recovery message sent as part of
   lockspace recovery). */

void dlm_receive_buffer(union dlm_packet *p, int nodeid)
{
	struct dlm_header *hd = &p->header;
	struct dlm_ls *ls;
	int type = 0;

	switch (hd->h_cmd) {
	case DLM_MSG:
		dlm_message_in(&p->message);
		type = p->message.m_type;
		break;
	case DLM_RCOM:
		dlm_rcom_in(&p->rcom);
		type = p->rcom.rc_type;
		break;
	default:
		log_print("invalid h_cmd %d from %u", hd->h_cmd, nodeid);
		return;
	}

	if (hd->h_nodeid != nodeid) {
		log_print("invalid h_nodeid %d from %d lockspace %x",
			  hd->h_nodeid, nodeid, hd->h_lockspace);
		return;
	}

	ls = dlm_find_lockspace_global(hd->h_lockspace);
	if (!ls) {
		if (dlm_config.ci_log_debug) {
			printk_ratelimited(KERN_DEBUG "dlm: invalid lockspace "
				"%u from %d cmd %d type %d\n",
				hd->h_lockspace, nodeid, hd->h_cmd, type);
		}

		if (hd->h_cmd == DLM_RCOM && type == DLM_RCOM_STATUS)
			dlm_send_ls_not_ready(nodeid, &p->rcom);
		return;
	}

	/* this rwsem allows dlm_ls_stop() to wait for all dlm_recv threads to
	   be inactive (in this ls) before transitioning to recovery mode */

	down_read(&ls->ls_recv_active);
	if (hd->h_cmd == DLM_MSG)
		dlm_receive_message(ls, &p->message, nodeid);
	else
		dlm_receive_rcom(ls, &p->rcom, nodeid);
	up_read(&ls->ls_recv_active);

	dlm_put_lockspace(ls);
}

static void recover_convert_waiter(struct dlm_ls *ls, struct dlm_lkb *lkb,
				   struct dlm_message *ms_stub)
{
	if (middle_conversion(lkb)) {
		hold_lkb(lkb);
		memset(ms_stub, 0, sizeof(struct dlm_message));
		ms_stub->m_flags = DLM_IFL_STUB_MS;
		ms_stub->m_type = DLM_MSG_CONVERT_REPLY;
		ms_stub->m_result = -EINPROGRESS;
		ms_stub->m_header.h_nodeid = lkb->lkb_nodeid;
		_receive_convert_reply(lkb, ms_stub);

		/* Same special case as in receive_rcom_lock_args() */
		lkb->lkb_grmode = DLM_LOCK_IV;
		rsb_set_flag(lkb->lkb_resource, RSB_RECOVER_CONVERT);
		unhold_lkb(lkb);

	} else if (lkb->lkb_rqmode >= lkb->lkb_grmode) {
		lkb->lkb_flags |= DLM_IFL_RESEND;
	}

	/* lkb->lkb_rqmode < lkb->lkb_grmode shouldn't happen since down
	   conversions are async; there's no reply from the remote master */
}

/* A waiting lkb needs recovery if the master node has failed, or
   the master node is changing (only when no directory is used) */

static int waiter_needs_recovery(struct dlm_ls *ls, struct dlm_lkb *lkb,
				 int dir_nodeid)
{
	if (dlm_no_directory(ls))
		return 1;

	if (dlm_is_removed(ls, lkb->lkb_wait_nodeid))
		return 1;

	return 0;
}

/* Recovery for locks that are waiting for replies from nodes that are now
   gone.  We can just complete unlocks and cancels by faking a reply from the
   dead node.  Requests and up-conversions we flag to be resent after
   recovery.  Down-conversions can just be completed with a fake reply like
   unlocks.  Conversions between PR and CW need special attention. */

void dlm_recover_waiters_pre(struct dlm_ls *ls)
{
	struct dlm_lkb *lkb, *safe;
	struct dlm_message *ms_stub;
	int wait_type, stub_unlock_result, stub_cancel_result;
	int dir_nodeid;

	ms_stub = kmalloc(sizeof(struct dlm_message), GFP_KERNEL);
	if (!ms_stub) {
		log_error(ls, "dlm_recover_waiters_pre no mem");
		return;
	}

	mutex_lock(&ls->ls_waiters_mutex);

	list_for_each_entry_safe(lkb, safe, &ls->ls_waiters, lkb_wait_reply) {

		dir_nodeid = dlm_dir_nodeid(lkb->lkb_resource);

		/* exclude debug messages about unlocks because there can be so
		   many and they aren't very interesting */

		if (lkb->lkb_wait_type != DLM_MSG_UNLOCK) {
			log_debug(ls, "waiter %x remote %x msg %d r_nodeid %d "
				  "lkb_nodeid %d wait_nodeid %d dir_nodeid %d",
				  lkb->lkb_id,
				  lkb->lkb_remid,
				  lkb->lkb_wait_type,
				  lkb->lkb_resource->res_nodeid,
				  lkb->lkb_nodeid,
				  lkb->lkb_wait_nodeid,
				  dir_nodeid);
		}

		/* all outstanding lookups, regardless of destination  will be
		   resent after recovery is done */

		if (lkb->lkb_wait_type == DLM_MSG_LOOKUP) {
			lkb->lkb_flags |= DLM_IFL_RESEND;
			continue;
		}

		if (!waiter_needs_recovery(ls, lkb, dir_nodeid))
			continue;

		wait_type = lkb->lkb_wait_type;
		stub_unlock_result = -DLM_EUNLOCK;
		stub_cancel_result = -DLM_ECANCEL;

		/* Main reply may have been received leaving a zero wait_type,
		   but a reply for the overlapping op may not have been
		   received.  In that case we need to fake the appropriate
		   reply for the overlap op. */

		if (!wait_type) {
			if (is_overlap_cancel(lkb)) {
				wait_type = DLM_MSG_CANCEL;
				if (lkb->lkb_grmode == DLM_LOCK_IV)
					stub_cancel_result = 0;
			}
			if (is_overlap_unlock(lkb)) {
				wait_type = DLM_MSG_UNLOCK;
				if (lkb->lkb_grmode == DLM_LOCK_IV)
					stub_unlock_result = -ENOENT;
			}

			log_debug(ls, "rwpre overlap %x %x %d %d %d",
				  lkb->lkb_id, lkb->lkb_flags, wait_type,
				  stub_cancel_result, stub_unlock_result);
		}

		switch (wait_type) {

		case DLM_MSG_REQUEST:
			lkb->lkb_flags |= DLM_IFL_RESEND;
			break;

		case DLM_MSG_CONVERT:
			recover_convert_waiter(ls, lkb, ms_stub);
			break;

		case DLM_MSG_UNLOCK:
			hold_lkb(lkb);
			memset(ms_stub, 0, sizeof(struct dlm_message));
			ms_stub->m_flags = DLM_IFL_STUB_MS;
			ms_stub->m_type = DLM_MSG_UNLOCK_REPLY;
			ms_stub->m_result = stub_unlock_result;
			ms_stub->m_header.h_nodeid = lkb->lkb_nodeid;
			_receive_unlock_reply(lkb, ms_stub);
			dlm_put_lkb(lkb);
			break;

		case DLM_MSG_CANCEL:
			hold_lkb(lkb);
			memset(ms_stub, 0, sizeof(struct dlm_message));
			ms_stub->m_flags = DLM_IFL_STUB_MS;
			ms_stub->m_type = DLM_MSG_CANCEL_REPLY;
			ms_stub->m_result = stub_cancel_result;
			ms_stub->m_header.h_nodeid = lkb->lkb_nodeid;
			_receive_cancel_reply(lkb, ms_stub);
			dlm_put_lkb(lkb);
			break;

		default:
			log_error(ls, "invalid lkb wait_type %d %d",
				  lkb->lkb_wait_type, wait_type);
		}
		schedule();
	}
	mutex_unlock(&ls->ls_waiters_mutex);
	kfree(ms_stub);
}

static struct dlm_lkb *find_resend_waiter(struct dlm_ls *ls)
{
	struct dlm_lkb *lkb;
	int found = 0;

	mutex_lock(&ls->ls_waiters_mutex);
	list_for_each_entry(lkb, &ls->ls_waiters, lkb_wait_reply) {
		if (lkb->lkb_flags & DLM_IFL_RESEND) {
			hold_lkb(lkb);
			found = 1;
			break;
		}
	}
	mutex_unlock(&ls->ls_waiters_mutex);

	if (!found)
		lkb = NULL;
	return lkb;
}

/* Deal with lookups and lkb's marked RESEND from _pre.  We may now be the
   master or dir-node for r.  Processing the lkb may result in it being placed
   back on waiters. */

/* We do this after normal locking has been enabled and any saved messages
   (in requestqueue) have been processed.  We should be confident that at
   this point we won't get or process a reply to any of these waiting
   operations.  But, new ops may be coming in on the rsbs/locks here from
   userspace or remotely. */

/* there may have been an overlap unlock/cancel prior to recovery or after
   recovery.  if before, the lkb may still have a pos wait_count; if after, the
   overlap flag would just have been set and nothing new sent.  we can be
   confident here than any replies to either the initial op or overlap ops
   prior to recovery have been received. */

int dlm_recover_waiters_post(struct dlm_ls *ls)
{
	struct dlm_lkb *lkb;
	struct dlm_rsb *r;
	int error = 0, mstype, err, oc, ou;

	while (1) {
		if (dlm_locking_stopped(ls)) {
			log_debug(ls, "recover_waiters_post aborted");
			error = -EINTR;
			break;
		}

		lkb = find_resend_waiter(ls);
		if (!lkb)
			break;

		r = lkb->lkb_resource;
		hold_rsb(r);
		lock_rsb(r);

		mstype = lkb->lkb_wait_type;
		oc = is_overlap_cancel(lkb);
		ou = is_overlap_unlock(lkb);
		err = 0;

		log_debug(ls, "waiter %x remote %x msg %d r_nodeid %d "
			  "lkb_nodeid %d wait_nodeid %d dir_nodeid %d "
			  "overlap %d %d", lkb->lkb_id, lkb->lkb_remid, mstype,
			  r->res_nodeid, lkb->lkb_nodeid, lkb->lkb_wait_nodeid,
			  dlm_dir_nodeid(r), oc, ou);

		/* At this point we assume that we won't get a reply to any
		   previous op or overlap op on this lock.  First, do a big
		   remove_from_waiters() for all previous ops. */

		lkb->lkb_flags &= ~DLM_IFL_RESEND;
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_UNLOCK;
		lkb->lkb_flags &= ~DLM_IFL_OVERLAP_CANCEL;
		lkb->lkb_wait_type = 0;
		lkb->lkb_wait_count = 0;
		mutex_lock(&ls->ls_waiters_mutex);
		list_del_init(&lkb->lkb_wait_reply);
		mutex_unlock(&ls->ls_waiters_mutex);
		unhold_lkb(lkb); /* for waiters list */

		if (oc || ou) {
			/* do an unlock or cancel instead of resending */
			switch (mstype) {
			case DLM_MSG_LOOKUP:
			case DLM_MSG_REQUEST:
				queue_cast(r, lkb, ou ? -DLM_EUNLOCK :
							-DLM_ECANCEL);
				unhold_lkb(lkb); /* undoes create_lkb() */
				break;
			case DLM_MSG_CONVERT:
				if (oc) {
					queue_cast(r, lkb, -DLM_ECANCEL);
				} else {
					lkb->lkb_exflags |= DLM_LKF_FORCEUNLOCK;
					_unlock_lock(r, lkb);
				}
				break;
			default:
				err = 1;
			}
		} else {
			switch (mstype) {
			case DLM_MSG_LOOKUP:
			case DLM_MSG_REQUEST:
				_request_lock(r, lkb);
				if (is_master(r))
					confirm_master(r, 0);
				break;
			case DLM_MSG_CONVERT:
				_convert_lock(r, lkb);
				break;
			default:
				err = 1;
			}
		}

		if (err) {
			log_error(ls, "waiter %x msg %d r_nodeid %d "
				  "dir_nodeid %d overlap %d %d",
				  lkb->lkb_id, mstype, r->res_nodeid,
				  dlm_dir_nodeid(r), oc, ou);
		}
		unlock_rsb(r);
		put_rsb(r);
		dlm_put_lkb(lkb);
	}

	return error;
}

static void purge_mstcpy_list(struct dlm_ls *ls, struct dlm_rsb *r,
			      struct list_head *list)
{
	struct dlm_lkb *lkb, *safe;

	list_for_each_entry_safe(lkb, safe, list, lkb_statequeue) {
		if (!is_master_copy(lkb))
			continue;

		/* don't purge lkbs we've added in recover_master_copy for
		   the current recovery seq */

		if (lkb->lkb_recover_seq == ls->ls_recover_seq)
			continue;

		del_lkb(r, lkb);

		/* this put should free the lkb */
		if (!dlm_put_lkb(lkb))
			log_error(ls, "purged mstcpy lkb not released");
	}
}

void dlm_purge_mstcpy_locks(struct dlm_rsb *r)
{
	struct dlm_ls *ls = r->res_ls;

	purge_mstcpy_list(ls, r, &r->res_grantqueue);
	purge_mstcpy_list(ls, r, &r->res_convertqueue);
	purge_mstcpy_list(ls, r, &r->res_waitqueue);
}

static void purge_dead_list(struct dlm_ls *ls, struct dlm_rsb *r,
			    struct list_head *list,
			    int nodeid_gone, unsigned int *count)
{
	struct dlm_lkb *lkb, *safe;

	list_for_each_entry_safe(lkb, safe, list, lkb_statequeue) {
		if (!is_master_copy(lkb))
			continue;

		if ((lkb->lkb_nodeid == nodeid_gone) ||
		    dlm_is_removed(ls, lkb->lkb_nodeid)) {

			/* tell recover_lvb to invalidate the lvb
			   because a node holding EX/PW failed */
			if ((lkb->lkb_exflags & DLM_LKF_VALBLK) &&
			    (lkb->lkb_grmode >= DLM_LOCK_PW)) {
				rsb_set_flag(r, RSB_RECOVER_LVB_INVAL);
			}

			del_lkb(r, lkb);

			/* this put should free the lkb */
			if (!dlm_put_lkb(lkb))
				log_error(ls, "purged dead lkb not released");

			rsb_set_flag(r, RSB_RECOVER_GRANT);

			(*count)++;
		}
	}
}

/* Get rid of locks held by nodes that are gone. */

void dlm_recover_purge(struct dlm_ls *ls)
{
	struct dlm_rsb *r;
	struct dlm_member *memb;
	int nodes_count = 0;
	int nodeid_gone = 0;
	unsigned int lkb_count = 0;

	/* cache one removed nodeid to optimize the common
	   case of a single node removed */

	list_for_each_entry(memb, &ls->ls_nodes_gone, list) {
		nodes_count++;
		nodeid_gone = memb->nodeid;
	}

	if (!nodes_count)
		return;

	down_write(&ls->ls_root_sem);
	list_for_each_entry(r, &ls->ls_root_list, res_root_list) {
		hold_rsb(r);
		lock_rsb(r);
		if (is_master(r)) {
			purge_dead_list(ls, r, &r->res_grantqueue,
					nodeid_gone, &lkb_count);
			purge_dead_list(ls, r, &r->res_convertqueue,
					nodeid_gone, &lkb_count);
			purge_dead_list(ls, r, &r->res_waitqueue,
					nodeid_gone, &lkb_count);
		}
		unlock_rsb(r);
		unhold_rsb(r);
		cond_resched();
	}
	up_write(&ls->ls_root_sem);

	if (lkb_count)
		log_rinfo(ls, "dlm_recover_purge %u locks for %u nodes",
			  lkb_count, nodes_count);
}

static struct dlm_rsb *find_grant_rsb(struct dlm_ls *ls, int bucket)
{
	struct rb_node *n;
	struct dlm_rsb *r;

	spin_lock(&ls->ls_rsbtbl[bucket].lock);
	for (n = rb_first(&ls->ls_rsbtbl[bucket].keep); n; n = rb_next(n)) {
		r = rb_entry(n, struct dlm_rsb, res_hashnode);

		if (!rsb_flag(r, RSB_RECOVER_GRANT))
			continue;
		if (!is_master(r)) {
			rsb_clear_flag(r, RSB_RECOVER_GRANT);
			continue;
		}
		hold_rsb(r);
		spin_unlock(&ls->ls_rsbtbl[bucket].lock);
		return r;
	}
	spin_unlock(&ls->ls_rsbtbl[bucket].lock);
	return NULL;
}

/*
 * Attempt to grant locks on resources that we are the master of.
 * Locks may have become grantable during recovery because locks
 * from departed nodes have been purged (or not rebuilt), allowing
 * previously blocked locks to now be granted.  The subset of rsb's
 * we are interested in are those with lkb's on either the convert or
 * waiting queues.
 *
 * Simplest would be to go through each master rsb and check for non-empty
 * convert or waiting queues, and attempt to grant on those rsbs.
 * Checking the queues requires lock_rsb, though, for which we'd need
 * to release the rsbtbl lock.  This would make iterating through all
 * rsb's very inefficient.  So, we rely on earlier recovery routines
 * to set RECOVER_GRANT on any rsb's that we should attempt to grant
 * locks for.
 */

void dlm_recover_grant(struct dlm_ls *ls)
{
	struct dlm_rsb *r;
	int bucket = 0;
	unsigned int count = 0;
	unsigned int rsb_count = 0;
	unsigned int lkb_count = 0;

	while (1) {
		r = find_grant_rsb(ls, bucket);
		if (!r) {
			if (bucket == ls->ls_rsbtbl_size - 1)
				break;
			bucket++;
			continue;
		}
		rsb_count++;
		count = 0;
		lock_rsb(r);
		/* the RECOVER_GRANT flag is checked in the grant path */
		grant_pending_locks(r, &count);
		rsb_clear_flag(r, RSB_RECOVER_GRANT);
		lkb_count += count;
		confirm_master(r, 0);
		unlock_rsb(r);
		put_rsb(r);
		cond_resched();
	}

	if (lkb_count)
		log_rinfo(ls, "dlm_recover_grant %u locks on %u resources",
			  lkb_count, rsb_count);
}

static struct dlm_lkb *search_remid_list(struct list_head *head, int nodeid,
					 uint32_t remid)
{
	struct dlm_lkb *lkb;

	list_for_each_entry(lkb, head, lkb_statequeue) {
		if (lkb->lkb_nodeid == nodeid && lkb->lkb_remid == remid)
			return lkb;
	}
	return NULL;
}

static struct dlm_lkb *search_remid(struct dlm_rsb *r, int nodeid,
				    uint32_t remid)
{
	struct dlm_lkb *lkb;

	lkb = search_remid_list(&r->res_grantqueue, nodeid, remid);
	if (lkb)
		return lkb;
	lkb = search_remid_list(&r->res_convertqueue, nodeid, remid);
	if (lkb)
		return lkb;
	lkb = search_remid_list(&r->res_waitqueue, nodeid, remid);
	if (lkb)
		return lkb;
	return NULL;
}

/* needs at least dlm_rcom + rcom_lock */
static int receive_rcom_lock_args(struct dlm_ls *ls, struct dlm_lkb *lkb,
				  struct dlm_rsb *r, struct dlm_rcom *rc)
{
	struct rcom_lock *rl = (struct rcom_lock *) rc->rc_buf;

	lkb->lkb_nodeid = rc->rc_header.h_nodeid;
	lkb->lkb_ownpid = le32_to_cpu(rl->rl_ownpid);
	lkb->lkb_remid = le32_to_cpu(rl->rl_lkid);
	lkb->lkb_exflags = le32_to_cpu(rl->rl_exflags);
	lkb->lkb_flags = le32_to_cpu(rl->rl_flags) & 0x0000FFFF;
	lkb->lkb_flags |= DLM_IFL_MSTCPY;
	lkb->lkb_lvbseq = le32_to_cpu(rl->rl_lvbseq);
	lkb->lkb_rqmode = rl->rl_rqmode;
	lkb->lkb_grmode = rl->rl_grmode;
	/* don't set lkb_status because add_lkb wants to itself */

	lkb->lkb_bastfn = (rl->rl_asts & DLM_CB_BAST) ? &fake_bastfn : NULL;
	lkb->lkb_astfn = (rl->rl_asts & DLM_CB_CAST) ? &fake_astfn : NULL;

	if (lkb->lkb_exflags & DLM_LKF_VALBLK) {
		int lvblen = rc->rc_header.h_length - sizeof(struct dlm_rcom) -
			 sizeof(struct rcom_lock);
		if (lvblen > ls->ls_lvblen)
			return -EINVAL;
		lkb->lkb_lvbptr = dlm_allocate_lvb(ls);
		if (!lkb->lkb_lvbptr)
			return -ENOMEM;
		memcpy(lkb->lkb_lvbptr, rl->rl_lvb, lvblen);
	}

	/* Conversions between PR and CW (middle modes) need special handling.
	   The real granted mode of these converting locks cannot be determined
	   until all locks have been rebuilt on the rsb (recover_conversion) */

	if (rl->rl_wait_type == cpu_to_le16(DLM_MSG_CONVERT) &&
	    middle_conversion(lkb)) {
		rl->rl_status = DLM_LKSTS_CONVERT;
		lkb->lkb_grmode = DLM_LOCK_IV;
		rsb_set_flag(r, RSB_RECOVER_CONVERT);
	}

	return 0;
}

/* This lkb may have been recovered in a previous aborted recovery so we need
   to check if the rsb already has an lkb with the given remote nodeid/lkid.
   If so we just send back a standard reply.  If not, we create a new lkb with
   the given values and send back our lkid.  We send back our lkid by sending
   back the rcom_lock struct we got but with the remid field filled in. */

/* needs at least dlm_rcom + rcom_lock */
int dlm_recover_master_copy(struct dlm_ls *ls, struct dlm_rcom *rc)
{
	struct rcom_lock *rl = (struct rcom_lock *) rc->rc_buf;
	struct dlm_rsb *r;
	struct dlm_lkb *lkb;
	uint32_t remid = 0;
	int from_nodeid = rc->rc_header.h_nodeid;
	int error;

	if (rl->rl_parent_lkid) {
		error = -EOPNOTSUPP;
		goto out;
	}

	remid = le32_to_cpu(rl->rl_lkid);

	/* In general we expect the rsb returned to be R_MASTER, but we don't
	   have to require it.  Recovery of masters on one node can overlap
	   recovery of locks on another node, so one node can send us MSTCPY
	   locks before we've made ourselves master of this rsb.  We can still
	   add new MSTCPY locks that we receive here without any harm; when
	   we make ourselves master, dlm_recover_masters() won't touch the
	   MSTCPY locks we've received early. */

	error = find_rsb(ls, rl->rl_name, le16_to_cpu(rl->rl_namelen),
			 from_nodeid, R_RECEIVE_RECOVER, &r);
	if (error)
		goto out;

	lock_rsb(r);

	if (dlm_no_directory(ls) && (dlm_dir_nodeid(r) != dlm_our_nodeid())) {
		log_error(ls, "dlm_recover_master_copy remote %d %x not dir",
			  from_nodeid, remid);
		error = -EBADR;
		goto out_unlock;
	}

	lkb = search_remid(r, from_nodeid, remid);
	if (lkb) {
		error = -EEXIST;
		goto out_remid;
	}

	error = create_lkb(ls, &lkb);
	if (error)
		goto out_unlock;

	error = receive_rcom_lock_args(ls, lkb, r, rc);
	if (error) {
		__put_lkb(ls, lkb);
		goto out_unlock;
	}

	attach_lkb(r, lkb);
	add_lkb(r, lkb, rl->rl_status);
	error = 0;
	ls->ls_recover_locks_in++;

	if (!list_empty(&r->res_waitqueue) || !list_empty(&r->res_convertqueue))
		rsb_set_flag(r, RSB_RECOVER_GRANT);

 out_remid:
	/* this is the new value returned to the lock holder for
	   saving in its process-copy lkb */
	rl->rl_remid = cpu_to_le32(lkb->lkb_id);

	lkb->lkb_recover_seq = ls->ls_recover_seq;

 out_unlock:
	unlock_rsb(r);
	put_rsb(r);
 out:
	if (error && error != -EEXIST)
		log_rinfo(ls, "dlm_recover_master_copy remote %d %x error %d",
			  from_nodeid, remid, error);
	rl->rl_result = cpu_to_le32(error);
	return error;
}

/* needs at least dlm_rcom + rcom_lock */
int dlm_recover_process_copy(struct dlm_ls *ls, struct dlm_rcom *rc)
{
	struct rcom_lock *rl = (struct rcom_lock *) rc->rc_buf;
	struct dlm_rsb *r;
	struct dlm_lkb *lkb;
	uint32_t lkid, remid;
	int error, result;

	lkid = le32_to_cpu(rl->rl_lkid);
	remid = le32_to_cpu(rl->rl_remid);
	result = le32_to_cpu(rl->rl_result);

	error = find_lkb(ls, lkid, &lkb);
	if (error) {
		log_error(ls, "dlm_recover_process_copy no %x remote %d %x %d",
			  lkid, rc->rc_header.h_nodeid, remid, result);
		return error;
	}

	r = lkb->lkb_resource;
	hold_rsb(r);
	lock_rsb(r);

	if (!is_process_copy(lkb)) {
		log_error(ls, "dlm_recover_process_copy bad %x remote %d %x %d",
			  lkid, rc->rc_header.h_nodeid, remid, result);
		dlm_dump_rsb(r);
		unlock_rsb(r);
		put_rsb(r);
		dlm_put_lkb(lkb);
		return -EINVAL;
	}

	switch (result) {
	case -EBADR:
		/* There's a chance the new master received our lock before
		   dlm_recover_master_reply(), this wouldn't happen if we did
		   a barrier between recover_masters and recover_locks. */

		log_debug(ls, "dlm_recover_process_copy %x remote %d %x %d",
			  lkid, rc->rc_header.h_nodeid, remid, result);
	
		dlm_send_rcom_lock(r, lkb);
		goto out;
	case -EEXIST:
	case 0:
		lkb->lkb_remid = remid;
		break;
	default:
		log_error(ls, "dlm_recover_process_copy %x remote %d %x %d unk",
			  lkid, rc->rc_header.h_nodeid, remid, result);
	}

	/* an ack for dlm_recover_locks() which waits for replies from
	   all the locks it sends to new masters */
	dlm_recovered_lock(r);
 out:
	unlock_rsb(r);
	put_rsb(r);
	dlm_put_lkb(lkb);

	return 0;
}

int dlm_user_request(struct dlm_ls *ls, struct dlm_user_args *ua,
		     int mode, uint32_t flags, void *name, unsigned int namelen,
		     unsigned long timeout_cs)
{
	struct dlm_lkb *lkb;
	struct dlm_args args;
	int error;

	dlm_lock_recovery(ls);

	error = create_lkb(ls, &lkb);
	if (error) {
		kfree(ua);
		goto out;
	}

	if (flags & DLM_LKF_VALBLK) {
		ua->lksb.sb_lvbptr = kzalloc(DLM_USER_LVB_LEN, GFP_NOFS);
		if (!ua->lksb.sb_lvbptr) {
			kfree(ua);
			__put_lkb(ls, lkb);
			error = -ENOMEM;
			goto out;
		}
	}

	/* After ua is attached to lkb it will be freed by dlm_free_lkb().
	   When DLM_IFL_USER is set, the dlm knows that this is a userspace
	   lock and that lkb_astparam is the dlm_user_args structure. */

	error = set_lock_args(mode, &ua->lksb, flags, namelen, timeout_cs,
			      fake_astfn, ua, fake_bastfn, &args);
	lkb->lkb_flags |= DLM_IFL_USER;

	if (error) {
		__put_lkb(ls, lkb);
		goto out;
	}

	error = request_lock(ls, lkb, name, namelen, &args);

	switch (error) {
	case 0:
		break;
	case -EINPROGRESS:
		error = 0;
		break;
	case -EAGAIN:
		error = 0;
		/* fall through */
	default:
		__put_lkb(ls, lkb);
		goto out;
	}

	/* add this new lkb to the per-process list of locks */
	spin_lock(&ua->proc->locks_spin);
	hold_lkb(lkb);
	list_add_tail(&lkb->lkb_ownqueue, &ua->proc->locks);
	spin_unlock(&ua->proc->locks_spin);
 out:
	dlm_unlock_recovery(ls);
	return error;
}

int dlm_user_convert(struct dlm_ls *ls, struct dlm_user_args *ua_tmp,
		     int mode, uint32_t flags, uint32_t lkid, char *lvb_in,
		     unsigned long timeout_cs)
{
	struct dlm_lkb *lkb;
	struct dlm_args args;
	struct dlm_user_args *ua;
	int error;

	dlm_lock_recovery(ls);

	error = find_lkb(ls, lkid, &lkb);
	if (error)
		goto out;

	/* user can change the params on its lock when it converts it, or
	   add an lvb that didn't exist before */

	ua = lkb->lkb_ua;

	if (flags & DLM_LKF_VALBLK && !ua->lksb.sb_lvbptr) {
		ua->lksb.sb_lvbptr = kzalloc(DLM_USER_LVB_LEN, GFP_NOFS);
		if (!ua->lksb.sb_lvbptr) {
			error = -ENOMEM;
			goto out_put;
		}
	}
	if (lvb_in && ua->lksb.sb_lvbptr)
		memcpy(ua->lksb.sb_lvbptr, lvb_in, DLM_USER_LVB_LEN);

	ua->xid = ua_tmp->xid;
	ua->castparam = ua_tmp->castparam;
	ua->castaddr = ua_tmp->castaddr;
	ua->bastparam = ua_tmp->bastparam;
	ua->bastaddr = ua_tmp->bastaddr;
	ua->user_lksb = ua_tmp->user_lksb;

	error = set_lock_args(mode, &ua->lksb, flags, 0, timeout_cs,
			      fake_astfn, ua, fake_bastfn, &args);
	if (error)
		goto out_put;

	error = convert_lock(ls, lkb, &args);

	if (error == -EINPROGRESS || error == -EAGAIN || error == -EDEADLK)
		error = 0;
 out_put:
	dlm_put_lkb(lkb);
 out:
	dlm_unlock_recovery(ls);
	kfree(ua_tmp);
	return error;
}

/*
 * The caller asks for an orphan lock on a given resource with a given mode.
 * If a matching lock exists, it's moved to the owner's list of locks and
 * the lkid is returned.
 */

int dlm_user_adopt_orphan(struct dlm_ls *ls, struct dlm_user_args *ua_tmp,
		     int mode, uint32_t flags, void *name, unsigned int namelen,
		     unsigned long timeout_cs, uint32_t *lkid)
{
	struct dlm_lkb *lkb;
	struct dlm_user_args *ua;
	int found_other_mode = 0;
	int found = 0;
	int rv = 0;

	mutex_lock(&ls->ls_orphans_mutex);
	list_for_each_entry(lkb, &ls->ls_orphans, lkb_ownqueue) {
		if (lkb->lkb_resource->res_length != namelen)
			continue;
		if (memcmp(lkb->lkb_resource->res_name, name, namelen))
			continue;
		if (lkb->lkb_grmode != mode) {
			found_other_mode = 1;
			continue;
		}

		found = 1;
		list_del_init(&lkb->lkb_ownqueue);
		lkb->lkb_flags &= ~DLM_IFL_ORPHAN;
		*lkid = lkb->lkb_id;
		break;
	}
	mutex_unlock(&ls->ls_orphans_mutex);

	if (!found && found_other_mode) {
		rv = -EAGAIN;
		goto out;
	}

	if (!found) {
		rv = -ENOENT;
		goto out;
	}

	lkb->lkb_exflags = flags;
	lkb->lkb_ownpid = (int) current->pid;

	ua = lkb->lkb_ua;

	ua->proc = ua_tmp->proc;
	ua->xid = ua_tmp->xid;
	ua->castparam = ua_tmp->castparam;
	ua->castaddr = ua_tmp->castaddr;
	ua->bastparam = ua_tmp->bastparam;
	ua->bastaddr = ua_tmp->bastaddr;
	ua->user_lksb = ua_tmp->user_lksb;

	/*
	 * The lkb reference from the ls_orphans list was not
	 * removed above, and is now considered the reference
	 * for the proc locks list.
	 */

	spin_lock(&ua->proc->locks_spin);
	list_add_tail(&lkb->lkb_ownqueue, &ua->proc->locks);
	spin_unlock(&ua->proc->locks_spin);
 out:
	kfree(ua_tmp);
	return rv;
}

int dlm_user_unlock(struct dlm_ls *ls, struct dlm_user_args *ua_tmp,
		    uint32_t flags, uint32_t lkid, char *lvb_in)
{
	struct dlm_lkb *lkb;
	struct dlm_args args;
	struct dlm_user_args *ua;
	int error;

	dlm_lock_recovery(ls);

	error = find_lkb(ls, lkid, &lkb);
	if (error)
		goto out;

	ua = lkb->lkb_ua;

	if (lvb_in && ua->lksb.sb_lvbptr)
		memcpy(ua->lksb.sb_lvbptr, lvb_in, DLM_USER_LVB_LEN);
	if (ua_tmp->castparam)
		ua->castparam = ua_tmp->castparam;
	ua->user_lksb = ua_tmp->user_lksb;

	error = set_unlock_args(flags, ua, &args);
	if (error)
		goto out_put;

	error = unlock_lock(ls, lkb, &args);

	if (error == -DLM_EUNLOCK)
		error = 0;
	/* from validate_unlock_args() */
	if (error == -EBUSY && (flags & DLM_LKF_FORCEUNLOCK))
		error = 0;
	if (error)
		goto out_put;

	spin_lock(&ua->proc->locks_spin);
	/* dlm_user_add_cb() may have already taken lkb off the proc list */
	if (!list_empty(&lkb->lkb_ownqueue))
		list_move(&lkb->lkb_ownqueue, &ua->proc->unlocking);
	spin_unlock(&ua->proc->locks_spin);
 out_put:
	dlm_put_lkb(lkb);
 out:
	dlm_unlock_recovery(ls);
	kfree(ua_tmp);
	return error;
}

int dlm_user_cancel(struct dlm_ls *ls, struct dlm_user_args *ua_tmp,
		    uint32_t flags, uint32_t lkid)
{
	struct dlm_lkb *lkb;
	struct dlm_args args;
	struct dlm_user_args *ua;
	int error;

	dlm_lock_recovery(ls);

	error = find_lkb(ls, lkid, &lkb);
	if (error)
		goto out;

	ua = lkb->lkb_ua;
	if (ua_tmp->castparam)
		ua->castparam = ua_tmp->castparam;
	ua->user_lksb = ua_tmp->user_lksb;

	error = set_unlock_args(flags, ua, &args);
	if (error)
		goto out_put;

	error = cancel_lock(ls, lkb, &args);

	if (error == -DLM_ECANCEL)
		error = 0;
	/* from validate_unlock_args() */
	if (error == -EBUSY)
		error = 0;
 out_put:
	dlm_put_lkb(lkb);
 out:
	dlm_unlock_recovery(ls);
	kfree(ua_tmp);
	return error;
}

int dlm_user_deadlock(struct dlm_ls *ls, uint32_t flags, uint32_t lkid)
{
	struct dlm_lkb *lkb;
	struct dlm_args args;
	struct dlm_user_args *ua;
	struct dlm_rsb *r;
	int error;

	dlm_lock_recovery(ls);

	error = find_lkb(ls, lkid, &lkb);
	if (error)
		goto out;

	ua = lkb->lkb_ua;

	error = set_unlock_args(flags, ua, &args);
	if (error)
		goto out_put;

	/* same as cancel_lock(), but set DEADLOCK_CANCEL after lock_rsb */

	r = lkb->lkb_resource;
	hold_rsb(r);
	lock_rsb(r);

	error = validate_unlock_args(lkb, &args);
	if (error)
		goto out_r;
	lkb->lkb_flags |= DLM_IFL_DEADLOCK_CANCEL;

	error = _cancel_lock(r, lkb);
 out_r:
	unlock_rsb(r);
	put_rsb(r);

	if (error == -DLM_ECANCEL)
		error = 0;
	/* from validate_unlock_args() */
	if (error == -EBUSY)
		error = 0;
 out_put:
	dlm_put_lkb(lkb);
 out:
	dlm_unlock_recovery(ls);
	return error;
}

/* lkb's that are removed from the waiters list by revert are just left on the
   orphans list with the granted orphan locks, to be freed by purge */

static int orphan_proc_lock(struct dlm_ls *ls, struct dlm_lkb *lkb)
{
	struct dlm_args args;
	int error;

	hold_lkb(lkb); /* reference for the ls_orphans list */
	mutex_lock(&ls->ls_orphans_mutex);
	list_add_tail(&lkb->lkb_ownqueue, &ls->ls_orphans);
	mutex_unlock(&ls->ls_orphans_mutex);

	set_unlock_args(0, lkb->lkb_ua, &args);

	error = cancel_lock(ls, lkb, &args);
	if (error == -DLM_ECANCEL)
		error = 0;
	return error;
}

/* The FORCEUNLOCK flag allows the unlock to go ahead even if the lkb isn't
   granted.  Regardless of what rsb queue the lock is on, it's removed and
   freed.  The IVVALBLK flag causes the lvb on the resource to be invalidated
   if our lock is PW/EX (it's ignored if our granted mode is smaller.) */

static int unlock_proc_lock(struct dlm_ls *ls, struct dlm_lkb *lkb)
{
	struct dlm_args args;
	int error;

	set_unlock_args(DLM_LKF_FORCEUNLOCK | DLM_LKF_IVVALBLK,
			lkb->lkb_ua, &args);

	error = unlock_lock(ls, lkb, &args);
	if (error == -DLM_EUNLOCK)
		error = 0;
	return error;
}

/* We have to release clear_proc_locks mutex before calling unlock_proc_lock()
   (which does lock_rsb) due to deadlock with receiving a message that does
   lock_rsb followed by dlm_user_add_cb() */

static struct dlm_lkb *del_proc_lock(struct dlm_ls *ls,
				     struct dlm_user_proc *proc)
{
	struct dlm_lkb *lkb = NULL;

	mutex_lock(&ls->ls_clear_proc_locks);
	if (list_empty(&proc->locks))
		goto out;

	lkb = list_entry(proc->locks.next, struct dlm_lkb, lkb_ownqueue);
	list_del_init(&lkb->lkb_ownqueue);

	if (lkb->lkb_exflags & DLM_LKF_PERSISTENT)
		lkb->lkb_flags |= DLM_IFL_ORPHAN;
	else
		lkb->lkb_flags |= DLM_IFL_DEAD;
 out:
	mutex_unlock(&ls->ls_clear_proc_locks);
	return lkb;
}

/* The ls_clear_proc_locks mutex protects against dlm_user_add_cb() which
   1) references lkb->ua which we free here and 2) adds lkbs to proc->asts,
   which we clear here. */

/* proc CLOSING flag is set so no more device_reads should look at proc->asts
   list, and no more device_writes should add lkb's to proc->locks list; so we
   shouldn't need to take asts_spin or locks_spin here.  this assumes that
   device reads/writes/closes are serialized -- FIXME: we may need to serialize
   them ourself. */

void dlm_clear_proc_locks(struct dlm_ls *ls, struct dlm_user_proc *proc)
{
	struct dlm_lkb *lkb, *safe;

	dlm_lock_recovery(ls);

	while (1) {
		lkb = del_proc_lock(ls, proc);
		if (!lkb)
			break;
		del_timeout(lkb);
		if (lkb->lkb_exflags & DLM_LKF_PERSISTENT)
			orphan_proc_lock(ls, lkb);
		else
			unlock_proc_lock(ls, lkb);

		/* this removes the reference for the proc->locks list
		   added by dlm_user_request, it may result in the lkb
		   being freed */

		dlm_put_lkb(lkb);
	}

	mutex_lock(&ls->ls_clear_proc_locks);

	/* in-progress unlocks */
	list_for_each_entry_safe(lkb, safe, &proc->unlocking, lkb_ownqueue) {
		list_del_init(&lkb->lkb_ownqueue);
		lkb->lkb_flags |= DLM_IFL_DEAD;
		dlm_put_lkb(lkb);
	}

	list_for_each_entry_safe(lkb, safe, &proc->asts, lkb_cb_list) {
		memset(&lkb->lkb_callbacks, 0,
		       sizeof(struct dlm_callback) * DLM_CALLBACKS_SIZE);
		list_del_init(&lkb->lkb_cb_list);
		dlm_put_lkb(lkb);
	}

	mutex_unlock(&ls->ls_clear_proc_locks);
	dlm_unlock_recovery(ls);
}

static void purge_proc_locks(struct dlm_ls *ls, struct dlm_user_proc *proc)
{
	struct dlm_lkb *lkb, *safe;

	while (1) {
		lkb = NULL;
		spin_lock(&proc->locks_spin);
		if (!list_empty(&proc->locks)) {
			lkb = list_entry(proc->locks.next, struct dlm_lkb,
					 lkb_ownqueue);
			list_del_init(&lkb->lkb_ownqueue);
		}
		spin_unlock(&proc->locks_spin);

		if (!lkb)
			break;

		lkb->lkb_flags |= DLM_IFL_DEAD;
		unlock_proc_lock(ls, lkb);
		dlm_put_lkb(lkb); /* ref from proc->locks list */
	}

	spin_lock(&proc->locks_spin);
	list_for_each_entry_safe(lkb, safe, &proc->unlocking, lkb_ownqueue) {
		list_del_init(&lkb->lkb_ownqueue);
		lkb->lkb_flags |= DLM_IFL_DEAD;
		dlm_put_lkb(lkb);
	}
	spin_unlock(&proc->locks_spin);

	spin_lock(&proc->asts_spin);
	list_for_each_entry_safe(lkb, safe, &proc->asts, lkb_cb_list) {
		memset(&lkb->lkb_callbacks, 0,
		       sizeof(struct dlm_callback) * DLM_CALLBACKS_SIZE);
		list_del_init(&lkb->lkb_cb_list);
		dlm_put_lkb(lkb);
	}
	spin_unlock(&proc->asts_spin);
}

/* pid of 0 means purge all orphans */

static void do_purge(struct dlm_ls *ls, int nodeid, int pid)
{
	struct dlm_lkb *lkb, *safe;

	mutex_lock(&ls->ls_orphans_mutex);
	list_for_each_entry_safe(lkb, safe, &ls->ls_orphans, lkb_ownqueue) {
		if (pid && lkb->lkb_ownpid != pid)
			continue;
		unlock_proc_lock(ls, lkb);
		list_del_init(&lkb->lkb_ownqueue);
		dlm_put_lkb(lkb);
	}
	mutex_unlock(&ls->ls_orphans_mutex);
}

static int send_purge(struct dlm_ls *ls, int nodeid, int pid)
{
	struct dlm_message *ms;
	struct dlm_mhandle *mh;
	int error;

	error = _create_message(ls, sizeof(struct dlm_message), nodeid,
				DLM_MSG_PURGE, &ms, &mh);
	if (error)
		return error;
	ms->m_nodeid = nodeid;
	ms->m_pid = pid;

	return send_message(mh, ms);
}

int dlm_user_purge(struct dlm_ls *ls, struct dlm_user_proc *proc,
		   int nodeid, int pid)
{
	int error = 0;

	if (nodeid && (nodeid != dlm_our_nodeid())) {
		error = send_purge(ls, nodeid, pid);
	} else {
		dlm_lock_recovery(ls);
		if (pid == current->pid)
			purge_proc_locks(ls, proc);
		else
			do_purge(ls, nodeid, pid);
		dlm_unlock_recovery(ls);
	}
	return error;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/lock.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2011 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
// #include "lockspace.h"
// #include "member.h"
#include "recoverd.h"
// #include "dir.h"
// #include "lowcomms.h"
// #include "config.h"
// #include "memory.h"
// #include "lock.h"
// #include "recover.h"
// #include "requestqueue.h"
// #include "user.h"
// #include "ast.h"
#include "../../inc/__fss.h"

static int			ls_count;
static struct mutex		ls_lock;
static struct list_head		lslist;
static spinlock_t		lslist_lock;
static struct task_struct *	scand_task;


static ssize_t dlm_control_store(struct dlm_ls *ls, const char *buf, size_t len)
{
	ssize_t ret = len;
	int n;
	int rc = kstrtoint(buf, 0, &n);

	if (rc)
		return rc;
	ls = dlm_find_lockspace_local(ls->ls_local_handle);
	if (!ls)
		return -EINVAL;

	switch (n) {
	case 0:
		dlm_ls_stop(ls);
		break;
	case 1:
		dlm_ls_start(ls);
		break;
	default:
		ret = -EINVAL;
	}
	dlm_put_lockspace(ls);
	return ret;
}

static ssize_t dlm_event_store(struct dlm_ls *ls, const char *buf, size_t len)
{
	int rc = kstrtoint(buf, 0, &ls->ls_uevent_result);

	if (rc)
		return rc;
	set_bit(LSFL_UEVENT_WAIT, &ls->ls_flags);
	wake_up(&ls->ls_uevent_wait);
	return len;
}

static ssize_t dlm_id_show(struct dlm_ls *ls, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", ls->ls_global_id);
}

static ssize_t dlm_id_store(struct dlm_ls *ls, const char *buf, size_t len)
{
	int rc = kstrtouint(buf, 0, &ls->ls_global_id);

	if (rc)
		return rc;
	return len;
}

static ssize_t dlm_nodir_show(struct dlm_ls *ls, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", dlm_no_directory(ls));
}

static ssize_t dlm_nodir_store(struct dlm_ls *ls, const char *buf, size_t len)
{
	int val;
	int rc = kstrtoint(buf, 0, &val);

	if (rc)
		return rc;
	if (val == 1)
		set_bit(LSFL_NODIR, &ls->ls_flags);
	return len;
}

static ssize_t dlm_recover_status_show(struct dlm_ls *ls, char *buf)
{
	uint32_t status = dlm_recover_status(ls);
	return snprintf(buf, PAGE_SIZE, "%x\n", status);
}

static ssize_t dlm_recover_nodeid_show(struct dlm_ls *ls, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", ls->ls_recover_nodeid);
}

struct dlm_attr {
	struct attribute attr;
	ssize_t (*show)(struct dlm_ls *, char *);
	ssize_t (*store)(struct dlm_ls *, const char *, size_t);
};

static struct dlm_attr dlm_attr_control = {
	.attr  = {.name = "control", .mode = S_IWUSR},
	.store = dlm_control_store
};

static struct dlm_attr dlm_attr_event = {
	.attr  = {.name = "event_done", .mode = S_IWUSR},
	.store = dlm_event_store
};

static struct dlm_attr dlm_attr_id = {
	.attr  = {.name = "id", .mode = S_IRUGO | S_IWUSR},
	.show  = dlm_id_show,
	.store = dlm_id_store
};

static struct dlm_attr dlm_attr_nodir = {
	.attr  = {.name = "nodir", .mode = S_IRUGO | S_IWUSR},
	.show  = dlm_nodir_show,
	.store = dlm_nodir_store
};

static struct dlm_attr dlm_attr_recover_status = {
	.attr  = {.name = "recover_status", .mode = S_IRUGO},
	.show  = dlm_recover_status_show
};

static struct dlm_attr dlm_attr_recover_nodeid = {
	.attr  = {.name = "recover_nodeid", .mode = S_IRUGO},
	.show  = dlm_recover_nodeid_show
};

static struct attribute *dlm_attrs[] = {
	&dlm_attr_control.attr,
	&dlm_attr_event.attr,
	&dlm_attr_id.attr,
	&dlm_attr_nodir.attr,
	&dlm_attr_recover_status.attr,
	&dlm_attr_recover_nodeid.attr,
	NULL,
};

static ssize_t dlm_attr_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct dlm_ls *ls  = container_of(kobj, struct dlm_ls, ls_kobj);
	struct dlm_attr *a = container_of(attr, struct dlm_attr, attr);
	return a->show ? a->show(ls, buf) : 0;
}

static ssize_t dlm_attr_store(struct kobject *kobj, struct attribute *attr,
			      const char *buf, size_t len)
{
	struct dlm_ls *ls  = container_of(kobj, struct dlm_ls, ls_kobj);
	struct dlm_attr *a = container_of(attr, struct dlm_attr, attr);
	return a->store ? a->store(ls, buf, len) : len;
}

static void lockspace_kobj_release(struct kobject *k)
{
	struct dlm_ls *ls  = container_of(k, struct dlm_ls, ls_kobj);
	kfree(ls);
}

static const struct sysfs_ops dlm_attr_ops = {
	.show  = dlm_attr_show,
	.store = dlm_attr_store,
};

static struct kobj_type dlm_ktype = {
	.default_attrs = dlm_attrs,
	.sysfs_ops     = &dlm_attr_ops,
	.release       = lockspace_kobj_release,
};

static struct kset *dlm_kset;

static int do_uevent(struct dlm_ls *ls, int in)
{
	int error;

	if (in)
		kobject_uevent(&ls->ls_kobj, KOBJ_ONLINE);
	else
		kobject_uevent(&ls->ls_kobj, KOBJ_OFFLINE);

	log_rinfo(ls, "%s the lockspace group...", in ? "joining" : "leaving");

	/* dlm_controld will see the uevent, do the necessary group management
	   and then write to sysfs to wake us */

	error = wait_event_interruptible(ls->ls_uevent_wait,
			test_and_clear_bit(LSFL_UEVENT_WAIT, &ls->ls_flags));

	log_rinfo(ls, "group event done %d %d", error, ls->ls_uevent_result);

	if (error)
		goto out;

	error = ls->ls_uevent_result;
 out:
	if (error)
		log_error(ls, "group %s failed %d %d", in ? "join" : "leave",
			  error, ls->ls_uevent_result);
	return error;
}

static int dlm_uevent(struct kset *kset, struct kobject *kobj,
		      struct kobj_uevent_env *env)
{
	struct dlm_ls *ls = container_of(kobj, struct dlm_ls, ls_kobj);

	add_uevent_var(env, "LOCKSPACE=%s", ls->ls_name);
	return 0;
}

static struct kset_uevent_ops dlm_uevent_ops = {
	.uevent = dlm_uevent,
};

int __init dlm_lockspace_init(void)
{
	ls_count = 0;
	mutex_init(&ls_lock);
	INIT_LIST_HEAD(&lslist);
	spin_lock_init(&lslist_lock);

	dlm_kset = kset_create_and_add("dlm", &dlm_uevent_ops, kernel_kobj);
	if (!dlm_kset) {
		printk(KERN_WARNING "%s: can not create kset\n", __func__);
		return -ENOMEM;
	}
	return 0;
}

void dlm_lockspace_exit(void)
{
	kset_unregister(dlm_kset);
}

static struct dlm_ls *find_ls_to_scan(void)
{
	struct dlm_ls *ls;

	spin_lock(&lslist_lock);
	list_for_each_entry(ls, &lslist, ls_list) {
		if (time_after_eq(jiffies, ls->ls_scan_time +
					    dlm_config.ci_scan_secs * HZ)) {
			spin_unlock(&lslist_lock);
			return ls;
		}
	}
	spin_unlock(&lslist_lock);
	return NULL;
}

static int dlm_scand(void *data)
{
	struct dlm_ls *ls;

	while (!kthread_should_stop()) {
		ls = find_ls_to_scan();
		if (ls) {
			if (dlm_lock_recovery_try(ls)) {
				ls->ls_scan_time = jiffies;
				dlm_scan_rsbs(ls);
				dlm_scan_timeout(ls);
				dlm_scan_waiters(ls);
				dlm_unlock_recovery(ls);
			} else {
				ls->ls_scan_time += HZ;
			}
			continue;
		}
		schedule_timeout_interruptible(dlm_config.ci_scan_secs * HZ);
	}
	return 0;
}

static int dlm_scand_start(void)
{
	struct task_struct *p;
	int error = 0;

	p = kthread_run(dlm_scand, NULL, "dlm_scand");
	if (IS_ERR(p))
		error = PTR_ERR(p);
	else
		scand_task = p;
	return error;
}

static void dlm_scand_stop(void)
{
	kthread_stop(scand_task);
}

struct dlm_ls *dlm_find_lockspace_global(uint32_t id)
{
	struct dlm_ls *ls;

	spin_lock(&lslist_lock);

	list_for_each_entry(ls, &lslist, ls_list) {
		if (ls->ls_global_id == id) {
			ls->ls_count++;
			goto out;
		}
	}
	ls = NULL;
 out:
	spin_unlock(&lslist_lock);
	return ls;
}

struct dlm_ls *dlm_find_lockspace_local(dlm_lockspace_t *lockspace)
{
	struct dlm_ls *ls;

	spin_lock(&lslist_lock);
	list_for_each_entry(ls, &lslist, ls_list) {
		if (ls->ls_local_handle == lockspace) {
			ls->ls_count++;
			goto out;
		}
	}
	ls = NULL;
 out:
	spin_unlock(&lslist_lock);
	return ls;
}

struct dlm_ls *dlm_find_lockspace_device(int minor)
{
	struct dlm_ls *ls;

	spin_lock(&lslist_lock);
	list_for_each_entry(ls, &lslist, ls_list) {
		if (ls->ls_device.minor == minor) {
			ls->ls_count++;
			goto out;
		}
	}
	ls = NULL;
 out:
	spin_unlock(&lslist_lock);
	return ls;
}

void dlm_put_lockspace(struct dlm_ls *ls)
{
	spin_lock(&lslist_lock);
	ls->ls_count--;
	spin_unlock(&lslist_lock);
}

static void remove_lockspace(struct dlm_ls *ls)
{
	for (;;) {
		spin_lock(&lslist_lock);
		if (ls->ls_count == 0) {
			WARN_ON(ls->ls_create_count != 0);
			list_del(&ls->ls_list);
			spin_unlock(&lslist_lock);
			return;
		}
		spin_unlock(&lslist_lock);
		ssleep(1);
	}
}

static int threads_start(void)
{
	int error;

	error = dlm_scand_start();
	if (error) {
		log_print("cannot start dlm_scand thread %d", error);
		goto fail;
	}

	/* Thread for sending/receiving messages for all lockspace's */
	error = dlm_lowcomms_start();
	if (error) {
		log_print("cannot start dlm lowcomms %d", error);
		goto scand_fail;
	}

	return 0;

 scand_fail:
	dlm_scand_stop();
 fail:
	return error;
}

static void threads_stop(void)
{
	dlm_scand_stop();
	dlm_lowcomms_stop();
}

static int new_lockspace(const char *name, const char *cluster,
			 uint32_t flags, int lvblen,
			 const struct dlm_lockspace_ops *ops, void *ops_arg,
			 int *ops_result, dlm_lockspace_t **lockspace)
{
	struct dlm_ls *ls;
	int i, size, error;
	int do_unreg = 0;
	int namelen = strlen(name);

	if (namelen > DLM_LOCKSPACE_LEN)
		return -EINVAL;

	if (!lvblen || (lvblen % 8))
		return -EINVAL;

	if (!try_module_get(THIS_MODULE))
		return -EINVAL;

	if (!dlm_user_daemon_available()) {
		log_print("dlm user daemon not available");
		error = -EUNATCH;
		goto out;
	}

	if (ops && ops_result) {
	       	if (!dlm_config.ci_recover_callbacks)
			*ops_result = -EOPNOTSUPP;
		else
			*ops_result = 0;
	}

	if (dlm_config.ci_recover_callbacks && cluster &&
	    strncmp(cluster, dlm_config.ci_cluster_name, DLM_LOCKSPACE_LEN)) {
		log_print("dlm cluster name %s mismatch %s",
			  dlm_config.ci_cluster_name, cluster);
		error = -EBADR;
		goto out;
	}

	error = 0;

	spin_lock(&lslist_lock);
	list_for_each_entry(ls, &lslist, ls_list) {
		WARN_ON(ls->ls_create_count <= 0);
		if (ls->ls_namelen != namelen)
			continue;
		if (memcmp(ls->ls_name, name, namelen))
			continue;
		if (flags & DLM_LSFL_NEWEXCL) {
			error = -EEXIST;
			break;
		}
		ls->ls_create_count++;
		*lockspace = ls;
		error = 1;
		break;
	}
	spin_unlock(&lslist_lock);

	if (error)
		goto out;

	error = -ENOMEM;

	ls = kzalloc(sizeof(struct dlm_ls) + namelen, GFP_NOFS);
	if (!ls)
		goto out;
	memcpy(ls->ls_name, name, namelen);
	ls->ls_namelen = namelen;
	ls->ls_lvblen = lvblen;
	ls->ls_count = 0;
	ls->ls_flags = 0;
	ls->ls_scan_time = jiffies;

	if (ops && dlm_config.ci_recover_callbacks) {
		ls->ls_ops = ops;
		ls->ls_ops_arg = ops_arg;
	}

	if (flags & DLM_LSFL_TIMEWARN)
		set_bit(LSFL_TIMEWARN, &ls->ls_flags);

	/* ls_exflags are forced to match among nodes, and we don't
	   need to require all nodes to have some flags set */
	ls->ls_exflags = (flags & ~(DLM_LSFL_TIMEWARN | DLM_LSFL_FS |
				    DLM_LSFL_NEWEXCL));

	size = dlm_config.ci_rsbtbl_size;
	ls->ls_rsbtbl_size = size;

	ls->ls_rsbtbl = vmalloc(sizeof(struct dlm_rsbtable) * size);
	if (!ls->ls_rsbtbl)
		goto out_lsfree;
	for (i = 0; i < size; i++) {
		ls->ls_rsbtbl[i].keep.rb_node = NULL;
		ls->ls_rsbtbl[i].toss.rb_node = NULL;
		spin_lock_init(&ls->ls_rsbtbl[i].lock);
	}

	spin_lock_init(&ls->ls_remove_spin);

	for (i = 0; i < DLM_REMOVE_NAMES_MAX; i++) {
		ls->ls_remove_names[i] = kzalloc(DLM_RESNAME_MAXLEN+1,
						 GFP_KERNEL);
		if (!ls->ls_remove_names[i])
			goto out_rsbtbl;
	}

	idr_init(&ls->ls_lkbidr);
	spin_lock_init(&ls->ls_lkbidr_spin);

	INIT_LIST_HEAD(&ls->ls_waiters);
	mutex_init(&ls->ls_waiters_mutex);
	INIT_LIST_HEAD(&ls->ls_orphans);
	mutex_init(&ls->ls_orphans_mutex);
	INIT_LIST_HEAD(&ls->ls_timeout);
	mutex_init(&ls->ls_timeout_mutex);

	INIT_LIST_HEAD(&ls->ls_new_rsb);
	spin_lock_init(&ls->ls_new_rsb_spin);

	INIT_LIST_HEAD(&ls->ls_nodes);
	INIT_LIST_HEAD(&ls->ls_nodes_gone);
	ls->ls_num_nodes = 0;
	ls->ls_low_nodeid = 0;
	ls->ls_total_weight = 0;
	ls->ls_node_array = NULL;

	memset(&ls->ls_stub_rsb, 0, sizeof(struct dlm_rsb));
	ls->ls_stub_rsb.res_ls = ls;

	ls->ls_debug_rsb_dentry = NULL;
	ls->ls_debug_waiters_dentry = NULL;

	init_waitqueue_head(&ls->ls_uevent_wait);
	ls->ls_uevent_result = 0;
	init_completion(&ls->ls_members_done);
	ls->ls_members_result = -1;

	mutex_init(&ls->ls_cb_mutex);
	INIT_LIST_HEAD(&ls->ls_cb_delay);

	ls->ls_recoverd_task = NULL;
	mutex_init(&ls->ls_recoverd_active);
	spin_lock_init(&ls->ls_recover_lock);
	spin_lock_init(&ls->ls_rcom_spin);
	get_random_bytes(&ls->ls_rcom_seq, sizeof(uint64_t));
	ls->ls_recover_status = 0;
	ls->ls_recover_seq = 0;
	ls->ls_recover_args = NULL;
	init_rwsem(&ls->ls_in_recovery);
	init_rwsem(&ls->ls_recv_active);
	INIT_LIST_HEAD(&ls->ls_requestqueue);
	mutex_init(&ls->ls_requestqueue_mutex);
	mutex_init(&ls->ls_clear_proc_locks);

	ls->ls_recover_buf = kmalloc(dlm_config.ci_buffer_size, GFP_NOFS);
	if (!ls->ls_recover_buf)
		goto out_lkbidr;

	ls->ls_slot = 0;
	ls->ls_num_slots = 0;
	ls->ls_slots_size = 0;
	ls->ls_slots = NULL;

	INIT_LIST_HEAD(&ls->ls_recover_list);
	spin_lock_init(&ls->ls_recover_list_lock);
	idr_init(&ls->ls_recover_idr);
	spin_lock_init(&ls->ls_recover_idr_lock);
	ls->ls_recover_list_count = 0;
	ls->ls_local_handle = ls;
	init_waitqueue_head(&ls->ls_wait_general);
	INIT_LIST_HEAD(&ls->ls_root_list);
	init_rwsem(&ls->ls_root_sem);

	spin_lock(&lslist_lock);
	ls->ls_create_count = 1;
	list_add(&ls->ls_list, &lslist);
	spin_unlock(&lslist_lock);

	if (flags & DLM_LSFL_FS) {
		error = dlm_callback_start(ls);
		if (error) {
			log_error(ls, "can't start dlm_callback %d", error);
			goto out_delist;
		}
	}

	init_waitqueue_head(&ls->ls_recover_lock_wait);

	/*
	 * Once started, dlm_recoverd first looks for ls in lslist, then
	 * initializes ls_in_recovery as locked in "down" mode.  We need
	 * to wait for the wakeup from dlm_recoverd because in_recovery
	 * has to start out in down mode.
	 */

	error = dlm_recoverd_start(ls);
	if (error) {
		log_error(ls, "can't start dlm_recoverd %d", error);
		goto out_callback;
	}

	wait_event(ls->ls_recover_lock_wait,
		   test_bit(LSFL_RECOVER_LOCK, &ls->ls_flags));

	ls->ls_kobj.kset = dlm_kset;
	error = kobject_init_and_add(&ls->ls_kobj, &dlm_ktype, NULL,
				     "%s", ls->ls_name);
	if (error)
		goto out_recoverd;
	kobject_uevent(&ls->ls_kobj, KOBJ_ADD);

	/* let kobject handle freeing of ls if there's an error */
	do_unreg = 1;

	/* This uevent triggers dlm_controld in userspace to add us to the
	   group of nodes that are members of this lockspace (managed by the
	   cluster infrastructure.)  Once it's done that, it tells us who the
	   current lockspace members are (via configfs) and then tells the
	   lockspace to start running (via sysfs) in dlm_ls_start(). */

	error = do_uevent(ls, 1);
	if (error)
		goto out_recoverd;

	wait_for_completion(&ls->ls_members_done);
	error = ls->ls_members_result;
	if (error)
		goto out_members;

	dlm_create_debug_file(ls);

	log_rinfo(ls, "join complete");
	*lockspace = ls;
	return 0;

 out_members:
	do_uevent(ls, 0);
	dlm_clear_members(ls);
	kfree(ls->ls_node_array);
 out_recoverd:
	dlm_recoverd_stop(ls);
 out_callback:
	dlm_callback_stop(ls);
 out_delist:
	spin_lock(&lslist_lock);
	list_del(&ls->ls_list);
	spin_unlock(&lslist_lock);
	idr_destroy(&ls->ls_recover_idr);
	kfree(ls->ls_recover_buf);
 out_lkbidr:
	idr_destroy(&ls->ls_lkbidr);
	for (i = 0; i < DLM_REMOVE_NAMES_MAX; i++) {
		if (ls->ls_remove_names[i])
			kfree(ls->ls_remove_names[i]);
	}
 out_rsbtbl:
	vfree(ls->ls_rsbtbl);
 out_lsfree:
	if (do_unreg)
		kobject_put(&ls->ls_kobj);
	else
		kfree(ls);
 out:
	module_put(THIS_MODULE);
	return error;
}

int dlm_new_lockspace(const char *name, const char *cluster,
		      uint32_t flags, int lvblen,
		      const struct dlm_lockspace_ops *ops, void *ops_arg,
		      int *ops_result, dlm_lockspace_t **lockspace)
{
	int error = 0;

	mutex_lock(&ls_lock);
	if (!ls_count)
		error = threads_start();
	if (error)
		goto out;

	error = new_lockspace(name, cluster, flags, lvblen, ops, ops_arg,
			      ops_result, lockspace);
	if (!error)
		ls_count++;
	if (error > 0)
		error = 0;
	if (!ls_count)
		threads_stop();
 out:
	mutex_unlock(&ls_lock);
	return error;
}

static int lkb_idr_is_local(int id, void *p, void *data)
{
	struct dlm_lkb *lkb = p;

	return lkb->lkb_nodeid == 0 && lkb->lkb_grmode != DLM_LOCK_IV;
}

static int lkb_idr_is_any(int id, void *p, void *data)
{
	return 1;
}

static int lkb_idr_free(int id, void *p, void *data)
{
	struct dlm_lkb *lkb = p;

	if (lkb->lkb_lvbptr && lkb->lkb_flags & DLM_IFL_MSTCPY)
		dlm_free_lvb(lkb->lkb_lvbptr);

	dlm_free_lkb(lkb);
	return 0;
}

/* NOTE: We check the lkbidr here rather than the resource table.
   This is because there may be LKBs queued as ASTs that have been unlinked
   from their RSBs and are pending deletion once the AST has been delivered */

static int lockspace_busy(struct dlm_ls *ls, int force)
{
	int rv;

	spin_lock(&ls->ls_lkbidr_spin);
	if (force == 0) {
		rv = idr_for_each(&ls->ls_lkbidr, lkb_idr_is_any, ls);
	} else if (force == 1) {
		rv = idr_for_each(&ls->ls_lkbidr, lkb_idr_is_local, ls);
	} else {
		rv = 0;
	}
	spin_unlock(&ls->ls_lkbidr_spin);
	return rv;
}

static int release_lockspace(struct dlm_ls *ls, int force)
{
	struct dlm_rsb *rsb;
	struct rb_node *n;
	int i, busy, rv;

	busy = lockspace_busy(ls, force);

	spin_lock(&lslist_lock);
	if (ls->ls_create_count == 1) {
		if (busy) {
			rv = -EBUSY;
		} else {
			/* remove_lockspace takes ls off lslist */
			ls->ls_create_count = 0;
			rv = 0;
		}
	} else if (ls->ls_create_count > 1) {
		rv = --ls->ls_create_count;
	} else {
		rv = -EINVAL;
	}
	spin_unlock(&lslist_lock);

	if (rv) {
		log_debug(ls, "release_lockspace no remove %d", rv);
		return rv;
	}

	dlm_device_deregister(ls);

	if (force < 3 && dlm_user_daemon_available())
		do_uevent(ls, 0);

	dlm_recoverd_stop(ls);

	dlm_callback_stop(ls);

	remove_lockspace(ls);

	dlm_delete_debug_file(ls);

	kfree(ls->ls_recover_buf);

	/*
	 * Free all lkb's in idr
	 */

	idr_for_each(&ls->ls_lkbidr, lkb_idr_free, ls);
	idr_destroy(&ls->ls_lkbidr);

	/*
	 * Free all rsb's on rsbtbl[] lists
	 */

	for (i = 0; i < ls->ls_rsbtbl_size; i++) {
		while ((n = rb_first(&ls->ls_rsbtbl[i].keep))) {
			rsb = rb_entry(n, struct dlm_rsb, res_hashnode);
			rb_erase(n, &ls->ls_rsbtbl[i].keep);
			dlm_free_rsb(rsb);
		}

		while ((n = rb_first(&ls->ls_rsbtbl[i].toss))) {
			rsb = rb_entry(n, struct dlm_rsb, res_hashnode);
			rb_erase(n, &ls->ls_rsbtbl[i].toss);
			dlm_free_rsb(rsb);
		}
	}

	vfree(ls->ls_rsbtbl);

	for (i = 0; i < DLM_REMOVE_NAMES_MAX; i++)
		kfree(ls->ls_remove_names[i]);

	while (!list_empty(&ls->ls_new_rsb)) {
		rsb = list_first_entry(&ls->ls_new_rsb, struct dlm_rsb,
				       res_hashchain);
		list_del(&rsb->res_hashchain);
		dlm_free_rsb(rsb);
	}

	/*
	 * Free structures on any other lists
	 */

	dlm_purge_requestqueue(ls);
	kfree(ls->ls_recover_args);
	dlm_clear_members(ls);
	dlm_clear_members_gone(ls);
	kfree(ls->ls_node_array);
	log_rinfo(ls, "release_lockspace final free");
	kobject_put(&ls->ls_kobj);
	/* The ls structure will be freed when the kobject is done with */

	module_put(THIS_MODULE);
	return 0;
}

/*
 * Called when a system has released all its locks and is not going to use the
 * lockspace any longer.  We free everything we're managing for this lockspace.
 * Remaining nodes will go through the recovery process as if we'd died.  The
 * lockspace must continue to function as usual, participating in recoveries,
 * until this returns.
 *
 * Force has 4 possible values:
 * 0 - don't destroy locksapce if it has any LKBs
 * 1 - destroy lockspace if it has remote LKBs but not if it has local LKBs
 * 2 - destroy lockspace regardless of LKBs
 * 3 - destroy lockspace as part of a forced shutdown
 */

int dlm_release_lockspace(void *lockspace, int force)
{
	struct dlm_ls *ls;
	int error;

	ls = dlm_find_lockspace_local(lockspace);
	if (!ls)
		return -EINVAL;
	dlm_put_lockspace(ls);

	mutex_lock(&ls_lock);
	error = release_lockspace(ls, force);
	if (!error)
		ls_count--;
	if (!ls_count)
		threads_stop();
	mutex_unlock(&ls_lock);

	return error;
}

void dlm_stop_lockspaces(void)
{
	struct dlm_ls *ls;
	int count;

 restart:
	count = 0;
	spin_lock(&lslist_lock);
	list_for_each_entry(ls, &lslist, ls_list) {
		if (!test_bit(LSFL_RUNNING, &ls->ls_flags)) {
			count++;
			continue;
		}
		spin_unlock(&lslist_lock);
		log_error(ls, "no userland control daemon, stopping lockspace");
		dlm_ls_stop(ls);
		goto restart;
	}
	spin_unlock(&lslist_lock);

	if (count)
		log_print("dlm user daemon left %d lockspaces", count);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/lockspace.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2007 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
// #include "lockspace.h"
// #include "lock.h"
// #include "user.h"
// #include "memory.h"
// #include "config.h"
// #include "lowcomms.h"

static int __init init_dlm(void)
{
	int error;

	error = dlm_memory_init();
	if (error)
		goto out;

	error = dlm_lockspace_init();
	if (error)
		goto out_mem;

	error = dlm_config_init();
	if (error)
		goto out_lockspace;

	error = dlm_register_debugfs();
	if (error)
		goto out_config;

	error = dlm_user_init();
	if (error)
		goto out_debug;

	error = dlm_netlink_init();
	if (error)
		goto out_user;

	error = dlm_plock_init();
	if (error)
		goto out_netlink;

	printk("DLM installed\n");

	return 0;

 out_netlink:
	dlm_netlink_exit();
 out_user:
	dlm_user_exit();
 out_debug:
	dlm_unregister_debugfs();
 out_config:
	dlm_config_exit();
 out_lockspace:
	dlm_lockspace_exit();
 out_mem:
	dlm_memory_exit();
 out:
	return error;
}

static void __exit exit_dlm(void)
{
	dlm_plock_exit();
	dlm_netlink_exit();
	dlm_user_exit();
	dlm_config_exit();
	dlm_memory_exit();
	dlm_lockspace_exit();
	dlm_lowcomms_exit();
	dlm_unregister_debugfs();
}

module_init(init_dlm);
module_exit(exit_dlm);

MODULE_DESCRIPTION("Distributed Lock Manager");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL_GPL(dlm_new_lockspace);
EXPORT_SYMBOL_GPL(dlm_release_lockspace);
EXPORT_SYMBOL_GPL(dlm_lock);
EXPORT_SYMBOL_GPL(dlm_unlock);
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/main.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) 2005-2011 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
// #include "lockspace.h"
// #include "member.h"
// #include "recoverd.h"
// #include "recover.h"
// #include "rcom.h"
// #include "config.h"
// #include "lowcomms.h"

int dlm_slots_version(struct dlm_header *h)
{
	if ((h->h_version & 0x0000FFFF) < DLM_HEADER_SLOTS)
		return 0;
	return 1;
}

void dlm_slot_save(struct dlm_ls *ls, struct dlm_rcom *rc,
		   struct dlm_member *memb)
{
	struct rcom_config *rf = (struct rcom_config *)rc->rc_buf;

	if (!dlm_slots_version(&rc->rc_header))
		return;

	memb->slot = le16_to_cpu(rf->rf_our_slot);
	memb->generation = le32_to_cpu(rf->rf_generation);
}

void dlm_slots_copy_out(struct dlm_ls *ls, struct dlm_rcom *rc)
{
	struct dlm_slot *slot;
	struct rcom_slot *ro;
	int i;

	ro = (struct rcom_slot *)(rc->rc_buf + sizeof(struct rcom_config));

	/* ls_slots array is sparse, but not rcom_slots */

	for (i = 0; i < ls->ls_slots_size; i++) {
		slot = &ls->ls_slots[i];
		if (!slot->nodeid)
			continue;
		ro->ro_nodeid = cpu_to_le32(slot->nodeid);
		ro->ro_slot = cpu_to_le16(slot->slot);
		ro++;
	}
}

#define SLOT_DEBUG_LINE 128

static void log_slots(struct dlm_ls *ls, uint32_t gen, int num_slots,
		      struct rcom_slot *ro0, struct dlm_slot *array,
		      int array_size)
{
	char line[SLOT_DEBUG_LINE];
	int len = SLOT_DEBUG_LINE - 1;
	int pos = 0;
	int ret, i;

	memset(line, 0, sizeof(line));

	if (array) {
		for (i = 0; i < array_size; i++) {
			if (!array[i].nodeid)
				continue;

			ret = snprintf(line + pos, len - pos, " %d:%d",
				       array[i].slot, array[i].nodeid);
			if (ret >= len - pos)
				break;
			pos += ret;
		}
	} else if (ro0) {
		for (i = 0; i < num_slots; i++) {
			ret = snprintf(line + pos, len - pos, " %d:%d",
				       ro0[i].ro_slot, ro0[i].ro_nodeid);
			if (ret >= len - pos)
				break;
			pos += ret;
		}
	}

	log_rinfo(ls, "generation %u slots %d%s", gen, num_slots, line);
}

int dlm_slots_copy_in(struct dlm_ls *ls)
{
	struct dlm_member *memb;
	struct dlm_rcom *rc = ls->ls_recover_buf;
	struct rcom_config *rf = (struct rcom_config *)rc->rc_buf;
	struct rcom_slot *ro0, *ro;
	int our_nodeid = dlm_our_nodeid();
	int i, num_slots;
	uint32_t gen;

	if (!dlm_slots_version(&rc->rc_header))
		return -1;

	gen = le32_to_cpu(rf->rf_generation);
	if (gen <= ls->ls_generation) {
		log_error(ls, "dlm_slots_copy_in gen %u old %u",
			  gen, ls->ls_generation);
	}
	ls->ls_generation = gen;

	num_slots = le16_to_cpu(rf->rf_num_slots);
	if (!num_slots)
		return -1;

	ro0 = (struct rcom_slot *)(rc->rc_buf + sizeof(struct rcom_config));

	for (i = 0, ro = ro0; i < num_slots; i++, ro++) {
		ro->ro_nodeid = le32_to_cpu(ro->ro_nodeid);
		ro->ro_slot = le16_to_cpu(ro->ro_slot);
	}

	log_slots(ls, gen, num_slots, ro0, NULL, 0);

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		for (i = 0, ro = ro0; i < num_slots; i++, ro++) {
			if (ro->ro_nodeid != memb->nodeid)
				continue;
			memb->slot = ro->ro_slot;
			memb->slot_prev = memb->slot;
			break;
		}

		if (memb->nodeid == our_nodeid) {
			if (ls->ls_slot && ls->ls_slot != memb->slot) {
				log_error(ls, "dlm_slots_copy_in our slot "
					  "changed %d %d", ls->ls_slot,
					  memb->slot);
				return -1;
			}

			if (!ls->ls_slot)
				ls->ls_slot = memb->slot;
		}

		if (!memb->slot) {
			log_error(ls, "dlm_slots_copy_in nodeid %d no slot",
				   memb->nodeid);
			return -1;
		}
	}

	return 0;
}

/* for any nodes that do not support slots, we will not have set memb->slot
   in wait_status_all(), so memb->slot will remain -1, and we will not
   assign slots or set ls_num_slots here */

int dlm_slots_assign(struct dlm_ls *ls, int *num_slots, int *slots_size,
		     struct dlm_slot **slots_out, uint32_t *gen_out)
{
	struct dlm_member *memb;
	struct dlm_slot *array;
	int our_nodeid = dlm_our_nodeid();
	int array_size, max_slots, i;
	int need = 0;
	int max = 0;
	int num = 0;
	uint32_t gen = 0;

	/* our own memb struct will have slot -1 gen 0 */

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		if (memb->nodeid == our_nodeid) {
			memb->slot = ls->ls_slot;
			memb->generation = ls->ls_generation;
			break;
		}
	}

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		if (memb->generation > gen)
			gen = memb->generation;

		/* node doesn't support slots */

		if (memb->slot == -1)
			return -1;

		/* node needs a slot assigned */

		if (!memb->slot)
			need++;

		/* node has a slot assigned */

		num++;

		if (!max || max < memb->slot)
			max = memb->slot;

		/* sanity check, once slot is assigned it shouldn't change */

		if (memb->slot_prev && memb->slot && memb->slot_prev != memb->slot) {
			log_error(ls, "nodeid %d slot changed %d %d",
				  memb->nodeid, memb->slot_prev, memb->slot);
			return -1;
		}
		memb->slot_prev = memb->slot;
	}

	array_size = max + need;

	array = kzalloc(array_size * sizeof(struct dlm_slot), GFP_NOFS);
	if (!array)
		return -ENOMEM;

	num = 0;

	/* fill in slots (offsets) that are used */

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		if (!memb->slot)
			continue;

		if (memb->slot > array_size) {
			log_error(ls, "invalid slot number %d", memb->slot);
			kfree(array);
			return -1;
		}

		array[memb->slot - 1].nodeid = memb->nodeid;
		array[memb->slot - 1].slot = memb->slot;
		num++;
	}

	/* assign new slots from unused offsets */

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		if (memb->slot)
			continue;

		for (i = 0; i < array_size; i++) {
			if (array[i].nodeid)
				continue;

			memb->slot = i + 1;
			memb->slot_prev = memb->slot;
			array[i].nodeid = memb->nodeid;
			array[i].slot = memb->slot;
			num++;

			if (!ls->ls_slot && memb->nodeid == our_nodeid)
				ls->ls_slot = memb->slot;
			break;
		}

		if (!memb->slot) {
			log_error(ls, "no free slot found");
			kfree(array);
			return -1;
		}
	}

	gen++;

	log_slots(ls, gen, num, NULL, array, array_size);

	max_slots = (dlm_config.ci_buffer_size - sizeof(struct dlm_rcom) -
		     sizeof(struct rcom_config)) / sizeof(struct rcom_slot);

	if (num > max_slots) {
		log_error(ls, "num_slots %d exceeds max_slots %d",
			  num, max_slots);
		kfree(array);
		return -1;
	}

	*gen_out = gen;
	*slots_out = array;
	*slots_size = array_size;
	*num_slots = num;
	return 0;
}

static void add_ordered_member(struct dlm_ls *ls, struct dlm_member *new)
{
	struct dlm_member *memb = NULL;
	struct list_head *tmp;
	struct list_head *newlist = &new->list;
	struct list_head *head = &ls->ls_nodes;

	list_for_each(tmp, head) {
		memb = list_entry(tmp, struct dlm_member, list);
		if (new->nodeid < memb->nodeid)
			break;
	}

	if (!memb)
		list_add_tail(newlist, head);
	else {
		/* FIXME: can use list macro here */
		newlist->prev = tmp->prev;
		newlist->next = tmp;
		tmp->prev->next = newlist;
		tmp->prev = newlist;
	}
}

static int dlm_add_member(struct dlm_ls *ls, struct dlm_config_node *node)
{
	struct dlm_member *memb;
	int error;

	memb = kzalloc(sizeof(struct dlm_member), GFP_NOFS);
	if (!memb)
		return -ENOMEM;

	error = dlm_lowcomms_connect_node(node->nodeid);
	if (error < 0) {
		kfree(memb);
		return error;
	}

	memb->nodeid = node->nodeid;
	memb->weight = node->weight;
	memb->comm_seq = node->comm_seq;
	add_ordered_member(ls, memb);
	ls->ls_num_nodes++;
	return 0;
}

static struct dlm_member *find_memb(struct list_head *head, int nodeid)
{
	struct dlm_member *memb;

	list_for_each_entry(memb, head, list) {
		if (memb->nodeid == nodeid)
			return memb;
	}
	return NULL;
}

int dlm_is_member(struct dlm_ls *ls, int nodeid)
{
	if (find_memb(&ls->ls_nodes, nodeid))
		return 1;
	return 0;
}

int dlm_is_removed(struct dlm_ls *ls, int nodeid)
{
	if (find_memb(&ls->ls_nodes_gone, nodeid))
		return 1;
	return 0;
}

static void clear_memb_list(struct list_head *head)
{
	struct dlm_member *memb;

	while (!list_empty(head)) {
		memb = list_entry(head->next, struct dlm_member, list);
		list_del(&memb->list);
		kfree(memb);
	}
}

void dlm_clear_members(struct dlm_ls *ls)
{
	clear_memb_list(&ls->ls_nodes);
	ls->ls_num_nodes = 0;
}

void dlm_clear_members_gone(struct dlm_ls *ls)
{
	clear_memb_list(&ls->ls_nodes_gone);
}

static void make_member_array(struct dlm_ls *ls)
{
	struct dlm_member *memb;
	int i, w, x = 0, total = 0, all_zero = 0, *array;

	kfree(ls->ls_node_array);
	ls->ls_node_array = NULL;

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		if (memb->weight)
			total += memb->weight;
	}

	/* all nodes revert to weight of 1 if all have weight 0 */

	if (!total) {
		total = ls->ls_num_nodes;
		all_zero = 1;
	}

	ls->ls_total_weight = total;

	array = kmalloc(sizeof(int) * total, GFP_NOFS);
	if (!array)
		return;

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		if (!all_zero && !memb->weight)
			continue;

		if (all_zero)
			w = 1;
		else
			w = memb->weight;

		DLM_ASSERT(x < total, printk("total %d x %d\n", total, x););

		for (i = 0; i < w; i++)
			array[x++] = memb->nodeid;
	}

	ls->ls_node_array = array;
}

/* send a status request to all members just to establish comms connections */

static int ping_members(struct dlm_ls *ls)
{
	struct dlm_member *memb;
	int error = 0;

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		error = dlm_recovery_stopped(ls);
		if (error)
			break;
		error = dlm_rcom_status(ls, memb->nodeid, 0);
		if (error)
			break;
	}
	if (error)
		log_rinfo(ls, "ping_members aborted %d last nodeid %d",
			  error, ls->ls_recover_nodeid);
	return error;
}

static void dlm_lsop_recover_prep(struct dlm_ls *ls)
{
	if (!ls->ls_ops || !ls->ls_ops->recover_prep)
		return;
	ls->ls_ops->recover_prep(ls->ls_ops_arg);
}

static void dlm_lsop_recover_slot(struct dlm_ls *ls, struct dlm_member *memb)
{
	struct dlm_slot slot;
	uint32_t seq;
	int error;

	if (!ls->ls_ops || !ls->ls_ops->recover_slot)
		return;

	/* if there is no comms connection with this node
	   or the present comms connection is newer
	   than the one when this member was added, then
	   we consider the node to have failed (versus
	   being removed due to dlm_release_lockspace) */

	error = dlm_comm_seq(memb->nodeid, &seq);

	if (!error && seq == memb->comm_seq)
		return;

	slot.nodeid = memb->nodeid;
	slot.slot = memb->slot;

	ls->ls_ops->recover_slot(ls->ls_ops_arg, &slot);
}

void dlm_lsop_recover_done(struct dlm_ls *ls)
{
	struct dlm_member *memb;
	struct dlm_slot *slots;
	int i, num;

	if (!ls->ls_ops || !ls->ls_ops->recover_done)
		return;

	num = ls->ls_num_nodes;

	slots = kzalloc(num * sizeof(struct dlm_slot), GFP_KERNEL);
	if (!slots)
		return;

	i = 0;
	list_for_each_entry(memb, &ls->ls_nodes, list) {
		if (i == num) {
			log_error(ls, "dlm_lsop_recover_done bad num %d", num);
			goto out;
		}
		slots[i].nodeid = memb->nodeid;
		slots[i].slot = memb->slot;
		i++;
	}

	ls->ls_ops->recover_done(ls->ls_ops_arg, slots, num,
				 ls->ls_slot, ls->ls_generation);
 out:
	kfree(slots);
}

static struct dlm_config_node *find_config_node(struct dlm_recover *rv,
						int nodeid)
{
	int i;

	for (i = 0; i < rv->nodes_count; i++) {
		if (rv->nodes[i].nodeid == nodeid)
			return &rv->nodes[i];
	}
	return NULL;
}

int dlm_recover_members(struct dlm_ls *ls, struct dlm_recover *rv, int *neg_out)
{
	struct dlm_member *memb, *safe;
	struct dlm_config_node *node;
	int i, error, neg = 0, low = -1;

	/* previously removed members that we've not finished removing need to
	   count as a negative change so the "neg" recovery steps will happen */

	list_for_each_entry(memb, &ls->ls_nodes_gone, list) {
		log_rinfo(ls, "prev removed member %d", memb->nodeid);
		neg++;
	}

	/* move departed members from ls_nodes to ls_nodes_gone */

	list_for_each_entry_safe(memb, safe, &ls->ls_nodes, list) {
		node = find_config_node(rv, memb->nodeid);
		if (node && !node->new)
			continue;

		if (!node) {
			log_rinfo(ls, "remove member %d", memb->nodeid);
		} else {
			/* removed and re-added */
			log_rinfo(ls, "remove member %d comm_seq %u %u",
				  memb->nodeid, memb->comm_seq, node->comm_seq);
		}

		neg++;
		list_move(&memb->list, &ls->ls_nodes_gone);
		ls->ls_num_nodes--;
		dlm_lsop_recover_slot(ls, memb);
	}

	/* add new members to ls_nodes */

	for (i = 0; i < rv->nodes_count; i++) {
		node = &rv->nodes[i];
		if (dlm_is_member(ls, node->nodeid))
			continue;
		dlm_add_member(ls, node);
		log_rinfo(ls, "add member %d", node->nodeid);
	}

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		if (low == -1 || memb->nodeid < low)
			low = memb->nodeid;
	}
	ls->ls_low_nodeid = low;

	make_member_array(ls);
	*neg_out = neg;

	error = ping_members(ls);
	if (!error || error == -EPROTO) {
		/* new_lockspace() may be waiting to know if the config
		   is good or bad */
		ls->ls_members_result = error;
		complete(&ls->ls_members_done);
	}

	log_rinfo(ls, "dlm_recover_members %d nodes", ls->ls_num_nodes);
	return error;
}

/* Userspace guarantees that dlm_ls_stop() has completed on all nodes before
   dlm_ls_start() is called on any of them to start the new recovery. */

int dlm_ls_stop(struct dlm_ls *ls)
{
	int new;

	/*
	 * Prevent dlm_recv from being in the middle of something when we do
	 * the stop.  This includes ensuring dlm_recv isn't processing a
	 * recovery message (rcom), while dlm_recoverd is aborting and
	 * resetting things from an in-progress recovery.  i.e. we want
	 * dlm_recoverd to abort its recovery without worrying about dlm_recv
	 * processing an rcom at the same time.  Stopping dlm_recv also makes
	 * it easy for dlm_receive_message() to check locking stopped and add a
	 * message to the requestqueue without races.
	 */

	down_write(&ls->ls_recv_active);

	/*
	 * Abort any recovery that's in progress (see RECOVER_STOP,
	 * dlm_recovery_stopped()) and tell any other threads running in the
	 * dlm to quit any processing (see RUNNING, dlm_locking_stopped()).
	 */

	spin_lock(&ls->ls_recover_lock);
	set_bit(LSFL_RECOVER_STOP, &ls->ls_flags);
	new = test_and_clear_bit(LSFL_RUNNING, &ls->ls_flags);
	ls->ls_recover_seq++;
	spin_unlock(&ls->ls_recover_lock);

	/*
	 * Let dlm_recv run again, now any normal messages will be saved on the
	 * requestqueue for later.
	 */

	up_write(&ls->ls_recv_active);

	/*
	 * This in_recovery lock does two things:
	 * 1) Keeps this function from returning until all threads are out
	 *    of locking routines and locking is truly stopped.
	 * 2) Keeps any new requests from being processed until it's unlocked
	 *    when recovery is complete.
	 */

	if (new) {
		set_bit(LSFL_RECOVER_DOWN, &ls->ls_flags);
		wake_up_process(ls->ls_recoverd_task);
		wait_event(ls->ls_recover_lock_wait,
			   test_bit(LSFL_RECOVER_LOCK, &ls->ls_flags));
	}

	/*
	 * The recoverd suspend/resume makes sure that dlm_recoverd (if
	 * running) has noticed RECOVER_STOP above and quit processing the
	 * previous recovery.
	 */

	dlm_recoverd_suspend(ls);

	spin_lock(&ls->ls_recover_lock);
	kfree(ls->ls_slots);
	ls->ls_slots = NULL;
	ls->ls_num_slots = 0;
	ls->ls_slots_size = 0;
	ls->ls_recover_status = 0;
	spin_unlock(&ls->ls_recover_lock);

	dlm_recoverd_resume(ls);

	if (!ls->ls_recover_begin)
		ls->ls_recover_begin = jiffies;

	dlm_lsop_recover_prep(ls);
	return 0;
}

int dlm_ls_start(struct dlm_ls *ls)
{
	struct dlm_recover *rv = NULL, *rv_old;
	struct dlm_config_node *nodes;
	int error, count;

	rv = kzalloc(sizeof(struct dlm_recover), GFP_NOFS);
	if (!rv)
		return -ENOMEM;

	error = dlm_config_nodes(ls->ls_name, &nodes, &count);
	if (error < 0)
		goto fail;

	spin_lock(&ls->ls_recover_lock);

	/* the lockspace needs to be stopped before it can be started */

	if (!dlm_locking_stopped(ls)) {
		spin_unlock(&ls->ls_recover_lock);
		log_error(ls, "start ignored: lockspace running");
		error = -EINVAL;
		goto fail;
	}

	rv->nodes = nodes;
	rv->nodes_count = count;
	rv->seq = ++ls->ls_recover_seq;
	rv_old = ls->ls_recover_args;
	ls->ls_recover_args = rv;
	spin_unlock(&ls->ls_recover_lock);

	if (rv_old) {
		log_error(ls, "unused recovery %llx %d",
			  (unsigned long long)rv_old->seq, rv_old->nodes_count);
		kfree(rv_old->nodes);
		kfree(rv_old);
	}

	set_bit(LSFL_RECOVER_WORK, &ls->ls_flags);
	wake_up_process(ls->ls_recoverd_task);
	return 0;

 fail:
	kfree(rv);
	kfree(nodes);
	return error;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/member.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2007 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
// #include "config.h"
// #include "memory.h"

static struct kmem_cache *lkb_cache;
static struct kmem_cache *rsb_cache;


int __init dlm_memory_init(void)
{
	lkb_cache = kmem_cache_create("dlm_lkb", sizeof(struct dlm_lkb),
				__alignof__(struct dlm_lkb), 0, NULL);
	if (!lkb_cache)
		return -ENOMEM;

	rsb_cache = kmem_cache_create("dlm_rsb", sizeof(struct dlm_rsb),
				__alignof__(struct dlm_rsb), 0, NULL);
	if (!rsb_cache) {
		kmem_cache_destroy(lkb_cache);
		return -ENOMEM;
	}

	return 0;
}

void dlm_memory_exit(void)
{
	if (lkb_cache)
		kmem_cache_destroy(lkb_cache);
	if (rsb_cache)
		kmem_cache_destroy(rsb_cache);
}

char *dlm_allocate_lvb(struct dlm_ls *ls)
{
	char *p;

	p = kzalloc(ls->ls_lvblen, GFP_NOFS);
	return p;
}

void dlm_free_lvb(char *p)
{
	kfree(p);
}

struct dlm_rsb *dlm_allocate_rsb(struct dlm_ls *ls)
{
	struct dlm_rsb *r;

	r = kmem_cache_zalloc(rsb_cache, GFP_NOFS);
	return r;
}

void dlm_free_rsb(struct dlm_rsb *r)
{
	if (r->res_lvbptr)
		dlm_free_lvb(r->res_lvbptr);
	kmem_cache_free(rsb_cache, r);
}

struct dlm_lkb *dlm_allocate_lkb(struct dlm_ls *ls)
{
	struct dlm_lkb *lkb;

	lkb = kmem_cache_zalloc(lkb_cache, GFP_NOFS);
	return lkb;
}

void dlm_free_lkb(struct dlm_lkb *lkb)
{
	if (lkb->lkb_flags & DLM_IFL_USER) {
		struct dlm_user_args *ua;
		ua = lkb->lkb_ua;
		if (ua) {
			if (ua->lksb.sb_lvbptr)
				kfree(ua->lksb.sb_lvbptr);
			kfree(ua);
		}
	}
	kmem_cache_free(lkb_cache, lkb);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/memory.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

/*
 * midcomms.c
 *
 * This is the appallingly named "mid-level" comms layer.
 *
 * Its purpose is to take packets from the "real" comms layer,
 * split them up into packets and pass them to the interested
 * part of the locking mechanism.
 *
 * It also takes messages from the locking layer, formats them
 * into packets and sends them to the comms layer.
 */

// #include "dlm_internal.h"
// #include "lowcomms.h"
// #include "config.h"
// #include "lock.h"
#include "midcomms.h"
#include "../../inc/__fss.h"


static void copy_from_cb(void *dst, const void *base, unsigned offset,
			 unsigned len, unsigned limit)
{
	unsigned copy = len;

	if ((copy + offset) > limit)
		copy = limit - offset;
	memcpy(dst, base + offset, copy);
	len -= copy;
	if (len)
		memcpy(dst + copy, base, len);
}

/*
 * Called from the low-level comms layer to process a buffer of
 * commands.
 *
 * Only complete messages are processed here, any "spare" bytes from
 * the end of a buffer are saved and tacked onto the front of the next
 * message that comes in. I doubt this will happen very often but we
 * need to be able to cope with it and I don't want the task to be waiting
 * for packets to come in when there is useful work to be done.
 */

int dlm_process_incoming_buffer(int nodeid, const void *base,
				unsigned offset, unsigned len, unsigned limit)
{
	union {
		unsigned char __buf[DLM_INBUF_LEN];
		/* this is to force proper alignment on some arches */
		union dlm_packet p;
	} __tmp;
	union dlm_packet *p = &__tmp.p;
	int ret = 0;
	int err = 0;
	uint16_t msglen;
	uint32_t lockspace;

	while (len > sizeof(struct dlm_header)) {

		/* Copy just the header to check the total length.  The
		   message may wrap around the end of the buffer back to the
		   start, so we need to use a temp buffer and copy_from_cb. */

		copy_from_cb(p, base, offset, sizeof(struct dlm_header),
			     limit);

		msglen = le16_to_cpu(p->header.h_length);
		lockspace = p->header.h_lockspace;

		err = -EINVAL;
		if (msglen < sizeof(struct dlm_header))
			break;
		if (p->header.h_cmd == DLM_MSG) {
			if (msglen < sizeof(struct dlm_message))
				break;
		} else {
			if (msglen < sizeof(struct dlm_rcom))
				break;
		}
		err = -E2BIG;
		if (msglen > dlm_config.ci_buffer_size) {
			log_print("message size %d from %d too big, buf len %d",
				  msglen, nodeid, len);
			break;
		}
		err = 0;

		/* If only part of the full message is contained in this
		   buffer, then do nothing and wait for lowcomms to call
		   us again later with more data.  We return 0 meaning
		   we've consumed none of the input buffer. */

		if (msglen > len)
			break;

		/* Allocate a larger temp buffer if the full message won't fit
		   in the buffer on the stack (which should work for most
		   ordinary messages). */

		if (msglen > sizeof(__tmp) && p == &__tmp.p) {
			p = kmalloc(dlm_config.ci_buffer_size, GFP_NOFS);
			if (p == NULL)
				return ret;
		}

		copy_from_cb(p, base, offset, msglen, limit);

		BUG_ON(lockspace != p->header.h_lockspace);

		ret += msglen;
		offset += msglen;
		offset &= (limit - 1);
		len -= msglen;

		dlm_receive_buffer(p, nodeid);
	}

	if (p != &__tmp.p)
		kfree(p);

	return err ? err : ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/midcomms.c */
/************************************************************/
/*
 * Copyright (C) 2007 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#include <net/genetlink.h>
#include <linux/dlm.h>
#include <linux/dlm_netlink.h>
#include <linux/gfp.h>
#include "../../inc/__fss.h"

// #include "dlm_internal.h"

static uint32_t dlm_nl_seqnum;
static uint32_t listener_nlportid;

static struct genl_family family = {
	.id		= GENL_ID_GENERATE,
	.name		= DLM_GENL_NAME,
	.version	= DLM_GENL_VERSION,
};

static int prepare_data(u8 cmd, struct sk_buff **skbp, size_t size)
{
	struct sk_buff *skb;
	void *data;

	skb = genlmsg_new(size, GFP_NOFS);
	if (!skb)
		return -ENOMEM;

	/* add the message headers */
	data = genlmsg_put(skb, 0, dlm_nl_seqnum++, &family, 0, cmd);
	if (!data) {
		nlmsg_free(skb);
		return -EINVAL;
	}

	*skbp = skb;
	return 0;
}

static struct dlm_lock_data *mk_data(struct sk_buff *skb)
{
	struct nlattr *ret;

	ret = nla_reserve(skb, DLM_TYPE_LOCK, sizeof(struct dlm_lock_data));
	if (!ret)
		return NULL;
	return nla_data(ret);
}

static int send_data(struct sk_buff *skb)
{
	struct genlmsghdr *genlhdr = nlmsg_data((struct nlmsghdr *)skb->data);
	void *data = genlmsg_data(genlhdr);

	genlmsg_end(skb, data);

	return genlmsg_unicast(&init_net, skb, listener_nlportid);
}

static int user_cmd(struct sk_buff *skb, struct genl_info *info)
{
	listener_nlportid = info->snd_portid;
	printk("user_cmd nlpid %u\n", listener_nlportid);
	return 0;
}

static struct genl_ops dlm_nl_ops[] = {
	{
		.cmd	= DLM_CMD_HELLO,
		.doit	= user_cmd,
	},
};

int __init dlm_netlink_init(void)
{
	return genl_register_family_with_ops(&family, dlm_nl_ops);
}

void dlm_netlink_exit(void)
{
	genl_unregister_family(&family);
}

static void fill_data(struct dlm_lock_data *data, struct dlm_lkb *lkb)
{
	struct dlm_rsb *r = lkb->lkb_resource;

	memset(data, 0, sizeof(struct dlm_lock_data));

	data->version = DLM_LOCK_DATA_VERSION;
	data->nodeid = lkb->lkb_nodeid;
	data->ownpid = lkb->lkb_ownpid;
	data->id = lkb->lkb_id;
	data->remid = lkb->lkb_remid;
	data->status = lkb->lkb_status;
	data->grmode = lkb->lkb_grmode;
	data->rqmode = lkb->lkb_rqmode;
	if (lkb->lkb_ua)
		data->xid = lkb->lkb_ua->xid;
	if (r) {
		data->lockspace_id = r->res_ls->ls_global_id;
		data->resource_namelen = r->res_length;
		memcpy(data->resource_name, r->res_name, r->res_length);
	}
}

void dlm_timeout_warn(struct dlm_lkb *lkb)
{
	struct sk_buff *uninitialized_var(send_skb);
	struct dlm_lock_data *data;
	size_t size;
	int rv;

	size = nla_total_size(sizeof(struct dlm_lock_data)) +
	       nla_total_size(0); /* why this? */

	rv = prepare_data(DLM_CMD_TIMEOUT, &send_skb, size);
	if (rv < 0)
		return;

	data = mk_data(send_skb);
	if (!data) {
		nlmsg_free(send_skb);
		return;
	}

	fill_data(data, lkb);

	send_data(send_skb);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/netlink.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2009 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

/*
 * lowcomms.c
 *
 * This is the "low-level" comms layer.
 *
 * It is responsible for sending/receiving messages
 * from other nodes in the cluster.
 *
 * Cluster nodes are referred to by their nodeids. nodeids are
 * simply 32 bit numbers to the locking module - if they need to
 * be expanded for the cluster infrastructure then that is its
 * responsibility. It is this layer's
 * responsibility to resolve these into IP address or
 * whatever it needs for inter-node communication.
 *
 * The comms level is two kernel threads that deal mainly with
 * the receiving of messages from other nodes and passing them
 * up to the mid-level comms layer (which understands the
 * message format) for execution by the locking core, and
 * a send thread which does all the setting up of connections
 * to remote nodes and the sending of data. Threads are not allowed
 * to send their own data because it may cause them to wait in times
 * of high load. Also, this way, the sending thread can collect together
 * messages bound for one node and send them in one block.
 *
 * lowcomms will choose to use either TCP or SCTP as its transport layer
 * depending on the configuration variable 'protocol'. This should be set
 * to 0 (default) for TCP or 1 for SCTP. It should be configured using a
 * cluster-wide mechanism as it must be the same on all nodes of the cluster
 * for the DLM to function.
 *
 */

#include <asm/ioctls.h>
// #include <net/sock.h>
#include <net/tcp.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/sctp.h>
// #include <linux/slab.h>
#include <net/sctp/sctp.h>
// #include <net/ipv6.h>
#include "../../inc/__fss.h"

// #include "dlm_internal.h"
// #include "lowcomms.h"
// #include "midcomms.h"
// #include "config.h"

#define NEEDED_RMEM (4*1024*1024)
#define CONN_HASH_SIZE 32

/* Number of messages to send before rescheduling */
#define MAX_SEND_MSG_COUNT 25

struct cbuf {
	unsigned int base;
	unsigned int len;
	unsigned int mask;
};

static void cbuf_add(struct cbuf *cb, int n)
{
	cb->len += n;
}

static int cbuf_data(struct cbuf *cb)
{
	return ((cb->base + cb->len) & cb->mask);
}

static void cbuf_init(struct cbuf *cb, int size)
{
	cb->base = cb->len = 0;
	cb->mask = size-1;
}

static void cbuf_eat(struct cbuf *cb, int n)
{
	cb->len  -= n;
	cb->base += n;
	cb->base &= cb->mask;
}

static bool cbuf_empty(struct cbuf *cb)
{
	return cb->len == 0;
}

struct connection {
	struct socket *sock;	/* NULL if not connected */
	uint32_t nodeid;	/* So we know who we are in the list */
	struct mutex sock_mutex;
	unsigned long flags;
#define CF_READ_PENDING 1
#define CF_WRITE_PENDING 2
#define CF_CONNECT_PENDING 3
#define CF_INIT_PENDING 4
#define CF_IS_OTHERCON 5
#define CF_CLOSE 6
#define CF_APP_LIMITED 7
	struct list_head writequeue;  /* List of outgoing writequeue_entries */
	spinlock_t writequeue_lock;
	int (*rx_action) (struct connection *);	/* What to do when active */
	void (*connect_action) (struct connection *);	/* What to do to connect */
	struct page *rx_page;
	struct cbuf cb;
	int retries;
#define MAX_CONNECT_RETRIES 3
	int sctp_assoc;
	struct hlist_node list;
	struct connection *othercon;
	struct work_struct rwork; /* Receive workqueue */
	struct work_struct swork; /* Send workqueue */
	bool try_new_addr;
};
#define sock2con(x) ((struct connection *)(x)->sk_user_data)

/* An entry waiting to be sent */
struct writequeue_entry {
	struct list_head list;
	struct page *page;
	int offset;
	int len;
	int end;
	int users;
	struct connection *con;
};

struct dlm_node_addr {
	struct list_head list;
	int nodeid;
	int addr_count;
	int curr_addr_index;
	struct sockaddr_storage *addr[DLM_MAX_ADDR_COUNT];
};

static LIST_HEAD(dlm_node_addrs);
static DEFINE_SPINLOCK(dlm_node_addrs_spin);

static struct sockaddr_storage *dlm_local_addr[DLM_MAX_ADDR_COUNT];
static int dlm_local_count;
static int dlm_allow_conn;

/* Work queues */
static struct workqueue_struct *recv_workqueue;
static struct workqueue_struct *send_workqueue;

static struct hlist_head connection_hash[CONN_HASH_SIZE];
static DEFINE_MUTEX(connections_lock);
static struct kmem_cache *con_cache;

static void process_recv_sockets(struct work_struct *work);
static void process_send_sockets(struct work_struct *work);


/* This is deliberately very simple because most clusters have simple
   sequential nodeids, so we should be able to go straight to a connection
   struct in the array */
static inline int nodeid_hash(int nodeid)
{
	return nodeid & (CONN_HASH_SIZE-1);
}

static struct connection *__find_con(int nodeid)
{
	int r;
	struct connection *con;

	r = nodeid_hash(nodeid);

	hlist_for_each_entry(con, &connection_hash[r], list) {
		if (con->nodeid == nodeid)
			return con;
	}
	return NULL;
}

/*
 * If 'allocation' is zero then we don't attempt to create a new
 * connection structure for this node.
 */
static struct connection *__nodeid2con(int nodeid, gfp_t alloc)
{
	struct connection *con = NULL;
	int r;

	con = __find_con(nodeid);
	if (con || !alloc)
		return con;

	con = kmem_cache_zalloc(con_cache, alloc);
	if (!con)
		return NULL;

	r = nodeid_hash(nodeid);
	hlist_add_head(&con->list, &connection_hash[r]);

	con->nodeid = nodeid;
	mutex_init(&con->sock_mutex);
	INIT_LIST_HEAD(&con->writequeue);
	spin_lock_init(&con->writequeue_lock);
	INIT_WORK(&con->swork, process_send_sockets);
	INIT_WORK(&con->rwork, process_recv_sockets);

	/* Setup action pointers for child sockets */
	if (con->nodeid) {
		struct connection *zerocon = __find_con(0);

		con->connect_action = zerocon->connect_action;
		if (!con->rx_action)
			con->rx_action = zerocon->rx_action;
	}

	return con;
}

/* Loop round all connections */
static void foreach_conn(void (*conn_func)(struct connection *c))
{
	int i;
	struct hlist_node *n;
	struct connection *con;

	for (i = 0; i < CONN_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(con, n, &connection_hash[i], list)
			conn_func(con);
	}
}

static struct connection *nodeid2con(int nodeid, gfp_t allocation)
{
	struct connection *con;

	mutex_lock(&connections_lock);
	con = __nodeid2con(nodeid, allocation);
	mutex_unlock(&connections_lock);

	return con;
}

/* This is a bit drastic, but only called when things go wrong */
static struct connection *assoc2con(int assoc_id)
{
	int i;
	struct connection *con;

	mutex_lock(&connections_lock);

	for (i = 0 ; i < CONN_HASH_SIZE; i++) {
		hlist_for_each_entry(con, &connection_hash[i], list) {
			if (con->sctp_assoc == assoc_id) {
				mutex_unlock(&connections_lock);
				return con;
			}
		}
	}
	mutex_unlock(&connections_lock);
	return NULL;
}

static struct dlm_node_addr *find_node_addr(int nodeid)
{
	struct dlm_node_addr *na;

	list_for_each_entry(na, &dlm_node_addrs, list) {
		if (na->nodeid == nodeid)
			return na;
	}
	return NULL;
}

static int addr_compare(struct sockaddr_storage *x, struct sockaddr_storage *y)
{
	switch (x->ss_family) {
	case AF_INET: {
		struct sockaddr_in *sinx = (struct sockaddr_in *)x;
		struct sockaddr_in *siny = (struct sockaddr_in *)y;
		if (sinx->sin_addr.s_addr != siny->sin_addr.s_addr)
			return 0;
		if (sinx->sin_port != siny->sin_port)
			return 0;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sinx = (struct sockaddr_in6 *)x;
		struct sockaddr_in6 *siny = (struct sockaddr_in6 *)y;
		if (!ipv6_addr_equal(&sinx->sin6_addr, &siny->sin6_addr))
			return 0;
		if (sinx->sin6_port != siny->sin6_port)
			return 0;
		break;
	}
	default:
		return 0;
	}
	return 1;
}

static int nodeid_to_addr(int nodeid, struct sockaddr_storage *sas_out,
			  struct sockaddr *sa_out, bool try_new_addr)
{
	struct sockaddr_storage sas;
	struct dlm_node_addr *na;

	if (!dlm_local_count)
		return -1;

	spin_lock(&dlm_node_addrs_spin);
	na = find_node_addr(nodeid);
	if (na && na->addr_count) {
		if (try_new_addr) {
			na->curr_addr_index++;
			if (na->curr_addr_index == na->addr_count)
				na->curr_addr_index = 0;
		}

		memcpy(&sas, na->addr[na->curr_addr_index ],
			sizeof(struct sockaddr_storage));
	}
	spin_unlock(&dlm_node_addrs_spin);

	if (!na)
		return -EEXIST;

	if (!na->addr_count)
		return -ENOENT;

	if (sas_out)
		memcpy(sas_out, &sas, sizeof(struct sockaddr_storage));

	if (!sa_out)
		return 0;

	if (dlm_local_addr[0]->ss_family == AF_INET) {
		struct sockaddr_in *in4  = (struct sockaddr_in *) &sas;
		struct sockaddr_in *ret4 = (struct sockaddr_in *) sa_out;
		ret4->sin_addr.s_addr = in4->sin_addr.s_addr;
	} else {
		struct sockaddr_in6 *in6  = (struct sockaddr_in6 *) &sas;
		struct sockaddr_in6 *ret6 = (struct sockaddr_in6 *) sa_out;
		ret6->sin6_addr = in6->sin6_addr;
	}

	return 0;
}

static int addr_to_nodeid(struct sockaddr_storage *addr, int *nodeid)
{
	struct dlm_node_addr *na;
	int rv = -EEXIST;
	int addr_i;

	spin_lock(&dlm_node_addrs_spin);
	list_for_each_entry(na, &dlm_node_addrs, list) {
		if (!na->addr_count)
			continue;

		for (addr_i = 0; addr_i < na->addr_count; addr_i++) {
			if (addr_compare(na->addr[addr_i], addr)) {
				*nodeid = na->nodeid;
				rv = 0;
				goto unlock;
			}
		}
	}
unlock:
	spin_unlock(&dlm_node_addrs_spin);
	return rv;
}

int dlm_lowcomms_addr(int nodeid, struct sockaddr_storage *addr, int len)
{
	struct sockaddr_storage *new_addr;
	struct dlm_node_addr *new_node, *na;

	new_node = kzalloc(sizeof(struct dlm_node_addr), GFP_NOFS);
	if (!new_node)
		return -ENOMEM;

	new_addr = kzalloc(sizeof(struct sockaddr_storage), GFP_NOFS);
	if (!new_addr) {
		kfree(new_node);
		return -ENOMEM;
	}

	memcpy(new_addr, addr, len);

	spin_lock(&dlm_node_addrs_spin);
	na = find_node_addr(nodeid);
	if (!na) {
		new_node->nodeid = nodeid;
		new_node->addr[0] = new_addr;
		new_node->addr_count = 1;
		list_add(&new_node->list, &dlm_node_addrs);
		spin_unlock(&dlm_node_addrs_spin);
		return 0;
	}

	if (na->addr_count >= DLM_MAX_ADDR_COUNT) {
		spin_unlock(&dlm_node_addrs_spin);
		kfree(new_addr);
		kfree(new_node);
		return -ENOSPC;
	}

	na->addr[na->addr_count++] = new_addr;
	spin_unlock(&dlm_node_addrs_spin);
	kfree(new_node);
	return 0;
}

/* Data available on socket or listen socket received a connect */
static void lowcomms_data_ready(struct sock *sk)
{
	struct connection *con = sock2con(sk);
	if (con && !test_and_set_bit(CF_READ_PENDING, &con->flags))
		queue_work(recv_workqueue, &con->rwork);
}

static void lowcomms_write_space(struct sock *sk)
{
	struct connection *con = sock2con(sk);

	if (!con)
		return;

	clear_bit(SOCK_NOSPACE, &con->sock->flags);

	if (test_and_clear_bit(CF_APP_LIMITED, &con->flags)) {
		con->sock->sk->sk_write_pending--;
		clear_bit(SOCK_ASYNC_NOSPACE, &con->sock->flags);
	}

	if (!test_and_set_bit(CF_WRITE_PENDING, &con->flags))
		queue_work(send_workqueue, &con->swork);
}

static inline void lowcomms_connect_sock(struct connection *con)
{
	if (test_bit(CF_CLOSE, &con->flags))
		return;
	if (!test_and_set_bit(CF_CONNECT_PENDING, &con->flags))
		queue_work(send_workqueue, &con->swork);
}

static void lowcomms_state_change(struct sock *sk)
{
	if (sk->sk_state == TCP_ESTABLISHED)
		lowcomms_write_space(sk);
}

int dlm_lowcomms_connect_node(int nodeid)
{
	struct connection *con;

	/* with sctp there's no connecting without sending */
	if (dlm_config.ci_protocol != 0)
		return 0;

	if (nodeid == dlm_our_nodeid())
		return 0;

	con = nodeid2con(nodeid, GFP_NOFS);
	if (!con)
		return -ENOMEM;
	lowcomms_connect_sock(con);
	return 0;
}

/* Make a socket active */
static void add_sock(struct socket *sock, struct connection *con)
{
	con->sock = sock;

	/* Install a data_ready callback */
	con->sock->sk->sk_data_ready = lowcomms_data_ready;
	con->sock->sk->sk_write_space = lowcomms_write_space;
	con->sock->sk->sk_state_change = lowcomms_state_change;
	con->sock->sk->sk_user_data = con;
	con->sock->sk->sk_allocation = GFP_NOFS;
}

/* Add the port number to an IPv6 or 4 sockaddr and return the address
   length */
static void make_sockaddr(struct sockaddr_storage *saddr, uint16_t port,
			  int *addr_len)
{
	saddr->ss_family =  dlm_local_addr[0]->ss_family;
	if (saddr->ss_family == AF_INET) {
		struct sockaddr_in *in4_addr = (struct sockaddr_in *)saddr;
		in4_addr->sin_port = cpu_to_be16(port);
		*addr_len = sizeof(struct sockaddr_in);
		memset(&in4_addr->sin_zero, 0, sizeof(in4_addr->sin_zero));
	} else {
		struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)saddr;
		in6_addr->sin6_port = cpu_to_be16(port);
		*addr_len = sizeof(struct sockaddr_in6);
	}
	memset((char *)saddr + *addr_len, 0, sizeof(struct sockaddr_storage) - *addr_len);
}

/* Close a remote connection and tidy up */
static void close_connection(struct connection *con, bool and_other)
{
	mutex_lock(&con->sock_mutex);

	if (con->sock) {
		sock_release(con->sock);
		con->sock = NULL;
	}
	if (con->othercon && and_other) {
		/* Will only re-enter once. */
		close_connection(con->othercon, false);
	}
	if (con->rx_page) {
		__free_page(con->rx_page);
		con->rx_page = NULL;
	}

	con->retries = 0;
	mutex_unlock(&con->sock_mutex);
}

/* We only send shutdown messages to nodes that are not part of the cluster */
static void sctp_send_shutdown(sctp_assoc_t associd)
{
	static char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct msghdr outmessage;
	struct cmsghdr *cmsg;
	struct sctp_sndrcvinfo *sinfo;
	int ret;
	struct connection *con;

	con = nodeid2con(0,0);
	BUG_ON(con == NULL);

	outmessage.msg_name = NULL;
	outmessage.msg_namelen = 0;
	outmessage.msg_control = outcmsg;
	outmessage.msg_controllen = sizeof(outcmsg);
	outmessage.msg_flags = MSG_EOR;

	cmsg = CMSG_FIRSTHDR(&outmessage);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
	outmessage.msg_controllen = cmsg->cmsg_len;
	sinfo = CMSG_DATA(cmsg);
	memset(sinfo, 0x00, sizeof(struct sctp_sndrcvinfo));

	sinfo->sinfo_flags |= MSG_EOF;
	sinfo->sinfo_assoc_id = associd;

	ret = kernel_sendmsg(con->sock, &outmessage, NULL, 0, 0);

	if (ret != 0)
		log_print("send EOF to node failed: %d", ret);
}

static void sctp_init_failed_foreach(struct connection *con)
{

	/*
	 * Don't try to recover base con and handle race where the
	 * other node's assoc init creates a assoc and we get that
	 * notification, then we get a notification that our attempt
	 * failed due. This happens when we are still trying the primary
	 * address, but the other node has already tried secondary addrs
	 * and found one that worked.
	 */
	if (!con->nodeid || con->sctp_assoc)
		return;

	log_print("Retrying SCTP association init for node %d\n", con->nodeid);

	con->try_new_addr = true;
	con->sctp_assoc = 0;
	if (test_and_clear_bit(CF_INIT_PENDING, &con->flags)) {
		if (!test_and_set_bit(CF_WRITE_PENDING, &con->flags))
			queue_work(send_workqueue, &con->swork);
	}
}

/* INIT failed but we don't know which node...
   restart INIT on all pending nodes */
static void sctp_init_failed(void)
{
	mutex_lock(&connections_lock);

	foreach_conn(sctp_init_failed_foreach);

	mutex_unlock(&connections_lock);
}

static void retry_failed_sctp_send(struct connection *recv_con,
				   struct sctp_send_failed *sn_send_failed,
				   char *buf)
{
	int len = sn_send_failed->ssf_length - sizeof(struct sctp_send_failed);
	struct dlm_mhandle *mh;
	struct connection *con;
	char *retry_buf;
	int nodeid = sn_send_failed->ssf_info.sinfo_ppid;

	log_print("Retry sending %d bytes to node id %d", len, nodeid);
	
	if (!nodeid) {
		log_print("Shouldn't resend data via listening connection.");
		return;
	}

	con = nodeid2con(nodeid, 0);
	if (!con) {
		log_print("Could not look up con for nodeid %d\n",
			  nodeid);
		return;
	}

	mh = dlm_lowcomms_get_buffer(nodeid, len, GFP_NOFS, &retry_buf);
	if (!mh) {
		log_print("Could not allocate buf for retry.");
		return;
	}
	memcpy(retry_buf, buf + sizeof(struct sctp_send_failed), len);
	dlm_lowcomms_commit_buffer(mh);

	/*
	 * If we got a assoc changed event before the send failed event then
	 * we only need to retry the send.
	 */
	if (con->sctp_assoc) {
		if (!test_and_set_bit(CF_WRITE_PENDING, &con->flags))
			queue_work(send_workqueue, &con->swork);
	} else
		sctp_init_failed_foreach(con);
}

/* Something happened to an association */
static void process_sctp_notification(struct connection *con,
				      struct msghdr *msg, char *buf)
{
	union sctp_notification *sn = (union sctp_notification *)buf;
	struct linger linger;

	switch (sn->sn_header.sn_type) {
	case SCTP_SEND_FAILED:
		retry_failed_sctp_send(con, &sn->sn_send_failed, buf);
		break;
	case SCTP_ASSOC_CHANGE:
		switch (sn->sn_assoc_change.sac_state) {
		case SCTP_COMM_UP:
		case SCTP_RESTART:
		{
			/* Check that the new node is in the lockspace */
			struct sctp_prim prim;
			int nodeid;
			int prim_len, ret;
			int addr_len;
			struct connection *new_con;

			/*
			 * We get this before any data for an association.
			 * We verify that the node is in the cluster and
			 * then peel off a socket for it.
			 */
			if ((int)sn->sn_assoc_change.sac_assoc_id <= 0) {
				log_print("COMM_UP for invalid assoc ID %d",
					 (int)sn->sn_assoc_change.sac_assoc_id);
				sctp_init_failed();
				return;
			}
			memset(&prim, 0, sizeof(struct sctp_prim));
			prim_len = sizeof(struct sctp_prim);
			prim.ssp_assoc_id = sn->sn_assoc_change.sac_assoc_id;

			ret = kernel_getsockopt(con->sock,
						IPPROTO_SCTP,
						SCTP_PRIMARY_ADDR,
						(char*)&prim,
						&prim_len);
			if (ret < 0) {
				log_print("getsockopt/sctp_primary_addr on "
					  "new assoc %d failed : %d",
					  (int)sn->sn_assoc_change.sac_assoc_id,
					  ret);

				/* Retry INIT later */
				new_con = assoc2con(sn->sn_assoc_change.sac_assoc_id);
				if (new_con)
					clear_bit(CF_CONNECT_PENDING, &con->flags);
				return;
			}
			make_sockaddr(&prim.ssp_addr, 0, &addr_len);
			if (addr_to_nodeid(&prim.ssp_addr, &nodeid)) {
				unsigned char *b=(unsigned char *)&prim.ssp_addr;
				log_print("reject connect from unknown addr");
				print_hex_dump_bytes("ss: ", DUMP_PREFIX_NONE, 
						     b, sizeof(struct sockaddr_storage));
				sctp_send_shutdown(prim.ssp_assoc_id);
				return;
			}

			new_con = nodeid2con(nodeid, GFP_NOFS);
			if (!new_con)
				return;

			/* Peel off a new sock */
			lock_sock(con->sock->sk);
			ret = sctp_do_peeloff(con->sock->sk,
				sn->sn_assoc_change.sac_assoc_id,
				&new_con->sock);
			release_sock(con->sock->sk);
			if (ret < 0) {
				log_print("Can't peel off a socket for "
					  "connection %d to node %d: err=%d",
					  (int)sn->sn_assoc_change.sac_assoc_id,
					  nodeid, ret);
				return;
			}
			add_sock(new_con->sock, new_con);

			linger.l_onoff = 1;
			linger.l_linger = 0;
			ret = kernel_setsockopt(new_con->sock, SOL_SOCKET, SO_LINGER,
						(char *)&linger, sizeof(linger));
			if (ret < 0)
				log_print("set socket option SO_LINGER failed");

			log_print("connecting to %d sctp association %d",
				 nodeid, (int)sn->sn_assoc_change.sac_assoc_id);

			new_con->sctp_assoc = sn->sn_assoc_change.sac_assoc_id;
			new_con->try_new_addr = false;
			/* Send any pending writes */
			clear_bit(CF_CONNECT_PENDING, &new_con->flags);
			clear_bit(CF_INIT_PENDING, &new_con->flags);
			if (!test_and_set_bit(CF_WRITE_PENDING, &new_con->flags)) {
				queue_work(send_workqueue, &new_con->swork);
			}
			if (!test_and_set_bit(CF_READ_PENDING, &new_con->flags))
				queue_work(recv_workqueue, &new_con->rwork);
		}
		break;

		case SCTP_COMM_LOST:
		case SCTP_SHUTDOWN_COMP:
		{
			con = assoc2con(sn->sn_assoc_change.sac_assoc_id);
			if (con) {
				con->sctp_assoc = 0;
			}
		}
		break;

		case SCTP_CANT_STR_ASSOC:
		{
			/* Will retry init when we get the send failed notification */
			log_print("Can't start SCTP association - retrying");
		}
		break;

		default:
			log_print("unexpected SCTP assoc change id=%d state=%d",
				  (int)sn->sn_assoc_change.sac_assoc_id,
				  sn->sn_assoc_change.sac_state);
		}
	default:
		; /* fall through */
	}
}

/* Data received from remote end */
static int receive_from_sock(struct connection *con)
{
	int ret = 0;
	struct msghdr msg = {};
	struct kvec iov[2];
	unsigned len;
	int r;
	int call_again_soon = 0;
	int nvec;
	char incmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];

	mutex_lock(&con->sock_mutex);

	if (con->sock == NULL) {
		ret = -EAGAIN;
		goto out_close;
	}

	if (con->rx_page == NULL) {
		/*
		 * This doesn't need to be atomic, but I think it should
		 * improve performance if it is.
		 */
		con->rx_page = alloc_page(GFP_ATOMIC);
		if (con->rx_page == NULL)
			goto out_resched;
		cbuf_init(&con->cb, PAGE_CACHE_SIZE);
	}

	/* Only SCTP needs these really */
	memset(&incmsg, 0, sizeof(incmsg));
	msg.msg_control = incmsg;
	msg.msg_controllen = sizeof(incmsg);

	/*
	 * iov[0] is the bit of the circular buffer between the current end
	 * point (cb.base + cb.len) and the end of the buffer.
	 */
	iov[0].iov_len = con->cb.base - cbuf_data(&con->cb);
	iov[0].iov_base = page_address(con->rx_page) + cbuf_data(&con->cb);
	iov[1].iov_len = 0;
	nvec = 1;

	/*
	 * iov[1] is the bit of the circular buffer between the start of the
	 * buffer and the start of the currently used section (cb.base)
	 */
	if (cbuf_data(&con->cb) >= con->cb.base) {
		iov[0].iov_len = PAGE_CACHE_SIZE - cbuf_data(&con->cb);
		iov[1].iov_len = con->cb.base;
		iov[1].iov_base = page_address(con->rx_page);
		nvec = 2;
	}
	len = iov[0].iov_len + iov[1].iov_len;

	r = ret = kernel_recvmsg(con->sock, &msg, iov, nvec, len,
			       MSG_DONTWAIT | MSG_NOSIGNAL);
	if (ret <= 0)
		goto out_close;

	/* Process SCTP notifications */
	if (msg.msg_flags & MSG_NOTIFICATION) {
		msg.msg_control = incmsg;
		msg.msg_controllen = sizeof(incmsg);

		process_sctp_notification(con, &msg,
				page_address(con->rx_page) + con->cb.base);
		mutex_unlock(&con->sock_mutex);
		return 0;
	}
	BUG_ON(con->nodeid == 0);

	if (ret == len)
		call_again_soon = 1;
	cbuf_add(&con->cb, ret);
	ret = dlm_process_incoming_buffer(con->nodeid,
					  page_address(con->rx_page),
					  con->cb.base, con->cb.len,
					  PAGE_CACHE_SIZE);
	if (ret == -EBADMSG) {
		log_print("lowcomms: addr=%p, base=%u, len=%u, "
			  "iov_len=%u, iov_base[0]=%p, read=%d",
			  page_address(con->rx_page), con->cb.base, con->cb.len,
			  len, iov[0].iov_base, r);
	}
	if (ret < 0)
		goto out_close;
	cbuf_eat(&con->cb, ret);

	if (cbuf_empty(&con->cb) && !call_again_soon) {
		__free_page(con->rx_page);
		con->rx_page = NULL;
	}

	if (call_again_soon)
		goto out_resched;
	mutex_unlock(&con->sock_mutex);
	return 0;

out_resched:
	if (!test_and_set_bit(CF_READ_PENDING, &con->flags))
		queue_work(recv_workqueue, &con->rwork);
	mutex_unlock(&con->sock_mutex);
	return -EAGAIN;

out_close:
	mutex_unlock(&con->sock_mutex);
	if (ret != -EAGAIN) {
		close_connection(con, false);
		/* Reconnect when there is something to send */
	}
	/* Don't return success if we really got EOF */
	if (ret == 0)
		ret = -EAGAIN;

	return ret;
}

/* Listening socket is busy, accept a connection */
static int tcp_accept_from_sock(struct connection *con)
{
	int result;
	struct sockaddr_storage peeraddr;
	struct socket *newsock;
	int len;
	int nodeid;
	struct connection *newcon;
	struct connection *addcon;

	mutex_lock(&connections_lock);
	if (!dlm_allow_conn) {
		mutex_unlock(&connections_lock);
		return -1;
	}
	mutex_unlock(&connections_lock);

	memset(&peeraddr, 0, sizeof(peeraddr));
	result = sock_create_kern(dlm_local_addr[0]->ss_family, SOCK_STREAM,
				  IPPROTO_TCP, &newsock);
	if (result < 0)
		return -ENOMEM;

	mutex_lock_nested(&con->sock_mutex, 0);

	result = -ENOTCONN;
	if (con->sock == NULL)
		goto accept_err;

	newsock->type = con->sock->type;
	newsock->ops = con->sock->ops;

	result = con->sock->ops->accept(con->sock, newsock, O_NONBLOCK);
	if (result < 0)
		goto accept_err;

	/* Get the connected socket's peer */
	memset(&peeraddr, 0, sizeof(peeraddr));
	if (newsock->ops->getname(newsock, (struct sockaddr *)&peeraddr,
				  &len, 2)) {
		result = -ECONNABORTED;
		goto accept_err;
	}

	/* Get the new node's NODEID */
	make_sockaddr(&peeraddr, 0, &len);
	if (addr_to_nodeid(&peeraddr, &nodeid)) {
		unsigned char *b=(unsigned char *)&peeraddr;
		log_print("connect from non cluster node");
		print_hex_dump_bytes("ss: ", DUMP_PREFIX_NONE, 
				     b, sizeof(struct sockaddr_storage));
		sock_release(newsock);
		mutex_unlock(&con->sock_mutex);
		return -1;
	}

	log_print("got connection from %d", nodeid);

	/*  Check to see if we already have a connection to this node. This
	 *  could happen if the two nodes initiate a connection at roughly
	 *  the same time and the connections cross on the wire.
	 *  In this case we store the incoming one in "othercon"
	 */
	newcon = nodeid2con(nodeid, GFP_NOFS);
	if (!newcon) {
		result = -ENOMEM;
		goto accept_err;
	}
	mutex_lock_nested(&newcon->sock_mutex, 1);
	if (newcon->sock) {
		struct connection *othercon = newcon->othercon;

		if (!othercon) {
			othercon = kmem_cache_zalloc(con_cache, GFP_NOFS);
			if (!othercon) {
				log_print("failed to allocate incoming socket");
				mutex_unlock(&newcon->sock_mutex);
				result = -ENOMEM;
				goto accept_err;
			}
			othercon->nodeid = nodeid;
			othercon->rx_action = receive_from_sock;
			mutex_init(&othercon->sock_mutex);
			INIT_WORK(&othercon->swork, process_send_sockets);
			INIT_WORK(&othercon->rwork, process_recv_sockets);
			set_bit(CF_IS_OTHERCON, &othercon->flags);
		}
		if (!othercon->sock) {
			newcon->othercon = othercon;
			othercon->sock = newsock;
			newsock->sk->sk_user_data = othercon;
			add_sock(newsock, othercon);
			addcon = othercon;
		}
		else {
			printk("Extra connection from node %d attempted\n", nodeid);
			result = -EAGAIN;
			mutex_unlock(&newcon->sock_mutex);
			goto accept_err;
		}
	}
	else {
		newsock->sk->sk_user_data = newcon;
		newcon->rx_action = receive_from_sock;
		add_sock(newsock, newcon);
		addcon = newcon;
	}

	mutex_unlock(&newcon->sock_mutex);

	/*
	 * Add it to the active queue in case we got data
	 * between processing the accept adding the socket
	 * to the read_sockets list
	 */
	if (!test_and_set_bit(CF_READ_PENDING, &addcon->flags))
		queue_work(recv_workqueue, &addcon->rwork);
	mutex_unlock(&con->sock_mutex);

	return 0;

accept_err:
	mutex_unlock(&con->sock_mutex);
	sock_release(newsock);

	if (result != -EAGAIN)
		log_print("error accepting connection from node: %d", result);
	return result;
}

static void free_entry(struct writequeue_entry *e)
{
	__free_page(e->page);
	kfree(e);
}

/*
 * writequeue_entry_complete - try to delete and free write queue entry
 * @e: write queue entry to try to delete
 * @completed: bytes completed
 *
 * writequeue_lock must be held.
 */
static void writequeue_entry_complete(struct writequeue_entry *e, int completed)
{
	e->offset += completed;
	e->len -= completed;

	if (e->len == 0 && e->users == 0) {
		list_del(&e->list);
		free_entry(e);
	}
}

/* Initiate an SCTP association.
   This is a special case of send_to_sock() in that we don't yet have a
   peeled-off socket for this association, so we use the listening socket
   and add the primary IP address of the remote node.
 */
static void sctp_init_assoc(struct connection *con)
{
	struct sockaddr_storage rem_addr;
	char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct msghdr outmessage;
	struct cmsghdr *cmsg;
	struct sctp_sndrcvinfo *sinfo;
	struct connection *base_con;
	struct writequeue_entry *e;
	int len, offset;
	int ret;
	int addrlen;
	struct kvec iov[1];

	mutex_lock(&con->sock_mutex);
	if (test_and_set_bit(CF_INIT_PENDING, &con->flags))
		goto unlock;

	if (nodeid_to_addr(con->nodeid, NULL, (struct sockaddr *)&rem_addr,
			   con->try_new_addr)) {
		log_print("no address for nodeid %d", con->nodeid);
		goto unlock;
	}
	base_con = nodeid2con(0, 0);
	BUG_ON(base_con == NULL);

	make_sockaddr(&rem_addr, dlm_config.ci_tcp_port, &addrlen);

	outmessage.msg_name = &rem_addr;
	outmessage.msg_namelen = addrlen;
	outmessage.msg_control = outcmsg;
	outmessage.msg_controllen = sizeof(outcmsg);
	outmessage.msg_flags = MSG_EOR;

	spin_lock(&con->writequeue_lock);

	if (list_empty(&con->writequeue)) {
		spin_unlock(&con->writequeue_lock);
		log_print("writequeue empty for nodeid %d", con->nodeid);
		goto unlock;
	}

	e = list_first_entry(&con->writequeue, struct writequeue_entry, list);
	len = e->len;
	offset = e->offset;

	/* Send the first block off the write queue */
	iov[0].iov_base = page_address(e->page)+offset;
	iov[0].iov_len = len;
	spin_unlock(&con->writequeue_lock);

	if (rem_addr.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&rem_addr;
		log_print("Trying to connect to %pI4", &sin->sin_addr.s_addr);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&rem_addr;
		log_print("Trying to connect to %pI6", &sin6->sin6_addr);
	}

	cmsg = CMSG_FIRSTHDR(&outmessage);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDRCV;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
	sinfo = CMSG_DATA(cmsg);
	memset(sinfo, 0x00, sizeof(struct sctp_sndrcvinfo));
	sinfo->sinfo_ppid = cpu_to_le32(con->nodeid);
	outmessage.msg_controllen = cmsg->cmsg_len;
	sinfo->sinfo_flags |= SCTP_ADDR_OVER;

	ret = kernel_sendmsg(base_con->sock, &outmessage, iov, 1, len);
	if (ret < 0) {
		log_print("Send first packet to node %d failed: %d",
			  con->nodeid, ret);

		/* Try again later */
		clear_bit(CF_CONNECT_PENDING, &con->flags);
		clear_bit(CF_INIT_PENDING, &con->flags);
	}
	else {
		spin_lock(&con->writequeue_lock);
		writequeue_entry_complete(e, ret);
		spin_unlock(&con->writequeue_lock);
	}

unlock:
	mutex_unlock(&con->sock_mutex);
}

/* Connect a new socket to its peer */
static void tcp_connect_to_sock(struct connection *con)
{
	struct sockaddr_storage saddr, src_addr;
	int addr_len;
	struct socket *sock = NULL;
	int one = 1;
	int result;

	if (con->nodeid == 0) {
		log_print("attempt to connect sock 0 foiled");
		return;
	}

	mutex_lock(&con->sock_mutex);
	if (con->retries++ > MAX_CONNECT_RETRIES)
		goto out;

	/* Some odd races can cause double-connects, ignore them */
	if (con->sock)
		goto out;

	/* Create a socket to communicate with */
	result = sock_create_kern(dlm_local_addr[0]->ss_family, SOCK_STREAM,
				  IPPROTO_TCP, &sock);
	if (result < 0)
		goto out_err;

	memset(&saddr, 0, sizeof(saddr));
	result = nodeid_to_addr(con->nodeid, &saddr, NULL, false);
	if (result < 0) {
		log_print("no address for nodeid %d", con->nodeid);
		goto out_err;
	}

	sock->sk->sk_user_data = con;
	con->rx_action = receive_from_sock;
	con->connect_action = tcp_connect_to_sock;
	add_sock(sock, con);

	/* Bind to our cluster-known address connecting to avoid
	   routing problems */
	memcpy(&src_addr, dlm_local_addr[0], sizeof(src_addr));
	make_sockaddr(&src_addr, 0, &addr_len);
	result = sock->ops->bind(sock, (struct sockaddr *) &src_addr,
				 addr_len);
	if (result < 0) {
		log_print("could not bind for connect: %d", result);
		/* This *may* not indicate a critical error */
	}

	make_sockaddr(&saddr, dlm_config.ci_tcp_port, &addr_len);

	log_print("connecting to %d", con->nodeid);

	/* Turn off Nagle's algorithm */
	kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&one,
			  sizeof(one));

	result = sock->ops->connect(sock, (struct sockaddr *)&saddr, addr_len,
				   O_NONBLOCK);
	if (result == -EINPROGRESS)
		result = 0;
	if (result == 0)
		goto out;

out_err:
	if (con->sock) {
		sock_release(con->sock);
		con->sock = NULL;
	} else if (sock) {
		sock_release(sock);
	}
	/*
	 * Some errors are fatal and this list might need adjusting. For other
	 * errors we try again until the max number of retries is reached.
	 */
	if (result != -EHOSTUNREACH &&
	    result != -ENETUNREACH &&
	    result != -ENETDOWN && 
	    result != -EINVAL &&
	    result != -EPROTONOSUPPORT) {
		log_print("connect %d try %d error %d", con->nodeid,
			  con->retries, result);
		mutex_unlock(&con->sock_mutex);
		msleep(1000);
		lowcomms_connect_sock(con);
		return;
	}
out:
	mutex_unlock(&con->sock_mutex);
	return;
}

static struct socket *tcp_create_listen_sock(struct connection *con,
					     struct sockaddr_storage *saddr)
{
	struct socket *sock = NULL;
	int result = 0;
	int one = 1;
	int addr_len;

	if (dlm_local_addr[0]->ss_family == AF_INET)
		addr_len = sizeof(struct sockaddr_in);
	else
		addr_len = sizeof(struct sockaddr_in6);

	/* Create a socket to communicate with */
	result = sock_create_kern(dlm_local_addr[0]->ss_family, SOCK_STREAM,
				  IPPROTO_TCP, &sock);
	if (result < 0) {
		log_print("Can't create listening comms socket");
		goto create_out;
	}

	/* Turn off Nagle's algorithm */
	kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&one,
			  sizeof(one));

	result = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				   (char *)&one, sizeof(one));

	if (result < 0) {
		log_print("Failed to set SO_REUSEADDR on socket: %d", result);
	}
	con->rx_action = tcp_accept_from_sock;
	con->connect_action = tcp_connect_to_sock;

	/* Bind to our port */
	make_sockaddr(saddr, dlm_config.ci_tcp_port, &addr_len);
	result = sock->ops->bind(sock, (struct sockaddr *) saddr, addr_len);
	if (result < 0) {
		log_print("Can't bind to port %d", dlm_config.ci_tcp_port);
		sock_release(sock);
		sock = NULL;
		con->sock = NULL;
		goto create_out;
	}
	result = kernel_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
				 (char *)&one, sizeof(one));
	if (result < 0) {
		log_print("Set keepalive failed: %d", result);
	}

	result = sock->ops->listen(sock, 5);
	if (result < 0) {
		log_print("Can't listen on port %d", dlm_config.ci_tcp_port);
		sock_release(sock);
		sock = NULL;
		goto create_out;
	}

create_out:
	return sock;
}

/* Get local addresses */
static void init_local(void)
{
	struct sockaddr_storage sas, *addr;
	int i;

	dlm_local_count = 0;
	for (i = 0; i < DLM_MAX_ADDR_COUNT; i++) {
		if (dlm_our_addr(&sas, i))
			break;

		addr = kmalloc(sizeof(*addr), GFP_NOFS);
		if (!addr)
			break;
		memcpy(addr, &sas, sizeof(*addr));
		dlm_local_addr[dlm_local_count++] = addr;
	}
}

/* Bind to an IP address. SCTP allows multiple address so it can do
   multi-homing */
static int add_sctp_bind_addr(struct connection *sctp_con,
			      struct sockaddr_storage *addr,
			      int addr_len, int num)
{
	int result = 0;

	if (num == 1)
		result = kernel_bind(sctp_con->sock,
				     (struct sockaddr *) addr,
				     addr_len);
	else
		result = kernel_setsockopt(sctp_con->sock, SOL_SCTP,
					   SCTP_SOCKOPT_BINDX_ADD,
					   (char *)addr, addr_len);

	if (result < 0)
		log_print("Can't bind to port %d addr number %d",
			  dlm_config.ci_tcp_port, num);

	return result;
}

/* Initialise SCTP socket and bind to all interfaces */
static int sctp_listen_for_all(void)
{
	struct socket *sock = NULL;
	struct sockaddr_storage localaddr;
	struct sctp_event_subscribe subscribe;
	int result = -EINVAL, num = 1, i, addr_len;
	struct connection *con = nodeid2con(0, GFP_NOFS);
	int bufsize = NEEDED_RMEM;
	int one = 1;

	if (!con)
		return -ENOMEM;

	log_print("Using SCTP for communications");

	result = sock_create_kern(dlm_local_addr[0]->ss_family, SOCK_SEQPACKET,
				  IPPROTO_SCTP, &sock);
	if (result < 0) {
		log_print("Can't create comms socket, check SCTP is loaded");
		goto out;
	}

	/* Listen for events */
	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.sctp_data_io_event = 1;
	subscribe.sctp_association_event = 1;
	subscribe.sctp_send_failure_event = 1;
	subscribe.sctp_shutdown_event = 1;
	subscribe.sctp_partial_delivery_event = 1;

	result = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE,
				 (char *)&bufsize, sizeof(bufsize));
	if (result)
		log_print("Error increasing buffer space on socket %d", result);

	result = kernel_setsockopt(sock, SOL_SCTP, SCTP_EVENTS,
				   (char *)&subscribe, sizeof(subscribe));
	if (result < 0) {
		log_print("Failed to set SCTP_EVENTS on socket: result=%d",
			  result);
		goto create_delsock;
	}

	result = kernel_setsockopt(sock, SOL_SCTP, SCTP_NODELAY, (char *)&one,
				   sizeof(one));
	if (result < 0)
		log_print("Could not set SCTP NODELAY error %d\n", result);

	/* Init con struct */
	sock->sk->sk_user_data = con;
	con->sock = sock;
	con->sock->sk->sk_data_ready = lowcomms_data_ready;
	con->rx_action = receive_from_sock;
	con->connect_action = sctp_init_assoc;

	/* Bind to all interfaces. */
	for (i = 0; i < dlm_local_count; i++) {
		memcpy(&localaddr, dlm_local_addr[i], sizeof(localaddr));
		make_sockaddr(&localaddr, dlm_config.ci_tcp_port, &addr_len);

		result = add_sctp_bind_addr(con, &localaddr, addr_len, num);
		if (result)
			goto create_delsock;
		++num;
	}

	result = sock->ops->listen(sock, 5);
	if (result < 0) {
		log_print("Can't set socket listening");
		goto create_delsock;
	}

	return 0;

create_delsock:
	sock_release(sock);
	con->sock = NULL;
out:
	return result;
}

static int tcp_listen_for_all(void)
{
	struct socket *sock = NULL;
	struct connection *con = nodeid2con(0, GFP_NOFS);
	int result = -EINVAL;

	if (!con)
		return -ENOMEM;

	/* We don't support multi-homed hosts */
	if (dlm_local_addr[1] != NULL) {
		log_print("TCP protocol can't handle multi-homed hosts, "
			  "try SCTP");
		return -EINVAL;
	}

	log_print("Using TCP for communications");

	sock = tcp_create_listen_sock(con, dlm_local_addr[0]);
	if (sock) {
		add_sock(sock, con);
		result = 0;
	}
	else {
		result = -EADDRINUSE;
	}

	return result;
}



static struct writequeue_entry *new_writequeue_entry(struct connection *con,
						     gfp_t allocation)
{
	struct writequeue_entry *entry;

	entry = kmalloc(sizeof(struct writequeue_entry), allocation);
	if (!entry)
		return NULL;

	entry->page = alloc_page(allocation);
	if (!entry->page) {
		kfree(entry);
		return NULL;
	}

	entry->offset = 0;
	entry->len = 0;
	entry->end = 0;
	entry->users = 0;
	entry->con = con;

	return entry;
}

void *dlm_lowcomms_get_buffer(int nodeid, int len, gfp_t allocation, char **ppc)
{
	struct connection *con;
	struct writequeue_entry *e;
	int offset = 0;

	con = nodeid2con(nodeid, allocation);
	if (!con)
		return NULL;

	spin_lock(&con->writequeue_lock);
	e = list_entry(con->writequeue.prev, struct writequeue_entry, list);
	if ((&e->list == &con->writequeue) ||
	    (PAGE_CACHE_SIZE - e->end < len)) {
		e = NULL;
	} else {
		offset = e->end;
		e->end += len;
		e->users++;
	}
	spin_unlock(&con->writequeue_lock);

	if (e) {
	got_one:
		*ppc = page_address(e->page) + offset;
		return e;
	}

	e = new_writequeue_entry(con, allocation);
	if (e) {
		spin_lock(&con->writequeue_lock);
		offset = e->end;
		e->end += len;
		e->users++;
		list_add_tail(&e->list, &con->writequeue);
		spin_unlock(&con->writequeue_lock);
		goto got_one;
	}
	return NULL;
}

void dlm_lowcomms_commit_buffer(void *mh)
{
	struct writequeue_entry *e = (struct writequeue_entry *)mh;
	struct connection *con = e->con;
	int users;

	spin_lock(&con->writequeue_lock);
	users = --e->users;
	if (users)
		goto out;
	e->len = e->end - e->offset;
	spin_unlock(&con->writequeue_lock);

	if (!test_and_set_bit(CF_WRITE_PENDING, &con->flags)) {
		queue_work(send_workqueue, &con->swork);
	}
	return;

out:
	spin_unlock(&con->writequeue_lock);
	return;
}

/* Send a message */
static void send_to_sock(struct connection *con)
{
	int ret = 0;
	const int msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;
	struct writequeue_entry *e;
	int len, offset;
	int count = 0;

	mutex_lock(&con->sock_mutex);
	if (con->sock == NULL)
		goto out_connect;

	spin_lock(&con->writequeue_lock);
	for (;;) {
		e = list_entry(con->writequeue.next, struct writequeue_entry,
			       list);
		if ((struct list_head *) e == &con->writequeue)
			break;

		len = e->len;
		offset = e->offset;
		BUG_ON(len == 0 && e->users == 0);
		spin_unlock(&con->writequeue_lock);

		ret = 0;
		if (len) {
			ret = kernel_sendpage(con->sock, e->page, offset, len,
					      msg_flags);
			if (ret == -EAGAIN || ret == 0) {
				if (ret == -EAGAIN &&
				    test_bit(SOCK_ASYNC_NOSPACE, &con->sock->flags) &&
				    !test_and_set_bit(CF_APP_LIMITED, &con->flags)) {
					/* Notify TCP that we're limited by the
					 * application window size.
					 */
					set_bit(SOCK_NOSPACE, &con->sock->flags);
					con->sock->sk->sk_write_pending++;
				}
				cond_resched();
				goto out;
			} else if (ret < 0)
				goto send_error;
		}

		/* Don't starve people filling buffers */
		if (++count >= MAX_SEND_MSG_COUNT) {
			cond_resched();
			count = 0;
		}

		spin_lock(&con->writequeue_lock);
		writequeue_entry_complete(e, ret);
	}
	spin_unlock(&con->writequeue_lock);
out:
	mutex_unlock(&con->sock_mutex);
	return;

send_error:
	mutex_unlock(&con->sock_mutex);
	close_connection(con, false);
	lowcomms_connect_sock(con);
	return;

out_connect:
	mutex_unlock(&con->sock_mutex);
	if (!test_bit(CF_INIT_PENDING, &con->flags))
		lowcomms_connect_sock(con);
}

static void clean_one_writequeue(struct connection *con)
{
	struct writequeue_entry *e, *safe;

	spin_lock(&con->writequeue_lock);
	list_for_each_entry_safe(e, safe, &con->writequeue, list) {
		list_del(&e->list);
		free_entry(e);
	}
	spin_unlock(&con->writequeue_lock);
}

/* Called from recovery when it knows that a node has
   left the cluster */
int dlm_lowcomms_close(int nodeid)
{
	struct connection *con;
	struct dlm_node_addr *na;

	log_print("closing connection to node %d", nodeid);
	con = nodeid2con(nodeid, 0);
	if (con) {
		clear_bit(CF_CONNECT_PENDING, &con->flags);
		clear_bit(CF_WRITE_PENDING, &con->flags);
		set_bit(CF_CLOSE, &con->flags);
		if (cancel_work_sync(&con->swork))
			log_print("canceled swork for node %d", nodeid);
		if (cancel_work_sync(&con->rwork))
			log_print("canceled rwork for node %d", nodeid);
		clean_one_writequeue(con);
		close_connection(con, true);
	}

	spin_lock(&dlm_node_addrs_spin);
	na = find_node_addr(nodeid);
	if (na) {
		list_del(&na->list);
		while (na->addr_count--)
			kfree(na->addr[na->addr_count]);
		kfree(na);
	}
	spin_unlock(&dlm_node_addrs_spin);

	return 0;
}

/* Receive workqueue function */
static void process_recv_sockets(struct work_struct *work)
{
	struct connection *con = container_of(work, struct connection, rwork);
	int err;

	clear_bit(CF_READ_PENDING, &con->flags);
	do {
		err = con->rx_action(con);
	} while (!err);
}

/* Send workqueue function */
static void process_send_sockets(struct work_struct *work)
{
	struct connection *con = container_of(work, struct connection, swork);

	if (test_and_clear_bit(CF_CONNECT_PENDING, &con->flags)) {
		con->connect_action(con);
		set_bit(CF_WRITE_PENDING, &con->flags);
	}
	if (test_and_clear_bit(CF_WRITE_PENDING, &con->flags))
		send_to_sock(con);
}


/* Discard all entries on the write queues */
static void clean_writequeues(void)
{
	foreach_conn(clean_one_writequeue);
}

static void work_stop(void)
{
	destroy_workqueue(recv_workqueue);
	destroy_workqueue(send_workqueue);
}

static int work_start(void)
{
	recv_workqueue = alloc_workqueue("dlm_recv",
					 WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!recv_workqueue) {
		log_print("can't start dlm_recv");
		return -ENOMEM;
	}

	send_workqueue = alloc_workqueue("dlm_send",
					 WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!send_workqueue) {
		log_print("can't start dlm_send");
		destroy_workqueue(recv_workqueue);
		return -ENOMEM;
	}

	return 0;
}

static void stop_conn(struct connection *con)
{
	con->flags |= 0x0F;
	if (con->sock && con->sock->sk)
		con->sock->sk->sk_user_data = NULL;
}

static void free_conn(struct connection *con)
{
	close_connection(con, true);
	if (con->othercon)
		kmem_cache_free(con_cache, con->othercon);
	hlist_del(&con->list);
	kmem_cache_free(con_cache, con);
}

void dlm_lowcomms_stop(void)
{
	/* Set all the flags to prevent any
	   socket activity.
	*/
	mutex_lock(&connections_lock);
	dlm_allow_conn = 0;
	foreach_conn(stop_conn);
	mutex_unlock(&connections_lock);

	work_stop();

	mutex_lock(&connections_lock);
	clean_writequeues();

	foreach_conn(free_conn);

	mutex_unlock(&connections_lock);
	kmem_cache_destroy(con_cache);
}

int dlm_lowcomms_start(void)
{
	int error = -EINVAL;
	struct connection *con;
	int i;

	for (i = 0; i < CONN_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&connection_hash[i]);

	init_local();
	if (!dlm_local_count) {
		error = -ENOTCONN;
		log_print("no local IP address has been set");
		goto fail;
	}

	error = -ENOMEM;
	con_cache = kmem_cache_create("dlm_conn", sizeof(struct connection),
				      __alignof__(struct connection), 0,
				      NULL);
	if (!con_cache)
		goto fail;

	error = work_start();
	if (error)
		goto fail_destroy;

	dlm_allow_conn = 1;

	/* Start listening */
	if (dlm_config.ci_protocol == 0)
		error = tcp_listen_for_all();
	else
		error = sctp_listen_for_all();
	if (error)
		goto fail_unlisten;

	return 0;

fail_unlisten:
	dlm_allow_conn = 0;
	con = nodeid2con(0,0);
	if (con) {
		close_connection(con, false);
		kmem_cache_free(con_cache, con);
	}
fail_destroy:
	kmem_cache_destroy(con_cache);
fail:
	return error;
}

void dlm_lowcomms_exit(void)
{
	struct dlm_node_addr *na, *safe;

	spin_lock(&dlm_node_addrs_spin);
	list_for_each_entry_safe(na, safe, &dlm_node_addrs, list) {
		list_del(&na->list);
		while (na->addr_count--)
			kfree(na->addr[na->addr_count]);
		kfree(na);
	}
	spin_unlock(&dlm_node_addrs_spin);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/lowcomms.c */
/************************************************************/
/*
 * Copyright (C) 2005-2008 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
// #include <linux/dlm.h>
#include <linux/dlm_plock.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

// #include "dlm_internal.h"
// #include "lockspace.h"

static spinlock_t ops_lock;
static struct list_head send_list;
static struct list_head recv_list;
static wait_queue_head_t send_wq;
static wait_queue_head_t recv_wq;

struct plock_op {
	struct list_head list;
	int done;
	struct dlm_plock_info info;
};

struct plock_xop {
	struct plock_op xop;
	int (*callback)(struct file_lock *fl, int result);
	void *fl;
	void *file;
	struct file_lock flc;
};


static inline void set_version(struct dlm_plock_info *info)
{
	info->version[0] = DLM_PLOCK_VERSION_MAJOR;
	info->version[1] = DLM_PLOCK_VERSION_MINOR;
	info->version[2] = DLM_PLOCK_VERSION_PATCH;
}

static int check_version_plock_c(struct dlm_plock_info *info)
{
	if ((DLM_PLOCK_VERSION_MAJOR != info->version[0]) ||
	    (DLM_PLOCK_VERSION_MINOR < info->version[1])) {
		log_print("plock device version mismatch: "
			  "kernel (%u.%u.%u), user (%u.%u.%u)",
			  DLM_PLOCK_VERSION_MAJOR,
			  DLM_PLOCK_VERSION_MINOR,
			  DLM_PLOCK_VERSION_PATCH,
			  info->version[0],
			  info->version[1],
			  info->version[2]);
		return -EINVAL;
	}
	return 0;
}

static void send_op(struct plock_op *op)
{
	set_version(&op->info);
	INIT_LIST_HEAD(&op->list);
	spin_lock(&ops_lock);
	list_add_tail(&op->list, &send_list);
	spin_unlock(&ops_lock);
	wake_up(&send_wq);
}

/* If a process was killed while waiting for the only plock on a file,
   locks_remove_posix will not see any lock on the file so it won't
   send an unlock-close to us to pass on to userspace to clean up the
   abandoned waiter.  So, we have to insert the unlock-close when the
   lock call is interrupted. */

static void do_unlock_close(struct dlm_ls *ls, u64 number,
			    struct file *file, struct file_lock *fl)
{
	struct plock_op *op;

	op = kzalloc(sizeof(*op), GFP_NOFS);
	if (!op)
		return;

	op->info.optype		= DLM_PLOCK_OP_UNLOCK;
	op->info.pid		= fl->fl_pid;
	op->info.fsid		= ls->ls_global_id;
	op->info.number		= number;
	op->info.start		= 0;
	op->info.end		= OFFSET_MAX;
	if (fl->fl_lmops && fl->fl_lmops->lm_grant)
		op->info.owner	= (__u64) fl->fl_pid;
	else
		op->info.owner	= (__u64)(long) fl->fl_owner;

	op->info.flags |= DLM_PLOCK_FL_CLOSE;
	send_op(op);
}

int dlm_posix_lock(dlm_lockspace_t *lockspace, u64 number, struct file *file,
		   int cmd, struct file_lock *fl)
{
	struct dlm_ls *ls;
	struct plock_op *op;
	struct plock_xop *xop;
	int rv;

	ls = dlm_find_lockspace_local(lockspace);
	if (!ls)
		return -EINVAL;

	xop = kzalloc(sizeof(*xop), GFP_NOFS);
	if (!xop) {
		rv = -ENOMEM;
		goto out;
	}

	op = &xop->xop;
	op->info.optype		= DLM_PLOCK_OP_LOCK;
	op->info.pid		= fl->fl_pid;
	op->info.ex		= (fl->fl_type == F_WRLCK);
	op->info.wait		= IS_SETLKW(cmd);
	op->info.fsid		= ls->ls_global_id;
	op->info.number		= number;
	op->info.start		= fl->fl_start;
	op->info.end		= fl->fl_end;
	if (fl->fl_lmops && fl->fl_lmops->lm_grant) {
		/* fl_owner is lockd which doesn't distinguish
		   processes on the nfs client */
		op->info.owner	= (__u64) fl->fl_pid;
		xop->callback	= fl->fl_lmops->lm_grant;
		locks_init_lock(&xop->flc);
		locks_copy_lock(&xop->flc, fl);
		xop->fl		= fl;
		xop->file	= file;
	} else {
		op->info.owner	= (__u64)(long) fl->fl_owner;
		xop->callback	= NULL;
	}

	send_op(op);

	if (xop->callback == NULL) {
		rv = wait_event_killable(recv_wq, (op->done != 0));
		if (rv == -ERESTARTSYS) {
			log_debug(ls, "dlm_posix_lock: wait killed %llx",
				  (unsigned long long)number);
			spin_lock(&ops_lock);
			list_del(&op->list);
			spin_unlock(&ops_lock);
			kfree(xop);
			do_unlock_close(ls, number, file, fl);
			goto out;
		}
	} else {
		rv = FILE_LOCK_DEFERRED;
		goto out;
	}

	spin_lock(&ops_lock);
	if (!list_empty(&op->list)) {
		log_error(ls, "dlm_posix_lock: op on list %llx",
			  (unsigned long long)number);
		list_del(&op->list);
	}
	spin_unlock(&ops_lock);

	rv = op->info.rv;

	if (!rv) {
		if (posix_lock_file_wait(file, fl) < 0)
			log_error(ls, "dlm_posix_lock: vfs lock error %llx",
				  (unsigned long long)number);
	}

	kfree(xop);
out:
	dlm_put_lockspace(ls);
	return rv;
}
EXPORT_SYMBOL_GPL(dlm_posix_lock);

/* Returns failure iff a successful lock operation should be canceled */
static int dlm_plock_callback(struct plock_op *op)
{
	struct file *file;
	struct file_lock *fl;
	struct file_lock *flc;
	int (*notify)(struct file_lock *fl, int result) = NULL;
	struct plock_xop *xop = (struct plock_xop *)op;
	int rv = 0;

	spin_lock(&ops_lock);
	if (!list_empty(&op->list)) {
		log_print("dlm_plock_callback: op on list %llx",
			  (unsigned long long)op->info.number);
		list_del(&op->list);
	}
	spin_unlock(&ops_lock);

	/* check if the following 2 are still valid or make a copy */
	file = xop->file;
	flc = &xop->flc;
	fl = xop->fl;
	notify = xop->callback;

	if (op->info.rv) {
		notify(fl, op->info.rv);
		goto out;
	}

	/* got fs lock; bookkeep locally as well: */
	flc->fl_flags &= ~FL_SLEEP;
	if (posix_lock_file(file, flc, NULL)) {
		/*
		 * This can only happen in the case of kmalloc() failure.
		 * The filesystem's own lock is the authoritative lock,
		 * so a failure to get the lock locally is not a disaster.
		 * As long as the fs cannot reliably cancel locks (especially
		 * in a low-memory situation), we're better off ignoring
		 * this failure than trying to recover.
		 */
		log_print("dlm_plock_callback: vfs lock error %llx file %p fl %p",
			  (unsigned long long)op->info.number, file, fl);
	}

	rv = notify(fl, 0);
	if (rv) {
		/* XXX: We need to cancel the fs lock here: */
		log_print("dlm_plock_callback: lock granted after lock request "
			  "failed; dangling lock!\n");
		goto out;
	}

out:
	kfree(xop);
	return rv;
}

int dlm_posix_unlock(dlm_lockspace_t *lockspace, u64 number, struct file *file,
		     struct file_lock *fl)
{
	struct dlm_ls *ls;
	struct plock_op *op;
	int rv;
	unsigned char fl_flags = fl->fl_flags;

	ls = dlm_find_lockspace_local(lockspace);
	if (!ls)
		return -EINVAL;

	op = kzalloc(sizeof(*op), GFP_NOFS);
	if (!op) {
		rv = -ENOMEM;
		goto out;
	}

	/* cause the vfs unlock to return ENOENT if lock is not found */
	fl->fl_flags |= FL_EXISTS;

	rv = posix_lock_file_wait(file, fl);
	if (rv == -ENOENT) {
		rv = 0;
		goto out_free;
	}
	if (rv < 0) {
		log_error(ls, "dlm_posix_unlock: vfs unlock error %d %llx",
			  rv, (unsigned long long)number);
	}

	op->info.optype		= DLM_PLOCK_OP_UNLOCK;
	op->info.pid		= fl->fl_pid;
	op->info.fsid		= ls->ls_global_id;
	op->info.number		= number;
	op->info.start		= fl->fl_start;
	op->info.end		= fl->fl_end;
	if (fl->fl_lmops && fl->fl_lmops->lm_grant)
		op->info.owner	= (__u64) fl->fl_pid;
	else
		op->info.owner	= (__u64)(long) fl->fl_owner;

	if (fl->fl_flags & FL_CLOSE) {
		op->info.flags |= DLM_PLOCK_FL_CLOSE;
		send_op(op);
		rv = 0;
		goto out;
	}

	send_op(op);
	wait_event(recv_wq, (op->done != 0));

	spin_lock(&ops_lock);
	if (!list_empty(&op->list)) {
		log_error(ls, "dlm_posix_unlock: op on list %llx",
			  (unsigned long long)number);
		list_del(&op->list);
	}
	spin_unlock(&ops_lock);

	rv = op->info.rv;

	if (rv == -ENOENT)
		rv = 0;

out_free:
	kfree(op);
out:
	dlm_put_lockspace(ls);
	fl->fl_flags = fl_flags;
	return rv;
}
EXPORT_SYMBOL_GPL(dlm_posix_unlock);

int dlm_posix_get(dlm_lockspace_t *lockspace, u64 number, struct file *file,
		  struct file_lock *fl)
{
	struct dlm_ls *ls;
	struct plock_op *op;
	int rv;

	ls = dlm_find_lockspace_local(lockspace);
	if (!ls)
		return -EINVAL;

	op = kzalloc(sizeof(*op), GFP_NOFS);
	if (!op) {
		rv = -ENOMEM;
		goto out;
	}

	op->info.optype		= DLM_PLOCK_OP_GET;
	op->info.pid		= fl->fl_pid;
	op->info.ex		= (fl->fl_type == F_WRLCK);
	op->info.fsid		= ls->ls_global_id;
	op->info.number		= number;
	op->info.start		= fl->fl_start;
	op->info.end		= fl->fl_end;
	if (fl->fl_lmops && fl->fl_lmops->lm_grant)
		op->info.owner	= (__u64) fl->fl_pid;
	else
		op->info.owner	= (__u64)(long) fl->fl_owner;

	send_op(op);
	wait_event(recv_wq, (op->done != 0));

	spin_lock(&ops_lock);
	if (!list_empty(&op->list)) {
		log_error(ls, "dlm_posix_get: op on list %llx",
			  (unsigned long long)number);
		list_del(&op->list);
	}
	spin_unlock(&ops_lock);

	/* info.rv from userspace is 1 for conflict, 0 for no-conflict,
	   -ENOENT if there are no locks on the file */

	rv = op->info.rv;

	fl->fl_type = F_UNLCK;
	if (rv == -ENOENT)
		rv = 0;
	else if (rv > 0) {
		locks_init_lock(fl);
		fl->fl_type = (op->info.ex) ? F_WRLCK : F_RDLCK;
		fl->fl_flags = FL_POSIX;
		fl->fl_pid = op->info.pid;
		fl->fl_start = op->info.start;
		fl->fl_end = op->info.end;
		rv = 0;
	}

	kfree(op);
out:
	dlm_put_lockspace(ls);
	return rv;
}
EXPORT_SYMBOL_GPL(dlm_posix_get);

/* a read copies out one plock request from the send list */
static ssize_t dev_read(struct file *file, char __user *u, size_t count,
			loff_t *ppos)
{
	struct dlm_plock_info info;
	struct plock_op *op = NULL;

	if (count < sizeof(info))
		return -EINVAL;

	spin_lock(&ops_lock);
	if (!list_empty(&send_list)) {
		op = list_entry(send_list.next, struct plock_op, list);
		if (op->info.flags & DLM_PLOCK_FL_CLOSE)
			list_del(&op->list);
		else
			list_move(&op->list, &recv_list);
		memcpy(&info, &op->info, sizeof(info));
	}
	spin_unlock(&ops_lock);

	if (!op)
		return -EAGAIN;

	/* there is no need to get a reply from userspace for unlocks
	   that were generated by the vfs cleaning up for a close
	   (the process did not make an unlock call). */

	if (op->info.flags & DLM_PLOCK_FL_CLOSE)
		kfree(op);

	if (copy_to_user(u, &info, sizeof(info)))
		return -EFAULT;
	return sizeof(info);
}

/* a write copies in one plock result that should match a plock_op
   on the recv list */
static ssize_t dev_write(struct file *file, const char __user *u, size_t count,
			 loff_t *ppos)
{
	struct dlm_plock_info info;
	struct plock_op *op;
	int found = 0, do_callback = 0;

	if (count != sizeof(info))
		return -EINVAL;

	if (copy_from_user(&info, u, sizeof(info)))
		return -EFAULT;

	if (check_version_plock_c(&info))
		return -EINVAL;

	spin_lock(&ops_lock);
	list_for_each_entry(op, &recv_list, list) {
		if (op->info.fsid == info.fsid &&
		    op->info.number == info.number &&
		    op->info.owner == info.owner) {
			struct plock_xop *xop = (struct plock_xop *)op;
			list_del_init(&op->list);
			memcpy(&op->info, &info, sizeof(info));
			if (xop->callback)
				do_callback = 1;
			else
				op->done = 1;
			found = 1;
			break;
		}
	}
	spin_unlock(&ops_lock);

	if (found) {
		if (do_callback)
			dlm_plock_callback(op);
		else
			wake_up(&recv_wq);
	} else
		log_print("dev_write no op %x %llx", info.fsid,
			  (unsigned long long)info.number);
	return count;
}

static unsigned int dev_poll(struct file *file, poll_table *wait)
{
	unsigned int mask = 0;

	poll_wait(file, &send_wq, wait);

	spin_lock(&ops_lock);
	if (!list_empty(&send_list))
		mask = POLLIN | POLLRDNORM;
	spin_unlock(&ops_lock);

	return mask;
}

static const struct file_operations dev_fops = {
	.read    = dev_read,
	.write   = dev_write,
	.poll    = dev_poll,
	.owner   = THIS_MODULE,
	.llseek  = noop_llseek,
};

static struct miscdevice plock_dev_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DLM_PLOCK_MISC_NAME,
	.fops = &dev_fops
};

int dlm_plock_init(void)
{
	int rv;

	spin_lock_init(&ops_lock);
	INIT_LIST_HEAD(&send_list);
	INIT_LIST_HEAD(&recv_list);
	init_waitqueue_head(&send_wq);
	init_waitqueue_head(&recv_wq);

	rv = misc_register(&plock_dev_misc);
	if (rv)
		log_print("dlm_plock_init: misc_register failed %d", rv);
	return rv;
}

void dlm_plock_exit(void)
{
	if (misc_deregister(&plock_dev_misc) < 0)
		log_print("dlm_plock_exit: misc_deregister failed");
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/plock.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2005-2008 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
// #include "lockspace.h"
// #include "member.h"
// #include "lowcomms.h"
// #include "midcomms.h"
// #include "rcom.h"
// #include "recover.h"
// #include "dir.h"
// #include "config.h"
// #include "memory.h"
// #include "lock.h"
// #include "util.h"

static int rcom_response(struct dlm_ls *ls)
{
	return test_bit(LSFL_RCOM_READY, &ls->ls_flags);
}

static int create_rcom(struct dlm_ls *ls, int to_nodeid, int type, int len,
		       struct dlm_rcom **rc_ret, struct dlm_mhandle **mh_ret)
{
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	char *mb;
	int mb_len = sizeof(struct dlm_rcom) + len;

	mh = dlm_lowcomms_get_buffer(to_nodeid, mb_len, GFP_NOFS, &mb);
	if (!mh) {
		log_print("create_rcom to %d type %d len %d ENOBUFS",
			  to_nodeid, type, len);
		return -ENOBUFS;
	}
	memset(mb, 0, mb_len);

	rc = (struct dlm_rcom *) mb;

	rc->rc_header.h_version = (DLM_HEADER_MAJOR | DLM_HEADER_MINOR);
	rc->rc_header.h_lockspace = ls->ls_global_id;
	rc->rc_header.h_nodeid = dlm_our_nodeid();
	rc->rc_header.h_length = mb_len;
	rc->rc_header.h_cmd = DLM_RCOM;

	rc->rc_type = type;

	spin_lock(&ls->ls_recover_lock);
	rc->rc_seq = ls->ls_recover_seq;
	spin_unlock(&ls->ls_recover_lock);

	*mh_ret = mh;
	*rc_ret = rc;
	return 0;
}

static void send_rcom(struct dlm_ls *ls, struct dlm_mhandle *mh,
		      struct dlm_rcom *rc)
{
	dlm_rcom_out(rc);
	dlm_lowcomms_commit_buffer(mh);
}

static void set_rcom_status(struct dlm_ls *ls, struct rcom_status *rs,
			    uint32_t flags)
{
	rs->rs_flags = cpu_to_le32(flags);
}

/* When replying to a status request, a node also sends back its
   configuration values.  The requesting node then checks that the remote
   node is configured the same way as itself. */

static void set_rcom_config(struct dlm_ls *ls, struct rcom_config *rf,
			    uint32_t num_slots)
{
	rf->rf_lvblen = cpu_to_le32(ls->ls_lvblen);
	rf->rf_lsflags = cpu_to_le32(ls->ls_exflags);

	rf->rf_our_slot = cpu_to_le16(ls->ls_slot);
	rf->rf_num_slots = cpu_to_le16(num_slots);
	rf->rf_generation =  cpu_to_le32(ls->ls_generation);
}

static int check_rcom_config(struct dlm_ls *ls, struct dlm_rcom *rc, int nodeid)
{
	struct rcom_config *rf = (struct rcom_config *) rc->rc_buf;

	if ((rc->rc_header.h_version & 0xFFFF0000) != DLM_HEADER_MAJOR) {
		log_error(ls, "version mismatch: %x nodeid %d: %x",
			  DLM_HEADER_MAJOR | DLM_HEADER_MINOR, nodeid,
			  rc->rc_header.h_version);
		return -EPROTO;
	}

	if (le32_to_cpu(rf->rf_lvblen) != ls->ls_lvblen ||
	    le32_to_cpu(rf->rf_lsflags) != ls->ls_exflags) {
		log_error(ls, "config mismatch: %d,%x nodeid %d: %d,%x",
			  ls->ls_lvblen, ls->ls_exflags, nodeid,
			  le32_to_cpu(rf->rf_lvblen),
			  le32_to_cpu(rf->rf_lsflags));
		return -EPROTO;
	}
	return 0;
}

static void allow_sync_reply(struct dlm_ls *ls, uint64_t *new_seq)
{
	spin_lock(&ls->ls_rcom_spin);
	*new_seq = ++ls->ls_rcom_seq;
	set_bit(LSFL_RCOM_WAIT, &ls->ls_flags);
	spin_unlock(&ls->ls_rcom_spin);
}

static void disallow_sync_reply(struct dlm_ls *ls)
{
	spin_lock(&ls->ls_rcom_spin);
	clear_bit(LSFL_RCOM_WAIT, &ls->ls_flags);
	clear_bit(LSFL_RCOM_READY, &ls->ls_flags);
	spin_unlock(&ls->ls_rcom_spin);
}

/*
 * low nodeid gathers one slot value at a time from each node.
 * it sets need_slots=0, and saves rf_our_slot returned from each
 * rcom_config.
 *
 * other nodes gather all slot values at once from the low nodeid.
 * they set need_slots=1, and ignore the rf_our_slot returned from each
 * rcom_config.  they use the rf_num_slots returned from the low
 * node's rcom_config.
 */

int dlm_rcom_status(struct dlm_ls *ls, int nodeid, uint32_t status_flags)
{
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	int error = 0;

	ls->ls_recover_nodeid = nodeid;

	if (nodeid == dlm_our_nodeid()) {
		rc = ls->ls_recover_buf;
		rc->rc_result = dlm_recover_status(ls);
		goto out;
	}

	error = create_rcom(ls, nodeid, DLM_RCOM_STATUS,
			    sizeof(struct rcom_status), &rc, &mh);
	if (error)
		goto out;

	set_rcom_status(ls, (struct rcom_status *)rc->rc_buf, status_flags);

	allow_sync_reply(ls, &rc->rc_id);
	memset(ls->ls_recover_buf, 0, dlm_config.ci_buffer_size);

	send_rcom(ls, mh, rc);

	error = dlm_wait_function(ls, &rcom_response);
	disallow_sync_reply(ls);
	if (error)
		goto out;

	rc = ls->ls_recover_buf;

	if (rc->rc_result == -ESRCH) {
		/* we pretend the remote lockspace exists with 0 status */
		log_debug(ls, "remote node %d not ready", nodeid);
		rc->rc_result = 0;
		error = 0;
	} else {
		error = check_rcom_config(ls, rc, nodeid);
	}

	/* the caller looks at rc_result for the remote recovery status */
 out:
	return error;
}

static void receive_rcom_status(struct dlm_ls *ls, struct dlm_rcom *rc_in)
{
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	struct rcom_status *rs;
	uint32_t status;
	int nodeid = rc_in->rc_header.h_nodeid;
	int len = sizeof(struct rcom_config);
	int num_slots = 0;
	int error;

	if (!dlm_slots_version(&rc_in->rc_header)) {
		status = dlm_recover_status(ls);
		goto do_create;
	}

	rs = (struct rcom_status *)rc_in->rc_buf;

	if (!(le32_to_cpu(rs->rs_flags) & DLM_RSF_NEED_SLOTS)) {
		status = dlm_recover_status(ls);
		goto do_create;
	}

	spin_lock(&ls->ls_recover_lock);
	status = ls->ls_recover_status;
	num_slots = ls->ls_num_slots;
	spin_unlock(&ls->ls_recover_lock);
	len += num_slots * sizeof(struct rcom_slot);

 do_create:
	error = create_rcom(ls, nodeid, DLM_RCOM_STATUS_REPLY,
			    len, &rc, &mh);
	if (error)
		return;

	rc->rc_id = rc_in->rc_id;
	rc->rc_seq_reply = rc_in->rc_seq;
	rc->rc_result = status;

	set_rcom_config(ls, (struct rcom_config *)rc->rc_buf, num_slots);

	if (!num_slots)
		goto do_send;

	spin_lock(&ls->ls_recover_lock);
	if (ls->ls_num_slots != num_slots) {
		spin_unlock(&ls->ls_recover_lock);
		log_debug(ls, "receive_rcom_status num_slots %d to %d",
			  num_slots, ls->ls_num_slots);
		rc->rc_result = 0;
		set_rcom_config(ls, (struct rcom_config *)rc->rc_buf, 0);
		goto do_send;
	}

	dlm_slots_copy_out(ls, rc);
	spin_unlock(&ls->ls_recover_lock);

 do_send:
	send_rcom(ls, mh, rc);
}

static void receive_sync_reply(struct dlm_ls *ls, struct dlm_rcom *rc_in)
{
	spin_lock(&ls->ls_rcom_spin);
	if (!test_bit(LSFL_RCOM_WAIT, &ls->ls_flags) ||
	    rc_in->rc_id != ls->ls_rcom_seq) {
		log_debug(ls, "reject reply %d from %d seq %llx expect %llx",
			  rc_in->rc_type, rc_in->rc_header.h_nodeid,
			  (unsigned long long)rc_in->rc_id,
			  (unsigned long long)ls->ls_rcom_seq);
		goto out;
	}
	memcpy(ls->ls_recover_buf, rc_in, rc_in->rc_header.h_length);
	set_bit(LSFL_RCOM_READY, &ls->ls_flags);
	clear_bit(LSFL_RCOM_WAIT, &ls->ls_flags);
	wake_up(&ls->ls_wait_general);
 out:
	spin_unlock(&ls->ls_rcom_spin);
}

int dlm_rcom_names(struct dlm_ls *ls, int nodeid, char *last_name, int last_len)
{
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	int error = 0;

	ls->ls_recover_nodeid = nodeid;

	error = create_rcom(ls, nodeid, DLM_RCOM_NAMES, last_len, &rc, &mh);
	if (error)
		goto out;
	memcpy(rc->rc_buf, last_name, last_len);

	allow_sync_reply(ls, &rc->rc_id);
	memset(ls->ls_recover_buf, 0, dlm_config.ci_buffer_size);

	send_rcom(ls, mh, rc);

	error = dlm_wait_function(ls, &rcom_response);
	disallow_sync_reply(ls);
 out:
	return error;
}

static void receive_rcom_names(struct dlm_ls *ls, struct dlm_rcom *rc_in)
{
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	int error, inlen, outlen, nodeid;

	nodeid = rc_in->rc_header.h_nodeid;
	inlen = rc_in->rc_header.h_length - sizeof(struct dlm_rcom);
	outlen = dlm_config.ci_buffer_size - sizeof(struct dlm_rcom);

	error = create_rcom(ls, nodeid, DLM_RCOM_NAMES_REPLY, outlen, &rc, &mh);
	if (error)
		return;
	rc->rc_id = rc_in->rc_id;
	rc->rc_seq_reply = rc_in->rc_seq;

	dlm_copy_master_names(ls, rc_in->rc_buf, inlen, rc->rc_buf, outlen,
			      nodeid);
	send_rcom(ls, mh, rc);
}

int dlm_send_rcom_lookup(struct dlm_rsb *r, int dir_nodeid)
{
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	struct dlm_ls *ls = r->res_ls;
	int error;

	error = create_rcom(ls, dir_nodeid, DLM_RCOM_LOOKUP, r->res_length,
			    &rc, &mh);
	if (error)
		goto out;
	memcpy(rc->rc_buf, r->res_name, r->res_length);
	rc->rc_id = (unsigned long) r->res_id;

	send_rcom(ls, mh, rc);
 out:
	return error;
}

int dlm_send_rcom_lookup_dump(struct dlm_rsb *r, int to_nodeid)
{
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	struct dlm_ls *ls = r->res_ls;
	int error;

	error = create_rcom(ls, to_nodeid, DLM_RCOM_LOOKUP, r->res_length,
			    &rc, &mh);
	if (error)
		goto out;
	memcpy(rc->rc_buf, r->res_name, r->res_length);
	rc->rc_id = 0xFFFFFFFF;

	send_rcom(ls, mh, rc);
 out:
	return error;
}

static void receive_rcom_lookup(struct dlm_ls *ls, struct dlm_rcom *rc_in)
{
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	int error, ret_nodeid, nodeid = rc_in->rc_header.h_nodeid;
	int len = rc_in->rc_header.h_length - sizeof(struct dlm_rcom);

	error = create_rcom(ls, nodeid, DLM_RCOM_LOOKUP_REPLY, 0, &rc, &mh);
	if (error)
		return;

	if (rc_in->rc_id == 0xFFFFFFFF) {
		log_error(ls, "receive_rcom_lookup dump from %d", nodeid);
		dlm_dump_rsb_name(ls, rc_in->rc_buf, len);
		return;
	}

	error = dlm_master_lookup(ls, nodeid, rc_in->rc_buf, len,
				  DLM_LU_RECOVER_MASTER, &ret_nodeid, NULL);
	if (error)
		ret_nodeid = error;
	rc->rc_result = ret_nodeid;
	rc->rc_id = rc_in->rc_id;
	rc->rc_seq_reply = rc_in->rc_seq;

	send_rcom(ls, mh, rc);
}

static void receive_rcom_lookup_reply(struct dlm_ls *ls, struct dlm_rcom *rc_in)
{
	dlm_recover_master_reply(ls, rc_in);
}

static void pack_rcom_lock(struct dlm_rsb *r, struct dlm_lkb *lkb,
			   struct rcom_lock *rl)
{
	memset(rl, 0, sizeof(*rl));

	rl->rl_ownpid = cpu_to_le32(lkb->lkb_ownpid);
	rl->rl_lkid = cpu_to_le32(lkb->lkb_id);
	rl->rl_exflags = cpu_to_le32(lkb->lkb_exflags);
	rl->rl_flags = cpu_to_le32(lkb->lkb_flags);
	rl->rl_lvbseq = cpu_to_le32(lkb->lkb_lvbseq);
	rl->rl_rqmode = lkb->lkb_rqmode;
	rl->rl_grmode = lkb->lkb_grmode;
	rl->rl_status = lkb->lkb_status;
	rl->rl_wait_type = cpu_to_le16(lkb->lkb_wait_type);

	if (lkb->lkb_bastfn)
		rl->rl_asts |= DLM_CB_BAST;
	if (lkb->lkb_astfn)
		rl->rl_asts |= DLM_CB_CAST;

	rl->rl_namelen = cpu_to_le16(r->res_length);
	memcpy(rl->rl_name, r->res_name, r->res_length);

	/* FIXME: might we have an lvb without DLM_LKF_VALBLK set ?
	   If so, receive_rcom_lock_args() won't take this copy. */

	if (lkb->lkb_lvbptr)
		memcpy(rl->rl_lvb, lkb->lkb_lvbptr, r->res_ls->ls_lvblen);
}

int dlm_send_rcom_lock(struct dlm_rsb *r, struct dlm_lkb *lkb)
{
	struct dlm_ls *ls = r->res_ls;
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	struct rcom_lock *rl;
	int error, len = sizeof(struct rcom_lock);

	if (lkb->lkb_lvbptr)
		len += ls->ls_lvblen;

	error = create_rcom(ls, r->res_nodeid, DLM_RCOM_LOCK, len, &rc, &mh);
	if (error)
		goto out;

	rl = (struct rcom_lock *) rc->rc_buf;
	pack_rcom_lock(r, lkb, rl);
	rc->rc_id = (unsigned long) r;

	send_rcom(ls, mh, rc);
 out:
	return error;
}

/* needs at least dlm_rcom + rcom_lock */
static void receive_rcom_lock(struct dlm_ls *ls, struct dlm_rcom *rc_in)
{
	struct dlm_rcom *rc;
	struct dlm_mhandle *mh;
	int error, nodeid = rc_in->rc_header.h_nodeid;

	dlm_recover_master_copy(ls, rc_in);

	error = create_rcom(ls, nodeid, DLM_RCOM_LOCK_REPLY,
			    sizeof(struct rcom_lock), &rc, &mh);
	if (error)
		return;

	/* We send back the same rcom_lock struct we received, but
	   dlm_recover_master_copy() has filled in rl_remid and rl_result */

	memcpy(rc->rc_buf, rc_in->rc_buf, sizeof(struct rcom_lock));
	rc->rc_id = rc_in->rc_id;
	rc->rc_seq_reply = rc_in->rc_seq;

	send_rcom(ls, mh, rc);
}

/* If the lockspace doesn't exist then still send a status message
   back; it's possible that it just doesn't have its global_id yet. */

int dlm_send_ls_not_ready(int nodeid, struct dlm_rcom *rc_in)
{
	struct dlm_rcom *rc;
	struct rcom_config *rf;
	struct dlm_mhandle *mh;
	char *mb;
	int mb_len = sizeof(struct dlm_rcom) + sizeof(struct rcom_config);

	mh = dlm_lowcomms_get_buffer(nodeid, mb_len, GFP_NOFS, &mb);
	if (!mh)
		return -ENOBUFS;
	memset(mb, 0, mb_len);

	rc = (struct dlm_rcom *) mb;

	rc->rc_header.h_version = (DLM_HEADER_MAJOR | DLM_HEADER_MINOR);
	rc->rc_header.h_lockspace = rc_in->rc_header.h_lockspace;
	rc->rc_header.h_nodeid = dlm_our_nodeid();
	rc->rc_header.h_length = mb_len;
	rc->rc_header.h_cmd = DLM_RCOM;

	rc->rc_type = DLM_RCOM_STATUS_REPLY;
	rc->rc_id = rc_in->rc_id;
	rc->rc_seq_reply = rc_in->rc_seq;
	rc->rc_result = -ESRCH;

	rf = (struct rcom_config *) rc->rc_buf;
	rf->rf_lvblen = cpu_to_le32(~0U);

	dlm_rcom_out(rc);
	dlm_lowcomms_commit_buffer(mh);

	return 0;
}

/*
 * Ignore messages for stage Y before we set
 * recover_status bit for stage X:
 *
 * recover_status = 0
 *
 * dlm_recover_members()
 * - send nothing
 * - recv nothing
 * - ignore NAMES, NAMES_REPLY
 * - ignore LOOKUP, LOOKUP_REPLY
 * - ignore LOCK, LOCK_REPLY
 *
 * recover_status |= NODES
 *
 * dlm_recover_members_wait()
 *
 * dlm_recover_directory()
 * - send NAMES
 * - recv NAMES_REPLY
 * - ignore LOOKUP, LOOKUP_REPLY
 * - ignore LOCK, LOCK_REPLY
 *
 * recover_status |= DIR
 *
 * dlm_recover_directory_wait()
 *
 * dlm_recover_masters()
 * - send LOOKUP
 * - recv LOOKUP_REPLY
 *
 * dlm_recover_locks()
 * - send LOCKS
 * - recv LOCKS_REPLY
 *
 * recover_status |= LOCKS
 *
 * dlm_recover_locks_wait()
 *
 * recover_status |= DONE
 */

/* Called by dlm_recv; corresponds to dlm_receive_message() but special
   recovery-only comms are sent through here. */

void dlm_receive_rcom(struct dlm_ls *ls, struct dlm_rcom *rc, int nodeid)
{
	int lock_size = sizeof(struct dlm_rcom) + sizeof(struct rcom_lock);
	int stop, reply = 0, names = 0, lookup = 0, lock = 0;
	uint32_t status;
	uint64_t seq;

	switch (rc->rc_type) {
	case DLM_RCOM_STATUS_REPLY:
		reply = 1;
		break;
	case DLM_RCOM_NAMES:
		names = 1;
		break;
	case DLM_RCOM_NAMES_REPLY:
		names = 1;
		reply = 1;
		break;
	case DLM_RCOM_LOOKUP:
		lookup = 1;
		break;
	case DLM_RCOM_LOOKUP_REPLY:
		lookup = 1;
		reply = 1;
		break;
	case DLM_RCOM_LOCK:
		lock = 1;
		break;
	case DLM_RCOM_LOCK_REPLY:
		lock = 1;
		reply = 1;
		break;
	};

	spin_lock(&ls->ls_recover_lock);
	status = ls->ls_recover_status;
	stop = test_bit(LSFL_RECOVER_STOP, &ls->ls_flags);
	seq = ls->ls_recover_seq;
	spin_unlock(&ls->ls_recover_lock);

	if (stop && (rc->rc_type != DLM_RCOM_STATUS))
		goto ignore;

	if (reply && (rc->rc_seq_reply != seq))
		goto ignore;

	if (!(status & DLM_RS_NODES) && (names || lookup || lock))
		goto ignore;

	if (!(status & DLM_RS_DIR) && (lookup || lock))
		goto ignore;

	switch (rc->rc_type) {
	case DLM_RCOM_STATUS:
		receive_rcom_status(ls, rc);
		break;

	case DLM_RCOM_NAMES:
		receive_rcom_names(ls, rc);
		break;

	case DLM_RCOM_LOOKUP:
		receive_rcom_lookup(ls, rc);
		break;

	case DLM_RCOM_LOCK:
		if (rc->rc_header.h_length < lock_size)
			goto Eshort;
		receive_rcom_lock(ls, rc);
		break;

	case DLM_RCOM_STATUS_REPLY:
		receive_sync_reply(ls, rc);
		break;

	case DLM_RCOM_NAMES_REPLY:
		receive_sync_reply(ls, rc);
		break;

	case DLM_RCOM_LOOKUP_REPLY:
		receive_rcom_lookup_reply(ls, rc);
		break;

	case DLM_RCOM_LOCK_REPLY:
		if (rc->rc_header.h_length < lock_size)
			goto Eshort;
		dlm_recover_process_copy(ls, rc);
		break;

	default:
		log_error(ls, "receive_rcom bad type %d", rc->rc_type);
	}
	return;

ignore:
	log_limit(ls, "dlm_receive_rcom ignore msg %d "
		  "from %d %llu %llu recover seq %llu sts %x gen %u",
		   rc->rc_type,
		   nodeid,
		   (unsigned long long)rc->rc_seq,
		   (unsigned long long)rc->rc_seq_reply,
		   (unsigned long long)seq,
		   status, ls->ls_generation);
	return;
Eshort:
	log_error(ls, "recovery message %d from %d is too short",
		  rc->rc_type, nodeid);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/rcom.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2005 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
// #include "lockspace.h"
// #include "dir.h"
// #include "config.h"
// #include "ast.h"
// #include "memory.h"
// #include "rcom.h"
// #include "lock.h"
// #include "lowcomms.h"
// #include "member.h"
// #include "recover.h"


/*
 * Recovery waiting routines: these functions wait for a particular reply from
 * a remote node, or for the remote node to report a certain status.  They need
 * to abort if the lockspace is stopped indicating a node has failed (perhaps
 * the one being waited for).
 */

/*
 * Wait until given function returns non-zero or lockspace is stopped
 * (LS_RECOVERY_STOP set due to failure of a node in ls_nodes).  When another
 * function thinks it could have completed the waited-on task, they should wake
 * up ls_wait_general to get an immediate response rather than waiting for the
 * timeout.  This uses a timeout so it can check periodically if the wait
 * should abort due to node failure (which doesn't cause a wake_up).
 * This should only be called by the dlm_recoverd thread.
 */

int dlm_wait_function(struct dlm_ls *ls, int (*testfn) (struct dlm_ls *ls))
{
	int error = 0;
	int rv;

	while (1) {
		rv = wait_event_timeout(ls->ls_wait_general,
					testfn(ls) || dlm_recovery_stopped(ls),
					dlm_config.ci_recover_timer * HZ);
		if (rv)
			break;
	}

	if (dlm_recovery_stopped(ls)) {
		log_debug(ls, "dlm_wait_function aborted");
		error = -EINTR;
	}
	return error;
}

/*
 * An efficient way for all nodes to wait for all others to have a certain
 * status.  The node with the lowest nodeid polls all the others for their
 * status (wait_status_all) and all the others poll the node with the low id
 * for its accumulated result (wait_status_low).  When all nodes have set
 * status flag X, then status flag X_ALL will be set on the low nodeid.
 */

uint32_t dlm_recover_status(struct dlm_ls *ls)
{
	uint32_t status;
	spin_lock(&ls->ls_recover_lock);
	status = ls->ls_recover_status;
	spin_unlock(&ls->ls_recover_lock);
	return status;
}

static void _set_recover_status(struct dlm_ls *ls, uint32_t status)
{
	ls->ls_recover_status |= status;
}

void dlm_set_recover_status(struct dlm_ls *ls, uint32_t status)
{
	spin_lock(&ls->ls_recover_lock);
	_set_recover_status(ls, status);
	spin_unlock(&ls->ls_recover_lock);
}

static int wait_status_all(struct dlm_ls *ls, uint32_t wait_status,
			   int save_slots)
{
	struct dlm_rcom *rc = ls->ls_recover_buf;
	struct dlm_member *memb;
	int error = 0, delay;

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		delay = 0;
		for (;;) {
			if (dlm_recovery_stopped(ls)) {
				error = -EINTR;
				goto out;
			}

			error = dlm_rcom_status(ls, memb->nodeid, 0);
			if (error)
				goto out;

			if (save_slots)
				dlm_slot_save(ls, rc, memb);

			if (rc->rc_result & wait_status)
				break;
			if (delay < 1000)
				delay += 20;
			msleep(delay);
		}
	}
 out:
	return error;
}

static int wait_status_low(struct dlm_ls *ls, uint32_t wait_status,
			   uint32_t status_flags)
{
	struct dlm_rcom *rc = ls->ls_recover_buf;
	int error = 0, delay = 0, nodeid = ls->ls_low_nodeid;

	for (;;) {
		if (dlm_recovery_stopped(ls)) {
			error = -EINTR;
			goto out;
		}

		error = dlm_rcom_status(ls, nodeid, status_flags);
		if (error)
			break;

		if (rc->rc_result & wait_status)
			break;
		if (delay < 1000)
			delay += 20;
		msleep(delay);
	}
 out:
	return error;
}

static int wait_status(struct dlm_ls *ls, uint32_t status)
{
	uint32_t status_all = status << 1;
	int error;

	if (ls->ls_low_nodeid == dlm_our_nodeid()) {
		error = wait_status_all(ls, status, 0);
		if (!error)
			dlm_set_recover_status(ls, status_all);
	} else
		error = wait_status_low(ls, status_all, 0);

	return error;
}

int dlm_recover_members_wait(struct dlm_ls *ls)
{
	struct dlm_member *memb;
	struct dlm_slot *slots;
	int num_slots, slots_size;
	int error, rv;
	uint32_t gen;

	list_for_each_entry(memb, &ls->ls_nodes, list) {
		memb->slot = -1;
		memb->generation = 0;
	}

	if (ls->ls_low_nodeid == dlm_our_nodeid()) {
		error = wait_status_all(ls, DLM_RS_NODES, 1);
		if (error)
			goto out;

		/* slots array is sparse, slots_size may be > num_slots */

		rv = dlm_slots_assign(ls, &num_slots, &slots_size, &slots, &gen);
		if (!rv) {
			spin_lock(&ls->ls_recover_lock);
			_set_recover_status(ls, DLM_RS_NODES_ALL);
			ls->ls_num_slots = num_slots;
			ls->ls_slots_size = slots_size;
			ls->ls_slots = slots;
			ls->ls_generation = gen;
			spin_unlock(&ls->ls_recover_lock);
		} else {
			dlm_set_recover_status(ls, DLM_RS_NODES_ALL);
		}
	} else {
		error = wait_status_low(ls, DLM_RS_NODES_ALL, DLM_RSF_NEED_SLOTS);
		if (error)
			goto out;

		dlm_slots_copy_in(ls);
	}
 out:
	return error;
}

int dlm_recover_directory_wait(struct dlm_ls *ls)
{
	return wait_status(ls, DLM_RS_DIR);
}

int dlm_recover_locks_wait(struct dlm_ls *ls)
{
	return wait_status(ls, DLM_RS_LOCKS);
}

int dlm_recover_done_wait(struct dlm_ls *ls)
{
	return wait_status(ls, DLM_RS_DONE);
}

/*
 * The recover_list contains all the rsb's for which we've requested the new
 * master nodeid.  As replies are returned from the resource directories the
 * rsb's are removed from the list.  When the list is empty we're done.
 *
 * The recover_list is later similarly used for all rsb's for which we've sent
 * new lkb's and need to receive new corresponding lkid's.
 *
 * We use the address of the rsb struct as a simple local identifier for the
 * rsb so we can match an rcom reply with the rsb it was sent for.
 */

static int recover_list_empty(struct dlm_ls *ls)
{
	int empty;

	spin_lock(&ls->ls_recover_list_lock);
	empty = list_empty(&ls->ls_recover_list);
	spin_unlock(&ls->ls_recover_list_lock);

	return empty;
}

static void recover_list_add(struct dlm_rsb *r)
{
	struct dlm_ls *ls = r->res_ls;

	spin_lock(&ls->ls_recover_list_lock);
	if (list_empty(&r->res_recover_list)) {
		list_add_tail(&r->res_recover_list, &ls->ls_recover_list);
		ls->ls_recover_list_count++;
		dlm_hold_rsb(r);
	}
	spin_unlock(&ls->ls_recover_list_lock);
}

static void recover_list_del(struct dlm_rsb *r)
{
	struct dlm_ls *ls = r->res_ls;

	spin_lock(&ls->ls_recover_list_lock);
	list_del_init(&r->res_recover_list);
	ls->ls_recover_list_count--;
	spin_unlock(&ls->ls_recover_list_lock);

	dlm_put_rsb(r);
}

static void recover_list_clear(struct dlm_ls *ls)
{
	struct dlm_rsb *r, *s;

	spin_lock(&ls->ls_recover_list_lock);
	list_for_each_entry_safe(r, s, &ls->ls_recover_list, res_recover_list) {
		list_del_init(&r->res_recover_list);
		r->res_recover_locks_count = 0;
		dlm_put_rsb(r);
		ls->ls_recover_list_count--;
	}

	if (ls->ls_recover_list_count != 0) {
		log_error(ls, "warning: recover_list_count %d",
			  ls->ls_recover_list_count);
		ls->ls_recover_list_count = 0;
	}
	spin_unlock(&ls->ls_recover_list_lock);
}

static int recover_idr_empty(struct dlm_ls *ls)
{
	int empty = 1;

	spin_lock(&ls->ls_recover_idr_lock);
	if (ls->ls_recover_list_count)
		empty = 0;
	spin_unlock(&ls->ls_recover_idr_lock);

	return empty;
}

static int recover_idr_add(struct dlm_rsb *r)
{
	struct dlm_ls *ls = r->res_ls;
	int rv;

	idr_preload(GFP_NOFS);
	spin_lock(&ls->ls_recover_idr_lock);
	if (r->res_id) {
		rv = -1;
		goto out_unlock;
	}
	rv = idr_alloc(&ls->ls_recover_idr, r, 1, 0, GFP_NOWAIT);
	if (rv < 0)
		goto out_unlock;

	r->res_id = rv;
	ls->ls_recover_list_count++;
	dlm_hold_rsb(r);
	rv = 0;
out_unlock:
	spin_unlock(&ls->ls_recover_idr_lock);
	idr_preload_end();
	return rv;
}

static void recover_idr_del(struct dlm_rsb *r)
{
	struct dlm_ls *ls = r->res_ls;

	spin_lock(&ls->ls_recover_idr_lock);
	idr_remove(&ls->ls_recover_idr, r->res_id);
	r->res_id = 0;
	ls->ls_recover_list_count--;
	spin_unlock(&ls->ls_recover_idr_lock);

	dlm_put_rsb(r);
}

static struct dlm_rsb *recover_idr_find(struct dlm_ls *ls, uint64_t id)
{
	struct dlm_rsb *r;

	spin_lock(&ls->ls_recover_idr_lock);
	r = idr_find(&ls->ls_recover_idr, (int)id);
	spin_unlock(&ls->ls_recover_idr_lock);
	return r;
}

static void recover_idr_clear(struct dlm_ls *ls)
{
	struct dlm_rsb *r;
	int id;

	spin_lock(&ls->ls_recover_idr_lock);

	idr_for_each_entry(&ls->ls_recover_idr, r, id) {
		idr_remove(&ls->ls_recover_idr, id);
		r->res_id = 0;
		r->res_recover_locks_count = 0;
		ls->ls_recover_list_count--;

		dlm_put_rsb(r);
	}

	if (ls->ls_recover_list_count != 0) {
		log_error(ls, "warning: recover_list_count %d",
			  ls->ls_recover_list_count);
		ls->ls_recover_list_count = 0;
	}
	spin_unlock(&ls->ls_recover_idr_lock);
}


/* Master recovery: find new master node for rsb's that were
   mastered on nodes that have been removed.

   dlm_recover_masters
   recover_master
   dlm_send_rcom_lookup            ->  receive_rcom_lookup
                                       dlm_dir_lookup
   receive_rcom_lookup_reply       <-
   dlm_recover_master_reply
   set_new_master
   set_master_lkbs
   set_lock_master
*/

/*
 * Set the lock master for all LKBs in a lock queue
 * If we are the new master of the rsb, we may have received new
 * MSTCPY locks from other nodes already which we need to ignore
 * when setting the new nodeid.
 */

static void set_lock_master(struct list_head *queue, int nodeid)
{
	struct dlm_lkb *lkb;

	list_for_each_entry(lkb, queue, lkb_statequeue) {
		if (!(lkb->lkb_flags & DLM_IFL_MSTCPY)) {
			lkb->lkb_nodeid = nodeid;
			lkb->lkb_remid = 0;
		}
	}
}

static void set_master_lkbs(struct dlm_rsb *r)
{
	set_lock_master(&r->res_grantqueue, r->res_nodeid);
	set_lock_master(&r->res_convertqueue, r->res_nodeid);
	set_lock_master(&r->res_waitqueue, r->res_nodeid);
}

/*
 * Propagate the new master nodeid to locks
 * The NEW_MASTER flag tells dlm_recover_locks() which rsb's to consider.
 * The NEW_MASTER2 flag tells recover_lvb() and recover_grant() which
 * rsb's to consider.
 */

static void set_new_master(struct dlm_rsb *r)
{
	set_master_lkbs(r);
	rsb_set_flag(r, RSB_NEW_MASTER);
	rsb_set_flag(r, RSB_NEW_MASTER2);
}

/*
 * We do async lookups on rsb's that need new masters.  The rsb's
 * waiting for a lookup reply are kept on the recover_list.
 *
 * Another node recovering the master may have sent us a rcom lookup,
 * and our dlm_master_lookup() set it as the new master, along with
 * NEW_MASTER so that we'll recover it here (this implies dir_nodeid
 * equals our_nodeid below).
 */

static int recover_master(struct dlm_rsb *r, unsigned int *count)
{
	struct dlm_ls *ls = r->res_ls;
	int our_nodeid, dir_nodeid;
	int is_removed = 0;
	int error;

	if (is_master(r))
		return 0;

	is_removed = dlm_is_removed(ls, r->res_nodeid);

	if (!is_removed && !rsb_flag(r, RSB_NEW_MASTER))
		return 0;

	our_nodeid = dlm_our_nodeid();
	dir_nodeid = dlm_dir_nodeid(r);

	if (dir_nodeid == our_nodeid) {
		if (is_removed) {
			r->res_master_nodeid = our_nodeid;
			r->res_nodeid = 0;
		}

		/* set master of lkbs to ourself when is_removed, or to
		   another new master which we set along with NEW_MASTER
		   in dlm_master_lookup */
		set_new_master(r);
		error = 0;
	} else {
		recover_idr_add(r);
		error = dlm_send_rcom_lookup(r, dir_nodeid);
	}

	(*count)++;
	return error;
}

/*
 * All MSTCPY locks are purged and rebuilt, even if the master stayed the same.
 * This is necessary because recovery can be started, aborted and restarted,
 * causing the master nodeid to briefly change during the aborted recovery, and
 * change back to the original value in the second recovery.  The MSTCPY locks
 * may or may not have been purged during the aborted recovery.  Another node
 * with an outstanding request in waiters list and a request reply saved in the
 * requestqueue, cannot know whether it should ignore the reply and resend the
 * request, or accept the reply and complete the request.  It must do the
 * former if the remote node purged MSTCPY locks, and it must do the later if
 * the remote node did not.  This is solved by always purging MSTCPY locks, in
 * which case, the request reply would always be ignored and the request
 * resent.
 */

static int recover_master_static(struct dlm_rsb *r, unsigned int *count)
{
	int dir_nodeid = dlm_dir_nodeid(r);
	int new_master = dir_nodeid;

	if (dir_nodeid == dlm_our_nodeid())
		new_master = 0;

	dlm_purge_mstcpy_locks(r);
	r->res_master_nodeid = dir_nodeid;
	r->res_nodeid = new_master;
	set_new_master(r);
	(*count)++;
	return 0;
}

/*
 * Go through local root resources and for each rsb which has a master which
 * has departed, get the new master nodeid from the directory.  The dir will
 * assign mastery to the first node to look up the new master.  That means
 * we'll discover in this lookup if we're the new master of any rsb's.
 *
 * We fire off all the dir lookup requests individually and asynchronously to
 * the correct dir node.
 */

int dlm_recover_masters(struct dlm_ls *ls)
{
	struct dlm_rsb *r;
	unsigned int total = 0;
	unsigned int count = 0;
	int nodir = dlm_no_directory(ls);
	int error;

	log_rinfo(ls, "dlm_recover_masters");

	down_read(&ls->ls_root_sem);
	list_for_each_entry(r, &ls->ls_root_list, res_root_list) {
		if (dlm_recovery_stopped(ls)) {
			up_read(&ls->ls_root_sem);
			error = -EINTR;
			goto out;
		}

		lock_rsb(r);
		if (nodir)
			error = recover_master_static(r, &count);
		else
			error = recover_master(r, &count);
		unlock_rsb(r);
		cond_resched();
		total++;

		if (error) {
			up_read(&ls->ls_root_sem);
			goto out;
		}
	}
	up_read(&ls->ls_root_sem);

	log_rinfo(ls, "dlm_recover_masters %u of %u", count, total);

	error = dlm_wait_function(ls, &recover_idr_empty);
 out:
	if (error)
		recover_idr_clear(ls);
	return error;
}

int dlm_recover_master_reply(struct dlm_ls *ls, struct dlm_rcom *rc)
{
	struct dlm_rsb *r;
	int ret_nodeid, new_master;

	r = recover_idr_find(ls, rc->rc_id);
	if (!r) {
		log_error(ls, "dlm_recover_master_reply no id %llx",
			  (unsigned long long)rc->rc_id);
		goto out;
	}

	ret_nodeid = rc->rc_result;

	if (ret_nodeid == dlm_our_nodeid())
		new_master = 0;
	else
		new_master = ret_nodeid;

	lock_rsb(r);
	r->res_master_nodeid = ret_nodeid;
	r->res_nodeid = new_master;
	set_new_master(r);
	unlock_rsb(r);
	recover_idr_del(r);

	if (recover_idr_empty(ls))
		wake_up(&ls->ls_wait_general);
 out:
	return 0;
}


/* Lock recovery: rebuild the process-copy locks we hold on a
   remastered rsb on the new rsb master.

   dlm_recover_locks
   recover_locks
   recover_locks_queue
   dlm_send_rcom_lock              ->  receive_rcom_lock
                                       dlm_recover_master_copy
   receive_rcom_lock_reply         <-
   dlm_recover_process_copy
*/


/*
 * keep a count of the number of lkb's we send to the new master; when we get
 * an equal number of replies then recovery for the rsb is done
 */

static int recover_locks_queue(struct dlm_rsb *r, struct list_head *head)
{
	struct dlm_lkb *lkb;
	int error = 0;

	list_for_each_entry(lkb, head, lkb_statequeue) {
	   	error = dlm_send_rcom_lock(r, lkb);
		if (error)
			break;
		r->res_recover_locks_count++;
	}

	return error;
}

static int recover_locks(struct dlm_rsb *r)
{
	int error = 0;

	lock_rsb(r);

	DLM_ASSERT(!r->res_recover_locks_count, dlm_dump_rsb(r););

	error = recover_locks_queue(r, &r->res_grantqueue);
	if (error)
		goto out;
	error = recover_locks_queue(r, &r->res_convertqueue);
	if (error)
		goto out;
	error = recover_locks_queue(r, &r->res_waitqueue);
	if (error)
		goto out;

	if (r->res_recover_locks_count)
		recover_list_add(r);
	else
		rsb_clear_flag(r, RSB_NEW_MASTER);
 out:
	unlock_rsb(r);
	return error;
}

int dlm_recover_locks(struct dlm_ls *ls)
{
	struct dlm_rsb *r;
	int error, count = 0;

	down_read(&ls->ls_root_sem);
	list_for_each_entry(r, &ls->ls_root_list, res_root_list) {
		if (is_master(r)) {
			rsb_clear_flag(r, RSB_NEW_MASTER);
			continue;
		}

		if (!rsb_flag(r, RSB_NEW_MASTER))
			continue;

		if (dlm_recovery_stopped(ls)) {
			error = -EINTR;
			up_read(&ls->ls_root_sem);
			goto out;
		}

		error = recover_locks(r);
		if (error) {
			up_read(&ls->ls_root_sem);
			goto out;
		}

		count += r->res_recover_locks_count;
	}
	up_read(&ls->ls_root_sem);

	log_rinfo(ls, "dlm_recover_locks %d out", count);

	error = dlm_wait_function(ls, &recover_list_empty);
 out:
	if (error)
		recover_list_clear(ls);
	return error;
}

void dlm_recovered_lock(struct dlm_rsb *r)
{
	DLM_ASSERT(rsb_flag(r, RSB_NEW_MASTER), dlm_dump_rsb(r););

	r->res_recover_locks_count--;
	if (!r->res_recover_locks_count) {
		rsb_clear_flag(r, RSB_NEW_MASTER);
		recover_list_del(r);
	}

	if (recover_list_empty(r->res_ls))
		wake_up(&r->res_ls->ls_wait_general);
}

/*
 * The lvb needs to be recovered on all master rsb's.  This includes setting
 * the VALNOTVALID flag if necessary, and determining the correct lvb contents
 * based on the lvb's of the locks held on the rsb.
 *
 * RSB_VALNOTVALID is set in two cases:
 *
 * 1. we are master, but not new, and we purged an EX/PW lock held by a
 * failed node (in dlm_recover_purge which set RSB_RECOVER_LVB_INVAL)
 *
 * 2. we are a new master, and there are only NL/CR locks left.
 * (We could probably improve this by only invaliding in this way when
 * the previous master left uncleanly.  VMS docs mention that.)
 *
 * The LVB contents are only considered for changing when this is a new master
 * of the rsb (NEW_MASTER2).  Then, the rsb's lvb is taken from any lkb with
 * mode > CR.  If no lkb's exist with mode above CR, the lvb contents are taken
 * from the lkb with the largest lvb sequence number.
 */

static void recover_lvb(struct dlm_rsb *r)
{
	struct dlm_lkb *lkb, *high_lkb = NULL;
	uint32_t high_seq = 0;
	int lock_lvb_exists = 0;
	int big_lock_exists = 0;
	int lvblen = r->res_ls->ls_lvblen;

	if (!rsb_flag(r, RSB_NEW_MASTER2) &&
	    rsb_flag(r, RSB_RECOVER_LVB_INVAL)) {
		/* case 1 above */
		rsb_set_flag(r, RSB_VALNOTVALID);
		return;
	}

	if (!rsb_flag(r, RSB_NEW_MASTER2))
		return;

	/* we are the new master, so figure out if VALNOTVALID should
	   be set, and set the rsb lvb from the best lkb available. */

	list_for_each_entry(lkb, &r->res_grantqueue, lkb_statequeue) {
		if (!(lkb->lkb_exflags & DLM_LKF_VALBLK))
			continue;

		lock_lvb_exists = 1;

		if (lkb->lkb_grmode > DLM_LOCK_CR) {
			big_lock_exists = 1;
			goto setflag;
		}

		if (((int)lkb->lkb_lvbseq - (int)high_seq) >= 0) {
			high_lkb = lkb;
			high_seq = lkb->lkb_lvbseq;
		}
	}

	list_for_each_entry(lkb, &r->res_convertqueue, lkb_statequeue) {
		if (!(lkb->lkb_exflags & DLM_LKF_VALBLK))
			continue;

		lock_lvb_exists = 1;

		if (lkb->lkb_grmode > DLM_LOCK_CR) {
			big_lock_exists = 1;
			goto setflag;
		}

		if (((int)lkb->lkb_lvbseq - (int)high_seq) >= 0) {
			high_lkb = lkb;
			high_seq = lkb->lkb_lvbseq;
		}
	}

 setflag:
	if (!lock_lvb_exists)
		goto out;

	/* lvb is invalidated if only NL/CR locks remain */
	if (!big_lock_exists)
		rsb_set_flag(r, RSB_VALNOTVALID);

	if (!r->res_lvbptr) {
		r->res_lvbptr = dlm_allocate_lvb(r->res_ls);
		if (!r->res_lvbptr)
			goto out;
	}

	if (big_lock_exists) {
		r->res_lvbseq = lkb->lkb_lvbseq;
		memcpy(r->res_lvbptr, lkb->lkb_lvbptr, lvblen);
	} else if (high_lkb) {
		r->res_lvbseq = high_lkb->lkb_lvbseq;
		memcpy(r->res_lvbptr, high_lkb->lkb_lvbptr, lvblen);
	} else {
		r->res_lvbseq = 0;
		memset(r->res_lvbptr, 0, lvblen);
	}
 out:
	return;
}

/* All master rsb's flagged RECOVER_CONVERT need to be looked at.  The locks
   converting PR->CW or CW->PR need to have their lkb_grmode set. */

static void recover_conversion(struct dlm_rsb *r)
{
	struct dlm_ls *ls = r->res_ls;
	struct dlm_lkb *lkb;
	int grmode = -1;

	list_for_each_entry(lkb, &r->res_grantqueue, lkb_statequeue) {
		if (lkb->lkb_grmode == DLM_LOCK_PR ||
		    lkb->lkb_grmode == DLM_LOCK_CW) {
			grmode = lkb->lkb_grmode;
			break;
		}
	}

	list_for_each_entry(lkb, &r->res_convertqueue, lkb_statequeue) {
		if (lkb->lkb_grmode != DLM_LOCK_IV)
			continue;
		if (grmode == -1) {
			log_debug(ls, "recover_conversion %x set gr to rq %d",
				  lkb->lkb_id, lkb->lkb_rqmode);
			lkb->lkb_grmode = lkb->lkb_rqmode;
		} else {
			log_debug(ls, "recover_conversion %x set gr %d",
				  lkb->lkb_id, grmode);
			lkb->lkb_grmode = grmode;
		}
	}
}

/* We've become the new master for this rsb and waiting/converting locks may
   need to be granted in dlm_recover_grant() due to locks that may have
   existed from a removed node. */

static void recover_grant(struct dlm_rsb *r)
{
	if (!list_empty(&r->res_waitqueue) || !list_empty(&r->res_convertqueue))
		rsb_set_flag(r, RSB_RECOVER_GRANT);
}

void dlm_recover_rsbs(struct dlm_ls *ls)
{
	struct dlm_rsb *r;
	unsigned int count = 0;

	down_read(&ls->ls_root_sem);
	list_for_each_entry(r, &ls->ls_root_list, res_root_list) {
		lock_rsb(r);
		if (is_master(r)) {
			if (rsb_flag(r, RSB_RECOVER_CONVERT))
				recover_conversion(r);

			/* recover lvb before granting locks so the updated
			   lvb/VALNOTVALID is presented in the completion */
			recover_lvb(r);

			if (rsb_flag(r, RSB_NEW_MASTER2))
				recover_grant(r);
			count++;
		} else {
			rsb_clear_flag(r, RSB_VALNOTVALID);
		}
		rsb_clear_flag(r, RSB_RECOVER_CONVERT);
		rsb_clear_flag(r, RSB_RECOVER_LVB_INVAL);
		rsb_clear_flag(r, RSB_NEW_MASTER2);
		unlock_rsb(r);
	}
	up_read(&ls->ls_root_sem);

	if (count)
		log_rinfo(ls, "dlm_recover_rsbs %d done", count);
}

/* Create a single list of all root rsb's to be used during recovery */

int dlm_create_root_list(struct dlm_ls *ls)
{
	struct rb_node *n;
	struct dlm_rsb *r;
	int i, error = 0;

	down_write(&ls->ls_root_sem);
	if (!list_empty(&ls->ls_root_list)) {
		log_error(ls, "root list not empty");
		error = -EINVAL;
		goto out;
	}

	for (i = 0; i < ls->ls_rsbtbl_size; i++) {
		spin_lock(&ls->ls_rsbtbl[i].lock);
		for (n = rb_first(&ls->ls_rsbtbl[i].keep); n; n = rb_next(n)) {
			r = rb_entry(n, struct dlm_rsb, res_hashnode);
			list_add(&r->res_root_list, &ls->ls_root_list);
			dlm_hold_rsb(r);
		}

		if (!RB_EMPTY_ROOT(&ls->ls_rsbtbl[i].toss))
			log_error(ls, "dlm_create_root_list toss not empty");
		spin_unlock(&ls->ls_rsbtbl[i].lock);
	}
 out:
	up_write(&ls->ls_root_sem);
	return error;
}

void dlm_release_root_list(struct dlm_ls *ls)
{
	struct dlm_rsb *r, *safe;

	down_write(&ls->ls_root_sem);
	list_for_each_entry_safe(r, safe, &ls->ls_root_list, res_root_list) {
		list_del_init(&r->res_root_list);
		dlm_put_rsb(r);
	}
	up_write(&ls->ls_root_sem);
}

void dlm_clear_toss(struct dlm_ls *ls)
{
	struct rb_node *n, *next;
	struct dlm_rsb *r;
	unsigned int count = 0;
	int i;

	for (i = 0; i < ls->ls_rsbtbl_size; i++) {
		spin_lock(&ls->ls_rsbtbl[i].lock);
		for (n = rb_first(&ls->ls_rsbtbl[i].toss); n; n = next) {
			next = rb_next(n);
			r = rb_entry(n, struct dlm_rsb, res_hashnode);
			rb_erase(n, &ls->ls_rsbtbl[i].toss);
			dlm_free_rsb(r);
			count++;
		}
		spin_unlock(&ls->ls_rsbtbl[i].lock);
	}

	if (count)
		log_rinfo(ls, "dlm_clear_toss %u done", count);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/recover.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
**  Copyright (C) 2004-2011 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
// #include "lockspace.h"
// #include "member.h"
// #include "dir.h"
// #include "ast.h"
// #include "recover.h"
// #include "lowcomms.h"
// #include "lock.h"
// #include "requestqueue.h"
// #include "recoverd.h"


/* If the start for which we're re-enabling locking (seq) has been superseded
   by a newer stop (ls_recover_seq), we need to leave locking disabled.

   We suspend dlm_recv threads here to avoid the race where dlm_recv a) sees
   locking stopped and b) adds a message to the requestqueue, but dlm_recoverd
   enables locking and clears the requestqueue between a and b. */

static int enable_locking(struct dlm_ls *ls, uint64_t seq)
{
	int error = -EINTR;

	down_write(&ls->ls_recv_active);

	spin_lock(&ls->ls_recover_lock);
	if (ls->ls_recover_seq == seq) {
		set_bit(LSFL_RUNNING, &ls->ls_flags);
		/* unblocks processes waiting to enter the dlm */
		up_write(&ls->ls_in_recovery);
		clear_bit(LSFL_RECOVER_LOCK, &ls->ls_flags);
		error = 0;
	}
	spin_unlock(&ls->ls_recover_lock);

	up_write(&ls->ls_recv_active);
	return error;
}

static int ls_recover(struct dlm_ls *ls, struct dlm_recover *rv)
{
	unsigned long start;
	int error, neg = 0;

	log_rinfo(ls, "dlm_recover %llu", (unsigned long long)rv->seq);

	mutex_lock(&ls->ls_recoverd_active);

	dlm_callback_suspend(ls);

	dlm_clear_toss(ls);

	/*
	 * This list of root rsb's will be the basis of most of the recovery
	 * routines.
	 */

	dlm_create_root_list(ls);

	/*
	 * Add or remove nodes from the lockspace's ls_nodes list.
	 */

	error = dlm_recover_members(ls, rv, &neg);
	if (error) {
		log_rinfo(ls, "dlm_recover_members error %d", error);
		goto fail;
	}

	dlm_recover_dir_nodeid(ls);

	ls->ls_recover_dir_sent_res = 0;
	ls->ls_recover_dir_sent_msg = 0;
	ls->ls_recover_locks_in = 0;

	dlm_set_recover_status(ls, DLM_RS_NODES);

	error = dlm_recover_members_wait(ls);
	if (error) {
		log_rinfo(ls, "dlm_recover_members_wait error %d", error);
		goto fail;
	}

	start = jiffies;

	/*
	 * Rebuild our own share of the directory by collecting from all other
	 * nodes their master rsb names that hash to us.
	 */

	error = dlm_recover_directory(ls);
	if (error) {
		log_rinfo(ls, "dlm_recover_directory error %d", error);
		goto fail;
	}

	dlm_set_recover_status(ls, DLM_RS_DIR);

	error = dlm_recover_directory_wait(ls);
	if (error) {
		log_rinfo(ls, "dlm_recover_directory_wait error %d", error);
		goto fail;
	}

	log_rinfo(ls, "dlm_recover_directory %u out %u messages",
		  ls->ls_recover_dir_sent_res, ls->ls_recover_dir_sent_msg);

	/*
	 * We may have outstanding operations that are waiting for a reply from
	 * a failed node.  Mark these to be resent after recovery.  Unlock and
	 * cancel ops can just be completed.
	 */

	dlm_recover_waiters_pre(ls);

	error = dlm_recovery_stopped(ls);
	if (error)
		goto fail;

	if (neg || dlm_no_directory(ls)) {
		/*
		 * Clear lkb's for departed nodes.
		 */

		dlm_recover_purge(ls);

		/*
		 * Get new master nodeid's for rsb's that were mastered on
		 * departed nodes.
		 */

		error = dlm_recover_masters(ls);
		if (error) {
			log_rinfo(ls, "dlm_recover_masters error %d", error);
			goto fail;
		}

		/*
		 * Send our locks on remastered rsb's to the new masters.
		 */

		error = dlm_recover_locks(ls);
		if (error) {
			log_rinfo(ls, "dlm_recover_locks error %d", error);
			goto fail;
		}

		dlm_set_recover_status(ls, DLM_RS_LOCKS);

		error = dlm_recover_locks_wait(ls);
		if (error) {
			log_rinfo(ls, "dlm_recover_locks_wait error %d", error);
			goto fail;
		}

		log_rinfo(ls, "dlm_recover_locks %u in",
			  ls->ls_recover_locks_in);

		/*
		 * Finalize state in master rsb's now that all locks can be
		 * checked.  This includes conversion resolution and lvb
		 * settings.
		 */

		dlm_recover_rsbs(ls);
	} else {
		/*
		 * Other lockspace members may be going through the "neg" steps
		 * while also adding us to the lockspace, in which case they'll
		 * be doing the recover_locks (RS_LOCKS) barrier.
		 */
		dlm_set_recover_status(ls, DLM_RS_LOCKS);

		error = dlm_recover_locks_wait(ls);
		if (error) {
			log_rinfo(ls, "dlm_recover_locks_wait error %d", error);
			goto fail;
		}
	}

	dlm_release_root_list(ls);

	/*
	 * Purge directory-related requests that are saved in requestqueue.
	 * All dir requests from before recovery are invalid now due to the dir
	 * rebuild and will be resent by the requesting nodes.
	 */

	dlm_purge_requestqueue(ls);

	dlm_set_recover_status(ls, DLM_RS_DONE);

	error = dlm_recover_done_wait(ls);
	if (error) {
		log_rinfo(ls, "dlm_recover_done_wait error %d", error);
		goto fail;
	}

	dlm_clear_members_gone(ls);

	dlm_adjust_timeouts(ls);

	dlm_callback_resume(ls);

	error = enable_locking(ls, rv->seq);
	if (error) {
		log_rinfo(ls, "enable_locking error %d", error);
		goto fail;
	}

	error = dlm_process_requestqueue(ls);
	if (error) {
		log_rinfo(ls, "dlm_process_requestqueue error %d", error);
		goto fail;
	}

	error = dlm_recover_waiters_post(ls);
	if (error) {
		log_rinfo(ls, "dlm_recover_waiters_post error %d", error);
		goto fail;
	}

	dlm_recover_grant(ls);

	log_rinfo(ls, "dlm_recover %llu generation %u done: %u ms",
		  (unsigned long long)rv->seq, ls->ls_generation,
		  jiffies_to_msecs(jiffies - start));
	mutex_unlock(&ls->ls_recoverd_active);

	dlm_lsop_recover_done(ls);
	return 0;

 fail:
	dlm_release_root_list(ls);
	log_rinfo(ls, "dlm_recover %llu error %d",
		  (unsigned long long)rv->seq, error);
	mutex_unlock(&ls->ls_recoverd_active);
	return error;
}

/* The dlm_ls_start() that created the rv we take here may already have been
   stopped via dlm_ls_stop(); in that case we need to leave the RECOVERY_STOP
   flag set. */

static void do_ls_recovery(struct dlm_ls *ls)
{
	struct dlm_recover *rv = NULL;

	spin_lock(&ls->ls_recover_lock);
	rv = ls->ls_recover_args;
	ls->ls_recover_args = NULL;
	if (rv && ls->ls_recover_seq == rv->seq)
		clear_bit(LSFL_RECOVER_STOP, &ls->ls_flags);
	spin_unlock(&ls->ls_recover_lock);

	if (rv) {
		ls_recover(ls, rv);
		kfree(rv->nodes);
		kfree(rv);
	}
}

static int dlm_recoverd(void *arg)
{
	struct dlm_ls *ls;

	ls = dlm_find_lockspace_local(arg);
	if (!ls) {
		log_print("dlm_recoverd: no lockspace %p", arg);
		return -1;
	}

	down_write(&ls->ls_in_recovery);
	set_bit(LSFL_RECOVER_LOCK, &ls->ls_flags);
	wake_up(&ls->ls_recover_lock_wait);

	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (!test_bit(LSFL_RECOVER_WORK, &ls->ls_flags) &&
		    !test_bit(LSFL_RECOVER_DOWN, &ls->ls_flags))
			schedule();
		set_current_state(TASK_RUNNING);

		if (test_and_clear_bit(LSFL_RECOVER_DOWN, &ls->ls_flags)) {
			down_write(&ls->ls_in_recovery);
			set_bit(LSFL_RECOVER_LOCK, &ls->ls_flags);
			wake_up(&ls->ls_recover_lock_wait);
		}

		if (test_and_clear_bit(LSFL_RECOVER_WORK, &ls->ls_flags))
			do_ls_recovery(ls);
	}

	if (test_bit(LSFL_RECOVER_LOCK, &ls->ls_flags))
		up_write(&ls->ls_in_recovery);

	dlm_put_lockspace(ls);
	return 0;
}

int dlm_recoverd_start(struct dlm_ls *ls)
{
	struct task_struct *p;
	int error = 0;

	p = kthread_run(dlm_recoverd, ls, "dlm_recoverd");
	if (IS_ERR(p))
		error = PTR_ERR(p);
	else
                ls->ls_recoverd_task = p;
	return error;
}

void dlm_recoverd_stop(struct dlm_ls *ls)
{
	kthread_stop(ls->ls_recoverd_task);
}

void dlm_recoverd_suspend(struct dlm_ls *ls)
{
	wake_up(&ls->ls_wait_general);
	mutex_lock(&ls->ls_recoverd_active);
}

void dlm_recoverd_resume(struct dlm_ls *ls)
{
	mutex_unlock(&ls->ls_recoverd_active);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/recoverd.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) 2005-2007 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
// #include "member.h"
// #include "lock.h"
// #include "dir.h"
// #include "config.h"
// #include "requestqueue.h"

struct rq_entry {
	struct list_head list;
	uint32_t recover_seq;
	int nodeid;
	struct dlm_message request;
};

/*
 * Requests received while the lockspace is in recovery get added to the
 * request queue and processed when recovery is complete.  This happens when
 * the lockspace is suspended on some nodes before it is on others, or the
 * lockspace is enabled on some while still suspended on others.
 */

void dlm_add_requestqueue(struct dlm_ls *ls, int nodeid, struct dlm_message *ms)
{
	struct rq_entry *e;
	int length = ms->m_header.h_length - sizeof(struct dlm_message);

	e = kmalloc(sizeof(struct rq_entry) + length, GFP_NOFS);
	if (!e) {
		log_print("dlm_add_requestqueue: out of memory len %d", length);
		return;
	}

	e->recover_seq = ls->ls_recover_seq & 0xFFFFFFFF;
	e->nodeid = nodeid;
	memcpy(&e->request, ms, ms->m_header.h_length);

	mutex_lock(&ls->ls_requestqueue_mutex);
	list_add_tail(&e->list, &ls->ls_requestqueue);
	mutex_unlock(&ls->ls_requestqueue_mutex);
}

/*
 * Called by dlm_recoverd to process normal messages saved while recovery was
 * happening.  Normal locking has been enabled before this is called.  dlm_recv
 * upon receiving a message, will wait for all saved messages to be drained
 * here before processing the message it got.  If a new dlm_ls_stop() arrives
 * while we're processing these saved messages, it may block trying to suspend
 * dlm_recv if dlm_recv is waiting for us in dlm_wait_requestqueue.  In that
 * case, we don't abort since locking_stopped is still 0.  If dlm_recv is not
 * waiting for us, then this processing may be aborted due to locking_stopped.
 */

int dlm_process_requestqueue(struct dlm_ls *ls)
{
	struct rq_entry *e;
	struct dlm_message *ms;
	int error = 0;

	mutex_lock(&ls->ls_requestqueue_mutex);

	for (;;) {
		if (list_empty(&ls->ls_requestqueue)) {
			mutex_unlock(&ls->ls_requestqueue_mutex);
			error = 0;
			break;
		}
		e = list_entry(ls->ls_requestqueue.next, struct rq_entry, list);
		mutex_unlock(&ls->ls_requestqueue_mutex);

		ms = &e->request;

		log_limit(ls, "dlm_process_requestqueue msg %d from %d "
			  "lkid %x remid %x result %d seq %u",
			  ms->m_type, ms->m_header.h_nodeid,
			  ms->m_lkid, ms->m_remid, ms->m_result,
			  e->recover_seq);

		dlm_receive_message_saved(ls, &e->request, e->recover_seq);

		mutex_lock(&ls->ls_requestqueue_mutex);
		list_del(&e->list);
		kfree(e);

		if (dlm_locking_stopped(ls)) {
			log_debug(ls, "process_requestqueue abort running");
			mutex_unlock(&ls->ls_requestqueue_mutex);
			error = -EINTR;
			break;
		}
		schedule();
	}

	return error;
}

/*
 * After recovery is done, locking is resumed and dlm_recoverd takes all the
 * saved requests and processes them as they would have been by dlm_recv.  At
 * the same time, dlm_recv will start receiving new requests from remote nodes.
 * We want to delay dlm_recv processing new requests until dlm_recoverd has
 * finished processing the old saved requests.  We don't check for locking
 * stopped here because dlm_ls_stop won't stop locking until it's suspended us
 * (dlm_recv).
 */

void dlm_wait_requestqueue(struct dlm_ls *ls)
{
	for (;;) {
		mutex_lock(&ls->ls_requestqueue_mutex);
		if (list_empty(&ls->ls_requestqueue))
			break;
		mutex_unlock(&ls->ls_requestqueue_mutex);
		schedule();
	}
	mutex_unlock(&ls->ls_requestqueue_mutex);
}

static int purge_request(struct dlm_ls *ls, struct dlm_message *ms, int nodeid)
{
	uint32_t type = ms->m_type;

	/* the ls is being cleaned up and freed by release_lockspace */
	if (!ls->ls_count)
		return 1;

	if (dlm_is_removed(ls, nodeid))
		return 1;

	/* directory operations are always purged because the directory is
	   always rebuilt during recovery and the lookups resent */

	if (type == DLM_MSG_REMOVE ||
	    type == DLM_MSG_LOOKUP ||
	    type == DLM_MSG_LOOKUP_REPLY)
		return 1;

	if (!dlm_no_directory(ls))
		return 0;

	return 1;
}

void dlm_purge_requestqueue(struct dlm_ls *ls)
{
	struct dlm_message *ms;
	struct rq_entry *e, *safe;

	mutex_lock(&ls->ls_requestqueue_mutex);
	list_for_each_entry_safe(e, safe, &ls->ls_requestqueue, list) {
		ms =  &e->request;

		if (purge_request(ls, ms, e->nodeid)) {
			list_del(&e->list);
			kfree(e);
		}
	}
	mutex_unlock(&ls->ls_requestqueue_mutex);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/requestqueue.c */
/************************************************************/
/*
 * Copyright (C) 2006-2010 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

// #include <linux/miscdevice.h>
#include <linux/init.h>
#include <linux/wait.h>
// #include <linux/module.h>
// #include <linux/file.h>
// #include <linux/fs.h>
// #include <linux/poll.h>
#include <linux/signal.h>
#include <linux/spinlock.h>
// #include <linux/dlm.h>
// #include <linux/dlm_device.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

// #include "dlm_internal.h"
// #include "lockspace.h"
// #include "lock.h"
// #include "lvb_table.h"
// #include "user.h"
// #include "ast.h"

static const char name_prefix[] = "dlm";
static const struct file_operations device_fops;
static atomic_t dlm_monitor_opened;
static int dlm_monitor_unused = 1;

#ifdef CONFIG_COMPAT

struct dlm_lock_params32 {
	__u8 mode;
	__u8 namelen;
	__u16 unused;
	__u32 flags;
	__u32 lkid;
	__u32 parent;
	__u64 xid;
	__u64 timeout;
	__u32 castparam;
	__u32 castaddr;
	__u32 bastparam;
	__u32 bastaddr;
	__u32 lksb;
	char lvb[DLM_USER_LVB_LEN];
	char name[0];
};

struct dlm_write_request32 {
	__u32 version[3];
	__u8 cmd;
	__u8 is64bit;
	__u8 unused[2];

	union  {
		struct dlm_lock_params32 lock;
		struct dlm_lspace_params lspace;
		struct dlm_purge_params purge;
	} i;
};

struct dlm_lksb32 {
	__u32 sb_status;
	__u32 sb_lkid;
	__u8 sb_flags;
	__u32 sb_lvbptr;
};

struct dlm_lock_result32 {
	__u32 version[3];
	__u32 length;
	__u32 user_astaddr;
	__u32 user_astparam;
	__u32 user_lksb;
	struct dlm_lksb32 lksb;
	__u8 bast_mode;
	__u8 unused[3];
	/* Offsets may be zero if no data is present */
	__u32 lvb_offset;
};

static void compat_input(struct dlm_write_request *kb,
			 struct dlm_write_request32 *kb32,
			 int namelen)
{
	kb->version[0] = kb32->version[0];
	kb->version[1] = kb32->version[1];
	kb->version[2] = kb32->version[2];

	kb->cmd = kb32->cmd;
	kb->is64bit = kb32->is64bit;
	if (kb->cmd == DLM_USER_CREATE_LOCKSPACE ||
	    kb->cmd == DLM_USER_REMOVE_LOCKSPACE) {
		kb->i.lspace.flags = kb32->i.lspace.flags;
		kb->i.lspace.minor = kb32->i.lspace.minor;
		memcpy(kb->i.lspace.name, kb32->i.lspace.name, namelen);
	} else if (kb->cmd == DLM_USER_PURGE) {
		kb->i.purge.nodeid = kb32->i.purge.nodeid;
		kb->i.purge.pid = kb32->i.purge.pid;
	} else {
		kb->i.lock.mode = kb32->i.lock.mode;
		kb->i.lock.namelen = kb32->i.lock.namelen;
		kb->i.lock.flags = kb32->i.lock.flags;
		kb->i.lock.lkid = kb32->i.lock.lkid;
		kb->i.lock.parent = kb32->i.lock.parent;
		kb->i.lock.xid = kb32->i.lock.xid;
		kb->i.lock.timeout = kb32->i.lock.timeout;
		kb->i.lock.castparam = (void *)(long)kb32->i.lock.castparam;
		kb->i.lock.castaddr = (void *)(long)kb32->i.lock.castaddr;
		kb->i.lock.bastparam = (void *)(long)kb32->i.lock.bastparam;
		kb->i.lock.bastaddr = (void *)(long)kb32->i.lock.bastaddr;
		kb->i.lock.lksb = (void *)(long)kb32->i.lock.lksb;
		memcpy(kb->i.lock.lvb, kb32->i.lock.lvb, DLM_USER_LVB_LEN);
		memcpy(kb->i.lock.name, kb32->i.lock.name, namelen);
	}
}

static void compat_output(struct dlm_lock_result *res,
			  struct dlm_lock_result32 *res32)
{
	res32->version[0] = res->version[0];
	res32->version[1] = res->version[1];
	res32->version[2] = res->version[2];

	res32->user_astaddr = (__u32)(long)res->user_astaddr;
	res32->user_astparam = (__u32)(long)res->user_astparam;
	res32->user_lksb = (__u32)(long)res->user_lksb;
	res32->bast_mode = res->bast_mode;

	res32->lvb_offset = res->lvb_offset;
	res32->length = res->length;

	res32->lksb.sb_status = res->lksb.sb_status;
	res32->lksb.sb_flags = res->lksb.sb_flags;
	res32->lksb.sb_lkid = res->lksb.sb_lkid;
	res32->lksb.sb_lvbptr = (__u32)(long)res->lksb.sb_lvbptr;
}
#endif

/* Figure out if this lock is at the end of its life and no longer
   available for the application to use.  The lkb still exists until
   the final ast is read.  A lock becomes EOL in three situations:
     1. a noqueue request fails with EAGAIN
     2. an unlock completes with EUNLOCK
     3. a cancel of a waiting request completes with ECANCEL/EDEADLK
   An EOL lock needs to be removed from the process's list of locks.
   And we can't allow any new operation on an EOL lock.  This is
   not related to the lifetime of the lkb struct which is managed
   entirely by refcount. */

static int lkb_is_endoflife(int mode, int status)
{
	switch (status) {
	case -DLM_EUNLOCK:
		return 1;
	case -DLM_ECANCEL:
	case -ETIMEDOUT:
	case -EDEADLK:
	case -EAGAIN:
		if (mode == DLM_LOCK_IV)
			return 1;
		break;
	}
	return 0;
}

/* we could possibly check if the cancel of an orphan has resulted in the lkb
   being removed and then remove that lkb from the orphans list and free it */

void dlm_user_add_ast(struct dlm_lkb *lkb, uint32_t flags, int mode,
		      int status, uint32_t sbflags, uint64_t seq)
{
	struct dlm_ls *ls;
	struct dlm_user_args *ua;
	struct dlm_user_proc *proc;
	int rv;

	if (lkb->lkb_flags & (DLM_IFL_ORPHAN | DLM_IFL_DEAD))
		return;

	ls = lkb->lkb_resource->res_ls;
	mutex_lock(&ls->ls_clear_proc_locks);

	/* If ORPHAN/DEAD flag is set, it means the process is dead so an ast
	   can't be delivered.  For ORPHAN's, dlm_clear_proc_locks() freed
	   lkb->ua so we can't try to use it.  This second check is necessary
	   for cases where a completion ast is received for an operation that
	   began before clear_proc_locks did its cancel/unlock. */

	if (lkb->lkb_flags & (DLM_IFL_ORPHAN | DLM_IFL_DEAD))
		goto out;

	DLM_ASSERT(lkb->lkb_ua, dlm_print_lkb(lkb););
	ua = lkb->lkb_ua;
	proc = ua->proc;

	if ((flags & DLM_CB_BAST) && ua->bastaddr == NULL)
		goto out;

	if ((flags & DLM_CB_CAST) && lkb_is_endoflife(mode, status))
		lkb->lkb_flags |= DLM_IFL_ENDOFLIFE;

	spin_lock(&proc->asts_spin);

	rv = dlm_add_lkb_callback(lkb, flags, mode, status, sbflags, seq);
	if (rv < 0) {
		spin_unlock(&proc->asts_spin);
		goto out;
	}

	if (list_empty(&lkb->lkb_cb_list)) {
		kref_get(&lkb->lkb_ref);
		list_add_tail(&lkb->lkb_cb_list, &proc->asts);
		wake_up_interruptible(&proc->wait);
	}
	spin_unlock(&proc->asts_spin);

	if (lkb->lkb_flags & DLM_IFL_ENDOFLIFE) {
		/* N.B. spin_lock locks_spin, not asts_spin */
		spin_lock(&proc->locks_spin);
		if (!list_empty(&lkb->lkb_ownqueue)) {
			list_del_init(&lkb->lkb_ownqueue);
			dlm_put_lkb(lkb);
		}
		spin_unlock(&proc->locks_spin);
	}
 out:
	mutex_unlock(&ls->ls_clear_proc_locks);
}

static int device_user_lock(struct dlm_user_proc *proc,
			    struct dlm_lock_params *params)
{
	struct dlm_ls *ls;
	struct dlm_user_args *ua;
	uint32_t lkid;
	int error = -ENOMEM;

	ls = dlm_find_lockspace_local(proc->lockspace);
	if (!ls)
		return -ENOENT;

	if (!params->castaddr || !params->lksb) {
		error = -EINVAL;
		goto out;
	}

	ua = kzalloc(sizeof(struct dlm_user_args), GFP_NOFS);
	if (!ua)
		goto out;
	ua->proc = proc;
	ua->user_lksb = params->lksb;
	ua->castparam = params->castparam;
	ua->castaddr = params->castaddr;
	ua->bastparam = params->bastparam;
	ua->bastaddr = params->bastaddr;
	ua->xid = params->xid;

	if (params->flags & DLM_LKF_CONVERT) {
		error = dlm_user_convert(ls, ua,
				         params->mode, params->flags,
				         params->lkid, params->lvb,
					 (unsigned long) params->timeout);
	} else if (params->flags & DLM_LKF_ORPHAN) {
		error = dlm_user_adopt_orphan(ls, ua,
					 params->mode, params->flags,
					 params->name, params->namelen,
					 (unsigned long) params->timeout,
					 &lkid);
		if (!error)
			error = lkid;
	} else {
		error = dlm_user_request(ls, ua,
					 params->mode, params->flags,
					 params->name, params->namelen,
					 (unsigned long) params->timeout);
		if (!error)
			error = ua->lksb.sb_lkid;
	}
 out:
	dlm_put_lockspace(ls);
	return error;
}

static int device_user_unlock(struct dlm_user_proc *proc,
			      struct dlm_lock_params *params)
{
	struct dlm_ls *ls;
	struct dlm_user_args *ua;
	int error = -ENOMEM;

	ls = dlm_find_lockspace_local(proc->lockspace);
	if (!ls)
		return -ENOENT;

	ua = kzalloc(sizeof(struct dlm_user_args), GFP_NOFS);
	if (!ua)
		goto out;
	ua->proc = proc;
	ua->user_lksb = params->lksb;
	ua->castparam = params->castparam;
	ua->castaddr = params->castaddr;

	if (params->flags & DLM_LKF_CANCEL)
		error = dlm_user_cancel(ls, ua, params->flags, params->lkid);
	else
		error = dlm_user_unlock(ls, ua, params->flags, params->lkid,
					params->lvb);
 out:
	dlm_put_lockspace(ls);
	return error;
}

static int device_user_deadlock(struct dlm_user_proc *proc,
				struct dlm_lock_params *params)
{
	struct dlm_ls *ls;
	int error;

	ls = dlm_find_lockspace_local(proc->lockspace);
	if (!ls)
		return -ENOENT;

	error = dlm_user_deadlock(ls, params->flags, params->lkid);

	dlm_put_lockspace(ls);
	return error;
}

static int dlm_device_register(struct dlm_ls *ls, char *name)
{
	int error, len;

	/* The device is already registered.  This happens when the
	   lockspace is created multiple times from userspace. */
	if (ls->ls_device.name)
		return 0;

	error = -ENOMEM;
	len = strlen(name) + strlen(name_prefix) + 2;
	ls->ls_device.name = kzalloc(len, GFP_NOFS);
	if (!ls->ls_device.name)
		goto fail;

	snprintf((char *)ls->ls_device.name, len, "%s_%s", name_prefix,
		 name);
	ls->ls_device.fops = &device_fops;
	ls->ls_device.minor = MISC_DYNAMIC_MINOR;

	error = misc_register(&ls->ls_device);
	if (error) {
		kfree(ls->ls_device.name);
	}
fail:
	return error;
}

int dlm_device_deregister(struct dlm_ls *ls)
{
	int error;

	/* The device is not registered.  This happens when the lockspace
	   was never used from userspace, or when device_create_lockspace()
	   calls dlm_release_lockspace() after the register fails. */
	if (!ls->ls_device.name)
		return 0;

	error = misc_deregister(&ls->ls_device);
	if (!error)
		kfree(ls->ls_device.name);
	return error;
}

static int device_user_purge(struct dlm_user_proc *proc,
			     struct dlm_purge_params *params)
{
	struct dlm_ls *ls;
	int error;

	ls = dlm_find_lockspace_local(proc->lockspace);
	if (!ls)
		return -ENOENT;

	error = dlm_user_purge(ls, proc, params->nodeid, params->pid);

	dlm_put_lockspace(ls);
	return error;
}

static int device_create_lockspace(struct dlm_lspace_params *params)
{
	dlm_lockspace_t *lockspace;
	struct dlm_ls *ls;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	error = dlm_new_lockspace(params->name, NULL, params->flags,
				  DLM_USER_LVB_LEN, NULL, NULL, NULL,
				  &lockspace);
	if (error)
		return error;

	ls = dlm_find_lockspace_local(lockspace);
	if (!ls)
		return -ENOENT;

	error = dlm_device_register(ls, params->name);
	dlm_put_lockspace(ls);

	if (error)
		dlm_release_lockspace(lockspace, 0);
	else
		error = ls->ls_device.minor;

	return error;
}

static int device_remove_lockspace(struct dlm_lspace_params *params)
{
	dlm_lockspace_t *lockspace;
	struct dlm_ls *ls;
	int error, force = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ls = dlm_find_lockspace_device(params->minor);
	if (!ls)
		return -ENOENT;

	if (params->flags & DLM_USER_LSFLG_FORCEFREE)
		force = 2;

	lockspace = ls->ls_local_handle;
	dlm_put_lockspace(ls);

	/* The final dlm_release_lockspace waits for references to go to
	   zero, so all processes will need to close their device for the
	   ls before the release will proceed.  release also calls the
	   device_deregister above.  Converting a positive return value
	   from release to zero means that userspace won't know when its
	   release was the final one, but it shouldn't need to know. */

	error = dlm_release_lockspace(lockspace, force);
	if (error > 0)
		error = 0;
	return error;
}

/* Check the user's version matches ours */
static int check_version(struct dlm_write_request *req)
{
	if (req->version[0] != DLM_DEVICE_VERSION_MAJOR ||
	    (req->version[0] == DLM_DEVICE_VERSION_MAJOR &&
	     req->version[1] > DLM_DEVICE_VERSION_MINOR)) {

		printk(KERN_DEBUG "dlm: process %s (%d) version mismatch "
		       "user (%d.%d.%d) kernel (%d.%d.%d)\n",
		       current->comm,
		       task_pid_nr(current),
		       req->version[0],
		       req->version[1],
		       req->version[2],
		       DLM_DEVICE_VERSION_MAJOR,
		       DLM_DEVICE_VERSION_MINOR,
		       DLM_DEVICE_VERSION_PATCH);
		return -EINVAL;
	}
	return 0;
}

/*
 * device_write
 *
 *   device_user_lock
 *     dlm_user_request -> request_lock
 *     dlm_user_convert -> convert_lock
 *
 *   device_user_unlock
 *     dlm_user_unlock -> unlock_lock
 *     dlm_user_cancel -> cancel_lock
 *
 *   device_create_lockspace
 *     dlm_new_lockspace
 *
 *   device_remove_lockspace
 *     dlm_release_lockspace
 */

/* a write to a lockspace device is a lock or unlock request, a write
   to the control device is to create/remove a lockspace */

static ssize_t device_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct dlm_user_proc *proc = file->private_data;
	struct dlm_write_request *kbuf;
	int error;

#ifdef CONFIG_COMPAT
	if (count < sizeof(struct dlm_write_request32))
#else
	if (count < sizeof(struct dlm_write_request))
#endif
		return -EINVAL;

	/*
	 * can't compare against COMPAT/dlm_write_request32 because
	 * we don't yet know if is64bit is zero
	 */
	if (count > sizeof(struct dlm_write_request) + DLM_RESNAME_MAXLEN)
		return -EINVAL;

	kbuf = kzalloc(count + 1, GFP_NOFS);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, count)) {
		error = -EFAULT;
		goto out_free;
	}

	if (check_version(kbuf)) {
		error = -EBADE;
		goto out_free;
	}

#ifdef CONFIG_COMPAT
	if (!kbuf->is64bit) {
		struct dlm_write_request32 *k32buf;
		int namelen = 0;

		if (count > sizeof(struct dlm_write_request32))
			namelen = count - sizeof(struct dlm_write_request32);

		k32buf = (struct dlm_write_request32 *)kbuf;

		/* add 1 after namelen so that the name string is terminated */
		kbuf = kzalloc(sizeof(struct dlm_write_request) + namelen + 1,
			       GFP_NOFS);
		if (!kbuf) {
			kfree(k32buf);
			return -ENOMEM;
		}

		if (proc)
			set_bit(DLM_PROC_FLAGS_COMPAT, &proc->flags);

		compat_input(kbuf, k32buf, namelen);
		kfree(k32buf);
	}
#endif

	/* do we really need this? can a write happen after a close? */
	if ((kbuf->cmd == DLM_USER_LOCK || kbuf->cmd == DLM_USER_UNLOCK) &&
	    (proc && test_bit(DLM_PROC_FLAGS_CLOSING, &proc->flags))) {
		error = -EINVAL;
		goto out_free;
	}

	error = -EINVAL;

	switch (kbuf->cmd)
	{
	case DLM_USER_LOCK:
		if (!proc) {
			log_print("no locking on control device");
			goto out_free;
		}
		error = device_user_lock(proc, &kbuf->i.lock);
		break;

	case DLM_USER_UNLOCK:
		if (!proc) {
			log_print("no locking on control device");
			goto out_free;
		}
		error = device_user_unlock(proc, &kbuf->i.lock);
		break;

	case DLM_USER_DEADLOCK:
		if (!proc) {
			log_print("no locking on control device");
			goto out_free;
		}
		error = device_user_deadlock(proc, &kbuf->i.lock);
		break;

	case DLM_USER_CREATE_LOCKSPACE:
		if (proc) {
			log_print("create/remove only on control device");
			goto out_free;
		}
		error = device_create_lockspace(&kbuf->i.lspace);
		break;

	case DLM_USER_REMOVE_LOCKSPACE:
		if (proc) {
			log_print("create/remove only on control device");
			goto out_free;
		}
		error = device_remove_lockspace(&kbuf->i.lspace);
		break;

	case DLM_USER_PURGE:
		if (!proc) {
			log_print("no locking on control device");
			goto out_free;
		}
		error = device_user_purge(proc, &kbuf->i.purge);
		break;

	default:
		log_print("Unknown command passed to DLM device : %d\n",
			  kbuf->cmd);
	}

 out_free:
	kfree(kbuf);
	return error;
}

/* Every process that opens the lockspace device has its own "proc" structure
   hanging off the open file that's used to keep track of locks owned by the
   process and asts that need to be delivered to the process. */

static int device_open(struct inode *inode, struct file *file)
{
	struct dlm_user_proc *proc;
	struct dlm_ls *ls;

	ls = dlm_find_lockspace_device(iminor(inode));
	if (!ls)
		return -ENOENT;

	proc = kzalloc(sizeof(struct dlm_user_proc), GFP_NOFS);
	if (!proc) {
		dlm_put_lockspace(ls);
		return -ENOMEM;
	}

	proc->lockspace = ls->ls_local_handle;
	INIT_LIST_HEAD(&proc->asts);
	INIT_LIST_HEAD(&proc->locks);
	INIT_LIST_HEAD(&proc->unlocking);
	spin_lock_init(&proc->asts_spin);
	spin_lock_init(&proc->locks_spin);
	init_waitqueue_head(&proc->wait);
	file->private_data = proc;

	return 0;
}

static int device_close(struct inode *inode, struct file *file)
{
	struct dlm_user_proc *proc = file->private_data;
	struct dlm_ls *ls;

	ls = dlm_find_lockspace_local(proc->lockspace);
	if (!ls)
		return -ENOENT;

	set_bit(DLM_PROC_FLAGS_CLOSING, &proc->flags);

	dlm_clear_proc_locks(ls, proc);

	/* at this point no more lkb's should exist for this lockspace,
	   so there's no chance of dlm_user_add_ast() being called and
	   looking for lkb->ua->proc */

	kfree(proc);
	file->private_data = NULL;

	dlm_put_lockspace(ls);
	dlm_put_lockspace(ls);  /* for the find in device_open() */

	/* FIXME: AUTOFREE: if this ls is no longer used do
	   device_remove_lockspace() */

	return 0;
}

static int copy_result_to_user(struct dlm_user_args *ua, int compat,
			       uint32_t flags, int mode, int copy_lvb,
			       char __user *buf, size_t count)
{
#ifdef CONFIG_COMPAT
	struct dlm_lock_result32 result32;
#endif
	struct dlm_lock_result result;
	void *resultptr;
	int error=0;
	int len;
	int struct_len;

	memset(&result, 0, sizeof(struct dlm_lock_result));
	result.version[0] = DLM_DEVICE_VERSION_MAJOR;
	result.version[1] = DLM_DEVICE_VERSION_MINOR;
	result.version[2] = DLM_DEVICE_VERSION_PATCH;
	memcpy(&result.lksb, &ua->lksb, sizeof(struct dlm_lksb));
	result.user_lksb = ua->user_lksb;

	/* FIXME: dlm1 provides for the user's bastparam/addr to not be updated
	   in a conversion unless the conversion is successful.  See code
	   in dlm_user_convert() for updating ua from ua_tmp.  OpenVMS, though,
	   notes that a new blocking AST address and parameter are set even if
	   the conversion fails, so maybe we should just do that. */

	if (flags & DLM_CB_BAST) {
		result.user_astaddr = ua->bastaddr;
		result.user_astparam = ua->bastparam;
		result.bast_mode = mode;
	} else {
		result.user_astaddr = ua->castaddr;
		result.user_astparam = ua->castparam;
	}

#ifdef CONFIG_COMPAT
	if (compat)
		len = sizeof(struct dlm_lock_result32);
	else
#endif
		len = sizeof(struct dlm_lock_result);
	struct_len = len;

	/* copy lvb to userspace if there is one, it's been updated, and
	   the user buffer has space for it */

	if (copy_lvb && ua->lksb.sb_lvbptr && count >= len + DLM_USER_LVB_LEN) {
		if (copy_to_user(buf+len, ua->lksb.sb_lvbptr,
				 DLM_USER_LVB_LEN)) {
			error = -EFAULT;
			goto out;
		}

		result.lvb_offset = len;
		len += DLM_USER_LVB_LEN;
	}

	result.length = len;
	resultptr = &result;
#ifdef CONFIG_COMPAT
	if (compat) {
		compat_output(&result, &result32);
		resultptr = &result32;
	}
#endif

	if (copy_to_user(buf, resultptr, struct_len))
		error = -EFAULT;
	else
		error = len;
 out:
	return error;
}

static int copy_version_to_user(char __user *buf, size_t count)
{
	struct dlm_device_version ver;

	memset(&ver, 0, sizeof(struct dlm_device_version));
	ver.version[0] = DLM_DEVICE_VERSION_MAJOR;
	ver.version[1] = DLM_DEVICE_VERSION_MINOR;
	ver.version[2] = DLM_DEVICE_VERSION_PATCH;

	if (copy_to_user(buf, &ver, sizeof(struct dlm_device_version)))
		return -EFAULT;
	return sizeof(struct dlm_device_version);
}

/* a read returns a single ast described in a struct dlm_lock_result */

static ssize_t device_read(struct file *file, char __user *buf, size_t count,
			   loff_t *ppos)
{
	struct dlm_user_proc *proc = file->private_data;
	struct dlm_lkb *lkb;
	DECLARE_WAITQUEUE(wait, current);
	struct dlm_callback cb;
	int rv, resid, copy_lvb = 0;

	if (count == sizeof(struct dlm_device_version)) {
		rv = copy_version_to_user(buf, count);
		return rv;
	}

	if (!proc) {
		log_print("non-version read from control device %zu", count);
		return -EINVAL;
	}

#ifdef CONFIG_COMPAT
	if (count < sizeof(struct dlm_lock_result32))
#else
	if (count < sizeof(struct dlm_lock_result))
#endif
		return -EINVAL;

 try_another:

	/* do we really need this? can a read happen after a close? */
	if (test_bit(DLM_PROC_FLAGS_CLOSING, &proc->flags))
		return -EINVAL;

	spin_lock(&proc->asts_spin);
	if (list_empty(&proc->asts)) {
		if (file->f_flags & O_NONBLOCK) {
			spin_unlock(&proc->asts_spin);
			return -EAGAIN;
		}

		add_wait_queue(&proc->wait, &wait);

	repeat:
		set_current_state(TASK_INTERRUPTIBLE);
		if (list_empty(&proc->asts) && !signal_pending(current)) {
			spin_unlock(&proc->asts_spin);
			schedule();
			spin_lock(&proc->asts_spin);
			goto repeat;
		}
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&proc->wait, &wait);

		if (signal_pending(current)) {
			spin_unlock(&proc->asts_spin);
			return -ERESTARTSYS;
		}
	}

	/* if we empty lkb_callbacks, we don't want to unlock the spinlock
	   without removing lkb_cb_list; so empty lkb_cb_list is always
	   consistent with empty lkb_callbacks */

	lkb = list_entry(proc->asts.next, struct dlm_lkb, lkb_cb_list);

	rv = dlm_rem_lkb_callback(lkb->lkb_resource->res_ls, lkb, &cb, &resid);
	if (rv < 0) {
		/* this shouldn't happen; lkb should have been removed from
		   list when resid was zero */
		log_print("dlm_rem_lkb_callback empty %x", lkb->lkb_id);
		list_del_init(&lkb->lkb_cb_list);
		spin_unlock(&proc->asts_spin);
		/* removes ref for proc->asts, may cause lkb to be freed */
		dlm_put_lkb(lkb);
		goto try_another;
	}
	if (!resid)
		list_del_init(&lkb->lkb_cb_list);
	spin_unlock(&proc->asts_spin);

	if (cb.flags & DLM_CB_SKIP) {
		/* removes ref for proc->asts, may cause lkb to be freed */
		if (!resid)
			dlm_put_lkb(lkb);
		goto try_another;
	}

	if (cb.flags & DLM_CB_CAST) {
		int old_mode, new_mode;

		old_mode = lkb->lkb_last_cast.mode;
		new_mode = cb.mode;

		if (!cb.sb_status && lkb->lkb_lksb->sb_lvbptr &&
		    dlm_lvb_operations[old_mode + 1][new_mode + 1])
			copy_lvb = 1;

		lkb->lkb_lksb->sb_status = cb.sb_status;
		lkb->lkb_lksb->sb_flags = cb.sb_flags;
	}

	rv = copy_result_to_user(lkb->lkb_ua,
				 test_bit(DLM_PROC_FLAGS_COMPAT, &proc->flags),
				 cb.flags, cb.mode, copy_lvb, buf, count);

	/* removes ref for proc->asts, may cause lkb to be freed */
	if (!resid)
		dlm_put_lkb(lkb);

	return rv;
}

static unsigned int device_poll(struct file *file, poll_table *wait)
{
	struct dlm_user_proc *proc = file->private_data;

	poll_wait(file, &proc->wait, wait);

	spin_lock(&proc->asts_spin);
	if (!list_empty(&proc->asts)) {
		spin_unlock(&proc->asts_spin);
		return POLLIN | POLLRDNORM;
	}
	spin_unlock(&proc->asts_spin);
	return 0;
}

int dlm_user_daemon_available(void)
{
	/* dlm_controld hasn't started (or, has started, but not
	   properly populated configfs) */

	if (!dlm_our_nodeid())
		return 0;

	/* This is to deal with versions of dlm_controld that don't
	   know about the monitor device.  We assume that if the
	   dlm_controld was started (above), but the monitor device
	   was never opened, that it's an old version.  dlm_controld
	   should open the monitor device before populating configfs. */

	if (dlm_monitor_unused)
		return 1;

	return atomic_read(&dlm_monitor_opened) ? 1 : 0;
}

static int ctl_device_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static int ctl_device_close(struct inode *inode, struct file *file)
{
	return 0;
}

static int monitor_device_open(struct inode *inode, struct file *file)
{
	atomic_inc(&dlm_monitor_opened);
	dlm_monitor_unused = 0;
	return 0;
}

static int monitor_device_close(struct inode *inode, struct file *file)
{
	if (atomic_dec_and_test(&dlm_monitor_opened))
		dlm_stop_lockspaces();
	return 0;
}

static const struct file_operations device_fops = {
	.open    = device_open,
	.release = device_close,
	.read    = device_read,
	.write   = device_write,
	.poll    = device_poll,
	.owner   = THIS_MODULE,
	.llseek  = noop_llseek,
};

static const struct file_operations ctl_device_fops = {
	.open    = ctl_device_open,
	.release = ctl_device_close,
	.read    = device_read,
	.write   = device_write,
	.owner   = THIS_MODULE,
	.llseek  = noop_llseek,
};

static struct miscdevice ctl_device = {
	.name  = "dlm-control",
	.fops  = &ctl_device_fops,
	.minor = MISC_DYNAMIC_MINOR,
};

static const struct file_operations monitor_device_fops = {
	.open    = monitor_device_open,
	.release = monitor_device_close,
	.owner   = THIS_MODULE,
	.llseek  = noop_llseek,
};

static struct miscdevice monitor_device = {
	.name  = "dlm-monitor",
	.fops  = &monitor_device_fops,
	.minor = MISC_DYNAMIC_MINOR,
};

int __init dlm_user_init(void)
{
	int error;

	atomic_set(&dlm_monitor_opened, 0);

	error = misc_register(&ctl_device);
	if (error) {
		log_print("misc_register failed for control device");
		goto out;
	}

	error = misc_register(&monitor_device);
	if (error) {
		log_print("misc_register failed for monitor device");
		misc_deregister(&ctl_device);
	}
 out:
	return error;
}

void dlm_user_exit(void)
{
	misc_deregister(&ctl_device);
	misc_deregister(&monitor_device);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/user.c */
/************************************************************/
/******************************************************************************
*******************************************************************************
**
**  Copyright (C) 2005-2008 Red Hat, Inc.  All rights reserved.
**
**  This copyrighted material is made available to anyone wishing to use,
**  modify, copy, or redistribute it subject to the terms and conditions
**  of the GNU General Public License v.2.
**
*******************************************************************************
******************************************************************************/

// #include "dlm_internal.h"
// #include "rcom.h"
// #include "util.h"

#define DLM_ERRNO_EDEADLK		35
#define DLM_ERRNO_EBADR			53
#define DLM_ERRNO_EBADSLT		57
#define DLM_ERRNO_EPROTO		71
#define DLM_ERRNO_EOPNOTSUPP		95
#define DLM_ERRNO_ETIMEDOUT	       110
#define DLM_ERRNO_EINPROGRESS	       115

static void header_out(struct dlm_header *hd)
{
	hd->h_version		= cpu_to_le32(hd->h_version);
	hd->h_lockspace		= cpu_to_le32(hd->h_lockspace);
	hd->h_nodeid		= cpu_to_le32(hd->h_nodeid);
	hd->h_length		= cpu_to_le16(hd->h_length);
}

static void header_in(struct dlm_header *hd)
{
	hd->h_version		= le32_to_cpu(hd->h_version);
	hd->h_lockspace		= le32_to_cpu(hd->h_lockspace);
	hd->h_nodeid		= le32_to_cpu(hd->h_nodeid);
	hd->h_length		= le16_to_cpu(hd->h_length);
}

/* higher errno values are inconsistent across architectures, so select
   one set of values for on the wire */

static int to_dlm_errno(int err)
{
	switch (err) {
	case -EDEADLK:
		return -DLM_ERRNO_EDEADLK;
	case -EBADR:
		return -DLM_ERRNO_EBADR;
	case -EBADSLT:
		return -DLM_ERRNO_EBADSLT;
	case -EPROTO:
		return -DLM_ERRNO_EPROTO;
	case -EOPNOTSUPP:
		return -DLM_ERRNO_EOPNOTSUPP;
	case -ETIMEDOUT:
		return -DLM_ERRNO_ETIMEDOUT;
	case -EINPROGRESS:
		return -DLM_ERRNO_EINPROGRESS;
	}
	return err;
}

static int from_dlm_errno(int err)
{
	switch (err) {
	case -DLM_ERRNO_EDEADLK:
		return -EDEADLK;
	case -DLM_ERRNO_EBADR:
		return -EBADR;
	case -DLM_ERRNO_EBADSLT:
		return -EBADSLT;
	case -DLM_ERRNO_EPROTO:
		return -EPROTO;
	case -DLM_ERRNO_EOPNOTSUPP:
		return -EOPNOTSUPP;
	case -DLM_ERRNO_ETIMEDOUT:
		return -ETIMEDOUT;
	case -DLM_ERRNO_EINPROGRESS:
		return -EINPROGRESS;
	}
	return err;
}

void dlm_message_out(struct dlm_message *ms)
{
	header_out(&ms->m_header);

	ms->m_type		= cpu_to_le32(ms->m_type);
	ms->m_nodeid		= cpu_to_le32(ms->m_nodeid);
	ms->m_pid		= cpu_to_le32(ms->m_pid);
	ms->m_lkid		= cpu_to_le32(ms->m_lkid);
	ms->m_remid		= cpu_to_le32(ms->m_remid);
	ms->m_parent_lkid	= cpu_to_le32(ms->m_parent_lkid);
	ms->m_parent_remid	= cpu_to_le32(ms->m_parent_remid);
	ms->m_exflags		= cpu_to_le32(ms->m_exflags);
	ms->m_sbflags		= cpu_to_le32(ms->m_sbflags);
	ms->m_flags		= cpu_to_le32(ms->m_flags);
	ms->m_lvbseq		= cpu_to_le32(ms->m_lvbseq);
	ms->m_hash		= cpu_to_le32(ms->m_hash);
	ms->m_status		= cpu_to_le32(ms->m_status);
	ms->m_grmode		= cpu_to_le32(ms->m_grmode);
	ms->m_rqmode		= cpu_to_le32(ms->m_rqmode);
	ms->m_bastmode		= cpu_to_le32(ms->m_bastmode);
	ms->m_asts		= cpu_to_le32(ms->m_asts);
	ms->m_result		= cpu_to_le32(to_dlm_errno(ms->m_result));
}

void dlm_message_in(struct dlm_message *ms)
{
	header_in(&ms->m_header);

	ms->m_type		= le32_to_cpu(ms->m_type);
	ms->m_nodeid		= le32_to_cpu(ms->m_nodeid);
	ms->m_pid		= le32_to_cpu(ms->m_pid);
	ms->m_lkid		= le32_to_cpu(ms->m_lkid);
	ms->m_remid		= le32_to_cpu(ms->m_remid);
	ms->m_parent_lkid	= le32_to_cpu(ms->m_parent_lkid);
	ms->m_parent_remid	= le32_to_cpu(ms->m_parent_remid);
	ms->m_exflags		= le32_to_cpu(ms->m_exflags);
	ms->m_sbflags		= le32_to_cpu(ms->m_sbflags);
	ms->m_flags		= le32_to_cpu(ms->m_flags);
	ms->m_lvbseq		= le32_to_cpu(ms->m_lvbseq);
	ms->m_hash		= le32_to_cpu(ms->m_hash);
	ms->m_status		= le32_to_cpu(ms->m_status);
	ms->m_grmode		= le32_to_cpu(ms->m_grmode);
	ms->m_rqmode		= le32_to_cpu(ms->m_rqmode);
	ms->m_bastmode		= le32_to_cpu(ms->m_bastmode);
	ms->m_asts		= le32_to_cpu(ms->m_asts);
	ms->m_result		= from_dlm_errno(le32_to_cpu(ms->m_result));
}

void dlm_rcom_out(struct dlm_rcom *rc)
{
	header_out(&rc->rc_header);

	rc->rc_type		= cpu_to_le32(rc->rc_type);
	rc->rc_result		= cpu_to_le32(rc->rc_result);
	rc->rc_id		= cpu_to_le64(rc->rc_id);
	rc->rc_seq		= cpu_to_le64(rc->rc_seq);
	rc->rc_seq_reply	= cpu_to_le64(rc->rc_seq_reply);
}

void dlm_rcom_in(struct dlm_rcom *rc)
{
	header_in(&rc->rc_header);

	rc->rc_type		= le32_to_cpu(rc->rc_type);
	rc->rc_result		= le32_to_cpu(rc->rc_result);
	rc->rc_id		= le64_to_cpu(rc->rc_id);
	rc->rc_seq		= le64_to_cpu(rc->rc_seq);
	rc->rc_seq_reply	= le64_to_cpu(rc->rc_seq_reply);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/dlm/util.c */
/************************************************************/
