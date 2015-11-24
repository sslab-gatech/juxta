/* -*- c -*- --------------------------------------------------------------- *
 *
 * linux/fs/autofs/init.c
 *
 *  Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

#include <linux/module.h>
#include <linux/init.h>
#include "autofs_i.h"
#include "../../inc/__fss.h"

static struct dentry *autofs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, autofs4_fill_super);
}

static struct file_system_type autofs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "autofs",
	.mount		= autofs_mount,
	.kill_sb	= autofs4_kill_sb,
};
MODULE_ALIAS_FS("autofs");

static int __init init_autofs4_fs(void)
{
	int err;

	autofs_dev_ioctl_init();

	err = register_filesystem(&autofs_fs_type);
	if (err)
		autofs_dev_ioctl_exit();

	return err;
}

static void __exit exit_autofs4_fs(void)
{
	autofs_dev_ioctl_exit();
	unregister_filesystem(&autofs_fs_type);
}

module_init(init_autofs4_fs) 
module_exit(exit_autofs4_fs)
MODULE_LICENSE("GPL");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/autofs4/init.c */
/************************************************************/
/* -*- c -*- --------------------------------------------------------------- *
 *
 * linux/fs/autofs/inode.c
 *
 *  Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 *  Copyright 2005-2006 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/pagemap.h>
#include <linux/parser.h>
#include <linux/bitops.h>
#include <linux/magic.h>
// #include "autofs_i.h"
// #include <linux/module.h>
#include "../../inc/__fss.h"

struct autofs_info *autofs4_new_ino(struct autofs_sb_info *sbi)
{
	struct autofs_info *ino = kzalloc(sizeof(*ino), GFP_KERNEL);
	if (ino) {
		INIT_LIST_HEAD(&ino->active);
		INIT_LIST_HEAD(&ino->expiring);
		ino->last_used = jiffies;
		ino->sbi = sbi;
	}
	return ino;
}

void autofs4_clean_ino(struct autofs_info *ino)
{
	ino->uid = GLOBAL_ROOT_UID;
	ino->gid = GLOBAL_ROOT_GID;
	ino->last_used = jiffies;
}

void autofs4_free_ino(struct autofs_info *ino)
{
	kfree(ino);
}

void autofs4_kill_sb(struct super_block *sb)
{
	struct autofs_sb_info *sbi = autofs4_sbi(sb);

	/*
	 * In the event of a failure in get_sb_nodev the superblock
	 * info is not present so nothing else has been setup, so
	 * just call kill_anon_super when we are called from
	 * deactivate_super.
	 */
	if (sbi) {
		/* Free wait queues, close pipe */
		autofs4_catatonic_mode(sbi);
		put_pid(sbi->oz_pgrp);
	}

	DPRINTK("shutting down");
	kill_litter_super(sb);
	if (sbi)
		kfree_rcu(sbi, rcu);
}

static int autofs4_show_options(struct seq_file *m, struct dentry *root)
{
	struct autofs_sb_info *sbi = autofs4_sbi(root->d_sb);
	struct inode *root_inode = root->d_sb->s_root->d_inode;

	if (!sbi)
		return 0;

	seq_printf(m, ",fd=%d", sbi->pipefd);
	if (!uid_eq(root_inode->i_uid, GLOBAL_ROOT_UID))
		seq_printf(m, ",uid=%u",
			from_kuid_munged(&init_user_ns, root_inode->i_uid));
	if (!gid_eq(root_inode->i_gid, GLOBAL_ROOT_GID))
		seq_printf(m, ",gid=%u",
			from_kgid_munged(&init_user_ns, root_inode->i_gid));
	seq_printf(m, ",pgrp=%d", pid_vnr(sbi->oz_pgrp));
	seq_printf(m, ",timeout=%lu", sbi->exp_timeout/HZ);
	seq_printf(m, ",minproto=%d", sbi->min_proto);
	seq_printf(m, ",maxproto=%d", sbi->max_proto);

	if (autofs_type_offset(sbi->type))
		seq_printf(m, ",offset");
	else if (autofs_type_direct(sbi->type))
		seq_printf(m, ",direct");
	else
		seq_printf(m, ",indirect");

	return 0;
}

static void autofs4_evict_inode(struct inode *inode)
{
	clear_inode(inode);
	kfree(inode->i_private);
}

static const struct super_operations autofs4_sops = {
	.statfs		= simple_statfs,
	.show_options	= autofs4_show_options,
	.evict_inode	= autofs4_evict_inode,
};

enum {Opt_err, Opt_fd, Opt_uid, Opt_gid, Opt_pgrp, Opt_minproto, Opt_maxproto,
	Opt_indirect, Opt_direct, Opt_offset};

static const match_table_t tokens = {
	{Opt_fd, "fd=%u"},
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_pgrp, "pgrp=%u"},
	{Opt_minproto, "minproto=%u"},
	{Opt_maxproto, "maxproto=%u"},
	{Opt_indirect, "indirect"},
	{Opt_direct, "direct"},
	{Opt_offset, "offset"},
	{Opt_err, NULL}
};

static int parse_options(char *options, int *pipefd, kuid_t *uid, kgid_t *gid,
			 int *pgrp, bool *pgrp_set, unsigned int *type,
			 int *minproto, int *maxproto)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;

	*uid = current_uid();
	*gid = current_gid();

	*minproto = AUTOFS_MIN_PROTO_VERSION;
	*maxproto = AUTOFS_MAX_PROTO_VERSION;

	*pipefd = -1;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_fd:
			if (match_int(args, pipefd))
				return 1;
			break;
		case Opt_uid:
			if (match_int(args, &option))
				return 1;
			*uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(*uid))
				return 1;
			break;
		case Opt_gid:
			if (match_int(args, &option))
				return 1;
			*gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(*gid))
				return 1;
			break;
		case Opt_pgrp:
			if (match_int(args, &option))
				return 1;
			*pgrp = option;
			*pgrp_set = true;
			break;
		case Opt_minproto:
			if (match_int(args, &option))
				return 1;
			*minproto = option;
			break;
		case Opt_maxproto:
			if (match_int(args, &option))
				return 1;
			*maxproto = option;
			break;
		case Opt_indirect:
			set_autofs_type_indirect(type);
			break;
		case Opt_direct:
			set_autofs_type_direct(type);
			break;
		case Opt_offset:
			set_autofs_type_offset(type);
			break;
		default:
			return 1;
		}
	}
	return (*pipefd < 0);
}

int autofs4_fill_super(struct super_block *s, void *data, int silent)
{
	struct inode * root_inode;
	struct dentry * root;
	struct file * pipe;
	int pipefd;
	struct autofs_sb_info *sbi;
	struct autofs_info *ino;
	int pgrp = 0;
	bool pgrp_set = false;
	int ret = -EINVAL;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	DPRINTK("starting up, sbi = %p",sbi);

	s->s_fs_info = sbi;
	sbi->magic = AUTOFS_SBI_MAGIC;
	sbi->pipefd = -1;
	sbi->pipe = NULL;
	sbi->catatonic = 1;
	sbi->exp_timeout = 0;
	sbi->oz_pgrp = NULL;
	sbi->sb = s;
	sbi->version = 0;
	sbi->sub_version = 0;
	set_autofs_type_indirect(&sbi->type);
	sbi->min_proto = 0;
	sbi->max_proto = 0;
	mutex_init(&sbi->wq_mutex);
	mutex_init(&sbi->pipe_mutex);
	spin_lock_init(&sbi->fs_lock);
	sbi->queues = NULL;
	spin_lock_init(&sbi->lookup_lock);
	INIT_LIST_HEAD(&sbi->active_list);
	INIT_LIST_HEAD(&sbi->expiring_list);
	s->s_blocksize = 1024;
	s->s_blocksize_bits = 10;
	s->s_magic = AUTOFS_SUPER_MAGIC;
	s->s_op = &autofs4_sops;
	s->s_d_op = &autofs4_dentry_operations;
	s->s_time_gran = 1;

	/*
	 * Get the root inode and dentry, but defer checking for errors.
	 */
	ino = autofs4_new_ino(sbi);
	if (!ino) {
		ret = -ENOMEM;
		goto fail_free;
	}
	root_inode = autofs4_get_inode(s, S_IFDIR | 0755);
	root = d_make_root(root_inode);
	if (!root)
		goto fail_ino;
	pipe = NULL;

	root->d_fsdata = ino;

	/* Can this call block? */
	if (parse_options(data, &pipefd, &root_inode->i_uid, &root_inode->i_gid,
			  &pgrp, &pgrp_set, &sbi->type, &sbi->min_proto,
			  &sbi->max_proto)) {
		printk("autofs: called with bogus options\n");
		goto fail_dput;
	}

	if (pgrp_set) {
		sbi->oz_pgrp = find_get_pid(pgrp);
		if (!sbi->oz_pgrp) {
			pr_warn("autofs: could not find process group %d\n",
				pgrp);
			goto fail_dput;
		}
	} else {
		sbi->oz_pgrp = get_task_pid(current, PIDTYPE_PGID);
	}

	if (autofs_type_trigger(sbi->type))
		__managed_dentry_set_managed(root);

	root_inode->i_fop = &autofs4_root_operations;
	root_inode->i_op = &autofs4_dir_inode_operations;

	/* Couldn't this be tested earlier? */
	if (sbi->max_proto < AUTOFS_MIN_PROTO_VERSION ||
	    sbi->min_proto > AUTOFS_MAX_PROTO_VERSION) {
		printk("autofs: kernel does not match daemon version "
		       "daemon (%d, %d) kernel (%d, %d)\n",
			sbi->min_proto, sbi->max_proto,
			AUTOFS_MIN_PROTO_VERSION, AUTOFS_MAX_PROTO_VERSION);
		goto fail_dput;
	}

	/* Establish highest kernel protocol version */
	if (sbi->max_proto > AUTOFS_MAX_PROTO_VERSION)
		sbi->version = AUTOFS_MAX_PROTO_VERSION;
	else
		sbi->version = sbi->max_proto;
	sbi->sub_version = AUTOFS_PROTO_SUBVERSION;

	DPRINTK("pipe fd = %d, pgrp = %u", pipefd, pid_nr(sbi->oz_pgrp));
	pipe = fget(pipefd);

	if (!pipe) {
		printk("autofs: could not open pipe file descriptor\n");
		goto fail_dput;
	}
	ret = autofs_prepare_pipe(pipe);
	if (ret < 0)
		goto fail_fput;
	sbi->pipe = pipe;
	sbi->pipefd = pipefd;
	sbi->catatonic = 0;

	/*
	 * Success! Install the root dentry now to indicate completion.
	 */
	s->s_root = root;
	return 0;
	
	/*
	 * Failure ... clean up.
	 */
fail_fput:
	printk("autofs: pipe file descriptor does not contain proper ops\n");
	fput(pipe);
	/* fall through */
fail_dput:
	dput(root);
	goto fail_free;
fail_ino:
	kfree(ino);
fail_free:
	put_pid(sbi->oz_pgrp);
	kfree(sbi);
	s->s_fs_info = NULL;
	return ret;
}

struct inode *autofs4_get_inode(struct super_block *sb, umode_t mode)
{
	struct inode *inode = new_inode(sb);

	if (inode == NULL)
		return NULL;

	inode->i_mode = mode;
	if (sb->s_root) {
		inode->i_uid = sb->s_root->d_inode->i_uid;
		inode->i_gid = sb->s_root->d_inode->i_gid;
	}
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_ino = get_next_ino();

	if (S_ISDIR(mode)) {
		set_nlink(inode, 2);
		inode->i_op = &autofs4_dir_inode_operations;
		inode->i_fop = &autofs4_dir_operations;
	} else if (S_ISLNK(mode)) {
		inode->i_op = &autofs4_symlink_inode_operations;
	}

	return inode;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/autofs4/inode.c */
/************************************************************/
/* -*- c -*- --------------------------------------------------------------- *
 *
 * linux/fs/autofs/root.c
 *
 *  Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 *  Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *  Copyright 2001-2006 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/stat.h>
// #include <linux/slab.h>
#include <linux/param.h>
#include <linux/time.h>
#include <linux/compat.h>
#include <linux/mutex.h>
#include "../../inc/__fss.h"

// #include "autofs_i.h"

static int autofs4_dir_symlink(struct inode *,struct dentry *,const char *);
static int autofs4_dir_unlink(struct inode *,struct dentry *);
static int autofs4_dir_rmdir(struct inode *,struct dentry *);
static int autofs4_dir_mkdir(struct inode *,struct dentry *,umode_t);
static long autofs4_root_ioctl(struct file *,unsigned int,unsigned long);
#ifdef CONFIG_COMPAT
static long autofs4_root_compat_ioctl(struct file *,unsigned int,unsigned long);
#endif
static int autofs4_dir_open(struct inode *inode, struct file *file);
static struct dentry *autofs4_lookup(struct inode *,struct dentry *, unsigned int);
static struct vfsmount *autofs4_d_automount(struct path *);
static int autofs4_d_manage(struct dentry *, bool);
static void autofs4_dentry_release(struct dentry *);

const struct file_operations autofs4_root_operations = {
	.open		= dcache_dir_open,
	.release	= dcache_dir_close,
	.read		= generic_read_dir,
	.iterate	= dcache_readdir,
	.llseek		= dcache_dir_lseek,
	.unlocked_ioctl	= autofs4_root_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= autofs4_root_compat_ioctl,
#endif
};

const struct file_operations autofs4_dir_operations = {
	.open		= autofs4_dir_open,
	.release	= dcache_dir_close,
	.read		= generic_read_dir,
	.iterate	= dcache_readdir,
	.llseek		= dcache_dir_lseek,
};

const struct inode_operations autofs4_dir_inode_operations = {
	.lookup		= autofs4_lookup,
	.unlink		= autofs4_dir_unlink,
	.symlink	= autofs4_dir_symlink,
	.mkdir		= autofs4_dir_mkdir,
	.rmdir		= autofs4_dir_rmdir,
};

const struct dentry_operations autofs4_dentry_operations = {
	.d_automount	= autofs4_d_automount,
	.d_manage	= autofs4_d_manage,
	.d_release	= autofs4_dentry_release,
};

static void autofs4_add_active(struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	if (ino) {
		spin_lock(&sbi->lookup_lock);
		if (!ino->active_count) {
			if (list_empty(&ino->active))
				list_add(&ino->active, &sbi->active_list);
		}
		ino->active_count++;
		spin_unlock(&sbi->lookup_lock);
	}
	return;
}

static void autofs4_del_active(struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	if (ino) {
		spin_lock(&sbi->lookup_lock);
		ino->active_count--;
		if (!ino->active_count) {
			if (!list_empty(&ino->active))
				list_del_init(&ino->active);
		}
		spin_unlock(&sbi->lookup_lock);
	}
	return;
}

static int autofs4_dir_open(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);

	DPRINTK("file=%p dentry=%p %pd", file, dentry, dentry);

	if (autofs4_oz_mode(sbi))
		goto out;

	/*
	 * An empty directory in an autofs file system is always a
	 * mount point. The daemon must have failed to mount this
	 * during lookup so it doesn't exist. This can happen, for
	 * example, if user space returns an incorrect status for a
	 * mount request. Otherwise we're doing a readdir on the
	 * autofs file system so just let the libfs routines handle
	 * it.
	 */
	spin_lock(&sbi->lookup_lock);
	if (!d_mountpoint(dentry) && simple_empty(dentry)) {
		spin_unlock(&sbi->lookup_lock);
		return -ENOENT;
	}
	spin_unlock(&sbi->lookup_lock);

out:
	return dcache_dir_open(inode, file);
}

static void autofs4_dentry_release(struct dentry *de)
{
	struct autofs_info *ino = autofs4_dentry_ino(de);
	struct autofs_sb_info *sbi = autofs4_sbi(de->d_sb);

	DPRINTK("releasing %p", de);

	if (!ino)
		return;

	if (sbi) {
		spin_lock(&sbi->lookup_lock);
		if (!list_empty(&ino->active))
			list_del(&ino->active);
		if (!list_empty(&ino->expiring))
			list_del(&ino->expiring);
		spin_unlock(&sbi->lookup_lock);
	}

	autofs4_free_ino(ino);
}

static struct dentry *autofs4_lookup_active(struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct dentry *parent = dentry->d_parent;
	struct qstr *name = &dentry->d_name;
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct list_head *p, *head;

	head = &sbi->active_list;
	if (list_empty(head))
		return NULL;
	spin_lock(&sbi->lookup_lock);
	list_for_each(p, head) {
		struct autofs_info *ino;
		struct dentry *active;
		struct qstr *qstr;

		ino = list_entry(p, struct autofs_info, active);
		active = ino->dentry;

		spin_lock(&active->d_lock);

		/* Already gone? */
		if ((int) d_count(active) <= 0)
			goto next;

		qstr = &active->d_name;

		if (active->d_name.hash != hash)
			goto next;
		if (active->d_parent != parent)
			goto next;

		if (qstr->len != len)
			goto next;
		if (memcmp(qstr->name, str, len))
			goto next;

		if (d_unhashed(active)) {
			dget_dlock(active);
			spin_unlock(&active->d_lock);
			spin_unlock(&sbi->lookup_lock);
			return active;
		}
next:
		spin_unlock(&active->d_lock);
	}
	spin_unlock(&sbi->lookup_lock);

	return NULL;
}

static struct dentry *autofs4_lookup_expiring(struct dentry *dentry,
					      bool rcu_walk)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct dentry *parent = dentry->d_parent;
	struct qstr *name = &dentry->d_name;
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct list_head *p, *head;

	head = &sbi->expiring_list;
	if (list_empty(head))
		return NULL;
	spin_lock(&sbi->lookup_lock);
	list_for_each(p, head) {
		struct autofs_info *ino;
		struct dentry *expiring;
		struct qstr *qstr;

		if (rcu_walk) {
			spin_unlock(&sbi->lookup_lock);
			return ERR_PTR(-ECHILD);
		}

		ino = list_entry(p, struct autofs_info, expiring);
		expiring = ino->dentry;

		spin_lock(&expiring->d_lock);

		/* We've already been dentry_iput or unlinked */
		if (!expiring->d_inode)
			goto next;

		qstr = &expiring->d_name;

		if (expiring->d_name.hash != hash)
			goto next;
		if (expiring->d_parent != parent)
			goto next;

		if (qstr->len != len)
			goto next;
		if (memcmp(qstr->name, str, len))
			goto next;

		if (d_unhashed(expiring)) {
			dget_dlock(expiring);
			spin_unlock(&expiring->d_lock);
			spin_unlock(&sbi->lookup_lock);
			return expiring;
		}
next:
		spin_unlock(&expiring->d_lock);
	}
	spin_unlock(&sbi->lookup_lock);

	return NULL;
}

static int autofs4_mount_wait(struct dentry *dentry, bool rcu_walk)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	int status = 0;

	if (ino->flags & AUTOFS_INF_PENDING) {
		if (rcu_walk)
			return -ECHILD;
		DPRINTK("waiting for mount name=%pd", dentry);
		status = autofs4_wait(sbi, dentry, NFY_MOUNT);
		DPRINTK("mount wait done status=%d", status);
	}
	ino->last_used = jiffies;
	return status;
}

static int do_expire_wait(struct dentry *dentry, bool rcu_walk)
{
	struct dentry *expiring;

	expiring = autofs4_lookup_expiring(dentry, rcu_walk);
	if (IS_ERR(expiring))
		return PTR_ERR(expiring);
	if (!expiring)
		return autofs4_expire_wait(dentry, rcu_walk);
	else {
		/*
		 * If we are racing with expire the request might not
		 * be quite complete, but the directory has been removed
		 * so it must have been successful, just wait for it.
		 */
		autofs4_expire_wait(expiring, 0);
		autofs4_del_expiring(expiring);
		dput(expiring);
	}
	return 0;
}

static struct dentry *autofs4_mountpoint_changed(struct path *path)
{
	struct dentry *dentry = path->dentry;
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);

	/*
	 * If this is an indirect mount the dentry could have gone away
	 * as a result of an expire and a new one created.
	 */
	if (autofs_type_indirect(sbi->type) && d_unhashed(dentry)) {
		struct dentry *parent = dentry->d_parent;
		struct autofs_info *ino;
		struct dentry *new = d_lookup(parent, &dentry->d_name);
		if (!new)
			return NULL;
		ino = autofs4_dentry_ino(new);
		ino->last_used = jiffies;
		dput(path->dentry);
		path->dentry = new;
	}
	return path->dentry;
}

static struct vfsmount *autofs4_d_automount(struct path *path)
{
	struct dentry *dentry = path->dentry;
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	int status;

	DPRINTK("dentry=%p %pd", dentry, dentry);

	/* The daemon never triggers a mount. */
	if (autofs4_oz_mode(sbi))
		return NULL;

	/*
	 * If an expire request is pending everyone must wait.
	 * If the expire fails we're still mounted so continue
	 * the follow and return. A return of -EAGAIN (which only
	 * happens with indirect mounts) means the expire completed
	 * and the directory was removed, so just go ahead and try
	 * the mount.
	 */
	status = do_expire_wait(dentry, 0);
	if (status && status != -EAGAIN)
		return NULL;

	/* Callback to the daemon to perform the mount or wait */
	spin_lock(&sbi->fs_lock);
	if (ino->flags & AUTOFS_INF_PENDING) {
		spin_unlock(&sbi->fs_lock);
		status = autofs4_mount_wait(dentry, 0);
		if (status)
			return ERR_PTR(status);
		goto done;
	}

	/*
	 * If the dentry is a symlink it's equivalent to a directory
	 * having d_mountpoint() true, so there's no need to call back
	 * to the daemon.
	 */
	if (dentry->d_inode && d_is_symlink(dentry)) {
		spin_unlock(&sbi->fs_lock);
		goto done;
	}

	if (!d_mountpoint(dentry)) {
		/*
		 * It's possible that user space hasn't removed directories
		 * after umounting a rootless multi-mount, although it
		 * should. For v5 have_submounts() is sufficient to handle
		 * this because the leaves of the directory tree under the
		 * mount never trigger mounts themselves (they have an autofs
		 * trigger mount mounted on them). But v4 pseudo direct mounts
		 * do need the leaves to trigger mounts. In this case we
		 * have no choice but to use the list_empty() check and
		 * require user space behave.
		 */
		if (sbi->version > 4) {
			if (have_submounts(dentry)) {
				spin_unlock(&sbi->fs_lock);
				goto done;
			}
		} else {
			if (!simple_empty(dentry)) {
				spin_unlock(&sbi->fs_lock);
				goto done;
			}
		}
		ino->flags |= AUTOFS_INF_PENDING;
		spin_unlock(&sbi->fs_lock);
		status = autofs4_mount_wait(dentry, 0);
		spin_lock(&sbi->fs_lock);
		ino->flags &= ~AUTOFS_INF_PENDING;
		if (status) {
			spin_unlock(&sbi->fs_lock);
			return ERR_PTR(status);
		}
	}
	spin_unlock(&sbi->fs_lock);
done:
	/* Mount succeeded, check if we ended up with a new dentry */
	dentry = autofs4_mountpoint_changed(path);
	if (!dentry)
		return ERR_PTR(-ENOENT);

	return NULL;
}

static int autofs4_d_manage(struct dentry *dentry, bool rcu_walk)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	int status;

	DPRINTK("dentry=%p %pd", dentry, dentry);

	/* The daemon never waits. */
	if (autofs4_oz_mode(sbi)) {
		if (!d_mountpoint(dentry))
			return -EISDIR;
		return 0;
	}

	/* Wait for pending expires */
	if (do_expire_wait(dentry, rcu_walk) == -ECHILD)
		return -ECHILD;

	/*
	 * This dentry may be under construction so wait on mount
	 * completion.
	 */
	status = autofs4_mount_wait(dentry, rcu_walk);
	if (status)
		return status;

	if (rcu_walk) {
		/* We don't need fs_lock in rcu_walk mode,
		 * just testing 'AUTOFS_INFO_NO_RCU' is enough.
		 * simple_empty() takes a spinlock, so leave it
		 * to last.
		 * We only return -EISDIR when certain this isn't
		 * a mount-trap.
		 */
		struct inode *inode;
		if (ino->flags & (AUTOFS_INF_EXPIRING | AUTOFS_INF_NO_RCU))
			return 0;
		if (d_mountpoint(dentry))
			return 0;
		inode = ACCESS_ONCE(dentry->d_inode);
		if (inode && S_ISLNK(inode->i_mode))
			return -EISDIR;
		if (list_empty(&dentry->d_subdirs))
			return 0;
		if (!simple_empty(dentry))
			return -EISDIR;
		return 0;
	}

	spin_lock(&sbi->fs_lock);
	/*
	 * If the dentry has been selected for expire while we slept
	 * on the lock then it might go away. We'll deal with that in
	 * ->d_automount() and wait on a new mount if the expire
	 * succeeds or return here if it doesn't (since there's no
	 * mount to follow with a rootless multi-mount).
	 */
	if (!(ino->flags & AUTOFS_INF_EXPIRING)) {
		/*
		 * Any needed mounting has been completed and the path
		 * updated so check if this is a rootless multi-mount so
		 * we can avoid needless calls ->d_automount() and avoid
		 * an incorrect ELOOP error return.
		 */
		if ((!d_mountpoint(dentry) && !simple_empty(dentry)) ||
		    (dentry->d_inode && d_is_symlink(dentry)))
			status = -EISDIR;
	}
	spin_unlock(&sbi->fs_lock);

	return status;
}

/* Lookups in the root directory */
static struct dentry *autofs4_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct autofs_sb_info *sbi;
	struct autofs_info *ino;
	struct dentry *active;

	DPRINTK("name = %pd", dentry);

	/* File name too long to exist */
	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	sbi = autofs4_sbi(dir->i_sb);

	DPRINTK("pid = %u, pgrp = %u, catatonic = %d, oz_mode = %d",
		current->pid, task_pgrp_nr(current), sbi->catatonic,
		autofs4_oz_mode(sbi));

	active = autofs4_lookup_active(dentry);
	if (active) {
		return active;
	} else {
		/*
		 * A dentry that is not within the root can never trigger a
		 * mount operation, unless the directory already exists, so we
		 * can return fail immediately.  The daemon however does need
		 * to create directories within the file system.
		 */
		if (!autofs4_oz_mode(sbi) && !IS_ROOT(dentry->d_parent))
			return ERR_PTR(-ENOENT);

		/* Mark entries in the root as mount triggers */
		if (autofs_type_indirect(sbi->type) && IS_ROOT(dentry->d_parent))
			__managed_dentry_set_managed(dentry);

		ino = autofs4_new_ino(sbi);
		if (!ino)
			return ERR_PTR(-ENOMEM);

		dentry->d_fsdata = ino;
		ino->dentry = dentry;

		autofs4_add_active(dentry);

		d_instantiate(dentry, NULL);
	}
	return NULL;
}

static int autofs4_dir_symlink(struct inode *dir, 
			       struct dentry *dentry,
			       const char *symname)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dir->i_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	struct autofs_info *p_ino;
	struct inode *inode;
	size_t size = strlen(symname);
	char *cp;

	DPRINTK("%s <- %pd", symname, dentry);

	if (!autofs4_oz_mode(sbi))
		return -EACCES;

	BUG_ON(!ino);

	autofs4_clean_ino(ino);

	autofs4_del_active(dentry);

	cp = kmalloc(size + 1, GFP_KERNEL);
	if (!cp)
		return -ENOMEM;

	strcpy(cp, symname);

	inode = autofs4_get_inode(dir->i_sb, S_IFLNK | 0555);
	if (!inode) {
		kfree(cp);
		if (!dentry->d_fsdata)
			kfree(ino);
		return -ENOMEM;
	}
	inode->i_private = cp;
	inode->i_size = size;
	d_add(dentry, inode);

	dget(dentry);
	atomic_inc(&ino->count);
	p_ino = autofs4_dentry_ino(dentry->d_parent);
	if (p_ino && !IS_ROOT(dentry))
		atomic_inc(&p_ino->count);

	dir->i_mtime = CURRENT_TIME;

	return 0;
}

/*
 * NOTE!
 *
 * Normal filesystems would do a "d_delete()" to tell the VFS dcache
 * that the file no longer exists. However, doing that means that the
 * VFS layer can turn the dentry into a negative dentry.  We don't want
 * this, because the unlink is probably the result of an expire.
 * We simply d_drop it and add it to a expiring list in the super block,
 * which allows the dentry lookup to check for an incomplete expire.
 *
 * If a process is blocked on the dentry waiting for the expire to finish,
 * it will invalidate the dentry and try to mount with a new one.
 *
 * Also see autofs4_dir_rmdir()..
 */
static int autofs4_dir_unlink(struct inode *dir, struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dir->i_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	struct autofs_info *p_ino;
	
	/* This allows root to remove symlinks */
	if (!autofs4_oz_mode(sbi) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (atomic_dec_and_test(&ino->count)) {
		p_ino = autofs4_dentry_ino(dentry->d_parent);
		if (p_ino && !IS_ROOT(dentry))
			atomic_dec(&p_ino->count);
	}
	dput(ino->dentry);

	dentry->d_inode->i_size = 0;
	clear_nlink(dentry->d_inode);

	dir->i_mtime = CURRENT_TIME;

	spin_lock(&sbi->lookup_lock);
	__autofs4_add_expiring(dentry);
	d_drop(dentry);
	spin_unlock(&sbi->lookup_lock);

	return 0;
}

/*
 * Version 4 of autofs provides a pseudo direct mount implementation
 * that relies on directories at the leaves of a directory tree under
 * an indirect mount to trigger mounts. To allow for this we need to
 * set the DMANAGED_AUTOMOUNT and DMANAGED_TRANSIT flags on the leaves
 * of the directory tree. There is no need to clear the automount flag
 * following a mount or restore it after an expire because these mounts
 * are always covered. However, it is necessary to ensure that these
 * flags are clear on non-empty directories to avoid unnecessary calls
 * during path walks.
 */
static void autofs_set_leaf_automount_flags(struct dentry *dentry)
{
	struct dentry *parent;

	/* root and dentrys in the root are already handled */
	if (IS_ROOT(dentry->d_parent))
		return;

	managed_dentry_set_managed(dentry);

	parent = dentry->d_parent;
	/* only consider parents below dentrys in the root */
	if (IS_ROOT(parent->d_parent))
		return;
	managed_dentry_clear_managed(parent);
	return;
}

static void autofs_clear_leaf_automount_flags(struct dentry *dentry)
{
	struct list_head *d_child;
	struct dentry *parent;

	/* flags for dentrys in the root are handled elsewhere */
	if (IS_ROOT(dentry->d_parent))
		return;

	managed_dentry_clear_managed(dentry);

	parent = dentry->d_parent;
	/* only consider parents below dentrys in the root */
	if (IS_ROOT(parent->d_parent))
		return;
	d_child = &dentry->d_child;
	/* Set parent managed if it's becoming empty */
	if (d_child->next == &parent->d_subdirs &&
	    d_child->prev == &parent->d_subdirs)
		managed_dentry_set_managed(parent);
	return;
}

static int autofs4_dir_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dir->i_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	struct autofs_info *p_ino;
	
	DPRINTK("dentry %p, removing %pd", dentry, dentry);

	if (!autofs4_oz_mode(sbi))
		return -EACCES;

	spin_lock(&sbi->lookup_lock);
	if (!simple_empty(dentry)) {
		spin_unlock(&sbi->lookup_lock);
		return -ENOTEMPTY;
	}
	__autofs4_add_expiring(dentry);
	d_drop(dentry);
	spin_unlock(&sbi->lookup_lock);

	if (sbi->version < 5)
		autofs_clear_leaf_automount_flags(dentry);

	if (atomic_dec_and_test(&ino->count)) {
		p_ino = autofs4_dentry_ino(dentry->d_parent);
		if (p_ino && dentry->d_parent != dentry)
			atomic_dec(&p_ino->count);
	}
	dput(ino->dentry);
	dentry->d_inode->i_size = 0;
	clear_nlink(dentry->d_inode);

	if (dir->i_nlink)
		drop_nlink(dir);

	return 0;
}

static int autofs4_dir_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dir->i_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	struct autofs_info *p_ino;
	struct inode *inode;

	if (!autofs4_oz_mode(sbi))
		return -EACCES;

	DPRINTK("dentry %p, creating %pd", dentry, dentry);

	BUG_ON(!ino);

	autofs4_clean_ino(ino);

	autofs4_del_active(dentry);

	inode = autofs4_get_inode(dir->i_sb, S_IFDIR | 0555);
	if (!inode)
		return -ENOMEM;
	d_add(dentry, inode);

	if (sbi->version < 5)
		autofs_set_leaf_automount_flags(dentry);

	dget(dentry);
	atomic_inc(&ino->count);
	p_ino = autofs4_dentry_ino(dentry->d_parent);
	if (p_ino && !IS_ROOT(dentry))
		atomic_inc(&p_ino->count);
	inc_nlink(dir);
	dir->i_mtime = CURRENT_TIME;

	return 0;
}

/* Get/set timeout ioctl() operation */
#ifdef CONFIG_COMPAT
static inline int autofs4_compat_get_set_timeout(struct autofs_sb_info *sbi,
					 compat_ulong_t __user *p)
{
	int rv;
	unsigned long ntimeout;

	if ((rv = get_user(ntimeout, p)) ||
	     (rv = put_user(sbi->exp_timeout/HZ, p)))
		return rv;

	if (ntimeout > UINT_MAX/HZ)
		sbi->exp_timeout = 0;
	else
		sbi->exp_timeout = ntimeout * HZ;

	return 0;
}
#endif

static inline int autofs4_get_set_timeout(struct autofs_sb_info *sbi,
					 unsigned long __user *p)
{
	int rv;
	unsigned long ntimeout;

	if ((rv = get_user(ntimeout, p)) ||
	     (rv = put_user(sbi->exp_timeout/HZ, p)))
		return rv;

	if (ntimeout > ULONG_MAX/HZ)
		sbi->exp_timeout = 0;
	else
		sbi->exp_timeout = ntimeout * HZ;

	return 0;
}

/* Return protocol version */
static inline int autofs4_get_protover(struct autofs_sb_info *sbi, int __user *p)
{
	return put_user(sbi->version, p);
}

/* Return protocol sub version */
static inline int autofs4_get_protosubver(struct autofs_sb_info *sbi, int __user *p)
{
	return put_user(sbi->sub_version, p);
}

/*
* Tells the daemon whether it can umount the autofs mount.
*/
static inline int autofs4_ask_umount(struct vfsmount *mnt, int __user *p)
{
	int status = 0;

	if (may_umount(mnt))
		status = 1;

	DPRINTK("returning %d", status);

	status = put_user(status, p);

	return status;
}

/* Identify autofs4_dentries - this is so we can tell if there's
   an extra dentry refcount or not.  We only hold a refcount on the
   dentry if its non-negative (ie, d_inode != NULL)
*/
int is_autofs4_dentry(struct dentry *dentry)
{
	return dentry && dentry->d_inode &&
		dentry->d_op == &autofs4_dentry_operations &&
		dentry->d_fsdata != NULL;
}

/*
 * ioctl()'s on the root directory is the chief method for the daemon to
 * generate kernel reactions
 */
static int autofs4_root_ioctl_unlocked(struct inode *inode, struct file *filp,
				       unsigned int cmd, unsigned long arg)
{
	struct autofs_sb_info *sbi = autofs4_sbi(inode->i_sb);
	void __user *p = (void __user *)arg;

	DPRINTK("cmd = 0x%08x, arg = 0x%08lx, sbi = %p, pgrp = %u",
		cmd,arg,sbi,task_pgrp_nr(current));

	if (_IOC_TYPE(cmd) != _IOC_TYPE(AUTOFS_IOC_FIRST) ||
	     _IOC_NR(cmd) - _IOC_NR(AUTOFS_IOC_FIRST) >= AUTOFS_IOC_COUNT)
		return -ENOTTY;
	
	if (!autofs4_oz_mode(sbi) && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	
	switch(cmd) {
	case AUTOFS_IOC_READY:	/* Wait queue: go ahead and retry */
		return autofs4_wait_release(sbi,(autofs_wqt_t)arg,0);
	case AUTOFS_IOC_FAIL:	/* Wait queue: fail with ENOENT */
		return autofs4_wait_release(sbi,(autofs_wqt_t)arg,-ENOENT);
	case AUTOFS_IOC_CATATONIC: /* Enter catatonic mode (daemon shutdown) */
		autofs4_catatonic_mode(sbi);
		return 0;
	case AUTOFS_IOC_PROTOVER: /* Get protocol version */
		return autofs4_get_protover(sbi, p);
	case AUTOFS_IOC_PROTOSUBVER: /* Get protocol sub version */
		return autofs4_get_protosubver(sbi, p);
	case AUTOFS_IOC_SETTIMEOUT:
		return autofs4_get_set_timeout(sbi, p);
#ifdef CONFIG_COMPAT
	case AUTOFS_IOC_SETTIMEOUT32:
		return autofs4_compat_get_set_timeout(sbi, p);
#endif

	case AUTOFS_IOC_ASKUMOUNT:
		return autofs4_ask_umount(filp->f_path.mnt, p);

	/* return a single thing to expire */
	case AUTOFS_IOC_EXPIRE:
		return autofs4_expire_run(inode->i_sb,filp->f_path.mnt,sbi, p);
	/* same as above, but can send multiple expires through pipe */
	case AUTOFS_IOC_EXPIRE_MULTI:
		return autofs4_expire_multi(inode->i_sb,filp->f_path.mnt,sbi, p);

	default:
		return -ENOSYS;
	}
}

static long autofs4_root_ioctl(struct file *filp,
			       unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	return autofs4_root_ioctl_unlocked(inode, filp, cmd, arg);
}

#ifdef CONFIG_COMPAT
static long autofs4_root_compat_ioctl(struct file *filp,
			     unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (cmd == AUTOFS_IOC_READY || cmd == AUTOFS_IOC_FAIL)
		ret = autofs4_root_ioctl_unlocked(inode, filp, cmd, arg);
	else
		ret = autofs4_root_ioctl_unlocked(inode, filp, cmd,
			(unsigned long)compat_ptr(arg));

	return ret;
}
#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/autofs4/root.c */
/************************************************************/
/* -*- c -*- --------------------------------------------------------------- *
 *
 * linux/fs/autofs/symlink.c
 *
 *  Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

// #include "autofs_i.h"

static void *autofs4_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	if (ino && !autofs4_oz_mode(sbi))
		ino->last_used = jiffies;
	nd_set_link(nd, dentry->d_inode->i_private);
	return NULL;
}

const struct inode_operations autofs4_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= autofs4_follow_link
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/autofs4/symlink.c */
/************************************************************/
/* -*- c -*- --------------------------------------------------------------- *
 *
 * linux/fs/autofs/waitq.c
 *
 *  Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 *  Copyright 2001-2006 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

// #include <linux/slab.h>
// #include <linux/time.h>
#include <linux/signal.h>
// #include <linux/file.h>
// #include "autofs_i.h"
#include "../../inc/__fss.h"

/* We make this a static variable rather than a part of the superblock; it
   is better if we don't reassign numbers easily even across filesystems */
static autofs_wqt_t autofs4_next_wait_queue = 1;

/* These are the signals we allow interrupting a pending mount */
#define SHUTDOWN_SIGS	(sigmask(SIGKILL) | sigmask(SIGINT) | sigmask(SIGQUIT))

void autofs4_catatonic_mode(struct autofs_sb_info *sbi)
{
	struct autofs_wait_queue *wq, *nwq;

	mutex_lock(&sbi->wq_mutex);
	if (sbi->catatonic) {
		mutex_unlock(&sbi->wq_mutex);
		return;
	}

	DPRINTK("entering catatonic mode");

	sbi->catatonic = 1;
	wq = sbi->queues;
	sbi->queues = NULL;	/* Erase all wait queues */
	while (wq) {
		nwq = wq->next;
		wq->status = -ENOENT; /* Magic is gone - report failure */
		kfree(wq->name.name);
		wq->name.name = NULL;
		wq->wait_ctr--;
		wake_up_interruptible(&wq->queue);
		wq = nwq;
	}
	fput(sbi->pipe);	/* Close the pipe */
	sbi->pipe = NULL;
	sbi->pipefd = -1;
	mutex_unlock(&sbi->wq_mutex);
}

static int autofs4_write(struct autofs_sb_info *sbi,
			 struct file *file, const void *addr, int bytes)
{
	unsigned long sigpipe, flags;
	mm_segment_t fs;
	const char *data = (const char *)addr;
	ssize_t wr = 0;

	sigpipe = sigismember(&current->pending.signal, SIGPIPE);

	/* Save pointer to user space and point back to kernel space */
	fs = get_fs();
	set_fs(KERNEL_DS);

	mutex_lock(&sbi->pipe_mutex);
	while (bytes &&
	       (wr = file->f_op->write(file,data,bytes,&file->f_pos)) > 0) {
		data += wr;
		bytes -= wr;
	}
	mutex_unlock(&sbi->pipe_mutex);

	set_fs(fs);

	/* Keep the currently executing process from receiving a
	   SIGPIPE unless it was already supposed to get one */
	if (wr == -EPIPE && !sigpipe) {
		spin_lock_irqsave(&current->sighand->siglock, flags);
		sigdelset(&current->pending.signal, SIGPIPE);
		recalc_sigpending();
		spin_unlock_irqrestore(&current->sighand->siglock, flags);
	}

	return (bytes > 0);
}
	
static void autofs4_notify_daemon(struct autofs_sb_info *sbi,
				 struct autofs_wait_queue *wq,
				 int type)
{
	union {
		struct autofs_packet_hdr hdr;
		union autofs_packet_union v4_pkt;
		union autofs_v5_packet_union v5_pkt;
	} pkt;
	struct file *pipe = NULL;
	size_t pktsz;

	DPRINTK("wait id = 0x%08lx, name = %.*s, type=%d",
		(unsigned long) wq->wait_queue_token, wq->name.len, wq->name.name, type);

	memset(&pkt,0,sizeof pkt); /* For security reasons */

	pkt.hdr.proto_version = sbi->version;
	pkt.hdr.type = type;

	switch (type) {
	/* Kernel protocol v4 missing and expire packets */
	case autofs_ptype_missing:
	{
		struct autofs_packet_missing *mp = &pkt.v4_pkt.missing;

		pktsz = sizeof(*mp);

		mp->wait_queue_token = wq->wait_queue_token;
		mp->len = wq->name.len;
		memcpy(mp->name, wq->name.name, wq->name.len);
		mp->name[wq->name.len] = '\0';
		break;
	}
	case autofs_ptype_expire_multi:
	{
		struct autofs_packet_expire_multi *ep = &pkt.v4_pkt.expire_multi;

		pktsz = sizeof(*ep);

		ep->wait_queue_token = wq->wait_queue_token;
		ep->len = wq->name.len;
		memcpy(ep->name, wq->name.name, wq->name.len);
		ep->name[wq->name.len] = '\0';
		break;
	}
	/*
	 * Kernel protocol v5 packet for handling indirect and direct
	 * mount missing and expire requests
	 */
	case autofs_ptype_missing_indirect:
	case autofs_ptype_expire_indirect:
	case autofs_ptype_missing_direct:
	case autofs_ptype_expire_direct:
	{
		struct autofs_v5_packet *packet = &pkt.v5_pkt.v5_packet;
		struct user_namespace *user_ns = sbi->pipe->f_cred->user_ns;

		pktsz = sizeof(*packet);

		packet->wait_queue_token = wq->wait_queue_token;
		packet->len = wq->name.len;
		memcpy(packet->name, wq->name.name, wq->name.len);
		packet->name[wq->name.len] = '\0';
		packet->dev = wq->dev;
		packet->ino = wq->ino;
		packet->uid = from_kuid_munged(user_ns, wq->uid);
		packet->gid = from_kgid_munged(user_ns, wq->gid);
		packet->pid = wq->pid;
		packet->tgid = wq->tgid;
		break;
	}
	default:
		printk("autofs4_notify_daemon: bad type %d!\n", type);
		mutex_unlock(&sbi->wq_mutex);
		return;
	}

	pipe = get_file(sbi->pipe);

	mutex_unlock(&sbi->wq_mutex);

	if (autofs4_write(sbi, pipe, &pkt, pktsz))
		autofs4_catatonic_mode(sbi);
	fput(pipe);
}

static int autofs4_getpath(struct autofs_sb_info *sbi,
			   struct dentry *dentry, char **name)
{
	struct dentry *root = sbi->sb->s_root;
	struct dentry *tmp;
	char *buf;
	char *p;
	int len;
	unsigned seq;

rename_retry:
	buf = *name;
	len = 0;

	seq = read_seqbegin(&rename_lock);
	rcu_read_lock();
	spin_lock(&sbi->fs_lock);
	for (tmp = dentry ; tmp != root ; tmp = tmp->d_parent)
		len += tmp->d_name.len + 1;

	if (!len || --len > NAME_MAX) {
		spin_unlock(&sbi->fs_lock);
		rcu_read_unlock();
		if (read_seqretry(&rename_lock, seq))
			goto rename_retry;
		return 0;
	}

	*(buf + len) = '\0';
	p = buf + len - dentry->d_name.len;
	strncpy(p, dentry->d_name.name, dentry->d_name.len);

	for (tmp = dentry->d_parent; tmp != root ; tmp = tmp->d_parent) {
		*(--p) = '/';
		p -= tmp->d_name.len;
		strncpy(p, tmp->d_name.name, tmp->d_name.len);
	}
	spin_unlock(&sbi->fs_lock);
	rcu_read_unlock();
	if (read_seqretry(&rename_lock, seq))
		goto rename_retry;

	return len;
}

static struct autofs_wait_queue *
autofs4_find_wait(struct autofs_sb_info *sbi, struct qstr *qstr)
{
	struct autofs_wait_queue *wq;

	for (wq = sbi->queues; wq; wq = wq->next) {
		if (wq->name.hash == qstr->hash &&
		    wq->name.len == qstr->len &&
		    wq->name.name &&
			 !memcmp(wq->name.name, qstr->name, qstr->len))
			break;
	}
	return wq;
}

/*
 * Check if we have a valid request.
 * Returns
 * 1 if the request should continue.
 *   In this case we can return an autofs_wait_queue entry if one is
 *   found or NULL to idicate a new wait needs to be created.
 * 0 or a negative errno if the request shouldn't continue.
 */
static int validate_request(struct autofs_wait_queue **wait,
			    struct autofs_sb_info *sbi,
			    struct qstr *qstr,
			    struct dentry*dentry, enum autofs_notify notify)
{
	struct autofs_wait_queue *wq;
	struct autofs_info *ino;

	if (sbi->catatonic)
		return -ENOENT;

	/* Wait in progress, continue; */
	wq = autofs4_find_wait(sbi, qstr);
	if (wq) {
		*wait = wq;
		return 1;
	}

	*wait = NULL;

	/* If we don't yet have any info this is a new request */
	ino = autofs4_dentry_ino(dentry);
	if (!ino)
		return 1;

	/*
	 * If we've been asked to wait on an existing expire (NFY_NONE)
	 * but there is no wait in the queue ...
	 */
	if (notify == NFY_NONE) {
		/*
		 * Either we've betean the pending expire to post it's
		 * wait or it finished while we waited on the mutex.
		 * So we need to wait till either, the wait appears
		 * or the expire finishes.
		 */

		while (ino->flags & AUTOFS_INF_EXPIRING) {
			mutex_unlock(&sbi->wq_mutex);
			schedule_timeout_interruptible(HZ/10);
			if (mutex_lock_interruptible(&sbi->wq_mutex))
				return -EINTR;

			if (sbi->catatonic)
				return -ENOENT;

			wq = autofs4_find_wait(sbi, qstr);
			if (wq) {
				*wait = wq;
				return 1;
			}
		}

		/*
		 * Not ideal but the status has already gone. Of the two
		 * cases where we wait on NFY_NONE neither depend on the
		 * return status of the wait.
		 */
		return 0;
	}

	/*
	 * If we've been asked to trigger a mount and the request
	 * completed while we waited on the mutex ...
	 */
	if (notify == NFY_MOUNT) {
		struct dentry *new = NULL;
		int valid = 1;

		/*
		 * If the dentry was successfully mounted while we slept
		 * on the wait queue mutex we can return success. If it
		 * isn't mounted (doesn't have submounts for the case of
		 * a multi-mount with no mount at it's base) we can
		 * continue on and create a new request.
		 */
		if (!IS_ROOT(dentry)) {
			if (dentry->d_inode && d_unhashed(dentry)) {
				struct dentry *parent = dentry->d_parent;
				new = d_lookup(parent, &dentry->d_name);
				if (new)
					dentry = new;
			}
		}
		if (have_submounts(dentry))
			valid = 0;

		if (new)
			dput(new);
		return valid;
	}

	return 1;
}

int autofs4_wait(struct autofs_sb_info *sbi, struct dentry *dentry,
		enum autofs_notify notify)
{
	struct autofs_wait_queue *wq;
	struct qstr qstr;
	char *name;
	int status, ret, type;
	pid_t pid;
	pid_t tgid;

	/* In catatonic mode, we don't wait for nobody */
	if (sbi->catatonic)
		return -ENOENT;

	/*
	 * Try translating pids to the namespace of the daemon.
	 *
	 * Zero means failure: we are in an unrelated pid namespace.
	 */
	pid = task_pid_nr_ns(current, ns_of_pid(sbi->oz_pgrp));
	tgid = task_tgid_nr_ns(current, ns_of_pid(sbi->oz_pgrp));
	if (pid == 0 || tgid == 0)
		return -ENOENT;

	if (!dentry->d_inode) {
		/*
		 * A wait for a negative dentry is invalid for certain
		 * cases. A direct or offset mount "always" has its mount
		 * point directory created and so the request dentry must
		 * be positive or the map key doesn't exist. The situation
		 * is very similar for indirect mounts except only dentrys
		 * in the root of the autofs file system may be negative.
		 */
		if (autofs_type_trigger(sbi->type))
			return -ENOENT;
		else if (!IS_ROOT(dentry->d_parent))
			return -ENOENT;
	}

	name = kmalloc(NAME_MAX + 1, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	/* If this is a direct mount request create a dummy name */
	if (IS_ROOT(dentry) && autofs_type_trigger(sbi->type))
		qstr.len = sprintf(name, "%p", dentry);
	else {
		qstr.len = autofs4_getpath(sbi, dentry, &name);
		if (!qstr.len) {
			kfree(name);
			return -ENOENT;
		}
	}
	qstr.name = name;
	qstr.hash = full_name_hash(name, qstr.len);

	if (mutex_lock_interruptible(&sbi->wq_mutex)) {
		kfree(qstr.name);
		return -EINTR;
	}

	ret = validate_request(&wq, sbi, &qstr, dentry, notify);
	if (ret <= 0) {
		if (ret != -EINTR)
			mutex_unlock(&sbi->wq_mutex);
		kfree(qstr.name);
		return ret;
	}

	if (!wq) {
		/* Create a new wait queue */
		wq = kmalloc(sizeof(struct autofs_wait_queue),GFP_KERNEL);
		if (!wq) {
			kfree(qstr.name);
			mutex_unlock(&sbi->wq_mutex);
			return -ENOMEM;
		}

		wq->wait_queue_token = autofs4_next_wait_queue;
		if (++autofs4_next_wait_queue == 0)
			autofs4_next_wait_queue = 1;
		wq->next = sbi->queues;
		sbi->queues = wq;
		init_waitqueue_head(&wq->queue);
		memcpy(&wq->name, &qstr, sizeof(struct qstr));
		wq->dev = autofs4_get_dev(sbi);
		wq->ino = autofs4_get_ino(sbi);
		wq->uid = current_uid();
		wq->gid = current_gid();
		wq->pid = pid;
		wq->tgid = tgid;
		wq->status = -EINTR; /* Status return if interrupted */
		wq->wait_ctr = 2;

		if (sbi->version < 5) {
			if (notify == NFY_MOUNT)
				type = autofs_ptype_missing;
			else
				type = autofs_ptype_expire_multi;
		} else {
			if (notify == NFY_MOUNT)
				type = autofs_type_trigger(sbi->type) ?
					autofs_ptype_missing_direct :
					 autofs_ptype_missing_indirect;
			else
				type = autofs_type_trigger(sbi->type) ?
					autofs_ptype_expire_direct :
					autofs_ptype_expire_indirect;
		}

		DPRINTK("new wait id = 0x%08lx, name = %.*s, nfy=%d\n",
			(unsigned long) wq->wait_queue_token, wq->name.len,
			wq->name.name, notify);

		/* autofs4_notify_daemon() may block; it will unlock ->wq_mutex */
		autofs4_notify_daemon(sbi, wq, type);
	} else {
		wq->wait_ctr++;
		DPRINTK("existing wait id = 0x%08lx, name = %.*s, nfy=%d",
			(unsigned long) wq->wait_queue_token, wq->name.len,
			wq->name.name, notify);
		mutex_unlock(&sbi->wq_mutex);
		kfree(qstr.name);
	}

	/*
	 * wq->name.name is NULL iff the lock is already released
	 * or the mount has been made catatonic.
	 */
	if (wq->name.name) {
		/* Block all but "shutdown" signals while waiting */
		sigset_t oldset;
		unsigned long irqflags;

		spin_lock_irqsave(&current->sighand->siglock, irqflags);
		oldset = current->blocked;
		siginitsetinv(&current->blocked, SHUTDOWN_SIGS & ~oldset.sig[0]);
		recalc_sigpending();
		spin_unlock_irqrestore(&current->sighand->siglock, irqflags);

		wait_event_interruptible(wq->queue, wq->name.name == NULL);

		spin_lock_irqsave(&current->sighand->siglock, irqflags);
		current->blocked = oldset;
		recalc_sigpending();
		spin_unlock_irqrestore(&current->sighand->siglock, irqflags);
	} else {
		DPRINTK("skipped sleeping");
	}

	status = wq->status;

	/*
	 * For direct and offset mounts we need to track the requester's
	 * uid and gid in the dentry info struct. This is so it can be
	 * supplied, on request, by the misc device ioctl interface.
	 * This is needed during daemon resatart when reconnecting
	 * to existing, active, autofs mounts. The uid and gid (and
	 * related string values) may be used for macro substitution
	 * in autofs mount maps.
	 */
	if (!status) {
		struct autofs_info *ino;
		struct dentry *de = NULL;

		/* direct mount or browsable map */
		ino = autofs4_dentry_ino(dentry);
		if (!ino) {
			/* If not lookup actual dentry used */
			de = d_lookup(dentry->d_parent, &dentry->d_name);
			if (de)
				ino = autofs4_dentry_ino(de);
		}

		/* Set mount requester */
		if (ino) {
			spin_lock(&sbi->fs_lock);
			ino->uid = wq->uid;
			ino->gid = wq->gid;
			spin_unlock(&sbi->fs_lock);
		}

		if (de)
			dput(de);
	}

	/* Are we the last process to need status? */
	mutex_lock(&sbi->wq_mutex);
	if (!--wq->wait_ctr)
		kfree(wq);
	mutex_unlock(&sbi->wq_mutex);

	return status;
}


int autofs4_wait_release(struct autofs_sb_info *sbi, autofs_wqt_t wait_queue_token, int status)
{
	struct autofs_wait_queue *wq, **wql;

	mutex_lock(&sbi->wq_mutex);
	for (wql = &sbi->queues; (wq = *wql) != NULL; wql = &wq->next) {
		if (wq->wait_queue_token == wait_queue_token)
			break;
	}

	if (!wq) {
		mutex_unlock(&sbi->wq_mutex);
		return -EINVAL;
	}

	*wql = wq->next;	/* Unlink from chain */
	kfree(wq->name.name);
	wq->name.name = NULL;	/* Do not wait on this queue */
	wq->status = status;
	wake_up_interruptible(&wq->queue);
	if (!--wq->wait_ctr)
		kfree(wq);
	mutex_unlock(&sbi->wq_mutex);

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/autofs4/waitq.c */
/************************************************************/
/* -*- c -*- --------------------------------------------------------------- *
 *
 * linux/fs/autofs/expire.c
 *
 *  Copyright 1997-1998 Transmeta Corporation -- All Rights Reserved
 *  Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *  Copyright 2001-2006 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * ------------------------------------------------------------------------- */

// #include "autofs_i.h"

static unsigned long now;

/* Check if a dentry can be expired */
static inline int autofs4_can_expire(struct dentry *dentry,
					unsigned long timeout, int do_now)
{
	struct autofs_info *ino = autofs4_dentry_ino(dentry);

	/* dentry in the process of being deleted */
	if (ino == NULL)
		return 0;

	if (!do_now) {
		/* Too young to die */
		if (!timeout || time_after(ino->last_used + timeout, now))
			return 0;
	}
	return 1;
}

/* Check a mount point for busyness */
static int autofs4_mount_busy(struct vfsmount *mnt, struct dentry *dentry)
{
	struct dentry *top = dentry;
	struct path path = {.mnt = mnt, .dentry = dentry};
	int status = 1;

	DPRINTK("dentry %p %pd", dentry, dentry);

	path_get(&path);

	if (!follow_down_one(&path))
		goto done;

	if (is_autofs4_dentry(path.dentry)) {
		struct autofs_sb_info *sbi = autofs4_sbi(path.dentry->d_sb);

		/* This is an autofs submount, we can't expire it */
		if (autofs_type_indirect(sbi->type))
			goto done;
	}

	/* Update the expiry counter if fs is busy */
	if (!may_umount_tree(path.mnt)) {
		struct autofs_info *ino = autofs4_dentry_ino(top);
		ino->last_used = jiffies;
		goto done;
	}

	status = 0;
done:
	DPRINTK("returning = %d", status);
	path_put(&path);
	return status;
}

/*
 * Calculate and dget next entry in the subdirs list under root.
 */
static struct dentry *get_next_positive_subdir(struct dentry *prev,
						struct dentry *root)
{
	struct autofs_sb_info *sbi = autofs4_sbi(root->d_sb);
	struct list_head *next;
	struct dentry *q;

	spin_lock(&sbi->lookup_lock);
	spin_lock(&root->d_lock);

	if (prev)
		next = prev->d_child.next;
	else {
		prev = dget_dlock(root);
		next = prev->d_subdirs.next;
	}

cont:
	if (next == &root->d_subdirs) {
		spin_unlock(&root->d_lock);
		spin_unlock(&sbi->lookup_lock);
		dput(prev);
		return NULL;
	}

	q = list_entry(next, struct dentry, d_child);

	spin_lock_nested(&q->d_lock, DENTRY_D_LOCK_NESTED);
	/* Already gone or negative dentry (under construction) - try next */
	if (!d_count(q) || !simple_positive(q)) {
		spin_unlock(&q->d_lock);
		next = q->d_child.next;
		goto cont;
	}
	dget_dlock(q);
	spin_unlock(&q->d_lock);
	spin_unlock(&root->d_lock);
	spin_unlock(&sbi->lookup_lock);

	dput(prev);

	return q;
}

/*
 * Calculate and dget next entry in top down tree traversal.
 */
static struct dentry *get_next_positive_dentry(struct dentry *prev,
						struct dentry *root)
{
	struct autofs_sb_info *sbi = autofs4_sbi(root->d_sb);
	struct list_head *next;
	struct dentry *p, *ret;

	if (prev == NULL)
		return dget(root);

	spin_lock(&sbi->lookup_lock);
relock:
	p = prev;
	spin_lock(&p->d_lock);
again:
	next = p->d_subdirs.next;
	if (next == &p->d_subdirs) {
		while (1) {
			struct dentry *parent;

			if (p == root) {
				spin_unlock(&p->d_lock);
				spin_unlock(&sbi->lookup_lock);
				dput(prev);
				return NULL;
			}

			parent = p->d_parent;
			if (!spin_trylock(&parent->d_lock)) {
				spin_unlock(&p->d_lock);
				cpu_relax();
				goto relock;
			}
			spin_unlock(&p->d_lock);
			next = p->d_child.next;
			p = parent;
			if (next != &parent->d_subdirs)
				break;
		}
	}
	ret = list_entry(next, struct dentry, d_child);

	spin_lock_nested(&ret->d_lock, DENTRY_D_LOCK_NESTED);
	/* Negative dentry - try next */
	if (!simple_positive(ret)) {
		spin_unlock(&p->d_lock);
		lock_set_subclass(&ret->d_lock.dep_map, 0, _RET_IP_);
		p = ret;
		goto again;
	}
	dget_dlock(ret);
	spin_unlock(&ret->d_lock);
	spin_unlock(&p->d_lock);
	spin_unlock(&sbi->lookup_lock);

	dput(prev);

	return ret;
}

/*
 * Check a direct mount point for busyness.
 * Direct mounts have similar expiry semantics to tree mounts.
 * The tree is not busy iff no mountpoints are busy and there are no
 * autofs submounts.
 */
static int autofs4_direct_busy(struct vfsmount *mnt,
				struct dentry *top,
				unsigned long timeout,
				int do_now)
{
	DPRINTK("top %p %pd", top, top);

	/* If it's busy update the expiry counters */
	if (!may_umount_tree(mnt)) {
		struct autofs_info *ino = autofs4_dentry_ino(top);
		if (ino)
			ino->last_used = jiffies;
		return 1;
	}

	/* Timeout of a direct mount is determined by its top dentry */
	if (!autofs4_can_expire(top, timeout, do_now))
		return 1;

	return 0;
}

/* Check a directory tree of mount points for busyness
 * The tree is not busy iff no mountpoints are busy
 */
static int autofs4_tree_busy(struct vfsmount *mnt,
	       		     struct dentry *top,
			     unsigned long timeout,
			     int do_now)
{
	struct autofs_info *top_ino = autofs4_dentry_ino(top);
	struct dentry *p;

	DPRINTK("top %p %pd", top, top);

	/* Negative dentry - give up */
	if (!simple_positive(top))
		return 1;

	p = NULL;
	while ((p = get_next_positive_dentry(p, top))) {
		DPRINTK("dentry %p %pd", p, p);

		/*
		 * Is someone visiting anywhere in the subtree ?
		 * If there's no mount we need to check the usage
		 * count for the autofs dentry.
		 * If the fs is busy update the expiry counter.
		 */
		if (d_mountpoint(p)) {
			if (autofs4_mount_busy(mnt, p)) {
				top_ino->last_used = jiffies;
				dput(p);
				return 1;
			}
		} else {
			struct autofs_info *ino = autofs4_dentry_ino(p);
			unsigned int ino_count = atomic_read(&ino->count);

			/* allow for dget above and top is already dgot */
			if (p == top)
				ino_count += 2;
			else
				ino_count++;

			if (d_count(p) > ino_count) {
				top_ino->last_used = jiffies;
				dput(p);
				return 1;
			}
		}
	}

	/* Timeout of a tree mount is ultimately determined by its top dentry */
	if (!autofs4_can_expire(top, timeout, do_now))
		return 1;

	return 0;
}

static struct dentry *autofs4_check_leaves(struct vfsmount *mnt,
					   struct dentry *parent,
					   unsigned long timeout,
					   int do_now)
{
	struct dentry *p;

	DPRINTK("parent %p %pd", parent, parent);

	p = NULL;
	while ((p = get_next_positive_dentry(p, parent))) {
		DPRINTK("dentry %p %pd", p, p);

		if (d_mountpoint(p)) {
			/* Can we umount this guy */
			if (autofs4_mount_busy(mnt, p))
				continue;

			/* Can we expire this guy */
			if (autofs4_can_expire(p, timeout, do_now))
				return p;
		}
	}
	return NULL;
}

/* Check if we can expire a direct mount (possibly a tree) */
struct dentry *autofs4_expire_direct(struct super_block *sb,
				     struct vfsmount *mnt,
				     struct autofs_sb_info *sbi,
				     int how)
{
	unsigned long timeout;
	struct dentry *root = dget(sb->s_root);
	int do_now = how & AUTOFS_EXP_IMMEDIATE;
	struct autofs_info *ino;

	if (!root)
		return NULL;

	now = jiffies;
	timeout = sbi->exp_timeout;

	spin_lock(&sbi->fs_lock);
	ino = autofs4_dentry_ino(root);
	/* No point expiring a pending mount */
	if (ino->flags & AUTOFS_INF_PENDING)
		goto out;
	if (!autofs4_direct_busy(mnt, root, timeout, do_now)) {
		ino->flags |= AUTOFS_INF_NO_RCU;
		spin_unlock(&sbi->fs_lock);
		synchronize_rcu();
		spin_lock(&sbi->fs_lock);
		if (!autofs4_direct_busy(mnt, root, timeout, do_now)) {
			ino->flags |= AUTOFS_INF_EXPIRING;
			smp_mb();
			ino->flags &= ~AUTOFS_INF_NO_RCU;
			init_completion(&ino->expire_complete);
			spin_unlock(&sbi->fs_lock);
			return root;
		}
		ino->flags &= ~AUTOFS_INF_NO_RCU;
	}
out:
	spin_unlock(&sbi->fs_lock);
	dput(root);

	return NULL;
}

/* Check if 'dentry' should expire, or return a nearby
 * dentry that is suitable.
 * If returned dentry is different from arg dentry,
 * then a dget() reference was taken, else not.
 */
static struct dentry *should_expire(struct dentry *dentry,
				    struct vfsmount *mnt,
				    unsigned long timeout,
				    int how)
{
	int do_now = how & AUTOFS_EXP_IMMEDIATE;
	int exp_leaves = how & AUTOFS_EXP_LEAVES;
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	unsigned int ino_count;

	/* No point expiring a pending mount */
	if (ino->flags & AUTOFS_INF_PENDING)
		return NULL;

	/*
	 * Case 1: (i) indirect mount or top level pseudo direct mount
	 *	   (autofs-4.1).
	 *	   (ii) indirect mount with offset mount, check the "/"
	 *	   offset (autofs-5.0+).
	 */
	if (d_mountpoint(dentry)) {
		DPRINTK("checking mountpoint %p %pd", dentry, dentry);

		/* Can we umount this guy */
		if (autofs4_mount_busy(mnt, dentry))
			return NULL;

		/* Can we expire this guy */
		if (autofs4_can_expire(dentry, timeout, do_now))
			return dentry;
		return NULL;
	}

	if (dentry->d_inode && d_is_symlink(dentry)) {
		DPRINTK("checking symlink %p %pd", dentry, dentry);
		/*
		 * A symlink can't be "busy" in the usual sense so
		 * just check last used for expire timeout.
		 */
		if (autofs4_can_expire(dentry, timeout, do_now))
			return dentry;
		return NULL;
	}

	if (simple_empty(dentry))
		return NULL;

	/* Case 2: tree mount, expire iff entire tree is not busy */
	if (!exp_leaves) {
		/* Path walk currently on this dentry? */
		ino_count = atomic_read(&ino->count) + 1;
		if (d_count(dentry) > ino_count)
			return NULL;

		if (!autofs4_tree_busy(mnt, dentry, timeout, do_now))
			return dentry;
	/*
	 * Case 3: pseudo direct mount, expire individual leaves
	 *	   (autofs-4.1).
	 */
	} else {
		/* Path walk currently on this dentry? */
		struct dentry *expired;
		ino_count = atomic_read(&ino->count) + 1;
		if (d_count(dentry) > ino_count)
			return NULL;

		expired = autofs4_check_leaves(mnt, dentry, timeout, do_now);
		if (expired) {
			if (expired == dentry)
				dput(dentry);
			return expired;
		}
	}
	return NULL;
}
/*
 * Find an eligible tree to time-out
 * A tree is eligible if :-
 *  - it is unused by any user process
 *  - it has been unused for exp_timeout time
 */
struct dentry *autofs4_expire_indirect(struct super_block *sb,
				       struct vfsmount *mnt,
				       struct autofs_sb_info *sbi,
				       int how)
{
	unsigned long timeout;
	struct dentry *root = sb->s_root;
	struct dentry *dentry;
	struct dentry *expired;
	struct autofs_info *ino;

	if (!root)
		return NULL;

	now = jiffies;
	timeout = sbi->exp_timeout;

	dentry = NULL;
	while ((dentry = get_next_positive_subdir(dentry, root))) {
		spin_lock(&sbi->fs_lock);
		ino = autofs4_dentry_ino(dentry);
		if (ino->flags & AUTOFS_INF_NO_RCU)
			expired = NULL;
		else
			expired = should_expire(dentry, mnt, timeout, how);
		if (!expired) {
			spin_unlock(&sbi->fs_lock);
			continue;
		}
		ino = autofs4_dentry_ino(expired);
		ino->flags |= AUTOFS_INF_NO_RCU;
		spin_unlock(&sbi->fs_lock);
		synchronize_rcu();
		spin_lock(&sbi->fs_lock);
		if (should_expire(expired, mnt, timeout, how)) {
			if (expired != dentry)
				dput(dentry);
			goto found;
		}

		ino->flags &= ~AUTOFS_INF_NO_RCU;
		if (expired != dentry)
			dput(expired);
		spin_unlock(&sbi->fs_lock);
	}
	return NULL;

found:
	DPRINTK("returning %p %pd", expired, expired);
	ino->flags |= AUTOFS_INF_EXPIRING;
	smp_mb();
	ino->flags &= ~AUTOFS_INF_NO_RCU;
	init_completion(&ino->expire_complete);
	spin_unlock(&sbi->fs_lock);
	spin_lock(&sbi->lookup_lock);
	spin_lock(&expired->d_parent->d_lock);
	spin_lock_nested(&expired->d_lock, DENTRY_D_LOCK_NESTED);
	list_move(&expired->d_parent->d_subdirs, &expired->d_child);
	spin_unlock(&expired->d_lock);
	spin_unlock(&expired->d_parent->d_lock);
	spin_unlock(&sbi->lookup_lock);
	return expired;
}

int autofs4_expire_wait(struct dentry *dentry, int rcu_walk)
{
	struct autofs_sb_info *sbi = autofs4_sbi(dentry->d_sb);
	struct autofs_info *ino = autofs4_dentry_ino(dentry);
	int status;

	/* Block on any pending expire */
	if (!(ino->flags & (AUTOFS_INF_EXPIRING | AUTOFS_INF_NO_RCU)))
		return 0;
	if (rcu_walk)
		return -ECHILD;

	spin_lock(&sbi->fs_lock);
	if (ino->flags & AUTOFS_INF_EXPIRING) {
		spin_unlock(&sbi->fs_lock);

		DPRINTK("waiting for expire %p name=%pd", dentry, dentry);

		status = autofs4_wait(sbi, dentry, NFY_NONE);
		wait_for_completion(&ino->expire_complete);

		DPRINTK("expire done status=%d", status);

		if (d_unhashed(dentry))
			return -EAGAIN;

		return status;
	}
	spin_unlock(&sbi->fs_lock);

	return 0;
}

/* Perform an expiry operation */
int autofs4_expire_run(struct super_block *sb,
		      struct vfsmount *mnt,
		      struct autofs_sb_info *sbi,
		      struct autofs_packet_expire __user *pkt_p)
{
	struct autofs_packet_expire pkt;
	struct autofs_info *ino;
	struct dentry *dentry;
	int ret = 0;

	memset(&pkt,0,sizeof pkt);

	pkt.hdr.proto_version = sbi->version;
	pkt.hdr.type = autofs_ptype_expire;

	if ((dentry = autofs4_expire_indirect(sb, mnt, sbi, 0)) == NULL)
		return -EAGAIN;

	pkt.len = dentry->d_name.len;
	memcpy(pkt.name, dentry->d_name.name, pkt.len);
	pkt.name[pkt.len] = '\0';
	dput(dentry);

	if ( copy_to_user(pkt_p, &pkt, sizeof(struct autofs_packet_expire)) )
		ret = -EFAULT;

	spin_lock(&sbi->fs_lock);
	ino = autofs4_dentry_ino(dentry);
	/* avoid rapid-fire expire attempts if expiry fails */
	ino->last_used = now;
	ino->flags &= ~AUTOFS_INF_EXPIRING;
	complete_all(&ino->expire_complete);
	spin_unlock(&sbi->fs_lock);

	return ret;
}

int autofs4_do_expire_multi(struct super_block *sb, struct vfsmount *mnt,
			    struct autofs_sb_info *sbi, int when)
{
	struct dentry *dentry;
	int ret = -EAGAIN;

	if (autofs_type_trigger(sbi->type))
		dentry = autofs4_expire_direct(sb, mnt, sbi, when);
	else
		dentry = autofs4_expire_indirect(sb, mnt, sbi, when);

	if (dentry) {
		struct autofs_info *ino = autofs4_dentry_ino(dentry);

		/* This is synchronous because it makes the daemon a
                   little easier */
		ret = autofs4_wait(sbi, dentry, NFY_EXPIRE);

		spin_lock(&sbi->fs_lock);
		/* avoid rapid-fire expire attempts if expiry fails */
		ino->last_used = now;
		ino->flags &= ~AUTOFS_INF_EXPIRING;
		complete_all(&ino->expire_complete);
		spin_unlock(&sbi->fs_lock);
		dput(dentry);
	}

	return ret;
}

/* Call repeatedly until it returns -EAGAIN, meaning there's nothing
   more to be done */
int autofs4_expire_multi(struct super_block *sb, struct vfsmount *mnt,
			struct autofs_sb_info *sbi, int __user *arg)
{
	int do_now = 0;

	if (arg && get_user(do_now, arg))
		return -EFAULT;

	return autofs4_do_expire_multi(sb, mnt, sbi, do_now);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/autofs4/expire.c */
/************************************************************/
/*
 * Copyright 2008 Red Hat, Inc. All rights reserved.
 * Copyright 2008 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

// #include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/miscdevice.h>
// #include <linux/init.h>
#include <linux/wait.h>
#include <linux/namei.h>
#include <linux/fcntl.h>
// #include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
// #include <linux/compat.h>
#include <linux/syscalls.h>
// #include <linux/magic.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

// #include "autofs_i.h"

/*
 * This module implements an interface for routing autofs ioctl control
 * commands via a miscellaneous device file.
 *
 * The alternate interface is needed because we need to be able open
 * an ioctl file descriptor on an autofs mount that may be covered by
 * another mount. This situation arises when starting automount(8)
 * or other user space daemon which uses direct mounts or offset
 * mounts (used for autofs lazy mount/umount of nested mount trees),
 * which have been left busy at at service shutdown.
 */

#define AUTOFS_DEV_IOCTL_SIZE	sizeof(struct autofs_dev_ioctl)

typedef int (*ioctl_fn)(struct file *, struct autofs_sb_info *,
			struct autofs_dev_ioctl *);

static int check_name(const char *name)
{
	if (!strchr(name, '/'))
		return -EINVAL;
	return 0;
}

/*
 * Check a string doesn't overrun the chunk of
 * memory we copied from user land.
 */
static int invalid_str(char *str, size_t size)
{
	if (memchr(str, 0, size))
		return 0;
	return -EINVAL;
}

/*
 * Check that the user compiled against correct version of autofs
 * misc device code.
 *
 * As well as checking the version compatibility this always copies
 * the kernel interface version out.
 */
static int check_dev_ioctl_version(int cmd, struct autofs_dev_ioctl *param)
{
	int err = 0;

	if ((AUTOFS_DEV_IOCTL_VERSION_MAJOR != param->ver_major) ||
	    (AUTOFS_DEV_IOCTL_VERSION_MINOR < param->ver_minor)) {
		AUTOFS_WARN("ioctl control interface version mismatch: "
		     "kernel(%u.%u), user(%u.%u), cmd(%d)",
		     AUTOFS_DEV_IOCTL_VERSION_MAJOR,
		     AUTOFS_DEV_IOCTL_VERSION_MINOR,
		     param->ver_major, param->ver_minor, cmd);
		err = -EINVAL;
	}

	/* Fill in the kernel version. */
	param->ver_major = AUTOFS_DEV_IOCTL_VERSION_MAJOR;
	param->ver_minor = AUTOFS_DEV_IOCTL_VERSION_MINOR;

	return err;
}

/*
 * Copy parameter control struct, including a possible path allocated
 * at the end of the struct.
 */
static struct autofs_dev_ioctl *copy_dev_ioctl(struct autofs_dev_ioctl __user *in)
{
	struct autofs_dev_ioctl tmp, *res;

	if (copy_from_user(&tmp, in, sizeof(tmp)))
		return ERR_PTR(-EFAULT);

	if (tmp.size < sizeof(tmp))
		return ERR_PTR(-EINVAL);

	if (tmp.size > (PATH_MAX + sizeof(tmp)))
		return ERR_PTR(-ENAMETOOLONG);

	res = memdup_user(in, tmp.size);
	if (!IS_ERR(res))
		res->size = tmp.size;

	return res;
}

static inline void free_dev_ioctl(struct autofs_dev_ioctl *param)
{
	kfree(param);
	return;
}

/*
 * Check sanity of parameter control fields and if a path is present
 * check that it is terminated and contains at least one "/".
 */
static int validate_dev_ioctl(int cmd, struct autofs_dev_ioctl *param)
{
	int err;

	err = check_dev_ioctl_version(cmd, param);
	if (err) {
		AUTOFS_WARN("invalid device control module version "
		     "supplied for cmd(0x%08x)", cmd);
		goto out;
	}

	if (param->size > sizeof(*param)) {
		err = invalid_str(param->path, param->size - sizeof(*param));
		if (err) {
			AUTOFS_WARN(
			  "path string terminator missing for cmd(0x%08x)",
			  cmd);
			goto out;
		}

		err = check_name(param->path);
		if (err) {
			AUTOFS_WARN("invalid path supplied for cmd(0x%08x)",
				    cmd);
			goto out;
		}
	}

	err = 0;
out:
	return err;
}

/*
 * Get the autofs super block info struct from the file opened on
 * the autofs mount point.
 */
static struct autofs_sb_info *autofs_dev_ioctl_sbi(struct file *f)
{
	struct autofs_sb_info *sbi = NULL;
	struct inode *inode;

	if (f) {
		inode = file_inode(f);
		sbi = autofs4_sbi(inode->i_sb);
	}
	return sbi;
}

/* Return autofs module protocol version */
static int autofs_dev_ioctl_protover(struct file *fp,
				     struct autofs_sb_info *sbi,
				     struct autofs_dev_ioctl *param)
{
	param->protover.version = sbi->version;
	return 0;
}

/* Return autofs module protocol sub version */
static int autofs_dev_ioctl_protosubver(struct file *fp,
					struct autofs_sb_info *sbi,
					struct autofs_dev_ioctl *param)
{
	param->protosubver.sub_version = sbi->sub_version;
	return 0;
}

/* Find the topmost mount satisfying test() */
static int find_autofs_mount(const char *pathname,
			     struct path *res,
			     int test(struct path *path, void *data),
			     void *data)
{
	struct path path;
	int err = kern_path_mountpoint(AT_FDCWD, pathname, &path, 0);
	if (err)
		return err;
	err = -ENOENT;
	while (path.dentry == path.mnt->mnt_root) {
		if (path.dentry->d_sb->s_magic == AUTOFS_SUPER_MAGIC) {
			if (test(&path, data)) {
				path_get(&path);
				*res = path;
				err = 0;
				break;
			}
		}
		if (!follow_up(&path))
			break;
	}
	path_put(&path);
	return err;
}

static int test_by_dev(struct path *path, void *p)
{
	return path->dentry->d_sb->s_dev == *(dev_t *)p;
}

static int test_by_type(struct path *path, void *p)
{
	struct autofs_info *ino = autofs4_dentry_ino(path->dentry);
	return ino && ino->sbi->type & *(unsigned *)p;
}

/*
 * Open a file descriptor on the autofs mount point corresponding
 * to the given path and device number (aka. new_encode_dev(sb->s_dev)).
 */
static int autofs_dev_ioctl_open_mountpoint(const char *name, dev_t devid)
{
	int err, fd;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (likely(fd >= 0)) {
		struct file *filp;
		struct path path;

		err = find_autofs_mount(name, &path, test_by_dev, &devid);
		if (err)
			goto out;

		/*
		 * Find autofs super block that has the device number
		 * corresponding to the autofs fs we want to open.
		 */

		filp = dentry_open(&path, O_RDONLY, current_cred());
		path_put(&path);
		if (IS_ERR(filp)) {
			err = PTR_ERR(filp);
			goto out;
		}

		fd_install(fd, filp);
	}

	return fd;

out:
	put_unused_fd(fd);
	return err;
}

/* Open a file descriptor on an autofs mount point */
static int autofs_dev_ioctl_openmount(struct file *fp,
				      struct autofs_sb_info *sbi,
				      struct autofs_dev_ioctl *param)
{
	const char *path;
	dev_t devid;
	int err, fd;

	/* param->path has already been checked */
	if (!param->openmount.devid)
		return -EINVAL;

	param->ioctlfd = -1;

	path = param->path;
	devid = new_decode_dev(param->openmount.devid);

	err = 0;
	fd = autofs_dev_ioctl_open_mountpoint(path, devid);
	if (unlikely(fd < 0)) {
		err = fd;
		goto out;
	}

	param->ioctlfd = fd;
out:
	return err;
}

/* Close file descriptor allocated above (user can also use close(2)). */
static int autofs_dev_ioctl_closemount(struct file *fp,
				       struct autofs_sb_info *sbi,
				       struct autofs_dev_ioctl *param)
{
	return sys_close(param->ioctlfd);
}

/*
 * Send "ready" status for an existing wait (either a mount or an expire
 * request).
 */
static int autofs_dev_ioctl_ready(struct file *fp,
				  struct autofs_sb_info *sbi,
				  struct autofs_dev_ioctl *param)
{
	autofs_wqt_t token;

	token = (autofs_wqt_t) param->ready.token;
	return autofs4_wait_release(sbi, token, 0);
}

/*
 * Send "fail" status for an existing wait (either a mount or an expire
 * request).
 */
static int autofs_dev_ioctl_fail(struct file *fp,
				 struct autofs_sb_info *sbi,
				 struct autofs_dev_ioctl *param)
{
	autofs_wqt_t token;
	int status;

	token = (autofs_wqt_t) param->fail.token;
	status = param->fail.status ? param->fail.status : -ENOENT;
	return autofs4_wait_release(sbi, token, status);
}

/*
 * Set the pipe fd for kernel communication to the daemon.
 *
 * Normally this is set at mount using an option but if we
 * are reconnecting to a busy mount then we need to use this
 * to tell the autofs mount about the new kernel pipe fd. In
 * order to protect mounts against incorrectly setting the
 * pipefd we also require that the autofs mount be catatonic.
 *
 * This also sets the process group id used to identify the
 * controlling process (eg. the owning automount(8) daemon).
 */
static int autofs_dev_ioctl_setpipefd(struct file *fp,
				      struct autofs_sb_info *sbi,
				      struct autofs_dev_ioctl *param)
{
	int pipefd;
	int err = 0;
	struct pid *new_pid = NULL;

	if (param->setpipefd.pipefd == -1)
		return -EINVAL;

	pipefd = param->setpipefd.pipefd;

	mutex_lock(&sbi->wq_mutex);
	if (!sbi->catatonic) {
		mutex_unlock(&sbi->wq_mutex);
		return -EBUSY;
	} else {
		struct file *pipe;

		new_pid = get_task_pid(current, PIDTYPE_PGID);

		if (ns_of_pid(new_pid) != ns_of_pid(sbi->oz_pgrp)) {
			AUTOFS_WARN("Not allowed to change PID namespace");
			err = -EINVAL;
			goto out;
		}

		pipe = fget(pipefd);
		if (!pipe) {
			err = -EBADF;
			goto out;
		}
		if (autofs_prepare_pipe(pipe) < 0) {
			err = -EPIPE;
			fput(pipe);
			goto out;
		}
		swap(sbi->oz_pgrp, new_pid);
		sbi->pipefd = pipefd;
		sbi->pipe = pipe;
		sbi->catatonic = 0;
	}
out:
	put_pid(new_pid);
	mutex_unlock(&sbi->wq_mutex);
	return err;
}

/*
 * Make the autofs mount point catatonic, no longer responsive to
 * mount requests. Also closes the kernel pipe file descriptor.
 */
static int autofs_dev_ioctl_catatonic(struct file *fp,
				      struct autofs_sb_info *sbi,
				      struct autofs_dev_ioctl *param)
{
	autofs4_catatonic_mode(sbi);
	return 0;
}

/* Set the autofs mount timeout */
static int autofs_dev_ioctl_timeout(struct file *fp,
				    struct autofs_sb_info *sbi,
				    struct autofs_dev_ioctl *param)
{
	unsigned long timeout;

	timeout = param->timeout.timeout;
	param->timeout.timeout = sbi->exp_timeout / HZ;
	sbi->exp_timeout = timeout * HZ;
	return 0;
}

/*
 * Return the uid and gid of the last request for the mount
 *
 * When reconstructing an autofs mount tree with active mounts
 * we need to re-connect to mounts that may have used the original
 * process uid and gid (or string variations of them) for mount
 * lookups within the map entry.
 */
static int autofs_dev_ioctl_requester(struct file *fp,
				      struct autofs_sb_info *sbi,
				      struct autofs_dev_ioctl *param)
{
	struct autofs_info *ino;
	struct path path;
	dev_t devid;
	int err = -ENOENT;

	if (param->size <= sizeof(*param)) {
		err = -EINVAL;
		goto out;
	}

	devid = sbi->sb->s_dev;

	param->requester.uid = param->requester.gid = -1;

	err = find_autofs_mount(param->path, &path, test_by_dev, &devid);
	if (err)
		goto out;

	ino = autofs4_dentry_ino(path.dentry);
	if (ino) {
		err = 0;
		autofs4_expire_wait(path.dentry, 0);
		spin_lock(&sbi->fs_lock);
		param->requester.uid = from_kuid_munged(current_user_ns(), ino->uid);
		param->requester.gid = from_kgid_munged(current_user_ns(), ino->gid);
		spin_unlock(&sbi->fs_lock);
	}
	path_put(&path);
out:
	return err;
}

/*
 * Call repeatedly until it returns -EAGAIN, meaning there's nothing
 * more that can be done.
 */
static int autofs_dev_ioctl_expire(struct file *fp,
				   struct autofs_sb_info *sbi,
				   struct autofs_dev_ioctl *param)
{
	struct vfsmount *mnt;
	int how;

	how = param->expire.how;
	mnt = fp->f_path.mnt;

	return autofs4_do_expire_multi(sbi->sb, mnt, sbi, how);
}

/* Check if autofs mount point is in use */
static int autofs_dev_ioctl_askumount(struct file *fp,
				      struct autofs_sb_info *sbi,
				      struct autofs_dev_ioctl *param)
{
	param->askumount.may_umount = 0;
	if (may_umount(fp->f_path.mnt))
		param->askumount.may_umount = 1;
	return 0;
}

/*
 * Check if the given path is a mountpoint.
 *
 * If we are supplied with the file descriptor of an autofs
 * mount we're looking for a specific mount. In this case
 * the path is considered a mountpoint if it is itself a
 * mountpoint or contains a mount, such as a multi-mount
 * without a root mount. In this case we return 1 if the
 * path is a mount point and the super magic of the covering
 * mount if there is one or 0 if it isn't a mountpoint.
 *
 * If we aren't supplied with a file descriptor then we
 * lookup the path and check if it is the root of a mount.
 * If a type is given we are looking for a particular autofs
 * mount and if we don't find a match we return fail. If the
 * located path is the root of a mount we return 1 along with
 * the super magic of the mount or 0 otherwise.
 *
 * In both cases the the device number (as returned by
 * new_encode_dev()) is also returned.
 */
static int autofs_dev_ioctl_ismountpoint(struct file *fp,
					 struct autofs_sb_info *sbi,
					 struct autofs_dev_ioctl *param)
{
	struct path path;
	const char *name;
	unsigned int type;
	unsigned int devid, magic;
	int err = -ENOENT;

	if (param->size <= sizeof(*param)) {
		err = -EINVAL;
		goto out;
	}

	name = param->path;
	type = param->ismountpoint.in.type;

	param->ismountpoint.out.devid = devid = 0;
	param->ismountpoint.out.magic = magic = 0;

	if (!fp || param->ioctlfd == -1) {
		if (autofs_type_any(type))
			err = kern_path_mountpoint(AT_FDCWD,
						   name, &path, LOOKUP_FOLLOW);
		else
			err = find_autofs_mount(name, &path,
						test_by_type, &type);
		if (err)
			goto out;
		devid = new_encode_dev(path.dentry->d_sb->s_dev);
		err = 0;
		if (path.mnt->mnt_root == path.dentry) {
			err = 1;
			magic = path.dentry->d_sb->s_magic;
		}
	} else {
		dev_t dev = sbi->sb->s_dev;

		err = find_autofs_mount(name, &path, test_by_dev, &dev);
		if (err)
			goto out;

		devid = new_encode_dev(dev);

		err = have_submounts(path.dentry);

		if (follow_down_one(&path))
			magic = path.dentry->d_sb->s_magic;
	}

	param->ismountpoint.out.devid = devid;
	param->ismountpoint.out.magic = magic;
	path_put(&path);
out:
	return err;
}

/*
 * Our range of ioctl numbers isn't 0 based so we need to shift
 * the array index by _IOC_NR(AUTOFS_CTL_IOC_FIRST) for the table
 * lookup.
 */
#define cmd_idx(cmd)	(cmd - _IOC_NR(AUTOFS_DEV_IOCTL_IOC_FIRST))

static ioctl_fn lookup_dev_ioctl(unsigned int cmd)
{
	static struct {
		int cmd;
		ioctl_fn fn;
	} _ioctls[] = {
		{cmd_idx(AUTOFS_DEV_IOCTL_VERSION_CMD), NULL},
		{cmd_idx(AUTOFS_DEV_IOCTL_PROTOVER_CMD),
			 autofs_dev_ioctl_protover},
		{cmd_idx(AUTOFS_DEV_IOCTL_PROTOSUBVER_CMD),
			 autofs_dev_ioctl_protosubver},
		{cmd_idx(AUTOFS_DEV_IOCTL_OPENMOUNT_CMD),
			 autofs_dev_ioctl_openmount},
		{cmd_idx(AUTOFS_DEV_IOCTL_CLOSEMOUNT_CMD),
			 autofs_dev_ioctl_closemount},
		{cmd_idx(AUTOFS_DEV_IOCTL_READY_CMD),
			 autofs_dev_ioctl_ready},
		{cmd_idx(AUTOFS_DEV_IOCTL_FAIL_CMD),
			 autofs_dev_ioctl_fail},
		{cmd_idx(AUTOFS_DEV_IOCTL_SETPIPEFD_CMD),
			 autofs_dev_ioctl_setpipefd},
		{cmd_idx(AUTOFS_DEV_IOCTL_CATATONIC_CMD),
			 autofs_dev_ioctl_catatonic},
		{cmd_idx(AUTOFS_DEV_IOCTL_TIMEOUT_CMD),
			 autofs_dev_ioctl_timeout},
		{cmd_idx(AUTOFS_DEV_IOCTL_REQUESTER_CMD),
			 autofs_dev_ioctl_requester},
		{cmd_idx(AUTOFS_DEV_IOCTL_EXPIRE_CMD),
			 autofs_dev_ioctl_expire},
		{cmd_idx(AUTOFS_DEV_IOCTL_ASKUMOUNT_CMD),
			 autofs_dev_ioctl_askumount},
		{cmd_idx(AUTOFS_DEV_IOCTL_ISMOUNTPOINT_CMD),
			 autofs_dev_ioctl_ismountpoint}
	};
	unsigned int idx = cmd_idx(cmd);

	return (idx >= ARRAY_SIZE(_ioctls)) ? NULL : _ioctls[idx].fn;
}

/* ioctl dispatcher */
static int _autofs_dev_ioctl(unsigned int command, struct autofs_dev_ioctl __user *user)
{
	struct autofs_dev_ioctl *param;
	struct file *fp;
	struct autofs_sb_info *sbi;
	unsigned int cmd_first, cmd;
	ioctl_fn fn = NULL;
	int err = 0;

	/* only root can play with this */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	cmd_first = _IOC_NR(AUTOFS_DEV_IOCTL_IOC_FIRST);
	cmd = _IOC_NR(command);

	if (_IOC_TYPE(command) != _IOC_TYPE(AUTOFS_DEV_IOCTL_IOC_FIRST) ||
	    cmd - cmd_first >= AUTOFS_DEV_IOCTL_IOC_COUNT) {
		return -ENOTTY;
	}

	/* Copy the parameters into kernel space. */
	param = copy_dev_ioctl(user);
	if (IS_ERR(param))
		return PTR_ERR(param);

	err = validate_dev_ioctl(command, param);
	if (err)
		goto out;

	/* The validate routine above always sets the version */
	if (cmd == AUTOFS_DEV_IOCTL_VERSION_CMD)
		goto done;

	fn = lookup_dev_ioctl(cmd);
	if (!fn) {
		AUTOFS_WARN("unknown command 0x%08x", command);
		return -ENOTTY;
	}

	fp = NULL;
	sbi = NULL;

	/*
	 * For obvious reasons the openmount can't have a file
	 * descriptor yet. We don't take a reference to the
	 * file during close to allow for immediate release.
	 */
	if (cmd != AUTOFS_DEV_IOCTL_OPENMOUNT_CMD &&
	    cmd != AUTOFS_DEV_IOCTL_CLOSEMOUNT_CMD) {
		fp = fget(param->ioctlfd);
		if (!fp) {
			if (cmd == AUTOFS_DEV_IOCTL_ISMOUNTPOINT_CMD)
				goto cont;
			err = -EBADF;
			goto out;
		}

		sbi = autofs_dev_ioctl_sbi(fp);
		if (!sbi || sbi->magic != AUTOFS_SBI_MAGIC) {
			err = -EINVAL;
			fput(fp);
			goto out;
		}

		/*
		 * Admin needs to be able to set the mount catatonic in
		 * order to be able to perform the re-open.
		 */
		if (!autofs4_oz_mode(sbi) &&
		    cmd != AUTOFS_DEV_IOCTL_CATATONIC_CMD) {
			err = -EACCES;
			fput(fp);
			goto out;
		}
	}
cont:
	err = fn(fp, sbi, param);

	if (fp)
		fput(fp);
done:
	if (err >= 0 && copy_to_user(user, param, AUTOFS_DEV_IOCTL_SIZE))
		err = -EFAULT;
out:
	free_dev_ioctl(param);
	return err;
}

static long autofs_dev_ioctl(struct file *file, uint command, ulong u)
{
	int err;
	err = _autofs_dev_ioctl(command, (struct autofs_dev_ioctl __user *) u);
	return (long) err;
}

#ifdef CONFIG_COMPAT
static long autofs_dev_ioctl_compat(struct file *file, uint command, ulong u)
{
	return (long) autofs_dev_ioctl(file, command, (ulong) compat_ptr(u));
}
#else
#define autofs_dev_ioctl_compat NULL
#endif

static const struct file_operations _dev_ioctl_fops = {
	.unlocked_ioctl	 = autofs_dev_ioctl,
	.compat_ioctl = autofs_dev_ioctl_compat,
	.owner	 = THIS_MODULE,
	.llseek = noop_llseek,
};

static struct miscdevice _autofs_dev_ioctl_misc = {
	.minor		= AUTOFS_MINOR,
	.name  		= AUTOFS_DEVICE_NAME,
	.fops  		= &_dev_ioctl_fops
};

MODULE_ALIAS_MISCDEV(AUTOFS_MINOR);
MODULE_ALIAS("devname:autofs");

/* Register/deregister misc character device */
int __init autofs_dev_ioctl_init(void)
{
	int r;

	r = misc_register(&_autofs_dev_ioctl_misc);
	if (r) {
		AUTOFS_ERROR("misc_register failed for control device");
		return r;
	}

	return 0;
}

void autofs_dev_ioctl_exit(void)
{
	misc_deregister(&_autofs_dev_ioctl_misc);
	return;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/autofs4/dev-ioctl.c */
/************************************************************/
