/*
 *  linux/fs/9p/vfs_super.c
 *
 * This file contians superblock ops for 9P2000. It is intended that
 * you mount this file system on directories.
 *
 *  Copyright (C) 2004 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/idr.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/magic.h>
#include <net/9p/9p.h>
#include <net/9p/client.h>
#include "../../inc/__fss.h"

#include "v9fs.h"
#include "v9fs_vfs.h"
#include "fid.h"
#include "xattr.h"
#include "acl.h"
#include "../../inc/__fss.h"

static const struct super_operations v9fs_super_ops, v9fs_super_ops_dotl;

/**
 * v9fs_set_super - set the superblock
 * @s: super block
 * @data: file system specific data
 *
 */

static int v9fs_set_super(struct super_block *s, void *data)
{
	s->s_fs_info = data;
	return set_anon_super(s, data);
}

/**
 * v9fs_fill_super - populate superblock with info
 * @sb: superblock
 * @v9ses: session information
 * @flags: flags propagated from v9fs_mount()
 *
 */

static void
v9fs_fill_super(struct super_block *sb, struct v9fs_session_info *v9ses,
		int flags, void *data)
{
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize_bits = fls(v9ses->maxdata - 1);
	sb->s_blocksize = 1 << sb->s_blocksize_bits;
	sb->s_magic = V9FS_MAGIC;
	if (v9fs_proto_dotl(v9ses)) {
		sb->s_op = &v9fs_super_ops_dotl;
		sb->s_xattr = v9fs_xattr_handlers;
	} else
		sb->s_op = &v9fs_super_ops;
	sb->s_bdi = &v9ses->bdi;
	if (v9ses->cache)
		sb->s_bdi->ra_pages = (VM_MAX_READAHEAD * 1024)/PAGE_CACHE_SIZE;

	sb->s_flags |= MS_ACTIVE | MS_DIRSYNC | MS_NOATIME;
	if (!v9ses->cache)
		sb->s_flags |= MS_SYNCHRONOUS;

#ifdef CONFIG_9P_FS_POSIX_ACL
	if ((v9ses->flags & V9FS_ACL_MASK) == V9FS_POSIX_ACL)
		sb->s_flags |= MS_POSIXACL;
#endif

	save_mount_options(sb, data);
}

/**
 * v9fs_mount - mount a superblock
 * @fs_type: file system type
 * @flags: mount flags
 * @dev_name: device name that was mounted
 * @data: mount options
 *
 */

static struct dentry *v9fs_mount(struct file_system_type *fs_type, int flags,
		       const char *dev_name, void *data)
{
	struct super_block *sb = NULL;
	struct inode *inode = NULL;
	struct dentry *root = NULL;
	struct v9fs_session_info *v9ses = NULL;
	umode_t mode = S_IRWXUGO | S_ISVTX;
	struct p9_fid *fid;
	int retval = 0;

	p9_debug(P9_DEBUG_VFS, "\n");

	v9ses = kzalloc(sizeof(struct v9fs_session_info), GFP_KERNEL);
	if (!v9ses)
		return ERR_PTR(-ENOMEM);

	fid = v9fs_session_init(v9ses, dev_name, data);
	if (IS_ERR(fid)) {
		retval = PTR_ERR(fid);
		/*
		 * we need to call session_close to tear down some
		 * of the data structure setup by session_init
		 */
		goto close_session;
	}

	sb = sget(fs_type, NULL, v9fs_set_super, flags, v9ses);
	if (IS_ERR(sb)) {
		retval = PTR_ERR(sb);
		goto clunk_fid;
	}
	v9fs_fill_super(sb, v9ses, flags, data);

	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE)
		sb->s_d_op = &v9fs_cached_dentry_operations;
	else
		sb->s_d_op = &v9fs_dentry_operations;

	inode = v9fs_get_inode(sb, S_IFDIR | mode, 0);
	if (IS_ERR(inode)) {
		retval = PTR_ERR(inode);
		goto release_sb;
	}

	root = d_make_root(inode);
	if (!root) {
		retval = -ENOMEM;
		goto release_sb;
	}
	sb->s_root = root;
	if (v9fs_proto_dotl(v9ses)) {
		struct p9_stat_dotl *st = NULL;
		st = p9_client_getattr_dotl(fid, P9_STATS_BASIC);
		if (IS_ERR(st)) {
			retval = PTR_ERR(st);
			goto release_sb;
		}
		root->d_inode->i_ino = v9fs_qid2ino(&st->qid);
		v9fs_stat2inode_dotl(st, root->d_inode);
		kfree(st);
	} else {
		struct p9_wstat *st = NULL;
		st = p9_client_stat(fid);
		if (IS_ERR(st)) {
			retval = PTR_ERR(st);
			goto release_sb;
		}

		root->d_inode->i_ino = v9fs_qid2ino(&st->qid);
		v9fs_stat2inode(st, root->d_inode, sb);

		p9stat_free(st);
		kfree(st);
	}
	retval = v9fs_get_acl(inode, fid);
	if (retval)
		goto release_sb;
	v9fs_fid_add(root, fid);

	p9_debug(P9_DEBUG_VFS, " simple set mount, return 0\n");
	return dget(sb->s_root);

clunk_fid:
	p9_client_clunk(fid);
close_session:
	v9fs_session_close(v9ses);
	kfree(v9ses);
	return ERR_PTR(retval);

release_sb:
	/*
	 * we will do the session_close and root dentry release
	 * in the below call. But we need to clunk fid, because we haven't
	 * attached the fid to dentry so it won't get clunked
	 * automatically.
	 */
	p9_client_clunk(fid);
	deactivate_locked_super(sb);
	return ERR_PTR(retval);
}

/**
 * v9fs_kill_super - Kill Superblock
 * @s: superblock
 *
 */

static void v9fs_kill_super(struct super_block *s)
{
	struct v9fs_session_info *v9ses = s->s_fs_info;

	p9_debug(P9_DEBUG_VFS, " %p\n", s);

	kill_anon_super(s);

	v9fs_session_cancel(v9ses);
	v9fs_session_close(v9ses);
	kfree(v9ses);
	s->s_fs_info = NULL;
	p9_debug(P9_DEBUG_VFS, "exiting kill_super\n");
}

static void
v9fs_umount_begin(struct super_block *sb)
{
	struct v9fs_session_info *v9ses;

	v9ses = sb->s_fs_info;
	v9fs_session_begin_cancel(v9ses);
}

static int v9fs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct v9fs_session_info *v9ses;
	struct p9_fid *fid;
	struct p9_rstatfs rs;
	int res;

	fid = v9fs_fid_lookup(dentry);
	if (IS_ERR(fid)) {
		res = PTR_ERR(fid);
		goto done;
	}

	v9ses = v9fs_dentry2v9ses(dentry);
	if (v9fs_proto_dotl(v9ses)) {
		res = p9_client_statfs(fid, &rs);
		if (res == 0) {
			buf->f_type = rs.type;
			buf->f_bsize = rs.bsize;
			buf->f_blocks = rs.blocks;
			buf->f_bfree = rs.bfree;
			buf->f_bavail = rs.bavail;
			buf->f_files = rs.files;
			buf->f_ffree = rs.ffree;
			buf->f_fsid.val[0] = rs.fsid & 0xFFFFFFFFUL;
			buf->f_fsid.val[1] = (rs.fsid >> 32) & 0xFFFFFFFFUL;
			buf->f_namelen = rs.namelen;
		}
		if (res != -ENOSYS)
			goto done;
	}
	res = simple_statfs(dentry, buf);
done:
	return res;
}

static int v9fs_drop_inode(struct inode *inode)
{
	struct v9fs_session_info *v9ses;
	v9ses = v9fs_inode2v9ses(inode);
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE)
		return generic_drop_inode(inode);
	/*
	 * in case of non cached mode always drop the
	 * the inode because we want the inode attribute
	 * to always match that on the server.
	 */
	return 1;
}

static int v9fs_write_inode(struct inode *inode,
			    struct writeback_control *wbc)
{
	int ret;
	struct p9_wstat wstat;
	struct v9fs_inode *v9inode;
	/*
	 * send an fsync request to server irrespective of
	 * wbc->sync_mode.
	 */
	p9_debug(P9_DEBUG_VFS, "%s: inode %p\n", __func__, inode);
	v9inode = V9FS_I(inode);
	if (!v9inode->writeback_fid)
		return 0;
	v9fs_blank_wstat(&wstat);

	ret = p9_client_wstat(v9inode->writeback_fid, &wstat);
	if (ret < 0) {
		__mark_inode_dirty(inode, I_DIRTY_DATASYNC);
		return ret;
	}
	return 0;
}

static int v9fs_write_inode_dotl(struct inode *inode,
				 struct writeback_control *wbc)
{
	int ret;
	struct v9fs_inode *v9inode;
	/*
	 * send an fsync request to server irrespective of
	 * wbc->sync_mode.
	 */
	v9inode = V9FS_I(inode);
	p9_debug(P9_DEBUG_VFS, "%s: inode %p, writeback_fid %p\n",
		 __func__, inode, v9inode->writeback_fid);
	if (!v9inode->writeback_fid)
		return 0;

	ret = p9_client_fsync(v9inode->writeback_fid, 0);
	if (ret < 0) {
		__mark_inode_dirty(inode, I_DIRTY_DATASYNC);
		return ret;
	}
	return 0;
}

static const struct super_operations v9fs_super_ops = {
	.alloc_inode = v9fs_alloc_inode,
	.destroy_inode = v9fs_destroy_inode,
	.statfs = simple_statfs,
	.evict_inode = v9fs_evict_inode,
	.show_options = generic_show_options,
	.umount_begin = v9fs_umount_begin,
	.write_inode = v9fs_write_inode,
};

static const struct super_operations v9fs_super_ops_dotl = {
	.alloc_inode = v9fs_alloc_inode,
	.destroy_inode = v9fs_destroy_inode,
	.statfs = v9fs_statfs,
	.drop_inode = v9fs_drop_inode,
	.evict_inode = v9fs_evict_inode,
	.show_options = generic_show_options,
	.umount_begin = v9fs_umount_begin,
	.write_inode = v9fs_write_inode_dotl,
};

struct file_system_type v9fs_fs_type = {
	.name = "9p",
	.mount = v9fs_mount,
	.kill_sb = v9fs_kill_super,
	.owner = THIS_MODULE,
	.fs_flags = FS_RENAME_DOES_D_MOVE,
};
MODULE_ALIAS_FS("9p");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/vfs_super.c */
/************************************************************/
/*
 *  linux/fs/9p/vfs_inode.c
 *
 * This file contains vfs inode ops for the 9P2000 protocol.
 *
 *  Copyright (C) 2004 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/module.h>
// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/file.h>
// #include <linux/pagemap.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <linux/inet.h>
#include <linux/namei.h>
// #include <linux/idr.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>
#include "../../inc/__fss.h"

// #include "v9fs.h"
// #include "v9fs_vfs.h"
// #include "fid.h"
#include "cache.h"
// #include "xattr.h"
// #include "acl.h"
#include "../../inc/__fss.h"

static const struct inode_operations v9fs_dir_inode_operations;
static const struct inode_operations v9fs_dir_inode_operations_dotu;
static const struct inode_operations v9fs_file_inode_operations;
static const struct inode_operations v9fs_symlink_inode_operations;

/**
 * unixmode2p9mode - convert unix mode bits to plan 9
 * @v9ses: v9fs session information
 * @mode: mode to convert
 *
 */

static u32 unixmode2p9mode(struct v9fs_session_info *v9ses, umode_t mode)
{
	int res;
	res = mode & 0777;
	if (S_ISDIR(mode))
		res |= P9_DMDIR;
	if (v9fs_proto_dotu(v9ses)) {
		if (v9ses->nodev == 0) {
			if (S_ISSOCK(mode))
				res |= P9_DMSOCKET;
			if (S_ISFIFO(mode))
				res |= P9_DMNAMEDPIPE;
			if (S_ISBLK(mode))
				res |= P9_DMDEVICE;
			if (S_ISCHR(mode))
				res |= P9_DMDEVICE;
		}

		if ((mode & S_ISUID) == S_ISUID)
			res |= P9_DMSETUID;
		if ((mode & S_ISGID) == S_ISGID)
			res |= P9_DMSETGID;
		if ((mode & S_ISVTX) == S_ISVTX)
			res |= P9_DMSETVTX;
	}
	return res;
}

/**
 * p9mode2perm- convert plan9 mode bits to unix permission bits
 * @v9ses: v9fs session information
 * @stat: p9_wstat from which mode need to be derived
 *
 */
static int p9mode2perm(struct v9fs_session_info *v9ses,
		       struct p9_wstat *stat)
{
	int res;
	int mode = stat->mode;

	res = mode & S_IALLUGO;
	if (v9fs_proto_dotu(v9ses)) {
		if ((mode & P9_DMSETUID) == P9_DMSETUID)
			res |= S_ISUID;

		if ((mode & P9_DMSETGID) == P9_DMSETGID)
			res |= S_ISGID;

		if ((mode & P9_DMSETVTX) == P9_DMSETVTX)
			res |= S_ISVTX;
	}
	return res;
}

/**
 * p9mode2unixmode- convert plan9 mode bits to unix mode bits
 * @v9ses: v9fs session information
 * @stat: p9_wstat from which mode need to be derived
 * @rdev: major number, minor number in case of device files.
 *
 */
static umode_t p9mode2unixmode(struct v9fs_session_info *v9ses,
			       struct p9_wstat *stat, dev_t *rdev)
{
	int res;
	u32 mode = stat->mode;

	*rdev = 0;
	res = p9mode2perm(v9ses, stat);

	if ((mode & P9_DMDIR) == P9_DMDIR)
		res |= S_IFDIR;
	else if ((mode & P9_DMSYMLINK) && (v9fs_proto_dotu(v9ses)))
		res |= S_IFLNK;
	else if ((mode & P9_DMSOCKET) && (v9fs_proto_dotu(v9ses))
		 && (v9ses->nodev == 0))
		res |= S_IFSOCK;
	else if ((mode & P9_DMNAMEDPIPE) && (v9fs_proto_dotu(v9ses))
		 && (v9ses->nodev == 0))
		res |= S_IFIFO;
	else if ((mode & P9_DMDEVICE) && (v9fs_proto_dotu(v9ses))
		 && (v9ses->nodev == 0)) {
		char type = 0, ext[32];
		int major = -1, minor = -1;

		strlcpy(ext, stat->extension, sizeof(ext));
		sscanf(ext, "%c %i %i", &type, &major, &minor);
		switch (type) {
		case 'c':
			res |= S_IFCHR;
			break;
		case 'b':
			res |= S_IFBLK;
			break;
		default:
			p9_debug(P9_DEBUG_ERROR, "Unknown special type %c %s\n",
				 type, stat->extension);
		};
		*rdev = MKDEV(major, minor);
	} else
		res |= S_IFREG;

	return res;
}

/**
 * v9fs_uflags2omode- convert posix open flags to plan 9 mode bits
 * @uflags: flags to convert
 * @extended: if .u extensions are active
 */

int v9fs_uflags2omode(int uflags, int extended)
{
	int ret;

	ret = 0;
	switch (uflags&3) {
	default:
	case O_RDONLY:
		ret = P9_OREAD;
		break;

	case O_WRONLY:
		ret = P9_OWRITE;
		break;

	case O_RDWR:
		ret = P9_ORDWR;
		break;
	}

	if (extended) {
		if (uflags & O_EXCL)
			ret |= P9_OEXCL;

		if (uflags & O_APPEND)
			ret |= P9_OAPPEND;
	}

	return ret;
}

/**
 * v9fs_blank_wstat - helper function to setup a 9P stat structure
 * @wstat: structure to initialize
 *
 */

void
v9fs_blank_wstat(struct p9_wstat *wstat)
{
	wstat->type = ~0;
	wstat->dev = ~0;
	wstat->qid.type = ~0;
	wstat->qid.version = ~0;
	*((long long *)&wstat->qid.path) = ~0;
	wstat->mode = ~0;
	wstat->atime = ~0;
	wstat->mtime = ~0;
	wstat->length = ~0;
	wstat->name = NULL;
	wstat->uid = NULL;
	wstat->gid = NULL;
	wstat->muid = NULL;
	wstat->n_uid = INVALID_UID;
	wstat->n_gid = INVALID_GID;
	wstat->n_muid = INVALID_UID;
	wstat->extension = NULL;
}

/**
 * v9fs_alloc_inode - helper function to allocate an inode
 *
 */
struct inode *v9fs_alloc_inode(struct super_block *sb)
{
	struct v9fs_inode *v9inode;
	v9inode = (struct v9fs_inode *)kmem_cache_alloc(v9fs_inode_cache,
							GFP_KERNEL);
	if (!v9inode)
		return NULL;
#ifdef CONFIG_9P_FSCACHE
	v9inode->fscache = NULL;
	spin_lock_init(&v9inode->fscache_lock);
#endif
	v9inode->writeback_fid = NULL;
	v9inode->cache_validity = 0;
	mutex_init(&v9inode->v_mutex);
	return &v9inode->vfs_inode;
}

/**
 * v9fs_destroy_inode - destroy an inode
 *
 */

static void v9fs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(v9fs_inode_cache, V9FS_I(inode));
}

void v9fs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, v9fs_i_callback);
}

int v9fs_init_inode(struct v9fs_session_info *v9ses,
		    struct inode *inode, umode_t mode, dev_t rdev)
{
	int err = 0;

	inode_init_owner(inode, NULL, mode);
	inode->i_blocks = 0;
	inode->i_rdev = rdev;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_mapping->a_ops = &v9fs_addr_operations;

	switch (mode & S_IFMT) {
	case S_IFIFO:
	case S_IFBLK:
	case S_IFCHR:
	case S_IFSOCK:
		if (v9fs_proto_dotl(v9ses)) {
			inode->i_op = &v9fs_file_inode_operations_dotl;
		} else if (v9fs_proto_dotu(v9ses)) {
			inode->i_op = &v9fs_file_inode_operations;
		} else {
			p9_debug(P9_DEBUG_ERROR,
				 "special files without extended mode\n");
			err = -EINVAL;
			goto error;
		}
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		break;
	case S_IFREG:
		if (v9fs_proto_dotl(v9ses)) {
			inode->i_op = &v9fs_file_inode_operations_dotl;
			if (v9ses->cache == CACHE_LOOSE ||
			    v9ses->cache == CACHE_FSCACHE)
				inode->i_fop =
					&v9fs_cached_file_operations_dotl;
			else if (v9ses->cache == CACHE_MMAP)
				inode->i_fop = &v9fs_mmap_file_operations_dotl;
			else
				inode->i_fop = &v9fs_file_operations_dotl;
		} else {
			inode->i_op = &v9fs_file_inode_operations;
			if (v9ses->cache == CACHE_LOOSE ||
			    v9ses->cache == CACHE_FSCACHE)
				inode->i_fop =
					&v9fs_cached_file_operations;
			else if (v9ses->cache == CACHE_MMAP)
				inode->i_fop = &v9fs_mmap_file_operations;
			else
				inode->i_fop = &v9fs_file_operations;
		}

		break;
	case S_IFLNK:
		if (!v9fs_proto_dotu(v9ses) && !v9fs_proto_dotl(v9ses)) {
			p9_debug(P9_DEBUG_ERROR,
				 "extended modes used with legacy protocol\n");
			err = -EINVAL;
			goto error;
		}

		if (v9fs_proto_dotl(v9ses))
			inode->i_op = &v9fs_symlink_inode_operations_dotl;
		else
			inode->i_op = &v9fs_symlink_inode_operations;

		break;
	case S_IFDIR:
		inc_nlink(inode);
		if (v9fs_proto_dotl(v9ses))
			inode->i_op = &v9fs_dir_inode_operations_dotl;
		else if (v9fs_proto_dotu(v9ses))
			inode->i_op = &v9fs_dir_inode_operations_dotu;
		else
			inode->i_op = &v9fs_dir_inode_operations;

		if (v9fs_proto_dotl(v9ses))
			inode->i_fop = &v9fs_dir_operations_dotl;
		else
			inode->i_fop = &v9fs_dir_operations;

		break;
	default:
		p9_debug(P9_DEBUG_ERROR, "BAD mode 0x%hx S_IFMT 0x%x\n",
			 mode, mode & S_IFMT);
		err = -EINVAL;
		goto error;
	}
error:
	return err;

}

/**
 * v9fs_get_inode - helper function to setup an inode
 * @sb: superblock
 * @mode: mode to setup inode with
 *
 */

struct inode *v9fs_get_inode(struct super_block *sb, umode_t mode, dev_t rdev)
{
	int err;
	struct inode *inode;
	struct v9fs_session_info *v9ses = sb->s_fs_info;

	p9_debug(P9_DEBUG_VFS, "super block: %p mode: %ho\n", sb, mode);

	inode = new_inode(sb);
	if (!inode) {
		pr_warn("%s (%d): Problem allocating inode\n",
			__func__, task_pid_nr(current));
		return ERR_PTR(-ENOMEM);
	}
	err = v9fs_init_inode(v9ses, inode, mode, rdev);
	if (err) {
		iput(inode);
		return ERR_PTR(err);
	}
	return inode;
}

/*
static struct v9fs_fid*
v9fs_clone_walk(struct v9fs_session_info *v9ses, u32 fid, struct dentry *dentry)
{
	int err;
	int nfid;
	struct v9fs_fid *ret;
	struct v9fs_fcall *fcall;

	nfid = v9fs_get_idpool(&v9ses->fidpool);
	if (nfid < 0) {
		eprintk(KERN_WARNING, "no free fids available\n");
		return ERR_PTR(-ENOSPC);
	}

	err = v9fs_t_walk(v9ses, fid, nfid, (char *) dentry->d_name.name,
		&fcall);

	if (err < 0) {
		if (fcall && fcall->id == RWALK)
			goto clunk_fid;

		PRINT_FCALL_ERROR("walk error", fcall);
		v9fs_put_idpool(nfid, &v9ses->fidpool);
		goto error;
	}

	kfree(fcall);
	fcall = NULL;
	ret = v9fs_fid_create(v9ses, nfid);
	if (!ret) {
		err = -ENOMEM;
		goto clunk_fid;
	}

	err = v9fs_fid_insert(ret, dentry);
	if (err < 0) {
		v9fs_fid_destroy(ret);
		goto clunk_fid;
	}

	return ret;

clunk_fid:
	v9fs_t_clunk(v9ses, nfid);

error:
	kfree(fcall);
	return ERR_PTR(err);
}
*/


/**
 * v9fs_clear_inode - release an inode
 * @inode: inode to release
 *
 */
void v9fs_evict_inode(struct inode *inode)
{
	struct v9fs_inode *v9inode = V9FS_I(inode);

	truncate_inode_pages_final(inode->i_mapping);
	clear_inode(inode);
	filemap_fdatawrite(inode->i_mapping);

	v9fs_cache_inode_put_cookie(inode);
	/* clunk the fid stashed in writeback_fid */
	if (v9inode->writeback_fid) {
		p9_client_clunk(v9inode->writeback_fid);
		v9inode->writeback_fid = NULL;
	}
}

static int v9fs_test_inode(struct inode *inode, void *data)
{
	int umode;
	dev_t rdev;
	struct v9fs_inode *v9inode = V9FS_I(inode);
	struct p9_wstat *st = (struct p9_wstat *)data;
	struct v9fs_session_info *v9ses = v9fs_inode2v9ses(inode);

	umode = p9mode2unixmode(v9ses, st, &rdev);
	/* don't match inode of different type */
	if ((inode->i_mode & S_IFMT) != (umode & S_IFMT))
		return 0;

	/* compare qid details */
	if (memcmp(&v9inode->qid.version,
		   &st->qid.version, sizeof(v9inode->qid.version)))
		return 0;

	if (v9inode->qid.type != st->qid.type)
		return 0;
	return 1;
}

static int v9fs_test_new_inode(struct inode *inode, void *data)
{
	return 0;
}

static int v9fs_set_inode(struct inode *inode,  void *data)
{
	struct v9fs_inode *v9inode = V9FS_I(inode);
	struct p9_wstat *st = (struct p9_wstat *)data;

	memcpy(&v9inode->qid, &st->qid, sizeof(st->qid));
	return 0;
}

static struct inode *v9fs_qid_iget(struct super_block *sb,
				   struct p9_qid *qid,
				   struct p9_wstat *st,
				   int new)
{
	dev_t rdev;
	int retval;
	umode_t umode;
	unsigned long i_ino;
	struct inode *inode;
	struct v9fs_session_info *v9ses = sb->s_fs_info;
	int (*test)(struct inode *, void *);

	if (new)
		test = v9fs_test_new_inode;
	else
		test = v9fs_test_inode;

	i_ino = v9fs_qid2ino(qid);
	inode = iget5_locked(sb, i_ino, test, v9fs_set_inode, st);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;
	/*
	 * initialize the inode with the stat info
	 * FIXME!! we may need support for stale inodes
	 * later.
	 */
	inode->i_ino = i_ino;
	umode = p9mode2unixmode(v9ses, st, &rdev);
	retval = v9fs_init_inode(v9ses, inode, umode, rdev);
	if (retval)
		goto error;

	v9fs_stat2inode(st, inode, sb);
	v9fs_cache_inode_get_cookie(inode);
	unlock_new_inode(inode);
	return inode;
error:
	unlock_new_inode(inode);
	iput(inode);
	return ERR_PTR(retval);

}

struct inode *
v9fs_inode_from_fid(struct v9fs_session_info *v9ses, struct p9_fid *fid,
		    struct super_block *sb, int new)
{
	struct p9_wstat *st;
	struct inode *inode = NULL;

	st = p9_client_stat(fid);
	if (IS_ERR(st))
		return ERR_CAST(st);

	inode = v9fs_qid_iget(sb, &st->qid, st, new);
	p9stat_free(st);
	kfree(st);
	return inode;
}

/**
 * v9fs_at_to_dotl_flags- convert Linux specific AT flags to
 * plan 9 AT flag.
 * @flags: flags to convert
 */
static int v9fs_at_to_dotl_flags(int flags)
{
	int rflags = 0;
	if (flags & AT_REMOVEDIR)
		rflags |= P9_DOTL_AT_REMOVEDIR;
	return rflags;
}

/**
 * v9fs_remove - helper function to remove files and directories
 * @dir: directory inode that is being deleted
 * @dentry:  dentry that is being deleted
 * @flags: removing a directory
 *
 */

static int v9fs_remove(struct inode *dir, struct dentry *dentry, int flags)
{
	struct inode *inode;
	int retval = -EOPNOTSUPP;
	struct p9_fid *v9fid, *dfid;
	struct v9fs_session_info *v9ses;

	p9_debug(P9_DEBUG_VFS, "inode: %p dentry: %p rmdir: %x\n",
		 dir, dentry, flags);

	v9ses = v9fs_inode2v9ses(dir);
	inode = dentry->d_inode;
	dfid = v9fs_fid_lookup(dentry->d_parent);
	if (IS_ERR(dfid)) {
		retval = PTR_ERR(dfid);
		p9_debug(P9_DEBUG_VFS, "fid lookup failed %d\n", retval);
		return retval;
	}
	if (v9fs_proto_dotl(v9ses))
		retval = p9_client_unlinkat(dfid, dentry->d_name.name,
					    v9fs_at_to_dotl_flags(flags));
	if (retval == -EOPNOTSUPP) {
		/* Try the one based on path */
		v9fid = v9fs_fid_clone(dentry);
		if (IS_ERR(v9fid))
			return PTR_ERR(v9fid);
		retval = p9_client_remove(v9fid);
	}
	if (!retval) {
		/*
		 * directories on unlink should have zero
		 * link count
		 */
		if (flags & AT_REMOVEDIR) {
			clear_nlink(inode);
			drop_nlink(dir);
		} else
			drop_nlink(inode);

		v9fs_invalidate_inode_attr(inode);
		v9fs_invalidate_inode_attr(dir);
	}
	return retval;
}

/**
 * v9fs_create - Create a file
 * @v9ses: session information
 * @dir: directory that dentry is being created in
 * @dentry:  dentry that is being created
 * @extension: 9p2000.u extension string to support devices, etc.
 * @perm: create permissions
 * @mode: open mode
 *
 */
static struct p9_fid *
v9fs_create(struct v9fs_session_info *v9ses, struct inode *dir,
		struct dentry *dentry, char *extension, u32 perm, u8 mode)
{
	int err;
	char *name;
	struct p9_fid *dfid, *ofid, *fid;
	struct inode *inode;

	p9_debug(P9_DEBUG_VFS, "name %pd\n", dentry);

	err = 0;
	ofid = NULL;
	fid = NULL;
	name = (char *) dentry->d_name.name;
	dfid = v9fs_fid_lookup(dentry->d_parent);
	if (IS_ERR(dfid)) {
		err = PTR_ERR(dfid);
		p9_debug(P9_DEBUG_VFS, "fid lookup failed %d\n", err);
		return ERR_PTR(err);
	}

	/* clone a fid to use for creation */
	ofid = p9_client_walk(dfid, 0, NULL, 1);
	if (IS_ERR(ofid)) {
		err = PTR_ERR(ofid);
		p9_debug(P9_DEBUG_VFS, "p9_client_walk failed %d\n", err);
		return ERR_PTR(err);
	}

	err = p9_client_fcreate(ofid, name, perm, mode, extension);
	if (err < 0) {
		p9_debug(P9_DEBUG_VFS, "p9_client_fcreate failed %d\n", err);
		goto error;
	}

	if (!(perm & P9_DMLINK)) {
		/* now walk from the parent so we can get unopened fid */
		fid = p9_client_walk(dfid, 1, &name, 1);
		if (IS_ERR(fid)) {
			err = PTR_ERR(fid);
			p9_debug(P9_DEBUG_VFS,
				   "p9_client_walk failed %d\n", err);
			fid = NULL;
			goto error;
		}
		/*
		 * instantiate inode and assign the unopened fid to the dentry
		 */
		inode = v9fs_get_new_inode_from_fid(v9ses, fid, dir->i_sb);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			p9_debug(P9_DEBUG_VFS,
				   "inode creation failed %d\n", err);
			goto error;
		}
		v9fs_fid_add(dentry, fid);
		d_instantiate(dentry, inode);
	}
	return ofid;
error:
	if (ofid)
		p9_client_clunk(ofid);

	if (fid)
		p9_client_clunk(fid);

	return ERR_PTR(err);
}

/**
 * v9fs_vfs_create - VFS hook to create a regular file
 *
 * open(.., O_CREAT) is handled in v9fs_vfs_atomic_open().  This is only called
 * for mknod(2).
 *
 * @dir: directory inode that is being created
 * @dentry:  dentry that is being deleted
 * @mode: create permissions
 *
 */

static int
v9fs_vfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	struct v9fs_session_info *v9ses = v9fs_inode2v9ses(dir);
	u32 perm = unixmode2p9mode(v9ses, mode);
	struct p9_fid *fid;

	/* P9_OEXCL? */
	fid = v9fs_create(v9ses, dir, dentry, NULL, perm, P9_ORDWR);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	v9fs_invalidate_inode_attr(dir);
	p9_client_clunk(fid);

	return 0;
}

/**
 * v9fs_vfs_mkdir - VFS mkdir hook to create a directory
 * @dir:  inode that is being unlinked
 * @dentry: dentry that is being unlinked
 * @mode: mode for new directory
 *
 */

static int v9fs_vfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	u32 perm;
	struct p9_fid *fid;
	struct v9fs_session_info *v9ses;

	p9_debug(P9_DEBUG_VFS, "name %pd\n", dentry);
	err = 0;
	v9ses = v9fs_inode2v9ses(dir);
	perm = unixmode2p9mode(v9ses, mode | S_IFDIR);
	fid = v9fs_create(v9ses, dir, dentry, NULL, perm, P9_OREAD);
	if (IS_ERR(fid)) {
		err = PTR_ERR(fid);
		fid = NULL;
	} else {
		inc_nlink(dir);
		v9fs_invalidate_inode_attr(dir);
	}

	if (fid)
		p9_client_clunk(fid);

	return err;
}

/**
 * v9fs_vfs_lookup - VFS lookup hook to "walk" to a new inode
 * @dir:  inode that is being walked from
 * @dentry: dentry that is being walked to?
 * @flags: lookup flags (unused)
 *
 */

struct dentry *v9fs_vfs_lookup(struct inode *dir, struct dentry *dentry,
				      unsigned int flags)
{
	struct dentry *res;
	struct v9fs_session_info *v9ses;
	struct p9_fid *dfid, *fid;
	struct inode *inode;
	char *name;

	p9_debug(P9_DEBUG_VFS, "dir: %p dentry: (%pd) %p flags: %x\n",
		 dir, dentry, dentry, flags);

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	v9ses = v9fs_inode2v9ses(dir);
	/* We can walk d_parent because we hold the dir->i_mutex */
	dfid = v9fs_fid_lookup(dentry->d_parent);
	if (IS_ERR(dfid))
		return ERR_CAST(dfid);

	name = (char *) dentry->d_name.name;
	fid = p9_client_walk(dfid, 1, &name, 1);
	if (IS_ERR(fid)) {
		if (fid == ERR_PTR(-ENOENT)) {
			d_add(dentry, NULL);
			return NULL;
		}
		return ERR_CAST(fid);
	}
	/*
	 * Make sure we don't use a wrong inode due to parallel
	 * unlink. For cached mode create calls request for new
	 * inode. But with cache disabled, lookup should do this.
	 */
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE)
		inode = v9fs_get_inode_from_fid(v9ses, fid, dir->i_sb);
	else
		inode = v9fs_get_new_inode_from_fid(v9ses, fid, dir->i_sb);
	if (IS_ERR(inode)) {
		p9_client_clunk(fid);
		return ERR_CAST(inode);
	}
	/*
	 * If we had a rename on the server and a parallel lookup
	 * for the new name, then make sure we instantiate with
	 * the new name. ie look up for a/b, while on server somebody
	 * moved b under k and client parallely did a lookup for
	 * k/b.
	 */
	res = d_splice_alias(inode, dentry);
	if (!res)
		v9fs_fid_add(dentry, fid);
	else if (!IS_ERR(res))
		v9fs_fid_add(res, fid);
	else
		p9_client_clunk(fid);
	return res;
}

static int
v9fs_vfs_atomic_open(struct inode *dir, struct dentry *dentry,
		     struct file *file, unsigned flags, umode_t mode,
		     int *opened)
{
	int err;
	u32 perm;
	struct v9fs_inode *v9inode;
	struct v9fs_session_info *v9ses;
	struct p9_fid *fid, *inode_fid;
	struct dentry *res = NULL;

	if (d_unhashed(dentry)) {
		res = v9fs_vfs_lookup(dir, dentry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);

		if (res)
			dentry = res;
	}

	/* Only creates */
	if (!(flags & O_CREAT) || dentry->d_inode)
		return finish_no_open(file, res);

	err = 0;

	v9ses = v9fs_inode2v9ses(dir);
	perm = unixmode2p9mode(v9ses, mode);
	fid = v9fs_create(v9ses, dir, dentry, NULL, perm,
				v9fs_uflags2omode(flags,
						v9fs_proto_dotu(v9ses)));
	if (IS_ERR(fid)) {
		err = PTR_ERR(fid);
		fid = NULL;
		goto error;
	}

	v9fs_invalidate_inode_attr(dir);
	v9inode = V9FS_I(dentry->d_inode);
	mutex_lock(&v9inode->v_mutex);
	if ((v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE) &&
	    !v9inode->writeback_fid &&
	    ((flags & O_ACCMODE) != O_RDONLY)) {
		/*
		 * clone a fid and add it to writeback_fid
		 * we do it during open time instead of
		 * page dirty time via write_begin/page_mkwrite
		 * because we want write after unlink usecase
		 * to work.
		 */
		inode_fid = v9fs_writeback_fid(dentry);
		if (IS_ERR(inode_fid)) {
			err = PTR_ERR(inode_fid);
			mutex_unlock(&v9inode->v_mutex);
			goto error;
		}
		v9inode->writeback_fid = (void *) inode_fid;
	}
	mutex_unlock(&v9inode->v_mutex);
	err = finish_open(file, dentry, generic_file_open, opened);
	if (err)
		goto error;

	file->private_data = fid;
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE)
		v9fs_cache_inode_set_cookie(dentry->d_inode, file);

	*opened |= FILE_CREATED;
out:
	dput(res);
	return err;

error:
	if (fid)
		p9_client_clunk(fid);
	goto out;
}

/**
 * v9fs_vfs_unlink - VFS unlink hook to delete an inode
 * @i:  inode that is being unlinked
 * @d: dentry that is being unlinked
 *
 */

int v9fs_vfs_unlink(struct inode *i, struct dentry *d)
{
	return v9fs_remove(i, d, 0);
}

/**
 * v9fs_vfs_rmdir - VFS unlink hook to delete a directory
 * @i:  inode that is being unlinked
 * @d: dentry that is being unlinked
 *
 */

int v9fs_vfs_rmdir(struct inode *i, struct dentry *d)
{
	return v9fs_remove(i, d, AT_REMOVEDIR);
}

/**
 * v9fs_vfs_rename - VFS hook to rename an inode
 * @old_dir:  old dir inode
 * @old_dentry: old dentry
 * @new_dir: new dir inode
 * @new_dentry: new dentry
 *
 */

int
v9fs_vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	int retval;
	struct inode *old_inode;
	struct inode *new_inode;
	struct v9fs_session_info *v9ses;
	struct p9_fid *oldfid;
	struct p9_fid *olddirfid;
	struct p9_fid *newdirfid;
	struct p9_wstat wstat;

	p9_debug(P9_DEBUG_VFS, "\n");
	retval = 0;
	old_inode = old_dentry->d_inode;
	new_inode = new_dentry->d_inode;
	v9ses = v9fs_inode2v9ses(old_inode);
	oldfid = v9fs_fid_lookup(old_dentry);
	if (IS_ERR(oldfid))
		return PTR_ERR(oldfid);

	olddirfid = v9fs_fid_clone(old_dentry->d_parent);
	if (IS_ERR(olddirfid)) {
		retval = PTR_ERR(olddirfid);
		goto done;
	}

	newdirfid = v9fs_fid_clone(new_dentry->d_parent);
	if (IS_ERR(newdirfid)) {
		retval = PTR_ERR(newdirfid);
		goto clunk_olddir;
	}

	down_write(&v9ses->rename_sem);
	if (v9fs_proto_dotl(v9ses)) {
		retval = p9_client_renameat(olddirfid, old_dentry->d_name.name,
					    newdirfid, new_dentry->d_name.name);
		if (retval == -EOPNOTSUPP)
			retval = p9_client_rename(oldfid, newdirfid,
						  new_dentry->d_name.name);
		if (retval != -EOPNOTSUPP)
			goto clunk_newdir;
	}
	if (old_dentry->d_parent != new_dentry->d_parent) {
		/*
		 * 9P .u can only handle file rename in the same directory
		 */

		p9_debug(P9_DEBUG_ERROR, "old dir and new dir are different\n");
		retval = -EXDEV;
		goto clunk_newdir;
	}
	v9fs_blank_wstat(&wstat);
	wstat.muid = v9ses->uname;
	wstat.name = (char *) new_dentry->d_name.name;
	retval = p9_client_wstat(oldfid, &wstat);

clunk_newdir:
	if (!retval) {
		if (new_inode) {
			if (S_ISDIR(new_inode->i_mode))
				clear_nlink(new_inode);
			else
				drop_nlink(new_inode);
		}
		if (S_ISDIR(old_inode->i_mode)) {
			if (!new_inode)
				inc_nlink(new_dir);
			drop_nlink(old_dir);
		}
		v9fs_invalidate_inode_attr(old_inode);
		v9fs_invalidate_inode_attr(old_dir);
		v9fs_invalidate_inode_attr(new_dir);

		/* successful rename */
		d_move(old_dentry, new_dentry);
	}
	up_write(&v9ses->rename_sem);
	p9_client_clunk(newdirfid);

clunk_olddir:
	p9_client_clunk(olddirfid);

done:
	return retval;
}

/**
 * v9fs_vfs_getattr - retrieve file metadata
 * @mnt: mount information
 * @dentry: file to get attributes on
 * @stat: metadata structure to populate
 *
 */

static int
v9fs_vfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		 struct kstat *stat)
{
	struct v9fs_session_info *v9ses;
	struct p9_fid *fid;
	struct p9_wstat *st;

	p9_debug(P9_DEBUG_VFS, "dentry: %p\n", dentry);
	v9ses = v9fs_dentry2v9ses(dentry);
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE) {
		generic_fillattr(dentry->d_inode, stat);
		return 0;
	}
	fid = v9fs_fid_lookup(dentry);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	st = p9_client_stat(fid);
	if (IS_ERR(st))
		return PTR_ERR(st);

	v9fs_stat2inode(st, dentry->d_inode, dentry->d_inode->i_sb);
	generic_fillattr(dentry->d_inode, stat);

	p9stat_free(st);
	kfree(st);
	return 0;
}

/**
 * v9fs_vfs_setattr - set file metadata
 * @dentry: file whose metadata to set
 * @iattr: metadata assignment structure
 *
 */

static int v9fs_vfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	int retval;
	struct v9fs_session_info *v9ses;
	struct p9_fid *fid;
	struct p9_wstat wstat;

	p9_debug(P9_DEBUG_VFS, "\n");
	retval = inode_change_ok(dentry->d_inode, iattr);
	if (retval)
		return retval;

	retval = -EPERM;
	v9ses = v9fs_dentry2v9ses(dentry);
	fid = v9fs_fid_lookup(dentry);
	if(IS_ERR(fid))
		return PTR_ERR(fid);

	v9fs_blank_wstat(&wstat);
	if (iattr->ia_valid & ATTR_MODE)
		wstat.mode = unixmode2p9mode(v9ses, iattr->ia_mode);

	if (iattr->ia_valid & ATTR_MTIME)
		wstat.mtime = iattr->ia_mtime.tv_sec;

	if (iattr->ia_valid & ATTR_ATIME)
		wstat.atime = iattr->ia_atime.tv_sec;

	if (iattr->ia_valid & ATTR_SIZE)
		wstat.length = iattr->ia_size;

	if (v9fs_proto_dotu(v9ses)) {
		if (iattr->ia_valid & ATTR_UID)
			wstat.n_uid = iattr->ia_uid;

		if (iattr->ia_valid & ATTR_GID)
			wstat.n_gid = iattr->ia_gid;
	}

	/* Write all dirty data */
	if (d_is_reg(dentry))
		filemap_write_and_wait(dentry->d_inode->i_mapping);

	retval = p9_client_wstat(fid, &wstat);
	if (retval < 0)
		return retval;

	if ((iattr->ia_valid & ATTR_SIZE) &&
	    iattr->ia_size != i_size_read(dentry->d_inode))
		truncate_setsize(dentry->d_inode, iattr->ia_size);

	v9fs_invalidate_inode_attr(dentry->d_inode);

	setattr_copy(dentry->d_inode, iattr);
	mark_inode_dirty(dentry->d_inode);
	return 0;
}

/**
 * v9fs_stat2inode - populate an inode structure with mistat info
 * @stat: Plan 9 metadata (mistat) structure
 * @inode: inode to populate
 * @sb: superblock of filesystem
 *
 */

void
v9fs_stat2inode(struct p9_wstat *stat, struct inode *inode,
	struct super_block *sb)
{
	umode_t mode;
	char ext[32];
	char tag_name[14];
	unsigned int i_nlink;
	struct v9fs_session_info *v9ses = sb->s_fs_info;
	struct v9fs_inode *v9inode = V9FS_I(inode);

	set_nlink(inode, 1);

	inode->i_atime.tv_sec = stat->atime;
	inode->i_mtime.tv_sec = stat->mtime;
	inode->i_ctime.tv_sec = stat->mtime;

	inode->i_uid = v9ses->dfltuid;
	inode->i_gid = v9ses->dfltgid;

	if (v9fs_proto_dotu(v9ses)) {
		inode->i_uid = stat->n_uid;
		inode->i_gid = stat->n_gid;
	}
	if ((S_ISREG(inode->i_mode)) || (S_ISDIR(inode->i_mode))) {
		if (v9fs_proto_dotu(v9ses) && (stat->extension[0] != '\0')) {
			/*
			 * Hadlink support got added later to
			 * to the .u extension. So there can be
			 * server out there that doesn't support
			 * this even with .u extension. So check
			 * for non NULL stat->extension
			 */
			strlcpy(ext, stat->extension, sizeof(ext));
			/* HARDLINKCOUNT %u */
			sscanf(ext, "%13s %u", tag_name, &i_nlink);
			if (!strncmp(tag_name, "HARDLINKCOUNT", 13))
				set_nlink(inode, i_nlink);
		}
	}
	mode = p9mode2perm(v9ses, stat);
	mode |= inode->i_mode & ~S_IALLUGO;
	inode->i_mode = mode;
	i_size_write(inode, stat->length);

	/* not real number of blocks, but 512 byte ones ... */
	inode->i_blocks = (i_size_read(inode) + 512 - 1) >> 9;
	v9inode->cache_validity &= ~V9FS_INO_INVALID_ATTR;
}

/**
 * v9fs_qid2ino - convert qid into inode number
 * @qid: qid to hash
 *
 * BUG: potential for inode number collisions?
 */

ino_t v9fs_qid2ino(struct p9_qid *qid)
{
	u64 path = qid->path + 2;
	ino_t i = 0;

	if (sizeof(ino_t) == sizeof(path))
		memcpy(&i, &path, sizeof(ino_t));
	else
		i = (ino_t) (path ^ (path >> 32));

	return i;
}

/**
 * v9fs_readlink - read a symlink's location (internal version)
 * @dentry: dentry for symlink
 * @buffer: buffer to load symlink location into
 * @buflen: length of buffer
 *
 */

static int v9fs_readlink(struct dentry *dentry, char *buffer, int buflen)
{
	int retval;

	struct v9fs_session_info *v9ses;
	struct p9_fid *fid;
	struct p9_wstat *st;

	p9_debug(P9_DEBUG_VFS, " %pd\n", dentry);
	retval = -EPERM;
	v9ses = v9fs_dentry2v9ses(dentry);
	fid = v9fs_fid_lookup(dentry);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (!v9fs_proto_dotu(v9ses))
		return -EBADF;

	st = p9_client_stat(fid);
	if (IS_ERR(st))
		return PTR_ERR(st);

	if (!(st->mode & P9_DMSYMLINK)) {
		retval = -EINVAL;
		goto done;
	}

	/* copy extension buffer into buffer */
	retval = min(strlen(st->extension)+1, (size_t)buflen);
	memcpy(buffer, st->extension, retval);

	p9_debug(P9_DEBUG_VFS, "%pd -> %s (%.*s)\n",
		 dentry, st->extension, buflen, buffer);

done:
	p9stat_free(st);
	kfree(st);
	return retval;
}

/**
 * v9fs_vfs_follow_link - follow a symlink path
 * @dentry: dentry for symlink
 * @nd: nameidata
 *
 */

static void *v9fs_vfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int len = 0;
	char *link = __getname();

	p9_debug(P9_DEBUG_VFS, "%pd\n", dentry);

	if (!link)
		link = ERR_PTR(-ENOMEM);
	else {
		len = v9fs_readlink(dentry, link, PATH_MAX);

		if (len < 0) {
			__putname(link);
			link = ERR_PTR(len);
		} else
			link[min(len, PATH_MAX-1)] = 0;
	}
	nd_set_link(nd, link);

	return NULL;
}

/**
 * v9fs_vfs_put_link - release a symlink path
 * @dentry: dentry for symlink
 * @nd: nameidata
 * @p: unused
 *
 */

void
v9fs_vfs_put_link(struct dentry *dentry, struct nameidata *nd, void *p)
{
	char *s = nd_get_link(nd);

	p9_debug(P9_DEBUG_VFS, " %pd %s\n",
		 dentry, IS_ERR(s) ? "<error>" : s);
	if (!IS_ERR(s))
		__putname(s);
}

/**
 * v9fs_vfs_mkspecial - create a special file
 * @dir: inode to create special file in
 * @dentry: dentry to create
 * @perm: mode to create special file
 * @extension: 9p2000.u format extension string representing special file
 *
 */

static int v9fs_vfs_mkspecial(struct inode *dir, struct dentry *dentry,
	u32 perm, const char *extension)
{
	struct p9_fid *fid;
	struct v9fs_session_info *v9ses;

	v9ses = v9fs_inode2v9ses(dir);
	if (!v9fs_proto_dotu(v9ses)) {
		p9_debug(P9_DEBUG_ERROR, "not extended\n");
		return -EPERM;
	}

	fid = v9fs_create(v9ses, dir, dentry, (char *) extension, perm,
								P9_OREAD);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	v9fs_invalidate_inode_attr(dir);
	p9_client_clunk(fid);
	return 0;
}

/**
 * v9fs_vfs_symlink - helper function to create symlinks
 * @dir: directory inode containing symlink
 * @dentry: dentry for symlink
 * @symname: symlink data
 *
 * See Also: 9P2000.u RFC for more information
 *
 */

static int
v9fs_vfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	p9_debug(P9_DEBUG_VFS, " %lu,%pd,%s\n",
		 dir->i_ino, dentry, symname);

	return v9fs_vfs_mkspecial(dir, dentry, P9_DMSYMLINK, symname);
}

/**
 * v9fs_vfs_link - create a hardlink
 * @old_dentry: dentry for file to link to
 * @dir: inode destination for new link
 * @dentry: dentry for link
 *
 */

static int
v9fs_vfs_link(struct dentry *old_dentry, struct inode *dir,
	      struct dentry *dentry)
{
	int retval;
	char *name;
	struct p9_fid *oldfid;

	p9_debug(P9_DEBUG_VFS, " %lu,%pd,%pd\n",
		 dir->i_ino, dentry, old_dentry);

	oldfid = v9fs_fid_clone(old_dentry);
	if (IS_ERR(oldfid))
		return PTR_ERR(oldfid);

	name = __getname();
	if (unlikely(!name)) {
		retval = -ENOMEM;
		goto clunk_fid;
	}

	sprintf(name, "%d\n", oldfid->fid);
	retval = v9fs_vfs_mkspecial(dir, dentry, P9_DMLINK, name);
	__putname(name);
	if (!retval) {
		v9fs_refresh_inode(oldfid, old_dentry->d_inode);
		v9fs_invalidate_inode_attr(dir);
	}
clunk_fid:
	p9_client_clunk(oldfid);
	return retval;
}

/**
 * v9fs_vfs_mknod - create a special file
 * @dir: inode destination for new link
 * @dentry: dentry for file
 * @mode: mode for creation
 * @rdev: device associated with special file
 *
 */

static int
v9fs_vfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct v9fs_session_info *v9ses = v9fs_inode2v9ses(dir);
	int retval;
	char *name;
	u32 perm;

	p9_debug(P9_DEBUG_VFS, " %lu,%pd mode: %hx MAJOR: %u MINOR: %u\n",
		 dir->i_ino, dentry, mode,
		 MAJOR(rdev), MINOR(rdev));

	if (!new_valid_dev(rdev))
		return -EINVAL;

	name = __getname();
	if (!name)
		return -ENOMEM;
	/* build extension */
	if (S_ISBLK(mode))
		sprintf(name, "b %u %u", MAJOR(rdev), MINOR(rdev));
	else if (S_ISCHR(mode))
		sprintf(name, "c %u %u", MAJOR(rdev), MINOR(rdev));
	else if (S_ISFIFO(mode))
		*name = 0;
	else if (S_ISSOCK(mode))
		*name = 0;
	else {
		__putname(name);
		return -EINVAL;
	}

	perm = unixmode2p9mode(v9ses, mode);
	retval = v9fs_vfs_mkspecial(dir, dentry, perm, name);
	__putname(name);

	return retval;
}

int v9fs_refresh_inode(struct p9_fid *fid, struct inode *inode)
{
	int umode;
	dev_t rdev;
	loff_t i_size;
	struct p9_wstat *st;
	struct v9fs_session_info *v9ses;

	v9ses = v9fs_inode2v9ses(inode);
	st = p9_client_stat(fid);
	if (IS_ERR(st))
		return PTR_ERR(st);
	/*
	 * Don't update inode if the file type is different
	 */
	umode = p9mode2unixmode(v9ses, st, &rdev);
	if ((inode->i_mode & S_IFMT) != (umode & S_IFMT))
		goto out;

	spin_lock(&inode->i_lock);
	/*
	 * We don't want to refresh inode->i_size,
	 * because we may have cached data
	 */
	i_size = inode->i_size;
	v9fs_stat2inode(st, inode, inode->i_sb);
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE)
		inode->i_size = i_size;
	spin_unlock(&inode->i_lock);
out:
	p9stat_free(st);
	kfree(st);
	return 0;
}

static const struct inode_operations v9fs_dir_inode_operations_dotu = {
	.create = v9fs_vfs_create,
	.lookup = v9fs_vfs_lookup,
	.atomic_open = v9fs_vfs_atomic_open,
	.symlink = v9fs_vfs_symlink,
	.link = v9fs_vfs_link,
	.unlink = v9fs_vfs_unlink,
	.mkdir = v9fs_vfs_mkdir,
	.rmdir = v9fs_vfs_rmdir,
	.mknod = v9fs_vfs_mknod,
	.rename = v9fs_vfs_rename,
	.getattr = v9fs_vfs_getattr,
	.setattr = v9fs_vfs_setattr,
};

static const struct inode_operations v9fs_dir_inode_operations = {
	.create = v9fs_vfs_create,
	.lookup = v9fs_vfs_lookup,
	.atomic_open = v9fs_vfs_atomic_open,
	.unlink = v9fs_vfs_unlink,
	.mkdir = v9fs_vfs_mkdir,
	.rmdir = v9fs_vfs_rmdir,
	.mknod = v9fs_vfs_mknod,
	.rename = v9fs_vfs_rename,
	.getattr = v9fs_vfs_getattr,
	.setattr = v9fs_vfs_setattr,
};

static const struct inode_operations v9fs_file_inode_operations = {
	.getattr = v9fs_vfs_getattr,
	.setattr = v9fs_vfs_setattr,
};

static const struct inode_operations v9fs_symlink_inode_operations = {
	.readlink = generic_readlink,
	.follow_link = v9fs_vfs_follow_link,
	.put_link = v9fs_vfs_put_link,
	.getattr = v9fs_vfs_getattr,
	.setattr = v9fs_vfs_setattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/vfs_inode.c */
/************************************************************/
/*
 *  linux/fs/9p/vfs_inode_dotl.c
 *
 * This file contains vfs inode ops for the 9P2000.L protocol.
 *
 *  Copyright (C) 2004 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

// #include <linux/module.h>
// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/file.h>
// #include <linux/pagemap.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <linux/inet.h>
// #include <linux/namei.h>
// #include <linux/idr.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/xattr.h>
// #include <linux/posix_acl.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>

// #include "v9fs.h"
// #include "v9fs_vfs.h"
// #include "fid.h"
// #include "cache.h"
// #include "xattr.h"
// #include "acl.h"

static int
v9fs_vfs_mknod_dotl(struct inode *dir, struct dentry *dentry, umode_t omode,
		    dev_t rdev);

/**
 * v9fs_get_fsgid_for_create - Helper function to get the gid for creating a
 * new file system object. This checks the S_ISGID to determine the owning
 * group of the new file system object.
 */

static kgid_t v9fs_get_fsgid_for_create(struct inode *dir_inode)
{
	BUG_ON(dir_inode == NULL);

	if (dir_inode->i_mode & S_ISGID) {
		/* set_gid bit is set.*/
		return dir_inode->i_gid;
	}
	return current_fsgid();
}

static int v9fs_test_inode_dotl(struct inode *inode, void *data)
{
	struct v9fs_inode *v9inode = V9FS_I(inode);
	struct p9_stat_dotl *st = (struct p9_stat_dotl *)data;

	/* don't match inode of different type */
	if ((inode->i_mode & S_IFMT) != (st->st_mode & S_IFMT))
		return 0;

	if (inode->i_generation != st->st_gen)
		return 0;

	/* compare qid details */
	if (memcmp(&v9inode->qid.version,
		   &st->qid.version, sizeof(v9inode->qid.version)))
		return 0;

	if (v9inode->qid.type != st->qid.type)
		return 0;
	return 1;
}

/* Always get a new inode */
static int v9fs_test_new_inode_dotl(struct inode *inode, void *data)
{
	return 0;
}

static int v9fs_set_inode_dotl(struct inode *inode,  void *data)
{
	struct v9fs_inode *v9inode = V9FS_I(inode);
	struct p9_stat_dotl *st = (struct p9_stat_dotl *)data;

	memcpy(&v9inode->qid, &st->qid, sizeof(st->qid));
	inode->i_generation = st->st_gen;
	return 0;
}

static struct inode *v9fs_qid_iget_dotl(struct super_block *sb,
					struct p9_qid *qid,
					struct p9_fid *fid,
					struct p9_stat_dotl *st,
					int new)
{
	int retval;
	unsigned long i_ino;
	struct inode *inode;
	struct v9fs_session_info *v9ses = sb->s_fs_info;
	int (*test)(struct inode *, void *);

	if (new)
		test = v9fs_test_new_inode_dotl;
	else
		test = v9fs_test_inode_dotl;

	i_ino = v9fs_qid2ino(qid);
	inode = iget5_locked(sb, i_ino, test, v9fs_set_inode_dotl, st);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;
	/*
	 * initialize the inode with the stat info
	 * FIXME!! we may need support for stale inodes
	 * later.
	 */
	inode->i_ino = i_ino;
	retval = v9fs_init_inode(v9ses, inode,
				 st->st_mode, new_decode_dev(st->st_rdev));
	if (retval)
		goto error;

	v9fs_stat2inode_dotl(st, inode);
	v9fs_cache_inode_get_cookie(inode);
	retval = v9fs_get_acl(inode, fid);
	if (retval)
		goto error;

	unlock_new_inode(inode);
	return inode;
error:
	unlock_new_inode(inode);
	iput(inode);
	return ERR_PTR(retval);

}

struct inode *
v9fs_inode_from_fid_dotl(struct v9fs_session_info *v9ses, struct p9_fid *fid,
			 struct super_block *sb, int new)
{
	struct p9_stat_dotl *st;
	struct inode *inode = NULL;

	st = p9_client_getattr_dotl(fid, P9_STATS_BASIC | P9_STATS_GEN);
	if (IS_ERR(st))
		return ERR_CAST(st);

	inode = v9fs_qid_iget_dotl(sb, &st->qid, fid, st, new);
	kfree(st);
	return inode;
}

struct dotl_openflag_map {
	int open_flag;
	int dotl_flag;
};

static int v9fs_mapped_dotl_flags(int flags)
{
	int i;
	int rflags = 0;
	struct dotl_openflag_map dotl_oflag_map[] = {
		{ O_CREAT,	P9_DOTL_CREATE },
		{ O_EXCL,	P9_DOTL_EXCL },
		{ O_NOCTTY,	P9_DOTL_NOCTTY },
		{ O_APPEND,	P9_DOTL_APPEND },
		{ O_NONBLOCK,	P9_DOTL_NONBLOCK },
		{ O_DSYNC,	P9_DOTL_DSYNC },
		{ FASYNC,	P9_DOTL_FASYNC },
		{ O_DIRECT,	P9_DOTL_DIRECT },
		{ O_LARGEFILE,	P9_DOTL_LARGEFILE },
		{ O_DIRECTORY,	P9_DOTL_DIRECTORY },
		{ O_NOFOLLOW,	P9_DOTL_NOFOLLOW },
		{ O_NOATIME,	P9_DOTL_NOATIME },
		{ O_CLOEXEC,	P9_DOTL_CLOEXEC },
		{ O_SYNC,	P9_DOTL_SYNC},
	};
	for (i = 0; i < ARRAY_SIZE(dotl_oflag_map); i++) {
		if (flags & dotl_oflag_map[i].open_flag)
			rflags |= dotl_oflag_map[i].dotl_flag;
	}
	return rflags;
}

/**
 * v9fs_open_to_dotl_flags- convert Linux specific open flags to
 * plan 9 open flag.
 * @flags: flags to convert
 */
int v9fs_open_to_dotl_flags(int flags)
{
	int rflags = 0;

	/*
	 * We have same bits for P9_DOTL_READONLY, P9_DOTL_WRONLY
	 * and P9_DOTL_NOACCESS
	 */
	rflags |= flags & O_ACCMODE;
	rflags |= v9fs_mapped_dotl_flags(flags);

	return rflags;
}

/**
 * v9fs_vfs_create_dotl - VFS hook to create files for 9P2000.L protocol.
 * @dir: directory inode that is being created
 * @dentry:  dentry that is being deleted
 * @omode: create permissions
 *
 */

static int
v9fs_vfs_create_dotl(struct inode *dir, struct dentry *dentry, umode_t omode,
		bool excl)
{
	return v9fs_vfs_mknod_dotl(dir, dentry, omode, 0);
}

static int
v9fs_vfs_atomic_open_dotl(struct inode *dir, struct dentry *dentry,
			  struct file *file, unsigned flags, umode_t omode,
			  int *opened)
{
	int err = 0;
	kgid_t gid;
	umode_t mode;
	char *name = NULL;
	struct p9_qid qid;
	struct inode *inode;
	struct p9_fid *fid = NULL;
	struct v9fs_inode *v9inode;
	struct p9_fid *dfid, *ofid, *inode_fid;
	struct v9fs_session_info *v9ses;
	struct posix_acl *pacl = NULL, *dacl = NULL;
	struct dentry *res = NULL;

	if (d_unhashed(dentry)) {
		res = v9fs_vfs_lookup(dir, dentry, 0);
		if (IS_ERR(res))
			return PTR_ERR(res);

		if (res)
			dentry = res;
	}

	/* Only creates */
	if (!(flags & O_CREAT) || dentry->d_inode)
		return	finish_no_open(file, res);

	v9ses = v9fs_inode2v9ses(dir);

	name = (char *) dentry->d_name.name;
	p9_debug(P9_DEBUG_VFS, "name:%s flags:0x%x mode:0x%hx\n",
		 name, flags, omode);

	dfid = v9fs_fid_lookup(dentry->d_parent);
	if (IS_ERR(dfid)) {
		err = PTR_ERR(dfid);
		p9_debug(P9_DEBUG_VFS, "fid lookup failed %d\n", err);
		goto out;
	}

	/* clone a fid to use for creation */
	ofid = p9_client_walk(dfid, 0, NULL, 1);
	if (IS_ERR(ofid)) {
		err = PTR_ERR(ofid);
		p9_debug(P9_DEBUG_VFS, "p9_client_walk failed %d\n", err);
		goto out;
	}

	gid = v9fs_get_fsgid_for_create(dir);

	mode = omode;
	/* Update mode based on ACL value */
	err = v9fs_acl_mode(dir, &mode, &dacl, &pacl);
	if (err) {
		p9_debug(P9_DEBUG_VFS, "Failed to get acl values in creat %d\n",
			 err);
		goto error;
	}
	err = p9_client_create_dotl(ofid, name, v9fs_open_to_dotl_flags(flags),
				    mode, gid, &qid);
	if (err < 0) {
		p9_debug(P9_DEBUG_VFS, "p9_client_open_dotl failed in creat %d\n",
			 err);
		goto error;
	}
	v9fs_invalidate_inode_attr(dir);

	/* instantiate inode and assign the unopened fid to the dentry */
	fid = p9_client_walk(dfid, 1, &name, 1);
	if (IS_ERR(fid)) {
		err = PTR_ERR(fid);
		p9_debug(P9_DEBUG_VFS, "p9_client_walk failed %d\n", err);
		fid = NULL;
		goto error;
	}
	inode = v9fs_get_new_inode_from_fid(v9ses, fid, dir->i_sb);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		p9_debug(P9_DEBUG_VFS, "inode creation failed %d\n", err);
		goto error;
	}
	/* Now set the ACL based on the default value */
	v9fs_set_create_acl(inode, fid, dacl, pacl);

	v9fs_fid_add(dentry, fid);
	d_instantiate(dentry, inode);

	v9inode = V9FS_I(inode);
	mutex_lock(&v9inode->v_mutex);
	if ((v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE) &&
	    !v9inode->writeback_fid &&
	    ((flags & O_ACCMODE) != O_RDONLY)) {
		/*
		 * clone a fid and add it to writeback_fid
		 * we do it during open time instead of
		 * page dirty time via write_begin/page_mkwrite
		 * because we want write after unlink usecase
		 * to work.
		 */
		inode_fid = v9fs_writeback_fid(dentry);
		if (IS_ERR(inode_fid)) {
			err = PTR_ERR(inode_fid);
			mutex_unlock(&v9inode->v_mutex);
			goto err_clunk_old_fid;
		}
		v9inode->writeback_fid = (void *) inode_fid;
	}
	mutex_unlock(&v9inode->v_mutex);
	/* Since we are opening a file, assign the open fid to the file */
	err = finish_open(file, dentry, generic_file_open, opened);
	if (err)
		goto err_clunk_old_fid;
	file->private_data = ofid;
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE)
		v9fs_cache_inode_set_cookie(inode, file);
	*opened |= FILE_CREATED;
out:
	v9fs_put_acl(dacl, pacl);
	dput(res);
	return err;

error:
	if (fid)
		p9_client_clunk(fid);
err_clunk_old_fid:
	if (ofid)
		p9_client_clunk(ofid);
	goto out;
}

/**
 * v9fs_vfs_mkdir_dotl - VFS mkdir hook to create a directory
 * @dir:  inode that is being unlinked
 * @dentry: dentry that is being unlinked
 * @omode: mode for new directory
 *
 */

static int v9fs_vfs_mkdir_dotl(struct inode *dir,
			       struct dentry *dentry, umode_t omode)
{
	int err;
	struct v9fs_session_info *v9ses;
	struct p9_fid *fid = NULL, *dfid = NULL;
	kgid_t gid;
	char *name;
	umode_t mode;
	struct inode *inode;
	struct p9_qid qid;
	struct dentry *dir_dentry;
	struct posix_acl *dacl = NULL, *pacl = NULL;

	p9_debug(P9_DEBUG_VFS, "name %pd\n", dentry);
	err = 0;
	v9ses = v9fs_inode2v9ses(dir);

	omode |= S_IFDIR;
	if (dir->i_mode & S_ISGID)
		omode |= S_ISGID;

	dir_dentry = dentry->d_parent;
	dfid = v9fs_fid_lookup(dir_dentry);
	if (IS_ERR(dfid)) {
		err = PTR_ERR(dfid);
		p9_debug(P9_DEBUG_VFS, "fid lookup failed %d\n", err);
		dfid = NULL;
		goto error;
	}

	gid = v9fs_get_fsgid_for_create(dir);
	mode = omode;
	/* Update mode based on ACL value */
	err = v9fs_acl_mode(dir, &mode, &dacl, &pacl);
	if (err) {
		p9_debug(P9_DEBUG_VFS, "Failed to get acl values in mkdir %d\n",
			 err);
		goto error;
	}
	name = (char *) dentry->d_name.name;
	err = p9_client_mkdir_dotl(dfid, name, mode, gid, &qid);
	if (err < 0)
		goto error;

	fid = p9_client_walk(dfid, 1, &name, 1);
	if (IS_ERR(fid)) {
		err = PTR_ERR(fid);
		p9_debug(P9_DEBUG_VFS, "p9_client_walk failed %d\n",
			 err);
		fid = NULL;
		goto error;
	}

	/* instantiate inode and assign the unopened fid to the dentry */
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE) {
		inode = v9fs_get_new_inode_from_fid(v9ses, fid, dir->i_sb);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			p9_debug(P9_DEBUG_VFS, "inode creation failed %d\n",
				 err);
			goto error;
		}
		v9fs_fid_add(dentry, fid);
		v9fs_set_create_acl(inode, fid, dacl, pacl);
		d_instantiate(dentry, inode);
		fid = NULL;
		err = 0;
	} else {
		/*
		 * Not in cached mode. No need to populate
		 * inode with stat. We need to get an inode
		 * so that we can set the acl with dentry
		 */
		inode = v9fs_get_inode(dir->i_sb, mode, 0);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		v9fs_set_create_acl(inode, fid, dacl, pacl);
		d_instantiate(dentry, inode);
	}
	inc_nlink(dir);
	v9fs_invalidate_inode_attr(dir);
error:
	if (fid)
		p9_client_clunk(fid);
	v9fs_put_acl(dacl, pacl);
	return err;
}

static int
v9fs_vfs_getattr_dotl(struct vfsmount *mnt, struct dentry *dentry,
		 struct kstat *stat)
{
	struct v9fs_session_info *v9ses;
	struct p9_fid *fid;
	struct p9_stat_dotl *st;

	p9_debug(P9_DEBUG_VFS, "dentry: %p\n", dentry);
	v9ses = v9fs_dentry2v9ses(dentry);
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE) {
		generic_fillattr(dentry->d_inode, stat);
		return 0;
	}
	fid = v9fs_fid_lookup(dentry);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	/* Ask for all the fields in stat structure. Server will return
	 * whatever it supports
	 */

	st = p9_client_getattr_dotl(fid, P9_STATS_ALL);
	if (IS_ERR(st))
		return PTR_ERR(st);

	v9fs_stat2inode_dotl(st, dentry->d_inode);
	generic_fillattr(dentry->d_inode, stat);
	/* Change block size to what the server returned */
	stat->blksize = st->st_blksize;

	kfree(st);
	return 0;
}

/*
 * Attribute flags.
 */
#define P9_ATTR_MODE		(1 << 0)
#define P9_ATTR_UID		(1 << 1)
#define P9_ATTR_GID		(1 << 2)
#define P9_ATTR_SIZE		(1 << 3)
#define P9_ATTR_ATIME		(1 << 4)
#define P9_ATTR_MTIME		(1 << 5)
#define P9_ATTR_CTIME		(1 << 6)
#define P9_ATTR_ATIME_SET	(1 << 7)
#define P9_ATTR_MTIME_SET	(1 << 8)

struct dotl_iattr_map {
	int iattr_valid;
	int p9_iattr_valid;
};

static int v9fs_mapped_iattr_valid(int iattr_valid)
{
	int i;
	int p9_iattr_valid = 0;
	struct dotl_iattr_map dotl_iattr_map[] = {
		{ ATTR_MODE,		P9_ATTR_MODE },
		{ ATTR_UID,		P9_ATTR_UID },
		{ ATTR_GID,		P9_ATTR_GID },
		{ ATTR_SIZE,		P9_ATTR_SIZE },
		{ ATTR_ATIME,		P9_ATTR_ATIME },
		{ ATTR_MTIME,		P9_ATTR_MTIME },
		{ ATTR_CTIME,		P9_ATTR_CTIME },
		{ ATTR_ATIME_SET,	P9_ATTR_ATIME_SET },
		{ ATTR_MTIME_SET,	P9_ATTR_MTIME_SET },
	};
	for (i = 0; i < ARRAY_SIZE(dotl_iattr_map); i++) {
		if (iattr_valid & dotl_iattr_map[i].iattr_valid)
			p9_iattr_valid |= dotl_iattr_map[i].p9_iattr_valid;
	}
	return p9_iattr_valid;
}

/**
 * v9fs_vfs_setattr_dotl - set file metadata
 * @dentry: file whose metadata to set
 * @iattr: metadata assignment structure
 *
 */

int v9fs_vfs_setattr_dotl(struct dentry *dentry, struct iattr *iattr)
{
	int retval;
	struct p9_fid *fid;
	struct p9_iattr_dotl p9attr;
	struct inode *inode = dentry->d_inode;

	p9_debug(P9_DEBUG_VFS, "\n");

	retval = inode_change_ok(inode, iattr);
	if (retval)
		return retval;

	p9attr.valid = v9fs_mapped_iattr_valid(iattr->ia_valid);
	p9attr.mode = iattr->ia_mode;
	p9attr.uid = iattr->ia_uid;
	p9attr.gid = iattr->ia_gid;
	p9attr.size = iattr->ia_size;
	p9attr.atime_sec = iattr->ia_atime.tv_sec;
	p9attr.atime_nsec = iattr->ia_atime.tv_nsec;
	p9attr.mtime_sec = iattr->ia_mtime.tv_sec;
	p9attr.mtime_nsec = iattr->ia_mtime.tv_nsec;

	fid = v9fs_fid_lookup(dentry);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	/* Write all dirty data */
	if (S_ISREG(inode->i_mode))
		filemap_write_and_wait(inode->i_mapping);

	retval = p9_client_setattr(fid, &p9attr);
	if (retval < 0)
		return retval;

	if ((iattr->ia_valid & ATTR_SIZE) &&
	    iattr->ia_size != i_size_read(inode))
		truncate_setsize(inode, iattr->ia_size);

	v9fs_invalidate_inode_attr(inode);
	setattr_copy(inode, iattr);
	mark_inode_dirty(inode);
	if (iattr->ia_valid & ATTR_MODE) {
		/* We also want to update ACL when we update mode bits */
		retval = v9fs_acl_chmod(inode, fid);
		if (retval < 0)
			return retval;
	}
	return 0;
}

/**
 * v9fs_stat2inode_dotl - populate an inode structure with stat info
 * @stat: stat structure
 * @inode: inode to populate
 *
 */

void
v9fs_stat2inode_dotl(struct p9_stat_dotl *stat, struct inode *inode)
{
	umode_t mode;
	struct v9fs_inode *v9inode = V9FS_I(inode);

	if ((stat->st_result_mask & P9_STATS_BASIC) == P9_STATS_BASIC) {
		inode->i_atime.tv_sec = stat->st_atime_sec;
		inode->i_atime.tv_nsec = stat->st_atime_nsec;
		inode->i_mtime.tv_sec = stat->st_mtime_sec;
		inode->i_mtime.tv_nsec = stat->st_mtime_nsec;
		inode->i_ctime.tv_sec = stat->st_ctime_sec;
		inode->i_ctime.tv_nsec = stat->st_ctime_nsec;
		inode->i_uid = stat->st_uid;
		inode->i_gid = stat->st_gid;
		set_nlink(inode, stat->st_nlink);

		mode = stat->st_mode & S_IALLUGO;
		mode |= inode->i_mode & ~S_IALLUGO;
		inode->i_mode = mode;

		i_size_write(inode, stat->st_size);
		inode->i_blocks = stat->st_blocks;
	} else {
		if (stat->st_result_mask & P9_STATS_ATIME) {
			inode->i_atime.tv_sec = stat->st_atime_sec;
			inode->i_atime.tv_nsec = stat->st_atime_nsec;
		}
		if (stat->st_result_mask & P9_STATS_MTIME) {
			inode->i_mtime.tv_sec = stat->st_mtime_sec;
			inode->i_mtime.tv_nsec = stat->st_mtime_nsec;
		}
		if (stat->st_result_mask & P9_STATS_CTIME) {
			inode->i_ctime.tv_sec = stat->st_ctime_sec;
			inode->i_ctime.tv_nsec = stat->st_ctime_nsec;
		}
		if (stat->st_result_mask & P9_STATS_UID)
			inode->i_uid = stat->st_uid;
		if (stat->st_result_mask & P9_STATS_GID)
			inode->i_gid = stat->st_gid;
		if (stat->st_result_mask & P9_STATS_NLINK)
			set_nlink(inode, stat->st_nlink);
		if (stat->st_result_mask & P9_STATS_MODE) {
			inode->i_mode = stat->st_mode;
			if ((S_ISBLK(inode->i_mode)) ||
						(S_ISCHR(inode->i_mode)))
				init_special_inode(inode, inode->i_mode,
								inode->i_rdev);
		}
		if (stat->st_result_mask & P9_STATS_RDEV)
			inode->i_rdev = new_decode_dev(stat->st_rdev);
		if (stat->st_result_mask & P9_STATS_SIZE)
			i_size_write(inode, stat->st_size);
		if (stat->st_result_mask & P9_STATS_BLOCKS)
			inode->i_blocks = stat->st_blocks;
	}
	if (stat->st_result_mask & P9_STATS_GEN)
		inode->i_generation = stat->st_gen;

	/* Currently we don't support P9_STATS_BTIME and P9_STATS_DATA_VERSION
	 * because the inode structure does not have fields for them.
	 */
	v9inode->cache_validity &= ~V9FS_INO_INVALID_ATTR;
}

static int
v9fs_vfs_symlink_dotl(struct inode *dir, struct dentry *dentry,
		const char *symname)
{
	int err;
	kgid_t gid;
	char *name;
	struct p9_qid qid;
	struct inode *inode;
	struct p9_fid *dfid;
	struct p9_fid *fid = NULL;
	struct v9fs_session_info *v9ses;

	name = (char *) dentry->d_name.name;
	p9_debug(P9_DEBUG_VFS, "%lu,%s,%s\n", dir->i_ino, name, symname);
	v9ses = v9fs_inode2v9ses(dir);

	dfid = v9fs_fid_lookup(dentry->d_parent);
	if (IS_ERR(dfid)) {
		err = PTR_ERR(dfid);
		p9_debug(P9_DEBUG_VFS, "fid lookup failed %d\n", err);
		return err;
	}

	gid = v9fs_get_fsgid_for_create(dir);

	/* Server doesn't alter fid on TSYMLINK. Hence no need to clone it. */
	err = p9_client_symlink(dfid, name, (char *)symname, gid, &qid);

	if (err < 0) {
		p9_debug(P9_DEBUG_VFS, "p9_client_symlink failed %d\n", err);
		goto error;
	}

	v9fs_invalidate_inode_attr(dir);
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE) {
		/* Now walk from the parent so we can get an unopened fid. */
		fid = p9_client_walk(dfid, 1, &name, 1);
		if (IS_ERR(fid)) {
			err = PTR_ERR(fid);
			p9_debug(P9_DEBUG_VFS, "p9_client_walk failed %d\n",
				 err);
			fid = NULL;
			goto error;
		}

		/* instantiate inode and assign the unopened fid to dentry */
		inode = v9fs_get_new_inode_from_fid(v9ses, fid, dir->i_sb);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			p9_debug(P9_DEBUG_VFS, "inode creation failed %d\n",
				 err);
			goto error;
		}
		v9fs_fid_add(dentry, fid);
		d_instantiate(dentry, inode);
		fid = NULL;
		err = 0;
	} else {
		/* Not in cached mode. No need to populate inode with stat */
		inode = v9fs_get_inode(dir->i_sb, S_IFLNK, 0);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		d_instantiate(dentry, inode);
	}

error:
	if (fid)
		p9_client_clunk(fid);

	return err;
}

/**
 * v9fs_vfs_link_dotl - create a hardlink for dotl
 * @old_dentry: dentry for file to link to
 * @dir: inode destination for new link
 * @dentry: dentry for link
 *
 */

static int
v9fs_vfs_link_dotl(struct dentry *old_dentry, struct inode *dir,
		struct dentry *dentry)
{
	int err;
	struct dentry *dir_dentry;
	struct p9_fid *dfid, *oldfid;
	struct v9fs_session_info *v9ses;

	p9_debug(P9_DEBUG_VFS, "dir ino: %lu, old_name: %pd, new_name: %pd\n",
		 dir->i_ino, old_dentry, dentry);

	v9ses = v9fs_inode2v9ses(dir);
	dir_dentry = dentry->d_parent;
	dfid = v9fs_fid_lookup(dir_dentry);
	if (IS_ERR(dfid))
		return PTR_ERR(dfid);

	oldfid = v9fs_fid_lookup(old_dentry);
	if (IS_ERR(oldfid))
		return PTR_ERR(oldfid);

	err = p9_client_link(dfid, oldfid, (char *)dentry->d_name.name);

	if (err < 0) {
		p9_debug(P9_DEBUG_VFS, "p9_client_link failed %d\n", err);
		return err;
	}

	v9fs_invalidate_inode_attr(dir);
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE) {
		/* Get the latest stat info from server. */
		struct p9_fid *fid;
		fid = v9fs_fid_lookup(old_dentry);
		if (IS_ERR(fid))
			return PTR_ERR(fid);

		v9fs_refresh_inode_dotl(fid, old_dentry->d_inode);
	}
	ihold(old_dentry->d_inode);
	d_instantiate(dentry, old_dentry->d_inode);

	return err;
}

/**
 * v9fs_vfs_mknod_dotl - create a special file
 * @dir: inode destination for new link
 * @dentry: dentry for file
 * @omode: mode for creation
 * @rdev: device associated with special file
 *
 */
static int
v9fs_vfs_mknod_dotl(struct inode *dir, struct dentry *dentry, umode_t omode,
		dev_t rdev)
{
	int err;
	kgid_t gid;
	char *name;
	umode_t mode;
	struct v9fs_session_info *v9ses;
	struct p9_fid *fid = NULL, *dfid = NULL;
	struct inode *inode;
	struct p9_qid qid;
	struct dentry *dir_dentry;
	struct posix_acl *dacl = NULL, *pacl = NULL;

	p9_debug(P9_DEBUG_VFS, " %lu,%pd mode: %hx MAJOR: %u MINOR: %u\n",
		 dir->i_ino, dentry, omode,
		 MAJOR(rdev), MINOR(rdev));

	if (!new_valid_dev(rdev))
		return -EINVAL;

	v9ses = v9fs_inode2v9ses(dir);
	dir_dentry = dentry->d_parent;
	dfid = v9fs_fid_lookup(dir_dentry);
	if (IS_ERR(dfid)) {
		err = PTR_ERR(dfid);
		p9_debug(P9_DEBUG_VFS, "fid lookup failed %d\n", err);
		dfid = NULL;
		goto error;
	}

	gid = v9fs_get_fsgid_for_create(dir);
	mode = omode;
	/* Update mode based on ACL value */
	err = v9fs_acl_mode(dir, &mode, &dacl, &pacl);
	if (err) {
		p9_debug(P9_DEBUG_VFS, "Failed to get acl values in mknod %d\n",
			 err);
		goto error;
	}
	name = (char *) dentry->d_name.name;

	err = p9_client_mknod_dotl(dfid, name, mode, rdev, gid, &qid);
	if (err < 0)
		goto error;

	v9fs_invalidate_inode_attr(dir);
	fid = p9_client_walk(dfid, 1, &name, 1);
	if (IS_ERR(fid)) {
		err = PTR_ERR(fid);
		p9_debug(P9_DEBUG_VFS, "p9_client_walk failed %d\n",
			 err);
		fid = NULL;
		goto error;
	}

	/* instantiate inode and assign the unopened fid to the dentry */
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE) {
		inode = v9fs_get_new_inode_from_fid(v9ses, fid, dir->i_sb);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			p9_debug(P9_DEBUG_VFS, "inode creation failed %d\n",
				 err);
			goto error;
		}
		v9fs_set_create_acl(inode, fid, dacl, pacl);
		v9fs_fid_add(dentry, fid);
		d_instantiate(dentry, inode);
		fid = NULL;
		err = 0;
	} else {
		/*
		 * Not in cached mode. No need to populate inode with stat.
		 * socket syscall returns a fd, so we need instantiate
		 */
		inode = v9fs_get_inode(dir->i_sb, mode, rdev);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto error;
		}
		v9fs_set_create_acl(inode, fid, dacl, pacl);
		d_instantiate(dentry, inode);
	}
error:
	if (fid)
		p9_client_clunk(fid);
	v9fs_put_acl(dacl, pacl);
	return err;
}

/**
 * v9fs_vfs_follow_link_dotl - follow a symlink path
 * @dentry: dentry for symlink
 * @nd: nameidata
 *
 */

static void *
v9fs_vfs_follow_link_dotl(struct dentry *dentry, struct nameidata *nd)
{
	int retval;
	struct p9_fid *fid;
	char *link = __getname();
	char *target;

	p9_debug(P9_DEBUG_VFS, "%pd\n", dentry);

	if (!link) {
		link = ERR_PTR(-ENOMEM);
		goto ndset;
	}
	fid = v9fs_fid_lookup(dentry);
	if (IS_ERR(fid)) {
		__putname(link);
		link = ERR_CAST(fid);
		goto ndset;
	}
	retval = p9_client_readlink(fid, &target);
	if (!retval) {
		strcpy(link, target);
		kfree(target);
		goto ndset;
	}
	__putname(link);
	link = ERR_PTR(retval);
ndset:
	nd_set_link(nd, link);
	return NULL;
}

int v9fs_refresh_inode_dotl(struct p9_fid *fid, struct inode *inode)
{
	loff_t i_size;
	struct p9_stat_dotl *st;
	struct v9fs_session_info *v9ses;

	v9ses = v9fs_inode2v9ses(inode);
	st = p9_client_getattr_dotl(fid, P9_STATS_ALL);
	if (IS_ERR(st))
		return PTR_ERR(st);
	/*
	 * Don't update inode if the file type is different
	 */
	if ((inode->i_mode & S_IFMT) != (st->st_mode & S_IFMT))
		goto out;

	spin_lock(&inode->i_lock);
	/*
	 * We don't want to refresh inode->i_size,
	 * because we may have cached data
	 */
	i_size = inode->i_size;
	v9fs_stat2inode_dotl(st, inode);
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE)
		inode->i_size = i_size;
	spin_unlock(&inode->i_lock);
out:
	kfree(st);
	return 0;
}

const struct inode_operations v9fs_dir_inode_operations_dotl = {
	.create = v9fs_vfs_create_dotl,
	.atomic_open = v9fs_vfs_atomic_open_dotl,
	.lookup = v9fs_vfs_lookup,
	.link = v9fs_vfs_link_dotl,
	.symlink = v9fs_vfs_symlink_dotl,
	.unlink = v9fs_vfs_unlink,
	.mkdir = v9fs_vfs_mkdir_dotl,
	.rmdir = v9fs_vfs_rmdir,
	.mknod = v9fs_vfs_mknod_dotl,
	.rename = v9fs_vfs_rename,
	.getattr = v9fs_vfs_getattr_dotl,
	.setattr = v9fs_vfs_setattr_dotl,
	.setxattr = generic_setxattr,
	.getxattr = generic_getxattr,
	.removexattr = generic_removexattr,
	.listxattr = v9fs_listxattr,
	.get_acl = v9fs_iop_get_acl,
};

const struct inode_operations v9fs_file_inode_operations_dotl = {
	.getattr = v9fs_vfs_getattr_dotl,
	.setattr = v9fs_vfs_setattr_dotl,
	.setxattr = generic_setxattr,
	.getxattr = generic_getxattr,
	.removexattr = generic_removexattr,
	.listxattr = v9fs_listxattr,
	.get_acl = v9fs_iop_get_acl,
};

const struct inode_operations v9fs_symlink_inode_operations_dotl = {
	.readlink = generic_readlink,
	.follow_link = v9fs_vfs_follow_link_dotl,
	.put_link = v9fs_vfs_put_link,
	.getattr = v9fs_vfs_getattr_dotl,
	.setattr = v9fs_vfs_setattr_dotl,
	.setxattr = generic_setxattr,
	.getxattr = generic_getxattr,
	.removexattr = generic_removexattr,
	.listxattr = v9fs_listxattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/vfs_inode_dotl.c */
/************************************************************/
/*
 *  linux/fs/9p/vfs_addr.c
 *
 * This file contians vfs address (mmap) ops for 9P2000.
 *
 *  Copyright (C) 2005 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

// #include <linux/module.h>
// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/file.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <linux/inet.h>
// #include <linux/pagemap.h>
// #include <linux/idr.h>
// #include <linux/sched.h>
#include <linux/aio.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>
#include "../../inc/__fss.h"

// #include "v9fs.h"
// #include "v9fs_vfs.h"
// #include "cache.h"
// #include "fid.h"

/**
 * v9fs_fid_readpage - read an entire page in from 9P
 *
 * @fid: fid being read
 * @page: structure to page
 *
 */
static int v9fs_fid_readpage(struct p9_fid *fid, struct page *page)
{
	int retval;
	loff_t offset;
	char *buffer;
	struct inode *inode;

	inode = page->mapping->host;
	p9_debug(P9_DEBUG_VFS, "\n");

	BUG_ON(!PageLocked(page));

	retval = v9fs_readpage_from_fscache(inode, page);
	if (retval == 0)
		return retval;

	buffer = kmap(page);
	offset = page_offset(page);

	retval = v9fs_fid_readn(fid, buffer, NULL, PAGE_CACHE_SIZE, offset);
	if (retval < 0) {
		v9fs_uncache_page(inode, page);
		goto done;
	}

	memset(buffer + retval, 0, PAGE_CACHE_SIZE - retval);
	flush_dcache_page(page);
	SetPageUptodate(page);

	v9fs_readpage_to_fscache(inode, page);
	retval = 0;

done:
	kunmap(page);
	unlock_page(page);
	return retval;
}

/**
 * v9fs_vfs_readpage - read an entire page in from 9P
 *
 * @filp: file being read
 * @page: structure to page
 *
 */

static int v9fs_vfs_readpage(struct file *filp, struct page *page)
{
	return v9fs_fid_readpage(filp->private_data, page);
}

/**
 * v9fs_vfs_readpages - read a set of pages from 9P
 *
 * @filp: file being read
 * @mapping: the address space
 * @pages: list of pages to read
 * @nr_pages: count of pages to read
 *
 */

static int v9fs_vfs_readpages(struct file *filp, struct address_space *mapping,
			     struct list_head *pages, unsigned nr_pages)
{
	int ret = 0;
	struct inode *inode;

	inode = mapping->host;
	p9_debug(P9_DEBUG_VFS, "inode: %p file: %p\n", inode, filp);

	ret = v9fs_readpages_from_fscache(inode, mapping, pages, &nr_pages);
	if (ret == 0)
		return ret;

	ret = read_cache_pages(mapping, pages, (void *)v9fs_vfs_readpage, filp);
	p9_debug(P9_DEBUG_VFS, "  = %d\n", ret);
	return ret;
}

/**
 * v9fs_release_page - release the private state associated with a page
 *
 * Returns 1 if the page can be released, false otherwise.
 */

static int v9fs_release_page(struct page *page, gfp_t gfp)
{
	if (PagePrivate(page))
		return 0;
	return v9fs_fscache_release_page(page, gfp);
}

/**
 * v9fs_invalidate_page - Invalidate a page completely or partially
 *
 * @page: structure to page
 * @offset: offset in the page
 */

static void v9fs_invalidate_page(struct page *page, unsigned int offset,
				 unsigned int length)
{
	/*
	 * If called with zero offset, we should release
	 * the private state assocated with the page
	 */
	if (offset == 0 && length == PAGE_CACHE_SIZE)
		v9fs_fscache_invalidate_page(page);
}

static int v9fs_vfs_writepage_locked(struct page *page)
{
	char *buffer;
	int retval, len;
	loff_t offset, size;
	mm_segment_t old_fs;
	struct v9fs_inode *v9inode;
	struct inode *inode = page->mapping->host;

	v9inode = V9FS_I(inode);
	size = i_size_read(inode);
	if (page->index == size >> PAGE_CACHE_SHIFT)
		len = size & ~PAGE_CACHE_MASK;
	else
		len = PAGE_CACHE_SIZE;

	set_page_writeback(page);

	buffer = kmap(page);
	offset = page_offset(page);

	old_fs = get_fs();
	set_fs(get_ds());
	/* We should have writeback_fid always set */
	BUG_ON(!v9inode->writeback_fid);

	retval = v9fs_file_write_internal(inode,
					  v9inode->writeback_fid,
					  (__force const char __user *)buffer,
					  len, &offset, 0);
	if (retval > 0)
		retval = 0;

	set_fs(old_fs);
	kunmap(page);
	end_page_writeback(page);
	return retval;
}

static int v9fs_vfs_writepage(struct page *page, struct writeback_control *wbc)
{
	int retval;

	p9_debug(P9_DEBUG_VFS, "page %p\n", page);

	retval = v9fs_vfs_writepage_locked(page);
	if (retval < 0) {
		if (retval == -EAGAIN) {
			redirty_page_for_writepage(wbc, page);
			retval = 0;
		} else {
			SetPageError(page);
			mapping_set_error(page->mapping, retval);
		}
	} else
		retval = 0;

	unlock_page(page);
	return retval;
}

/**
 * v9fs_launder_page - Writeback a dirty page
 * Returns 0 on success.
 */

static int v9fs_launder_page(struct page *page)
{
	int retval;
	struct inode *inode = page->mapping->host;

	v9fs_fscache_wait_on_page_write(inode, page);
	if (clear_page_dirty_for_io(page)) {
		retval = v9fs_vfs_writepage_locked(page);
		if (retval)
			return retval;
	}
	return 0;
}

/**
 * v9fs_direct_IO - 9P address space operation for direct I/O
 * @rw: direction (read or write)
 * @iocb: target I/O control block
 * @iov: array of vectors that define I/O buffer
 * @pos: offset in file to begin the operation
 * @nr_segs: size of iovec array
 *
 * The presence of v9fs_direct_IO() in the address space ops vector
 * allowes open() O_DIRECT flags which would have failed otherwise.
 *
 * In the non-cached mode, we shunt off direct read and write requests before
 * the VFS gets them, so this method should never be called.
 *
 * Direct IO is not 'yet' supported in the cached mode. Hence when
 * this routine is called through generic_file_aio_read(), the read/write fails
 * with an error.
 *
 */
static ssize_t
v9fs_direct_IO(int rw, struct kiocb *iocb, struct iov_iter *iter, loff_t pos)
{
	/*
	 * FIXME
	 * Now that we do caching with cache mode enabled, We need
	 * to support direct IO
	 */
	p9_debug(P9_DEBUG_VFS, "v9fs_direct_IO: v9fs_direct_IO (%pD) off/no(%lld/%lu) EINVAL\n",
		 iocb->ki_filp,
		 (long long)pos, iter->nr_segs);

	return -EINVAL;
}

static int v9fs_write_begin(struct file *filp, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{
	int retval = 0;
	struct page *page;
	struct v9fs_inode *v9inode;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct inode *inode = mapping->host;


	p9_debug(P9_DEBUG_VFS, "filp %p, mapping %p\n", filp, mapping);

	v9inode = V9FS_I(inode);
start:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		retval = -ENOMEM;
		goto out;
	}
	BUG_ON(!v9inode->writeback_fid);
	if (PageUptodate(page))
		goto out;

	if (len == PAGE_CACHE_SIZE)
		goto out;

	retval = v9fs_fid_readpage(v9inode->writeback_fid, page);
	page_cache_release(page);
	if (!retval)
		goto start;
out:
	*pagep = page;
	return retval;
}

static int v9fs_write_end(struct file *filp, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{
	loff_t last_pos = pos + copied;
	struct inode *inode = page->mapping->host;

	p9_debug(P9_DEBUG_VFS, "filp %p, mapping %p\n", filp, mapping);

	if (unlikely(copied < len)) {
		/*
		 * zero out the rest of the area
		 */
		unsigned from = pos & (PAGE_CACHE_SIZE - 1);

		zero_user(page, from + copied, len - copied);
		flush_dcache_page(page);
	}

	if (!PageUptodate(page))
		SetPageUptodate(page);
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold the i_mutex.
	 */
	if (last_pos > inode->i_size) {
		inode_add_bytes(inode, last_pos - inode->i_size);
		i_size_write(inode, last_pos);
	}
	set_page_dirty(page);
	unlock_page(page);
	page_cache_release(page);

	return copied;
}


const struct address_space_operations v9fs_addr_operations = {
	.readpage = v9fs_vfs_readpage,
	.readpages = v9fs_vfs_readpages,
	.set_page_dirty = __set_page_dirty_nobuffers,
	.writepage = v9fs_vfs_writepage,
	.write_begin = v9fs_write_begin,
	.write_end = v9fs_write_end,
	.releasepage = v9fs_release_page,
	.invalidatepage = v9fs_invalidate_page,
	.launder_page = v9fs_launder_page,
	.direct_IO = v9fs_direct_IO,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/vfs_addr.c */
/************************************************************/
/*
 *  linux/fs/9p/vfs_file.c
 *
 * This file contians vfs file ops for 9P2000.
 *
 *  Copyright (C) 2004 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

// #include <linux/module.h>
// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/sched.h>
// #include <linux/file.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <linux/inet.h>
#include <linux/list.h>
// #include <linux/pagemap.h>
#include <linux/utsname.h>
#include <asm/uaccess.h>
// #include <linux/idr.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>
#include "../../inc/__fss.h"

// #include "v9fs.h"
// #include "v9fs_vfs.h"
// #include "fid.h"
// #include "cache.h"

static const struct vm_operations_struct v9fs_file_vm_ops;
static const struct vm_operations_struct v9fs_mmap_file_vm_ops;

/**
 * v9fs_file_open - open a file (or directory)
 * @inode: inode to be opened
 * @file: file being opened
 *
 */

int v9fs_file_open(struct inode *inode, struct file *file)
{
	int err;
	struct v9fs_inode *v9inode;
	struct v9fs_session_info *v9ses;
	struct p9_fid *fid;
	int omode;

	p9_debug(P9_DEBUG_VFS, "inode: %p file: %p\n", inode, file);
	v9inode = V9FS_I(inode);
	v9ses = v9fs_inode2v9ses(inode);
	if (v9fs_proto_dotl(v9ses))
		omode = v9fs_open_to_dotl_flags(file->f_flags);
	else
		omode = v9fs_uflags2omode(file->f_flags,
					v9fs_proto_dotu(v9ses));
	fid = file->private_data;
	if (!fid) {
		fid = v9fs_fid_clone(file->f_path.dentry);
		if (IS_ERR(fid))
			return PTR_ERR(fid);

		err = p9_client_open(fid, omode);
		if (err < 0) {
			p9_client_clunk(fid);
			return err;
		}
		if ((file->f_flags & O_APPEND) &&
			(!v9fs_proto_dotu(v9ses) && !v9fs_proto_dotl(v9ses)))
			generic_file_llseek(file, 0, SEEK_END);
	}

	file->private_data = fid;
	mutex_lock(&v9inode->v_mutex);
	if ((v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE) &&
	    !v9inode->writeback_fid &&
	    ((file->f_flags & O_ACCMODE) != O_RDONLY)) {
		/*
		 * clone a fid and add it to writeback_fid
		 * we do it during open time instead of
		 * page dirty time via write_begin/page_mkwrite
		 * because we want write after unlink usecase
		 * to work.
		 */
		fid = v9fs_writeback_fid(file->f_path.dentry);
		if (IS_ERR(fid)) {
			err = PTR_ERR(fid);
			mutex_unlock(&v9inode->v_mutex);
			goto out_error;
		}
		v9inode->writeback_fid = (void *) fid;
	}
	mutex_unlock(&v9inode->v_mutex);
	if (v9ses->cache == CACHE_LOOSE || v9ses->cache == CACHE_FSCACHE)
		v9fs_cache_inode_set_cookie(inode, file);
	return 0;
out_error:
	p9_client_clunk(file->private_data);
	file->private_data = NULL;
	return err;
}

/**
 * v9fs_file_lock - lock a file (or directory)
 * @filp: file to be locked
 * @cmd: lock command
 * @fl: file lock structure
 *
 * Bugs: this looks like a local only lock, we should extend into 9P
 *       by using open exclusive
 */

static int v9fs_file_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	int res = 0;
	struct inode *inode = file_inode(filp);

	p9_debug(P9_DEBUG_VFS, "filp: %p lock: %p\n", filp, fl);

	/* No mandatory locks */
	if (__mandatory_lock(inode) && fl->fl_type != F_UNLCK)
		return -ENOLCK;

	if ((IS_SETLK(cmd) || IS_SETLKW(cmd)) && fl->fl_type != F_UNLCK) {
		filemap_write_and_wait(inode->i_mapping);
		invalidate_mapping_pages(&inode->i_data, 0, -1);
	}

	return res;
}

static int v9fs_file_do_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	struct p9_flock flock;
	struct p9_fid *fid;
	uint8_t status;
	int res = 0;
	unsigned char fl_type;

	fid = filp->private_data;
	BUG_ON(fid == NULL);

	if ((fl->fl_flags & FL_POSIX) != FL_POSIX)
		BUG();

	res = posix_lock_file_wait(filp, fl);
	if (res < 0)
		goto out;

	/* convert posix lock to p9 tlock args */
	memset(&flock, 0, sizeof(flock));
	/* map the lock type */
	switch (fl->fl_type) {
	case F_RDLCK:
		flock.type = P9_LOCK_TYPE_RDLCK;
		break;
	case F_WRLCK:
		flock.type = P9_LOCK_TYPE_WRLCK;
		break;
	case F_UNLCK:
		flock.type = P9_LOCK_TYPE_UNLCK;
		break;
	}
	flock.start = fl->fl_start;
	if (fl->fl_end == OFFSET_MAX)
		flock.length = 0;
	else
		flock.length = fl->fl_end - fl->fl_start + 1;
	flock.proc_id = fl->fl_pid;
	flock.client_id = fid->clnt->name;
	if (IS_SETLKW(cmd))
		flock.flags = P9_LOCK_FLAGS_BLOCK;

	/*
	 * if its a blocked request and we get P9_LOCK_BLOCKED as the status
	 * for lock request, keep on trying
	 */
	for (;;) {
		res = p9_client_lock_dotl(fid, &flock, &status);
		if (res < 0)
			break;

		if (status != P9_LOCK_BLOCKED)
			break;
		if (status == P9_LOCK_BLOCKED && !IS_SETLKW(cmd))
			break;
		if (schedule_timeout_interruptible(P9_LOCK_TIMEOUT) != 0)
			break;
	}

	/* map 9p status to VFS status */
	switch (status) {
	case P9_LOCK_SUCCESS:
		res = 0;
		break;
	case P9_LOCK_BLOCKED:
		res = -EAGAIN;
		break;
	case P9_LOCK_ERROR:
	case P9_LOCK_GRACE:
		res = -ENOLCK;
		break;
	default:
		BUG();
	}

	/*
	 * incase server returned error for lock request, revert
	 * it locally
	 */
	if (res < 0 && fl->fl_type != F_UNLCK) {
		fl_type = fl->fl_type;
		fl->fl_type = F_UNLCK;
		res = posix_lock_file_wait(filp, fl);
		fl->fl_type = fl_type;
	}
out:
	return res;
}

static int v9fs_file_getlock(struct file *filp, struct file_lock *fl)
{
	struct p9_getlock glock;
	struct p9_fid *fid;
	int res = 0;

	fid = filp->private_data;
	BUG_ON(fid == NULL);

	posix_test_lock(filp, fl);
	/*
	 * if we have a conflicting lock locally, no need to validate
	 * with server
	 */
	if (fl->fl_type != F_UNLCK)
		return res;

	/* convert posix lock to p9 tgetlock args */
	memset(&glock, 0, sizeof(glock));
	glock.type  = P9_LOCK_TYPE_UNLCK;
	glock.start = fl->fl_start;
	if (fl->fl_end == OFFSET_MAX)
		glock.length = 0;
	else
		glock.length = fl->fl_end - fl->fl_start + 1;
	glock.proc_id = fl->fl_pid;
	glock.client_id = fid->clnt->name;

	res = p9_client_getlock_dotl(fid, &glock);
	if (res < 0)
		return res;
	/* map 9p lock type to os lock type */
	switch (glock.type) {
	case P9_LOCK_TYPE_RDLCK:
		fl->fl_type = F_RDLCK;
		break;
	case P9_LOCK_TYPE_WRLCK:
		fl->fl_type = F_WRLCK;
		break;
	case P9_LOCK_TYPE_UNLCK:
		fl->fl_type = F_UNLCK;
		break;
	}
	if (glock.type != P9_LOCK_TYPE_UNLCK) {
		fl->fl_start = glock.start;
		if (glock.length == 0)
			fl->fl_end = OFFSET_MAX;
		else
			fl->fl_end = glock.start + glock.length - 1;
		fl->fl_pid = glock.proc_id;
	}
	return res;
}

/**
 * v9fs_file_lock_dotl - lock a file (or directory)
 * @filp: file to be locked
 * @cmd: lock command
 * @fl: file lock structure
 *
 */

static int v9fs_file_lock_dotl(struct file *filp, int cmd, struct file_lock *fl)
{
	struct inode *inode = file_inode(filp);
	int ret = -ENOLCK;

	p9_debug(P9_DEBUG_VFS, "filp: %p cmd:%d lock: %p name: %pD\n",
		 filp, cmd, fl, filp);

	/* No mandatory locks */
	if (__mandatory_lock(inode) && fl->fl_type != F_UNLCK)
		goto out_err;

	if ((IS_SETLK(cmd) || IS_SETLKW(cmd)) && fl->fl_type != F_UNLCK) {
		filemap_write_and_wait(inode->i_mapping);
		invalidate_mapping_pages(&inode->i_data, 0, -1);
	}

	if (IS_SETLK(cmd) || IS_SETLKW(cmd))
		ret = v9fs_file_do_lock(filp, cmd, fl);
	else if (IS_GETLK(cmd))
		ret = v9fs_file_getlock(filp, fl);
	else
		ret = -EINVAL;
out_err:
	return ret;
}

/**
 * v9fs_file_flock_dotl - lock a file
 * @filp: file to be locked
 * @cmd: lock command
 * @fl: file lock structure
 *
 */

static int v9fs_file_flock_dotl(struct file *filp, int cmd,
	struct file_lock *fl)
{
	struct inode *inode = file_inode(filp);
	int ret = -ENOLCK;

	p9_debug(P9_DEBUG_VFS, "filp: %p cmd:%d lock: %p name: %pD\n",
		 filp, cmd, fl, filp);

	/* No mandatory locks */
	if (__mandatory_lock(inode) && fl->fl_type != F_UNLCK)
		goto out_err;

	if (!(fl->fl_flags & FL_FLOCK))
		goto out_err;

	if ((IS_SETLK(cmd) || IS_SETLKW(cmd)) && fl->fl_type != F_UNLCK) {
		filemap_write_and_wait(inode->i_mapping);
		invalidate_mapping_pages(&inode->i_data, 0, -1);
	}
	/* Convert flock to posix lock */
	fl->fl_flags |= FL_POSIX;
	fl->fl_flags ^= FL_FLOCK;

	if (IS_SETLK(cmd) | IS_SETLKW(cmd))
		ret = v9fs_file_do_lock(filp, cmd, fl);
	else
		ret = -EINVAL;
out_err:
	return ret;
}

/**
 * v9fs_fid_readn - read from a fid
 * @fid: fid to read
 * @data: data buffer to read data into
 * @udata: user data buffer to read data into
 * @count: size of buffer
 * @offset: offset at which to read data
 *
 */
ssize_t
v9fs_fid_readn(struct p9_fid *fid, char *data, char __user *udata, u32 count,
	       u64 offset)
{
	int n, total, size;

	p9_debug(P9_DEBUG_VFS, "fid %d offset %llu count %d\n",
		 fid->fid, (long long unsigned)offset, count);
	n = 0;
	total = 0;
	size = fid->iounit ? fid->iounit : fid->clnt->msize - P9_IOHDRSZ;
	do {
		n = p9_client_read(fid, data, udata, offset, count);
		if (n <= 0)
			break;

		if (data)
			data += n;
		if (udata)
			udata += n;

		offset += n;
		count -= n;
		total += n;
	} while (count > 0 && n == size);

	if (n < 0)
		total = n;

	return total;
}

/**
 * v9fs_file_readn - read from a file
 * @filp: file pointer to read
 * @data: data buffer to read data into
 * @udata: user data buffer to read data into
 * @count: size of buffer
 * @offset: offset at which to read data
 *
 */
ssize_t
v9fs_file_readn(struct file *filp, char *data, char __user *udata, u32 count,
	       u64 offset)
{
	return v9fs_fid_readn(filp->private_data, data, udata, count, offset);
}

/**
 * v9fs_file_read - read from a file
 * @filp: file pointer to read
 * @udata: user data buffer to read data into
 * @count: size of buffer
 * @offset: offset at which to read data
 *
 */

static ssize_t
v9fs_file_read(struct file *filp, char __user *udata, size_t count,
	       loff_t * offset)
{
	int ret;
	struct p9_fid *fid;
	size_t size;

	p9_debug(P9_DEBUG_VFS, "count %zu offset %lld\n", count, *offset);
	fid = filp->private_data;

	size = fid->iounit ? fid->iounit : fid->clnt->msize - P9_IOHDRSZ;
	if (count > size)
		ret = v9fs_file_readn(filp, NULL, udata, count, *offset);
	else
		ret = p9_client_read(fid, NULL, udata, *offset, count);

	if (ret > 0)
		*offset += ret;

	return ret;
}

ssize_t
v9fs_file_write_internal(struct inode *inode, struct p9_fid *fid,
			 const char __user *data, size_t count,
			 loff_t *offset, int invalidate)
{
	int n;
	loff_t i_size;
	size_t total = 0;
	loff_t origin = *offset;
	unsigned long pg_start, pg_end;

	p9_debug(P9_DEBUG_VFS, "data %p count %d offset %x\n",
		 data, (int)count, (int)*offset);

	do {
		n = p9_client_write(fid, NULL, data+total, origin+total, count);
		if (n <= 0)
			break;
		count -= n;
		total += n;
	} while (count > 0);

	if (invalidate && (total > 0)) {
		pg_start = origin >> PAGE_CACHE_SHIFT;
		pg_end = (origin + total - 1) >> PAGE_CACHE_SHIFT;
		if (inode->i_mapping && inode->i_mapping->nrpages)
			invalidate_inode_pages2_range(inode->i_mapping,
						      pg_start, pg_end);
		*offset += total;
		i_size = i_size_read(inode);
		if (*offset > i_size) {
			inode_add_bytes(inode, *offset - i_size);
			i_size_write(inode, *offset);
		}
	}
	if (n < 0)
		return n;

	return total;
}

/**
 * v9fs_file_write - write to a file
 * @filp: file pointer to write
 * @data: data buffer to write data from
 * @count: size of buffer
 * @offset: offset at which to write data
 *
 */
static ssize_t
v9fs_file_write(struct file *filp, const char __user * data,
		size_t count, loff_t *offset)
{
	ssize_t retval = 0;
	loff_t origin = *offset;


	retval = generic_write_checks(filp, &origin, &count, 0);
	if (retval)
		goto out;

	retval = -EINVAL;
	if ((ssize_t) count < 0)
		goto out;
	retval = 0;
	if (!count)
		goto out;

	retval = v9fs_file_write_internal(file_inode(filp),
					filp->private_data,
					data, count, &origin, 1);
	/* update offset on successful write */
	if (retval > 0)
		*offset = origin;
out:
	return retval;
}


static int v9fs_file_fsync(struct file *filp, loff_t start, loff_t end,
			   int datasync)
{
	struct p9_fid *fid;
	struct inode *inode = filp->f_mapping->host;
	struct p9_wstat wstat;
	int retval;

	retval = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (retval)
		return retval;

	mutex_lock(&inode->i_mutex);
	p9_debug(P9_DEBUG_VFS, "filp %p datasync %x\n", filp, datasync);

	fid = filp->private_data;
	v9fs_blank_wstat(&wstat);

	retval = p9_client_wstat(fid, &wstat);
	mutex_unlock(&inode->i_mutex);

	return retval;
}

int v9fs_file_fsync_dotl(struct file *filp, loff_t start, loff_t end,
			 int datasync)
{
	struct p9_fid *fid;
	struct inode *inode = filp->f_mapping->host;
	int retval;

	retval = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (retval)
		return retval;

	mutex_lock(&inode->i_mutex);
	p9_debug(P9_DEBUG_VFS, "filp %p datasync %x\n", filp, datasync);

	fid = filp->private_data;

	retval = p9_client_fsync(fid, datasync);
	mutex_unlock(&inode->i_mutex);

	return retval;
}

static int
v9fs_file_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int retval;


	retval = generic_file_mmap(filp, vma);
	if (!retval)
		vma->vm_ops = &v9fs_file_vm_ops;

	return retval;
}

static int
v9fs_mmap_file_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int retval;
	struct inode *inode;
	struct v9fs_inode *v9inode;
	struct p9_fid *fid;

	inode = file_inode(filp);
	v9inode = V9FS_I(inode);
	mutex_lock(&v9inode->v_mutex);
	if (!v9inode->writeback_fid &&
	    (vma->vm_flags & VM_WRITE)) {
		/*
		 * clone a fid and add it to writeback_fid
		 * we do it during mmap instead of
		 * page dirty time via write_begin/page_mkwrite
		 * because we want write after unlink usecase
		 * to work.
		 */
		fid = v9fs_writeback_fid(filp->f_path.dentry);
		if (IS_ERR(fid)) {
			retval = PTR_ERR(fid);
			mutex_unlock(&v9inode->v_mutex);
			return retval;
		}
		v9inode->writeback_fid = (void *) fid;
	}
	mutex_unlock(&v9inode->v_mutex);

	retval = generic_file_mmap(filp, vma);
	if (!retval)
		vma->vm_ops = &v9fs_mmap_file_vm_ops;

	return retval;
}

static int
v9fs_vm_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct v9fs_inode *v9inode;
	struct page *page = vmf->page;
	struct file *filp = vma->vm_file;
	struct inode *inode = file_inode(filp);


	p9_debug(P9_DEBUG_VFS, "page %p fid %lx\n",
		 page, (unsigned long)filp->private_data);

	/* Update file times before taking page lock */
	file_update_time(filp);

	v9inode = V9FS_I(inode);
	/* make sure the cache has finished storing the page */
	v9fs_fscache_wait_on_page_write(inode, page);
	BUG_ON(!v9inode->writeback_fid);
	lock_page(page);
	if (page->mapping != inode->i_mapping)
		goto out_unlock;
	wait_for_stable_page(page);

	return VM_FAULT_LOCKED;
out_unlock:
	unlock_page(page);
	return VM_FAULT_NOPAGE;
}

static ssize_t
v9fs_direct_read(struct file *filp, char __user *udata, size_t count,
		 loff_t *offsetp)
{
	loff_t size, offset;
	struct inode *inode;
	struct address_space *mapping;

	offset = *offsetp;
	mapping = filp->f_mapping;
	inode = mapping->host;
	if (!count)
		return 0;
	size = i_size_read(inode);
	if (offset < size)
		filemap_write_and_wait_range(mapping, offset,
					     offset + count - 1);

	return v9fs_file_read(filp, udata, count, offsetp);
}

/**
 * v9fs_cached_file_read - read from a file
 * @filp: file pointer to read
 * @data: user data buffer to read data into
 * @count: size of buffer
 * @offset: offset at which to read data
 *
 */
static ssize_t
v9fs_cached_file_read(struct file *filp, char __user *data, size_t count,
		      loff_t *offset)
{
	if (filp->f_flags & O_DIRECT)
		return v9fs_direct_read(filp, data, count, offset);
	return new_sync_read(filp, data, count, offset);
}

/**
 * v9fs_mmap_file_read - read from a file
 * @filp: file pointer to read
 * @data: user data buffer to read data into
 * @count: size of buffer
 * @offset: offset at which to read data
 *
 */
static ssize_t
v9fs_mmap_file_read(struct file *filp, char __user *data, size_t count,
		      loff_t *offset)
{
	/* TODO: Check if there are dirty pages */
	return v9fs_file_read(filp, data, count, offset);
}

static ssize_t
v9fs_direct_write(struct file *filp, const char __user * data,
		  size_t count, loff_t *offsetp)
{
	loff_t offset;
	ssize_t retval;
	struct inode *inode;
	struct address_space *mapping;

	offset = *offsetp;
	mapping = filp->f_mapping;
	inode = mapping->host;
	if (!count)
		return 0;

	mutex_lock(&inode->i_mutex);
	retval = filemap_write_and_wait_range(mapping, offset,
					      offset + count - 1);
	if (retval)
		goto err_out;
	/*
	 * After a write we want buffered reads to be sure to go to disk to get
	 * the new data.  We invalidate clean cached page from the region we're
	 * about to write.  We do this *before* the write so that if we fail
	 * here we fall back to buffered write
	 */
	if (mapping->nrpages) {
		pgoff_t pg_start = offset >> PAGE_CACHE_SHIFT;
		pgoff_t pg_end   = (offset + count - 1) >> PAGE_CACHE_SHIFT;

		retval = invalidate_inode_pages2_range(mapping,
							pg_start, pg_end);
		/*
		 * If a page can not be invalidated, fall back
		 * to buffered write.
		 */
		if (retval) {
			if (retval == -EBUSY)
				goto buff_write;
			goto err_out;
		}
	}
	retval = v9fs_file_write(filp, data, count, offsetp);
err_out:
	mutex_unlock(&inode->i_mutex);
	return retval;

buff_write:
	mutex_unlock(&inode->i_mutex);
	return new_sync_write(filp, data, count, offsetp);
}

/**
 * v9fs_cached_file_write - write to a file
 * @filp: file pointer to write
 * @data: data buffer to write data from
 * @count: size of buffer
 * @offset: offset at which to write data
 *
 */
static ssize_t
v9fs_cached_file_write(struct file *filp, const char __user * data,
		       size_t count, loff_t *offset)
{

	if (filp->f_flags & O_DIRECT)
		return v9fs_direct_write(filp, data, count, offset);
	return new_sync_write(filp, data, count, offset);
}


/**
 * v9fs_mmap_file_write - write to a file
 * @filp: file pointer to write
 * @data: data buffer to write data from
 * @count: size of buffer
 * @offset: offset at which to write data
 *
 */
static ssize_t
v9fs_mmap_file_write(struct file *filp, const char __user *data,
		       size_t count, loff_t *offset)
{
	/*
	 * TODO: invalidate mmaps on filp's inode between
	 * offset and offset+count
	 */
	return v9fs_file_write(filp, data, count, offset);
}

static void v9fs_mmap_vm_close(struct vm_area_struct *vma)
{
	struct inode *inode;

	struct writeback_control wbc = {
		.nr_to_write = LONG_MAX,
		.sync_mode = WB_SYNC_ALL,
		.range_start = vma->vm_pgoff * PAGE_SIZE,
		 /* absolute end, byte at end included */
		.range_end = vma->vm_pgoff * PAGE_SIZE +
			(vma->vm_end - vma->vm_start - 1),
	};


	p9_debug(P9_DEBUG_VFS, "9p VMA close, %p, flushing", vma);

	inode = file_inode(vma->vm_file);

	if (!mapping_cap_writeback_dirty(inode->i_mapping))
		wbc.nr_to_write = 0;

	might_sleep();
	sync_inode(inode, &wbc);
}


static const struct vm_operations_struct v9fs_file_vm_ops = {
	.fault = filemap_fault,
	.map_pages = filemap_map_pages,
	.page_mkwrite = v9fs_vm_page_mkwrite,
};

static const struct vm_operations_struct v9fs_mmap_file_vm_ops = {
	.close = v9fs_mmap_vm_close,
	.fault = filemap_fault,
	.map_pages = filemap_map_pages,
	.page_mkwrite = v9fs_vm_page_mkwrite,
};


const struct file_operations v9fs_cached_file_operations = {
	.llseek = generic_file_llseek,
	.read = v9fs_cached_file_read,
	.write = v9fs_cached_file_write,
	.read_iter = generic_file_read_iter,
	.write_iter = generic_file_write_iter,
	.open = v9fs_file_open,
	.release = v9fs_dir_release,
	.lock = v9fs_file_lock,
	.mmap = v9fs_file_mmap,
	.fsync = v9fs_file_fsync,
};

const struct file_operations v9fs_cached_file_operations_dotl = {
	.llseek = generic_file_llseek,
	.read = v9fs_cached_file_read,
	.write = v9fs_cached_file_write,
	.read_iter = generic_file_read_iter,
	.write_iter = generic_file_write_iter,
	.open = v9fs_file_open,
	.release = v9fs_dir_release,
	.lock = v9fs_file_lock_dotl,
	.flock = v9fs_file_flock_dotl,
	.mmap = v9fs_file_mmap,
	.fsync = v9fs_file_fsync_dotl,
};

const struct file_operations v9fs_file_operations = {
	.llseek = generic_file_llseek,
	.read = v9fs_file_read,
	.write = v9fs_file_write,
	.open = v9fs_file_open,
	.release = v9fs_dir_release,
	.lock = v9fs_file_lock,
	.mmap = generic_file_readonly_mmap,
	.fsync = v9fs_file_fsync,
};

const struct file_operations v9fs_file_operations_dotl = {
	.llseek = generic_file_llseek,
	.read = v9fs_file_read,
	.write = v9fs_file_write,
	.open = v9fs_file_open,
	.release = v9fs_dir_release,
	.lock = v9fs_file_lock_dotl,
	.flock = v9fs_file_flock_dotl,
	.mmap = generic_file_readonly_mmap,
	.fsync = v9fs_file_fsync_dotl,
};

const struct file_operations v9fs_mmap_file_operations = {
	.llseek = generic_file_llseek,
	.read = v9fs_mmap_file_read,
	.write = v9fs_mmap_file_write,
	.open = v9fs_file_open,
	.release = v9fs_dir_release,
	.lock = v9fs_file_lock,
	.mmap = v9fs_mmap_file_mmap,
	.fsync = v9fs_file_fsync,
};

const struct file_operations v9fs_mmap_file_operations_dotl = {
	.llseek = generic_file_llseek,
	.read = v9fs_mmap_file_read,
	.write = v9fs_mmap_file_write,
	.open = v9fs_file_open,
	.release = v9fs_dir_release,
	.lock = v9fs_file_lock_dotl,
	.flock = v9fs_file_flock_dotl,
	.mmap = v9fs_mmap_file_mmap,
	.fsync = v9fs_file_fsync_dotl,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/vfs_file.c */
/************************************************************/
/*
 * linux/fs/9p/vfs_dir.c
 *
 * This file contains vfs directory ops for the 9P2000 protocol.
 *
 *  Copyright (C) 2004 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

// #include <linux/module.h>
// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/file.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <linux/sched.h>
// #include <linux/inet.h>
// #include <linux/idr.h>
// #include <linux/slab.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>

// #include "v9fs.h"
// #include "v9fs_vfs.h"
// #include "fid.h"

/**
 * struct p9_rdir - readdir accounting
 * @head: start offset of current dirread buffer
 * @tail: end offset of current dirread buffer
 * @buf: dirread buffer
 *
 * private structure for keeping track of readdir
 * allocated on demand
 */

struct p9_rdir {
	int head;
	int tail;
	uint8_t buf[];
};

/**
 * dt_type - return file type
 * @mistat: mistat structure
 *
 */

static inline int dt_type(struct p9_wstat *mistat)
{
	unsigned long perm = mistat->mode;
	int rettype = DT_REG;

	if (perm & P9_DMDIR)
		rettype = DT_DIR;
	if (perm & P9_DMSYMLINK)
		rettype = DT_LNK;

	return rettype;
}

static void p9stat_init(struct p9_wstat *stbuf)
{
	stbuf->name  = NULL;
	stbuf->uid   = NULL;
	stbuf->gid   = NULL;
	stbuf->muid  = NULL;
	stbuf->extension = NULL;
}

/**
 * v9fs_alloc_rdir_buf - Allocate buffer used for read and readdir
 * @filp: opened file structure
 * @buflen: Length in bytes of buffer to allocate
 *
 */

static struct p9_rdir *v9fs_alloc_rdir_buf(struct file *filp, int buflen)
{
	struct p9_fid *fid = filp->private_data;
	if (!fid->rdir)
		fid->rdir = kzalloc(sizeof(struct p9_rdir) + buflen, GFP_KERNEL);
	return fid->rdir;
}

/**
 * v9fs_dir_readdir - iterate through a directory
 * @file: opened file structure
 * @ctx: actor we feed the entries to
 *
 */

static int v9fs_dir_readdir(struct file *file, struct dir_context *ctx)
{
	bool over;
	struct p9_wstat st;
	int err = 0;
	struct p9_fid *fid;
	int buflen;
	int reclen = 0;
	struct p9_rdir *rdir;

	p9_debug(P9_DEBUG_VFS, "name %pD\n", file);
	fid = file->private_data;

	buflen = fid->clnt->msize - P9_IOHDRSZ;

	rdir = v9fs_alloc_rdir_buf(file, buflen);
	if (!rdir)
		return -ENOMEM;

	while (1) {
		if (rdir->tail == rdir->head) {
			err = v9fs_file_readn(file, rdir->buf, NULL,
							buflen, ctx->pos);
			if (err <= 0)
				return err;

			rdir->head = 0;
			rdir->tail = err;
		}
		while (rdir->head < rdir->tail) {
			p9stat_init(&st);
			err = p9stat_read(fid->clnt, rdir->buf + rdir->head,
					  rdir->tail - rdir->head, &st);
			if (err) {
				p9_debug(P9_DEBUG_VFS, "returned %d\n", err);
				p9stat_free(&st);
				return -EIO;
			}
			reclen = st.size+2;

			over = !dir_emit(ctx, st.name, strlen(st.name),
					 v9fs_qid2ino(&st.qid), dt_type(&st));
			p9stat_free(&st);
			if (over)
				return 0;

			rdir->head += reclen;
			ctx->pos += reclen;
		}
	}
}

/**
 * v9fs_dir_readdir_dotl - iterate through a directory
 * @file: opened file structure
 * @ctx: actor we feed the entries to
 *
 */
static int v9fs_dir_readdir_dotl(struct file *file, struct dir_context *ctx)
{
	int err = 0;
	struct p9_fid *fid;
	int buflen;
	struct p9_rdir *rdir;
	struct p9_dirent curdirent;

	p9_debug(P9_DEBUG_VFS, "name %pD\n", file);
	fid = file->private_data;

	buflen = fid->clnt->msize - P9_READDIRHDRSZ;

	rdir = v9fs_alloc_rdir_buf(file, buflen);
	if (!rdir)
		return -ENOMEM;

	while (1) {
		if (rdir->tail == rdir->head) {
			err = p9_client_readdir(fid, rdir->buf, buflen,
						ctx->pos);
			if (err <= 0)
				return err;

			rdir->head = 0;
			rdir->tail = err;
		}

		while (rdir->head < rdir->tail) {

			err = p9dirent_read(fid->clnt, rdir->buf + rdir->head,
					    rdir->tail - rdir->head,
					    &curdirent);
			if (err < 0) {
				p9_debug(P9_DEBUG_VFS, "returned %d\n", err);
				return -EIO;
			}

			if (!dir_emit(ctx, curdirent.d_name,
				      strlen(curdirent.d_name),
				      v9fs_qid2ino(&curdirent.qid),
				      curdirent.d_type))
				return 0;

			ctx->pos = curdirent.d_off;
			rdir->head += err;
		}
	}
}


/**
 * v9fs_dir_release - close a directory
 * @inode: inode of the directory
 * @filp: file pointer to a directory
 *
 */

int v9fs_dir_release(struct inode *inode, struct file *filp)
{
	struct p9_fid *fid;

	fid = filp->private_data;
	p9_debug(P9_DEBUG_VFS, "inode: %p filp: %p fid: %d\n",
		 inode, filp, fid ? fid->fid : -1);
	if (fid)
		p9_client_clunk(fid);
	return 0;
}

const struct file_operations v9fs_dir_operations = {
	.read = generic_read_dir,
	.llseek = generic_file_llseek,
	.iterate = v9fs_dir_readdir,
	.open = v9fs_file_open,
	.release = v9fs_dir_release,
};

const struct file_operations v9fs_dir_operations_dotl = {
	.read = generic_read_dir,
	.llseek = generic_file_llseek,
	.iterate = v9fs_dir_readdir_dotl,
	.open = v9fs_file_open,
	.release = v9fs_dir_release,
        .fsync = v9fs_file_fsync_dotl,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/vfs_dir.c */
/************************************************************/
/*
 *  linux/fs/9p/vfs_dentry.c
 *
 * This file contians vfs dentry ops for the 9P2000 protocol.
 *
 *  Copyright (C) 2004 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

// #include <linux/module.h>
// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/file.h>
// #include <linux/pagemap.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <linux/inet.h>
// #include <linux/namei.h>
// #include <linux/idr.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>

// #include "v9fs.h"
// #include "v9fs_vfs.h"
// #include "fid.h"

/**
 * v9fs_cached_dentry_delete - called when dentry refcount equals 0
 * @dentry:  dentry in question
 *
 */
static int v9fs_cached_dentry_delete(const struct dentry *dentry)
{
	p9_debug(P9_DEBUG_VFS, " dentry: %pd (%p)\n",
		 dentry, dentry);

	/* Don't cache negative dentries */
	if (!dentry->d_inode)
		return 1;
	return 0;
}

/**
 * v9fs_dentry_release - called when dentry is going to be freed
 * @dentry:  dentry that is being release
 *
 */

static void v9fs_dentry_release(struct dentry *dentry)
{
	struct hlist_node *p, *n;
	p9_debug(P9_DEBUG_VFS, " dentry: %pd (%p)\n",
		 dentry, dentry);
	hlist_for_each_safe(p, n, (struct hlist_head *)&dentry->d_fsdata)
		p9_client_clunk(hlist_entry(p, struct p9_fid, dlist));
	dentry->d_fsdata = NULL;
}

static int v9fs_lookup_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct p9_fid *fid;
	struct inode *inode;
	struct v9fs_inode *v9inode;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	inode = dentry->d_inode;
	if (!inode)
		goto out_valid;

	v9inode = V9FS_I(inode);
	if (v9inode->cache_validity & V9FS_INO_INVALID_ATTR) {
		int retval;
		struct v9fs_session_info *v9ses;
		fid = v9fs_fid_lookup(dentry);
		if (IS_ERR(fid))
			return PTR_ERR(fid);

		v9ses = v9fs_inode2v9ses(inode);
		if (v9fs_proto_dotl(v9ses))
			retval = v9fs_refresh_inode_dotl(fid, inode);
		else
			retval = v9fs_refresh_inode(fid, inode);
		if (retval == -ENOENT)
			return 0;
		if (retval < 0)
			return retval;
	}
out_valid:
	return 1;
}

const struct dentry_operations v9fs_cached_dentry_operations = {
	.d_revalidate = v9fs_lookup_revalidate,
	.d_weak_revalidate = v9fs_lookup_revalidate,
	.d_delete = v9fs_cached_dentry_delete,
	.d_release = v9fs_dentry_release,
};

const struct dentry_operations v9fs_dentry_operations = {
	.d_delete = always_delete_dentry,
	.d_release = v9fs_dentry_release,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/vfs_dentry.c */
/************************************************************/
/*
 *  linux/fs/9p/v9fs.c
 *
 *  This file contains functions assisting in mapping VFS to 9P2000
 *
 *  Copyright (C) 2004-2008 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 2002 by Ron Minnich <rminnich@lanl.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/module.h>
// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/sched.h>
#include <linux/parser.h>
// #include <linux/idr.h>
// #include <linux/slab.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>
#include <net/9p/transport.h>
// #include "v9fs.h"
// #include "v9fs_vfs.h"
// #include "cache.h"
#include "../../inc/__fss.h"

static DEFINE_SPINLOCK(v9fs_sessionlist_lock);
static LIST_HEAD(v9fs_sessionlist);
struct kmem_cache *v9fs_inode_cache;

/*
 * Option Parsing (code inspired by NFS code)
 *  NOTE: each transport will parse its own options
 */

enum {
	/* Options that take integer arguments */
	Opt_debug, Opt_dfltuid, Opt_dfltgid, Opt_afid,
	/* String options */
	Opt_uname, Opt_remotename, Opt_trans, Opt_cache, Opt_cachetag,
	/* Options that take no arguments */
	Opt_nodevmap,
	/* Cache options */
	Opt_cache_loose, Opt_fscache, Opt_mmap,
	/* Access options */
	Opt_access, Opt_posixacl,
	/* Error token */
	Opt_err
};

static const match_table_t tokens = {
	{Opt_debug, "debug=%x"},
	{Opt_dfltuid, "dfltuid=%u"},
	{Opt_dfltgid, "dfltgid=%u"},
	{Opt_afid, "afid=%u"},
	{Opt_uname, "uname=%s"},
	{Opt_remotename, "aname=%s"},
	{Opt_nodevmap, "nodevmap"},
	{Opt_cache, "cache=%s"},
	{Opt_cache_loose, "loose"},
	{Opt_fscache, "fscache"},
	{Opt_mmap, "mmap"},
	{Opt_cachetag, "cachetag=%s"},
	{Opt_access, "access=%s"},
	{Opt_posixacl, "posixacl"},
	{Opt_err, NULL}
};

/* Interpret mount options for cache mode */
static int get_cache_mode(char *s)
{
	int version = -EINVAL;

	if (!strcmp(s, "loose")) {
		version = CACHE_LOOSE;
		p9_debug(P9_DEBUG_9P, "Cache mode: loose\n");
	} else if (!strcmp(s, "fscache")) {
		version = CACHE_FSCACHE;
		p9_debug(P9_DEBUG_9P, "Cache mode: fscache\n");
	} else if (!strcmp(s, "mmap")) {
		version = CACHE_MMAP;
		p9_debug(P9_DEBUG_9P, "Cache mode: mmap\n");
	} else if (!strcmp(s, "none")) {
		version = CACHE_NONE;
		p9_debug(P9_DEBUG_9P, "Cache mode: none\n");
	} else
		pr_info("Unknown Cache mode %s\n", s);
	return version;
}

/**
 * v9fs_parse_options - parse mount options into session structure
 * @v9ses: existing v9fs session information
 *
 * Return 0 upon success, -ERRNO upon failure.
 */

static int v9fs_parse_options(struct v9fs_session_info *v9ses, char *opts)
{
	char *options, *tmp_options;
	substring_t args[MAX_OPT_ARGS];
	char *p;
	int option = 0;
	char *s, *e;
	int ret = 0;

	/* setup defaults */
	v9ses->afid = ~0;
	v9ses->debug = 0;
	v9ses->cache = CACHE_NONE;
#ifdef CONFIG_9P_FSCACHE
	v9ses->cachetag = NULL;
#endif

	if (!opts)
		return 0;

	tmp_options = kstrdup(opts, GFP_KERNEL);
	if (!tmp_options) {
		ret = -ENOMEM;
		goto fail_option_alloc;
	}
	options = tmp_options;

	while ((p = strsep(&options, ",")) != NULL) {
		int token, r;
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_debug:
			r = match_int(&args[0], &option);
			if (r < 0) {
				p9_debug(P9_DEBUG_ERROR,
					 "integer field, but no integer?\n");
				ret = r;
				continue;
			}
			v9ses->debug = option;
#ifdef CONFIG_NET_9P_DEBUG
			p9_debug_level = option;
#endif
			break;

		case Opt_dfltuid:
			r = match_int(&args[0], &option);
			if (r < 0) {
				p9_debug(P9_DEBUG_ERROR,
					 "integer field, but no integer?\n");
				ret = r;
				continue;
			}
			v9ses->dfltuid = make_kuid(current_user_ns(), option);
			if (!uid_valid(v9ses->dfltuid)) {
				p9_debug(P9_DEBUG_ERROR,
					 "uid field, but not a uid?\n");
				ret = -EINVAL;
				continue;
			}
			break;
		case Opt_dfltgid:
			r = match_int(&args[0], &option);
			if (r < 0) {
				p9_debug(P9_DEBUG_ERROR,
					 "integer field, but no integer?\n");
				ret = r;
				continue;
			}
			v9ses->dfltgid = make_kgid(current_user_ns(), option);
			if (!gid_valid(v9ses->dfltgid)) {
				p9_debug(P9_DEBUG_ERROR,
					 "gid field, but not a gid?\n");
				ret = -EINVAL;
				continue;
			}
			break;
		case Opt_afid:
			r = match_int(&args[0], &option);
			if (r < 0) {
				p9_debug(P9_DEBUG_ERROR,
					 "integer field, but no integer?\n");
				ret = r;
				continue;
			}
			v9ses->afid = option;
			break;
		case Opt_uname:
			kfree(v9ses->uname);
			v9ses->uname = match_strdup(&args[0]);
			if (!v9ses->uname) {
				ret = -ENOMEM;
				goto free_and_return;
			}
			break;
		case Opt_remotename:
			kfree(v9ses->aname);
			v9ses->aname = match_strdup(&args[0]);
			if (!v9ses->aname) {
				ret = -ENOMEM;
				goto free_and_return;
			}
			break;
		case Opt_nodevmap:
			v9ses->nodev = 1;
			break;
		case Opt_cache_loose:
			v9ses->cache = CACHE_LOOSE;
			break;
		case Opt_fscache:
			v9ses->cache = CACHE_FSCACHE;
			break;
		case Opt_mmap:
			v9ses->cache = CACHE_MMAP;
			break;
		case Opt_cachetag:
#ifdef CONFIG_9P_FSCACHE
			v9ses->cachetag = match_strdup(&args[0]);
#endif
			break;
		case Opt_cache:
			s = match_strdup(&args[0]);
			if (!s) {
				ret = -ENOMEM;
				p9_debug(P9_DEBUG_ERROR,
					 "problem allocating copy of cache arg\n");
				goto free_and_return;
			}
			ret = get_cache_mode(s);
			if (ret == -EINVAL) {
				kfree(s);
				goto free_and_return;
			}

			v9ses->cache = ret;
			kfree(s);
			break;

		case Opt_access:
			s = match_strdup(&args[0]);
			if (!s) {
				ret = -ENOMEM;
				p9_debug(P9_DEBUG_ERROR,
					 "problem allocating copy of access arg\n");
				goto free_and_return;
			}

			v9ses->flags &= ~V9FS_ACCESS_MASK;
			if (strcmp(s, "user") == 0)
				v9ses->flags |= V9FS_ACCESS_USER;
			else if (strcmp(s, "any") == 0)
				v9ses->flags |= V9FS_ACCESS_ANY;
			else if (strcmp(s, "client") == 0) {
				v9ses->flags |= V9FS_ACCESS_CLIENT;
			} else {
				uid_t uid;
				v9ses->flags |= V9FS_ACCESS_SINGLE;
				uid = simple_strtoul(s, &e, 10);
				if (*e != '\0') {
					ret = -EINVAL;
					pr_info("Unknown access argument %s\n",
						s);
					kfree(s);
					goto free_and_return;
				}
				v9ses->uid = make_kuid(current_user_ns(), uid);
				if (!uid_valid(v9ses->uid)) {
					ret = -EINVAL;
					pr_info("Uknown uid %s\n", s);
					kfree(s);
					goto free_and_return;
				}
			}

			kfree(s);
			break;

		case Opt_posixacl:
#ifdef CONFIG_9P_FS_POSIX_ACL
			v9ses->flags |= V9FS_POSIX_ACL;
#else
			p9_debug(P9_DEBUG_ERROR,
				 "Not defined CONFIG_9P_FS_POSIX_ACL. Ignoring posixacl option\n");
#endif
			break;

		default:
			continue;
		}
	}

free_and_return:
	kfree(tmp_options);
fail_option_alloc:
	return ret;
}

/**
 * v9fs_session_init - initialize session
 * @v9ses: session information structure
 * @dev_name: device being mounted
 * @data: options
 *
 */

struct p9_fid *v9fs_session_init(struct v9fs_session_info *v9ses,
		  const char *dev_name, char *data)
{
	int retval = -EINVAL;
	struct p9_fid *fid;
	int rc;

	v9ses->uname = kstrdup(V9FS_DEFUSER, GFP_KERNEL);
	if (!v9ses->uname)
		return ERR_PTR(-ENOMEM);

	v9ses->aname = kstrdup(V9FS_DEFANAME, GFP_KERNEL);
	if (!v9ses->aname) {
		kfree(v9ses->uname);
		return ERR_PTR(-ENOMEM);
	}
	init_rwsem(&v9ses->rename_sem);

	rc = bdi_setup_and_register(&v9ses->bdi, "9p");
	if (rc) {
		kfree(v9ses->aname);
		kfree(v9ses->uname);
		return ERR_PTR(rc);
	}

	spin_lock(&v9fs_sessionlist_lock);
	list_add(&v9ses->slist, &v9fs_sessionlist);
	spin_unlock(&v9fs_sessionlist_lock);

	v9ses->uid = INVALID_UID;
	v9ses->dfltuid = V9FS_DEFUID;
	v9ses->dfltgid = V9FS_DEFGID;

	v9ses->clnt = p9_client_create(dev_name, data);
	if (IS_ERR(v9ses->clnt)) {
		retval = PTR_ERR(v9ses->clnt);
		v9ses->clnt = NULL;
		p9_debug(P9_DEBUG_ERROR, "problem initializing 9p client\n");
		goto error;
	}

	v9ses->flags = V9FS_ACCESS_USER;

	if (p9_is_proto_dotl(v9ses->clnt)) {
		v9ses->flags = V9FS_ACCESS_CLIENT;
		v9ses->flags |= V9FS_PROTO_2000L;
	} else if (p9_is_proto_dotu(v9ses->clnt)) {
		v9ses->flags |= V9FS_PROTO_2000U;
	}

	rc = v9fs_parse_options(v9ses, data);
	if (rc < 0) {
		retval = rc;
		goto error;
	}

	v9ses->maxdata = v9ses->clnt->msize - P9_IOHDRSZ;

	if (!v9fs_proto_dotl(v9ses) &&
	    ((v9ses->flags & V9FS_ACCESS_MASK) == V9FS_ACCESS_CLIENT)) {
		/*
		 * We support ACCESS_CLIENT only for dotl.
		 * Fall back to ACCESS_USER
		 */
		v9ses->flags &= ~V9FS_ACCESS_MASK;
		v9ses->flags |= V9FS_ACCESS_USER;
	}
	/*FIXME !! */
	/* for legacy mode, fall back to V9FS_ACCESS_ANY */
	if (!(v9fs_proto_dotu(v9ses) || v9fs_proto_dotl(v9ses)) &&
		((v9ses->flags&V9FS_ACCESS_MASK) == V9FS_ACCESS_USER)) {

		v9ses->flags &= ~V9FS_ACCESS_MASK;
		v9ses->flags |= V9FS_ACCESS_ANY;
		v9ses->uid = INVALID_UID;
	}
	if (!v9fs_proto_dotl(v9ses) ||
		!((v9ses->flags & V9FS_ACCESS_MASK) == V9FS_ACCESS_CLIENT)) {
		/*
		 * We support ACL checks on clinet only if the protocol is
		 * 9P2000.L and access is V9FS_ACCESS_CLIENT.
		 */
		v9ses->flags &= ~V9FS_ACL_MASK;
	}

	fid = p9_client_attach(v9ses->clnt, NULL, v9ses->uname, INVALID_UID,
							v9ses->aname);
	if (IS_ERR(fid)) {
		retval = PTR_ERR(fid);
		fid = NULL;
		p9_debug(P9_DEBUG_ERROR, "cannot attach\n");
		goto error;
	}

	if ((v9ses->flags & V9FS_ACCESS_MASK) == V9FS_ACCESS_SINGLE)
		fid->uid = v9ses->uid;
	else
		fid->uid = INVALID_UID;

#ifdef CONFIG_9P_FSCACHE
	/* register the session for caching */
	v9fs_cache_session_get_cookie(v9ses);
#endif

	return fid;

error:
	bdi_destroy(&v9ses->bdi);
	return ERR_PTR(retval);
}

/**
 * v9fs_session_close - shutdown a session
 * @v9ses: session information structure
 *
 */

void v9fs_session_close(struct v9fs_session_info *v9ses)
{
	if (v9ses->clnt) {
		p9_client_destroy(v9ses->clnt);
		v9ses->clnt = NULL;
	}

#ifdef CONFIG_9P_FSCACHE
	if (v9ses->fscache) {
		v9fs_cache_session_put_cookie(v9ses);
		kfree(v9ses->cachetag);
	}
#endif
	kfree(v9ses->uname);
	kfree(v9ses->aname);

	bdi_destroy(&v9ses->bdi);

	spin_lock(&v9fs_sessionlist_lock);
	list_del(&v9ses->slist);
	spin_unlock(&v9fs_sessionlist_lock);
}

/**
 * v9fs_session_cancel - terminate a session
 * @v9ses: session to terminate
 *
 * mark transport as disconnected and cancel all pending requests.
 */

void v9fs_session_cancel(struct v9fs_session_info *v9ses) {
	p9_debug(P9_DEBUG_ERROR, "cancel session %p\n", v9ses);
	p9_client_disconnect(v9ses->clnt);
}

/**
 * v9fs_session_begin_cancel - Begin terminate of a session
 * @v9ses: session to terminate
 *
 * After this call we don't allow any request other than clunk.
 */

void v9fs_session_begin_cancel(struct v9fs_session_info *v9ses)
{
	p9_debug(P9_DEBUG_ERROR, "begin cancel session %p\n", v9ses);
	p9_client_begin_disconnect(v9ses->clnt);
}

extern int v9fs_error_init(void);

static struct kobject *v9fs_kobj;

#ifdef CONFIG_9P_FSCACHE
/**
 * caches_show - list caches associated with a session
 *
 * Returns the size of buffer written.
 */

static ssize_t caches_show(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   char *buf)
{
	ssize_t n = 0, count = 0, limit = PAGE_SIZE;
	struct v9fs_session_info *v9ses;

	spin_lock(&v9fs_sessionlist_lock);
	list_for_each_entry(v9ses, &v9fs_sessionlist, slist) {
		if (v9ses->cachetag) {
			n = snprintf(buf, limit, "%s\n", v9ses->cachetag);
			if (n < 0) {
				count = n;
				break;
			}

			count += n;
			limit -= n;
		}
	}

	spin_unlock(&v9fs_sessionlist_lock);
	return count;
}

static struct kobj_attribute v9fs_attr_cache = __ATTR_RO(caches);
#endif /* CONFIG_9P_FSCACHE */

static struct attribute *v9fs_attrs[] = {
#ifdef CONFIG_9P_FSCACHE
	&v9fs_attr_cache.attr,
#endif
	NULL,
};

static struct attribute_group v9fs_attr_group = {
	.attrs = v9fs_attrs,
};

/**
 * v9fs_sysfs_init - Initialize the v9fs sysfs interface
 *
 */

static int __init v9fs_sysfs_init(void)
{
	v9fs_kobj = kobject_create_and_add("9p", fs_kobj);
	if (!v9fs_kobj)
		return -ENOMEM;

	if (sysfs_create_group(v9fs_kobj, &v9fs_attr_group)) {
		kobject_put(v9fs_kobj);
		return -ENOMEM;
	}

	return 0;
}

/**
 * v9fs_sysfs_cleanup - Unregister the v9fs sysfs interface
 *
 */

static void v9fs_sysfs_cleanup(void)
{
	sysfs_remove_group(v9fs_kobj, &v9fs_attr_group);
	kobject_put(v9fs_kobj);
}

static void v9fs_inode_init_once(void *foo)
{
	struct v9fs_inode *v9inode = (struct v9fs_inode *)foo;
#ifdef CONFIG_9P_FSCACHE
	v9inode->fscache = NULL;
#endif
	memset(&v9inode->qid, 0, sizeof(v9inode->qid));
	inode_init_once(&v9inode->vfs_inode);
}

/**
 * v9fs_init_inode_cache - initialize a cache for 9P
 * Returns 0 on success.
 */
static int v9fs_init_inode_cache(void)
{
	v9fs_inode_cache = kmem_cache_create("v9fs_inode_cache",
					  sizeof(struct v9fs_inode),
					  0, (SLAB_RECLAIM_ACCOUNT|
					      SLAB_MEM_SPREAD),
					  v9fs_inode_init_once);
	if (!v9fs_inode_cache)
		return -ENOMEM;

	return 0;
}

/**
 * v9fs_destroy_inode_cache - destroy the cache of 9P inode
 *
 */
static void v9fs_destroy_inode_cache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(v9fs_inode_cache);
}

static int v9fs_cache_register(void)
{
	int ret;
	ret = v9fs_init_inode_cache();
	if (ret < 0)
		return ret;
#ifdef CONFIG_9P_FSCACHE
	ret = fscache_register_netfs(&v9fs_cache_netfs);
	if (ret < 0)
		v9fs_destroy_inode_cache();
#endif
	return ret;
}

static void v9fs_cache_unregister(void)
{
	v9fs_destroy_inode_cache();
#ifdef CONFIG_9P_FSCACHE
	fscache_unregister_netfs(&v9fs_cache_netfs);
#endif
}

/**
 * init_v9fs - Initialize module
 *
 */

static int __init init_v9fs(void)
{
	int err;
	pr_info("Installing v9fs 9p2000 file system support\n");
	/* TODO: Setup list of registered trasnport modules */

	err = v9fs_cache_register();
	if (err < 0) {
		pr_err("Failed to register v9fs for caching\n");
		return err;
	}

	err = v9fs_sysfs_init();
	if (err < 0) {
		pr_err("Failed to register with sysfs\n");
		goto out_cache;
	}
	err = register_filesystem(&v9fs_fs_type);
	if (err < 0) {
		pr_err("Failed to register filesystem\n");
		goto out_sysfs_cleanup;
	}

	return 0;

out_sysfs_cleanup:
	v9fs_sysfs_cleanup();

out_cache:
	v9fs_cache_unregister();

	return err;
}

/**
 * exit_v9fs - shutdown module
 *
 */

static void __exit exit_v9fs(void)
{
	v9fs_sysfs_cleanup();
	v9fs_cache_unregister();
	unregister_filesystem(&v9fs_fs_type);
}

module_init(init_v9fs)
module_exit(exit_v9fs)

MODULE_AUTHOR("Latchesar Ionkov <lucho@ionkov.net>");
MODULE_AUTHOR("Eric Van Hensbergen <ericvh@gmail.com>");
MODULE_AUTHOR("Ron Minnich <rminnich@lanl.gov>");
MODULE_LICENSE("GPL");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/v9fs.c */
/************************************************************/
/*
 * V9FS FID Management
 *
 *  Copyright (C) 2007 by Latchesar Ionkov <lucho@ionkov.net>
 *  Copyright (C) 2005, 2006 by Eric Van Hensbergen <ericvh@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

// #include <linux/module.h>
// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/slab.h>
// #include <linux/sched.h>
// #include <linux/idr.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>

// #include "v9fs.h"
// #include "v9fs_vfs.h"
// #include "fid.h"

/**
 * v9fs_fid_add - add a fid to a dentry
 * @dentry: dentry that the fid is being added to
 * @fid: fid to add
 *
 */

static inline void __add_fid(struct dentry *dentry, struct p9_fid *fid)
{
	hlist_add_head(&fid->dlist, (struct hlist_head *)&dentry->d_fsdata);
}

void v9fs_fid_add(struct dentry *dentry, struct p9_fid *fid)
{
	spin_lock(&dentry->d_lock);
	__add_fid(dentry, fid);
	spin_unlock(&dentry->d_lock);
}

/**
 * v9fs_fid_find - retrieve a fid that belongs to the specified uid
 * @dentry: dentry to look for fid in
 * @uid: return fid that belongs to the specified user
 * @any: if non-zero, return any fid associated with the dentry
 *
 */

static struct p9_fid *v9fs_fid_find(struct dentry *dentry, kuid_t uid, int any)
{
	struct p9_fid *fid, *ret;

	p9_debug(P9_DEBUG_VFS, " dentry: %pd (%p) uid %d any %d\n",
		 dentry, dentry, from_kuid(&init_user_ns, uid),
		 any);
	ret = NULL;
	/* we'll recheck under lock if there's anything to look in */
	if (dentry->d_fsdata) {
		struct hlist_head *h = (struct hlist_head *)&dentry->d_fsdata;
		spin_lock(&dentry->d_lock);
		hlist_for_each_entry(fid, h, dlist) {
			if (any || uid_eq(fid->uid, uid)) {
				ret = fid;
				break;
			}
		}
		spin_unlock(&dentry->d_lock);
	}

	return ret;
}

/*
 * We need to hold v9ses->rename_sem as long as we hold references
 * to returned path array. Array element contain pointers to
 * dentry names.
 */
static int build_path_from_dentry(struct v9fs_session_info *v9ses,
				  struct dentry *dentry, char ***names)
{
	int n = 0, i;
	char **wnames;
	struct dentry *ds;

	for (ds = dentry; !IS_ROOT(ds); ds = ds->d_parent)
		n++;

	wnames = kmalloc(sizeof(char *) * n, GFP_KERNEL);
	if (!wnames)
		goto err_out;

	for (ds = dentry, i = (n-1); i >= 0; i--, ds = ds->d_parent)
		wnames[i] = (char  *)ds->d_name.name;

	*names = wnames;
	return n;
err_out:
	return -ENOMEM;
}

static struct p9_fid *v9fs_fid_lookup_with_uid(struct dentry *dentry,
					       kuid_t uid, int any)
{
	struct dentry *ds;
	char **wnames, *uname;
	int i, n, l, clone, access;
	struct v9fs_session_info *v9ses;
	struct p9_fid *fid, *old_fid = NULL;

	v9ses = v9fs_dentry2v9ses(dentry);
	access = v9ses->flags & V9FS_ACCESS_MASK;
	fid = v9fs_fid_find(dentry, uid, any);
	if (fid)
		return fid;
	/*
	 * we don't have a matching fid. To do a TWALK we need
	 * parent fid. We need to prevent rename when we want to
	 * look at the parent.
	 */
	down_read(&v9ses->rename_sem);
	ds = dentry->d_parent;
	fid = v9fs_fid_find(ds, uid, any);
	if (fid) {
		/* Found the parent fid do a lookup with that */
		fid = p9_client_walk(fid, 1, (char **)&dentry->d_name.name, 1);
		goto fid_out;
	}
	up_read(&v9ses->rename_sem);

	/* start from the root and try to do a lookup */
	fid = v9fs_fid_find(dentry->d_sb->s_root, uid, any);
	if (!fid) {
		/* the user is not attached to the fs yet */
		if (access == V9FS_ACCESS_SINGLE)
			return ERR_PTR(-EPERM);

		if (v9fs_proto_dotu(v9ses) || v9fs_proto_dotl(v9ses))
				uname = NULL;
		else
			uname = v9ses->uname;

		fid = p9_client_attach(v9ses->clnt, NULL, uname, uid,
				       v9ses->aname);
		if (IS_ERR(fid))
			return fid;

		v9fs_fid_add(dentry->d_sb->s_root, fid);
	}
	/* If we are root ourself just return that */
	if (dentry->d_sb->s_root == dentry)
		return fid;
	/*
	 * Do a multipath walk with attached root.
	 * When walking parent we need to make sure we
	 * don't have a parallel rename happening
	 */
	down_read(&v9ses->rename_sem);
	n  = build_path_from_dentry(v9ses, dentry, &wnames);
	if (n < 0) {
		fid = ERR_PTR(n);
		goto err_out;
	}
	clone = 1;
	i = 0;
	while (i < n) {
		l = min(n - i, P9_MAXWELEM);
		/*
		 * We need to hold rename lock when doing a multipath
		 * walk to ensure none of the patch component change
		 */
		fid = p9_client_walk(fid, l, &wnames[i], clone);
		if (IS_ERR(fid)) {
			if (old_fid) {
				/*
				 * If we fail, clunk fid which are mapping
				 * to path component and not the last component
				 * of the path.
				 */
				p9_client_clunk(old_fid);
			}
			kfree(wnames);
			goto err_out;
		}
		old_fid = fid;
		i += l;
		clone = 0;
	}
	kfree(wnames);
fid_out:
	if (!IS_ERR(fid)) {
		spin_lock(&dentry->d_lock);
		if (d_unhashed(dentry)) {
			spin_unlock(&dentry->d_lock);
			p9_client_clunk(fid);
			fid = ERR_PTR(-ENOENT);
		} else {
			__add_fid(dentry, fid);
			spin_unlock(&dentry->d_lock);
		}
	}
err_out:
	up_read(&v9ses->rename_sem);
	return fid;
}

/**
 * v9fs_fid_lookup - lookup for a fid, try to walk if not found
 * @dentry: dentry to look for fid in
 *
 * Look for a fid in the specified dentry for the current user.
 * If no fid is found, try to create one walking from a fid from the parent
 * dentry (if it has one), or the root dentry. If the user haven't accessed
 * the fs yet, attach now and walk from the root.
 */

struct p9_fid *v9fs_fid_lookup(struct dentry *dentry)
{
	kuid_t uid;
	int  any, access;
	struct v9fs_session_info *v9ses;

	v9ses = v9fs_dentry2v9ses(dentry);
	access = v9ses->flags & V9FS_ACCESS_MASK;
	switch (access) {
	case V9FS_ACCESS_SINGLE:
	case V9FS_ACCESS_USER:
	case V9FS_ACCESS_CLIENT:
		uid = current_fsuid();
		any = 0;
		break;

	case V9FS_ACCESS_ANY:
		uid = v9ses->uid;
		any = 1;
		break;

	default:
		uid = INVALID_UID;
		any = 0;
		break;
	}
	return v9fs_fid_lookup_with_uid(dentry, uid, any);
}

struct p9_fid *v9fs_fid_clone(struct dentry *dentry)
{
	struct p9_fid *fid, *ret;

	fid = v9fs_fid_lookup(dentry);
	if (IS_ERR(fid))
		return fid;

	ret = p9_client_walk(fid, 0, NULL, 1);
	return ret;
}

static struct p9_fid *v9fs_fid_clone_with_uid(struct dentry *dentry, kuid_t uid)
{
	struct p9_fid *fid, *ret;

	fid = v9fs_fid_lookup_with_uid(dentry, uid, 0);
	if (IS_ERR(fid))
		return fid;

	ret = p9_client_walk(fid, 0, NULL, 1);
	return ret;
}

struct p9_fid *v9fs_writeback_fid(struct dentry *dentry)
{
	int err;
	struct p9_fid *fid;

	fid = v9fs_fid_clone_with_uid(dentry, GLOBAL_ROOT_UID);
	if (IS_ERR(fid))
		goto error_out;
	/*
	 * writeback fid will only be used to write back the
	 * dirty pages. We always request for the open fid in read-write
	 * mode so that a partial page write which result in page
	 * read can work.
	 */
	err = p9_client_open(fid, O_RDWR);
	if (err < 0) {
		p9_client_clunk(fid);
		fid = ERR_PTR(err);
		goto error_out;
	}
error_out:
	return fid;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/fid.c */
/************************************************************/
/*
 * Copyright IBM Corporation, 2010
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

// #include <linux/module.h>
// #include <linux/fs.h>
// #include <linux/sched.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>

// #include "fid.h"
// #include "xattr.h"

ssize_t v9fs_fid_xattr_get(struct p9_fid *fid, const char *name,
			   void *buffer, size_t buffer_size)
{
	ssize_t retval;
	int msize, read_count;
	u64 offset = 0, attr_size;
	struct p9_fid *attr_fid;

	attr_fid = p9_client_xattrwalk(fid, name, &attr_size);
	if (IS_ERR(attr_fid)) {
		retval = PTR_ERR(attr_fid);
		p9_debug(P9_DEBUG_VFS, "p9_client_attrwalk failed %zd\n",
			 retval);
		attr_fid = NULL;
		goto error;
	}
	if (!buffer_size) {
		/* request to get the attr_size */
		retval = attr_size;
		goto error;
	}
	if (attr_size > buffer_size) {
		retval = -ERANGE;
		goto error;
	}
	msize = attr_fid->clnt->msize;
	while (attr_size) {
		if (attr_size > (msize - P9_IOHDRSZ))
			read_count = msize - P9_IOHDRSZ;
		else
			read_count = attr_size;
		read_count = p9_client_read(attr_fid, ((char *)buffer)+offset,
					NULL, offset, read_count);
		if (read_count < 0) {
			/* error in xattr read */
			retval = read_count;
			goto error;
		}
		offset += read_count;
		attr_size -= read_count;
	}
	/* Total read xattr bytes */
	retval = offset;
error:
	if (attr_fid)
		p9_client_clunk(attr_fid);
	return retval;

}


/*
 * v9fs_xattr_get()
 *
 * Copy an extended attribute into the buffer
 * provided, or compute the buffer size required.
 * Buffer is NULL to compute the size of the buffer required.
 *
 * Returns a negative error number on failure, or the number of bytes
 * used / required on success.
 */
ssize_t v9fs_xattr_get(struct dentry *dentry, const char *name,
		       void *buffer, size_t buffer_size)
{
	struct p9_fid *fid;

	p9_debug(P9_DEBUG_VFS, "name = %s value_len = %zu\n",
		 name, buffer_size);
	fid = v9fs_fid_lookup(dentry);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	return v9fs_fid_xattr_get(fid, name, buffer, buffer_size);
}

/*
 * v9fs_xattr_set()
 *
 * Create, replace or remove an extended attribute for this inode. Buffer
 * is NULL to remove an existing extended attribute, and non-NULL to
 * either replace an existing extended attribute, or create a new extended
 * attribute. The flags XATTR_REPLACE and XATTR_CREATE
 * specify that an extended attribute must exist and must not exist
 * previous to the call, respectively.
 *
 * Returns 0, or a negative error number on failure.
 */
int v9fs_xattr_set(struct dentry *dentry, const char *name,
		   const void *value, size_t value_len, int flags)
{
	struct p9_fid *fid = v9fs_fid_lookup(dentry);
	if (IS_ERR(fid))
		return PTR_ERR(fid);
	return v9fs_fid_xattr_set(fid, name, value, value_len, flags);
}

int v9fs_fid_xattr_set(struct p9_fid *fid, const char *name,
		   const void *value, size_t value_len, int flags)
{
	u64 offset = 0;
	int retval, msize, write_count;

	p9_debug(P9_DEBUG_VFS, "name = %s value_len = %zu flags = %d\n",
		 name, value_len, flags);

	/* Clone it */
	fid = p9_client_walk(fid, 0, NULL, 1);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	/*
	 * On success fid points to xattr
	 */
	retval = p9_client_xattrcreate(fid, name, value_len, flags);
	if (retval < 0) {
		p9_debug(P9_DEBUG_VFS, "p9_client_xattrcreate failed %d\n",
			 retval);
		goto err;
	}
	msize = fid->clnt->msize;
	while (value_len) {
		if (value_len > (msize - P9_IOHDRSZ))
			write_count = msize - P9_IOHDRSZ;
		else
			write_count = value_len;
		write_count = p9_client_write(fid, ((char *)value)+offset,
					NULL, offset, write_count);
		if (write_count < 0) {
			/* error in xattr write */
			retval = write_count;
			goto err;
		}
		offset += write_count;
		value_len -= write_count;
	}
	retval = 0;
err:
	p9_client_clunk(fid);
	return retval;
}

ssize_t v9fs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	return v9fs_xattr_get(dentry, NULL, buffer, buffer_size);
}

const struct xattr_handler *v9fs_xattr_handlers[] = {
	&v9fs_xattr_user_handler,
	&v9fs_xattr_trusted_handler,
#ifdef CONFIG_9P_FS_POSIX_ACL
	&v9fs_xattr_acl_access_handler,
	&v9fs_xattr_acl_default_handler,
#endif
#ifdef CONFIG_9P_FS_SECURITY
	&v9fs_xattr_security_handler,
#endif
	NULL
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/xattr.c */
/************************************************************/
/*
 * Copyright IBM Corporation, 2010
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */


// #include <linux/module.h>
// #include <linux/string.h>
// #include <linux/fs.h>
// #include <linux/slab.h>
// #include "xattr.h"

static int v9fs_xattr_user_get(struct dentry *dentry, const char *name,
			void *buffer, size_t size, int type)
{
	int retval;
	char *full_name;
	size_t name_len;
	size_t prefix_len = XATTR_USER_PREFIX_LEN;

	if (name == NULL)
		return -EINVAL;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	name_len = strlen(name);
	full_name = kmalloc(prefix_len + name_len + 1 , GFP_KERNEL);
	if (!full_name)
		return -ENOMEM;
	memcpy(full_name, XATTR_USER_PREFIX, prefix_len);
	memcpy(full_name+prefix_len, name, name_len);
	full_name[prefix_len + name_len] = '\0';

	retval = v9fs_xattr_get(dentry, full_name, buffer, size);
	kfree(full_name);
	return retval;
}

static int v9fs_xattr_user_set(struct dentry *dentry, const char *name,
			const void *value, size_t size, int flags, int type)
{
	int retval;
	char *full_name;
	size_t name_len;
	size_t prefix_len = XATTR_USER_PREFIX_LEN;

	if (name == NULL)
		return -EINVAL;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	name_len = strlen(name);
	full_name = kmalloc(prefix_len + name_len + 1 , GFP_KERNEL);
	if (!full_name)
		return -ENOMEM;
	memcpy(full_name, XATTR_USER_PREFIX, prefix_len);
	memcpy(full_name + prefix_len, name, name_len);
	full_name[prefix_len + name_len] = '\0';

	retval = v9fs_xattr_set(dentry, full_name, value, size, flags);
	kfree(full_name);
	return retval;
}

struct xattr_handler v9fs_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.get	= v9fs_xattr_user_get,
	.set	= v9fs_xattr_user_set,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/xattr_user.c */
/************************************************************/
/*
 * Copyright IBM Corporation, 2010
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */


// #include <linux/module.h>
// #include <linux/string.h>
// #include <linux/fs.h>
// #include <linux/slab.h>
// #include "xattr.h"

static int v9fs_xattr_trusted_get(struct dentry *dentry, const char *name,
			void *buffer, size_t size, int type)
{
	int retval;
	char *full_name;
	size_t name_len;
	size_t prefix_len = XATTR_TRUSTED_PREFIX_LEN;

	if (name == NULL)
		return -EINVAL;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	name_len = strlen(name);
	full_name = kmalloc(prefix_len + name_len + 1 , GFP_KERNEL);
	if (!full_name)
		return -ENOMEM;
	memcpy(full_name, XATTR_TRUSTED_PREFIX, prefix_len);
	memcpy(full_name+prefix_len, name, name_len);
	full_name[prefix_len + name_len] = '\0';

	retval = v9fs_xattr_get(dentry, full_name, buffer, size);
	kfree(full_name);
	return retval;
}

static int v9fs_xattr_trusted_set(struct dentry *dentry, const char *name,
			const void *value, size_t size, int flags, int type)
{
	int retval;
	char *full_name;
	size_t name_len;
	size_t prefix_len = XATTR_TRUSTED_PREFIX_LEN;

	if (name == NULL)
		return -EINVAL;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	name_len = strlen(name);
	full_name = kmalloc(prefix_len + name_len + 1 , GFP_KERNEL);
	if (!full_name)
		return -ENOMEM;
	memcpy(full_name, XATTR_TRUSTED_PREFIX, prefix_len);
	memcpy(full_name + prefix_len, name, name_len);
	full_name[prefix_len + name_len] = '\0';

	retval = v9fs_xattr_set(dentry, full_name, value, size, flags);
	kfree(full_name);
	return retval;
}

struct xattr_handler v9fs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.get	= v9fs_xattr_trusted_get,
	.set	= v9fs_xattr_trusted_set,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/xattr_trusted.c */
/************************************************************/
/*
 * Copyright IBM Corporation, 2010
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

// #include <linux/module.h>
// #include <linux/fs.h>
// #include <net/9p/9p.h>
// #include <net/9p/client.h>
// #include <linux/slab.h>
// #include <linux/sched.h>
#include <linux/posix_acl_xattr.h>
// #include "xattr.h"
// #include "acl.h"
// #include "v9fs.h"
// #include "v9fs_vfs.h"
// #include "fid.h"
#include "../../inc/__fss.h"

static struct posix_acl *__v9fs_get_acl(struct p9_fid *fid, char *name)
{
	ssize_t size;
	void *value = NULL;
	struct posix_acl *acl = NULL;

	size = v9fs_fid_xattr_get(fid, name, NULL, 0);
	if (size > 0) {
		value = kzalloc(size, GFP_NOFS);
		if (!value)
			return ERR_PTR(-ENOMEM);
		size = v9fs_fid_xattr_get(fid, name, value, size);
		if (size > 0) {
			acl = posix_acl_from_xattr(&init_user_ns, value, size);
			if (IS_ERR(acl))
				goto err_out;
		}
	} else if (size == -ENODATA || size == 0 ||
		   size == -ENOSYS || size == -EOPNOTSUPP) {
		acl = NULL;
	} else
		acl = ERR_PTR(-EIO);

err_out:
	kfree(value);
	return acl;
}

int v9fs_get_acl(struct inode *inode, struct p9_fid *fid)
{
	int retval = 0;
	struct posix_acl *pacl, *dacl;
	struct v9fs_session_info *v9ses;

	v9ses = v9fs_inode2v9ses(inode);
	if (((v9ses->flags & V9FS_ACCESS_MASK) != V9FS_ACCESS_CLIENT) ||
			((v9ses->flags & V9FS_ACL_MASK) != V9FS_POSIX_ACL)) {
		set_cached_acl(inode, ACL_TYPE_DEFAULT, NULL);
		set_cached_acl(inode, ACL_TYPE_ACCESS, NULL);
		return 0;
	}
	/* get the default/access acl values and cache them */
	dacl = __v9fs_get_acl(fid, POSIX_ACL_XATTR_DEFAULT);
	pacl = __v9fs_get_acl(fid, POSIX_ACL_XATTR_ACCESS);

	if (!IS_ERR(dacl) && !IS_ERR(pacl)) {
		set_cached_acl(inode, ACL_TYPE_DEFAULT, dacl);
		set_cached_acl(inode, ACL_TYPE_ACCESS, pacl);
	} else
		retval = -EIO;

	if (!IS_ERR(dacl))
		posix_acl_release(dacl);

	if (!IS_ERR(pacl))
		posix_acl_release(pacl);

	return retval;
}

static struct posix_acl *v9fs_get_cached_acl(struct inode *inode, int type)
{
	struct posix_acl *acl;
	/*
	 * 9p Always cache the acl value when
	 * instantiating the inode (v9fs_inode_from_fid)
	 */
	acl = get_cached_acl(inode, type);
	BUG_ON(acl == ACL_NOT_CACHED);
	return acl;
}

struct posix_acl *v9fs_iop_get_acl(struct inode *inode, int type)
{
	struct v9fs_session_info *v9ses;

	v9ses = v9fs_inode2v9ses(inode);
	if (((v9ses->flags & V9FS_ACCESS_MASK) != V9FS_ACCESS_CLIENT) ||
			((v9ses->flags & V9FS_ACL_MASK) != V9FS_POSIX_ACL)) {
		/*
		 * On access = client  and acl = on mode get the acl
		 * values from the server
		 */
		return NULL;
	}
	return v9fs_get_cached_acl(inode, type);

}

static int v9fs_set_acl(struct p9_fid *fid, int type, struct posix_acl *acl)
{
	int retval;
	char *name;
	size_t size;
	void *buffer;
	if (!acl)
		return 0;

	/* Set a setxattr request to server */
	size = posix_acl_xattr_size(acl->a_count);
	buffer = kmalloc(size, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	retval = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
	if (retval < 0)
		goto err_free_out;
	switch (type) {
	case ACL_TYPE_ACCESS:
		name = POSIX_ACL_XATTR_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name = POSIX_ACL_XATTR_DEFAULT;
		break;
	default:
		BUG();
	}
	retval = v9fs_fid_xattr_set(fid, name, buffer, size, 0);
err_free_out:
	kfree(buffer);
	return retval;
}

int v9fs_acl_chmod(struct inode *inode, struct p9_fid *fid)
{
	int retval = 0;
	struct posix_acl *acl;

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
	acl = v9fs_get_cached_acl(inode, ACL_TYPE_ACCESS);
	if (acl) {
		retval = __posix_acl_chmod(&acl, GFP_KERNEL, inode->i_mode);
		if (retval)
			return retval;
		set_cached_acl(inode, ACL_TYPE_ACCESS, acl);
		retval = v9fs_set_acl(fid, ACL_TYPE_ACCESS, acl);
		posix_acl_release(acl);
	}
	return retval;
}

int v9fs_set_create_acl(struct inode *inode, struct p9_fid *fid,
			struct posix_acl *dacl, struct posix_acl *acl)
{
	set_cached_acl(inode, ACL_TYPE_DEFAULT, dacl);
	set_cached_acl(inode, ACL_TYPE_ACCESS, acl);
	v9fs_set_acl(fid, ACL_TYPE_DEFAULT, dacl);
	v9fs_set_acl(fid, ACL_TYPE_ACCESS, acl);
	return 0;
}

void v9fs_put_acl(struct posix_acl *dacl,
		  struct posix_acl *acl)
{
	posix_acl_release(dacl);
	posix_acl_release(acl);
}

int v9fs_acl_mode(struct inode *dir, umode_t *modep,
		  struct posix_acl **dpacl, struct posix_acl **pacl)
{
	int retval = 0;
	umode_t mode = *modep;
	struct posix_acl *acl = NULL;

	if (!S_ISLNK(mode)) {
		acl = v9fs_get_cached_acl(dir, ACL_TYPE_DEFAULT);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		if (!acl)
			mode &= ~current_umask();
	}
	if (acl) {
		if (S_ISDIR(mode))
			*dpacl = posix_acl_dup(acl);
		retval = __posix_acl_create(&acl, GFP_NOFS, &mode);
		if (retval < 0)
			return retval;
		if (retval > 0)
			*pacl = acl;
		else
			posix_acl_release(acl);
	}
	*modep  = mode;
	return 0;
}

static int v9fs_remote_get_acl(struct dentry *dentry, const char *name,
			       void *buffer, size_t size, int type)
{
	char *full_name;

	switch (type) {
	case ACL_TYPE_ACCESS:
		full_name =  POSIX_ACL_XATTR_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		full_name = POSIX_ACL_XATTR_DEFAULT;
		break;
	default:
		BUG();
	}
	return v9fs_xattr_get(dentry, full_name, buffer, size);
}

static int v9fs_xattr_get_acl(struct dentry *dentry, const char *name,
			      void *buffer, size_t size, int type)
{
	struct v9fs_session_info *v9ses;
	struct posix_acl *acl;
	int error;

	if (strcmp(name, "") != 0)
		return -EINVAL;

	v9ses = v9fs_dentry2v9ses(dentry);
	/*
	 * We allow set/get/list of acl when access=client is not specified
	 */
	if ((v9ses->flags & V9FS_ACCESS_MASK) != V9FS_ACCESS_CLIENT)
		return v9fs_remote_get_acl(dentry, name, buffer, size, type);

	acl = v9fs_get_cached_acl(dentry->d_inode, type);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl == NULL)
		return -ENODATA;
	error = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
	posix_acl_release(acl);

	return error;
}

static int v9fs_remote_set_acl(struct dentry *dentry, const char *name,
			      const void *value, size_t size,
			      int flags, int type)
{
	char *full_name;

	switch (type) {
	case ACL_TYPE_ACCESS:
		full_name =  POSIX_ACL_XATTR_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		full_name = POSIX_ACL_XATTR_DEFAULT;
		break;
	default:
		BUG();
	}
	return v9fs_xattr_set(dentry, full_name, value, size, flags);
}


static int v9fs_xattr_set_acl(struct dentry *dentry, const char *name,
			      const void *value, size_t size,
			      int flags, int type)
{
	int retval;
	struct posix_acl *acl;
	struct v9fs_session_info *v9ses;
	struct inode *inode = dentry->d_inode;

	if (strcmp(name, "") != 0)
		return -EINVAL;

	v9ses = v9fs_dentry2v9ses(dentry);
	/*
	 * set the attribute on the remote. Without even looking at the
	 * xattr value. We leave it to the server to validate
	 */
	if ((v9ses->flags & V9FS_ACCESS_MASK) != V9FS_ACCESS_CLIENT)
		return v9fs_remote_set_acl(dentry, name,
					   value, size, flags, type);

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
	if (!inode_owner_or_capable(inode))
		return -EPERM;
	if (value) {
		/* update the cached acl value */
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		else if (acl) {
			retval = posix_acl_valid(acl);
			if (retval)
				goto err_out;
		}
	} else
		acl = NULL;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = POSIX_ACL_XATTR_ACCESS;
		if (acl) {
			umode_t mode = inode->i_mode;
			retval = posix_acl_equiv_mode(acl, &mode);
			if (retval < 0)
				goto err_out;
			else {
				struct iattr iattr;
				if (retval == 0) {
					/*
					 * ACL can be represented
					 * by the mode bits. So don't
					 * update ACL.
					 */
					acl = NULL;
					value = NULL;
					size = 0;
				}
				/* Updte the mode bits */
				iattr.ia_mode = ((mode & S_IALLUGO) |
						 (inode->i_mode & ~S_IALLUGO));
				iattr.ia_valid = ATTR_MODE;
				/* FIXME should we update ctime ?
				 * What is the following setxattr update the
				 * mode ?
				 */
				v9fs_vfs_setattr_dotl(dentry, &iattr);
			}
		}
		break;
	case ACL_TYPE_DEFAULT:
		name = POSIX_ACL_XATTR_DEFAULT;
		if (!S_ISDIR(inode->i_mode)) {
			retval = acl ? -EINVAL : 0;
			goto err_out;
		}
		break;
	default:
		BUG();
	}
	retval = v9fs_xattr_set(dentry, name, value, size, flags);
	if (!retval)
		set_cached_acl(inode, type, acl);
err_out:
	posix_acl_release(acl);
	return retval;
}

const struct xattr_handler v9fs_xattr_acl_access_handler = {
	.prefix	= POSIX_ACL_XATTR_ACCESS,
	.flags	= ACL_TYPE_ACCESS,
	.get	= v9fs_xattr_get_acl,
	.set	= v9fs_xattr_set_acl,
};

const struct xattr_handler v9fs_xattr_acl_default_handler = {
	.prefix	= POSIX_ACL_XATTR_DEFAULT,
	.flags	= ACL_TYPE_DEFAULT,
	.get	= v9fs_xattr_get_acl,
	.set	= v9fs_xattr_set_acl,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/acl.c */
/************************************************************/
/*
 * Copyright IBM Corporation, 2010
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */


// #include <linux/module.h>
// #include <linux/string.h>
// #include <linux/fs.h>
// #include <linux/slab.h>
// #include "xattr.h"

static int v9fs_xattr_security_get(struct dentry *dentry, const char *name,
			void *buffer, size_t size, int type)
{
	int retval;
	char *full_name;
	size_t name_len;
	size_t prefix_len = XATTR_SECURITY_PREFIX_LEN;

	if (name == NULL)
		return -EINVAL;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	name_len = strlen(name);
	full_name = kmalloc(prefix_len + name_len + 1 , GFP_KERNEL);
	if (!full_name)
		return -ENOMEM;
	memcpy(full_name, XATTR_SECURITY_PREFIX, prefix_len);
	memcpy(full_name+prefix_len, name, name_len);
	full_name[prefix_len + name_len] = '\0';

	retval = v9fs_xattr_get(dentry, full_name, buffer, size);
	kfree(full_name);
	return retval;
}

static int v9fs_xattr_security_set(struct dentry *dentry, const char *name,
			const void *value, size_t size, int flags, int type)
{
	int retval;
	char *full_name;
	size_t name_len;
	size_t prefix_len = XATTR_SECURITY_PREFIX_LEN;

	if (name == NULL)
		return -EINVAL;

	if (strcmp(name, "") == 0)
		return -EINVAL;

	name_len = strlen(name);
	full_name = kmalloc(prefix_len + name_len + 1 , GFP_KERNEL);
	if (!full_name)
		return -ENOMEM;
	memcpy(full_name, XATTR_SECURITY_PREFIX, prefix_len);
	memcpy(full_name + prefix_len, name, name_len);
	full_name[prefix_len + name_len] = '\0';

	retval = v9fs_xattr_set(dentry, full_name, value, size, flags);
	kfree(full_name);
	return retval;
}

struct xattr_handler v9fs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.get	= v9fs_xattr_security_get,
	.set	= v9fs_xattr_security_set,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/9p/xattr_security.c */
/************************************************************/
