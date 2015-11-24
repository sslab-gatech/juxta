/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/fs_stack.h>
#include <linux/slab.h>
#include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

/**
 * ecryptfs_d_revalidate - revalidate an ecryptfs dentry
 * @dentry: The ecryptfs dentry
 * @flags: lookup flags
 *
 * Called when the VFS needs to revalidate a dentry. This
 * is called whenever a name lookup finds a dentry in the
 * dcache. Most filesystems leave this as NULL, because all their
 * dentries in the dcache are valid.
 *
 * Returns 1 if valid, 0 otherwise.
 *
 */
static int ecryptfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	int rc;

	if (!(lower_dentry->d_flags & DCACHE_OP_REVALIDATE))
		return 1;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	rc = lower_dentry->d_op->d_revalidate(lower_dentry, flags);
	if (dentry->d_inode) {
		struct inode *lower_inode =
			ecryptfs_inode_to_lower(dentry->d_inode);

		fsstack_copy_attr_all(dentry->d_inode, lower_inode);
	}
	return rc;
}

struct kmem_cache *ecryptfs_dentry_info_cache;

static void ecryptfs_dentry_free_rcu(struct rcu_head *head)
{
	kmem_cache_free(ecryptfs_dentry_info_cache,
		container_of(head, struct ecryptfs_dentry_info, rcu));
}

/**
 * ecryptfs_d_release
 * @dentry: The ecryptfs dentry
 *
 * Called when a dentry is really deallocated.
 */
static void ecryptfs_d_release(struct dentry *dentry)
{
	struct ecryptfs_dentry_info *p = dentry->d_fsdata;
	if (p) {
		path_put(&p->lower_path);
		call_rcu(&p->rcu, ecryptfs_dentry_free_rcu);
	}
}

const struct dentry_operations ecryptfs_dops = {
	.d_revalidate = ecryptfs_d_revalidate,
	.d_release = ecryptfs_d_release,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/dentry.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2004 Erez Zadok
 * Copyright (C) 2001-2004 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *   		Michael C. Thompson <mcthomps@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/file.h>
#include <linux/poll.h>
// #include <linux/slab.h>
// #include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/security.h>
#include <linux/compat.h>
// #include <linux/fs_stack.h>
#include <linux/aio.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

/**
 * ecryptfs_read_update_atime
 *
 * generic_file_read updates the atime of upper layer inode.  But, it
 * doesn't give us a chance to update the atime of the lower layer
 * inode.  This function is a wrapper to generic_file_read.  It
 * updates the atime of the lower level inode if generic_file_read
 * returns without any errors. This is to be used only for file reads.
 * The function to be used for directory reads is ecryptfs_read.
 */
static ssize_t ecryptfs_read_update_atime(struct kiocb *iocb,
				struct iov_iter *to)
{
	ssize_t rc;
	struct path *path;
	struct file *file = iocb->ki_filp;

	rc = generic_file_read_iter(iocb, to);
	/*
	 * Even though this is a async interface, we need to wait
	 * for IO to finish to update atime
	 */
	if (-EIOCBQUEUED == rc)
		rc = wait_on_sync_kiocb(iocb);
	if (rc >= 0) {
		path = ecryptfs_dentry_to_lower_path(file->f_path.dentry);
		touch_atime(path);
	}
	return rc;
}

struct ecryptfs_getdents_callback {
	struct dir_context ctx;
	struct dir_context *caller;
	struct super_block *sb;
	int filldir_called;
	int entries_written;
};

/* Inspired by generic filldir in fs/readdir.c */
static int
ecryptfs_filldir(struct dir_context *ctx, const char *lower_name,
		 int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct ecryptfs_getdents_callback *buf =
		container_of(ctx, struct ecryptfs_getdents_callback, ctx);
	size_t name_size;
	char *name;
	int rc;

	buf->filldir_called++;
	rc = ecryptfs_decode_and_decrypt_filename(&name, &name_size,
						  buf->sb, lower_name,
						  lower_namelen);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to decode and decrypt "
		       "filename [%s]; rc = [%d]\n", __func__, lower_name,
		       rc);
		goto out;
	}
	buf->caller->pos = buf->ctx.pos;
	rc = !dir_emit(buf->caller, name, name_size, ino, d_type);
	kfree(name);
	if (!rc)
		buf->entries_written++;
out:
	return rc;
}

/**
 * ecryptfs_readdir
 * @file: The eCryptfs directory file
 * @ctx: The actor to feed the entries to
 */
static int ecryptfs_readdir(struct file *file, struct dir_context *ctx)
{
	int rc;
	struct file *lower_file;
	struct inode *inode = file_inode(file);
	struct ecryptfs_getdents_callback buf = {
		.ctx.actor = ecryptfs_filldir,
		.caller = ctx,
		.sb = inode->i_sb,
	};
	lower_file = ecryptfs_file_to_lower(file);
	lower_file->f_pos = ctx->pos;
	rc = iterate_dir(lower_file, &buf.ctx);
	ctx->pos = buf.ctx.pos;
	if (rc < 0)
		goto out;
	if (buf.filldir_called && !buf.entries_written)
		goto out;
	if (rc >= 0)
		fsstack_copy_attr_atime(inode,
					file_inode(lower_file));
out:
	return rc;
}

struct kmem_cache *ecryptfs_file_info_cache;

static int read_or_initialize_metadata(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	struct ecryptfs_crypt_stat *crypt_stat;
	int rc;

	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	mount_crypt_stat = &ecryptfs_superblock_to_private(
						inode->i_sb)->mount_crypt_stat;
	mutex_lock(&crypt_stat->cs_mutex);

	if (crypt_stat->flags & ECRYPTFS_POLICY_APPLIED &&
	    crypt_stat->flags & ECRYPTFS_KEY_VALID) {
		rc = 0;
		goto out;
	}

	rc = ecryptfs_read_metadata(dentry);
	if (!rc)
		goto out;

	if (mount_crypt_stat->flags & ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED) {
		crypt_stat->flags &= ~(ECRYPTFS_I_SIZE_INITIALIZED
				       | ECRYPTFS_ENCRYPTED);
		rc = 0;
		goto out;
	}

	if (!(mount_crypt_stat->flags & ECRYPTFS_XATTR_METADATA_ENABLED) &&
	    !i_size_read(ecryptfs_inode_to_lower(inode))) {
		rc = ecryptfs_initialize_file(dentry, inode);
		if (!rc)
			goto out;
	}

	rc = -EIO;
out:
	mutex_unlock(&crypt_stat->cs_mutex);
	return rc;
}

/**
 * ecryptfs_open
 * @inode: inode speciying file to open
 * @file: Structure to return filled in
 *
 * Opens the file specified by inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_open(struct inode *inode, struct file *file)
{
	int rc = 0;
	struct ecryptfs_crypt_stat *crypt_stat = NULL;
	struct dentry *ecryptfs_dentry = file->f_path.dentry;
	/* Private value of ecryptfs_dentry allocated in
	 * ecryptfs_lookup() */
	struct ecryptfs_file_info *file_info;

	/* Released in ecryptfs_release or end of function if failure */
	file_info = kmem_cache_zalloc(ecryptfs_file_info_cache, GFP_KERNEL);
	ecryptfs_set_file_private(file, file_info);
	if (!file_info) {
		ecryptfs_printk(KERN_ERR,
				"Error attempting to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	mutex_lock(&crypt_stat->cs_mutex);
	if (!(crypt_stat->flags & ECRYPTFS_POLICY_APPLIED)) {
		ecryptfs_printk(KERN_DEBUG, "Setting flags for stat...\n");
		/* Policy code enabled in future release */
		crypt_stat->flags |= (ECRYPTFS_POLICY_APPLIED
				      | ECRYPTFS_ENCRYPTED);
	}
	mutex_unlock(&crypt_stat->cs_mutex);
	rc = ecryptfs_get_lower_file(ecryptfs_dentry, inode);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%pd]; rc = [%d]\n", __func__,
			ecryptfs_dentry, rc);
		goto out_free;
	}
	if ((ecryptfs_inode_to_private(inode)->lower_file->f_flags & O_ACCMODE)
	    == O_RDONLY && (file->f_flags & O_ACCMODE) != O_RDONLY) {
		rc = -EPERM;
		printk(KERN_WARNING "%s: Lower file is RO; eCryptfs "
		       "file must hence be opened RO\n", __func__);
		goto out_put;
	}
	ecryptfs_set_file_lower(
		file, ecryptfs_inode_to_private(inode)->lower_file);
	if (d_is_dir(ecryptfs_dentry)) {
		ecryptfs_printk(KERN_DEBUG, "This is a directory\n");
		mutex_lock(&crypt_stat->cs_mutex);
		crypt_stat->flags &= ~(ECRYPTFS_ENCRYPTED);
		mutex_unlock(&crypt_stat->cs_mutex);
		rc = 0;
		goto out;
	}
	rc = read_or_initialize_metadata(ecryptfs_dentry);
	if (rc)
		goto out_put;
	ecryptfs_printk(KERN_DEBUG, "inode w/ addr = [0x%p], i_ino = "
			"[0x%.16lx] size: [0x%.16llx]\n", inode, inode->i_ino,
			(unsigned long long)i_size_read(inode));
	goto out;
out_put:
	ecryptfs_put_lower_file(inode);
out_free:
	kmem_cache_free(ecryptfs_file_info_cache,
			ecryptfs_file_to_private(file));
out:
	return rc;
}

static int ecryptfs_flush(struct file *file, fl_owner_t td)
{
	struct file *lower_file = ecryptfs_file_to_lower(file);

	if (lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		return lower_file->f_op->flush(lower_file, td);
	}

	return 0;
}

static int ecryptfs_release(struct inode *inode, struct file *file)
{
	ecryptfs_put_lower_file(inode);
	kmem_cache_free(ecryptfs_file_info_cache,
			ecryptfs_file_to_private(file));
	return 0;
}

static int
ecryptfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int rc;

	rc = filemap_write_and_wait(file->f_mapping);
	if (rc)
		return rc;

	return vfs_fsync(ecryptfs_file_to_lower(file), datasync);
}

static int ecryptfs_fasync(int fd, struct file *file, int flag)
{
	int rc = 0;
	struct file *lower_file = NULL;

	lower_file = ecryptfs_file_to_lower(file);
	if (lower_file->f_op->fasync)
		rc = lower_file->f_op->fasync(fd, lower_file, flag);
	return rc;
}

static long
ecryptfs_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct file *lower_file = ecryptfs_file_to_lower(file);
	long rc = -ENOTTY;

	if (lower_file->f_op->unlocked_ioctl)
		rc = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);
	return rc;
}

#ifdef CONFIG_COMPAT
static long
ecryptfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct file *lower_file = ecryptfs_file_to_lower(file);
	long rc = -ENOIOCTLCMD;

	if (lower_file->f_op->compat_ioctl)
		rc = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);
	return rc;
}
#endif

const struct file_operations ecryptfs_dir_fops = {
	.iterate = ecryptfs_readdir,
	.read = generic_read_dir,
	.unlocked_ioctl = ecryptfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ecryptfs_compat_ioctl,
#endif
	.open = ecryptfs_open,
	.flush = ecryptfs_flush,
	.release = ecryptfs_release,
	.fsync = ecryptfs_fsync,
	.fasync = ecryptfs_fasync,
	.splice_read = generic_file_splice_read,
	.llseek = default_llseek,
};

const struct file_operations ecryptfs_main_fops = {
	.llseek = generic_file_llseek,
	.read = new_sync_read,
	.read_iter = ecryptfs_read_update_atime,
	.write = new_sync_write,
	.write_iter = generic_file_write_iter,
	.iterate = ecryptfs_readdir,
	.unlocked_ioctl = ecryptfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ecryptfs_compat_ioctl,
#endif
	.mmap = generic_file_mmap,
	.open = ecryptfs_open,
	.flush = ecryptfs_flush,
	.release = ecryptfs_release,
	.fsync = ecryptfs_fsync,
	.fasync = ecryptfs_fasync,
	.splice_read = generic_file_splice_read,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/file.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2004 Erez Zadok
 * Copyright (C) 2001-2004 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Michael C. Thompsion <mcthomps@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

// #include <linux/file.h>
#include <linux/vmalloc.h>
// #include <linux/pagemap.h>
// #include <linux/dcache.h>
// #include <linux/namei.h>
// #include <linux/mount.h>
#include <linux/crypto.h>
// #include <linux/fs_stack.h>
// #include <linux/slab.h>
#include <linux/xattr.h>
#include <asm/unaligned.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

static struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir;

	dir = dget_parent(dentry);
	mutex_lock_nested(&(dir->d_inode->i_mutex), I_MUTEX_PARENT);
	return dir;
}

static void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}

static int ecryptfs_inode_test(struct inode *inode, void *lower_inode)
{
	return ecryptfs_inode_to_lower(inode) == lower_inode;
}

static int ecryptfs_inode_set(struct inode *inode, void *opaque)
{
	struct inode *lower_inode = opaque;

	ecryptfs_set_inode_lower(inode, lower_inode);
	fsstack_copy_attr_all(inode, lower_inode);
	/* i_size will be overwritten for encrypted regular files */
	fsstack_copy_inode_size(inode, lower_inode);
	inode->i_ino = lower_inode->i_ino;
	inode->i_version++;
	inode->i_mapping->a_ops = &ecryptfs_aops;

	if (S_ISLNK(inode->i_mode))
		inode->i_op = &ecryptfs_symlink_iops;
	else if (S_ISDIR(inode->i_mode))
		inode->i_op = &ecryptfs_dir_iops;
	else
		inode->i_op = &ecryptfs_main_iops;

	if (S_ISDIR(inode->i_mode))
		inode->i_fop = &ecryptfs_dir_fops;
	else if (special_file(inode->i_mode))
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	else
		inode->i_fop = &ecryptfs_main_fops;

	return 0;
}

static struct inode *__ecryptfs_get_inode(struct inode *lower_inode,
					  struct super_block *sb)
{
	struct inode *inode;

	if (lower_inode->i_sb != ecryptfs_superblock_to_lower(sb))
		return ERR_PTR(-EXDEV);
	if (!igrab(lower_inode))
		return ERR_PTR(-ESTALE);
	inode = iget5_locked(sb, (unsigned long)lower_inode,
			     ecryptfs_inode_test, ecryptfs_inode_set,
			     lower_inode);
	if (!inode) {
		iput(lower_inode);
		return ERR_PTR(-EACCES);
	}
	if (!(inode->i_state & I_NEW))
		iput(lower_inode);

	return inode;
}

struct inode *ecryptfs_get_inode(struct inode *lower_inode,
				 struct super_block *sb)
{
	struct inode *inode = __ecryptfs_get_inode(lower_inode, sb);

	if (!IS_ERR(inode) && (inode->i_state & I_NEW))
		unlock_new_inode(inode);

	return inode;
}

/**
 * ecryptfs_interpose
 * @lower_dentry: Existing dentry in the lower filesystem
 * @dentry: ecryptfs' dentry
 * @sb: ecryptfs's super_block
 *
 * Interposes upper and lower dentries.
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_interpose(struct dentry *lower_dentry,
			      struct dentry *dentry, struct super_block *sb)
{
	struct inode *inode = ecryptfs_get_inode(lower_dentry->d_inode, sb);

	if (IS_ERR(inode))
		return PTR_ERR(inode);
	d_instantiate(dentry, inode);

	return 0;
}

static int ecryptfs_do_unlink(struct inode *dir, struct dentry *dentry,
			      struct inode *inode)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	struct inode *lower_dir_inode = ecryptfs_inode_to_lower(dir);
	struct dentry *lower_dir_dentry;
	int rc;

	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	if (rc) {
		printk(KERN_ERR "Error in vfs_unlink; rc = [%d]\n", rc);
		goto out_unlock;
	}
	fsstack_copy_attr_times(dir, lower_dir_inode);
	set_nlink(inode, ecryptfs_inode_to_lower(inode)->i_nlink);
	inode->i_ctime = dir->i_ctime;
	d_drop(dentry);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	return rc;
}

/**
 * ecryptfs_do_create
 * @directory_inode: inode of the new file's dentry's parent in ecryptfs
 * @ecryptfs_dentry: New file's dentry in ecryptfs
 * @mode: The mode of the new file
 * @nd: nameidata of ecryptfs' parent's dentry & vfsmount
 *
 * Creates the underlying file and the eCryptfs inode which will link to
 * it. It will also update the eCryptfs directory inode to mimic the
 * stat of the lower directory inode.
 *
 * Returns the new eCryptfs inode on success; an ERR_PTR on error condition
 */
static struct inode *
ecryptfs_do_create(struct inode *directory_inode,
		   struct dentry *ecryptfs_dentry, umode_t mode)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct inode *inode;

	lower_dentry = ecryptfs_dentry_to_lower(ecryptfs_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_create(lower_dir_dentry->d_inode, lower_dentry, mode, true);
	if (rc) {
		printk(KERN_ERR "%s: Failure to create dentry in lower fs; "
		       "rc = [%d]\n", __func__, rc);
		inode = ERR_PTR(rc);
		goto out_lock;
	}
	inode = __ecryptfs_get_inode(lower_dentry->d_inode,
				     directory_inode->i_sb);
	if (IS_ERR(inode)) {
		vfs_unlink(lower_dir_dentry->d_inode, lower_dentry, NULL);
		goto out_lock;
	}
	fsstack_copy_attr_times(directory_inode, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(directory_inode, lower_dir_dentry->d_inode);
out_lock:
	unlock_dir(lower_dir_dentry);
	return inode;
}

/**
 * ecryptfs_initialize_file
 *
 * Cause the file to be changed from a basic empty file to an ecryptfs
 * file with a header and first data page.
 *
 * Returns zero on success
 */
int ecryptfs_initialize_file(struct dentry *ecryptfs_dentry,
			     struct inode *ecryptfs_inode)
{
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	int rc = 0;

	if (S_ISDIR(ecryptfs_inode->i_mode)) {
		ecryptfs_printk(KERN_DEBUG, "This is a directory\n");
		crypt_stat->flags &= ~(ECRYPTFS_ENCRYPTED);
		goto out;
	}
	ecryptfs_printk(KERN_DEBUG, "Initializing crypto context\n");
	rc = ecryptfs_new_file_context(ecryptfs_inode);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error creating new file "
				"context; rc = [%d]\n", rc);
		goto out;
	}
	rc = ecryptfs_get_lower_file(ecryptfs_dentry, ecryptfs_inode);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%pd]; rc = [%d]\n", __func__,
			ecryptfs_dentry, rc);
		goto out;
	}
	rc = ecryptfs_write_metadata(ecryptfs_dentry, ecryptfs_inode);
	if (rc)
		printk(KERN_ERR "Error writing headers; rc = [%d]\n", rc);
	ecryptfs_put_lower_file(ecryptfs_inode);
out:
	return rc;
}

/**
 * ecryptfs_create
 * @dir: The inode of the directory in which to create the file.
 * @dentry: The eCryptfs dentry
 * @mode: The mode of the new file.
 *
 * Creates a new file.
 *
 * Returns zero on success; non-zero on error condition
 */
static int
ecryptfs_create(struct inode *directory_inode, struct dentry *ecryptfs_dentry,
		umode_t mode, bool excl)
{
	struct inode *ecryptfs_inode;
	int rc;

	ecryptfs_inode = ecryptfs_do_create(directory_inode, ecryptfs_dentry,
					    mode);
	if (unlikely(IS_ERR(ecryptfs_inode))) {
		ecryptfs_printk(KERN_WARNING, "Failed to create file in"
				"lower filesystem\n");
		rc = PTR_ERR(ecryptfs_inode);
		goto out;
	}
	/* At this point, a file exists on "disk"; we need to make sure
	 * that this on disk file is prepared to be an ecryptfs file */
	rc = ecryptfs_initialize_file(ecryptfs_dentry, ecryptfs_inode);
	if (rc) {
		ecryptfs_do_unlink(directory_inode, ecryptfs_dentry,
				   ecryptfs_inode);
		make_bad_inode(ecryptfs_inode);
		unlock_new_inode(ecryptfs_inode);
		iput(ecryptfs_inode);
		goto out;
	}
	unlock_new_inode(ecryptfs_inode);
	d_instantiate(ecryptfs_dentry, ecryptfs_inode);
out:
	return rc;
}

static int ecryptfs_i_size_read(struct dentry *dentry, struct inode *inode)
{
	struct ecryptfs_crypt_stat *crypt_stat;
	int rc;

	rc = ecryptfs_get_lower_file(dentry, inode);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to initialize "
			"the lower file for the dentry with name "
			"[%pd]; rc = [%d]\n", __func__,
			dentry, rc);
		return rc;
	}

	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	/* TODO: lock for crypt_stat comparison */
	if (!(crypt_stat->flags & ECRYPTFS_POLICY_APPLIED))
		ecryptfs_set_default_sizes(crypt_stat);

	rc = ecryptfs_read_and_validate_header_region(inode);
	ecryptfs_put_lower_file(inode);
	if (rc) {
		rc = ecryptfs_read_and_validate_xattr_region(dentry, inode);
		if (!rc)
			crypt_stat->flags |= ECRYPTFS_METADATA_IN_XATTR;
	}

	/* Must return 0 to allow non-eCryptfs files to be looked up, too */
	return 0;
}

/**
 * ecryptfs_lookup_interpose - Dentry interposition for a lookup
 */
static int ecryptfs_lookup_interpose(struct dentry *dentry,
				     struct dentry *lower_dentry,
				     struct inode *dir_inode)
{
	struct inode *inode, *lower_inode = lower_dentry->d_inode;
	struct ecryptfs_dentry_info *dentry_info;
	struct vfsmount *lower_mnt;
	int rc = 0;

	dentry_info = kmem_cache_alloc(ecryptfs_dentry_info_cache, GFP_KERNEL);
	if (!dentry_info) {
		printk(KERN_ERR "%s: Out of memory whilst attempting "
		       "to allocate ecryptfs_dentry_info struct\n",
			__func__);
		dput(lower_dentry);
		return -ENOMEM;
	}

	lower_mnt = mntget(ecryptfs_dentry_to_lower_mnt(dentry->d_parent));
	fsstack_copy_attr_atime(dir_inode, lower_dentry->d_parent->d_inode);
	BUG_ON(!d_count(lower_dentry));

	ecryptfs_set_dentry_private(dentry, dentry_info);
	dentry_info->lower_path.mnt = lower_mnt;
	dentry_info->lower_path.dentry = lower_dentry;

	if (!lower_dentry->d_inode) {
		/* We want to add because we couldn't find in lower */
		d_add(dentry, NULL);
		return 0;
	}
	inode = __ecryptfs_get_inode(lower_inode, dir_inode->i_sb);
	if (IS_ERR(inode)) {
		printk(KERN_ERR "%s: Error interposing; rc = [%ld]\n",
		       __func__, PTR_ERR(inode));
		return PTR_ERR(inode);
	}
	if (S_ISREG(inode->i_mode)) {
		rc = ecryptfs_i_size_read(dentry, inode);
		if (rc) {
			make_bad_inode(inode);
			return rc;
		}
	}

	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);
	d_add(dentry, inode);

	return rc;
}

/**
 * ecryptfs_lookup
 * @ecryptfs_dir_inode: The eCryptfs directory inode
 * @ecryptfs_dentry: The eCryptfs dentry that we are looking up
 * @ecryptfs_nd: nameidata; may be NULL
 *
 * Find a file on disk. If the file does not exist, then we'll add it to the
 * dentry cache and continue on to read it from the disk.
 */
static struct dentry *ecryptfs_lookup(struct inode *ecryptfs_dir_inode,
				      struct dentry *ecryptfs_dentry,
				      unsigned int flags)
{
	char *encrypted_and_encoded_name = NULL;
	size_t encrypted_and_encoded_name_size;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat = NULL;
	struct dentry *lower_dir_dentry, *lower_dentry;
	int rc = 0;

	lower_dir_dentry = ecryptfs_dentry_to_lower(ecryptfs_dentry->d_parent);
	mutex_lock(&lower_dir_dentry->d_inode->i_mutex);
	lower_dentry = lookup_one_len(ecryptfs_dentry->d_name.name,
				      lower_dir_dentry,
				      ecryptfs_dentry->d_name.len);
	mutex_unlock(&lower_dir_dentry->d_inode->i_mutex);
	if (IS_ERR(lower_dentry)) {
		rc = PTR_ERR(lower_dentry);
		ecryptfs_printk(KERN_DEBUG, "%s: lookup_one_len() returned "
				"[%d] on lower_dentry = [%pd]\n", __func__, rc,
				ecryptfs_dentry);
		goto out;
	}
	if (lower_dentry->d_inode)
		goto interpose;
	mount_crypt_stat = &ecryptfs_superblock_to_private(
				ecryptfs_dentry->d_sb)->mount_crypt_stat;
	if (!(mount_crypt_stat
	    && (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)))
		goto interpose;
	dput(lower_dentry);
	rc = ecryptfs_encrypt_and_encode_filename(
		&encrypted_and_encoded_name, &encrypted_and_encoded_name_size,
		NULL, mount_crypt_stat, ecryptfs_dentry->d_name.name,
		ecryptfs_dentry->d_name.len);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to encrypt and encode "
		       "filename; rc = [%d]\n", __func__, rc);
		goto out;
	}
	mutex_lock(&lower_dir_dentry->d_inode->i_mutex);
	lower_dentry = lookup_one_len(encrypted_and_encoded_name,
				      lower_dir_dentry,
				      encrypted_and_encoded_name_size);
	mutex_unlock(&lower_dir_dentry->d_inode->i_mutex);
	if (IS_ERR(lower_dentry)) {
		rc = PTR_ERR(lower_dentry);
		ecryptfs_printk(KERN_DEBUG, "%s: lookup_one_len() returned "
				"[%d] on lower_dentry = [%s]\n", __func__, rc,
				encrypted_and_encoded_name);
		goto out;
	}
interpose:
	rc = ecryptfs_lookup_interpose(ecryptfs_dentry, lower_dentry,
				       ecryptfs_dir_inode);
out:
	kfree(encrypted_and_encoded_name);
	return ERR_PTR(rc);
}

static int ecryptfs_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int rc;

	file_size_save = i_size_read(old_dentry->d_inode);
	lower_old_dentry = ecryptfs_dentry_to_lower(old_dentry);
	lower_new_dentry = ecryptfs_dentry_to_lower(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_dir_dentry = lock_parent(lower_new_dentry);
	rc = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
		      lower_new_dentry, NULL);
	if (rc || !lower_new_dentry->d_inode)
		goto out_lock;
	rc = ecryptfs_interpose(lower_new_dentry, new_dentry, dir->i_sb);
	if (rc)
		goto out_lock;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
		  ecryptfs_inode_to_lower(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out_lock:
	unlock_dir(lower_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return rc;
}

static int ecryptfs_unlink(struct inode *dir, struct dentry *dentry)
{
	return ecryptfs_do_unlink(dir, dentry, dentry->d_inode);
}

static int ecryptfs_symlink(struct inode *dir, struct dentry *dentry,
			    const char *symname)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	char *encoded_symname;
	size_t encoded_symlen;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat = NULL;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	mount_crypt_stat = &ecryptfs_superblock_to_private(
		dir->i_sb)->mount_crypt_stat;
	rc = ecryptfs_encrypt_and_encode_filename(&encoded_symname,
						  &encoded_symlen,
						  NULL,
						  mount_crypt_stat, symname,
						  strlen(symname));
	if (rc)
		goto out_lock;
	rc = vfs_symlink(lower_dir_dentry->d_inode, lower_dentry,
			 encoded_symname);
	kfree(encoded_symname);
	if (rc || !lower_dentry->d_inode)
		goto out_lock;
	rc = ecryptfs_interpose(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out_lock;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
out_lock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return rc;
}

static int ecryptfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_mkdir(lower_dir_dentry->d_inode, lower_dentry, mode);
	if (rc || !lower_dentry->d_inode)
		goto out;
	rc = ecryptfs_interpose(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);
out:
	unlock_dir(lower_dir_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return rc;
}

static int ecryptfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int rc;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	dget(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	dget(lower_dentry);
	rc = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	dput(lower_dentry);
	if (!rc && dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);
	unlock_dir(lower_dir_dentry);
	if (!rc)
		d_drop(dentry);
	dput(dentry);
	return rc;
}

static int
ecryptfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	int rc;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	rc = vfs_mknod(lower_dir_dentry->d_inode, lower_dentry, mode, dev);
	if (rc || !lower_dentry->d_inode)
		goto out;
	rc = ecryptfs_interpose(lower_dentry, dentry, dir->i_sb);
	if (rc)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
out:
	unlock_dir(lower_dir_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
	return rc;
}

static int
ecryptfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	int rc;
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_old_dir_dentry;
	struct dentry *lower_new_dir_dentry;
	struct dentry *trap = NULL;
	struct inode *target_inode;

	lower_old_dentry = ecryptfs_dentry_to_lower(old_dentry);
	lower_new_dentry = ecryptfs_dentry_to_lower(new_dentry);
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);
	target_inode = new_dentry->d_inode;
	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		rc = -EINVAL;
		goto out_lock;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		rc = -ENOTEMPTY;
		goto out_lock;
	}
	rc = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			lower_new_dir_dentry->d_inode, lower_new_dentry,
			NULL, 0);
	if (rc)
		goto out_lock;
	if (target_inode)
		fsstack_copy_attr_all(target_inode,
				      ecryptfs_inode_to_lower(target_inode));
	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir)
		fsstack_copy_attr_all(old_dir, lower_old_dir_dentry->d_inode);
out_lock:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
	return rc;
}

static char *ecryptfs_readlink_lower(struct dentry *dentry, size_t *bufsiz)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	char *lower_buf;
	char *buf;
	mm_segment_t old_fs;
	int rc;

	lower_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!lower_buf)
		return ERR_PTR(-ENOMEM);
	old_fs = get_fs();
	set_fs(get_ds());
	rc = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						   (char __user *)lower_buf,
						   PATH_MAX);
	set_fs(old_fs);
	if (rc < 0)
		goto out;
	rc = ecryptfs_decode_and_decrypt_filename(&buf, bufsiz, dentry->d_sb,
						  lower_buf, rc);
out:
	kfree(lower_buf);
	return rc ? ERR_PTR(rc) : buf;
}

static void *ecryptfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	size_t len;
	char *buf = ecryptfs_readlink_lower(dentry, &len);
	if (IS_ERR(buf))
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode,
				ecryptfs_dentry_to_lower(dentry)->d_inode);
	buf[len] = '\0';
out:
	nd_set_link(nd, buf);
	return NULL;
}

/**
 * upper_size_to_lower_size
 * @crypt_stat: Crypt_stat associated with file
 * @upper_size: Size of the upper file
 *
 * Calculate the required size of the lower file based on the
 * specified size of the upper file. This calculation is based on the
 * number of headers in the underlying file and the extent size.
 *
 * Returns Calculated size of the lower file.
 */
static loff_t
upper_size_to_lower_size(struct ecryptfs_crypt_stat *crypt_stat,
			 loff_t upper_size)
{
	loff_t lower_size;

	lower_size = ecryptfs_lower_header_size(crypt_stat);
	if (upper_size != 0) {
		loff_t num_extents;

		num_extents = upper_size >> crypt_stat->extent_shift;
		if (upper_size & ~crypt_stat->extent_mask)
			num_extents++;
		lower_size += (num_extents * crypt_stat->extent_size);
	}
	return lower_size;
}

/**
 * truncate_upper
 * @dentry: The ecryptfs layer dentry
 * @ia: Address of the ecryptfs inode's attributes
 * @lower_ia: Address of the lower inode's attributes
 *
 * Function to handle truncations modifying the size of the file. Note
 * that the file sizes are interpolated. When expanding, we are simply
 * writing strings of 0's out. When truncating, we truncate the upper
 * inode and update the lower_ia according to the page index
 * interpolations. If ATTR_SIZE is set in lower_ia->ia_valid upon return,
 * the caller must use lower_ia in a call to notify_change() to perform
 * the truncation of the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int truncate_upper(struct dentry *dentry, struct iattr *ia,
			  struct iattr *lower_ia)
{
	int rc = 0;
	struct inode *inode = dentry->d_inode;
	struct ecryptfs_crypt_stat *crypt_stat;
	loff_t i_size = i_size_read(inode);
	loff_t lower_size_before_truncate;
	loff_t lower_size_after_truncate;

	if (unlikely((ia->ia_size == i_size))) {
		lower_ia->ia_valid &= ~ATTR_SIZE;
		return 0;
	}
	rc = ecryptfs_get_lower_file(dentry, inode);
	if (rc)
		return rc;
	crypt_stat = &ecryptfs_inode_to_private(dentry->d_inode)->crypt_stat;
	/* Switch on growing or shrinking file */
	if (ia->ia_size > i_size) {
		char zero[] = { 0x00 };

		lower_ia->ia_valid &= ~ATTR_SIZE;
		/* Write a single 0 at the last position of the file;
		 * this triggers code that will fill in 0's throughout
		 * the intermediate portion of the previous end of the
		 * file and the new and of the file */
		rc = ecryptfs_write(inode, zero,
				    (ia->ia_size - 1), 1);
	} else { /* ia->ia_size < i_size_read(inode) */
		/* We're chopping off all the pages down to the page
		 * in which ia->ia_size is located. Fill in the end of
		 * that page from (ia->ia_size & ~PAGE_CACHE_MASK) to
		 * PAGE_CACHE_SIZE with zeros. */
		size_t num_zeros = (PAGE_CACHE_SIZE
				    - (ia->ia_size & ~PAGE_CACHE_MASK));

		if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
			truncate_setsize(inode, ia->ia_size);
			lower_ia->ia_size = ia->ia_size;
			lower_ia->ia_valid |= ATTR_SIZE;
			goto out;
		}
		if (num_zeros) {
			char *zeros_virt;

			zeros_virt = kzalloc(num_zeros, GFP_KERNEL);
			if (!zeros_virt) {
				rc = -ENOMEM;
				goto out;
			}
			rc = ecryptfs_write(inode, zeros_virt,
					    ia->ia_size, num_zeros);
			kfree(zeros_virt);
			if (rc) {
				printk(KERN_ERR "Error attempting to zero out "
				       "the remainder of the end page on "
				       "reducing truncate; rc = [%d]\n", rc);
				goto out;
			}
		}
		truncate_setsize(inode, ia->ia_size);
		rc = ecryptfs_write_inode_size_to_metadata(inode);
		if (rc) {
			printk(KERN_ERR	"Problem with "
			       "ecryptfs_write_inode_size_to_metadata; "
			       "rc = [%d]\n", rc);
			goto out;
		}
		/* We are reducing the size of the ecryptfs file, and need to
		 * know if we need to reduce the size of the lower file. */
		lower_size_before_truncate =
		    upper_size_to_lower_size(crypt_stat, i_size);
		lower_size_after_truncate =
		    upper_size_to_lower_size(crypt_stat, ia->ia_size);
		if (lower_size_after_truncate < lower_size_before_truncate) {
			lower_ia->ia_size = lower_size_after_truncate;
			lower_ia->ia_valid |= ATTR_SIZE;
		} else
			lower_ia->ia_valid &= ~ATTR_SIZE;
	}
out:
	ecryptfs_put_lower_file(inode);
	return rc;
}

static int ecryptfs_inode_newsize_ok(struct inode *inode, loff_t offset)
{
	struct ecryptfs_crypt_stat *crypt_stat;
	loff_t lower_oldsize, lower_newsize;

	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	lower_oldsize = upper_size_to_lower_size(crypt_stat,
						 i_size_read(inode));
	lower_newsize = upper_size_to_lower_size(crypt_stat, offset);
	if (lower_newsize > lower_oldsize) {
		/*
		 * The eCryptfs inode and the new *lower* size are mixed here
		 * because we may not have the lower i_mutex held and/or it may
		 * not be appropriate to call inode_newsize_ok() with inodes
		 * from other filesystems.
		 */
		return inode_newsize_ok(inode, lower_newsize);
	}

	return 0;
}

/**
 * ecryptfs_truncate
 * @dentry: The ecryptfs layer dentry
 * @new_length: The length to expand the file to
 *
 * Simple function that handles the truncation of an eCryptfs inode and
 * its corresponding lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_truncate(struct dentry *dentry, loff_t new_length)
{
	struct iattr ia = { .ia_valid = ATTR_SIZE, .ia_size = new_length };
	struct iattr lower_ia = { .ia_valid = 0 };
	int rc;

	rc = ecryptfs_inode_newsize_ok(dentry->d_inode, new_length);
	if (rc)
		return rc;

	rc = truncate_upper(dentry, &ia, &lower_ia);
	if (!rc && lower_ia.ia_valid & ATTR_SIZE) {
		struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);

		mutex_lock(&lower_dentry->d_inode->i_mutex);
		rc = notify_change(lower_dentry, &lower_ia, NULL);
		mutex_unlock(&lower_dentry->d_inode->i_mutex);
	}
	return rc;
}

static int
ecryptfs_permission(struct inode *inode, int mask)
{
	return inode_permission(ecryptfs_inode_to_lower(inode), mask);
}

/**
 * ecryptfs_setattr
 * @dentry: dentry handle to the inode to modify
 * @ia: Structure with flags of what to change and values
 *
 * Updates the metadata of an inode. If the update is to the size
 * i.e. truncation, then ecryptfs_truncate will handle the size modification
 * of both the ecryptfs inode and the lower inode.
 *
 * All other metadata changes will be passed right to the lower filesystem,
 * and we will just update our inode to look like the lower.
 */
static int ecryptfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int rc = 0;
	struct dentry *lower_dentry;
	struct iattr lower_ia;
	struct inode *inode;
	struct inode *lower_inode;
	struct ecryptfs_crypt_stat *crypt_stat;

	crypt_stat = &ecryptfs_inode_to_private(dentry->d_inode)->crypt_stat;
	if (!(crypt_stat->flags & ECRYPTFS_STRUCT_INITIALIZED))
		ecryptfs_init_crypt_stat(crypt_stat);
	inode = dentry->d_inode;
	lower_inode = ecryptfs_inode_to_lower(inode);
	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	mutex_lock(&crypt_stat->cs_mutex);
	if (d_is_dir(dentry))
		crypt_stat->flags &= ~(ECRYPTFS_ENCRYPTED);
	else if (d_is_reg(dentry)
		 && (!(crypt_stat->flags & ECRYPTFS_POLICY_APPLIED)
		     || !(crypt_stat->flags & ECRYPTFS_KEY_VALID))) {
		struct ecryptfs_mount_crypt_stat *mount_crypt_stat;

		mount_crypt_stat = &ecryptfs_superblock_to_private(
			dentry->d_sb)->mount_crypt_stat;
		rc = ecryptfs_get_lower_file(dentry, inode);
		if (rc) {
			mutex_unlock(&crypt_stat->cs_mutex);
			goto out;
		}
		rc = ecryptfs_read_metadata(dentry);
		ecryptfs_put_lower_file(inode);
		if (rc) {
			if (!(mount_crypt_stat->flags
			      & ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED)) {
				rc = -EIO;
				printk(KERN_WARNING "Either the lower file "
				       "is not in a valid eCryptfs format, "
				       "or the key could not be retrieved. "
				       "Plaintext passthrough mode is not "
				       "enabled; returning -EIO\n");
				mutex_unlock(&crypt_stat->cs_mutex);
				goto out;
			}
			rc = 0;
			crypt_stat->flags &= ~(ECRYPTFS_I_SIZE_INITIALIZED
					       | ECRYPTFS_ENCRYPTED);
		}
	}
	mutex_unlock(&crypt_stat->cs_mutex);

	rc = inode_change_ok(inode, ia);
	if (rc)
		goto out;
	if (ia->ia_valid & ATTR_SIZE) {
		rc = ecryptfs_inode_newsize_ok(inode, ia->ia_size);
		if (rc)
			goto out;
	}

	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = ecryptfs_file_to_lower(ia->ia_file);
	if (ia->ia_valid & ATTR_SIZE) {
		rc = truncate_upper(dentry, ia, &lower_ia);
		if (rc < 0)
			goto out;
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = notify_change(lower_dentry, &lower_ia, NULL);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	fsstack_copy_attr_all(inode, lower_inode);
	return rc;
}

static int ecryptfs_getattr_link(struct vfsmount *mnt, struct dentry *dentry,
				 struct kstat *stat)
{
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	int rc = 0;

	mount_crypt_stat = &ecryptfs_superblock_to_private(
						dentry->d_sb)->mount_crypt_stat;
	generic_fillattr(dentry->d_inode, stat);
	if (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES) {
		char *target;
		size_t targetsiz;

		target = ecryptfs_readlink_lower(dentry, &targetsiz);
		if (!IS_ERR(target)) {
			kfree(target);
			stat->size = targetsiz;
		} else {
			rc = PTR_ERR(target);
		}
	}
	return rc;
}

static int ecryptfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			    struct kstat *stat)
{
	struct kstat lower_stat;
	int rc;

	rc = vfs_getattr(ecryptfs_dentry_to_lower_path(dentry), &lower_stat);
	if (!rc) {
		fsstack_copy_attr_all(dentry->d_inode,
				      ecryptfs_inode_to_lower(dentry->d_inode));
		generic_fillattr(dentry->d_inode, stat);
		stat->blocks = lower_stat.blocks;
	}
	return rc;
}

int
ecryptfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		  size_t size, int flags)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->setxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	rc = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (!rc && dentry->d_inode)
		fsstack_copy_attr_all(dentry->d_inode, lower_dentry->d_inode);
out:
	return rc;
}

ssize_t
ecryptfs_getxattr_lower(struct dentry *lower_dentry, const char *name,
			void *value, size_t size)
{
	int rc = 0;

	if (!lower_dentry->d_inode->i_op->getxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->getxattr(lower_dentry, name, value,
						   size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

static ssize_t
ecryptfs_getxattr(struct dentry *dentry, const char *name, void *value,
		  size_t size)
{
	return ecryptfs_getxattr_lower(ecryptfs_dentry_to_lower(dentry), name,
				       value, size);
}

static ssize_t
ecryptfs_listxattr(struct dentry *dentry, char *list, size_t size)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->listxattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->listxattr(lower_dentry, list, size);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

static int ecryptfs_removexattr(struct dentry *dentry, const char *name)
{
	int rc = 0;
	struct dentry *lower_dentry;

	lower_dentry = ecryptfs_dentry_to_lower(dentry);
	if (!lower_dentry->d_inode->i_op->removexattr) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	rc = lower_dentry->d_inode->i_op->removexattr(lower_dentry, name);
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
out:
	return rc;
}

const struct inode_operations ecryptfs_symlink_iops = {
	.readlink = generic_readlink,
	.follow_link = ecryptfs_follow_link,
	.put_link = kfree_put_link,
	.permission = ecryptfs_permission,
	.setattr = ecryptfs_setattr,
	.getattr = ecryptfs_getattr_link,
	.setxattr = ecryptfs_setxattr,
	.getxattr = ecryptfs_getxattr,
	.listxattr = ecryptfs_listxattr,
	.removexattr = ecryptfs_removexattr
};

const struct inode_operations ecryptfs_dir_iops = {
	.create = ecryptfs_create,
	.lookup = ecryptfs_lookup,
	.link = ecryptfs_link,
	.unlink = ecryptfs_unlink,
	.symlink = ecryptfs_symlink,
	.mkdir = ecryptfs_mkdir,
	.rmdir = ecryptfs_rmdir,
	.mknod = ecryptfs_mknod,
	.rename = ecryptfs_rename,
	.permission = ecryptfs_permission,
	.setattr = ecryptfs_setattr,
	.setxattr = ecryptfs_setxattr,
	.getxattr = ecryptfs_getxattr,
	.listxattr = ecryptfs_listxattr,
	.removexattr = ecryptfs_removexattr
};

const struct inode_operations ecryptfs_main_iops = {
	.permission = ecryptfs_permission,
	.setattr = ecryptfs_setattr,
	.getattr = ecryptfs_getattr,
	.setxattr = ecryptfs_setxattr,
	.getxattr = ecryptfs_getxattr,
	.listxattr = ecryptfs_listxattr,
	.removexattr = ecryptfs_removexattr
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/inode.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Michael C. Thompson <mcthomps@us.ibm.com>
 *              Tyler Hicks <tyhicks@ou.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

// #include <linux/dcache.h>
// #include <linux/file.h>
#include <linux/module.h>
// #include <linux/namei.h>
#include <linux/skbuff.h>
// #include <linux/crypto.h>
// #include <linux/mount.h>
// #include <linux/pagemap.h>
#include <linux/key.h>
#include <linux/parser.h>
// #include <linux/fs_stack.h>
// #include <linux/slab.h>
#include <linux/magic.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

/**
 * Module parameter that defines the ecryptfs_verbosity level.
 */
int ecryptfs_verbosity = 0;

module_param(ecryptfs_verbosity, int, 0);
MODULE_PARM_DESC(ecryptfs_verbosity,
		 "Initial verbosity level (0 or 1; defaults to "
		 "0, which is Quiet)");

/**
 * Module parameter that defines the number of message buffer elements
 */
unsigned int ecryptfs_message_buf_len = ECRYPTFS_DEFAULT_MSG_CTX_ELEMS;

module_param(ecryptfs_message_buf_len, uint, 0);
MODULE_PARM_DESC(ecryptfs_message_buf_len,
		 "Number of message buffer elements");

/**
 * Module parameter that defines the maximum guaranteed amount of time to wait
 * for a response from ecryptfsd.  The actual sleep time will be, more than
 * likely, a small amount greater than this specified value, but only less if
 * the message successfully arrives.
 */
signed long ecryptfs_message_wait_timeout = ECRYPTFS_MAX_MSG_CTX_TTL / HZ;

module_param(ecryptfs_message_wait_timeout, long, 0);
MODULE_PARM_DESC(ecryptfs_message_wait_timeout,
		 "Maximum number of seconds that an operation will "
		 "sleep while waiting for a message response from "
		 "userspace");

/**
 * Module parameter that is an estimate of the maximum number of users
 * that will be concurrently using eCryptfs. Set this to the right
 * value to balance performance and memory use.
 */
unsigned int ecryptfs_number_of_users = ECRYPTFS_DEFAULT_NUM_USERS;

module_param(ecryptfs_number_of_users, uint, 0);
MODULE_PARM_DESC(ecryptfs_number_of_users, "An estimate of the number of "
		 "concurrent users of eCryptfs");

void __ecryptfs_printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (fmt[1] == '7') { /* KERN_DEBUG */
		if (ecryptfs_verbosity >= 1)
			vprintk(fmt, args);
	} else
		vprintk(fmt, args);
	va_end(args);
}

/**
 * ecryptfs_init_lower_file
 * @ecryptfs_dentry: Fully initialized eCryptfs dentry object, with
 *                   the lower dentry and the lower mount set
 *
 * eCryptfs only ever keeps a single open file for every lower
 * inode. All I/O operations to the lower inode occur through that
 * file. When the first eCryptfs dentry that interposes with the first
 * lower dentry for that inode is created, this function creates the
 * lower file struct and associates it with the eCryptfs
 * inode. When all eCryptfs files associated with the inode are released, the
 * file is closed.
 *
 * The lower file will be opened with read/write permissions, if
 * possible. Otherwise, it is opened read-only.
 *
 * This function does nothing if a lower file is already
 * associated with the eCryptfs inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_init_lower_file(struct dentry *dentry,
				    struct file **lower_file)
{
	const struct cred *cred = current_cred();
	struct path *path = ecryptfs_dentry_to_lower_path(dentry);
	int rc;

	rc = ecryptfs_privileged_open(lower_file, path->dentry, path->mnt,
				      cred);
	if (rc) {
		printk(KERN_ERR "Error opening lower file "
		       "for lower_dentry [0x%p] and lower_mnt [0x%p]; "
		       "rc = [%d]\n", path->dentry, path->mnt, rc);
		(*lower_file) = NULL;
	}
	return rc;
}

int ecryptfs_get_lower_file(struct dentry *dentry, struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info;
	int count, rc = 0;

	inode_info = ecryptfs_inode_to_private(inode);
	mutex_lock(&inode_info->lower_file_mutex);
	count = atomic_inc_return(&inode_info->lower_file_count);
	if (WARN_ON_ONCE(count < 1))
		rc = -EINVAL;
	else if (count == 1) {
		rc = ecryptfs_init_lower_file(dentry,
					      &inode_info->lower_file);
		if (rc)
			atomic_set(&inode_info->lower_file_count, 0);
	}
	mutex_unlock(&inode_info->lower_file_mutex);
	return rc;
}

void ecryptfs_put_lower_file(struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info;

	inode_info = ecryptfs_inode_to_private(inode);
	if (atomic_dec_and_mutex_lock(&inode_info->lower_file_count,
				      &inode_info->lower_file_mutex)) {
		filemap_write_and_wait(inode->i_mapping);
		fput(inode_info->lower_file);
		inode_info->lower_file = NULL;
		mutex_unlock(&inode_info->lower_file_mutex);
	}
}

enum { ecryptfs_opt_sig, ecryptfs_opt_ecryptfs_sig,
       ecryptfs_opt_cipher, ecryptfs_opt_ecryptfs_cipher,
       ecryptfs_opt_ecryptfs_key_bytes,
       ecryptfs_opt_passthrough, ecryptfs_opt_xattr_metadata,
       ecryptfs_opt_encrypted_view, ecryptfs_opt_fnek_sig,
       ecryptfs_opt_fn_cipher, ecryptfs_opt_fn_cipher_key_bytes,
       ecryptfs_opt_unlink_sigs, ecryptfs_opt_mount_auth_tok_only,
       ecryptfs_opt_check_dev_ruid,
       ecryptfs_opt_err };

static const match_table_t tokens = {
	{ecryptfs_opt_sig, "sig=%s"},
	{ecryptfs_opt_ecryptfs_sig, "ecryptfs_sig=%s"},
	{ecryptfs_opt_cipher, "cipher=%s"},
	{ecryptfs_opt_ecryptfs_cipher, "ecryptfs_cipher=%s"},
	{ecryptfs_opt_ecryptfs_key_bytes, "ecryptfs_key_bytes=%u"},
	{ecryptfs_opt_passthrough, "ecryptfs_passthrough"},
	{ecryptfs_opt_xattr_metadata, "ecryptfs_xattr_metadata"},
	{ecryptfs_opt_encrypted_view, "ecryptfs_encrypted_view"},
	{ecryptfs_opt_fnek_sig, "ecryptfs_fnek_sig=%s"},
	{ecryptfs_opt_fn_cipher, "ecryptfs_fn_cipher=%s"},
	{ecryptfs_opt_fn_cipher_key_bytes, "ecryptfs_fn_key_bytes=%u"},
	{ecryptfs_opt_unlink_sigs, "ecryptfs_unlink_sigs"},
	{ecryptfs_opt_mount_auth_tok_only, "ecryptfs_mount_auth_tok_only"},
	{ecryptfs_opt_check_dev_ruid, "ecryptfs_check_dev_ruid"},
	{ecryptfs_opt_err, NULL}
};

static int ecryptfs_init_global_auth_toks(
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	struct ecryptfs_global_auth_tok *global_auth_tok;
	struct ecryptfs_auth_tok *auth_tok;
	int rc = 0;

	list_for_each_entry(global_auth_tok,
			    &mount_crypt_stat->global_auth_tok_list,
			    mount_crypt_stat_list) {
		rc = ecryptfs_keyring_auth_tok_for_sig(
			&global_auth_tok->global_auth_tok_key, &auth_tok,
			global_auth_tok->sig);
		if (rc) {
			printk(KERN_ERR "Could not find valid key in user "
			       "session keyring for sig specified in mount "
			       "option: [%s]\n", global_auth_tok->sig);
			global_auth_tok->flags |= ECRYPTFS_AUTH_TOK_INVALID;
			goto out;
		} else {
			global_auth_tok->flags &= ~ECRYPTFS_AUTH_TOK_INVALID;
			up_write(&(global_auth_tok->global_auth_tok_key)->sem);
		}
	}
out:
	return rc;
}

static void ecryptfs_init_mount_crypt_stat(
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	memset((void *)mount_crypt_stat, 0,
	       sizeof(struct ecryptfs_mount_crypt_stat));
	INIT_LIST_HEAD(&mount_crypt_stat->global_auth_tok_list);
	mutex_init(&mount_crypt_stat->global_auth_tok_list_mutex);
	mount_crypt_stat->flags |= ECRYPTFS_MOUNT_CRYPT_STAT_INITIALIZED;
}

/**
 * ecryptfs_parse_options
 * @sb: The ecryptfs super block
 * @options: The options passed to the kernel
 * @check_ruid: set to 1 if device uid should be checked against the ruid
 *
 * Parse mount options:
 * debug=N 	   - ecryptfs_verbosity level for debug output
 * sig=XXX	   - description(signature) of the key to use
 *
 * Returns the dentry object of the lower-level (lower/interposed)
 * directory; We want to mount our stackable file system on top of
 * that lower directory.
 *
 * The signature of the key to use must be the description of a key
 * already in the keyring. Mounting will fail if the key can not be
 * found.
 *
 * Returns zero on success; non-zero on error
 */
static int ecryptfs_parse_options(struct ecryptfs_sb_info *sbi, char *options,
				  uid_t *check_ruid)
{
	char *p;
	int rc = 0;
	int sig_set = 0;
	int cipher_name_set = 0;
	int fn_cipher_name_set = 0;
	int cipher_key_bytes;
	int cipher_key_bytes_set = 0;
	int fn_cipher_key_bytes;
	int fn_cipher_key_bytes_set = 0;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&sbi->mount_crypt_stat;
	substring_t args[MAX_OPT_ARGS];
	int token;
	char *sig_src;
	char *cipher_name_dst;
	char *cipher_name_src;
	char *fn_cipher_name_dst;
	char *fn_cipher_name_src;
	char *fnek_dst;
	char *fnek_src;
	char *cipher_key_bytes_src;
	char *fn_cipher_key_bytes_src;
	u8 cipher_code;

	*check_ruid = 0;

	if (!options) {
		rc = -EINVAL;
		goto out;
	}
	ecryptfs_init_mount_crypt_stat(mount_crypt_stat);
	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case ecryptfs_opt_sig:
		case ecryptfs_opt_ecryptfs_sig:
			sig_src = args[0].from;
			rc = ecryptfs_add_global_auth_tok(mount_crypt_stat,
							  sig_src, 0);
			if (rc) {
				printk(KERN_ERR "Error attempting to register "
				       "global sig; rc = [%d]\n", rc);
				goto out;
			}
			sig_set = 1;
			break;
		case ecryptfs_opt_cipher:
		case ecryptfs_opt_ecryptfs_cipher:
			cipher_name_src = args[0].from;
			cipher_name_dst =
				mount_crypt_stat->
				global_default_cipher_name;
			strncpy(cipher_name_dst, cipher_name_src,
				ECRYPTFS_MAX_CIPHER_NAME_SIZE);
			cipher_name_dst[ECRYPTFS_MAX_CIPHER_NAME_SIZE] = '\0';
			cipher_name_set = 1;
			break;
		case ecryptfs_opt_ecryptfs_key_bytes:
			cipher_key_bytes_src = args[0].from;
			cipher_key_bytes =
				(int)simple_strtol(cipher_key_bytes_src,
						   &cipher_key_bytes_src, 0);
			mount_crypt_stat->global_default_cipher_key_size =
				cipher_key_bytes;
			cipher_key_bytes_set = 1;
			break;
		case ecryptfs_opt_passthrough:
			mount_crypt_stat->flags |=
				ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED;
			break;
		case ecryptfs_opt_xattr_metadata:
			mount_crypt_stat->flags |=
				ECRYPTFS_XATTR_METADATA_ENABLED;
			break;
		case ecryptfs_opt_encrypted_view:
			mount_crypt_stat->flags |=
				ECRYPTFS_XATTR_METADATA_ENABLED;
			mount_crypt_stat->flags |=
				ECRYPTFS_ENCRYPTED_VIEW_ENABLED;
			break;
		case ecryptfs_opt_fnek_sig:
			fnek_src = args[0].from;
			fnek_dst =
				mount_crypt_stat->global_default_fnek_sig;
			strncpy(fnek_dst, fnek_src, ECRYPTFS_SIG_SIZE_HEX);
			mount_crypt_stat->global_default_fnek_sig[
				ECRYPTFS_SIG_SIZE_HEX] = '\0';
			rc = ecryptfs_add_global_auth_tok(
				mount_crypt_stat,
				mount_crypt_stat->global_default_fnek_sig,
				ECRYPTFS_AUTH_TOK_FNEK);
			if (rc) {
				printk(KERN_ERR "Error attempting to register "
				       "global fnek sig [%s]; rc = [%d]\n",
				       mount_crypt_stat->global_default_fnek_sig,
				       rc);
				goto out;
			}
			mount_crypt_stat->flags |=
				(ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES
				 | ECRYPTFS_GLOBAL_ENCFN_USE_MOUNT_FNEK);
			break;
		case ecryptfs_opt_fn_cipher:
			fn_cipher_name_src = args[0].from;
			fn_cipher_name_dst =
				mount_crypt_stat->global_default_fn_cipher_name;
			strncpy(fn_cipher_name_dst, fn_cipher_name_src,
				ECRYPTFS_MAX_CIPHER_NAME_SIZE);
			mount_crypt_stat->global_default_fn_cipher_name[
				ECRYPTFS_MAX_CIPHER_NAME_SIZE] = '\0';
			fn_cipher_name_set = 1;
			break;
		case ecryptfs_opt_fn_cipher_key_bytes:
			fn_cipher_key_bytes_src = args[0].from;
			fn_cipher_key_bytes =
				(int)simple_strtol(fn_cipher_key_bytes_src,
						   &fn_cipher_key_bytes_src, 0);
			mount_crypt_stat->global_default_fn_cipher_key_bytes =
				fn_cipher_key_bytes;
			fn_cipher_key_bytes_set = 1;
			break;
		case ecryptfs_opt_unlink_sigs:
			mount_crypt_stat->flags |= ECRYPTFS_UNLINK_SIGS;
			break;
		case ecryptfs_opt_mount_auth_tok_only:
			mount_crypt_stat->flags |=
				ECRYPTFS_GLOBAL_MOUNT_AUTH_TOK_ONLY;
			break;
		case ecryptfs_opt_check_dev_ruid:
			*check_ruid = 1;
			break;
		case ecryptfs_opt_err:
		default:
			printk(KERN_WARNING
			       "%s: eCryptfs: unrecognized option [%s]\n",
			       __func__, p);
		}
	}
	if (!sig_set) {
		rc = -EINVAL;
		ecryptfs_printk(KERN_ERR, "You must supply at least one valid "
				"auth tok signature as a mount "
				"parameter; see the eCryptfs README\n");
		goto out;
	}
	if (!cipher_name_set) {
		int cipher_name_len = strlen(ECRYPTFS_DEFAULT_CIPHER);

		BUG_ON(cipher_name_len >= ECRYPTFS_MAX_CIPHER_NAME_SIZE);
		strcpy(mount_crypt_stat->global_default_cipher_name,
		       ECRYPTFS_DEFAULT_CIPHER);
	}
	if ((mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !fn_cipher_name_set)
		strcpy(mount_crypt_stat->global_default_fn_cipher_name,
		       mount_crypt_stat->global_default_cipher_name);
	if (!cipher_key_bytes_set)
		mount_crypt_stat->global_default_cipher_key_size = 0;
	if ((mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !fn_cipher_key_bytes_set)
		mount_crypt_stat->global_default_fn_cipher_key_bytes =
			mount_crypt_stat->global_default_cipher_key_size;

	cipher_code = ecryptfs_code_for_cipher_string(
		mount_crypt_stat->global_default_cipher_name,
		mount_crypt_stat->global_default_cipher_key_size);
	if (!cipher_code) {
		ecryptfs_printk(KERN_ERR,
				"eCryptfs doesn't support cipher: %s",
				mount_crypt_stat->global_default_cipher_name);
		rc = -EINVAL;
		goto out;
	}

	mutex_lock(&key_tfm_list_mutex);
	if (!ecryptfs_tfm_exists(mount_crypt_stat->global_default_cipher_name,
				 NULL)) {
		rc = ecryptfs_add_new_key_tfm(
			NULL, mount_crypt_stat->global_default_cipher_name,
			mount_crypt_stat->global_default_cipher_key_size);
		if (rc) {
			printk(KERN_ERR "Error attempting to initialize "
			       "cipher with name = [%s] and key size = [%td]; "
			       "rc = [%d]\n",
			       mount_crypt_stat->global_default_cipher_name,
			       mount_crypt_stat->global_default_cipher_key_size,
			       rc);
			rc = -EINVAL;
			mutex_unlock(&key_tfm_list_mutex);
			goto out;
		}
	}
	if ((mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !ecryptfs_tfm_exists(
		    mount_crypt_stat->global_default_fn_cipher_name, NULL)) {
		rc = ecryptfs_add_new_key_tfm(
			NULL, mount_crypt_stat->global_default_fn_cipher_name,
			mount_crypt_stat->global_default_fn_cipher_key_bytes);
		if (rc) {
			printk(KERN_ERR "Error attempting to initialize "
			       "cipher with name = [%s] and key size = [%td]; "
			       "rc = [%d]\n",
			       mount_crypt_stat->global_default_fn_cipher_name,
			       mount_crypt_stat->global_default_fn_cipher_key_bytes,
			       rc);
			rc = -EINVAL;
			mutex_unlock(&key_tfm_list_mutex);
			goto out;
		}
	}
	mutex_unlock(&key_tfm_list_mutex);
	rc = ecryptfs_init_global_auth_toks(mount_crypt_stat);
	if (rc)
		printk(KERN_WARNING "One or more global auth toks could not "
		       "properly register; rc = [%d]\n", rc);
out:
	return rc;
}

struct kmem_cache *ecryptfs_sb_info_cache;
static struct file_system_type ecryptfs_fs_type;

/**
 * ecryptfs_get_sb
 * @fs_type
 * @flags
 * @dev_name: The path to mount over
 * @raw_data: The options passed into the kernel
 */
static struct dentry *ecryptfs_mount(struct file_system_type *fs_type, int flags,
			const char *dev_name, void *raw_data)
{
	struct super_block *s;
	struct ecryptfs_sb_info *sbi;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	struct ecryptfs_dentry_info *root_info;
	const char *err = "Getting sb failed";
	struct inode *inode;
	struct path path;
	uid_t check_ruid;
	int rc;

	sbi = kmem_cache_zalloc(ecryptfs_sb_info_cache, GFP_KERNEL);
	if (!sbi) {
		rc = -ENOMEM;
		goto out;
	}

	rc = ecryptfs_parse_options(sbi, raw_data, &check_ruid);
	if (rc) {
		err = "Error parsing options";
		goto out;
	}
	mount_crypt_stat = &sbi->mount_crypt_stat;

	s = sget(fs_type, NULL, set_anon_super, flags, NULL);
	if (IS_ERR(s)) {
		rc = PTR_ERR(s);
		goto out;
	}

	rc = bdi_setup_and_register(&sbi->bdi, "ecryptfs");
	if (rc)
		goto out1;

	ecryptfs_set_superblock_private(s, sbi);
	s->s_bdi = &sbi->bdi;

	/* ->kill_sb() will take care of sbi after that point */
	sbi = NULL;
	s->s_op = &ecryptfs_sops;
	s->s_d_op = &ecryptfs_dops;

	err = "Reading sb failed";
	rc = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "kern_path() failed\n");
		goto out1;
	}
	if (path.dentry->d_sb->s_type == &ecryptfs_fs_type) {
		rc = -EINVAL;
		printk(KERN_ERR "Mount on filesystem of type "
			"eCryptfs explicitly disallowed due to "
			"known incompatibilities\n");
		goto out_free;
	}

	if (check_ruid && !uid_eq(path.dentry->d_inode->i_uid, current_uid())) {
		rc = -EPERM;
		printk(KERN_ERR "Mount of device (uid: %d) not owned by "
		       "requested user (uid: %d)\n",
			i_uid_read(path.dentry->d_inode),
			from_kuid(&init_user_ns, current_uid()));
		goto out_free;
	}

	ecryptfs_set_superblock_lower(s, path.dentry->d_sb);

	/**
	 * Set the POSIX ACL flag based on whether they're enabled in the lower
	 * mount.
	 */
	s->s_flags = flags & ~MS_POSIXACL;
	s->s_flags |= path.dentry->d_sb->s_flags & MS_POSIXACL;

	/**
	 * Force a read-only eCryptfs mount when:
	 *   1) The lower mount is ro
	 *   2) The ecryptfs_encrypted_view mount option is specified
	 */
	if (path.dentry->d_sb->s_flags & MS_RDONLY ||
	    mount_crypt_stat->flags & ECRYPTFS_ENCRYPTED_VIEW_ENABLED)
		s->s_flags |= MS_RDONLY;

	s->s_maxbytes = path.dentry->d_sb->s_maxbytes;
	s->s_blocksize = path.dentry->d_sb->s_blocksize;
	s->s_magic = ECRYPTFS_SUPER_MAGIC;
	s->s_stack_depth = path.dentry->d_sb->s_stack_depth + 1;

	rc = -EINVAL;
	if (s->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("eCryptfs: maximum fs stacking depth exceeded\n");
		goto out_free;
	}

	inode = ecryptfs_get_inode(path.dentry->d_inode, s);
	rc = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_free;

	s->s_root = d_make_root(inode);
	if (!s->s_root) {
		rc = -ENOMEM;
		goto out_free;
	}

	rc = -ENOMEM;
	root_info = kmem_cache_zalloc(ecryptfs_dentry_info_cache, GFP_KERNEL);
	if (!root_info)
		goto out_free;

	/* ->kill_sb() will take care of root_info */
	ecryptfs_set_dentry_private(s->s_root, root_info);
	root_info->lower_path = path;

	s->s_flags |= MS_ACTIVE;
	return dget(s->s_root);

out_free:
	path_put(&path);
out1:
	deactivate_locked_super(s);
out:
	if (sbi) {
		ecryptfs_destroy_mount_crypt_stat(&sbi->mount_crypt_stat);
		kmem_cache_free(ecryptfs_sb_info_cache, sbi);
	}
	printk(KERN_ERR "%s; rc = [%d]\n", err, rc);
	return ERR_PTR(rc);
}

/**
 * ecryptfs_kill_block_super
 * @sb: The ecryptfs super block
 *
 * Used to bring the superblock down and free the private data.
 */
static void ecryptfs_kill_block_super(struct super_block *sb)
{
	struct ecryptfs_sb_info *sb_info = ecryptfs_superblock_to_private(sb);
	kill_anon_super(sb);
	if (!sb_info)
		return;
	ecryptfs_destroy_mount_crypt_stat(&sb_info->mount_crypt_stat);
	bdi_destroy(&sb_info->bdi);
	kmem_cache_free(ecryptfs_sb_info_cache, sb_info);
}

static struct file_system_type ecryptfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "ecryptfs",
	.mount = ecryptfs_mount,
	.kill_sb = ecryptfs_kill_block_super,
	.fs_flags = 0
};
MODULE_ALIAS_FS("ecryptfs");

/**
 * inode_info_init_once
 *
 * Initializes the ecryptfs_inode_info_cache when it is created
 */
static void
inode_info_init_once(void *vptr)
{
	struct ecryptfs_inode_info *ei = (struct ecryptfs_inode_info *)vptr;

	inode_init_once(&ei->vfs_inode);
}

static struct ecryptfs_cache_info {
	struct kmem_cache **cache;
	const char *name;
	size_t size;
	void (*ctor)(void *obj);
} ecryptfs_cache_infos[] = {
	{
		.cache = &ecryptfs_auth_tok_list_item_cache,
		.name = "ecryptfs_auth_tok_list_item",
		.size = sizeof(struct ecryptfs_auth_tok_list_item),
	},
	{
		.cache = &ecryptfs_file_info_cache,
		.name = "ecryptfs_file_cache",
		.size = sizeof(struct ecryptfs_file_info),
	},
	{
		.cache = &ecryptfs_dentry_info_cache,
		.name = "ecryptfs_dentry_info_cache",
		.size = sizeof(struct ecryptfs_dentry_info),
	},
	{
		.cache = &ecryptfs_inode_info_cache,
		.name = "ecryptfs_inode_cache",
		.size = sizeof(struct ecryptfs_inode_info),
		.ctor = inode_info_init_once,
	},
	{
		.cache = &ecryptfs_sb_info_cache,
		.name = "ecryptfs_sb_cache",
		.size = sizeof(struct ecryptfs_sb_info),
	},
	{
		.cache = &ecryptfs_header_cache,
		.name = "ecryptfs_headers",
		.size = PAGE_CACHE_SIZE,
	},
	{
		.cache = &ecryptfs_xattr_cache,
		.name = "ecryptfs_xattr_cache",
		.size = PAGE_CACHE_SIZE,
	},
	{
		.cache = &ecryptfs_key_record_cache,
		.name = "ecryptfs_key_record_cache",
		.size = sizeof(struct ecryptfs_key_record),
	},
	{
		.cache = &ecryptfs_key_sig_cache,
		.name = "ecryptfs_key_sig_cache",
		.size = sizeof(struct ecryptfs_key_sig),
	},
	{
		.cache = &ecryptfs_global_auth_tok_cache,
		.name = "ecryptfs_global_auth_tok_cache",
		.size = sizeof(struct ecryptfs_global_auth_tok),
	},
	{
		.cache = &ecryptfs_key_tfm_cache,
		.name = "ecryptfs_key_tfm_cache",
		.size = sizeof(struct ecryptfs_key_tfm),
	},
};

static void ecryptfs_free_kmem_caches(void)
{
	int i;

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();

	for (i = 0; i < ARRAY_SIZE(ecryptfs_cache_infos); i++) {
		struct ecryptfs_cache_info *info;

		info = &ecryptfs_cache_infos[i];
		if (*(info->cache))
			kmem_cache_destroy(*(info->cache));
	}
}

/**
 * ecryptfs_init_kmem_caches
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_init_kmem_caches(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ecryptfs_cache_infos); i++) {
		struct ecryptfs_cache_info *info;

		info = &ecryptfs_cache_infos[i];
		*(info->cache) = kmem_cache_create(info->name, info->size,
				0, SLAB_HWCACHE_ALIGN, info->ctor);
		if (!*(info->cache)) {
			ecryptfs_free_kmem_caches();
			ecryptfs_printk(KERN_WARNING, "%s: "
					"kmem_cache_create failed\n",
					info->name);
			return -ENOMEM;
		}
	}
	return 0;
}

static struct kobject *ecryptfs_kobj;

static ssize_t version_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buff)
{
	return snprintf(buff, PAGE_SIZE, "%d\n", ECRYPTFS_VERSIONING_MASK);
}

static struct kobj_attribute version_attr = __ATTR_RO(version);

static struct attribute *attributes[] = {
	&version_attr.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attributes,
};

static int do_sysfs_registration(void)
{
	int rc;

	ecryptfs_kobj = kobject_create_and_add("ecryptfs", fs_kobj);
	if (!ecryptfs_kobj) {
		printk(KERN_ERR "Unable to create ecryptfs kset\n");
		rc = -ENOMEM;
		goto out;
	}
	rc = sysfs_create_group(ecryptfs_kobj, &attr_group);
	if (rc) {
		printk(KERN_ERR
		       "Unable to create ecryptfs version attributes\n");
		kobject_put(ecryptfs_kobj);
	}
out:
	return rc;
}

static void do_sysfs_unregistration(void)
{
	sysfs_remove_group(ecryptfs_kobj, &attr_group);
	kobject_put(ecryptfs_kobj);
}

static int __init ecryptfs_init(void)
{
	int rc;

	if (ECRYPTFS_DEFAULT_EXTENT_SIZE > PAGE_CACHE_SIZE) {
		rc = -EINVAL;
		ecryptfs_printk(KERN_ERR, "The eCryptfs extent size is "
				"larger than the host's page size, and so "
				"eCryptfs cannot run on this system. The "
				"default eCryptfs extent size is [%u] bytes; "
				"the page size is [%lu] bytes.\n",
				ECRYPTFS_DEFAULT_EXTENT_SIZE,
				(unsigned long)PAGE_CACHE_SIZE);
		goto out;
	}
	rc = ecryptfs_init_kmem_caches();
	if (rc) {
		printk(KERN_ERR
		       "Failed to allocate one or more kmem_cache objects\n");
		goto out;
	}
	rc = do_sysfs_registration();
	if (rc) {
		printk(KERN_ERR "sysfs registration failed\n");
		goto out_free_kmem_caches;
	}
	rc = ecryptfs_init_kthread();
	if (rc) {
		printk(KERN_ERR "%s: kthread initialization failed; "
		       "rc = [%d]\n", __func__, rc);
		goto out_do_sysfs_unregistration;
	}
	rc = ecryptfs_init_messaging();
	if (rc) {
		printk(KERN_ERR "Failure occurred while attempting to "
				"initialize the communications channel to "
				"ecryptfsd\n");
		goto out_destroy_kthread;
	}
	rc = ecryptfs_init_crypto();
	if (rc) {
		printk(KERN_ERR "Failure whilst attempting to init crypto; "
		       "rc = [%d]\n", rc);
		goto out_release_messaging;
	}
	rc = register_filesystem(&ecryptfs_fs_type);
	if (rc) {
		printk(KERN_ERR "Failed to register filesystem\n");
		goto out_destroy_crypto;
	}
	if (ecryptfs_verbosity > 0)
		printk(KERN_CRIT "eCryptfs verbosity set to %d. Secret values "
			"will be written to the syslog!\n", ecryptfs_verbosity);

	goto out;
out_destroy_crypto:
	ecryptfs_destroy_crypto();
out_release_messaging:
	ecryptfs_release_messaging();
out_destroy_kthread:
	ecryptfs_destroy_kthread();
out_do_sysfs_unregistration:
	do_sysfs_unregistration();
out_free_kmem_caches:
	ecryptfs_free_kmem_caches();
out:
	return rc;
}

static void __exit ecryptfs_exit(void)
{
	int rc;

	rc = ecryptfs_destroy_crypto();
	if (rc)
		printk(KERN_ERR "Failure whilst attempting to destroy crypto; "
		       "rc = [%d]\n", rc);
	ecryptfs_release_messaging();
	ecryptfs_destroy_kthread();
	do_sysfs_unregistration();
	unregister_filesystem(&ecryptfs_fs_type);
	ecryptfs_free_kmem_caches();
}

MODULE_AUTHOR("Michael A. Halcrow <mhalcrow@us.ibm.com>");
MODULE_DESCRIPTION("eCryptfs");

MODULE_LICENSE("GPL");

module_init(ecryptfs_init)
module_exit(ecryptfs_exit)
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/main.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Michael C. Thompson <mcthomps@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/fs.h>
// #include <linux/mount.h>
// #include <linux/key.h>
// #include <linux/slab.h>
#include <linux/seq_file.h>
// #include <linux/file.h>
// #include <linux/crypto.h>
#include <linux/statfs.h>
// #include <linux/magic.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

struct kmem_cache *ecryptfs_inode_info_cache;

/**
 * ecryptfs_alloc_inode - allocate an ecryptfs inode
 * @sb: Pointer to the ecryptfs super block
 *
 * Called to bring an inode into existence.
 *
 * Only handle allocation, setting up structures should be done in
 * ecryptfs_read_inode. This is because the kernel, between now and
 * then, will 0 out the private data pointer.
 *
 * Returns a pointer to a newly allocated inode, NULL otherwise
 */
static struct inode *ecryptfs_alloc_inode(struct super_block *sb)
{
	struct ecryptfs_inode_info *inode_info;
	struct inode *inode = NULL;

	inode_info = kmem_cache_alloc(ecryptfs_inode_info_cache, GFP_KERNEL);
	if (unlikely(!inode_info))
		goto out;
	ecryptfs_init_crypt_stat(&inode_info->crypt_stat);
	mutex_init(&inode_info->lower_file_mutex);
	atomic_set(&inode_info->lower_file_count, 0);
	inode_info->lower_file = NULL;
	inode = &inode_info->vfs_inode;
out:
	return inode;
}

static void ecryptfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct ecryptfs_inode_info *inode_info;
	inode_info = ecryptfs_inode_to_private(inode);

	kmem_cache_free(ecryptfs_inode_info_cache, inode_info);
}

/**
 * ecryptfs_destroy_inode
 * @inode: The ecryptfs inode
 *
 * This is used during the final destruction of the inode.  All
 * allocation of memory related to the inode, including allocated
 * memory in the crypt_stat struct, will be released here.
 * There should be no chance that this deallocation will be missed.
 */
static void ecryptfs_destroy_inode(struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info;

	inode_info = ecryptfs_inode_to_private(inode);
	BUG_ON(inode_info->lower_file);
	ecryptfs_destroy_crypt_stat(&inode_info->crypt_stat);
	call_rcu(&inode->i_rcu, ecryptfs_i_callback);
}

/**
 * ecryptfs_statfs
 * @sb: The ecryptfs super block
 * @buf: The struct kstatfs to fill in with stats
 *
 * Get the filesystem statistics. Currently, we let this pass right through
 * to the lower filesystem and take no action ourselves.
 */
static int ecryptfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct dentry *lower_dentry = ecryptfs_dentry_to_lower(dentry);
	int rc;

	if (!lower_dentry->d_sb->s_op->statfs)
		return -ENOSYS;

	rc = lower_dentry->d_sb->s_op->statfs(lower_dentry, buf);
	if (rc)
		return rc;

	buf->f_type = ECRYPTFS_SUPER_MAGIC;
	rc = ecryptfs_set_f_namelen(&buf->f_namelen, buf->f_namelen,
	       &ecryptfs_superblock_to_private(dentry->d_sb)->mount_crypt_stat);

	return rc;
}

/**
 * ecryptfs_evict_inode
 * @inode - The ecryptfs inode
 *
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list. We use this to drop out reference to the
 * lower inode.
 */
static void ecryptfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	iput(ecryptfs_inode_to_lower(inode));
}

/**
 * ecryptfs_show_options
 *
 * Prints the mount options for a given superblock.
 * Returns zero; does not fail.
 */
static int ecryptfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(sb)->mount_crypt_stat;
	struct ecryptfs_global_auth_tok *walker;

	mutex_lock(&mount_crypt_stat->global_auth_tok_list_mutex);
	list_for_each_entry(walker,
			    &mount_crypt_stat->global_auth_tok_list,
			    mount_crypt_stat_list) {
		if (walker->flags & ECRYPTFS_AUTH_TOK_FNEK)
			seq_printf(m, ",ecryptfs_fnek_sig=%s", walker->sig);
		else
			seq_printf(m, ",ecryptfs_sig=%s", walker->sig);
	}
	mutex_unlock(&mount_crypt_stat->global_auth_tok_list_mutex);

	seq_printf(m, ",ecryptfs_cipher=%s",
		mount_crypt_stat->global_default_cipher_name);

	if (mount_crypt_stat->global_default_cipher_key_size)
		seq_printf(m, ",ecryptfs_key_bytes=%zd",
			   mount_crypt_stat->global_default_cipher_key_size);
	if (mount_crypt_stat->flags & ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED)
		seq_printf(m, ",ecryptfs_passthrough");
	if (mount_crypt_stat->flags & ECRYPTFS_XATTR_METADATA_ENABLED)
		seq_printf(m, ",ecryptfs_xattr_metadata");
	if (mount_crypt_stat->flags & ECRYPTFS_ENCRYPTED_VIEW_ENABLED)
		seq_printf(m, ",ecryptfs_encrypted_view");
	if (mount_crypt_stat->flags & ECRYPTFS_UNLINK_SIGS)
		seq_printf(m, ",ecryptfs_unlink_sigs");
	if (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_MOUNT_AUTH_TOK_ONLY)
		seq_printf(m, ",ecryptfs_mount_auth_tok_only");

	return 0;
}

const struct super_operations ecryptfs_sops = {
	.alloc_inode = ecryptfs_alloc_inode,
	.destroy_inode = ecryptfs_destroy_inode,
	.statfs = ecryptfs_statfs,
	.remount_fs = NULL,
	.evict_inode = ecryptfs_evict_inode,
	.show_options = ecryptfs_show_options
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/super.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 * This is where eCryptfs coordinates the symmetric encryption and
 * decryption of the file data as it passes between the lower
 * encrypted file and the upper decrypted file.
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

// #include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/page-flags.h>
// #include <linux/mount.h>
// #include <linux/file.h>
// #include <linux/crypto.h>
#include <linux/scatterlist.h>
// #include <linux/slab.h>
// #include <asm/unaligned.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

/**
 * ecryptfs_get_locked_page
 *
 * Get one page from cache or lower f/s, return error otherwise.
 *
 * Returns locked and up-to-date page (if ok), with increased
 * refcnt.
 */
struct page *ecryptfs_get_locked_page(struct inode *inode, loff_t index)
{
	struct page *page = read_mapping_page(inode->i_mapping, index, NULL);
	if (!IS_ERR(page))
		lock_page(page);
	return page;
}

/**
 * ecryptfs_writepage
 * @page: Page that is locked before this call is made
 *
 * Returns zero on success; non-zero otherwise
 *
 * This is where we encrypt the data and pass the encrypted data to
 * the lower filesystem.  In OpenPGP-compatible mode, we operate on
 * entire underlying packets.
 */
static int ecryptfs_writepage(struct page *page, struct writeback_control *wbc)
{
	int rc;

	rc = ecryptfs_encrypt_page(page);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error encrypting "
				"page (upper index [0x%.16lx])\n", page->index);
		ClearPageUptodate(page);
		goto out;
	}
	SetPageUptodate(page);
out:
	unlock_page(page);
	return rc;
}

static void strip_xattr_flag(char *page_virt,
			     struct ecryptfs_crypt_stat *crypt_stat)
{
	if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR) {
		size_t written;

		crypt_stat->flags &= ~ECRYPTFS_METADATA_IN_XATTR;
		ecryptfs_write_crypt_stat_flags(page_virt, crypt_stat,
						&written);
		crypt_stat->flags |= ECRYPTFS_METADATA_IN_XATTR;
	}
}

/**
 *   Header Extent:
 *     Octets 0-7:        Unencrypted file size (big-endian)
 *     Octets 8-15:       eCryptfs special marker
 *     Octets 16-19:      Flags
 *      Octet 16:         File format version number (between 0 and 255)
 *      Octets 17-18:     Reserved
 *      Octet 19:         Bit 1 (lsb): Reserved
 *                        Bit 2: Encrypted?
 *                        Bits 3-8: Reserved
 *     Octets 20-23:      Header extent size (big-endian)
 *     Octets 24-25:      Number of header extents at front of file
 *                        (big-endian)
 *     Octet  26:         Begin RFC 2440 authentication token packet set
 */

/**
 * ecryptfs_copy_up_encrypted_with_header
 * @page: Sort of a ``virtual'' representation of the encrypted lower
 *        file. The actual lower file does not have the metadata in
 *        the header. This is locked.
 * @crypt_stat: The eCryptfs inode's cryptographic context
 *
 * The ``view'' is the version of the file that userspace winds up
 * seeing, with the header information inserted.
 */
static int
ecryptfs_copy_up_encrypted_with_header(struct page *page,
				       struct ecryptfs_crypt_stat *crypt_stat)
{
	loff_t extent_num_in_page = 0;
	loff_t num_extents_per_page = (PAGE_CACHE_SIZE
				       / crypt_stat->extent_size);
	int rc = 0;

	while (extent_num_in_page < num_extents_per_page) {
		loff_t view_extent_num = ((((loff_t)page->index)
					   * num_extents_per_page)
					  + extent_num_in_page);
		size_t num_header_extents_at_front =
			(crypt_stat->metadata_size / crypt_stat->extent_size);

		if (view_extent_num < num_header_extents_at_front) {
			/* This is a header extent */
			char *page_virt;

			page_virt = kmap_atomic(page);
			memset(page_virt, 0, PAGE_CACHE_SIZE);
			/* TODO: Support more than one header extent */
			if (view_extent_num == 0) {
				size_t written;

				rc = ecryptfs_read_xattr_region(
					page_virt, page->mapping->host);
				strip_xattr_flag(page_virt + 16, crypt_stat);
				ecryptfs_write_header_metadata(page_virt + 20,
							       crypt_stat,
							       &written);
			}
			kunmap_atomic(page_virt);
			flush_dcache_page(page);
			if (rc) {
				printk(KERN_ERR "%s: Error reading xattr "
				       "region; rc = [%d]\n", __func__, rc);
				goto out;
			}
		} else {
			/* This is an encrypted data extent */
			loff_t lower_offset =
				((view_extent_num * crypt_stat->extent_size)
				 - crypt_stat->metadata_size);

			rc = ecryptfs_read_lower_page_segment(
				page, (lower_offset >> PAGE_CACHE_SHIFT),
				(lower_offset & ~PAGE_CACHE_MASK),
				crypt_stat->extent_size, page->mapping->host);
			if (rc) {
				printk(KERN_ERR "%s: Error attempting to read "
				       "extent at offset [%lld] in the lower "
				       "file; rc = [%d]\n", __func__,
				       lower_offset, rc);
				goto out;
			}
		}
		extent_num_in_page++;
	}
out:
	return rc;
}

/**
 * ecryptfs_readpage
 * @file: An eCryptfs file
 * @page: Page from eCryptfs inode mapping into which to stick the read data
 *
 * Read in a page, decrypting if necessary.
 *
 * Returns zero on success; non-zero on error.
 */
static int ecryptfs_readpage(struct file *file, struct page *page)
{
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(page->mapping->host)->crypt_stat;
	int rc = 0;

	if (!crypt_stat || !(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		rc = ecryptfs_read_lower_page_segment(page, page->index, 0,
						      PAGE_CACHE_SIZE,
						      page->mapping->host);
	} else if (crypt_stat->flags & ECRYPTFS_VIEW_AS_ENCRYPTED) {
		if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR) {
			rc = ecryptfs_copy_up_encrypted_with_header(page,
								    crypt_stat);
			if (rc) {
				printk(KERN_ERR "%s: Error attempting to copy "
				       "the encrypted content from the lower "
				       "file whilst inserting the metadata "
				       "from the xattr into the header; rc = "
				       "[%d]\n", __func__, rc);
				goto out;
			}

		} else {
			rc = ecryptfs_read_lower_page_segment(
				page, page->index, 0, PAGE_CACHE_SIZE,
				page->mapping->host);
			if (rc) {
				printk(KERN_ERR "Error reading page; rc = "
				       "[%d]\n", rc);
				goto out;
			}
		}
	} else {
		rc = ecryptfs_decrypt_page(page);
		if (rc) {
			ecryptfs_printk(KERN_ERR, "Error decrypting page; "
					"rc = [%d]\n", rc);
			goto out;
		}
	}
out:
	if (rc)
		ClearPageUptodate(page);
	else
		SetPageUptodate(page);
	ecryptfs_printk(KERN_DEBUG, "Unlocking page with index = [0x%.16lx]\n",
			page->index);
	unlock_page(page);
	return rc;
}

/**
 * Called with lower inode mutex held.
 */
static int fill_zeros_to_end_of_page(struct page *page, unsigned int to)
{
	struct inode *inode = page->mapping->host;
	int end_byte_in_page;

	if ((i_size_read(inode) / PAGE_CACHE_SIZE) != page->index)
		goto out;
	end_byte_in_page = i_size_read(inode) % PAGE_CACHE_SIZE;
	if (to > end_byte_in_page)
		end_byte_in_page = to;
	zero_user_segment(page, end_byte_in_page, PAGE_CACHE_SIZE);
out:
	return 0;
}

/**
 * ecryptfs_write_begin
 * @file: The eCryptfs file
 * @mapping: The eCryptfs object
 * @pos: The file offset at which to start writing
 * @len: Length of the write
 * @flags: Various flags
 * @pagep: Pointer to return the page
 * @fsdata: Pointer to return fs data (unused)
 *
 * This function must zero any hole we create
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_write_begin(struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	loff_t prev_page_end_size;
	int rc = 0;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	prev_page_end_size = ((loff_t)index << PAGE_CACHE_SHIFT);
	if (!PageUptodate(page)) {
		struct ecryptfs_crypt_stat *crypt_stat =
			&ecryptfs_inode_to_private(mapping->host)->crypt_stat;

		if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
			rc = ecryptfs_read_lower_page_segment(
				page, index, 0, PAGE_CACHE_SIZE, mapping->host);
			if (rc) {
				printk(KERN_ERR "%s: Error attemping to read "
				       "lower page segment; rc = [%d]\n",
				       __func__, rc);
				ClearPageUptodate(page);
				goto out;
			} else
				SetPageUptodate(page);
		} else if (crypt_stat->flags & ECRYPTFS_VIEW_AS_ENCRYPTED) {
			if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR) {
				rc = ecryptfs_copy_up_encrypted_with_header(
					page, crypt_stat);
				if (rc) {
					printk(KERN_ERR "%s: Error attempting "
					       "to copy the encrypted content "
					       "from the lower file whilst "
					       "inserting the metadata from "
					       "the xattr into the header; rc "
					       "= [%d]\n", __func__, rc);
					ClearPageUptodate(page);
					goto out;
				}
				SetPageUptodate(page);
			} else {
				rc = ecryptfs_read_lower_page_segment(
					page, index, 0, PAGE_CACHE_SIZE,
					mapping->host);
				if (rc) {
					printk(KERN_ERR "%s: Error reading "
					       "page; rc = [%d]\n",
					       __func__, rc);
					ClearPageUptodate(page);
					goto out;
				}
				SetPageUptodate(page);
			}
		} else {
			if (prev_page_end_size
			    >= i_size_read(page->mapping->host)) {
				zero_user(page, 0, PAGE_CACHE_SIZE);
				SetPageUptodate(page);
			} else if (len < PAGE_CACHE_SIZE) {
				rc = ecryptfs_decrypt_page(page);
				if (rc) {
					printk(KERN_ERR "%s: Error decrypting "
					       "page at index [%ld]; "
					       "rc = [%d]\n",
					       __func__, page->index, rc);
					ClearPageUptodate(page);
					goto out;
				}
				SetPageUptodate(page);
			}
		}
	}
	/* If creating a page or more of holes, zero them out via truncate.
	 * Note, this will increase i_size. */
	if (index != 0) {
		if (prev_page_end_size > i_size_read(page->mapping->host)) {
			rc = ecryptfs_truncate(file->f_path.dentry,
					       prev_page_end_size);
			if (rc) {
				printk(KERN_ERR "%s: Error on attempt to "
				       "truncate to (higher) offset [%lld];"
				       " rc = [%d]\n", __func__,
				       prev_page_end_size, rc);
				goto out;
			}
		}
	}
	/* Writing to a new page, and creating a small hole from start
	 * of page?  Zero it out. */
	if ((i_size_read(mapping->host) == prev_page_end_size)
	    && (pos != 0))
		zero_user(page, 0, PAGE_CACHE_SIZE);
out:
	if (unlikely(rc)) {
		unlock_page(page);
		page_cache_release(page);
		*pagep = NULL;
	}
	return rc;
}

/**
 * ecryptfs_write_inode_size_to_header
 *
 * Writes the lower file size to the first 8 bytes of the header.
 *
 * Returns zero on success; non-zero on error.
 */
static int ecryptfs_write_inode_size_to_header(struct inode *ecryptfs_inode)
{
	char *file_size_virt;
	int rc;

	file_size_virt = kmalloc(sizeof(u64), GFP_KERNEL);
	if (!file_size_virt) {
		rc = -ENOMEM;
		goto out;
	}
	put_unaligned_be64(i_size_read(ecryptfs_inode), file_size_virt);
	rc = ecryptfs_write_lower(ecryptfs_inode, file_size_virt, 0,
				  sizeof(u64));
	kfree(file_size_virt);
	if (rc < 0)
		printk(KERN_ERR "%s: Error writing file size to header; "
		       "rc = [%d]\n", __func__, rc);
	else
		rc = 0;
out:
	return rc;
}

struct kmem_cache *ecryptfs_xattr_cache;

static int ecryptfs_write_inode_size_to_xattr(struct inode *ecryptfs_inode)
{
	ssize_t size;
	void *xattr_virt;
	struct dentry *lower_dentry =
		ecryptfs_inode_to_private(ecryptfs_inode)->lower_file->f_path.dentry;
	struct inode *lower_inode = lower_dentry->d_inode;
	int rc;

	if (!lower_inode->i_op->getxattr || !lower_inode->i_op->setxattr) {
		printk(KERN_WARNING
		       "No support for setting xattr in lower filesystem\n");
		rc = -ENOSYS;
		goto out;
	}
	xattr_virt = kmem_cache_alloc(ecryptfs_xattr_cache, GFP_KERNEL);
	if (!xattr_virt) {
		printk(KERN_ERR "Out of memory whilst attempting to write "
		       "inode size to xattr\n");
		rc = -ENOMEM;
		goto out;
	}
	mutex_lock(&lower_inode->i_mutex);
	size = lower_inode->i_op->getxattr(lower_dentry, ECRYPTFS_XATTR_NAME,
					   xattr_virt, PAGE_CACHE_SIZE);
	if (size < 0)
		size = 8;
	put_unaligned_be64(i_size_read(ecryptfs_inode), xattr_virt);
	rc = lower_inode->i_op->setxattr(lower_dentry, ECRYPTFS_XATTR_NAME,
					 xattr_virt, size, 0);
	mutex_unlock(&lower_inode->i_mutex);
	if (rc)
		printk(KERN_ERR "Error whilst attempting to write inode size "
		       "to lower file xattr; rc = [%d]\n", rc);
	kmem_cache_free(ecryptfs_xattr_cache, xattr_virt);
out:
	return rc;
}

int ecryptfs_write_inode_size_to_metadata(struct inode *ecryptfs_inode)
{
	struct ecryptfs_crypt_stat *crypt_stat;

	crypt_stat = &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	BUG_ON(!(crypt_stat->flags & ECRYPTFS_ENCRYPTED));
	if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR)
		return ecryptfs_write_inode_size_to_xattr(ecryptfs_inode);
	else
		return ecryptfs_write_inode_size_to_header(ecryptfs_inode);
}

/**
 * ecryptfs_write_end
 * @file: The eCryptfs file object
 * @mapping: The eCryptfs object
 * @pos: The file position
 * @len: The length of the data (unused)
 * @copied: The amount of data copied
 * @page: The eCryptfs page
 * @fsdata: The fsdata (unused)
 */
static int ecryptfs_write_end(struct file *file,
			struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned to = from + copied;
	struct inode *ecryptfs_inode = mapping->host;
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	int rc;

	ecryptfs_printk(KERN_DEBUG, "Calling fill_zeros_to_end_of_page"
			"(page w/ index = [0x%.16lx], to = [%d])\n", index, to);
	if (!(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		rc = ecryptfs_write_lower_page_segment(ecryptfs_inode, page, 0,
						       to);
		if (!rc) {
			rc = copied;
			fsstack_copy_inode_size(ecryptfs_inode,
				ecryptfs_inode_to_lower(ecryptfs_inode));
		}
		goto out;
	}
	if (!PageUptodate(page)) {
		if (copied < PAGE_CACHE_SIZE) {
			rc = 0;
			goto out;
		}
		SetPageUptodate(page);
	}
	/* Fills in zeros if 'to' goes beyond inode size */
	rc = fill_zeros_to_end_of_page(page, to);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error attempting to fill "
			"zeros in page with index = [0x%.16lx]\n", index);
		goto out;
	}
	rc = ecryptfs_encrypt_page(page);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error encrypting page (upper "
				"index [0x%.16lx])\n", index);
		goto out;
	}
	if (pos + copied > i_size_read(ecryptfs_inode)) {
		i_size_write(ecryptfs_inode, pos + copied);
		ecryptfs_printk(KERN_DEBUG, "Expanded file size to "
			"[0x%.16llx]\n",
			(unsigned long long)i_size_read(ecryptfs_inode));
	}
	rc = ecryptfs_write_inode_size_to_metadata(ecryptfs_inode);
	if (rc)
		printk(KERN_ERR "Error writing inode size to metadata; "
		       "rc = [%d]\n", rc);
	else
		rc = copied;
out:
	unlock_page(page);
	page_cache_release(page);
	return rc;
}

static sector_t ecryptfs_bmap(struct address_space *mapping, sector_t block)
{
	int rc = 0;
	struct inode *inode;
	struct inode *lower_inode;

	inode = (struct inode *)mapping->host;
	lower_inode = ecryptfs_inode_to_lower(inode);
	if (lower_inode->i_mapping->a_ops->bmap)
		rc = lower_inode->i_mapping->a_ops->bmap(lower_inode->i_mapping,
							 block);
	return rc;
}

const struct address_space_operations ecryptfs_aops = {
	.writepage = ecryptfs_writepage,
	.readpage = ecryptfs_readpage,
	.write_begin = ecryptfs_write_begin,
	.write_end = ecryptfs_write_end,
	.bmap = ecryptfs_bmap,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/mmap.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

// #include <linux/fs.h>
// #include <linux/pagemap.h>
// #include "ecryptfs_kernel.h"

/**
 * ecryptfs_write_lower
 * @ecryptfs_inode: The eCryptfs inode
 * @data: Data to write
 * @offset: Byte offset in the lower file to which to write the data
 * @size: Number of bytes from @data to write at @offset in the lower
 *        file
 *
 * Write data to the lower file.
 *
 * Returns bytes written on success; less than zero on error
 */
int ecryptfs_write_lower(struct inode *ecryptfs_inode, char *data,
			 loff_t offset, size_t size)
{
	struct file *lower_file;
	ssize_t rc;

	lower_file = ecryptfs_inode_to_private(ecryptfs_inode)->lower_file;
	if (!lower_file)
		return -EIO;
	rc = kernel_write(lower_file, data, size, offset);
	mark_inode_dirty_sync(ecryptfs_inode);
	return rc;
}

/**
 * ecryptfs_write_lower_page_segment
 * @ecryptfs_inode: The eCryptfs inode
 * @page_for_lower: The page containing the data to be written to the
 *                  lower file
 * @offset_in_page: The offset in the @page_for_lower from which to
 *                  start writing the data
 * @size: The amount of data from @page_for_lower to write to the
 *        lower file
 *
 * Determines the byte offset in the file for the given page and
 * offset within the page, maps the page, and makes the call to write
 * the contents of @page_for_lower to the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_write_lower_page_segment(struct inode *ecryptfs_inode,
				      struct page *page_for_lower,
				      size_t offset_in_page, size_t size)
{
	char *virt;
	loff_t offset;
	int rc;

	offset = ((((loff_t)page_for_lower->index) << PAGE_CACHE_SHIFT)
		  + offset_in_page);
	virt = kmap(page_for_lower);
	rc = ecryptfs_write_lower(ecryptfs_inode, virt, offset, size);
	if (rc > 0)
		rc = 0;
	kunmap(page_for_lower);
	return rc;
}

/**
 * ecryptfs_write
 * @ecryptfs_inode: The eCryptfs file into which to write
 * @data: Virtual address where data to write is located
 * @offset: Offset in the eCryptfs file at which to begin writing the
 *          data from @data
 * @size: The number of bytes to write from @data
 *
 * Write an arbitrary amount of data to an arbitrary location in the
 * eCryptfs inode page cache. This is done on a page-by-page, and then
 * by an extent-by-extent, basis; individual extents are encrypted and
 * written to the lower page cache (via VFS writes). This function
 * takes care of all the address translation to locations in the lower
 * filesystem; it also handles truncate events, writing out zeros
 * where necessary.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_write(struct inode *ecryptfs_inode, char *data, loff_t offset,
		   size_t size)
{
	struct page *ecryptfs_page;
	struct ecryptfs_crypt_stat *crypt_stat;
	char *ecryptfs_page_virt;
	loff_t ecryptfs_file_size = i_size_read(ecryptfs_inode);
	loff_t data_offset = 0;
	loff_t pos;
	int rc = 0;

	crypt_stat = &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	/*
	 * if we are writing beyond current size, then start pos
	 * at the current size - we'll fill in zeros from there.
	 */
	if (offset > ecryptfs_file_size)
		pos = ecryptfs_file_size;
	else
		pos = offset;
	while (pos < (offset + size)) {
		pgoff_t ecryptfs_page_idx = (pos >> PAGE_CACHE_SHIFT);
		size_t start_offset_in_page = (pos & ~PAGE_CACHE_MASK);
		size_t num_bytes = (PAGE_CACHE_SIZE - start_offset_in_page);
		loff_t total_remaining_bytes = ((offset + size) - pos);

		if (fatal_signal_pending(current)) {
			rc = -EINTR;
			break;
		}

		if (num_bytes > total_remaining_bytes)
			num_bytes = total_remaining_bytes;
		if (pos < offset) {
			/* remaining zeros to write, up to destination offset */
			loff_t total_remaining_zeros = (offset - pos);

			if (num_bytes > total_remaining_zeros)
				num_bytes = total_remaining_zeros;
		}
		ecryptfs_page = ecryptfs_get_locked_page(ecryptfs_inode,
							 ecryptfs_page_idx);
		if (IS_ERR(ecryptfs_page)) {
			rc = PTR_ERR(ecryptfs_page);
			printk(KERN_ERR "%s: Error getting page at "
			       "index [%ld] from eCryptfs inode "
			       "mapping; rc = [%d]\n", __func__,
			       ecryptfs_page_idx, rc);
			goto out;
		}
		ecryptfs_page_virt = kmap_atomic(ecryptfs_page);

		/*
		 * pos: where we're now writing, offset: where the request was
		 * If current pos is before request, we are filling zeros
		 * If we are at or beyond request, we are writing the *data*
		 * If we're in a fresh page beyond eof, zero it in either case
		 */
		if (pos < offset || !start_offset_in_page) {
			/* We are extending past the previous end of the file.
			 * Fill in zero values to the end of the page */
			memset(((char *)ecryptfs_page_virt
				+ start_offset_in_page), 0,
				PAGE_CACHE_SIZE - start_offset_in_page);
		}

		/* pos >= offset, we are now writing the data request */
		if (pos >= offset) {
			memcpy(((char *)ecryptfs_page_virt
				+ start_offset_in_page),
			       (data + data_offset), num_bytes);
			data_offset += num_bytes;
		}
		kunmap_atomic(ecryptfs_page_virt);
		flush_dcache_page(ecryptfs_page);
		SetPageUptodate(ecryptfs_page);
		unlock_page(ecryptfs_page);
		if (crypt_stat->flags & ECRYPTFS_ENCRYPTED)
			rc = ecryptfs_encrypt_page(ecryptfs_page);
		else
			rc = ecryptfs_write_lower_page_segment(ecryptfs_inode,
						ecryptfs_page,
						start_offset_in_page,
						data_offset);
		page_cache_release(ecryptfs_page);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting "
			       "page; rc = [%d]\n", __func__, rc);
			goto out;
		}
		pos += num_bytes;
	}
	if (pos > ecryptfs_file_size) {
		i_size_write(ecryptfs_inode, pos);
		if (crypt_stat->flags & ECRYPTFS_ENCRYPTED) {
			int rc2;

			rc2 = ecryptfs_write_inode_size_to_metadata(
								ecryptfs_inode);
			if (rc2) {
				printk(KERN_ERR	"Problem with "
				       "ecryptfs_write_inode_size_to_metadata; "
				       "rc = [%d]\n", rc2);
				if (!rc)
					rc = rc2;
				goto out;
			}
		}
	}
out:
	return rc;
}

/**
 * ecryptfs_read_lower
 * @data: The read data is stored here by this function
 * @offset: Byte offset in the lower file from which to read the data
 * @size: Number of bytes to read from @offset of the lower file and
 *        store into @data
 * @ecryptfs_inode: The eCryptfs inode
 *
 * Read @size bytes of data at byte offset @offset from the lower
 * inode into memory location @data.
 *
 * Returns bytes read on success; 0 on EOF; less than zero on error
 */
int ecryptfs_read_lower(char *data, loff_t offset, size_t size,
			struct inode *ecryptfs_inode)
{
	struct file *lower_file;
	lower_file = ecryptfs_inode_to_private(ecryptfs_inode)->lower_file;
	if (!lower_file)
		return -EIO;
	return kernel_read(lower_file, offset, data, size);
}

/**
 * ecryptfs_read_lower_page_segment
 * @page_for_ecryptfs: The page into which data for eCryptfs will be
 *                     written
 * @offset_in_page: Offset in @page_for_ecryptfs from which to start
 *                  writing
 * @size: The number of bytes to write into @page_for_ecryptfs
 * @ecryptfs_inode: The eCryptfs inode
 *
 * Determines the byte offset in the file for the given page and
 * offset within the page, maps the page, and makes the call to read
 * the contents of @page_for_ecryptfs from the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_read_lower_page_segment(struct page *page_for_ecryptfs,
				     pgoff_t page_index,
				     size_t offset_in_page, size_t size,
				     struct inode *ecryptfs_inode)
{
	char *virt;
	loff_t offset;
	int rc;

	offset = ((((loff_t)page_index) << PAGE_CACHE_SHIFT) + offset_in_page);
	virt = kmap(page_for_ecryptfs);
	rc = ecryptfs_read_lower(virt, offset, size, ecryptfs_inode);
	if (rc > 0)
		rc = 0;
	kunmap(page_for_ecryptfs);
	flush_dcache_page(page_for_ecryptfs);
	return rc;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/read_write.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2004 Erez Zadok
 * Copyright (C) 2001-2004 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *   		Michael C. Thompson <mcthomps@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

// #include <linux/fs.h>
// #include <linux/mount.h>
// #include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/compiler.h>
// #include <linux/key.h>
// #include <linux/namei.h>
// #include <linux/crypto.h>
// #include <linux/file.h>
// #include <linux/scatterlist.h>
// #include <linux/slab.h>
// #include <asm/unaligned.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

#define DECRYPT		0
#define ENCRYPT		1

/**
 * ecryptfs_to_hex
 * @dst: Buffer to take hex character representation of contents of
 *       src; must be at least of size (src_size * 2)
 * @src: Buffer to be converted to a hex string respresentation
 * @src_size: number of bytes to convert
 */
void ecryptfs_to_hex(char *dst, char *src, size_t src_size)
{
	int x;

	for (x = 0; x < src_size; x++)
		sprintf(&dst[x * 2], "%.2x", (unsigned char)src[x]);
}

/**
 * ecryptfs_from_hex
 * @dst: Buffer to take the bytes from src hex; must be at least of
 *       size (src_size / 2)
 * @src: Buffer to be converted from a hex string respresentation to raw value
 * @dst_size: size of dst buffer, or number of hex characters pairs to convert
 */
void ecryptfs_from_hex(char *dst, char *src, int dst_size)
{
	int x;
	char tmp[3] = { 0, };

	for (x = 0; x < dst_size; x++) {
		tmp[0] = src[x * 2];
		tmp[1] = src[x * 2 + 1];
		dst[x] = (unsigned char)simple_strtol(tmp, NULL, 16);
	}
}

/**
 * ecryptfs_calculate_md5 - calculates the md5 of @src
 * @dst: Pointer to 16 bytes of allocated memory
 * @crypt_stat: Pointer to crypt_stat struct for the current inode
 * @src: Data to be md5'd
 * @len: Length of @src
 *
 * Uses the allocated crypto context that crypt_stat references to
 * generate the MD5 sum of the contents of src.
 */
static int ecryptfs_calculate_md5(char *dst,
				  struct ecryptfs_crypt_stat *crypt_stat,
				  char *src, int len)
{
	struct scatterlist sg;
	struct hash_desc desc = {
		.tfm = crypt_stat->hash_tfm,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
	int rc = 0;

	mutex_lock(&crypt_stat->cs_hash_tfm_mutex);
	sg_init_one(&sg, (u8 *)src, len);
	if (!desc.tfm) {
		desc.tfm = crypto_alloc_hash(ECRYPTFS_DEFAULT_HASH, 0,
					     CRYPTO_ALG_ASYNC);
		if (IS_ERR(desc.tfm)) {
			rc = PTR_ERR(desc.tfm);
			ecryptfs_printk(KERN_ERR, "Error attempting to "
					"allocate crypto context; rc = [%d]\n",
					rc);
			goto out;
		}
		crypt_stat->hash_tfm = desc.tfm;
	}
	rc = crypto_hash_init(&desc);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error initializing crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out;
	}
	rc = crypto_hash_update(&desc, &sg, len);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error updating crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out;
	}
	rc = crypto_hash_final(&desc, dst);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error finalizing crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out;
	}
out:
	mutex_unlock(&crypt_stat->cs_hash_tfm_mutex);
	return rc;
}

static int ecryptfs_crypto_api_algify_cipher_name(char **algified_name,
						  char *cipher_name,
						  char *chaining_modifier)
{
	int cipher_name_len = strlen(cipher_name);
	int chaining_modifier_len = strlen(chaining_modifier);
	int algified_name_len;
	int rc;

	algified_name_len = (chaining_modifier_len + cipher_name_len + 3);
	(*algified_name) = kmalloc(algified_name_len, GFP_KERNEL);
	if (!(*algified_name)) {
		rc = -ENOMEM;
		goto out;
	}
	snprintf((*algified_name), algified_name_len, "%s(%s)",
		 chaining_modifier, cipher_name);
	rc = 0;
out:
	return rc;
}

/**
 * ecryptfs_derive_iv
 * @iv: destination for the derived iv vale
 * @crypt_stat: Pointer to crypt_stat struct for the current inode
 * @offset: Offset of the extent whose IV we are to derive
 *
 * Generate the initialization vector from the given root IV and page
 * offset.
 *
 * Returns zero on success; non-zero on error.
 */
int ecryptfs_derive_iv(char *iv, struct ecryptfs_crypt_stat *crypt_stat,
		       loff_t offset)
{
	int rc = 0;
	char dst[MD5_DIGEST_SIZE];
	char src[ECRYPTFS_MAX_IV_BYTES + 16];

	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(KERN_DEBUG, "root iv:\n");
		ecryptfs_dump_hex(crypt_stat->root_iv, crypt_stat->iv_bytes);
	}
	/* TODO: It is probably secure to just cast the least
	 * significant bits of the root IV into an unsigned long and
	 * add the offset to that rather than go through all this
	 * hashing business. -Halcrow */
	memcpy(src, crypt_stat->root_iv, crypt_stat->iv_bytes);
	memset((src + crypt_stat->iv_bytes), 0, 16);
	snprintf((src + crypt_stat->iv_bytes), 16, "%lld", offset);
	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(KERN_DEBUG, "source:\n");
		ecryptfs_dump_hex(src, (crypt_stat->iv_bytes + 16));
	}
	rc = ecryptfs_calculate_md5(dst, crypt_stat, src,
				    (crypt_stat->iv_bytes + 16));
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error attempting to compute "
				"MD5 while generating IV for a page\n");
		goto out;
	}
	memcpy(iv, dst, crypt_stat->iv_bytes);
	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(KERN_DEBUG, "derived iv:\n");
		ecryptfs_dump_hex(iv, crypt_stat->iv_bytes);
	}
out:
	return rc;
}

/**
 * ecryptfs_init_crypt_stat
 * @crypt_stat: Pointer to the crypt_stat struct to initialize.
 *
 * Initialize the crypt_stat structure.
 */
void
ecryptfs_init_crypt_stat(struct ecryptfs_crypt_stat *crypt_stat)
{
	memset((void *)crypt_stat, 0, sizeof(struct ecryptfs_crypt_stat));
	INIT_LIST_HEAD(&crypt_stat->keysig_list);
	mutex_init(&crypt_stat->keysig_list_mutex);
	mutex_init(&crypt_stat->cs_mutex);
	mutex_init(&crypt_stat->cs_tfm_mutex);
	mutex_init(&crypt_stat->cs_hash_tfm_mutex);
	crypt_stat->flags |= ECRYPTFS_STRUCT_INITIALIZED;
}

/**
 * ecryptfs_destroy_crypt_stat
 * @crypt_stat: Pointer to the crypt_stat struct to initialize.
 *
 * Releases all memory associated with a crypt_stat struct.
 */
void ecryptfs_destroy_crypt_stat(struct ecryptfs_crypt_stat *crypt_stat)
{
	struct ecryptfs_key_sig *key_sig, *key_sig_tmp;

	if (crypt_stat->tfm)
		crypto_free_ablkcipher(crypt_stat->tfm);
	if (crypt_stat->hash_tfm)
		crypto_free_hash(crypt_stat->hash_tfm);
	list_for_each_entry_safe(key_sig, key_sig_tmp,
				 &crypt_stat->keysig_list, crypt_stat_list) {
		list_del(&key_sig->crypt_stat_list);
		kmem_cache_free(ecryptfs_key_sig_cache, key_sig);
	}
	memset(crypt_stat, 0, sizeof(struct ecryptfs_crypt_stat));
}

void ecryptfs_destroy_mount_crypt_stat(
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	struct ecryptfs_global_auth_tok *auth_tok, *auth_tok_tmp;

	if (!(mount_crypt_stat->flags & ECRYPTFS_MOUNT_CRYPT_STAT_INITIALIZED))
		return;
	mutex_lock(&mount_crypt_stat->global_auth_tok_list_mutex);
	list_for_each_entry_safe(auth_tok, auth_tok_tmp,
				 &mount_crypt_stat->global_auth_tok_list,
				 mount_crypt_stat_list) {
		list_del(&auth_tok->mount_crypt_stat_list);
		if (auth_tok->global_auth_tok_key
		    && !(auth_tok->flags & ECRYPTFS_AUTH_TOK_INVALID))
			key_put(auth_tok->global_auth_tok_key);
		kmem_cache_free(ecryptfs_global_auth_tok_cache, auth_tok);
	}
	mutex_unlock(&mount_crypt_stat->global_auth_tok_list_mutex);
	memset(mount_crypt_stat, 0, sizeof(struct ecryptfs_mount_crypt_stat));
}

/**
 * virt_to_scatterlist
 * @addr: Virtual address
 * @size: Size of data; should be an even multiple of the block size
 * @sg: Pointer to scatterlist array; set to NULL to obtain only
 *      the number of scatterlist structs required in array
 * @sg_size: Max array size
 *
 * Fills in a scatterlist array with page references for a passed
 * virtual address.
 *
 * Returns the number of scatterlist structs in array used
 */
int virt_to_scatterlist(const void *addr, int size, struct scatterlist *sg,
			int sg_size)
{
	int i = 0;
	struct page *pg;
	int offset;
	int remainder_of_page;

	sg_init_table(sg, sg_size);

	while (size > 0 && i < sg_size) {
		pg = virt_to_page(addr);
		offset = offset_in_page(addr);
		sg_set_page(&sg[i], pg, 0, offset);
		remainder_of_page = PAGE_CACHE_SIZE - offset;
		if (size >= remainder_of_page) {
			sg[i].length = remainder_of_page;
			addr += remainder_of_page;
			size -= remainder_of_page;
		} else {
			sg[i].length = size;
			addr += size;
			size = 0;
		}
		i++;
	}
	if (size > 0)
		return -ENOMEM;
	return i;
}

struct extent_crypt_result {
	struct completion completion;
	int rc;
};

static void extent_crypt_complete(struct crypto_async_request *req, int rc)
{
	struct extent_crypt_result *ecr = req->data;

	if (rc == -EINPROGRESS)
		return;

	ecr->rc = rc;
	complete(&ecr->completion);
}

/**
 * crypt_scatterlist
 * @crypt_stat: Pointer to the crypt_stat struct to initialize.
 * @dst_sg: Destination of the data after performing the crypto operation
 * @src_sg: Data to be encrypted or decrypted
 * @size: Length of data
 * @iv: IV to use
 * @op: ENCRYPT or DECRYPT to indicate the desired operation
 *
 * Returns the number of bytes encrypted or decrypted; negative value on error
 */
static int crypt_scatterlist(struct ecryptfs_crypt_stat *crypt_stat,
			     struct scatterlist *dst_sg,
			     struct scatterlist *src_sg, int size,
			     unsigned char *iv, int op)
{
	struct ablkcipher_request *req = NULL;
	struct extent_crypt_result ecr;
	int rc = 0;

	BUG_ON(!crypt_stat || !crypt_stat->tfm
	       || !(crypt_stat->flags & ECRYPTFS_STRUCT_INITIALIZED));
	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(KERN_DEBUG, "Key size [%zd]; key:\n",
				crypt_stat->key_size);
		ecryptfs_dump_hex(crypt_stat->key,
				  crypt_stat->key_size);
	}

	init_completion(&ecr.completion);

	mutex_lock(&crypt_stat->cs_tfm_mutex);
	req = ablkcipher_request_alloc(crypt_stat->tfm, GFP_NOFS);
	if (!req) {
		mutex_unlock(&crypt_stat->cs_tfm_mutex);
		rc = -ENOMEM;
		goto out;
	}

	ablkcipher_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			extent_crypt_complete, &ecr);
	/* Consider doing this once, when the file is opened */
	if (!(crypt_stat->flags & ECRYPTFS_KEY_SET)) {
		rc = crypto_ablkcipher_setkey(crypt_stat->tfm, crypt_stat->key,
					      crypt_stat->key_size);
		if (rc) {
			ecryptfs_printk(KERN_ERR,
					"Error setting key; rc = [%d]\n",
					rc);
			mutex_unlock(&crypt_stat->cs_tfm_mutex);
			rc = -EINVAL;
			goto out;
		}
		crypt_stat->flags |= ECRYPTFS_KEY_SET;
	}
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
	ablkcipher_request_set_crypt(req, src_sg, dst_sg, size, iv);
	rc = op == ENCRYPT ? crypto_ablkcipher_encrypt(req) :
			     crypto_ablkcipher_decrypt(req);
	if (rc == -EINPROGRESS || rc == -EBUSY) {
		struct extent_crypt_result *ecr = req->base.data;

		wait_for_completion(&ecr->completion);
		rc = ecr->rc;
		reinit_completion(&ecr->completion);
	}
out:
	ablkcipher_request_free(req);
	return rc;
}

/**
 * lower_offset_for_page
 *
 * Convert an eCryptfs page index into a lower byte offset
 */
static loff_t lower_offset_for_page(struct ecryptfs_crypt_stat *crypt_stat,
				    struct page *page)
{
	return ecryptfs_lower_header_size(crypt_stat) +
	       ((loff_t)page->index << PAGE_CACHE_SHIFT);
}

/**
 * crypt_extent
 * @crypt_stat: crypt_stat containing cryptographic context for the
 *              encryption operation
 * @dst_page: The page to write the result into
 * @src_page: The page to read from
 * @extent_offset: Page extent offset for use in generating IV
 * @op: ENCRYPT or DECRYPT to indicate the desired operation
 *
 * Encrypts or decrypts one extent of data.
 *
 * Return zero on success; non-zero otherwise
 */
static int crypt_extent(struct ecryptfs_crypt_stat *crypt_stat,
			struct page *dst_page,
			struct page *src_page,
			unsigned long extent_offset, int op)
{
	pgoff_t page_index = op == ENCRYPT ? src_page->index : dst_page->index;
	loff_t extent_base;
	char extent_iv[ECRYPTFS_MAX_IV_BYTES];
	struct scatterlist src_sg, dst_sg;
	size_t extent_size = crypt_stat->extent_size;
	int rc;

	extent_base = (((loff_t)page_index) * (PAGE_CACHE_SIZE / extent_size));
	rc = ecryptfs_derive_iv(extent_iv, crypt_stat,
				(extent_base + extent_offset));
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error attempting to derive IV for "
			"extent [0x%.16llx]; rc = [%d]\n",
			(unsigned long long)(extent_base + extent_offset), rc);
		goto out;
	}

	sg_init_table(&src_sg, 1);
	sg_init_table(&dst_sg, 1);

	sg_set_page(&src_sg, src_page, extent_size,
		    extent_offset * extent_size);
	sg_set_page(&dst_sg, dst_page, extent_size,
		    extent_offset * extent_size);

	rc = crypt_scatterlist(crypt_stat, &dst_sg, &src_sg, extent_size,
			       extent_iv, op);
	if (rc < 0) {
		printk(KERN_ERR "%s: Error attempting to crypt page with "
		       "page_index = [%ld], extent_offset = [%ld]; "
		       "rc = [%d]\n", __func__, page_index, extent_offset, rc);
		goto out;
	}
	rc = 0;
out:
	return rc;
}

/**
 * ecryptfs_encrypt_page
 * @page: Page mapped from the eCryptfs inode for the file; contains
 *        decrypted content that needs to be encrypted (to a temporary
 *        page; not in place) and written out to the lower file
 *
 * Encrypt an eCryptfs page. This is done on a per-extent basis. Note
 * that eCryptfs pages may straddle the lower pages -- for instance,
 * if the file was created on a machine with an 8K page size
 * (resulting in an 8K header), and then the file is copied onto a
 * host with a 32K page size, then when reading page 0 of the eCryptfs
 * file, 24K of page 0 of the lower file will be read and decrypted,
 * and then 8K of page 1 of the lower file will be read and decrypted.
 *
 * Returns zero on success; negative on error
 */
int ecryptfs_encrypt_page(struct page *page)
{
	struct inode *ecryptfs_inode;
	struct ecryptfs_crypt_stat *crypt_stat;
	char *enc_extent_virt;
	struct page *enc_extent_page = NULL;
	loff_t extent_offset;
	loff_t lower_offset;
	int rc = 0;

	ecryptfs_inode = page->mapping->host;
	crypt_stat =
		&(ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat);
	BUG_ON(!(crypt_stat->flags & ECRYPTFS_ENCRYPTED));
	enc_extent_page = alloc_page(GFP_USER);
	if (!enc_extent_page) {
		rc = -ENOMEM;
		ecryptfs_printk(KERN_ERR, "Error allocating memory for "
				"encrypted extent\n");
		goto out;
	}

	for (extent_offset = 0;
	     extent_offset < (PAGE_CACHE_SIZE / crypt_stat->extent_size);
	     extent_offset++) {
		rc = crypt_extent(crypt_stat, enc_extent_page, page,
				  extent_offset, ENCRYPT);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting extent; "
			       "rc = [%d]\n", __func__, rc);
			goto out;
		}
	}

	lower_offset = lower_offset_for_page(crypt_stat, page);
	enc_extent_virt = kmap(enc_extent_page);
	rc = ecryptfs_write_lower(ecryptfs_inode, enc_extent_virt, lower_offset,
				  PAGE_CACHE_SIZE);
	kunmap(enc_extent_page);
	if (rc < 0) {
		ecryptfs_printk(KERN_ERR,
			"Error attempting to write lower page; rc = [%d]\n",
			rc);
		goto out;
	}
	rc = 0;
out:
	if (enc_extent_page) {
		__free_page(enc_extent_page);
	}
	return rc;
}

/**
 * ecryptfs_decrypt_page
 * @page: Page mapped from the eCryptfs inode for the file; data read
 *        and decrypted from the lower file will be written into this
 *        page
 *
 * Decrypt an eCryptfs page. This is done on a per-extent basis. Note
 * that eCryptfs pages may straddle the lower pages -- for instance,
 * if the file was created on a machine with an 8K page size
 * (resulting in an 8K header), and then the file is copied onto a
 * host with a 32K page size, then when reading page 0 of the eCryptfs
 * file, 24K of page 0 of the lower file will be read and decrypted,
 * and then 8K of page 1 of the lower file will be read and decrypted.
 *
 * Returns zero on success; negative on error
 */
int ecryptfs_decrypt_page(struct page *page)
{
	struct inode *ecryptfs_inode;
	struct ecryptfs_crypt_stat *crypt_stat;
	char *page_virt;
	unsigned long extent_offset;
	loff_t lower_offset;
	int rc = 0;

	ecryptfs_inode = page->mapping->host;
	crypt_stat =
		&(ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat);
	BUG_ON(!(crypt_stat->flags & ECRYPTFS_ENCRYPTED));

	lower_offset = lower_offset_for_page(crypt_stat, page);
	page_virt = kmap(page);
	rc = ecryptfs_read_lower(page_virt, lower_offset, PAGE_CACHE_SIZE,
				 ecryptfs_inode);
	kunmap(page);
	if (rc < 0) {
		ecryptfs_printk(KERN_ERR,
			"Error attempting to read lower page; rc = [%d]\n",
			rc);
		goto out;
	}

	for (extent_offset = 0;
	     extent_offset < (PAGE_CACHE_SIZE / crypt_stat->extent_size);
	     extent_offset++) {
		rc = crypt_extent(crypt_stat, page, page,
				  extent_offset, DECRYPT);
		if (rc) {
			printk(KERN_ERR "%s: Error encrypting extent; "
			       "rc = [%d]\n", __func__, rc);
			goto out;
		}
	}
out:
	return rc;
}

#define ECRYPTFS_MAX_SCATTERLIST_LEN 4

/**
 * ecryptfs_init_crypt_ctx
 * @crypt_stat: Uninitialized crypt stats structure
 *
 * Initialize the crypto context.
 *
 * TODO: Performance: Keep a cache of initialized cipher contexts;
 * only init if needed
 */
int ecryptfs_init_crypt_ctx(struct ecryptfs_crypt_stat *crypt_stat)
{
	char *full_alg_name;
	int rc = -EINVAL;

	ecryptfs_printk(KERN_DEBUG,
			"Initializing cipher [%s]; strlen = [%d]; "
			"key_size_bits = [%zd]\n",
			crypt_stat->cipher, (int)strlen(crypt_stat->cipher),
			crypt_stat->key_size << 3);
	mutex_lock(&crypt_stat->cs_tfm_mutex);
	if (crypt_stat->tfm) {
		rc = 0;
		goto out_unlock;
	}
	rc = ecryptfs_crypto_api_algify_cipher_name(&full_alg_name,
						    crypt_stat->cipher, "cbc");
	if (rc)
		goto out_unlock;
	crypt_stat->tfm = crypto_alloc_ablkcipher(full_alg_name, 0, 0);
	if (IS_ERR(crypt_stat->tfm)) {
		rc = PTR_ERR(crypt_stat->tfm);
		crypt_stat->tfm = NULL;
		ecryptfs_printk(KERN_ERR, "cryptfs: init_crypt_ctx(): "
				"Error initializing cipher [%s]\n",
				full_alg_name);
		goto out_free;
	}
	crypto_ablkcipher_set_flags(crypt_stat->tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	rc = 0;
out_free:
	kfree(full_alg_name);
out_unlock:
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
	return rc;
}

static void set_extent_mask_and_shift(struct ecryptfs_crypt_stat *crypt_stat)
{
	int extent_size_tmp;

	crypt_stat->extent_mask = 0xFFFFFFFF;
	crypt_stat->extent_shift = 0;
	if (crypt_stat->extent_size == 0)
		return;
	extent_size_tmp = crypt_stat->extent_size;
	while ((extent_size_tmp & 0x01) == 0) {
		extent_size_tmp >>= 1;
		crypt_stat->extent_mask <<= 1;
		crypt_stat->extent_shift++;
	}
}

void ecryptfs_set_default_sizes(struct ecryptfs_crypt_stat *crypt_stat)
{
	/* Default values; may be overwritten as we are parsing the
	 * packets. */
	crypt_stat->extent_size = ECRYPTFS_DEFAULT_EXTENT_SIZE;
	set_extent_mask_and_shift(crypt_stat);
	crypt_stat->iv_bytes = ECRYPTFS_DEFAULT_IV_BYTES;
	if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR)
		crypt_stat->metadata_size = ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE;
	else {
		if (PAGE_CACHE_SIZE <= ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE)
			crypt_stat->metadata_size =
				ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE;
		else
			crypt_stat->metadata_size = PAGE_CACHE_SIZE;
	}
}

/**
 * ecryptfs_compute_root_iv
 * @crypt_stats
 *
 * On error, sets the root IV to all 0's.
 */
int ecryptfs_compute_root_iv(struct ecryptfs_crypt_stat *crypt_stat)
{
	int rc = 0;
	char dst[MD5_DIGEST_SIZE];

	BUG_ON(crypt_stat->iv_bytes > MD5_DIGEST_SIZE);
	BUG_ON(crypt_stat->iv_bytes <= 0);
	if (!(crypt_stat->flags & ECRYPTFS_KEY_VALID)) {
		rc = -EINVAL;
		ecryptfs_printk(KERN_WARNING, "Session key not valid; "
				"cannot generate root IV\n");
		goto out;
	}
	rc = ecryptfs_calculate_md5(dst, crypt_stat, crypt_stat->key,
				    crypt_stat->key_size);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error attempting to compute "
				"MD5 while generating root IV\n");
		goto out;
	}
	memcpy(crypt_stat->root_iv, dst, crypt_stat->iv_bytes);
out:
	if (rc) {
		memset(crypt_stat->root_iv, 0, crypt_stat->iv_bytes);
		crypt_stat->flags |= ECRYPTFS_SECURITY_WARNING;
	}
	return rc;
}

static void ecryptfs_generate_new_key(struct ecryptfs_crypt_stat *crypt_stat)
{
	get_random_bytes(crypt_stat->key, crypt_stat->key_size);
	crypt_stat->flags |= ECRYPTFS_KEY_VALID;
	ecryptfs_compute_root_iv(crypt_stat);
	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(KERN_DEBUG, "Generated new session key:\n");
		ecryptfs_dump_hex(crypt_stat->key,
				  crypt_stat->key_size);
	}
}

/**
 * ecryptfs_copy_mount_wide_flags_to_inode_flags
 * @crypt_stat: The inode's cryptographic context
 * @mount_crypt_stat: The mount point's cryptographic context
 *
 * This function propagates the mount-wide flags to individual inode
 * flags.
 */
static void ecryptfs_copy_mount_wide_flags_to_inode_flags(
	struct ecryptfs_crypt_stat *crypt_stat,
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	if (mount_crypt_stat->flags & ECRYPTFS_XATTR_METADATA_ENABLED)
		crypt_stat->flags |= ECRYPTFS_METADATA_IN_XATTR;
	if (mount_crypt_stat->flags & ECRYPTFS_ENCRYPTED_VIEW_ENABLED)
		crypt_stat->flags |= ECRYPTFS_VIEW_AS_ENCRYPTED;
	if (mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES) {
		crypt_stat->flags |= ECRYPTFS_ENCRYPT_FILENAMES;
		if (mount_crypt_stat->flags
		    & ECRYPTFS_GLOBAL_ENCFN_USE_MOUNT_FNEK)
			crypt_stat->flags |= ECRYPTFS_ENCFN_USE_MOUNT_FNEK;
		else if (mount_crypt_stat->flags
			 & ECRYPTFS_GLOBAL_ENCFN_USE_FEK)
			crypt_stat->flags |= ECRYPTFS_ENCFN_USE_FEK;
	}
}

static int ecryptfs_copy_mount_wide_sigs_to_inode_sigs(
	struct ecryptfs_crypt_stat *crypt_stat,
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	struct ecryptfs_global_auth_tok *global_auth_tok;
	int rc = 0;

	mutex_lock(&crypt_stat->keysig_list_mutex);
	mutex_lock(&mount_crypt_stat->global_auth_tok_list_mutex);

	list_for_each_entry(global_auth_tok,
			    &mount_crypt_stat->global_auth_tok_list,
			    mount_crypt_stat_list) {
		if (global_auth_tok->flags & ECRYPTFS_AUTH_TOK_FNEK)
			continue;
		rc = ecryptfs_add_keysig(crypt_stat, global_auth_tok->sig);
		if (rc) {
			printk(KERN_ERR "Error adding keysig; rc = [%d]\n", rc);
			goto out;
		}
	}

out:
	mutex_unlock(&mount_crypt_stat->global_auth_tok_list_mutex);
	mutex_unlock(&crypt_stat->keysig_list_mutex);
	return rc;
}

/**
 * ecryptfs_set_default_crypt_stat_vals
 * @crypt_stat: The inode's cryptographic context
 * @mount_crypt_stat: The mount point's cryptographic context
 *
 * Default values in the event that policy does not override them.
 */
static void ecryptfs_set_default_crypt_stat_vals(
	struct ecryptfs_crypt_stat *crypt_stat,
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	ecryptfs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
						      mount_crypt_stat);
	ecryptfs_set_default_sizes(crypt_stat);
	strcpy(crypt_stat->cipher, ECRYPTFS_DEFAULT_CIPHER);
	crypt_stat->key_size = ECRYPTFS_DEFAULT_KEY_BYTES;
	crypt_stat->flags &= ~(ECRYPTFS_KEY_VALID);
	crypt_stat->file_version = ECRYPTFS_FILE_VERSION;
	crypt_stat->mount_crypt_stat = mount_crypt_stat;
}

/**
 * ecryptfs_new_file_context
 * @ecryptfs_inode: The eCryptfs inode
 *
 * If the crypto context for the file has not yet been established,
 * this is where we do that.  Establishing a new crypto context
 * involves the following decisions:
 *  - What cipher to use?
 *  - What set of authentication tokens to use?
 * Here we just worry about getting enough information into the
 * authentication tokens so that we know that they are available.
 * We associate the available authentication tokens with the new file
 * via the set of signatures in the crypt_stat struct.  Later, when
 * the headers are actually written out, we may again defer to
 * userspace to perform the encryption of the session key; for the
 * foreseeable future, this will be the case with public key packets.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_new_file_context(struct inode *ecryptfs_inode)
{
	struct ecryptfs_crypt_stat *crypt_stat =
	    &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
	    &ecryptfs_superblock_to_private(
		    ecryptfs_inode->i_sb)->mount_crypt_stat;
	int cipher_name_len;
	int rc = 0;

	ecryptfs_set_default_crypt_stat_vals(crypt_stat, mount_crypt_stat);
	crypt_stat->flags |= (ECRYPTFS_ENCRYPTED | ECRYPTFS_KEY_VALID);
	ecryptfs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
						      mount_crypt_stat);
	rc = ecryptfs_copy_mount_wide_sigs_to_inode_sigs(crypt_stat,
							 mount_crypt_stat);
	if (rc) {
		printk(KERN_ERR "Error attempting to copy mount-wide key sigs "
		       "to the inode key sigs; rc = [%d]\n", rc);
		goto out;
	}
	cipher_name_len =
		strlen(mount_crypt_stat->global_default_cipher_name);
	memcpy(crypt_stat->cipher,
	       mount_crypt_stat->global_default_cipher_name,
	       cipher_name_len);
	crypt_stat->cipher[cipher_name_len] = '\0';
	crypt_stat->key_size =
		mount_crypt_stat->global_default_cipher_key_size;
	ecryptfs_generate_new_key(crypt_stat);
	rc = ecryptfs_init_crypt_ctx(crypt_stat);
	if (rc)
		ecryptfs_printk(KERN_ERR, "Error initializing cryptographic "
				"context for cipher [%s]: rc = [%d]\n",
				crypt_stat->cipher, rc);
out:
	return rc;
}

/**
 * ecryptfs_validate_marker - check for the ecryptfs marker
 * @data: The data block in which to check
 *
 * Returns zero if marker found; -EINVAL if not found
 */
static int ecryptfs_validate_marker(char *data)
{
	u32 m_1, m_2;

	m_1 = get_unaligned_be32(data);
	m_2 = get_unaligned_be32(data + 4);
	if ((m_1 ^ MAGIC_ECRYPTFS_MARKER) == m_2)
		return 0;
	ecryptfs_printk(KERN_DEBUG, "m_1 = [0x%.8x]; m_2 = [0x%.8x]; "
			"MAGIC_ECRYPTFS_MARKER = [0x%.8x]\n", m_1, m_2,
			MAGIC_ECRYPTFS_MARKER);
	ecryptfs_printk(KERN_DEBUG, "(m_1 ^ MAGIC_ECRYPTFS_MARKER) = "
			"[0x%.8x]\n", (m_1 ^ MAGIC_ECRYPTFS_MARKER));
	return -EINVAL;
}

struct ecryptfs_flag_map_elem {
	u32 file_flag;
	u32 local_flag;
};

/* Add support for additional flags by adding elements here. */
static struct ecryptfs_flag_map_elem ecryptfs_flag_map[] = {
	{0x00000001, ECRYPTFS_ENABLE_HMAC},
	{0x00000002, ECRYPTFS_ENCRYPTED},
	{0x00000004, ECRYPTFS_METADATA_IN_XATTR},
	{0x00000008, ECRYPTFS_ENCRYPT_FILENAMES}
};

/**
 * ecryptfs_process_flags
 * @crypt_stat: The cryptographic context
 * @page_virt: Source data to be parsed
 * @bytes_read: Updated with the number of bytes read
 *
 * Returns zero on success; non-zero if the flag set is invalid
 */
static int ecryptfs_process_flags(struct ecryptfs_crypt_stat *crypt_stat,
				  char *page_virt, int *bytes_read)
{
	int rc = 0;
	int i;
	u32 flags;

	flags = get_unaligned_be32(page_virt);
	for (i = 0; i < ((sizeof(ecryptfs_flag_map)
			  / sizeof(struct ecryptfs_flag_map_elem))); i++)
		if (flags & ecryptfs_flag_map[i].file_flag) {
			crypt_stat->flags |= ecryptfs_flag_map[i].local_flag;
		} else
			crypt_stat->flags &= ~(ecryptfs_flag_map[i].local_flag);
	/* Version is in top 8 bits of the 32-bit flag vector */
	crypt_stat->file_version = ((flags >> 24) & 0xFF);
	(*bytes_read) = 4;
	return rc;
}

/**
 * write_ecryptfs_marker
 * @page_virt: The pointer to in a page to begin writing the marker
 * @written: Number of bytes written
 *
 * Marker = 0x3c81b7f5
 */
static void write_ecryptfs_marker(char *page_virt, size_t *written)
{
	u32 m_1, m_2;

	get_random_bytes(&m_1, (MAGIC_ECRYPTFS_MARKER_SIZE_BYTES / 2));
	m_2 = (m_1 ^ MAGIC_ECRYPTFS_MARKER);
	put_unaligned_be32(m_1, page_virt);
	page_virt += (MAGIC_ECRYPTFS_MARKER_SIZE_BYTES / 2);
	put_unaligned_be32(m_2, page_virt);
	(*written) = MAGIC_ECRYPTFS_MARKER_SIZE_BYTES;
}

void ecryptfs_write_crypt_stat_flags(char *page_virt,
				     struct ecryptfs_crypt_stat *crypt_stat,
				     size_t *written)
{
	u32 flags = 0;
	int i;

	for (i = 0; i < ((sizeof(ecryptfs_flag_map)
			  / sizeof(struct ecryptfs_flag_map_elem))); i++)
		if (crypt_stat->flags & ecryptfs_flag_map[i].local_flag)
			flags |= ecryptfs_flag_map[i].file_flag;
	/* Version is in top 8 bits of the 32-bit flag vector */
	flags |= ((((u8)crypt_stat->file_version) << 24) & 0xFF000000);
	put_unaligned_be32(flags, page_virt);
	(*written) = 4;
}

struct ecryptfs_cipher_code_str_map_elem {
	char cipher_str[16];
	u8 cipher_code;
};

/* Add support for additional ciphers by adding elements here. The
 * cipher_code is whatever OpenPGP applicatoins use to identify the
 * ciphers. List in order of probability. */
static struct ecryptfs_cipher_code_str_map_elem
ecryptfs_cipher_code_str_map[] = {
	{"aes",RFC2440_CIPHER_AES_128 },
	{"blowfish", RFC2440_CIPHER_BLOWFISH},
	{"des3_ede", RFC2440_CIPHER_DES3_EDE},
	{"cast5", RFC2440_CIPHER_CAST_5},
	{"twofish", RFC2440_CIPHER_TWOFISH},
	{"cast6", RFC2440_CIPHER_CAST_6},
	{"aes", RFC2440_CIPHER_AES_192},
	{"aes", RFC2440_CIPHER_AES_256}
};

/**
 * ecryptfs_code_for_cipher_string
 * @cipher_name: The string alias for the cipher
 * @key_bytes: Length of key in bytes; used for AES code selection
 *
 * Returns zero on no match, or the cipher code on match
 */
u8 ecryptfs_code_for_cipher_string(char *cipher_name, size_t key_bytes)
{
	int i;
	u8 code = 0;
	struct ecryptfs_cipher_code_str_map_elem *map =
		ecryptfs_cipher_code_str_map;

	if (strcmp(cipher_name, "aes") == 0) {
		switch (key_bytes) {
		case 16:
			code = RFC2440_CIPHER_AES_128;
			break;
		case 24:
			code = RFC2440_CIPHER_AES_192;
			break;
		case 32:
			code = RFC2440_CIPHER_AES_256;
		}
	} else {
		for (i = 0; i < ARRAY_SIZE(ecryptfs_cipher_code_str_map); i++)
			if (strcmp(cipher_name, map[i].cipher_str) == 0) {
				code = map[i].cipher_code;
				break;
			}
	}
	return code;
}

/**
 * ecryptfs_cipher_code_to_string
 * @str: Destination to write out the cipher name
 * @cipher_code: The code to convert to cipher name string
 *
 * Returns zero on success
 */
int ecryptfs_cipher_code_to_string(char *str, u8 cipher_code)
{
	int rc = 0;
	int i;

	str[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(ecryptfs_cipher_code_str_map); i++)
		if (cipher_code == ecryptfs_cipher_code_str_map[i].cipher_code)
			strcpy(str, ecryptfs_cipher_code_str_map[i].cipher_str);
	if (str[0] == '\0') {
		ecryptfs_printk(KERN_WARNING, "Cipher code not recognized: "
				"[%d]\n", cipher_code);
		rc = -EINVAL;
	}
	return rc;
}

int ecryptfs_read_and_validate_header_region(struct inode *inode)
{
	u8 file_size[ECRYPTFS_SIZE_AND_MARKER_BYTES];
	u8 *marker = file_size + ECRYPTFS_FILE_SIZE_BYTES;
	int rc;

	rc = ecryptfs_read_lower(file_size, 0, ECRYPTFS_SIZE_AND_MARKER_BYTES,
				 inode);
	if (rc < ECRYPTFS_SIZE_AND_MARKER_BYTES)
		return rc >= 0 ? -EINVAL : rc;
	rc = ecryptfs_validate_marker(marker);
	if (!rc)
		ecryptfs_i_size_init(file_size, inode);
	return rc;
}

void
ecryptfs_write_header_metadata(char *virt,
			       struct ecryptfs_crypt_stat *crypt_stat,
			       size_t *written)
{
	u32 header_extent_size;
	u16 num_header_extents_at_front;

	header_extent_size = (u32)crypt_stat->extent_size;
	num_header_extents_at_front =
		(u16)(crypt_stat->metadata_size / crypt_stat->extent_size);
	put_unaligned_be32(header_extent_size, virt);
	virt += 4;
	put_unaligned_be16(num_header_extents_at_front, virt);
	(*written) = 6;
}

struct kmem_cache *ecryptfs_header_cache;

/**
 * ecryptfs_write_headers_virt
 * @page_virt: The virtual address to write the headers to
 * @max: The size of memory allocated at page_virt
 * @size: Set to the number of bytes written by this function
 * @crypt_stat: The cryptographic context
 * @ecryptfs_dentry: The eCryptfs dentry
 *
 * Format version: 1
 *
 *   Header Extent:
 *     Octets 0-7:        Unencrypted file size (big-endian)
 *     Octets 8-15:       eCryptfs special marker
 *     Octets 16-19:      Flags
 *      Octet 16:         File format version number (between 0 and 255)
 *      Octets 17-18:     Reserved
 *      Octet 19:         Bit 1 (lsb): Reserved
 *                        Bit 2: Encrypted?
 *                        Bits 3-8: Reserved
 *     Octets 20-23:      Header extent size (big-endian)
 *     Octets 24-25:      Number of header extents at front of file
 *                        (big-endian)
 *     Octet  26:         Begin RFC 2440 authentication token packet set
 *   Data Extent 0:
 *     Lower data (CBC encrypted)
 *   Data Extent 1:
 *     Lower data (CBC encrypted)
 *   ...
 *
 * Returns zero on success
 */
static int ecryptfs_write_headers_virt(char *page_virt, size_t max,
				       size_t *size,
				       struct ecryptfs_crypt_stat *crypt_stat,
				       struct dentry *ecryptfs_dentry)
{
	int rc;
	size_t written;
	size_t offset;

	offset = ECRYPTFS_FILE_SIZE_BYTES;
	write_ecryptfs_marker((page_virt + offset), &written);
	offset += written;
	ecryptfs_write_crypt_stat_flags((page_virt + offset), crypt_stat,
					&written);
	offset += written;
	ecryptfs_write_header_metadata((page_virt + offset), crypt_stat,
				       &written);
	offset += written;
	rc = ecryptfs_generate_key_packet_set((page_virt + offset), crypt_stat,
					      ecryptfs_dentry, &written,
					      max - offset);
	if (rc)
		ecryptfs_printk(KERN_WARNING, "Error generating key packet "
				"set; rc = [%d]\n", rc);
	if (size) {
		offset += written;
		*size = offset;
	}
	return rc;
}

static int
ecryptfs_write_metadata_to_contents(struct inode *ecryptfs_inode,
				    char *virt, size_t virt_len)
{
	int rc;

	rc = ecryptfs_write_lower(ecryptfs_inode, virt,
				  0, virt_len);
	if (rc < 0)
		printk(KERN_ERR "%s: Error attempting to write header "
		       "information to lower file; rc = [%d]\n", __func__, rc);
	else
		rc = 0;
	return rc;
}

static int
ecryptfs_write_metadata_to_xattr(struct dentry *ecryptfs_dentry,
				 char *page_virt, size_t size)
{
	int rc;

	rc = ecryptfs_setxattr(ecryptfs_dentry, ECRYPTFS_XATTR_NAME, page_virt,
			       size, 0);
	return rc;
}

static unsigned long ecryptfs_get_zeroed_pages(gfp_t gfp_mask,
					       unsigned int order)
{
	struct page *page;

	page = alloc_pages(gfp_mask | __GFP_ZERO, order);
	if (page)
		return (unsigned long) page_address(page);
	return 0;
}

/**
 * ecryptfs_write_metadata
 * @ecryptfs_dentry: The eCryptfs dentry, which should be negative
 * @ecryptfs_inode: The newly created eCryptfs inode
 *
 * Write the file headers out.  This will likely involve a userspace
 * callout, in which the session key is encrypted with one or more
 * public keys and/or the passphrase necessary to do the encryption is
 * retrieved via a prompt.  Exactly what happens at this point should
 * be policy-dependent.
 *
 * Returns zero on success; non-zero on error
 */
int ecryptfs_write_metadata(struct dentry *ecryptfs_dentry,
			    struct inode *ecryptfs_inode)
{
	struct ecryptfs_crypt_stat *crypt_stat =
		&ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	unsigned int order;
	char *virt;
	size_t virt_len;
	size_t size = 0;
	int rc = 0;

	if (likely(crypt_stat->flags & ECRYPTFS_ENCRYPTED)) {
		if (!(crypt_stat->flags & ECRYPTFS_KEY_VALID)) {
			printk(KERN_ERR "Key is invalid; bailing out\n");
			rc = -EINVAL;
			goto out;
		}
	} else {
		printk(KERN_WARNING "%s: Encrypted flag not set\n",
		       __func__);
		rc = -EINVAL;
		goto out;
	}
	virt_len = crypt_stat->metadata_size;
	order = get_order(virt_len);
	/* Released in this function */
	virt = (char *)ecryptfs_get_zeroed_pages(GFP_KERNEL, order);
	if (!virt) {
		printk(KERN_ERR "%s: Out of memory\n", __func__);
		rc = -ENOMEM;
		goto out;
	}
	/* Zeroed page ensures the in-header unencrypted i_size is set to 0 */
	rc = ecryptfs_write_headers_virt(virt, virt_len, &size, crypt_stat,
					 ecryptfs_dentry);
	if (unlikely(rc)) {
		printk(KERN_ERR "%s: Error whilst writing headers; rc = [%d]\n",
		       __func__, rc);
		goto out_free;
	}
	if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR)
		rc = ecryptfs_write_metadata_to_xattr(ecryptfs_dentry, virt,
						      size);
	else
		rc = ecryptfs_write_metadata_to_contents(ecryptfs_inode, virt,
							 virt_len);
	if (rc) {
		printk(KERN_ERR "%s: Error writing metadata out to lower file; "
		       "rc = [%d]\n", __func__, rc);
		goto out_free;
	}
out_free:
	free_pages((unsigned long)virt, order);
out:
	return rc;
}

#define ECRYPTFS_DONT_VALIDATE_HEADER_SIZE 0
#define ECRYPTFS_VALIDATE_HEADER_SIZE 1
static int parse_header_metadata(struct ecryptfs_crypt_stat *crypt_stat,
				 char *virt, int *bytes_read,
				 int validate_header_size)
{
	int rc = 0;
	u32 header_extent_size;
	u16 num_header_extents_at_front;

	header_extent_size = get_unaligned_be32(virt);
	virt += sizeof(__be32);
	num_header_extents_at_front = get_unaligned_be16(virt);
	crypt_stat->metadata_size = (((size_t)num_header_extents_at_front
				     * (size_t)header_extent_size));
	(*bytes_read) = (sizeof(__be32) + sizeof(__be16));
	if ((validate_header_size == ECRYPTFS_VALIDATE_HEADER_SIZE)
	    && (crypt_stat->metadata_size
		< ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE)) {
		rc = -EINVAL;
		printk(KERN_WARNING "Invalid header size: [%zd]\n",
		       crypt_stat->metadata_size);
	}
	return rc;
}

/**
 * set_default_header_data
 * @crypt_stat: The cryptographic context
 *
 * For version 0 file format; this function is only for backwards
 * compatibility for files created with the prior versions of
 * eCryptfs.
 */
static void set_default_header_data(struct ecryptfs_crypt_stat *crypt_stat)
{
	crypt_stat->metadata_size = ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE;
}

void ecryptfs_i_size_init(const char *page_virt, struct inode *inode)
{
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	struct ecryptfs_crypt_stat *crypt_stat;
	u64 file_size;

	crypt_stat = &ecryptfs_inode_to_private(inode)->crypt_stat;
	mount_crypt_stat =
		&ecryptfs_superblock_to_private(inode->i_sb)->mount_crypt_stat;
	if (mount_crypt_stat->flags & ECRYPTFS_ENCRYPTED_VIEW_ENABLED) {
		file_size = i_size_read(ecryptfs_inode_to_lower(inode));
		if (crypt_stat->flags & ECRYPTFS_METADATA_IN_XATTR)
			file_size += crypt_stat->metadata_size;
	} else
		file_size = get_unaligned_be64(page_virt);
	i_size_write(inode, (loff_t)file_size);
	crypt_stat->flags |= ECRYPTFS_I_SIZE_INITIALIZED;
}

/**
 * ecryptfs_read_headers_virt
 * @page_virt: The virtual address into which to read the headers
 * @crypt_stat: The cryptographic context
 * @ecryptfs_dentry: The eCryptfs dentry
 * @validate_header_size: Whether to validate the header size while reading
 *
 * Read/parse the header data. The header format is detailed in the
 * comment block for the ecryptfs_write_headers_virt() function.
 *
 * Returns zero on success
 */
static int ecryptfs_read_headers_virt(char *page_virt,
				      struct ecryptfs_crypt_stat *crypt_stat,
				      struct dentry *ecryptfs_dentry,
				      int validate_header_size)
{
	int rc = 0;
	int offset;
	int bytes_read;

	ecryptfs_set_default_sizes(crypt_stat);
	crypt_stat->mount_crypt_stat = &ecryptfs_superblock_to_private(
		ecryptfs_dentry->d_sb)->mount_crypt_stat;
	offset = ECRYPTFS_FILE_SIZE_BYTES;
	rc = ecryptfs_validate_marker(page_virt + offset);
	if (rc)
		goto out;
	if (!(crypt_stat->flags & ECRYPTFS_I_SIZE_INITIALIZED))
		ecryptfs_i_size_init(page_virt, ecryptfs_dentry->d_inode);
	offset += MAGIC_ECRYPTFS_MARKER_SIZE_BYTES;
	rc = ecryptfs_process_flags(crypt_stat, (page_virt + offset),
				    &bytes_read);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error processing flags\n");
		goto out;
	}
	if (crypt_stat->file_version > ECRYPTFS_SUPPORTED_FILE_VERSION) {
		ecryptfs_printk(KERN_WARNING, "File version is [%d]; only "
				"file version [%d] is supported by this "
				"version of eCryptfs\n",
				crypt_stat->file_version,
				ECRYPTFS_SUPPORTED_FILE_VERSION);
		rc = -EINVAL;
		goto out;
	}
	offset += bytes_read;
	if (crypt_stat->file_version >= 1) {
		rc = parse_header_metadata(crypt_stat, (page_virt + offset),
					   &bytes_read, validate_header_size);
		if (rc) {
			ecryptfs_printk(KERN_WARNING, "Error reading header "
					"metadata; rc = [%d]\n", rc);
		}
		offset += bytes_read;
	} else
		set_default_header_data(crypt_stat);
	rc = ecryptfs_parse_packet_set(crypt_stat, (page_virt + offset),
				       ecryptfs_dentry);
out:
	return rc;
}

/**
 * ecryptfs_read_xattr_region
 * @page_virt: The vitual address into which to read the xattr data
 * @ecryptfs_inode: The eCryptfs inode
 *
 * Attempts to read the crypto metadata from the extended attribute
 * region of the lower file.
 *
 * Returns zero on success; non-zero on error
 */
int ecryptfs_read_xattr_region(char *page_virt, struct inode *ecryptfs_inode)
{
	struct dentry *lower_dentry =
		ecryptfs_inode_to_private(ecryptfs_inode)->lower_file->f_path.dentry;
	ssize_t size;
	int rc = 0;

	size = ecryptfs_getxattr_lower(lower_dentry, ECRYPTFS_XATTR_NAME,
				       page_virt, ECRYPTFS_DEFAULT_EXTENT_SIZE);
	if (size < 0) {
		if (unlikely(ecryptfs_verbosity > 0))
			printk(KERN_INFO "Error attempting to read the [%s] "
			       "xattr from the lower file; return value = "
			       "[%zd]\n", ECRYPTFS_XATTR_NAME, size);
		rc = -EINVAL;
		goto out;
	}
out:
	return rc;
}

int ecryptfs_read_and_validate_xattr_region(struct dentry *dentry,
					    struct inode *inode)
{
	u8 file_size[ECRYPTFS_SIZE_AND_MARKER_BYTES];
	u8 *marker = file_size + ECRYPTFS_FILE_SIZE_BYTES;
	int rc;

	rc = ecryptfs_getxattr_lower(ecryptfs_dentry_to_lower(dentry),
				     ECRYPTFS_XATTR_NAME, file_size,
				     ECRYPTFS_SIZE_AND_MARKER_BYTES);
	if (rc < ECRYPTFS_SIZE_AND_MARKER_BYTES)
		return rc >= 0 ? -EINVAL : rc;
	rc = ecryptfs_validate_marker(marker);
	if (!rc)
		ecryptfs_i_size_init(file_size, inode);
	return rc;
}

/**
 * ecryptfs_read_metadata
 *
 * Common entry point for reading file metadata. From here, we could
 * retrieve the header information from the header region of the file,
 * the xattr region of the file, or some other repostory that is
 * stored separately from the file itself. The current implementation
 * supports retrieving the metadata information from the file contents
 * and from the xattr region.
 *
 * Returns zero if valid headers found and parsed; non-zero otherwise
 */
int ecryptfs_read_metadata(struct dentry *ecryptfs_dentry)
{
	int rc;
	char *page_virt;
	struct inode *ecryptfs_inode = ecryptfs_dentry->d_inode;
	struct ecryptfs_crypt_stat *crypt_stat =
	    &ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(
			ecryptfs_dentry->d_sb)->mount_crypt_stat;

	ecryptfs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
						      mount_crypt_stat);
	/* Read the first page from the underlying file */
	page_virt = kmem_cache_alloc(ecryptfs_header_cache, GFP_USER);
	if (!page_virt) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Unable to allocate page_virt\n",
		       __func__);
		goto out;
	}
	rc = ecryptfs_read_lower(page_virt, 0, crypt_stat->extent_size,
				 ecryptfs_inode);
	if (rc >= 0)
		rc = ecryptfs_read_headers_virt(page_virt, crypt_stat,
						ecryptfs_dentry,
						ECRYPTFS_VALIDATE_HEADER_SIZE);
	if (rc) {
		/* metadata is not in the file header, so try xattrs */
		memset(page_virt, 0, PAGE_CACHE_SIZE);
		rc = ecryptfs_read_xattr_region(page_virt, ecryptfs_inode);
		if (rc) {
			printk(KERN_DEBUG "Valid eCryptfs headers not found in "
			       "file header region or xattr region, inode %lu\n",
				ecryptfs_inode->i_ino);
			rc = -EINVAL;
			goto out;
		}
		rc = ecryptfs_read_headers_virt(page_virt, crypt_stat,
						ecryptfs_dentry,
						ECRYPTFS_DONT_VALIDATE_HEADER_SIZE);
		if (rc) {
			printk(KERN_DEBUG "Valid eCryptfs headers not found in "
			       "file xattr region either, inode %lu\n",
				ecryptfs_inode->i_ino);
			rc = -EINVAL;
		}
		if (crypt_stat->mount_crypt_stat->flags
		    & ECRYPTFS_XATTR_METADATA_ENABLED) {
			crypt_stat->flags |= ECRYPTFS_METADATA_IN_XATTR;
		} else {
			printk(KERN_WARNING "Attempt to access file with "
			       "crypto metadata only in the extended attribute "
			       "region, but eCryptfs was mounted without "
			       "xattr support enabled. eCryptfs will not treat "
			       "this like an encrypted file, inode %lu\n",
				ecryptfs_inode->i_ino);
			rc = -EINVAL;
		}
	}
out:
	if (page_virt) {
		memset(page_virt, 0, PAGE_CACHE_SIZE);
		kmem_cache_free(ecryptfs_header_cache, page_virt);
	}
	return rc;
}

/**
 * ecryptfs_encrypt_filename - encrypt filename
 *
 * CBC-encrypts the filename. We do not want to encrypt the same
 * filename with the same key and IV, which may happen with hard
 * links, so we prepend random bits to each filename.
 *
 * Returns zero on success; non-zero otherwise
 */
static int
ecryptfs_encrypt_filename(struct ecryptfs_filename *filename,
			  struct ecryptfs_crypt_stat *crypt_stat,
			  struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	int rc = 0;

	filename->encrypted_filename = NULL;
	filename->encrypted_filename_size = 0;
	if ((crypt_stat && (crypt_stat->flags & ECRYPTFS_ENCFN_USE_MOUNT_FNEK))
	    || (mount_crypt_stat && (mount_crypt_stat->flags
				     & ECRYPTFS_GLOBAL_ENCFN_USE_MOUNT_FNEK))) {
		size_t packet_size;
		size_t remaining_bytes;

		rc = ecryptfs_write_tag_70_packet(
			NULL, NULL,
			&filename->encrypted_filename_size,
			mount_crypt_stat, NULL,
			filename->filename_size);
		if (rc) {
			printk(KERN_ERR "%s: Error attempting to get packet "
			       "size for tag 72; rc = [%d]\n", __func__,
			       rc);
			filename->encrypted_filename_size = 0;
			goto out;
		}
		filename->encrypted_filename =
			kmalloc(filename->encrypted_filename_size, GFP_KERNEL);
		if (!filename->encrypted_filename) {
			printk(KERN_ERR "%s: Out of memory whilst attempting "
			       "to kmalloc [%zd] bytes\n", __func__,
			       filename->encrypted_filename_size);
			rc = -ENOMEM;
			goto out;
		}
		remaining_bytes = filename->encrypted_filename_size;
		rc = ecryptfs_write_tag_70_packet(filename->encrypted_filename,
						  &remaining_bytes,
						  &packet_size,
						  mount_crypt_stat,
						  filename->filename,
						  filename->filename_size);
		if (rc) {
			printk(KERN_ERR "%s: Error attempting to generate "
			       "tag 70 packet; rc = [%d]\n", __func__,
			       rc);
			kfree(filename->encrypted_filename);
			filename->encrypted_filename = NULL;
			filename->encrypted_filename_size = 0;
			goto out;
		}
		filename->encrypted_filename_size = packet_size;
	} else {
		printk(KERN_ERR "%s: No support for requested filename "
		       "encryption method in this release\n", __func__);
		rc = -EOPNOTSUPP;
		goto out;
	}
out:
	return rc;
}

static int ecryptfs_copy_filename(char **copied_name, size_t *copied_name_size,
				  const char *name, size_t name_size)
{
	int rc = 0;

	(*copied_name) = kmalloc((name_size + 1), GFP_KERNEL);
	if (!(*copied_name)) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy((void *)(*copied_name), (void *)name, name_size);
	(*copied_name)[(name_size)] = '\0';	/* Only for convenience
						 * in printing out the
						 * string in debug
						 * messages */
	(*copied_name_size) = name_size;
out:
	return rc;
}

/**
 * ecryptfs_process_key_cipher - Perform key cipher initialization.
 * @key_tfm: Crypto context for key material, set by this function
 * @cipher_name: Name of the cipher
 * @key_size: Size of the key in bytes
 *
 * Returns zero on success. Any crypto_tfm structs allocated here
 * should be released by other functions, such as on a superblock put
 * event, regardless of whether this function succeeds for fails.
 */
static int
ecryptfs_process_key_cipher(struct crypto_blkcipher **key_tfm,
			    char *cipher_name, size_t *key_size)
{
	char dummy_key[ECRYPTFS_MAX_KEY_BYTES];
	char *full_alg_name = NULL;
	int rc;

	*key_tfm = NULL;
	if (*key_size > ECRYPTFS_MAX_KEY_BYTES) {
		rc = -EINVAL;
		printk(KERN_ERR "Requested key size is [%zd] bytes; maximum "
		      "allowable is [%d]\n", *key_size, ECRYPTFS_MAX_KEY_BYTES);
		goto out;
	}
	rc = ecryptfs_crypto_api_algify_cipher_name(&full_alg_name, cipher_name,
						    "ecb");
	if (rc)
		goto out;
	*key_tfm = crypto_alloc_blkcipher(full_alg_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(*key_tfm)) {
		rc = PTR_ERR(*key_tfm);
		printk(KERN_ERR "Unable to allocate crypto cipher with name "
		       "[%s]; rc = [%d]\n", full_alg_name, rc);
		goto out;
	}
	crypto_blkcipher_set_flags(*key_tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	if (*key_size == 0) {
		struct blkcipher_alg *alg = crypto_blkcipher_alg(*key_tfm);

		*key_size = alg->max_keysize;
	}
	get_random_bytes(dummy_key, *key_size);
	rc = crypto_blkcipher_setkey(*key_tfm, dummy_key, *key_size);
	if (rc) {
		printk(KERN_ERR "Error attempting to set key of size [%zd] for "
		       "cipher [%s]; rc = [%d]\n", *key_size, full_alg_name,
		       rc);
		rc = -EINVAL;
		goto out;
	}
out:
	kfree(full_alg_name);
	return rc;
}

struct kmem_cache *ecryptfs_key_tfm_cache;
static struct list_head key_tfm_list;
struct mutex key_tfm_list_mutex;

int __init ecryptfs_init_crypto(void)
{
	mutex_init(&key_tfm_list_mutex);
	INIT_LIST_HEAD(&key_tfm_list);
	return 0;
}

/**
 * ecryptfs_destroy_crypto - free all cached key_tfms on key_tfm_list
 *
 * Called only at module unload time
 */
int ecryptfs_destroy_crypto(void)
{
	struct ecryptfs_key_tfm *key_tfm, *key_tfm_tmp;

	mutex_lock(&key_tfm_list_mutex);
	list_for_each_entry_safe(key_tfm, key_tfm_tmp, &key_tfm_list,
				 key_tfm_list) {
		list_del(&key_tfm->key_tfm_list);
		if (key_tfm->key_tfm)
			crypto_free_blkcipher(key_tfm->key_tfm);
		kmem_cache_free(ecryptfs_key_tfm_cache, key_tfm);
	}
	mutex_unlock(&key_tfm_list_mutex);
	return 0;
}

int
ecryptfs_add_new_key_tfm(struct ecryptfs_key_tfm **key_tfm, char *cipher_name,
			 size_t key_size)
{
	struct ecryptfs_key_tfm *tmp_tfm;
	int rc = 0;

	BUG_ON(!mutex_is_locked(&key_tfm_list_mutex));

	tmp_tfm = kmem_cache_alloc(ecryptfs_key_tfm_cache, GFP_KERNEL);
	if (key_tfm != NULL)
		(*key_tfm) = tmp_tfm;
	if (!tmp_tfm) {
		rc = -ENOMEM;
		printk(KERN_ERR "Error attempting to allocate from "
		       "ecryptfs_key_tfm_cache\n");
		goto out;
	}
	mutex_init(&tmp_tfm->key_tfm_mutex);
	strncpy(tmp_tfm->cipher_name, cipher_name,
		ECRYPTFS_MAX_CIPHER_NAME_SIZE);
	tmp_tfm->cipher_name[ECRYPTFS_MAX_CIPHER_NAME_SIZE] = '\0';
	tmp_tfm->key_size = key_size;
	rc = ecryptfs_process_key_cipher(&tmp_tfm->key_tfm,
					 tmp_tfm->cipher_name,
					 &tmp_tfm->key_size);
	if (rc) {
		printk(KERN_ERR "Error attempting to initialize key TFM "
		       "cipher with name = [%s]; rc = [%d]\n",
		       tmp_tfm->cipher_name, rc);
		kmem_cache_free(ecryptfs_key_tfm_cache, tmp_tfm);
		if (key_tfm != NULL)
			(*key_tfm) = NULL;
		goto out;
	}
	list_add(&tmp_tfm->key_tfm_list, &key_tfm_list);
out:
	return rc;
}

/**
 * ecryptfs_tfm_exists - Search for existing tfm for cipher_name.
 * @cipher_name: the name of the cipher to search for
 * @key_tfm: set to corresponding tfm if found
 *
 * Searches for cached key_tfm matching @cipher_name
 * Must be called with &key_tfm_list_mutex held
 * Returns 1 if found, with @key_tfm set
 * Returns 0 if not found, with @key_tfm set to NULL
 */
int ecryptfs_tfm_exists(char *cipher_name, struct ecryptfs_key_tfm **key_tfm)
{
	struct ecryptfs_key_tfm *tmp_key_tfm;

	BUG_ON(!mutex_is_locked(&key_tfm_list_mutex));

	list_for_each_entry(tmp_key_tfm, &key_tfm_list, key_tfm_list) {
		if (strcmp(tmp_key_tfm->cipher_name, cipher_name) == 0) {
			if (key_tfm)
				(*key_tfm) = tmp_key_tfm;
			return 1;
		}
	}
	if (key_tfm)
		(*key_tfm) = NULL;
	return 0;
}

/**
 * ecryptfs_get_tfm_and_mutex_for_cipher_name
 *
 * @tfm: set to cached tfm found, or new tfm created
 * @tfm_mutex: set to mutex for cached tfm found, or new tfm created
 * @cipher_name: the name of the cipher to search for and/or add
 *
 * Sets pointers to @tfm & @tfm_mutex matching @cipher_name.
 * Searches for cached item first, and creates new if not found.
 * Returns 0 on success, non-zero if adding new cipher failed
 */
int ecryptfs_get_tfm_and_mutex_for_cipher_name(struct crypto_blkcipher **tfm,
					       struct mutex **tfm_mutex,
					       char *cipher_name)
{
	struct ecryptfs_key_tfm *key_tfm;
	int rc = 0;

	(*tfm) = NULL;
	(*tfm_mutex) = NULL;

	mutex_lock(&key_tfm_list_mutex);
	if (!ecryptfs_tfm_exists(cipher_name, &key_tfm)) {
		rc = ecryptfs_add_new_key_tfm(&key_tfm, cipher_name, 0);
		if (rc) {
			printk(KERN_ERR "Error adding new key_tfm to list; "
					"rc = [%d]\n", rc);
			goto out;
		}
	}
	(*tfm) = key_tfm->key_tfm;
	(*tfm_mutex) = &key_tfm->key_tfm_mutex;
out:
	mutex_unlock(&key_tfm_list_mutex);
	return rc;
}

/* 64 characters forming a 6-bit target field */
static unsigned char *portable_filename_chars = ("-.0123456789ABCD"
						 "EFGHIJKLMNOPQRST"
						 "UVWXYZabcdefghij"
						 "klmnopqrstuvwxyz");

/* We could either offset on every reverse map or just pad some 0x00's
 * at the front here */
static const unsigned char filename_rev_map[256] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 7 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 15 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 23 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 31 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 39 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* 47 */
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, /* 55 */
	0x0A, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 63 */
	0x00, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, /* 71 */
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, /* 79 */
	0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, /* 87 */
	0x23, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, /* 95 */
	0x00, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, /* 103 */
	0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, /* 111 */
	0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, /* 119 */
	0x3D, 0x3E, 0x3F /* 123 - 255 initialized to 0x00 */
};

/**
 * ecryptfs_encode_for_filename
 * @dst: Destination location for encoded filename
 * @dst_size: Size of the encoded filename in bytes
 * @src: Source location for the filename to encode
 * @src_size: Size of the source in bytes
 */
static void ecryptfs_encode_for_filename(unsigned char *dst, size_t *dst_size,
				  unsigned char *src, size_t src_size)
{
	size_t num_blocks;
	size_t block_num = 0;
	size_t dst_offset = 0;
	unsigned char last_block[3];

	if (src_size == 0) {
		(*dst_size) = 0;
		goto out;
	}
	num_blocks = (src_size / 3);
	if ((src_size % 3) == 0) {
		memcpy(last_block, (&src[src_size - 3]), 3);
	} else {
		num_blocks++;
		last_block[2] = 0x00;
		switch (src_size % 3) {
		case 1:
			last_block[0] = src[src_size - 1];
			last_block[1] = 0x00;
			break;
		case 2:
			last_block[0] = src[src_size - 2];
			last_block[1] = src[src_size - 1];
		}
	}
	(*dst_size) = (num_blocks * 4);
	if (!dst)
		goto out;
	while (block_num < num_blocks) {
		unsigned char *src_block;
		unsigned char dst_block[4];

		if (block_num == (num_blocks - 1))
			src_block = last_block;
		else
			src_block = &src[block_num * 3];
		dst_block[0] = ((src_block[0] >> 2) & 0x3F);
		dst_block[1] = (((src_block[0] << 4) & 0x30)
				| ((src_block[1] >> 4) & 0x0F));
		dst_block[2] = (((src_block[1] << 2) & 0x3C)
				| ((src_block[2] >> 6) & 0x03));
		dst_block[3] = (src_block[2] & 0x3F);
		dst[dst_offset++] = portable_filename_chars[dst_block[0]];
		dst[dst_offset++] = portable_filename_chars[dst_block[1]];
		dst[dst_offset++] = portable_filename_chars[dst_block[2]];
		dst[dst_offset++] = portable_filename_chars[dst_block[3]];
		block_num++;
	}
out:
	return;
}

static size_t ecryptfs_max_decoded_size(size_t encoded_size)
{
	/* Not exact; conservatively long. Every block of 4
	 * encoded characters decodes into a block of 3
	 * decoded characters. This segment of code provides
	 * the caller with the maximum amount of allocated
	 * space that @dst will need to point to in a
	 * subsequent call. */
	return ((encoded_size + 1) * 3) / 4;
}

/**
 * ecryptfs_decode_from_filename
 * @dst: If NULL, this function only sets @dst_size and returns. If
 *       non-NULL, this function decodes the encoded octets in @src
 *       into the memory that @dst points to.
 * @dst_size: Set to the size of the decoded string.
 * @src: The encoded set of octets to decode.
 * @src_size: The size of the encoded set of octets to decode.
 */
static void
ecryptfs_decode_from_filename(unsigned char *dst, size_t *dst_size,
			      const unsigned char *src, size_t src_size)
{
	u8 current_bit_offset = 0;
	size_t src_byte_offset = 0;
	size_t dst_byte_offset = 0;

	if (dst == NULL) {
		(*dst_size) = ecryptfs_max_decoded_size(src_size);
		goto out;
	}
	while (src_byte_offset < src_size) {
		unsigned char src_byte =
				filename_rev_map[(int)src[src_byte_offset]];

		switch (current_bit_offset) {
		case 0:
			dst[dst_byte_offset] = (src_byte << 2);
			current_bit_offset = 6;
			break;
		case 6:
			dst[dst_byte_offset++] |= (src_byte >> 4);
			dst[dst_byte_offset] = ((src_byte & 0xF)
						 << 4);
			current_bit_offset = 4;
			break;
		case 4:
			dst[dst_byte_offset++] |= (src_byte >> 2);
			dst[dst_byte_offset] = (src_byte << 6);
			current_bit_offset = 2;
			break;
		case 2:
			dst[dst_byte_offset++] |= (src_byte);
			current_bit_offset = 0;
			break;
		}
		src_byte_offset++;
	}
	(*dst_size) = dst_byte_offset;
out:
	return;
}

/**
 * ecryptfs_encrypt_and_encode_filename - converts a plaintext file name to cipher text
 * @crypt_stat: The crypt_stat struct associated with the file anem to encode
 * @name: The plaintext name
 * @length: The length of the plaintext
 * @encoded_name: The encypted name
 *
 * Encrypts and encodes a filename into something that constitutes a
 * valid filename for a filesystem, with printable characters.
 *
 * We assume that we have a properly initialized crypto context,
 * pointed to by crypt_stat->tfm.
 *
 * Returns zero on success; non-zero on otherwise
 */
int ecryptfs_encrypt_and_encode_filename(
	char **encoded_name,
	size_t *encoded_name_size,
	struct ecryptfs_crypt_stat *crypt_stat,
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat,
	const char *name, size_t name_size)
{
	size_t encoded_name_no_prefix_size;
	int rc = 0;

	(*encoded_name) = NULL;
	(*encoded_name_size) = 0;
	if ((crypt_stat && (crypt_stat->flags & ECRYPTFS_ENCRYPT_FILENAMES))
	    || (mount_crypt_stat && (mount_crypt_stat->flags
				     & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES))) {
		struct ecryptfs_filename *filename;

		filename = kzalloc(sizeof(*filename), GFP_KERNEL);
		if (!filename) {
			printk(KERN_ERR "%s: Out of memory whilst attempting "
			       "to kzalloc [%zd] bytes\n", __func__,
			       sizeof(*filename));
			rc = -ENOMEM;
			goto out;
		}
		filename->filename = (char *)name;
		filename->filename_size = name_size;
		rc = ecryptfs_encrypt_filename(filename, crypt_stat,
					       mount_crypt_stat);
		if (rc) {
			printk(KERN_ERR "%s: Error attempting to encrypt "
			       "filename; rc = [%d]\n", __func__, rc);
			kfree(filename);
			goto out;
		}
		ecryptfs_encode_for_filename(
			NULL, &encoded_name_no_prefix_size,
			filename->encrypted_filename,
			filename->encrypted_filename_size);
		if ((crypt_stat && (crypt_stat->flags
				    & ECRYPTFS_ENCFN_USE_MOUNT_FNEK))
		    || (mount_crypt_stat
			&& (mount_crypt_stat->flags
			    & ECRYPTFS_GLOBAL_ENCFN_USE_MOUNT_FNEK)))
			(*encoded_name_size) =
				(ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE
				 + encoded_name_no_prefix_size);
		else
			(*encoded_name_size) =
				(ECRYPTFS_FEK_ENCRYPTED_FILENAME_PREFIX_SIZE
				 + encoded_name_no_prefix_size);
		(*encoded_name) = kmalloc((*encoded_name_size) + 1, GFP_KERNEL);
		if (!(*encoded_name)) {
			printk(KERN_ERR "%s: Out of memory whilst attempting "
			       "to kzalloc [%zd] bytes\n", __func__,
			       (*encoded_name_size));
			rc = -ENOMEM;
			kfree(filename->encrypted_filename);
			kfree(filename);
			goto out;
		}
		if ((crypt_stat && (crypt_stat->flags
				    & ECRYPTFS_ENCFN_USE_MOUNT_FNEK))
		    || (mount_crypt_stat
			&& (mount_crypt_stat->flags
			    & ECRYPTFS_GLOBAL_ENCFN_USE_MOUNT_FNEK))) {
			memcpy((*encoded_name),
			       ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX,
			       ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE);
			ecryptfs_encode_for_filename(
			    ((*encoded_name)
			     + ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE),
			    &encoded_name_no_prefix_size,
			    filename->encrypted_filename,
			    filename->encrypted_filename_size);
			(*encoded_name_size) =
				(ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE
				 + encoded_name_no_prefix_size);
			(*encoded_name)[(*encoded_name_size)] = '\0';
		} else {
			rc = -EOPNOTSUPP;
		}
		if (rc) {
			printk(KERN_ERR "%s: Error attempting to encode "
			       "encrypted filename; rc = [%d]\n", __func__,
			       rc);
			kfree((*encoded_name));
			(*encoded_name) = NULL;
			(*encoded_name_size) = 0;
		}
		kfree(filename->encrypted_filename);
		kfree(filename);
	} else {
		rc = ecryptfs_copy_filename(encoded_name,
					    encoded_name_size,
					    name, name_size);
	}
out:
	return rc;
}

/**
 * ecryptfs_decode_and_decrypt_filename - converts the encoded cipher text name to decoded plaintext
 * @plaintext_name: The plaintext name
 * @plaintext_name_size: The plaintext name size
 * @ecryptfs_dir_dentry: eCryptfs directory dentry
 * @name: The filename in cipher text
 * @name_size: The cipher text name size
 *
 * Decrypts and decodes the filename.
 *
 * Returns zero on error; non-zero otherwise
 */
int ecryptfs_decode_and_decrypt_filename(char **plaintext_name,
					 size_t *plaintext_name_size,
					 struct super_block *sb,
					 const char *name, size_t name_size)
{
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(sb)->mount_crypt_stat;
	char *decoded_name;
	size_t decoded_name_size;
	size_t packet_size;
	int rc = 0;

	if ((mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !(mount_crypt_stat->flags & ECRYPTFS_ENCRYPTED_VIEW_ENABLED)
	    && (name_size > ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE)
	    && (strncmp(name, ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX,
			ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE) == 0)) {
		const char *orig_name = name;
		size_t orig_name_size = name_size;

		name += ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE;
		name_size -= ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE;
		ecryptfs_decode_from_filename(NULL, &decoded_name_size,
					      name, name_size);
		decoded_name = kmalloc(decoded_name_size, GFP_KERNEL);
		if (!decoded_name) {
			printk(KERN_ERR "%s: Out of memory whilst attempting "
			       "to kmalloc [%zd] bytes\n", __func__,
			       decoded_name_size);
			rc = -ENOMEM;
			goto out;
		}
		ecryptfs_decode_from_filename(decoded_name, &decoded_name_size,
					      name, name_size);
		rc = ecryptfs_parse_tag_70_packet(plaintext_name,
						  plaintext_name_size,
						  &packet_size,
						  mount_crypt_stat,
						  decoded_name,
						  decoded_name_size);
		if (rc) {
			printk(KERN_INFO "%s: Could not parse tag 70 packet "
			       "from filename; copying through filename "
			       "as-is\n", __func__);
			rc = ecryptfs_copy_filename(plaintext_name,
						    plaintext_name_size,
						    orig_name, orig_name_size);
			goto out_free;
		}
	} else {
		rc = ecryptfs_copy_filename(plaintext_name,
					    plaintext_name_size,
					    name, name_size);
		goto out;
	}
out_free:
	kfree(decoded_name);
out:
	return rc;
}

#define ENC_NAME_MAX_BLOCKLEN_8_OR_16	143

int ecryptfs_set_f_namelen(long *namelen, long lower_namelen,
			   struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	struct blkcipher_desc desc;
	struct mutex *tfm_mutex;
	size_t cipher_blocksize;
	int rc;

	if (!(mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)) {
		(*namelen) = lower_namelen;
		return 0;
	}

	rc = ecryptfs_get_tfm_and_mutex_for_cipher_name(&desc.tfm, &tfm_mutex,
			mount_crypt_stat->global_default_fn_cipher_name);
	if (unlikely(rc)) {
		(*namelen) = 0;
		return rc;
	}

	mutex_lock(tfm_mutex);
	cipher_blocksize = crypto_blkcipher_blocksize(desc.tfm);
	mutex_unlock(tfm_mutex);

	/* Return an exact amount for the common cases */
	if (lower_namelen == NAME_MAX
	    && (cipher_blocksize == 8 || cipher_blocksize == 16)) {
		(*namelen) = ENC_NAME_MAX_BLOCKLEN_8_OR_16;
		return 0;
	}

	/* Return a safe estimate for the uncommon cases */
	(*namelen) = lower_namelen;
	(*namelen) -= ECRYPTFS_FNEK_ENCRYPTED_FILENAME_PREFIX_SIZE;
	/* Since this is the max decoded size, subtract 1 "decoded block" len */
	(*namelen) = ecryptfs_max_decoded_size(*namelen) - 3;
	(*namelen) -= ECRYPTFS_TAG_70_MAX_METADATA_SIZE;
	(*namelen) -= ECRYPTFS_FILENAME_MIN_RANDOM_PREPEND_BYTES;
	/* Worst case is that the filename is padded nearly a full block size */
	(*namelen) -= cipher_blocksize - 1;

	if ((*namelen) < 0)
		(*namelen) = 0;

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/crypto.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 * In-kernel key management code.  Includes functions to parse and
 * write authentication token-related packets with the underlying
 * file.
 *
 * Copyright (C) 2004-2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *              Michael C. Thompson <mcthomps@us.ibm.com>
 *              Trevor S. Highland <trevor.highland@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/string.h>
// #include <linux/pagemap.h>
// #include <linux/key.h>
// #include <linux/random.h>
// #include <linux/crypto.h>
// #include <linux/scatterlist.h>
// #include <linux/slab.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

/**
 * request_key returned an error instead of a valid key address;
 * determine the type of error, make appropriate log entries, and
 * return an error code.
 */
static int process_request_key_err(long err_code)
{
	int rc = 0;

	switch (err_code) {
	case -ENOKEY:
		ecryptfs_printk(KERN_WARNING, "No key\n");
		rc = -ENOENT;
		break;
	case -EKEYEXPIRED:
		ecryptfs_printk(KERN_WARNING, "Key expired\n");
		rc = -ETIME;
		break;
	case -EKEYREVOKED:
		ecryptfs_printk(KERN_WARNING, "Key revoked\n");
		rc = -EINVAL;
		break;
	default:
		ecryptfs_printk(KERN_WARNING, "Unknown error code: "
				"[0x%.16lx]\n", err_code);
		rc = -EINVAL;
	}
	return rc;
}

static int process_find_global_auth_tok_for_sig_err(int err_code)
{
	int rc = err_code;

	switch (err_code) {
	case -ENOENT:
		ecryptfs_printk(KERN_WARNING, "Missing auth tok\n");
		break;
	case -EINVAL:
		ecryptfs_printk(KERN_WARNING, "Invalid auth tok\n");
		break;
	default:
		rc = process_request_key_err(err_code);
		break;
	}
	return rc;
}

/**
 * ecryptfs_parse_packet_length
 * @data: Pointer to memory containing length at offset
 * @size: This function writes the decoded size to this memory
 *        address; zero on error
 * @length_size: The number of bytes occupied by the encoded length
 *
 * Returns zero on success; non-zero on error
 */
int ecryptfs_parse_packet_length(unsigned char *data, size_t *size,
				 size_t *length_size)
{
	int rc = 0;

	(*length_size) = 0;
	(*size) = 0;
	if (data[0] < 192) {
		/* One-byte length */
		(*size) = data[0];
		(*length_size) = 1;
	} else if (data[0] < 224) {
		/* Two-byte length */
		(*size) = (data[0] - 192) * 256;
		(*size) += data[1] + 192;
		(*length_size) = 2;
	} else if (data[0] == 255) {
		/* If support is added, adjust ECRYPTFS_MAX_PKT_LEN_SIZE */
		ecryptfs_printk(KERN_ERR, "Five-byte packet length not "
				"supported\n");
		rc = -EINVAL;
		goto out;
	} else {
		ecryptfs_printk(KERN_ERR, "Error parsing packet length\n");
		rc = -EINVAL;
		goto out;
	}
out:
	return rc;
}

/**
 * ecryptfs_write_packet_length
 * @dest: The byte array target into which to write the length. Must
 *        have at least ECRYPTFS_MAX_PKT_LEN_SIZE bytes allocated.
 * @size: The length to write.
 * @packet_size_length: The number of bytes used to encode the packet
 *                      length is written to this address.
 *
 * Returns zero on success; non-zero on error.
 */
int ecryptfs_write_packet_length(char *dest, size_t size,
				 size_t *packet_size_length)
{
	int rc = 0;

	if (size < 192) {
		dest[0] = size;
		(*packet_size_length) = 1;
	} else if (size < 65536) {
		dest[0] = (((size - 192) / 256) + 192);
		dest[1] = ((size - 192) % 256);
		(*packet_size_length) = 2;
	} else {
		/* If support is added, adjust ECRYPTFS_MAX_PKT_LEN_SIZE */
		rc = -EINVAL;
		ecryptfs_printk(KERN_WARNING,
				"Unsupported packet size: [%zd]\n", size);
	}
	return rc;
}

static int
write_tag_64_packet(char *signature, struct ecryptfs_session_key *session_key,
		    char **packet, size_t *packet_len)
{
	size_t i = 0;
	size_t data_len;
	size_t packet_size_len;
	char *message;
	int rc;

	/*
	 *              ***** TAG 64 Packet Format *****
	 *    | Content Type                       | 1 byte       |
	 *    | Key Identifier Size                | 1 or 2 bytes |
	 *    | Key Identifier                     | arbitrary    |
	 *    | Encrypted File Encryption Key Size | 1 or 2 bytes |
	 *    | Encrypted File Encryption Key      | arbitrary    |
	 */
	data_len = (5 + ECRYPTFS_SIG_SIZE_HEX
		    + session_key->encrypted_key_size);
	*packet = kmalloc(data_len, GFP_KERNEL);
	message = *packet;
	if (!message) {
		ecryptfs_printk(KERN_ERR, "Unable to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	message[i++] = ECRYPTFS_TAG_64_PACKET_TYPE;
	rc = ecryptfs_write_packet_length(&message[i], ECRYPTFS_SIG_SIZE_HEX,
					  &packet_size_len);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error generating tag 64 packet "
				"header; cannot generate packet length\n");
		goto out;
	}
	i += packet_size_len;
	memcpy(&message[i], signature, ECRYPTFS_SIG_SIZE_HEX);
	i += ECRYPTFS_SIG_SIZE_HEX;
	rc = ecryptfs_write_packet_length(&message[i],
					  session_key->encrypted_key_size,
					  &packet_size_len);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error generating tag 64 packet "
				"header; cannot generate packet length\n");
		goto out;
	}
	i += packet_size_len;
	memcpy(&message[i], session_key->encrypted_key,
	       session_key->encrypted_key_size);
	i += session_key->encrypted_key_size;
	*packet_len = i;
out:
	return rc;
}

static int
parse_tag_65_packet(struct ecryptfs_session_key *session_key, u8 *cipher_code,
		    struct ecryptfs_message *msg)
{
	size_t i = 0;
	char *data;
	size_t data_len;
	size_t m_size;
	size_t message_len;
	u16 checksum = 0;
	u16 expected_checksum = 0;
	int rc;

	/*
	 *              ***** TAG 65 Packet Format *****
	 *         | Content Type             | 1 byte       |
	 *         | Status Indicator         | 1 byte       |
	 *         | File Encryption Key Size | 1 or 2 bytes |
	 *         | File Encryption Key      | arbitrary    |
	 */
	message_len = msg->data_len;
	data = msg->data;
	if (message_len < 4) {
		rc = -EIO;
		goto out;
	}
	if (data[i++] != ECRYPTFS_TAG_65_PACKET_TYPE) {
		ecryptfs_printk(KERN_ERR, "Type should be ECRYPTFS_TAG_65\n");
		rc = -EIO;
		goto out;
	}
	if (data[i++]) {
		ecryptfs_printk(KERN_ERR, "Status indicator has non-zero value "
				"[%d]\n", data[i-1]);
		rc = -EIO;
		goto out;
	}
	rc = ecryptfs_parse_packet_length(&data[i], &m_size, &data_len);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error parsing packet length; "
				"rc = [%d]\n", rc);
		goto out;
	}
	i += data_len;
	if (message_len < (i + m_size)) {
		ecryptfs_printk(KERN_ERR, "The message received from ecryptfsd "
				"is shorter than expected\n");
		rc = -EIO;
		goto out;
	}
	if (m_size < 3) {
		ecryptfs_printk(KERN_ERR,
				"The decrypted key is not long enough to "
				"include a cipher code and checksum\n");
		rc = -EIO;
		goto out;
	}
	*cipher_code = data[i++];
	/* The decrypted key includes 1 byte cipher code and 2 byte checksum */
	session_key->decrypted_key_size = m_size - 3;
	if (session_key->decrypted_key_size > ECRYPTFS_MAX_KEY_BYTES) {
		ecryptfs_printk(KERN_ERR, "key_size [%d] larger than "
				"the maximum key size [%d]\n",
				session_key->decrypted_key_size,
				ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES);
		rc = -EIO;
		goto out;
	}
	memcpy(session_key->decrypted_key, &data[i],
	       session_key->decrypted_key_size);
	i += session_key->decrypted_key_size;
	expected_checksum += (unsigned char)(data[i++]) << 8;
	expected_checksum += (unsigned char)(data[i++]);
	for (i = 0; i < session_key->decrypted_key_size; i++)
		checksum += session_key->decrypted_key[i];
	if (expected_checksum != checksum) {
		ecryptfs_printk(KERN_ERR, "Invalid checksum for file "
				"encryption  key; expected [%x]; calculated "
				"[%x]\n", expected_checksum, checksum);
		rc = -EIO;
	}
out:
	return rc;
}


static int
write_tag_66_packet(char *signature, u8 cipher_code,
		    struct ecryptfs_crypt_stat *crypt_stat, char **packet,
		    size_t *packet_len)
{
	size_t i = 0;
	size_t j;
	size_t data_len;
	size_t checksum = 0;
	size_t packet_size_len;
	char *message;
	int rc;

	/*
	 *              ***** TAG 66 Packet Format *****
	 *         | Content Type             | 1 byte       |
	 *         | Key Identifier Size      | 1 or 2 bytes |
	 *         | Key Identifier           | arbitrary    |
	 *         | File Encryption Key Size | 1 or 2 bytes |
	 *         | File Encryption Key      | arbitrary    |
	 */
	data_len = (5 + ECRYPTFS_SIG_SIZE_HEX + crypt_stat->key_size);
	*packet = kmalloc(data_len, GFP_KERNEL);
	message = *packet;
	if (!message) {
		ecryptfs_printk(KERN_ERR, "Unable to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	message[i++] = ECRYPTFS_TAG_66_PACKET_TYPE;
	rc = ecryptfs_write_packet_length(&message[i], ECRYPTFS_SIG_SIZE_HEX,
					  &packet_size_len);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error generating tag 66 packet "
				"header; cannot generate packet length\n");
		goto out;
	}
	i += packet_size_len;
	memcpy(&message[i], signature, ECRYPTFS_SIG_SIZE_HEX);
	i += ECRYPTFS_SIG_SIZE_HEX;
	/* The encrypted key includes 1 byte cipher code and 2 byte checksum */
	rc = ecryptfs_write_packet_length(&message[i], crypt_stat->key_size + 3,
					  &packet_size_len);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error generating tag 66 packet "
				"header; cannot generate packet length\n");
		goto out;
	}
	i += packet_size_len;
	message[i++] = cipher_code;
	memcpy(&message[i], crypt_stat->key, crypt_stat->key_size);
	i += crypt_stat->key_size;
	for (j = 0; j < crypt_stat->key_size; j++)
		checksum += crypt_stat->key[j];
	message[i++] = (checksum / 256) % 256;
	message[i++] = (checksum % 256);
	*packet_len = i;
out:
	return rc;
}

static int
parse_tag_67_packet(struct ecryptfs_key_record *key_rec,
		    struct ecryptfs_message *msg)
{
	size_t i = 0;
	char *data;
	size_t data_len;
	size_t message_len;
	int rc;

	/*
	 *              ***** TAG 65 Packet Format *****
	 *    | Content Type                       | 1 byte       |
	 *    | Status Indicator                   | 1 byte       |
	 *    | Encrypted File Encryption Key Size | 1 or 2 bytes |
	 *    | Encrypted File Encryption Key      | arbitrary    |
	 */
	message_len = msg->data_len;
	data = msg->data;
	/* verify that everything through the encrypted FEK size is present */
	if (message_len < 4) {
		rc = -EIO;
		printk(KERN_ERR "%s: message_len is [%zd]; minimum acceptable "
		       "message length is [%d]\n", __func__, message_len, 4);
		goto out;
	}
	if (data[i++] != ECRYPTFS_TAG_67_PACKET_TYPE) {
		rc = -EIO;
		printk(KERN_ERR "%s: Type should be ECRYPTFS_TAG_67\n",
		       __func__);
		goto out;
	}
	if (data[i++]) {
		rc = -EIO;
		printk(KERN_ERR "%s: Status indicator has non zero "
		       "value [%d]\n", __func__, data[i-1]);

		goto out;
	}
	rc = ecryptfs_parse_packet_length(&data[i], &key_rec->enc_key_size,
					  &data_len);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "Error parsing packet length; "
				"rc = [%d]\n", rc);
		goto out;
	}
	i += data_len;
	if (message_len < (i + key_rec->enc_key_size)) {
		rc = -EIO;
		printk(KERN_ERR "%s: message_len [%zd]; max len is [%zd]\n",
		       __func__, message_len, (i + key_rec->enc_key_size));
		goto out;
	}
	if (key_rec->enc_key_size > ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES) {
		rc = -EIO;
		printk(KERN_ERR "%s: Encrypted key_size [%zd] larger than "
		       "the maximum key size [%d]\n", __func__,
		       key_rec->enc_key_size,
		       ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES);
		goto out;
	}
	memcpy(key_rec->enc_key, &data[i], key_rec->enc_key_size);
out:
	return rc;
}

/**
 * ecryptfs_verify_version
 * @version: The version number to confirm
 *
 * Returns zero on good version; non-zero otherwise
 */
static int ecryptfs_verify_version(u16 version)
{
	int rc = 0;
	unsigned char major;
	unsigned char minor;

	major = ((version >> 8) & 0xFF);
	minor = (version & 0xFF);
	if (major != ECRYPTFS_VERSION_MAJOR) {
		ecryptfs_printk(KERN_ERR, "Major version number mismatch. "
				"Expected [%d]; got [%d]\n",
				ECRYPTFS_VERSION_MAJOR, major);
		rc = -EINVAL;
		goto out;
	}
	if (minor != ECRYPTFS_VERSION_MINOR) {
		ecryptfs_printk(KERN_ERR, "Minor version number mismatch. "
				"Expected [%d]; got [%d]\n",
				ECRYPTFS_VERSION_MINOR, minor);
		rc = -EINVAL;
		goto out;
	}
out:
	return rc;
}

/**
 * ecryptfs_verify_auth_tok_from_key
 * @auth_tok_key: key containing the authentication token
 * @auth_tok: authentication token
 *
 * Returns zero on valid auth tok; -EINVAL otherwise
 */
static int
ecryptfs_verify_auth_tok_from_key(struct key *auth_tok_key,
				  struct ecryptfs_auth_tok **auth_tok)
{
	int rc = 0;

	(*auth_tok) = ecryptfs_get_key_payload_data(auth_tok_key);
	if (ecryptfs_verify_version((*auth_tok)->version)) {
		printk(KERN_ERR "Data structure version mismatch. Userspace "
		       "tools must match eCryptfs kernel module with major "
		       "version [%d] and minor version [%d]\n",
		       ECRYPTFS_VERSION_MAJOR, ECRYPTFS_VERSION_MINOR);
		rc = -EINVAL;
		goto out;
	}
	if ((*auth_tok)->token_type != ECRYPTFS_PASSWORD
	    && (*auth_tok)->token_type != ECRYPTFS_PRIVATE_KEY) {
		printk(KERN_ERR "Invalid auth_tok structure "
		       "returned from key query\n");
		rc = -EINVAL;
		goto out;
	}
out:
	return rc;
}

static int
ecryptfs_find_global_auth_tok_for_sig(
	struct key **auth_tok_key,
	struct ecryptfs_auth_tok **auth_tok,
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat, char *sig)
{
	struct ecryptfs_global_auth_tok *walker;
	int rc = 0;

	(*auth_tok_key) = NULL;
	(*auth_tok) = NULL;
	mutex_lock(&mount_crypt_stat->global_auth_tok_list_mutex);
	list_for_each_entry(walker,
			    &mount_crypt_stat->global_auth_tok_list,
			    mount_crypt_stat_list) {
		if (memcmp(walker->sig, sig, ECRYPTFS_SIG_SIZE_HEX))
			continue;

		if (walker->flags & ECRYPTFS_AUTH_TOK_INVALID) {
			rc = -EINVAL;
			goto out;
		}

		rc = key_validate(walker->global_auth_tok_key);
		if (rc) {
			if (rc == -EKEYEXPIRED)
				goto out;
			goto out_invalid_auth_tok;
		}

		down_write(&(walker->global_auth_tok_key->sem));
		rc = ecryptfs_verify_auth_tok_from_key(
				walker->global_auth_tok_key, auth_tok);
		if (rc)
			goto out_invalid_auth_tok_unlock;

		(*auth_tok_key) = walker->global_auth_tok_key;
		key_get(*auth_tok_key);
		goto out;
	}
	rc = -ENOENT;
	goto out;
out_invalid_auth_tok_unlock:
	up_write(&(walker->global_auth_tok_key->sem));
out_invalid_auth_tok:
	printk(KERN_WARNING "Invalidating auth tok with sig = [%s]\n", sig);
	walker->flags |= ECRYPTFS_AUTH_TOK_INVALID;
	key_put(walker->global_auth_tok_key);
	walker->global_auth_tok_key = NULL;
out:
	mutex_unlock(&mount_crypt_stat->global_auth_tok_list_mutex);
	return rc;
}

/**
 * ecryptfs_find_auth_tok_for_sig
 * @auth_tok: Set to the matching auth_tok; NULL if not found
 * @crypt_stat: inode crypt_stat crypto context
 * @sig: Sig of auth_tok to find
 *
 * For now, this function simply looks at the registered auth_tok's
 * linked off the mount_crypt_stat, so all the auth_toks that can be
 * used must be registered at mount time. This function could
 * potentially try a lot harder to find auth_tok's (e.g., by calling
 * out to ecryptfsd to dynamically retrieve an auth_tok object) so
 * that static registration of auth_tok's will no longer be necessary.
 *
 * Returns zero on no error; non-zero on error
 */
static int
ecryptfs_find_auth_tok_for_sig(
	struct key **auth_tok_key,
	struct ecryptfs_auth_tok **auth_tok,
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat,
	char *sig)
{
	int rc = 0;

	rc = ecryptfs_find_global_auth_tok_for_sig(auth_tok_key, auth_tok,
						   mount_crypt_stat, sig);
	if (rc == -ENOENT) {
		/* if the flag ECRYPTFS_GLOBAL_MOUNT_AUTH_TOK_ONLY is set in the
		 * mount_crypt_stat structure, we prevent to use auth toks that
		 * are not inserted through the ecryptfs_add_global_auth_tok
		 * function.
		 */
		if (mount_crypt_stat->flags
				& ECRYPTFS_GLOBAL_MOUNT_AUTH_TOK_ONLY)
			return -EINVAL;

		rc = ecryptfs_keyring_auth_tok_for_sig(auth_tok_key, auth_tok,
						       sig);
	}
	return rc;
}

/**
 * write_tag_70_packet can gobble a lot of stack space. We stuff most
 * of the function's parameters in a kmalloc'd struct to help reduce
 * eCryptfs' overall stack usage.
 */
struct ecryptfs_write_tag_70_packet_silly_stack {
	u8 cipher_code;
	size_t max_packet_size;
	size_t packet_size_len;
	size_t block_aligned_filename_size;
	size_t block_size;
	size_t i;
	size_t j;
	size_t num_rand_bytes;
	struct mutex *tfm_mutex;
	char *block_aligned_filename;
	struct ecryptfs_auth_tok *auth_tok;
	struct scatterlist src_sg[2];
	struct scatterlist dst_sg[2];
	struct blkcipher_desc desc;
	char iv[ECRYPTFS_MAX_IV_BYTES];
	char hash[ECRYPTFS_TAG_70_DIGEST_SIZE];
	char tmp_hash[ECRYPTFS_TAG_70_DIGEST_SIZE];
	struct hash_desc hash_desc;
	struct scatterlist hash_sg;
};

/**
 * write_tag_70_packet - Write encrypted filename (EFN) packet against FNEK
 * @filename: NULL-terminated filename string
 *
 * This is the simplest mechanism for achieving filename encryption in
 * eCryptfs. It encrypts the given filename with the mount-wide
 * filename encryption key (FNEK) and stores it in a packet to @dest,
 * which the callee will encode and write directly into the dentry
 * name.
 */
int
ecryptfs_write_tag_70_packet(char *dest, size_t *remaining_bytes,
			     size_t *packet_size,
			     struct ecryptfs_mount_crypt_stat *mount_crypt_stat,
			     char *filename, size_t filename_size)
{
	struct ecryptfs_write_tag_70_packet_silly_stack *s;
	struct key *auth_tok_key = NULL;
	int rc = 0;

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		printk(KERN_ERR "%s: Out of memory whilst trying to kmalloc "
		       "[%zd] bytes of kernel memory\n", __func__, sizeof(*s));
		rc = -ENOMEM;
		goto out;
	}
	s->desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	(*packet_size) = 0;
	rc = ecryptfs_find_auth_tok_for_sig(
		&auth_tok_key,
		&s->auth_tok, mount_crypt_stat,
		mount_crypt_stat->global_default_fnek_sig);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to find auth tok for "
		       "fnek sig [%s]; rc = [%d]\n", __func__,
		       mount_crypt_stat->global_default_fnek_sig, rc);
		goto out;
	}
	rc = ecryptfs_get_tfm_and_mutex_for_cipher_name(
		&s->desc.tfm,
		&s->tfm_mutex, mount_crypt_stat->global_default_fn_cipher_name);
	if (unlikely(rc)) {
		printk(KERN_ERR "Internal error whilst attempting to get "
		       "tfm and mutex for cipher name [%s]; rc = [%d]\n",
		       mount_crypt_stat->global_default_fn_cipher_name, rc);
		goto out;
	}
	mutex_lock(s->tfm_mutex);
	s->block_size = crypto_blkcipher_blocksize(s->desc.tfm);
	/* Plus one for the \0 separator between the random prefix
	 * and the plaintext filename */
	s->num_rand_bytes = (ECRYPTFS_FILENAME_MIN_RANDOM_PREPEND_BYTES + 1);
	s->block_aligned_filename_size = (s->num_rand_bytes + filename_size);
	if ((s->block_aligned_filename_size % s->block_size) != 0) {
		s->num_rand_bytes += (s->block_size
				      - (s->block_aligned_filename_size
					 % s->block_size));
		s->block_aligned_filename_size = (s->num_rand_bytes
						  + filename_size);
	}
	/* Octet 0: Tag 70 identifier
	 * Octets 1-N1: Tag 70 packet size (includes cipher identifier
	 *              and block-aligned encrypted filename size)
	 * Octets N1-N2: FNEK sig (ECRYPTFS_SIG_SIZE)
	 * Octet N2-N3: Cipher identifier (1 octet)
	 * Octets N3-N4: Block-aligned encrypted filename
	 *  - Consists of a minimum number of random characters, a \0
	 *    separator, and then the filename */
	s->max_packet_size = (ECRYPTFS_TAG_70_MAX_METADATA_SIZE
			      + s->block_aligned_filename_size);
	if (dest == NULL) {
		(*packet_size) = s->max_packet_size;
		goto out_unlock;
	}
	if (s->max_packet_size > (*remaining_bytes)) {
		printk(KERN_WARNING "%s: Require [%zd] bytes to write; only "
		       "[%zd] available\n", __func__, s->max_packet_size,
		       (*remaining_bytes));
		rc = -EINVAL;
		goto out_unlock;
	}
	s->block_aligned_filename = kzalloc(s->block_aligned_filename_size,
					    GFP_KERNEL);
	if (!s->block_aligned_filename) {
		printk(KERN_ERR "%s: Out of kernel memory whilst attempting to "
		       "kzalloc [%zd] bytes\n", __func__,
		       s->block_aligned_filename_size);
		rc = -ENOMEM;
		goto out_unlock;
	}
	s->i = 0;
	dest[s->i++] = ECRYPTFS_TAG_70_PACKET_TYPE;
	rc = ecryptfs_write_packet_length(&dest[s->i],
					  (ECRYPTFS_SIG_SIZE
					   + 1 /* Cipher code */
					   + s->block_aligned_filename_size),
					  &s->packet_size_len);
	if (rc) {
		printk(KERN_ERR "%s: Error generating tag 70 packet "
		       "header; cannot generate packet length; rc = [%d]\n",
		       __func__, rc);
		goto out_free_unlock;
	}
	s->i += s->packet_size_len;
	ecryptfs_from_hex(&dest[s->i],
			  mount_crypt_stat->global_default_fnek_sig,
			  ECRYPTFS_SIG_SIZE);
	s->i += ECRYPTFS_SIG_SIZE;
	s->cipher_code = ecryptfs_code_for_cipher_string(
		mount_crypt_stat->global_default_fn_cipher_name,
		mount_crypt_stat->global_default_fn_cipher_key_bytes);
	if (s->cipher_code == 0) {
		printk(KERN_WARNING "%s: Unable to generate code for "
		       "cipher [%s] with key bytes [%zd]\n", __func__,
		       mount_crypt_stat->global_default_fn_cipher_name,
		       mount_crypt_stat->global_default_fn_cipher_key_bytes);
		rc = -EINVAL;
		goto out_free_unlock;
	}
	dest[s->i++] = s->cipher_code;
	/* TODO: Support other key modules than passphrase for
	 * filename encryption */
	if (s->auth_tok->token_type != ECRYPTFS_PASSWORD) {
		rc = -EOPNOTSUPP;
		printk(KERN_INFO "%s: Filename encryption only supports "
		       "password tokens\n", __func__);
		goto out_free_unlock;
	}
	sg_init_one(
		&s->hash_sg,
		(u8 *)s->auth_tok->token.password.session_key_encryption_key,
		s->auth_tok->token.password.session_key_encryption_key_bytes);
	s->hash_desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	s->hash_desc.tfm = crypto_alloc_hash(ECRYPTFS_TAG_70_DIGEST, 0,
					     CRYPTO_ALG_ASYNC);
	if (IS_ERR(s->hash_desc.tfm)) {
			rc = PTR_ERR(s->hash_desc.tfm);
			printk(KERN_ERR "%s: Error attempting to "
			       "allocate hash crypto context; rc = [%d]\n",
			       __func__, rc);
			goto out_free_unlock;
	}
	rc = crypto_hash_init(&s->hash_desc);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error initializing crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out_release_free_unlock;
	}
	rc = crypto_hash_update(
		&s->hash_desc, &s->hash_sg,
		s->auth_tok->token.password.session_key_encryption_key_bytes);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error updating crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out_release_free_unlock;
	}
	rc = crypto_hash_final(&s->hash_desc, s->hash);
	if (rc) {
		printk(KERN_ERR
		       "%s: Error finalizing crypto hash; rc = [%d]\n",
		       __func__, rc);
		goto out_release_free_unlock;
	}
	for (s->j = 0; s->j < (s->num_rand_bytes - 1); s->j++) {
		s->block_aligned_filename[s->j] =
			s->hash[(s->j % ECRYPTFS_TAG_70_DIGEST_SIZE)];
		if ((s->j % ECRYPTFS_TAG_70_DIGEST_SIZE)
		    == (ECRYPTFS_TAG_70_DIGEST_SIZE - 1)) {
			sg_init_one(&s->hash_sg, (u8 *)s->hash,
				    ECRYPTFS_TAG_70_DIGEST_SIZE);
			rc = crypto_hash_init(&s->hash_desc);
			if (rc) {
				printk(KERN_ERR
				       "%s: Error initializing crypto hash; "
				       "rc = [%d]\n", __func__, rc);
				goto out_release_free_unlock;
			}
			rc = crypto_hash_update(&s->hash_desc, &s->hash_sg,
						ECRYPTFS_TAG_70_DIGEST_SIZE);
			if (rc) {
				printk(KERN_ERR
				       "%s: Error updating crypto hash; "
				       "rc = [%d]\n", __func__, rc);
				goto out_release_free_unlock;
			}
			rc = crypto_hash_final(&s->hash_desc, s->tmp_hash);
			if (rc) {
				printk(KERN_ERR
				       "%s: Error finalizing crypto hash; "
				       "rc = [%d]\n", __func__, rc);
				goto out_release_free_unlock;
			}
			memcpy(s->hash, s->tmp_hash,
			       ECRYPTFS_TAG_70_DIGEST_SIZE);
		}
		if (s->block_aligned_filename[s->j] == '\0')
			s->block_aligned_filename[s->j] = ECRYPTFS_NON_NULL;
	}
	memcpy(&s->block_aligned_filename[s->num_rand_bytes], filename,
	       filename_size);
	rc = virt_to_scatterlist(s->block_aligned_filename,
				 s->block_aligned_filename_size, s->src_sg, 2);
	if (rc < 1) {
		printk(KERN_ERR "%s: Internal error whilst attempting to "
		       "convert filename memory to scatterlist; rc = [%d]. "
		       "block_aligned_filename_size = [%zd]\n", __func__, rc,
		       s->block_aligned_filename_size);
		goto out_release_free_unlock;
	}
	rc = virt_to_scatterlist(&dest[s->i], s->block_aligned_filename_size,
				 s->dst_sg, 2);
	if (rc < 1) {
		printk(KERN_ERR "%s: Internal error whilst attempting to "
		       "convert encrypted filename memory to scatterlist; "
		       "rc = [%d]. block_aligned_filename_size = [%zd]\n",
		       __func__, rc, s->block_aligned_filename_size);
		goto out_release_free_unlock;
	}
	/* The characters in the first block effectively do the job
	 * of the IV here, so we just use 0's for the IV. Note the
	 * constraint that ECRYPTFS_FILENAME_MIN_RANDOM_PREPEND_BYTES
	 * >= ECRYPTFS_MAX_IV_BYTES. */
	memset(s->iv, 0, ECRYPTFS_MAX_IV_BYTES);
	s->desc.info = s->iv;
	rc = crypto_blkcipher_setkey(
		s->desc.tfm,
		s->auth_tok->token.password.session_key_encryption_key,
		mount_crypt_stat->global_default_fn_cipher_key_bytes);
	if (rc < 0) {
		printk(KERN_ERR "%s: Error setting key for crypto context; "
		       "rc = [%d]. s->auth_tok->token.password.session_key_"
		       "encryption_key = [0x%p]; mount_crypt_stat->"
		       "global_default_fn_cipher_key_bytes = [%zd]\n", __func__,
		       rc,
		       s->auth_tok->token.password.session_key_encryption_key,
		       mount_crypt_stat->global_default_fn_cipher_key_bytes);
		goto out_release_free_unlock;
	}
	rc = crypto_blkcipher_encrypt_iv(&s->desc, s->dst_sg, s->src_sg,
					 s->block_aligned_filename_size);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to encrypt filename; "
		       "rc = [%d]\n", __func__, rc);
		goto out_release_free_unlock;
	}
	s->i += s->block_aligned_filename_size;
	(*packet_size) = s->i;
	(*remaining_bytes) -= (*packet_size);
out_release_free_unlock:
	crypto_free_hash(s->hash_desc.tfm);
out_free_unlock:
	kzfree(s->block_aligned_filename);
out_unlock:
	mutex_unlock(s->tfm_mutex);
out:
	if (auth_tok_key) {
		up_write(&(auth_tok_key->sem));
		key_put(auth_tok_key);
	}
	kfree(s);
	return rc;
}

struct ecryptfs_parse_tag_70_packet_silly_stack {
	u8 cipher_code;
	size_t max_packet_size;
	size_t packet_size_len;
	size_t parsed_tag_70_packet_size;
	size_t block_aligned_filename_size;
	size_t block_size;
	size_t i;
	struct mutex *tfm_mutex;
	char *decrypted_filename;
	struct ecryptfs_auth_tok *auth_tok;
	struct scatterlist src_sg[2];
	struct scatterlist dst_sg[2];
	struct blkcipher_desc desc;
	char fnek_sig_hex[ECRYPTFS_SIG_SIZE_HEX + 1];
	char iv[ECRYPTFS_MAX_IV_BYTES];
	char cipher_string[ECRYPTFS_MAX_CIPHER_NAME_SIZE];
};

/**
 * parse_tag_70_packet - Parse and process FNEK-encrypted passphrase packet
 * @filename: This function kmalloc's the memory for the filename
 * @filename_size: This function sets this to the amount of memory
 *                 kmalloc'd for the filename
 * @packet_size: This function sets this to the the number of octets
 *               in the packet parsed
 * @mount_crypt_stat: The mount-wide cryptographic context
 * @data: The memory location containing the start of the tag 70
 *        packet
 * @max_packet_size: The maximum legal size of the packet to be parsed
 *                   from @data
 *
 * Returns zero on success; non-zero otherwise
 */
int
ecryptfs_parse_tag_70_packet(char **filename, size_t *filename_size,
			     size_t *packet_size,
			     struct ecryptfs_mount_crypt_stat *mount_crypt_stat,
			     char *data, size_t max_packet_size)
{
	struct ecryptfs_parse_tag_70_packet_silly_stack *s;
	struct key *auth_tok_key = NULL;
	int rc = 0;

	(*packet_size) = 0;
	(*filename_size) = 0;
	(*filename) = NULL;
	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		printk(KERN_ERR "%s: Out of memory whilst trying to kmalloc "
		       "[%zd] bytes of kernel memory\n", __func__, sizeof(*s));
		rc = -ENOMEM;
		goto out;
	}
	s->desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	if (max_packet_size < ECRYPTFS_TAG_70_MIN_METADATA_SIZE) {
		printk(KERN_WARNING "%s: max_packet_size is [%zd]; it must be "
		       "at least [%d]\n", __func__, max_packet_size,
		       ECRYPTFS_TAG_70_MIN_METADATA_SIZE);
		rc = -EINVAL;
		goto out;
	}
	/* Octet 0: Tag 70 identifier
	 * Octets 1-N1: Tag 70 packet size (includes cipher identifier
	 *              and block-aligned encrypted filename size)
	 * Octets N1-N2: FNEK sig (ECRYPTFS_SIG_SIZE)
	 * Octet N2-N3: Cipher identifier (1 octet)
	 * Octets N3-N4: Block-aligned encrypted filename
	 *  - Consists of a minimum number of random numbers, a \0
	 *    separator, and then the filename */
	if (data[(*packet_size)++] != ECRYPTFS_TAG_70_PACKET_TYPE) {
		printk(KERN_WARNING "%s: Invalid packet tag [0x%.2x]; must be "
		       "tag [0x%.2x]\n", __func__,
		       data[((*packet_size) - 1)], ECRYPTFS_TAG_70_PACKET_TYPE);
		rc = -EINVAL;
		goto out;
	}
	rc = ecryptfs_parse_packet_length(&data[(*packet_size)],
					  &s->parsed_tag_70_packet_size,
					  &s->packet_size_len);
	if (rc) {
		printk(KERN_WARNING "%s: Error parsing packet length; "
		       "rc = [%d]\n", __func__, rc);
		goto out;
	}
	s->block_aligned_filename_size = (s->parsed_tag_70_packet_size
					  - ECRYPTFS_SIG_SIZE - 1);
	if ((1 + s->packet_size_len + s->parsed_tag_70_packet_size)
	    > max_packet_size) {
		printk(KERN_WARNING "%s: max_packet_size is [%zd]; real packet "
		       "size is [%zd]\n", __func__, max_packet_size,
		       (1 + s->packet_size_len + 1
			+ s->block_aligned_filename_size));
		rc = -EINVAL;
		goto out;
	}
	(*packet_size) += s->packet_size_len;
	ecryptfs_to_hex(s->fnek_sig_hex, &data[(*packet_size)],
			ECRYPTFS_SIG_SIZE);
	s->fnek_sig_hex[ECRYPTFS_SIG_SIZE_HEX] = '\0';
	(*packet_size) += ECRYPTFS_SIG_SIZE;
	s->cipher_code = data[(*packet_size)++];
	rc = ecryptfs_cipher_code_to_string(s->cipher_string, s->cipher_code);
	if (rc) {
		printk(KERN_WARNING "%s: Cipher code [%d] is invalid\n",
		       __func__, s->cipher_code);
		goto out;
	}
	rc = ecryptfs_find_auth_tok_for_sig(&auth_tok_key,
					    &s->auth_tok, mount_crypt_stat,
					    s->fnek_sig_hex);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to find auth tok for "
		       "fnek sig [%s]; rc = [%d]\n", __func__, s->fnek_sig_hex,
		       rc);
		goto out;
	}
	rc = ecryptfs_get_tfm_and_mutex_for_cipher_name(&s->desc.tfm,
							&s->tfm_mutex,
							s->cipher_string);
	if (unlikely(rc)) {
		printk(KERN_ERR "Internal error whilst attempting to get "
		       "tfm and mutex for cipher name [%s]; rc = [%d]\n",
		       s->cipher_string, rc);
		goto out;
	}
	mutex_lock(s->tfm_mutex);
	rc = virt_to_scatterlist(&data[(*packet_size)],
				 s->block_aligned_filename_size, s->src_sg, 2);
	if (rc < 1) {
		printk(KERN_ERR "%s: Internal error whilst attempting to "
		       "convert encrypted filename memory to scatterlist; "
		       "rc = [%d]. block_aligned_filename_size = [%zd]\n",
		       __func__, rc, s->block_aligned_filename_size);
		goto out_unlock;
	}
	(*packet_size) += s->block_aligned_filename_size;
	s->decrypted_filename = kmalloc(s->block_aligned_filename_size,
					GFP_KERNEL);
	if (!s->decrypted_filename) {
		printk(KERN_ERR "%s: Out of memory whilst attempting to "
		       "kmalloc [%zd] bytes\n", __func__,
		       s->block_aligned_filename_size);
		rc = -ENOMEM;
		goto out_unlock;
	}
	rc = virt_to_scatterlist(s->decrypted_filename,
				 s->block_aligned_filename_size, s->dst_sg, 2);
	if (rc < 1) {
		printk(KERN_ERR "%s: Internal error whilst attempting to "
		       "convert decrypted filename memory to scatterlist; "
		       "rc = [%d]. block_aligned_filename_size = [%zd]\n",
		       __func__, rc, s->block_aligned_filename_size);
		goto out_free_unlock;
	}
	/* The characters in the first block effectively do the job of
	 * the IV here, so we just use 0's for the IV. Note the
	 * constraint that ECRYPTFS_FILENAME_MIN_RANDOM_PREPEND_BYTES
	 * >= ECRYPTFS_MAX_IV_BYTES. */
	memset(s->iv, 0, ECRYPTFS_MAX_IV_BYTES);
	s->desc.info = s->iv;
	/* TODO: Support other key modules than passphrase for
	 * filename encryption */
	if (s->auth_tok->token_type != ECRYPTFS_PASSWORD) {
		rc = -EOPNOTSUPP;
		printk(KERN_INFO "%s: Filename encryption only supports "
		       "password tokens\n", __func__);
		goto out_free_unlock;
	}
	rc = crypto_blkcipher_setkey(
		s->desc.tfm,
		s->auth_tok->token.password.session_key_encryption_key,
		mount_crypt_stat->global_default_fn_cipher_key_bytes);
	if (rc < 0) {
		printk(KERN_ERR "%s: Error setting key for crypto context; "
		       "rc = [%d]. s->auth_tok->token.password.session_key_"
		       "encryption_key = [0x%p]; mount_crypt_stat->"
		       "global_default_fn_cipher_key_bytes = [%zd]\n", __func__,
		       rc,
		       s->auth_tok->token.password.session_key_encryption_key,
		       mount_crypt_stat->global_default_fn_cipher_key_bytes);
		goto out_free_unlock;
	}
	rc = crypto_blkcipher_decrypt_iv(&s->desc, s->dst_sg, s->src_sg,
					 s->block_aligned_filename_size);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to decrypt filename; "
		       "rc = [%d]\n", __func__, rc);
		goto out_free_unlock;
	}
	s->i = 0;
	while (s->decrypted_filename[s->i] != '\0'
	       && s->i < s->block_aligned_filename_size)
		s->i++;
	if (s->i == s->block_aligned_filename_size) {
		printk(KERN_WARNING "%s: Invalid tag 70 packet; could not "
		       "find valid separator between random characters and "
		       "the filename\n", __func__);
		rc = -EINVAL;
		goto out_free_unlock;
	}
	s->i++;
	(*filename_size) = (s->block_aligned_filename_size - s->i);
	if (!((*filename_size) > 0 && (*filename_size < PATH_MAX))) {
		printk(KERN_WARNING "%s: Filename size is [%zd], which is "
		       "invalid\n", __func__, (*filename_size));
		rc = -EINVAL;
		goto out_free_unlock;
	}
	(*filename) = kmalloc(((*filename_size) + 1), GFP_KERNEL);
	if (!(*filename)) {
		printk(KERN_ERR "%s: Out of memory whilst attempting to "
		       "kmalloc [%zd] bytes\n", __func__,
		       ((*filename_size) + 1));
		rc = -ENOMEM;
		goto out_free_unlock;
	}
	memcpy((*filename), &s->decrypted_filename[s->i], (*filename_size));
	(*filename)[(*filename_size)] = '\0';
out_free_unlock:
	kfree(s->decrypted_filename);
out_unlock:
	mutex_unlock(s->tfm_mutex);
out:
	if (rc) {
		(*packet_size) = 0;
		(*filename_size) = 0;
		(*filename) = NULL;
	}
	if (auth_tok_key) {
		up_write(&(auth_tok_key->sem));
		key_put(auth_tok_key);
	}
	kfree(s);
	return rc;
}

static int
ecryptfs_get_auth_tok_sig(char **sig, struct ecryptfs_auth_tok *auth_tok)
{
	int rc = 0;

	(*sig) = NULL;
	switch (auth_tok->token_type) {
	case ECRYPTFS_PASSWORD:
		(*sig) = auth_tok->token.password.signature;
		break;
	case ECRYPTFS_PRIVATE_KEY:
		(*sig) = auth_tok->token.private_key.signature;
		break;
	default:
		printk(KERN_ERR "Cannot get sig for auth_tok of type [%d]\n",
		       auth_tok->token_type);
		rc = -EINVAL;
	}
	return rc;
}

/**
 * decrypt_pki_encrypted_session_key - Decrypt the session key with the given auth_tok.
 * @auth_tok: The key authentication token used to decrypt the session key
 * @crypt_stat: The cryptographic context
 *
 * Returns zero on success; non-zero error otherwise.
 */
static int
decrypt_pki_encrypted_session_key(struct ecryptfs_auth_tok *auth_tok,
				  struct ecryptfs_crypt_stat *crypt_stat)
{
	u8 cipher_code = 0;
	struct ecryptfs_msg_ctx *msg_ctx;
	struct ecryptfs_message *msg = NULL;
	char *auth_tok_sig;
	char *payload = NULL;
	size_t payload_len = 0;
	int rc;

	rc = ecryptfs_get_auth_tok_sig(&auth_tok_sig, auth_tok);
	if (rc) {
		printk(KERN_ERR "Unrecognized auth tok type: [%d]\n",
		       auth_tok->token_type);
		goto out;
	}
	rc = write_tag_64_packet(auth_tok_sig, &(auth_tok->session_key),
				 &payload, &payload_len);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Failed to write tag 64 packet\n");
		goto out;
	}
	rc = ecryptfs_send_message(payload, payload_len, &msg_ctx);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error sending message to "
				"ecryptfsd: %d\n", rc);
		goto out;
	}
	rc = ecryptfs_wait_for_response(msg_ctx, &msg);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Failed to receive tag 65 packet "
				"from the user space daemon\n");
		rc = -EIO;
		goto out;
	}
	rc = parse_tag_65_packet(&(auth_tok->session_key),
				 &cipher_code, msg);
	if (rc) {
		printk(KERN_ERR "Failed to parse tag 65 packet; rc = [%d]\n",
		       rc);
		goto out;
	}
	auth_tok->session_key.flags |= ECRYPTFS_CONTAINS_DECRYPTED_KEY;
	memcpy(crypt_stat->key, auth_tok->session_key.decrypted_key,
	       auth_tok->session_key.decrypted_key_size);
	crypt_stat->key_size = auth_tok->session_key.decrypted_key_size;
	rc = ecryptfs_cipher_code_to_string(crypt_stat->cipher, cipher_code);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Cipher code [%d] is invalid\n",
				cipher_code)
		goto out;
	}
	crypt_stat->flags |= ECRYPTFS_KEY_VALID;
	if (ecryptfs_verbosity > 0) {
		ecryptfs_printk(KERN_DEBUG, "Decrypted session key:\n");
		ecryptfs_dump_hex(crypt_stat->key,
				  crypt_stat->key_size);
	}
out:
	kfree(msg);
	kfree(payload);
	return rc;
}

static void wipe_auth_tok_list(struct list_head *auth_tok_list_head)
{
	struct ecryptfs_auth_tok_list_item *auth_tok_list_item;
	struct ecryptfs_auth_tok_list_item *auth_tok_list_item_tmp;

	list_for_each_entry_safe(auth_tok_list_item, auth_tok_list_item_tmp,
				 auth_tok_list_head, list) {
		list_del(&auth_tok_list_item->list);
		kmem_cache_free(ecryptfs_auth_tok_list_item_cache,
				auth_tok_list_item);
	}
}

struct kmem_cache *ecryptfs_auth_tok_list_item_cache;

/**
 * parse_tag_1_packet
 * @crypt_stat: The cryptographic context to modify based on packet contents
 * @data: The raw bytes of the packet.
 * @auth_tok_list: eCryptfs parses packets into authentication tokens;
 *                 a new authentication token will be placed at the
 *                 end of this list for this packet.
 * @new_auth_tok: Pointer to a pointer to memory that this function
 *                allocates; sets the memory address of the pointer to
 *                NULL on error. This object is added to the
 *                auth_tok_list.
 * @packet_size: This function writes the size of the parsed packet
 *               into this memory location; zero on error.
 * @max_packet_size: The maximum allowable packet size
 *
 * Returns zero on success; non-zero on error.
 */
static int
parse_tag_1_packet(struct ecryptfs_crypt_stat *crypt_stat,
		   unsigned char *data, struct list_head *auth_tok_list,
		   struct ecryptfs_auth_tok **new_auth_tok,
		   size_t *packet_size, size_t max_packet_size)
{
	size_t body_size;
	struct ecryptfs_auth_tok_list_item *auth_tok_list_item;
	size_t length_size;
	int rc = 0;

	(*packet_size) = 0;
	(*new_auth_tok) = NULL;
	/**
	 * This format is inspired by OpenPGP; see RFC 2440
	 * packet tag 1
	 *
	 * Tag 1 identifier (1 byte)
	 * Max Tag 1 packet size (max 3 bytes)
	 * Version (1 byte)
	 * Key identifier (8 bytes; ECRYPTFS_SIG_SIZE)
	 * Cipher identifier (1 byte)
	 * Encrypted key size (arbitrary)
	 *
	 * 12 bytes minimum packet size
	 */
	if (unlikely(max_packet_size < 12)) {
		printk(KERN_ERR "Invalid max packet size; must be >=12\n");
		rc = -EINVAL;
		goto out;
	}
	if (data[(*packet_size)++] != ECRYPTFS_TAG_1_PACKET_TYPE) {
		printk(KERN_ERR "Enter w/ first byte != 0x%.2x\n",
		       ECRYPTFS_TAG_1_PACKET_TYPE);
		rc = -EINVAL;
		goto out;
	}
	/* Released: wipe_auth_tok_list called in ecryptfs_parse_packet_set or
	 * at end of function upon failure */
	auth_tok_list_item =
		kmem_cache_zalloc(ecryptfs_auth_tok_list_item_cache,
				  GFP_KERNEL);
	if (!auth_tok_list_item) {
		printk(KERN_ERR "Unable to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	(*new_auth_tok) = &auth_tok_list_item->auth_tok;
	rc = ecryptfs_parse_packet_length(&data[(*packet_size)], &body_size,
					  &length_size);
	if (rc) {
		printk(KERN_WARNING "Error parsing packet length; "
		       "rc = [%d]\n", rc);
		goto out_free;
	}
	if (unlikely(body_size < (ECRYPTFS_SIG_SIZE + 2))) {
		printk(KERN_WARNING "Invalid body size ([%td])\n", body_size);
		rc = -EINVAL;
		goto out_free;
	}
	(*packet_size) += length_size;
	if (unlikely((*packet_size) + body_size > max_packet_size)) {
		printk(KERN_WARNING "Packet size exceeds max\n");
		rc = -EINVAL;
		goto out_free;
	}
	if (unlikely(data[(*packet_size)++] != 0x03)) {
		printk(KERN_WARNING "Unknown version number [%d]\n",
		       data[(*packet_size) - 1]);
		rc = -EINVAL;
		goto out_free;
	}
	ecryptfs_to_hex((*new_auth_tok)->token.private_key.signature,
			&data[(*packet_size)], ECRYPTFS_SIG_SIZE);
	*packet_size += ECRYPTFS_SIG_SIZE;
	/* This byte is skipped because the kernel does not need to
	 * know which public key encryption algorithm was used */
	(*packet_size)++;
	(*new_auth_tok)->session_key.encrypted_key_size =
		body_size - (ECRYPTFS_SIG_SIZE + 2);
	if ((*new_auth_tok)->session_key.encrypted_key_size
	    > ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES) {
		printk(KERN_WARNING "Tag 1 packet contains key larger "
		       "than ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES");
		rc = -EINVAL;
		goto out;
	}
	memcpy((*new_auth_tok)->session_key.encrypted_key,
	       &data[(*packet_size)], (body_size - (ECRYPTFS_SIG_SIZE + 2)));
	(*packet_size) += (*new_auth_tok)->session_key.encrypted_key_size;
	(*new_auth_tok)->session_key.flags &=
		~ECRYPTFS_CONTAINS_DECRYPTED_KEY;
	(*new_auth_tok)->session_key.flags |=
		ECRYPTFS_CONTAINS_ENCRYPTED_KEY;
	(*new_auth_tok)->token_type = ECRYPTFS_PRIVATE_KEY;
	(*new_auth_tok)->flags = 0;
	(*new_auth_tok)->session_key.flags &=
		~(ECRYPTFS_USERSPACE_SHOULD_TRY_TO_DECRYPT);
	(*new_auth_tok)->session_key.flags &=
		~(ECRYPTFS_USERSPACE_SHOULD_TRY_TO_ENCRYPT);
	list_add(&auth_tok_list_item->list, auth_tok_list);
	goto out;
out_free:
	(*new_auth_tok) = NULL;
	memset(auth_tok_list_item, 0,
	       sizeof(struct ecryptfs_auth_tok_list_item));
	kmem_cache_free(ecryptfs_auth_tok_list_item_cache,
			auth_tok_list_item);
out:
	if (rc)
		(*packet_size) = 0;
	return rc;
}

/**
 * parse_tag_3_packet
 * @crypt_stat: The cryptographic context to modify based on packet
 *              contents.
 * @data: The raw bytes of the packet.
 * @auth_tok_list: eCryptfs parses packets into authentication tokens;
 *                 a new authentication token will be placed at the end
 *                 of this list for this packet.
 * @new_auth_tok: Pointer to a pointer to memory that this function
 *                allocates; sets the memory address of the pointer to
 *                NULL on error. This object is added to the
 *                auth_tok_list.
 * @packet_size: This function writes the size of the parsed packet
 *               into this memory location; zero on error.
 * @max_packet_size: maximum number of bytes to parse
 *
 * Returns zero on success; non-zero on error.
 */
static int
parse_tag_3_packet(struct ecryptfs_crypt_stat *crypt_stat,
		   unsigned char *data, struct list_head *auth_tok_list,
		   struct ecryptfs_auth_tok **new_auth_tok,
		   size_t *packet_size, size_t max_packet_size)
{
	size_t body_size;
	struct ecryptfs_auth_tok_list_item *auth_tok_list_item;
	size_t length_size;
	int rc = 0;

	(*packet_size) = 0;
	(*new_auth_tok) = NULL;
	/**
	 *This format is inspired by OpenPGP; see RFC 2440
	 * packet tag 3
	 *
	 * Tag 3 identifier (1 byte)
	 * Max Tag 3 packet size (max 3 bytes)
	 * Version (1 byte)
	 * Cipher code (1 byte)
	 * S2K specifier (1 byte)
	 * Hash identifier (1 byte)
	 * Salt (ECRYPTFS_SALT_SIZE)
	 * Hash iterations (1 byte)
	 * Encrypted key (arbitrary)
	 *
	 * (ECRYPTFS_SALT_SIZE + 7) minimum packet size
	 */
	if (max_packet_size < (ECRYPTFS_SALT_SIZE + 7)) {
		printk(KERN_ERR "Max packet size too large\n");
		rc = -EINVAL;
		goto out;
	}
	if (data[(*packet_size)++] != ECRYPTFS_TAG_3_PACKET_TYPE) {
		printk(KERN_ERR "First byte != 0x%.2x; invalid packet\n",
		       ECRYPTFS_TAG_3_PACKET_TYPE);
		rc = -EINVAL;
		goto out;
	}
	/* Released: wipe_auth_tok_list called in ecryptfs_parse_packet_set or
	 * at end of function upon failure */
	auth_tok_list_item =
	    kmem_cache_zalloc(ecryptfs_auth_tok_list_item_cache, GFP_KERNEL);
	if (!auth_tok_list_item) {
		printk(KERN_ERR "Unable to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	(*new_auth_tok) = &auth_tok_list_item->auth_tok;
	rc = ecryptfs_parse_packet_length(&data[(*packet_size)], &body_size,
					  &length_size);
	if (rc) {
		printk(KERN_WARNING "Error parsing packet length; rc = [%d]\n",
		       rc);
		goto out_free;
	}
	if (unlikely(body_size < (ECRYPTFS_SALT_SIZE + 5))) {
		printk(KERN_WARNING "Invalid body size ([%td])\n", body_size);
		rc = -EINVAL;
		goto out_free;
	}
	(*packet_size) += length_size;
	if (unlikely((*packet_size) + body_size > max_packet_size)) {
		printk(KERN_ERR "Packet size exceeds max\n");
		rc = -EINVAL;
		goto out_free;
	}
	(*new_auth_tok)->session_key.encrypted_key_size =
		(body_size - (ECRYPTFS_SALT_SIZE + 5));
	if ((*new_auth_tok)->session_key.encrypted_key_size
	    > ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES) {
		printk(KERN_WARNING "Tag 3 packet contains key larger "
		       "than ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES\n");
		rc = -EINVAL;
		goto out_free;
	}
	if (unlikely(data[(*packet_size)++] != 0x04)) {
		printk(KERN_WARNING "Unknown version number [%d]\n",
		       data[(*packet_size) - 1]);
		rc = -EINVAL;
		goto out_free;
	}
	rc = ecryptfs_cipher_code_to_string(crypt_stat->cipher,
					    (u16)data[(*packet_size)]);
	if (rc)
		goto out_free;
	/* A little extra work to differentiate among the AES key
	 * sizes; see RFC2440 */
	switch(data[(*packet_size)++]) {
	case RFC2440_CIPHER_AES_192:
		crypt_stat->key_size = 24;
		break;
	default:
		crypt_stat->key_size =
			(*new_auth_tok)->session_key.encrypted_key_size;
	}
	rc = ecryptfs_init_crypt_ctx(crypt_stat);
	if (rc)
		goto out_free;
	if (unlikely(data[(*packet_size)++] != 0x03)) {
		printk(KERN_WARNING "Only S2K ID 3 is currently supported\n");
		rc = -ENOSYS;
		goto out_free;
	}
	/* TODO: finish the hash mapping */
	switch (data[(*packet_size)++]) {
	case 0x01: /* See RFC2440 for these numbers and their mappings */
		/* Choose MD5 */
		memcpy((*new_auth_tok)->token.password.salt,
		       &data[(*packet_size)], ECRYPTFS_SALT_SIZE);
		(*packet_size) += ECRYPTFS_SALT_SIZE;
		/* This conversion was taken straight from RFC2440 */
		(*new_auth_tok)->token.password.hash_iterations =
			((u32) 16 + (data[(*packet_size)] & 15))
				<< ((data[(*packet_size)] >> 4) + 6);
		(*packet_size)++;
		/* Friendly reminder:
		 * (*new_auth_tok)->session_key.encrypted_key_size =
		 *         (body_size - (ECRYPTFS_SALT_SIZE + 5)); */
		memcpy((*new_auth_tok)->session_key.encrypted_key,
		       &data[(*packet_size)],
		       (*new_auth_tok)->session_key.encrypted_key_size);
		(*packet_size) +=
			(*new_auth_tok)->session_key.encrypted_key_size;
		(*new_auth_tok)->session_key.flags &=
			~ECRYPTFS_CONTAINS_DECRYPTED_KEY;
		(*new_auth_tok)->session_key.flags |=
			ECRYPTFS_CONTAINS_ENCRYPTED_KEY;
		(*new_auth_tok)->token.password.hash_algo = 0x01; /* MD5 */
		break;
	default:
		ecryptfs_printk(KERN_ERR, "Unsupported hash algorithm: "
				"[%d]\n", data[(*packet_size) - 1]);
		rc = -ENOSYS;
		goto out_free;
	}
	(*new_auth_tok)->token_type = ECRYPTFS_PASSWORD;
	/* TODO: Parametarize; we might actually want userspace to
	 * decrypt the session key. */
	(*new_auth_tok)->session_key.flags &=
			    ~(ECRYPTFS_USERSPACE_SHOULD_TRY_TO_DECRYPT);
	(*new_auth_tok)->session_key.flags &=
			    ~(ECRYPTFS_USERSPACE_SHOULD_TRY_TO_ENCRYPT);
	list_add(&auth_tok_list_item->list, auth_tok_list);
	goto out;
out_free:
	(*new_auth_tok) = NULL;
	memset(auth_tok_list_item, 0,
	       sizeof(struct ecryptfs_auth_tok_list_item));
	kmem_cache_free(ecryptfs_auth_tok_list_item_cache,
			auth_tok_list_item);
out:
	if (rc)
		(*packet_size) = 0;
	return rc;
}

/**
 * parse_tag_11_packet
 * @data: The raw bytes of the packet
 * @contents: This function writes the data contents of the literal
 *            packet into this memory location
 * @max_contents_bytes: The maximum number of bytes that this function
 *                      is allowed to write into contents
 * @tag_11_contents_size: This function writes the size of the parsed
 *                        contents into this memory location; zero on
 *                        error
 * @packet_size: This function writes the size of the parsed packet
 *               into this memory location; zero on error
 * @max_packet_size: maximum number of bytes to parse
 *
 * Returns zero on success; non-zero on error.
 */
static int
parse_tag_11_packet(unsigned char *data, unsigned char *contents,
		    size_t max_contents_bytes, size_t *tag_11_contents_size,
		    size_t *packet_size, size_t max_packet_size)
{
	size_t body_size;
	size_t length_size;
	int rc = 0;

	(*packet_size) = 0;
	(*tag_11_contents_size) = 0;
	/* This format is inspired by OpenPGP; see RFC 2440
	 * packet tag 11
	 *
	 * Tag 11 identifier (1 byte)
	 * Max Tag 11 packet size (max 3 bytes)
	 * Binary format specifier (1 byte)
	 * Filename length (1 byte)
	 * Filename ("_CONSOLE") (8 bytes)
	 * Modification date (4 bytes)
	 * Literal data (arbitrary)
	 *
	 * We need at least 16 bytes of data for the packet to even be
	 * valid.
	 */
	if (max_packet_size < 16) {
		printk(KERN_ERR "Maximum packet size too small\n");
		rc = -EINVAL;
		goto out;
	}
	if (data[(*packet_size)++] != ECRYPTFS_TAG_11_PACKET_TYPE) {
		printk(KERN_WARNING "Invalid tag 11 packet format\n");
		rc = -EINVAL;
		goto out;
	}
	rc = ecryptfs_parse_packet_length(&data[(*packet_size)], &body_size,
					  &length_size);
	if (rc) {
		printk(KERN_WARNING "Invalid tag 11 packet format\n");
		goto out;
	}
	if (body_size < 14) {
		printk(KERN_WARNING "Invalid body size ([%td])\n", body_size);
		rc = -EINVAL;
		goto out;
	}
	(*packet_size) += length_size;
	(*tag_11_contents_size) = (body_size - 14);
	if (unlikely((*packet_size) + body_size + 1 > max_packet_size)) {
		printk(KERN_ERR "Packet size exceeds max\n");
		rc = -EINVAL;
		goto out;
	}
	if (unlikely((*tag_11_contents_size) > max_contents_bytes)) {
		printk(KERN_ERR "Literal data section in tag 11 packet exceeds "
		       "expected size\n");
		rc = -EINVAL;
		goto out;
	}
	if (data[(*packet_size)++] != 0x62) {
		printk(KERN_WARNING "Unrecognizable packet\n");
		rc = -EINVAL;
		goto out;
	}
	if (data[(*packet_size)++] != 0x08) {
		printk(KERN_WARNING "Unrecognizable packet\n");
		rc = -EINVAL;
		goto out;
	}
	(*packet_size) += 12; /* Ignore filename and modification date */
	memcpy(contents, &data[(*packet_size)], (*tag_11_contents_size));
	(*packet_size) += (*tag_11_contents_size);
out:
	if (rc) {
		(*packet_size) = 0;
		(*tag_11_contents_size) = 0;
	}
	return rc;
}

int ecryptfs_keyring_auth_tok_for_sig(struct key **auth_tok_key,
				      struct ecryptfs_auth_tok **auth_tok,
				      char *sig)
{
	int rc = 0;

	(*auth_tok_key) = request_key(&key_type_user, sig, NULL);
	if (!(*auth_tok_key) || IS_ERR(*auth_tok_key)) {
		(*auth_tok_key) = ecryptfs_get_encrypted_key(sig);
		if (!(*auth_tok_key) || IS_ERR(*auth_tok_key)) {
			printk(KERN_ERR "Could not find key with description: [%s]\n",
			      sig);
			rc = process_request_key_err(PTR_ERR(*auth_tok_key));
			(*auth_tok_key) = NULL;
			goto out;
		}
	}
	down_write(&(*auth_tok_key)->sem);
	rc = ecryptfs_verify_auth_tok_from_key(*auth_tok_key, auth_tok);
	if (rc) {
		up_write(&(*auth_tok_key)->sem);
		key_put(*auth_tok_key);
		(*auth_tok_key) = NULL;
		goto out;
	}
out:
	return rc;
}

/**
 * decrypt_passphrase_encrypted_session_key - Decrypt the session key with the given auth_tok.
 * @auth_tok: The passphrase authentication token to use to encrypt the FEK
 * @crypt_stat: The cryptographic context
 *
 * Returns zero on success; non-zero error otherwise
 */
static int
decrypt_passphrase_encrypted_session_key(struct ecryptfs_auth_tok *auth_tok,
					 struct ecryptfs_crypt_stat *crypt_stat)
{
	struct scatterlist dst_sg[2];
	struct scatterlist src_sg[2];
	struct mutex *tfm_mutex;
	struct blkcipher_desc desc = {
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
	int rc = 0;

	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(
			KERN_DEBUG, "Session key encryption key (size [%d]):\n",
			auth_tok->token.password.session_key_encryption_key_bytes);
		ecryptfs_dump_hex(
			auth_tok->token.password.session_key_encryption_key,
			auth_tok->token.password.session_key_encryption_key_bytes);
	}
	rc = ecryptfs_get_tfm_and_mutex_for_cipher_name(&desc.tfm, &tfm_mutex,
							crypt_stat->cipher);
	if (unlikely(rc)) {
		printk(KERN_ERR "Internal error whilst attempting to get "
		       "tfm and mutex for cipher name [%s]; rc = [%d]\n",
		       crypt_stat->cipher, rc);
		goto out;
	}
	rc = virt_to_scatterlist(auth_tok->session_key.encrypted_key,
				 auth_tok->session_key.encrypted_key_size,
				 src_sg, 2);
	if (rc < 1 || rc > 2) {
		printk(KERN_ERR "Internal error whilst attempting to convert "
			"auth_tok->session_key.encrypted_key to scatterlist; "
			"expected rc = 1; got rc = [%d]. "
		       "auth_tok->session_key.encrypted_key_size = [%d]\n", rc,
			auth_tok->session_key.encrypted_key_size);
		goto out;
	}
	auth_tok->session_key.decrypted_key_size =
		auth_tok->session_key.encrypted_key_size;
	rc = virt_to_scatterlist(auth_tok->session_key.decrypted_key,
				 auth_tok->session_key.decrypted_key_size,
				 dst_sg, 2);
	if (rc < 1 || rc > 2) {
		printk(KERN_ERR "Internal error whilst attempting to convert "
			"auth_tok->session_key.decrypted_key to scatterlist; "
			"expected rc = 1; got rc = [%d]\n", rc);
		goto out;
	}
	mutex_lock(tfm_mutex);
	rc = crypto_blkcipher_setkey(
		desc.tfm, auth_tok->token.password.session_key_encryption_key,
		crypt_stat->key_size);
	if (unlikely(rc < 0)) {
		mutex_unlock(tfm_mutex);
		printk(KERN_ERR "Error setting key for crypto context\n");
		rc = -EINVAL;
		goto out;
	}
	rc = crypto_blkcipher_decrypt(&desc, dst_sg, src_sg,
				      auth_tok->session_key.encrypted_key_size);
	mutex_unlock(tfm_mutex);
	if (unlikely(rc)) {
		printk(KERN_ERR "Error decrypting; rc = [%d]\n", rc);
		goto out;
	}
	auth_tok->session_key.flags |= ECRYPTFS_CONTAINS_DECRYPTED_KEY;
	memcpy(crypt_stat->key, auth_tok->session_key.decrypted_key,
	       auth_tok->session_key.decrypted_key_size);
	crypt_stat->flags |= ECRYPTFS_KEY_VALID;
	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(KERN_DEBUG, "FEK of size [%zd]:\n",
				crypt_stat->key_size);
		ecryptfs_dump_hex(crypt_stat->key,
				  crypt_stat->key_size);
	}
out:
	return rc;
}

/**
 * ecryptfs_parse_packet_set
 * @crypt_stat: The cryptographic context
 * @src: Virtual address of region of memory containing the packets
 * @ecryptfs_dentry: The eCryptfs dentry associated with the packet set
 *
 * Get crypt_stat to have the file's session key if the requisite key
 * is available to decrypt the session key.
 *
 * Returns Zero if a valid authentication token was retrieved and
 * processed; negative value for file not encrypted or for error
 * conditions.
 */
int ecryptfs_parse_packet_set(struct ecryptfs_crypt_stat *crypt_stat,
			      unsigned char *src,
			      struct dentry *ecryptfs_dentry)
{
	size_t i = 0;
	size_t found_auth_tok;
	size_t next_packet_is_auth_tok_packet;
	struct list_head auth_tok_list;
	struct ecryptfs_auth_tok *matching_auth_tok;
	struct ecryptfs_auth_tok *candidate_auth_tok;
	char *candidate_auth_tok_sig;
	size_t packet_size;
	struct ecryptfs_auth_tok *new_auth_tok;
	unsigned char sig_tmp_space[ECRYPTFS_SIG_SIZE];
	struct ecryptfs_auth_tok_list_item *auth_tok_list_item;
	size_t tag_11_contents_size;
	size_t tag_11_packet_size;
	struct key *auth_tok_key = NULL;
	int rc = 0;

	INIT_LIST_HEAD(&auth_tok_list);
	/* Parse the header to find as many packets as we can; these will be
	 * added the our &auth_tok_list */
	next_packet_is_auth_tok_packet = 1;
	while (next_packet_is_auth_tok_packet) {
		size_t max_packet_size = ((PAGE_CACHE_SIZE - 8) - i);

		switch (src[i]) {
		case ECRYPTFS_TAG_3_PACKET_TYPE:
			rc = parse_tag_3_packet(crypt_stat,
						(unsigned char *)&src[i],
						&auth_tok_list, &new_auth_tok,
						&packet_size, max_packet_size);
			if (rc) {
				ecryptfs_printk(KERN_ERR, "Error parsing "
						"tag 3 packet\n");
				rc = -EIO;
				goto out_wipe_list;
			}
			i += packet_size;
			rc = parse_tag_11_packet((unsigned char *)&src[i],
						 sig_tmp_space,
						 ECRYPTFS_SIG_SIZE,
						 &tag_11_contents_size,
						 &tag_11_packet_size,
						 max_packet_size);
			if (rc) {
				ecryptfs_printk(KERN_ERR, "No valid "
						"(ecryptfs-specific) literal "
						"packet containing "
						"authentication token "
						"signature found after "
						"tag 3 packet\n");
				rc = -EIO;
				goto out_wipe_list;
			}
			i += tag_11_packet_size;
			if (ECRYPTFS_SIG_SIZE != tag_11_contents_size) {
				ecryptfs_printk(KERN_ERR, "Expected "
						"signature of size [%d]; "
						"read size [%zd]\n",
						ECRYPTFS_SIG_SIZE,
						tag_11_contents_size);
				rc = -EIO;
				goto out_wipe_list;
			}
			ecryptfs_to_hex(new_auth_tok->token.password.signature,
					sig_tmp_space, tag_11_contents_size);
			new_auth_tok->token.password.signature[
				ECRYPTFS_PASSWORD_SIG_SIZE] = '\0';
			crypt_stat->flags |= ECRYPTFS_ENCRYPTED;
			break;
		case ECRYPTFS_TAG_1_PACKET_TYPE:
			rc = parse_tag_1_packet(crypt_stat,
						(unsigned char *)&src[i],
						&auth_tok_list, &new_auth_tok,
						&packet_size, max_packet_size);
			if (rc) {
				ecryptfs_printk(KERN_ERR, "Error parsing "
						"tag 1 packet\n");
				rc = -EIO;
				goto out_wipe_list;
			}
			i += packet_size;
			crypt_stat->flags |= ECRYPTFS_ENCRYPTED;
			break;
		case ECRYPTFS_TAG_11_PACKET_TYPE:
			ecryptfs_printk(KERN_WARNING, "Invalid packet set "
					"(Tag 11 not allowed by itself)\n");
			rc = -EIO;
			goto out_wipe_list;
		default:
			ecryptfs_printk(KERN_DEBUG, "No packet at offset [%zd] "
					"of the file header; hex value of "
					"character is [0x%.2x]\n", i, src[i]);
			next_packet_is_auth_tok_packet = 0;
		}
	}
	if (list_empty(&auth_tok_list)) {
		printk(KERN_ERR "The lower file appears to be a non-encrypted "
		       "eCryptfs file; this is not supported in this version "
		       "of the eCryptfs kernel module\n");
		rc = -EINVAL;
		goto out;
	}
	/* auth_tok_list contains the set of authentication tokens
	 * parsed from the metadata. We need to find a matching
	 * authentication token that has the secret component(s)
	 * necessary to decrypt the EFEK in the auth_tok parsed from
	 * the metadata. There may be several potential matches, but
	 * just one will be sufficient to decrypt to get the FEK. */
find_next_matching_auth_tok:
	found_auth_tok = 0;
	list_for_each_entry(auth_tok_list_item, &auth_tok_list, list) {
		candidate_auth_tok = &auth_tok_list_item->auth_tok;
		if (unlikely(ecryptfs_verbosity > 0)) {
			ecryptfs_printk(KERN_DEBUG,
					"Considering cadidate auth tok:\n");
			ecryptfs_dump_auth_tok(candidate_auth_tok);
		}
		rc = ecryptfs_get_auth_tok_sig(&candidate_auth_tok_sig,
					       candidate_auth_tok);
		if (rc) {
			printk(KERN_ERR
			       "Unrecognized candidate auth tok type: [%d]\n",
			       candidate_auth_tok->token_type);
			rc = -EINVAL;
			goto out_wipe_list;
		}
		rc = ecryptfs_find_auth_tok_for_sig(&auth_tok_key,
					       &matching_auth_tok,
					       crypt_stat->mount_crypt_stat,
					       candidate_auth_tok_sig);
		if (!rc) {
			found_auth_tok = 1;
			goto found_matching_auth_tok;
		}
	}
	if (!found_auth_tok) {
		ecryptfs_printk(KERN_ERR, "Could not find a usable "
				"authentication token\n");
		rc = -EIO;
		goto out_wipe_list;
	}
found_matching_auth_tok:
	if (candidate_auth_tok->token_type == ECRYPTFS_PRIVATE_KEY) {
		memcpy(&(candidate_auth_tok->token.private_key),
		       &(matching_auth_tok->token.private_key),
		       sizeof(struct ecryptfs_private_key));
		up_write(&(auth_tok_key->sem));
		key_put(auth_tok_key);
		rc = decrypt_pki_encrypted_session_key(candidate_auth_tok,
						       crypt_stat);
	} else if (candidate_auth_tok->token_type == ECRYPTFS_PASSWORD) {
		memcpy(&(candidate_auth_tok->token.password),
		       &(matching_auth_tok->token.password),
		       sizeof(struct ecryptfs_password));
		up_write(&(auth_tok_key->sem));
		key_put(auth_tok_key);
		rc = decrypt_passphrase_encrypted_session_key(
			candidate_auth_tok, crypt_stat);
	} else {
		up_write(&(auth_tok_key->sem));
		key_put(auth_tok_key);
		rc = -EINVAL;
	}
	if (rc) {
		struct ecryptfs_auth_tok_list_item *auth_tok_list_item_tmp;

		ecryptfs_printk(KERN_WARNING, "Error decrypting the "
				"session key for authentication token with sig "
				"[%.*s]; rc = [%d]. Removing auth tok "
				"candidate from the list and searching for "
				"the next match.\n", ECRYPTFS_SIG_SIZE_HEX,
				candidate_auth_tok_sig,	rc);
		list_for_each_entry_safe(auth_tok_list_item,
					 auth_tok_list_item_tmp,
					 &auth_tok_list, list) {
			if (candidate_auth_tok
			    == &auth_tok_list_item->auth_tok) {
				list_del(&auth_tok_list_item->list);
				kmem_cache_free(
					ecryptfs_auth_tok_list_item_cache,
					auth_tok_list_item);
				goto find_next_matching_auth_tok;
			}
		}
		BUG();
	}
	rc = ecryptfs_compute_root_iv(crypt_stat);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error computing "
				"the root IV\n");
		goto out_wipe_list;
	}
	rc = ecryptfs_init_crypt_ctx(crypt_stat);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error initializing crypto "
				"context for cipher [%s]; rc = [%d]\n",
				crypt_stat->cipher, rc);
	}
out_wipe_list:
	wipe_auth_tok_list(&auth_tok_list);
out:
	return rc;
}

static int
pki_encrypt_session_key(struct key *auth_tok_key,
			struct ecryptfs_auth_tok *auth_tok,
			struct ecryptfs_crypt_stat *crypt_stat,
			struct ecryptfs_key_record *key_rec)
{
	struct ecryptfs_msg_ctx *msg_ctx = NULL;
	char *payload = NULL;
	size_t payload_len = 0;
	struct ecryptfs_message *msg;
	int rc;

	rc = write_tag_66_packet(auth_tok->token.private_key.signature,
				 ecryptfs_code_for_cipher_string(
					 crypt_stat->cipher,
					 crypt_stat->key_size),
				 crypt_stat, &payload, &payload_len);
	up_write(&(auth_tok_key->sem));
	key_put(auth_tok_key);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error generating tag 66 packet\n");
		goto out;
	}
	rc = ecryptfs_send_message(payload, payload_len, &msg_ctx);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error sending message to "
				"ecryptfsd: %d\n", rc);
		goto out;
	}
	rc = ecryptfs_wait_for_response(msg_ctx, &msg);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Failed to receive tag 67 packet "
				"from the user space daemon\n");
		rc = -EIO;
		goto out;
	}
	rc = parse_tag_67_packet(key_rec, msg);
	if (rc)
		ecryptfs_printk(KERN_ERR, "Error parsing tag 67 packet\n");
	kfree(msg);
out:
	kfree(payload);
	return rc;
}
/**
 * write_tag_1_packet - Write an RFC2440-compatible tag 1 (public key) packet
 * @dest: Buffer into which to write the packet
 * @remaining_bytes: Maximum number of bytes that can be writtn
 * @auth_tok_key: The authentication token key to unlock and put when done with
 *                @auth_tok
 * @auth_tok: The authentication token used for generating the tag 1 packet
 * @crypt_stat: The cryptographic context
 * @key_rec: The key record struct for the tag 1 packet
 * @packet_size: This function will write the number of bytes that end
 *               up constituting the packet; set to zero on error
 *
 * Returns zero on success; non-zero on error.
 */
static int
write_tag_1_packet(char *dest, size_t *remaining_bytes,
		   struct key *auth_tok_key, struct ecryptfs_auth_tok *auth_tok,
		   struct ecryptfs_crypt_stat *crypt_stat,
		   struct ecryptfs_key_record *key_rec, size_t *packet_size)
{
	size_t i;
	size_t encrypted_session_key_valid = 0;
	size_t packet_size_length;
	size_t max_packet_size;
	int rc = 0;

	(*packet_size) = 0;
	ecryptfs_from_hex(key_rec->sig, auth_tok->token.private_key.signature,
			  ECRYPTFS_SIG_SIZE);
	encrypted_session_key_valid = 0;
	for (i = 0; i < crypt_stat->key_size; i++)
		encrypted_session_key_valid |=
			auth_tok->session_key.encrypted_key[i];
	if (encrypted_session_key_valid) {
		memcpy(key_rec->enc_key,
		       auth_tok->session_key.encrypted_key,
		       auth_tok->session_key.encrypted_key_size);
		up_write(&(auth_tok_key->sem));
		key_put(auth_tok_key);
		goto encrypted_session_key_set;
	}
	if (auth_tok->session_key.encrypted_key_size == 0)
		auth_tok->session_key.encrypted_key_size =
			auth_tok->token.private_key.key_size;
	rc = pki_encrypt_session_key(auth_tok_key, auth_tok, crypt_stat,
				     key_rec);
	if (rc) {
		printk(KERN_ERR "Failed to encrypt session key via a key "
		       "module; rc = [%d]\n", rc);
		goto out;
	}
	if (ecryptfs_verbosity > 0) {
		ecryptfs_printk(KERN_DEBUG, "Encrypted key:\n");
		ecryptfs_dump_hex(key_rec->enc_key, key_rec->enc_key_size);
	}
encrypted_session_key_set:
	/* This format is inspired by OpenPGP; see RFC 2440
	 * packet tag 1 */
	max_packet_size = (1                         /* Tag 1 identifier */
			   + 3                       /* Max Tag 1 packet size */
			   + 1                       /* Version */
			   + ECRYPTFS_SIG_SIZE       /* Key identifier */
			   + 1                       /* Cipher identifier */
			   + key_rec->enc_key_size); /* Encrypted key size */
	if (max_packet_size > (*remaining_bytes)) {
		printk(KERN_ERR "Packet length larger than maximum allowable; "
		       "need up to [%td] bytes, but there are only [%td] "
		       "available\n", max_packet_size, (*remaining_bytes));
		rc = -EINVAL;
		goto out;
	}
	dest[(*packet_size)++] = ECRYPTFS_TAG_1_PACKET_TYPE;
	rc = ecryptfs_write_packet_length(&dest[(*packet_size)],
					  (max_packet_size - 4),
					  &packet_size_length);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error generating tag 1 packet "
				"header; cannot generate packet length\n");
		goto out;
	}
	(*packet_size) += packet_size_length;
	dest[(*packet_size)++] = 0x03; /* version 3 */
	memcpy(&dest[(*packet_size)], key_rec->sig, ECRYPTFS_SIG_SIZE);
	(*packet_size) += ECRYPTFS_SIG_SIZE;
	dest[(*packet_size)++] = RFC2440_CIPHER_RSA;
	memcpy(&dest[(*packet_size)], key_rec->enc_key,
	       key_rec->enc_key_size);
	(*packet_size) += key_rec->enc_key_size;
out:
	if (rc)
		(*packet_size) = 0;
	else
		(*remaining_bytes) -= (*packet_size);
	return rc;
}

/**
 * write_tag_11_packet
 * @dest: Target into which Tag 11 packet is to be written
 * @remaining_bytes: Maximum packet length
 * @contents: Byte array of contents to copy in
 * @contents_length: Number of bytes in contents
 * @packet_length: Length of the Tag 11 packet written; zero on error
 *
 * Returns zero on success; non-zero on error.
 */
static int
write_tag_11_packet(char *dest, size_t *remaining_bytes, char *contents,
		    size_t contents_length, size_t *packet_length)
{
	size_t packet_size_length;
	size_t max_packet_size;
	int rc = 0;

	(*packet_length) = 0;
	/* This format is inspired by OpenPGP; see RFC 2440
	 * packet tag 11 */
	max_packet_size = (1                   /* Tag 11 identifier */
			   + 3                 /* Max Tag 11 packet size */
			   + 1                 /* Binary format specifier */
			   + 1                 /* Filename length */
			   + 8                 /* Filename ("_CONSOLE") */
			   + 4                 /* Modification date */
			   + contents_length); /* Literal data */
	if (max_packet_size > (*remaining_bytes)) {
		printk(KERN_ERR "Packet length larger than maximum allowable; "
		       "need up to [%td] bytes, but there are only [%td] "
		       "available\n", max_packet_size, (*remaining_bytes));
		rc = -EINVAL;
		goto out;
	}
	dest[(*packet_length)++] = ECRYPTFS_TAG_11_PACKET_TYPE;
	rc = ecryptfs_write_packet_length(&dest[(*packet_length)],
					  (max_packet_size - 4),
					  &packet_size_length);
	if (rc) {
		printk(KERN_ERR "Error generating tag 11 packet header; cannot "
		       "generate packet length. rc = [%d]\n", rc);
		goto out;
	}
	(*packet_length) += packet_size_length;
	dest[(*packet_length)++] = 0x62; /* binary data format specifier */
	dest[(*packet_length)++] = 8;
	memcpy(&dest[(*packet_length)], "_CONSOLE", 8);
	(*packet_length) += 8;
	memset(&dest[(*packet_length)], 0x00, 4);
	(*packet_length) += 4;
	memcpy(&dest[(*packet_length)], contents, contents_length);
	(*packet_length) += contents_length;
 out:
	if (rc)
		(*packet_length) = 0;
	else
		(*remaining_bytes) -= (*packet_length);
	return rc;
}

/**
 * write_tag_3_packet
 * @dest: Buffer into which to write the packet
 * @remaining_bytes: Maximum number of bytes that can be written
 * @auth_tok: Authentication token
 * @crypt_stat: The cryptographic context
 * @key_rec: encrypted key
 * @packet_size: This function will write the number of bytes that end
 *               up constituting the packet; set to zero on error
 *
 * Returns zero on success; non-zero on error.
 */
static int
write_tag_3_packet(char *dest, size_t *remaining_bytes,
		   struct ecryptfs_auth_tok *auth_tok,
		   struct ecryptfs_crypt_stat *crypt_stat,
		   struct ecryptfs_key_record *key_rec, size_t *packet_size)
{
	size_t i;
	size_t encrypted_session_key_valid = 0;
	char session_key_encryption_key[ECRYPTFS_MAX_KEY_BYTES];
	struct scatterlist dst_sg[2];
	struct scatterlist src_sg[2];
	struct mutex *tfm_mutex = NULL;
	u8 cipher_code;
	size_t packet_size_length;
	size_t max_packet_size;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		crypt_stat->mount_crypt_stat;
	struct blkcipher_desc desc = {
		.tfm = NULL,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
	int rc = 0;

	(*packet_size) = 0;
	ecryptfs_from_hex(key_rec->sig, auth_tok->token.password.signature,
			  ECRYPTFS_SIG_SIZE);
	rc = ecryptfs_get_tfm_and_mutex_for_cipher_name(&desc.tfm, &tfm_mutex,
							crypt_stat->cipher);
	if (unlikely(rc)) {
		printk(KERN_ERR "Internal error whilst attempting to get "
		       "tfm and mutex for cipher name [%s]; rc = [%d]\n",
		       crypt_stat->cipher, rc);
		goto out;
	}
	if (mount_crypt_stat->global_default_cipher_key_size == 0) {
		struct blkcipher_alg *alg = crypto_blkcipher_alg(desc.tfm);

		printk(KERN_WARNING "No key size specified at mount; "
		       "defaulting to [%d]\n", alg->max_keysize);
		mount_crypt_stat->global_default_cipher_key_size =
			alg->max_keysize;
	}
	if (crypt_stat->key_size == 0)
		crypt_stat->key_size =
			mount_crypt_stat->global_default_cipher_key_size;
	if (auth_tok->session_key.encrypted_key_size == 0)
		auth_tok->session_key.encrypted_key_size =
			crypt_stat->key_size;
	if (crypt_stat->key_size == 24
	    && strcmp("aes", crypt_stat->cipher) == 0) {
		memset((crypt_stat->key + 24), 0, 8);
		auth_tok->session_key.encrypted_key_size = 32;
	} else
		auth_tok->session_key.encrypted_key_size = crypt_stat->key_size;
	key_rec->enc_key_size =
		auth_tok->session_key.encrypted_key_size;
	encrypted_session_key_valid = 0;
	for (i = 0; i < auth_tok->session_key.encrypted_key_size; i++)
		encrypted_session_key_valid |=
			auth_tok->session_key.encrypted_key[i];
	if (encrypted_session_key_valid) {
		ecryptfs_printk(KERN_DEBUG, "encrypted_session_key_valid != 0; "
				"using auth_tok->session_key.encrypted_key, "
				"where key_rec->enc_key_size = [%zd]\n",
				key_rec->enc_key_size);
		memcpy(key_rec->enc_key,
		       auth_tok->session_key.encrypted_key,
		       key_rec->enc_key_size);
		goto encrypted_session_key_set;
	}
	if (auth_tok->token.password.flags &
	    ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET) {
		ecryptfs_printk(KERN_DEBUG, "Using previously generated "
				"session key encryption key of size [%d]\n",
				auth_tok->token.password.
				session_key_encryption_key_bytes);
		memcpy(session_key_encryption_key,
		       auth_tok->token.password.session_key_encryption_key,
		       crypt_stat->key_size);
		ecryptfs_printk(KERN_DEBUG,
				"Cached session key encryption key:\n");
		if (ecryptfs_verbosity > 0)
			ecryptfs_dump_hex(session_key_encryption_key, 16);
	}
	if (unlikely(ecryptfs_verbosity > 0)) {
		ecryptfs_printk(KERN_DEBUG, "Session key encryption key:\n");
		ecryptfs_dump_hex(session_key_encryption_key, 16);
	}
	rc = virt_to_scatterlist(crypt_stat->key, key_rec->enc_key_size,
				 src_sg, 2);
	if (rc < 1 || rc > 2) {
		ecryptfs_printk(KERN_ERR, "Error generating scatterlist "
				"for crypt_stat session key; expected rc = 1; "
				"got rc = [%d]. key_rec->enc_key_size = [%zd]\n",
				rc, key_rec->enc_key_size);
		rc = -ENOMEM;
		goto out;
	}
	rc = virt_to_scatterlist(key_rec->enc_key, key_rec->enc_key_size,
				 dst_sg, 2);
	if (rc < 1 || rc > 2) {
		ecryptfs_printk(KERN_ERR, "Error generating scatterlist "
				"for crypt_stat encrypted session key; "
				"expected rc = 1; got rc = [%d]. "
				"key_rec->enc_key_size = [%zd]\n", rc,
				key_rec->enc_key_size);
		rc = -ENOMEM;
		goto out;
	}
	mutex_lock(tfm_mutex);
	rc = crypto_blkcipher_setkey(desc.tfm, session_key_encryption_key,
				     crypt_stat->key_size);
	if (rc < 0) {
		mutex_unlock(tfm_mutex);
		ecryptfs_printk(KERN_ERR, "Error setting key for crypto "
				"context; rc = [%d]\n", rc);
		goto out;
	}
	rc = 0;
	ecryptfs_printk(KERN_DEBUG, "Encrypting [%zd] bytes of the key\n",
			crypt_stat->key_size);
	rc = crypto_blkcipher_encrypt(&desc, dst_sg, src_sg,
				      (*key_rec).enc_key_size);
	mutex_unlock(tfm_mutex);
	if (rc) {
		printk(KERN_ERR "Error encrypting; rc = [%d]\n", rc);
		goto out;
	}
	ecryptfs_printk(KERN_DEBUG, "This should be the encrypted key:\n");
	if (ecryptfs_verbosity > 0) {
		ecryptfs_printk(KERN_DEBUG, "EFEK of size [%zd]:\n",
				key_rec->enc_key_size);
		ecryptfs_dump_hex(key_rec->enc_key,
				  key_rec->enc_key_size);
	}
encrypted_session_key_set:
	/* This format is inspired by OpenPGP; see RFC 2440
	 * packet tag 3 */
	max_packet_size = (1                         /* Tag 3 identifier */
			   + 3                       /* Max Tag 3 packet size */
			   + 1                       /* Version */
			   + 1                       /* Cipher code */
			   + 1                       /* S2K specifier */
			   + 1                       /* Hash identifier */
			   + ECRYPTFS_SALT_SIZE      /* Salt */
			   + 1                       /* Hash iterations */
			   + key_rec->enc_key_size); /* Encrypted key size */
	if (max_packet_size > (*remaining_bytes)) {
		printk(KERN_ERR "Packet too large; need up to [%td] bytes, but "
		       "there are only [%td] available\n", max_packet_size,
		       (*remaining_bytes));
		rc = -EINVAL;
		goto out;
	}
	dest[(*packet_size)++] = ECRYPTFS_TAG_3_PACKET_TYPE;
	/* Chop off the Tag 3 identifier(1) and Tag 3 packet size(3)
	 * to get the number of octets in the actual Tag 3 packet */
	rc = ecryptfs_write_packet_length(&dest[(*packet_size)],
					  (max_packet_size - 4),
					  &packet_size_length);
	if (rc) {
		printk(KERN_ERR "Error generating tag 3 packet header; cannot "
		       "generate packet length. rc = [%d]\n", rc);
		goto out;
	}
	(*packet_size) += packet_size_length;
	dest[(*packet_size)++] = 0x04; /* version 4 */
	/* TODO: Break from RFC2440 so that arbitrary ciphers can be
	 * specified with strings */
	cipher_code = ecryptfs_code_for_cipher_string(crypt_stat->cipher,
						      crypt_stat->key_size);
	if (cipher_code == 0) {
		ecryptfs_printk(KERN_WARNING, "Unable to generate code for "
				"cipher [%s]\n", crypt_stat->cipher);
		rc = -EINVAL;
		goto out;
	}
	dest[(*packet_size)++] = cipher_code;
	dest[(*packet_size)++] = 0x03;	/* S2K */
	dest[(*packet_size)++] = 0x01;	/* MD5 (TODO: parameterize) */
	memcpy(&dest[(*packet_size)], auth_tok->token.password.salt,
	       ECRYPTFS_SALT_SIZE);
	(*packet_size) += ECRYPTFS_SALT_SIZE;	/* salt */
	dest[(*packet_size)++] = 0x60;	/* hash iterations (65536) */
	memcpy(&dest[(*packet_size)], key_rec->enc_key,
	       key_rec->enc_key_size);
	(*packet_size) += key_rec->enc_key_size;
out:
	if (rc)
		(*packet_size) = 0;
	else
		(*remaining_bytes) -= (*packet_size);
	return rc;
}

struct kmem_cache *ecryptfs_key_record_cache;

/**
 * ecryptfs_generate_key_packet_set
 * @dest_base: Virtual address from which to write the key record set
 * @crypt_stat: The cryptographic context from which the
 *              authentication tokens will be retrieved
 * @ecryptfs_dentry: The dentry, used to retrieve the mount crypt stat
 *                   for the global parameters
 * @len: The amount written
 * @max: The maximum amount of data allowed to be written
 *
 * Generates a key packet set and writes it to the virtual address
 * passed in.
 *
 * Returns zero on success; non-zero on error.
 */
int
ecryptfs_generate_key_packet_set(char *dest_base,
				 struct ecryptfs_crypt_stat *crypt_stat,
				 struct dentry *ecryptfs_dentry, size_t *len,
				 size_t max)
{
	struct ecryptfs_auth_tok *auth_tok;
	struct key *auth_tok_key = NULL;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(
			ecryptfs_dentry->d_sb)->mount_crypt_stat;
	size_t written;
	struct ecryptfs_key_record *key_rec;
	struct ecryptfs_key_sig *key_sig;
	int rc = 0;

	(*len) = 0;
	mutex_lock(&crypt_stat->keysig_list_mutex);
	key_rec = kmem_cache_alloc(ecryptfs_key_record_cache, GFP_KERNEL);
	if (!key_rec) {
		rc = -ENOMEM;
		goto out;
	}
	list_for_each_entry(key_sig, &crypt_stat->keysig_list,
			    crypt_stat_list) {
		memset(key_rec, 0, sizeof(*key_rec));
		rc = ecryptfs_find_global_auth_tok_for_sig(&auth_tok_key,
							   &auth_tok,
							   mount_crypt_stat,
							   key_sig->keysig);
		if (rc) {
			printk(KERN_WARNING "Unable to retrieve auth tok with "
			       "sig = [%s]\n", key_sig->keysig);
			rc = process_find_global_auth_tok_for_sig_err(rc);
			goto out_free;
		}
		if (auth_tok->token_type == ECRYPTFS_PASSWORD) {
			rc = write_tag_3_packet((dest_base + (*len)),
						&max, auth_tok,
						crypt_stat, key_rec,
						&written);
			up_write(&(auth_tok_key->sem));
			key_put(auth_tok_key);
			if (rc) {
				ecryptfs_printk(KERN_WARNING, "Error "
						"writing tag 3 packet\n");
				goto out_free;
			}
			(*len) += written;
			/* Write auth tok signature packet */
			rc = write_tag_11_packet((dest_base + (*len)), &max,
						 key_rec->sig,
						 ECRYPTFS_SIG_SIZE, &written);
			if (rc) {
				ecryptfs_printk(KERN_ERR, "Error writing "
						"auth tok signature packet\n");
				goto out_free;
			}
			(*len) += written;
		} else if (auth_tok->token_type == ECRYPTFS_PRIVATE_KEY) {
			rc = write_tag_1_packet(dest_base + (*len), &max,
						auth_tok_key, auth_tok,
						crypt_stat, key_rec, &written);
			if (rc) {
				ecryptfs_printk(KERN_WARNING, "Error "
						"writing tag 1 packet\n");
				goto out_free;
			}
			(*len) += written;
		} else {
			up_write(&(auth_tok_key->sem));
			key_put(auth_tok_key);
			ecryptfs_printk(KERN_WARNING, "Unsupported "
					"authentication token type\n");
			rc = -EINVAL;
			goto out_free;
		}
	}
	if (likely(max > 0)) {
		dest_base[(*len)] = 0x00;
	} else {
		ecryptfs_printk(KERN_ERR, "Error writing boundary byte\n");
		rc = -EIO;
	}
out_free:
	kmem_cache_free(ecryptfs_key_record_cache, key_rec);
out:
	if (rc)
		(*len) = 0;
	mutex_unlock(&crypt_stat->keysig_list_mutex);
	return rc;
}

struct kmem_cache *ecryptfs_key_sig_cache;

int ecryptfs_add_keysig(struct ecryptfs_crypt_stat *crypt_stat, char *sig)
{
	struct ecryptfs_key_sig *new_key_sig;

	new_key_sig = kmem_cache_alloc(ecryptfs_key_sig_cache, GFP_KERNEL);
	if (!new_key_sig) {
		printk(KERN_ERR
		       "Error allocating from ecryptfs_key_sig_cache\n");
		return -ENOMEM;
	}
	memcpy(new_key_sig->keysig, sig, ECRYPTFS_SIG_SIZE_HEX);
	new_key_sig->keysig[ECRYPTFS_SIG_SIZE_HEX] = '\0';
	/* Caller must hold keysig_list_mutex */
	list_add(&new_key_sig->crypt_stat_list, &crypt_stat->keysig_list);

	return 0;
}

struct kmem_cache *ecryptfs_global_auth_tok_cache;

int
ecryptfs_add_global_auth_tok(struct ecryptfs_mount_crypt_stat *mount_crypt_stat,
			     char *sig, u32 global_auth_tok_flags)
{
	struct ecryptfs_global_auth_tok *new_auth_tok;
	int rc = 0;

	new_auth_tok = kmem_cache_zalloc(ecryptfs_global_auth_tok_cache,
					GFP_KERNEL);
	if (!new_auth_tok) {
		rc = -ENOMEM;
		printk(KERN_ERR "Error allocating from "
		       "ecryptfs_global_auth_tok_cache\n");
		goto out;
	}
	memcpy(new_auth_tok->sig, sig, ECRYPTFS_SIG_SIZE_HEX);
	new_auth_tok->flags = global_auth_tok_flags;
	new_auth_tok->sig[ECRYPTFS_SIG_SIZE_HEX] = '\0';
	mutex_lock(&mount_crypt_stat->global_auth_tok_list_mutex);
	list_add(&new_auth_tok->mount_crypt_stat_list,
		 &mount_crypt_stat->global_auth_tok_list);
	mutex_unlock(&mount_crypt_stat->global_auth_tok_list_mutex);
out:
	return rc;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/keystore.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/kthread.h>
#include <linux/freezer.h>
// #include <linux/slab.h>
#include <linux/wait.h>
// #include <linux/mount.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

struct ecryptfs_open_req {
	struct file **lower_file;
	struct path path;
	struct completion done;
	struct list_head kthread_ctl_list;
};

static struct ecryptfs_kthread_ctl {
#define ECRYPTFS_KTHREAD_ZOMBIE 0x00000001
	u32 flags;
	struct mutex mux;
	struct list_head req_list;
	wait_queue_head_t wait;
} ecryptfs_kthread_ctl;

static struct task_struct *ecryptfs_kthread;

/**
 * ecryptfs_threadfn
 * @ignored: ignored
 *
 * The eCryptfs kernel thread that has the responsibility of getting
 * the lower file with RW permissions.
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_threadfn(void *ignored)
{
	set_freezable();
	while (1)  {
		struct ecryptfs_open_req *req;

		wait_event_freezable(
			ecryptfs_kthread_ctl.wait,
			(!list_empty(&ecryptfs_kthread_ctl.req_list)
			 || kthread_should_stop()));
		mutex_lock(&ecryptfs_kthread_ctl.mux);
		if (ecryptfs_kthread_ctl.flags & ECRYPTFS_KTHREAD_ZOMBIE) {
			mutex_unlock(&ecryptfs_kthread_ctl.mux);
			goto out;
		}
		while (!list_empty(&ecryptfs_kthread_ctl.req_list)) {
			req = list_first_entry(&ecryptfs_kthread_ctl.req_list,
					       struct ecryptfs_open_req,
					       kthread_ctl_list);
			list_del(&req->kthread_ctl_list);
			*req->lower_file = dentry_open(&req->path,
				(O_RDWR | O_LARGEFILE), current_cred());
			complete(&req->done);
		}
		mutex_unlock(&ecryptfs_kthread_ctl.mux);
	}
out:
	return 0;
}

int __init ecryptfs_init_kthread(void)
{
	int rc = 0;

	mutex_init(&ecryptfs_kthread_ctl.mux);
	init_waitqueue_head(&ecryptfs_kthread_ctl.wait);
	INIT_LIST_HEAD(&ecryptfs_kthread_ctl.req_list);
	ecryptfs_kthread = kthread_run(&ecryptfs_threadfn, NULL,
				       "ecryptfs-kthread");
	if (IS_ERR(ecryptfs_kthread)) {
		rc = PTR_ERR(ecryptfs_kthread);
		printk(KERN_ERR "%s: Failed to create kernel thread; rc = [%d]"
		       "\n", __func__, rc);
	}
	return rc;
}

void ecryptfs_destroy_kthread(void)
{
	struct ecryptfs_open_req *req, *tmp;

	mutex_lock(&ecryptfs_kthread_ctl.mux);
	ecryptfs_kthread_ctl.flags |= ECRYPTFS_KTHREAD_ZOMBIE;
	list_for_each_entry_safe(req, tmp, &ecryptfs_kthread_ctl.req_list,
				 kthread_ctl_list) {
		list_del(&req->kthread_ctl_list);
		*req->lower_file = ERR_PTR(-EIO);
		complete(&req->done);
	}
	mutex_unlock(&ecryptfs_kthread_ctl.mux);
	kthread_stop(ecryptfs_kthread);
	wake_up(&ecryptfs_kthread_ctl.wait);
}

/**
 * ecryptfs_privileged_open
 * @lower_file: Result of dentry_open by root on lower dentry
 * @lower_dentry: Lower dentry for file to open
 * @lower_mnt: Lower vfsmount for file to open
 *
 * This function gets a r/w file opened againt the lower dentry.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_privileged_open(struct file **lower_file,
			     struct dentry *lower_dentry,
			     struct vfsmount *lower_mnt,
			     const struct cred *cred)
{
	struct ecryptfs_open_req req;
	int flags = O_LARGEFILE;
	int rc = 0;

	init_completion(&req.done);
	req.lower_file = lower_file;
	req.path.dentry = lower_dentry;
	req.path.mnt = lower_mnt;

	/* Corresponding dput() and mntput() are done when the
	 * lower file is fput() when all eCryptfs files for the inode are
	 * released. */
	flags |= IS_RDONLY(lower_dentry->d_inode) ? O_RDONLY : O_RDWR;
	(*lower_file) = dentry_open(&req.path, flags, cred);
	if (!IS_ERR(*lower_file))
		goto out;
	if ((flags & O_ACCMODE) == O_RDONLY) {
		rc = PTR_ERR((*lower_file));
		goto out;
	}
	mutex_lock(&ecryptfs_kthread_ctl.mux);
	if (ecryptfs_kthread_ctl.flags & ECRYPTFS_KTHREAD_ZOMBIE) {
		rc = -EIO;
		mutex_unlock(&ecryptfs_kthread_ctl.mux);
		printk(KERN_ERR "%s: We are in the middle of shutting down; "
		       "aborting privileged request to open lower file\n",
			__func__);
		goto out;
	}
	list_add_tail(&req.kthread_ctl_list, &ecryptfs_kthread_ctl.req_list);
	mutex_unlock(&ecryptfs_kthread_ctl.mux);
	wake_up(&ecryptfs_kthread_ctl.wait);
	wait_for_completion(&req.done);
	if (IS_ERR(*lower_file))
		rc = PTR_ERR(*lower_file);
out:
	return rc;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/kthread.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 * Functions only useful for debugging.
 *
 * Copyright (C) 2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

// #include "ecryptfs_kernel.h"

/**
 * ecryptfs_dump_auth_tok - debug function to print auth toks
 *
 * This function will print the contents of an ecryptfs authentication
 * token.
 */
void ecryptfs_dump_auth_tok(struct ecryptfs_auth_tok *auth_tok)
{
	char salt[ECRYPTFS_SALT_SIZE * 2 + 1];
	char sig[ECRYPTFS_SIG_SIZE_HEX + 1];

	ecryptfs_printk(KERN_DEBUG, "Auth tok at mem loc [%p]:\n",
			auth_tok);
	if (auth_tok->flags & ECRYPTFS_PRIVATE_KEY) {
		ecryptfs_printk(KERN_DEBUG, " * private key type\n");
	} else {
		ecryptfs_printk(KERN_DEBUG, " * passphrase type\n");
		ecryptfs_to_hex(salt, auth_tok->token.password.salt,
				ECRYPTFS_SALT_SIZE);
		salt[ECRYPTFS_SALT_SIZE * 2] = '\0';
		ecryptfs_printk(KERN_DEBUG, " * salt = [%s]\n", salt);
		if (auth_tok->token.password.flags &
		    ECRYPTFS_PERSISTENT_PASSWORD) {
			ecryptfs_printk(KERN_DEBUG, " * persistent\n");
		}
		memcpy(sig, auth_tok->token.password.signature,
		       ECRYPTFS_SIG_SIZE_HEX);
		sig[ECRYPTFS_SIG_SIZE_HEX] = '\0';
		ecryptfs_printk(KERN_DEBUG, " * signature = [%s]\n", sig);
	}
	ecryptfs_printk(KERN_DEBUG, " * session_key.flags = [0x%x]\n",
			auth_tok->session_key.flags);
	if (auth_tok->session_key.flags
	    & ECRYPTFS_USERSPACE_SHOULD_TRY_TO_DECRYPT)
		ecryptfs_printk(KERN_DEBUG,
				" * Userspace decrypt request set\n");
	if (auth_tok->session_key.flags
	    & ECRYPTFS_USERSPACE_SHOULD_TRY_TO_ENCRYPT)
		ecryptfs_printk(KERN_DEBUG,
				" * Userspace encrypt request set\n");
	if (auth_tok->session_key.flags & ECRYPTFS_CONTAINS_DECRYPTED_KEY) {
		ecryptfs_printk(KERN_DEBUG, " * Contains decrypted key\n");
		ecryptfs_printk(KERN_DEBUG,
				" * session_key.decrypted_key_size = [0x%x]\n",
				auth_tok->session_key.decrypted_key_size);
		ecryptfs_printk(KERN_DEBUG, " * Decrypted session key "
				"dump:\n");
		if (ecryptfs_verbosity > 0)
			ecryptfs_dump_hex(auth_tok->session_key.decrypted_key,
					  ECRYPTFS_DEFAULT_KEY_BYTES);
	}
	if (auth_tok->session_key.flags & ECRYPTFS_CONTAINS_ENCRYPTED_KEY) {
		ecryptfs_printk(KERN_DEBUG, " * Contains encrypted key\n");
		ecryptfs_printk(KERN_DEBUG,
				" * session_key.encrypted_key_size = [0x%x]\n",
				auth_tok->session_key.encrypted_key_size);
		ecryptfs_printk(KERN_DEBUG, " * Encrypted session key "
				"dump:\n");
		if (ecryptfs_verbosity > 0)
			ecryptfs_dump_hex(auth_tok->session_key.encrypted_key,
					  auth_tok->session_key.
					  encrypted_key_size);
	}
}

/**
 * ecryptfs_dump_hex - debug hex printer
 * @data: string of bytes to be printed
 * @bytes: number of bytes to print
 *
 * Dump hexadecimal representation of char array
 */
void ecryptfs_dump_hex(char *data, int bytes)
{
	int i = 0;
	int add_newline = 1;

	if (ecryptfs_verbosity < 1)
		return;
	if (bytes != 0) {
		printk(KERN_DEBUG "0x%.2x.", (unsigned char)data[i]);
		i++;
	}
	while (i < bytes) {
		printk("0x%.2x.", (unsigned char)data[i]);
		i++;
		if (i % 16 == 0) {
			printk("\n");
			add_newline = 0;
		} else
			add_newline = 1;
	}
	if (add_newline)
		printk("\n");
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/debug.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 2004-2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *		Tyler Hicks <tyhicks@ou.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <linux/sched.h>
// #include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/nsproxy.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

static LIST_HEAD(ecryptfs_msg_ctx_free_list);
static LIST_HEAD(ecryptfs_msg_ctx_alloc_list);
static struct mutex ecryptfs_msg_ctx_lists_mux;

static struct hlist_head *ecryptfs_daemon_hash;
struct mutex ecryptfs_daemon_hash_mux;
static int ecryptfs_hash_bits;
#define ecryptfs_current_euid_hash(uid) \
	hash_long((unsigned long)from_kuid(&init_user_ns, current_euid()), ecryptfs_hash_bits)

static u32 ecryptfs_msg_counter;
static struct ecryptfs_msg_ctx *ecryptfs_msg_ctx_arr;

/**
 * ecryptfs_acquire_free_msg_ctx
 * @msg_ctx: The context that was acquired from the free list
 *
 * Acquires a context element from the free list and locks the mutex
 * on the context.  Sets the msg_ctx task to current.  Returns zero on
 * success; non-zero on error or upon failure to acquire a free
 * context element.  Must be called with ecryptfs_msg_ctx_lists_mux
 * held.
 */
static int ecryptfs_acquire_free_msg_ctx(struct ecryptfs_msg_ctx **msg_ctx)
{
	struct list_head *p;
	int rc;

	if (list_empty(&ecryptfs_msg_ctx_free_list)) {
		printk(KERN_WARNING "%s: The eCryptfs free "
		       "context list is empty.  It may be helpful to "
		       "specify the ecryptfs_message_buf_len "
		       "parameter to be greater than the current "
		       "value of [%d]\n", __func__, ecryptfs_message_buf_len);
		rc = -ENOMEM;
		goto out;
	}
	list_for_each(p, &ecryptfs_msg_ctx_free_list) {
		*msg_ctx = list_entry(p, struct ecryptfs_msg_ctx, node);
		if (mutex_trylock(&(*msg_ctx)->mux)) {
			(*msg_ctx)->task = current;
			rc = 0;
			goto out;
		}
	}
	rc = -ENOMEM;
out:
	return rc;
}

/**
 * ecryptfs_msg_ctx_free_to_alloc
 * @msg_ctx: The context to move from the free list to the alloc list
 *
 * Must be called with ecryptfs_msg_ctx_lists_mux held.
 */
static void ecryptfs_msg_ctx_free_to_alloc(struct ecryptfs_msg_ctx *msg_ctx)
{
	list_move(&msg_ctx->node, &ecryptfs_msg_ctx_alloc_list);
	msg_ctx->state = ECRYPTFS_MSG_CTX_STATE_PENDING;
	msg_ctx->counter = ++ecryptfs_msg_counter;
}

/**
 * ecryptfs_msg_ctx_alloc_to_free
 * @msg_ctx: The context to move from the alloc list to the free list
 *
 * Must be called with ecryptfs_msg_ctx_lists_mux held.
 */
void ecryptfs_msg_ctx_alloc_to_free(struct ecryptfs_msg_ctx *msg_ctx)
{
	list_move(&(msg_ctx->node), &ecryptfs_msg_ctx_free_list);
	kfree(msg_ctx->msg);
	msg_ctx->msg = NULL;
	msg_ctx->state = ECRYPTFS_MSG_CTX_STATE_FREE;
}

/**
 * ecryptfs_find_daemon_by_euid
 * @daemon: If return value is zero, points to the desired daemon pointer
 *
 * Must be called with ecryptfs_daemon_hash_mux held.
 *
 * Search the hash list for the current effective user id.
 *
 * Returns zero if the user id exists in the list; non-zero otherwise.
 */
int ecryptfs_find_daemon_by_euid(struct ecryptfs_daemon **daemon)
{
	int rc;

	hlist_for_each_entry(*daemon,
			    &ecryptfs_daemon_hash[ecryptfs_current_euid_hash()],
			    euid_chain) {
		if (uid_eq((*daemon)->file->f_cred->euid, current_euid())) {
			rc = 0;
			goto out;
		}
	}
	rc = -EINVAL;
out:
	return rc;
}

/**
 * ecryptfs_spawn_daemon - Create and initialize a new daemon struct
 * @daemon: Pointer to set to newly allocated daemon struct
 * @file: File used when opening /dev/ecryptfs
 *
 * Must be called ceremoniously while in possession of
 * ecryptfs_sacred_daemon_hash_mux
 *
 * Returns zero on success; non-zero otherwise
 */
int
ecryptfs_spawn_daemon(struct ecryptfs_daemon **daemon, struct file *file)
{
	int rc = 0;

	(*daemon) = kzalloc(sizeof(**daemon), GFP_KERNEL);
	if (!(*daemon)) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Failed to allocate [%zd] bytes of "
		       "GFP_KERNEL memory\n", __func__, sizeof(**daemon));
		goto out;
	}
	(*daemon)->file = file;
	mutex_init(&(*daemon)->mux);
	INIT_LIST_HEAD(&(*daemon)->msg_ctx_out_queue);
	init_waitqueue_head(&(*daemon)->wait);
	(*daemon)->num_queued_msg_ctx = 0;
	hlist_add_head(&(*daemon)->euid_chain,
		       &ecryptfs_daemon_hash[ecryptfs_current_euid_hash()]);
out:
	return rc;
}

/**
 * ecryptfs_exorcise_daemon - Destroy the daemon struct
 *
 * Must be called ceremoniously while in possession of
 * ecryptfs_daemon_hash_mux and the daemon's own mux.
 */
int ecryptfs_exorcise_daemon(struct ecryptfs_daemon *daemon)
{
	struct ecryptfs_msg_ctx *msg_ctx, *msg_ctx_tmp;
	int rc = 0;

	mutex_lock(&daemon->mux);
	if ((daemon->flags & ECRYPTFS_DAEMON_IN_READ)
	    || (daemon->flags & ECRYPTFS_DAEMON_IN_POLL)) {
		rc = -EBUSY;
		mutex_unlock(&daemon->mux);
		goto out;
	}
	list_for_each_entry_safe(msg_ctx, msg_ctx_tmp,
				 &daemon->msg_ctx_out_queue, daemon_out_list) {
		list_del(&msg_ctx->daemon_out_list);
		daemon->num_queued_msg_ctx--;
		printk(KERN_WARNING "%s: Warning: dropping message that is in "
		       "the out queue of a dying daemon\n", __func__);
		ecryptfs_msg_ctx_alloc_to_free(msg_ctx);
	}
	hlist_del(&daemon->euid_chain);
	mutex_unlock(&daemon->mux);
	kzfree(daemon);
out:
	return rc;
}

/**
 * ecryptfs_process_reponse
 * @msg: The ecryptfs message received; the caller should sanity check
 *       msg->data_len and free the memory
 * @seq: The sequence number of the message; must match the sequence
 *       number for the existing message context waiting for this
 *       response
 *
 * Processes a response message after sending an operation request to
 * userspace. Some other process is awaiting this response. Before
 * sending out its first communications, the other process allocated a
 * msg_ctx from the ecryptfs_msg_ctx_arr at a particular index. The
 * response message contains this index so that we can copy over the
 * response message into the msg_ctx that the process holds a
 * reference to. The other process is going to wake up, check to see
 * that msg_ctx->state == ECRYPTFS_MSG_CTX_STATE_DONE, and then
 * proceed to read off and process the response message. Returns zero
 * upon delivery to desired context element; non-zero upon delivery
 * failure or error.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_process_response(struct ecryptfs_daemon *daemon,
			      struct ecryptfs_message *msg, u32 seq)
{
	struct ecryptfs_msg_ctx *msg_ctx;
	size_t msg_size;
	int rc;

	if (msg->index >= ecryptfs_message_buf_len) {
		rc = -EINVAL;
		printk(KERN_ERR "%s: Attempt to reference "
		       "context buffer at index [%d]; maximum "
		       "allowable is [%d]\n", __func__, msg->index,
		       (ecryptfs_message_buf_len - 1));
		goto out;
	}
	msg_ctx = &ecryptfs_msg_ctx_arr[msg->index];
	mutex_lock(&msg_ctx->mux);
	if (msg_ctx->state != ECRYPTFS_MSG_CTX_STATE_PENDING) {
		rc = -EINVAL;
		printk(KERN_WARNING "%s: Desired context element is not "
		       "pending a response\n", __func__);
		goto unlock;
	} else if (msg_ctx->counter != seq) {
		rc = -EINVAL;
		printk(KERN_WARNING "%s: Invalid message sequence; "
		       "expected [%d]; received [%d]\n", __func__,
		       msg_ctx->counter, seq);
		goto unlock;
	}
	msg_size = (sizeof(*msg) + msg->data_len);
	msg_ctx->msg = kmemdup(msg, msg_size, GFP_KERNEL);
	if (!msg_ctx->msg) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Failed to allocate [%zd] bytes of "
		       "GFP_KERNEL memory\n", __func__, msg_size);
		goto unlock;
	}
	msg_ctx->state = ECRYPTFS_MSG_CTX_STATE_DONE;
	wake_up_process(msg_ctx->task);
	rc = 0;
unlock:
	mutex_unlock(&msg_ctx->mux);
out:
	return rc;
}

/**
 * ecryptfs_send_message_locked
 * @data: The data to send
 * @data_len: The length of data
 * @msg_ctx: The message context allocated for the send
 *
 * Must be called with ecryptfs_daemon_hash_mux held.
 *
 * Returns zero on success; non-zero otherwise
 */
static int
ecryptfs_send_message_locked(char *data, int data_len, u8 msg_type,
			     struct ecryptfs_msg_ctx **msg_ctx)
{
	struct ecryptfs_daemon *daemon;
	int rc;

	rc = ecryptfs_find_daemon_by_euid(&daemon);
	if (rc) {
		rc = -ENOTCONN;
		goto out;
	}
	mutex_lock(&ecryptfs_msg_ctx_lists_mux);
	rc = ecryptfs_acquire_free_msg_ctx(msg_ctx);
	if (rc) {
		mutex_unlock(&ecryptfs_msg_ctx_lists_mux);
		printk(KERN_WARNING "%s: Could not claim a free "
		       "context element\n", __func__);
		goto out;
	}
	ecryptfs_msg_ctx_free_to_alloc(*msg_ctx);
	mutex_unlock(&(*msg_ctx)->mux);
	mutex_unlock(&ecryptfs_msg_ctx_lists_mux);
	rc = ecryptfs_send_miscdev(data, data_len, *msg_ctx, msg_type, 0,
				   daemon);
	if (rc)
		printk(KERN_ERR "%s: Error attempting to send message to "
		       "userspace daemon; rc = [%d]\n", __func__, rc);
out:
	return rc;
}

/**
 * ecryptfs_send_message
 * @data: The data to send
 * @data_len: The length of data
 * @msg_ctx: The message context allocated for the send
 *
 * Grabs ecryptfs_daemon_hash_mux.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_send_message(char *data, int data_len,
			  struct ecryptfs_msg_ctx **msg_ctx)
{
	int rc;

	mutex_lock(&ecryptfs_daemon_hash_mux);
	rc = ecryptfs_send_message_locked(data, data_len, ECRYPTFS_MSG_REQUEST,
					  msg_ctx);
	mutex_unlock(&ecryptfs_daemon_hash_mux);
	return rc;
}

/**
 * ecryptfs_wait_for_response
 * @msg_ctx: The context that was assigned when sending a message
 * @msg: The incoming message from userspace; not set if rc != 0
 *
 * Sleeps until awaken by ecryptfs_receive_message or until the amount
 * of time exceeds ecryptfs_message_wait_timeout.  If zero is
 * returned, msg will point to a valid message from userspace; a
 * non-zero value is returned upon failure to receive a message or an
 * error occurs. Callee must free @msg on success.
 */
int ecryptfs_wait_for_response(struct ecryptfs_msg_ctx *msg_ctx,
			       struct ecryptfs_message **msg)
{
	signed long timeout = ecryptfs_message_wait_timeout * HZ;
	int rc = 0;

sleep:
	timeout = schedule_timeout_interruptible(timeout);
	mutex_lock(&ecryptfs_msg_ctx_lists_mux);
	mutex_lock(&msg_ctx->mux);
	if (msg_ctx->state != ECRYPTFS_MSG_CTX_STATE_DONE) {
		if (timeout) {
			mutex_unlock(&msg_ctx->mux);
			mutex_unlock(&ecryptfs_msg_ctx_lists_mux);
			goto sleep;
		}
		rc = -ENOMSG;
	} else {
		*msg = msg_ctx->msg;
		msg_ctx->msg = NULL;
	}
	ecryptfs_msg_ctx_alloc_to_free(msg_ctx);
	mutex_unlock(&msg_ctx->mux);
	mutex_unlock(&ecryptfs_msg_ctx_lists_mux);
	return rc;
}

int __init ecryptfs_init_messaging(void)
{
	int i;
	int rc = 0;

	if (ecryptfs_number_of_users > ECRYPTFS_MAX_NUM_USERS) {
		ecryptfs_number_of_users = ECRYPTFS_MAX_NUM_USERS;
		printk(KERN_WARNING "%s: Specified number of users is "
		       "too large, defaulting to [%d] users\n", __func__,
		       ecryptfs_number_of_users);
	}
	mutex_init(&ecryptfs_daemon_hash_mux);
	mutex_lock(&ecryptfs_daemon_hash_mux);
	ecryptfs_hash_bits = 1;
	while (ecryptfs_number_of_users >> ecryptfs_hash_bits)
		ecryptfs_hash_bits++;
	ecryptfs_daemon_hash = kmalloc((sizeof(struct hlist_head)
					* (1 << ecryptfs_hash_bits)),
				       GFP_KERNEL);
	if (!ecryptfs_daemon_hash) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Failed to allocate memory\n", __func__);
		mutex_unlock(&ecryptfs_daemon_hash_mux);
		goto out;
	}
	for (i = 0; i < (1 << ecryptfs_hash_bits); i++)
		INIT_HLIST_HEAD(&ecryptfs_daemon_hash[i]);
	mutex_unlock(&ecryptfs_daemon_hash_mux);
	ecryptfs_msg_ctx_arr = kmalloc((sizeof(struct ecryptfs_msg_ctx)
					* ecryptfs_message_buf_len),
				       GFP_KERNEL);
	if (!ecryptfs_msg_ctx_arr) {
		rc = -ENOMEM;
		printk(KERN_ERR "%s: Failed to allocate memory\n", __func__);
		goto out;
	}
	mutex_init(&ecryptfs_msg_ctx_lists_mux);
	mutex_lock(&ecryptfs_msg_ctx_lists_mux);
	ecryptfs_msg_counter = 0;
	for (i = 0; i < ecryptfs_message_buf_len; i++) {
		INIT_LIST_HEAD(&ecryptfs_msg_ctx_arr[i].node);
		INIT_LIST_HEAD(&ecryptfs_msg_ctx_arr[i].daemon_out_list);
		mutex_init(&ecryptfs_msg_ctx_arr[i].mux);
		mutex_lock(&ecryptfs_msg_ctx_arr[i].mux);
		ecryptfs_msg_ctx_arr[i].index = i;
		ecryptfs_msg_ctx_arr[i].state = ECRYPTFS_MSG_CTX_STATE_FREE;
		ecryptfs_msg_ctx_arr[i].counter = 0;
		ecryptfs_msg_ctx_arr[i].task = NULL;
		ecryptfs_msg_ctx_arr[i].msg = NULL;
		list_add_tail(&ecryptfs_msg_ctx_arr[i].node,
			      &ecryptfs_msg_ctx_free_list);
		mutex_unlock(&ecryptfs_msg_ctx_arr[i].mux);
	}
	mutex_unlock(&ecryptfs_msg_ctx_lists_mux);
	rc = ecryptfs_init_ecryptfs_miscdev();
	if (rc)
		ecryptfs_release_messaging();
out:
	return rc;
}

void ecryptfs_release_messaging(void)
{
	if (ecryptfs_msg_ctx_arr) {
		int i;

		mutex_lock(&ecryptfs_msg_ctx_lists_mux);
		for (i = 0; i < ecryptfs_message_buf_len; i++) {
			mutex_lock(&ecryptfs_msg_ctx_arr[i].mux);
			kfree(ecryptfs_msg_ctx_arr[i].msg);
			mutex_unlock(&ecryptfs_msg_ctx_arr[i].mux);
		}
		kfree(ecryptfs_msg_ctx_arr);
		mutex_unlock(&ecryptfs_msg_ctx_lists_mux);
	}
	if (ecryptfs_daemon_hash) {
		struct ecryptfs_daemon *daemon;
		int i;

		mutex_lock(&ecryptfs_daemon_hash_mux);
		for (i = 0; i < (1 << ecryptfs_hash_bits); i++) {
			int rc;

			hlist_for_each_entry(daemon,
					     &ecryptfs_daemon_hash[i],
					     euid_chain) {
				rc = ecryptfs_exorcise_daemon(daemon);
				if (rc)
					printk(KERN_ERR "%s: Error whilst "
					       "attempting to destroy daemon; "
					       "rc = [%d]. Dazed and confused, "
					       "but trying to continue.\n",
					       __func__, rc);
			}
		}
		kfree(ecryptfs_daemon_hash);
		mutex_unlock(&ecryptfs_daemon_hash_mux);
	}
	ecryptfs_destroy_ecryptfs_miscdev();
	return;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/messaging.c */
/************************************************************/
/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

// #include <linux/fs.h>
#include <linux/hash.h>
// #include <linux/random.h>
#include <linux/miscdevice.h>
// #include <linux/poll.h>
// #include <linux/slab.h>
// #include <linux/wait.h>
// #include <linux/module.h>
// #include "ecryptfs_kernel.h"
#include "../../inc/__fss.h"

static atomic_t ecryptfs_num_miscdev_opens;

/**
 * ecryptfs_miscdev_poll
 * @file: dev file
 * @pt: dev poll table (ignored)
 *
 * Returns the poll mask
 */
static unsigned int
ecryptfs_miscdev_poll(struct file *file, poll_table *pt)
{
	struct ecryptfs_daemon *daemon = file->private_data;
	unsigned int mask = 0;

	mutex_lock(&daemon->mux);
	if (daemon->flags & ECRYPTFS_DAEMON_ZOMBIE) {
		printk(KERN_WARNING "%s: Attempt to poll on zombified "
		       "daemon\n", __func__);
		goto out_unlock_daemon;
	}
	if (daemon->flags & ECRYPTFS_DAEMON_IN_READ)
		goto out_unlock_daemon;
	if (daemon->flags & ECRYPTFS_DAEMON_IN_POLL)
		goto out_unlock_daemon;
	daemon->flags |= ECRYPTFS_DAEMON_IN_POLL;
	mutex_unlock(&daemon->mux);
	poll_wait(file, &daemon->wait, pt);
	mutex_lock(&daemon->mux);
	if (!list_empty(&daemon->msg_ctx_out_queue))
		mask |= POLLIN | POLLRDNORM;
out_unlock_daemon:
	daemon->flags &= ~ECRYPTFS_DAEMON_IN_POLL;
	mutex_unlock(&daemon->mux);
	return mask;
}

/**
 * ecryptfs_miscdev_open
 * @inode: inode of miscdev handle (ignored)
 * @file: file for miscdev handle
 *
 * Returns zero on success; non-zero otherwise
 */
static int
ecryptfs_miscdev_open(struct inode *inode, struct file *file)
{
	struct ecryptfs_daemon *daemon = NULL;
	int rc;

	mutex_lock(&ecryptfs_daemon_hash_mux);
	rc = ecryptfs_find_daemon_by_euid(&daemon);
	if (!rc) {
		rc = -EINVAL;
		goto out_unlock_daemon_list;
	}
	rc = ecryptfs_spawn_daemon(&daemon, file);
	if (rc) {
		printk(KERN_ERR "%s: Error attempting to spawn daemon; "
		       "rc = [%d]\n", __func__, rc);
		goto out_unlock_daemon_list;
	}
	mutex_lock(&daemon->mux);
	if (daemon->flags & ECRYPTFS_DAEMON_MISCDEV_OPEN) {
		rc = -EBUSY;
		goto out_unlock_daemon;
	}
	daemon->flags |= ECRYPTFS_DAEMON_MISCDEV_OPEN;
	file->private_data = daemon;
	atomic_inc(&ecryptfs_num_miscdev_opens);
out_unlock_daemon:
	mutex_unlock(&daemon->mux);
out_unlock_daemon_list:
	mutex_unlock(&ecryptfs_daemon_hash_mux);
	return rc;
}

/**
 * ecryptfs_miscdev_release
 * @inode: inode of fs/ecryptfs/euid handle (ignored)
 * @file: file for fs/ecryptfs/euid handle
 *
 * This keeps the daemon registered until the daemon sends another
 * ioctl to fs/ecryptfs/ctl or until the kernel module unregisters.
 *
 * Returns zero on success; non-zero otherwise
 */
static int
ecryptfs_miscdev_release(struct inode *inode, struct file *file)
{
	struct ecryptfs_daemon *daemon = file->private_data;
	int rc;

	mutex_lock(&daemon->mux);
	BUG_ON(!(daemon->flags & ECRYPTFS_DAEMON_MISCDEV_OPEN));
	daemon->flags &= ~ECRYPTFS_DAEMON_MISCDEV_OPEN;
	atomic_dec(&ecryptfs_num_miscdev_opens);
	mutex_unlock(&daemon->mux);

	mutex_lock(&ecryptfs_daemon_hash_mux);
	rc = ecryptfs_exorcise_daemon(daemon);
	mutex_unlock(&ecryptfs_daemon_hash_mux);
	if (rc) {
		printk(KERN_CRIT "%s: Fatal error whilst attempting to "
		       "shut down daemon; rc = [%d]. Please report this "
		       "bug.\n", __func__, rc);
		BUG();
	}
	return rc;
}

/**
 * ecryptfs_send_miscdev
 * @data: Data to send to daemon; may be NULL
 * @data_size: Amount of data to send to daemon
 * @msg_ctx: Message context, which is used to handle the reply. If
 *           this is NULL, then we do not expect a reply.
 * @msg_type: Type of message
 * @msg_flags: Flags for message
 * @daemon: eCryptfs daemon object
 *
 * Add msg_ctx to queue and then, if it exists, notify the blocked
 * miscdevess about the data being available. Must be called with
 * ecryptfs_daemon_hash_mux held.
 *
 * Returns zero on success; non-zero otherwise
 */
int ecryptfs_send_miscdev(char *data, size_t data_size,
			  struct ecryptfs_msg_ctx *msg_ctx, u8 msg_type,
			  u16 msg_flags, struct ecryptfs_daemon *daemon)
{
	struct ecryptfs_message *msg;

	msg = kmalloc((sizeof(*msg) + data_size), GFP_KERNEL);
	if (!msg) {
		printk(KERN_ERR "%s: Out of memory whilst attempting "
		       "to kmalloc(%zd, GFP_KERNEL)\n", __func__,
		       (sizeof(*msg) + data_size));
		return -ENOMEM;
	}

	mutex_lock(&msg_ctx->mux);
	msg_ctx->msg = msg;
	msg_ctx->msg->index = msg_ctx->index;
	msg_ctx->msg->data_len = data_size;
	msg_ctx->type = msg_type;
	memcpy(msg_ctx->msg->data, data, data_size);
	msg_ctx->msg_size = (sizeof(*msg_ctx->msg) + data_size);
	list_add_tail(&msg_ctx->daemon_out_list, &daemon->msg_ctx_out_queue);
	mutex_unlock(&msg_ctx->mux);

	mutex_lock(&daemon->mux);
	daemon->num_queued_msg_ctx++;
	wake_up_interruptible(&daemon->wait);
	mutex_unlock(&daemon->mux);

	return 0;
}

/*
 * miscdevfs packet format:
 *  Octet 0: Type
 *  Octets 1-4: network byte order msg_ctx->counter
 *  Octets 5-N0: Size of struct ecryptfs_message to follow
 *  Octets N0-N1: struct ecryptfs_message (including data)
 *
 *  Octets 5-N1 not written if the packet type does not include a message
 */
#define PKT_TYPE_SIZE		1
#define PKT_CTR_SIZE		4
#define MIN_NON_MSG_PKT_SIZE	(PKT_TYPE_SIZE + PKT_CTR_SIZE)
#define MIN_MSG_PKT_SIZE	(PKT_TYPE_SIZE + PKT_CTR_SIZE \
				 + ECRYPTFS_MIN_PKT_LEN_SIZE)
/* 4 + ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES comes from tag 65 packet format */
#define MAX_MSG_PKT_SIZE	(PKT_TYPE_SIZE + PKT_CTR_SIZE \
				 + ECRYPTFS_MAX_PKT_LEN_SIZE \
				 + sizeof(struct ecryptfs_message) \
				 + 4 + ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES)
#define PKT_TYPE_OFFSET		0
#define PKT_CTR_OFFSET		PKT_TYPE_SIZE
#define PKT_LEN_OFFSET		(PKT_TYPE_SIZE + PKT_CTR_SIZE)

/**
 * ecryptfs_miscdev_read - format and send message from queue
 * @file: miscdevfs handle
 * @buf: User buffer into which to copy the next message on the daemon queue
 * @count: Amount of space available in @buf
 * @ppos: Offset in file (ignored)
 *
 * Pulls the most recent message from the daemon queue, formats it for
 * being sent via a miscdevfs handle, and copies it into @buf
 *
 * Returns the number of bytes copied into the user buffer
 */
static ssize_t
ecryptfs_miscdev_read(struct file *file, char __user *buf, size_t count,
		      loff_t *ppos)
{
	struct ecryptfs_daemon *daemon = file->private_data;
	struct ecryptfs_msg_ctx *msg_ctx;
	size_t packet_length_size;
	char packet_length[ECRYPTFS_MAX_PKT_LEN_SIZE];
	size_t i;
	size_t total_length;
	int rc;

	mutex_lock(&daemon->mux);
	if (daemon->flags & ECRYPTFS_DAEMON_ZOMBIE) {
		rc = 0;
		printk(KERN_WARNING "%s: Attempt to read from zombified "
		       "daemon\n", __func__);
		goto out_unlock_daemon;
	}
	if (daemon->flags & ECRYPTFS_DAEMON_IN_READ) {
		rc = 0;
		goto out_unlock_daemon;
	}
	/* This daemon will not go away so long as this flag is set */
	daemon->flags |= ECRYPTFS_DAEMON_IN_READ;
check_list:
	if (list_empty(&daemon->msg_ctx_out_queue)) {
		mutex_unlock(&daemon->mux);
		rc = wait_event_interruptible(
			daemon->wait, !list_empty(&daemon->msg_ctx_out_queue));
		mutex_lock(&daemon->mux);
		if (rc < 0) {
			rc = 0;
			goto out_unlock_daemon;
		}
	}
	if (daemon->flags & ECRYPTFS_DAEMON_ZOMBIE) {
		rc = 0;
		goto out_unlock_daemon;
	}
	if (list_empty(&daemon->msg_ctx_out_queue)) {
		/* Something else jumped in since the
		 * wait_event_interruptable() and removed the
		 * message from the queue; try again */
		goto check_list;
	}
	msg_ctx = list_first_entry(&daemon->msg_ctx_out_queue,
				   struct ecryptfs_msg_ctx, daemon_out_list);
	BUG_ON(!msg_ctx);
	mutex_lock(&msg_ctx->mux);
	if (msg_ctx->msg) {
		rc = ecryptfs_write_packet_length(packet_length,
						  msg_ctx->msg_size,
						  &packet_length_size);
		if (rc) {
			rc = 0;
			printk(KERN_WARNING "%s: Error writing packet length; "
			       "rc = [%d]\n", __func__, rc);
			goto out_unlock_msg_ctx;
		}
	} else {
		packet_length_size = 0;
		msg_ctx->msg_size = 0;
	}
	total_length = (PKT_TYPE_SIZE + PKT_CTR_SIZE + packet_length_size
			+ msg_ctx->msg_size);
	if (count < total_length) {
		rc = 0;
		printk(KERN_WARNING "%s: Only given user buffer of "
		       "size [%zd], but we need [%zd] to read the "
		       "pending message\n", __func__, count, total_length);
		goto out_unlock_msg_ctx;
	}
	rc = -EFAULT;
	if (put_user(msg_ctx->type, buf))
		goto out_unlock_msg_ctx;
	if (put_user(cpu_to_be32(msg_ctx->counter),
		     (__be32 __user *)(&buf[PKT_CTR_OFFSET])))
		goto out_unlock_msg_ctx;
	i = PKT_TYPE_SIZE + PKT_CTR_SIZE;
	if (msg_ctx->msg) {
		if (copy_to_user(&buf[i], packet_length, packet_length_size))
			goto out_unlock_msg_ctx;
		i += packet_length_size;
		if (copy_to_user(&buf[i], msg_ctx->msg, msg_ctx->msg_size))
			goto out_unlock_msg_ctx;
		i += msg_ctx->msg_size;
	}
	rc = i;
	list_del(&msg_ctx->daemon_out_list);
	kfree(msg_ctx->msg);
	msg_ctx->msg = NULL;
	/* We do not expect a reply from the userspace daemon for any
	 * message type other than ECRYPTFS_MSG_REQUEST */
	if (msg_ctx->type != ECRYPTFS_MSG_REQUEST)
		ecryptfs_msg_ctx_alloc_to_free(msg_ctx);
out_unlock_msg_ctx:
	mutex_unlock(&msg_ctx->mux);
out_unlock_daemon:
	daemon->flags &= ~ECRYPTFS_DAEMON_IN_READ;
	mutex_unlock(&daemon->mux);
	return rc;
}

/**
 * ecryptfs_miscdev_response - miscdevess response to message previously sent to daemon
 * @data: Bytes comprising struct ecryptfs_message
 * @data_size: sizeof(struct ecryptfs_message) + data len
 * @seq: Sequence number for miscdev response packet
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_miscdev_response(struct ecryptfs_daemon *daemon, char *data,
				     size_t data_size, u32 seq)
{
	struct ecryptfs_message *msg = (struct ecryptfs_message *)data;
	int rc;

	if ((sizeof(*msg) + msg->data_len) != data_size) {
		printk(KERN_WARNING "%s: (sizeof(*msg) + msg->data_len) = "
		       "[%zd]; data_size = [%zd]. Invalid packet.\n", __func__,
		       (sizeof(*msg) + msg->data_len), data_size);
		rc = -EINVAL;
		goto out;
	}
	rc = ecryptfs_process_response(daemon, msg, seq);
	if (rc)
		printk(KERN_ERR
		       "Error processing response message; rc = [%d]\n", rc);
out:
	return rc;
}

/**
 * ecryptfs_miscdev_write - handle write to daemon miscdev handle
 * @file: File for misc dev handle
 * @buf: Buffer containing user data
 * @count: Amount of data in @buf
 * @ppos: Pointer to offset in file (ignored)
 *
 * Returns the number of bytes read from @buf
 */
static ssize_t
ecryptfs_miscdev_write(struct file *file, const char __user *buf,
		       size_t count, loff_t *ppos)
{
	__be32 counter_nbo;
	u32 seq;
	size_t packet_size, packet_size_length;
	char *data;
	unsigned char packet_size_peek[ECRYPTFS_MAX_PKT_LEN_SIZE];
	ssize_t rc;

	if (count == 0) {
		return 0;
	} else if (count == MIN_NON_MSG_PKT_SIZE) {
		/* Likely a harmless MSG_HELO or MSG_QUIT - no packet length */
		goto memdup;
	} else if (count < MIN_MSG_PKT_SIZE || count > MAX_MSG_PKT_SIZE) {
		printk(KERN_WARNING "%s: Acceptable packet size range is "
		       "[%d-%zu], but amount of data written is [%zu].",
		       __func__, MIN_MSG_PKT_SIZE, MAX_MSG_PKT_SIZE, count);
		return -EINVAL;
	}

	if (copy_from_user(packet_size_peek, &buf[PKT_LEN_OFFSET],
			   sizeof(packet_size_peek))) {
		printk(KERN_WARNING "%s: Error while inspecting packet size\n",
		       __func__);
		return -EFAULT;
	}

	rc = ecryptfs_parse_packet_length(packet_size_peek, &packet_size,
					  &packet_size_length);
	if (rc) {
		printk(KERN_WARNING "%s: Error parsing packet length; "
		       "rc = [%zd]\n", __func__, rc);
		return rc;
	}

	if ((PKT_TYPE_SIZE + PKT_CTR_SIZE + packet_size_length + packet_size)
	    != count) {
		printk(KERN_WARNING "%s: Invalid packet size [%zu]\n", __func__,
		       packet_size);
		return -EINVAL;
	}

memdup:
	data = memdup_user(buf, count);
	if (IS_ERR(data)) {
		printk(KERN_ERR "%s: memdup_user returned error [%ld]\n",
		       __func__, PTR_ERR(data));
		return PTR_ERR(data);
	}
	switch (data[PKT_TYPE_OFFSET]) {
	case ECRYPTFS_MSG_RESPONSE:
		if (count < (MIN_MSG_PKT_SIZE
			     + sizeof(struct ecryptfs_message))) {
			printk(KERN_WARNING "%s: Minimum acceptable packet "
			       "size is [%zd], but amount of data written is "
			       "only [%zd]. Discarding response packet.\n",
			       __func__,
			       (MIN_MSG_PKT_SIZE
				+ sizeof(struct ecryptfs_message)), count);
			rc = -EINVAL;
			goto out_free;
		}
		memcpy(&counter_nbo, &data[PKT_CTR_OFFSET], PKT_CTR_SIZE);
		seq = be32_to_cpu(counter_nbo);
		rc = ecryptfs_miscdev_response(file->private_data,
				&data[PKT_LEN_OFFSET + packet_size_length],
				packet_size, seq);
		if (rc) {
			printk(KERN_WARNING "%s: Failed to deliver miscdev "
			       "response to requesting operation; rc = [%zd]\n",
			       __func__, rc);
			goto out_free;
		}
		break;
	case ECRYPTFS_MSG_HELO:
	case ECRYPTFS_MSG_QUIT:
		break;
	default:
		ecryptfs_printk(KERN_WARNING, "Dropping miscdev "
				"message of unrecognized type [%d]\n",
				data[0]);
		rc = -EINVAL;
		goto out_free;
	}
	rc = count;
out_free:
	kfree(data);
	return rc;
}


static const struct file_operations ecryptfs_miscdev_fops = {
	.owner   = THIS_MODULE,
	.open    = ecryptfs_miscdev_open,
	.poll    = ecryptfs_miscdev_poll,
	.read    = ecryptfs_miscdev_read,
	.write   = ecryptfs_miscdev_write,
	.release = ecryptfs_miscdev_release,
	.llseek  = noop_llseek,
};

static struct miscdevice ecryptfs_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "ecryptfs",
	.fops  = &ecryptfs_miscdev_fops
};

/**
 * ecryptfs_init_ecryptfs_miscdev
 *
 * Messages sent to the userspace daemon from the kernel are placed on
 * a queue associated with the daemon. The next read against the
 * miscdev handle by that daemon will return the oldest message placed
 * on the message queue for the daemon.
 *
 * Returns zero on success; non-zero otherwise
 */
int __init ecryptfs_init_ecryptfs_miscdev(void)
{
	int rc;

	atomic_set(&ecryptfs_num_miscdev_opens, 0);
	rc = misc_register(&ecryptfs_miscdev);
	if (rc)
		printk(KERN_ERR "%s: Failed to register miscellaneous device "
		       "for communications with userspace daemons; rc = [%d]\n",
		       __func__, rc);
	return rc;
}

/**
 * ecryptfs_destroy_ecryptfs_miscdev
 *
 * All of the daemons must be exorcised prior to calling this
 * function.
 */
void ecryptfs_destroy_ecryptfs_miscdev(void)
{
	BUG_ON(atomic_read(&ecryptfs_num_miscdev_opens) != 0);
	misc_deregister(&ecryptfs_miscdev);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ecryptfs/miscdev.c */
/************************************************************/
