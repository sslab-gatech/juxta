/*
 *      	An implementation of a loadable kernel mode driver providing
 *		multiple kernel/user space bidirectional communications links.
 *
 * 		Author: 	Alan Cox <alan@lxorguk.ukuu.org.uk>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *              Adapted to become the Linux 2.0 Coda pseudo device
 *              Peter  Braam  <braam@maths.ox.ac.uk>
 *              Michael Callahan <mjc@emmy.smith.edu>
 *
 *              Changes for Linux 2.1
 *              Copyright (c) 1997 Carnegie-Mellon University
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/pid_namespace.h>
#include <asm/io.h>
#include <asm/poll.h>
#include <linux/uaccess.h>

#include <linux/coda.h>
#include <linux/coda_psdev.h>

#include "coda_linux.h"

#include "coda_int.h"

/* statistics */
int           coda_hard;         /* allows signals during upcalls */
unsigned long coda_timeout = 30; /* .. secs, then signals will dequeue */


struct venus_comm coda_comms[MAX_CODADEVS];
static struct class *coda_psdev_class;

/*
 * Device operations
 */

static unsigned int coda_psdev_poll(struct file *file, poll_table * wait)
{
        struct venus_comm *vcp = (struct venus_comm *) file->private_data;
	unsigned int mask = POLLOUT | POLLWRNORM;

	poll_wait(file, &vcp->vc_waitq, wait);
	mutex_lock(&vcp->vc_mutex);
	if (!list_empty(&vcp->vc_pending))
                mask |= POLLIN | POLLRDNORM;
	mutex_unlock(&vcp->vc_mutex);

	return mask;
}

static long coda_psdev_ioctl(struct file * filp, unsigned int cmd, unsigned long arg)
{
	unsigned int data;

	switch(cmd) {
	case CIOC_KERNEL_VERSION:
		data = CODA_KERNEL_VERSION;
		return put_user(data, (int __user *) arg);
	default:
		return -ENOTTY;
	}

	return 0;
}

/*
 *	Receive a message written by Venus to the psdev
 */

static ssize_t coda_psdev_write(struct file *file, const char __user *buf,
				size_t nbytes, loff_t *off)
{
        struct venus_comm *vcp = (struct venus_comm *) file->private_data;
        struct upc_req *req = NULL;
        struct upc_req *tmp;
	struct list_head *lh;
	struct coda_in_hdr hdr;
	ssize_t retval = 0, count = 0;
	int error;

        /* Peek at the opcode, uniquefier */
	if (copy_from_user(&hdr, buf, 2 * sizeof(u_long)))
	        return -EFAULT;

        if (DOWNCALL(hdr.opcode)) {
		union outputArgs *dcbuf;
		int size = sizeof(*dcbuf);

		if  ( nbytes < sizeof(struct coda_out_hdr) ) {
			pr_warn("coda_downcall opc %d uniq %d, not enough!\n",
				hdr.opcode, hdr.unique);
			count = nbytes;
			goto out;
		}
		if ( nbytes > size ) {
			pr_warn("downcall opc %d, uniq %d, too much!",
				hdr.opcode, hdr.unique);
		        nbytes = size;
		}
		CODA_ALLOC(dcbuf, union outputArgs *, nbytes);
		if (copy_from_user(dcbuf, buf, nbytes)) {
			CODA_FREE(dcbuf, nbytes);
			retval = -EFAULT;
			goto out;
		}

		/* what downcall errors does Venus handle ? */
		error = coda_downcall(vcp, hdr.opcode, dcbuf);

		CODA_FREE(dcbuf, nbytes);
		if (error) {
			pr_warn("%s: coda_downcall error: %d\n",
				__func__, error);
			retval = error;
			goto out;
		}
		count = nbytes;
		goto out;
	}

	/* Look for the message on the processing queue. */
	mutex_lock(&vcp->vc_mutex);
	list_for_each(lh, &vcp->vc_processing) {
		tmp = list_entry(lh, struct upc_req , uc_chain);
		if (tmp->uc_unique == hdr.unique) {
			req = tmp;
			list_del(&req->uc_chain);
			break;
		}
	}
	mutex_unlock(&vcp->vc_mutex);

	if (!req) {
		pr_warn("%s: msg (%d, %d) not found\n",
			__func__, hdr.opcode, hdr.unique);
		retval = -ESRCH;
		goto out;
	}

        /* move data into response buffer. */
	if (req->uc_outSize < nbytes) {
		pr_warn("%s: too much cnt: %d, cnt: %ld, opc: %d, uniq: %d.\n",
			__func__, req->uc_outSize, (long)nbytes,
			hdr.opcode, hdr.unique);
		nbytes = req->uc_outSize; /* don't have more space! */
	}
        if (copy_from_user(req->uc_data, buf, nbytes)) {
		req->uc_flags |= CODA_REQ_ABORT;
		wake_up(&req->uc_sleep);
		retval = -EFAULT;
		goto out;
	}

	/* adjust outsize. is this useful ?? */
	req->uc_outSize = nbytes;
	req->uc_flags |= CODA_REQ_WRITE;
	count = nbytes;

	/* Convert filedescriptor into a file handle */
	if (req->uc_opcode == CODA_OPEN_BY_FD) {
		struct coda_open_by_fd_out *outp =
			(struct coda_open_by_fd_out *)req->uc_data;
		if (!outp->oh.result)
			outp->fh = fget(outp->fd);
	}

        wake_up(&req->uc_sleep);
out:
        return(count ? count : retval);
}

/*
 *	Read a message from the kernel to Venus
 */

static ssize_t coda_psdev_read(struct file * file, char __user * buf,
			       size_t nbytes, loff_t *off)
{
	DECLARE_WAITQUEUE(wait, current);
        struct venus_comm *vcp = (struct venus_comm *) file->private_data;
        struct upc_req *req;
	ssize_t retval = 0, count = 0;

	if (nbytes == 0)
		return 0;

	mutex_lock(&vcp->vc_mutex);

	add_wait_queue(&vcp->vc_waitq, &wait);
	set_current_state(TASK_INTERRUPTIBLE);

	while (list_empty(&vcp->vc_pending)) {
		if (file->f_flags & O_NONBLOCK) {
			retval = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			retval = -ERESTARTSYS;
			break;
		}
		mutex_unlock(&vcp->vc_mutex);
		schedule();
		mutex_lock(&vcp->vc_mutex);
	}

	set_current_state(TASK_RUNNING);
	remove_wait_queue(&vcp->vc_waitq, &wait);

	if (retval)
		goto out;

	req = list_entry(vcp->vc_pending.next, struct upc_req,uc_chain);
	list_del(&req->uc_chain);

	/* Move the input args into userspace */
	count = req->uc_inSize;
	if (nbytes < req->uc_inSize) {
		pr_warn("%s: Venus read %ld bytes of %d in message\n",
			__func__, (long)nbytes, req->uc_inSize);
		count = nbytes;
        }

	if (copy_to_user(buf, req->uc_data, count))
	        retval = -EFAULT;

	/* If request was not a signal, enqueue and don't free */
	if (!(req->uc_flags & CODA_REQ_ASYNC)) {
		req->uc_flags |= CODA_REQ_READ;
		list_add_tail(&(req->uc_chain), &vcp->vc_processing);
		goto out;
	}

	CODA_FREE(req->uc_data, sizeof(struct coda_in_hdr));
	kfree(req);
out:
	mutex_unlock(&vcp->vc_mutex);
	return (count ? count : retval);
}

static int coda_psdev_open(struct inode * inode, struct file * file)
{
	struct venus_comm *vcp;
	int idx, err;

	if (task_active_pid_ns(current) != &init_pid_ns)
		return -EINVAL;

	if (current_user_ns() != &init_user_ns)
		return -EINVAL;

	idx = iminor(inode);
	if (idx < 0 || idx >= MAX_CODADEVS)
		return -ENODEV;

	err = -EBUSY;
	vcp = &coda_comms[idx];
	mutex_lock(&vcp->vc_mutex);

	if (!vcp->vc_inuse) {
		vcp->vc_inuse++;

		INIT_LIST_HEAD(&vcp->vc_pending);
		INIT_LIST_HEAD(&vcp->vc_processing);
		init_waitqueue_head(&vcp->vc_waitq);
		vcp->vc_sb = NULL;
		vcp->vc_seq = 0;

		file->private_data = vcp;
		err = 0;
	}

	mutex_unlock(&vcp->vc_mutex);
	return err;
}


static int coda_psdev_release(struct inode * inode, struct file * file)
{
	struct venus_comm *vcp = (struct venus_comm *) file->private_data;
	struct upc_req *req, *tmp;

	if (!vcp || !vcp->vc_inuse ) {
		pr_warn("%s: Not open.\n", __func__);
		return -1;
	}

	mutex_lock(&vcp->vc_mutex);

	/* Wakeup clients so they can return. */
	list_for_each_entry_safe(req, tmp, &vcp->vc_pending, uc_chain) {
		list_del(&req->uc_chain);

		/* Async requests need to be freed here */
		if (req->uc_flags & CODA_REQ_ASYNC) {
			CODA_FREE(req->uc_data, sizeof(struct coda_in_hdr));
			kfree(req);
			continue;
		}
		req->uc_flags |= CODA_REQ_ABORT;
		wake_up(&req->uc_sleep);
	}

	list_for_each_entry_safe(req, tmp, &vcp->vc_processing, uc_chain) {
		list_del(&req->uc_chain);

		req->uc_flags |= CODA_REQ_ABORT;
		wake_up(&req->uc_sleep);
	}

	file->private_data = NULL;
	vcp->vc_inuse--;
	mutex_unlock(&vcp->vc_mutex);
	return 0;
}


static const struct file_operations coda_psdev_fops = {
	.owner		= THIS_MODULE,
	.read		= coda_psdev_read,
	.write		= coda_psdev_write,
	.poll		= coda_psdev_poll,
	.unlocked_ioctl	= coda_psdev_ioctl,
	.open		= coda_psdev_open,
	.release	= coda_psdev_release,
	.llseek		= noop_llseek,
};

static int init_coda_psdev(void)
{
	int i, err = 0;
	if (register_chrdev(CODA_PSDEV_MAJOR, "coda", &coda_psdev_fops)) {
		pr_err("%s: unable to get major %d\n",
		       __func__, CODA_PSDEV_MAJOR);
              return -EIO;
	}
	coda_psdev_class = class_create(THIS_MODULE, "coda");
	if (IS_ERR(coda_psdev_class)) {
		err = PTR_ERR(coda_psdev_class);
		goto out_chrdev;
	}
	for (i = 0; i < MAX_CODADEVS; i++) {
		mutex_init(&(&coda_comms[i])->vc_mutex);
		device_create(coda_psdev_class, NULL,
			      MKDEV(CODA_PSDEV_MAJOR, i), NULL, "cfs%d", i);
	}
	coda_sysctl_init();
	goto out;

out_chrdev:
	unregister_chrdev(CODA_PSDEV_MAJOR, "coda");
out:
	return err;
}

MODULE_AUTHOR("Jan Harkes, Peter J. Braam");
MODULE_DESCRIPTION("Coda Distributed File System VFS interface");
MODULE_ALIAS_CHARDEV_MAJOR(CODA_PSDEV_MAJOR);
MODULE_LICENSE("GPL");
MODULE_VERSION("6.6");

static int __init init_coda(void)
{
	int status;
	int i;

	status = coda_init_inodecache();
	if (status)
		goto out2;
	status = init_coda_psdev();
	if ( status ) {
		pr_warn("Problem (%d) in init_coda_psdev\n", status);
		goto out1;
	}

	status = register_filesystem(&coda_fs_type);
	if (status) {
		pr_warn("failed to register filesystem!\n");
		goto out;
	}
	return 0;
out:
	for (i = 0; i < MAX_CODADEVS; i++)
		device_destroy(coda_psdev_class, MKDEV(CODA_PSDEV_MAJOR, i));
	class_destroy(coda_psdev_class);
	unregister_chrdev(CODA_PSDEV_MAJOR, "coda");
	coda_sysctl_clean();
out1:
	coda_destroy_inodecache();
out2:
	return status;
}

static void __exit exit_coda(void)
{
        int err, i;

	err = unregister_filesystem(&coda_fs_type);
	if (err != 0)
		pr_warn("failed to unregister filesystem\n");
	for (i = 0; i < MAX_CODADEVS; i++)
		device_destroy(coda_psdev_class, MKDEV(CODA_PSDEV_MAJOR, i));
	class_destroy(coda_psdev_class);
	unregister_chrdev(CODA_PSDEV_MAJOR, "coda");
	coda_sysctl_clean();
	coda_destroy_inodecache();
}

module_init(init_coda);
module_exit(exit_coda);
/************************************************************/
/* ../linux-3.17/fs/coda/psdev.c */
/************************************************************/
/*
 * Cache operations for Coda.
 * For Linux 2.1: (C) 1997 Carnegie Mellon University
 * For Linux 2.3: (C) 2000 Carnegie Mellon University
 *
 * Carnegie Mellon encourages users of this code to contribute improvements
 * to the Coda project http://www.coda.cs.cmu.edu/ <coda@cs.cmu.edu>.
 */

#include <linux/types.h>
// #include <linux/kernel.h>
// #include <linux/time.h>
// #include <linux/fs.h>
#include <linux/stat.h>
// #include <linux/errno.h>
// #include <linux/uaccess.h>
#include <linux/string.h>
// #include <linux/list.h>
// #include <linux/sched.h>
#include <linux/spinlock.h>

// #include <linux/coda.h>
// #include <linux/coda_psdev.h>
// #include "coda_linux.h"
#include "coda_cache.h"

static atomic_t permission_epoch = ATOMIC_INIT(0);

/* replace or extend an acl cache hit */
void coda_cache_enter(struct inode *inode, int mask)
{
	struct coda_inode_info *cii = ITOC(inode);

	spin_lock(&cii->c_lock);
	cii->c_cached_epoch = atomic_read(&permission_epoch);
	if (!uid_eq(cii->c_uid, current_fsuid())) {
		cii->c_uid = current_fsuid();
                cii->c_cached_perm = mask;
        } else
                cii->c_cached_perm |= mask;
	spin_unlock(&cii->c_lock);
}

/* remove cached acl from an inode */
void coda_cache_clear_inode(struct inode *inode)
{
	struct coda_inode_info *cii = ITOC(inode);
	spin_lock(&cii->c_lock);
	cii->c_cached_epoch = atomic_read(&permission_epoch) - 1;
	spin_unlock(&cii->c_lock);
}

/* remove all acl caches */
void coda_cache_clear_all(struct super_block *sb)
{
	atomic_inc(&permission_epoch);
}


/* check if the mask has been matched against the acl already */
int coda_cache_check(struct inode *inode, int mask)
{
	struct coda_inode_info *cii = ITOC(inode);
	int hit;

	spin_lock(&cii->c_lock);
	hit = (mask & cii->c_cached_perm) == mask &&
	    uid_eq(cii->c_uid, current_fsuid()) &&
	    cii->c_cached_epoch == atomic_read(&permission_epoch);
	spin_unlock(&cii->c_lock);

	return hit;
}


/* Purging dentries and children */
/* The following routines drop dentries which are not
   in use and flag dentries which are in use to be
   zapped later.

   The flags are detected by:
   - coda_dentry_revalidate (for lookups) if the flag is C_PURGE
   - coda_dentry_delete: to remove dentry from the cache when d_count
     falls to zero
   - an inode method coda_revalidate (for attributes) if the
     flag is C_VATTR
*/

/* this won't do any harm: just flag all children */
static void coda_flag_children(struct dentry *parent, int flag)
{
	struct dentry *de;

	spin_lock(&parent->d_lock);
	list_for_each_entry(de, &parent->d_subdirs, d_u.d_child) {
		/* don't know what to do with negative dentries */
		if (de->d_inode )
			coda_flag_inode(de->d_inode, flag);
	}
	spin_unlock(&parent->d_lock);
	return;
}

void coda_flag_inode_children(struct inode *inode, int flag)
{
	struct dentry *alias_de;

	if ( !inode || !S_ISDIR(inode->i_mode))
		return;

	alias_de = d_find_alias(inode);
	if (!alias_de)
		return;
	coda_flag_children(alias_de, flag);
	shrink_dcache_parent(alias_de);
	dput(alias_de);
}
/************************************************************/
/* ../linux-3.17/fs/coda/cache.c */
/************************************************************/
/* cnode related routines for the coda kernel code
   (C) 1996 Peter Braam
   */

// #include <linux/types.h>
// #include <linux/string.h>
// #include <linux/time.h>

// #include <linux/coda.h>
// #include <linux/coda_psdev.h>
// #include "coda_linux.h"

static inline int coda_fideq(struct CodaFid *fid1, struct CodaFid *fid2)
{
	return memcmp(fid1, fid2, sizeof(*fid1)) == 0;
}

static const struct inode_operations coda_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.setattr	= coda_setattr,
};

/* cnode.c */
static void coda_fill_inode(struct inode *inode, struct coda_vattr *attr)
{
        coda_vattr_to_iattr(inode, attr);

        if (S_ISREG(inode->i_mode)) {
                inode->i_op = &coda_file_inode_operations;
                inode->i_fop = &coda_file_operations;
        } else if (S_ISDIR(inode->i_mode)) {
                inode->i_op = &coda_dir_inode_operations;
                inode->i_fop = &coda_dir_operations;
        } else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &coda_symlink_inode_operations;
		inode->i_data.a_ops = &coda_symlink_aops;
		inode->i_mapping = &inode->i_data;
	} else
                init_special_inode(inode, inode->i_mode, huge_decode_dev(attr->va_rdev));
}

static int coda_test_inode(struct inode *inode, void *data)
{
	struct CodaFid *fid = (struct CodaFid *)data;
	struct coda_inode_info *cii = ITOC(inode);
	return coda_fideq(&cii->c_fid, fid);
}

static int coda_set_inode(struct inode *inode, void *data)
{
	struct CodaFid *fid = (struct CodaFid *)data;
	struct coda_inode_info *cii = ITOC(inode);
	cii->c_fid = *fid;
	return 0;
}

struct inode * coda_iget(struct super_block * sb, struct CodaFid * fid,
			 struct coda_vattr * attr)
{
	struct inode *inode;
	struct coda_inode_info *cii;
	unsigned long hash = coda_f2i(fid);

	inode = iget5_locked(sb, hash, coda_test_inode, coda_set_inode, fid);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (inode->i_state & I_NEW) {
		cii = ITOC(inode);
		/* we still need to set i_ino for things like stat(2) */
		inode->i_ino = hash;
		/* inode is locked and unique, no need to grab cii->c_lock */
		cii->c_mapcount = 0;
		unlock_new_inode(inode);
	}

	/* always replace the attributes, type might have changed */
	coda_fill_inode(inode, attr);
	return inode;
}

/* this is effectively coda_iget:
   - get attributes (might be cached)
   - get the inode for the fid using vfs iget
   - link the two up if this is needed
   - fill in the attributes
*/
struct inode *coda_cnode_make(struct CodaFid *fid, struct super_block *sb)
{
        struct coda_vattr attr;
	struct inode *inode;
        int error;

	/* We get inode numbers from Venus -- see venus source */
	error = venus_getattr(sb, fid, &attr);
	if (error)
		return ERR_PTR(error);

	inode = coda_iget(sb, fid, &attr);
	if (IS_ERR(inode))
		pr_warn("%s: coda_iget failed\n", __func__);
	return inode;
}


/* Although we treat Coda file identifiers as immutable, there is one
 * special case for files created during a disconnection where they may
 * not be globally unique. When an identifier collision is detected we
 * first try to flush the cached inode from the kernel and finally
 * resort to renaming/rehashing in-place. Userspace remembers both old
 * and new values of the identifier to handle any in-flight upcalls.
 * The real solution is to use globally unique UUIDs as identifiers, but
 * retrofitting the existing userspace code for this is non-trivial. */
void coda_replace_fid(struct inode *inode, struct CodaFid *oldfid,
		      struct CodaFid *newfid)
{
	struct coda_inode_info *cii = ITOC(inode);
	unsigned long hash = coda_f2i(newfid);

	BUG_ON(!coda_fideq(&cii->c_fid, oldfid));

	/* replace fid and rehash inode */
	/* XXX we probably need to hold some lock here! */
	remove_inode_hash(inode);
	cii->c_fid = *newfid;
	inode->i_ino = hash;
	__insert_inode_hash(inode, hash);
}

/* convert a fid to an inode. */
struct inode *coda_fid_to_inode(struct CodaFid *fid, struct super_block *sb)
{
	struct inode *inode;
	unsigned long hash = coda_f2i(fid);

	if ( !sb ) {
		pr_warn("%s: no sb!\n", __func__);
		return NULL;
	}

	inode = ilookup5(sb, hash, coda_test_inode, fid);
	if ( !inode )
		return NULL;

	/* we should never see newly created inodes because we intentionally
	 * fail in the initialization callback */
	BUG_ON(inode->i_state & I_NEW);

	return inode;
}

/* the CONTROL inode is made without asking attributes from Venus */
struct inode *coda_cnode_makectl(struct super_block *sb)
{
	struct inode *inode = new_inode(sb);
	if (inode) {
		inode->i_ino = CTL_INO;
		inode->i_op = &coda_ioctl_inode_operations;
		inode->i_fop = &coda_ioctl_operations;
		inode->i_mode = 0444;
		return inode;
	}
	return ERR_PTR(-ENOMEM);
}
/************************************************************/
/* ../linux-3.17/fs/coda/cnode.c */
/************************************************************/
/*
 * Super block/filesystem wide operations
 *
 * Copyright (C) 1996 Peter J. Braam <braam@maths.ox.ac.uk> and
 * Michael Callahan <callahan@maths.ox.ac.uk>
 *
 * Rewritten for Linux 2.1.  Peter Braam <braam@cs.cmu.edu>
 * Copyright (C) Carnegie Mellon University
 */

// #include <linux/module.h>
// #include <linux/kernel.h>
#include <linux/mm.h>
// #include <linux/string.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
#include <linux/unistd.h>
// #include <linux/mutex.h>
// #include <linux/spinlock.h>
// #include <linux/file.h>
#include <linux/vfs.h>
// #include <linux/slab.h>
// #include <linux/pid_namespace.h>
// #include <linux/uaccess.h>
// #include <linux/fs.h>
// #include <linux/vmalloc.h>

// #include <linux/coda.h>
// #include <linux/coda_psdev.h>
// #include "coda_linux.h"
// #include "coda_cache.h"

// #include "coda_int.h"

/* VFS super_block ops */
static void coda_evict_inode(struct inode *);
static void coda_put_super(struct super_block *);
static int coda_statfs(struct dentry *dentry, struct kstatfs *buf);

static struct kmem_cache * coda_inode_cachep;

static struct inode *coda_alloc_inode(struct super_block *sb)
{
	struct coda_inode_info *ei;
	ei = kmem_cache_alloc(coda_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	memset(&ei->c_fid, 0, sizeof(struct CodaFid));
	ei->c_flags = 0;
	ei->c_uid = GLOBAL_ROOT_UID;
	ei->c_cached_perm = 0;
	spin_lock_init(&ei->c_lock);
	return &ei->vfs_inode;
}

static void coda_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(coda_inode_cachep, ITOC(inode));
}

static void coda_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, coda_i_callback);
}

static void init_once(void *foo)
{
	struct coda_inode_info *ei = (struct coda_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

int __init coda_init_inodecache(void)
{
	coda_inode_cachep = kmem_cache_create("coda_inode_cache",
				sizeof(struct coda_inode_info),
				0, SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD,
				init_once);
	if (coda_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void coda_destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(coda_inode_cachep);
}

static int coda_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	*flags |= MS_NOATIME;
	return 0;
}

/* exported operations */
static const struct super_operations coda_super_operations =
{
	.alloc_inode	= coda_alloc_inode,
	.destroy_inode	= coda_destroy_inode,
	.evict_inode	= coda_evict_inode,
	.put_super	= coda_put_super,
	.statfs		= coda_statfs,
	.remount_fs	= coda_remount,
};

static int get_device_index(struct coda_mount_data *data)
{
	struct fd f;
	struct inode *inode;
	int idx;

	if (data == NULL) {
		pr_warn("%s: Bad mount data\n", __func__);
		return -1;
	}

	if (data->version != CODA_MOUNT_VERSION) {
		pr_warn("%s: Bad mount version\n", __func__);
		return -1;
	}

	f = fdget(data->fd);
	if (!f.file)
		goto Ebadf;
	inode = file_inode(f.file);
	if (!S_ISCHR(inode->i_mode) || imajor(inode) != CODA_PSDEV_MAJOR) {
		fdput(f);
		goto Ebadf;
	}

	idx = iminor(inode);
	fdput(f);

	if (idx < 0 || idx >= MAX_CODADEVS) {
		pr_warn("%s: Bad minor number\n", __func__);
		return -1;
	}

	return idx;
Ebadf:
	pr_warn("%s: Bad file\n", __func__);
	return -1;
}

static int coda_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root = NULL;
	struct venus_comm *vc;
	struct CodaFid fid;
	int error;
	int idx;

	if (task_active_pid_ns(current) != &init_pid_ns)
		return -EINVAL;

	idx = get_device_index((struct coda_mount_data *) data);

	/* Ignore errors in data, for backward compatibility */
	if(idx == -1)
		idx = 0;

	pr_info("%s: device index: %i\n", __func__,  idx);

	vc = &coda_comms[idx];
	mutex_lock(&vc->vc_mutex);

	if (!vc->vc_inuse) {
		pr_warn("%s: No pseudo device\n", __func__);
		error = -EINVAL;
		goto unlock_out;
	}

	if (vc->vc_sb) {
		pr_warn("%s: Device already mounted\n", __func__);
		error = -EBUSY;
		goto unlock_out;
	}

	error = bdi_setup_and_register(&vc->bdi, "coda", BDI_CAP_MAP_COPY);
	if (error)
		goto unlock_out;

	vc->vc_sb = sb;
	mutex_unlock(&vc->vc_mutex);

	sb->s_fs_info = vc;
	sb->s_flags |= MS_NOATIME;
	sb->s_blocksize = 4096;	/* XXXXX  what do we put here?? */
	sb->s_blocksize_bits = 12;
	sb->s_magic = CODA_SUPER_MAGIC;
	sb->s_op = &coda_super_operations;
	sb->s_d_op = &coda_dentry_operations;
	sb->s_bdi = &vc->bdi;

	/* get root fid from Venus: this needs the root inode */
	error = venus_rootfid(sb, &fid);
	if ( error ) {
		pr_warn("%s: coda_get_rootfid failed with %d\n",
			__func__, error);
		goto error;
	}
	pr_info("%s: rootfid is %s\n", __func__, coda_f2s(&fid));

	/* make root inode */
        root = coda_cnode_make(&fid, sb);
        if (IS_ERR(root)) {
		error = PTR_ERR(root);
		pr_warn("Failure of coda_cnode_make for root: error %d\n",
			error);
		goto error;
	}

	pr_info("%s: rootinode is %ld dev %s\n",
		__func__, root->i_ino, root->i_sb->s_id);
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		error = -EINVAL;
		goto error;
	}
	return 0;

error:
	mutex_lock(&vc->vc_mutex);
	bdi_destroy(&vc->bdi);
	vc->vc_sb = NULL;
	sb->s_fs_info = NULL;
unlock_out:
	mutex_unlock(&vc->vc_mutex);
	return error;
}

static void coda_put_super(struct super_block *sb)
{
	struct venus_comm *vcp = coda_vcp(sb);
	mutex_lock(&vcp->vc_mutex);
	bdi_destroy(&vcp->bdi);
	vcp->vc_sb = NULL;
	sb->s_fs_info = NULL;
	mutex_unlock(&vcp->vc_mutex);

	pr_info("Bye bye.\n");
}

static void coda_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	coda_cache_clear_inode(inode);
}

int coda_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	int err = coda_revalidate_inode(dentry->d_inode);
	if (!err)
		generic_fillattr(dentry->d_inode, stat);
	return err;
}

int coda_setattr(struct dentry *de, struct iattr *iattr)
{
	struct inode *inode = de->d_inode;
	struct coda_vattr vattr;
	int error;

	memset(&vattr, 0, sizeof(vattr));

	inode->i_ctime = CURRENT_TIME_SEC;
	coda_iattr_to_vattr(iattr, &vattr);
	vattr.va_type = C_VNON; /* cannot set type */

	/* Venus is responsible for truncating the container-file!!! */
	error = venus_setattr(inode->i_sb, coda_i2f(inode), &vattr);

	if (!error) {
	        coda_vattr_to_iattr(inode, &vattr);
		coda_cache_clear_inode(inode);
	}
	return error;
}

const struct inode_operations coda_file_inode_operations = {
	.permission	= coda_permission,
	.getattr	= coda_getattr,
	.setattr	= coda_setattr,
};

static int coda_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int error;

	error = venus_statfs(dentry, buf);

	if (error) {
		/* fake something like AFS does */
		buf->f_blocks = 9000000;
		buf->f_bfree  = 9000000;
		buf->f_bavail = 9000000;
		buf->f_files  = 9000000;
		buf->f_ffree  = 9000000;
	}

	/* and fill in the rest */
	buf->f_type = CODA_SUPER_MAGIC;
	buf->f_bsize = 4096;
	buf->f_namelen = CODA_MAXNAMLEN;

	return 0;
}

/* init_coda: used by filesystems.c to register coda */

static struct dentry *coda_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, coda_fill_super);
}

struct file_system_type coda_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "coda",
	.mount		= coda_mount,
	.kill_sb	= kill_anon_super,
	.fs_flags	= FS_BINARY_MOUNTDATA,
};
MODULE_ALIAS_FS("coda");
/************************************************************/
/* ../linux-3.17/fs/coda/inode.c */
/************************************************************/
/*
 * Directory operations for Coda filesystem
 * Original version: (C) 1996 P. Braam and M. Callahan
 * Rewritten for Linux 2.1. (C) 1997 Carnegie Mellon University
 *
 * Carnegie Mellon encourages users to contribute improvements to
 * the Coda project. Contact Peter Braam (coda@cs.cmu.edu).
 */

// #include <linux/types.h>
// #include <linux/kernel.h>
// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/slab.h>
// #include <linux/file.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
// #include <linux/string.h>
// #include <linux/spinlock.h>
#include <linux/namei.h>
// #include <linux/uaccess.h>

// #include <linux/coda.h>
// #include <linux/coda_psdev.h>
// #include "coda_linux.h"
// #include "coda_cache.h"

// #include "coda_int.h"

/* dir inode-ops */
static int coda_create(struct inode *dir, struct dentry *new, umode_t mode, bool excl);
static struct dentry *coda_lookup(struct inode *dir, struct dentry *target, unsigned int flags);
static int coda_link(struct dentry *old_dentry, struct inode *dir_inode,
		     struct dentry *entry);
static int coda_unlink(struct inode *dir_inode, struct dentry *entry);
static int coda_symlink(struct inode *dir_inode, struct dentry *entry,
			const char *symname);
static int coda_mkdir(struct inode *dir_inode, struct dentry *entry, umode_t mode);
static int coda_rmdir(struct inode *dir_inode, struct dentry *entry);
static int coda_rename(struct inode *old_inode, struct dentry *old_dentry,
                       struct inode *new_inode, struct dentry *new_dentry);

/* dir file-ops */
static int coda_readdir(struct file *file, struct dir_context *ctx);

/* dentry ops */
static int coda_dentry_revalidate(struct dentry *de, unsigned int flags);
static int coda_dentry_delete(const struct dentry *);

/* support routines */
static int coda_venus_readdir(struct file *, struct dir_context *);

/* same as fs/bad_inode.c */
static int coda_return_EIO(void)
{
	return -EIO;
}
#define CODA_EIO_ERROR ((void *) (coda_return_EIO))

const struct dentry_operations coda_dentry_operations =
{
	.d_revalidate	= coda_dentry_revalidate,
	.d_delete	= coda_dentry_delete,
};

const struct inode_operations coda_dir_inode_operations =
{
	.create		= coda_create,
	.lookup		= coda_lookup,
	.link		= coda_link,
	.unlink		= coda_unlink,
	.symlink	= coda_symlink,
	.mkdir		= coda_mkdir,
	.rmdir		= coda_rmdir,
	.mknod		= CODA_EIO_ERROR,
	.rename		= coda_rename,
	.permission	= coda_permission,
	.getattr	= coda_getattr,
	.setattr	= coda_setattr,
};

const struct file_operations coda_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= coda_readdir,
	.open		= coda_open,
	.release	= coda_release,
	.fsync		= coda_fsync,
};


/* inode operations for directories */
/* access routines: lookup, readlink, permission */
static struct dentry *coda_lookup(struct inode *dir, struct dentry *entry, unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	const char *name = entry->d_name.name;
	size_t length = entry->d_name.len;
	struct inode *inode;
	int type = 0;

	if (length > CODA_MAXNAMLEN) {
		pr_err("name too long: lookup, %s (%*s)\n",
		       coda_i2s(dir), (int)length, name);
		return ERR_PTR(-ENAMETOOLONG);
	}

	/* control object, create inode on the fly */
	if (coda_isroot(dir) && coda_iscontrol(name, length)) {
		inode = coda_cnode_makectl(sb);
		type = CODA_NOCACHE;
	} else {
		struct CodaFid fid = { { 0, } };
		int error = venus_lookup(sb, coda_i2f(dir), name, length,
				     &type, &fid);
		inode = !error ? coda_cnode_make(&fid, sb) : ERR_PTR(error);
	}

	if (!IS_ERR(inode) && (type & CODA_NOCACHE))
		coda_flag_inode(inode, C_VATTR | C_PURGE);

	if (inode == ERR_PTR(-ENOENT))
		inode = NULL;

	return d_splice_alias(inode, entry);
}


int coda_permission(struct inode *inode, int mask)
{
	int error;

	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	mask &= MAY_READ | MAY_WRITE | MAY_EXEC;

	if (!mask)
		return 0;

	if ((mask & MAY_EXEC) && !execute_ok(inode))
		return -EACCES;

	if (coda_cache_check(inode, mask))
		return 0;

	error = venus_access(inode->i_sb, coda_i2f(inode), mask);

	if (!error)
		coda_cache_enter(inode, mask);

	return error;
}


static inline void coda_dir_update_mtime(struct inode *dir)
{
#ifdef REQUERY_VENUS_FOR_MTIME
	/* invalidate the directory cnode's attributes so we refetch the
	 * attributes from venus next time the inode is referenced */
	coda_flag_inode(dir, C_VATTR);
#else
	/* optimistically we can also act as if our nose bleeds. The
	 * granularity of the mtime is coarse anyways so we might actually be
	 * right most of the time. Note: we only do this for directories. */
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
#endif
}

/* we have to wrap inc_nlink/drop_nlink because sometimes userspace uses a
 * trick to fool GNU find's optimizations. If we can't be sure of the link
 * (because of volume mount points) we set i_nlink to 1 which forces find
 * to consider every child as a possible directory. We should also never
 * see an increment or decrement for deleted directories where i_nlink == 0 */
static inline void coda_dir_inc_nlink(struct inode *dir)
{
	if (dir->i_nlink >= 2)
		inc_nlink(dir);
}

static inline void coda_dir_drop_nlink(struct inode *dir)
{
	if (dir->i_nlink > 2)
		drop_nlink(dir);
}

/* creation routines: create, mknod, mkdir, link, symlink */
static int coda_create(struct inode *dir, struct dentry *de, umode_t mode, bool excl)
{
	int error;
	const char *name=de->d_name.name;
	int length=de->d_name.len;
	struct inode *inode;
	struct CodaFid newfid;
	struct coda_vattr attrs;

	if (coda_isroot(dir) && coda_iscontrol(name, length))
		return -EPERM;

	error = venus_create(dir->i_sb, coda_i2f(dir), name, length,
				0, mode, &newfid, &attrs);
	if (error)
		goto err_out;

	inode = coda_iget(dir->i_sb, &newfid, &attrs);
	if (IS_ERR(inode)) {
		error = PTR_ERR(inode);
		goto err_out;
	}

	/* invalidate the directory cnode's attributes */
	coda_dir_update_mtime(dir);
	d_instantiate(de, inode);
	return 0;
err_out:
	d_drop(de);
	return error;
}

static int coda_mkdir(struct inode *dir, struct dentry *de, umode_t mode)
{
	struct inode *inode;
	struct coda_vattr attrs;
	const char *name = de->d_name.name;
	int len = de->d_name.len;
	int error;
	struct CodaFid newfid;

	if (coda_isroot(dir) && coda_iscontrol(name, len))
		return -EPERM;

	attrs.va_mode = mode;
	error = venus_mkdir(dir->i_sb, coda_i2f(dir),
			       name, len, &newfid, &attrs);
	if (error)
		goto err_out;

	inode = coda_iget(dir->i_sb, &newfid, &attrs);
	if (IS_ERR(inode)) {
		error = PTR_ERR(inode);
		goto err_out;
	}

	/* invalidate the directory cnode's attributes */
	coda_dir_inc_nlink(dir);
	coda_dir_update_mtime(dir);
	d_instantiate(de, inode);
	return 0;
err_out:
	d_drop(de);
	return error;
}

/* try to make de an entry in dir_inodde linked to source_de */
static int coda_link(struct dentry *source_de, struct inode *dir_inode,
	  struct dentry *de)
{
	struct inode *inode = source_de->d_inode;
        const char * name = de->d_name.name;
	int len = de->d_name.len;
	int error;

	if (coda_isroot(dir_inode) && coda_iscontrol(name, len))
		return -EPERM;

	error = venus_link(dir_inode->i_sb, coda_i2f(inode),
			   coda_i2f(dir_inode), (const char *)name, len);
	if (error) {
		d_drop(de);
		return error;
	}

	coda_dir_update_mtime(dir_inode);
	ihold(inode);
	d_instantiate(de, inode);
	inc_nlink(inode);
	return 0;
}


static int coda_symlink(struct inode *dir_inode, struct dentry *de,
			const char *symname)
{
	const char *name = de->d_name.name;
	int len = de->d_name.len;
	int symlen;
	int error;

	if (coda_isroot(dir_inode) && coda_iscontrol(name, len))
		return -EPERM;

	symlen = strlen(symname);
	if (symlen > CODA_MAXPATHLEN)
		return -ENAMETOOLONG;

	/*
	 * This entry is now negative. Since we do not create
	 * an inode for the entry we have to drop it.
	 */
	d_drop(de);
	error = venus_symlink(dir_inode->i_sb, coda_i2f(dir_inode), name, len,
			      symname, symlen);

	/* mtime is no good anymore */
	if (!error)
		coda_dir_update_mtime(dir_inode);

	return error;
}

/* destruction routines: unlink, rmdir */
static int coda_unlink(struct inode *dir, struct dentry *de)
{
        int error;
	const char *name = de->d_name.name;
	int len = de->d_name.len;

	error = venus_remove(dir->i_sb, coda_i2f(dir), name, len);
	if (error)
		return error;

	coda_dir_update_mtime(dir);
	drop_nlink(de->d_inode);
	return 0;
}

static int coda_rmdir(struct inode *dir, struct dentry *de)
{
	const char *name = de->d_name.name;
	int len = de->d_name.len;
	int error;

	error = venus_rmdir(dir->i_sb, coda_i2f(dir), name, len);
	if (!error) {
		/* VFS may delete the child */
		if (de->d_inode)
			clear_nlink(de->d_inode);

		/* fix the link count of the parent */
		coda_dir_drop_nlink(dir);
		coda_dir_update_mtime(dir);
	}
	return error;
}

/* rename */
static int coda_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry)
{
	const char *old_name = old_dentry->d_name.name;
	const char *new_name = new_dentry->d_name.name;
	int old_length = old_dentry->d_name.len;
	int new_length = new_dentry->d_name.len;
	int error;

	error = venus_rename(old_dir->i_sb, coda_i2f(old_dir),
			     coda_i2f(new_dir), old_length, new_length,
			     (const char *) old_name, (const char *)new_name);
	if (!error) {
		if (new_dentry->d_inode) {
			if (S_ISDIR(new_dentry->d_inode->i_mode)) {
				coda_dir_drop_nlink(old_dir);
				coda_dir_inc_nlink(new_dir);
			}
			coda_dir_update_mtime(old_dir);
			coda_dir_update_mtime(new_dir);
			coda_flag_inode(new_dentry->d_inode, C_VATTR);
		} else {
			coda_flag_inode(old_dir, C_VATTR);
			coda_flag_inode(new_dir, C_VATTR);
		}
	}
	return error;
}


/* file operations for directories */
static int coda_readdir(struct file *coda_file, struct dir_context *ctx)
{
	struct coda_file_info *cfi;
	struct file *host_file;
	int ret;

	cfi = CODA_FTOC(coda_file);
	BUG_ON(!cfi || cfi->cfi_magic != CODA_MAGIC);
	host_file = cfi->cfi_container;

	if (host_file->f_op->iterate) {
		struct inode *host_inode = file_inode(host_file);
		mutex_lock(&host_inode->i_mutex);
		ret = -ENOENT;
		if (!IS_DEADDIR(host_inode)) {
			ret = host_file->f_op->iterate(host_file, ctx);
			file_accessed(host_file);
		}
		mutex_unlock(&host_inode->i_mutex);
		return ret;
	}
	/* Venus: we must read Venus dirents from a file */
	return coda_venus_readdir(coda_file, ctx);
}

static inline unsigned int CDT2DT(unsigned char cdt)
{
	unsigned int dt;

	switch(cdt) {
	case CDT_UNKNOWN: dt = DT_UNKNOWN; break;
	case CDT_FIFO:	  dt = DT_FIFO;    break;
	case CDT_CHR:	  dt = DT_CHR;     break;
	case CDT_DIR:	  dt = DT_DIR;     break;
	case CDT_BLK:	  dt = DT_BLK;     break;
	case CDT_REG:	  dt = DT_REG;     break;
	case CDT_LNK:	  dt = DT_LNK;     break;
	case CDT_SOCK:	  dt = DT_SOCK;    break;
	case CDT_WHT:	  dt = DT_WHT;     break;
	default:	  dt = DT_UNKNOWN; break;
	}
	return dt;
}

/* support routines */
static int coda_venus_readdir(struct file *coda_file, struct dir_context *ctx)
{
	struct coda_file_info *cfi;
	struct coda_inode_info *cii;
	struct file *host_file;
	struct dentry *de;
	struct venus_dirent *vdir;
	unsigned long vdir_size = offsetof(struct venus_dirent, d_name);
	unsigned int type;
	struct qstr name;
	ino_t ino;
	int ret;

	cfi = CODA_FTOC(coda_file);
	BUG_ON(!cfi || cfi->cfi_magic != CODA_MAGIC);
	host_file = cfi->cfi_container;

	de = coda_file->f_path.dentry;
	cii = ITOC(de->d_inode);

	vdir = kmalloc(sizeof(*vdir), GFP_KERNEL);
	if (!vdir) return -ENOMEM;

	if (!dir_emit_dots(coda_file, ctx))
		goto out;

	while (1) {
		/* read entries from the directory file */
		ret = kernel_read(host_file, ctx->pos - 2, (char *)vdir,
				  sizeof(*vdir));
		if (ret < 0) {
			pr_err("%s: read dir %s failed %d\n",
			       __func__, coda_f2s(&cii->c_fid), ret);
			break;
		}
		if (ret == 0) break; /* end of directory file reached */

		/* catch truncated reads */
		if (ret < vdir_size || ret < vdir_size + vdir->d_namlen) {
			pr_err("%s: short read on %s\n",
			       __func__, coda_f2s(&cii->c_fid));
			ret = -EBADF;
			break;
		}
		/* validate whether the directory file actually makes sense */
		if (vdir->d_reclen < vdir_size + vdir->d_namlen) {
			pr_err("%s: invalid dir %s\n",
			       __func__, coda_f2s(&cii->c_fid));
			ret = -EBADF;
			break;
		}

		name.len = vdir->d_namlen;
		name.name = vdir->d_name;

		/* Make sure we skip '.' and '..', we already got those */
		if (name.name[0] == '.' && (name.len == 1 ||
		    (name.name[1] == '.' && name.len == 2)))
			vdir->d_fileno = name.len = 0;

		/* skip null entries */
		if (vdir->d_fileno && name.len) {
			ino = vdir->d_fileno;
			type = CDT2DT(vdir->d_type);
			if (!dir_emit(ctx, name.name, name.len, ino, type))
				break;
		}
		/* we'll always have progress because d_reclen is unsigned and
		 * we've already established it is non-zero. */
		ctx->pos += vdir->d_reclen;
	}
out:
	kfree(vdir);
	return 0;
}

/* called when a cache lookup succeeds */
static int coda_dentry_revalidate(struct dentry *de, unsigned int flags)
{
	struct inode *inode;
	struct coda_inode_info *cii;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	inode = de->d_inode;
	if (!inode || coda_isroot(inode))
		goto out;
	if (is_bad_inode(inode))
		goto bad;

	cii = ITOC(de->d_inode);
	if (!(cii->c_flags & (C_PURGE | C_FLUSH)))
		goto out;

	shrink_dcache_parent(de);

	/* propagate for a flush */
	if (cii->c_flags & C_FLUSH)
		coda_flag_inode_children(inode, C_FLUSH);

	if (d_count(de) > 1)
		/* pretend it's valid, but don't change the flags */
		goto out;

	/* clear the flags. */
	spin_lock(&cii->c_lock);
	cii->c_flags &= ~(C_VATTR | C_PURGE | C_FLUSH);
	spin_unlock(&cii->c_lock);
bad:
	return 0;
out:
	return 1;
}

/*
 * This is the callback from dput() when d_count is going to 0.
 * We use this to unhash dentries with bad inodes.
 */
static int coda_dentry_delete(const struct dentry * dentry)
{
	int flags;

	if (!dentry->d_inode)
		return 0;

	flags = (ITOC(dentry->d_inode)->c_flags) & C_PURGE;
	if (is_bad_inode(dentry->d_inode) || flags) {
		return 1;
	}
	return 0;
}



/*
 * This is called when we want to check if the inode has
 * changed on the server.  Coda makes this easy since the
 * cache manager Venus issues a downcall to the kernel when this
 * happens
 */
int coda_revalidate_inode(struct inode *inode)
{
	struct coda_vattr attr;
	int error;
	int old_mode;
	ino_t old_ino;
	struct coda_inode_info *cii = ITOC(inode);

	if (!cii->c_flags)
		return 0;

	if (cii->c_flags & (C_VATTR | C_PURGE | C_FLUSH)) {
		error = venus_getattr(inode->i_sb, &(cii->c_fid), &attr);
		if (error)
			return -EIO;

		/* this inode may be lost if:
		   - it's ino changed
		   - type changes must be permitted for repair and
		   missing mount points.
		*/
		old_mode = inode->i_mode;
		old_ino = inode->i_ino;
		coda_vattr_to_iattr(inode, &attr);

		if ((old_mode & S_IFMT) != (inode->i_mode & S_IFMT)) {
			pr_warn("inode %ld, fid %s changed type!\n",
				inode->i_ino, coda_f2s(&(cii->c_fid)));
		}

		/* the following can happen when a local fid is replaced
		   with a global one, here we lose and declare the inode bad */
		if (inode->i_ino != old_ino)
			return -EIO;

		coda_flag_inode_children(inode, C_FLUSH);

		spin_lock(&cii->c_lock);
		cii->c_flags &= ~(C_VATTR | C_PURGE | C_FLUSH);
		spin_unlock(&cii->c_lock);
	}
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/coda/dir.c */
/************************************************************/
/*
 * File operations for Coda.
 * Original version: (C) 1996 Peter Braam
 * Rewritten for Linux 2.1: (C) 1997 Carnegie Mellon University
 *
 * Carnegie Mellon encourages users of this code to contribute improvements
 * to the Coda project. Contact Peter Braam <coda@cs.cmu.edu>.
 */

// #include <linux/types.h>
// #include <linux/kernel.h>
// #include <linux/time.h>
// #include <linux/file.h>
// #include <linux/fs.h>
// #include <linux/stat.h>
#include <linux/cred.h>
// #include <linux/errno.h>
// #include <linux/spinlock.h>
// #include <linux/string.h>
// #include <linux/slab.h>
// #include <linux/uaccess.h>

// #include <linux/coda.h>
// #include <linux/coda_psdev.h>

// #include "coda_linux.h"
// #include "coda_int.h"

static ssize_t
coda_file_read(struct file *coda_file, char __user *buf, size_t count, loff_t *ppos)
{
	struct coda_file_info *cfi;
	struct file *host_file;

	cfi = CODA_FTOC(coda_file);
	BUG_ON(!cfi || cfi->cfi_magic != CODA_MAGIC);
	host_file = cfi->cfi_container;

	if (!host_file->f_op->read)
		return -EINVAL;

	return host_file->f_op->read(host_file, buf, count, ppos);
}

static ssize_t
coda_file_splice_read(struct file *coda_file, loff_t *ppos,
		      struct pipe_inode_info *pipe, size_t count,
		      unsigned int flags)
{
	ssize_t (*splice_read)(struct file *, loff_t *,
			       struct pipe_inode_info *, size_t, unsigned int);
	struct coda_file_info *cfi;
	struct file *host_file;

	cfi = CODA_FTOC(coda_file);
	BUG_ON(!cfi || cfi->cfi_magic != CODA_MAGIC);
	host_file = cfi->cfi_container;

	splice_read = host_file->f_op->splice_read;
	if (!splice_read)
		splice_read = default_file_splice_read;

	return splice_read(host_file, ppos, pipe, count, flags);
}

static ssize_t
coda_file_write(struct file *coda_file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct inode *host_inode, *coda_inode = file_inode(coda_file);
	struct coda_file_info *cfi;
	struct file *host_file;
	ssize_t ret;

	cfi = CODA_FTOC(coda_file);
	BUG_ON(!cfi || cfi->cfi_magic != CODA_MAGIC);
	host_file = cfi->cfi_container;

	if (!host_file->f_op->write)
		return -EINVAL;

	host_inode = file_inode(host_file);
	file_start_write(host_file);
	mutex_lock(&coda_inode->i_mutex);

	ret = host_file->f_op->write(host_file, buf, count, ppos);

	coda_inode->i_size = host_inode->i_size;
	coda_inode->i_blocks = (coda_inode->i_size + 511) >> 9;
	coda_inode->i_mtime = coda_inode->i_ctime = CURRENT_TIME_SEC;
	mutex_unlock(&coda_inode->i_mutex);
	file_end_write(host_file);

	return ret;
}

static int
coda_file_mmap(struct file *coda_file, struct vm_area_struct *vma)
{
	struct coda_file_info *cfi;
	struct coda_inode_info *cii;
	struct file *host_file;
	struct inode *coda_inode, *host_inode;

	cfi = CODA_FTOC(coda_file);
	BUG_ON(!cfi || cfi->cfi_magic != CODA_MAGIC);
	host_file = cfi->cfi_container;

	if (!host_file->f_op->mmap)
		return -ENODEV;

	coda_inode = file_inode(coda_file);
	host_inode = file_inode(host_file);

	cii = ITOC(coda_inode);
	spin_lock(&cii->c_lock);
	coda_file->f_mapping = host_file->f_mapping;
	if (coda_inode->i_mapping == &coda_inode->i_data)
		coda_inode->i_mapping = host_inode->i_mapping;

	/* only allow additional mmaps as long as userspace isn't changing
	 * the container file on us! */
	else if (coda_inode->i_mapping != host_inode->i_mapping) {
		spin_unlock(&cii->c_lock);
		return -EBUSY;
	}

	/* keep track of how often the coda_inode/host_file has been mmapped */
	cii->c_mapcount++;
	cfi->cfi_mapcount++;
	spin_unlock(&cii->c_lock);

	return host_file->f_op->mmap(host_file, vma);
}

int coda_open(struct inode *coda_inode, struct file *coda_file)
{
	struct file *host_file = NULL;
	int error;
	unsigned short flags = coda_file->f_flags & (~O_EXCL);
	unsigned short coda_flags = coda_flags_to_cflags(flags);
	struct coda_file_info *cfi;

	cfi = kmalloc(sizeof(struct coda_file_info), GFP_KERNEL);
	if (!cfi)
		return -ENOMEM;

	error = venus_open(coda_inode->i_sb, coda_i2f(coda_inode), coda_flags,
			   &host_file);
	if (!host_file)
		error = -EIO;

	if (error) {
		kfree(cfi);
		return error;
	}

	host_file->f_flags |= coda_file->f_flags & (O_APPEND | O_SYNC);

	cfi->cfi_magic = CODA_MAGIC;
	cfi->cfi_mapcount = 0;
	cfi->cfi_container = host_file;

	BUG_ON(coda_file->private_data != NULL);
	coda_file->private_data = cfi;
	return 0;
}

int coda_release(struct inode *coda_inode, struct file *coda_file)
{
	unsigned short flags = (coda_file->f_flags) & (~O_EXCL);
	unsigned short coda_flags = coda_flags_to_cflags(flags);
	struct coda_file_info *cfi;
	struct coda_inode_info *cii;
	struct inode *host_inode;
	int err;

	cfi = CODA_FTOC(coda_file);
	BUG_ON(!cfi || cfi->cfi_magic != CODA_MAGIC);

	err = venus_close(coda_inode->i_sb, coda_i2f(coda_inode),
			  coda_flags, coda_file->f_cred->fsuid);

	host_inode = file_inode(cfi->cfi_container);
	cii = ITOC(coda_inode);

	/* did we mmap this file? */
	spin_lock(&cii->c_lock);
	if (coda_inode->i_mapping == &host_inode->i_data) {
		cii->c_mapcount -= cfi->cfi_mapcount;
		if (!cii->c_mapcount)
			coda_inode->i_mapping = &coda_inode->i_data;
	}
	spin_unlock(&cii->c_lock);

	fput(cfi->cfi_container);
	kfree(coda_file->private_data);
	coda_file->private_data = NULL;

	/* VFS fput ignores the return value from file_operations->release, so
	 * there is no use returning an error here */
	return 0;
}

int coda_fsync(struct file *coda_file, loff_t start, loff_t end, int datasync)
{
	struct file *host_file;
	struct inode *coda_inode = file_inode(coda_file);
	struct coda_file_info *cfi;
	int err;

	if (!(S_ISREG(coda_inode->i_mode) || S_ISDIR(coda_inode->i_mode) ||
	      S_ISLNK(coda_inode->i_mode)))
		return -EINVAL;

	err = filemap_write_and_wait_range(coda_inode->i_mapping, start, end);
	if (err)
		return err;
	mutex_lock(&coda_inode->i_mutex);

	cfi = CODA_FTOC(coda_file);
	BUG_ON(!cfi || cfi->cfi_magic != CODA_MAGIC);
	host_file = cfi->cfi_container;

	err = vfs_fsync(host_file, datasync);
	if (!err && !datasync)
		err = venus_fsync(coda_inode->i_sb, coda_i2f(coda_inode));
	mutex_unlock(&coda_inode->i_mutex);

	return err;
}

const struct file_operations coda_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= coda_file_read,
	.write		= coda_file_write,
	.mmap		= coda_file_mmap,
	.open		= coda_open,
	.release	= coda_release,
	.fsync		= coda_fsync,
	.splice_read	= coda_file_splice_read,
};
/************************************************************/
/* ../linux-3.17/fs/coda/file.c */
/************************************************************/
/*
 * Mostly platform independent upcall operations to Venus:
 *  -- upcalls
 *  -- upcall routines
 *
 * Linux 2.0 version
 * Copyright (C) 1996 Peter J. Braam <braam@maths.ox.ac.uk>,
 * Michael Callahan <callahan@maths.ox.ac.uk>
 *
 * Redone for Linux 2.1
 * Copyright (C) 1997 Carnegie Mellon University
 *
 * Carnegie Mellon University encourages users of this code to contribute
 * improvements to the Coda project. Contact Peter Braam <coda@cs.cmu.edu>.
 */

#include <linux/signal.h>
// #include <linux/sched.h>
// #include <linux/types.h>
// #include <linux/kernel.h>
// #include <linux/mm.h>
// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/file.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
// #include <linux/string.h>
// #include <linux/slab.h>
// #include <linux/mutex.h>
// #include <linux/uaccess.h>
// #include <linux/vmalloc.h>
// #include <linux/vfs.h>

// #include <linux/coda.h>
// #include <linux/coda_psdev.h>
// #include "coda_linux.h"
// #include "coda_cache.h"

// #include "coda_int.h"

static int coda_upcall(struct venus_comm *vc, int inSize, int *outSize,
		       union inputArgs *buffer);

static void *alloc_upcall(int opcode, int size)
{
	union inputArgs *inp;

	CODA_ALLOC(inp, union inputArgs *, size);
        if (!inp)
		return ERR_PTR(-ENOMEM);

        inp->ih.opcode = opcode;
	inp->ih.pid = task_pid_nr_ns(current, &init_pid_ns);
	inp->ih.pgid = task_pgrp_nr_ns(current, &init_pid_ns);
	inp->ih.uid = from_kuid(&init_user_ns, current_fsuid());

	return (void*)inp;
}

#define UPARG(op)\
do {\
	inp = (union inputArgs *)alloc_upcall(op, insize); \
        if (IS_ERR(inp)) { return PTR_ERR(inp); }\
        outp = (union outputArgs *)(inp); \
        outsize = insize; \
} while (0)

#define INSIZE(tag) sizeof(struct coda_ ## tag ## _in)
#define OUTSIZE(tag) sizeof(struct coda_ ## tag ## _out)
#define SIZE(tag)  max_t(unsigned int, INSIZE(tag), OUTSIZE(tag))


/* the upcalls */
int venus_rootfid(struct super_block *sb, struct CodaFid *fidp)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;

        insize = SIZE(root);
        UPARG(CODA_ROOT);

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);
	if (!error)
		*fidp = outp->coda_root.VFid;

	CODA_FREE(inp, insize);
	return error;
}

int venus_getattr(struct super_block *sb, struct CodaFid *fid,
		     struct coda_vattr *attr)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;

        insize = SIZE(getattr);
	UPARG(CODA_GETATTR);
        inp->coda_getattr.VFid = *fid;

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);
	if (!error)
		*attr = outp->coda_getattr.attr;

	CODA_FREE(inp, insize);
        return error;
}

int venus_setattr(struct super_block *sb, struct CodaFid *fid,
		  struct coda_vattr *vattr)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;

	insize = SIZE(setattr);
	UPARG(CODA_SETATTR);

        inp->coda_setattr.VFid = *fid;
	inp->coda_setattr.attr = *vattr;

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);

        CODA_FREE(inp, insize);
        return error;
}

int venus_lookup(struct super_block *sb, struct CodaFid *fid,
		    const char *name, int length, int * type,
		    struct CodaFid *resfid)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;
	int offset;

	offset = INSIZE(lookup);
        insize = max_t(unsigned int, offset + length +1, OUTSIZE(lookup));
	UPARG(CODA_LOOKUP);

        inp->coda_lookup.VFid = *fid;
	inp->coda_lookup.name = offset;
	inp->coda_lookup.flags = CLU_CASE_SENSITIVE;
        /* send Venus a null terminated string */
        memcpy((char *)(inp) + offset, name, length);
        *((char *)inp + offset + length) = '\0';

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);
	if (!error) {
		*resfid = outp->coda_lookup.VFid;
		*type = outp->coda_lookup.vtype;
	}

	CODA_FREE(inp, insize);
	return error;
}

int venus_close(struct super_block *sb, struct CodaFid *fid, int flags,
		kuid_t uid)
{
	union inputArgs *inp;
	union outputArgs *outp;
	int insize, outsize, error;

	insize = SIZE(release);
	UPARG(CODA_CLOSE);

	inp->ih.uid = from_kuid(&init_user_ns, uid);
        inp->coda_close.VFid = *fid;
        inp->coda_close.flags = flags;

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);

	CODA_FREE(inp, insize);
        return error;
}

int venus_open(struct super_block *sb, struct CodaFid *fid,
		  int flags, struct file **fh)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;

	insize = SIZE(open_by_fd);
	UPARG(CODA_OPEN_BY_FD);

	inp->coda_open_by_fd.VFid = *fid;
	inp->coda_open_by_fd.flags = flags;

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);
	if (!error)
		*fh = outp->coda_open_by_fd.fh;

	CODA_FREE(inp, insize);
	return error;
}

int venus_mkdir(struct super_block *sb, struct CodaFid *dirfid,
		   const char *name, int length,
		   struct CodaFid *newfid, struct coda_vattr *attrs)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;
        int offset;

	offset = INSIZE(mkdir);
	insize = max_t(unsigned int, offset + length + 1, OUTSIZE(mkdir));
	UPARG(CODA_MKDIR);

        inp->coda_mkdir.VFid = *dirfid;
        inp->coda_mkdir.attr = *attrs;
	inp->coda_mkdir.name = offset;
        /* Venus must get null terminated string */
        memcpy((char *)(inp) + offset, name, length);
        *((char *)inp + offset + length) = '\0';

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);
	if (!error) {
		*attrs = outp->coda_mkdir.attr;
		*newfid = outp->coda_mkdir.VFid;
	}

	CODA_FREE(inp, insize);
	return error;
}


int venus_rename(struct super_block *sb, struct CodaFid *old_fid,
		 struct CodaFid *new_fid, size_t old_length,
		 size_t new_length, const char *old_name,
		 const char *new_name)
{
	union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;
	int offset, s;

	offset = INSIZE(rename);
	insize = max_t(unsigned int, offset + new_length + old_length + 8,
		     OUTSIZE(rename));
 	UPARG(CODA_RENAME);

        inp->coda_rename.sourceFid = *old_fid;
        inp->coda_rename.destFid =  *new_fid;
        inp->coda_rename.srcname = offset;

        /* Venus must receive an null terminated string */
        s = ( old_length & ~0x3) +4; /* round up to word boundary */
        memcpy((char *)(inp) + offset, old_name, old_length);
        *((char *)inp + offset + old_length) = '\0';

        /* another null terminated string for Venus */
        offset += s;
        inp->coda_rename.destname = offset;
        s = ( new_length & ~0x3) +4; /* round up to word boundary */
        memcpy((char *)(inp) + offset, new_name, new_length);
        *((char *)inp + offset + new_length) = '\0';

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);

	CODA_FREE(inp, insize);
	return error;
}

int venus_create(struct super_block *sb, struct CodaFid *dirfid,
		 const char *name, int length, int excl, int mode,
		 struct CodaFid *newfid, struct coda_vattr *attrs)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;
        int offset;

        offset = INSIZE(create);
	insize = max_t(unsigned int, offset + length + 1, OUTSIZE(create));
	UPARG(CODA_CREATE);

        inp->coda_create.VFid = *dirfid;
        inp->coda_create.attr.va_mode = mode;
	inp->coda_create.excl = excl;
        inp->coda_create.mode = mode;
        inp->coda_create.name = offset;

        /* Venus must get null terminated string */
        memcpy((char *)(inp) + offset, name, length);
        *((char *)inp + offset + length) = '\0';

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);
	if (!error) {
		*attrs = outp->coda_create.attr;
		*newfid = outp->coda_create.VFid;
	}

	CODA_FREE(inp, insize);
	return error;
}

int venus_rmdir(struct super_block *sb, struct CodaFid *dirfid,
		    const char *name, int length)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;
        int offset;

        offset = INSIZE(rmdir);
	insize = max_t(unsigned int, offset + length + 1, OUTSIZE(rmdir));
	UPARG(CODA_RMDIR);

        inp->coda_rmdir.VFid = *dirfid;
        inp->coda_rmdir.name = offset;
        memcpy((char *)(inp) + offset, name, length);
	*((char *)inp + offset + length) = '\0';

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);

	CODA_FREE(inp, insize);
	return error;
}

int venus_remove(struct super_block *sb, struct CodaFid *dirfid,
		    const char *name, int length)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int error=0, insize, outsize, offset;

        offset = INSIZE(remove);
	insize = max_t(unsigned int, offset + length + 1, OUTSIZE(remove));
	UPARG(CODA_REMOVE);

        inp->coda_remove.VFid = *dirfid;
        inp->coda_remove.name = offset;
        memcpy((char *)(inp) + offset, name, length);
	*((char *)inp + offset + length) = '\0';

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);

	CODA_FREE(inp, insize);
	return error;
}

int venus_readlink(struct super_block *sb, struct CodaFid *fid,
		      char *buffer, int *length)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;
        int retlen;
        char *result;

	insize = max_t(unsigned int,
		     INSIZE(readlink), OUTSIZE(readlink)+ *length + 1);
	UPARG(CODA_READLINK);

        inp->coda_readlink.VFid = *fid;

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);
	if (!error) {
		retlen = outp->coda_readlink.count;
		if ( retlen > *length )
			retlen = *length;
		*length = retlen;
		result =  (char *)outp + (long)outp->coda_readlink.data;
		memcpy(buffer, result, retlen);
		*(buffer + retlen) = '\0';
	}

        CODA_FREE(inp, insize);
        return error;
}



int venus_link(struct super_block *sb, struct CodaFid *fid,
		  struct CodaFid *dirfid, const char *name, int len )
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;
        int offset;

	offset = INSIZE(link);
	insize = max_t(unsigned int, offset  + len + 1, OUTSIZE(link));
        UPARG(CODA_LINK);

        inp->coda_link.sourceFid = *fid;
        inp->coda_link.destFid = *dirfid;
        inp->coda_link.tname = offset;

        /* make sure strings are null terminated */
        memcpy((char *)(inp) + offset, name, len);
        *((char *)inp + offset + len) = '\0';

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);

	CODA_FREE(inp, insize);
        return error;
}

int venus_symlink(struct super_block *sb, struct CodaFid *fid,
		     const char *name, int len,
		     const char *symname, int symlen)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;
        int offset, s;

        offset = INSIZE(symlink);
	insize = max_t(unsigned int, offset + len + symlen + 8, OUTSIZE(symlink));
	UPARG(CODA_SYMLINK);

        /*        inp->coda_symlink.attr = *tva; XXXXXX */
        inp->coda_symlink.VFid = *fid;

	/* Round up to word boundary and null terminate */
        inp->coda_symlink.srcname = offset;
        s = ( symlen  & ~0x3 ) + 4;
        memcpy((char *)(inp) + offset, symname, symlen);
        *((char *)inp + offset + symlen) = '\0';

	/* Round up to word boundary and null terminate */
        offset += s;
        inp->coda_symlink.tname = offset;
        s = (len & ~0x3) + 4;
        memcpy((char *)(inp) + offset, name, len);
        *((char *)inp + offset + len) = '\0';

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);

	CODA_FREE(inp, insize);
        return error;
}

int venus_fsync(struct super_block *sb, struct CodaFid *fid)
{
        union inputArgs *inp;
        union outputArgs *outp;
	int insize, outsize, error;

	insize=SIZE(fsync);
	UPARG(CODA_FSYNC);

	inp->coda_fsync.VFid = *fid;
	error = coda_upcall(coda_vcp(sb), sizeof(union inputArgs),
			    &outsize, inp);

	CODA_FREE(inp, insize);
	return error;
}

int venus_access(struct super_block *sb, struct CodaFid *fid, int mask)
{
        union inputArgs *inp;
        union outputArgs *outp;
	int insize, outsize, error;

	insize = SIZE(access);
	UPARG(CODA_ACCESS);

        inp->coda_access.VFid = *fid;
        inp->coda_access.flags = mask;

	error = coda_upcall(coda_vcp(sb), insize, &outsize, inp);

	CODA_FREE(inp, insize);
	return error;
}


int venus_pioctl(struct super_block *sb, struct CodaFid *fid,
		 unsigned int cmd, struct PioctlData *data)
{
        union inputArgs *inp;
        union outputArgs *outp;
	int insize, outsize, error;
	int iocsize;

	insize = VC_MAXMSGSIZE;
	UPARG(CODA_IOCTL);

        /* build packet for Venus */
        if (data->vi.in_size > VC_MAXDATASIZE) {
		error = -EINVAL;
		goto exit;
        }

        if (data->vi.out_size > VC_MAXDATASIZE) {
		error = -EINVAL;
		goto exit;
	}

        inp->coda_ioctl.VFid = *fid;

        /* the cmd field was mutated by increasing its size field to
         * reflect the path and follow args. We need to subtract that
         * out before sending the command to Venus.  */
        inp->coda_ioctl.cmd = (cmd & ~(PIOCPARM_MASK << 16));
        iocsize = ((cmd >> 16) & PIOCPARM_MASK) - sizeof(char *) - sizeof(int);
        inp->coda_ioctl.cmd |= (iocsize & PIOCPARM_MASK) <<	16;

        /* in->coda_ioctl.rwflag = flag; */
        inp->coda_ioctl.len = data->vi.in_size;
        inp->coda_ioctl.data = (char *)(INSIZE(ioctl));

        /* get the data out of user space */
	if (copy_from_user((char *)inp + (long)inp->coda_ioctl.data,
			   data->vi.in, data->vi.in_size)) {
		error = -EINVAL;
	        goto exit;
	}

	error = coda_upcall(coda_vcp(sb), SIZE(ioctl) + data->vi.in_size,
			    &outsize, inp);

        if (error) {
		pr_warn("%s: Venus returns: %d for %s\n",
			__func__, error, coda_f2s(fid));
		goto exit;
	}

	if (outsize < (long)outp->coda_ioctl.data + outp->coda_ioctl.len) {
		error = -EINVAL;
		goto exit;
	}

	/* Copy out the OUT buffer. */
        if (outp->coda_ioctl.len > data->vi.out_size) {
		error = -EINVAL;
		goto exit;
        }

	/* Copy out the OUT buffer. */
	if (copy_to_user(data->vi.out,
			 (char *)outp + (long)outp->coda_ioctl.data,
			 outp->coda_ioctl.len)) {
		error = -EFAULT;
		goto exit;
	}

 exit:
	CODA_FREE(inp, insize);
	return error;
}

int venus_statfs(struct dentry *dentry, struct kstatfs *sfs)
{
        union inputArgs *inp;
        union outputArgs *outp;
        int insize, outsize, error;

	insize = max_t(unsigned int, INSIZE(statfs), OUTSIZE(statfs));
	UPARG(CODA_STATFS);

	error = coda_upcall(coda_vcp(dentry->d_sb), insize, &outsize, inp);
	if (!error) {
		sfs->f_blocks = outp->coda_statfs.stat.f_blocks;
		sfs->f_bfree  = outp->coda_statfs.stat.f_bfree;
		sfs->f_bavail = outp->coda_statfs.stat.f_bavail;
		sfs->f_files  = outp->coda_statfs.stat.f_files;
		sfs->f_ffree  = outp->coda_statfs.stat.f_ffree;
	}

        CODA_FREE(inp, insize);
        return error;
}

/*
 * coda_upcall and coda_downcall routines.
 */
static void coda_block_signals(sigset_t *old)
{
	spin_lock_irq(&current->sighand->siglock);
	*old = current->blocked;

	sigfillset(&current->blocked);
	sigdelset(&current->blocked, SIGKILL);
	sigdelset(&current->blocked, SIGSTOP);
	sigdelset(&current->blocked, SIGINT);

	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}

static void coda_unblock_signals(sigset_t *old)
{
	spin_lock_irq(&current->sighand->siglock);
	current->blocked = *old;
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}

/* Don't allow signals to interrupt the following upcalls before venus
 * has seen them,
 * - CODA_CLOSE or CODA_RELEASE upcall  (to avoid reference count problems)
 * - CODA_STORE				(to avoid data loss)
 */
#define CODA_INTERRUPTIBLE(r) (!coda_hard && \
			       (((r)->uc_opcode != CODA_CLOSE && \
				 (r)->uc_opcode != CODA_STORE && \
				 (r)->uc_opcode != CODA_RELEASE) || \
				(r)->uc_flags & CODA_REQ_READ))

static inline void coda_waitfor_upcall(struct venus_comm *vcp,
				       struct upc_req *req)
{
	DECLARE_WAITQUEUE(wait, current);
	unsigned long timeout = jiffies + coda_timeout * HZ;
	sigset_t old;
	int blocked;

	coda_block_signals(&old);
	blocked = 1;

	add_wait_queue(&req->uc_sleep, &wait);
	for (;;) {
		if (CODA_INTERRUPTIBLE(req))
			set_current_state(TASK_INTERRUPTIBLE);
		else
			set_current_state(TASK_UNINTERRUPTIBLE);

		/* got a reply */
		if (req->uc_flags & (CODA_REQ_WRITE | CODA_REQ_ABORT))
			break;

		if (blocked && time_after(jiffies, timeout) &&
		    CODA_INTERRUPTIBLE(req))
		{
			coda_unblock_signals(&old);
			blocked = 0;
		}

		if (signal_pending(current)) {
			list_del(&req->uc_chain);
			break;
		}

		mutex_unlock(&vcp->vc_mutex);
		if (blocked)
			schedule_timeout(HZ);
		else
			schedule();
		mutex_lock(&vcp->vc_mutex);
	}
	if (blocked)
		coda_unblock_signals(&old);

	remove_wait_queue(&req->uc_sleep, &wait);
	set_current_state(TASK_RUNNING);
}


/*
 * coda_upcall will return an error in the case of
 * failed communication with Venus _or_ will peek at Venus
 * reply and return Venus' error.
 *
 * As venus has 2 types of errors, normal errors (positive) and internal
 * errors (negative), normal errors are negated, while internal errors
 * are all mapped to -EINTR, while showing a nice warning message. (jh)
 */
static int coda_upcall(struct venus_comm *vcp,
		       int inSize, int *outSize,
		       union inputArgs *buffer)
{
	union outputArgs *out;
	union inputArgs *sig_inputArgs;
	struct upc_req *req = NULL, *sig_req;
	int error;

	mutex_lock(&vcp->vc_mutex);

	if (!vcp->vc_inuse) {
		pr_notice("Venus dead, not sending upcall\n");
		error = -ENXIO;
		goto exit;
	}

	/* Format the request message. */
	req = kmalloc(sizeof(struct upc_req), GFP_KERNEL);
	if (!req) {
		error = -ENOMEM;
		goto exit;
	}

	req->uc_data = (void *)buffer;
	req->uc_flags = 0;
	req->uc_inSize = inSize;
	req->uc_outSize = *outSize ? *outSize : inSize;
	req->uc_opcode = ((union inputArgs *)buffer)->ih.opcode;
	req->uc_unique = ++vcp->vc_seq;
	init_waitqueue_head(&req->uc_sleep);

	/* Fill in the common input args. */
	((union inputArgs *)buffer)->ih.unique = req->uc_unique;

	/* Append msg to pending queue and poke Venus. */
	list_add_tail(&req->uc_chain, &vcp->vc_pending);

	wake_up_interruptible(&vcp->vc_waitq);
	/* We can be interrupted while we wait for Venus to process
	 * our request.  If the interrupt occurs before Venus has read
	 * the request, we dequeue and return. If it occurs after the
	 * read but before the reply, we dequeue, send a signal
	 * message, and return. If it occurs after the reply we ignore
	 * it. In no case do we want to restart the syscall.  If it
	 * was interrupted by a venus shutdown (psdev_close), return
	 * ENODEV.  */

	/* Go to sleep.  Wake up on signals only after the timeout. */
	coda_waitfor_upcall(vcp, req);

	/* Op went through, interrupt or not... */
	if (req->uc_flags & CODA_REQ_WRITE) {
		out = (union outputArgs *)req->uc_data;
		/* here we map positive Venus errors to kernel errors */
		error = -out->oh.result;
		*outSize = req->uc_outSize;
		goto exit;
	}

	error = -EINTR;
	if ((req->uc_flags & CODA_REQ_ABORT) || !signal_pending(current)) {
		pr_warn("Unexpected interruption.\n");
		goto exit;
	}

	/* Interrupted before venus read it. */
	if (!(req->uc_flags & CODA_REQ_READ))
		goto exit;

	/* Venus saw the upcall, make sure we can send interrupt signal */
	if (!vcp->vc_inuse) {
		pr_info("Venus dead, not sending signal.\n");
		goto exit;
	}

	error = -ENOMEM;
	sig_req = kmalloc(sizeof(struct upc_req), GFP_KERNEL);
	if (!sig_req) goto exit;

	CODA_ALLOC((sig_req->uc_data), char *, sizeof(struct coda_in_hdr));
	if (!sig_req->uc_data) {
		kfree(sig_req);
		goto exit;
	}

	error = -EINTR;
	sig_inputArgs = (union inputArgs *)sig_req->uc_data;
	sig_inputArgs->ih.opcode = CODA_SIGNAL;
	sig_inputArgs->ih.unique = req->uc_unique;

	sig_req->uc_flags = CODA_REQ_ASYNC;
	sig_req->uc_opcode = sig_inputArgs->ih.opcode;
	sig_req->uc_unique = sig_inputArgs->ih.unique;
	sig_req->uc_inSize = sizeof(struct coda_in_hdr);
	sig_req->uc_outSize = sizeof(struct coda_in_hdr);

	/* insert at head of queue! */
	list_add(&(sig_req->uc_chain), &vcp->vc_pending);
	wake_up_interruptible(&vcp->vc_waitq);

exit:
	kfree(req);
	mutex_unlock(&vcp->vc_mutex);
	return error;
}

/*
    The statements below are part of the Coda opportunistic
    programming -- taken from the Mach/BSD kernel code for Coda.
    You don't get correct semantics by stating what needs to be
    done without guaranteeing the invariants needed for it to happen.
    When will be have time to find out what exactly is going on?  (pjb)
*/


/*
 * There are 7 cases where cache invalidations occur.  The semantics
 *  of each is listed here:
 *
 * CODA_FLUSH     -- flush all entries from the name cache and the cnode cache.
 * CODA_PURGEUSER -- flush all entries from the name cache for a specific user
 *                  This call is a result of token expiration.
 *
 * The next arise as the result of callbacks on a file or directory.
 * CODA_ZAPFILE   -- flush the cached attributes for a file.

 * CODA_ZAPDIR    -- flush the attributes for the dir and
 *                  force a new lookup for all the children
                    of this dir.

 *
 * The next is a result of Venus detecting an inconsistent file.
 * CODA_PURGEFID  -- flush the attribute for the file
 *                  purge it and its children from the dcache
 *
 * The last  allows Venus to replace local fids with global ones
 * during reintegration.
 *
 * CODA_REPLACE -- replace one CodaFid with another throughout the name cache */

int coda_downcall(struct venus_comm *vcp, int opcode, union outputArgs *out)
{
	struct inode *inode = NULL;
	struct CodaFid *fid = NULL, *newfid;
	struct super_block *sb;

	/* Handle invalidation requests. */
	mutex_lock(&vcp->vc_mutex);
	sb = vcp->vc_sb;
	if (!sb || !sb->s_root)
		goto unlock_out;

	switch (opcode) {
	case CODA_FLUSH:
		coda_cache_clear_all(sb);
		shrink_dcache_sb(sb);
		if (sb->s_root->d_inode)
			coda_flag_inode(sb->s_root->d_inode, C_FLUSH);
		break;

	case CODA_PURGEUSER:
		coda_cache_clear_all(sb);
		break;

	case CODA_ZAPDIR:
		fid = &out->coda_zapdir.CodaFid;
		break;

	case CODA_ZAPFILE:
		fid = &out->coda_zapfile.CodaFid;
		break;

	case CODA_PURGEFID:
		fid = &out->coda_purgefid.CodaFid;
		break;

	case CODA_REPLACE:
		fid = &out->coda_replace.OldFid;
		break;
	}
	if (fid)
		inode = coda_fid_to_inode(fid, sb);

unlock_out:
	mutex_unlock(&vcp->vc_mutex);

	if (!inode)
		return 0;

	switch (opcode) {
	case CODA_ZAPDIR:
		coda_flag_inode_children(inode, C_PURGE);
		coda_flag_inode(inode, C_VATTR);
		break;

	case CODA_ZAPFILE:
		coda_flag_inode(inode, C_VATTR);
		break;

	case CODA_PURGEFID:
		coda_flag_inode_children(inode, C_PURGE);

		/* catch the dentries later if some are still busy */
		coda_flag_inode(inode, C_PURGE);
		d_prune_aliases(inode);
		break;

	case CODA_REPLACE:
		newfid = &out->coda_replace.NewFid;
		coda_replace_fid(inode, fid, newfid);
		break;
	}
	iput(inode);
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/coda/upcall.c */
/************************************************************/
/*
 * Inode operations for Coda filesystem
 * Original version: (C) 1996 P. Braam and M. Callahan
 * Rewritten for Linux 2.1. (C) 1997 Carnegie Mellon University
 *
 * Carnegie Mellon encourages users to contribute improvements to
 * the Coda project. Contact Peter Braam (coda@cs.cmu.edu).
 */

// #include <linux/types.h>
// #include <linux/kernel.h>
// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
// #include <linux/uaccess.h>
// #include <linux/string.h>

// #include <linux/coda.h>
// #include <linux/coda_psdev.h>
// #include "coda_linux.h"

/* initialize the debugging variables */
int coda_fake_statfs;

/* print a fid */
char * coda_f2s(struct CodaFid *f)
{
	static char s[60];

 	sprintf(s, "(%08x.%08x.%08x.%08x)", f->opaque[0], f->opaque[1], f->opaque[2], f->opaque[3]);

	return s;
}

/* recognize special .CONTROL name */
int coda_iscontrol(const char *name, size_t length)
{
	return ((CODA_CONTROLLEN == length) &&
                (strncmp(name, CODA_CONTROL, CODA_CONTROLLEN) == 0));
}

/* recognize /coda inode */
int coda_isroot(struct inode *i)
{
    return ( i->i_sb->s_root->d_inode == i );
}

unsigned short coda_flags_to_cflags(unsigned short flags)
{
	unsigned short coda_flags = 0;

	if ((flags & O_ACCMODE) == O_RDONLY)
		coda_flags |= C_O_READ;

	if ((flags & O_ACCMODE) == O_RDWR)
		coda_flags |= C_O_READ | C_O_WRITE;

	if ((flags & O_ACCMODE) == O_WRONLY)
		coda_flags |= C_O_WRITE;

	if (flags & O_TRUNC)
		coda_flags |= C_O_TRUNC;

	if (flags & O_CREAT)
		coda_flags |= C_O_CREAT;

	if (flags & O_EXCL)
		coda_flags |= C_O_EXCL;

	return coda_flags;
}


/* utility functions below */
void coda_vattr_to_iattr(struct inode *inode, struct coda_vattr *attr)
{
        int inode_type;
        /* inode's i_flags, i_ino are set by iget
           XXX: is this all we need ??
           */
        switch (attr->va_type) {
        case C_VNON:
                inode_type  = 0;
                break;
        case C_VREG:
                inode_type = S_IFREG;
                break;
        case C_VDIR:
                inode_type = S_IFDIR;
                break;
        case C_VLNK:
                inode_type = S_IFLNK;
                break;
        default:
                inode_type = 0;
        }
	inode->i_mode |= inode_type;

	if (attr->va_mode != (u_short) -1)
	        inode->i_mode = attr->va_mode | inode_type;
        if (attr->va_uid != -1)
	        inode->i_uid = make_kuid(&init_user_ns, (uid_t) attr->va_uid);
        if (attr->va_gid != -1)
	        inode->i_gid = make_kgid(&init_user_ns, (gid_t) attr->va_gid);
	if (attr->va_nlink != -1)
		set_nlink(inode, attr->va_nlink);
	if (attr->va_size != -1)
	        inode->i_size = attr->va_size;
	if (attr->va_size != -1)
		inode->i_blocks = (attr->va_size + 511) >> 9;
	if (attr->va_atime.tv_sec != -1)
	        inode->i_atime = attr->va_atime;
	if (attr->va_mtime.tv_sec != -1)
	        inode->i_mtime = attr->va_mtime;
        if (attr->va_ctime.tv_sec != -1)
	        inode->i_ctime = attr->va_ctime;
}


/*
 * BSD sets attributes that need not be modified to -1.
 * Linux uses the valid field to indicate what should be
 * looked at.  The BSD type field needs to be deduced from linux
 * mode.
 * So we have to do some translations here.
 */

void coda_iattr_to_vattr(struct iattr *iattr, struct coda_vattr *vattr)
{
        unsigned int valid;

        /* clean out */
	vattr->va_mode = -1;
        vattr->va_uid = (vuid_t) -1;
        vattr->va_gid = (vgid_t) -1;
        vattr->va_size = (off_t) -1;
	vattr->va_atime.tv_sec = (time_t) -1;
	vattr->va_atime.tv_nsec =  (time_t) -1;
        vattr->va_mtime.tv_sec = (time_t) -1;
        vattr->va_mtime.tv_nsec = (time_t) -1;
	vattr->va_ctime.tv_sec = (time_t) -1;
	vattr->va_ctime.tv_nsec = (time_t) -1;
        vattr->va_type = C_VNON;
	vattr->va_fileid = -1;
	vattr->va_gen = -1;
	vattr->va_bytes = -1;
	vattr->va_nlink = -1;
	vattr->va_blocksize = -1;
	vattr->va_rdev = -1;
        vattr->va_flags = 0;

        /* determine the type */
#if 0
        mode = iattr->ia_mode;
                if ( S_ISDIR(mode) ) {
                vattr->va_type = C_VDIR;
        } else if ( S_ISREG(mode) ) {
                vattr->va_type = C_VREG;
        } else if ( S_ISLNK(mode) ) {
                vattr->va_type = C_VLNK;
        } else {
                /* don't do others */
                vattr->va_type = C_VNON;
        }
#endif

        /* set those vattrs that need change */
        valid = iattr->ia_valid;
        if ( valid & ATTR_MODE ) {
                vattr->va_mode = iattr->ia_mode;
	}
        if ( valid & ATTR_UID ) {
                vattr->va_uid = (vuid_t) from_kuid(&init_user_ns, iattr->ia_uid);
	}
        if ( valid & ATTR_GID ) {
                vattr->va_gid = (vgid_t) from_kgid(&init_user_ns, iattr->ia_gid);
	}
        if ( valid & ATTR_SIZE ) {
                vattr->va_size = iattr->ia_size;
	}
        if ( valid & ATTR_ATIME ) {
                vattr->va_atime = iattr->ia_atime;
	}
        if ( valid & ATTR_MTIME ) {
                vattr->va_mtime = iattr->ia_mtime;
	}
        if ( valid & ATTR_CTIME ) {
                vattr->va_ctime = iattr->ia_ctime;
	}
}
/************************************************************/
/* ../linux-3.17/fs/coda/coda_linux.c */
/************************************************************/
/*
 * Symlink inode operations for Coda filesystem
 * Original version: (C) 1996 P. Braam and M. Callahan
 * Rewritten for Linux 2.1. (C) 1997 Carnegie Mellon University
 *
 * Carnegie Mellon encourages users to contribute improvements to
 * the Coda project. Contact Peter Braam (coda@cs.cmu.edu).
 */

// #include <linux/types.h>
// #include <linux/kernel.h>
// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
#include <linux/pagemap.h>

// #include <linux/coda.h>
// #include <linux/coda_psdev.h>

// #include "coda_linux.h"

static int coda_symlink_filler(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	int error;
	struct coda_inode_info *cii;
	unsigned int len = PAGE_SIZE;
	char *p = kmap(page);

	cii = ITOC(inode);

	error = venus_readlink(inode->i_sb, &cii->c_fid, p, &len);
	if (error)
		goto fail;
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);
	return 0;

fail:
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	return error;
}

const struct address_space_operations coda_symlink_aops = {
	.readpage	= coda_symlink_filler,
};
/************************************************************/
/* ../linux-3.17/fs/coda/symlink.c */
/************************************************************/
/*
 * Pioctl operations for Coda.
 * Original version: (C) 1996 Peter Braam
 * Rewritten for Linux 2.1: (C) 1997 Carnegie Mellon University
 *
 * Carnegie Mellon encourages users of this code to contribute improvements
 * to the Coda project. Contact Peter Braam <coda@cs.cmu.edu>.
 */

// #include <linux/types.h>
// #include <linux/kernel.h>
// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
// #include <linux/string.h>
// #include <linux/namei.h>
// #include <linux/module.h>
// #include <linux/uaccess.h>

// #include <linux/coda.h>
// #include <linux/coda_psdev.h>

// #include "coda_linux.h"

/* pioctl ops */
static int coda_ioctl_permission(struct inode *inode, int mask);
static long coda_pioctl(struct file *filp, unsigned int cmd,
			unsigned long user_data);

/* exported from this file */
const struct inode_operations coda_ioctl_inode_operations = {
	.permission	= coda_ioctl_permission,
	.setattr	= coda_setattr,
};

const struct file_operations coda_ioctl_operations = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= coda_pioctl,
	.llseek		= noop_llseek,
};

/* the coda pioctl inode ops */
static int coda_ioctl_permission(struct inode *inode, int mask)
{
	return (mask & MAY_EXEC) ? -EACCES : 0;
}

static long coda_pioctl(struct file *filp, unsigned int cmd,
			unsigned long user_data)
{
	struct path path;
	int error;
	struct PioctlData data;
	struct inode *inode = file_inode(filp);
	struct inode *target_inode = NULL;
	struct coda_inode_info *cnp;

	/* get the Pioctl data arguments from user space */
	if (copy_from_user(&data, (void __user *)user_data, sizeof(data)))
		return -EINVAL;

	/*
	 * Look up the pathname. Note that the pathname is in
	 * user memory, and namei takes care of this
	 */
	if (data.follow)
		error = user_path(data.path, &path);
	else
		error = user_lpath(data.path, &path);

	if (error)
		return error;

	target_inode = path.dentry->d_inode;

	/* return if it is not a Coda inode */
	if (target_inode->i_sb != inode->i_sb) {
		error = -EINVAL;
		goto out;
	}

	/* now proceed to make the upcall */
	cnp = ITOC(target_inode);

	error = venus_pioctl(inode->i_sb, &(cnp->c_fid), cmd, &data);
out:
	path_put(&path);
	return error;
}
/************************************************************/
/* ../linux-3.17/fs/coda/pioctl.c */
/************************************************************/
/*
 * Sysctl operations for Coda filesystem
 * Original version: (C) 1996 P. Braam and M. Callahan
 * Rewritten for Linux 2.1. (C) 1997 Carnegie Mellon University
 *
 * Carnegie Mellon encourages users to contribute improvements to
 * the Coda project. Contact Peter Braam (coda@cs.cmu.edu).
 */

#include <linux/sysctl.h>

// #include "coda_int.h"

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *fs_table_header;

static struct ctl_table coda_table[] = {
	{
		.procname	= "timeout",
		.data		= &coda_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "hard",
		.data		= &coda_hard,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "fake_statfs",
		.data		= &coda_fake_statfs,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= proc_dointvec
	},
	{}
};

static struct ctl_table fs_table[] = {
	{
		.procname	= "coda",
		.mode		= 0555,
		.child		= coda_table
	},
	{}
};

void coda_sysctl_init(void)
{
	if ( !fs_table_header )
		fs_table_header = register_sysctl_table(fs_table);
}

void coda_sysctl_clean(void)
{
	if ( fs_table_header ) {
		unregister_sysctl_table(fs_table_header);
		fs_table_header = NULL;
	}
}

#else
void coda_sysctl_init(void)
{
}

void coda_sysctl_clean(void)
{
}
#endif
/************************************************************/
/* ../linux-3.17/fs/coda/sysctl.c */
/************************************************************/
