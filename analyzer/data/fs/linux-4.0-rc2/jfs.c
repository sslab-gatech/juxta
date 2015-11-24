/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *   Portions Copyright (C) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/completion.h>
#include <linux/vfs.h>
#include <linux/quotaops.h>
#include <linux/mount.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/posix_acl.h>
#include <linux/buffer_head.h>
#include <linux/exportfs.h>
#include <linux/crc32.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/seq_file.h>
#include <linux/blkdev.h>
#include "../../inc/__fss.h"

#include "jfs_incore.h"
#include "jfs_filsys.h"
#include "jfs_inode.h"
#include "jfs_metapage.h"
#include "jfs_superblock.h"
#include "jfs_dmap.h"
#include "jfs_imap.h"
#include "jfs_acl.h"
#include "jfs_debug.h"
#include "jfs_xattr.h"
#include "../../inc/__fss.h"

MODULE_DESCRIPTION("The Journaled Filesystem (JFS)");
MODULE_AUTHOR("Steve Best/Dave Kleikamp/Barry Arndt, IBM");
MODULE_LICENSE("GPL");

static struct kmem_cache *jfs_inode_cachep;

static const struct super_operations jfs_super_operations;
static const struct export_operations jfs_export_operations;
static struct file_system_type jfs_fs_type;

#define MAX_COMMIT_THREADS 64
static int commit_threads;
module_param(commit_threads, int, 0);
MODULE_PARM_DESC(commit_threads, "Number of commit threads");

static struct task_struct *jfsCommitThread[MAX_COMMIT_THREADS];
struct task_struct *jfsIOthread;
struct task_struct *jfsSyncThread;

#ifdef CONFIG_JFS_DEBUG
int jfsloglevel = JFS_LOGLEVEL_WARN;
module_param(jfsloglevel, int, 0644);
MODULE_PARM_DESC(jfsloglevel, "Specify JFS loglevel (0, 1 or 2)");
#endif

static void jfs_handle_error(struct super_block *sb)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);

	if (sb->s_flags & MS_RDONLY)
		return;

	updateSuper(sb, FM_DIRTY);

	if (sbi->flag & JFS_ERR_PANIC)
		panic("JFS (device %s): panic forced after error\n",
			sb->s_id);
	else if (sbi->flag & JFS_ERR_REMOUNT_RO) {
		jfs_err("ERROR: (device %s): remounting filesystem as read-only\n",
			sb->s_id);
		sb->s_flags |= MS_RDONLY;
	}

	/* nothing is done for continue beyond marking the superblock dirty */
}

void jfs_error(struct super_block *sb, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	pr_err("ERROR: (device %s): %pf: %pV\n",
	       sb->s_id, __builtin_return_address(0), &vaf);

	va_end(args);

	jfs_handle_error(sb);
}

static struct inode *jfs_alloc_inode(struct super_block *sb)
{
	struct jfs_inode_info *jfs_inode;

	jfs_inode = kmem_cache_alloc(jfs_inode_cachep, GFP_NOFS);
	if (!jfs_inode)
		return NULL;
#ifdef CONFIG_QUOTA
	memset(&jfs_inode->i_dquot, 0, sizeof(jfs_inode->i_dquot));
#endif
	return &jfs_inode->vfs_inode;
}

static void jfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct jfs_inode_info *ji = JFS_IP(inode);
	kmem_cache_free(jfs_inode_cachep, ji);
}

static void jfs_destroy_inode(struct inode *inode)
{
	struct jfs_inode_info *ji = JFS_IP(inode);

	BUG_ON(!list_empty(&ji->anon_inode_list));

	spin_lock_irq(&ji->ag_lock);
	if (ji->active_ag != -1) {
		struct bmap *bmap = JFS_SBI(inode->i_sb)->bmap;
		atomic_dec(&bmap->db_active[ji->active_ag]);
		ji->active_ag = -1;
	}
	spin_unlock_irq(&ji->ag_lock);
	call_rcu(&inode->i_rcu, jfs_i_callback);
}

static int jfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct jfs_sb_info *sbi = JFS_SBI(dentry->d_sb);
	s64 maxinodes;
	struct inomap *imap = JFS_IP(sbi->ipimap)->i_imap;

	jfs_info("In jfs_statfs");
	buf->f_type = JFS_SUPER_MAGIC;
	buf->f_bsize = sbi->bsize;
	buf->f_blocks = sbi->bmap->db_mapsize;
	buf->f_bfree = sbi->bmap->db_nfree;
	buf->f_bavail = sbi->bmap->db_nfree;
	/*
	 * If we really return the number of allocated & free inodes, some
	 * applications will fail because they won't see enough free inodes.
	 * We'll try to calculate some guess as to how many inodes we can
	 * really allocate
	 *
	 * buf->f_files = atomic_read(&imap->im_numinos);
	 * buf->f_ffree = atomic_read(&imap->im_numfree);
	 */
	maxinodes = min((s64) atomic_read(&imap->im_numinos) +
			((sbi->bmap->db_nfree >> imap->im_l2nbperiext)
			 << L2INOSPEREXT), (s64) 0xffffffffLL);
	buf->f_files = maxinodes;
	buf->f_ffree = maxinodes - (atomic_read(&imap->im_numinos) -
				    atomic_read(&imap->im_numfree));
	buf->f_fsid.val[0] = (u32)crc32_le(0, sbi->uuid, sizeof(sbi->uuid)/2);
	buf->f_fsid.val[1] = (u32)crc32_le(0, sbi->uuid + sizeof(sbi->uuid)/2,
					sizeof(sbi->uuid)/2);

	buf->f_namelen = JFS_NAME_MAX;
	return 0;
}

static void jfs_put_super(struct super_block *sb)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	int rc;

	jfs_info("In jfs_put_super");

	dquot_disable(sb, -1, DQUOT_USAGE_ENABLED | DQUOT_LIMITS_ENABLED);

	rc = jfs_umount(sb);
	if (rc)
		jfs_err("jfs_umount failed with return code %d", rc);

	unload_nls(sbi->nls_tab);

	truncate_inode_pages(sbi->direct_inode->i_mapping, 0);
	iput(sbi->direct_inode);

	kfree(sbi);
}

enum {
	Opt_integrity, Opt_nointegrity, Opt_iocharset, Opt_resize,
	Opt_resize_nosize, Opt_errors, Opt_ignore, Opt_err, Opt_quota,
	Opt_usrquota, Opt_grpquota, Opt_uid, Opt_gid, Opt_umask,
	Opt_discard, Opt_nodiscard, Opt_discard_minblk
};

static const match_table_t tokens = {
	{Opt_integrity, "integrity"},
	{Opt_nointegrity, "nointegrity"},
	{Opt_iocharset, "iocharset=%s"},
	{Opt_resize, "resize=%u"},
	{Opt_resize_nosize, "resize"},
	{Opt_errors, "errors=%s"},
	{Opt_ignore, "noquota"},
	{Opt_ignore, "quota"},
	{Opt_usrquota, "usrquota"},
	{Opt_grpquota, "grpquota"},
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_umask, "umask=%u"},
	{Opt_discard, "discard"},
	{Opt_nodiscard, "nodiscard"},
	{Opt_discard_minblk, "discard=%u"},
	{Opt_err, NULL}
};

static int parse_options(char *options, struct super_block *sb, s64 *newLVSize,
			 int *flag)
{
	void *nls_map = (void *)-1;	/* -1: no change;  NULL: none */
	char *p;
	struct jfs_sb_info *sbi = JFS_SBI(sb);

	*newLVSize = 0;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_integrity:
			*flag &= ~JFS_NOINTEGRITY;
			break;
		case Opt_nointegrity:
			*flag |= JFS_NOINTEGRITY;
			break;
		case Opt_ignore:
			/* Silently ignore the quota options */
			/* Don't do anything ;-) */
			break;
		case Opt_iocharset:
			if (nls_map && nls_map != (void *) -1)
				unload_nls(nls_map);
			if (!strcmp(args[0].from, "none"))
				nls_map = NULL;
			else {
				nls_map = load_nls(args[0].from);
				if (!nls_map) {
					pr_err("JFS: charset not found\n");
					goto cleanup;
				}
			}
			break;
		case Opt_resize:
		{
			char *resize = args[0].from;
			int rc = kstrtoll(resize, 0, newLVSize);

			if (rc)
				goto cleanup;
			break;
		}
		case Opt_resize_nosize:
		{
			*newLVSize = sb->s_bdev->bd_inode->i_size >>
				sb->s_blocksize_bits;
			if (*newLVSize == 0)
				pr_err("JFS: Cannot determine volume size\n");
			break;
		}
		case Opt_errors:
		{
			char *errors = args[0].from;
			if (!errors || !*errors)
				goto cleanup;
			if (!strcmp(errors, "continue")) {
				*flag &= ~JFS_ERR_REMOUNT_RO;
				*flag &= ~JFS_ERR_PANIC;
				*flag |= JFS_ERR_CONTINUE;
			} else if (!strcmp(errors, "remount-ro")) {
				*flag &= ~JFS_ERR_CONTINUE;
				*flag &= ~JFS_ERR_PANIC;
				*flag |= JFS_ERR_REMOUNT_RO;
			} else if (!strcmp(errors, "panic")) {
				*flag &= ~JFS_ERR_CONTINUE;
				*flag &= ~JFS_ERR_REMOUNT_RO;
				*flag |= JFS_ERR_PANIC;
			} else {
				pr_err("JFS: %s is an invalid error handler\n",
				       errors);
				goto cleanup;
			}
			break;
		}

#ifdef CONFIG_QUOTA
		case Opt_quota:
		case Opt_usrquota:
			*flag |= JFS_USRQUOTA;
			break;
		case Opt_grpquota:
			*flag |= JFS_GRPQUOTA;
			break;
#else
		case Opt_usrquota:
		case Opt_grpquota:
		case Opt_quota:
			pr_err("JFS: quota operations not supported\n");
			break;
#endif
		case Opt_uid:
		{
			char *uid = args[0].from;
			uid_t val;
			int rc = kstrtouint(uid, 0, &val);

			if (rc)
				goto cleanup;
			sbi->uid = make_kuid(current_user_ns(), val);
			if (!uid_valid(sbi->uid))
				goto cleanup;
			break;
		}

		case Opt_gid:
		{
			char *gid = args[0].from;
			gid_t val;
			int rc = kstrtouint(gid, 0, &val);

			if (rc)
				goto cleanup;
			sbi->gid = make_kgid(current_user_ns(), val);
			if (!gid_valid(sbi->gid))
				goto cleanup;
			break;
		}

		case Opt_umask:
		{
			char *umask = args[0].from;
			int rc = kstrtouint(umask, 8, &sbi->umask);

			if (rc)
				goto cleanup;
			if (sbi->umask & ~0777) {
				pr_err("JFS: Invalid value of umask\n");
				goto cleanup;
			}
			break;
		}

		case Opt_discard:
		{
			struct request_queue *q = bdev_get_queue(sb->s_bdev);
			/* if set to 1, even copying files will cause
			 * trimming :O
			 * -> user has more control over the online trimming
			 */
			sbi->minblks_trim = 64;
			if (blk_queue_discard(q))
				*flag |= JFS_DISCARD;
			else
				pr_err("JFS: discard option not supported on device\n");
			break;
		}

		case Opt_nodiscard:
			*flag &= ~JFS_DISCARD;
			break;

		case Opt_discard_minblk:
		{
			struct request_queue *q = bdev_get_queue(sb->s_bdev);
			char *minblks_trim = args[0].from;
			int rc;
			if (blk_queue_discard(q)) {
				*flag |= JFS_DISCARD;
				rc = kstrtouint(minblks_trim, 0,
						&sbi->minblks_trim);
				if (rc)
					goto cleanup;
			} else
				pr_err("JFS: discard option not supported on device\n");
			break;
		}

		default:
			printk("jfs: Unrecognized mount option \"%s\" or missing value\n",
			       p);
			goto cleanup;
		}
	}

	if (nls_map != (void *) -1) {
		/* Discard old (if remount) */
		unload_nls(sbi->nls_tab);
		sbi->nls_tab = nls_map;
	}
	return 1;

cleanup:
	if (nls_map && nls_map != (void *) -1)
		unload_nls(nls_map);
	return 0;
}

static int jfs_remount(struct super_block *sb, int *flags, char *data)
{
	s64 newLVSize = 0;
	int rc = 0;
	int flag = JFS_SBI(sb)->flag;
	int ret;

	sync_filesystem(sb);
	if (!parse_options(data, sb, &newLVSize, &flag))
		return -EINVAL;

	if (newLVSize) {
		if (sb->s_flags & MS_RDONLY) {
			pr_err("JFS: resize requires volume to be mounted read-write\n");
			return -EROFS;
		}
		rc = jfs_extendfs(sb, newLVSize, 0);
		if (rc)
			return rc;
	}

	if ((sb->s_flags & MS_RDONLY) && !(*flags & MS_RDONLY)) {
		/*
		 * Invalidate any previously read metadata.  fsck may have
		 * changed the on-disk data since we mounted r/o
		 */
		truncate_inode_pages(JFS_SBI(sb)->direct_inode->i_mapping, 0);

		JFS_SBI(sb)->flag = flag;
		ret = jfs_mount_rw(sb, 1);

		/* mark the fs r/w for quota activity */
		sb->s_flags &= ~MS_RDONLY;

		dquot_resume(sb, -1);
		return ret;
	}
	if ((!(sb->s_flags & MS_RDONLY)) && (*flags & MS_RDONLY)) {
		rc = dquot_suspend(sb, -1);
		if (rc < 0)
			return rc;
		rc = jfs_umount_rw(sb);
		JFS_SBI(sb)->flag = flag;
		return rc;
	}
	if ((JFS_SBI(sb)->flag & JFS_NOINTEGRITY) != (flag & JFS_NOINTEGRITY))
		if (!(sb->s_flags & MS_RDONLY)) {
			rc = jfs_umount_rw(sb);
			if (rc)
				return rc;

			JFS_SBI(sb)->flag = flag;
			ret = jfs_mount_rw(sb, 1);
			return ret;
		}
	JFS_SBI(sb)->flag = flag;

	return 0;
}

static int jfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct jfs_sb_info *sbi;
	struct inode *inode;
	int rc;
	s64 newLVSize = 0;
	int flag, ret = -EINVAL;

	jfs_info("In jfs_read_super: s_flags=0x%lx", sb->s_flags);

	if (!new_valid_dev(sb->s_bdev->bd_dev))
		return -EOVERFLOW;

	sbi = kzalloc(sizeof(struct jfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;
	sb->s_max_links = JFS_LINK_MAX;
	sbi->sb = sb;
	sbi->uid = INVALID_UID;
	sbi->gid = INVALID_GID;
	sbi->umask = -1;

	/* initialize the mount flag and determine the default error handler */
	flag = JFS_ERR_REMOUNT_RO;

	if (!parse_options((char *) data, sb, &newLVSize, &flag))
		goto out_kfree;
	sbi->flag = flag;

#ifdef CONFIG_JFS_POSIX_ACL
	sb->s_flags |= MS_POSIXACL;
#endif

	if (newLVSize) {
		pr_err("resize option for remount only\n");
		goto out_kfree;
	}

	/*
	 * Initialize blocksize to 4K.
	 */
	sb_set_blocksize(sb, PSIZE);

	/*
	 * Set method vectors.
	 */
	sb->s_op = &jfs_super_operations;
	sb->s_export_op = &jfs_export_operations;
	sb->s_xattr = jfs_xattr_handlers;
#ifdef CONFIG_QUOTA
	sb->dq_op = &dquot_operations;
	sb->s_qcop = &dquot_quotactl_ops;
	sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP;
#endif

	/*
	 * Initialize direct-mapping inode/address-space
	 */
	inode = new_inode(sb);
	if (inode == NULL) {
		ret = -ENOMEM;
		goto out_unload;
	}
	inode->i_ino = 0;
	inode->i_size = sb->s_bdev->bd_inode->i_size;
	inode->i_mapping->a_ops = &jfs_metapage_aops;
	hlist_add_fake(&inode->i_hash);
	mapping_set_gfp_mask(inode->i_mapping, GFP_NOFS);

	sbi->direct_inode = inode;

	rc = jfs_mount(sb);
	if (rc) {
		if (!silent)
			jfs_err("jfs_mount failed w/return code = %d", rc);
		goto out_mount_failed;
	}
	if (sb->s_flags & MS_RDONLY)
		sbi->log = NULL;
	else {
		rc = jfs_mount_rw(sb, 0);
		if (rc) {
			if (!silent) {
				jfs_err("jfs_mount_rw failed, return code = %d",
					rc);
			}
			goto out_no_rw;
		}
	}

	sb->s_magic = JFS_SUPER_MAGIC;

	if (sbi->mntflag & JFS_OS2)
		sb->s_d_op = &jfs_ci_dentry_operations;

	inode = jfs_iget(sb, ROOT_I);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out_no_rw;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		goto out_no_root;

	/* logical blocks are represented by 40 bits in pxd_t, etc. */
	sb->s_maxbytes = ((u64) sb->s_blocksize) << 40;
#if BITS_PER_LONG == 32
	/*
	 * Page cache is indexed by long.
	 * I would use MAX_LFS_FILESIZE, but it's only half as big
	 */
	sb->s_maxbytes = min(((u64) PAGE_CACHE_SIZE << 32) - 1,
			     (u64)sb->s_maxbytes);
#endif
	sb->s_time_gran = 1;
	return 0;

out_no_root:
	jfs_err("jfs_read_super: get root dentry failed");

out_no_rw:
	rc = jfs_umount(sb);
	if (rc)
		jfs_err("jfs_umount failed with return code %d", rc);
out_mount_failed:
	filemap_write_and_wait(sbi->direct_inode->i_mapping);
	truncate_inode_pages(sbi->direct_inode->i_mapping, 0);
	make_bad_inode(sbi->direct_inode);
	iput(sbi->direct_inode);
	sbi->direct_inode = NULL;
out_unload:
	unload_nls(sbi->nls_tab);
out_kfree:
	kfree(sbi);
	return ret;
}

static int jfs_freeze(struct super_block *sb)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct jfs_log *log = sbi->log;
	int rc = 0;

	if (!(sb->s_flags & MS_RDONLY)) {
		txQuiesce(sb);
		rc = lmLogShutdown(log);
		if (rc) {
			jfs_error(sb, "lmLogShutdown failed\n");

			/* let operations fail rather than hang */
			txResume(sb);

			return rc;
		}
		rc = updateSuper(sb, FM_CLEAN);
		if (rc) {
			jfs_err("jfs_freeze: updateSuper failed\n");
			/*
			 * Don't fail here. Everything succeeded except
			 * marking the superblock clean, so there's really
			 * no harm in leaving it frozen for now.
			 */
		}
	}
	return 0;
}

static int jfs_unfreeze(struct super_block *sb)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct jfs_log *log = sbi->log;
	int rc = 0;

	if (!(sb->s_flags & MS_RDONLY)) {
		rc = updateSuper(sb, FM_MOUNT);
		if (rc) {
			jfs_error(sb, "updateSuper failed\n");
			goto out;
		}
		rc = lmLogInit(log);
		if (rc)
			jfs_error(sb, "lmLogInit failed\n");
out:
		txResume(sb);
	}
	return rc;
}

static struct dentry *jfs_do_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, jfs_fill_super);
}

static int jfs_sync_fs(struct super_block *sb, int wait)
{
	struct jfs_log *log = JFS_SBI(sb)->log;

	/* log == NULL indicates read-only mount */
	if (log) {
		/*
		 * Write quota structures to quota file, sync_blockdev() will
		 * write them to disk later
		 */
		dquot_writeback_dquots(sb, -1);
		jfs_flush_journal(log, wait);
		jfs_syncpt(log, 0);
	}

	return 0;
}

static int jfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct jfs_sb_info *sbi = JFS_SBI(root->d_sb);

	if (uid_valid(sbi->uid))
		seq_printf(seq, ",uid=%d", from_kuid(&init_user_ns, sbi->uid));
	if (gid_valid(sbi->gid))
		seq_printf(seq, ",gid=%d", from_kgid(&init_user_ns, sbi->gid));
	if (sbi->umask != -1)
		seq_printf(seq, ",umask=%03o", sbi->umask);
	if (sbi->flag & JFS_NOINTEGRITY)
		seq_puts(seq, ",nointegrity");
	if (sbi->flag & JFS_DISCARD)
		seq_printf(seq, ",discard=%u", sbi->minblks_trim);
	if (sbi->nls_tab)
		seq_printf(seq, ",iocharset=%s", sbi->nls_tab->charset);
	if (sbi->flag & JFS_ERR_CONTINUE)
		seq_printf(seq, ",errors=continue");
	if (sbi->flag & JFS_ERR_PANIC)
		seq_printf(seq, ",errors=panic");

#ifdef CONFIG_QUOTA
	if (sbi->flag & JFS_USRQUOTA)
		seq_puts(seq, ",usrquota");

	if (sbi->flag & JFS_GRPQUOTA)
		seq_puts(seq, ",grpquota");
#endif

	return 0;
}

#ifdef CONFIG_QUOTA

/* Read data from quotafile - avoid pagecache and such because we cannot afford
 * acquiring the locks... As quota files are never truncated and quota code
 * itself serializes the operations (and no one else should touch the files)
 * we don't have to be afraid of races */
static ssize_t jfs_quota_read(struct super_block *sb, int type, char *data,
			      size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	sector_t blk = off >> sb->s_blocksize_bits;
	int err = 0;
	int offset = off & (sb->s_blocksize - 1);
	int tocopy;
	size_t toread;
	struct buffer_head tmp_bh;
	struct buffer_head *bh;
	loff_t i_size = i_size_read(inode);

	if (off > i_size)
		return 0;
	if (off+len > i_size)
		len = i_size-off;
	toread = len;
	while (toread > 0) {
		tocopy = sb->s_blocksize - offset < toread ?
				sb->s_blocksize - offset : toread;

		tmp_bh.b_state = 0;
		tmp_bh.b_size = 1 << inode->i_blkbits;
		err = jfs_get_block(inode, blk, &tmp_bh, 0);
		if (err)
			return err;
		if (!buffer_mapped(&tmp_bh))	/* A hole? */
			memset(data, 0, tocopy);
		else {
			bh = sb_bread(sb, tmp_bh.b_blocknr);
			if (!bh)
				return -EIO;
			memcpy(data, bh->b_data+offset, tocopy);
			brelse(bh);
		}
		offset = 0;
		toread -= tocopy;
		data += tocopy;
		blk++;
	}
	return len;
}

/* Write to quotafile */
static ssize_t jfs_quota_write(struct super_block *sb, int type,
			       const char *data, size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	sector_t blk = off >> sb->s_blocksize_bits;
	int err = 0;
	int offset = off & (sb->s_blocksize - 1);
	int tocopy;
	size_t towrite = len;
	struct buffer_head tmp_bh;
	struct buffer_head *bh;

	mutex_lock(&inode->i_mutex);
	while (towrite > 0) {
		tocopy = sb->s_blocksize - offset < towrite ?
				sb->s_blocksize - offset : towrite;

		tmp_bh.b_state = 0;
		tmp_bh.b_size = 1 << inode->i_blkbits;
		err = jfs_get_block(inode, blk, &tmp_bh, 1);
		if (err)
			goto out;
		if (offset || tocopy != sb->s_blocksize)
			bh = sb_bread(sb, tmp_bh.b_blocknr);
		else
			bh = sb_getblk(sb, tmp_bh.b_blocknr);
		if (!bh) {
			err = -EIO;
			goto out;
		}
		lock_buffer(bh);
		memcpy(bh->b_data+offset, data, tocopy);
		flush_dcache_page(bh->b_page);
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		unlock_buffer(bh);
		brelse(bh);
		offset = 0;
		towrite -= tocopy;
		data += tocopy;
		blk++;
	}
out:
	if (len == towrite) {
		mutex_unlock(&inode->i_mutex);
		return err;
	}
	if (inode->i_size < off+len-towrite)
		i_size_write(inode, off+len-towrite);
	inode->i_version++;
	inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	mark_inode_dirty(inode);
	mutex_unlock(&inode->i_mutex);
	return len - towrite;
}

static struct dquot **jfs_get_dquots(struct inode *inode)
{
	return JFS_IP(inode)->i_dquot;
}
#endif

static const struct super_operations jfs_super_operations = {
	.alloc_inode	= jfs_alloc_inode,
	.destroy_inode	= jfs_destroy_inode,
	.dirty_inode	= jfs_dirty_inode,
	.write_inode	= jfs_write_inode,
	.evict_inode	= jfs_evict_inode,
	.put_super	= jfs_put_super,
	.sync_fs	= jfs_sync_fs,
	.freeze_fs	= jfs_freeze,
	.unfreeze_fs	= jfs_unfreeze,
	.statfs		= jfs_statfs,
	.remount_fs	= jfs_remount,
	.show_options	= jfs_show_options,
#ifdef CONFIG_QUOTA
	.quota_read	= jfs_quota_read,
	.quota_write	= jfs_quota_write,
	.get_dquots	= jfs_get_dquots,
#endif
};

static const struct export_operations jfs_export_operations = {
	.fh_to_dentry	= jfs_fh_to_dentry,
	.fh_to_parent	= jfs_fh_to_parent,
	.get_parent	= jfs_get_parent,
};

static struct file_system_type jfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "jfs",
	.mount		= jfs_do_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("jfs");

static void init_once_super_c(void *foo)
{
	struct jfs_inode_info *jfs_ip = (struct jfs_inode_info *) foo;

	memset(jfs_ip, 0, sizeof(struct jfs_inode_info));
	INIT_LIST_HEAD(&jfs_ip->anon_inode_list);
	init_rwsem(&jfs_ip->rdwrlock);
	mutex_init(&jfs_ip->commit_mutex);
	init_rwsem(&jfs_ip->xattr_sem);
	spin_lock_init(&jfs_ip->ag_lock);
	jfs_ip->active_ag = -1;
	inode_init_once(&jfs_ip->vfs_inode);
}

static int __init init_jfs_fs(void)
{
	int i;
	int rc;

	jfs_inode_cachep =
	    kmem_cache_create("jfs_ip", sizeof(struct jfs_inode_info), 0,
			    SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD,
			    init_once_super_c);
	if (jfs_inode_cachep == NULL)
		return -ENOMEM;

	/*
	 * Metapage initialization
	 */
	rc = metapage_init();
	if (rc) {
		jfs_err("metapage_init failed w/rc = %d", rc);
		goto free_slab;
	}

	/*
	 * Transaction Manager initialization
	 */
	rc = txInit();
	if (rc) {
		jfs_err("txInit failed w/rc = %d", rc);
		goto free_metapage;
	}

	/*
	 * I/O completion thread (endio)
	 */
	jfsIOthread = kthread_run(jfsIOWait, NULL, "jfsIO");
	if (IS_ERR(jfsIOthread)) {
		rc = PTR_ERR(jfsIOthread);
		jfs_err("init_jfs_fs: fork failed w/rc = %d", rc);
		goto end_txmngr;
	}

	if (commit_threads < 1)
		commit_threads = num_online_cpus();
	if (commit_threads > MAX_COMMIT_THREADS)
		commit_threads = MAX_COMMIT_THREADS;

	for (i = 0; i < commit_threads; i++) {
		jfsCommitThread[i] = kthread_run(jfs_lazycommit, NULL,
						 "jfsCommit");
		if (IS_ERR(jfsCommitThread[i])) {
			rc = PTR_ERR(jfsCommitThread[i]);
			jfs_err("init_jfs_fs: fork failed w/rc = %d", rc);
			commit_threads = i;
			goto kill_committask;
		}
	}

	jfsSyncThread = kthread_run(jfs_sync, NULL, "jfsSync");
	if (IS_ERR(jfsSyncThread)) {
		rc = PTR_ERR(jfsSyncThread);
		jfs_err("init_jfs_fs: fork failed w/rc = %d", rc);
		goto kill_committask;
	}

#ifdef PROC_FS_JFS
	jfs_proc_init();
#endif

	rc = register_filesystem(&jfs_fs_type);
	if (!rc)
		return 0;

#ifdef PROC_FS_JFS
	jfs_proc_clean();
#endif
	kthread_stop(jfsSyncThread);
kill_committask:
	for (i = 0; i < commit_threads; i++)
		kthread_stop(jfsCommitThread[i]);
	kthread_stop(jfsIOthread);
end_txmngr:
	txExit();
free_metapage:
	metapage_exit();
free_slab:
	kmem_cache_destroy(jfs_inode_cachep);
	return rc;
}

static void __exit exit_jfs_fs(void)
{
	int i;

	jfs_info("exit_jfs_fs called");

	txExit();
	metapage_exit();

	kthread_stop(jfsIOthread);
	for (i = 0; i < commit_threads; i++)
		kthread_stop(jfsCommitThread[i]);
	kthread_stop(jfsSyncThread);
#ifdef PROC_FS_JFS
	jfs_proc_clean();
#endif
	unregister_filesystem(&jfs_fs_type);

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(jfs_inode_cachep);
}

module_init(init_jfs_fs)
module_exit(exit_jfs_fs)
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/super.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2002
 *   Portions Copyright (C) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/mm.h>
// #include <linux/fs.h>
// #include <linux/posix_acl.h>
// #include <linux/quotaops.h>
// #include "jfs_incore.h"
// #include "jfs_inode.h"
// #include "jfs_dmap.h"
#include "jfs_txnmgr.h"
// #include "jfs_xattr.h"
// #include "jfs_acl.h"
// #include "jfs_debug.h"
#include "../../inc/__fss.h"

int jfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	int rc = 0;

	rc = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (rc)
		return rc;

	mutex_lock(&inode->i_mutex);
	if (!(inode->i_state & I_DIRTY_ALL) ||
	    (datasync && !(inode->i_state & I_DIRTY_DATASYNC))) {
		/* Make sure committed changes hit the disk */
		jfs_flush_journal(JFS_SBI(inode->i_sb)->log, 1);
		mutex_unlock(&inode->i_mutex);
		return rc;
	}

	rc |= jfs_commit_inode(inode, 1);
	mutex_unlock(&inode->i_mutex);

	return rc ? -EIO : 0;
}

static int jfs_open(struct inode *inode, struct file *file)
{
	int rc;

	if ((rc = dquot_file_open(inode, file)))
		return rc;

	/*
	 * We attempt to allow only one "active" file open per aggregate
	 * group.  Otherwise, appending to files in parallel can cause
	 * fragmentation within the files.
	 *
	 * If the file is empty, it was probably just created and going
	 * to be written to.  If it has a size, we'll hold off until the
	 * file is actually grown.
	 */
	if (S_ISREG(inode->i_mode) && file->f_mode & FMODE_WRITE &&
	    (inode->i_size == 0)) {
		struct jfs_inode_info *ji = JFS_IP(inode);
		spin_lock_irq(&ji->ag_lock);
		if (ji->active_ag == -1) {
			struct jfs_sb_info *jfs_sb = JFS_SBI(inode->i_sb);
			ji->active_ag = BLKTOAG(addressPXD(&ji->ixpxd), jfs_sb);
			atomic_inc( &jfs_sb->bmap->db_active[ji->active_ag]);
		}
		spin_unlock_irq(&ji->ag_lock);
	}

	return 0;
}
static int jfs_release(struct inode *inode, struct file *file)
{
	struct jfs_inode_info *ji = JFS_IP(inode);

	spin_lock_irq(&ji->ag_lock);
	if (ji->active_ag != -1) {
		struct bmap *bmap = JFS_SBI(inode->i_sb)->bmap;
		atomic_dec(&bmap->db_active[ji->active_ag]);
		ji->active_ag = -1;
	}
	spin_unlock_irq(&ji->ag_lock);

	return 0;
}

int jfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	int rc;

	rc = inode_change_ok(inode, iattr);
	if (rc)
		return rc;

	if (is_quota_modification(inode, iattr))
		dquot_initialize(inode);
	if ((iattr->ia_valid & ATTR_UID && !uid_eq(iattr->ia_uid, inode->i_uid)) ||
	    (iattr->ia_valid & ATTR_GID && !gid_eq(iattr->ia_gid, inode->i_gid))) {
		rc = dquot_transfer(inode, iattr);
		if (rc)
			return rc;
	}

	if ((iattr->ia_valid & ATTR_SIZE) &&
	    iattr->ia_size != i_size_read(inode)) {
		inode_dio_wait(inode);

		rc = inode_newsize_ok(inode, iattr->ia_size);
		if (rc)
			return rc;

		truncate_setsize(inode, iattr->ia_size);
		jfs_truncate(inode);
	}

	setattr_copy(inode, iattr);
	mark_inode_dirty(inode);

	if (iattr->ia_valid & ATTR_MODE)
		rc = posix_acl_chmod(inode, inode->i_mode);
	return rc;
}

const struct inode_operations jfs_file_inode_operations = {
	.setxattr	= jfs_setxattr,
	.getxattr	= jfs_getxattr,
	.listxattr	= jfs_listxattr,
	.removexattr	= jfs_removexattr,
	.setattr	= jfs_setattr,
#ifdef CONFIG_JFS_POSIX_ACL
	.get_acl	= jfs_get_acl,
	.set_acl	= jfs_set_acl,
#endif
};

const struct file_operations jfs_file_operations = {
	.open		= jfs_open,
	.llseek		= generic_file_llseek,
	.write		= new_sync_write,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fsync		= jfs_fsync,
	.release	= jfs_release,
	.unlocked_ioctl = jfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= jfs_compat_ioctl,
#endif
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/file.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *   Portions Copyright (C) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
#include <linux/mpage.h>
// #include <linux/buffer_head.h>
#include <linux/pagemap.h>
// #include <linux/quotaops.h>
#include <linux/writeback.h>
#include <linux/aio.h>
// #include "jfs_incore.h"
// #include "jfs_inode.h"
// #include "jfs_filsys.h"
// #include "jfs_imap.h"
#include "jfs_extent.h"
#include "jfs_unicode.h"
// #include "jfs_debug.h"
#include "../../inc/__fss.h"


struct inode *jfs_iget(struct super_block *sb, unsigned long ino)
{
	struct inode *inode;
	int ret;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ret = diRead(inode);
	if (ret < 0) {
		iget_failed(inode);
		return ERR_PTR(ret);
	}

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &jfs_file_inode_operations;
		inode->i_fop = &jfs_file_operations;
		inode->i_mapping->a_ops = &jfs_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &jfs_dir_inode_operations;
		inode->i_fop = &jfs_dir_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		if (inode->i_size >= IDATASIZE) {
			inode->i_op = &page_symlink_inode_operations;
			inode->i_mapping->a_ops = &jfs_aops;
		} else {
			inode->i_op = &jfs_fast_symlink_inode_operations;
			/*
			 * The inline data should be null-terminated, but
			 * don't let on-disk corruption crash the kernel
			 */
			JFS_IP(inode)->i_inline[inode->i_size] = '\0';
		}
	} else {
		inode->i_op = &jfs_file_inode_operations;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	}
	unlock_new_inode(inode);
	return inode;
}

/*
 * Workhorse of both fsync & write_inode
 */
int jfs_commit_inode(struct inode *inode, int wait)
{
	int rc = 0;
	tid_t tid;
	static int noisy = 5;

	jfs_info("In jfs_commit_inode, inode = 0x%p", inode);

	/*
	 * Don't commit if inode has been committed since last being
	 * marked dirty, or if it has been deleted.
	 */
	if (inode->i_nlink == 0 || !test_cflag(COMMIT_Dirty, inode))
		return 0;

	if (isReadOnly(inode)) {
		/* kernel allows writes to devices on read-only
		 * partitions and may think inode is dirty
		 */
		if (!special_file(inode->i_mode) && noisy) {
			jfs_err("jfs_commit_inode(0x%p) called on "
				   "read-only volume", inode);
			jfs_err("Is remount racy?");
			noisy--;
		}
		return 0;
	}

	tid = txBegin(inode->i_sb, COMMIT_INODE);
	mutex_lock(&JFS_IP(inode)->commit_mutex);

	/*
	 * Retest inode state after taking commit_mutex
	 */
	if (inode->i_nlink && test_cflag(COMMIT_Dirty, inode))
		rc = txCommit(tid, 1, &inode, wait ? COMMIT_SYNC : 0);

	txEnd(tid);
	mutex_unlock(&JFS_IP(inode)->commit_mutex);
	return rc;
}

int jfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int wait = wbc->sync_mode == WB_SYNC_ALL;

	if (inode->i_nlink == 0)
		return 0;
	/*
	 * If COMMIT_DIRTY is not set, the inode isn't really dirty.
	 * It has been committed since the last change, but was still
	 * on the dirty inode list.
	 */
	 if (!test_cflag(COMMIT_Dirty, inode)) {
		/* Make sure committed changes hit the disk */
		jfs_flush_journal(JFS_SBI(inode->i_sb)->log, wait);
		return 0;
	 }

	if (jfs_commit_inode(inode, wait)) {
		jfs_err("jfs_write_inode: jfs_commit_inode failed!");
		return -EIO;
	} else
		return 0;
}

void jfs_evict_inode(struct inode *inode)
{
	jfs_info("In jfs_evict_inode, inode = 0x%p", inode);

	if (!inode->i_nlink && !is_bad_inode(inode)) {
		dquot_initialize(inode);

		if (JFS_IP(inode)->fileset == FILESYSTEM_I) {
			truncate_inode_pages_final(&inode->i_data);

			if (test_cflag(COMMIT_Freewmap, inode))
				jfs_free_zero_link(inode);

			diFree(inode);

			/*
			 * Free the inode from the quota allocation.
			 */
			dquot_initialize(inode);
			dquot_free_inode(inode);
		}
	} else {
		truncate_inode_pages_final(&inode->i_data);
	}
	clear_inode(inode);
	dquot_drop(inode);
}

void jfs_dirty_inode(struct inode *inode, int flags)
{
	static int noisy = 5;

	if (isReadOnly(inode)) {
		if (!special_file(inode->i_mode) && noisy) {
			/* kernel allows writes to devices on read-only
			 * partitions and may try to mark inode dirty
			 */
			jfs_err("jfs_dirty_inode called on read-only volume");
			jfs_err("Is remount racy?");
			noisy--;
		}
		return;
	}

	set_cflag(COMMIT_Dirty, inode);
}

int jfs_get_block(struct inode *ip, sector_t lblock,
		  struct buffer_head *bh_result, int create)
{
	s64 lblock64 = lblock;
	int rc = 0;
	xad_t xad;
	s64 xaddr;
	int xflag;
	s32 xlen = bh_result->b_size >> ip->i_blkbits;

	/*
	 * Take appropriate lock on inode
	 */
	if (create)
		IWRITE_LOCK(ip, RDWRLOCK_NORMAL);
	else
		IREAD_LOCK(ip, RDWRLOCK_NORMAL);

	if (((lblock64 << ip->i_sb->s_blocksize_bits) < ip->i_size) &&
	    (!xtLookup(ip, lblock64, xlen, &xflag, &xaddr, &xlen, 0)) &&
	    xaddr) {
		if (xflag & XAD_NOTRECORDED) {
			if (!create)
				/*
				 * Allocated but not recorded, read treats
				 * this as a hole
				 */
				goto unlock;
#ifdef _JFS_4K
			XADoffset(&xad, lblock64);
			XADlength(&xad, xlen);
			XADaddress(&xad, xaddr);
#else				/* _JFS_4K */
			/*
			 * As long as block size = 4K, this isn't a problem.
			 * We should mark the whole page not ABNR, but how
			 * will we know to mark the other blocks BH_New?
			 */
			BUG();
#endif				/* _JFS_4K */
			rc = extRecord(ip, &xad);
			if (rc)
				goto unlock;
			set_buffer_new(bh_result);
		}

		map_bh(bh_result, ip->i_sb, xaddr);
		bh_result->b_size = xlen << ip->i_blkbits;
		goto unlock;
	}
	if (!create)
		goto unlock;

	/*
	 * Allocate a new block
	 */
#ifdef _JFS_4K
	if ((rc = extHint(ip, lblock64 << ip->i_sb->s_blocksize_bits, &xad)))
		goto unlock;
	rc = extAlloc(ip, xlen, lblock64, &xad, false);
	if (rc)
		goto unlock;

	set_buffer_new(bh_result);
	map_bh(bh_result, ip->i_sb, addressXAD(&xad));
	bh_result->b_size = lengthXAD(&xad) << ip->i_blkbits;

#else				/* _JFS_4K */
	/*
	 * We need to do whatever it takes to keep all but the last buffers
	 * in 4K pages - see jfs_write.c
	 */
	BUG();
#endif				/* _JFS_4K */

      unlock:
	/*
	 * Release lock on inode
	 */
	if (create)
		IWRITE_UNLOCK(ip);
	else
		IREAD_UNLOCK(ip);
	return rc;
}

static int jfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, jfs_get_block, wbc);
}

static int jfs_writepages(struct address_space *mapping,
			struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, jfs_get_block);
}

static int jfs_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, jfs_get_block);
}

static int jfs_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, jfs_get_block);
}

static void jfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		jfs_truncate(inode);
	}
}

static int jfs_write_begin(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	int ret;

	ret = nobh_write_begin(mapping, pos, len, flags, pagep, fsdata,
				jfs_get_block);
	if (unlikely(ret))
		jfs_write_failed(mapping, pos + len);

	return ret;
}

static sector_t jfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, jfs_get_block);
}

static ssize_t jfs_direct_IO(int rw, struct kiocb *iocb,
	struct iov_iter *iter, loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file->f_mapping->host;
	size_t count = iov_iter_count(iter);
	ssize_t ret;

	ret = blockdev_direct_IO(rw, iocb, inode, iter, offset, jfs_get_block);

	/*
	 * In case of error extending write may have instantiated a few
	 * blocks outside i_size. Trim these off again.
	 */
	if (unlikely((rw & WRITE) && ret < 0)) {
		loff_t isize = i_size_read(inode);
		loff_t end = offset + count;

		if (end > isize)
			jfs_write_failed(mapping, end);
	}

	return ret;
}

const struct address_space_operations jfs_aops = {
	.readpage	= jfs_readpage,
	.readpages	= jfs_readpages,
	.writepage	= jfs_writepage,
	.writepages	= jfs_writepages,
	.write_begin	= jfs_write_begin,
	.write_end	= nobh_write_end,
	.bmap		= jfs_bmap,
	.direct_IO	= jfs_direct_IO,
};

/*
 * Guts of jfs_truncate.  Called with locks already held.  Can be called
 * with directory for truncating directory index table.
 */
void jfs_truncate_nolock(struct inode *ip, loff_t length)
{
	loff_t newsize;
	tid_t tid;

	ASSERT(length >= 0);

	if (test_cflag(COMMIT_Nolink, ip)) {
		xtTruncate(0, ip, length, COMMIT_WMAP);
		return;
	}

	do {
		tid = txBegin(ip->i_sb, 0);

		/*
		 * The commit_mutex cannot be taken before txBegin.
		 * txBegin may block and there is a chance the inode
		 * could be marked dirty and need to be committed
		 * before txBegin unblocks
		 */
		mutex_lock(&JFS_IP(ip)->commit_mutex);

		newsize = xtTruncate(tid, ip, length,
				     COMMIT_TRUNCATE | COMMIT_PWMAP);
		if (newsize < 0) {
			txEnd(tid);
			mutex_unlock(&JFS_IP(ip)->commit_mutex);
			break;
		}

		ip->i_mtime = ip->i_ctime = CURRENT_TIME;
		mark_inode_dirty(ip);

		txCommit(tid, 1, &ip, 0);
		txEnd(tid);
		mutex_unlock(&JFS_IP(ip)->commit_mutex);
	} while (newsize > length);	/* Truncate isn't always atomic */
}

void jfs_truncate(struct inode *ip)
{
	jfs_info("jfs_truncate: size = 0x%lx", (ulong) ip->i_size);

	nobh_truncate_page(ip->i_mapping, ip->i_size, jfs_get_block);

	IWRITE_LOCK(ip, RDWRLOCK_NORMAL);
	jfs_truncate_nolock(ip, ip->i_size);
	IWRITE_UNLOCK(ip);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/inode.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *   Portions Copyright (C) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
#include <linux/namei.h>
#include <linux/ctype.h>
// #include <linux/quotaops.h>
// #include <linux/exportfs.h>
// #include "jfs_incore.h"
// #include "jfs_superblock.h"
// #include "jfs_inode.h"
#include "jfs_dinode.h"
// #include "jfs_dmap.h"
// #include "jfs_unicode.h"
// #include "jfs_metapage.h"
// #include "jfs_xattr.h"
// #include "jfs_acl.h"
// #include "jfs_debug.h"
#include "../../inc/__fss.h"

/*
 * forward references
 */
const struct dentry_operations jfs_ci_dentry_operations;

static s64 commitZeroLink(tid_t, struct inode *);

/*
 * NAME:	free_ea_wmap(inode)
 *
 * FUNCTION:	free uncommitted extended attributes from working map
 *
 */
static inline void free_ea_wmap(struct inode *inode)
{
	dxd_t *ea = &JFS_IP(inode)->ea;

	if (ea->flag & DXD_EXTENT) {
		/* free EA pages from cache */
		invalidate_dxd_metapages(inode, *ea);
		dbFree(inode, addressDXD(ea), lengthDXD(ea));
	}
	ea->flag = 0;
}

/*
 * NAME:	jfs_create(dip, dentry, mode)
 *
 * FUNCTION:	create a regular file in the parent directory <dip>
 *		with name = <from dentry> and mode = <mode>
 *
 * PARAMETER:	dip	- parent directory vnode
 *		dentry	- dentry of new file
 *		mode	- create mode (rwxrwxrwx).
 *		nd- nd struct
 *
 * RETURN:	Errors from subroutines
 *
 */
static int jfs_create(struct inode *dip, struct dentry *dentry, umode_t mode,
		bool excl)
{
	int rc = 0;
	tid_t tid;		/* transaction id */
	struct inode *ip = NULL;	/* child directory inode */
	ino_t ino;
	struct component_name dname;	/* child directory name */
	struct btstack btstack;
	struct inode *iplist[2];
	struct tblock *tblk;

	jfs_info("jfs_create: dip:0x%p name:%pd", dip, dentry);

	dquot_initialize(dip);

	/*
	 * search parent directory for entry/freespace
	 * (dtSearch() returns parent directory page pinned)
	 */
	if ((rc = get_UCSname(&dname, dentry)))
		goto out1;

	/*
	 * Either iAlloc() or txBegin() may block.  Deadlock can occur if we
	 * block there while holding dtree page, so we allocate the inode &
	 * begin the transaction before we search the directory.
	 */
	ip = ialloc(dip, mode);
	if (IS_ERR(ip)) {
		rc = PTR_ERR(ip);
		goto out2;
	}

	tid = txBegin(dip->i_sb, 0);

	mutex_lock_nested(&JFS_IP(dip)->commit_mutex, COMMIT_MUTEX_PARENT);
	mutex_lock_nested(&JFS_IP(ip)->commit_mutex, COMMIT_MUTEX_CHILD);

	rc = jfs_init_acl(tid, ip, dip);
	if (rc)
		goto out3;

	rc = jfs_init_security(tid, ip, dip, &dentry->d_name);
	if (rc) {
		txAbort(tid, 0);
		goto out3;
	}

	if ((rc = dtSearch(dip, &dname, &ino, &btstack, JFS_CREATE))) {
		jfs_err("jfs_create: dtSearch returned %d", rc);
		txAbort(tid, 0);
		goto out3;
	}

	tblk = tid_to_tblock(tid);
	tblk->xflag |= COMMIT_CREATE;
	tblk->ino = ip->i_ino;
	tblk->u.ixpxd = JFS_IP(ip)->ixpxd;

	iplist[0] = dip;
	iplist[1] = ip;

	/*
	 * initialize the child XAD tree root in-line in inode
	 */
	xtInitRoot(tid, ip);

	/*
	 * create entry in parent directory for child directory
	 * (dtInsert() releases parent directory page)
	 */
	ino = ip->i_ino;
	if ((rc = dtInsert(tid, dip, &dname, &ino, &btstack))) {
		if (rc == -EIO) {
			jfs_err("jfs_create: dtInsert returned -EIO");
			txAbort(tid, 1);	/* Marks Filesystem dirty */
		} else
			txAbort(tid, 0);	/* Filesystem full */
		goto out3;
	}

	ip->i_op = &jfs_file_inode_operations;
	ip->i_fop = &jfs_file_operations;
	ip->i_mapping->a_ops = &jfs_aops;

	mark_inode_dirty(ip);

	dip->i_ctime = dip->i_mtime = CURRENT_TIME;

	mark_inode_dirty(dip);

	rc = txCommit(tid, 2, &iplist[0], 0);

      out3:
	txEnd(tid);
	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	mutex_unlock(&JFS_IP(dip)->commit_mutex);
	if (rc) {
		free_ea_wmap(ip);
		clear_nlink(ip);
		unlock_new_inode(ip);
		iput(ip);
	} else {
		unlock_new_inode(ip);
		d_instantiate(dentry, ip);
	}

      out2:
	free_UCSname(&dname);

      out1:

	jfs_info("jfs_create: rc:%d", rc);
	return rc;
}


/*
 * NAME:	jfs_mkdir(dip, dentry, mode)
 *
 * FUNCTION:	create a child directory in the parent directory <dip>
 *		with name = <from dentry> and mode = <mode>
 *
 * PARAMETER:	dip	- parent directory vnode
 *		dentry	- dentry of child directory
 *		mode	- create mode (rwxrwxrwx).
 *
 * RETURN:	Errors from subroutines
 *
 * note:
 * EACCESS: user needs search+write permission on the parent directory
 */
static int jfs_mkdir(struct inode *dip, struct dentry *dentry, umode_t mode)
{
	int rc = 0;
	tid_t tid;		/* transaction id */
	struct inode *ip = NULL;	/* child directory inode */
	ino_t ino;
	struct component_name dname;	/* child directory name */
	struct btstack btstack;
	struct inode *iplist[2];
	struct tblock *tblk;

	jfs_info("jfs_mkdir: dip:0x%p name:%pd", dip, dentry);

	dquot_initialize(dip);

	/*
	 * search parent directory for entry/freespace
	 * (dtSearch() returns parent directory page pinned)
	 */
	if ((rc = get_UCSname(&dname, dentry)))
		goto out1;

	/*
	 * Either iAlloc() or txBegin() may block.  Deadlock can occur if we
	 * block there while holding dtree page, so we allocate the inode &
	 * begin the transaction before we search the directory.
	 */
	ip = ialloc(dip, S_IFDIR | mode);
	if (IS_ERR(ip)) {
		rc = PTR_ERR(ip);
		goto out2;
	}

	tid = txBegin(dip->i_sb, 0);

	mutex_lock_nested(&JFS_IP(dip)->commit_mutex, COMMIT_MUTEX_PARENT);
	mutex_lock_nested(&JFS_IP(ip)->commit_mutex, COMMIT_MUTEX_CHILD);

	rc = jfs_init_acl(tid, ip, dip);
	if (rc)
		goto out3;

	rc = jfs_init_security(tid, ip, dip, &dentry->d_name);
	if (rc) {
		txAbort(tid, 0);
		goto out3;
	}

	if ((rc = dtSearch(dip, &dname, &ino, &btstack, JFS_CREATE))) {
		jfs_err("jfs_mkdir: dtSearch returned %d", rc);
		txAbort(tid, 0);
		goto out3;
	}

	tblk = tid_to_tblock(tid);
	tblk->xflag |= COMMIT_CREATE;
	tblk->ino = ip->i_ino;
	tblk->u.ixpxd = JFS_IP(ip)->ixpxd;

	iplist[0] = dip;
	iplist[1] = ip;

	/*
	 * initialize the child directory in-line in inode
	 */
	dtInitRoot(tid, ip, dip->i_ino);

	/*
	 * create entry in parent directory for child directory
	 * (dtInsert() releases parent directory page)
	 */
	ino = ip->i_ino;
	if ((rc = dtInsert(tid, dip, &dname, &ino, &btstack))) {
		if (rc == -EIO) {
			jfs_err("jfs_mkdir: dtInsert returned -EIO");
			txAbort(tid, 1);	/* Marks Filesystem dirty */
		} else
			txAbort(tid, 0);	/* Filesystem full */
		goto out3;
	}

	set_nlink(ip, 2);	/* for '.' */
	ip->i_op = &jfs_dir_inode_operations;
	ip->i_fop = &jfs_dir_operations;

	mark_inode_dirty(ip);

	/* update parent directory inode */
	inc_nlink(dip);		/* for '..' from child directory */
	dip->i_ctime = dip->i_mtime = CURRENT_TIME;
	mark_inode_dirty(dip);

	rc = txCommit(tid, 2, &iplist[0], 0);

      out3:
	txEnd(tid);
	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	mutex_unlock(&JFS_IP(dip)->commit_mutex);
	if (rc) {
		free_ea_wmap(ip);
		clear_nlink(ip);
		unlock_new_inode(ip);
		iput(ip);
	} else {
		unlock_new_inode(ip);
		d_instantiate(dentry, ip);
	}

      out2:
	free_UCSname(&dname);


      out1:

	jfs_info("jfs_mkdir: rc:%d", rc);
	return rc;
}

/*
 * NAME:	jfs_rmdir(dip, dentry)
 *
 * FUNCTION:	remove a link to child directory
 *
 * PARAMETER:	dip	- parent inode
 *		dentry	- child directory dentry
 *
 * RETURN:	-EINVAL	- if name is . or ..
 *		-EINVAL - if . or .. exist but are invalid.
 *		errors from subroutines
 *
 * note:
 * if other threads have the directory open when the last link
 * is removed, the "." and ".." entries, if present, are removed before
 * rmdir() returns and no new entries may be created in the directory,
 * but the directory is not removed until the last reference to
 * the directory is released (cf.unlink() of regular file).
 */
static int jfs_rmdir(struct inode *dip, struct dentry *dentry)
{
	int rc;
	tid_t tid;		/* transaction id */
	struct inode *ip = dentry->d_inode;
	ino_t ino;
	struct component_name dname;
	struct inode *iplist[2];
	struct tblock *tblk;

	jfs_info("jfs_rmdir: dip:0x%p name:%pd", dip, dentry);

	/* Init inode for quota operations. */
	dquot_initialize(dip);
	dquot_initialize(ip);

	/* directory must be empty to be removed */
	if (!dtEmpty(ip)) {
		rc = -ENOTEMPTY;
		goto out;
	}

	if ((rc = get_UCSname(&dname, dentry))) {
		goto out;
	}

	tid = txBegin(dip->i_sb, 0);

	mutex_lock_nested(&JFS_IP(dip)->commit_mutex, COMMIT_MUTEX_PARENT);
	mutex_lock_nested(&JFS_IP(ip)->commit_mutex, COMMIT_MUTEX_CHILD);

	iplist[0] = dip;
	iplist[1] = ip;

	tblk = tid_to_tblock(tid);
	tblk->xflag |= COMMIT_DELETE;
	tblk->u.ip = ip;

	/*
	 * delete the entry of target directory from parent directory
	 */
	ino = ip->i_ino;
	if ((rc = dtDelete(tid, dip, &dname, &ino, JFS_REMOVE))) {
		jfs_err("jfs_rmdir: dtDelete returned %d", rc);
		if (rc == -EIO)
			txAbort(tid, 1);
		txEnd(tid);
		mutex_unlock(&JFS_IP(ip)->commit_mutex);
		mutex_unlock(&JFS_IP(dip)->commit_mutex);

		goto out2;
	}

	/* update parent directory's link count corresponding
	 * to ".." entry of the target directory deleted
	 */
	dip->i_ctime = dip->i_mtime = CURRENT_TIME;
	inode_dec_link_count(dip);

	/*
	 * OS/2 could have created EA and/or ACL
	 */
	/* free EA from both persistent and working map */
	if (JFS_IP(ip)->ea.flag & DXD_EXTENT) {
		/* free EA pages */
		txEA(tid, ip, &JFS_IP(ip)->ea, NULL);
	}
	JFS_IP(ip)->ea.flag = 0;

	/* free ACL from both persistent and working map */
	if (JFS_IP(ip)->acl.flag & DXD_EXTENT) {
		/* free ACL pages */
		txEA(tid, ip, &JFS_IP(ip)->acl, NULL);
	}
	JFS_IP(ip)->acl.flag = 0;

	/* mark the target directory as deleted */
	clear_nlink(ip);
	mark_inode_dirty(ip);

	rc = txCommit(tid, 2, &iplist[0], 0);

	txEnd(tid);

	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	mutex_unlock(&JFS_IP(dip)->commit_mutex);

	/*
	 * Truncating the directory index table is not guaranteed.  It
	 * may need to be done iteratively
	 */
	if (test_cflag(COMMIT_Stale, dip)) {
		if (dip->i_size > 1)
			jfs_truncate_nolock(dip, 0);

		clear_cflag(COMMIT_Stale, dip);
	}

      out2:
	free_UCSname(&dname);

      out:
	jfs_info("jfs_rmdir: rc:%d", rc);
	return rc;
}

/*
 * NAME:	jfs_unlink(dip, dentry)
 *
 * FUNCTION:	remove a link to object <vp> named by <name>
 *		from parent directory <dvp>
 *
 * PARAMETER:	dip	- inode of parent directory
 *		dentry	- dentry of object to be removed
 *
 * RETURN:	errors from subroutines
 *
 * note:
 * temporary file: if one or more processes have the file open
 * when the last link is removed, the link will be removed before
 * unlink() returns, but the removal of the file contents will be
 * postponed until all references to the files are closed.
 *
 * JFS does NOT support unlink() on directories.
 *
 */
static int jfs_unlink(struct inode *dip, struct dentry *dentry)
{
	int rc;
	tid_t tid;		/* transaction id */
	struct inode *ip = dentry->d_inode;
	ino_t ino;
	struct component_name dname;	/* object name */
	struct inode *iplist[2];
	struct tblock *tblk;
	s64 new_size = 0;
	int commit_flag;

	jfs_info("jfs_unlink: dip:0x%p name:%pd", dip, dentry);

	/* Init inode for quota operations. */
	dquot_initialize(dip);
	dquot_initialize(ip);

	if ((rc = get_UCSname(&dname, dentry)))
		goto out;

	IWRITE_LOCK(ip, RDWRLOCK_NORMAL);

	tid = txBegin(dip->i_sb, 0);

	mutex_lock_nested(&JFS_IP(dip)->commit_mutex, COMMIT_MUTEX_PARENT);
	mutex_lock_nested(&JFS_IP(ip)->commit_mutex, COMMIT_MUTEX_CHILD);

	iplist[0] = dip;
	iplist[1] = ip;

	/*
	 * delete the entry of target file from parent directory
	 */
	ino = ip->i_ino;
	if ((rc = dtDelete(tid, dip, &dname, &ino, JFS_REMOVE))) {
		jfs_err("jfs_unlink: dtDelete returned %d", rc);
		if (rc == -EIO)
			txAbort(tid, 1);	/* Marks FS Dirty */
		txEnd(tid);
		mutex_unlock(&JFS_IP(ip)->commit_mutex);
		mutex_unlock(&JFS_IP(dip)->commit_mutex);
		IWRITE_UNLOCK(ip);
		goto out1;
	}

	ASSERT(ip->i_nlink);

	ip->i_ctime = dip->i_ctime = dip->i_mtime = CURRENT_TIME;
	mark_inode_dirty(dip);

	/* update target's inode */
	inode_dec_link_count(ip);

	/*
	 *	commit zero link count object
	 */
	if (ip->i_nlink == 0) {
		assert(!test_cflag(COMMIT_Nolink, ip));
		/* free block resources */
		if ((new_size = commitZeroLink(tid, ip)) < 0) {
			txAbort(tid, 1);	/* Marks FS Dirty */
			txEnd(tid);
			mutex_unlock(&JFS_IP(ip)->commit_mutex);
			mutex_unlock(&JFS_IP(dip)->commit_mutex);
			IWRITE_UNLOCK(ip);
			rc = new_size;
			goto out1;
		}
		tblk = tid_to_tblock(tid);
		tblk->xflag |= COMMIT_DELETE;
		tblk->u.ip = ip;
	}

	/*
	 * Incomplete truncate of file data can
	 * result in timing problems unless we synchronously commit the
	 * transaction.
	 */
	if (new_size)
		commit_flag = COMMIT_SYNC;
	else
		commit_flag = 0;

	/*
	 * If xtTruncate was incomplete, commit synchronously to avoid
	 * timing complications
	 */
	rc = txCommit(tid, 2, &iplist[0], commit_flag);

	txEnd(tid);

	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	mutex_unlock(&JFS_IP(dip)->commit_mutex);

	while (new_size && (rc == 0)) {
		tid = txBegin(dip->i_sb, 0);
		mutex_lock(&JFS_IP(ip)->commit_mutex);
		new_size = xtTruncate_pmap(tid, ip, new_size);
		if (new_size < 0) {
			txAbort(tid, 1);	/* Marks FS Dirty */
			rc = new_size;
		} else
			rc = txCommit(tid, 2, &iplist[0], COMMIT_SYNC);
		txEnd(tid);
		mutex_unlock(&JFS_IP(ip)->commit_mutex);
	}

	if (ip->i_nlink == 0)
		set_cflag(COMMIT_Nolink, ip);

	IWRITE_UNLOCK(ip);

	/*
	 * Truncating the directory index table is not guaranteed.  It
	 * may need to be done iteratively
	 */
	if (test_cflag(COMMIT_Stale, dip)) {
		if (dip->i_size > 1)
			jfs_truncate_nolock(dip, 0);

		clear_cflag(COMMIT_Stale, dip);
	}

      out1:
	free_UCSname(&dname);
      out:
	jfs_info("jfs_unlink: rc:%d", rc);
	return rc;
}

/*
 * NAME:	commitZeroLink()
 *
 * FUNCTION:	for non-directory, called by jfs_remove(),
 *		truncate a regular file, directory or symbolic
 *		link to zero length. return 0 if type is not
 *		one of these.
 *
 *		if the file is currently associated with a VM segment
 *		only permanent disk and inode map resources are freed,
 *		and neither the inode nor indirect blocks are modified
 *		so that the resources can be later freed in the work
 *		map by ctrunc1.
 *		if there is no VM segment on entry, the resources are
 *		freed in both work and permanent map.
 *		(? for temporary file - memory object is cached even
 *		after no reference:
 *		reference count > 0 -   )
 *
 * PARAMETERS:	cd	- pointer to commit data structure.
 *			  current inode is the one to truncate.
 *
 * RETURN:	Errors from subroutines
 */
static s64 commitZeroLink(tid_t tid, struct inode *ip)
{
	int filetype;
	struct tblock *tblk;

	jfs_info("commitZeroLink: tid = %d, ip = 0x%p", tid, ip);

	filetype = ip->i_mode & S_IFMT;
	switch (filetype) {
	case S_IFREG:
		break;
	case S_IFLNK:
		/* fast symbolic link */
		if (ip->i_size < IDATASIZE) {
			ip->i_size = 0;
			return 0;
		}
		break;
	default:
		assert(filetype != S_IFDIR);
		return 0;
	}

	set_cflag(COMMIT_Freewmap, ip);

	/* mark transaction of block map update type */
	tblk = tid_to_tblock(tid);
	tblk->xflag |= COMMIT_PMAP;

	/*
	 * free EA
	 */
	if (JFS_IP(ip)->ea.flag & DXD_EXTENT)
		/* acquire maplock on EA to be freed from block map */
		txEA(tid, ip, &JFS_IP(ip)->ea, NULL);

	/*
	 * free ACL
	 */
	if (JFS_IP(ip)->acl.flag & DXD_EXTENT)
		/* acquire maplock on EA to be freed from block map */
		txEA(tid, ip, &JFS_IP(ip)->acl, NULL);

	/*
	 * free xtree/data (truncate to zero length):
	 * free xtree/data pages from cache if COMMIT_PWMAP,
	 * free xtree/data blocks from persistent block map, and
	 * free xtree/data blocks from working block map if COMMIT_PWMAP;
	 */
	if (ip->i_size)
		return xtTruncate_pmap(tid, ip, 0);

	return 0;
}


/*
 * NAME:	jfs_free_zero_link()
 *
 * FUNCTION:	for non-directory, called by iClose(),
 *		free resources of a file from cache and WORKING map
 *		for a file previously committed with zero link count
 *		while associated with a pager object,
 *
 * PARAMETER:	ip	- pointer to inode of file.
 */
void jfs_free_zero_link(struct inode *ip)
{
	int type;

	jfs_info("jfs_free_zero_link: ip = 0x%p", ip);

	/* return if not reg or symbolic link or if size is
	 * already ok.
	 */
	type = ip->i_mode & S_IFMT;

	switch (type) {
	case S_IFREG:
		break;
	case S_IFLNK:
		/* if its contained in inode nothing to do */
		if (ip->i_size < IDATASIZE)
			return;
		break;
	default:
		return;
	}

	/*
	 * free EA
	 */
	if (JFS_IP(ip)->ea.flag & DXD_EXTENT) {
		s64 xaddr = addressDXD(&JFS_IP(ip)->ea);
		int xlen = lengthDXD(&JFS_IP(ip)->ea);
		struct maplock maplock;	/* maplock for COMMIT_WMAP */
		struct pxd_lock *pxdlock;	/* maplock for COMMIT_WMAP */

		/* free EA pages from cache */
		invalidate_dxd_metapages(ip, JFS_IP(ip)->ea);

		/* free EA extent from working block map */
		maplock.index = 1;
		pxdlock = (struct pxd_lock *) & maplock;
		pxdlock->flag = mlckFREEPXD;
		PXDaddress(&pxdlock->pxd, xaddr);
		PXDlength(&pxdlock->pxd, xlen);
		txFreeMap(ip, pxdlock, NULL, COMMIT_WMAP);
	}

	/*
	 * free ACL
	 */
	if (JFS_IP(ip)->acl.flag & DXD_EXTENT) {
		s64 xaddr = addressDXD(&JFS_IP(ip)->acl);
		int xlen = lengthDXD(&JFS_IP(ip)->acl);
		struct maplock maplock;	/* maplock for COMMIT_WMAP */
		struct pxd_lock *pxdlock;	/* maplock for COMMIT_WMAP */

		invalidate_dxd_metapages(ip, JFS_IP(ip)->acl);

		/* free ACL extent from working block map */
		maplock.index = 1;
		pxdlock = (struct pxd_lock *) & maplock;
		pxdlock->flag = mlckFREEPXD;
		PXDaddress(&pxdlock->pxd, xaddr);
		PXDlength(&pxdlock->pxd, xlen);
		txFreeMap(ip, pxdlock, NULL, COMMIT_WMAP);
	}

	/*
	 * free xtree/data (truncate to zero length):
	 * free xtree/data pages from cache, and
	 * free xtree/data blocks from working block map;
	 */
	if (ip->i_size)
		xtTruncate(0, ip, 0, COMMIT_WMAP);
}

/*
 * NAME:	jfs_link(vp, dvp, name, crp)
 *
 * FUNCTION:	create a link to <vp> by the name = <name>
 *		in the parent directory <dvp>
 *
 * PARAMETER:	vp	- target object
 *		dvp	- parent directory of new link
 *		name	- name of new link to target object
 *		crp	- credential
 *
 * RETURN:	Errors from subroutines
 *
 * note:
 * JFS does NOT support link() on directories (to prevent circular
 * path in the directory hierarchy);
 * EPERM: the target object is a directory, and either the caller
 * does not have appropriate privileges or the implementation prohibits
 * using link() on directories [XPG4.2].
 *
 * JFS does NOT support links between file systems:
 * EXDEV: target object and new link are on different file systems and
 * implementation does not support links between file systems [XPG4.2].
 */
static int jfs_link(struct dentry *old_dentry,
	     struct inode *dir, struct dentry *dentry)
{
	int rc;
	tid_t tid;
	struct inode *ip = old_dentry->d_inode;
	ino_t ino;
	struct component_name dname;
	struct btstack btstack;
	struct inode *iplist[2];

	jfs_info("jfs_link: %pd %pd", old_dentry, dentry);

	dquot_initialize(dir);

	tid = txBegin(ip->i_sb, 0);

	mutex_lock_nested(&JFS_IP(dir)->commit_mutex, COMMIT_MUTEX_PARENT);
	mutex_lock_nested(&JFS_IP(ip)->commit_mutex, COMMIT_MUTEX_CHILD);

	/*
	 * scan parent directory for entry/freespace
	 */
	if ((rc = get_UCSname(&dname, dentry)))
		goto out;

	if ((rc = dtSearch(dir, &dname, &ino, &btstack, JFS_CREATE)))
		goto free_dname;

	/*
	 * create entry for new link in parent directory
	 */
	ino = ip->i_ino;
	if ((rc = dtInsert(tid, dir, &dname, &ino, &btstack)))
		goto free_dname;

	/* update object inode */
	inc_nlink(ip);		/* for new link */
	ip->i_ctime = CURRENT_TIME;
	dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	mark_inode_dirty(dir);
	ihold(ip);

	iplist[0] = ip;
	iplist[1] = dir;
	rc = txCommit(tid, 2, &iplist[0], 0);

	if (rc) {
		drop_nlink(ip); /* never instantiated */
		iput(ip);
	} else
		d_instantiate(dentry, ip);

      free_dname:
	free_UCSname(&dname);

      out:
	txEnd(tid);

	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	mutex_unlock(&JFS_IP(dir)->commit_mutex);

	jfs_info("jfs_link: rc:%d", rc);
	return rc;
}

/*
 * NAME:	jfs_symlink(dip, dentry, name)
 *
 * FUNCTION:	creates a symbolic link to <symlink> by name <name>
 *			in directory <dip>
 *
 * PARAMETER:	dip	- parent directory vnode
 *		dentry	- dentry of symbolic link
 *		name	- the path name of the existing object
 *			  that will be the source of the link
 *
 * RETURN:	errors from subroutines
 *
 * note:
 * ENAMETOOLONG: pathname resolution of a symbolic link produced
 * an intermediate result whose length exceeds PATH_MAX [XPG4.2]
*/

static int jfs_symlink(struct inode *dip, struct dentry *dentry,
		const char *name)
{
	int rc;
	tid_t tid;
	ino_t ino = 0;
	struct component_name dname;
	int ssize;		/* source pathname size */
	struct btstack btstack;
	struct inode *ip = dentry->d_inode;
	unchar *i_fastsymlink;
	s64 xlen = 0;
	int bmask = 0, xsize;
	s64 xaddr;
	struct metapage *mp;
	struct super_block *sb;
	struct tblock *tblk;

	struct inode *iplist[2];

	jfs_info("jfs_symlink: dip:0x%p name:%s", dip, name);

	dquot_initialize(dip);

	ssize = strlen(name) + 1;

	/*
	 * search parent directory for entry/freespace
	 * (dtSearch() returns parent directory page pinned)
	 */

	if ((rc = get_UCSname(&dname, dentry)))
		goto out1;

	/*
	 * allocate on-disk/in-memory inode for symbolic link:
	 * (iAlloc() returns new, locked inode)
	 */
	ip = ialloc(dip, S_IFLNK | 0777);
	if (IS_ERR(ip)) {
		rc = PTR_ERR(ip);
		goto out2;
	}

	tid = txBegin(dip->i_sb, 0);

	mutex_lock_nested(&JFS_IP(dip)->commit_mutex, COMMIT_MUTEX_PARENT);
	mutex_lock_nested(&JFS_IP(ip)->commit_mutex, COMMIT_MUTEX_CHILD);

	rc = jfs_init_security(tid, ip, dip, &dentry->d_name);
	if (rc)
		goto out3;

	tblk = tid_to_tblock(tid);
	tblk->xflag |= COMMIT_CREATE;
	tblk->ino = ip->i_ino;
	tblk->u.ixpxd = JFS_IP(ip)->ixpxd;

	/* fix symlink access permission
	 * (dir_create() ANDs in the u.u_cmask,
	 * but symlinks really need to be 777 access)
	 */
	ip->i_mode |= 0777;

	/*
	 * write symbolic link target path name
	 */
	xtInitRoot(tid, ip);

	/*
	 * write source path name inline in on-disk inode (fast symbolic link)
	 */

	if (ssize <= IDATASIZE) {
		ip->i_op = &jfs_fast_symlink_inode_operations;

		i_fastsymlink = JFS_IP(ip)->i_inline;
		memcpy(i_fastsymlink, name, ssize);
		ip->i_size = ssize - 1;

		/*
		 * if symlink is > 128 bytes, we don't have the space to
		 * store inline extended attributes
		 */
		if (ssize > sizeof (JFS_IP(ip)->i_inline))
			JFS_IP(ip)->mode2 &= ~INLINEEA;

		jfs_info("jfs_symlink: fast symlink added  ssize:%d name:%s ",
			 ssize, name);
	}
	/*
	 * write source path name in a single extent
	 */
	else {
		jfs_info("jfs_symlink: allocate extent ip:0x%p", ip);

		ip->i_op = &jfs_symlink_inode_operations;
		ip->i_mapping->a_ops = &jfs_aops;

		/*
		 * even though the data of symlink object (source
		 * path name) is treated as non-journaled user data,
		 * it is read/written thru buffer cache for performance.
		 */
		sb = ip->i_sb;
		bmask = JFS_SBI(sb)->bsize - 1;
		xsize = (ssize + bmask) & ~bmask;
		xaddr = 0;
		xlen = xsize >> JFS_SBI(sb)->l2bsize;
		if ((rc = xtInsert(tid, ip, 0, 0, xlen, &xaddr, 0))) {
			txAbort(tid, 0);
			goto out3;
		}
		ip->i_size = ssize - 1;
		while (ssize) {
			/* This is kind of silly since PATH_MAX == 4K */
			int copy_size = min(ssize, PSIZE);

			mp = get_metapage(ip, xaddr, PSIZE, 1);

			if (mp == NULL) {
				xtTruncate(tid, ip, 0, COMMIT_PWMAP);
				rc = -EIO;
				txAbort(tid, 0);
				goto out3;
			}
			memcpy(mp->data, name, copy_size);
			flush_metapage(mp);
			ssize -= copy_size;
			name += copy_size;
			xaddr += JFS_SBI(sb)->nbperpage;
		}
	}

	/*
	 * create entry for symbolic link in parent directory
	 */
	rc = dtSearch(dip, &dname, &ino, &btstack, JFS_CREATE);
	if (rc == 0) {
		ino = ip->i_ino;
		rc = dtInsert(tid, dip, &dname, &ino, &btstack);
	}
	if (rc) {
		if (xlen)
			xtTruncate(tid, ip, 0, COMMIT_PWMAP);
		txAbort(tid, 0);
		/* discard new inode */
		goto out3;
	}

	mark_inode_dirty(ip);

	dip->i_ctime = dip->i_mtime = CURRENT_TIME;
	mark_inode_dirty(dip);
	/*
	 * commit update of parent directory and link object
	 */

	iplist[0] = dip;
	iplist[1] = ip;
	rc = txCommit(tid, 2, &iplist[0], 0);

      out3:
	txEnd(tid);
	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	mutex_unlock(&JFS_IP(dip)->commit_mutex);
	if (rc) {
		free_ea_wmap(ip);
		clear_nlink(ip);
		unlock_new_inode(ip);
		iput(ip);
	} else {
		unlock_new_inode(ip);
		d_instantiate(dentry, ip);
	}

      out2:
	free_UCSname(&dname);

      out1:
	jfs_info("jfs_symlink: rc:%d", rc);
	return rc;
}


/*
 * NAME:	jfs_rename
 *
 * FUNCTION:	rename a file or directory
 */
static int jfs_rename(struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry)
{
	struct btstack btstack;
	ino_t ino;
	struct component_name new_dname;
	struct inode *new_ip;
	struct component_name old_dname;
	struct inode *old_ip;
	int rc;
	tid_t tid;
	struct tlock *tlck;
	struct dt_lock *dtlck;
	struct lv *lv;
	int ipcount;
	struct inode *iplist[4];
	struct tblock *tblk;
	s64 new_size = 0;
	int commit_flag;


	jfs_info("jfs_rename: %pd %pd", old_dentry, new_dentry);

	dquot_initialize(old_dir);
	dquot_initialize(new_dir);

	old_ip = old_dentry->d_inode;
	new_ip = new_dentry->d_inode;

	if ((rc = get_UCSname(&old_dname, old_dentry)))
		goto out1;

	if ((rc = get_UCSname(&new_dname, new_dentry)))
		goto out2;

	/*
	 * Make sure source inode number is what we think it is
	 */
	rc = dtSearch(old_dir, &old_dname, &ino, &btstack, JFS_LOOKUP);
	if (rc || (ino != old_ip->i_ino)) {
		rc = -ENOENT;
		goto out3;
	}

	/*
	 * Make sure dest inode number (if any) is what we think it is
	 */
	rc = dtSearch(new_dir, &new_dname, &ino, &btstack, JFS_LOOKUP);
	if (!rc) {
		if ((!new_ip) || (ino != new_ip->i_ino)) {
			rc = -ESTALE;
			goto out3;
		}
	} else if (rc != -ENOENT)
		goto out3;
	else if (new_ip) {
		/* no entry exists, but one was expected */
		rc = -ESTALE;
		goto out3;
	}

	if (S_ISDIR(old_ip->i_mode)) {
		if (new_ip) {
			if (!dtEmpty(new_ip)) {
				rc = -ENOTEMPTY;
				goto out3;
			}
		}
	} else if (new_ip) {
		IWRITE_LOCK(new_ip, RDWRLOCK_NORMAL);
		/* Init inode for quota operations. */
		dquot_initialize(new_ip);
	}

	/*
	 * The real work starts here
	 */
	tid = txBegin(new_dir->i_sb, 0);

	/*
	 * How do we know the locking is safe from deadlocks?
	 * The vfs does the hard part for us.  Any time we are taking nested
	 * commit_mutexes, the vfs already has i_mutex held on the parent.
	 * Here, the vfs has already taken i_mutex on both old_dir and new_dir.
	 */
	mutex_lock_nested(&JFS_IP(new_dir)->commit_mutex, COMMIT_MUTEX_PARENT);
	mutex_lock_nested(&JFS_IP(old_ip)->commit_mutex, COMMIT_MUTEX_CHILD);
	if (old_dir != new_dir)
		mutex_lock_nested(&JFS_IP(old_dir)->commit_mutex,
				  COMMIT_MUTEX_SECOND_PARENT);

	if (new_ip) {
		mutex_lock_nested(&JFS_IP(new_ip)->commit_mutex,
				  COMMIT_MUTEX_VICTIM);
		/*
		 * Change existing directory entry to new inode number
		 */
		ino = new_ip->i_ino;
		rc = dtModify(tid, new_dir, &new_dname, &ino,
			      old_ip->i_ino, JFS_RENAME);
		if (rc)
			goto out4;
		drop_nlink(new_ip);
		if (S_ISDIR(new_ip->i_mode)) {
			drop_nlink(new_ip);
			if (new_ip->i_nlink) {
				mutex_unlock(&JFS_IP(new_ip)->commit_mutex);
				if (old_dir != new_dir)
					mutex_unlock(&JFS_IP(old_dir)->commit_mutex);
				mutex_unlock(&JFS_IP(old_ip)->commit_mutex);
				mutex_unlock(&JFS_IP(new_dir)->commit_mutex);
				if (!S_ISDIR(old_ip->i_mode) && new_ip)
					IWRITE_UNLOCK(new_ip);
				jfs_error(new_ip->i_sb,
					  "new_ip->i_nlink != 0\n");
				return -EIO;
			}
			tblk = tid_to_tblock(tid);
			tblk->xflag |= COMMIT_DELETE;
			tblk->u.ip = new_ip;
		} else if (new_ip->i_nlink == 0) {
			assert(!test_cflag(COMMIT_Nolink, new_ip));
			/* free block resources */
			if ((new_size = commitZeroLink(tid, new_ip)) < 0) {
				txAbort(tid, 1);	/* Marks FS Dirty */
				rc = new_size;
				goto out4;
			}
			tblk = tid_to_tblock(tid);
			tblk->xflag |= COMMIT_DELETE;
			tblk->u.ip = new_ip;
		} else {
			new_ip->i_ctime = CURRENT_TIME;
			mark_inode_dirty(new_ip);
		}
	} else {
		/*
		 * Add new directory entry
		 */
		rc = dtSearch(new_dir, &new_dname, &ino, &btstack,
			      JFS_CREATE);
		if (rc) {
			jfs_err("jfs_rename didn't expect dtSearch to fail "
				"w/rc = %d", rc);
			goto out4;
		}

		ino = old_ip->i_ino;
		rc = dtInsert(tid, new_dir, &new_dname, &ino, &btstack);
		if (rc) {
			if (rc == -EIO)
				jfs_err("jfs_rename: dtInsert returned -EIO");
			goto out4;
		}
		if (S_ISDIR(old_ip->i_mode))
			inc_nlink(new_dir);
	}
	/*
	 * Remove old directory entry
	 */

	ino = old_ip->i_ino;
	rc = dtDelete(tid, old_dir, &old_dname, &ino, JFS_REMOVE);
	if (rc) {
		jfs_err("jfs_rename did not expect dtDelete to return rc = %d",
			rc);
		txAbort(tid, 1);	/* Marks Filesystem dirty */
		goto out4;
	}
	if (S_ISDIR(old_ip->i_mode)) {
		drop_nlink(old_dir);
		if (old_dir != new_dir) {
			/*
			 * Change inode number of parent for moved directory
			 */

			JFS_IP(old_ip)->i_dtroot.header.idotdot =
				cpu_to_le32(new_dir->i_ino);

			/* Linelock header of dtree */
			tlck = txLock(tid, old_ip,
				    (struct metapage *) &JFS_IP(old_ip)->bxflag,
				      tlckDTREE | tlckBTROOT | tlckRELINK);
			dtlck = (struct dt_lock *) & tlck->lock;
			ASSERT(dtlck->index == 0);
			lv = & dtlck->lv[0];
			lv->offset = 0;
			lv->length = 1;
			dtlck->index++;
		}
	}

	/*
	 * Update ctime on changed/moved inodes & mark dirty
	 */
	old_ip->i_ctime = CURRENT_TIME;
	mark_inode_dirty(old_ip);

	new_dir->i_ctime = new_dir->i_mtime = current_fs_time(new_dir->i_sb);
	mark_inode_dirty(new_dir);

	/* Build list of inodes modified by this transaction */
	ipcount = 0;
	iplist[ipcount++] = old_ip;
	if (new_ip)
		iplist[ipcount++] = new_ip;
	iplist[ipcount++] = old_dir;

	if (old_dir != new_dir) {
		iplist[ipcount++] = new_dir;
		old_dir->i_ctime = old_dir->i_mtime = CURRENT_TIME;
		mark_inode_dirty(old_dir);
	}

	/*
	 * Incomplete truncate of file data can
	 * result in timing problems unless we synchronously commit the
	 * transaction.
	 */
	if (new_size)
		commit_flag = COMMIT_SYNC;
	else
		commit_flag = 0;

	rc = txCommit(tid, ipcount, iplist, commit_flag);

      out4:
	txEnd(tid);
	if (new_ip)
		mutex_unlock(&JFS_IP(new_ip)->commit_mutex);
	if (old_dir != new_dir)
		mutex_unlock(&JFS_IP(old_dir)->commit_mutex);
	mutex_unlock(&JFS_IP(old_ip)->commit_mutex);
	mutex_unlock(&JFS_IP(new_dir)->commit_mutex);

	while (new_size && (rc == 0)) {
		tid = txBegin(new_ip->i_sb, 0);
		mutex_lock(&JFS_IP(new_ip)->commit_mutex);
		new_size = xtTruncate_pmap(tid, new_ip, new_size);
		if (new_size < 0) {
			txAbort(tid, 1);
			rc = new_size;
		} else
			rc = txCommit(tid, 1, &new_ip, COMMIT_SYNC);
		txEnd(tid);
		mutex_unlock(&JFS_IP(new_ip)->commit_mutex);
	}
	if (new_ip && (new_ip->i_nlink == 0))
		set_cflag(COMMIT_Nolink, new_ip);
      out3:
	free_UCSname(&new_dname);
      out2:
	free_UCSname(&old_dname);
      out1:
	if (new_ip && !S_ISDIR(new_ip->i_mode))
		IWRITE_UNLOCK(new_ip);
	/*
	 * Truncating the directory index table is not guaranteed.  It
	 * may need to be done iteratively
	 */
	if (test_cflag(COMMIT_Stale, old_dir)) {
		if (old_dir->i_size > 1)
			jfs_truncate_nolock(old_dir, 0);

		clear_cflag(COMMIT_Stale, old_dir);
	}

	jfs_info("jfs_rename: returning %d", rc);
	return rc;
}


/*
 * NAME:	jfs_mknod
 *
 * FUNCTION:	Create a special file (device)
 */
static int jfs_mknod(struct inode *dir, struct dentry *dentry,
		umode_t mode, dev_t rdev)
{
	struct jfs_inode_info *jfs_ip;
	struct btstack btstack;
	struct component_name dname;
	ino_t ino;
	struct inode *ip;
	struct inode *iplist[2];
	int rc;
	tid_t tid;
	struct tblock *tblk;

	if (!new_valid_dev(rdev))
		return -EINVAL;

	jfs_info("jfs_mknod: %pd", dentry);

	dquot_initialize(dir);

	if ((rc = get_UCSname(&dname, dentry)))
		goto out;

	ip = ialloc(dir, mode);
	if (IS_ERR(ip)) {
		rc = PTR_ERR(ip);
		goto out1;
	}
	jfs_ip = JFS_IP(ip);

	tid = txBegin(dir->i_sb, 0);

	mutex_lock_nested(&JFS_IP(dir)->commit_mutex, COMMIT_MUTEX_PARENT);
	mutex_lock_nested(&JFS_IP(ip)->commit_mutex, COMMIT_MUTEX_CHILD);

	rc = jfs_init_acl(tid, ip, dir);
	if (rc)
		goto out3;

	rc = jfs_init_security(tid, ip, dir, &dentry->d_name);
	if (rc) {
		txAbort(tid, 0);
		goto out3;
	}

	if ((rc = dtSearch(dir, &dname, &ino, &btstack, JFS_CREATE))) {
		txAbort(tid, 0);
		goto out3;
	}

	tblk = tid_to_tblock(tid);
	tblk->xflag |= COMMIT_CREATE;
	tblk->ino = ip->i_ino;
	tblk->u.ixpxd = JFS_IP(ip)->ixpxd;

	ino = ip->i_ino;
	if ((rc = dtInsert(tid, dir, &dname, &ino, &btstack))) {
		txAbort(tid, 0);
		goto out3;
	}

	ip->i_op = &jfs_file_inode_operations;
	jfs_ip->dev = new_encode_dev(rdev);
	init_special_inode(ip, ip->i_mode, rdev);

	mark_inode_dirty(ip);

	dir->i_ctime = dir->i_mtime = CURRENT_TIME;

	mark_inode_dirty(dir);

	iplist[0] = dir;
	iplist[1] = ip;
	rc = txCommit(tid, 2, iplist, 0);

      out3:
	txEnd(tid);
	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	mutex_unlock(&JFS_IP(dir)->commit_mutex);
	if (rc) {
		free_ea_wmap(ip);
		clear_nlink(ip);
		unlock_new_inode(ip);
		iput(ip);
	} else {
		unlock_new_inode(ip);
		d_instantiate(dentry, ip);
	}

      out1:
	free_UCSname(&dname);

      out:
	jfs_info("jfs_mknod: returning %d", rc);
	return rc;
}

static struct dentry *jfs_lookup(struct inode *dip, struct dentry *dentry, unsigned int flags)
{
	struct btstack btstack;
	ino_t inum;
	struct inode *ip;
	struct component_name key;
	int rc;

	jfs_info("jfs_lookup: name = %pd", dentry);

	if ((rc = get_UCSname(&key, dentry)))
		return ERR_PTR(rc);
	rc = dtSearch(dip, &key, &inum, &btstack, JFS_LOOKUP);
	free_UCSname(&key);
	if (rc == -ENOENT) {
		ip = NULL;
	} else if (rc) {
		jfs_err("jfs_lookup: dtSearch returned %d", rc);
		ip = ERR_PTR(rc);
	} else {
		ip = jfs_iget(dip->i_sb, inum);
		if (IS_ERR(ip))
			jfs_err("jfs_lookup: iget failed on inum %d", (uint)inum);
	}

	return d_splice_alias(ip, dentry);
}

static struct inode *jfs_nfs_get_inode(struct super_block *sb,
		u64 ino, u32 generation)
{
	struct inode *inode;

	if (ino == 0)
		return ERR_PTR(-ESTALE);
	inode = jfs_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

struct dentry *jfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    jfs_nfs_get_inode);
}

struct dentry *jfs_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    jfs_nfs_get_inode);
}

struct dentry *jfs_get_parent(struct dentry *dentry)
{
	unsigned long parent_ino;

	parent_ino =
		le32_to_cpu(JFS_IP(dentry->d_inode)->i_dtroot.header.idotdot);

	return d_obtain_alias(jfs_iget(dentry->d_inode->i_sb, parent_ino));
}

const struct inode_operations jfs_dir_inode_operations = {
	.create		= jfs_create,
	.lookup		= jfs_lookup,
	.link		= jfs_link,
	.unlink		= jfs_unlink,
	.symlink	= jfs_symlink,
	.mkdir		= jfs_mkdir,
	.rmdir		= jfs_rmdir,
	.mknod		= jfs_mknod,
	.rename		= jfs_rename,
	.setxattr	= jfs_setxattr,
	.getxattr	= jfs_getxattr,
	.listxattr	= jfs_listxattr,
	.removexattr	= jfs_removexattr,
	.setattr	= jfs_setattr,
#ifdef CONFIG_JFS_POSIX_ACL
	.get_acl	= jfs_get_acl,
	.set_acl	= jfs_set_acl,
#endif
};

const struct file_operations jfs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= jfs_readdir,
	.fsync		= jfs_fsync,
	.unlocked_ioctl = jfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= jfs_compat_ioctl,
#endif
	.llseek		= generic_file_llseek,
};

static int jfs_ci_hash(const struct dentry *dir, struct qstr *this)
{
	unsigned long hash;
	int i;

	hash = init_name_hash();
	for (i=0; i < this->len; i++)
		hash = partial_name_hash(tolower(this->name[i]), hash);
	this->hash = end_name_hash(hash);

	return 0;
}

static int jfs_ci_compare(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	int i, result = 1;

	if (len != name->len)
		goto out;
	for (i=0; i < len; i++) {
		if (tolower(str[i]) != tolower(name->name[i]))
			goto out;
	}
	result = 0;
out:
	return result;
}

static int jfs_ci_revalidate(struct dentry *dentry, unsigned int flags)
{
	/*
	 * This is not negative dentry. Always valid.
	 *
	 * Note, rename() to existing directory entry will have ->d_inode,
	 * and will use existing name which isn't specified name by user.
	 *
	 * We may be able to drop this positive dentry here. But dropping
	 * positive dentry isn't good idea. So it's unsupported like
	 * rename("filename", "FILENAME") for now.
	 */
	if (dentry->d_inode)
		return 1;

	/*
	 * This may be nfsd (or something), anyway, we can't see the
	 * intent of this. So, since this can be for creation, drop it.
	 */
	if (!flags)
		return 0;

	/*
	 * Drop the negative dentry, in order to make sure to use the
	 * case sensitive name which is specified by user if this is
	 * for creation.
	 */
	if (flags & (LOOKUP_CREATE | LOOKUP_RENAME_TARGET))
		return 0;
	return 1;
}

const struct dentry_operations jfs_ci_dentry_operations =
{
	.d_hash = jfs_ci_hash,
	.d_compare = jfs_ci_compare,
	.d_revalidate = jfs_ci_revalidate,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/namei.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * Module: jfs_mount.c
 *
 * note: file system in transition to aggregate/fileset:
 *
 * file system mount is interpreted as the mount of aggregate,
 * if not already mounted, and mount of the single/only fileset in
 * the aggregate;
 *
 * a file system/aggregate is represented by an internal inode
 * (aka mount inode) initialized with aggregate superblock;
 * each vfs represents a fileset, and points to its "fileset inode
 * allocation map inode" (aka fileset inode):
 * (an aggregate itself is structured recursively as a filset:
 * an internal vfs is constructed and points to its "fileset inode
 * allocation map inode" (aka aggregate inode) where each inode
 * represents a fileset inode) so that inode number is mapped to
 * on-disk inode in uniform way at both aggregate and fileset level;
 *
 * each vnode/inode of a fileset is linked to its vfs (to facilitate
 * per fileset inode operations, e.g., unmount of a fileset, etc.);
 * each inode points to the mount inode (to facilitate access to
 * per aggregate information, e.g., block size, etc.) as well as
 * its file set inode.
 *
 *   aggregate
 *   ipmnt
 *   mntvfs -> fileset ipimap+ -> aggregate ipbmap -> aggregate ipaimap;
 *             fileset vfs     -> vp(1) <-> ... <-> vp(n) <->vproot;
 */

// #include <linux/fs.h>
// #include <linux/buffer_head.h>

// #include "jfs_incore.h"
// #include "jfs_filsys.h"
// #include "jfs_superblock.h"
// #include "jfs_dmap.h"
// #include "jfs_imap.h"
// #include "jfs_metapage.h"
// #include "jfs_debug.h"


/*
 * forward references
 */
static int chkSuper(struct super_block *);
static int logMOUNT(struct super_block *sb);

/*
 * NAME:	jfs_mount(sb)
 *
 * FUNCTION:	vfs_mount()
 *
 * PARAMETER:	sb	- super block
 *
 * RETURN:	-EBUSY	- device already mounted or open for write
 *		-EBUSY	- cvrdvp already mounted;
 *		-EBUSY	- mount table full
 *		-ENOTDIR- cvrdvp not directory on a device mount
 *		-ENXIO	- device open failure
 */
int jfs_mount(struct super_block *sb)
{
	int rc = 0;		/* Return code */
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct inode *ipaimap = NULL;
	struct inode *ipaimap2 = NULL;
	struct inode *ipimap = NULL;
	struct inode *ipbmap = NULL;

	/*
	 * read/validate superblock
	 * (initialize mount inode from the superblock)
	 */
	if ((rc = chkSuper(sb))) {
		goto errout20;
	}

	ipaimap = diReadSpecial(sb, AGGREGATE_I, 0);
	if (ipaimap == NULL) {
		jfs_err("jfs_mount: Failed to read AGGREGATE_I");
		rc = -EIO;
		goto errout20;
	}
	sbi->ipaimap = ipaimap;

	jfs_info("jfs_mount: ipaimap:0x%p", ipaimap);

	/*
	 * initialize aggregate inode allocation map
	 */
	if ((rc = diMount(ipaimap))) {
		jfs_err("jfs_mount: diMount(ipaimap) failed w/rc = %d", rc);
		goto errout21;
	}

	/*
	 * open aggregate block allocation map
	 */
	ipbmap = diReadSpecial(sb, BMAP_I, 0);
	if (ipbmap == NULL) {
		rc = -EIO;
		goto errout22;
	}

	jfs_info("jfs_mount: ipbmap:0x%p", ipbmap);

	sbi->ipbmap = ipbmap;

	/*
	 * initialize aggregate block allocation map
	 */
	if ((rc = dbMount(ipbmap))) {
		jfs_err("jfs_mount: dbMount failed w/rc = %d", rc);
		goto errout22;
	}

	/*
	 * open the secondary aggregate inode allocation map
	 *
	 * This is a duplicate of the aggregate inode allocation map.
	 *
	 * hand craft a vfs in the same fashion as we did to read ipaimap.
	 * By adding INOSPEREXT (32) to the inode number, we are telling
	 * diReadSpecial that we are reading from the secondary aggregate
	 * inode table.  This also creates a unique entry in the inode hash
	 * table.
	 */
	if ((sbi->mntflag & JFS_BAD_SAIT) == 0) {
		ipaimap2 = diReadSpecial(sb, AGGREGATE_I, 1);
		if (!ipaimap2) {
			jfs_err("jfs_mount: Failed to read AGGREGATE_I");
			rc = -EIO;
			goto errout35;
		}
		sbi->ipaimap2 = ipaimap2;

		jfs_info("jfs_mount: ipaimap2:0x%p", ipaimap2);

		/*
		 * initialize secondary aggregate inode allocation map
		 */
		if ((rc = diMount(ipaimap2))) {
			jfs_err("jfs_mount: diMount(ipaimap2) failed, rc = %d",
				rc);
			goto errout35;
		}
	} else
		/* Secondary aggregate inode table is not valid */
		sbi->ipaimap2 = NULL;

	/*
	 *	mount (the only/single) fileset
	 */
	/*
	 * open fileset inode allocation map (aka fileset inode)
	 */
	ipimap = diReadSpecial(sb, FILESYSTEM_I, 0);
	if (ipimap == NULL) {
		jfs_err("jfs_mount: Failed to read FILESYSTEM_I");
		/* open fileset secondary inode allocation map */
		rc = -EIO;
		goto errout40;
	}
	jfs_info("jfs_mount: ipimap:0x%p", ipimap);

	/* map further access of per fileset inodes by the fileset inode */
	sbi->ipimap = ipimap;

	/* initialize fileset inode allocation map */
	if ((rc = diMount(ipimap))) {
		jfs_err("jfs_mount: diMount failed w/rc = %d", rc);
		goto errout41;
	}

	goto out;

	/*
	 *	unwind on error
	 */
      errout41:		/* close fileset inode allocation map inode */
	diFreeSpecial(ipimap);

      errout40:		/* fileset closed */

	/* close secondary aggregate inode allocation map */
	if (ipaimap2) {
		diUnmount(ipaimap2, 1);
		diFreeSpecial(ipaimap2);
	}

      errout35:

	/* close aggregate block allocation map */
	dbUnmount(ipbmap, 1);
	diFreeSpecial(ipbmap);

      errout22:		/* close aggregate inode allocation map */

	diUnmount(ipaimap, 1);

      errout21:		/* close aggregate inodes */
	diFreeSpecial(ipaimap);
      errout20:		/* aggregate closed */

      out:

	if (rc)
		jfs_err("Mount JFS Failure: %d", rc);

	return rc;
}

/*
 * NAME:	jfs_mount_rw(sb, remount)
 *
 * FUNCTION:	Completes read-write mount, or remounts read-only volume
 *		as read-write
 */
int jfs_mount_rw(struct super_block *sb, int remount)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	int rc;

	/*
	 * If we are re-mounting a previously read-only volume, we want to
	 * re-read the inode and block maps, since fsck.jfs may have updated
	 * them.
	 */
	if (remount) {
		if (chkSuper(sb) || (sbi->state != FM_CLEAN))
			return -EINVAL;

		truncate_inode_pages(sbi->ipimap->i_mapping, 0);
		truncate_inode_pages(sbi->ipbmap->i_mapping, 0);
		diUnmount(sbi->ipimap, 1);
		if ((rc = diMount(sbi->ipimap))) {
			jfs_err("jfs_mount_rw: diMount failed!");
			return rc;
		}

		dbUnmount(sbi->ipbmap, 1);
		if ((rc = dbMount(sbi->ipbmap))) {
			jfs_err("jfs_mount_rw: dbMount failed!");
			return rc;
		}
	}

	/*
	 * open/initialize log
	 */
	if ((rc = lmLogOpen(sb)))
		return rc;

	/*
	 * update file system superblock;
	 */
	if ((rc = updateSuper(sb, FM_MOUNT))) {
		jfs_err("jfs_mount: updateSuper failed w/rc = %d", rc);
		lmLogClose(sb);
		return rc;
	}

	/*
	 * write MOUNT log record of the file system
	 */
	logMOUNT(sb);

	return rc;
}

/*
 *	chkSuper()
 *
 * validate the superblock of the file system to be mounted and
 * get the file system parameters.
 *
 * returns
 *	0 with fragsize set if check successful
 *	error code if not successful
 */
static int chkSuper(struct super_block *sb)
{
	int rc = 0;
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct jfs_superblock *j_sb;
	struct buffer_head *bh;
	int AIM_bytesize, AIT_bytesize;
	int expected_AIM_bytesize, expected_AIT_bytesize;
	s64 AIM_byte_addr, AIT_byte_addr, fsckwsp_addr;
	s64 byte_addr_diff0, byte_addr_diff1;
	s32 bsize;

	if ((rc = readSuper(sb, &bh)))
		return rc;
	j_sb = (struct jfs_superblock *)bh->b_data;

	/*
	 * validate superblock
	 */
	/* validate fs signature */
	if (strncmp(j_sb->s_magic, JFS_MAGIC, 4) ||
	    le32_to_cpu(j_sb->s_version) > JFS_VERSION) {
		rc = -EINVAL;
		goto out;
	}

	bsize = le32_to_cpu(j_sb->s_bsize);
#ifdef _JFS_4K
	if (bsize != PSIZE) {
		jfs_err("Currently only 4K block size supported!");
		rc = -EINVAL;
		goto out;
	}
#endif				/* _JFS_4K */

	jfs_info("superblock: flag:0x%08x state:0x%08x size:0x%Lx",
		 le32_to_cpu(j_sb->s_flag), le32_to_cpu(j_sb->s_state),
		 (unsigned long long) le64_to_cpu(j_sb->s_size));

	/* validate the descriptors for Secondary AIM and AIT */
	if ((j_sb->s_flag & cpu_to_le32(JFS_BAD_SAIT)) !=
	    cpu_to_le32(JFS_BAD_SAIT)) {
		expected_AIM_bytesize = 2 * PSIZE;
		AIM_bytesize = lengthPXD(&(j_sb->s_aim2)) * bsize;
		expected_AIT_bytesize = 4 * PSIZE;
		AIT_bytesize = lengthPXD(&(j_sb->s_ait2)) * bsize;
		AIM_byte_addr = addressPXD(&(j_sb->s_aim2)) * bsize;
		AIT_byte_addr = addressPXD(&(j_sb->s_ait2)) * bsize;
		byte_addr_diff0 = AIT_byte_addr - AIM_byte_addr;
		fsckwsp_addr = addressPXD(&(j_sb->s_fsckpxd)) * bsize;
		byte_addr_diff1 = fsckwsp_addr - AIT_byte_addr;
		if ((AIM_bytesize != expected_AIM_bytesize) ||
		    (AIT_bytesize != expected_AIT_bytesize) ||
		    (byte_addr_diff0 != AIM_bytesize) ||
		    (byte_addr_diff1 <= AIT_bytesize))
			j_sb->s_flag |= cpu_to_le32(JFS_BAD_SAIT);
	}

	if ((j_sb->s_flag & cpu_to_le32(JFS_GROUPCOMMIT)) !=
	    cpu_to_le32(JFS_GROUPCOMMIT))
		j_sb->s_flag |= cpu_to_le32(JFS_GROUPCOMMIT);

	/* validate fs state */
	if (j_sb->s_state != cpu_to_le32(FM_CLEAN) &&
	    !(sb->s_flags & MS_RDONLY)) {
		jfs_err("jfs_mount: Mount Failure: File System Dirty.");
		rc = -EINVAL;
		goto out;
	}

	sbi->state = le32_to_cpu(j_sb->s_state);
	sbi->mntflag = le32_to_cpu(j_sb->s_flag);

	/*
	 * JFS always does I/O by 4K pages.  Don't tell the buffer cache
	 * that we use anything else (leave s_blocksize alone).
	 */
	sbi->bsize = bsize;
	sbi->l2bsize = le16_to_cpu(j_sb->s_l2bsize);

	/*
	 * For now, ignore s_pbsize, l2bfactor.  All I/O going through buffer
	 * cache.
	 */
	sbi->nbperpage = PSIZE >> sbi->l2bsize;
	sbi->l2nbperpage = L2PSIZE - sbi->l2bsize;
	sbi->l2niperblk = sbi->l2bsize - L2DISIZE;
	if (sbi->mntflag & JFS_INLINELOG)
		sbi->logpxd = j_sb->s_logpxd;
	else {
		sbi->logdev = new_decode_dev(le32_to_cpu(j_sb->s_logdev));
		memcpy(sbi->uuid, j_sb->s_uuid, sizeof(sbi->uuid));
		memcpy(sbi->loguuid, j_sb->s_loguuid, sizeof(sbi->uuid));
	}
	sbi->fsckpxd = j_sb->s_fsckpxd;
	sbi->ait2 = j_sb->s_ait2;

      out:
	brelse(bh);
	return rc;
}


/*
 *	updateSuper()
 *
 * update synchronously superblock if it is mounted read-write.
 */
int updateSuper(struct super_block *sb, uint state)
{
	struct jfs_superblock *j_sb;
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct buffer_head *bh;
	int rc;

	if (sbi->flag & JFS_NOINTEGRITY) {
		if (state == FM_DIRTY) {
			sbi->p_state = state;
			return 0;
		} else if (state == FM_MOUNT) {
			sbi->p_state = sbi->state;
			state = FM_DIRTY;
		} else if (state == FM_CLEAN) {
			state = sbi->p_state;
		} else
			jfs_err("updateSuper: bad state");
	} else if (sbi->state == FM_DIRTY)
		return 0;

	if ((rc = readSuper(sb, &bh)))
		return rc;

	j_sb = (struct jfs_superblock *)bh->b_data;

	j_sb->s_state = cpu_to_le32(state);
	sbi->state = state;

	if (state == FM_MOUNT) {
		/* record log's dev_t and mount serial number */
		j_sb->s_logdev = cpu_to_le32(new_encode_dev(sbi->log->bdev->bd_dev));
		j_sb->s_logserial = cpu_to_le32(sbi->log->serial);
	} else if (state == FM_CLEAN) {
		/*
		 * If this volume is shared with OS/2, OS/2 will need to
		 * recalculate DASD usage, since we don't deal with it.
		 */
		if (j_sb->s_flag & cpu_to_le32(JFS_DASD_ENABLED))
			j_sb->s_flag |= cpu_to_le32(JFS_DASD_PRIME);
	}

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	return 0;
}


/*
 *	readSuper()
 *
 * read superblock by raw sector address
 */
int readSuper(struct super_block *sb, struct buffer_head **bpp)
{
	/* read in primary superblock */
	*bpp = sb_bread(sb, SUPER1_OFF >> sb->s_blocksize_bits);
	if (*bpp)
		return 0;

	/* read in secondary/replicated superblock */
	*bpp = sb_bread(sb, SUPER2_OFF >> sb->s_blocksize_bits);
	if (*bpp)
		return 0;

	return -EIO;
}


/*
 *	logMOUNT()
 *
 * function: write a MOUNT log record for file system.
 *
 * MOUNT record keeps logredo() from processing log records
 * for this file system past this point in log.
 * it is harmless if mount fails.
 *
 * note: MOUNT record is at aggregate level, not at fileset level,
 * since log records of previous mounts of a fileset
 * (e.g., AFTER record of extent allocation) have to be processed
 * to update block allocation map at aggregate level.
 */
static int logMOUNT(struct super_block *sb)
{
	struct jfs_log *log = JFS_SBI(sb)->log;
	struct lrd lrd;

	lrd.logtid = 0;
	lrd.backchain = 0;
	lrd.type = cpu_to_le16(LOG_MOUNT);
	lrd.length = 0;
	lrd.aggregate = cpu_to_le32(new_encode_dev(sb->s_bdev->bd_dev));
	lmLog(log, NULL, &lrd, NULL);

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_mount.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 *	jfs_umount.c
 *
 * note: file system in transition to aggregate/fileset:
 * (ref. jfs_mount.c)
 *
 * file system unmount is interpreted as mount of the single/only
 * fileset in the aggregate and, if unmount of the last fileset,
 * as unmount of the aggerate;
 */

// #include <linux/fs.h>
// #include "jfs_incore.h"
// #include "jfs_filsys.h"
// #include "jfs_superblock.h"
// #include "jfs_dmap.h"
// #include "jfs_imap.h"
// #include "jfs_metapage.h"
// #include "jfs_debug.h"

/*
 * NAME:	jfs_umount(vfsp, flags, crp)
 *
 * FUNCTION:	vfs_umount()
 *
 * PARAMETERS:	vfsp	- virtual file system pointer
 *		flags	- unmount for shutdown
 *		crp	- credential
 *
 * RETURN :	EBUSY	- device has open files
 */
int jfs_umount(struct super_block *sb)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct inode *ipbmap = sbi->ipbmap;
	struct inode *ipimap = sbi->ipimap;
	struct inode *ipaimap = sbi->ipaimap;
	struct inode *ipaimap2 = sbi->ipaimap2;
	struct jfs_log *log;
	int rc = 0;

	jfs_info("UnMount JFS: sb:0x%p", sb);

	/*
	 *	update superblock and close log
	 *
	 * if mounted read-write and log based recovery was enabled
	 */
	if ((log = sbi->log))
		/*
		 * Wait for outstanding transactions to be written to log:
		 */
		jfs_flush_journal(log, 2);

	/*
	 * close fileset inode allocation map (aka fileset inode)
	 */
	diUnmount(ipimap, 0);

	diFreeSpecial(ipimap);
	sbi->ipimap = NULL;

	/*
	 * close secondary aggregate inode allocation map
	 */
	ipaimap2 = sbi->ipaimap2;
	if (ipaimap2) {
		diUnmount(ipaimap2, 0);
		diFreeSpecial(ipaimap2);
		sbi->ipaimap2 = NULL;
	}

	/*
	 * close aggregate inode allocation map
	 */
	ipaimap = sbi->ipaimap;
	diUnmount(ipaimap, 0);
	diFreeSpecial(ipaimap);
	sbi->ipaimap = NULL;

	/*
	 * close aggregate block allocation map
	 */
	dbUnmount(ipbmap, 0);

	diFreeSpecial(ipbmap);
	sbi->ipimap = NULL;

	/*
	 * Make sure all metadata makes it to disk before we mark
	 * the superblock as clean
	 */
	filemap_write_and_wait(sbi->direct_inode->i_mapping);

	/*
	 * ensure all file system file pages are propagated to their
	 * home blocks on disk (and their in-memory buffer pages are
	 * invalidated) BEFORE updating file system superblock state
	 * (to signify file system is unmounted cleanly, and thus in
	 * consistent state) and log superblock active file system
	 * list (to signify skip logredo()).
	 */
	if (log) {		/* log = NULL if read-only mount */
		updateSuper(sb, FM_CLEAN);

		/*
		 * close log:
		 *
		 * remove file system from log active file system list.
		 */
		rc = lmLogClose(sb);
	}
	jfs_info("UnMount JFS Complete: rc = %d", rc);
	return rc;
}


int jfs_umount_rw(struct super_block *sb)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct jfs_log *log = sbi->log;

	if (!log)
		return 0;

	/*
	 * close log:
	 *
	 * remove file system from log active file system list.
	 */
	jfs_flush_journal(log, 2);

	/*
	 * Make sure all metadata makes it to disk
	 */
	dbSync(sbi->ipbmap);
	diSync(sbi->ipimap);

	/*
	 * Note that we have to do this even if sync_blockdev() will
	 * do exactly the same a few instructions later:  We can't
	 * mark the superblock clean before everything is flushed to
	 * disk.
	 */
	filemap_write_and_wait(sbi->direct_inode->i_mapping);

	updateSuper(sb, FM_CLEAN);

	return lmLogClose(sb);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_umount.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2005
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
/*
 *	jfs_xtree.c: extent allocation descriptor B+-tree manager
 */

// #include <linux/fs.h>
// #include <linux/module.h>
// #include <linux/quotaops.h>
// #include <linux/seq_file.h>
// #include "jfs_incore.h"
// #include "jfs_filsys.h"
// #include "jfs_metapage.h"
// #include "jfs_dmap.h"
// #include "jfs_dinode.h"
// #include "jfs_superblock.h"
// #include "jfs_debug.h"

/*
 * xtree local flag
 */
#define XT_INSERT	0x00000001

/*
 *	xtree key/entry comparison: extent offset
 *
 * return:
 *	-1: k < start of extent
 *	 0: start_of_extent <= k <= end_of_extent
 *	 1: k > end_of_extent
 */
#define XT_CMP(CMP, K, X, OFFSET64)\
{\
	OFFSET64 = offsetXAD(X);\
	(CMP) = ((K) >= OFFSET64 + lengthXAD(X)) ? 1 :\
		((K) < OFFSET64) ? -1 : 0;\
}

/* write a xad entry */
#define XT_PUTENTRY(XAD, FLAG, OFF, LEN, ADDR)\
{\
	(XAD)->flag = (FLAG);\
	XADoffset((XAD), (OFF));\
	XADlength((XAD), (LEN));\
	XADaddress((XAD), (ADDR));\
}

#define XT_PAGE(IP, MP) BT_PAGE(IP, MP, xtpage_t, i_xtroot)

/* get page buffer for specified block address */
/* ToDo: Replace this ugly macro with a function */
#define XT_GETPAGE(IP, BN, MP, SIZE, P, RC)				\
do {									\
	BT_GETPAGE(IP, BN, MP, xtpage_t, SIZE, P, RC, i_xtroot);	\
	if (!(RC)) {							\
		if ((le16_to_cpu((P)->header.nextindex) < XTENTRYSTART) || \
		    (le16_to_cpu((P)->header.nextindex) >		\
		     le16_to_cpu((P)->header.maxentry)) ||		\
		    (le16_to_cpu((P)->header.maxentry) >		\
		     (((BN) == 0) ? XTROOTMAXSLOT : PSIZE >> L2XTSLOTSIZE))) { \
			jfs_error((IP)->i_sb,				\
				  "XT_GETPAGE: xtree page corrupt\n");	\
			BT_PUTPAGE(MP);					\
			MP = NULL;					\
			RC = -EIO;					\
		}							\
	}								\
} while (0)

/* for consistency */
#define XT_PUTPAGE(MP) BT_PUTPAGE(MP)

#define XT_GETSEARCH(IP, LEAF, BN, MP, P, INDEX) \
	BT_GETSEARCH(IP, LEAF, BN, MP, xtpage_t, P, INDEX, i_xtroot)
/* xtree entry parameter descriptor */
struct xtsplit {
	struct metapage *mp;
	s16 index;
	u8 flag;
	s64 off;
	s64 addr;
	int len;
	struct pxdlist *pxdlist;
};


/*
 *	statistics
 */
#ifdef CONFIG_JFS_STATISTICS
static struct {
	uint search;
	uint fastSearch;
	uint split;
} xtStat;
#endif


/*
 * forward references
 */
static int xtSearch(struct inode *ip, s64 xoff, s64 *next, int *cmpp,
		    struct btstack * btstack, int flag);

static int xtSplitUp(tid_t tid,
		     struct inode *ip,
		     struct xtsplit * split, struct btstack * btstack);

static int xtSplitPage(tid_t tid, struct inode *ip, struct xtsplit * split,
		       struct metapage ** rmpp, s64 * rbnp);

static int xtSplitRoot(tid_t tid, struct inode *ip,
		       struct xtsplit * split, struct metapage ** rmpp);

#ifdef _STILL_TO_PORT
static int xtDeleteUp(tid_t tid, struct inode *ip, struct metapage * fmp,
		      xtpage_t * fp, struct btstack * btstack);

static int xtSearchNode(struct inode *ip,
			xad_t * xad,
			int *cmpp, struct btstack * btstack, int flag);

static int xtRelink(tid_t tid, struct inode *ip, xtpage_t * fp);
#endif				/*  _STILL_TO_PORT */

/*
 *	xtLookup()
 *
 * function: map a single page into a physical extent;
 */
int xtLookup(struct inode *ip, s64 lstart,
	     s64 llen, int *pflag, s64 * paddr, s32 * plen, int no_check)
{
	int rc = 0;
	struct btstack btstack;
	int cmp;
	s64 bn;
	struct metapage *mp;
	xtpage_t *p;
	int index;
	xad_t *xad;
	s64 next, size, xoff, xend;
	int xlen;
	s64 xaddr;

	*paddr = 0;
	*plen = llen;

	if (!no_check) {
		/* is lookup offset beyond eof ? */
		size = ((u64) ip->i_size + (JFS_SBI(ip->i_sb)->bsize - 1)) >>
		    JFS_SBI(ip->i_sb)->l2bsize;
		if (lstart >= size)
			return 0;
	}

	/*
	 * search for the xad entry covering the logical extent
	 */
//search:
	if ((rc = xtSearch(ip, lstart, &next, &cmp, &btstack, 0))) {
		jfs_err("xtLookup: xtSearch returned %d", rc);
		return rc;
	}

	/*
	 *	compute the physical extent covering logical extent
	 *
	 * N.B. search may have failed (e.g., hole in sparse file),
	 * and returned the index of the next entry.
	 */
	/* retrieve search result */
	XT_GETSEARCH(ip, btstack.top, bn, mp, p, index);

	/* is xad found covering start of logical extent ?
	 * lstart is a page start address,
	 * i.e., lstart cannot start in a hole;
	 */
	if (cmp) {
		if (next)
			*plen = min(next - lstart, llen);
		goto out;
	}

	/*
	 * lxd covered by xad
	 */
	xad = &p->xad[index];
	xoff = offsetXAD(xad);
	xlen = lengthXAD(xad);
	xend = xoff + xlen;
	xaddr = addressXAD(xad);

	/* initialize new pxd */
	*pflag = xad->flag;
	*paddr = xaddr + (lstart - xoff);
	/* a page must be fully covered by an xad */
	*plen = min(xend - lstart, llen);

      out:
	XT_PUTPAGE(mp);

	return rc;
}

/*
 *	xtSearch()
 *
 * function:	search for the xad entry covering specified offset.
 *
 * parameters:
 *	ip	- file object;
 *	xoff	- extent offset;
 *	nextp	- address of next extent (if any) for search miss
 *	cmpp	- comparison result:
 *	btstack - traverse stack;
 *	flag	- search process flag (XT_INSERT);
 *
 * returns:
 *	btstack contains (bn, index) of search path traversed to the entry.
 *	*cmpp is set to result of comparison with the entry returned.
 *	the page containing the entry is pinned at exit.
 */
static int xtSearch(struct inode *ip, s64 xoff,	s64 *nextp,
		    int *cmpp, struct btstack * btstack, int flag)
{
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	int rc = 0;
	int cmp = 1;		/* init for empty page */
	s64 bn;			/* block number */
	struct metapage *mp;	/* page buffer */
	xtpage_t *p;		/* page */
	xad_t *xad;
	int base, index, lim, btindex;
	struct btframe *btsp;
	int nsplit = 0;		/* number of pages to split */
	s64 t64;
	s64 next = 0;

	INCREMENT(xtStat.search);

	BT_CLR(btstack);

	btstack->nsplit = 0;

	/*
	 *	search down tree from root:
	 *
	 * between two consecutive entries of <Ki, Pi> and <Kj, Pj> of
	 * internal page, child page Pi contains entry with k, Ki <= K < Kj.
	 *
	 * if entry with search key K is not found
	 * internal page search find the entry with largest key Ki
	 * less than K which point to the child page to search;
	 * leaf page search find the entry with smallest key Kj
	 * greater than K so that the returned index is the position of
	 * the entry to be shifted right for insertion of new entry.
	 * for empty tree, search key is greater than any key of the tree.
	 *
	 * by convention, root bn = 0.
	 */
	for (bn = 0;;) {
		/* get/pin the page to search */
		XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		/* try sequential access heuristics with the previous
		 * access entry in target leaf page:
		 * once search narrowed down into the target leaf,
		 * key must either match an entry in the leaf or
		 * key entry does not exist in the tree;
		 */
//fastSearch:
		if ((jfs_ip->btorder & BT_SEQUENTIAL) &&
		    (p->header.flag & BT_LEAF) &&
		    (index = jfs_ip->btindex) <
		    le16_to_cpu(p->header.nextindex)) {
			xad = &p->xad[index];
			t64 = offsetXAD(xad);
			if (xoff < t64 + lengthXAD(xad)) {
				if (xoff >= t64) {
					*cmpp = 0;
					goto out;
				}

				/* stop sequential access heuristics */
				goto binarySearch;
			} else {	/* (t64 + lengthXAD(xad)) <= xoff */

				/* try next sequential entry */
				index++;
				if (index <
				    le16_to_cpu(p->header.nextindex)) {
					xad++;
					t64 = offsetXAD(xad);
					if (xoff < t64 + lengthXAD(xad)) {
						if (xoff >= t64) {
							*cmpp = 0;
							goto out;
						}

						/* miss: key falls between
						 * previous and this entry
						 */
						*cmpp = 1;
						next = t64;
						goto out;
					}

					/* (xoff >= t64 + lengthXAD(xad));
					 * matching entry may be further out:
					 * stop heuristic search
					 */
					/* stop sequential access heuristics */
					goto binarySearch;
				}

				/* (index == p->header.nextindex);
				 * miss: key entry does not exist in
				 * the target leaf/tree
				 */
				*cmpp = 1;
				goto out;
			}

			/*
			 * if hit, return index of the entry found, and
			 * if miss, where new entry with search key is
			 * to be inserted;
			 */
		      out:
			/* compute number of pages to split */
			if (flag & XT_INSERT) {
				if (p->header.nextindex ==	/* little-endian */
				    p->header.maxentry)
					nsplit++;
				else
					nsplit = 0;
				btstack->nsplit = nsplit;
			}

			/* save search result */
			btsp = btstack->top;
			btsp->bn = bn;
			btsp->index = index;
			btsp->mp = mp;

			/* update sequential access heuristics */
			jfs_ip->btindex = index;

			if (nextp)
				*nextp = next;

			INCREMENT(xtStat.fastSearch);
			return 0;
		}

		/* well, ... full search now */
	      binarySearch:
		lim = le16_to_cpu(p->header.nextindex) - XTENTRYSTART;

		/*
		 * binary search with search key K on the current page
		 */
		for (base = XTENTRYSTART; lim; lim >>= 1) {
			index = base + (lim >> 1);

			XT_CMP(cmp, xoff, &p->xad[index], t64);
			if (cmp == 0) {
				/*
				 *	search hit
				 */
				/* search hit - leaf page:
				 * return the entry found
				 */
				if (p->header.flag & BT_LEAF) {
					*cmpp = cmp;

					/* compute number of pages to split */
					if (flag & XT_INSERT) {
						if (p->header.nextindex ==
						    p->header.maxentry)
							nsplit++;
						else
							nsplit = 0;
						btstack->nsplit = nsplit;
					}

					/* save search result */
					btsp = btstack->top;
					btsp->bn = bn;
					btsp->index = index;
					btsp->mp = mp;

					/* init sequential access heuristics */
					btindex = jfs_ip->btindex;
					if (index == btindex ||
					    index == btindex + 1)
						jfs_ip->btorder = BT_SEQUENTIAL;
					else
						jfs_ip->btorder = BT_RANDOM;
					jfs_ip->btindex = index;

					return 0;
				}
				/* search hit - internal page:
				 * descend/search its child page
				 */
				if (index < le16_to_cpu(p->header.nextindex)-1)
					next = offsetXAD(&p->xad[index + 1]);
				goto next;
			}

			if (cmp > 0) {
				base = index + 1;
				--lim;
			}
		}

		/*
		 *	search miss
		 *
		 * base is the smallest index with key (Kj) greater than
		 * search key (K) and may be zero or maxentry index.
		 */
		if (base < le16_to_cpu(p->header.nextindex))
			next = offsetXAD(&p->xad[base]);
		/*
		 * search miss - leaf page:
		 *
		 * return location of entry (base) where new entry with
		 * search key K is to be inserted.
		 */
		if (p->header.flag & BT_LEAF) {
			*cmpp = cmp;

			/* compute number of pages to split */
			if (flag & XT_INSERT) {
				if (p->header.nextindex ==
				    p->header.maxentry)
					nsplit++;
				else
					nsplit = 0;
				btstack->nsplit = nsplit;
			}

			/* save search result */
			btsp = btstack->top;
			btsp->bn = bn;
			btsp->index = base;
			btsp->mp = mp;

			/* init sequential access heuristics */
			btindex = jfs_ip->btindex;
			if (base == btindex || base == btindex + 1)
				jfs_ip->btorder = BT_SEQUENTIAL;
			else
				jfs_ip->btorder = BT_RANDOM;
			jfs_ip->btindex = base;

			if (nextp)
				*nextp = next;

			return 0;
		}

		/*
		 * search miss - non-leaf page:
		 *
		 * if base is non-zero, decrement base by one to get the parent
		 * entry of the child page to search.
		 */
		index = base ? base - 1 : base;

		/*
		 * go down to child page
		 */
	      next:
		/* update number of pages to split */
		if (p->header.nextindex == p->header.maxentry)
			nsplit++;
		else
			nsplit = 0;

		/* push (bn, index) of the parent page/entry */
		if (BT_STACK_FULL(btstack)) {
			jfs_error(ip->i_sb, "stack overrun!\n");
			XT_PUTPAGE(mp);
			return -EIO;
		}
		BT_PUSH(btstack, bn, index);

		/* get the child page block number */
		bn = addressXAD(&p->xad[index]);

		/* unpin the parent page */
		XT_PUTPAGE(mp);
	}
}

/*
 *	xtInsert()
 *
 * function:
 *
 * parameter:
 *	tid	- transaction id;
 *	ip	- file object;
 *	xflag	- extent flag (XAD_NOTRECORDED):
 *	xoff	- extent offset;
 *	xlen	- extent length;
 *	xaddrp	- extent address pointer (in/out):
 *		if (*xaddrp)
 *			caller allocated data extent at *xaddrp;
 *		else
 *			allocate data extent and return its xaddr;
 *	flag	-
 *
 * return:
 */
int xtInsert(tid_t tid,		/* transaction id */
	     struct inode *ip, int xflag, s64 xoff, s32 xlen, s64 * xaddrp,
	     int flag)
{
	int rc = 0;
	s64 xaddr, hint;
	struct metapage *mp;	/* meta-page buffer */
	xtpage_t *p;		/* base B+-tree index page */
	s64 bn;
	int index, nextindex;
	struct btstack btstack;	/* traverse stack */
	struct xtsplit split;	/* split information */
	xad_t *xad;
	int cmp;
	s64 next;
	struct tlock *tlck;
	struct xtlock *xtlck;

	jfs_info("xtInsert: nxoff:0x%lx nxlen:0x%x", (ulong) xoff, xlen);

	/*
	 *	search for the entry location at which to insert:
	 *
	 * xtFastSearch() and xtSearch() both returns (leaf page
	 * pinned, index at which to insert).
	 * n.b. xtSearch() may return index of maxentry of
	 * the full page.
	 */
	if ((rc = xtSearch(ip, xoff, &next, &cmp, &btstack, XT_INSERT)))
		return rc;

	/* retrieve search result */
	XT_GETSEARCH(ip, btstack.top, bn, mp, p, index);

	/* This test must follow XT_GETSEARCH since mp must be valid if
	 * we branch to out: */
	if ((cmp == 0) || (next && (xlen > next - xoff))) {
		rc = -EEXIST;
		goto out;
	}

	/*
	 * allocate data extent requested
	 *
	 * allocation hint: last xad
	 */
	if ((xaddr = *xaddrp) == 0) {
		if (index > XTENTRYSTART) {
			xad = &p->xad[index - 1];
			hint = addressXAD(xad) + lengthXAD(xad) - 1;
		} else
			hint = 0;
		if ((rc = dquot_alloc_block(ip, xlen)))
			goto out;
		if ((rc = dbAlloc(ip, hint, (s64) xlen, &xaddr))) {
			dquot_free_block(ip, xlen);
			goto out;
		}
	}

	/*
	 *	insert entry for new extent
	 */
	xflag |= XAD_NEW;

	/*
	 *	if the leaf page is full, split the page and
	 *	propagate up the router entry for the new page from split
	 *
	 * The xtSplitUp() will insert the entry and unpin the leaf page.
	 */
	nextindex = le16_to_cpu(p->header.nextindex);
	if (nextindex == le16_to_cpu(p->header.maxentry)) {
		split.mp = mp;
		split.index = index;
		split.flag = xflag;
		split.off = xoff;
		split.len = xlen;
		split.addr = xaddr;
		split.pxdlist = NULL;
		if ((rc = xtSplitUp(tid, ip, &split, &btstack))) {
			/* undo data extent allocation */
			if (*xaddrp == 0) {
				dbFree(ip, xaddr, (s64) xlen);
				dquot_free_block(ip, xlen);
			}
			return rc;
		}

		*xaddrp = xaddr;
		return 0;
	}

	/*
	 *	insert the new entry into the leaf page
	 */
	/*
	 * acquire a transaction lock on the leaf page;
	 *
	 * action: xad insertion/extension;
	 */
	BT_MARK_DIRTY(mp, ip);

	/* if insert into middle, shift right remaining entries. */
	if (index < nextindex)
		memmove(&p->xad[index + 1], &p->xad[index],
			(nextindex - index) * sizeof(xad_t));

	/* insert the new entry: mark the entry NEW */
	xad = &p->xad[index];
	XT_PUTENTRY(xad, xflag, xoff, xlen, xaddr);

	/* advance next available entry index */
	le16_add_cpu(&p->header.nextindex, 1);

	/* Don't log it if there are no links to the file */
	if (!test_cflag(COMMIT_Nolink, ip)) {
		tlck = txLock(tid, ip, mp, tlckXTREE | tlckGROW);
		xtlck = (struct xtlock *) & tlck->lock;
		xtlck->lwm.offset =
		    (xtlck->lwm.offset) ? min(index,
					      (int)xtlck->lwm.offset) : index;
		xtlck->lwm.length =
		    le16_to_cpu(p->header.nextindex) - xtlck->lwm.offset;
	}

	*xaddrp = xaddr;

      out:
	/* unpin the leaf page */
	XT_PUTPAGE(mp);

	return rc;
}


/*
 *	xtSplitUp()
 *
 * function:
 *	split full pages as propagating insertion up the tree
 *
 * parameter:
 *	tid	- transaction id;
 *	ip	- file object;
 *	split	- entry parameter descriptor;
 *	btstack - traverse stack from xtSearch()
 *
 * return:
 */
static int
xtSplitUp(tid_t tid,
	  struct inode *ip, struct xtsplit * split, struct btstack * btstack)
{
	int rc = 0;
	struct metapage *smp;
	xtpage_t *sp;		/* split page */
	struct metapage *rmp;
	s64 rbn;		/* new right page block number */
	struct metapage *rcmp;
	xtpage_t *rcp;		/* right child page */
	s64 rcbn;		/* right child page block number */
	int skip;		/* index of entry of insertion */
	int nextindex;		/* next available entry index of p */
	struct btframe *parent;	/* parent page entry on traverse stack */
	xad_t *xad;
	s64 xaddr;
	int xlen;
	int nsplit;		/* number of pages split */
	struct pxdlist pxdlist;
	pxd_t *pxd;
	struct tlock *tlck;
	struct xtlock *xtlck;

	smp = split->mp;
	sp = XT_PAGE(ip, smp);

	/* is inode xtree root extension/inline EA area free ? */
	if ((sp->header.flag & BT_ROOT) && (!S_ISDIR(ip->i_mode)) &&
	    (le16_to_cpu(sp->header.maxentry) < XTROOTMAXSLOT) &&
	    (JFS_IP(ip)->mode2 & INLINEEA)) {
		sp->header.maxentry = cpu_to_le16(XTROOTMAXSLOT);
		JFS_IP(ip)->mode2 &= ~INLINEEA;

		BT_MARK_DIRTY(smp, ip);
		/*
		 * acquire a transaction lock on the leaf page;
		 *
		 * action: xad insertion/extension;
		 */

		/* if insert into middle, shift right remaining entries. */
		skip = split->index;
		nextindex = le16_to_cpu(sp->header.nextindex);
		if (skip < nextindex)
			memmove(&sp->xad[skip + 1], &sp->xad[skip],
				(nextindex - skip) * sizeof(xad_t));

		/* insert the new entry: mark the entry NEW */
		xad = &sp->xad[skip];
		XT_PUTENTRY(xad, split->flag, split->off, split->len,
			    split->addr);

		/* advance next available entry index */
		le16_add_cpu(&sp->header.nextindex, 1);

		/* Don't log it if there are no links to the file */
		if (!test_cflag(COMMIT_Nolink, ip)) {
			tlck = txLock(tid, ip, smp, tlckXTREE | tlckGROW);
			xtlck = (struct xtlock *) & tlck->lock;
			xtlck->lwm.offset = (xtlck->lwm.offset) ?
			    min(skip, (int)xtlck->lwm.offset) : skip;
			xtlck->lwm.length =
			    le16_to_cpu(sp->header.nextindex) -
			    xtlck->lwm.offset;
		}

		return 0;
	}

	/*
	 * allocate new index blocks to cover index page split(s)
	 *
	 * allocation hint: ?
	 */
	if (split->pxdlist == NULL) {
		nsplit = btstack->nsplit;
		split->pxdlist = &pxdlist;
		pxdlist.maxnpxd = pxdlist.npxd = 0;
		pxd = &pxdlist.pxd[0];
		xlen = JFS_SBI(ip->i_sb)->nbperpage;
		for (; nsplit > 0; nsplit--, pxd++) {
			if ((rc = dbAlloc(ip, (s64) 0, (s64) xlen, &xaddr))
			    == 0) {
				PXDaddress(pxd, xaddr);
				PXDlength(pxd, xlen);

				pxdlist.maxnpxd++;

				continue;
			}

			/* undo allocation */

			XT_PUTPAGE(smp);
			return rc;
		}
	}

	/*
	 * Split leaf page <sp> into <sp> and a new right page <rp>.
	 *
	 * The split routines insert the new entry into the leaf page,
	 * and acquire txLock as appropriate.
	 * return <rp> pinned and its block number <rpbn>.
	 */
	rc = (sp->header.flag & BT_ROOT) ?
	    xtSplitRoot(tid, ip, split, &rmp) :
	    xtSplitPage(tid, ip, split, &rmp, &rbn);

	XT_PUTPAGE(smp);

	if (rc)
		return -EIO;
	/*
	 * propagate up the router entry for the leaf page just split
	 *
	 * insert a router entry for the new page into the parent page,
	 * propagate the insert/split up the tree by walking back the stack
	 * of (bn of parent page, index of child page entry in parent page)
	 * that were traversed during the search for the page that split.
	 *
	 * the propagation of insert/split up the tree stops if the root
	 * splits or the page inserted into doesn't have to split to hold
	 * the new entry.
	 *
	 * the parent entry for the split page remains the same, and
	 * a new entry is inserted at its right with the first key and
	 * block number of the new right page.
	 *
	 * There are a maximum of 3 pages pinned at any time:
	 * right child, left parent and right parent (when the parent splits)
	 * to keep the child page pinned while working on the parent.
	 * make sure that all pins are released at exit.
	 */
	while ((parent = BT_POP(btstack)) != NULL) {
		/* parent page specified by stack frame <parent> */

		/* keep current child pages <rcp> pinned */
		rcmp = rmp;
		rcbn = rbn;
		rcp = XT_PAGE(ip, rcmp);

		/*
		 * insert router entry in parent for new right child page <rp>
		 */
		/* get/pin the parent page <sp> */
		XT_GETPAGE(ip, parent->bn, smp, PSIZE, sp, rc);
		if (rc) {
			XT_PUTPAGE(rcmp);
			return rc;
		}

		/*
		 * The new key entry goes ONE AFTER the index of parent entry,
		 * because the split was to the right.
		 */
		skip = parent->index + 1;

		/*
		 * split or shift right remaining entries of the parent page
		 */
		nextindex = le16_to_cpu(sp->header.nextindex);
		/*
		 * parent page is full - split the parent page
		 */
		if (nextindex == le16_to_cpu(sp->header.maxentry)) {
			/* init for parent page split */
			split->mp = smp;
			split->index = skip;	/* index at insert */
			split->flag = XAD_NEW;
			split->off = offsetXAD(&rcp->xad[XTENTRYSTART]);
			split->len = JFS_SBI(ip->i_sb)->nbperpage;
			split->addr = rcbn;

			/* unpin previous right child page */
			XT_PUTPAGE(rcmp);

			/* The split routines insert the new entry,
			 * and acquire txLock as appropriate.
			 * return <rp> pinned and its block number <rpbn>.
			 */
			rc = (sp->header.flag & BT_ROOT) ?
			    xtSplitRoot(tid, ip, split, &rmp) :
			    xtSplitPage(tid, ip, split, &rmp, &rbn);
			if (rc) {
				XT_PUTPAGE(smp);
				return rc;
			}

			XT_PUTPAGE(smp);
			/* keep new child page <rp> pinned */
		}
		/*
		 * parent page is not full - insert in parent page
		 */
		else {
			/*
			 * insert router entry in parent for the right child
			 * page from the first entry of the right child page:
			 */
			/*
			 * acquire a transaction lock on the parent page;
			 *
			 * action: router xad insertion;
			 */
			BT_MARK_DIRTY(smp, ip);

			/*
			 * if insert into middle, shift right remaining entries
			 */
			if (skip < nextindex)
				memmove(&sp->xad[skip + 1], &sp->xad[skip],
					(nextindex -
					 skip) << L2XTSLOTSIZE);

			/* insert the router entry */
			xad = &sp->xad[skip];
			XT_PUTENTRY(xad, XAD_NEW,
				    offsetXAD(&rcp->xad[XTENTRYSTART]),
				    JFS_SBI(ip->i_sb)->nbperpage, rcbn);

			/* advance next available entry index. */
			le16_add_cpu(&sp->header.nextindex, 1);

			/* Don't log it if there are no links to the file */
			if (!test_cflag(COMMIT_Nolink, ip)) {
				tlck = txLock(tid, ip, smp,
					      tlckXTREE | tlckGROW);
				xtlck = (struct xtlock *) & tlck->lock;
				xtlck->lwm.offset = (xtlck->lwm.offset) ?
				    min(skip, (int)xtlck->lwm.offset) : skip;
				xtlck->lwm.length =
				    le16_to_cpu(sp->header.nextindex) -
				    xtlck->lwm.offset;
			}

			/* unpin parent page */
			XT_PUTPAGE(smp);

			/* exit propagate up */
			break;
		}
	}

	/* unpin current right page */
	XT_PUTPAGE(rmp);

	return 0;
}


/*
 *	xtSplitPage()
 *
 * function:
 *	split a full non-root page into
 *	original/split/left page and new right page
 *	i.e., the original/split page remains as left page.
 *
 * parameter:
 *	int		tid,
 *	struct inode	*ip,
 *	struct xtsplit	*split,
 *	struct metapage	**rmpp,
 *	u64		*rbnp,
 *
 * return:
 *	Pointer to page in which to insert or NULL on error.
 */
static int
xtSplitPage(tid_t tid, struct inode *ip,
	    struct xtsplit * split, struct metapage ** rmpp, s64 * rbnp)
{
	int rc = 0;
	struct metapage *smp;
	xtpage_t *sp;
	struct metapage *rmp;
	xtpage_t *rp;		/* new right page allocated */
	s64 rbn;		/* new right page block number */
	struct metapage *mp;
	xtpage_t *p;
	s64 nextbn;
	int skip, maxentry, middle, righthalf, n;
	xad_t *xad;
	struct pxdlist *pxdlist;
	pxd_t *pxd;
	struct tlock *tlck;
	struct xtlock *sxtlck = NULL, *rxtlck = NULL;
	int quota_allocation = 0;

	smp = split->mp;
	sp = XT_PAGE(ip, smp);

	INCREMENT(xtStat.split);

	pxdlist = split->pxdlist;
	pxd = &pxdlist->pxd[pxdlist->npxd];
	pxdlist->npxd++;
	rbn = addressPXD(pxd);

	/* Allocate blocks to quota. */
	rc = dquot_alloc_block(ip, lengthPXD(pxd));
	if (rc)
		goto clean_up;

	quota_allocation += lengthPXD(pxd);

	/*
	 * allocate the new right page for the split
	 */
	rmp = get_metapage(ip, rbn, PSIZE, 1);
	if (rmp == NULL) {
		rc = -EIO;
		goto clean_up;
	}

	jfs_info("xtSplitPage: ip:0x%p smp:0x%p rmp:0x%p", ip, smp, rmp);

	BT_MARK_DIRTY(rmp, ip);
	/*
	 * action: new page;
	 */

	rp = (xtpage_t *) rmp->data;
	rp->header.self = *pxd;
	rp->header.flag = sp->header.flag & BT_TYPE;
	rp->header.maxentry = sp->header.maxentry;	/* little-endian */
	rp->header.nextindex = cpu_to_le16(XTENTRYSTART);

	BT_MARK_DIRTY(smp, ip);
	/* Don't log it if there are no links to the file */
	if (!test_cflag(COMMIT_Nolink, ip)) {
		/*
		 * acquire a transaction lock on the new right page;
		 */
		tlck = txLock(tid, ip, rmp, tlckXTREE | tlckNEW);
		rxtlck = (struct xtlock *) & tlck->lock;
		rxtlck->lwm.offset = XTENTRYSTART;
		/*
		 * acquire a transaction lock on the split page
		 */
		tlck = txLock(tid, ip, smp, tlckXTREE | tlckGROW);
		sxtlck = (struct xtlock *) & tlck->lock;
	}

	/*
	 * initialize/update sibling pointers of <sp> and <rp>
	 */
	nextbn = le64_to_cpu(sp->header.next);
	rp->header.next = cpu_to_le64(nextbn);
	rp->header.prev = cpu_to_le64(addressPXD(&sp->header.self));
	sp->header.next = cpu_to_le64(rbn);

	skip = split->index;

	/*
	 *	sequential append at tail (after last entry of last page)
	 *
	 * if splitting the last page on a level because of appending
	 * a entry to it (skip is maxentry), it's likely that the access is
	 * sequential. adding an empty page on the side of the level is less
	 * work and can push the fill factor much higher than normal.
	 * if we're wrong it's no big deal -  we will do the split the right
	 * way next time.
	 * (it may look like it's equally easy to do a similar hack for
	 * reverse sorted data, that is, split the tree left, but it's not.
	 * Be my guest.)
	 */
	if (nextbn == 0 && skip == le16_to_cpu(sp->header.maxentry)) {
		/*
		 * acquire a transaction lock on the new/right page;
		 *
		 * action: xad insertion;
		 */
		/* insert entry at the first entry of the new right page */
		xad = &rp->xad[XTENTRYSTART];
		XT_PUTENTRY(xad, split->flag, split->off, split->len,
			    split->addr);

		rp->header.nextindex = cpu_to_le16(XTENTRYSTART + 1);

		if (!test_cflag(COMMIT_Nolink, ip)) {
			/* rxtlck->lwm.offset = XTENTRYSTART; */
			rxtlck->lwm.length = 1;
		}

		*rmpp = rmp;
		*rbnp = rbn;

		jfs_info("xtSplitPage: sp:0x%p rp:0x%p", sp, rp);
		return 0;
	}

	/*
	 *	non-sequential insert (at possibly middle page)
	 */

	/*
	 * update previous pointer of old next/right page of <sp>
	 */
	if (nextbn != 0) {
		XT_GETPAGE(ip, nextbn, mp, PSIZE, p, rc);
		if (rc) {
			XT_PUTPAGE(rmp);
			goto clean_up;
		}

		BT_MARK_DIRTY(mp, ip);
		/*
		 * acquire a transaction lock on the next page;
		 *
		 * action:sibling pointer update;
		 */
		if (!test_cflag(COMMIT_Nolink, ip))
			tlck = txLock(tid, ip, mp, tlckXTREE | tlckRELINK);

		p->header.prev = cpu_to_le64(rbn);

		/* sibling page may have been updated previously, or
		 * it may be updated later;
		 */

		XT_PUTPAGE(mp);
	}

	/*
	 * split the data between the split and new/right pages
	 */
	maxentry = le16_to_cpu(sp->header.maxentry);
	middle = maxentry >> 1;
	righthalf = maxentry - middle;

	/*
	 * skip index in old split/left page - insert into left page:
	 */
	if (skip <= middle) {
		/* move right half of split page to the new right page */
		memmove(&rp->xad[XTENTRYSTART], &sp->xad[middle],
			righthalf << L2XTSLOTSIZE);

		/* shift right tail of left half to make room for new entry */
		if (skip < middle)
			memmove(&sp->xad[skip + 1], &sp->xad[skip],
				(middle - skip) << L2XTSLOTSIZE);

		/* insert new entry */
		xad = &sp->xad[skip];
		XT_PUTENTRY(xad, split->flag, split->off, split->len,
			    split->addr);

		/* update page header */
		sp->header.nextindex = cpu_to_le16(middle + 1);
		if (!test_cflag(COMMIT_Nolink, ip)) {
			sxtlck->lwm.offset = (sxtlck->lwm.offset) ?
			    min(skip, (int)sxtlck->lwm.offset) : skip;
		}

		rp->header.nextindex =
		    cpu_to_le16(XTENTRYSTART + righthalf);
	}
	/*
	 * skip index in new right page - insert into right page:
	 */
	else {
		/* move left head of right half to right page */
		n = skip - middle;
		memmove(&rp->xad[XTENTRYSTART], &sp->xad[middle],
			n << L2XTSLOTSIZE);

		/* insert new entry */
		n += XTENTRYSTART;
		xad = &rp->xad[n];
		XT_PUTENTRY(xad, split->flag, split->off, split->len,
			    split->addr);

		/* move right tail of right half to right page */
		if (skip < maxentry)
			memmove(&rp->xad[n + 1], &sp->xad[skip],
				(maxentry - skip) << L2XTSLOTSIZE);

		/* update page header */
		sp->header.nextindex = cpu_to_le16(middle);
		if (!test_cflag(COMMIT_Nolink, ip)) {
			sxtlck->lwm.offset = (sxtlck->lwm.offset) ?
			    min(middle, (int)sxtlck->lwm.offset) : middle;
		}

		rp->header.nextindex = cpu_to_le16(XTENTRYSTART +
						   righthalf + 1);
	}

	if (!test_cflag(COMMIT_Nolink, ip)) {
		sxtlck->lwm.length = le16_to_cpu(sp->header.nextindex) -
		    sxtlck->lwm.offset;

		/* rxtlck->lwm.offset = XTENTRYSTART; */
		rxtlck->lwm.length = le16_to_cpu(rp->header.nextindex) -
		    XTENTRYSTART;
	}

	*rmpp = rmp;
	*rbnp = rbn;

	jfs_info("xtSplitPage: sp:0x%p rp:0x%p", sp, rp);
	return rc;

      clean_up:

	/* Rollback quota allocation. */
	if (quota_allocation)
		dquot_free_block(ip, quota_allocation);

	return (rc);
}


/*
 *	xtSplitRoot()
 *
 * function:
 *	split the full root page into original/root/split page and new
 *	right page
 *	i.e., root remains fixed in tree anchor (inode) and the root is
 *	copied to a single new right child page since root page <<
 *	non-root page, and the split root page contains a single entry
 *	for the new right child page.
 *
 * parameter:
 *	int		tid,
 *	struct inode	*ip,
 *	struct xtsplit	*split,
 *	struct metapage	**rmpp)
 *
 * return:
 *	Pointer to page in which to insert or NULL on error.
 */
static int
xtSplitRoot(tid_t tid,
	    struct inode *ip, struct xtsplit * split, struct metapage ** rmpp)
{
	xtpage_t *sp;
	struct metapage *rmp;
	xtpage_t *rp;
	s64 rbn;
	int skip, nextindex;
	xad_t *xad;
	pxd_t *pxd;
	struct pxdlist *pxdlist;
	struct tlock *tlck;
	struct xtlock *xtlck;
	int rc;

	sp = &JFS_IP(ip)->i_xtroot;

	INCREMENT(xtStat.split);

	/*
	 *	allocate a single (right) child page
	 */
	pxdlist = split->pxdlist;
	pxd = &pxdlist->pxd[pxdlist->npxd];
	pxdlist->npxd++;
	rbn = addressPXD(pxd);
	rmp = get_metapage(ip, rbn, PSIZE, 1);
	if (rmp == NULL)
		return -EIO;

	/* Allocate blocks to quota. */
	rc = dquot_alloc_block(ip, lengthPXD(pxd));
	if (rc) {
		release_metapage(rmp);
		return rc;
	}

	jfs_info("xtSplitRoot: ip:0x%p rmp:0x%p", ip, rmp);

	/*
	 * acquire a transaction lock on the new right page;
	 *
	 * action: new page;
	 */
	BT_MARK_DIRTY(rmp, ip);

	rp = (xtpage_t *) rmp->data;
	rp->header.flag =
	    (sp->header.flag & BT_LEAF) ? BT_LEAF : BT_INTERNAL;
	rp->header.self = *pxd;
	rp->header.nextindex = cpu_to_le16(XTENTRYSTART);
	rp->header.maxentry = cpu_to_le16(PSIZE >> L2XTSLOTSIZE);

	/* initialize sibling pointers */
	rp->header.next = 0;
	rp->header.prev = 0;

	/*
	 * copy the in-line root page into new right page extent
	 */
	nextindex = le16_to_cpu(sp->header.maxentry);
	memmove(&rp->xad[XTENTRYSTART], &sp->xad[XTENTRYSTART],
		(nextindex - XTENTRYSTART) << L2XTSLOTSIZE);

	/*
	 * insert the new entry into the new right/child page
	 * (skip index in the new right page will not change)
	 */
	skip = split->index;
	/* if insert into middle, shift right remaining entries */
	if (skip != nextindex)
		memmove(&rp->xad[skip + 1], &rp->xad[skip],
			(nextindex - skip) * sizeof(xad_t));

	xad = &rp->xad[skip];
	XT_PUTENTRY(xad, split->flag, split->off, split->len, split->addr);

	/* update page header */
	rp->header.nextindex = cpu_to_le16(nextindex + 1);

	if (!test_cflag(COMMIT_Nolink, ip)) {
		tlck = txLock(tid, ip, rmp, tlckXTREE | tlckNEW);
		xtlck = (struct xtlock *) & tlck->lock;
		xtlck->lwm.offset = XTENTRYSTART;
		xtlck->lwm.length = le16_to_cpu(rp->header.nextindex) -
		    XTENTRYSTART;
	}

	/*
	 *	reset the root
	 *
	 * init root with the single entry for the new right page
	 * set the 1st entry offset to 0, which force the left-most key
	 * at any level of the tree to be less than any search key.
	 */
	/*
	 * acquire a transaction lock on the root page (in-memory inode);
	 *
	 * action: root split;
	 */
	BT_MARK_DIRTY(split->mp, ip);

	xad = &sp->xad[XTENTRYSTART];
	XT_PUTENTRY(xad, XAD_NEW, 0, JFS_SBI(ip->i_sb)->nbperpage, rbn);

	/* update page header of root */
	sp->header.flag &= ~BT_LEAF;
	sp->header.flag |= BT_INTERNAL;

	sp->header.nextindex = cpu_to_le16(XTENTRYSTART + 1);

	if (!test_cflag(COMMIT_Nolink, ip)) {
		tlck = txLock(tid, ip, split->mp, tlckXTREE | tlckGROW);
		xtlck = (struct xtlock *) & tlck->lock;
		xtlck->lwm.offset = XTENTRYSTART;
		xtlck->lwm.length = 1;
	}

	*rmpp = rmp;

	jfs_info("xtSplitRoot: sp:0x%p rp:0x%p", sp, rp);
	return 0;
}


/*
 *	xtExtend()
 *
 * function: extend in-place;
 *
 * note: existing extent may or may not have been committed.
 * caller is responsible for pager buffer cache update, and
 * working block allocation map update;
 * update pmap: alloc whole extended extent;
 */
int xtExtend(tid_t tid,		/* transaction id */
	     struct inode *ip, s64 xoff,	/* delta extent offset */
	     s32 xlen,		/* delta extent length */
	     int flag)
{
	int rc = 0;
	int cmp;
	struct metapage *mp;	/* meta-page buffer */
	xtpage_t *p;		/* base B+-tree index page */
	s64 bn;
	int index, nextindex, len;
	struct btstack btstack;	/* traverse stack */
	struct xtsplit split;	/* split information */
	xad_t *xad;
	s64 xaddr;
	struct tlock *tlck;
	struct xtlock *xtlck = NULL;

	jfs_info("xtExtend: nxoff:0x%lx nxlen:0x%x", (ulong) xoff, xlen);

	/* there must exist extent to be extended */
	if ((rc = xtSearch(ip, xoff - 1, NULL, &cmp, &btstack, XT_INSERT)))
		return rc;

	/* retrieve search result */
	XT_GETSEARCH(ip, btstack.top, bn, mp, p, index);

	if (cmp != 0) {
		XT_PUTPAGE(mp);
		jfs_error(ip->i_sb, "xtSearch did not find extent\n");
		return -EIO;
	}

	/* extension must be contiguous */
	xad = &p->xad[index];
	if ((offsetXAD(xad) + lengthXAD(xad)) != xoff) {
		XT_PUTPAGE(mp);
		jfs_error(ip->i_sb, "extension is not contiguous\n");
		return -EIO;
	}

	/*
	 * acquire a transaction lock on the leaf page;
	 *
	 * action: xad insertion/extension;
	 */
	BT_MARK_DIRTY(mp, ip);
	if (!test_cflag(COMMIT_Nolink, ip)) {
		tlck = txLock(tid, ip, mp, tlckXTREE | tlckGROW);
		xtlck = (struct xtlock *) & tlck->lock;
	}

	/* extend will overflow extent ? */
	xlen = lengthXAD(xad) + xlen;
	if ((len = xlen - MAXXLEN) <= 0)
		goto extendOld;

	/*
	 *	extent overflow: insert entry for new extent
	 */
//insertNew:
	xoff = offsetXAD(xad) + MAXXLEN;
	xaddr = addressXAD(xad) + MAXXLEN;
	nextindex = le16_to_cpu(p->header.nextindex);

	/*
	 *	if the leaf page is full, insert the new entry and
	 *	propagate up the router entry for the new page from split
	 *
	 * The xtSplitUp() will insert the entry and unpin the leaf page.
	 */
	if (nextindex == le16_to_cpu(p->header.maxentry)) {
		/* xtSpliUp() unpins leaf pages */
		split.mp = mp;
		split.index = index + 1;
		split.flag = XAD_NEW;
		split.off = xoff;	/* split offset */
		split.len = len;
		split.addr = xaddr;
		split.pxdlist = NULL;
		if ((rc = xtSplitUp(tid, ip, &split, &btstack)))
			return rc;

		/* get back old page */
		XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;
		/*
		 * if leaf root has been split, original root has been
		 * copied to new child page, i.e., original entry now
		 * resides on the new child page;
		 */
		if (p->header.flag & BT_INTERNAL) {
			ASSERT(p->header.nextindex ==
			       cpu_to_le16(XTENTRYSTART + 1));
			xad = &p->xad[XTENTRYSTART];
			bn = addressXAD(xad);
			XT_PUTPAGE(mp);

			/* get new child page */
			XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
			if (rc)
				return rc;

			BT_MARK_DIRTY(mp, ip);
			if (!test_cflag(COMMIT_Nolink, ip)) {
				tlck = txLock(tid, ip, mp, tlckXTREE|tlckGROW);
				xtlck = (struct xtlock *) & tlck->lock;
			}
		}
	}
	/*
	 *	insert the new entry into the leaf page
	 */
	else {
		/* insert the new entry: mark the entry NEW */
		xad = &p->xad[index + 1];
		XT_PUTENTRY(xad, XAD_NEW, xoff, len, xaddr);

		/* advance next available entry index */
		le16_add_cpu(&p->header.nextindex, 1);
	}

	/* get back old entry */
	xad = &p->xad[index];
	xlen = MAXXLEN;

	/*
	 * extend old extent
	 */
      extendOld:
	XADlength(xad, xlen);
	if (!(xad->flag & XAD_NEW))
		xad->flag |= XAD_EXTENDED;

	if (!test_cflag(COMMIT_Nolink, ip)) {
		xtlck->lwm.offset =
		    (xtlck->lwm.offset) ? min(index,
					      (int)xtlck->lwm.offset) : index;
		xtlck->lwm.length =
		    le16_to_cpu(p->header.nextindex) - xtlck->lwm.offset;
	}

	/* unpin the leaf page */
	XT_PUTPAGE(mp);

	return rc;
}

#ifdef _NOTYET
/*
 *	xtTailgate()
 *
 * function: split existing 'tail' extent
 *	(split offset >= start offset of tail extent), and
 *	relocate and extend the split tail half;
 *
 * note: existing extent may or may not have been committed.
 * caller is responsible for pager buffer cache update, and
 * working block allocation map update;
 * update pmap: free old split tail extent, alloc new extent;
 */
int xtTailgate(tid_t tid,		/* transaction id */
	       struct inode *ip, s64 xoff,	/* split/new extent offset */
	       s32 xlen,	/* new extent length */
	       s64 xaddr,	/* new extent address */
	       int flag)
{
	int rc = 0;
	int cmp;
	struct metapage *mp;	/* meta-page buffer */
	xtpage_t *p;		/* base B+-tree index page */
	s64 bn;
	int index, nextindex, llen, rlen;
	struct btstack btstack;	/* traverse stack */
	struct xtsplit split;	/* split information */
	xad_t *xad;
	struct tlock *tlck;
	struct xtlock *xtlck = 0;
	struct tlock *mtlck;
	struct maplock *pxdlock;

/*
printf("xtTailgate: nxoff:0x%lx nxlen:0x%x nxaddr:0x%lx\n",
	(ulong)xoff, xlen, (ulong)xaddr);
*/

	/* there must exist extent to be tailgated */
	if ((rc = xtSearch(ip, xoff, NULL, &cmp, &btstack, XT_INSERT)))
		return rc;

	/* retrieve search result */
	XT_GETSEARCH(ip, btstack.top, bn, mp, p, index);

	if (cmp != 0) {
		XT_PUTPAGE(mp);
		jfs_error(ip->i_sb, "couldn't find extent\n");
		return -EIO;
	}

	/* entry found must be last entry */
	nextindex = le16_to_cpu(p->header.nextindex);
	if (index != nextindex - 1) {
		XT_PUTPAGE(mp);
		jfs_error(ip->i_sb, "the entry found is not the last entry\n");
		return -EIO;
	}

	BT_MARK_DIRTY(mp, ip);
	/*
	 * acquire tlock of the leaf page containing original entry
	 */
	if (!test_cflag(COMMIT_Nolink, ip)) {
		tlck = txLock(tid, ip, mp, tlckXTREE | tlckGROW);
		xtlck = (struct xtlock *) & tlck->lock;
	}

	/* completely replace extent ? */
	xad = &p->xad[index];
/*
printf("xtTailgate: xoff:0x%lx xlen:0x%x xaddr:0x%lx\n",
	(ulong)offsetXAD(xad), lengthXAD(xad), (ulong)addressXAD(xad));
*/
	if ((llen = xoff - offsetXAD(xad)) == 0)
		goto updateOld;

	/*
	 *	partially replace extent: insert entry for new extent
	 */
//insertNew:
	/*
	 *	if the leaf page is full, insert the new entry and
	 *	propagate up the router entry for the new page from split
	 *
	 * The xtSplitUp() will insert the entry and unpin the leaf page.
	 */
	if (nextindex == le16_to_cpu(p->header.maxentry)) {
		/* xtSpliUp() unpins leaf pages */
		split.mp = mp;
		split.index = index + 1;
		split.flag = XAD_NEW;
		split.off = xoff;	/* split offset */
		split.len = xlen;
		split.addr = xaddr;
		split.pxdlist = NULL;
		if ((rc = xtSplitUp(tid, ip, &split, &btstack)))
			return rc;

		/* get back old page */
		XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;
		/*
		 * if leaf root has been split, original root has been
		 * copied to new child page, i.e., original entry now
		 * resides on the new child page;
		 */
		if (p->header.flag & BT_INTERNAL) {
			ASSERT(p->header.nextindex ==
			       cpu_to_le16(XTENTRYSTART + 1));
			xad = &p->xad[XTENTRYSTART];
			bn = addressXAD(xad);
			XT_PUTPAGE(mp);

			/* get new child page */
			XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
			if (rc)
				return rc;

			BT_MARK_DIRTY(mp, ip);
			if (!test_cflag(COMMIT_Nolink, ip)) {
				tlck = txLock(tid, ip, mp, tlckXTREE|tlckGROW);
				xtlck = (struct xtlock *) & tlck->lock;
			}
		}
	}
	/*
	 *	insert the new entry into the leaf page
	 */
	else {
		/* insert the new entry: mark the entry NEW */
		xad = &p->xad[index + 1];
		XT_PUTENTRY(xad, XAD_NEW, xoff, xlen, xaddr);

		/* advance next available entry index */
		le16_add_cpu(&p->header.nextindex, 1);
	}

	/* get back old XAD */
	xad = &p->xad[index];

	/*
	 * truncate/relocate old extent at split offset
	 */
      updateOld:
	/* update dmap for old/committed/truncated extent */
	rlen = lengthXAD(xad) - llen;
	if (!(xad->flag & XAD_NEW)) {
		/* free from PWMAP at commit */
		if (!test_cflag(COMMIT_Nolink, ip)) {
			mtlck = txMaplock(tid, ip, tlckMAP);
			pxdlock = (struct maplock *) & mtlck->lock;
			pxdlock->flag = mlckFREEPXD;
			PXDaddress(&pxdlock->pxd, addressXAD(xad) + llen);
			PXDlength(&pxdlock->pxd, rlen);
			pxdlock->index = 1;
		}
	} else
		/* free from WMAP */
		dbFree(ip, addressXAD(xad) + llen, (s64) rlen);

	if (llen)
		/* truncate */
		XADlength(xad, llen);
	else
		/* replace */
		XT_PUTENTRY(xad, XAD_NEW, xoff, xlen, xaddr);

	if (!test_cflag(COMMIT_Nolink, ip)) {
		xtlck->lwm.offset = (xtlck->lwm.offset) ?
		    min(index, (int)xtlck->lwm.offset) : index;
		xtlck->lwm.length = le16_to_cpu(p->header.nextindex) -
		    xtlck->lwm.offset;
	}

	/* unpin the leaf page */
	XT_PUTPAGE(mp);

	return rc;
}
#endif /* _NOTYET */

/*
 *	xtUpdate()
 *
 * function: update XAD;
 *
 *	update extent for allocated_but_not_recorded or
 *	compressed extent;
 *
 * parameter:
 *	nxad	- new XAD;
 *		logical extent of the specified XAD must be completely
 *		contained by an existing XAD;
 */
int xtUpdate(tid_t tid, struct inode *ip, xad_t * nxad)
{				/* new XAD */
	int rc = 0;
	int cmp;
	struct metapage *mp;	/* meta-page buffer */
	xtpage_t *p;		/* base B+-tree index page */
	s64 bn;
	int index0, index, newindex, nextindex;
	struct btstack btstack;	/* traverse stack */
	struct xtsplit split;	/* split information */
	xad_t *xad, *lxad, *rxad;
	int xflag;
	s64 nxoff, xoff;
	int nxlen, xlen, lxlen, rxlen;
	s64 nxaddr, xaddr;
	struct tlock *tlck;
	struct xtlock *xtlck = NULL;
	int newpage = 0;

	/* there must exist extent to be tailgated */
	nxoff = offsetXAD(nxad);
	nxlen = lengthXAD(nxad);
	nxaddr = addressXAD(nxad);

	if ((rc = xtSearch(ip, nxoff, NULL, &cmp, &btstack, XT_INSERT)))
		return rc;

	/* retrieve search result */
	XT_GETSEARCH(ip, btstack.top, bn, mp, p, index0);

	if (cmp != 0) {
		XT_PUTPAGE(mp);
		jfs_error(ip->i_sb, "Could not find extent\n");
		return -EIO;
	}

	BT_MARK_DIRTY(mp, ip);
	/*
	 * acquire tlock of the leaf page containing original entry
	 */
	if (!test_cflag(COMMIT_Nolink, ip)) {
		tlck = txLock(tid, ip, mp, tlckXTREE | tlckGROW);
		xtlck = (struct xtlock *) & tlck->lock;
	}

	xad = &p->xad[index0];
	xflag = xad->flag;
	xoff = offsetXAD(xad);
	xlen = lengthXAD(xad);
	xaddr = addressXAD(xad);

	/* nXAD must be completely contained within XAD */
	if ((xoff > nxoff) ||
	    (nxoff + nxlen > xoff + xlen)) {
		XT_PUTPAGE(mp);
		jfs_error(ip->i_sb,
			  "nXAD in not completely contained within XAD\n");
		return -EIO;
	}

	index = index0;
	newindex = index + 1;
	nextindex = le16_to_cpu(p->header.nextindex);

#ifdef  _JFS_WIP_NOCOALESCE
	if (xoff < nxoff)
		goto updateRight;

	/*
	 * replace XAD with nXAD
	 */
      replace:			/* (nxoff == xoff) */
	if (nxlen == xlen) {
		/* replace XAD with nXAD:recorded */
		*xad = *nxad;
		xad->flag = xflag & ~XAD_NOTRECORDED;

		goto out;
	} else			/* (nxlen < xlen) */
		goto updateLeft;
#endif				/* _JFS_WIP_NOCOALESCE */

/* #ifdef _JFS_WIP_COALESCE */
	if (xoff < nxoff)
		goto coalesceRight;

	/*
	 * coalesce with left XAD
	 */
//coalesceLeft: /* (xoff == nxoff) */
	/* is XAD first entry of page ? */
	if (index == XTENTRYSTART)
		goto replace;

	/* is nXAD logically and physically contiguous with lXAD ? */
	lxad = &p->xad[index - 1];
	lxlen = lengthXAD(lxad);
	if (!(lxad->flag & XAD_NOTRECORDED) &&
	    (nxoff == offsetXAD(lxad) + lxlen) &&
	    (nxaddr == addressXAD(lxad) + lxlen) &&
	    (lxlen + nxlen < MAXXLEN)) {
		/* extend right lXAD */
		index0 = index - 1;
		XADlength(lxad, lxlen + nxlen);

		/* If we just merged two extents together, need to make sure the
		 * right extent gets logged.  If the left one is marked XAD_NEW,
		 * then we know it will be logged.  Otherwise, mark as
		 * XAD_EXTENDED
		 */
		if (!(lxad->flag & XAD_NEW))
			lxad->flag |= XAD_EXTENDED;

		if (xlen > nxlen) {
			/* truncate XAD */
			XADoffset(xad, xoff + nxlen);
			XADlength(xad, xlen - nxlen);
			XADaddress(xad, xaddr + nxlen);
			goto out;
		} else {	/* (xlen == nxlen) */

			/* remove XAD */
			if (index < nextindex - 1)
				memmove(&p->xad[index], &p->xad[index + 1],
					(nextindex - index -
					 1) << L2XTSLOTSIZE);

			p->header.nextindex =
			    cpu_to_le16(le16_to_cpu(p->header.nextindex) -
					1);

			index = index0;
			newindex = index + 1;
			nextindex = le16_to_cpu(p->header.nextindex);
			xoff = nxoff = offsetXAD(lxad);
			xlen = nxlen = lxlen + nxlen;
			xaddr = nxaddr = addressXAD(lxad);
			goto coalesceRight;
		}
	}

	/*
	 * replace XAD with nXAD
	 */
      replace:			/* (nxoff == xoff) */
	if (nxlen == xlen) {
		/* replace XAD with nXAD:recorded */
		*xad = *nxad;
		xad->flag = xflag & ~XAD_NOTRECORDED;

		goto coalesceRight;
	} else			/* (nxlen < xlen) */
		goto updateLeft;

	/*
	 * coalesce with right XAD
	 */
      coalesceRight:		/* (xoff <= nxoff) */
	/* is XAD last entry of page ? */
	if (newindex == nextindex) {
		if (xoff == nxoff)
			goto out;
		goto updateRight;
	}

	/* is nXAD logically and physically contiguous with rXAD ? */
	rxad = &p->xad[index + 1];
	rxlen = lengthXAD(rxad);
	if (!(rxad->flag & XAD_NOTRECORDED) &&
	    (nxoff + nxlen == offsetXAD(rxad)) &&
	    (nxaddr + nxlen == addressXAD(rxad)) &&
	    (rxlen + nxlen < MAXXLEN)) {
		/* extend left rXAD */
		XADoffset(rxad, nxoff);
		XADlength(rxad, rxlen + nxlen);
		XADaddress(rxad, nxaddr);

		/* If we just merged two extents together, need to make sure
		 * the left extent gets logged.  If the right one is marked
		 * XAD_NEW, then we know it will be logged.  Otherwise, mark as
		 * XAD_EXTENDED
		 */
		if (!(rxad->flag & XAD_NEW))
			rxad->flag |= XAD_EXTENDED;

		if (xlen > nxlen)
			/* truncate XAD */
			XADlength(xad, xlen - nxlen);
		else {		/* (xlen == nxlen) */

			/* remove XAD */
			memmove(&p->xad[index], &p->xad[index + 1],
				(nextindex - index - 1) << L2XTSLOTSIZE);

			p->header.nextindex =
			    cpu_to_le16(le16_to_cpu(p->header.nextindex) -
					1);
		}

		goto out;
	} else if (xoff == nxoff)
		goto out;

	if (xoff >= nxoff) {
		XT_PUTPAGE(mp);
		jfs_error(ip->i_sb, "xoff >= nxoff\n");
		return -EIO;
	}
/* #endif _JFS_WIP_COALESCE */

	/*
	 * split XAD into (lXAD, nXAD):
	 *
	 *          |---nXAD--->
	 * --|----------XAD----------|--
	 *   |-lXAD-|
	 */
      updateRight:		/* (xoff < nxoff) */
	/* truncate old XAD as lXAD:not_recorded */
	xad = &p->xad[index];
	XADlength(xad, nxoff - xoff);

	/* insert nXAD:recorded */
	if (nextindex == le16_to_cpu(p->header.maxentry)) {

		/* xtSpliUp() unpins leaf pages */
		split.mp = mp;
		split.index = newindex;
		split.flag = xflag & ~XAD_NOTRECORDED;
		split.off = nxoff;
		split.len = nxlen;
		split.addr = nxaddr;
		split.pxdlist = NULL;
		if ((rc = xtSplitUp(tid, ip, &split, &btstack)))
			return rc;

		/* get back old page */
		XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;
		/*
		 * if leaf root has been split, original root has been
		 * copied to new child page, i.e., original entry now
		 * resides on the new child page;
		 */
		if (p->header.flag & BT_INTERNAL) {
			ASSERT(p->header.nextindex ==
			       cpu_to_le16(XTENTRYSTART + 1));
			xad = &p->xad[XTENTRYSTART];
			bn = addressXAD(xad);
			XT_PUTPAGE(mp);

			/* get new child page */
			XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
			if (rc)
				return rc;

			BT_MARK_DIRTY(mp, ip);
			if (!test_cflag(COMMIT_Nolink, ip)) {
				tlck = txLock(tid, ip, mp, tlckXTREE|tlckGROW);
				xtlck = (struct xtlock *) & tlck->lock;
			}
		} else {
			/* is nXAD on new page ? */
			if (newindex >
			    (le16_to_cpu(p->header.maxentry) >> 1)) {
				newindex =
				    newindex -
				    le16_to_cpu(p->header.nextindex) +
				    XTENTRYSTART;
				newpage = 1;
			}
		}
	} else {
		/* if insert into middle, shift right remaining entries */
		if (newindex < nextindex)
			memmove(&p->xad[newindex + 1], &p->xad[newindex],
				(nextindex - newindex) << L2XTSLOTSIZE);

		/* insert the entry */
		xad = &p->xad[newindex];
		*xad = *nxad;
		xad->flag = xflag & ~XAD_NOTRECORDED;

		/* advance next available entry index. */
		p->header.nextindex =
		    cpu_to_le16(le16_to_cpu(p->header.nextindex) + 1);
	}

	/*
	 * does nXAD force 3-way split ?
	 *
	 *          |---nXAD--->|
	 * --|----------XAD-------------|--
	 *   |-lXAD-|           |-rXAD -|
	 */
	if (nxoff + nxlen == xoff + xlen)
		goto out;

	/* reorient nXAD as XAD for further split XAD into (nXAD, rXAD) */
	if (newpage) {
		/* close out old page */
		if (!test_cflag(COMMIT_Nolink, ip)) {
			xtlck->lwm.offset = (xtlck->lwm.offset) ?
			    min(index0, (int)xtlck->lwm.offset) : index0;
			xtlck->lwm.length =
			    le16_to_cpu(p->header.nextindex) -
			    xtlck->lwm.offset;
		}

		bn = le64_to_cpu(p->header.next);
		XT_PUTPAGE(mp);

		/* get new right page */
		XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		BT_MARK_DIRTY(mp, ip);
		if (!test_cflag(COMMIT_Nolink, ip)) {
			tlck = txLock(tid, ip, mp, tlckXTREE | tlckGROW);
			xtlck = (struct xtlock *) & tlck->lock;
		}

		index0 = index = newindex;
	} else
		index++;

	newindex = index + 1;
	nextindex = le16_to_cpu(p->header.nextindex);
	xlen = xlen - (nxoff - xoff);
	xoff = nxoff;
	xaddr = nxaddr;

	/* recompute split pages */
	if (nextindex == le16_to_cpu(p->header.maxentry)) {
		XT_PUTPAGE(mp);

		if ((rc = xtSearch(ip, nxoff, NULL, &cmp, &btstack, XT_INSERT)))
			return rc;

		/* retrieve search result */
		XT_GETSEARCH(ip, btstack.top, bn, mp, p, index0);

		if (cmp != 0) {
			XT_PUTPAGE(mp);
			jfs_error(ip->i_sb, "xtSearch failed\n");
			return -EIO;
		}

		if (index0 != index) {
			XT_PUTPAGE(mp);
			jfs_error(ip->i_sb, "unexpected value of index\n");
			return -EIO;
		}
	}

	/*
	 * split XAD into (nXAD, rXAD)
	 *
	 *          ---nXAD---|
	 * --|----------XAD----------|--
	 *                    |-rXAD-|
	 */
      updateLeft:		/* (nxoff == xoff) && (nxlen < xlen) */
	/* update old XAD with nXAD:recorded */
	xad = &p->xad[index];
	*xad = *nxad;
	xad->flag = xflag & ~XAD_NOTRECORDED;

	/* insert rXAD:not_recorded */
	xoff = xoff + nxlen;
	xlen = xlen - nxlen;
	xaddr = xaddr + nxlen;
	if (nextindex == le16_to_cpu(p->header.maxentry)) {
/*
printf("xtUpdate.updateLeft.split p:0x%p\n", p);
*/
		/* xtSpliUp() unpins leaf pages */
		split.mp = mp;
		split.index = newindex;
		split.flag = xflag;
		split.off = xoff;
		split.len = xlen;
		split.addr = xaddr;
		split.pxdlist = NULL;
		if ((rc = xtSplitUp(tid, ip, &split, &btstack)))
			return rc;

		/* get back old page */
		XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		/*
		 * if leaf root has been split, original root has been
		 * copied to new child page, i.e., original entry now
		 * resides on the new child page;
		 */
		if (p->header.flag & BT_INTERNAL) {
			ASSERT(p->header.nextindex ==
			       cpu_to_le16(XTENTRYSTART + 1));
			xad = &p->xad[XTENTRYSTART];
			bn = addressXAD(xad);
			XT_PUTPAGE(mp);

			/* get new child page */
			XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
			if (rc)
				return rc;

			BT_MARK_DIRTY(mp, ip);
			if (!test_cflag(COMMIT_Nolink, ip)) {
				tlck = txLock(tid, ip, mp, tlckXTREE|tlckGROW);
				xtlck = (struct xtlock *) & tlck->lock;
			}
		}
	} else {
		/* if insert into middle, shift right remaining entries */
		if (newindex < nextindex)
			memmove(&p->xad[newindex + 1], &p->xad[newindex],
				(nextindex - newindex) << L2XTSLOTSIZE);

		/* insert the entry */
		xad = &p->xad[newindex];
		XT_PUTENTRY(xad, xflag, xoff, xlen, xaddr);

		/* advance next available entry index. */
		p->header.nextindex =
		    cpu_to_le16(le16_to_cpu(p->header.nextindex) + 1);
	}

      out:
	if (!test_cflag(COMMIT_Nolink, ip)) {
		xtlck->lwm.offset = (xtlck->lwm.offset) ?
		    min(index0, (int)xtlck->lwm.offset) : index0;
		xtlck->lwm.length = le16_to_cpu(p->header.nextindex) -
		    xtlck->lwm.offset;
	}

	/* unpin the leaf page */
	XT_PUTPAGE(mp);

	return rc;
}


/*
 *	xtAppend()
 *
 * function: grow in append mode from contiguous region specified ;
 *
 * parameter:
 *	tid		- transaction id;
 *	ip		- file object;
 *	xflag		- extent flag:
 *	xoff		- extent offset;
 *	maxblocks	- max extent length;
 *	xlen		- extent length (in/out);
 *	xaddrp		- extent address pointer (in/out):
 *	flag		-
 *
 * return:
 */
int xtAppend(tid_t tid,		/* transaction id */
	     struct inode *ip, int xflag, s64 xoff, s32 maxblocks,
	     s32 * xlenp,	/* (in/out) */
	     s64 * xaddrp,	/* (in/out) */
	     int flag)
{
	int rc = 0;
	struct metapage *mp;	/* meta-page buffer */
	xtpage_t *p;		/* base B+-tree index page */
	s64 bn, xaddr;
	int index, nextindex;
	struct btstack btstack;	/* traverse stack */
	struct xtsplit split;	/* split information */
	xad_t *xad;
	int cmp;
	struct tlock *tlck;
	struct xtlock *xtlck;
	int nsplit, nblocks, xlen;
	struct pxdlist pxdlist;
	pxd_t *pxd;
	s64 next;

	xaddr = *xaddrp;
	xlen = *xlenp;
	jfs_info("xtAppend: xoff:0x%lx maxblocks:%d xlen:%d xaddr:0x%lx",
		 (ulong) xoff, maxblocks, xlen, (ulong) xaddr);

	/*
	 *	search for the entry location at which to insert:
	 *
	 * xtFastSearch() and xtSearch() both returns (leaf page
	 * pinned, index at which to insert).
	 * n.b. xtSearch() may return index of maxentry of
	 * the full page.
	 */
	if ((rc = xtSearch(ip, xoff, &next, &cmp, &btstack, XT_INSERT)))
		return rc;

	/* retrieve search result */
	XT_GETSEARCH(ip, btstack.top, bn, mp, p, index);

	if (cmp == 0) {
		rc = -EEXIST;
		goto out;
	}

	if (next)
		xlen = min(xlen, (int)(next - xoff));
//insert:
	/*
	 *	insert entry for new extent
	 */
	xflag |= XAD_NEW;

	/*
	 *	if the leaf page is full, split the page and
	 *	propagate up the router entry for the new page from split
	 *
	 * The xtSplitUp() will insert the entry and unpin the leaf page.
	 */
	nextindex = le16_to_cpu(p->header.nextindex);
	if (nextindex < le16_to_cpu(p->header.maxentry))
		goto insertLeaf;

	/*
	 * allocate new index blocks to cover index page split(s)
	 */
	nsplit = btstack.nsplit;
	split.pxdlist = &pxdlist;
	pxdlist.maxnpxd = pxdlist.npxd = 0;
	pxd = &pxdlist.pxd[0];
	nblocks = JFS_SBI(ip->i_sb)->nbperpage;
	for (; nsplit > 0; nsplit--, pxd++, xaddr += nblocks, maxblocks -= nblocks) {
		if ((rc = dbAllocBottomUp(ip, xaddr, (s64) nblocks)) == 0) {
			PXDaddress(pxd, xaddr);
			PXDlength(pxd, nblocks);

			pxdlist.maxnpxd++;

			continue;
		}

		/* undo allocation */

		goto out;
	}

	xlen = min(xlen, maxblocks);

	/*
	 * allocate data extent requested
	 */
	if ((rc = dbAllocBottomUp(ip, xaddr, (s64) xlen)))
		goto out;

	split.mp = mp;
	split.index = index;
	split.flag = xflag;
	split.off = xoff;
	split.len = xlen;
	split.addr = xaddr;
	if ((rc = xtSplitUp(tid, ip, &split, &btstack))) {
		/* undo data extent allocation */
		dbFree(ip, *xaddrp, (s64) * xlenp);

		return rc;
	}

	*xaddrp = xaddr;
	*xlenp = xlen;
	return 0;

	/*
	 *	insert the new entry into the leaf page
	 */
      insertLeaf:
	/*
	 * allocate data extent requested
	 */
	if ((rc = dbAllocBottomUp(ip, xaddr, (s64) xlen)))
		goto out;

	BT_MARK_DIRTY(mp, ip);
	/*
	 * acquire a transaction lock on the leaf page;
	 *
	 * action: xad insertion/extension;
	 */
	tlck = txLock(tid, ip, mp, tlckXTREE | tlckGROW);
	xtlck = (struct xtlock *) & tlck->lock;

	/* insert the new entry: mark the entry NEW */
	xad = &p->xad[index];
	XT_PUTENTRY(xad, xflag, xoff, xlen, xaddr);

	/* advance next available entry index */
	le16_add_cpu(&p->header.nextindex, 1);

	xtlck->lwm.offset =
	    (xtlck->lwm.offset) ? min(index,(int) xtlck->lwm.offset) : index;
	xtlck->lwm.length = le16_to_cpu(p->header.nextindex) -
	    xtlck->lwm.offset;

	*xaddrp = xaddr;
	*xlenp = xlen;

      out:
	/* unpin the leaf page */
	XT_PUTPAGE(mp);

	return rc;
}
#ifdef _STILL_TO_PORT

/* - TBD for defragmentaion/reorganization -
 *
 *	xtDelete()
 *
 * function:
 *	delete the entry with the specified key.
 *
 *	N.B.: whole extent of the entry is assumed to be deleted.
 *
 * parameter:
 *
 * return:
 *	ENOENT: if the entry is not found.
 *
 * exception:
 */
int xtDelete(tid_t tid, struct inode *ip, s64 xoff, s32 xlen, int flag)
{
	int rc = 0;
	struct btstack btstack;
	int cmp;
	s64 bn;
	struct metapage *mp;
	xtpage_t *p;
	int index, nextindex;
	struct tlock *tlck;
	struct xtlock *xtlck;

	/*
	 * find the matching entry; xtSearch() pins the page
	 */
	if ((rc = xtSearch(ip, xoff, NULL, &cmp, &btstack, 0)))
		return rc;

	XT_GETSEARCH(ip, btstack.top, bn, mp, p, index);
	if (cmp) {
		/* unpin the leaf page */
		XT_PUTPAGE(mp);
		return -ENOENT;
	}

	/*
	 * delete the entry from the leaf page
	 */
	nextindex = le16_to_cpu(p->header.nextindex);
	le16_add_cpu(&p->header.nextindex, -1);

	/*
	 * if the leaf page bocome empty, free the page
	 */
	if (p->header.nextindex == cpu_to_le16(XTENTRYSTART))
		return (xtDeleteUp(tid, ip, mp, p, &btstack));

	BT_MARK_DIRTY(mp, ip);
	/*
	 * acquire a transaction lock on the leaf page;
	 *
	 * action:xad deletion;
	 */
	tlck = txLock(tid, ip, mp, tlckXTREE);
	xtlck = (struct xtlock *) & tlck->lock;
	xtlck->lwm.offset =
	    (xtlck->lwm.offset) ? min(index, xtlck->lwm.offset) : index;

	/* if delete from middle, shift left/compact the remaining entries */
	if (index < nextindex - 1)
		memmove(&p->xad[index], &p->xad[index + 1],
			(nextindex - index - 1) * sizeof(xad_t));

	XT_PUTPAGE(mp);

	return 0;
}


/* - TBD for defragmentaion/reorganization -
 *
 *	xtDeleteUp()
 *
 * function:
 *	free empty pages as propagating deletion up the tree
 *
 * parameter:
 *
 * return:
 */
static int
xtDeleteUp(tid_t tid, struct inode *ip,
	   struct metapage * fmp, xtpage_t * fp, struct btstack * btstack)
{
	int rc = 0;
	struct metapage *mp;
	xtpage_t *p;
	int index, nextindex;
	s64 xaddr;
	int xlen;
	struct btframe *parent;
	struct tlock *tlck;
	struct xtlock *xtlck;

	/*
	 * keep root leaf page which has become empty
	 */
	if (fp->header.flag & BT_ROOT) {
		/* keep the root page */
		fp->header.flag &= ~BT_INTERNAL;
		fp->header.flag |= BT_LEAF;
		fp->header.nextindex = cpu_to_le16(XTENTRYSTART);

		/* XT_PUTPAGE(fmp); */

		return 0;
	}

	/*
	 * free non-root leaf page
	 */
	if ((rc = xtRelink(tid, ip, fp))) {
		XT_PUTPAGE(fmp);
		return rc;
	}

	xaddr = addressPXD(&fp->header.self);
	xlen = lengthPXD(&fp->header.self);
	/* free the page extent */
	dbFree(ip, xaddr, (s64) xlen);

	/* free the buffer page */
	discard_metapage(fmp);

	/*
	 * propagate page deletion up the index tree
	 *
	 * If the delete from the parent page makes it empty,
	 * continue all the way up the tree.
	 * stop if the root page is reached (which is never deleted) or
	 * if the entry deletion does not empty the page.
	 */
	while ((parent = BT_POP(btstack)) != NULL) {
		/* get/pin the parent page <sp> */
		XT_GETPAGE(ip, parent->bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		index = parent->index;

		/* delete the entry for the freed child page from parent.
		 */
		nextindex = le16_to_cpu(p->header.nextindex);

		/*
		 * the parent has the single entry being deleted:
		 * free the parent page which has become empty.
		 */
		if (nextindex == 1) {
			if (p->header.flag & BT_ROOT) {
				/* keep the root page */
				p->header.flag &= ~BT_INTERNAL;
				p->header.flag |= BT_LEAF;
				p->header.nextindex =
				    cpu_to_le16(XTENTRYSTART);

				/* XT_PUTPAGE(mp); */

				break;
			} else {
				/* free the parent page */
				if ((rc = xtRelink(tid, ip, p)))
					return rc;

				xaddr = addressPXD(&p->header.self);
				/* free the page extent */
				dbFree(ip, xaddr,
				       (s64) JFS_SBI(ip->i_sb)->nbperpage);

				/* unpin/free the buffer page */
				discard_metapage(mp);

				/* propagate up */
				continue;
			}
		}
		/*
		 * the parent has other entries remaining:
		 * delete the router entry from the parent page.
		 */
		else {
			BT_MARK_DIRTY(mp, ip);
			/*
			 * acquire a transaction lock on the leaf page;
			 *
			 * action:xad deletion;
			 */
			tlck = txLock(tid, ip, mp, tlckXTREE);
			xtlck = (struct xtlock *) & tlck->lock;
			xtlck->lwm.offset =
			    (xtlck->lwm.offset) ? min(index,
						      xtlck->lwm.
						      offset) : index;

			/* if delete from middle,
			 * shift left/compact the remaining entries in the page
			 */
			if (index < nextindex - 1)
				memmove(&p->xad[index], &p->xad[index + 1],
					(nextindex - index -
					 1) << L2XTSLOTSIZE);

			le16_add_cpu(&p->header.nextindex, -1);
			jfs_info("xtDeleteUp(entry): 0x%lx[%d]",
				 (ulong) parent->bn, index);
		}

		/* unpin the parent page */
		XT_PUTPAGE(mp);

		/* exit propagation up */
		break;
	}

	return 0;
}


/*
 * NAME:	xtRelocate()
 *
 * FUNCTION:	relocate xtpage or data extent of regular file;
 *		This function is mainly used by defragfs utility.
 *
 * NOTE:	This routine does not have the logic to handle
 *		uncommitted allocated extent. The caller should call
 *		txCommit() to commit all the allocation before call
 *		this routine.
 */
int
xtRelocate(tid_t tid, struct inode * ip, xad_t * oxad,	/* old XAD */
	   s64 nxaddr,		/* new xaddr */
	   int xtype)
{				/* extent type: XTPAGE or DATAEXT */
	int rc = 0;
	struct tblock *tblk;
	struct tlock *tlck;
	struct xtlock *xtlck;
	struct metapage *mp, *pmp, *lmp, *rmp;	/* meta-page buffer */
	xtpage_t *p, *pp, *rp, *lp;	/* base B+-tree index page */
	xad_t *xad;
	pxd_t *pxd;
	s64 xoff, xsize;
	int xlen;
	s64 oxaddr, sxaddr, dxaddr, nextbn, prevbn;
	cbuf_t *cp;
	s64 offset, nbytes, nbrd, pno;
	int nb, npages, nblks;
	s64 bn;
	int cmp;
	int index;
	struct pxd_lock *pxdlock;
	struct btstack btstack;	/* traverse stack */

	xtype = xtype & EXTENT_TYPE;

	xoff = offsetXAD(oxad);
	oxaddr = addressXAD(oxad);
	xlen = lengthXAD(oxad);

	/* validate extent offset */
	offset = xoff << JFS_SBI(ip->i_sb)->l2bsize;
	if (offset >= ip->i_size)
		return -ESTALE;	/* stale extent */

	jfs_info("xtRelocate: xtype:%d xoff:0x%lx xlen:0x%x xaddr:0x%lx:0x%lx",
		 xtype, (ulong) xoff, xlen, (ulong) oxaddr, (ulong) nxaddr);

	/*
	 *	1. get and validate the parent xtpage/xad entry
	 *	covering the source extent to be relocated;
	 */
	if (xtype == DATAEXT) {
		/* search in leaf entry */
		rc = xtSearch(ip, xoff, NULL, &cmp, &btstack, 0);
		if (rc)
			return rc;

		/* retrieve search result */
		XT_GETSEARCH(ip, btstack.top, bn, pmp, pp, index);

		if (cmp) {
			XT_PUTPAGE(pmp);
			return -ESTALE;
		}

		/* validate for exact match with a single entry */
		xad = &pp->xad[index];
		if (addressXAD(xad) != oxaddr || lengthXAD(xad) != xlen) {
			XT_PUTPAGE(pmp);
			return -ESTALE;
		}
	} else {		/* (xtype == XTPAGE) */

		/* search in internal entry */
		rc = xtSearchNode(ip, oxad, &cmp, &btstack, 0);
		if (rc)
			return rc;

		/* retrieve search result */
		XT_GETSEARCH(ip, btstack.top, bn, pmp, pp, index);

		if (cmp) {
			XT_PUTPAGE(pmp);
			return -ESTALE;
		}

		/* xtSearchNode() validated for exact match with a single entry
		 */
		xad = &pp->xad[index];
	}
	jfs_info("xtRelocate: parent xad entry validated.");

	/*
	 *	2. relocate the extent
	 */
	if (xtype == DATAEXT) {
		/* if the extent is allocated-but-not-recorded
		 * there is no real data to be moved in this extent,
		 */
		if (xad->flag & XAD_NOTRECORDED)
			goto out;
		else
			/* release xtpage for cmRead()/xtLookup() */
			XT_PUTPAGE(pmp);

		/*
		 *	cmRelocate()
		 *
		 * copy target data pages to be relocated;
		 *
		 * data extent must start at page boundary and
		 * multiple of page size (except the last data extent);
		 * read in each page of the source data extent into cbuf,
		 * update the cbuf extent descriptor of the page to be
		 * homeward bound to new dst data extent
		 * copy the data from the old extent to new extent.
		 * copy is essential for compressed files to avoid problems
		 * that can arise if there was a change in compression
		 * algorithms.
		 * it is a good strategy because it may disrupt cache
		 * policy to keep the pages in memory afterwards.
		 */
		offset = xoff << JFS_SBI(ip->i_sb)->l2bsize;
		assert((offset & CM_OFFSET) == 0);
		nbytes = xlen << JFS_SBI(ip->i_sb)->l2bsize;
		pno = offset >> CM_L2BSIZE;
		npages = (nbytes + (CM_BSIZE - 1)) >> CM_L2BSIZE;
/*
		npages = ((offset + nbytes - 1) >> CM_L2BSIZE) -
			  (offset >> CM_L2BSIZE) + 1;
*/
		sxaddr = oxaddr;
		dxaddr = nxaddr;

		/* process the request one cache buffer at a time */
		for (nbrd = 0; nbrd < nbytes; nbrd += nb,
		     offset += nb, pno++, npages--) {
			/* compute page size */
			nb = min(nbytes - nbrd, CM_BSIZE);

			/* get the cache buffer of the page */
			if (rc = cmRead(ip, offset, npages, &cp))
				break;

			assert(addressPXD(&cp->cm_pxd) == sxaddr);
			assert(!cp->cm_modified);

			/* bind buffer with the new extent address */
			nblks = nb >> JFS_IP(ip->i_sb)->l2bsize;
			cmSetXD(ip, cp, pno, dxaddr, nblks);

			/* release the cbuf, mark it as modified */
			cmPut(cp, true);

			dxaddr += nblks;
			sxaddr += nblks;
		}

		/* get back parent page */
		if ((rc = xtSearch(ip, xoff, NULL, &cmp, &btstack, 0)))
			return rc;

		XT_GETSEARCH(ip, btstack.top, bn, pmp, pp, index);
		jfs_info("xtRelocate: target data extent relocated.");
	} else {		/* (xtype == XTPAGE) */

		/*
		 * read in the target xtpage from the source extent;
		 */
		XT_GETPAGE(ip, oxaddr, mp, PSIZE, p, rc);
		if (rc) {
			XT_PUTPAGE(pmp);
			return rc;
		}

		/*
		 * read in sibling pages if any to update sibling pointers;
		 */
		rmp = NULL;
		if (p->header.next) {
			nextbn = le64_to_cpu(p->header.next);
			XT_GETPAGE(ip, nextbn, rmp, PSIZE, rp, rc);
			if (rc) {
				XT_PUTPAGE(pmp);
				XT_PUTPAGE(mp);
				return (rc);
			}
		}

		lmp = NULL;
		if (p->header.prev) {
			prevbn = le64_to_cpu(p->header.prev);
			XT_GETPAGE(ip, prevbn, lmp, PSIZE, lp, rc);
			if (rc) {
				XT_PUTPAGE(pmp);
				XT_PUTPAGE(mp);
				if (rmp)
					XT_PUTPAGE(rmp);
				return (rc);
			}
		}

		/* at this point, all xtpages to be updated are in memory */

		/*
		 * update sibling pointers of sibling xtpages if any;
		 */
		if (lmp) {
			BT_MARK_DIRTY(lmp, ip);
			tlck = txLock(tid, ip, lmp, tlckXTREE | tlckRELINK);
			lp->header.next = cpu_to_le64(nxaddr);
			XT_PUTPAGE(lmp);
		}

		if (rmp) {
			BT_MARK_DIRTY(rmp, ip);
			tlck = txLock(tid, ip, rmp, tlckXTREE | tlckRELINK);
			rp->header.prev = cpu_to_le64(nxaddr);
			XT_PUTPAGE(rmp);
		}

		/*
		 * update the target xtpage to be relocated
		 *
		 * update the self address of the target page
		 * and write to destination extent;
		 * redo image covers the whole xtpage since it is new page
		 * to the destination extent;
		 * update of bmap for the free of source extent
		 * of the target xtpage itself:
		 * update of bmap for the allocation of destination extent
		 * of the target xtpage itself:
		 * update of bmap for the extents covered by xad entries in
		 * the target xtpage is not necessary since they are not
		 * updated;
		 * if not committed before this relocation,
		 * target page may contain XAD_NEW entries which must
		 * be scanned for bmap update (logredo() always
		 * scan xtpage REDOPAGE image for bmap update);
		 * if committed before this relocation (tlckRELOCATE),
		 * scan may be skipped by commit() and logredo();
		 */
		BT_MARK_DIRTY(mp, ip);
		/* tlckNEW init xtlck->lwm.offset = XTENTRYSTART; */
		tlck = txLock(tid, ip, mp, tlckXTREE | tlckNEW);
		xtlck = (struct xtlock *) & tlck->lock;

		/* update the self address in the xtpage header */
		pxd = &p->header.self;
		PXDaddress(pxd, nxaddr);

		/* linelock for the after image of the whole page */
		xtlck->lwm.length =
		    le16_to_cpu(p->header.nextindex) - xtlck->lwm.offset;

		/* update the buffer extent descriptor of target xtpage */
		xsize = xlen << JFS_SBI(ip->i_sb)->l2bsize;
		bmSetXD(mp, nxaddr, xsize);

		/* unpin the target page to new homeward bound */
		XT_PUTPAGE(mp);
		jfs_info("xtRelocate: target xtpage relocated.");
	}

	/*
	 *	3. acquire maplock for the source extent to be freed;
	 *
	 * acquire a maplock saving the src relocated extent address;
	 * to free of the extent at commit time;
	 */
      out:
	/* if DATAEXT relocation, write a LOG_UPDATEMAP record for
	 * free PXD of the source data extent (logredo() will update
	 * bmap for free of source data extent), and update bmap for
	 * free of the source data extent;
	 */
	if (xtype == DATAEXT)
		tlck = txMaplock(tid, ip, tlckMAP);
	/* if XTPAGE relocation, write a LOG_NOREDOPAGE record
	 * for the source xtpage (logredo() will init NoRedoPage
	 * filter and will also update bmap for free of the source
	 * xtpage), and update bmap for free of the source xtpage;
	 * N.B. We use tlckMAP instead of tlkcXTREE because there
	 *      is no buffer associated with this lock since the buffer
	 *      has been redirected to the target location.
	 */
	else			/* (xtype == XTPAGE) */
		tlck = txMaplock(tid, ip, tlckMAP | tlckRELOCATE);

	pxdlock = (struct pxd_lock *) & tlck->lock;
	pxdlock->flag = mlckFREEPXD;
	PXDaddress(&pxdlock->pxd, oxaddr);
	PXDlength(&pxdlock->pxd, xlen);
	pxdlock->index = 1;

	/*
	 *	4. update the parent xad entry for relocation;
	 *
	 * acquire tlck for the parent entry with XAD_NEW as entry
	 * update which will write LOG_REDOPAGE and update bmap for
	 * allocation of XAD_NEW destination extent;
	 */
	jfs_info("xtRelocate: update parent xad entry.");
	BT_MARK_DIRTY(pmp, ip);
	tlck = txLock(tid, ip, pmp, tlckXTREE | tlckGROW);
	xtlck = (struct xtlock *) & tlck->lock;

	/* update the XAD with the new destination extent; */
	xad = &pp->xad[index];
	xad->flag |= XAD_NEW;
	XADaddress(xad, nxaddr);

	xtlck->lwm.offset = min(index, xtlck->lwm.offset);
	xtlck->lwm.length = le16_to_cpu(pp->header.nextindex) -
	    xtlck->lwm.offset;

	/* unpin the parent xtpage */
	XT_PUTPAGE(pmp);

	return rc;
}


/*
 *	xtSearchNode()
 *
 * function:	search for the internal xad entry covering specified extent.
 *		This function is mainly used by defragfs utility.
 *
 * parameters:
 *	ip	- file object;
 *	xad	- extent to find;
 *	cmpp	- comparison result:
 *	btstack - traverse stack;
 *	flag	- search process flag;
 *
 * returns:
 *	btstack contains (bn, index) of search path traversed to the entry.
 *	*cmpp is set to result of comparison with the entry returned.
 *	the page containing the entry is pinned at exit.
 */
static int xtSearchNode(struct inode *ip, xad_t * xad,	/* required XAD entry */
			int *cmpp, struct btstack * btstack, int flag)
{
	int rc = 0;
	s64 xoff, xaddr;
	int xlen;
	int cmp = 1;		/* init for empty page */
	s64 bn;			/* block number */
	struct metapage *mp;	/* meta-page buffer */
	xtpage_t *p;		/* page */
	int base, index, lim;
	struct btframe *btsp;
	s64 t64;

	BT_CLR(btstack);

	xoff = offsetXAD(xad);
	xlen = lengthXAD(xad);
	xaddr = addressXAD(xad);

	/*
	 *	search down tree from root:
	 *
	 * between two consecutive entries of <Ki, Pi> and <Kj, Pj> of
	 * internal page, child page Pi contains entry with k, Ki <= K < Kj.
	 *
	 * if entry with search key K is not found
	 * internal page search find the entry with largest key Ki
	 * less than K which point to the child page to search;
	 * leaf page search find the entry with smallest key Kj
	 * greater than K so that the returned index is the position of
	 * the entry to be shifted right for insertion of new entry.
	 * for empty tree, search key is greater than any key of the tree.
	 *
	 * by convention, root bn = 0.
	 */
	for (bn = 0;;) {
		/* get/pin the page to search */
		XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;
		if (p->header.flag & BT_LEAF) {
			XT_PUTPAGE(mp);
			return -ESTALE;
		}

		lim = le16_to_cpu(p->header.nextindex) - XTENTRYSTART;

		/*
		 * binary search with search key K on the current page
		 */
		for (base = XTENTRYSTART; lim; lim >>= 1) {
			index = base + (lim >> 1);

			XT_CMP(cmp, xoff, &p->xad[index], t64);
			if (cmp == 0) {
				/*
				 *	search hit
				 *
				 * verify for exact match;
				 */
				if (xaddr == addressXAD(&p->xad[index]) &&
				    xoff == offsetXAD(&p->xad[index])) {
					*cmpp = cmp;

					/* save search result */
					btsp = btstack->top;
					btsp->bn = bn;
					btsp->index = index;
					btsp->mp = mp;

					return 0;
				}

				/* descend/search its child page */
				goto next;
			}

			if (cmp > 0) {
				base = index + 1;
				--lim;
			}
		}

		/*
		 *	search miss - non-leaf page:
		 *
		 * base is the smallest index with key (Kj) greater than
		 * search key (K) and may be zero or maxentry index.
		 * if base is non-zero, decrement base by one to get the parent
		 * entry of the child page to search.
		 */
		index = base ? base - 1 : base;

		/*
		 * go down to child page
		 */
	      next:
		/* get the child page block number */
		bn = addressXAD(&p->xad[index]);

		/* unpin the parent page */
		XT_PUTPAGE(mp);
	}
}


/*
 *	xtRelink()
 *
 * function:
 *	link around a freed page.
 *
 * Parameter:
 *	int		tid,
 *	struct inode	*ip,
 *	xtpage_t	*p)
 *
 * returns:
 */
static int xtRelink(tid_t tid, struct inode *ip, xtpage_t * p)
{
	int rc = 0;
	struct metapage *mp;
	s64 nextbn, prevbn;
	struct tlock *tlck;

	nextbn = le64_to_cpu(p->header.next);
	prevbn = le64_to_cpu(p->header.prev);

	/* update prev pointer of the next page */
	if (nextbn != 0) {
		XT_GETPAGE(ip, nextbn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		/*
		 * acquire a transaction lock on the page;
		 *
		 * action: update prev pointer;
		 */
		BT_MARK_DIRTY(mp, ip);
		tlck = txLock(tid, ip, mp, tlckXTREE | tlckRELINK);

		/* the page may already have been tlock'd */

		p->header.prev = cpu_to_le64(prevbn);

		XT_PUTPAGE(mp);
	}

	/* update next pointer of the previous page */
	if (prevbn != 0) {
		XT_GETPAGE(ip, prevbn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		/*
		 * acquire a transaction lock on the page;
		 *
		 * action: update next pointer;
		 */
		BT_MARK_DIRTY(mp, ip);
		tlck = txLock(tid, ip, mp, tlckXTREE | tlckRELINK);

		/* the page may already have been tlock'd */

		p->header.next = le64_to_cpu(nextbn);

		XT_PUTPAGE(mp);
	}

	return 0;
}
#endif				/*  _STILL_TO_PORT */


/*
 *	xtInitRoot()
 *
 * initialize file root (inline in inode)
 */
void xtInitRoot(tid_t tid, struct inode *ip)
{
	xtpage_t *p;

	/*
	 * acquire a transaction lock on the root
	 *
	 * action:
	 */
	txLock(tid, ip, (struct metapage *) &JFS_IP(ip)->bxflag,
		      tlckXTREE | tlckNEW);
	p = &JFS_IP(ip)->i_xtroot;

	p->header.flag = DXD_INDEX | BT_ROOT | BT_LEAF;
	p->header.nextindex = cpu_to_le16(XTENTRYSTART);

	if (S_ISDIR(ip->i_mode))
		p->header.maxentry = cpu_to_le16(XTROOTINITSLOT_DIR);
	else {
		p->header.maxentry = cpu_to_le16(XTROOTINITSLOT);
		ip->i_size = 0;
	}


	return;
}


/*
 * We can run into a deadlock truncating a file with a large number of
 * xtree pages (large fragmented file).  A robust fix would entail a
 * reservation system where we would reserve a number of metadata pages
 * and tlocks which we would be guaranteed without a deadlock.  Without
 * this, a partial fix is to limit number of metadata pages we will lock
 * in a single transaction.  Currently we will truncate the file so that
 * no more than 50 leaf pages will be locked.  The caller of xtTruncate
 * will be responsible for ensuring that the current transaction gets
 * committed, and that subsequent transactions are created to truncate
 * the file further if needed.
 */
#define MAX_TRUNCATE_LEAVES 50

/*
 *	xtTruncate()
 *
 * function:
 *	traverse for truncation logging backward bottom up;
 *	terminate at the last extent entry at the current subtree
 *	root page covering new down size.
 *	truncation may occur within the last extent entry.
 *
 * parameter:
 *	int		tid,
 *	struct inode	*ip,
 *	s64		newsize,
 *	int		type)	{PWMAP, PMAP, WMAP; DELETE, TRUNCATE}
 *
 * return:
 *
 * note:
 *	PWMAP:
 *	 1. truncate (non-COMMIT_NOLINK file)
 *	    by jfs_truncate() or jfs_open(O_TRUNC):
 *	    xtree is updated;
 *	 2. truncate index table of directory when last entry removed
 *	map update via tlock at commit time;
 *	PMAP:
 *	 Call xtTruncate_pmap instead
 *	WMAP:
 *	 1. remove (free zero link count) on last reference release
 *	    (pmap has been freed at commit zero link count);
 *	 2. truncate (COMMIT_NOLINK file, i.e., tmp file):
 *	    xtree is updated;
 *	 map update directly at truncation time;
 *
 *	if (DELETE)
 *		no LOG_NOREDOPAGE is required (NOREDOFILE is sufficient);
 *	else if (TRUNCATE)
 *		must write LOG_NOREDOPAGE for deleted index page;
 *
 * pages may already have been tlocked by anonymous transactions
 * during file growth (i.e., write) before truncation;
 *
 * except last truncated entry, deleted entries remains as is
 * in the page (nextindex is updated) for other use
 * (e.g., log/update allocation map): this avoid copying the page
 * info but delay free of pages;
 *
 */
s64 xtTruncate(tid_t tid, struct inode *ip, s64 newsize, int flag)
{
	int rc = 0;
	s64 teof;
	struct metapage *mp;
	xtpage_t *p;
	s64 bn;
	int index, nextindex;
	xad_t *xad;
	s64 xoff, xaddr;
	int xlen, len, freexlen;
	struct btstack btstack;
	struct btframe *parent;
	struct tblock *tblk = NULL;
	struct tlock *tlck = NULL;
	struct xtlock *xtlck = NULL;
	struct xdlistlock xadlock;	/* maplock for COMMIT_WMAP */
	struct pxd_lock *pxdlock;		/* maplock for COMMIT_WMAP */
	s64 nfreed;
	int freed, log;
	int locked_leaves = 0;

	/* save object truncation type */
	if (tid) {
		tblk = tid_to_tblock(tid);
		tblk->xflag |= flag;
	}

	nfreed = 0;

	flag &= COMMIT_MAP;
	assert(flag != COMMIT_PMAP);

	if (flag == COMMIT_PWMAP)
		log = 1;
	else {
		log = 0;
		xadlock.flag = mlckFREEXADLIST;
		xadlock.index = 1;
	}

	/*
	 * if the newsize is not an integral number of pages,
	 * the file between newsize and next page boundary will
	 * be cleared.
	 * if truncating into a file hole, it will cause
	 * a full block to be allocated for the logical block.
	 */

	/*
	 * release page blocks of truncated region <teof, eof>
	 *
	 * free the data blocks from the leaf index blocks.
	 * delete the parent index entries corresponding to
	 * the freed child data/index blocks.
	 * free the index blocks themselves which aren't needed
	 * in new sized file.
	 *
	 * index blocks are updated only if the blocks are to be
	 * retained in the new sized file.
	 * if type is PMAP, the data and index pages are NOT
	 * freed, and the data and index blocks are NOT freed
	 * from working map.
	 * (this will allow continued access of data/index of
	 * temporary file (zerolink count file truncated to zero-length)).
	 */
	teof = (newsize + (JFS_SBI(ip->i_sb)->bsize - 1)) >>
	    JFS_SBI(ip->i_sb)->l2bsize;

	/* clear stack */
	BT_CLR(&btstack);

	/*
	 * start with root
	 *
	 * root resides in the inode
	 */
	bn = 0;

	/*
	 * first access of each page:
	 */
      getPage:
	XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
	if (rc)
		return rc;

	/* process entries backward from last index */
	index = le16_to_cpu(p->header.nextindex) - 1;


	/* Since this is the rightmost page at this level, and we may have
	 * already freed a page that was formerly to the right, let's make
	 * sure that the next pointer is zero.
	 */
	if (p->header.next) {
		if (log)
			/*
			 * Make sure this change to the header is logged.
			 * If we really truncate this leaf, the flag
			 * will be changed to tlckTRUNCATE
			 */
			tlck = txLock(tid, ip, mp, tlckXTREE|tlckGROW);
		BT_MARK_DIRTY(mp, ip);
		p->header.next = 0;
	}

	if (p->header.flag & BT_INTERNAL)
		goto getChild;

	/*
	 *	leaf page
	 */
	freed = 0;

	/* does region covered by leaf page precede Teof ? */
	xad = &p->xad[index];
	xoff = offsetXAD(xad);
	xlen = lengthXAD(xad);
	if (teof >= xoff + xlen) {
		XT_PUTPAGE(mp);
		goto getParent;
	}

	/* (re)acquire tlock of the leaf page */
	if (log) {
		if (++locked_leaves > MAX_TRUNCATE_LEAVES) {
			/*
			 * We need to limit the size of the transaction
			 * to avoid exhausting pagecache & tlocks
			 */
			XT_PUTPAGE(mp);
			newsize = (xoff + xlen) << JFS_SBI(ip->i_sb)->l2bsize;
			goto getParent;
		}
		tlck = txLock(tid, ip, mp, tlckXTREE);
		tlck->type = tlckXTREE | tlckTRUNCATE;
		xtlck = (struct xtlock *) & tlck->lock;
		xtlck->hwm.offset = le16_to_cpu(p->header.nextindex) - 1;
	}
	BT_MARK_DIRTY(mp, ip);

	/*
	 * scan backward leaf page entries
	 */
	for (; index >= XTENTRYSTART; index--) {
		xad = &p->xad[index];
		xoff = offsetXAD(xad);
		xlen = lengthXAD(xad);
		xaddr = addressXAD(xad);

		/*
		 * The "data" for a directory is indexed by the block
		 * device's address space.  This metadata must be invalidated
		 * here
		 */
		if (S_ISDIR(ip->i_mode) && (teof == 0))
			invalidate_xad_metapages(ip, *xad);
		/*
		 * entry beyond eof: continue scan of current page
		 *          xad
		 * ---|---=======------->
		 *   eof
		 */
		if (teof < xoff) {
			nfreed += xlen;
			continue;
		}

		/*
		 * (xoff <= teof): last entry to be deleted from page;
		 * If other entries remain in page: keep and update the page.
		 */

		/*
		 * eof == entry_start: delete the entry
		 *           xad
		 * -------|=======------->
		 *       eof
		 *
		 */
		if (teof == xoff) {
			nfreed += xlen;

			if (index == XTENTRYSTART)
				break;

			nextindex = index;
		}
		/*
		 * eof within the entry: truncate the entry.
		 *          xad
		 * -------===|===------->
		 *          eof
		 */
		else if (teof < xoff + xlen) {
			/* update truncated entry */
			len = teof - xoff;
			freexlen = xlen - len;
			XADlength(xad, len);

			/* save pxd of truncated extent in tlck */
			xaddr += len;
			if (log) {	/* COMMIT_PWMAP */
				xtlck->lwm.offset = (xtlck->lwm.offset) ?
				    min(index, (int)xtlck->lwm.offset) : index;
				xtlck->lwm.length = index + 1 -
				    xtlck->lwm.offset;
				xtlck->twm.offset = index;
				pxdlock = (struct pxd_lock *) & xtlck->pxdlock;
				pxdlock->flag = mlckFREEPXD;
				PXDaddress(&pxdlock->pxd, xaddr);
				PXDlength(&pxdlock->pxd, freexlen);
			}
			/* free truncated extent */
			else {	/* COMMIT_WMAP */

				pxdlock = (struct pxd_lock *) & xadlock;
				pxdlock->flag = mlckFREEPXD;
				PXDaddress(&pxdlock->pxd, xaddr);
				PXDlength(&pxdlock->pxd, freexlen);
				txFreeMap(ip, pxdlock, NULL, COMMIT_WMAP);

				/* reset map lock */
				xadlock.flag = mlckFREEXADLIST;
			}

			/* current entry is new last entry; */
			nextindex = index + 1;

			nfreed += freexlen;
		}
		/*
		 * eof beyond the entry:
		 *          xad
		 * -------=======---|--->
		 *                 eof
		 */
		else {		/* (xoff + xlen < teof) */

			nextindex = index + 1;
		}

		if (nextindex < le16_to_cpu(p->header.nextindex)) {
			if (!log) {	/* COMMIT_WAMP */
				xadlock.xdlist = &p->xad[nextindex];
				xadlock.count =
				    le16_to_cpu(p->header.nextindex) -
				    nextindex;
				txFreeMap(ip, (struct maplock *) & xadlock,
					  NULL, COMMIT_WMAP);
			}
			p->header.nextindex = cpu_to_le16(nextindex);
		}

		XT_PUTPAGE(mp);

		/* assert(freed == 0); */
		goto getParent;
	}			/* end scan of leaf page entries */

	freed = 1;

	/*
	 * leaf page become empty: free the page if type != PMAP
	 */
	if (log) {		/* COMMIT_PWMAP */
		/* txCommit() with tlckFREE:
		 * free data extents covered by leaf [XTENTRYSTART:hwm);
		 * invalidate leaf if COMMIT_PWMAP;
		 * if (TRUNCATE), will write LOG_NOREDOPAGE;
		 */
		tlck->type = tlckXTREE | tlckFREE;
	} else {		/* COMMIT_WAMP */

		/* free data extents covered by leaf */
		xadlock.xdlist = &p->xad[XTENTRYSTART];
		xadlock.count =
		    le16_to_cpu(p->header.nextindex) - XTENTRYSTART;
		txFreeMap(ip, (struct maplock *) & xadlock, NULL, COMMIT_WMAP);
	}

	if (p->header.flag & BT_ROOT) {
		p->header.flag &= ~BT_INTERNAL;
		p->header.flag |= BT_LEAF;
		p->header.nextindex = cpu_to_le16(XTENTRYSTART);

		XT_PUTPAGE(mp);	/* debug */
		goto out;
	} else {
		if (log) {	/* COMMIT_PWMAP */
			/* page will be invalidated at tx completion
			 */
			XT_PUTPAGE(mp);
		} else {	/* COMMIT_WMAP */

			if (mp->lid)
				lid_to_tlock(mp->lid)->flag |= tlckFREELOCK;

			/* invalidate empty leaf page */
			discard_metapage(mp);
		}
	}

	/*
	 * the leaf page become empty: delete the parent entry
	 * for the leaf page if the parent page is to be kept
	 * in the new sized file.
	 */

	/*
	 * go back up to the parent page
	 */
      getParent:
	/* pop/restore parent entry for the current child page */
	if ((parent = BT_POP(&btstack)) == NULL)
		/* current page must have been root */
		goto out;

	/* get back the parent page */
	bn = parent->bn;
	XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
	if (rc)
		return rc;

	index = parent->index;

	/*
	 * child page was not empty:
	 */
	if (freed == 0) {
		/* has any entry deleted from parent ? */
		if (index < le16_to_cpu(p->header.nextindex) - 1) {
			/* (re)acquire tlock on the parent page */
			if (log) {	/* COMMIT_PWMAP */
				/* txCommit() with tlckTRUNCATE:
				 * free child extents covered by parent [);
				 */
				tlck = txLock(tid, ip, mp, tlckXTREE);
				xtlck = (struct xtlock *) & tlck->lock;
				if (!(tlck->type & tlckTRUNCATE)) {
					xtlck->hwm.offset =
					    le16_to_cpu(p->header.
							nextindex) - 1;
					tlck->type =
					    tlckXTREE | tlckTRUNCATE;
				}
			} else {	/* COMMIT_WMAP */

				/* free child extents covered by parent */
				xadlock.xdlist = &p->xad[index + 1];
				xadlock.count =
				    le16_to_cpu(p->header.nextindex) -
				    index - 1;
				txFreeMap(ip, (struct maplock *) & xadlock,
					  NULL, COMMIT_WMAP);
			}
			BT_MARK_DIRTY(mp, ip);

			p->header.nextindex = cpu_to_le16(index + 1);
		}
		XT_PUTPAGE(mp);
		goto getParent;
	}

	/*
	 * child page was empty:
	 */
	nfreed += lengthXAD(&p->xad[index]);

	/*
	 * During working map update, child page's tlock must be handled
	 * before parent's.  This is because the parent's tlock will cause
	 * the child's disk space to be marked available in the wmap, so
	 * it's important that the child page be released by that time.
	 *
	 * ToDo:  tlocks should be on doubly-linked list, so we can
	 * quickly remove it and add it to the end.
	 */

	/*
	 * Move parent page's tlock to the end of the tid's tlock list
	 */
	if (log && mp->lid && (tblk->last != mp->lid) &&
	    lid_to_tlock(mp->lid)->tid) {
		lid_t lid = mp->lid;
		struct tlock *prev;

		tlck = lid_to_tlock(lid);

		if (tblk->next == lid)
			tblk->next = tlck->next;
		else {
			for (prev = lid_to_tlock(tblk->next);
			     prev->next != lid;
			     prev = lid_to_tlock(prev->next)) {
				assert(prev->next);
			}
			prev->next = tlck->next;
		}
		lid_to_tlock(tblk->last)->next = lid;
		tlck->next = 0;
		tblk->last = lid;
	}

	/*
	 * parent page become empty: free the page
	 */
	if (index == XTENTRYSTART) {
		if (log) {	/* COMMIT_PWMAP */
			/* txCommit() with tlckFREE:
			 * free child extents covered by parent;
			 * invalidate parent if COMMIT_PWMAP;
			 */
			tlck = txLock(tid, ip, mp, tlckXTREE);
			xtlck = (struct xtlock *) & tlck->lock;
			xtlck->hwm.offset =
			    le16_to_cpu(p->header.nextindex) - 1;
			tlck->type = tlckXTREE | tlckFREE;
		} else {	/* COMMIT_WMAP */

			/* free child extents covered by parent */
			xadlock.xdlist = &p->xad[XTENTRYSTART];
			xadlock.count =
			    le16_to_cpu(p->header.nextindex) -
			    XTENTRYSTART;
			txFreeMap(ip, (struct maplock *) & xadlock, NULL,
				  COMMIT_WMAP);
		}
		BT_MARK_DIRTY(mp, ip);

		if (p->header.flag & BT_ROOT) {
			p->header.flag &= ~BT_INTERNAL;
			p->header.flag |= BT_LEAF;
			p->header.nextindex = cpu_to_le16(XTENTRYSTART);
			if (le16_to_cpu(p->header.maxentry) == XTROOTMAXSLOT) {
				/*
				 * Shrink root down to allow inline
				 * EA (otherwise fsck complains)
				 */
				p->header.maxentry =
				    cpu_to_le16(XTROOTINITSLOT);
				JFS_IP(ip)->mode2 |= INLINEEA;
			}

			XT_PUTPAGE(mp);	/* debug */
			goto out;
		} else {
			if (log) {	/* COMMIT_PWMAP */
				/* page will be invalidated at tx completion
				 */
				XT_PUTPAGE(mp);
			} else {	/* COMMIT_WMAP */

				if (mp->lid)
					lid_to_tlock(mp->lid)->flag |=
						tlckFREELOCK;

				/* invalidate parent page */
				discard_metapage(mp);
			}

			/* parent has become empty and freed:
			 * go back up to its parent page
			 */
			/* freed = 1; */
			goto getParent;
		}
	}
	/*
	 * parent page still has entries for front region;
	 */
	else {
		/* try truncate region covered by preceding entry
		 * (process backward)
		 */
		index--;

		/* go back down to the child page corresponding
		 * to the entry
		 */
		goto getChild;
	}

	/*
	 *	internal page: go down to child page of current entry
	 */
      getChild:
	/* save current parent entry for the child page */
	if (BT_STACK_FULL(&btstack)) {
		jfs_error(ip->i_sb, "stack overrun!\n");
		XT_PUTPAGE(mp);
		return -EIO;
	}
	BT_PUSH(&btstack, bn, index);

	/* get child page */
	xad = &p->xad[index];
	bn = addressXAD(xad);

	/*
	 * first access of each internal entry:
	 */
	/* release parent page */
	XT_PUTPAGE(mp);

	/* process the child page */
	goto getPage;

      out:
	/*
	 * update file resource stat
	 */
	/* set size
	 */
	if (S_ISDIR(ip->i_mode) && !newsize)
		ip->i_size = 1;	/* fsck hates zero-length directories */
	else
		ip->i_size = newsize;

	/* update quota allocation to reflect freed blocks */
	dquot_free_block(ip, nfreed);

	/*
	 * free tlock of invalidated pages
	 */
	if (flag == COMMIT_WMAP)
		txFreelock(ip);

	return newsize;
}


/*
 *	xtTruncate_pmap()
 *
 * function:
 *	Perform truncate to zero length for deleted file, leaving the
 *	the xtree and working map untouched.  This allows the file to
 *	be accessed via open file handles, while the delete of the file
 *	is committed to disk.
 *
 * parameter:
 *	tid_t		tid,
 *	struct inode	*ip,
 *	s64		committed_size)
 *
 * return: new committed size
 *
 * note:
 *
 *	To avoid deadlock by holding too many transaction locks, the
 *	truncation may be broken up into multiple transactions.
 *	The committed_size keeps track of part of the file has been
 *	freed from the pmaps.
 */
s64 xtTruncate_pmap(tid_t tid, struct inode *ip, s64 committed_size)
{
	s64 bn;
	struct btstack btstack;
	int cmp;
	int index;
	int locked_leaves = 0;
	struct metapage *mp;
	xtpage_t *p;
	struct btframe *parent;
	int rc;
	struct tblock *tblk;
	struct tlock *tlck = NULL;
	xad_t *xad;
	int xlen;
	s64 xoff;
	struct xtlock *xtlck = NULL;

	/* save object truncation type */
	tblk = tid_to_tblock(tid);
	tblk->xflag |= COMMIT_PMAP;

	/* clear stack */
	BT_CLR(&btstack);

	if (committed_size) {
		xoff = (committed_size >> JFS_SBI(ip->i_sb)->l2bsize) - 1;
		rc = xtSearch(ip, xoff, NULL, &cmp, &btstack, 0);
		if (rc)
			return rc;

		XT_GETSEARCH(ip, btstack.top, bn, mp, p, index);

		if (cmp != 0) {
			XT_PUTPAGE(mp);
			jfs_error(ip->i_sb, "did not find extent\n");
			return -EIO;
		}
	} else {
		/*
		 * start with root
		 *
		 * root resides in the inode
		 */
		bn = 0;

		/*
		 * first access of each page:
		 */
      getPage:
		XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		/* process entries backward from last index */
		index = le16_to_cpu(p->header.nextindex) - 1;

		if (p->header.flag & BT_INTERNAL)
			goto getChild;
	}

	/*
	 *	leaf page
	 */

	if (++locked_leaves > MAX_TRUNCATE_LEAVES) {
		/*
		 * We need to limit the size of the transaction
		 * to avoid exhausting pagecache & tlocks
		 */
		xad = &p->xad[index];
		xoff = offsetXAD(xad);
		xlen = lengthXAD(xad);
		XT_PUTPAGE(mp);
		return (xoff + xlen) << JFS_SBI(ip->i_sb)->l2bsize;
	}
	tlck = txLock(tid, ip, mp, tlckXTREE);
	tlck->type = tlckXTREE | tlckFREE;
	xtlck = (struct xtlock *) & tlck->lock;
	xtlck->hwm.offset = index;


	XT_PUTPAGE(mp);

	/*
	 * go back up to the parent page
	 */
      getParent:
	/* pop/restore parent entry for the current child page */
	if ((parent = BT_POP(&btstack)) == NULL)
		/* current page must have been root */
		goto out;

	/* get back the parent page */
	bn = parent->bn;
	XT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
	if (rc)
		return rc;

	index = parent->index;

	/*
	 * parent page become empty: free the page
	 */
	if (index == XTENTRYSTART) {
		/* txCommit() with tlckFREE:
		 * free child extents covered by parent;
		 * invalidate parent if COMMIT_PWMAP;
		 */
		tlck = txLock(tid, ip, mp, tlckXTREE);
		xtlck = (struct xtlock *) & tlck->lock;
		xtlck->hwm.offset = le16_to_cpu(p->header.nextindex) - 1;
		tlck->type = tlckXTREE | tlckFREE;

		XT_PUTPAGE(mp);

		if (p->header.flag & BT_ROOT) {

			goto out;
		} else {
			goto getParent;
		}
	}
	/*
	 * parent page still has entries for front region;
	 */
	else
		index--;
	/*
	 *	internal page: go down to child page of current entry
	 */
      getChild:
	/* save current parent entry for the child page */
	if (BT_STACK_FULL(&btstack)) {
		jfs_error(ip->i_sb, "stack overrun!\n");
		XT_PUTPAGE(mp);
		return -EIO;
	}
	BT_PUSH(&btstack, bn, index);

	/* get child page */
	xad = &p->xad[index];
	bn = addressXAD(xad);

	/*
	 * first access of each internal entry:
	 */
	/* release parent page */
	XT_PUTPAGE(mp);

	/* process the child page */
	goto getPage;

      out:

	return 0;
}

#ifdef CONFIG_JFS_STATISTICS
static int jfs_xtstat_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		       "JFS Xtree statistics\n"
		       "====================\n"
		       "searches = %d\n"
		       "fast searches = %d\n"
		       "splits = %d\n",
		       xtStat.search,
		       xtStat.fastSearch,
		       xtStat.split);
	return 0;
}

static int jfs_xtstat_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, jfs_xtstat_proc_show, NULL);
}

const struct file_operations jfs_xtstat_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= jfs_xtstat_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_xtree.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 *	jfs_imap.c: inode allocation map manager
 *
 * Serialization:
 *   Each AG has a simple lock which is used to control the serialization of
 *	the AG level lists.  This lock should be taken first whenever an AG
 *	level list will be modified or accessed.
 *
 *   Each IAG is locked by obtaining the buffer for the IAG page.
 *
 *   There is also a inode lock for the inode map inode.  A read lock needs to
 *	be taken whenever an IAG is read from the map or the global level
 *	information is read.  A write lock needs to be taken whenever the global
 *	level information is modified or an atomic operation needs to be used.
 *
 *	If more than one IAG is read at one time, the read lock may not
 *	be given up until all of the IAG's are read.  Otherwise, a deadlock
 *	may occur when trying to obtain the read lock while another thread
 *	holding the read lock is waiting on the IAG already being held.
 *
 *   The control page of the inode map is read into memory by diMount().
 *	Thereafter it should only be modified in memory and then it will be
 *	written out when the filesystem is unmounted by diUnmount().
 */

// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include <linux/pagemap.h>
// #include <linux/quotaops.h>
// #include <linux/slab.h>

// #include "jfs_incore.h"
// #include "jfs_inode.h"
// #include "jfs_filsys.h"
// #include "jfs_dinode.h"
// #include "jfs_dmap.h"
// #include "jfs_imap.h"
// #include "jfs_metapage.h"
// #include "jfs_superblock.h"
// #include "jfs_debug.h"

/*
 * imap locks
 */
/* iag free list lock */
#define IAGFREE_LOCK_INIT(imap)		mutex_init(&imap->im_freelock)
#define IAGFREE_LOCK(imap)		mutex_lock(&imap->im_freelock)
#define IAGFREE_UNLOCK(imap)		mutex_unlock(&imap->im_freelock)

/* per ag iag list locks */
#define AG_LOCK_INIT(imap,index)	mutex_init(&(imap->im_aglock[index]))
#define AG_LOCK(imap,agno)		mutex_lock(&imap->im_aglock[agno])
#define AG_UNLOCK(imap,agno)		mutex_unlock(&imap->im_aglock[agno])

/*
 * forward references
 */
static int diAllocAG(struct inomap *, int, bool, struct inode *);
static int diAllocAny(struct inomap *, int, bool, struct inode *);
static int diAllocBit(struct inomap *, struct iag *, int);
static int diAllocExt(struct inomap *, int, struct inode *);
static int diAllocIno(struct inomap *, int, struct inode *);
static int diFindFree(u32, int);
static int diNewExt(struct inomap *, struct iag *, int);
static int diNewIAG(struct inomap *, int *, int, struct metapage **);
static void duplicateIXtree(struct super_block *, s64, int, s64 *);

static int diIAGRead(struct inomap * imap, int, struct metapage **);
static int copy_from_dinode(struct dinode *, struct inode *);
static void copy_to_dinode(struct dinode *, struct inode *);

/*
 * NAME:	diMount()
 *
 * FUNCTION:	initialize the incore inode map control structures for
 *		a fileset or aggregate init time.
 *
 *		the inode map's control structure (dinomap) is
 *		brought in from disk and placed in virtual memory.
 *
 * PARAMETERS:
 *	ipimap	- pointer to inode map inode for the aggregate or fileset.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOMEM	- insufficient free virtual memory.
 *	-EIO	- i/o error.
 */
int diMount(struct inode *ipimap)
{
	struct inomap *imap;
	struct metapage *mp;
	int index;
	struct dinomap_disk *dinom_le;

	/*
	 * allocate/initialize the in-memory inode map control structure
	 */
	/* allocate the in-memory inode map control structure. */
	imap = kmalloc(sizeof(struct inomap), GFP_KERNEL);
	if (imap == NULL) {
		jfs_err("diMount: kmalloc returned NULL!");
		return -ENOMEM;
	}

	/* read the on-disk inode map control structure. */

	mp = read_metapage(ipimap,
			   IMAPBLKNO << JFS_SBI(ipimap->i_sb)->l2nbperpage,
			   PSIZE, 0);
	if (mp == NULL) {
		kfree(imap);
		return -EIO;
	}

	/* copy the on-disk version to the in-memory version. */
	dinom_le = (struct dinomap_disk *) mp->data;
	imap->im_freeiag = le32_to_cpu(dinom_le->in_freeiag);
	imap->im_nextiag = le32_to_cpu(dinom_le->in_nextiag);
	atomic_set(&imap->im_numinos, le32_to_cpu(dinom_le->in_numinos));
	atomic_set(&imap->im_numfree, le32_to_cpu(dinom_le->in_numfree));
	imap->im_nbperiext = le32_to_cpu(dinom_le->in_nbperiext);
	imap->im_l2nbperiext = le32_to_cpu(dinom_le->in_l2nbperiext);
	for (index = 0; index < MAXAG; index++) {
		imap->im_agctl[index].inofree =
		    le32_to_cpu(dinom_le->in_agctl[index].inofree);
		imap->im_agctl[index].extfree =
		    le32_to_cpu(dinom_le->in_agctl[index].extfree);
		imap->im_agctl[index].numinos =
		    le32_to_cpu(dinom_le->in_agctl[index].numinos);
		imap->im_agctl[index].numfree =
		    le32_to_cpu(dinom_le->in_agctl[index].numfree);
	}

	/* release the buffer. */
	release_metapage(mp);

	/*
	 * allocate/initialize inode allocation map locks
	 */
	/* allocate and init iag free list lock */
	IAGFREE_LOCK_INIT(imap);

	/* allocate and init ag list locks */
	for (index = 0; index < MAXAG; index++) {
		AG_LOCK_INIT(imap, index);
	}

	/* bind the inode map inode and inode map control structure
	 * to each other.
	 */
	imap->im_ipimap = ipimap;
	JFS_IP(ipimap)->i_imap = imap;

	return (0);
}


/*
 * NAME:	diUnmount()
 *
 * FUNCTION:	write to disk the incore inode map control structures for
 *		a fileset or aggregate at unmount time.
 *
 * PARAMETERS:
 *	ipimap	- pointer to inode map inode for the aggregate or fileset.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOMEM	- insufficient free virtual memory.
 *	-EIO	- i/o error.
 */
int diUnmount(struct inode *ipimap, int mounterror)
{
	struct inomap *imap = JFS_IP(ipimap)->i_imap;

	/*
	 * update the on-disk inode map control structure
	 */

	if (!(mounterror || isReadOnly(ipimap)))
		diSync(ipimap);

	/*
	 * Invalidate the page cache buffers
	 */
	truncate_inode_pages(ipimap->i_mapping, 0);

	/*
	 * free in-memory control structure
	 */
	kfree(imap);

	return (0);
}


/*
 *	diSync()
 */
int diSync(struct inode *ipimap)
{
	struct dinomap_disk *dinom_le;
	struct inomap *imp = JFS_IP(ipimap)->i_imap;
	struct metapage *mp;
	int index;

	/*
	 * write imap global conrol page
	 */
	/* read the on-disk inode map control structure */
	mp = get_metapage(ipimap,
			  IMAPBLKNO << JFS_SBI(ipimap->i_sb)->l2nbperpage,
			  PSIZE, 0);
	if (mp == NULL) {
		jfs_err("diSync: get_metapage failed!");
		return -EIO;
	}

	/* copy the in-memory version to the on-disk version */
	dinom_le = (struct dinomap_disk *) mp->data;
	dinom_le->in_freeiag = cpu_to_le32(imp->im_freeiag);
	dinom_le->in_nextiag = cpu_to_le32(imp->im_nextiag);
	dinom_le->in_numinos = cpu_to_le32(atomic_read(&imp->im_numinos));
	dinom_le->in_numfree = cpu_to_le32(atomic_read(&imp->im_numfree));
	dinom_le->in_nbperiext = cpu_to_le32(imp->im_nbperiext);
	dinom_le->in_l2nbperiext = cpu_to_le32(imp->im_l2nbperiext);
	for (index = 0; index < MAXAG; index++) {
		dinom_le->in_agctl[index].inofree =
		    cpu_to_le32(imp->im_agctl[index].inofree);
		dinom_le->in_agctl[index].extfree =
		    cpu_to_le32(imp->im_agctl[index].extfree);
		dinom_le->in_agctl[index].numinos =
		    cpu_to_le32(imp->im_agctl[index].numinos);
		dinom_le->in_agctl[index].numfree =
		    cpu_to_le32(imp->im_agctl[index].numfree);
	}

	/* write out the control structure */
	write_metapage(mp);

	/*
	 * write out dirty pages of imap
	 */
	filemap_write_and_wait(ipimap->i_mapping);

	diWriteSpecial(ipimap, 0);

	return (0);
}


/*
 * NAME:	diRead()
 *
 * FUNCTION:	initialize an incore inode from disk.
 *
 *		on entry, the specifed incore inode should itself
 *		specify the disk inode number corresponding to the
 *		incore inode (i.e. i_number should be initialized).
 *
 *		this routine handles incore inode initialization for
 *		both "special" and "regular" inodes.  special inodes
 *		are those required early in the mount process and
 *		require special handling since much of the file system
 *		is not yet initialized.  these "special" inodes are
 *		identified by a NULL inode map inode pointer and are
 *		actually initialized by a call to diReadSpecial().
 *
 *		for regular inodes, the iag describing the disk inode
 *		is read from disk to determine the inode extent address
 *		for the disk inode.  with the inode extent address in
 *		hand, the page of the extent that contains the disk
 *		inode is read and the disk inode is copied to the
 *		incore inode.
 *
 * PARAMETERS:
 *	ip	-  pointer to incore inode to be initialized from disk.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 *	-ENOMEM	- insufficient memory
 *
 */
int diRead(struct inode *ip)
{
	struct jfs_sb_info *sbi = JFS_SBI(ip->i_sb);
	int iagno, ino, extno, rc;
	struct inode *ipimap;
	struct dinode *dp;
	struct iag *iagp;
	struct metapage *mp;
	s64 blkno, agstart;
	struct inomap *imap;
	int block_offset;
	int inodes_left;
	unsigned long pageno;
	int rel_inode;

	jfs_info("diRead: ino = %ld", ip->i_ino);

	ipimap = sbi->ipimap;
	JFS_IP(ip)->ipimap = ipimap;

	/* determine the iag number for this inode (number) */
	iagno = INOTOIAG(ip->i_ino);

	/* read the iag */
	imap = JFS_IP(ipimap)->i_imap;
	IREAD_LOCK(ipimap, RDWRLOCK_IMAP);
	rc = diIAGRead(imap, iagno, &mp);
	IREAD_UNLOCK(ipimap);
	if (rc) {
		jfs_err("diRead: diIAGRead returned %d", rc);
		return (rc);
	}

	iagp = (struct iag *) mp->data;

	/* determine inode extent that holds the disk inode */
	ino = ip->i_ino & (INOSPERIAG - 1);
	extno = ino >> L2INOSPEREXT;

	if ((lengthPXD(&iagp->inoext[extno]) != imap->im_nbperiext) ||
	    (addressPXD(&iagp->inoext[extno]) == 0)) {
		release_metapage(mp);
		return -ESTALE;
	}

	/* get disk block number of the page within the inode extent
	 * that holds the disk inode.
	 */
	blkno = INOPBLK(&iagp->inoext[extno], ino, sbi->l2nbperpage);

	/* get the ag for the iag */
	agstart = le64_to_cpu(iagp->agstart);

	release_metapage(mp);

	rel_inode = (ino & (INOSPERPAGE - 1));
	pageno = blkno >> sbi->l2nbperpage;

	if ((block_offset = ((u32) blkno & (sbi->nbperpage - 1)))) {
		/*
		 * OS/2 didn't always align inode extents on page boundaries
		 */
		inodes_left =
		     (sbi->nbperpage - block_offset) << sbi->l2niperblk;

		if (rel_inode < inodes_left)
			rel_inode += block_offset << sbi->l2niperblk;
		else {
			pageno += 1;
			rel_inode -= inodes_left;
		}
	}

	/* read the page of disk inode */
	mp = read_metapage(ipimap, pageno << sbi->l2nbperpage, PSIZE, 1);
	if (!mp) {
		jfs_err("diRead: read_metapage failed");
		return -EIO;
	}

	/* locate the disk inode requested */
	dp = (struct dinode *) mp->data;
	dp += rel_inode;

	if (ip->i_ino != le32_to_cpu(dp->di_number)) {
		jfs_error(ip->i_sb, "i_ino != di_number\n");
		rc = -EIO;
	} else if (le32_to_cpu(dp->di_nlink) == 0)
		rc = -ESTALE;
	else
		/* copy the disk inode to the in-memory inode */
		rc = copy_from_dinode(dp, ip);

	release_metapage(mp);

	/* set the ag for the inode */
	JFS_IP(ip)->agstart = agstart;
	JFS_IP(ip)->active_ag = -1;

	return (rc);
}


/*
 * NAME:	diReadSpecial()
 *
 * FUNCTION:	initialize a 'special' inode from disk.
 *
 *		this routines handles aggregate level inodes.  The
 *		inode cache cannot differentiate between the
 *		aggregate inodes and the filesystem inodes, so we
 *		handle these here.  We don't actually use the aggregate
 *		inode map, since these inodes are at a fixed location
 *		and in some cases the aggregate inode map isn't initialized
 *		yet.
 *
 * PARAMETERS:
 *	sb - filesystem superblock
 *	inum - aggregate inode number
 *	secondary - 1 if secondary aggregate inode table
 *
 * RETURN VALUES:
 *	new inode	- success
 *	NULL		- i/o error.
 */
struct inode *diReadSpecial(struct super_block *sb, ino_t inum, int secondary)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	uint address;
	struct dinode *dp;
	struct inode *ip;
	struct metapage *mp;

	ip = new_inode(sb);
	if (ip == NULL) {
		jfs_err("diReadSpecial: new_inode returned NULL!");
		return ip;
	}

	if (secondary) {
		address = addressPXD(&sbi->ait2) >> sbi->l2nbperpage;
		JFS_IP(ip)->ipimap = sbi->ipaimap2;
	} else {
		address = AITBL_OFF >> L2PSIZE;
		JFS_IP(ip)->ipimap = sbi->ipaimap;
	}

	ASSERT(inum < INOSPEREXT);

	ip->i_ino = inum;

	address += inum >> 3;	/* 8 inodes per 4K page */

	/* read the page of fixed disk inode (AIT) in raw mode */
	mp = read_metapage(ip, address << sbi->l2nbperpage, PSIZE, 1);
	if (mp == NULL) {
		set_nlink(ip, 1);	/* Don't want iput() deleting it */
		iput(ip);
		return (NULL);
	}

	/* get the pointer to the disk inode of interest */
	dp = (struct dinode *) (mp->data);
	dp += inum % 8;		/* 8 inodes per 4K page */

	/* copy on-disk inode to in-memory inode */
	if ((copy_from_dinode(dp, ip)) != 0) {
		/* handle bad return by returning NULL for ip */
		set_nlink(ip, 1);	/* Don't want iput() deleting it */
		iput(ip);
		/* release the page */
		release_metapage(mp);
		return (NULL);

	}

	ip->i_mapping->a_ops = &jfs_metapage_aops;
	mapping_set_gfp_mask(ip->i_mapping, GFP_NOFS);

	/* Allocations to metadata inodes should not affect quotas */
	ip->i_flags |= S_NOQUOTA;

	if ((inum == FILESYSTEM_I) && (JFS_IP(ip)->ipimap == sbi->ipaimap)) {
		sbi->gengen = le32_to_cpu(dp->di_gengen);
		sbi->inostamp = le32_to_cpu(dp->di_inostamp);
	}

	/* release the page */
	release_metapage(mp);

	/*
	 * __mark_inode_dirty expects inodes to be hashed.  Since we don't
	 * want special inodes in the fileset inode space, we make them
	 * appear hashed, but do not put on any lists.  hlist_del()
	 * will work fine and require no locking.
	 */
	hlist_add_fake(&ip->i_hash);

	return (ip);
}

/*
 * NAME:	diWriteSpecial()
 *
 * FUNCTION:	Write the special inode to disk
 *
 * PARAMETERS:
 *	ip - special inode
 *	secondary - 1 if secondary aggregate inode table
 *
 * RETURN VALUES: none
 */

void diWriteSpecial(struct inode *ip, int secondary)
{
	struct jfs_sb_info *sbi = JFS_SBI(ip->i_sb);
	uint address;
	struct dinode *dp;
	ino_t inum = ip->i_ino;
	struct metapage *mp;

	if (secondary)
		address = addressPXD(&sbi->ait2) >> sbi->l2nbperpage;
	else
		address = AITBL_OFF >> L2PSIZE;

	ASSERT(inum < INOSPEREXT);

	address += inum >> 3;	/* 8 inodes per 4K page */

	/* read the page of fixed disk inode (AIT) in raw mode */
	mp = read_metapage(ip, address << sbi->l2nbperpage, PSIZE, 1);
	if (mp == NULL) {
		jfs_err("diWriteSpecial: failed to read aggregate inode "
			"extent!");
		return;
	}

	/* get the pointer to the disk inode of interest */
	dp = (struct dinode *) (mp->data);
	dp += inum % 8;		/* 8 inodes per 4K page */

	/* copy on-disk inode to in-memory inode */
	copy_to_dinode(dp, ip);
	memcpy(&dp->di_xtroot, &JFS_IP(ip)->i_xtroot, 288);

	if (inum == FILESYSTEM_I)
		dp->di_gengen = cpu_to_le32(sbi->gengen);

	/* write the page */
	write_metapage(mp);
}

/*
 * NAME:	diFreeSpecial()
 *
 * FUNCTION:	Free allocated space for special inode
 */
void diFreeSpecial(struct inode *ip)
{
	if (ip == NULL) {
		jfs_err("diFreeSpecial called with NULL ip!");
		return;
	}
	filemap_write_and_wait(ip->i_mapping);
	truncate_inode_pages(ip->i_mapping, 0);
	iput(ip);
}



/*
 * NAME:	diWrite()
 *
 * FUNCTION:	write the on-disk inode portion of the in-memory inode
 *		to its corresponding on-disk inode.
 *
 *		on entry, the specifed incore inode should itself
 *		specify the disk inode number corresponding to the
 *		incore inode (i.e. i_number should be initialized).
 *
 *		the inode contains the inode extent address for the disk
 *		inode.  with the inode extent address in hand, the
 *		page of the extent that contains the disk inode is
 *		read and the disk inode portion of the incore inode
 *		is copied to the disk inode.
 *
 * PARAMETERS:
 *	tid -  transacation id
 *	ip  -  pointer to incore inode to be written to the inode extent.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 */
int diWrite(tid_t tid, struct inode *ip)
{
	struct jfs_sb_info *sbi = JFS_SBI(ip->i_sb);
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	int rc = 0;
	s32 ino;
	struct dinode *dp;
	s64 blkno;
	int block_offset;
	int inodes_left;
	struct metapage *mp;
	unsigned long pageno;
	int rel_inode;
	int dioffset;
	struct inode *ipimap;
	uint type;
	lid_t lid;
	struct tlock *ditlck, *tlck;
	struct linelock *dilinelock, *ilinelock;
	struct lv *lv;
	int n;

	ipimap = jfs_ip->ipimap;

	ino = ip->i_ino & (INOSPERIAG - 1);

	if (!addressPXD(&(jfs_ip->ixpxd)) ||
	    (lengthPXD(&(jfs_ip->ixpxd)) !=
	     JFS_IP(ipimap)->i_imap->im_nbperiext)) {
		jfs_error(ip->i_sb, "ixpxd invalid\n");
		return -EIO;
	}

	/*
	 * read the page of disk inode containing the specified inode:
	 */
	/* compute the block address of the page */
	blkno = INOPBLK(&(jfs_ip->ixpxd), ino, sbi->l2nbperpage);

	rel_inode = (ino & (INOSPERPAGE - 1));
	pageno = blkno >> sbi->l2nbperpage;

	if ((block_offset = ((u32) blkno & (sbi->nbperpage - 1)))) {
		/*
		 * OS/2 didn't always align inode extents on page boundaries
		 */
		inodes_left =
		    (sbi->nbperpage - block_offset) << sbi->l2niperblk;

		if (rel_inode < inodes_left)
			rel_inode += block_offset << sbi->l2niperblk;
		else {
			pageno += 1;
			rel_inode -= inodes_left;
		}
	}
	/* read the page of disk inode */
      retry:
	mp = read_metapage(ipimap, pageno << sbi->l2nbperpage, PSIZE, 1);
	if (!mp)
		return -EIO;

	/* get the pointer to the disk inode */
	dp = (struct dinode *) mp->data;
	dp += rel_inode;

	dioffset = (ino & (INOSPERPAGE - 1)) << L2DISIZE;

	/*
	 * acquire transaction lock on the on-disk inode;
	 * N.B. tlock is acquired on ipimap not ip;
	 */
	if ((ditlck =
	     txLock(tid, ipimap, mp, tlckINODE | tlckENTRY)) == NULL)
		goto retry;
	dilinelock = (struct linelock *) & ditlck->lock;

	/*
	 * copy btree root from in-memory inode to on-disk inode
	 *
	 * (tlock is taken from inline B+-tree root in in-memory
	 * inode when the B+-tree root is updated, which is pointed
	 * by jfs_ip->blid as well as being on tx tlock list)
	 *
	 * further processing of btree root is based on the copy
	 * in in-memory inode, where txLog() will log from, and,
	 * for xtree root, txUpdateMap() will update map and reset
	 * XAD_NEW bit;
	 */

	if (S_ISDIR(ip->i_mode) && (lid = jfs_ip->xtlid)) {
		/*
		 * This is the special xtree inside the directory for storing
		 * the directory table
		 */
		xtpage_t *p, *xp;
		xad_t *xad;

		jfs_ip->xtlid = 0;
		tlck = lid_to_tlock(lid);
		assert(tlck->type & tlckXTREE);
		tlck->type |= tlckBTROOT;
		tlck->mp = mp;
		ilinelock = (struct linelock *) & tlck->lock;

		/*
		 * copy xtree root from inode to dinode:
		 */
		p = &jfs_ip->i_xtroot;
		xp = (xtpage_t *) &dp->di_dirtable;
		lv = ilinelock->lv;
		for (n = 0; n < ilinelock->index; n++, lv++) {
			memcpy(&xp->xad[lv->offset], &p->xad[lv->offset],
			       lv->length << L2XTSLOTSIZE);
		}

		/* reset on-disk (metadata page) xtree XAD_NEW bit */
		xad = &xp->xad[XTENTRYSTART];
		for (n = XTENTRYSTART;
		     n < le16_to_cpu(xp->header.nextindex); n++, xad++)
			if (xad->flag & (XAD_NEW | XAD_EXTENDED))
				xad->flag &= ~(XAD_NEW | XAD_EXTENDED);
	}

	if ((lid = jfs_ip->blid) == 0)
		goto inlineData;
	jfs_ip->blid = 0;

	tlck = lid_to_tlock(lid);
	type = tlck->type;
	tlck->type |= tlckBTROOT;
	tlck->mp = mp;
	ilinelock = (struct linelock *) & tlck->lock;

	/*
	 *	regular file: 16 byte (XAD slot) granularity
	 */
	if (type & tlckXTREE) {
		xtpage_t *p, *xp;
		xad_t *xad;

		/*
		 * copy xtree root from inode to dinode:
		 */
		p = &jfs_ip->i_xtroot;
		xp = &dp->di_xtroot;
		lv = ilinelock->lv;
		for (n = 0; n < ilinelock->index; n++, lv++) {
			memcpy(&xp->xad[lv->offset], &p->xad[lv->offset],
			       lv->length << L2XTSLOTSIZE);
		}

		/* reset on-disk (metadata page) xtree XAD_NEW bit */
		xad = &xp->xad[XTENTRYSTART];
		for (n = XTENTRYSTART;
		     n < le16_to_cpu(xp->header.nextindex); n++, xad++)
			if (xad->flag & (XAD_NEW | XAD_EXTENDED))
				xad->flag &= ~(XAD_NEW | XAD_EXTENDED);
	}
	/*
	 *	directory: 32 byte (directory entry slot) granularity
	 */
	else if (type & tlckDTREE) {
		dtpage_t *p, *xp;

		/*
		 * copy dtree root from inode to dinode:
		 */
		p = (dtpage_t *) &jfs_ip->i_dtroot;
		xp = (dtpage_t *) & dp->di_dtroot;
		lv = ilinelock->lv;
		for (n = 0; n < ilinelock->index; n++, lv++) {
			memcpy(&xp->slot[lv->offset], &p->slot[lv->offset],
			       lv->length << L2DTSLOTSIZE);
		}
	} else {
		jfs_err("diWrite: UFO tlock");
	}

      inlineData:
	/*
	 * copy inline symlink from in-memory inode to on-disk inode
	 */
	if (S_ISLNK(ip->i_mode) && ip->i_size < IDATASIZE) {
		lv = & dilinelock->lv[dilinelock->index];
		lv->offset = (dioffset + 2 * 128) >> L2INODESLOTSIZE;
		lv->length = 2;
		memcpy(&dp->di_fastsymlink, jfs_ip->i_inline, IDATASIZE);
		dilinelock->index++;
	}
	/*
	 * copy inline data from in-memory inode to on-disk inode:
	 * 128 byte slot granularity
	 */
	if (test_cflag(COMMIT_Inlineea, ip)) {
		lv = & dilinelock->lv[dilinelock->index];
		lv->offset = (dioffset + 3 * 128) >> L2INODESLOTSIZE;
		lv->length = 1;
		memcpy(&dp->di_inlineea, jfs_ip->i_inline_ea, INODESLOTSIZE);
		dilinelock->index++;

		clear_cflag(COMMIT_Inlineea, ip);
	}

	/*
	 *	lock/copy inode base: 128 byte slot granularity
	 */
	lv = & dilinelock->lv[dilinelock->index];
	lv->offset = dioffset >> L2INODESLOTSIZE;
	copy_to_dinode(dp, ip);
	if (test_and_clear_cflag(COMMIT_Dirtable, ip)) {
		lv->length = 2;
		memcpy(&dp->di_dirtable, &jfs_ip->i_dirtable, 96);
	} else
		lv->length = 1;
	dilinelock->index++;

	/* release the buffer holding the updated on-disk inode.
	 * the buffer will be later written by commit processing.
	 */
	write_metapage(mp);

	return (rc);
}


/*
 * NAME:	diFree(ip)
 *
 * FUNCTION:	free a specified inode from the inode working map
 *		for a fileset or aggregate.
 *
 *		if the inode to be freed represents the first (only)
 *		free inode within the iag, the iag will be placed on
 *		the ag free inode list.
 *
 *		freeing the inode will cause the inode extent to be
 *		freed if the inode is the only allocated inode within
 *		the extent.  in this case all the disk resource backing
 *		up the inode extent will be freed. in addition, the iag
 *		will be placed on the ag extent free list if the extent
 *		is the first free extent in the iag.  if freeing the
 *		extent also means that no free inodes will exist for
 *		the iag, the iag will also be removed from the ag free
 *		inode list.
 *
 *		the iag describing the inode will be freed if the extent
 *		is to be freed and it is the only backed extent within
 *		the iag.  in this case, the iag will be removed from the
 *		ag free extent list and ag free inode list and placed on
 *		the inode map's free iag list.
 *
 *		a careful update approach is used to provide consistency
 *		in the face of updates to multiple buffers.  under this
 *		approach, all required buffers are obtained before making
 *		any updates and are held until all updates are complete.
 *
 * PARAMETERS:
 *	ip	- inode to be freed.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 */
int diFree(struct inode *ip)
{
	int rc;
	ino_t inum = ip->i_ino;
	struct iag *iagp, *aiagp, *biagp, *ciagp, *diagp;
	struct metapage *mp, *amp, *bmp, *cmp, *dmp;
	int iagno, ino, extno, bitno, sword, agno;
	int back, fwd;
	u32 bitmap, mask;
	struct inode *ipimap = JFS_SBI(ip->i_sb)->ipimap;
	struct inomap *imap = JFS_IP(ipimap)->i_imap;
	pxd_t freepxd;
	tid_t tid;
	struct inode *iplist[3];
	struct tlock *tlck;
	struct pxd_lock *pxdlock;

	/*
	 * This is just to suppress compiler warnings.  The same logic that
	 * references these variables is used to initialize them.
	 */
	aiagp = biagp = ciagp = diagp = NULL;

	/* get the iag number containing the inode.
	 */
	iagno = INOTOIAG(inum);

	/* make sure that the iag is contained within
	 * the map.
	 */
	if (iagno >= imap->im_nextiag) {
		print_hex_dump(KERN_ERR, "imap: ", DUMP_PREFIX_ADDRESS, 16, 4,
			       imap, 32, 0);
		jfs_error(ip->i_sb, "inum = %d, iagno = %d, nextiag = %d\n",
			  (uint) inum, iagno, imap->im_nextiag);
		return -EIO;
	}

	/* get the allocation group for this ino.
	 */
	agno = BLKTOAG(JFS_IP(ip)->agstart, JFS_SBI(ip->i_sb));

	/* Lock the AG specific inode map information
	 */
	AG_LOCK(imap, agno);

	/* Obtain read lock in imap inode.  Don't release it until we have
	 * read all of the IAG's that we are going to.
	 */
	IREAD_LOCK(ipimap, RDWRLOCK_IMAP);

	/* read the iag.
	 */
	if ((rc = diIAGRead(imap, iagno, &mp))) {
		IREAD_UNLOCK(ipimap);
		AG_UNLOCK(imap, agno);
		return (rc);
	}
	iagp = (struct iag *) mp->data;

	/* get the inode number and extent number of the inode within
	 * the iag and the inode number within the extent.
	 */
	ino = inum & (INOSPERIAG - 1);
	extno = ino >> L2INOSPEREXT;
	bitno = ino & (INOSPEREXT - 1);
	mask = HIGHORDER >> bitno;

	if (!(le32_to_cpu(iagp->wmap[extno]) & mask)) {
		jfs_error(ip->i_sb, "wmap shows inode already free\n");
	}

	if (!addressPXD(&iagp->inoext[extno])) {
		release_metapage(mp);
		IREAD_UNLOCK(ipimap);
		AG_UNLOCK(imap, agno);
		jfs_error(ip->i_sb, "invalid inoext\n");
		return -EIO;
	}

	/* compute the bitmap for the extent reflecting the freed inode.
	 */
	bitmap = le32_to_cpu(iagp->wmap[extno]) & ~mask;

	if (imap->im_agctl[agno].numfree > imap->im_agctl[agno].numinos) {
		release_metapage(mp);
		IREAD_UNLOCK(ipimap);
		AG_UNLOCK(imap, agno);
		jfs_error(ip->i_sb, "numfree > numinos\n");
		return -EIO;
	}
	/*
	 *	inode extent still has some inodes or below low water mark:
	 *	keep the inode extent;
	 */
	if (bitmap ||
	    imap->im_agctl[agno].numfree < 96 ||
	    (imap->im_agctl[agno].numfree < 288 &&
	     (((imap->im_agctl[agno].numfree * 100) /
	       imap->im_agctl[agno].numinos) <= 25))) {
		/* if the iag currently has no free inodes (i.e.,
		 * the inode being freed is the first free inode of iag),
		 * insert the iag at head of the inode free list for the ag.
		 */
		if (iagp->nfreeinos == 0) {
			/* check if there are any iags on the ag inode
			 * free list.  if so, read the first one so that
			 * we can link the current iag onto the list at
			 * the head.
			 */
			if ((fwd = imap->im_agctl[agno].inofree) >= 0) {
				/* read the iag that currently is the head
				 * of the list.
				 */
				if ((rc = diIAGRead(imap, fwd, &amp))) {
					IREAD_UNLOCK(ipimap);
					AG_UNLOCK(imap, agno);
					release_metapage(mp);
					return (rc);
				}
				aiagp = (struct iag *) amp->data;

				/* make current head point back to the iag.
				 */
				aiagp->inofreeback = cpu_to_le32(iagno);

				write_metapage(amp);
			}

			/* iag points forward to current head and iag
			 * becomes the new head of the list.
			 */
			iagp->inofreefwd =
			    cpu_to_le32(imap->im_agctl[agno].inofree);
			iagp->inofreeback = cpu_to_le32(-1);
			imap->im_agctl[agno].inofree = iagno;
		}
		IREAD_UNLOCK(ipimap);

		/* update the free inode summary map for the extent if
		 * freeing the inode means the extent will now have free
		 * inodes (i.e., the inode being freed is the first free
		 * inode of extent),
		 */
		if (iagp->wmap[extno] == cpu_to_le32(ONES)) {
			sword = extno >> L2EXTSPERSUM;
			bitno = extno & (EXTSPERSUM - 1);
			iagp->inosmap[sword] &=
			    cpu_to_le32(~(HIGHORDER >> bitno));
		}

		/* update the bitmap.
		 */
		iagp->wmap[extno] = cpu_to_le32(bitmap);

		/* update the free inode counts at the iag, ag and
		 * map level.
		 */
		le32_add_cpu(&iagp->nfreeinos, 1);
		imap->im_agctl[agno].numfree += 1;
		atomic_inc(&imap->im_numfree);

		/* release the AG inode map lock
		 */
		AG_UNLOCK(imap, agno);

		/* write the iag */
		write_metapage(mp);

		return (0);
	}


	/*
	 *	inode extent has become free and above low water mark:
	 *	free the inode extent;
	 */

	/*
	 *	prepare to update iag list(s) (careful update step 1)
	 */
	amp = bmp = cmp = dmp = NULL;
	fwd = back = -1;

	/* check if the iag currently has no free extents.  if so,
	 * it will be placed on the head of the ag extent free list.
	 */
	if (iagp->nfreeexts == 0) {
		/* check if the ag extent free list has any iags.
		 * if so, read the iag at the head of the list now.
		 * this (head) iag will be updated later to reflect
		 * the addition of the current iag at the head of
		 * the list.
		 */
		if ((fwd = imap->im_agctl[agno].extfree) >= 0) {
			if ((rc = diIAGRead(imap, fwd, &amp)))
				goto error_out;
			aiagp = (struct iag *) amp->data;
		}
	} else {
		/* iag has free extents. check if the addition of a free
		 * extent will cause all extents to be free within this
		 * iag.  if so, the iag will be removed from the ag extent
		 * free list and placed on the inode map's free iag list.
		 */
		if (iagp->nfreeexts == cpu_to_le32(EXTSPERIAG - 1)) {
			/* in preparation for removing the iag from the
			 * ag extent free list, read the iags preceding
			 * and following the iag on the ag extent free
			 * list.
			 */
			if ((fwd = le32_to_cpu(iagp->extfreefwd)) >= 0) {
				if ((rc = diIAGRead(imap, fwd, &amp)))
					goto error_out;
				aiagp = (struct iag *) amp->data;
			}

			if ((back = le32_to_cpu(iagp->extfreeback)) >= 0) {
				if ((rc = diIAGRead(imap, back, &bmp)))
					goto error_out;
				biagp = (struct iag *) bmp->data;
			}
		}
	}

	/* remove the iag from the ag inode free list if freeing
	 * this extent cause the iag to have no free inodes.
	 */
	if (iagp->nfreeinos == cpu_to_le32(INOSPEREXT - 1)) {
		int inofreeback = le32_to_cpu(iagp->inofreeback);
		int inofreefwd = le32_to_cpu(iagp->inofreefwd);

		/* in preparation for removing the iag from the
		 * ag inode free list, read the iags preceding
		 * and following the iag on the ag inode free
		 * list.  before reading these iags, we must make
		 * sure that we already don't have them in hand
		 * from up above, since re-reading an iag (buffer)
		 * we are currently holding would cause a deadlock.
		 */
		if (inofreefwd >= 0) {

			if (inofreefwd == fwd)
				ciagp = (struct iag *) amp->data;
			else if (inofreefwd == back)
				ciagp = (struct iag *) bmp->data;
			else {
				if ((rc =
				     diIAGRead(imap, inofreefwd, &cmp)))
					goto error_out;
				ciagp = (struct iag *) cmp->data;
			}
			assert(ciagp != NULL);
		}

		if (inofreeback >= 0) {
			if (inofreeback == fwd)
				diagp = (struct iag *) amp->data;
			else if (inofreeback == back)
				diagp = (struct iag *) bmp->data;
			else {
				if ((rc =
				     diIAGRead(imap, inofreeback, &dmp)))
					goto error_out;
				diagp = (struct iag *) dmp->data;
			}
			assert(diagp != NULL);
		}
	}

	IREAD_UNLOCK(ipimap);

	/*
	 * invalidate any page of the inode extent freed from buffer cache;
	 */
	freepxd = iagp->inoext[extno];
	invalidate_pxd_metapages(ip, freepxd);

	/*
	 *	update iag list(s) (careful update step 2)
	 */
	/* add the iag to the ag extent free list if this is the
	 * first free extent for the iag.
	 */
	if (iagp->nfreeexts == 0) {
		if (fwd >= 0)
			aiagp->extfreeback = cpu_to_le32(iagno);

		iagp->extfreefwd =
		    cpu_to_le32(imap->im_agctl[agno].extfree);
		iagp->extfreeback = cpu_to_le32(-1);
		imap->im_agctl[agno].extfree = iagno;
	} else {
		/* remove the iag from the ag extent list if all extents
		 * are now free and place it on the inode map iag free list.
		 */
		if (iagp->nfreeexts == cpu_to_le32(EXTSPERIAG - 1)) {
			if (fwd >= 0)
				aiagp->extfreeback = iagp->extfreeback;

			if (back >= 0)
				biagp->extfreefwd = iagp->extfreefwd;
			else
				imap->im_agctl[agno].extfree =
				    le32_to_cpu(iagp->extfreefwd);

			iagp->extfreefwd = iagp->extfreeback = cpu_to_le32(-1);

			IAGFREE_LOCK(imap);
			iagp->iagfree = cpu_to_le32(imap->im_freeiag);
			imap->im_freeiag = iagno;
			IAGFREE_UNLOCK(imap);
		}
	}

	/* remove the iag from the ag inode free list if freeing
	 * this extent causes the iag to have no free inodes.
	 */
	if (iagp->nfreeinos == cpu_to_le32(INOSPEREXT - 1)) {
		if ((int) le32_to_cpu(iagp->inofreefwd) >= 0)
			ciagp->inofreeback = iagp->inofreeback;

		if ((int) le32_to_cpu(iagp->inofreeback) >= 0)
			diagp->inofreefwd = iagp->inofreefwd;
		else
			imap->im_agctl[agno].inofree =
			    le32_to_cpu(iagp->inofreefwd);

		iagp->inofreefwd = iagp->inofreeback = cpu_to_le32(-1);
	}

	/* update the inode extent address and working map
	 * to reflect the free extent.
	 * the permanent map should have been updated already
	 * for the inode being freed.
	 */
	if (iagp->pmap[extno] != 0) {
		jfs_error(ip->i_sb, "the pmap does not show inode free\n");
	}
	iagp->wmap[extno] = 0;
	PXDlength(&iagp->inoext[extno], 0);
	PXDaddress(&iagp->inoext[extno], 0);

	/* update the free extent and free inode summary maps
	 * to reflect the freed extent.
	 * the inode summary map is marked to indicate no inodes
	 * available for the freed extent.
	 */
	sword = extno >> L2EXTSPERSUM;
	bitno = extno & (EXTSPERSUM - 1);
	mask = HIGHORDER >> bitno;
	iagp->inosmap[sword] |= cpu_to_le32(mask);
	iagp->extsmap[sword] &= cpu_to_le32(~mask);

	/* update the number of free inodes and number of free extents
	 * for the iag.
	 */
	le32_add_cpu(&iagp->nfreeinos, -(INOSPEREXT - 1));
	le32_add_cpu(&iagp->nfreeexts, 1);

	/* update the number of free inodes and backed inodes
	 * at the ag and inode map level.
	 */
	imap->im_agctl[agno].numfree -= (INOSPEREXT - 1);
	imap->im_agctl[agno].numinos -= INOSPEREXT;
	atomic_sub(INOSPEREXT - 1, &imap->im_numfree);
	atomic_sub(INOSPEREXT, &imap->im_numinos);

	if (amp)
		write_metapage(amp);
	if (bmp)
		write_metapage(bmp);
	if (cmp)
		write_metapage(cmp);
	if (dmp)
		write_metapage(dmp);

	/*
	 * start transaction to update block allocation map
	 * for the inode extent freed;
	 *
	 * N.B. AG_LOCK is released and iag will be released below, and
	 * other thread may allocate inode from/reusing the ixad freed
	 * BUT with new/different backing inode extent from the extent
	 * to be freed by the transaction;
	 */
	tid = txBegin(ipimap->i_sb, COMMIT_FORCE);
	mutex_lock(&JFS_IP(ipimap)->commit_mutex);

	/* acquire tlock of the iag page of the freed ixad
	 * to force the page NOHOMEOK (even though no data is
	 * logged from the iag page) until NOREDOPAGE|FREEXTENT log
	 * for the free of the extent is committed;
	 * write FREEXTENT|NOREDOPAGE log record
	 * N.B. linelock is overlaid as freed extent descriptor;
	 */
	tlck = txLock(tid, ipimap, mp, tlckINODE | tlckFREE);
	pxdlock = (struct pxd_lock *) & tlck->lock;
	pxdlock->flag = mlckFREEPXD;
	pxdlock->pxd = freepxd;
	pxdlock->index = 1;

	write_metapage(mp);

	iplist[0] = ipimap;

	/*
	 * logredo needs the IAG number and IAG extent index in order
	 * to ensure that the IMap is consistent.  The least disruptive
	 * way to pass these values through  to the transaction manager
	 * is in the iplist array.
	 *
	 * It's not pretty, but it works.
	 */
	iplist[1] = (struct inode *) (size_t)iagno;
	iplist[2] = (struct inode *) (size_t)extno;

	rc = txCommit(tid, 1, &iplist[0], COMMIT_FORCE);

	txEnd(tid);
	mutex_unlock(&JFS_IP(ipimap)->commit_mutex);

	/* unlock the AG inode map information */
	AG_UNLOCK(imap, agno);

	return (0);

      error_out:
	IREAD_UNLOCK(ipimap);

	if (amp)
		release_metapage(amp);
	if (bmp)
		release_metapage(bmp);
	if (cmp)
		release_metapage(cmp);
	if (dmp)
		release_metapage(dmp);

	AG_UNLOCK(imap, agno);

	release_metapage(mp);

	return (rc);
}

/*
 * There are several places in the diAlloc* routines where we initialize
 * the inode.
 */
static inline void
diInitInode(struct inode *ip, int iagno, int ino, int extno, struct iag * iagp)
{
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);

	ip->i_ino = (iagno << L2INOSPERIAG) + ino;
	jfs_ip->ixpxd = iagp->inoext[extno];
	jfs_ip->agstart = le64_to_cpu(iagp->agstart);
	jfs_ip->active_ag = -1;
}


/*
 * NAME:	diAlloc(pip,dir,ip)
 *
 * FUNCTION:	allocate a disk inode from the inode working map
 *		for a fileset or aggregate.
 *
 * PARAMETERS:
 *	pip	- pointer to incore inode for the parent inode.
 *	dir	- 'true' if the new disk inode is for a directory.
 *	ip	- pointer to a new inode
 *
 * RETURN VALUES:
 *	0	- success.
 *	-ENOSPC	- insufficient disk resources.
 *	-EIO	- i/o error.
 */
int diAlloc(struct inode *pip, bool dir, struct inode *ip)
{
	int rc, ino, iagno, addext, extno, bitno, sword;
	int nwords, rem, i, agno;
	u32 mask, inosmap, extsmap;
	struct inode *ipimap;
	struct metapage *mp;
	ino_t inum;
	struct iag *iagp;
	struct inomap *imap;

	/* get the pointers to the inode map inode and the
	 * corresponding imap control structure.
	 */
	ipimap = JFS_SBI(pip->i_sb)->ipimap;
	imap = JFS_IP(ipimap)->i_imap;
	JFS_IP(ip)->ipimap = ipimap;
	JFS_IP(ip)->fileset = FILESYSTEM_I;

	/* for a directory, the allocation policy is to start
	 * at the ag level using the preferred ag.
	 */
	if (dir) {
		agno = dbNextAG(JFS_SBI(pip->i_sb)->ipbmap);
		AG_LOCK(imap, agno);
		goto tryag;
	}

	/* for files, the policy starts off by trying to allocate from
	 * the same iag containing the parent disk inode:
	 * try to allocate the new disk inode close to the parent disk
	 * inode, using parent disk inode number + 1 as the allocation
	 * hint.  (we use a left-to-right policy to attempt to avoid
	 * moving backward on the disk.)  compute the hint within the
	 * file system and the iag.
	 */

	/* get the ag number of this iag */
	agno = BLKTOAG(JFS_IP(pip)->agstart, JFS_SBI(pip->i_sb));

	if (atomic_read(&JFS_SBI(pip->i_sb)->bmap->db_active[agno])) {
		/*
		 * There is an open file actively growing.  We want to
		 * allocate new inodes from a different ag to avoid
		 * fragmentation problems.
		 */
		agno = dbNextAG(JFS_SBI(pip->i_sb)->ipbmap);
		AG_LOCK(imap, agno);
		goto tryag;
	}

	inum = pip->i_ino + 1;
	ino = inum & (INOSPERIAG - 1);

	/* back off the hint if it is outside of the iag */
	if (ino == 0)
		inum = pip->i_ino;

	/* lock the AG inode map information */
	AG_LOCK(imap, agno);

	/* Get read lock on imap inode */
	IREAD_LOCK(ipimap, RDWRLOCK_IMAP);

	/* get the iag number and read the iag */
	iagno = INOTOIAG(inum);
	if ((rc = diIAGRead(imap, iagno, &mp))) {
		IREAD_UNLOCK(ipimap);
		AG_UNLOCK(imap, agno);
		return (rc);
	}
	iagp = (struct iag *) mp->data;

	/* determine if new inode extent is allowed to be added to the iag.
	 * new inode extent can be added to the iag if the ag
	 * has less than 32 free disk inodes and the iag has free extents.
	 */
	addext = (imap->im_agctl[agno].numfree < 32 && iagp->nfreeexts);

	/*
	 *	try to allocate from the IAG
	 */
	/* check if the inode may be allocated from the iag
	 * (i.e. the inode has free inodes or new extent can be added).
	 */
	if (iagp->nfreeinos || addext) {
		/* determine the extent number of the hint.
		 */
		extno = ino >> L2INOSPEREXT;

		/* check if the extent containing the hint has backed
		 * inodes.  if so, try to allocate within this extent.
		 */
		if (addressPXD(&iagp->inoext[extno])) {
			bitno = ino & (INOSPEREXT - 1);
			if ((bitno =
			     diFindFree(le32_to_cpu(iagp->wmap[extno]),
					bitno))
			    < INOSPEREXT) {
				ino = (extno << L2INOSPEREXT) + bitno;

				/* a free inode (bit) was found within this
				 * extent, so allocate it.
				 */
				rc = diAllocBit(imap, iagp, ino);
				IREAD_UNLOCK(ipimap);
				if (rc) {
					assert(rc == -EIO);
				} else {
					/* set the results of the allocation
					 * and write the iag.
					 */
					diInitInode(ip, iagno, ino, extno,
						    iagp);
					mark_metapage_dirty(mp);
				}
				release_metapage(mp);

				/* free the AG lock and return.
				 */
				AG_UNLOCK(imap, agno);
				return (rc);
			}

			if (!addext)
				extno =
				    (extno ==
				     EXTSPERIAG - 1) ? 0 : extno + 1;
		}

		/*
		 * no free inodes within the extent containing the hint.
		 *
		 * try to allocate from the backed extents following
		 * hint or, if appropriate (i.e. addext is true), allocate
		 * an extent of free inodes at or following the extent
		 * containing the hint.
		 *
		 * the free inode and free extent summary maps are used
		 * here, so determine the starting summary map position
		 * and the number of words we'll have to examine.  again,
		 * the approach is to allocate following the hint, so we
		 * might have to initially ignore prior bits of the summary
		 * map that represent extents prior to the extent containing
		 * the hint and later revisit these bits.
		 */
		bitno = extno & (EXTSPERSUM - 1);
		nwords = (bitno == 0) ? SMAPSZ : SMAPSZ + 1;
		sword = extno >> L2EXTSPERSUM;

		/* mask any prior bits for the starting words of the
		 * summary map.
		 */
		mask = (bitno == 0) ? 0 : (ONES << (EXTSPERSUM - bitno));
		inosmap = le32_to_cpu(iagp->inosmap[sword]) | mask;
		extsmap = le32_to_cpu(iagp->extsmap[sword]) | mask;

		/* scan the free inode and free extent summary maps for
		 * free resources.
		 */
		for (i = 0; i < nwords; i++) {
			/* check if this word of the free inode summary
			 * map describes an extent with free inodes.
			 */
			if (~inosmap) {
				/* an extent with free inodes has been
				 * found. determine the extent number
				 * and the inode number within the extent.
				 */
				rem = diFindFree(inosmap, 0);
				extno = (sword << L2EXTSPERSUM) + rem;
				rem = diFindFree(le32_to_cpu(iagp->wmap[extno]),
						 0);
				if (rem >= INOSPEREXT) {
					IREAD_UNLOCK(ipimap);
					release_metapage(mp);
					AG_UNLOCK(imap, agno);
					jfs_error(ip->i_sb,
						  "can't find free bit in wmap\n");
					return -EIO;
				}

				/* determine the inode number within the
				 * iag and allocate the inode from the
				 * map.
				 */
				ino = (extno << L2INOSPEREXT) + rem;
				rc = diAllocBit(imap, iagp, ino);
				IREAD_UNLOCK(ipimap);
				if (rc)
					assert(rc == -EIO);
				else {
					/* set the results of the allocation
					 * and write the iag.
					 */
					diInitInode(ip, iagno, ino, extno,
						    iagp);
					mark_metapage_dirty(mp);
				}
				release_metapage(mp);

				/* free the AG lock and return.
				 */
				AG_UNLOCK(imap, agno);
				return (rc);

			}

			/* check if we may allocate an extent of free
			 * inodes and whether this word of the free
			 * extents summary map describes a free extent.
			 */
			if (addext && ~extsmap) {
				/* a free extent has been found.  determine
				 * the extent number.
				 */
				rem = diFindFree(extsmap, 0);
				extno = (sword << L2EXTSPERSUM) + rem;

				/* allocate an extent of free inodes.
				 */
				if ((rc = diNewExt(imap, iagp, extno))) {
					/* if there is no disk space for a
					 * new extent, try to allocate the
					 * disk inode from somewhere else.
					 */
					if (rc == -ENOSPC)
						break;

					assert(rc == -EIO);
				} else {
					/* set the results of the allocation
					 * and write the iag.
					 */
					diInitInode(ip, iagno,
						    extno << L2INOSPEREXT,
						    extno, iagp);
					mark_metapage_dirty(mp);
				}
				release_metapage(mp);
				/* free the imap inode & the AG lock & return.
				 */
				IREAD_UNLOCK(ipimap);
				AG_UNLOCK(imap, agno);
				return (rc);
			}

			/* move on to the next set of summary map words.
			 */
			sword = (sword == SMAPSZ - 1) ? 0 : sword + 1;
			inosmap = le32_to_cpu(iagp->inosmap[sword]);
			extsmap = le32_to_cpu(iagp->extsmap[sword]);
		}
	}
	/* unlock imap inode */
	IREAD_UNLOCK(ipimap);

	/* nothing doing in this iag, so release it. */
	release_metapage(mp);

      tryag:
	/*
	 * try to allocate anywhere within the same AG as the parent inode.
	 */
	rc = diAllocAG(imap, agno, dir, ip);

	AG_UNLOCK(imap, agno);

	if (rc != -ENOSPC)
		return (rc);

	/*
	 * try to allocate in any AG.
	 */
	return (diAllocAny(imap, agno, dir, ip));
}


/*
 * NAME:	diAllocAG(imap,agno,dir,ip)
 *
 * FUNCTION:	allocate a disk inode from the allocation group.
 *
 *		this routine first determines if a new extent of free
 *		inodes should be added for the allocation group, with
 *		the current request satisfied from this extent. if this
 *		is the case, an attempt will be made to do just that.  if
 *		this attempt fails or it has been determined that a new
 *		extent should not be added, an attempt is made to satisfy
 *		the request by allocating an existing (backed) free inode
 *		from the allocation group.
 *
 * PRE CONDITION: Already have the AG lock for this AG.
 *
 * PARAMETERS:
 *	imap	- pointer to inode map control structure.
 *	agno	- allocation group to allocate from.
 *	dir	- 'true' if the new disk inode is for a directory.
 *	ip	- pointer to the new inode to be filled in on successful return
 *		  with the disk inode number allocated, its extent address
 *		  and the start of the ag.
 *
 * RETURN VALUES:
 *	0	- success.
 *	-ENOSPC	- insufficient disk resources.
 *	-EIO	- i/o error.
 */
static int
diAllocAG(struct inomap * imap, int agno, bool dir, struct inode *ip)
{
	int rc, addext, numfree, numinos;

	/* get the number of free and the number of backed disk
	 * inodes currently within the ag.
	 */
	numfree = imap->im_agctl[agno].numfree;
	numinos = imap->im_agctl[agno].numinos;

	if (numfree > numinos) {
		jfs_error(ip->i_sb, "numfree > numinos\n");
		return -EIO;
	}

	/* determine if we should allocate a new extent of free inodes
	 * within the ag: for directory inodes, add a new extent
	 * if there are a small number of free inodes or number of free
	 * inodes is a small percentage of the number of backed inodes.
	 */
	if (dir)
		addext = (numfree < 64 ||
			  (numfree < 256
			   && ((numfree * 100) / numinos) <= 20));
	else
		addext = (numfree == 0);

	/*
	 * try to allocate a new extent of free inodes.
	 */
	if (addext) {
		/* if free space is not available for this new extent, try
		 * below to allocate a free and existing (already backed)
		 * inode from the ag.
		 */
		if ((rc = diAllocExt(imap, agno, ip)) != -ENOSPC)
			return (rc);
	}

	/*
	 * try to allocate an existing free inode from the ag.
	 */
	return (diAllocIno(imap, agno, ip));
}


/*
 * NAME:	diAllocAny(imap,agno,dir,iap)
 *
 * FUNCTION:	allocate a disk inode from any other allocation group.
 *
 *		this routine is called when an allocation attempt within
 *		the primary allocation group has failed. if attempts to
 *		allocate an inode from any allocation group other than the
 *		specified primary group.
 *
 * PARAMETERS:
 *	imap	- pointer to inode map control structure.
 *	agno	- primary allocation group (to avoid).
 *	dir	- 'true' if the new disk inode is for a directory.
 *	ip	- pointer to a new inode to be filled in on successful return
 *		  with the disk inode number allocated, its extent address
 *		  and the start of the ag.
 *
 * RETURN VALUES:
 *	0	- success.
 *	-ENOSPC	- insufficient disk resources.
 *	-EIO	- i/o error.
 */
static int
diAllocAny(struct inomap * imap, int agno, bool dir, struct inode *ip)
{
	int ag, rc;
	int maxag = JFS_SBI(imap->im_ipimap->i_sb)->bmap->db_maxag;


	/* try to allocate from the ags following agno up to
	 * the maximum ag number.
	 */
	for (ag = agno + 1; ag <= maxag; ag++) {
		AG_LOCK(imap, ag);

		rc = diAllocAG(imap, ag, dir, ip);

		AG_UNLOCK(imap, ag);

		if (rc != -ENOSPC)
			return (rc);
	}

	/* try to allocate from the ags in front of agno.
	 */
	for (ag = 0; ag < agno; ag++) {
		AG_LOCK(imap, ag);

		rc = diAllocAG(imap, ag, dir, ip);

		AG_UNLOCK(imap, ag);

		if (rc != -ENOSPC)
			return (rc);
	}

	/* no free disk inodes.
	 */
	return -ENOSPC;
}


/*
 * NAME:	diAllocIno(imap,agno,ip)
 *
 * FUNCTION:	allocate a disk inode from the allocation group's free
 *		inode list, returning an error if this free list is
 *		empty (i.e. no iags on the list).
 *
 *		allocation occurs from the first iag on the list using
 *		the iag's free inode summary map to find the leftmost
 *		free inode in the iag.
 *
 * PRE CONDITION: Already have AG lock for this AG.
 *
 * PARAMETERS:
 *	imap	- pointer to inode map control structure.
 *	agno	- allocation group.
 *	ip	- pointer to new inode to be filled in on successful return
 *		  with the disk inode number allocated, its extent address
 *		  and the start of the ag.
 *
 * RETURN VALUES:
 *	0	- success.
 *	-ENOSPC	- insufficient disk resources.
 *	-EIO	- i/o error.
 */
static int diAllocIno(struct inomap * imap, int agno, struct inode *ip)
{
	int iagno, ino, rc, rem, extno, sword;
	struct metapage *mp;
	struct iag *iagp;

	/* check if there are iags on the ag's free inode list.
	 */
	if ((iagno = imap->im_agctl[agno].inofree) < 0)
		return -ENOSPC;

	/* obtain read lock on imap inode */
	IREAD_LOCK(imap->im_ipimap, RDWRLOCK_IMAP);

	/* read the iag at the head of the list.
	 */
	if ((rc = diIAGRead(imap, iagno, &mp))) {
		IREAD_UNLOCK(imap->im_ipimap);
		return (rc);
	}
	iagp = (struct iag *) mp->data;

	/* better be free inodes in this iag if it is on the
	 * list.
	 */
	if (!iagp->nfreeinos) {
		IREAD_UNLOCK(imap->im_ipimap);
		release_metapage(mp);
		jfs_error(ip->i_sb, "nfreeinos = 0, but iag on freelist\n");
		return -EIO;
	}

	/* scan the free inode summary map to find an extent
	 * with free inodes.
	 */
	for (sword = 0;; sword++) {
		if (sword >= SMAPSZ) {
			IREAD_UNLOCK(imap->im_ipimap);
			release_metapage(mp);
			jfs_error(ip->i_sb,
				  "free inode not found in summary map\n");
			return -EIO;
		}

		if (~iagp->inosmap[sword])
			break;
	}

	/* found a extent with free inodes. determine
	 * the extent number.
	 */
	rem = diFindFree(le32_to_cpu(iagp->inosmap[sword]), 0);
	if (rem >= EXTSPERSUM) {
		IREAD_UNLOCK(imap->im_ipimap);
		release_metapage(mp);
		jfs_error(ip->i_sb, "no free extent found\n");
		return -EIO;
	}
	extno = (sword << L2EXTSPERSUM) + rem;

	/* find the first free inode in the extent.
	 */
	rem = diFindFree(le32_to_cpu(iagp->wmap[extno]), 0);
	if (rem >= INOSPEREXT) {
		IREAD_UNLOCK(imap->im_ipimap);
		release_metapage(mp);
		jfs_error(ip->i_sb, "free inode not found\n");
		return -EIO;
	}

	/* compute the inode number within the iag.
	 */
	ino = (extno << L2INOSPEREXT) + rem;

	/* allocate the inode.
	 */
	rc = diAllocBit(imap, iagp, ino);
	IREAD_UNLOCK(imap->im_ipimap);
	if (rc) {
		release_metapage(mp);
		return (rc);
	}

	/* set the results of the allocation and write the iag.
	 */
	diInitInode(ip, iagno, ino, extno, iagp);
	write_metapage(mp);

	return (0);
}


/*
 * NAME:	diAllocExt(imap,agno,ip)
 *
 * FUNCTION:	add a new extent of free inodes to an iag, allocating
 *		an inode from this extent to satisfy the current allocation
 *		request.
 *
 *		this routine first tries to find an existing iag with free
 *		extents through the ag free extent list.  if list is not
 *		empty, the head of the list will be selected as the home
 *		of the new extent of free inodes.  otherwise (the list is
 *		empty), a new iag will be allocated for the ag to contain
 *		the extent.
 *
 *		once an iag has been selected, the free extent summary map
 *		is used to locate a free extent within the iag and diNewExt()
 *		is called to initialize the extent, with initialization
 *		including the allocation of the first inode of the extent
 *		for the purpose of satisfying this request.
 *
 * PARAMETERS:
 *	imap	- pointer to inode map control structure.
 *	agno	- allocation group number.
 *	ip	- pointer to new inode to be filled in on successful return
 *		  with the disk inode number allocated, its extent address
 *		  and the start of the ag.
 *
 * RETURN VALUES:
 *	0	- success.
 *	-ENOSPC	- insufficient disk resources.
 *	-EIO	- i/o error.
 */
static int diAllocExt(struct inomap * imap, int agno, struct inode *ip)
{
	int rem, iagno, sword, extno, rc;
	struct metapage *mp;
	struct iag *iagp;

	/* check if the ag has any iags with free extents.  if not,
	 * allocate a new iag for the ag.
	 */
	if ((iagno = imap->im_agctl[agno].extfree) < 0) {
		/* If successful, diNewIAG will obtain the read lock on the
		 * imap inode.
		 */
		if ((rc = diNewIAG(imap, &iagno, agno, &mp))) {
			return (rc);
		}
		iagp = (struct iag *) mp->data;

		/* set the ag number if this a brand new iag
		 */
		iagp->agstart =
		    cpu_to_le64(AGTOBLK(agno, imap->im_ipimap));
	} else {
		/* read the iag.
		 */
		IREAD_LOCK(imap->im_ipimap, RDWRLOCK_IMAP);
		if ((rc = diIAGRead(imap, iagno, &mp))) {
			IREAD_UNLOCK(imap->im_ipimap);
			jfs_error(ip->i_sb, "error reading iag\n");
			return rc;
		}
		iagp = (struct iag *) mp->data;
	}

	/* using the free extent summary map, find a free extent.
	 */
	for (sword = 0;; sword++) {
		if (sword >= SMAPSZ) {
			release_metapage(mp);
			IREAD_UNLOCK(imap->im_ipimap);
			jfs_error(ip->i_sb, "free ext summary map not found\n");
			return -EIO;
		}
		if (~iagp->extsmap[sword])
			break;
	}

	/* determine the extent number of the free extent.
	 */
	rem = diFindFree(le32_to_cpu(iagp->extsmap[sword]), 0);
	if (rem >= EXTSPERSUM) {
		release_metapage(mp);
		IREAD_UNLOCK(imap->im_ipimap);
		jfs_error(ip->i_sb, "free extent not found\n");
		return -EIO;
	}
	extno = (sword << L2EXTSPERSUM) + rem;

	/* initialize the new extent.
	 */
	rc = diNewExt(imap, iagp, extno);
	IREAD_UNLOCK(imap->im_ipimap);
	if (rc) {
		/* something bad happened.  if a new iag was allocated,
		 * place it back on the inode map's iag free list, and
		 * clear the ag number information.
		 */
		if (iagp->nfreeexts == cpu_to_le32(EXTSPERIAG)) {
			IAGFREE_LOCK(imap);
			iagp->iagfree = cpu_to_le32(imap->im_freeiag);
			imap->im_freeiag = iagno;
			IAGFREE_UNLOCK(imap);
		}
		write_metapage(mp);
		return (rc);
	}

	/* set the results of the allocation and write the iag.
	 */
	diInitInode(ip, iagno, extno << L2INOSPEREXT, extno, iagp);

	write_metapage(mp);

	return (0);
}


/*
 * NAME:	diAllocBit(imap,iagp,ino)
 *
 * FUNCTION:	allocate a backed inode from an iag.
 *
 *		this routine performs the mechanics of allocating a
 *		specified inode from a backed extent.
 *
 *		if the inode to be allocated represents the last free
 *		inode within the iag, the iag will be removed from the
 *		ag free inode list.
 *
 *		a careful update approach is used to provide consistency
 *		in the face of updates to multiple buffers.  under this
 *		approach, all required buffers are obtained before making
 *		any updates and are held all are updates are complete.
 *
 * PRE CONDITION: Already have buffer lock on iagp.  Already have AG lock on
 *	this AG.  Must have read lock on imap inode.
 *
 * PARAMETERS:
 *	imap	- pointer to inode map control structure.
 *	iagp	- pointer to iag.
 *	ino	- inode number to be allocated within the iag.
 *
 * RETURN VALUES:
 *	0	- success.
 *	-ENOSPC	- insufficient disk resources.
 *	-EIO	- i/o error.
 */
static int diAllocBit(struct inomap * imap, struct iag * iagp, int ino)
{
	int extno, bitno, agno, sword, rc;
	struct metapage *amp = NULL, *bmp = NULL;
	struct iag *aiagp = NULL, *biagp = NULL;
	u32 mask;

	/* check if this is the last free inode within the iag.
	 * if so, it will have to be removed from the ag free
	 * inode list, so get the iags preceding and following
	 * it on the list.
	 */
	if (iagp->nfreeinos == cpu_to_le32(1)) {
		if ((int) le32_to_cpu(iagp->inofreefwd) >= 0) {
			if ((rc =
			     diIAGRead(imap, le32_to_cpu(iagp->inofreefwd),
				       &amp)))
				return (rc);
			aiagp = (struct iag *) amp->data;
		}

		if ((int) le32_to_cpu(iagp->inofreeback) >= 0) {
			if ((rc =
			     diIAGRead(imap,
				       le32_to_cpu(iagp->inofreeback),
				       &bmp))) {
				if (amp)
					release_metapage(amp);
				return (rc);
			}
			biagp = (struct iag *) bmp->data;
		}
	}

	/* get the ag number, extent number, inode number within
	 * the extent.
	 */
	agno = BLKTOAG(le64_to_cpu(iagp->agstart), JFS_SBI(imap->im_ipimap->i_sb));
	extno = ino >> L2INOSPEREXT;
	bitno = ino & (INOSPEREXT - 1);

	/* compute the mask for setting the map.
	 */
	mask = HIGHORDER >> bitno;

	/* the inode should be free and backed.
	 */
	if (((le32_to_cpu(iagp->pmap[extno]) & mask) != 0) ||
	    ((le32_to_cpu(iagp->wmap[extno]) & mask) != 0) ||
	    (addressPXD(&iagp->inoext[extno]) == 0)) {
		if (amp)
			release_metapage(amp);
		if (bmp)
			release_metapage(bmp);

		jfs_error(imap->im_ipimap->i_sb, "iag inconsistent\n");
		return -EIO;
	}

	/* mark the inode as allocated in the working map.
	 */
	iagp->wmap[extno] |= cpu_to_le32(mask);

	/* check if all inodes within the extent are now
	 * allocated.  if so, update the free inode summary
	 * map to reflect this.
	 */
	if (iagp->wmap[extno] == cpu_to_le32(ONES)) {
		sword = extno >> L2EXTSPERSUM;
		bitno = extno & (EXTSPERSUM - 1);
		iagp->inosmap[sword] |= cpu_to_le32(HIGHORDER >> bitno);
	}

	/* if this was the last free inode in the iag, remove the
	 * iag from the ag free inode list.
	 */
	if (iagp->nfreeinos == cpu_to_le32(1)) {
		if (amp) {
			aiagp->inofreeback = iagp->inofreeback;
			write_metapage(amp);
		}

		if (bmp) {
			biagp->inofreefwd = iagp->inofreefwd;
			write_metapage(bmp);
		} else {
			imap->im_agctl[agno].inofree =
			    le32_to_cpu(iagp->inofreefwd);
		}
		iagp->inofreefwd = iagp->inofreeback = cpu_to_le32(-1);
	}

	/* update the free inode count at the iag, ag, inode
	 * map levels.
	 */
	le32_add_cpu(&iagp->nfreeinos, -1);
	imap->im_agctl[agno].numfree -= 1;
	atomic_dec(&imap->im_numfree);

	return (0);
}


/*
 * NAME:	diNewExt(imap,iagp,extno)
 *
 * FUNCTION:	initialize a new extent of inodes for an iag, allocating
 *		the first inode of the extent for use for the current
 *		allocation request.
 *
 *		disk resources are allocated for the new extent of inodes
 *		and the inodes themselves are initialized to reflect their
 *		existence within the extent (i.e. their inode numbers and
 *		inode extent addresses are set) and their initial state
 *		(mode and link count are set to zero).
 *
 *		if the iag is new, it is not yet on an ag extent free list
 *		but will now be placed on this list.
 *
 *		if the allocation of the new extent causes the iag to
 *		have no free extent, the iag will be removed from the
 *		ag extent free list.
 *
 *		if the iag has no free backed inodes, it will be placed
 *		on the ag free inode list, since the addition of the new
 *		extent will now cause it to have free inodes.
 *
 *		a careful update approach is used to provide consistency
 *		(i.e. list consistency) in the face of updates to multiple
 *		buffers.  under this approach, all required buffers are
 *		obtained before making any updates and are held until all
 *		updates are complete.
 *
 * PRE CONDITION: Already have buffer lock on iagp.  Already have AG lock on
 *	this AG.  Must have read lock on imap inode.
 *
 * PARAMETERS:
 *	imap	- pointer to inode map control structure.
 *	iagp	- pointer to iag.
 *	extno	- extent number.
 *
 * RETURN VALUES:
 *	0	- success.
 *	-ENOSPC	- insufficient disk resources.
 *	-EIO	- i/o error.
 */
static int diNewExt(struct inomap * imap, struct iag * iagp, int extno)
{
	int agno, iagno, fwd, back, freei = 0, sword, rc;
	struct iag *aiagp = NULL, *biagp = NULL, *ciagp = NULL;
	struct metapage *amp, *bmp, *cmp, *dmp;
	struct inode *ipimap;
	s64 blkno, hint;
	int i, j;
	u32 mask;
	ino_t ino;
	struct dinode *dp;
	struct jfs_sb_info *sbi;

	/* better have free extents.
	 */
	if (!iagp->nfreeexts) {
		jfs_error(imap->im_ipimap->i_sb, "no free extents\n");
		return -EIO;
	}

	/* get the inode map inode.
	 */
	ipimap = imap->im_ipimap;
	sbi = JFS_SBI(ipimap->i_sb);

	amp = bmp = cmp = NULL;

	/* get the ag and iag numbers for this iag.
	 */
	agno = BLKTOAG(le64_to_cpu(iagp->agstart), sbi);
	iagno = le32_to_cpu(iagp->iagnum);

	/* check if this is the last free extent within the
	 * iag.  if so, the iag must be removed from the ag
	 * free extent list, so get the iags preceding and
	 * following the iag on this list.
	 */
	if (iagp->nfreeexts == cpu_to_le32(1)) {
		if ((fwd = le32_to_cpu(iagp->extfreefwd)) >= 0) {
			if ((rc = diIAGRead(imap, fwd, &amp)))
				return (rc);
			aiagp = (struct iag *) amp->data;
		}

		if ((back = le32_to_cpu(iagp->extfreeback)) >= 0) {
			if ((rc = diIAGRead(imap, back, &bmp)))
				goto error_out;
			biagp = (struct iag *) bmp->data;
		}
	} else {
		/* the iag has free extents.  if all extents are free
		 * (as is the case for a newly allocated iag), the iag
		 * must be added to the ag free extent list, so get
		 * the iag at the head of the list in preparation for
		 * adding this iag to this list.
		 */
		fwd = back = -1;
		if (iagp->nfreeexts == cpu_to_le32(EXTSPERIAG)) {
			if ((fwd = imap->im_agctl[agno].extfree) >= 0) {
				if ((rc = diIAGRead(imap, fwd, &amp)))
					goto error_out;
				aiagp = (struct iag *) amp->data;
			}
		}
	}

	/* check if the iag has no free inodes.  if so, the iag
	 * will have to be added to the ag free inode list, so get
	 * the iag at the head of the list in preparation for
	 * adding this iag to this list.  in doing this, we must
	 * check if we already have the iag at the head of
	 * the list in hand.
	 */
	if (iagp->nfreeinos == 0) {
		freei = imap->im_agctl[agno].inofree;

		if (freei >= 0) {
			if (freei == fwd) {
				ciagp = aiagp;
			} else if (freei == back) {
				ciagp = biagp;
			} else {
				if ((rc = diIAGRead(imap, freei, &cmp)))
					goto error_out;
				ciagp = (struct iag *) cmp->data;
			}
			if (ciagp == NULL) {
				jfs_error(imap->im_ipimap->i_sb,
					  "ciagp == NULL\n");
				rc = -EIO;
				goto error_out;
			}
		}
	}

	/* allocate disk space for the inode extent.
	 */
	if ((extno == 0) || (addressPXD(&iagp->inoext[extno - 1]) == 0))
		hint = ((s64) agno << sbi->bmap->db_agl2size) - 1;
	else
		hint = addressPXD(&iagp->inoext[extno - 1]) +
		    lengthPXD(&iagp->inoext[extno - 1]) - 1;

	if ((rc = dbAlloc(ipimap, hint, (s64) imap->im_nbperiext, &blkno)))
		goto error_out;

	/* compute the inode number of the first inode within the
	 * extent.
	 */
	ino = (iagno << L2INOSPERIAG) + (extno << L2INOSPEREXT);

	/* initialize the inodes within the newly allocated extent a
	 * page at a time.
	 */
	for (i = 0; i < imap->im_nbperiext; i += sbi->nbperpage) {
		/* get a buffer for this page of disk inodes.
		 */
		dmp = get_metapage(ipimap, blkno + i, PSIZE, 1);
		if (dmp == NULL) {
			rc = -EIO;
			goto error_out;
		}
		dp = (struct dinode *) dmp->data;

		/* initialize the inode number, mode, link count and
		 * inode extent address.
		 */
		for (j = 0; j < INOSPERPAGE; j++, dp++, ino++) {
			dp->di_inostamp = cpu_to_le32(sbi->inostamp);
			dp->di_number = cpu_to_le32(ino);
			dp->di_fileset = cpu_to_le32(FILESYSTEM_I);
			dp->di_mode = 0;
			dp->di_nlink = 0;
			PXDaddress(&(dp->di_ixpxd), blkno);
			PXDlength(&(dp->di_ixpxd), imap->im_nbperiext);
		}
		write_metapage(dmp);
	}

	/* if this is the last free extent within the iag, remove the
	 * iag from the ag free extent list.
	 */
	if (iagp->nfreeexts == cpu_to_le32(1)) {
		if (fwd >= 0)
			aiagp->extfreeback = iagp->extfreeback;

		if (back >= 0)
			biagp->extfreefwd = iagp->extfreefwd;
		else
			imap->im_agctl[agno].extfree =
			    le32_to_cpu(iagp->extfreefwd);

		iagp->extfreefwd = iagp->extfreeback = cpu_to_le32(-1);
	} else {
		/* if the iag has all free extents (newly allocated iag),
		 * add the iag to the ag free extent list.
		 */
		if (iagp->nfreeexts == cpu_to_le32(EXTSPERIAG)) {
			if (fwd >= 0)
				aiagp->extfreeback = cpu_to_le32(iagno);

			iagp->extfreefwd = cpu_to_le32(fwd);
			iagp->extfreeback = cpu_to_le32(-1);
			imap->im_agctl[agno].extfree = iagno;
		}
	}

	/* if the iag has no free inodes, add the iag to the
	 * ag free inode list.
	 */
	if (iagp->nfreeinos == 0) {
		if (freei >= 0)
			ciagp->inofreeback = cpu_to_le32(iagno);

		iagp->inofreefwd =
		    cpu_to_le32(imap->im_agctl[agno].inofree);
		iagp->inofreeback = cpu_to_le32(-1);
		imap->im_agctl[agno].inofree = iagno;
	}

	/* initialize the extent descriptor of the extent. */
	PXDlength(&iagp->inoext[extno], imap->im_nbperiext);
	PXDaddress(&iagp->inoext[extno], blkno);

	/* initialize the working and persistent map of the extent.
	 * the working map will be initialized such that
	 * it indicates the first inode of the extent is allocated.
	 */
	iagp->wmap[extno] = cpu_to_le32(HIGHORDER);
	iagp->pmap[extno] = 0;

	/* update the free inode and free extent summary maps
	 * for the extent to indicate the extent has free inodes
	 * and no longer represents a free extent.
	 */
	sword = extno >> L2EXTSPERSUM;
	mask = HIGHORDER >> (extno & (EXTSPERSUM - 1));
	iagp->extsmap[sword] |= cpu_to_le32(mask);
	iagp->inosmap[sword] &= cpu_to_le32(~mask);

	/* update the free inode and free extent counts for the
	 * iag.
	 */
	le32_add_cpu(&iagp->nfreeinos, (INOSPEREXT - 1));
	le32_add_cpu(&iagp->nfreeexts, -1);

	/* update the free and backed inode counts for the ag.
	 */
	imap->im_agctl[agno].numfree += (INOSPEREXT - 1);
	imap->im_agctl[agno].numinos += INOSPEREXT;

	/* update the free and backed inode counts for the inode map.
	 */
	atomic_add(INOSPEREXT - 1, &imap->im_numfree);
	atomic_add(INOSPEREXT, &imap->im_numinos);

	/* write the iags.
	 */
	if (amp)
		write_metapage(amp);
	if (bmp)
		write_metapage(bmp);
	if (cmp)
		write_metapage(cmp);

	return (0);

      error_out:

	/* release the iags.
	 */
	if (amp)
		release_metapage(amp);
	if (bmp)
		release_metapage(bmp);
	if (cmp)
		release_metapage(cmp);

	return (rc);
}


/*
 * NAME:	diNewIAG(imap,iagnop,agno)
 *
 * FUNCTION:	allocate a new iag for an allocation group.
 *
 *		first tries to allocate the iag from the inode map
 *		iagfree list:
 *		if the list has free iags, the head of the list is removed
 *		and returned to satisfy the request.
 *		if the inode map's iag free list is empty, the inode map
 *		is extended to hold a new iag. this new iag is initialized
 *		and returned to satisfy the request.
 *
 * PARAMETERS:
 *	imap	- pointer to inode map control structure.
 *	iagnop	- pointer to an iag number set with the number of the
 *		  newly allocated iag upon successful return.
 *	agno	- allocation group number.
 *	bpp	- Buffer pointer to be filled in with new IAG's buffer
 *
 * RETURN VALUES:
 *	0	- success.
 *	-ENOSPC	- insufficient disk resources.
 *	-EIO	- i/o error.
 *
 * serialization:
 *	AG lock held on entry/exit;
 *	write lock on the map is held inside;
 *	read lock on the map is held on successful completion;
 *
 * note: new iag transaction:
 * . synchronously write iag;
 * . write log of xtree and inode of imap;
 * . commit;
 * . synchronous write of xtree (right to left, bottom to top);
 * . at start of logredo(): init in-memory imap with one additional iag page;
 * . at end of logredo(): re-read imap inode to determine
 *   new imap size;
 */
static int
diNewIAG(struct inomap * imap, int *iagnop, int agno, struct metapage ** mpp)
{
	int rc;
	int iagno, i, xlen;
	struct inode *ipimap;
	struct super_block *sb;
	struct jfs_sb_info *sbi;
	struct metapage *mp;
	struct iag *iagp;
	s64 xaddr = 0;
	s64 blkno;
	tid_t tid;
	struct inode *iplist[1];

	/* pick up pointers to the inode map and mount inodes */
	ipimap = imap->im_ipimap;
	sb = ipimap->i_sb;
	sbi = JFS_SBI(sb);

	/* acquire the free iag lock */
	IAGFREE_LOCK(imap);

	/* if there are any iags on the inode map free iag list,
	 * allocate the iag from the head of the list.
	 */
	if (imap->im_freeiag >= 0) {
		/* pick up the iag number at the head of the list */
		iagno = imap->im_freeiag;

		/* determine the logical block number of the iag */
		blkno = IAGTOLBLK(iagno, sbi->l2nbperpage);
	} else {
		/* no free iags. the inode map will have to be extented
		 * to include a new iag.
		 */

		/* acquire inode map lock */
		IWRITE_LOCK(ipimap, RDWRLOCK_IMAP);

		if (ipimap->i_size >> L2PSIZE != imap->im_nextiag + 1) {
			IWRITE_UNLOCK(ipimap);
			IAGFREE_UNLOCK(imap);
			jfs_error(imap->im_ipimap->i_sb,
				  "ipimap->i_size is wrong\n");
			return -EIO;
		}


		/* get the next available iag number */
		iagno = imap->im_nextiag;

		/* make sure that we have not exceeded the maximum inode
		 * number limit.
		 */
		if (iagno > (MAXIAGS - 1)) {
			/* release the inode map lock */
			IWRITE_UNLOCK(ipimap);

			rc = -ENOSPC;
			goto out;
		}

		/*
		 * synchronously append new iag page.
		 */
		/* determine the logical address of iag page to append */
		blkno = IAGTOLBLK(iagno, sbi->l2nbperpage);

		/* Allocate extent for new iag page */
		xlen = sbi->nbperpage;
		if ((rc = dbAlloc(ipimap, 0, (s64) xlen, &xaddr))) {
			/* release the inode map lock */
			IWRITE_UNLOCK(ipimap);

			goto out;
		}

		/*
		 * start transaction of update of the inode map
		 * addressing structure pointing to the new iag page;
		 */
		tid = txBegin(sb, COMMIT_FORCE);
		mutex_lock(&JFS_IP(ipimap)->commit_mutex);

		/* update the inode map addressing structure to point to it */
		if ((rc =
		     xtInsert(tid, ipimap, 0, blkno, xlen, &xaddr, 0))) {
			txEnd(tid);
			mutex_unlock(&JFS_IP(ipimap)->commit_mutex);
			/* Free the blocks allocated for the iag since it was
			 * not successfully added to the inode map
			 */
			dbFree(ipimap, xaddr, (s64) xlen);

			/* release the inode map lock */
			IWRITE_UNLOCK(ipimap);

			goto out;
		}

		/* update the inode map's inode to reflect the extension */
		ipimap->i_size += PSIZE;
		inode_add_bytes(ipimap, PSIZE);

		/* assign a buffer for the page */
		mp = get_metapage(ipimap, blkno, PSIZE, 0);
		if (!mp) {
			/*
			 * This is very unlikely since we just created the
			 * extent, but let's try to handle it correctly
			 */
			xtTruncate(tid, ipimap, ipimap->i_size - PSIZE,
				   COMMIT_PWMAP);

			txAbort(tid, 0);
			txEnd(tid);
			mutex_unlock(&JFS_IP(ipimap)->commit_mutex);

			/* release the inode map lock */
			IWRITE_UNLOCK(ipimap);

			rc = -EIO;
			goto out;
		}
		iagp = (struct iag *) mp->data;

		/* init the iag */
		memset(iagp, 0, sizeof(struct iag));
		iagp->iagnum = cpu_to_le32(iagno);
		iagp->inofreefwd = iagp->inofreeback = cpu_to_le32(-1);
		iagp->extfreefwd = iagp->extfreeback = cpu_to_le32(-1);
		iagp->iagfree = cpu_to_le32(-1);
		iagp->nfreeinos = 0;
		iagp->nfreeexts = cpu_to_le32(EXTSPERIAG);

		/* initialize the free inode summary map (free extent
		 * summary map initialization handled by bzero).
		 */
		for (i = 0; i < SMAPSZ; i++)
			iagp->inosmap[i] = cpu_to_le32(ONES);

		/*
		 * Write and sync the metapage
		 */
		flush_metapage(mp);

		/*
		 * txCommit(COMMIT_FORCE) will synchronously write address
		 * index pages and inode after commit in careful update order
		 * of address index pages (right to left, bottom up);
		 */
		iplist[0] = ipimap;
		rc = txCommit(tid, 1, &iplist[0], COMMIT_FORCE);

		txEnd(tid);
		mutex_unlock(&JFS_IP(ipimap)->commit_mutex);

		duplicateIXtree(sb, blkno, xlen, &xaddr);

		/* update the next available iag number */
		imap->im_nextiag += 1;

		/* Add the iag to the iag free list so we don't lose the iag
		 * if a failure happens now.
		 */
		imap->im_freeiag = iagno;

		/* Until we have logredo working, we want the imap inode &
		 * control page to be up to date.
		 */
		diSync(ipimap);

		/* release the inode map lock */
		IWRITE_UNLOCK(ipimap);
	}

	/* obtain read lock on map */
	IREAD_LOCK(ipimap, RDWRLOCK_IMAP);

	/* read the iag */
	if ((rc = diIAGRead(imap, iagno, &mp))) {
		IREAD_UNLOCK(ipimap);
		rc = -EIO;
		goto out;
	}
	iagp = (struct iag *) mp->data;

	/* remove the iag from the iag free list */
	imap->im_freeiag = le32_to_cpu(iagp->iagfree);
	iagp->iagfree = cpu_to_le32(-1);

	/* set the return iag number and buffer pointer */
	*iagnop = iagno;
	*mpp = mp;

      out:
	/* release the iag free lock */
	IAGFREE_UNLOCK(imap);

	return (rc);
}

/*
 * NAME:	diIAGRead()
 *
 * FUNCTION:	get the buffer for the specified iag within a fileset
 *		or aggregate inode map.
 *
 * PARAMETERS:
 *	imap	- pointer to inode map control structure.
 *	iagno	- iag number.
 *	bpp	- point to buffer pointer to be filled in on successful
 *		  exit.
 *
 * SERIALIZATION:
 *	must have read lock on imap inode
 *	(When called by diExtendFS, the filesystem is quiesced, therefore
 *	 the read lock is unnecessary.)
 *
 * RETURN VALUES:
 *	0	- success.
 *	-EIO	- i/o error.
 */
static int diIAGRead(struct inomap * imap, int iagno, struct metapage ** mpp)
{
	struct inode *ipimap = imap->im_ipimap;
	s64 blkno;

	/* compute the logical block number of the iag. */
	blkno = IAGTOLBLK(iagno, JFS_SBI(ipimap->i_sb)->l2nbperpage);

	/* read the iag. */
	*mpp = read_metapage(ipimap, blkno, PSIZE, 0);
	if (*mpp == NULL) {
		return -EIO;
	}

	return (0);
}

/*
 * NAME:	diFindFree()
 *
 * FUNCTION:	find the first free bit in a word starting at
 *		the specified bit position.
 *
 * PARAMETERS:
 *	word	- word to be examined.
 *	start	- starting bit position.
 *
 * RETURN VALUES:
 *	bit position of first free bit in the word or 32 if
 *	no free bits were found.
 */
static int diFindFree(u32 word, int start)
{
	int bitno;
	assert(start < 32);
	/* scan the word for the first free bit. */
	for (word <<= start, bitno = start; bitno < 32;
	     bitno++, word <<= 1) {
		if ((word & HIGHORDER) == 0)
			break;
	}
	return (bitno);
}

/*
 * NAME:	diUpdatePMap()
 *
 * FUNCTION: Update the persistent map in an IAG for the allocation or
 *	freeing of the specified inode.
 *
 * PRE CONDITIONS: Working map has already been updated for allocate.
 *
 * PARAMETERS:
 *	ipimap	- Incore inode map inode
 *	inum	- Number of inode to mark in permanent map
 *	is_free	- If 'true' indicates inode should be marked freed, otherwise
 *		  indicates inode should be marked allocated.
 *
 * RETURN VALUES:
 *		0 for success
 */
int
diUpdatePMap(struct inode *ipimap,
	     unsigned long inum, bool is_free, struct tblock * tblk)
{
	int rc;
	struct iag *iagp;
	struct metapage *mp;
	int iagno, ino, extno, bitno;
	struct inomap *imap;
	u32 mask;
	struct jfs_log *log;
	int lsn, difft, diffp;
	unsigned long flags;

	imap = JFS_IP(ipimap)->i_imap;
	/* get the iag number containing the inode */
	iagno = INOTOIAG(inum);
	/* make sure that the iag is contained within the map */
	if (iagno >= imap->im_nextiag) {
		jfs_error(ipimap->i_sb, "the iag is outside the map\n");
		return -EIO;
	}
	/* read the iag */
	IREAD_LOCK(ipimap, RDWRLOCK_IMAP);
	rc = diIAGRead(imap, iagno, &mp);
	IREAD_UNLOCK(ipimap);
	if (rc)
		return (rc);
	metapage_wait_for_io(mp);
	iagp = (struct iag *) mp->data;
	/* get the inode number and extent number of the inode within
	 * the iag and the inode number within the extent.
	 */
	ino = inum & (INOSPERIAG - 1);
	extno = ino >> L2INOSPEREXT;
	bitno = ino & (INOSPEREXT - 1);
	mask = HIGHORDER >> bitno;
	/*
	 * mark the inode free in persistent map:
	 */
	if (is_free) {
		/* The inode should have been allocated both in working
		 * map and in persistent map;
		 * the inode will be freed from working map at the release
		 * of last reference release;
		 */
		if (!(le32_to_cpu(iagp->wmap[extno]) & mask)) {
			jfs_error(ipimap->i_sb,
				  "inode %ld not marked as allocated in wmap!\n",
				  inum);
		}
		if (!(le32_to_cpu(iagp->pmap[extno]) & mask)) {
			jfs_error(ipimap->i_sb,
				  "inode %ld not marked as allocated in pmap!\n",
				  inum);
		}
		/* update the bitmap for the extent of the freed inode */
		iagp->pmap[extno] &= cpu_to_le32(~mask);
	}
	/*
	 * mark the inode allocated in persistent map:
	 */
	else {
		/* The inode should be already allocated in the working map
		 * and should be free in persistent map;
		 */
		if (!(le32_to_cpu(iagp->wmap[extno]) & mask)) {
			release_metapage(mp);
			jfs_error(ipimap->i_sb,
				  "the inode is not allocated in the working map\n");
			return -EIO;
		}
		if ((le32_to_cpu(iagp->pmap[extno]) & mask) != 0) {
			release_metapage(mp);
			jfs_error(ipimap->i_sb,
				  "the inode is not free in the persistent map\n");
			return -EIO;
		}
		/* update the bitmap for the extent of the allocated inode */
		iagp->pmap[extno] |= cpu_to_le32(mask);
	}
	/*
	 * update iag lsn
	 */
	lsn = tblk->lsn;
	log = JFS_SBI(tblk->sb)->log;
	LOGSYNC_LOCK(log, flags);
	if (mp->lsn != 0) {
		/* inherit older/smaller lsn */
		logdiff(difft, lsn, log);
		logdiff(diffp, mp->lsn, log);
		if (difft < diffp) {
			mp->lsn = lsn;
			/* move mp after tblock in logsync list */
			list_move(&mp->synclist, &tblk->synclist);
		}
		/* inherit younger/larger clsn */
		assert(mp->clsn);
		logdiff(difft, tblk->clsn, log);
		logdiff(diffp, mp->clsn, log);
		if (difft > diffp)
			mp->clsn = tblk->clsn;
	} else {
		mp->log = log;
		mp->lsn = lsn;
		/* insert mp after tblock in logsync list */
		log->count++;
		list_add(&mp->synclist, &tblk->synclist);
		mp->clsn = tblk->clsn;
	}
	LOGSYNC_UNLOCK(log, flags);
	write_metapage(mp);
	return (0);
}

/*
 *	diExtendFS()
 *
 * function: update imap for extendfs();
 *
 * note: AG size has been increased s.t. each k old contiguous AGs are
 * coalesced into a new AG;
 */
int diExtendFS(struct inode *ipimap, struct inode *ipbmap)
{
	int rc, rcx = 0;
	struct inomap *imap = JFS_IP(ipimap)->i_imap;
	struct iag *iagp = NULL, *hiagp = NULL;
	struct bmap *mp = JFS_SBI(ipbmap->i_sb)->bmap;
	struct metapage *bp, *hbp;
	int i, n, head;
	int numinos, xnuminos = 0, xnumfree = 0;
	s64 agstart;

	jfs_info("diExtendFS: nextiag:%d numinos:%d numfree:%d",
		   imap->im_nextiag, atomic_read(&imap->im_numinos),
		   atomic_read(&imap->im_numfree));

	/*
	 *	reconstruct imap
	 *
	 * coalesce contiguous k (newAGSize/oldAGSize) AGs;
	 * i.e., (AGi, ..., AGj) where i = k*n and j = k*(n+1) - 1 to AGn;
	 * note: new AG size = old AG size * (2**x).
	 */

	/* init per AG control information im_agctl[] */
	for (i = 0; i < MAXAG; i++) {
		imap->im_agctl[i].inofree = -1;
		imap->im_agctl[i].extfree = -1;
		imap->im_agctl[i].numinos = 0;	/* number of backed inodes */
		imap->im_agctl[i].numfree = 0;	/* number of free backed inodes */
	}

	/*
	 *	process each iag page of the map.
	 *
	 * rebuild AG Free Inode List, AG Free Inode Extent List;
	 */
	for (i = 0; i < imap->im_nextiag; i++) {
		if ((rc = diIAGRead(imap, i, &bp))) {
			rcx = rc;
			continue;
		}
		iagp = (struct iag *) bp->data;
		if (le32_to_cpu(iagp->iagnum) != i) {
			release_metapage(bp);
			jfs_error(ipimap->i_sb, "unexpected value of iagnum\n");
			return -EIO;
		}

		/* leave free iag in the free iag list */
		if (iagp->nfreeexts == cpu_to_le32(EXTSPERIAG)) {
			release_metapage(bp);
			continue;
		}

		agstart = le64_to_cpu(iagp->agstart);
		n = agstart >> mp->db_agl2size;
		iagp->agstart = cpu_to_le64((s64)n << mp->db_agl2size);

		/* compute backed inodes */
		numinos = (EXTSPERIAG - le32_to_cpu(iagp->nfreeexts))
		    << L2INOSPEREXT;
		if (numinos > 0) {
			/* merge AG backed inodes */
			imap->im_agctl[n].numinos += numinos;
			xnuminos += numinos;
		}

		/* if any backed free inodes, insert at AG free inode list */
		if ((int) le32_to_cpu(iagp->nfreeinos) > 0) {
			if ((head = imap->im_agctl[n].inofree) == -1) {
				iagp->inofreefwd = cpu_to_le32(-1);
				iagp->inofreeback = cpu_to_le32(-1);
			} else {
				if ((rc = diIAGRead(imap, head, &hbp))) {
					rcx = rc;
					goto nextiag;
				}
				hiagp = (struct iag *) hbp->data;
				hiagp->inofreeback = iagp->iagnum;
				iagp->inofreefwd = cpu_to_le32(head);
				iagp->inofreeback = cpu_to_le32(-1);
				write_metapage(hbp);
			}

			imap->im_agctl[n].inofree =
			    le32_to_cpu(iagp->iagnum);

			/* merge AG backed free inodes */
			imap->im_agctl[n].numfree +=
			    le32_to_cpu(iagp->nfreeinos);
			xnumfree += le32_to_cpu(iagp->nfreeinos);
		}

		/* if any free extents, insert at AG free extent list */
		if (le32_to_cpu(iagp->nfreeexts) > 0) {
			if ((head = imap->im_agctl[n].extfree) == -1) {
				iagp->extfreefwd = cpu_to_le32(-1);
				iagp->extfreeback = cpu_to_le32(-1);
			} else {
				if ((rc = diIAGRead(imap, head, &hbp))) {
					rcx = rc;
					goto nextiag;
				}
				hiagp = (struct iag *) hbp->data;
				hiagp->extfreeback = iagp->iagnum;
				iagp->extfreefwd = cpu_to_le32(head);
				iagp->extfreeback = cpu_to_le32(-1);
				write_metapage(hbp);
			}

			imap->im_agctl[n].extfree =
			    le32_to_cpu(iagp->iagnum);
		}

	      nextiag:
		write_metapage(bp);
	}

	if (xnuminos != atomic_read(&imap->im_numinos) ||
	    xnumfree != atomic_read(&imap->im_numfree)) {
		jfs_error(ipimap->i_sb, "numinos or numfree incorrect\n");
		return -EIO;
	}

	return rcx;
}


/*
 *	duplicateIXtree()
 *
 * serialization: IWRITE_LOCK held on entry/exit
 *
 * note: shadow page with regular inode (rel.2);
 */
static void duplicateIXtree(struct super_block *sb, s64 blkno,
			    int xlen, s64 *xaddr)
{
	struct jfs_superblock *j_sb;
	struct buffer_head *bh;
	struct inode *ip;
	tid_t tid;

	/* if AIT2 ipmap2 is bad, do not try to update it */
	if (JFS_SBI(sb)->mntflag & JFS_BAD_SAIT)	/* s_flag */
		return;
	ip = diReadSpecial(sb, FILESYSTEM_I, 1);
	if (ip == NULL) {
		JFS_SBI(sb)->mntflag |= JFS_BAD_SAIT;
		if (readSuper(sb, &bh))
			return;
		j_sb = (struct jfs_superblock *)bh->b_data;
		j_sb->s_flag |= cpu_to_le32(JFS_BAD_SAIT);

		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);
		return;
	}

	/* start transaction */
	tid = txBegin(sb, COMMIT_FORCE);
	/* update the inode map addressing structure to point to it */
	if (xtInsert(tid, ip, 0, blkno, xlen, xaddr, 0)) {
		JFS_SBI(sb)->mntflag |= JFS_BAD_SAIT;
		txAbort(tid, 1);
		goto cleanup;

	}
	/* update the inode map's inode to reflect the extension */
	ip->i_size += PSIZE;
	inode_add_bytes(ip, PSIZE);
	txCommit(tid, 1, &ip, COMMIT_FORCE);
      cleanup:
	txEnd(tid);
	diFreeSpecial(ip);
}

/*
 * NAME:	copy_from_dinode()
 *
 * FUNCTION:	Copies inode info from disk inode to in-memory inode
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOMEM	- insufficient memory
 */
static int copy_from_dinode(struct dinode * dip, struct inode *ip)
{
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	struct jfs_sb_info *sbi = JFS_SBI(ip->i_sb);

	jfs_ip->fileset = le32_to_cpu(dip->di_fileset);
	jfs_ip->mode2 = le32_to_cpu(dip->di_mode);
	jfs_set_inode_flags(ip);

	ip->i_mode = le32_to_cpu(dip->di_mode) & 0xffff;
	if (sbi->umask != -1) {
		ip->i_mode = (ip->i_mode & ~0777) | (0777 & ~sbi->umask);
		/* For directories, add x permission if r is allowed by umask */
		if (S_ISDIR(ip->i_mode)) {
			if (ip->i_mode & 0400)
				ip->i_mode |= 0100;
			if (ip->i_mode & 0040)
				ip->i_mode |= 0010;
			if (ip->i_mode & 0004)
				ip->i_mode |= 0001;
		}
	}
	set_nlink(ip, le32_to_cpu(dip->di_nlink));

	jfs_ip->saved_uid = make_kuid(&init_user_ns, le32_to_cpu(dip->di_uid));
	if (!uid_valid(sbi->uid))
		ip->i_uid = jfs_ip->saved_uid;
	else {
		ip->i_uid = sbi->uid;
	}

	jfs_ip->saved_gid = make_kgid(&init_user_ns, le32_to_cpu(dip->di_gid));
	if (!gid_valid(sbi->gid))
		ip->i_gid = jfs_ip->saved_gid;
	else {
		ip->i_gid = sbi->gid;
	}

	ip->i_size = le64_to_cpu(dip->di_size);
	ip->i_atime.tv_sec = le32_to_cpu(dip->di_atime.tv_sec);
	ip->i_atime.tv_nsec = le32_to_cpu(dip->di_atime.tv_nsec);
	ip->i_mtime.tv_sec = le32_to_cpu(dip->di_mtime.tv_sec);
	ip->i_mtime.tv_nsec = le32_to_cpu(dip->di_mtime.tv_nsec);
	ip->i_ctime.tv_sec = le32_to_cpu(dip->di_ctime.tv_sec);
	ip->i_ctime.tv_nsec = le32_to_cpu(dip->di_ctime.tv_nsec);
	ip->i_blocks = LBLK2PBLK(ip->i_sb, le64_to_cpu(dip->di_nblocks));
	ip->i_generation = le32_to_cpu(dip->di_gen);

	jfs_ip->ixpxd = dip->di_ixpxd;	/* in-memory pxd's are little-endian */
	jfs_ip->acl = dip->di_acl;	/* as are dxd's */
	jfs_ip->ea = dip->di_ea;
	jfs_ip->next_index = le32_to_cpu(dip->di_next_index);
	jfs_ip->otime = le32_to_cpu(dip->di_otime.tv_sec);
	jfs_ip->acltype = le32_to_cpu(dip->di_acltype);

	if (S_ISCHR(ip->i_mode) || S_ISBLK(ip->i_mode)) {
		jfs_ip->dev = le32_to_cpu(dip->di_rdev);
		ip->i_rdev = new_decode_dev(jfs_ip->dev);
	}

	if (S_ISDIR(ip->i_mode)) {
		memcpy(&jfs_ip->i_dirtable, &dip->di_dirtable, 384);
	} else if (S_ISREG(ip->i_mode) || S_ISLNK(ip->i_mode)) {
		memcpy(&jfs_ip->i_xtroot, &dip->di_xtroot, 288);
	} else
		memcpy(&jfs_ip->i_inline_ea, &dip->di_inlineea, 128);

	/* Zero the in-memory-only stuff */
	jfs_ip->cflag = 0;
	jfs_ip->btindex = 0;
	jfs_ip->btorder = 0;
	jfs_ip->bxflag = 0;
	jfs_ip->blid = 0;
	jfs_ip->atlhead = 0;
	jfs_ip->atltail = 0;
	jfs_ip->xtlid = 0;
	return (0);
}

/*
 * NAME:	copy_to_dinode()
 *
 * FUNCTION:	Copies inode info from in-memory inode to disk inode
 */
static void copy_to_dinode(struct dinode * dip, struct inode *ip)
{
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	struct jfs_sb_info *sbi = JFS_SBI(ip->i_sb);

	dip->di_fileset = cpu_to_le32(jfs_ip->fileset);
	dip->di_inostamp = cpu_to_le32(sbi->inostamp);
	dip->di_number = cpu_to_le32(ip->i_ino);
	dip->di_gen = cpu_to_le32(ip->i_generation);
	dip->di_size = cpu_to_le64(ip->i_size);
	dip->di_nblocks = cpu_to_le64(PBLK2LBLK(ip->i_sb, ip->i_blocks));
	dip->di_nlink = cpu_to_le32(ip->i_nlink);
	if (!uid_valid(sbi->uid))
		dip->di_uid = cpu_to_le32(i_uid_read(ip));
	else
		dip->di_uid =cpu_to_le32(from_kuid(&init_user_ns,
						   jfs_ip->saved_uid));
	if (!gid_valid(sbi->gid))
		dip->di_gid = cpu_to_le32(i_gid_read(ip));
	else
		dip->di_gid = cpu_to_le32(from_kgid(&init_user_ns,
						    jfs_ip->saved_gid));
	jfs_get_inode_flags(jfs_ip);
	/*
	 * mode2 is only needed for storing the higher order bits.
	 * Trust i_mode for the lower order ones
	 */
	if (sbi->umask == -1)
		dip->di_mode = cpu_to_le32((jfs_ip->mode2 & 0xffff0000) |
					   ip->i_mode);
	else /* Leave the original permissions alone */
		dip->di_mode = cpu_to_le32(jfs_ip->mode2);

	dip->di_atime.tv_sec = cpu_to_le32(ip->i_atime.tv_sec);
	dip->di_atime.tv_nsec = cpu_to_le32(ip->i_atime.tv_nsec);
	dip->di_ctime.tv_sec = cpu_to_le32(ip->i_ctime.tv_sec);
	dip->di_ctime.tv_nsec = cpu_to_le32(ip->i_ctime.tv_nsec);
	dip->di_mtime.tv_sec = cpu_to_le32(ip->i_mtime.tv_sec);
	dip->di_mtime.tv_nsec = cpu_to_le32(ip->i_mtime.tv_nsec);
	dip->di_ixpxd = jfs_ip->ixpxd;	/* in-memory pxd's are little-endian */
	dip->di_acl = jfs_ip->acl;	/* as are dxd's */
	dip->di_ea = jfs_ip->ea;
	dip->di_next_index = cpu_to_le32(jfs_ip->next_index);
	dip->di_otime.tv_sec = cpu_to_le32(jfs_ip->otime);
	dip->di_otime.tv_nsec = 0;
	dip->di_acltype = cpu_to_le32(jfs_ip->acltype);
	if (S_ISCHR(ip->i_mode) || S_ISBLK(ip->i_mode))
		dip->di_rdev = cpu_to_le32(jfs_ip->dev);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_imap.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *   Portions Copyright (C) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
// #include <linux/ctype.h>
// #include <linux/module.h>
#include <linux/proc_fs.h>
// #include <linux/seq_file.h>
// #include <asm/uaccess.h>
// #include "jfs_incore.h"
// #include "jfs_filsys.h"
// #include "jfs_debug.h"
#include "../../inc/__fss.h"

#ifdef PROC_FS_JFS /* see jfs_debug.h */

static struct proc_dir_entry *base;
#ifdef CONFIG_JFS_DEBUG
static int jfs_loglevel_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", jfsloglevel);
	return 0;
}

static int jfs_loglevel_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, jfs_loglevel_proc_show, NULL);
}

static ssize_t jfs_loglevel_proc_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{
	char c;

	if (get_user(c, buffer))
		return -EFAULT;

	/* yes, I know this is an ASCIIism.  --hch */
	if (c < '0' || c > '9')
		return -EINVAL;
	jfsloglevel = c - '0';
	return count;
}

static const struct file_operations jfs_loglevel_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= jfs_loglevel_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= jfs_loglevel_proc_write,
};
#endif

static struct {
	const char	*name;
	const struct file_operations *proc_fops;
} Entries[] = {
#ifdef CONFIG_JFS_STATISTICS
	{ "lmstats",	&jfs_lmstats_proc_fops, },
	{ "txstats",	&jfs_txstats_proc_fops, },
	{ "xtstat",	&jfs_xtstat_proc_fops, },
	{ "mpstat",	&jfs_mpstat_proc_fops, },
#endif
#ifdef CONFIG_JFS_DEBUG
	{ "TxAnchor",	&jfs_txanchor_proc_fops, },
	{ "loglevel",	&jfs_loglevel_proc_fops }
#endif
};
#define NPROCENT	ARRAY_SIZE(Entries)

void jfs_proc_init(void)
{
	int i;

	if (!(base = proc_mkdir("fs/jfs", NULL)))
		return;

	for (i = 0; i < NPROCENT; i++)
		proc_create(Entries[i].name, 0, base, Entries[i].proc_fops);
}

void jfs_proc_clean(void)
{
	int i;

	if (base) {
		for (i = 0; i < NPROCENT; i++)
			remove_proc_entry(Entries[i].name, base);
		remove_proc_entry("fs/jfs", NULL);
	}
}

#endif /* PROC_FS_JFS */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_debug.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *   Portions Copyright (C) Tino Reichardt, 2012
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
// #include <linux/slab.h>
// #include "jfs_incore.h"
// #include "jfs_superblock.h"
// #include "jfs_dmap.h"
// #include "jfs_imap.h"
#include "jfs_lock.h"
// #include "jfs_metapage.h"
// #include "jfs_debug.h"
#include "jfs_discard.h"
#include "../../inc/__fss.h"

/*
 *	SERIALIZATION of the Block Allocation Map.
 *
 *	the working state of the block allocation map is accessed in
 *	two directions:
 *
 *	1) allocation and free requests that start at the dmap
 *	   level and move up through the dmap control pages (i.e.
 *	   the vast majority of requests).
 *
 *	2) allocation requests that start at dmap control page
 *	   level and work down towards the dmaps.
 *
 *	the serialization scheme used here is as follows.
 *
 *	requests which start at the bottom are serialized against each
 *	other through buffers and each requests holds onto its buffers
 *	as it works it way up from a single dmap to the required level
 *	of dmap control page.
 *	requests that start at the top are serialized against each other
 *	and request that start from the bottom by the multiple read/single
 *	write inode lock of the bmap inode. requests starting at the top
 *	take this lock in write mode while request starting at the bottom
 *	take the lock in read mode.  a single top-down request may proceed
 *	exclusively while multiple bottoms-up requests may proceed
 *	simultaneously (under the protection of busy buffers).
 *
 *	in addition to information found in dmaps and dmap control pages,
 *	the working state of the block allocation map also includes read/
 *	write information maintained in the bmap descriptor (i.e. total
 *	free block count, allocation group level free block counts).
 *	a single exclusive lock (BMAP_LOCK) is used to guard this information
 *	in the face of multiple-bottoms up requests.
 *	(lock ordering: IREAD_LOCK, BMAP_LOCK);
 *
 *	accesses to the persistent state of the block allocation map (limited
 *	to the persistent bitmaps in dmaps) is guarded by (busy) buffers.
 */

#define BMAP_LOCK_INIT(bmp)	mutex_init(&bmp->db_bmaplock)
#define BMAP_LOCK(bmp)		mutex_lock(&bmp->db_bmaplock)
#define BMAP_UNLOCK(bmp)	mutex_unlock(&bmp->db_bmaplock)

/*
 * forward references
 */
static void dbAllocBits(struct bmap * bmp, struct dmap * dp, s64 blkno,
			int nblocks);
static void dbSplit(dmtree_t * tp, int leafno, int splitsz, int newval);
static int dbBackSplit(dmtree_t * tp, int leafno);
static int dbJoin(dmtree_t * tp, int leafno, int newval);
static void dbAdjTree(dmtree_t * tp, int leafno, int newval);
static int dbAdjCtl(struct bmap * bmp, s64 blkno, int newval, int alloc,
		    int level);
static int dbAllocAny(struct bmap * bmp, s64 nblocks, int l2nb, s64 * results);
static int dbAllocNext(struct bmap * bmp, struct dmap * dp, s64 blkno,
		       int nblocks);
static int dbAllocNear(struct bmap * bmp, struct dmap * dp, s64 blkno,
		       int nblocks,
		       int l2nb, s64 * results);
static int dbAllocDmap(struct bmap * bmp, struct dmap * dp, s64 blkno,
		       int nblocks);
static int dbAllocDmapLev(struct bmap * bmp, struct dmap * dp, int nblocks,
			  int l2nb,
			  s64 * results);
static int dbAllocAG(struct bmap * bmp, int agno, s64 nblocks, int l2nb,
		     s64 * results);
static int dbAllocCtl(struct bmap * bmp, s64 nblocks, int l2nb, s64 blkno,
		      s64 * results);
static int dbExtend(struct inode *ip, s64 blkno, s64 nblocks, s64 addnblocks);
static int dbFindBits(u32 word, int l2nb);
static int dbFindCtl(struct bmap * bmp, int l2nb, int level, s64 * blkno);
static int dbFindLeaf(dmtree_t * tp, int l2nb, int *leafidx);
static int dbFreeBits(struct bmap * bmp, struct dmap * dp, s64 blkno,
		      int nblocks);
static int dbFreeDmap(struct bmap * bmp, struct dmap * dp, s64 blkno,
		      int nblocks);
static int dbMaxBud(u8 * cp);
static int blkstol2(s64 nb);

static int cntlz(u32 value);
static int cnttz(u32 word);

static int dbAllocDmapBU(struct bmap * bmp, struct dmap * dp, s64 blkno,
			 int nblocks);
static int dbInitDmap(struct dmap * dp, s64 blkno, int nblocks);
static int dbInitDmapTree(struct dmap * dp);
static int dbInitTree(struct dmaptree * dtp);
static int dbInitDmapCtl(struct dmapctl * dcp, int level, int i);
static int dbGetL2AGSize(s64 nblocks);

/*
 *	buddy table
 *
 * table used for determining buddy sizes within characters of
 * dmap bitmap words.  the characters themselves serve as indexes
 * into the table, with the table elements yielding the maximum
 * binary buddy of free bits within the character.
 */
static const s8 budtab[256] = {
	3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
	2, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
	2, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
	2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
	2, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
	2, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
	2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	2, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
	2, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
	2, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, -1
};

/*
 * NAME:	dbMount()
 *
 * FUNCTION:	initializate the block allocation map.
 *
 *		memory is allocated for the in-core bmap descriptor and
 *		the in-core descriptor is initialized from disk.
 *
 * PARAMETERS:
 *	ipbmap	- pointer to in-core inode for the block map.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOMEM	- insufficient memory
 *	-EIO	- i/o error
 */
int dbMount(struct inode *ipbmap)
{
	struct bmap *bmp;
	struct dbmap_disk *dbmp_le;
	struct metapage *mp;
	int i;

	/*
	 * allocate/initialize the in-memory bmap descriptor
	 */
	/* allocate memory for the in-memory bmap descriptor */
	bmp = kmalloc(sizeof(struct bmap), GFP_KERNEL);
	if (bmp == NULL)
		return -ENOMEM;

	/* read the on-disk bmap descriptor. */
	mp = read_metapage(ipbmap,
			   BMAPBLKNO << JFS_SBI(ipbmap->i_sb)->l2nbperpage,
			   PSIZE, 0);
	if (mp == NULL) {
		kfree(bmp);
		return -EIO;
	}

	/* copy the on-disk bmap descriptor to its in-memory version. */
	dbmp_le = (struct dbmap_disk *) mp->data;
	bmp->db_mapsize = le64_to_cpu(dbmp_le->dn_mapsize);
	bmp->db_nfree = le64_to_cpu(dbmp_le->dn_nfree);
	bmp->db_l2nbperpage = le32_to_cpu(dbmp_le->dn_l2nbperpage);
	bmp->db_numag = le32_to_cpu(dbmp_le->dn_numag);
	bmp->db_maxlevel = le32_to_cpu(dbmp_le->dn_maxlevel);
	bmp->db_maxag = le32_to_cpu(dbmp_le->dn_maxag);
	bmp->db_agpref = le32_to_cpu(dbmp_le->dn_agpref);
	bmp->db_aglevel = le32_to_cpu(dbmp_le->dn_aglevel);
	bmp->db_agheight = le32_to_cpu(dbmp_le->dn_agheight);
	bmp->db_agwidth = le32_to_cpu(dbmp_le->dn_agwidth);
	bmp->db_agstart = le32_to_cpu(dbmp_le->dn_agstart);
	bmp->db_agl2size = le32_to_cpu(dbmp_le->dn_agl2size);
	for (i = 0; i < MAXAG; i++)
		bmp->db_agfree[i] = le64_to_cpu(dbmp_le->dn_agfree[i]);
	bmp->db_agsize = le64_to_cpu(dbmp_le->dn_agsize);
	bmp->db_maxfreebud = dbmp_le->dn_maxfreebud;

	/* release the buffer. */
	release_metapage(mp);

	/* bind the bmap inode and the bmap descriptor to each other. */
	bmp->db_ipbmap = ipbmap;
	JFS_SBI(ipbmap->i_sb)->bmap = bmp;

	memset(bmp->db_active, 0, sizeof(bmp->db_active));

	/*
	 * allocate/initialize the bmap lock
	 */
	BMAP_LOCK_INIT(bmp);

	return (0);
}


/*
 * NAME:	dbUnmount()
 *
 * FUNCTION:	terminate the block allocation map in preparation for
 *		file system unmount.
 *
 *		the in-core bmap descriptor is written to disk and
 *		the memory for this descriptor is freed.
 *
 * PARAMETERS:
 *	ipbmap	- pointer to in-core inode for the block map.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error
 */
int dbUnmount(struct inode *ipbmap, int mounterror)
{
	struct bmap *bmp = JFS_SBI(ipbmap->i_sb)->bmap;

	if (!(mounterror || isReadOnly(ipbmap)))
		dbSync(ipbmap);

	/*
	 * Invalidate the page cache buffers
	 */
	truncate_inode_pages(ipbmap->i_mapping, 0);

	/* free the memory for the in-memory bmap. */
	kfree(bmp);

	return (0);
}

/*
 *	dbSync()
 */
int dbSync(struct inode *ipbmap)
{
	struct dbmap_disk *dbmp_le;
	struct bmap *bmp = JFS_SBI(ipbmap->i_sb)->bmap;
	struct metapage *mp;
	int i;

	/*
	 * write bmap global control page
	 */
	/* get the buffer for the on-disk bmap descriptor. */
	mp = read_metapage(ipbmap,
			   BMAPBLKNO << JFS_SBI(ipbmap->i_sb)->l2nbperpage,
			   PSIZE, 0);
	if (mp == NULL) {
		jfs_err("dbSync: read_metapage failed!");
		return -EIO;
	}
	/* copy the in-memory version of the bmap to the on-disk version */
	dbmp_le = (struct dbmap_disk *) mp->data;
	dbmp_le->dn_mapsize = cpu_to_le64(bmp->db_mapsize);
	dbmp_le->dn_nfree = cpu_to_le64(bmp->db_nfree);
	dbmp_le->dn_l2nbperpage = cpu_to_le32(bmp->db_l2nbperpage);
	dbmp_le->dn_numag = cpu_to_le32(bmp->db_numag);
	dbmp_le->dn_maxlevel = cpu_to_le32(bmp->db_maxlevel);
	dbmp_le->dn_maxag = cpu_to_le32(bmp->db_maxag);
	dbmp_le->dn_agpref = cpu_to_le32(bmp->db_agpref);
	dbmp_le->dn_aglevel = cpu_to_le32(bmp->db_aglevel);
	dbmp_le->dn_agheight = cpu_to_le32(bmp->db_agheight);
	dbmp_le->dn_agwidth = cpu_to_le32(bmp->db_agwidth);
	dbmp_le->dn_agstart = cpu_to_le32(bmp->db_agstart);
	dbmp_le->dn_agl2size = cpu_to_le32(bmp->db_agl2size);
	for (i = 0; i < MAXAG; i++)
		dbmp_le->dn_agfree[i] = cpu_to_le64(bmp->db_agfree[i]);
	dbmp_le->dn_agsize = cpu_to_le64(bmp->db_agsize);
	dbmp_le->dn_maxfreebud = bmp->db_maxfreebud;

	/* write the buffer */
	write_metapage(mp);

	/*
	 * write out dirty pages of bmap
	 */
	filemap_write_and_wait(ipbmap->i_mapping);

	diWriteSpecial(ipbmap, 0);

	return (0);
}

/*
 * NAME:	dbFree()
 *
 * FUNCTION:	free the specified block range from the working block
 *		allocation map.
 *
 *		the blocks will be free from the working map one dmap
 *		at a time.
 *
 * PARAMETERS:
 *	ip	- pointer to in-core inode;
 *	blkno	- starting block number to be freed.
 *	nblocks	- number of blocks to be freed.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error
 */
int dbFree(struct inode *ip, s64 blkno, s64 nblocks)
{
	struct metapage *mp;
	struct dmap *dp;
	int nb, rc;
	s64 lblkno, rem;
	struct inode *ipbmap = JFS_SBI(ip->i_sb)->ipbmap;
	struct bmap *bmp = JFS_SBI(ip->i_sb)->bmap;
	struct super_block *sb = ipbmap->i_sb;

	IREAD_LOCK(ipbmap, RDWRLOCK_DMAP);

	/* block to be freed better be within the mapsize. */
	if (unlikely((blkno == 0) || (blkno + nblocks > bmp->db_mapsize))) {
		IREAD_UNLOCK(ipbmap);
		printk(KERN_ERR "blkno = %Lx, nblocks = %Lx\n",
		       (unsigned long long) blkno,
		       (unsigned long long) nblocks);
		jfs_error(ip->i_sb, "block to be freed is outside the map\n");
		return -EIO;
	}

	/**
	 * TRIM the blocks, when mounted with discard option
	 */
	if (JFS_SBI(sb)->flag & JFS_DISCARD)
		if (JFS_SBI(sb)->minblks_trim <= nblocks)
			jfs_issue_discard(ipbmap, blkno, nblocks);

	/*
	 * free the blocks a dmap at a time.
	 */
	mp = NULL;
	for (rem = nblocks; rem > 0; rem -= nb, blkno += nb) {
		/* release previous dmap if any */
		if (mp) {
			write_metapage(mp);
		}

		/* get the buffer for the current dmap. */
		lblkno = BLKTODMAP(blkno, bmp->db_l2nbperpage);
		mp = read_metapage(ipbmap, lblkno, PSIZE, 0);
		if (mp == NULL) {
			IREAD_UNLOCK(ipbmap);
			return -EIO;
		}
		dp = (struct dmap *) mp->data;

		/* determine the number of blocks to be freed from
		 * this dmap.
		 */
		nb = min(rem, BPERDMAP - (blkno & (BPERDMAP - 1)));

		/* free the blocks. */
		if ((rc = dbFreeDmap(bmp, dp, blkno, nb))) {
			jfs_error(ip->i_sb, "error in block map\n");
			release_metapage(mp);
			IREAD_UNLOCK(ipbmap);
			return (rc);
		}
	}

	/* write the last buffer. */
	write_metapage(mp);

	IREAD_UNLOCK(ipbmap);

	return (0);
}


/*
 * NAME:	dbUpdatePMap()
 *
 * FUNCTION:	update the allocation state (free or allocate) of the
 *		specified block range in the persistent block allocation map.
 *
 *		the blocks will be updated in the persistent map one
 *		dmap at a time.
 *
 * PARAMETERS:
 *	ipbmap	- pointer to in-core inode for the block map.
 *	free	- 'true' if block range is to be freed from the persistent
 *		  map; 'false' if it is to be allocated.
 *	blkno	- starting block number of the range.
 *	nblocks	- number of contiguous blocks in the range.
 *	tblk	- transaction block;
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error
 */
int
dbUpdatePMap(struct inode *ipbmap,
	     int free, s64 blkno, s64 nblocks, struct tblock * tblk)
{
	int nblks, dbitno, wbitno, rbits;
	int word, nbits, nwords;
	struct bmap *bmp = JFS_SBI(ipbmap->i_sb)->bmap;
	s64 lblkno, rem, lastlblkno;
	u32 mask;
	struct dmap *dp;
	struct metapage *mp;
	struct jfs_log *log;
	int lsn, difft, diffp;
	unsigned long flags;

	/* the blocks better be within the mapsize. */
	if (blkno + nblocks > bmp->db_mapsize) {
		printk(KERN_ERR "blkno = %Lx, nblocks = %Lx\n",
		       (unsigned long long) blkno,
		       (unsigned long long) nblocks);
		jfs_error(ipbmap->i_sb, "blocks are outside the map\n");
		return -EIO;
	}

	/* compute delta of transaction lsn from log syncpt */
	lsn = tblk->lsn;
	log = (struct jfs_log *) JFS_SBI(tblk->sb)->log;
	logdiff(difft, lsn, log);

	/*
	 * update the block state a dmap at a time.
	 */
	mp = NULL;
	lastlblkno = 0;
	for (rem = nblocks; rem > 0; rem -= nblks, blkno += nblks) {
		/* get the buffer for the current dmap. */
		lblkno = BLKTODMAP(blkno, bmp->db_l2nbperpage);
		if (lblkno != lastlblkno) {
			if (mp) {
				write_metapage(mp);
			}

			mp = read_metapage(bmp->db_ipbmap, lblkno, PSIZE,
					   0);
			if (mp == NULL)
				return -EIO;
			metapage_wait_for_io(mp);
		}
		dp = (struct dmap *) mp->data;

		/* determine the bit number and word within the dmap of
		 * the starting block.  also determine how many blocks
		 * are to be updated within this dmap.
		 */
		dbitno = blkno & (BPERDMAP - 1);
		word = dbitno >> L2DBWORD;
		nblks = min(rem, (s64)BPERDMAP - dbitno);

		/* update the bits of the dmap words. the first and last
		 * words may only have a subset of their bits updated. if
		 * this is the case, we'll work against that word (i.e.
		 * partial first and/or last) only in a single pass.  a
		 * single pass will also be used to update all words that
		 * are to have all their bits updated.
		 */
		for (rbits = nblks; rbits > 0;
		     rbits -= nbits, dbitno += nbits) {
			/* determine the bit number within the word and
			 * the number of bits within the word.
			 */
			wbitno = dbitno & (DBWORD - 1);
			nbits = min(rbits, DBWORD - wbitno);

			/* check if only part of the word is to be updated. */
			if (nbits < DBWORD) {
				/* update (free or allocate) the bits
				 * in this word.
				 */
				mask =
				    (ONES << (DBWORD - nbits) >> wbitno);
				if (free)
					dp->pmap[word] &=
					    cpu_to_le32(~mask);
				else
					dp->pmap[word] |=
					    cpu_to_le32(mask);

				word += 1;
			} else {
				/* one or more words are to have all
				 * their bits updated.  determine how
				 * many words and how many bits.
				 */
				nwords = rbits >> L2DBWORD;
				nbits = nwords << L2DBWORD;

				/* update (free or allocate) the bits
				 * in these words.
				 */
				if (free)
					memset(&dp->pmap[word], 0,
					       nwords * 4);
				else
					memset(&dp->pmap[word], (int) ONES,
					       nwords * 4);

				word += nwords;
			}
		}

		/*
		 * update dmap lsn
		 */
		if (lblkno == lastlblkno)
			continue;

		lastlblkno = lblkno;

		LOGSYNC_LOCK(log, flags);
		if (mp->lsn != 0) {
			/* inherit older/smaller lsn */
			logdiff(diffp, mp->lsn, log);
			if (difft < diffp) {
				mp->lsn = lsn;

				/* move bp after tblock in logsync list */
				list_move(&mp->synclist, &tblk->synclist);
			}

			/* inherit younger/larger clsn */
			logdiff(difft, tblk->clsn, log);
			logdiff(diffp, mp->clsn, log);
			if (difft > diffp)
				mp->clsn = tblk->clsn;
		} else {
			mp->log = log;
			mp->lsn = lsn;

			/* insert bp after tblock in logsync list */
			log->count++;
			list_add(&mp->synclist, &tblk->synclist);

			mp->clsn = tblk->clsn;
		}
		LOGSYNC_UNLOCK(log, flags);
	}

	/* write the last buffer. */
	if (mp) {
		write_metapage(mp);
	}

	return (0);
}


/*
 * NAME:	dbNextAG()
 *
 * FUNCTION:	find the preferred allocation group for new allocations.
 *
 *		Within the allocation groups, we maintain a preferred
 *		allocation group which consists of a group with at least
 *		average free space.  It is the preferred group that we target
 *		new inode allocation towards.  The tie-in between inode
 *		allocation and block allocation occurs as we allocate the
 *		first (data) block of an inode and specify the inode (block)
 *		as the allocation hint for this block.
 *
 *		We try to avoid having more than one open file growing in
 *		an allocation group, as this will lead to fragmentation.
 *		This differs from the old OS/2 method of trying to keep
 *		empty ags around for large allocations.
 *
 * PARAMETERS:
 *	ipbmap	- pointer to in-core inode for the block map.
 *
 * RETURN VALUES:
 *	the preferred allocation group number.
 */
int dbNextAG(struct inode *ipbmap)
{
	s64 avgfree;
	int agpref;
	s64 hwm = 0;
	int i;
	int next_best = -1;
	struct bmap *bmp = JFS_SBI(ipbmap->i_sb)->bmap;

	BMAP_LOCK(bmp);

	/* determine the average number of free blocks within the ags. */
	avgfree = (u32)bmp->db_nfree / bmp->db_numag;

	/*
	 * if the current preferred ag does not have an active allocator
	 * and has at least average freespace, return it
	 */
	agpref = bmp->db_agpref;
	if ((atomic_read(&bmp->db_active[agpref]) == 0) &&
	    (bmp->db_agfree[agpref] >= avgfree))
		goto unlock;

	/* From the last preferred ag, find the next one with at least
	 * average free space.
	 */
	for (i = 0 ; i < bmp->db_numag; i++, agpref++) {
		if (agpref == bmp->db_numag)
			agpref = 0;

		if (atomic_read(&bmp->db_active[agpref]))
			/* open file is currently growing in this ag */
			continue;
		if (bmp->db_agfree[agpref] >= avgfree) {
			/* Return this one */
			bmp->db_agpref = agpref;
			goto unlock;
		} else if (bmp->db_agfree[agpref] > hwm) {
			/* Less than avg. freespace, but best so far */
			hwm = bmp->db_agfree[agpref];
			next_best = agpref;
		}
	}

	/*
	 * If no inactive ag was found with average freespace, use the
	 * next best
	 */
	if (next_best != -1)
		bmp->db_agpref = next_best;
	/* else leave db_agpref unchanged */
unlock:
	BMAP_UNLOCK(bmp);

	/* return the preferred group.
	 */
	return (bmp->db_agpref);
}

/*
 * NAME:	dbAlloc()
 *
 * FUNCTION:	attempt to allocate a specified number of contiguous free
 *		blocks from the working allocation block map.
 *
 *		the block allocation policy uses hints and a multi-step
 *		approach.
 *
 *		for allocation requests smaller than the number of blocks
 *		per dmap, we first try to allocate the new blocks
 *		immediately following the hint.  if these blocks are not
 *		available, we try to allocate blocks near the hint.  if
 *		no blocks near the hint are available, we next try to
 *		allocate within the same dmap as contains the hint.
 *
 *		if no blocks are available in the dmap or the allocation
 *		request is larger than the dmap size, we try to allocate
 *		within the same allocation group as contains the hint. if
 *		this does not succeed, we finally try to allocate anywhere
 *		within the aggregate.
 *
 *		we also try to allocate anywhere within the aggregate for
 *		for allocation requests larger than the allocation group
 *		size or requests that specify no hint value.
 *
 * PARAMETERS:
 *	ip	- pointer to in-core inode;
 *	hint	- allocation hint.
 *	nblocks	- number of contiguous blocks in the range.
 *	results	- on successful return, set to the starting block number
 *		  of the newly allocated contiguous range.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 */
int dbAlloc(struct inode *ip, s64 hint, s64 nblocks, s64 * results)
{
	int rc, agno;
	struct inode *ipbmap = JFS_SBI(ip->i_sb)->ipbmap;
	struct bmap *bmp;
	struct metapage *mp;
	s64 lblkno, blkno;
	struct dmap *dp;
	int l2nb;
	s64 mapSize;
	int writers;

	/* assert that nblocks is valid */
	assert(nblocks > 0);

	/* get the log2 number of blocks to be allocated.
	 * if the number of blocks is not a log2 multiple,
	 * it will be rounded up to the next log2 multiple.
	 */
	l2nb = BLKSTOL2(nblocks);

	bmp = JFS_SBI(ip->i_sb)->bmap;

	mapSize = bmp->db_mapsize;

	/* the hint should be within the map */
	if (hint >= mapSize) {
		jfs_error(ip->i_sb, "the hint is outside the map\n");
		return -EIO;
	}

	/* if the number of blocks to be allocated is greater than the
	 * allocation group size, try to allocate anywhere.
	 */
	if (l2nb > bmp->db_agl2size) {
		IWRITE_LOCK(ipbmap, RDWRLOCK_DMAP);

		rc = dbAllocAny(bmp, nblocks, l2nb, results);

		goto write_unlock;
	}

	/*
	 * If no hint, let dbNextAG recommend an allocation group
	 */
	if (hint == 0)
		goto pref_ag;

	/* we would like to allocate close to the hint.  adjust the
	 * hint to the block following the hint since the allocators
	 * will start looking for free space starting at this point.
	 */
	blkno = hint + 1;

	if (blkno >= bmp->db_mapsize)
		goto pref_ag;

	agno = blkno >> bmp->db_agl2size;

	/* check if blkno crosses over into a new allocation group.
	 * if so, check if we should allow allocations within this
	 * allocation group.
	 */
	if ((blkno & (bmp->db_agsize - 1)) == 0)
		/* check if the AG is currently being written to.
		 * if so, call dbNextAG() to find a non-busy
		 * AG with sufficient free space.
		 */
		if (atomic_read(&bmp->db_active[agno]))
			goto pref_ag;

	/* check if the allocation request size can be satisfied from a
	 * single dmap.  if so, try to allocate from the dmap containing
	 * the hint using a tiered strategy.
	 */
	if (nblocks <= BPERDMAP) {
		IREAD_LOCK(ipbmap, RDWRLOCK_DMAP);

		/* get the buffer for the dmap containing the hint.
		 */
		rc = -EIO;
		lblkno = BLKTODMAP(blkno, bmp->db_l2nbperpage);
		mp = read_metapage(ipbmap, lblkno, PSIZE, 0);
		if (mp == NULL)
			goto read_unlock;

		dp = (struct dmap *) mp->data;

		/* first, try to satisfy the allocation request with the
		 * blocks beginning at the hint.
		 */
		if ((rc = dbAllocNext(bmp, dp, blkno, (int) nblocks))
		    != -ENOSPC) {
			if (rc == 0) {
				*results = blkno;
				mark_metapage_dirty(mp);
			}

			release_metapage(mp);
			goto read_unlock;
		}

		writers = atomic_read(&bmp->db_active[agno]);
		if ((writers > 1) ||
		    ((writers == 1) && (JFS_IP(ip)->active_ag != agno))) {
			/*
			 * Someone else is writing in this allocation
			 * group.  To avoid fragmenting, try another ag
			 */
			release_metapage(mp);
			IREAD_UNLOCK(ipbmap);
			goto pref_ag;
		}

		/* next, try to satisfy the allocation request with blocks
		 * near the hint.
		 */
		if ((rc =
		     dbAllocNear(bmp, dp, blkno, (int) nblocks, l2nb, results))
		    != -ENOSPC) {
			if (rc == 0)
				mark_metapage_dirty(mp);

			release_metapage(mp);
			goto read_unlock;
		}

		/* try to satisfy the allocation request with blocks within
		 * the same dmap as the hint.
		 */
		if ((rc = dbAllocDmapLev(bmp, dp, (int) nblocks, l2nb, results))
		    != -ENOSPC) {
			if (rc == 0)
				mark_metapage_dirty(mp);

			release_metapage(mp);
			goto read_unlock;
		}

		release_metapage(mp);
		IREAD_UNLOCK(ipbmap);
	}

	/* try to satisfy the allocation request with blocks within
	 * the same allocation group as the hint.
	 */
	IWRITE_LOCK(ipbmap, RDWRLOCK_DMAP);
	if ((rc = dbAllocAG(bmp, agno, nblocks, l2nb, results)) != -ENOSPC)
		goto write_unlock;

	IWRITE_UNLOCK(ipbmap);


      pref_ag:
	/*
	 * Let dbNextAG recommend a preferred allocation group
	 */
	agno = dbNextAG(ipbmap);
	IWRITE_LOCK(ipbmap, RDWRLOCK_DMAP);

	/* Try to allocate within this allocation group.  if that fails, try to
	 * allocate anywhere in the map.
	 */
	if ((rc = dbAllocAG(bmp, agno, nblocks, l2nb, results)) == -ENOSPC)
		rc = dbAllocAny(bmp, nblocks, l2nb, results);

      write_unlock:
	IWRITE_UNLOCK(ipbmap);

	return (rc);

      read_unlock:
	IREAD_UNLOCK(ipbmap);

	return (rc);
}

#ifdef _NOTYET
/*
 * NAME:	dbAllocExact()
 *
 * FUNCTION:	try to allocate the requested extent;
 *
 * PARAMETERS:
 *	ip	- pointer to in-core inode;
 *	blkno	- extent address;
 *	nblocks	- extent length;
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 */
int dbAllocExact(struct inode *ip, s64 blkno, int nblocks)
{
	int rc;
	struct inode *ipbmap = JFS_SBI(ip->i_sb)->ipbmap;
	struct bmap *bmp = JFS_SBI(ip->i_sb)->bmap;
	struct dmap *dp;
	s64 lblkno;
	struct metapage *mp;

	IREAD_LOCK(ipbmap, RDWRLOCK_DMAP);

	/*
	 * validate extent request:
	 *
	 * note: defragfs policy:
	 *  max 64 blocks will be moved.
	 *  allocation request size must be satisfied from a single dmap.
	 */
	if (nblocks <= 0 || nblocks > BPERDMAP || blkno >= bmp->db_mapsize) {
		IREAD_UNLOCK(ipbmap);
		return -EINVAL;
	}

	if (nblocks > ((s64) 1 << bmp->db_maxfreebud)) {
		/* the free space is no longer available */
		IREAD_UNLOCK(ipbmap);
		return -ENOSPC;
	}

	/* read in the dmap covering the extent */
	lblkno = BLKTODMAP(blkno, bmp->db_l2nbperpage);
	mp = read_metapage(ipbmap, lblkno, PSIZE, 0);
	if (mp == NULL) {
		IREAD_UNLOCK(ipbmap);
		return -EIO;
	}
	dp = (struct dmap *) mp->data;

	/* try to allocate the requested extent */
	rc = dbAllocNext(bmp, dp, blkno, nblocks);

	IREAD_UNLOCK(ipbmap);

	if (rc == 0)
		mark_metapage_dirty(mp);

	release_metapage(mp);

	return (rc);
}
#endif /* _NOTYET */

/*
 * NAME:	dbReAlloc()
 *
 * FUNCTION:	attempt to extend a current allocation by a specified
 *		number of blocks.
 *
 *		this routine attempts to satisfy the allocation request
 *		by first trying to extend the existing allocation in
 *		place by allocating the additional blocks as the blocks
 *		immediately following the current allocation.  if these
 *		blocks are not available, this routine will attempt to
 *		allocate a new set of contiguous blocks large enough
 *		to cover the existing allocation plus the additional
 *		number of blocks required.
 *
 * PARAMETERS:
 *	ip	    -  pointer to in-core inode requiring allocation.
 *	blkno	    -  starting block of the current allocation.
 *	nblocks	    -  number of contiguous blocks within the current
 *		       allocation.
 *	addnblocks  -  number of blocks to add to the allocation.
 *	results	-      on successful return, set to the starting block number
 *		       of the existing allocation if the existing allocation
 *		       was extended in place or to a newly allocated contiguous
 *		       range if the existing allocation could not be extended
 *		       in place.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 */
int
dbReAlloc(struct inode *ip,
	  s64 blkno, s64 nblocks, s64 addnblocks, s64 * results)
{
	int rc;

	/* try to extend the allocation in place.
	 */
	if ((rc = dbExtend(ip, blkno, nblocks, addnblocks)) == 0) {
		*results = blkno;
		return (0);
	} else {
		if (rc != -ENOSPC)
			return (rc);
	}

	/* could not extend the allocation in place, so allocate a
	 * new set of blocks for the entire request (i.e. try to get
	 * a range of contiguous blocks large enough to cover the
	 * existing allocation plus the additional blocks.)
	 */
	return (dbAlloc
		(ip, blkno + nblocks - 1, addnblocks + nblocks, results));
}


/*
 * NAME:	dbExtend()
 *
 * FUNCTION:	attempt to extend a current allocation by a specified
 *		number of blocks.
 *
 *		this routine attempts to satisfy the allocation request
 *		by first trying to extend the existing allocation in
 *		place by allocating the additional blocks as the blocks
 *		immediately following the current allocation.
 *
 * PARAMETERS:
 *	ip	    -  pointer to in-core inode requiring allocation.
 *	blkno	    -  starting block of the current allocation.
 *	nblocks	    -  number of contiguous blocks within the current
 *		       allocation.
 *	addnblocks  -  number of blocks to add to the allocation.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 */
static int dbExtend(struct inode *ip, s64 blkno, s64 nblocks, s64 addnblocks)
{
	struct jfs_sb_info *sbi = JFS_SBI(ip->i_sb);
	s64 lblkno, lastblkno, extblkno;
	uint rel_block;
	struct metapage *mp;
	struct dmap *dp;
	int rc;
	struct inode *ipbmap = sbi->ipbmap;
	struct bmap *bmp;

	/*
	 * We don't want a non-aligned extent to cross a page boundary
	 */
	if (((rel_block = blkno & (sbi->nbperpage - 1))) &&
	    (rel_block + nblocks + addnblocks > sbi->nbperpage))
		return -ENOSPC;

	/* get the last block of the current allocation */
	lastblkno = blkno + nblocks - 1;

	/* determine the block number of the block following
	 * the existing allocation.
	 */
	extblkno = lastblkno + 1;

	IREAD_LOCK(ipbmap, RDWRLOCK_DMAP);

	/* better be within the file system */
	bmp = sbi->bmap;
	if (lastblkno < 0 || lastblkno >= bmp->db_mapsize) {
		IREAD_UNLOCK(ipbmap);
		jfs_error(ip->i_sb, "the block is outside the filesystem\n");
		return -EIO;
	}

	/* we'll attempt to extend the current allocation in place by
	 * allocating the additional blocks as the blocks immediately
	 * following the current allocation.  we only try to extend the
	 * current allocation in place if the number of additional blocks
	 * can fit into a dmap, the last block of the current allocation
	 * is not the last block of the file system, and the start of the
	 * inplace extension is not on an allocation group boundary.
	 */
	if (addnblocks > BPERDMAP || extblkno >= bmp->db_mapsize ||
	    (extblkno & (bmp->db_agsize - 1)) == 0) {
		IREAD_UNLOCK(ipbmap);
		return -ENOSPC;
	}

	/* get the buffer for the dmap containing the first block
	 * of the extension.
	 */
	lblkno = BLKTODMAP(extblkno, bmp->db_l2nbperpage);
	mp = read_metapage(ipbmap, lblkno, PSIZE, 0);
	if (mp == NULL) {
		IREAD_UNLOCK(ipbmap);
		return -EIO;
	}

	dp = (struct dmap *) mp->data;

	/* try to allocate the blocks immediately following the
	 * current allocation.
	 */
	rc = dbAllocNext(bmp, dp, extblkno, (int) addnblocks);

	IREAD_UNLOCK(ipbmap);

	/* were we successful ? */
	if (rc == 0)
		write_metapage(mp);
	else
		/* we were not successful */
		release_metapage(mp);

	return (rc);
}


/*
 * NAME:	dbAllocNext()
 *
 * FUNCTION:	attempt to allocate the blocks of the specified block
 *		range within a dmap.
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	dp	-  pointer to dmap.
 *	blkno	-  starting block number of the range.
 *	nblocks	-  number of contiguous free blocks of the range.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 *
 * serialization: IREAD_LOCK(ipbmap) held on entry/exit;
 */
static int dbAllocNext(struct bmap * bmp, struct dmap * dp, s64 blkno,
		       int nblocks)
{
	int dbitno, word, rembits, nb, nwords, wbitno, nw;
	int l2size;
	s8 *leaf;
	u32 mask;

	if (dp->tree.leafidx != cpu_to_le32(LEAFIND)) {
		jfs_error(bmp->db_ipbmap->i_sb, "Corrupt dmap page\n");
		return -EIO;
	}

	/* pick up a pointer to the leaves of the dmap tree.
	 */
	leaf = dp->tree.stree + le32_to_cpu(dp->tree.leafidx);

	/* determine the bit number and word within the dmap of the
	 * starting block.
	 */
	dbitno = blkno & (BPERDMAP - 1);
	word = dbitno >> L2DBWORD;

	/* check if the specified block range is contained within
	 * this dmap.
	 */
	if (dbitno + nblocks > BPERDMAP)
		return -ENOSPC;

	/* check if the starting leaf indicates that anything
	 * is free.
	 */
	if (leaf[word] == NOFREE)
		return -ENOSPC;

	/* check the dmaps words corresponding to block range to see
	 * if the block range is free.  not all bits of the first and
	 * last words may be contained within the block range.  if this
	 * is the case, we'll work against those words (i.e. partial first
	 * and/or last) on an individual basis (a single pass) and examine
	 * the actual bits to determine if they are free.  a single pass
	 * will be used for all dmap words fully contained within the
	 * specified range.  within this pass, the leaves of the dmap
	 * tree will be examined to determine if the blocks are free. a
	 * single leaf may describe the free space of multiple dmap
	 * words, so we may visit only a subset of the actual leaves
	 * corresponding to the dmap words of the block range.
	 */
	for (rembits = nblocks; rembits > 0; rembits -= nb, dbitno += nb) {
		/* determine the bit number within the word and
		 * the number of bits within the word.
		 */
		wbitno = dbitno & (DBWORD - 1);
		nb = min(rembits, DBWORD - wbitno);

		/* check if only part of the word is to be examined.
		 */
		if (nb < DBWORD) {
			/* check if the bits are free.
			 */
			mask = (ONES << (DBWORD - nb) >> wbitno);
			if ((mask & ~le32_to_cpu(dp->wmap[word])) != mask)
				return -ENOSPC;

			word += 1;
		} else {
			/* one or more dmap words are fully contained
			 * within the block range.  determine how many
			 * words and how many bits.
			 */
			nwords = rembits >> L2DBWORD;
			nb = nwords << L2DBWORD;

			/* now examine the appropriate leaves to determine
			 * if the blocks are free.
			 */
			while (nwords > 0) {
				/* does the leaf describe any free space ?
				 */
				if (leaf[word] < BUDMIN)
					return -ENOSPC;

				/* determine the l2 number of bits provided
				 * by this leaf.
				 */
				l2size =
				    min_t(int, leaf[word], NLSTOL2BSZ(nwords));

				/* determine how many words were handled.
				 */
				nw = BUDSIZE(l2size, BUDMIN);

				nwords -= nw;
				word += nw;
			}
		}
	}

	/* allocate the blocks.
	 */
	return (dbAllocDmap(bmp, dp, blkno, nblocks));
}


/*
 * NAME:	dbAllocNear()
 *
 * FUNCTION:	attempt to allocate a number of contiguous free blocks near
 *		a specified block (hint) within a dmap.
 *
 *		starting with the dmap leaf that covers the hint, we'll
 *		check the next four contiguous leaves for sufficient free
 *		space.  if sufficient free space is found, we'll allocate
 *		the desired free space.
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	dp	-  pointer to dmap.
 *	blkno	-  block number to allocate near.
 *	nblocks	-  actual number of contiguous free blocks desired.
 *	l2nb	-  log2 number of contiguous free blocks desired.
 *	results	-  on successful return, set to the starting block number
 *		   of the newly allocated range.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 *
 * serialization: IREAD_LOCK(ipbmap) held on entry/exit;
 */
static int
dbAllocNear(struct bmap * bmp,
	    struct dmap * dp, s64 blkno, int nblocks, int l2nb, s64 * results)
{
	int word, lword, rc;
	s8 *leaf;

	if (dp->tree.leafidx != cpu_to_le32(LEAFIND)) {
		jfs_error(bmp->db_ipbmap->i_sb, "Corrupt dmap page\n");
		return -EIO;
	}

	leaf = dp->tree.stree + le32_to_cpu(dp->tree.leafidx);

	/* determine the word within the dmap that holds the hint
	 * (i.e. blkno).  also, determine the last word in the dmap
	 * that we'll include in our examination.
	 */
	word = (blkno & (BPERDMAP - 1)) >> L2DBWORD;
	lword = min(word + 4, LPERDMAP);

	/* examine the leaves for sufficient free space.
	 */
	for (; word < lword; word++) {
		/* does the leaf describe sufficient free space ?
		 */
		if (leaf[word] < l2nb)
			continue;

		/* determine the block number within the file system
		 * of the first block described by this dmap word.
		 */
		blkno = le64_to_cpu(dp->start) + (word << L2DBWORD);

		/* if not all bits of the dmap word are free, get the
		 * starting bit number within the dmap word of the required
		 * string of free bits and adjust the block number with the
		 * value.
		 */
		if (leaf[word] < BUDMIN)
			blkno +=
			    dbFindBits(le32_to_cpu(dp->wmap[word]), l2nb);

		/* allocate the blocks.
		 */
		if ((rc = dbAllocDmap(bmp, dp, blkno, nblocks)) == 0)
			*results = blkno;

		return (rc);
	}

	return -ENOSPC;
}


/*
 * NAME:	dbAllocAG()
 *
 * FUNCTION:	attempt to allocate the specified number of contiguous
 *		free blocks within the specified allocation group.
 *
 *		unless the allocation group size is equal to the number
 *		of blocks per dmap, the dmap control pages will be used to
 *		find the required free space, if available.  we start the
 *		search at the highest dmap control page level which
 *		distinctly describes the allocation group's free space
 *		(i.e. the highest level at which the allocation group's
 *		free space is not mixed in with that of any other group).
 *		in addition, we start the search within this level at a
 *		height of the dmapctl dmtree at which the nodes distinctly
 *		describe the allocation group's free space.  at this height,
 *		the allocation group's free space may be represented by 1
 *		or two sub-trees, depending on the allocation group size.
 *		we search the top nodes of these subtrees left to right for
 *		sufficient free space.  if sufficient free space is found,
 *		the subtree is searched to find the leftmost leaf that
 *		has free space.  once we have made it to the leaf, we
 *		move the search to the next lower level dmap control page
 *		corresponding to this leaf.  we continue down the dmap control
 *		pages until we find the dmap that contains or starts the
 *		sufficient free space and we allocate at this dmap.
 *
 *		if the allocation group size is equal to the dmap size,
 *		we'll start at the dmap corresponding to the allocation
 *		group and attempt the allocation at this level.
 *
 *		the dmap control page search is also not performed if the
 *		allocation group is completely free and we go to the first
 *		dmap of the allocation group to do the allocation.  this is
 *		done because the allocation group may be part (not the first
 *		part) of a larger binary buddy system, causing the dmap
 *		control pages to indicate no free space (NOFREE) within
 *		the allocation group.
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	agno	- allocation group number.
 *	nblocks	-  actual number of contiguous free blocks desired.
 *	l2nb	-  log2 number of contiguous free blocks desired.
 *	results	-  on successful return, set to the starting block number
 *		   of the newly allocated range.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 *
 * note: IWRITE_LOCK(ipmap) held on entry/exit;
 */
static int
dbAllocAG(struct bmap * bmp, int agno, s64 nblocks, int l2nb, s64 * results)
{
	struct metapage *mp;
	struct dmapctl *dcp;
	int rc, ti, i, k, m, n, agperlev;
	s64 blkno, lblkno;
	int budmin;

	/* allocation request should not be for more than the
	 * allocation group size.
	 */
	if (l2nb > bmp->db_agl2size) {
		jfs_error(bmp->db_ipbmap->i_sb,
			  "allocation request is larger than the allocation group size\n");
		return -EIO;
	}

	/* determine the starting block number of the allocation
	 * group.
	 */
	blkno = (s64) agno << bmp->db_agl2size;

	/* check if the allocation group size is the minimum allocation
	 * group size or if the allocation group is completely free. if
	 * the allocation group size is the minimum size of BPERDMAP (i.e.
	 * 1 dmap), there is no need to search the dmap control page (below)
	 * that fully describes the allocation group since the allocation
	 * group is already fully described by a dmap.  in this case, we
	 * just call dbAllocCtl() to search the dmap tree and allocate the
	 * required space if available.
	 *
	 * if the allocation group is completely free, dbAllocCtl() is
	 * also called to allocate the required space.  this is done for
	 * two reasons.  first, it makes no sense searching the dmap control
	 * pages for free space when we know that free space exists.  second,
	 * the dmap control pages may indicate that the allocation group
	 * has no free space if the allocation group is part (not the first
	 * part) of a larger binary buddy system.
	 */
	if (bmp->db_agsize == BPERDMAP
	    || bmp->db_agfree[agno] == bmp->db_agsize) {
		rc = dbAllocCtl(bmp, nblocks, l2nb, blkno, results);
		if ((rc == -ENOSPC) &&
		    (bmp->db_agfree[agno] == bmp->db_agsize)) {
			printk(KERN_ERR "blkno = %Lx, blocks = %Lx\n",
			       (unsigned long long) blkno,
			       (unsigned long long) nblocks);
			jfs_error(bmp->db_ipbmap->i_sb,
				  "dbAllocCtl failed in free AG\n");
		}
		return (rc);
	}

	/* the buffer for the dmap control page that fully describes the
	 * allocation group.
	 */
	lblkno = BLKTOCTL(blkno, bmp->db_l2nbperpage, bmp->db_aglevel);
	mp = read_metapage(bmp->db_ipbmap, lblkno, PSIZE, 0);
	if (mp == NULL)
		return -EIO;
	dcp = (struct dmapctl *) mp->data;
	budmin = dcp->budmin;

	if (dcp->leafidx != cpu_to_le32(CTLLEAFIND)) {
		jfs_error(bmp->db_ipbmap->i_sb, "Corrupt dmapctl page\n");
		release_metapage(mp);
		return -EIO;
	}

	/* search the subtree(s) of the dmap control page that describes
	 * the allocation group, looking for sufficient free space.  to begin,
	 * determine how many allocation groups are represented in a dmap
	 * control page at the control page level (i.e. L0, L1, L2) that
	 * fully describes an allocation group. next, determine the starting
	 * tree index of this allocation group within the control page.
	 */
	agperlev =
	    (1 << (L2LPERCTL - (bmp->db_agheight << 1))) / bmp->db_agwidth;
	ti = bmp->db_agstart + bmp->db_agwidth * (agno & (agperlev - 1));

	/* dmap control page trees fan-out by 4 and a single allocation
	 * group may be described by 1 or 2 subtrees within the ag level
	 * dmap control page, depending upon the ag size. examine the ag's
	 * subtrees for sufficient free space, starting with the leftmost
	 * subtree.
	 */
	for (i = 0; i < bmp->db_agwidth; i++, ti++) {
		/* is there sufficient free space ?
		 */
		if (l2nb > dcp->stree[ti])
			continue;

		/* sufficient free space found in a subtree. now search down
		 * the subtree to find the leftmost leaf that describes this
		 * free space.
		 */
		for (k = bmp->db_agheight; k > 0; k--) {
			for (n = 0, m = (ti << 2) + 1; n < 4; n++) {
				if (l2nb <= dcp->stree[m + n]) {
					ti = m + n;
					break;
				}
			}
			if (n == 4) {
				jfs_error(bmp->db_ipbmap->i_sb,
					  "failed descending stree\n");
				release_metapage(mp);
				return -EIO;
			}
		}

		/* determine the block number within the file system
		 * that corresponds to this leaf.
		 */
		if (bmp->db_aglevel == 2)
			blkno = 0;
		else if (bmp->db_aglevel == 1)
			blkno &= ~(MAXL1SIZE - 1);
		else		/* bmp->db_aglevel == 0 */
			blkno &= ~(MAXL0SIZE - 1);

		blkno +=
		    ((s64) (ti - le32_to_cpu(dcp->leafidx))) << budmin;

		/* release the buffer in preparation for going down
		 * the next level of dmap control pages.
		 */
		release_metapage(mp);

		/* check if we need to continue to search down the lower
		 * level dmap control pages.  we need to if the number of
		 * blocks required is less than maximum number of blocks
		 * described at the next lower level.
		 */
		if (l2nb < budmin) {

			/* search the lower level dmap control pages to get
			 * the starting block number of the dmap that
			 * contains or starts off the free space.
			 */
			if ((rc =
			     dbFindCtl(bmp, l2nb, bmp->db_aglevel - 1,
				       &blkno))) {
				if (rc == -ENOSPC) {
					jfs_error(bmp->db_ipbmap->i_sb,
						  "control page inconsistent\n");
					return -EIO;
				}
				return (rc);
			}
		}

		/* allocate the blocks.
		 */
		rc = dbAllocCtl(bmp, nblocks, l2nb, blkno, results);
		if (rc == -ENOSPC) {
			jfs_error(bmp->db_ipbmap->i_sb,
				  "unable to allocate blocks\n");
			rc = -EIO;
		}
		return (rc);
	}

	/* no space in the allocation group.  release the buffer and
	 * return -ENOSPC.
	 */
	release_metapage(mp);

	return -ENOSPC;
}


/*
 * NAME:	dbAllocAny()
 *
 * FUNCTION:	attempt to allocate the specified number of contiguous
 *		free blocks anywhere in the file system.
 *
 *		dbAllocAny() attempts to find the sufficient free space by
 *		searching down the dmap control pages, starting with the
 *		highest level (i.e. L0, L1, L2) control page.  if free space
 *		large enough to satisfy the desired free space is found, the
 *		desired free space is allocated.
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	nblocks	 -  actual number of contiguous free blocks desired.
 *	l2nb	 -  log2 number of contiguous free blocks desired.
 *	results	-  on successful return, set to the starting block number
 *		   of the newly allocated range.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 *
 * serialization: IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static int dbAllocAny(struct bmap * bmp, s64 nblocks, int l2nb, s64 * results)
{
	int rc;
	s64 blkno = 0;

	/* starting with the top level dmap control page, search
	 * down the dmap control levels for sufficient free space.
	 * if free space is found, dbFindCtl() returns the starting
	 * block number of the dmap that contains or starts off the
	 * range of free space.
	 */
	if ((rc = dbFindCtl(bmp, l2nb, bmp->db_maxlevel, &blkno)))
		return (rc);

	/* allocate the blocks.
	 */
	rc = dbAllocCtl(bmp, nblocks, l2nb, blkno, results);
	if (rc == -ENOSPC) {
		jfs_error(bmp->db_ipbmap->i_sb, "unable to allocate blocks\n");
		return -EIO;
	}
	return (rc);
}


/*
 * NAME:	dbDiscardAG()
 *
 * FUNCTION:	attempt to discard (TRIM) all free blocks of specific AG
 *
 *		algorithm:
 *		1) allocate blocks, as large as possible and save them
 *		   while holding IWRITE_LOCK on ipbmap
 *		2) trim all these saved block/length values
 *		3) mark the blocks free again
 *
 *		benefit:
 *		- we work only on one ag at some time, minimizing how long we
 *		  need to lock ipbmap
 *		- reading / writing the fs is possible most time, even on
 *		  trimming
 *
 *		downside:
 *		- we write two times to the dmapctl and dmap pages
 *		- but for me, this seems the best way, better ideas?
 *		/TR 2012
 *
 * PARAMETERS:
 *	ip	- pointer to in-core inode
 *	agno	- ag to trim
 *	minlen	- minimum value of contiguous blocks
 *
 * RETURN VALUES:
 *	s64	- actual number of blocks trimmed
 */
s64 dbDiscardAG(struct inode *ip, int agno, s64 minlen)
{
	struct inode *ipbmap = JFS_SBI(ip->i_sb)->ipbmap;
	struct bmap *bmp = JFS_SBI(ip->i_sb)->bmap;
	s64 nblocks, blkno;
	u64 trimmed = 0;
	int rc, l2nb;
	struct super_block *sb = ipbmap->i_sb;

	struct range2trim {
		u64 blkno;
		u64 nblocks;
	} *totrim, *tt;

	/* max blkno / nblocks pairs to trim */
	int count = 0, range_cnt;
	u64 max_ranges;

	/* prevent others from writing new stuff here, while trimming */
	IWRITE_LOCK(ipbmap, RDWRLOCK_DMAP);

	nblocks = bmp->db_agfree[agno];
	max_ranges = nblocks;
	do_div(max_ranges, minlen);
	range_cnt = min_t(u64, max_ranges + 1, 32 * 1024);
	totrim = kmalloc(sizeof(struct range2trim) * range_cnt, GFP_NOFS);
	if (totrim == NULL) {
		jfs_error(bmp->db_ipbmap->i_sb, "no memory for trim array\n");
		IWRITE_UNLOCK(ipbmap);
		return 0;
	}

	tt = totrim;
	while (nblocks >= minlen) {
		l2nb = BLKSTOL2(nblocks);

		/* 0 = okay, -EIO = fatal, -ENOSPC -> try smaller block */
		rc = dbAllocAG(bmp, agno, nblocks, l2nb, &blkno);
		if (rc == 0) {
			tt->blkno = blkno;
			tt->nblocks = nblocks;
			tt++; count++;

			/* the whole ag is free, trim now */
			if (bmp->db_agfree[agno] == 0)
				break;

			/* give a hint for the next while */
			nblocks = bmp->db_agfree[agno];
			continue;
		} else if (rc == -ENOSPC) {
			/* search for next smaller log2 block */
			l2nb = BLKSTOL2(nblocks) - 1;
			nblocks = 1 << l2nb;
		} else {
			/* Trim any already allocated blocks */
			jfs_error(bmp->db_ipbmap->i_sb, "-EIO\n");
			break;
		}

		/* check, if our trim array is full */
		if (unlikely(count >= range_cnt - 1))
			break;
	}
	IWRITE_UNLOCK(ipbmap);

	tt->nblocks = 0; /* mark the current end */
	for (tt = totrim; tt->nblocks != 0; tt++) {
		/* when mounted with online discard, dbFree() will
		 * call jfs_issue_discard() itself */
		if (!(JFS_SBI(sb)->flag & JFS_DISCARD))
			jfs_issue_discard(ip, tt->blkno, tt->nblocks);
		dbFree(ip, tt->blkno, tt->nblocks);
		trimmed += tt->nblocks;
	}
	kfree(totrim);

	return trimmed;
}

/*
 * NAME:	dbFindCtl()
 *
 * FUNCTION:	starting at a specified dmap control page level and block
 *		number, search down the dmap control levels for a range of
 *		contiguous free blocks large enough to satisfy an allocation
 *		request for the specified number of free blocks.
 *
 *		if sufficient contiguous free blocks are found, this routine
 *		returns the starting block number within a dmap page that
 *		contains or starts a range of contiqious free blocks that
 *		is sufficient in size.
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	level	-  starting dmap control page level.
 *	l2nb	-  log2 number of contiguous free blocks desired.
 *	*blkno	-  on entry, starting block number for conducting the search.
 *		   on successful return, the first block within a dmap page
 *		   that contains or starts a range of contiguous free blocks.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 *
 * serialization: IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static int dbFindCtl(struct bmap * bmp, int l2nb, int level, s64 * blkno)
{
	int rc, leafidx, lev;
	s64 b, lblkno;
	struct dmapctl *dcp;
	int budmin;
	struct metapage *mp;

	/* starting at the specified dmap control page level and block
	 * number, search down the dmap control levels for the starting
	 * block number of a dmap page that contains or starts off
	 * sufficient free blocks.
	 */
	for (lev = level, b = *blkno; lev >= 0; lev--) {
		/* get the buffer of the dmap control page for the block
		 * number and level (i.e. L0, L1, L2).
		 */
		lblkno = BLKTOCTL(b, bmp->db_l2nbperpage, lev);
		mp = read_metapage(bmp->db_ipbmap, lblkno, PSIZE, 0);
		if (mp == NULL)
			return -EIO;
		dcp = (struct dmapctl *) mp->data;
		budmin = dcp->budmin;

		if (dcp->leafidx != cpu_to_le32(CTLLEAFIND)) {
			jfs_error(bmp->db_ipbmap->i_sb,
				  "Corrupt dmapctl page\n");
			release_metapage(mp);
			return -EIO;
		}

		/* search the tree within the dmap control page for
		 * sufficient free space.  if sufficient free space is found,
		 * dbFindLeaf() returns the index of the leaf at which
		 * free space was found.
		 */
		rc = dbFindLeaf((dmtree_t *) dcp, l2nb, &leafidx);

		/* release the buffer.
		 */
		release_metapage(mp);

		/* space found ?
		 */
		if (rc) {
			if (lev != level) {
				jfs_error(bmp->db_ipbmap->i_sb,
					  "dmap inconsistent\n");
				return -EIO;
			}
			return -ENOSPC;
		}

		/* adjust the block number to reflect the location within
		 * the dmap control page (i.e. the leaf) at which free
		 * space was found.
		 */
		b += (((s64) leafidx) << budmin);

		/* we stop the search at this dmap control page level if
		 * the number of blocks required is greater than or equal
		 * to the maximum number of blocks described at the next
		 * (lower) level.
		 */
		if (l2nb >= budmin)
			break;
	}

	*blkno = b;
	return (0);
}


/*
 * NAME:	dbAllocCtl()
 *
 * FUNCTION:	attempt to allocate a specified number of contiguous
 *		blocks starting within a specific dmap.
 *
 *		this routine is called by higher level routines that search
 *		the dmap control pages above the actual dmaps for contiguous
 *		free space.  the result of successful searches by these
 *		routines are the starting block numbers within dmaps, with
 *		the dmaps themselves containing the desired contiguous free
 *		space or starting a contiguous free space of desired size
 *		that is made up of the blocks of one or more dmaps. these
 *		calls should not fail due to insufficent resources.
 *
 *		this routine is called in some cases where it is not known
 *		whether it will fail due to insufficient resources.  more
 *		specifically, this occurs when allocating from an allocation
 *		group whose size is equal to the number of blocks per dmap.
 *		in this case, the dmap control pages are not examined prior
 *		to calling this routine (to save pathlength) and the call
 *		might fail.
 *
 *		for a request size that fits within a dmap, this routine relies
 *		upon the dmap's dmtree to find the requested contiguous free
 *		space.  for request sizes that are larger than a dmap, the
 *		requested free space will start at the first block of the
 *		first dmap (i.e. blkno).
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	nblocks	 -  actual number of contiguous free blocks to allocate.
 *	l2nb	 -  log2 number of contiguous free blocks to allocate.
 *	blkno	 -  starting block number of the dmap to start the allocation
 *		    from.
 *	results	-  on successful return, set to the starting block number
 *		   of the newly allocated range.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 *
 * serialization: IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static int
dbAllocCtl(struct bmap * bmp, s64 nblocks, int l2nb, s64 blkno, s64 * results)
{
	int rc, nb;
	s64 b, lblkno, n;
	struct metapage *mp;
	struct dmap *dp;

	/* check if the allocation request is confined to a single dmap.
	 */
	if (l2nb <= L2BPERDMAP) {
		/* get the buffer for the dmap.
		 */
		lblkno = BLKTODMAP(blkno, bmp->db_l2nbperpage);
		mp = read_metapage(bmp->db_ipbmap, lblkno, PSIZE, 0);
		if (mp == NULL)
			return -EIO;
		dp = (struct dmap *) mp->data;

		/* try to allocate the blocks.
		 */
		rc = dbAllocDmapLev(bmp, dp, (int) nblocks, l2nb, results);
		if (rc == 0)
			mark_metapage_dirty(mp);

		release_metapage(mp);

		return (rc);
	}

	/* allocation request involving multiple dmaps. it must start on
	 * a dmap boundary.
	 */
	assert((blkno & (BPERDMAP - 1)) == 0);

	/* allocate the blocks dmap by dmap.
	 */
	for (n = nblocks, b = blkno; n > 0; n -= nb, b += nb) {
		/* get the buffer for the dmap.
		 */
		lblkno = BLKTODMAP(b, bmp->db_l2nbperpage);
		mp = read_metapage(bmp->db_ipbmap, lblkno, PSIZE, 0);
		if (mp == NULL) {
			rc = -EIO;
			goto backout;
		}
		dp = (struct dmap *) mp->data;

		/* the dmap better be all free.
		 */
		if (dp->tree.stree[ROOT] != L2BPERDMAP) {
			release_metapage(mp);
			jfs_error(bmp->db_ipbmap->i_sb,
				  "the dmap is not all free\n");
			rc = -EIO;
			goto backout;
		}

		/* determine how many blocks to allocate from this dmap.
		 */
		nb = min_t(s64, n, BPERDMAP);

		/* allocate the blocks from the dmap.
		 */
		if ((rc = dbAllocDmap(bmp, dp, b, nb))) {
			release_metapage(mp);
			goto backout;
		}

		/* write the buffer.
		 */
		write_metapage(mp);
	}

	/* set the results (starting block number) and return.
	 */
	*results = blkno;
	return (0);

	/* something failed in handling an allocation request involving
	 * multiple dmaps.  we'll try to clean up by backing out any
	 * allocation that has already happened for this request.  if
	 * we fail in backing out the allocation, we'll mark the file
	 * system to indicate that blocks have been leaked.
	 */
      backout:

	/* try to backout the allocations dmap by dmap.
	 */
	for (n = nblocks - n, b = blkno; n > 0;
	     n -= BPERDMAP, b += BPERDMAP) {
		/* get the buffer for this dmap.
		 */
		lblkno = BLKTODMAP(b, bmp->db_l2nbperpage);
		mp = read_metapage(bmp->db_ipbmap, lblkno, PSIZE, 0);
		if (mp == NULL) {
			/* could not back out.  mark the file system
			 * to indicate that we have leaked blocks.
			 */
			jfs_error(bmp->db_ipbmap->i_sb,
				  "I/O Error: Block Leakage\n");
			continue;
		}
		dp = (struct dmap *) mp->data;

		/* free the blocks is this dmap.
		 */
		if (dbFreeDmap(bmp, dp, b, BPERDMAP)) {
			/* could not back out.  mark the file system
			 * to indicate that we have leaked blocks.
			 */
			release_metapage(mp);
			jfs_error(bmp->db_ipbmap->i_sb, "Block Leakage\n");
			continue;
		}

		/* write the buffer.
		 */
		write_metapage(mp);
	}

	return (rc);
}


/*
 * NAME:	dbAllocDmapLev()
 *
 * FUNCTION:	attempt to allocate a specified number of contiguous blocks
 *		from a specified dmap.
 *
 *		this routine checks if the contiguous blocks are available.
 *		if so, nblocks of blocks are allocated; otherwise, ENOSPC is
 *		returned.
 *
 * PARAMETERS:
 *	mp	-  pointer to bmap descriptor
 *	dp	-  pointer to dmap to attempt to allocate blocks from.
 *	l2nb	-  log2 number of contiguous block desired.
 *	nblocks	-  actual number of contiguous block desired.
 *	results	-  on successful return, set to the starting block number
 *		   of the newly allocated range.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient disk resources
 *	-EIO	- i/o error
 *
 * serialization: IREAD_LOCK(ipbmap), e.g., from dbAlloc(), or
 *	IWRITE_LOCK(ipbmap), e.g., dbAllocCtl(), held on entry/exit;
 */
static int
dbAllocDmapLev(struct bmap * bmp,
	       struct dmap * dp, int nblocks, int l2nb, s64 * results)
{
	s64 blkno;
	int leafidx, rc;

	/* can't be more than a dmaps worth of blocks */
	assert(l2nb <= L2BPERDMAP);

	/* search the tree within the dmap page for sufficient
	 * free space.  if sufficient free space is found, dbFindLeaf()
	 * returns the index of the leaf at which free space was found.
	 */
	if (dbFindLeaf((dmtree_t *) & dp->tree, l2nb, &leafidx))
		return -ENOSPC;

	/* determine the block number within the file system corresponding
	 * to the leaf at which free space was found.
	 */
	blkno = le64_to_cpu(dp->start) + (leafidx << L2DBWORD);

	/* if not all bits of the dmap word are free, get the starting
	 * bit number within the dmap word of the required string of free
	 * bits and adjust the block number with this value.
	 */
	if (dp->tree.stree[leafidx + LEAFIND] < BUDMIN)
		blkno += dbFindBits(le32_to_cpu(dp->wmap[leafidx]), l2nb);

	/* allocate the blocks */
	if ((rc = dbAllocDmap(bmp, dp, blkno, nblocks)) == 0)
		*results = blkno;

	return (rc);
}


/*
 * NAME:	dbAllocDmap()
 *
 * FUNCTION:	adjust the disk allocation map to reflect the allocation
 *		of a specified block range within a dmap.
 *
 *		this routine allocates the specified blocks from the dmap
 *		through a call to dbAllocBits(). if the allocation of the
 *		block range causes the maximum string of free blocks within
 *		the dmap to change (i.e. the value of the root of the dmap's
 *		dmtree), this routine will cause this change to be reflected
 *		up through the appropriate levels of the dmap control pages
 *		by a call to dbAdjCtl() for the L0 dmap control page that
 *		covers this dmap.
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	dp	-  pointer to dmap to allocate the block range from.
 *	blkno	-  starting block number of the block to be allocated.
 *	nblocks	-  number of blocks to be allocated.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error
 *
 * serialization: IREAD_LOCK(ipbmap) or IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static int dbAllocDmap(struct bmap * bmp, struct dmap * dp, s64 blkno,
		       int nblocks)
{
	s8 oldroot;
	int rc;

	/* save the current value of the root (i.e. maximum free string)
	 * of the dmap tree.
	 */
	oldroot = dp->tree.stree[ROOT];

	/* allocate the specified (blocks) bits */
	dbAllocBits(bmp, dp, blkno, nblocks);

	/* if the root has not changed, done. */
	if (dp->tree.stree[ROOT] == oldroot)
		return (0);

	/* root changed. bubble the change up to the dmap control pages.
	 * if the adjustment of the upper level control pages fails,
	 * backout the bit allocation (thus making everything consistent).
	 */
	if ((rc = dbAdjCtl(bmp, blkno, dp->tree.stree[ROOT], 1, 0)))
		dbFreeBits(bmp, dp, blkno, nblocks);

	return (rc);
}


/*
 * NAME:	dbFreeDmap()
 *
 * FUNCTION:	adjust the disk allocation map to reflect the allocation
 *		of a specified block range within a dmap.
 *
 *		this routine frees the specified blocks from the dmap through
 *		a call to dbFreeBits(). if the deallocation of the block range
 *		causes the maximum string of free blocks within the dmap to
 *		change (i.e. the value of the root of the dmap's dmtree), this
 *		routine will cause this change to be reflected up through the
 *		appropriate levels of the dmap control pages by a call to
 *		dbAdjCtl() for the L0 dmap control page that covers this dmap.
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	dp	-  pointer to dmap to free the block range from.
 *	blkno	-  starting block number of the block to be freed.
 *	nblocks	-  number of blocks to be freed.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error
 *
 * serialization: IREAD_LOCK(ipbmap) or IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static int dbFreeDmap(struct bmap * bmp, struct dmap * dp, s64 blkno,
		      int nblocks)
{
	s8 oldroot;
	int rc = 0, word;

	/* save the current value of the root (i.e. maximum free string)
	 * of the dmap tree.
	 */
	oldroot = dp->tree.stree[ROOT];

	/* free the specified (blocks) bits */
	rc = dbFreeBits(bmp, dp, blkno, nblocks);

	/* if error or the root has not changed, done. */
	if (rc || (dp->tree.stree[ROOT] == oldroot))
		return (rc);

	/* root changed. bubble the change up to the dmap control pages.
	 * if the adjustment of the upper level control pages fails,
	 * backout the deallocation.
	 */
	if ((rc = dbAdjCtl(bmp, blkno, dp->tree.stree[ROOT], 0, 0))) {
		word = (blkno & (BPERDMAP - 1)) >> L2DBWORD;

		/* as part of backing out the deallocation, we will have
		 * to back split the dmap tree if the deallocation caused
		 * the freed blocks to become part of a larger binary buddy
		 * system.
		 */
		if (dp->tree.stree[word] == NOFREE)
			dbBackSplit((dmtree_t *) & dp->tree, word);

		dbAllocBits(bmp, dp, blkno, nblocks);
	}

	return (rc);
}


/*
 * NAME:	dbAllocBits()
 *
 * FUNCTION:	allocate a specified block range from a dmap.
 *
 *		this routine updates the dmap to reflect the working
 *		state allocation of the specified block range. it directly
 *		updates the bits of the working map and causes the adjustment
 *		of the binary buddy system described by the dmap's dmtree
 *		leaves to reflect the bits allocated.  it also causes the
 *		dmap's dmtree, as a whole, to reflect the allocated range.
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	dp	-  pointer to dmap to allocate bits from.
 *	blkno	-  starting block number of the bits to be allocated.
 *	nblocks	-  number of bits to be allocated.
 *
 * RETURN VALUES: none
 *
 * serialization: IREAD_LOCK(ipbmap) or IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static void dbAllocBits(struct bmap * bmp, struct dmap * dp, s64 blkno,
			int nblocks)
{
	int dbitno, word, rembits, nb, nwords, wbitno, nw, agno;
	dmtree_t *tp = (dmtree_t *) & dp->tree;
	int size;
	s8 *leaf;

	/* pick up a pointer to the leaves of the dmap tree */
	leaf = dp->tree.stree + LEAFIND;

	/* determine the bit number and word within the dmap of the
	 * starting block.
	 */
	dbitno = blkno & (BPERDMAP - 1);
	word = dbitno >> L2DBWORD;

	/* block range better be within the dmap */
	assert(dbitno + nblocks <= BPERDMAP);

	/* allocate the bits of the dmap's words corresponding to the block
	 * range. not all bits of the first and last words may be contained
	 * within the block range.  if this is the case, we'll work against
	 * those words (i.e. partial first and/or last) on an individual basis
	 * (a single pass), allocating the bits of interest by hand and
	 * updating the leaf corresponding to the dmap word. a single pass
	 * will be used for all dmap words fully contained within the
	 * specified range.  within this pass, the bits of all fully contained
	 * dmap words will be marked as free in a single shot and the leaves
	 * will be updated. a single leaf may describe the free space of
	 * multiple dmap words, so we may update only a subset of the actual
	 * leaves corresponding to the dmap words of the block range.
	 */
	for (rembits = nblocks; rembits > 0; rembits -= nb, dbitno += nb) {
		/* determine the bit number within the word and
		 * the number of bits within the word.
		 */
		wbitno = dbitno & (DBWORD - 1);
		nb = min(rembits, DBWORD - wbitno);

		/* check if only part of a word is to be allocated.
		 */
		if (nb < DBWORD) {
			/* allocate (set to 1) the appropriate bits within
			 * this dmap word.
			 */
			dp->wmap[word] |= cpu_to_le32(ONES << (DBWORD - nb)
						      >> wbitno);

			/* update the leaf for this dmap word. in addition
			 * to setting the leaf value to the binary buddy max
			 * of the updated dmap word, dbSplit() will split
			 * the binary system of the leaves if need be.
			 */
			dbSplit(tp, word, BUDMIN,
				dbMaxBud((u8 *) & dp->wmap[word]));

			word += 1;
		} else {
			/* one or more dmap words are fully contained
			 * within the block range.  determine how many
			 * words and allocate (set to 1) the bits of these
			 * words.
			 */
			nwords = rembits >> L2DBWORD;
			memset(&dp->wmap[word], (int) ONES, nwords * 4);

			/* determine how many bits.
			 */
			nb = nwords << L2DBWORD;

			/* now update the appropriate leaves to reflect
			 * the allocated words.
			 */
			for (; nwords > 0; nwords -= nw) {
				if (leaf[word] < BUDMIN) {
					jfs_error(bmp->db_ipbmap->i_sb,
						  "leaf page corrupt\n");
					break;
				}

				/* determine what the leaf value should be
				 * updated to as the minimum of the l2 number
				 * of bits being allocated and the l2 number
				 * of bits currently described by this leaf.
				 */
				size = min_t(int, leaf[word],
					     NLSTOL2BSZ(nwords));

				/* update the leaf to reflect the allocation.
				 * in addition to setting the leaf value to
				 * NOFREE, dbSplit() will split the binary
				 * system of the leaves to reflect the current
				 * allocation (size).
				 */
				dbSplit(tp, word, size, NOFREE);

				/* get the number of dmap words handled */
				nw = BUDSIZE(size, BUDMIN);
				word += nw;
			}
		}
	}

	/* update the free count for this dmap */
	le32_add_cpu(&dp->nfree, -nblocks);

	BMAP_LOCK(bmp);

	/* if this allocation group is completely free,
	 * update the maximum allocation group number if this allocation
	 * group is the new max.
	 */
	agno = blkno >> bmp->db_agl2size;
	if (agno > bmp->db_maxag)
		bmp->db_maxag = agno;

	/* update the free count for the allocation group and map */
	bmp->db_agfree[agno] -= nblocks;
	bmp->db_nfree -= nblocks;

	BMAP_UNLOCK(bmp);
}


/*
 * NAME:	dbFreeBits()
 *
 * FUNCTION:	free a specified block range from a dmap.
 *
 *		this routine updates the dmap to reflect the working
 *		state allocation of the specified block range. it directly
 *		updates the bits of the working map and causes the adjustment
 *		of the binary buddy system described by the dmap's dmtree
 *		leaves to reflect the bits freed.  it also causes the dmap's
 *		dmtree, as a whole, to reflect the deallocated range.
 *
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	dp	-  pointer to dmap to free bits from.
 *	blkno	-  starting block number of the bits to be freed.
 *	nblocks	-  number of bits to be freed.
 *
 * RETURN VALUES: 0 for success
 *
 * serialization: IREAD_LOCK(ipbmap) or IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static int dbFreeBits(struct bmap * bmp, struct dmap * dp, s64 blkno,
		       int nblocks)
{
	int dbitno, word, rembits, nb, nwords, wbitno, nw, agno;
	dmtree_t *tp = (dmtree_t *) & dp->tree;
	int rc = 0;
	int size;

	/* determine the bit number and word within the dmap of the
	 * starting block.
	 */
	dbitno = blkno & (BPERDMAP - 1);
	word = dbitno >> L2DBWORD;

	/* block range better be within the dmap.
	 */
	assert(dbitno + nblocks <= BPERDMAP);

	/* free the bits of the dmaps words corresponding to the block range.
	 * not all bits of the first and last words may be contained within
	 * the block range.  if this is the case, we'll work against those
	 * words (i.e. partial first and/or last) on an individual basis
	 * (a single pass), freeing the bits of interest by hand and updating
	 * the leaf corresponding to the dmap word. a single pass will be used
	 * for all dmap words fully contained within the specified range.
	 * within this pass, the bits of all fully contained dmap words will
	 * be marked as free in a single shot and the leaves will be updated. a
	 * single leaf may describe the free space of multiple dmap words,
	 * so we may update only a subset of the actual leaves corresponding
	 * to the dmap words of the block range.
	 *
	 * dbJoin() is used to update leaf values and will join the binary
	 * buddy system of the leaves if the new leaf values indicate this
	 * should be done.
	 */
	for (rembits = nblocks; rembits > 0; rembits -= nb, dbitno += nb) {
		/* determine the bit number within the word and
		 * the number of bits within the word.
		 */
		wbitno = dbitno & (DBWORD - 1);
		nb = min(rembits, DBWORD - wbitno);

		/* check if only part of a word is to be freed.
		 */
		if (nb < DBWORD) {
			/* free (zero) the appropriate bits within this
			 * dmap word.
			 */
			dp->wmap[word] &=
			    cpu_to_le32(~(ONES << (DBWORD - nb)
					  >> wbitno));

			/* update the leaf for this dmap word.
			 */
			rc = dbJoin(tp, word,
				    dbMaxBud((u8 *) & dp->wmap[word]));
			if (rc)
				return rc;

			word += 1;
		} else {
			/* one or more dmap words are fully contained
			 * within the block range.  determine how many
			 * words and free (zero) the bits of these words.
			 */
			nwords = rembits >> L2DBWORD;
			memset(&dp->wmap[word], 0, nwords * 4);

			/* determine how many bits.
			 */
			nb = nwords << L2DBWORD;

			/* now update the appropriate leaves to reflect
			 * the freed words.
			 */
			for (; nwords > 0; nwords -= nw) {
				/* determine what the leaf value should be
				 * updated to as the minimum of the l2 number
				 * of bits being freed and the l2 (max) number
				 * of bits that can be described by this leaf.
				 */
				size =
				    min(LITOL2BSZ
					(word, L2LPERDMAP, BUDMIN),
					NLSTOL2BSZ(nwords));

				/* update the leaf.
				 */
				rc = dbJoin(tp, word, size);
				if (rc)
					return rc;

				/* get the number of dmap words handled.
				 */
				nw = BUDSIZE(size, BUDMIN);
				word += nw;
			}
		}
	}

	/* update the free count for this dmap.
	 */
	le32_add_cpu(&dp->nfree, nblocks);

	BMAP_LOCK(bmp);

	/* update the free count for the allocation group and
	 * map.
	 */
	agno = blkno >> bmp->db_agl2size;
	bmp->db_nfree += nblocks;
	bmp->db_agfree[agno] += nblocks;

	/* check if this allocation group is not completely free and
	 * if it is currently the maximum (rightmost) allocation group.
	 * if so, establish the new maximum allocation group number by
	 * searching left for the first allocation group with allocation.
	 */
	if ((bmp->db_agfree[agno] == bmp->db_agsize && agno == bmp->db_maxag) ||
	    (agno == bmp->db_numag - 1 &&
	     bmp->db_agfree[agno] == (bmp-> db_mapsize & (BPERDMAP - 1)))) {
		while (bmp->db_maxag > 0) {
			bmp->db_maxag -= 1;
			if (bmp->db_agfree[bmp->db_maxag] !=
			    bmp->db_agsize)
				break;
		}

		/* re-establish the allocation group preference if the
		 * current preference is right of the maximum allocation
		 * group.
		 */
		if (bmp->db_agpref > bmp->db_maxag)
			bmp->db_agpref = bmp->db_maxag;
	}

	BMAP_UNLOCK(bmp);

	return 0;
}


/*
 * NAME:	dbAdjCtl()
 *
 * FUNCTION:	adjust a dmap control page at a specified level to reflect
 *		the change in a lower level dmap or dmap control page's
 *		maximum string of free blocks (i.e. a change in the root
 *		of the lower level object's dmtree) due to the allocation
 *		or deallocation of a range of blocks with a single dmap.
 *
 *		on entry, this routine is provided with the new value of
 *		the lower level dmap or dmap control page root and the
 *		starting block number of the block range whose allocation
 *		or deallocation resulted in the root change.  this range
 *		is respresented by a single leaf of the current dmapctl
 *		and the leaf will be updated with this value, possibly
 *		causing a binary buddy system within the leaves to be
 *		split or joined.  the update may also cause the dmapctl's
 *		dmtree to be updated.
 *
 *		if the adjustment of the dmap control page, itself, causes its
 *		root to change, this change will be bubbled up to the next dmap
 *		control level by a recursive call to this routine, specifying
 *		the new root value and the next dmap control page level to
 *		be adjusted.
 * PARAMETERS:
 *	bmp	-  pointer to bmap descriptor
 *	blkno	-  the first block of a block range within a dmap.  it is
 *		   the allocation or deallocation of this block range that
 *		   requires the dmap control page to be adjusted.
 *	newval	-  the new value of the lower level dmap or dmap control
 *		   page root.
 *	alloc	-  'true' if adjustment is due to an allocation.
 *	level	-  current level of dmap control page (i.e. L0, L1, L2) to
 *		   be adjusted.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error
 *
 * serialization: IREAD_LOCK(ipbmap) or IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static int
dbAdjCtl(struct bmap * bmp, s64 blkno, int newval, int alloc, int level)
{
	struct metapage *mp;
	s8 oldroot;
	int oldval;
	s64 lblkno;
	struct dmapctl *dcp;
	int rc, leafno, ti;

	/* get the buffer for the dmap control page for the specified
	 * block number and control page level.
	 */
	lblkno = BLKTOCTL(blkno, bmp->db_l2nbperpage, level);
	mp = read_metapage(bmp->db_ipbmap, lblkno, PSIZE, 0);
	if (mp == NULL)
		return -EIO;
	dcp = (struct dmapctl *) mp->data;

	if (dcp->leafidx != cpu_to_le32(CTLLEAFIND)) {
		jfs_error(bmp->db_ipbmap->i_sb, "Corrupt dmapctl page\n");
		release_metapage(mp);
		return -EIO;
	}

	/* determine the leaf number corresponding to the block and
	 * the index within the dmap control tree.
	 */
	leafno = BLKTOCTLLEAF(blkno, dcp->budmin);
	ti = leafno + le32_to_cpu(dcp->leafidx);

	/* save the current leaf value and the current root level (i.e.
	 * maximum l2 free string described by this dmapctl).
	 */
	oldval = dcp->stree[ti];
	oldroot = dcp->stree[ROOT];

	/* check if this is a control page update for an allocation.
	 * if so, update the leaf to reflect the new leaf value using
	 * dbSplit(); otherwise (deallocation), use dbJoin() to update
	 * the leaf with the new value.  in addition to updating the
	 * leaf, dbSplit() will also split the binary buddy system of
	 * the leaves, if required, and bubble new values within the
	 * dmapctl tree, if required.  similarly, dbJoin() will join
	 * the binary buddy system of leaves and bubble new values up
	 * the dmapctl tree as required by the new leaf value.
	 */
	if (alloc) {
		/* check if we are in the middle of a binary buddy
		 * system.  this happens when we are performing the
		 * first allocation out of an allocation group that
		 * is part (not the first part) of a larger binary
		 * buddy system.  if we are in the middle, back split
		 * the system prior to calling dbSplit() which assumes
		 * that it is at the front of a binary buddy system.
		 */
		if (oldval == NOFREE) {
			rc = dbBackSplit((dmtree_t *) dcp, leafno);
			if (rc)
				return rc;
			oldval = dcp->stree[ti];
		}
		dbSplit((dmtree_t *) dcp, leafno, dcp->budmin, newval);
	} else {
		rc = dbJoin((dmtree_t *) dcp, leafno, newval);
		if (rc)
			return rc;
	}

	/* check if the root of the current dmap control page changed due
	 * to the update and if the current dmap control page is not at
	 * the current top level (i.e. L0, L1, L2) of the map.  if so (i.e.
	 * root changed and this is not the top level), call this routine
	 * again (recursion) for the next higher level of the mapping to
	 * reflect the change in root for the current dmap control page.
	 */
	if (dcp->stree[ROOT] != oldroot) {
		/* are we below the top level of the map.  if so,
		 * bubble the root up to the next higher level.
		 */
		if (level < bmp->db_maxlevel) {
			/* bubble up the new root of this dmap control page to
			 * the next level.
			 */
			if ((rc =
			     dbAdjCtl(bmp, blkno, dcp->stree[ROOT], alloc,
				      level + 1))) {
				/* something went wrong in bubbling up the new
				 * root value, so backout the changes to the
				 * current dmap control page.
				 */
				if (alloc) {
					dbJoin((dmtree_t *) dcp, leafno,
					       oldval);
				} else {
					/* the dbJoin() above might have
					 * caused a larger binary buddy system
					 * to form and we may now be in the
					 * middle of it.  if this is the case,
					 * back split the buddies.
					 */
					if (dcp->stree[ti] == NOFREE)
						dbBackSplit((dmtree_t *)
							    dcp, leafno);
					dbSplit((dmtree_t *) dcp, leafno,
						dcp->budmin, oldval);
				}

				/* release the buffer and return the error.
				 */
				release_metapage(mp);
				return (rc);
			}
		} else {
			/* we're at the top level of the map. update
			 * the bmap control page to reflect the size
			 * of the maximum free buddy system.
			 */
			assert(level == bmp->db_maxlevel);
			if (bmp->db_maxfreebud != oldroot) {
				jfs_error(bmp->db_ipbmap->i_sb,
					  "the maximum free buddy is not the old root\n");
			}
			bmp->db_maxfreebud = dcp->stree[ROOT];
		}
	}

	/* write the buffer.
	 */
	write_metapage(mp);

	return (0);
}


/*
 * NAME:	dbSplit()
 *
 * FUNCTION:	update the leaf of a dmtree with a new value, splitting
 *		the leaf from the binary buddy system of the dmtree's
 *		leaves, as required.
 *
 * PARAMETERS:
 *	tp	- pointer to the tree containing the leaf.
 *	leafno	- the number of the leaf to be updated.
 *	splitsz	- the size the binary buddy system starting at the leaf
 *		  must be split to, specified as the log2 number of blocks.
 *	newval	- the new value for the leaf.
 *
 * RETURN VALUES: none
 *
 * serialization: IREAD_LOCK(ipbmap) or IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static void dbSplit(dmtree_t * tp, int leafno, int splitsz, int newval)
{
	int budsz;
	int cursz;
	s8 *leaf = tp->dmt_stree + le32_to_cpu(tp->dmt_leafidx);

	/* check if the leaf needs to be split.
	 */
	if (leaf[leafno] > tp->dmt_budmin) {
		/* the split occurs by cutting the buddy system in half
		 * at the specified leaf until we reach the specified
		 * size.  pick up the starting split size (current size
		 * - 1 in l2) and the corresponding buddy size.
		 */
		cursz = leaf[leafno] - 1;
		budsz = BUDSIZE(cursz, tp->dmt_budmin);

		/* split until we reach the specified size.
		 */
		while (cursz >= splitsz) {
			/* update the buddy's leaf with its new value.
			 */
			dbAdjTree(tp, leafno ^ budsz, cursz);

			/* on to the next size and buddy.
			 */
			cursz -= 1;
			budsz >>= 1;
		}
	}

	/* adjust the dmap tree to reflect the specified leaf's new
	 * value.
	 */
	dbAdjTree(tp, leafno, newval);
}


/*
 * NAME:	dbBackSplit()
 *
 * FUNCTION:	back split the binary buddy system of dmtree leaves
 *		that hold a specified leaf until the specified leaf
 *		starts its own binary buddy system.
 *
 *		the allocators typically perform allocations at the start
 *		of binary buddy systems and dbSplit() is used to accomplish
 *		any required splits.  in some cases, however, allocation
 *		may occur in the middle of a binary system and requires a
 *		back split, with the split proceeding out from the middle of
 *		the system (less efficient) rather than the start of the
 *		system (more efficient).  the cases in which a back split
 *		is required are rare and are limited to the first allocation
 *		within an allocation group which is a part (not first part)
 *		of a larger binary buddy system and a few exception cases
 *		in which a previous join operation must be backed out.
 *
 * PARAMETERS:
 *	tp	- pointer to the tree containing the leaf.
 *	leafno	- the number of the leaf to be updated.
 *
 * RETURN VALUES: none
 *
 * serialization: IREAD_LOCK(ipbmap) or IWRITE_LOCK(ipbmap) held on entry/exit;
 */
static int dbBackSplit(dmtree_t * tp, int leafno)
{
	int budsz, bud, w, bsz, size;
	int cursz;
	s8 *leaf = tp->dmt_stree + le32_to_cpu(tp->dmt_leafidx);

	/* leaf should be part (not first part) of a binary
	 * buddy system.
	 */
	assert(leaf[leafno] == NOFREE);

	/* the back split is accomplished by iteratively finding the leaf
	 * that starts the buddy system that contains the specified leaf and
	 * splitting that system in two.  this iteration continues until
	 * the specified leaf becomes the start of a buddy system.
	 *
	 * determine maximum possible l2 size for the specified leaf.
	 */
	size =
	    LITOL2BSZ(leafno, le32_to_cpu(tp->dmt_l2nleafs),
		      tp->dmt_budmin);

	/* determine the number of leaves covered by this size.  this
	 * is the buddy size that we will start with as we search for
	 * the buddy system that contains the specified leaf.
	 */
	budsz = BUDSIZE(size, tp->dmt_budmin);

	/* back split.
	 */
	while (leaf[leafno] == NOFREE) {
		/* find the leftmost buddy leaf.
		 */
		for (w = leafno, bsz = budsz;; bsz <<= 1,
		     w = (w < bud) ? w : bud) {
			if (bsz >= le32_to_cpu(tp->dmt_nleafs)) {
				jfs_err("JFS: block map error in dbBackSplit");
				return -EIO;
			}

			/* determine the buddy.
			 */
			bud = w ^ bsz;

			/* check if this buddy is the start of the system.
			 */
			if (leaf[bud] != NOFREE) {
				/* split the leaf at the start of the
				 * system in two.
				 */
				cursz = leaf[bud] - 1;
				dbSplit(tp, bud, cursz, cursz);
				break;
			}
		}
	}

	if (leaf[leafno] != size) {
		jfs_err("JFS: wrong leaf value in dbBackSplit");
		return -EIO;
	}
	return 0;
}


/*
 * NAME:	dbJoin()
 *
 * FUNCTION:	update the leaf of a dmtree with a new value, joining
 *		the leaf with other leaves of the dmtree into a multi-leaf
 *		binary buddy system, as required.
 *
 * PARAMETERS:
 *	tp	- pointer to the tree containing the leaf.
 *	leafno	- the number of the leaf to be updated.
 *	newval	- the new value for the leaf.
 *
 * RETURN VALUES: none
 */
static int dbJoin(dmtree_t * tp, int leafno, int newval)
{
	int budsz, buddy;
	s8 *leaf;

	/* can the new leaf value require a join with other leaves ?
	 */
	if (newval >= tp->dmt_budmin) {
		/* pickup a pointer to the leaves of the tree.
		 */
		leaf = tp->dmt_stree + le32_to_cpu(tp->dmt_leafidx);

		/* try to join the specified leaf into a large binary
		 * buddy system.  the join proceeds by attempting to join
		 * the specified leafno with its buddy (leaf) at new value.
		 * if the join occurs, we attempt to join the left leaf
		 * of the joined buddies with its buddy at new value + 1.
		 * we continue to join until we find a buddy that cannot be
		 * joined (does not have a value equal to the size of the
		 * last join) or until all leaves have been joined into a
		 * single system.
		 *
		 * get the buddy size (number of words covered) of
		 * the new value.
		 */
		budsz = BUDSIZE(newval, tp->dmt_budmin);

		/* try to join.
		 */
		while (budsz < le32_to_cpu(tp->dmt_nleafs)) {
			/* get the buddy leaf.
			 */
			buddy = leafno ^ budsz;

			/* if the leaf's new value is greater than its
			 * buddy's value, we join no more.
			 */
			if (newval > leaf[buddy])
				break;

			/* It shouldn't be less */
			if (newval < leaf[buddy])
				return -EIO;

			/* check which (leafno or buddy) is the left buddy.
			 * the left buddy gets to claim the blocks resulting
			 * from the join while the right gets to claim none.
			 * the left buddy is also eligible to participate in
			 * a join at the next higher level while the right
			 * is not.
			 *
			 */
			if (leafno < buddy) {
				/* leafno is the left buddy.
				 */
				dbAdjTree(tp, buddy, NOFREE);
			} else {
				/* buddy is the left buddy and becomes
				 * leafno.
				 */
				dbAdjTree(tp, leafno, NOFREE);
				leafno = buddy;
			}

			/* on to try the next join.
			 */
			newval += 1;
			budsz <<= 1;
		}
	}

	/* update the leaf value.
	 */
	dbAdjTree(tp, leafno, newval);

	return 0;
}


/*
 * NAME:	dbAdjTree()
 *
 * FUNCTION:	update a leaf of a dmtree with a new value, adjusting
 *		the dmtree, as required, to reflect the new leaf value.
 *		the combination of any buddies must already be done before
 *		this is called.
 *
 * PARAMETERS:
 *	tp	- pointer to the tree to be adjusted.
 *	leafno	- the number of the leaf to be updated.
 *	newval	- the new value for the leaf.
 *
 * RETURN VALUES: none
 */
static void dbAdjTree(dmtree_t * tp, int leafno, int newval)
{
	int lp, pp, k;
	int max;

	/* pick up the index of the leaf for this leafno.
	 */
	lp = leafno + le32_to_cpu(tp->dmt_leafidx);

	/* is the current value the same as the old value ?  if so,
	 * there is nothing to do.
	 */
	if (tp->dmt_stree[lp] == newval)
		return;

	/* set the new value.
	 */
	tp->dmt_stree[lp] = newval;

	/* bubble the new value up the tree as required.
	 */
	for (k = 0; k < le32_to_cpu(tp->dmt_height); k++) {
		/* get the index of the first leaf of the 4 leaf
		 * group containing the specified leaf (leafno).
		 */
		lp = ((lp - 1) & ~0x03) + 1;

		/* get the index of the parent of this 4 leaf group.
		 */
		pp = (lp - 1) >> 2;

		/* determine the maximum of the 4 leaves.
		 */
		max = TREEMAX(&tp->dmt_stree[lp]);

		/* if the maximum of the 4 is the same as the
		 * parent's value, we're done.
		 */
		if (tp->dmt_stree[pp] == max)
			break;

		/* parent gets new value.
		 */
		tp->dmt_stree[pp] = max;

		/* parent becomes leaf for next go-round.
		 */
		lp = pp;
	}
}


/*
 * NAME:	dbFindLeaf()
 *
 * FUNCTION:	search a dmtree_t for sufficient free blocks, returning
 *		the index of a leaf describing the free blocks if
 *		sufficient free blocks are found.
 *
 *		the search starts at the top of the dmtree_t tree and
 *		proceeds down the tree to the leftmost leaf with sufficient
 *		free space.
 *
 * PARAMETERS:
 *	tp	- pointer to the tree to be searched.
 *	l2nb	- log2 number of free blocks to search for.
 *	leafidx	- return pointer to be set to the index of the leaf
 *		  describing at least l2nb free blocks if sufficient
 *		  free blocks are found.
 *
 * RETURN VALUES:
 *	0	- success
 *	-ENOSPC	- insufficient free blocks.
 */
static int dbFindLeaf(dmtree_t * tp, int l2nb, int *leafidx)
{
	int ti, n = 0, k, x = 0;

	/* first check the root of the tree to see if there is
	 * sufficient free space.
	 */
	if (l2nb > tp->dmt_stree[ROOT])
		return -ENOSPC;

	/* sufficient free space available. now search down the tree
	 * starting at the next level for the leftmost leaf that
	 * describes sufficient free space.
	 */
	for (k = le32_to_cpu(tp->dmt_height), ti = 1;
	     k > 0; k--, ti = ((ti + n) << 2) + 1) {
		/* search the four nodes at this level, starting from
		 * the left.
		 */
		for (x = ti, n = 0; n < 4; n++) {
			/* sufficient free space found.  move to the next
			 * level (or quit if this is the last level).
			 */
			if (l2nb <= tp->dmt_stree[x + n])
				break;
		}

		/* better have found something since the higher
		 * levels of the tree said it was here.
		 */
		assert(n < 4);
	}

	/* set the return to the leftmost leaf describing sufficient
	 * free space.
	 */
	*leafidx = x + n - le32_to_cpu(tp->dmt_leafidx);

	return (0);
}


/*
 * NAME:	dbFindBits()
 *
 * FUNCTION:	find a specified number of binary buddy free bits within a
 *		dmap bitmap word value.
 *
 *		this routine searches the bitmap value for (1 << l2nb) free
 *		bits at (1 << l2nb) alignments within the value.
 *
 * PARAMETERS:
 *	word	-  dmap bitmap word value.
 *	l2nb	-  number of free bits specified as a log2 number.
 *
 * RETURN VALUES:
 *	starting bit number of free bits.
 */
static int dbFindBits(u32 word, int l2nb)
{
	int bitno, nb;
	u32 mask;

	/* get the number of bits.
	 */
	nb = 1 << l2nb;
	assert(nb <= DBWORD);

	/* complement the word so we can use a mask (i.e. 0s represent
	 * free bits) and compute the mask.
	 */
	word = ~word;
	mask = ONES << (DBWORD - nb);

	/* scan the word for nb free bits at nb alignments.
	 */
	for (bitno = 0; mask != 0; bitno += nb, mask >>= nb) {
		if ((mask & word) == mask)
			break;
	}

	ASSERT(bitno < 32);

	/* return the bit number.
	 */
	return (bitno);
}


/*
 * NAME:	dbMaxBud(u8 *cp)
 *
 * FUNCTION:	determine the largest binary buddy string of free
 *		bits within 32-bits of the map.
 *
 * PARAMETERS:
 *	cp	-  pointer to the 32-bit value.
 *
 * RETURN VALUES:
 *	largest binary buddy of free bits within a dmap word.
 */
static int dbMaxBud(u8 * cp)
{
	signed char tmp1, tmp2;

	/* check if the wmap word is all free. if so, the
	 * free buddy size is BUDMIN.
	 */
	if (*((uint *) cp) == 0)
		return (BUDMIN);

	/* check if the wmap word is half free. if so, the
	 * free buddy size is BUDMIN-1.
	 */
	if (*((u16 *) cp) == 0 || *((u16 *) cp + 1) == 0)
		return (BUDMIN - 1);

	/* not all free or half free. determine the free buddy
	 * size thru table lookup using quarters of the wmap word.
	 */
	tmp1 = max(budtab[cp[2]], budtab[cp[3]]);
	tmp2 = max(budtab[cp[0]], budtab[cp[1]]);
	return (max(tmp1, tmp2));
}


/*
 * NAME:	cnttz(uint word)
 *
 * FUNCTION:	determine the number of trailing zeros within a 32-bit
 *		value.
 *
 * PARAMETERS:
 *	value	-  32-bit value to be examined.
 *
 * RETURN VALUES:
 *	count of trailing zeros
 */
static int cnttz(u32 word)
{
	int n;

	for (n = 0; n < 32; n++, word >>= 1) {
		if (word & 0x01)
			break;
	}

	return (n);
}


/*
 * NAME:	cntlz(u32 value)
 *
 * FUNCTION:	determine the number of leading zeros within a 32-bit
 *		value.
 *
 * PARAMETERS:
 *	value	-  32-bit value to be examined.
 *
 * RETURN VALUES:
 *	count of leading zeros
 */
static int cntlz(u32 value)
{
	int n;

	for (n = 0; n < 32; n++, value <<= 1) {
		if (value & HIGHORDER)
			break;
	}
	return (n);
}


/*
 * NAME:	blkstol2(s64 nb)
 *
 * FUNCTION:	convert a block count to its log2 value. if the block
 *		count is not a l2 multiple, it is rounded up to the next
 *		larger l2 multiple.
 *
 * PARAMETERS:
 *	nb	-  number of blocks
 *
 * RETURN VALUES:
 *	log2 number of blocks
 */
static int blkstol2(s64 nb)
{
	int l2nb;
	s64 mask;		/* meant to be signed */

	mask = (s64) 1 << (64 - 1);

	/* count the leading bits.
	 */
	for (l2nb = 0; l2nb < 64; l2nb++, mask >>= 1) {
		/* leading bit found.
		 */
		if (nb & mask) {
			/* determine the l2 value.
			 */
			l2nb = (64 - 1) - l2nb;

			/* check if we need to round up.
			 */
			if (~mask & nb)
				l2nb++;

			return (l2nb);
		}
	}
	assert(0);
	return 0;		/* fix compiler warning */
}


/*
 * NAME:	dbAllocBottomUp()
 *
 * FUNCTION:	alloc the specified block range from the working block
 *		allocation map.
 *
 *		the blocks will be alloc from the working map one dmap
 *		at a time.
 *
 * PARAMETERS:
 *	ip	-  pointer to in-core inode;
 *	blkno	-  starting block number to be freed.
 *	nblocks	-  number of blocks to be freed.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error
 */
int dbAllocBottomUp(struct inode *ip, s64 blkno, s64 nblocks)
{
	struct metapage *mp;
	struct dmap *dp;
	int nb, rc;
	s64 lblkno, rem;
	struct inode *ipbmap = JFS_SBI(ip->i_sb)->ipbmap;
	struct bmap *bmp = JFS_SBI(ip->i_sb)->bmap;

	IREAD_LOCK(ipbmap, RDWRLOCK_DMAP);

	/* block to be allocated better be within the mapsize. */
	ASSERT(nblocks <= bmp->db_mapsize - blkno);

	/*
	 * allocate the blocks a dmap at a time.
	 */
	mp = NULL;
	for (rem = nblocks; rem > 0; rem -= nb, blkno += nb) {
		/* release previous dmap if any */
		if (mp) {
			write_metapage(mp);
		}

		/* get the buffer for the current dmap. */
		lblkno = BLKTODMAP(blkno, bmp->db_l2nbperpage);
		mp = read_metapage(ipbmap, lblkno, PSIZE, 0);
		if (mp == NULL) {
			IREAD_UNLOCK(ipbmap);
			return -EIO;
		}
		dp = (struct dmap *) mp->data;

		/* determine the number of blocks to be allocated from
		 * this dmap.
		 */
		nb = min(rem, BPERDMAP - (blkno & (BPERDMAP - 1)));

		/* allocate the blocks. */
		if ((rc = dbAllocDmapBU(bmp, dp, blkno, nb))) {
			release_metapage(mp);
			IREAD_UNLOCK(ipbmap);
			return (rc);
		}
	}

	/* write the last buffer. */
	write_metapage(mp);

	IREAD_UNLOCK(ipbmap);

	return (0);
}


static int dbAllocDmapBU(struct bmap * bmp, struct dmap * dp, s64 blkno,
			 int nblocks)
{
	int rc;
	int dbitno, word, rembits, nb, nwords, wbitno, agno;
	s8 oldroot;
	struct dmaptree *tp = (struct dmaptree *) & dp->tree;

	/* save the current value of the root (i.e. maximum free string)
	 * of the dmap tree.
	 */
	oldroot = tp->stree[ROOT];

	/* determine the bit number and word within the dmap of the
	 * starting block.
	 */
	dbitno = blkno & (BPERDMAP - 1);
	word = dbitno >> L2DBWORD;

	/* block range better be within the dmap */
	assert(dbitno + nblocks <= BPERDMAP);

	/* allocate the bits of the dmap's words corresponding to the block
	 * range. not all bits of the first and last words may be contained
	 * within the block range.  if this is the case, we'll work against
	 * those words (i.e. partial first and/or last) on an individual basis
	 * (a single pass), allocating the bits of interest by hand and
	 * updating the leaf corresponding to the dmap word. a single pass
	 * will be used for all dmap words fully contained within the
	 * specified range.  within this pass, the bits of all fully contained
	 * dmap words will be marked as free in a single shot and the leaves
	 * will be updated. a single leaf may describe the free space of
	 * multiple dmap words, so we may update only a subset of the actual
	 * leaves corresponding to the dmap words of the block range.
	 */
	for (rembits = nblocks; rembits > 0; rembits -= nb, dbitno += nb) {
		/* determine the bit number within the word and
		 * the number of bits within the word.
		 */
		wbitno = dbitno & (DBWORD - 1);
		nb = min(rembits, DBWORD - wbitno);

		/* check if only part of a word is to be allocated.
		 */
		if (nb < DBWORD) {
			/* allocate (set to 1) the appropriate bits within
			 * this dmap word.
			 */
			dp->wmap[word] |= cpu_to_le32(ONES << (DBWORD - nb)
						      >> wbitno);

			word++;
		} else {
			/* one or more dmap words are fully contained
			 * within the block range.  determine how many
			 * words and allocate (set to 1) the bits of these
			 * words.
			 */
			nwords = rembits >> L2DBWORD;
			memset(&dp->wmap[word], (int) ONES, nwords * 4);

			/* determine how many bits */
			nb = nwords << L2DBWORD;
			word += nwords;
		}
	}

	/* update the free count for this dmap */
	le32_add_cpu(&dp->nfree, -nblocks);

	/* reconstruct summary tree */
	dbInitDmapTree(dp);

	BMAP_LOCK(bmp);

	/* if this allocation group is completely free,
	 * update the highest active allocation group number
	 * if this allocation group is the new max.
	 */
	agno = blkno >> bmp->db_agl2size;
	if (agno > bmp->db_maxag)
		bmp->db_maxag = agno;

	/* update the free count for the allocation group and map */
	bmp->db_agfree[agno] -= nblocks;
	bmp->db_nfree -= nblocks;

	BMAP_UNLOCK(bmp);

	/* if the root has not changed, done. */
	if (tp->stree[ROOT] == oldroot)
		return (0);

	/* root changed. bubble the change up to the dmap control pages.
	 * if the adjustment of the upper level control pages fails,
	 * backout the bit allocation (thus making everything consistent).
	 */
	if ((rc = dbAdjCtl(bmp, blkno, tp->stree[ROOT], 1, 0)))
		dbFreeBits(bmp, dp, blkno, nblocks);

	return (rc);
}


/*
 * NAME:	dbExtendFS()
 *
 * FUNCTION:	extend bmap from blkno for nblocks;
 *		dbExtendFS() updates bmap ready for dbAllocBottomUp();
 *
 * L2
 *  |
 *   L1---------------------------------L1
 *    |					 |
 *     L0---------L0---------L0		  L0---------L0---------L0
 *      |	   |	      |		   |	      |		 |
 *	 d0,...,dn  d0,...,dn  d0,...,dn    d0,...,dn  d0,...,dn  d0,.,dm;
 * L2L1L0d0,...,dnL0d0,...,dnL0d0,...,dnL1L0d0,...,dnL0d0,...,dnL0d0,..dm
 *
 * <---old---><----------------------------extend----------------------->
 */
int dbExtendFS(struct inode *ipbmap, s64 blkno,	s64 nblocks)
{
	struct jfs_sb_info *sbi = JFS_SBI(ipbmap->i_sb);
	int nbperpage = sbi->nbperpage;
	int i, i0 = true, j, j0 = true, k, n;
	s64 newsize;
	s64 p;
	struct metapage *mp, *l2mp, *l1mp = NULL, *l0mp = NULL;
	struct dmapctl *l2dcp, *l1dcp, *l0dcp;
	struct dmap *dp;
	s8 *l0leaf, *l1leaf, *l2leaf;
	struct bmap *bmp = sbi->bmap;
	int agno, l2agsize, oldl2agsize;
	s64 ag_rem;

	newsize = blkno + nblocks;

	jfs_info("dbExtendFS: blkno:%Ld nblocks:%Ld newsize:%Ld",
		 (long long) blkno, (long long) nblocks, (long long) newsize);

	/*
	 *	initialize bmap control page.
	 *
	 * all the data in bmap control page should exclude
	 * the mkfs hidden dmap page.
	 */

	/* update mapsize */
	bmp->db_mapsize = newsize;
	bmp->db_maxlevel = BMAPSZTOLEV(bmp->db_mapsize);

	/* compute new AG size */
	l2agsize = dbGetL2AGSize(newsize);
	oldl2agsize = bmp->db_agl2size;

	bmp->db_agl2size = l2agsize;
	bmp->db_agsize = 1 << l2agsize;

	/* compute new number of AG */
	agno = bmp->db_numag;
	bmp->db_numag = newsize >> l2agsize;
	bmp->db_numag += ((u32) newsize % (u32) bmp->db_agsize) ? 1 : 0;

	/*
	 *	reconfigure db_agfree[]
	 * from old AG configuration to new AG configuration;
	 *
	 * coalesce contiguous k (newAGSize/oldAGSize) AGs;
	 * i.e., (AGi, ..., AGj) where i = k*n and j = k*(n+1) - 1 to AGn;
	 * note: new AG size = old AG size * (2**x).
	 */
	if (l2agsize == oldl2agsize)
		goto extend;
	k = 1 << (l2agsize - oldl2agsize);
	ag_rem = bmp->db_agfree[0];	/* save agfree[0] */
	for (i = 0, n = 0; i < agno; n++) {
		bmp->db_agfree[n] = 0;	/* init collection point */

		/* coalesce contiguous k AGs; */
		for (j = 0; j < k && i < agno; j++, i++) {
			/* merge AGi to AGn */
			bmp->db_agfree[n] += bmp->db_agfree[i];
		}
	}
	bmp->db_agfree[0] += ag_rem;	/* restore agfree[0] */

	for (; n < MAXAG; n++)
		bmp->db_agfree[n] = 0;

	/*
	 * update highest active ag number
	 */

	bmp->db_maxag = bmp->db_maxag / k;

	/*
	 *	extend bmap
	 *
	 * update bit maps and corresponding level control pages;
	 * global control page db_nfree, db_agfree[agno], db_maxfreebud;
	 */
      extend:
	/* get L2 page */
	p = BMAPBLKNO + nbperpage;	/* L2 page */
	l2mp = read_metapage(ipbmap, p, PSIZE, 0);
	if (!l2mp) {
		jfs_error(ipbmap->i_sb, "L2 page could not be read\n");
		return -EIO;
	}
	l2dcp = (struct dmapctl *) l2mp->data;

	/* compute start L1 */
	k = blkno >> L2MAXL1SIZE;
	l2leaf = l2dcp->stree + CTLLEAFIND + k;
	p = BLKTOL1(blkno, sbi->l2nbperpage);	/* L1 page */

	/*
	 * extend each L1 in L2
	 */
	for (; k < LPERCTL; k++, p += nbperpage) {
		/* get L1 page */
		if (j0) {
			/* read in L1 page: (blkno & (MAXL1SIZE - 1)) */
			l1mp = read_metapage(ipbmap, p, PSIZE, 0);
			if (l1mp == NULL)
				goto errout;
			l1dcp = (struct dmapctl *) l1mp->data;

			/* compute start L0 */
			j = (blkno & (MAXL1SIZE - 1)) >> L2MAXL0SIZE;
			l1leaf = l1dcp->stree + CTLLEAFIND + j;
			p = BLKTOL0(blkno, sbi->l2nbperpage);
			j0 = false;
		} else {
			/* assign/init L1 page */
			l1mp = get_metapage(ipbmap, p, PSIZE, 0);
			if (l1mp == NULL)
				goto errout;

			l1dcp = (struct dmapctl *) l1mp->data;

			/* compute start L0 */
			j = 0;
			l1leaf = l1dcp->stree + CTLLEAFIND;
			p += nbperpage;	/* 1st L0 of L1.k */
		}

		/*
		 * extend each L0 in L1
		 */
		for (; j < LPERCTL; j++) {
			/* get L0 page */
			if (i0) {
				/* read in L0 page: (blkno & (MAXL0SIZE - 1)) */

				l0mp = read_metapage(ipbmap, p, PSIZE, 0);
				if (l0mp == NULL)
					goto errout;
				l0dcp = (struct dmapctl *) l0mp->data;

				/* compute start dmap */
				i = (blkno & (MAXL0SIZE - 1)) >>
				    L2BPERDMAP;
				l0leaf = l0dcp->stree + CTLLEAFIND + i;
				p = BLKTODMAP(blkno,
					      sbi->l2nbperpage);
				i0 = false;
			} else {
				/* assign/init L0 page */
				l0mp = get_metapage(ipbmap, p, PSIZE, 0);
				if (l0mp == NULL)
					goto errout;

				l0dcp = (struct dmapctl *) l0mp->data;

				/* compute start dmap */
				i = 0;
				l0leaf = l0dcp->stree + CTLLEAFIND;
				p += nbperpage;	/* 1st dmap of L0.j */
			}

			/*
			 * extend each dmap in L0
			 */
			for (; i < LPERCTL; i++) {
				/*
				 * reconstruct the dmap page, and
				 * initialize corresponding parent L0 leaf
				 */
				if ((n = blkno & (BPERDMAP - 1))) {
					/* read in dmap page: */
					mp = read_metapage(ipbmap, p,
							   PSIZE, 0);
					if (mp == NULL)
						goto errout;
					n = min(nblocks, (s64)BPERDMAP - n);
				} else {
					/* assign/init dmap page */
					mp = read_metapage(ipbmap, p,
							   PSIZE, 0);
					if (mp == NULL)
						goto errout;

					n = min_t(s64, nblocks, BPERDMAP);
				}

				dp = (struct dmap *) mp->data;
				*l0leaf = dbInitDmap(dp, blkno, n);

				bmp->db_nfree += n;
				agno = le64_to_cpu(dp->start) >> l2agsize;
				bmp->db_agfree[agno] += n;

				write_metapage(mp);

				l0leaf++;
				p += nbperpage;

				blkno += n;
				nblocks -= n;
				if (nblocks == 0)
					break;
			}	/* for each dmap in a L0 */

			/*
			 * build current L0 page from its leaves, and
			 * initialize corresponding parent L1 leaf
			 */
			*l1leaf = dbInitDmapCtl(l0dcp, 0, ++i);
			write_metapage(l0mp);
			l0mp = NULL;

			if (nblocks)
				l1leaf++;	/* continue for next L0 */
			else {
				/* more than 1 L0 ? */
				if (j > 0)
					break;	/* build L1 page */
				else {
					/* summarize in global bmap page */
					bmp->db_maxfreebud = *l1leaf;
					release_metapage(l1mp);
					release_metapage(l2mp);
					goto finalize;
				}
			}
		}		/* for each L0 in a L1 */

		/*
		 * build current L1 page from its leaves, and
		 * initialize corresponding parent L2 leaf
		 */
		*l2leaf = dbInitDmapCtl(l1dcp, 1, ++j);
		write_metapage(l1mp);
		l1mp = NULL;

		if (nblocks)
			l2leaf++;	/* continue for next L1 */
		else {
			/* more than 1 L1 ? */
			if (k > 0)
				break;	/* build L2 page */
			else {
				/* summarize in global bmap page */
				bmp->db_maxfreebud = *l2leaf;
				release_metapage(l2mp);
				goto finalize;
			}
		}
	}			/* for each L1 in a L2 */

	jfs_error(ipbmap->i_sb, "function has not returned as expected\n");
errout:
	if (l0mp)
		release_metapage(l0mp);
	if (l1mp)
		release_metapage(l1mp);
	release_metapage(l2mp);
	return -EIO;

	/*
	 *	finalize bmap control page
	 */
finalize:

	return 0;
}


/*
 *	dbFinalizeBmap()
 */
void dbFinalizeBmap(struct inode *ipbmap)
{
	struct bmap *bmp = JFS_SBI(ipbmap->i_sb)->bmap;
	int actags, inactags, l2nl;
	s64 ag_rem, actfree, inactfree, avgfree;
	int i, n;

	/*
	 *	finalize bmap control page
	 */
//finalize:
	/*
	 * compute db_agpref: preferred ag to allocate from
	 * (the leftmost ag with average free space in it);
	 */
//agpref:
	/* get the number of active ags and inacitve ags */
	actags = bmp->db_maxag + 1;
	inactags = bmp->db_numag - actags;
	ag_rem = bmp->db_mapsize & (bmp->db_agsize - 1);	/* ??? */

	/* determine how many blocks are in the inactive allocation
	 * groups. in doing this, we must account for the fact that
	 * the rightmost group might be a partial group (i.e. file
	 * system size is not a multiple of the group size).
	 */
	inactfree = (inactags && ag_rem) ?
	    ((inactags - 1) << bmp->db_agl2size) + ag_rem
	    : inactags << bmp->db_agl2size;

	/* determine how many free blocks are in the active
	 * allocation groups plus the average number of free blocks
	 * within the active ags.
	 */
	actfree = bmp->db_nfree - inactfree;
	avgfree = (u32) actfree / (u32) actags;

	/* if the preferred allocation group has not average free space.
	 * re-establish the preferred group as the leftmost
	 * group with average free space.
	 */
	if (bmp->db_agfree[bmp->db_agpref] < avgfree) {
		for (bmp->db_agpref = 0; bmp->db_agpref < actags;
		     bmp->db_agpref++) {
			if (bmp->db_agfree[bmp->db_agpref] >= avgfree)
				break;
		}
		if (bmp->db_agpref >= bmp->db_numag) {
			jfs_error(ipbmap->i_sb,
				  "cannot find ag with average freespace\n");
		}
	}

	/*
	 * compute db_aglevel, db_agheight, db_width, db_agstart:
	 * an ag is covered in aglevel dmapctl summary tree,
	 * at agheight level height (from leaf) with agwidth number of nodes
	 * each, which starts at agstart index node of the smmary tree node
	 * array;
	 */
	bmp->db_aglevel = BMAPSZTOLEV(bmp->db_agsize);
	l2nl =
	    bmp->db_agl2size - (L2BPERDMAP + bmp->db_aglevel * L2LPERCTL);
	bmp->db_agheight = l2nl >> 1;
	bmp->db_agwidth = 1 << (l2nl - (bmp->db_agheight << 1));
	for (i = 5 - bmp->db_agheight, bmp->db_agstart = 0, n = 1; i > 0;
	     i--) {
		bmp->db_agstart += n;
		n <<= 2;
	}

}


/*
 * NAME:	dbInitDmap()/ujfs_idmap_page()
 *
 * FUNCTION:	initialize working/persistent bitmap of the dmap page
 *		for the specified number of blocks:
 *
 *		at entry, the bitmaps had been initialized as free (ZEROS);
 *		The number of blocks will only account for the actually
 *		existing blocks. Blocks which don't actually exist in
 *		the aggregate will be marked as allocated (ONES);
 *
 * PARAMETERS:
 *	dp	- pointer to page of map
 *	nblocks	- number of blocks this page
 *
 * RETURNS: NONE
 */
static int dbInitDmap(struct dmap * dp, s64 Blkno, int nblocks)
{
	int blkno, w, b, r, nw, nb, i;

	/* starting block number within the dmap */
	blkno = Blkno & (BPERDMAP - 1);

	if (blkno == 0) {
		dp->nblocks = dp->nfree = cpu_to_le32(nblocks);
		dp->start = cpu_to_le64(Blkno);

		if (nblocks == BPERDMAP) {
			memset(&dp->wmap[0], 0, LPERDMAP * 4);
			memset(&dp->pmap[0], 0, LPERDMAP * 4);
			goto initTree;
		}
	} else {
		le32_add_cpu(&dp->nblocks, nblocks);
		le32_add_cpu(&dp->nfree, nblocks);
	}

	/* word number containing start block number */
	w = blkno >> L2DBWORD;

	/*
	 * free the bits corresponding to the block range (ZEROS):
	 * note: not all bits of the first and last words may be contained
	 * within the block range.
	 */
	for (r = nblocks; r > 0; r -= nb, blkno += nb) {
		/* number of bits preceding range to be freed in the word */
		b = blkno & (DBWORD - 1);
		/* number of bits to free in the word */
		nb = min(r, DBWORD - b);

		/* is partial word to be freed ? */
		if (nb < DBWORD) {
			/* free (set to 0) from the bitmap word */
			dp->wmap[w] &= cpu_to_le32(~(ONES << (DBWORD - nb)
						     >> b));
			dp->pmap[w] &= cpu_to_le32(~(ONES << (DBWORD - nb)
						     >> b));

			/* skip the word freed */
			w++;
		} else {
			/* free (set to 0) contiguous bitmap words */
			nw = r >> L2DBWORD;
			memset(&dp->wmap[w], 0, nw * 4);
			memset(&dp->pmap[w], 0, nw * 4);

			/* skip the words freed */
			nb = nw << L2DBWORD;
			w += nw;
		}
	}

	/*
	 * mark bits following the range to be freed (non-existing
	 * blocks) as allocated (ONES)
	 */

	if (blkno == BPERDMAP)
		goto initTree;

	/* the first word beyond the end of existing blocks */
	w = blkno >> L2DBWORD;

	/* does nblocks fall on a 32-bit boundary ? */
	b = blkno & (DBWORD - 1);
	if (b) {
		/* mark a partial word allocated */
		dp->wmap[w] = dp->pmap[w] = cpu_to_le32(ONES >> b);
		w++;
	}

	/* set the rest of the words in the page to allocated (ONES) */
	for (i = w; i < LPERDMAP; i++)
		dp->pmap[i] = dp->wmap[i] = cpu_to_le32(ONES);

	/*
	 * init tree
	 */
      initTree:
	return (dbInitDmapTree(dp));
}


/*
 * NAME:	dbInitDmapTree()/ujfs_complete_dmap()
 *
 * FUNCTION:	initialize summary tree of the specified dmap:
 *
 *		at entry, bitmap of the dmap has been initialized;
 *
 * PARAMETERS:
 *	dp	- dmap to complete
 *	blkno	- starting block number for this dmap
 *	treemax	- will be filled in with max free for this dmap
 *
 * RETURNS:	max free string at the root of the tree
 */
static int dbInitDmapTree(struct dmap * dp)
{
	struct dmaptree *tp;
	s8 *cp;
	int i;

	/* init fixed info of tree */
	tp = &dp->tree;
	tp->nleafs = cpu_to_le32(LPERDMAP);
	tp->l2nleafs = cpu_to_le32(L2LPERDMAP);
	tp->leafidx = cpu_to_le32(LEAFIND);
	tp->height = cpu_to_le32(4);
	tp->budmin = BUDMIN;

	/* init each leaf from corresponding wmap word:
	 * note: leaf is set to NOFREE(-1) if all blocks of corresponding
	 * bitmap word are allocated.
	 */
	cp = tp->stree + le32_to_cpu(tp->leafidx);
	for (i = 0; i < LPERDMAP; i++)
		*cp++ = dbMaxBud((u8 *) & dp->wmap[i]);

	/* build the dmap's binary buddy summary tree */
	return (dbInitTree(tp));
}


/*
 * NAME:	dbInitTree()/ujfs_adjtree()
 *
 * FUNCTION:	initialize binary buddy summary tree of a dmap or dmapctl.
 *
 *		at entry, the leaves of the tree has been initialized
 *		from corresponding bitmap word or root of summary tree
 *		of the child control page;
 *		configure binary buddy system at the leaf level, then
 *		bubble up the values of the leaf nodes up the tree.
 *
 * PARAMETERS:
 *	cp	- Pointer to the root of the tree
 *	l2leaves- Number of leaf nodes as a power of 2
 *	l2min	- Number of blocks that can be covered by a leaf
 *		  as a power of 2
 *
 * RETURNS: max free string at the root of the tree
 */
static int dbInitTree(struct dmaptree * dtp)
{
	int l2max, l2free, bsize, nextb, i;
	int child, parent, nparent;
	s8 *tp, *cp, *cp1;

	tp = dtp->stree;

	/* Determine the maximum free string possible for the leaves */
	l2max = le32_to_cpu(dtp->l2nleafs) + dtp->budmin;

	/*
	 * configure the leaf levevl into binary buddy system
	 *
	 * Try to combine buddies starting with a buddy size of 1
	 * (i.e. two leaves). At a buddy size of 1 two buddy leaves
	 * can be combined if both buddies have a maximum free of l2min;
	 * the combination will result in the left-most buddy leaf having
	 * a maximum free of l2min+1.
	 * After processing all buddies for a given size, process buddies
	 * at the next higher buddy size (i.e. current size * 2) and
	 * the next maximum free (current free + 1).
	 * This continues until the maximum possible buddy combination
	 * yields maximum free.
	 */
	for (l2free = dtp->budmin, bsize = 1; l2free < l2max;
	     l2free++, bsize = nextb) {
		/* get next buddy size == current buddy pair size */
		nextb = bsize << 1;

		/* scan each adjacent buddy pair at current buddy size */
		for (i = 0, cp = tp + le32_to_cpu(dtp->leafidx);
		     i < le32_to_cpu(dtp->nleafs);
		     i += nextb, cp += nextb) {
			/* coalesce if both adjacent buddies are max free */
			if (*cp == l2free && *(cp + bsize) == l2free) {
				*cp = l2free + 1;	/* left take right */
				*(cp + bsize) = -1;	/* right give left */
			}
		}
	}

	/*
	 * bubble summary information of leaves up the tree.
	 *
	 * Starting at the leaf node level, the four nodes described by
	 * the higher level parent node are compared for a maximum free and
	 * this maximum becomes the value of the parent node.
	 * when all lower level nodes are processed in this fashion then
	 * move up to the next level (parent becomes a lower level node) and
	 * continue the process for that level.
	 */
	for (child = le32_to_cpu(dtp->leafidx),
	     nparent = le32_to_cpu(dtp->nleafs) >> 2;
	     nparent > 0; nparent >>= 2, child = parent) {
		/* get index of 1st node of parent level */
		parent = (child - 1) >> 2;

		/* set the value of the parent node as the maximum
		 * of the four nodes of the current level.
		 */
		for (i = 0, cp = tp + child, cp1 = tp + parent;
		     i < nparent; i++, cp += 4, cp1++)
			*cp1 = TREEMAX(cp);
	}

	return (*tp);
}


/*
 *	dbInitDmapCtl()
 *
 * function: initialize dmapctl page
 */
static int dbInitDmapCtl(struct dmapctl * dcp, int level, int i)
{				/* start leaf index not covered by range */
	s8 *cp;

	dcp->nleafs = cpu_to_le32(LPERCTL);
	dcp->l2nleafs = cpu_to_le32(L2LPERCTL);
	dcp->leafidx = cpu_to_le32(CTLLEAFIND);
	dcp->height = cpu_to_le32(5);
	dcp->budmin = L2BPERDMAP + L2LPERCTL * level;

	/*
	 * initialize the leaves of current level that were not covered
	 * by the specified input block range (i.e. the leaves have no
	 * low level dmapctl or dmap).
	 */
	cp = &dcp->stree[CTLLEAFIND + i];
	for (; i < LPERCTL; i++)
		*cp++ = NOFREE;

	/* build the dmap's binary buddy summary tree */
	return (dbInitTree((struct dmaptree *) dcp));
}


/*
 * NAME:	dbGetL2AGSize()/ujfs_getagl2size()
 *
 * FUNCTION:	Determine log2(allocation group size) from aggregate size
 *
 * PARAMETERS:
 *	nblocks	- Number of blocks in aggregate
 *
 * RETURNS: log2(allocation group size) in aggregate blocks
 */
static int dbGetL2AGSize(s64 nblocks)
{
	s64 sz;
	s64 m;
	int l2sz;

	if (nblocks < BPERDMAP * MAXAG)
		return (L2BPERDMAP);

	/* round up aggregate size to power of 2 */
	m = ((u64) 1 << (64 - 1));
	for (l2sz = 64; l2sz >= 0; l2sz--, m >>= 1) {
		if (m & nblocks)
			break;
	}

	sz = (s64) 1 << l2sz;
	if (sz < nblocks)
		l2sz += 1;

	/* agsize = roundupSize/max_number_of_ag */
	return (l2sz - L2MAXAG);
}


/*
 * NAME:	dbMapFileSizeToMapSize()
 *
 * FUNCTION:	compute number of blocks the block allocation map file
 *		can cover from the map file size;
 *
 * RETURNS:	Number of blocks which can be covered by this block map file;
 */

/*
 * maximum number of map pages at each level including control pages
 */
#define MAXL0PAGES	(1 + LPERCTL)
#define MAXL1PAGES	(1 + LPERCTL * MAXL0PAGES)
#define MAXL2PAGES	(1 + LPERCTL * MAXL1PAGES)

/*
 * convert number of map pages to the zero origin top dmapctl level
 */
#define BMAPPGTOLEV(npages)	\
	(((npages) <= 3 + MAXL0PAGES) ? 0 : \
	 ((npages) <= 2 + MAXL1PAGES) ? 1 : 2)

s64 dbMapFileSizeToMapSize(struct inode * ipbmap)
{
	struct super_block *sb = ipbmap->i_sb;
	s64 nblocks;
	s64 npages, ndmaps;
	int level, i;
	int complete, factor;

	nblocks = ipbmap->i_size >> JFS_SBI(sb)->l2bsize;
	npages = nblocks >> JFS_SBI(sb)->l2nbperpage;
	level = BMAPPGTOLEV(npages);

	/* At each level, accumulate the number of dmap pages covered by
	 * the number of full child levels below it;
	 * repeat for the last incomplete child level.
	 */
	ndmaps = 0;
	npages--;		/* skip the first global control page */
	/* skip higher level control pages above top level covered by map */
	npages -= (2 - level);
	npages--;		/* skip top level's control page */
	for (i = level; i >= 0; i--) {
		factor =
		    (i == 2) ? MAXL1PAGES : ((i == 1) ? MAXL0PAGES : 1);
		complete = (u32) npages / factor;
		ndmaps += complete * ((i == 2) ? LPERCTL * LPERCTL :
				      ((i == 1) ? LPERCTL : 1));

		/* pages in last/incomplete child */
		npages = (u32) npages % factor;
		/* skip incomplete child's level control page */
		npages--;
	}

	/* convert the number of dmaps into the number of blocks
	 * which can be covered by the dmaps;
	 */
	nblocks = ndmaps << L2BPERDMAP;

	return (nblocks);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_dmap.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
// #include <linux/slab.h>
// #include "jfs_incore.h"
// #include "jfs_filsys.h"
// #include "jfs_unicode.h"
// #include "jfs_debug.h"

/*
 * NAME:	jfs_strfromUCS()
 *
 * FUNCTION:	Convert little-endian unicode string to character string
 *
 */
int jfs_strfromUCS_le(char *to, const __le16 * from,
		      int len, struct nls_table *codepage)
{
	int i;
	int outlen = 0;
	static int warn_again = 5;	/* Only warn up to 5 times total */
	int warn = !!warn_again;	/* once per string */

	if (codepage) {
		for (i = 0; (i < len) && from[i]; i++) {
			int charlen;
			charlen =
			    codepage->uni2char(le16_to_cpu(from[i]),
					       &to[outlen],
					       NLS_MAX_CHARSET_SIZE);
			if (charlen > 0)
				outlen += charlen;
			else
				to[outlen++] = '?';
		}
	} else {
		for (i = 0; (i < len) && from[i]; i++) {
			if (unlikely(le16_to_cpu(from[i]) & 0xff00)) {
				to[i] = '?';
				if (unlikely(warn)) {
					warn--;
					warn_again--;
					printk(KERN_ERR
			"non-latin1 character 0x%x found in JFS file name\n",
					       le16_to_cpu(from[i]));
					printk(KERN_ERR
				"mount with iocharset=utf8 to access\n");
				}

			}
			else
				to[i] = (char) (le16_to_cpu(from[i]));
		}
		outlen = i;
	}
	to[outlen] = 0;
	return outlen;
}

/*
 * NAME:	jfs_strtoUCS()
 *
 * FUNCTION:	Convert character string to unicode string
 *
 */
static int jfs_strtoUCS(wchar_t * to, const unsigned char *from, int len,
		struct nls_table *codepage)
{
	int charlen;
	int i;

	if (codepage) {
		for (i = 0; len && *from; i++, from += charlen, len -= charlen)
		{
			charlen = codepage->char2uni(from, len, &to[i]);
			if (charlen < 1) {
				jfs_err("jfs_strtoUCS: char2uni returned %d.",
					charlen);
				jfs_err("charset = %s, char = 0x%x",
					codepage->charset, *from);
				return charlen;
			}
		}
	} else {
		for (i = 0; (i < len) && from[i]; i++)
			to[i] = (wchar_t) from[i];
	}

	to[i] = 0;
	return i;
}

/*
 * NAME:	get_UCSname()
 *
 * FUNCTION:	Allocate and translate to unicode string
 *
 */
int get_UCSname(struct component_name * uniName, struct dentry *dentry)
{
	struct nls_table *nls_tab = JFS_SBI(dentry->d_sb)->nls_tab;
	int length = dentry->d_name.len;

	if (length > JFS_NAME_MAX)
		return -ENAMETOOLONG;

	uniName->name =
	    kmalloc((length + 1) * sizeof(wchar_t), GFP_NOFS);

	if (uniName->name == NULL)
		return -ENOMEM;

	uniName->namlen = jfs_strtoUCS(uniName->name, dentry->d_name.name,
				       length, nls_tab);

	if (uniName->namlen < 0) {
		kfree(uniName->name);
		return uniName->namlen;
	}

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_unicode.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 *	jfs_dtree.c: directory B+-tree manager
 *
 * B+-tree with variable length key directory:
 *
 * each directory page is structured as an array of 32-byte
 * directory entry slots initialized as a freelist
 * to avoid search/compaction of free space at insertion.
 * when an entry is inserted, a number of slots are allocated
 * from the freelist as required to store variable length data
 * of the entry; when the entry is deleted, slots of the entry
 * are returned to freelist.
 *
 * leaf entry stores full name as key and file serial number
 * (aka inode number) as data.
 * internal/router entry stores sufffix compressed name
 * as key and simple extent descriptor as data.
 *
 * each directory page maintains a sorted entry index table
 * which stores the start slot index of sorted entries
 * to allow binary search on the table.
 *
 * directory starts as a root/leaf page in on-disk inode
 * inline data area.
 * when it becomes full, it starts a leaf of a external extent
 * of length of 1 block. each time the first leaf becomes full,
 * it is extended rather than split (its size is doubled),
 * until its length becoms 4 KBytes, from then the extent is split
 * with new 4 Kbyte extent when it becomes full
 * to reduce external fragmentation of small directories.
 *
 * blah, blah, blah, for linear scan of directory in pieces by
 * readdir().
 *
 *
 *	case-insensitive directory file system
 *
 * names are stored in case-sensitive way in leaf entry.
 * but stored, searched and compared in case-insensitive (uppercase) order
 * (i.e., both search key and entry key are folded for search/compare):
 * (note that case-sensitive order is BROKEN in storage, e.g.,
 *  sensitive: Ad, aB, aC, aD -> insensitive: aB, aC, aD, Ad
 *
 *  entries which folds to the same key makes up a equivalent class
 *  whose members are stored as contiguous cluster (may cross page boundary)
 *  but whose order is arbitrary and acts as duplicate, e.g.,
 *  abc, Abc, aBc, abC)
 *
 * once match is found at leaf, requires scan forward/backward
 * either for, in case-insensitive search, duplicate
 * or for, in case-sensitive search, for exact match
 *
 * router entry must be created/stored in case-insensitive way
 * in internal entry:
 * (right most key of left page and left most key of right page
 * are folded, and its suffix compression is propagated as router
 * key in parent)
 * (e.g., if split occurs <abc> and <aBd>, <ABD> trather than <aB>
 * should be made the router key for the split)
 *
 * case-insensitive search:
 *
 *	fold search key;
 *
 *	case-insensitive search of B-tree:
 *	for internal entry, router key is already folded;
 *	for leaf entry, fold the entry key before comparison.
 *
 *	if (leaf entry case-insensitive match found)
 *		if (next entry satisfies case-insensitive match)
 *			return EDUPLICATE;
 *		if (prev entry satisfies case-insensitive match)
 *			return EDUPLICATE;
 *		return match;
 *	else
 *		return no match;
 *
 *	serialization:
 * target directory inode lock is being held on entry/exit
 * of all main directory service routines.
 *
 *	log based recovery:
 */

// #include <linux/fs.h>
// #include <linux/quotaops.h>
// #include <linux/slab.h>
// #include "jfs_incore.h"
// #include "jfs_superblock.h"
// #include "jfs_filsys.h"
// #include "jfs_metapage.h"
// #include "jfs_dmap.h"
// #include "jfs_unicode.h"
// #include "jfs_debug.h"

/* dtree split parameter */
struct dtsplit {
	struct metapage *mp;
	s16 index;
	s16 nslot;
	struct component_name *key;
	ddata_t *data;
	struct pxdlist *pxdlist;
};

#define DT_PAGE(IP, MP) BT_PAGE(IP, MP, dtpage_t, i_dtroot)

/* get page buffer for specified block address */
#define DT_GETPAGE(IP, BN, MP, SIZE, P, RC)				\
do {									\
	BT_GETPAGE(IP, BN, MP, dtpage_t, SIZE, P, RC, i_dtroot);	\
	if (!(RC)) {							\
		if (((P)->header.nextindex >				\
		     (((BN) == 0) ? DTROOTMAXSLOT : (P)->header.maxslot)) || \
		    ((BN) && ((P)->header.maxslot > DTPAGEMAXSLOT))) {	\
			BT_PUTPAGE(MP);					\
			jfs_error((IP)->i_sb,				\
				  "DT_GETPAGE: dtree page corrupt\n");	\
			MP = NULL;					\
			RC = -EIO;					\
		}							\
	}								\
} while (0)

/* for consistency */
#define DT_PUTPAGE(MP) BT_PUTPAGE(MP)

#define DT_GETSEARCH(IP, LEAF, BN, MP, P, INDEX) \
	BT_GETSEARCH(IP, LEAF, BN, MP, dtpage_t, P, INDEX, i_dtroot)

/*
 * forward references
 */
static int dtSplitUp(tid_t tid, struct inode *ip,
		     struct dtsplit * split, struct btstack * btstack);

static int dtSplitPage(tid_t tid, struct inode *ip, struct dtsplit * split,
		       struct metapage ** rmpp, dtpage_t ** rpp, pxd_t * rxdp);

static int dtExtendPage(tid_t tid, struct inode *ip,
			struct dtsplit * split, struct btstack * btstack);

static int dtSplitRoot(tid_t tid, struct inode *ip,
		       struct dtsplit * split, struct metapage ** rmpp);

static int dtDeleteUp(tid_t tid, struct inode *ip, struct metapage * fmp,
		      dtpage_t * fp, struct btstack * btstack);

static int dtRelink(tid_t tid, struct inode *ip, dtpage_t * p);

static int dtReadFirst(struct inode *ip, struct btstack * btstack);

static int dtReadNext(struct inode *ip,
		      loff_t * offset, struct btstack * btstack);

static int dtCompare(struct component_name * key, dtpage_t * p, int si);

static int ciCompare(struct component_name * key, dtpage_t * p, int si,
		     int flag);

static void dtGetKey(dtpage_t * p, int i, struct component_name * key,
		     int flag);

static int ciGetLeafPrefixKey(dtpage_t * lp, int li, dtpage_t * rp,
			      int ri, struct component_name * key, int flag);

static void dtInsertEntry(dtpage_t * p, int index, struct component_name * key,
			  ddata_t * data, struct dt_lock **);

static void dtMoveEntry(dtpage_t * sp, int si, dtpage_t * dp,
			struct dt_lock ** sdtlock, struct dt_lock ** ddtlock,
			int do_index);

static void dtDeleteEntry(dtpage_t * p, int fi, struct dt_lock ** dtlock);

static void dtTruncateEntry(dtpage_t * p, int ti, struct dt_lock ** dtlock);

static void dtLinelockFreelist(dtpage_t * p, int m, struct dt_lock ** dtlock);

#define ciToUpper(c)	UniStrupr((c)->name)

/*
 *	read_index_page()
 *
 *	Reads a page of a directory's index table.
 *	Having metadata mapped into the directory inode's address space
 *	presents a multitude of problems.  We avoid this by mapping to
 *	the absolute address space outside of the *_metapage routines
 */
static struct metapage *read_index_page(struct inode *inode, s64 blkno)
{
	int rc;
	s64 xaddr;
	int xflag;
	s32 xlen;

	rc = xtLookup(inode, blkno, 1, &xflag, &xaddr, &xlen, 1);
	if (rc || (xaddr == 0))
		return NULL;

	return read_metapage(inode, xaddr, PSIZE, 1);
}

/*
 *	get_index_page()
 *
 *	Same as get_index_page(), but get's a new page without reading
 */
static struct metapage *get_index_page(struct inode *inode, s64 blkno)
{
	int rc;
	s64 xaddr;
	int xflag;
	s32 xlen;

	rc = xtLookup(inode, blkno, 1, &xflag, &xaddr, &xlen, 1);
	if (rc || (xaddr == 0))
		return NULL;

	return get_metapage(inode, xaddr, PSIZE, 1);
}

/*
 *	find_index()
 *
 *	Returns dtree page containing directory table entry for specified
 *	index and pointer to its entry.
 *
 *	mp must be released by caller.
 */
static struct dir_table_slot *find_index(struct inode *ip, u32 index,
					 struct metapage ** mp, s64 *lblock)
{
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	s64 blkno;
	s64 offset;
	int page_offset;
	struct dir_table_slot *slot;
	static int maxWarnings = 10;

	if (index < 2) {
		if (maxWarnings) {
			jfs_warn("find_entry called with index = %d", index);
			maxWarnings--;
		}
		return NULL;
	}

	if (index >= jfs_ip->next_index) {
		jfs_warn("find_entry called with index >= next_index");
		return NULL;
	}

	if (jfs_dirtable_inline(ip)) {
		/*
		 * Inline directory table
		 */
		*mp = NULL;
		slot = &jfs_ip->i_dirtable[index - 2];
	} else {
		offset = (index - 2) * sizeof(struct dir_table_slot);
		page_offset = offset & (PSIZE - 1);
		blkno = ((offset + 1) >> L2PSIZE) <<
		    JFS_SBI(ip->i_sb)->l2nbperpage;

		if (*mp && (*lblock != blkno)) {
			release_metapage(*mp);
			*mp = NULL;
		}
		if (!(*mp)) {
			*lblock = blkno;
			*mp = read_index_page(ip, blkno);
		}
		if (!(*mp)) {
			jfs_err("free_index: error reading directory table");
			return NULL;
		}

		slot =
		    (struct dir_table_slot *) ((char *) (*mp)->data +
					       page_offset);
	}
	return slot;
}

static inline void lock_index(tid_t tid, struct inode *ip, struct metapage * mp,
			      u32 index)
{
	struct tlock *tlck;
	struct linelock *llck;
	struct lv *lv;

	tlck = txLock(tid, ip, mp, tlckDATA);
	llck = (struct linelock *) tlck->lock;

	if (llck->index >= llck->maxcnt)
		llck = txLinelock(llck);
	lv = &llck->lv[llck->index];

	/*
	 *	Linelock slot size is twice the size of directory table
	 *	slot size.  512 entries per page.
	 */
	lv->offset = ((index - 2) & 511) >> 1;
	lv->length = 1;
	llck->index++;
}

/*
 *	add_index()
 *
 *	Adds an entry to the directory index table.  This is used to provide
 *	each directory entry with a persistent index in which to resume
 *	directory traversals
 */
static u32 add_index(tid_t tid, struct inode *ip, s64 bn, int slot)
{
	struct super_block *sb = ip->i_sb;
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	u64 blkno;
	struct dir_table_slot *dirtab_slot;
	u32 index;
	struct linelock *llck;
	struct lv *lv;
	struct metapage *mp;
	s64 offset;
	uint page_offset;
	struct tlock *tlck;
	s64 xaddr;

	ASSERT(DO_INDEX(ip));

	if (jfs_ip->next_index < 2) {
		jfs_warn("add_index: next_index = %d.  Resetting!",
			   jfs_ip->next_index);
		jfs_ip->next_index = 2;
	}

	index = jfs_ip->next_index++;

	if (index <= MAX_INLINE_DIRTABLE_ENTRY) {
		/*
		 * i_size reflects size of index table, or 8 bytes per entry.
		 */
		ip->i_size = (loff_t) (index - 1) << 3;

		/*
		 * dir table fits inline within inode
		 */
		dirtab_slot = &jfs_ip->i_dirtable[index-2];
		dirtab_slot->flag = DIR_INDEX_VALID;
		dirtab_slot->slot = slot;
		DTSaddress(dirtab_slot, bn);

		set_cflag(COMMIT_Dirtable, ip);

		return index;
	}
	if (index == (MAX_INLINE_DIRTABLE_ENTRY + 1)) {
		struct dir_table_slot temp_table[12];

		/*
		 * It's time to move the inline table to an external
		 * page and begin to build the xtree
		 */
		if (dquot_alloc_block(ip, sbi->nbperpage))
			goto clean_up;
		if (dbAlloc(ip, 0, sbi->nbperpage, &xaddr)) {
			dquot_free_block(ip, sbi->nbperpage);
			goto clean_up;
		}

		/*
		 * Save the table, we're going to overwrite it with the
		 * xtree root
		 */
		memcpy(temp_table, &jfs_ip->i_dirtable, sizeof(temp_table));

		/*
		 * Initialize empty x-tree
		 */
		xtInitRoot(tid, ip);

		/*
		 * Add the first block to the xtree
		 */
		if (xtInsert(tid, ip, 0, 0, sbi->nbperpage, &xaddr, 0)) {
			/* This really shouldn't fail */
			jfs_warn("add_index: xtInsert failed!");
			memcpy(&jfs_ip->i_dirtable, temp_table,
			       sizeof (temp_table));
			dbFree(ip, xaddr, sbi->nbperpage);
			dquot_free_block(ip, sbi->nbperpage);
			goto clean_up;
		}
		ip->i_size = PSIZE;

		mp = get_index_page(ip, 0);
		if (!mp) {
			jfs_err("add_index: get_metapage failed!");
			xtTruncate(tid, ip, 0, COMMIT_PWMAP);
			memcpy(&jfs_ip->i_dirtable, temp_table,
			       sizeof (temp_table));
			goto clean_up;
		}
		tlck = txLock(tid, ip, mp, tlckDATA);
		llck = (struct linelock *) & tlck->lock;
		ASSERT(llck->index == 0);
		lv = &llck->lv[0];

		lv->offset = 0;
		lv->length = 6;	/* tlckDATA slot size is 16 bytes */
		llck->index++;

		memcpy(mp->data, temp_table, sizeof(temp_table));

		mark_metapage_dirty(mp);
		release_metapage(mp);

		/*
		 * Logging is now directed by xtree tlocks
		 */
		clear_cflag(COMMIT_Dirtable, ip);
	}

	offset = (index - 2) * sizeof(struct dir_table_slot);
	page_offset = offset & (PSIZE - 1);
	blkno = ((offset + 1) >> L2PSIZE) << sbi->l2nbperpage;
	if (page_offset == 0) {
		/*
		 * This will be the beginning of a new page
		 */
		xaddr = 0;
		if (xtInsert(tid, ip, 0, blkno, sbi->nbperpage, &xaddr, 0)) {
			jfs_warn("add_index: xtInsert failed!");
			goto clean_up;
		}
		ip->i_size += PSIZE;

		if ((mp = get_index_page(ip, blkno)))
			memset(mp->data, 0, PSIZE);	/* Just looks better */
		else
			xtTruncate(tid, ip, offset, COMMIT_PWMAP);
	} else
		mp = read_index_page(ip, blkno);

	if (!mp) {
		jfs_err("add_index: get/read_metapage failed!");
		goto clean_up;
	}

	lock_index(tid, ip, mp, index);

	dirtab_slot =
	    (struct dir_table_slot *) ((char *) mp->data + page_offset);
	dirtab_slot->flag = DIR_INDEX_VALID;
	dirtab_slot->slot = slot;
	DTSaddress(dirtab_slot, bn);

	mark_metapage_dirty(mp);
	release_metapage(mp);

	return index;

      clean_up:

	jfs_ip->next_index--;

	return 0;
}

/*
 *	free_index()
 *
 *	Marks an entry to the directory index table as free.
 */
static void free_index(tid_t tid, struct inode *ip, u32 index, u32 next)
{
	struct dir_table_slot *dirtab_slot;
	s64 lblock;
	struct metapage *mp = NULL;

	dirtab_slot = find_index(ip, index, &mp, &lblock);

	if (!dirtab_slot)
		return;

	dirtab_slot->flag = DIR_INDEX_FREE;
	dirtab_slot->slot = dirtab_slot->addr1 = 0;
	dirtab_slot->addr2 = cpu_to_le32(next);

	if (mp) {
		lock_index(tid, ip, mp, index);
		mark_metapage_dirty(mp);
		release_metapage(mp);
	} else
		set_cflag(COMMIT_Dirtable, ip);
}

/*
 *	modify_index()
 *
 *	Changes an entry in the directory index table
 */
static void modify_index(tid_t tid, struct inode *ip, u32 index, s64 bn,
			 int slot, struct metapage ** mp, s64 *lblock)
{
	struct dir_table_slot *dirtab_slot;

	dirtab_slot = find_index(ip, index, mp, lblock);

	if (!dirtab_slot)
		return;

	DTSaddress(dirtab_slot, bn);
	dirtab_slot->slot = slot;

	if (*mp) {
		lock_index(tid, ip, *mp, index);
		mark_metapage_dirty(*mp);
	} else
		set_cflag(COMMIT_Dirtable, ip);
}

/*
 *	read_index()
 *
 *	reads a directory table slot
 */
static int read_index(struct inode *ip, u32 index,
		     struct dir_table_slot * dirtab_slot)
{
	s64 lblock;
	struct metapage *mp = NULL;
	struct dir_table_slot *slot;

	slot = find_index(ip, index, &mp, &lblock);
	if (!slot) {
		return -EIO;
	}

	memcpy(dirtab_slot, slot, sizeof(struct dir_table_slot));

	if (mp)
		release_metapage(mp);

	return 0;
}

/*
 *	dtSearch()
 *
 * function:
 *	Search for the entry with specified key
 *
 * parameter:
 *
 * return: 0 - search result on stack, leaf page pinned;
 *	   errno - I/O error
 */
int dtSearch(struct inode *ip, struct component_name * key, ino_t * data,
	     struct btstack * btstack, int flag)
{
	int rc = 0;
	int cmp = 1;		/* init for empty page */
	s64 bn;
	struct metapage *mp;
	dtpage_t *p;
	s8 *stbl;
	int base, index, lim;
	struct btframe *btsp;
	pxd_t *pxd;
	int psize = 288;	/* initial in-line directory */
	ino_t inumber;
	struct component_name ciKey;
	struct super_block *sb = ip->i_sb;

	ciKey.name = kmalloc((JFS_NAME_MAX + 1) * sizeof(wchar_t), GFP_NOFS);
	if (!ciKey.name) {
		rc = -ENOMEM;
		goto dtSearch_Exit2;
	}


	/* uppercase search key for c-i directory */
	UniStrcpy(ciKey.name, key->name);
	ciKey.namlen = key->namlen;

	/* only uppercase if case-insensitive support is on */
	if ((JFS_SBI(sb)->mntflag & JFS_OS2) == JFS_OS2) {
		ciToUpper(&ciKey);
	}
	BT_CLR(btstack);	/* reset stack */

	/* init level count for max pages to split */
	btstack->nsplit = 1;

	/*
	 *	search down tree from root:
	 *
	 * between two consecutive entries of <Ki, Pi> and <Kj, Pj> of
	 * internal page, child page Pi contains entry with k, Ki <= K < Kj.
	 *
	 * if entry with search key K is not found
	 * internal page search find the entry with largest key Ki
	 * less than K which point to the child page to search;
	 * leaf page search find the entry with smallest key Kj
	 * greater than K so that the returned index is the position of
	 * the entry to be shifted right for insertion of new entry.
	 * for empty tree, search key is greater than any key of the tree.
	 *
	 * by convention, root bn = 0.
	 */
	for (bn = 0;;) {
		/* get/pin the page to search */
		DT_GETPAGE(ip, bn, mp, psize, p, rc);
		if (rc)
			goto dtSearch_Exit1;

		/* get sorted entry table of the page */
		stbl = DT_GETSTBL(p);

		/*
		 * binary search with search key K on the current page.
		 */
		for (base = 0, lim = p->header.nextindex; lim; lim >>= 1) {
			index = base + (lim >> 1);

			if (p->header.flag & BT_LEAF) {
				/* uppercase leaf name to compare */
				cmp =
				    ciCompare(&ciKey, p, stbl[index],
					      JFS_SBI(sb)->mntflag);
			} else {
				/* router key is in uppercase */

				cmp = dtCompare(&ciKey, p, stbl[index]);


			}
			if (cmp == 0) {
				/*
				 *	search hit
				 */
				/* search hit - leaf page:
				 * return the entry found
				 */
				if (p->header.flag & BT_LEAF) {
					inumber = le32_to_cpu(
			((struct ldtentry *) & p->slot[stbl[index]])->inumber);

					/*
					 * search for JFS_LOOKUP
					 */
					if (flag == JFS_LOOKUP) {
						*data = inumber;
						rc = 0;
						goto out;
					}

					/*
					 * search for JFS_CREATE
					 */
					if (flag == JFS_CREATE) {
						*data = inumber;
						rc = -EEXIST;
						goto out;
					}

					/*
					 * search for JFS_REMOVE or JFS_RENAME
					 */
					if ((flag == JFS_REMOVE ||
					     flag == JFS_RENAME) &&
					    *data != inumber) {
						rc = -ESTALE;
						goto out;
					}

					/*
					 * JFS_REMOVE|JFS_FINDDIR|JFS_RENAME
					 */
					/* save search result */
					*data = inumber;
					btsp = btstack->top;
					btsp->bn = bn;
					btsp->index = index;
					btsp->mp = mp;

					rc = 0;
					goto dtSearch_Exit1;
				}

				/* search hit - internal page:
				 * descend/search its child page
				 */
				goto getChild;
			}

			if (cmp > 0) {
				base = index + 1;
				--lim;
			}
		}

		/*
		 *	search miss
		 *
		 * base is the smallest index with key (Kj) greater than
		 * search key (K) and may be zero or (maxindex + 1) index.
		 */
		/*
		 * search miss - leaf page
		 *
		 * return location of entry (base) where new entry with
		 * search key K is to be inserted.
		 */
		if (p->header.flag & BT_LEAF) {
			/*
			 * search for JFS_LOOKUP, JFS_REMOVE, or JFS_RENAME
			 */
			if (flag == JFS_LOOKUP || flag == JFS_REMOVE ||
			    flag == JFS_RENAME) {
				rc = -ENOENT;
				goto out;
			}

			/*
			 * search for JFS_CREATE|JFS_FINDDIR:
			 *
			 * save search result
			 */
			*data = 0;
			btsp = btstack->top;
			btsp->bn = bn;
			btsp->index = base;
			btsp->mp = mp;

			rc = 0;
			goto dtSearch_Exit1;
		}

		/*
		 * search miss - internal page
		 *
		 * if base is non-zero, decrement base by one to get the parent
		 * entry of the child page to search.
		 */
		index = base ? base - 1 : base;

		/*
		 * go down to child page
		 */
	      getChild:
		/* update max. number of pages to split */
		if (BT_STACK_FULL(btstack)) {
			/* Something's corrupted, mark filesystem dirty so
			 * chkdsk will fix it.
			 */
			jfs_error(sb, "stack overrun!\n");
			BT_STACK_DUMP(btstack);
			rc = -EIO;
			goto out;
		}
		btstack->nsplit++;

		/* push (bn, index) of the parent page/entry */
		BT_PUSH(btstack, bn, index);

		/* get the child page block number */
		pxd = (pxd_t *) & p->slot[stbl[index]];
		bn = addressPXD(pxd);
		psize = lengthPXD(pxd) << JFS_SBI(ip->i_sb)->l2bsize;

		/* unpin the parent page */
		DT_PUTPAGE(mp);
	}

      out:
	DT_PUTPAGE(mp);

      dtSearch_Exit1:

	kfree(ciKey.name);

      dtSearch_Exit2:

	return rc;
}


/*
 *	dtInsert()
 *
 * function: insert an entry to directory tree
 *
 * parameter:
 *
 * return: 0 - success;
 *	   errno - failure;
 */
int dtInsert(tid_t tid, struct inode *ip,
	 struct component_name * name, ino_t * fsn, struct btstack * btstack)
{
	int rc = 0;
	struct metapage *mp;	/* meta-page buffer */
	dtpage_t *p;		/* base B+-tree index page */
	s64 bn;
	int index;
	struct dtsplit split;	/* split information */
	ddata_t data;
	struct dt_lock *dtlck;
	int n;
	struct tlock *tlck;
	struct lv *lv;

	/*
	 *	retrieve search result
	 *
	 * dtSearch() returns (leaf page pinned, index at which to insert).
	 * n.b. dtSearch() may return index of (maxindex + 1) of
	 * the full page.
	 */
	DT_GETSEARCH(ip, btstack->top, bn, mp, p, index);

	/*
	 *	insert entry for new key
	 */
	if (DO_INDEX(ip)) {
		if (JFS_IP(ip)->next_index == DIREND) {
			DT_PUTPAGE(mp);
			return -EMLINK;
		}
		n = NDTLEAF(name->namlen);
		data.leaf.tid = tid;
		data.leaf.ip = ip;
	} else {
		n = NDTLEAF_LEGACY(name->namlen);
		data.leaf.ip = NULL;	/* signifies legacy directory format */
	}
	data.leaf.ino = *fsn;

	/*
	 *	leaf page does not have enough room for new entry:
	 *
	 *	extend/split the leaf page;
	 *
	 * dtSplitUp() will insert the entry and unpin the leaf page.
	 */
	if (n > p->header.freecnt) {
		split.mp = mp;
		split.index = index;
		split.nslot = n;
		split.key = name;
		split.data = &data;
		rc = dtSplitUp(tid, ip, &split, btstack);
		return rc;
	}

	/*
	 *	leaf page does have enough room for new entry:
	 *
	 *	insert the new data entry into the leaf page;
	 */
	BT_MARK_DIRTY(mp, ip);
	/*
	 * acquire a transaction lock on the leaf page
	 */
	tlck = txLock(tid, ip, mp, tlckDTREE | tlckENTRY);
	dtlck = (struct dt_lock *) & tlck->lock;
	ASSERT(dtlck->index == 0);
	lv = & dtlck->lv[0];

	/* linelock header */
	lv->offset = 0;
	lv->length = 1;
	dtlck->index++;

	dtInsertEntry(p, index, name, &data, &dtlck);

	/* linelock stbl of non-root leaf page */
	if (!(p->header.flag & BT_ROOT)) {
		if (dtlck->index >= dtlck->maxcnt)
			dtlck = (struct dt_lock *) txLinelock(dtlck);
		lv = & dtlck->lv[dtlck->index];
		n = index >> L2DTSLOTSIZE;
		lv->offset = p->header.stblindex + n;
		lv->length =
		    ((p->header.nextindex - 1) >> L2DTSLOTSIZE) - n + 1;
		dtlck->index++;
	}

	/* unpin the leaf page */
	DT_PUTPAGE(mp);

	return 0;
}


/*
 *	dtSplitUp()
 *
 * function: propagate insertion bottom up;
 *
 * parameter:
 *
 * return: 0 - success;
 *	   errno - failure;
 *	leaf page unpinned;
 */
static int dtSplitUp(tid_t tid,
	  struct inode *ip, struct dtsplit * split, struct btstack * btstack)
{
	struct jfs_sb_info *sbi = JFS_SBI(ip->i_sb);
	int rc = 0;
	struct metapage *smp;
	dtpage_t *sp;		/* split page */
	struct metapage *rmp;
	dtpage_t *rp;		/* new right page split from sp */
	pxd_t rpxd;		/* new right page extent descriptor */
	struct metapage *lmp;
	dtpage_t *lp;		/* left child page */
	int skip;		/* index of entry of insertion */
	struct btframe *parent;	/* parent page entry on traverse stack */
	s64 xaddr, nxaddr;
	int xlen, xsize;
	struct pxdlist pxdlist;
	pxd_t *pxd;
	struct component_name key = { 0, NULL };
	ddata_t *data = split->data;
	int n;
	struct dt_lock *dtlck;
	struct tlock *tlck;
	struct lv *lv;
	int quota_allocation = 0;

	/* get split page */
	smp = split->mp;
	sp = DT_PAGE(ip, smp);

	key.name = kmalloc((JFS_NAME_MAX + 2) * sizeof(wchar_t), GFP_NOFS);
	if (!key.name) {
		DT_PUTPAGE(smp);
		rc = -ENOMEM;
		goto dtSplitUp_Exit;
	}

	/*
	 *	split leaf page
	 *
	 * The split routines insert the new entry, and
	 * acquire txLock as appropriate.
	 */
	/*
	 *	split root leaf page:
	 */
	if (sp->header.flag & BT_ROOT) {
		/*
		 * allocate a single extent child page
		 */
		xlen = 1;
		n = sbi->bsize >> L2DTSLOTSIZE;
		n -= (n + 31) >> L2DTSLOTSIZE;	/* stbl size */
		n -= DTROOTMAXSLOT - sp->header.freecnt; /* header + entries */
		if (n <= split->nslot)
			xlen++;
		if ((rc = dbAlloc(ip, 0, (s64) xlen, &xaddr))) {
			DT_PUTPAGE(smp);
			goto freeKeyName;
		}

		pxdlist.maxnpxd = 1;
		pxdlist.npxd = 0;
		pxd = &pxdlist.pxd[0];
		PXDaddress(pxd, xaddr);
		PXDlength(pxd, xlen);
		split->pxdlist = &pxdlist;
		rc = dtSplitRoot(tid, ip, split, &rmp);

		if (rc)
			dbFree(ip, xaddr, xlen);
		else
			DT_PUTPAGE(rmp);

		DT_PUTPAGE(smp);

		if (!DO_INDEX(ip))
			ip->i_size = xlen << sbi->l2bsize;

		goto freeKeyName;
	}

	/*
	 *	extend first leaf page
	 *
	 * extend the 1st extent if less than buffer page size
	 * (dtExtendPage() reurns leaf page unpinned)
	 */
	pxd = &sp->header.self;
	xlen = lengthPXD(pxd);
	xsize = xlen << sbi->l2bsize;
	if (xsize < PSIZE) {
		xaddr = addressPXD(pxd);
		n = xsize >> L2DTSLOTSIZE;
		n -= (n + 31) >> L2DTSLOTSIZE;	/* stbl size */
		if ((n + sp->header.freecnt) <= split->nslot)
			n = xlen + (xlen << 1);
		else
			n = xlen;

		/* Allocate blocks to quota. */
		rc = dquot_alloc_block(ip, n);
		if (rc)
			goto extendOut;
		quota_allocation += n;

		if ((rc = dbReAlloc(sbi->ipbmap, xaddr, (s64) xlen,
				    (s64) n, &nxaddr)))
			goto extendOut;

		pxdlist.maxnpxd = 1;
		pxdlist.npxd = 0;
		pxd = &pxdlist.pxd[0];
		PXDaddress(pxd, nxaddr);
		PXDlength(pxd, xlen + n);
		split->pxdlist = &pxdlist;
		if ((rc = dtExtendPage(tid, ip, split, btstack))) {
			nxaddr = addressPXD(pxd);
			if (xaddr != nxaddr) {
				/* free relocated extent */
				xlen = lengthPXD(pxd);
				dbFree(ip, nxaddr, (s64) xlen);
			} else {
				/* free extended delta */
				xlen = lengthPXD(pxd) - n;
				xaddr = addressPXD(pxd) + xlen;
				dbFree(ip, xaddr, (s64) n);
			}
		} else if (!DO_INDEX(ip))
			ip->i_size = lengthPXD(pxd) << sbi->l2bsize;


	      extendOut:
		DT_PUTPAGE(smp);
		goto freeKeyName;
	}

	/*
	 *	split leaf page <sp> into <sp> and a new right page <rp>.
	 *
	 * return <rp> pinned and its extent descriptor <rpxd>
	 */
	/*
	 * allocate new directory page extent and
	 * new index page(s) to cover page split(s)
	 *
	 * allocation hint: ?
	 */
	n = btstack->nsplit;
	pxdlist.maxnpxd = pxdlist.npxd = 0;
	xlen = sbi->nbperpage;
	for (pxd = pxdlist.pxd; n > 0; n--, pxd++) {
		if ((rc = dbAlloc(ip, 0, (s64) xlen, &xaddr)) == 0) {
			PXDaddress(pxd, xaddr);
			PXDlength(pxd, xlen);
			pxdlist.maxnpxd++;
			continue;
		}

		DT_PUTPAGE(smp);

		/* undo allocation */
		goto splitOut;
	}

	split->pxdlist = &pxdlist;
	if ((rc = dtSplitPage(tid, ip, split, &rmp, &rp, &rpxd))) {
		DT_PUTPAGE(smp);

		/* undo allocation */
		goto splitOut;
	}

	if (!DO_INDEX(ip))
		ip->i_size += PSIZE;

	/*
	 * propagate up the router entry for the leaf page just split
	 *
	 * insert a router entry for the new page into the parent page,
	 * propagate the insert/split up the tree by walking back the stack
	 * of (bn of parent page, index of child page entry in parent page)
	 * that were traversed during the search for the page that split.
	 *
	 * the propagation of insert/split up the tree stops if the root
	 * splits or the page inserted into doesn't have to split to hold
	 * the new entry.
	 *
	 * the parent entry for the split page remains the same, and
	 * a new entry is inserted at its right with the first key and
	 * block number of the new right page.
	 *
	 * There are a maximum of 4 pages pinned at any time:
	 * two children, left parent and right parent (when the parent splits).
	 * keep the child pages pinned while working on the parent.
	 * make sure that all pins are released at exit.
	 */
	while ((parent = BT_POP(btstack)) != NULL) {
		/* parent page specified by stack frame <parent> */

		/* keep current child pages (<lp>, <rp>) pinned */
		lmp = smp;
		lp = sp;

		/*
		 * insert router entry in parent for new right child page <rp>
		 */
		/* get the parent page <sp> */
		DT_GETPAGE(ip, parent->bn, smp, PSIZE, sp, rc);
		if (rc) {
			DT_PUTPAGE(lmp);
			DT_PUTPAGE(rmp);
			goto splitOut;
		}

		/*
		 * The new key entry goes ONE AFTER the index of parent entry,
		 * because the split was to the right.
		 */
		skip = parent->index + 1;

		/*
		 * compute the key for the router entry
		 *
		 * key suffix compression:
		 * for internal pages that have leaf pages as children,
		 * retain only what's needed to distinguish between
		 * the new entry and the entry on the page to its left.
		 * If the keys compare equal, retain the entire key.
		 *
		 * note that compression is performed only at computing
		 * router key at the lowest internal level.
		 * further compression of the key between pairs of higher
		 * level internal pages loses too much information and
		 * the search may fail.
		 * (e.g., two adjacent leaf pages of {a, ..., x} {xx, ...,}
		 * results in two adjacent parent entries (a)(xx).
		 * if split occurs between these two entries, and
		 * if compression is applied, the router key of parent entry
		 * of right page (x) will divert search for x into right
		 * subtree and miss x in the left subtree.)
		 *
		 * the entire key must be retained for the next-to-leftmost
		 * internal key at any level of the tree, or search may fail
		 * (e.g., ?)
		 */
		switch (rp->header.flag & BT_TYPE) {
		case BT_LEAF:
			/*
			 * compute the length of prefix for suffix compression
			 * between last entry of left page and first entry
			 * of right page
			 */
			if ((sp->header.flag & BT_ROOT && skip > 1) ||
			    sp->header.prev != 0 || skip > 1) {
				/* compute uppercase router prefix key */
				rc = ciGetLeafPrefixKey(lp,
							lp->header.nextindex-1,
							rp, 0, &key,
							sbi->mntflag);
				if (rc) {
					DT_PUTPAGE(lmp);
					DT_PUTPAGE(rmp);
					DT_PUTPAGE(smp);
					goto splitOut;
				}
			} else {
				/* next to leftmost entry of
				   lowest internal level */

				/* compute uppercase router key */
				dtGetKey(rp, 0, &key, sbi->mntflag);
				key.name[key.namlen] = 0;

				if ((sbi->mntflag & JFS_OS2) == JFS_OS2)
					ciToUpper(&key);
			}

			n = NDTINTERNAL(key.namlen);
			break;

		case BT_INTERNAL:
			dtGetKey(rp, 0, &key, sbi->mntflag);
			n = NDTINTERNAL(key.namlen);
			break;

		default:
			jfs_err("dtSplitUp(): UFO!");
			break;
		}

		/* unpin left child page */
		DT_PUTPAGE(lmp);

		/*
		 * compute the data for the router entry
		 */
		data->xd = rpxd;	/* child page xd */

		/*
		 * parent page is full - split the parent page
		 */
		if (n > sp->header.freecnt) {
			/* init for parent page split */
			split->mp = smp;
			split->index = skip;	/* index at insert */
			split->nslot = n;
			split->key = &key;
			/* split->data = data; */

			/* unpin right child page */
			DT_PUTPAGE(rmp);

			/* The split routines insert the new entry,
			 * acquire txLock as appropriate.
			 * return <rp> pinned and its block number <rbn>.
			 */
			rc = (sp->header.flag & BT_ROOT) ?
			    dtSplitRoot(tid, ip, split, &rmp) :
			    dtSplitPage(tid, ip, split, &rmp, &rp, &rpxd);
			if (rc) {
				DT_PUTPAGE(smp);
				goto splitOut;
			}

			/* smp and rmp are pinned */
		}
		/*
		 * parent page is not full - insert router entry in parent page
		 */
		else {
			BT_MARK_DIRTY(smp, ip);
			/*
			 * acquire a transaction lock on the parent page
			 */
			tlck = txLock(tid, ip, smp, tlckDTREE | tlckENTRY);
			dtlck = (struct dt_lock *) & tlck->lock;
			ASSERT(dtlck->index == 0);
			lv = & dtlck->lv[0];

			/* linelock header */
			lv->offset = 0;
			lv->length = 1;
			dtlck->index++;

			/* linelock stbl of non-root parent page */
			if (!(sp->header.flag & BT_ROOT)) {
				lv++;
				n = skip >> L2DTSLOTSIZE;
				lv->offset = sp->header.stblindex + n;
				lv->length =
				    ((sp->header.nextindex -
				      1) >> L2DTSLOTSIZE) - n + 1;
				dtlck->index++;
			}

			dtInsertEntry(sp, skip, &key, data, &dtlck);

			/* exit propagate up */
			break;
		}
	}

	/* unpin current split and its right page */
	DT_PUTPAGE(smp);
	DT_PUTPAGE(rmp);

	/*
	 * free remaining extents allocated for split
	 */
      splitOut:
	n = pxdlist.npxd;
	pxd = &pxdlist.pxd[n];
	for (; n < pxdlist.maxnpxd; n++, pxd++)
		dbFree(ip, addressPXD(pxd), (s64) lengthPXD(pxd));

      freeKeyName:
	kfree(key.name);

	/* Rollback quota allocation */
	if (rc && quota_allocation)
		dquot_free_block(ip, quota_allocation);

      dtSplitUp_Exit:

	return rc;
}


/*
 *	dtSplitPage()
 *
 * function: Split a non-root page of a btree.
 *
 * parameter:
 *
 * return: 0 - success;
 *	   errno - failure;
 *	return split and new page pinned;
 */
static int dtSplitPage(tid_t tid, struct inode *ip, struct dtsplit * split,
	    struct metapage ** rmpp, dtpage_t ** rpp, pxd_t * rpxdp)
{
	int rc = 0;
	struct metapage *smp;
	dtpage_t *sp;
	struct metapage *rmp;
	dtpage_t *rp;		/* new right page allocated */
	s64 rbn;		/* new right page block number */
	struct metapage *mp;
	dtpage_t *p;
	s64 nextbn;
	struct pxdlist *pxdlist;
	pxd_t *pxd;
	int skip, nextindex, half, left, nxt, off, si;
	struct ldtentry *ldtentry;
	struct idtentry *idtentry;
	u8 *stbl;
	struct dtslot *f;
	int fsi, stblsize;
	int n;
	struct dt_lock *sdtlck, *rdtlck;
	struct tlock *tlck;
	struct dt_lock *dtlck;
	struct lv *slv, *rlv, *lv;

	/* get split page */
	smp = split->mp;
	sp = DT_PAGE(ip, smp);

	/*
	 * allocate the new right page for the split
	 */
	pxdlist = split->pxdlist;
	pxd = &pxdlist->pxd[pxdlist->npxd];
	pxdlist->npxd++;
	rbn = addressPXD(pxd);
	rmp = get_metapage(ip, rbn, PSIZE, 1);
	if (rmp == NULL)
		return -EIO;

	/* Allocate blocks to quota. */
	rc = dquot_alloc_block(ip, lengthPXD(pxd));
	if (rc) {
		release_metapage(rmp);
		return rc;
	}

	jfs_info("dtSplitPage: ip:0x%p smp:0x%p rmp:0x%p", ip, smp, rmp);

	BT_MARK_DIRTY(rmp, ip);
	/*
	 * acquire a transaction lock on the new right page
	 */
	tlck = txLock(tid, ip, rmp, tlckDTREE | tlckNEW);
	rdtlck = (struct dt_lock *) & tlck->lock;

	rp = (dtpage_t *) rmp->data;
	*rpp = rp;
	rp->header.self = *pxd;

	BT_MARK_DIRTY(smp, ip);
	/*
	 * acquire a transaction lock on the split page
	 *
	 * action:
	 */
	tlck = txLock(tid, ip, smp, tlckDTREE | tlckENTRY);
	sdtlck = (struct dt_lock *) & tlck->lock;

	/* linelock header of split page */
	ASSERT(sdtlck->index == 0);
	slv = & sdtlck->lv[0];
	slv->offset = 0;
	slv->length = 1;
	sdtlck->index++;

	/*
	 * initialize/update sibling pointers between sp and rp
	 */
	nextbn = le64_to_cpu(sp->header.next);
	rp->header.next = cpu_to_le64(nextbn);
	rp->header.prev = cpu_to_le64(addressPXD(&sp->header.self));
	sp->header.next = cpu_to_le64(rbn);

	/*
	 * initialize new right page
	 */
	rp->header.flag = sp->header.flag;

	/* compute sorted entry table at start of extent data area */
	rp->header.nextindex = 0;
	rp->header.stblindex = 1;

	n = PSIZE >> L2DTSLOTSIZE;
	rp->header.maxslot = n;
	stblsize = (n + 31) >> L2DTSLOTSIZE;	/* in unit of slot */

	/* init freelist */
	fsi = rp->header.stblindex + stblsize;
	rp->header.freelist = fsi;
	rp->header.freecnt = rp->header.maxslot - fsi;

	/*
	 *	sequential append at tail: append without split
	 *
	 * If splitting the last page on a level because of appending
	 * a entry to it (skip is maxentry), it's likely that the access is
	 * sequential. Adding an empty page on the side of the level is less
	 * work and can push the fill factor much higher than normal.
	 * If we're wrong it's no big deal, we'll just do the split the right
	 * way next time.
	 * (It may look like it's equally easy to do a similar hack for
	 * reverse sorted data, that is, split the tree left,
	 * but it's not. Be my guest.)
	 */
	if (nextbn == 0 && split->index == sp->header.nextindex) {
		/* linelock header + stbl (first slot) of new page */
		rlv = & rdtlck->lv[rdtlck->index];
		rlv->offset = 0;
		rlv->length = 2;
		rdtlck->index++;

		/*
		 * initialize freelist of new right page
		 */
		f = &rp->slot[fsi];
		for (fsi++; fsi < rp->header.maxslot; f++, fsi++)
			f->next = fsi;
		f->next = -1;

		/* insert entry at the first entry of the new right page */
		dtInsertEntry(rp, 0, split->key, split->data, &rdtlck);

		goto out;
	}

	/*
	 *	non-sequential insert (at possibly middle page)
	 */

	/*
	 * update prev pointer of previous right sibling page;
	 */
	if (nextbn != 0) {
		DT_GETPAGE(ip, nextbn, mp, PSIZE, p, rc);
		if (rc) {
			discard_metapage(rmp);
			return rc;
		}

		BT_MARK_DIRTY(mp, ip);
		/*
		 * acquire a transaction lock on the next page
		 */
		tlck = txLock(tid, ip, mp, tlckDTREE | tlckRELINK);
		jfs_info("dtSplitPage: tlck = 0x%p, ip = 0x%p, mp=0x%p",
			tlck, ip, mp);
		dtlck = (struct dt_lock *) & tlck->lock;

		/* linelock header of previous right sibling page */
		lv = & dtlck->lv[dtlck->index];
		lv->offset = 0;
		lv->length = 1;
		dtlck->index++;

		p->header.prev = cpu_to_le64(rbn);

		DT_PUTPAGE(mp);
	}

	/*
	 * split the data between the split and right pages.
	 */
	skip = split->index;
	half = (PSIZE >> L2DTSLOTSIZE) >> 1;	/* swag */
	left = 0;

	/*
	 *	compute fill factor for split pages
	 *
	 * <nxt> traces the next entry to move to rp
	 * <off> traces the next entry to stay in sp
	 */
	stbl = (u8 *) & sp->slot[sp->header.stblindex];
	nextindex = sp->header.nextindex;
	for (nxt = off = 0; nxt < nextindex; ++off) {
		if (off == skip)
			/* check for fill factor with new entry size */
			n = split->nslot;
		else {
			si = stbl[nxt];
			switch (sp->header.flag & BT_TYPE) {
			case BT_LEAF:
				ldtentry = (struct ldtentry *) & sp->slot[si];
				if (DO_INDEX(ip))
					n = NDTLEAF(ldtentry->namlen);
				else
					n = NDTLEAF_LEGACY(ldtentry->
							   namlen);
				break;

			case BT_INTERNAL:
				idtentry = (struct idtentry *) & sp->slot[si];
				n = NDTINTERNAL(idtentry->namlen);
				break;

			default:
				break;
			}

			++nxt;	/* advance to next entry to move in sp */
		}

		left += n;
		if (left >= half)
			break;
	}

	/* <nxt> poins to the 1st entry to move */

	/*
	 *	move entries to right page
	 *
	 * dtMoveEntry() initializes rp and reserves entry for insertion
	 *
	 * split page moved out entries are linelocked;
	 * new/right page moved in entries are linelocked;
	 */
	/* linelock header + stbl of new right page */
	rlv = & rdtlck->lv[rdtlck->index];
	rlv->offset = 0;
	rlv->length = 5;
	rdtlck->index++;

	dtMoveEntry(sp, nxt, rp, &sdtlck, &rdtlck, DO_INDEX(ip));

	sp->header.nextindex = nxt;

	/*
	 * finalize freelist of new right page
	 */
	fsi = rp->header.freelist;
	f = &rp->slot[fsi];
	for (fsi++; fsi < rp->header.maxslot; f++, fsi++)
		f->next = fsi;
	f->next = -1;

	/*
	 * Update directory index table for entries now in right page
	 */
	if ((rp->header.flag & BT_LEAF) && DO_INDEX(ip)) {
		s64 lblock;

		mp = NULL;
		stbl = DT_GETSTBL(rp);
		for (n = 0; n < rp->header.nextindex; n++) {
			ldtentry = (struct ldtentry *) & rp->slot[stbl[n]];
			modify_index(tid, ip, le32_to_cpu(ldtentry->index),
				     rbn, n, &mp, &lblock);
		}
		if (mp)
			release_metapage(mp);
	}

	/*
	 * the skipped index was on the left page,
	 */
	if (skip <= off) {
		/* insert the new entry in the split page */
		dtInsertEntry(sp, skip, split->key, split->data, &sdtlck);

		/* linelock stbl of split page */
		if (sdtlck->index >= sdtlck->maxcnt)
			sdtlck = (struct dt_lock *) txLinelock(sdtlck);
		slv = & sdtlck->lv[sdtlck->index];
		n = skip >> L2DTSLOTSIZE;
		slv->offset = sp->header.stblindex + n;
		slv->length =
		    ((sp->header.nextindex - 1) >> L2DTSLOTSIZE) - n + 1;
		sdtlck->index++;
	}
	/*
	 * the skipped index was on the right page,
	 */
	else {
		/* adjust the skip index to reflect the new position */
		skip -= nxt;

		/* insert the new entry in the right page */
		dtInsertEntry(rp, skip, split->key, split->data, &rdtlck);
	}

      out:
	*rmpp = rmp;
	*rpxdp = *pxd;

	return rc;
}


/*
 *	dtExtendPage()
 *
 * function: extend 1st/only directory leaf page
 *
 * parameter:
 *
 * return: 0 - success;
 *	   errno - failure;
 *	return extended page pinned;
 */
static int dtExtendPage(tid_t tid,
	     struct inode *ip, struct dtsplit * split, struct btstack * btstack)
{
	struct super_block *sb = ip->i_sb;
	int rc;
	struct metapage *smp, *pmp, *mp;
	dtpage_t *sp, *pp;
	struct pxdlist *pxdlist;
	pxd_t *pxd, *tpxd;
	int xlen, xsize;
	int newstblindex, newstblsize;
	int oldstblindex, oldstblsize;
	int fsi, last;
	struct dtslot *f;
	struct btframe *parent;
	int n;
	struct dt_lock *dtlck;
	s64 xaddr, txaddr;
	struct tlock *tlck;
	struct pxd_lock *pxdlock;
	struct lv *lv;
	uint type;
	struct ldtentry *ldtentry;
	u8 *stbl;

	/* get page to extend */
	smp = split->mp;
	sp = DT_PAGE(ip, smp);

	/* get parent/root page */
	parent = BT_POP(btstack);
	DT_GETPAGE(ip, parent->bn, pmp, PSIZE, pp, rc);
	if (rc)
		return (rc);

	/*
	 *	extend the extent
	 */
	pxdlist = split->pxdlist;
	pxd = &pxdlist->pxd[pxdlist->npxd];
	pxdlist->npxd++;

	xaddr = addressPXD(pxd);
	tpxd = &sp->header.self;
	txaddr = addressPXD(tpxd);
	/* in-place extension */
	if (xaddr == txaddr) {
		type = tlckEXTEND;
	}
	/* relocation */
	else {
		type = tlckNEW;

		/* save moved extent descriptor for later free */
		tlck = txMaplock(tid, ip, tlckDTREE | tlckRELOCATE);
		pxdlock = (struct pxd_lock *) & tlck->lock;
		pxdlock->flag = mlckFREEPXD;
		pxdlock->pxd = sp->header.self;
		pxdlock->index = 1;

		/*
		 * Update directory index table to reflect new page address
		 */
		if (DO_INDEX(ip)) {
			s64 lblock;

			mp = NULL;
			stbl = DT_GETSTBL(sp);
			for (n = 0; n < sp->header.nextindex; n++) {
				ldtentry =
				    (struct ldtentry *) & sp->slot[stbl[n]];
				modify_index(tid, ip,
					     le32_to_cpu(ldtentry->index),
					     xaddr, n, &mp, &lblock);
			}
			if (mp)
				release_metapage(mp);
		}
	}

	/*
	 *	extend the page
	 */
	sp->header.self = *pxd;

	jfs_info("dtExtendPage: ip:0x%p smp:0x%p sp:0x%p", ip, smp, sp);

	BT_MARK_DIRTY(smp, ip);
	/*
	 * acquire a transaction lock on the extended/leaf page
	 */
	tlck = txLock(tid, ip, smp, tlckDTREE | type);
	dtlck = (struct dt_lock *) & tlck->lock;
	lv = & dtlck->lv[0];

	/* update buffer extent descriptor of extended page */
	xlen = lengthPXD(pxd);
	xsize = xlen << JFS_SBI(sb)->l2bsize;

	/*
	 * copy old stbl to new stbl at start of extended area
	 */
	oldstblindex = sp->header.stblindex;
	oldstblsize = (sp->header.maxslot + 31) >> L2DTSLOTSIZE;
	newstblindex = sp->header.maxslot;
	n = xsize >> L2DTSLOTSIZE;
	newstblsize = (n + 31) >> L2DTSLOTSIZE;
	memcpy(&sp->slot[newstblindex], &sp->slot[oldstblindex],
	       sp->header.nextindex);

	/*
	 * in-line extension: linelock old area of extended page
	 */
	if (type == tlckEXTEND) {
		/* linelock header */
		lv->offset = 0;
		lv->length = 1;
		dtlck->index++;
		lv++;

		/* linelock new stbl of extended page */
		lv->offset = newstblindex;
		lv->length = newstblsize;
	}
	/*
	 * relocation: linelock whole relocated area
	 */
	else {
		lv->offset = 0;
		lv->length = sp->header.maxslot + newstblsize;
	}

	dtlck->index++;

	sp->header.maxslot = n;
	sp->header.stblindex = newstblindex;
	/* sp->header.nextindex remains the same */

	/*
	 * add old stbl region at head of freelist
	 */
	fsi = oldstblindex;
	f = &sp->slot[fsi];
	last = sp->header.freelist;
	for (n = 0; n < oldstblsize; n++, fsi++, f++) {
		f->next = last;
		last = fsi;
	}
	sp->header.freelist = last;
	sp->header.freecnt += oldstblsize;

	/*
	 * append free region of newly extended area at tail of freelist
	 */
	/* init free region of newly extended area */
	fsi = n = newstblindex + newstblsize;
	f = &sp->slot[fsi];
	for (fsi++; fsi < sp->header.maxslot; f++, fsi++)
		f->next = fsi;
	f->next = -1;

	/* append new free region at tail of old freelist */
	fsi = sp->header.freelist;
	if (fsi == -1)
		sp->header.freelist = n;
	else {
		do {
			f = &sp->slot[fsi];
			fsi = f->next;
		} while (fsi != -1);

		f->next = n;
	}

	sp->header.freecnt += sp->header.maxslot - n;

	/*
	 * insert the new entry
	 */
	dtInsertEntry(sp, split->index, split->key, split->data, &dtlck);

	BT_MARK_DIRTY(pmp, ip);
	/*
	 * linelock any freeslots residing in old extent
	 */
	if (type == tlckEXTEND) {
		n = sp->header.maxslot >> 2;
		if (sp->header.freelist < n)
			dtLinelockFreelist(sp, n, &dtlck);
	}

	/*
	 *	update parent entry on the parent/root page
	 */
	/*
	 * acquire a transaction lock on the parent/root page
	 */
	tlck = txLock(tid, ip, pmp, tlckDTREE | tlckENTRY);
	dtlck = (struct dt_lock *) & tlck->lock;
	lv = & dtlck->lv[dtlck->index];

	/* linelock parent entry - 1st slot */
	lv->offset = 1;
	lv->length = 1;
	dtlck->index++;

	/* update the parent pxd for page extension */
	tpxd = (pxd_t *) & pp->slot[1];
	*tpxd = *pxd;

	DT_PUTPAGE(pmp);
	return 0;
}


/*
 *	dtSplitRoot()
 *
 * function:
 *	split the full root page into
 *	original/root/split page and new right page
 *	i.e., root remains fixed in tree anchor (inode) and
 *	the root is copied to a single new right child page
 *	since root page << non-root page, and
 *	the split root page contains a single entry for the
 *	new right child page.
 *
 * parameter:
 *
 * return: 0 - success;
 *	   errno - failure;
 *	return new page pinned;
 */
static int dtSplitRoot(tid_t tid,
	    struct inode *ip, struct dtsplit * split, struct metapage ** rmpp)
{
	struct super_block *sb = ip->i_sb;
	struct metapage *smp;
	dtroot_t *sp;
	struct metapage *rmp;
	dtpage_t *rp;
	s64 rbn;
	int xlen;
	int xsize;
	struct dtslot *f;
	s8 *stbl;
	int fsi, stblsize, n;
	struct idtentry *s;
	pxd_t *ppxd;
	struct pxdlist *pxdlist;
	pxd_t *pxd;
	struct dt_lock *dtlck;
	struct tlock *tlck;
	struct lv *lv;
	int rc;

	/* get split root page */
	smp = split->mp;
	sp = &JFS_IP(ip)->i_dtroot;

	/*
	 *	allocate/initialize a single (right) child page
	 *
	 * N.B. at first split, a one (or two) block to fit new entry
	 * is allocated; at subsequent split, a full page is allocated;
	 */
	pxdlist = split->pxdlist;
	pxd = &pxdlist->pxd[pxdlist->npxd];
	pxdlist->npxd++;
	rbn = addressPXD(pxd);
	xlen = lengthPXD(pxd);
	xsize = xlen << JFS_SBI(sb)->l2bsize;
	rmp = get_metapage(ip, rbn, xsize, 1);
	if (!rmp)
		return -EIO;

	rp = rmp->data;

	/* Allocate blocks to quota. */
	rc = dquot_alloc_block(ip, lengthPXD(pxd));
	if (rc) {
		release_metapage(rmp);
		return rc;
	}

	BT_MARK_DIRTY(rmp, ip);
	/*
	 * acquire a transaction lock on the new right page
	 */
	tlck = txLock(tid, ip, rmp, tlckDTREE | tlckNEW);
	dtlck = (struct dt_lock *) & tlck->lock;

	rp->header.flag =
	    (sp->header.flag & BT_LEAF) ? BT_LEAF : BT_INTERNAL;
	rp->header.self = *pxd;

	/* initialize sibling pointers */
	rp->header.next = 0;
	rp->header.prev = 0;

	/*
	 *	move in-line root page into new right page extent
	 */
	/* linelock header + copied entries + new stbl (1st slot) in new page */
	ASSERT(dtlck->index == 0);
	lv = & dtlck->lv[0];
	lv->offset = 0;
	lv->length = 10;	/* 1 + 8 + 1 */
	dtlck->index++;

	n = xsize >> L2DTSLOTSIZE;
	rp->header.maxslot = n;
	stblsize = (n + 31) >> L2DTSLOTSIZE;

	/* copy old stbl to new stbl at start of extended area */
	rp->header.stblindex = DTROOTMAXSLOT;
	stbl = (s8 *) & rp->slot[DTROOTMAXSLOT];
	memcpy(stbl, sp->header.stbl, sp->header.nextindex);
	rp->header.nextindex = sp->header.nextindex;

	/* copy old data area to start of new data area */
	memcpy(&rp->slot[1], &sp->slot[1], IDATASIZE);

	/*
	 * append free region of newly extended area at tail of freelist
	 */
	/* init free region of newly extended area */
	fsi = n = DTROOTMAXSLOT + stblsize;
	f = &rp->slot[fsi];
	for (fsi++; fsi < rp->header.maxslot; f++, fsi++)
		f->next = fsi;
	f->next = -1;

	/* append new free region at tail of old freelist */
	fsi = sp->header.freelist;
	if (fsi == -1)
		rp->header.freelist = n;
	else {
		rp->header.freelist = fsi;

		do {
			f = &rp->slot[fsi];
			fsi = f->next;
		} while (fsi != -1);

		f->next = n;
	}

	rp->header.freecnt = sp->header.freecnt + rp->header.maxslot - n;

	/*
	 * Update directory index table for entries now in right page
	 */
	if ((rp->header.flag & BT_LEAF) && DO_INDEX(ip)) {
		s64 lblock;
		struct metapage *mp = NULL;
		struct ldtentry *ldtentry;

		stbl = DT_GETSTBL(rp);
		for (n = 0; n < rp->header.nextindex; n++) {
			ldtentry = (struct ldtentry *) & rp->slot[stbl[n]];
			modify_index(tid, ip, le32_to_cpu(ldtentry->index),
				     rbn, n, &mp, &lblock);
		}
		if (mp)
			release_metapage(mp);
	}
	/*
	 * insert the new entry into the new right/child page
	 * (skip index in the new right page will not change)
	 */
	dtInsertEntry(rp, split->index, split->key, split->data, &dtlck);

	/*
	 *	reset parent/root page
	 *
	 * set the 1st entry offset to 0, which force the left-most key
	 * at any level of the tree to be less than any search key.
	 *
	 * The btree comparison code guarantees that the left-most key on any
	 * level of the tree is never used, so it doesn't need to be filled in.
	 */
	BT_MARK_DIRTY(smp, ip);
	/*
	 * acquire a transaction lock on the root page (in-memory inode)
	 */
	tlck = txLock(tid, ip, smp, tlckDTREE | tlckNEW | tlckBTROOT);
	dtlck = (struct dt_lock *) & tlck->lock;

	/* linelock root */
	ASSERT(dtlck->index == 0);
	lv = & dtlck->lv[0];
	lv->offset = 0;
	lv->length = DTROOTMAXSLOT;
	dtlck->index++;

	/* update page header of root */
	if (sp->header.flag & BT_LEAF) {
		sp->header.flag &= ~BT_LEAF;
		sp->header.flag |= BT_INTERNAL;
	}

	/* init the first entry */
	s = (struct idtentry *) & sp->slot[DTENTRYSTART];
	ppxd = (pxd_t *) s;
	*ppxd = *pxd;
	s->next = -1;
	s->namlen = 0;

	stbl = sp->header.stbl;
	stbl[0] = DTENTRYSTART;
	sp->header.nextindex = 1;

	/* init freelist */
	fsi = DTENTRYSTART + 1;
	f = &sp->slot[fsi];

	/* init free region of remaining area */
	for (fsi++; fsi < DTROOTMAXSLOT; f++, fsi++)
		f->next = fsi;
	f->next = -1;

	sp->header.freelist = DTENTRYSTART + 1;
	sp->header.freecnt = DTROOTMAXSLOT - (DTENTRYSTART + 1);

	*rmpp = rmp;

	return 0;
}


/*
 *	dtDelete()
 *
 * function: delete the entry(s) referenced by a key.
 *
 * parameter:
 *
 * return:
 */
int dtDelete(tid_t tid,
	 struct inode *ip, struct component_name * key, ino_t * ino, int flag)
{
	int rc = 0;
	s64 bn;
	struct metapage *mp, *imp;
	dtpage_t *p;
	int index;
	struct btstack btstack;
	struct dt_lock *dtlck;
	struct tlock *tlck;
	struct lv *lv;
	int i;
	struct ldtentry *ldtentry;
	u8 *stbl;
	u32 table_index, next_index;
	struct metapage *nmp;
	dtpage_t *np;

	/*
	 *	search for the entry to delete:
	 *
	 * dtSearch() returns (leaf page pinned, index at which to delete).
	 */
	if ((rc = dtSearch(ip, key, ino, &btstack, flag)))
		return rc;

	/* retrieve search result */
	DT_GETSEARCH(ip, btstack.top, bn, mp, p, index);

	/*
	 * We need to find put the index of the next entry into the
	 * directory index table in order to resume a readdir from this
	 * entry.
	 */
	if (DO_INDEX(ip)) {
		stbl = DT_GETSTBL(p);
		ldtentry = (struct ldtentry *) & p->slot[stbl[index]];
		table_index = le32_to_cpu(ldtentry->index);
		if (index == (p->header.nextindex - 1)) {
			/*
			 * Last entry in this leaf page
			 */
			if ((p->header.flag & BT_ROOT)
			    || (p->header.next == 0))
				next_index = -1;
			else {
				/* Read next leaf page */
				DT_GETPAGE(ip, le64_to_cpu(p->header.next),
					   nmp, PSIZE, np, rc);
				if (rc)
					next_index = -1;
				else {
					stbl = DT_GETSTBL(np);
					ldtentry =
					    (struct ldtentry *) & np->
					    slot[stbl[0]];
					next_index =
					    le32_to_cpu(ldtentry->index);
					DT_PUTPAGE(nmp);
				}
			}
		} else {
			ldtentry =
			    (struct ldtentry *) & p->slot[stbl[index + 1]];
			next_index = le32_to_cpu(ldtentry->index);
		}
		free_index(tid, ip, table_index, next_index);
	}
	/*
	 * the leaf page becomes empty, delete the page
	 */
	if (p->header.nextindex == 1) {
		/* delete empty page */
		rc = dtDeleteUp(tid, ip, mp, p, &btstack);
	}
	/*
	 * the leaf page has other entries remaining:
	 *
	 * delete the entry from the leaf page.
	 */
	else {
		BT_MARK_DIRTY(mp, ip);
		/*
		 * acquire a transaction lock on the leaf page
		 */
		tlck = txLock(tid, ip, mp, tlckDTREE | tlckENTRY);
		dtlck = (struct dt_lock *) & tlck->lock;

		/*
		 * Do not assume that dtlck->index will be zero.  During a
		 * rename within a directory, this transaction may have
		 * modified this page already when adding the new entry.
		 */

		/* linelock header */
		if (dtlck->index >= dtlck->maxcnt)
			dtlck = (struct dt_lock *) txLinelock(dtlck);
		lv = & dtlck->lv[dtlck->index];
		lv->offset = 0;
		lv->length = 1;
		dtlck->index++;

		/* linelock stbl of non-root leaf page */
		if (!(p->header.flag & BT_ROOT)) {
			if (dtlck->index >= dtlck->maxcnt)
				dtlck = (struct dt_lock *) txLinelock(dtlck);
			lv = & dtlck->lv[dtlck->index];
			i = index >> L2DTSLOTSIZE;
			lv->offset = p->header.stblindex + i;
			lv->length =
			    ((p->header.nextindex - 1) >> L2DTSLOTSIZE) -
			    i + 1;
			dtlck->index++;
		}

		/* free the leaf entry */
		dtDeleteEntry(p, index, &dtlck);

		/*
		 * Update directory index table for entries moved in stbl
		 */
		if (DO_INDEX(ip) && index < p->header.nextindex) {
			s64 lblock;

			imp = NULL;
			stbl = DT_GETSTBL(p);
			for (i = index; i < p->header.nextindex; i++) {
				ldtentry =
				    (struct ldtentry *) & p->slot[stbl[i]];
				modify_index(tid, ip,
					     le32_to_cpu(ldtentry->index),
					     bn, i, &imp, &lblock);
			}
			if (imp)
				release_metapage(imp);
		}

		DT_PUTPAGE(mp);
	}

	return rc;
}


/*
 *	dtDeleteUp()
 *
 * function:
 *	free empty pages as propagating deletion up the tree
 *
 * parameter:
 *
 * return:
 */
static int dtDeleteUp(tid_t tid, struct inode *ip,
	   struct metapage * fmp, dtpage_t * fp, struct btstack * btstack)
{
	int rc = 0;
	struct metapage *mp;
	dtpage_t *p;
	int index, nextindex;
	int xlen;
	struct btframe *parent;
	struct dt_lock *dtlck;
	struct tlock *tlck;
	struct lv *lv;
	struct pxd_lock *pxdlock;
	int i;

	/*
	 *	keep the root leaf page which has become empty
	 */
	if (BT_IS_ROOT(fmp)) {
		/*
		 * reset the root
		 *
		 * dtInitRoot() acquires txlock on the root
		 */
		dtInitRoot(tid, ip, PARENT(ip));

		DT_PUTPAGE(fmp);

		return 0;
	}

	/*
	 *	free the non-root leaf page
	 */
	/*
	 * acquire a transaction lock on the page
	 *
	 * write FREEXTENT|NOREDOPAGE log record
	 * N.B. linelock is overlaid as freed extent descriptor, and
	 * the buffer page is freed;
	 */
	tlck = txMaplock(tid, ip, tlckDTREE | tlckFREE);
	pxdlock = (struct pxd_lock *) & tlck->lock;
	pxdlock->flag = mlckFREEPXD;
	pxdlock->pxd = fp->header.self;
	pxdlock->index = 1;

	/* update sibling pointers */
	if ((rc = dtRelink(tid, ip, fp))) {
		BT_PUTPAGE(fmp);
		return rc;
	}

	xlen = lengthPXD(&fp->header.self);

	/* Free quota allocation. */
	dquot_free_block(ip, xlen);

	/* free/invalidate its buffer page */
	discard_metapage(fmp);

	/*
	 *	propagate page deletion up the directory tree
	 *
	 * If the delete from the parent page makes it empty,
	 * continue all the way up the tree.
	 * stop if the root page is reached (which is never deleted) or
	 * if the entry deletion does not empty the page.
	 */
	while ((parent = BT_POP(btstack)) != NULL) {
		/* pin the parent page <sp> */
		DT_GETPAGE(ip, parent->bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		/*
		 * free the extent of the child page deleted
		 */
		index = parent->index;

		/*
		 * delete the entry for the child page from parent
		 */
		nextindex = p->header.nextindex;

		/*
		 * the parent has the single entry being deleted:
		 *
		 * free the parent page which has become empty.
		 */
		if (nextindex == 1) {
			/*
			 * keep the root internal page which has become empty
			 */
			if (p->header.flag & BT_ROOT) {
				/*
				 * reset the root
				 *
				 * dtInitRoot() acquires txlock on the root
				 */
				dtInitRoot(tid, ip, PARENT(ip));

				DT_PUTPAGE(mp);

				return 0;
			}
			/*
			 * free the parent page
			 */
			else {
				/*
				 * acquire a transaction lock on the page
				 *
				 * write FREEXTENT|NOREDOPAGE log record
				 */
				tlck =
				    txMaplock(tid, ip,
					      tlckDTREE | tlckFREE);
				pxdlock = (struct pxd_lock *) & tlck->lock;
				pxdlock->flag = mlckFREEPXD;
				pxdlock->pxd = p->header.self;
				pxdlock->index = 1;

				/* update sibling pointers */
				if ((rc = dtRelink(tid, ip, p))) {
					DT_PUTPAGE(mp);
					return rc;
				}

				xlen = lengthPXD(&p->header.self);

				/* Free quota allocation */
				dquot_free_block(ip, xlen);

				/* free/invalidate its buffer page */
				discard_metapage(mp);

				/* propagate up */
				continue;
			}
		}

		/*
		 * the parent has other entries remaining:
		 *
		 * delete the router entry from the parent page.
		 */
		BT_MARK_DIRTY(mp, ip);
		/*
		 * acquire a transaction lock on the page
		 *
		 * action: router entry deletion
		 */
		tlck = txLock(tid, ip, mp, tlckDTREE | tlckENTRY);
		dtlck = (struct dt_lock *) & tlck->lock;

		/* linelock header */
		if (dtlck->index >= dtlck->maxcnt)
			dtlck = (struct dt_lock *) txLinelock(dtlck);
		lv = & dtlck->lv[dtlck->index];
		lv->offset = 0;
		lv->length = 1;
		dtlck->index++;

		/* linelock stbl of non-root leaf page */
		if (!(p->header.flag & BT_ROOT)) {
			if (dtlck->index < dtlck->maxcnt)
				lv++;
			else {
				dtlck = (struct dt_lock *) txLinelock(dtlck);
				lv = & dtlck->lv[0];
			}
			i = index >> L2DTSLOTSIZE;
			lv->offset = p->header.stblindex + i;
			lv->length =
			    ((p->header.nextindex - 1) >> L2DTSLOTSIZE) -
			    i + 1;
			dtlck->index++;
		}

		/* free the router entry */
		dtDeleteEntry(p, index, &dtlck);

		/* reset key of new leftmost entry of level (for consistency) */
		if (index == 0 &&
		    ((p->header.flag & BT_ROOT) || p->header.prev == 0))
			dtTruncateEntry(p, 0, &dtlck);

		/* unpin the parent page */
		DT_PUTPAGE(mp);

		/* exit propagation up */
		break;
	}

	if (!DO_INDEX(ip))
		ip->i_size -= PSIZE;

	return 0;
}

#ifdef _NOTYET
/*
 * NAME:	dtRelocate()
 *
 * FUNCTION:	relocate dtpage (internal or leaf) of directory;
 *		This function is mainly used by defragfs utility.
 */
int dtRelocate(tid_t tid, struct inode *ip, s64 lmxaddr, pxd_t * opxd,
	       s64 nxaddr)
{
	int rc = 0;
	struct metapage *mp, *pmp, *lmp, *rmp;
	dtpage_t *p, *pp, *rp = 0, *lp= 0;
	s64 bn;
	int index;
	struct btstack btstack;
	pxd_t *pxd;
	s64 oxaddr, nextbn, prevbn;
	int xlen, xsize;
	struct tlock *tlck;
	struct dt_lock *dtlck;
	struct pxd_lock *pxdlock;
	s8 *stbl;
	struct lv *lv;

	oxaddr = addressPXD(opxd);
	xlen = lengthPXD(opxd);

	jfs_info("dtRelocate: lmxaddr:%Ld xaddr:%Ld:%Ld xlen:%d",
		   (long long)lmxaddr, (long long)oxaddr, (long long)nxaddr,
		   xlen);

	/*
	 *	1. get the internal parent dtpage covering
	 *	router entry for the tartget page to be relocated;
	 */
	rc = dtSearchNode(ip, lmxaddr, opxd, &btstack);
	if (rc)
		return rc;

	/* retrieve search result */
	DT_GETSEARCH(ip, btstack.top, bn, pmp, pp, index);
	jfs_info("dtRelocate: parent router entry validated.");

	/*
	 *	2. relocate the target dtpage
	 */
	/* read in the target page from src extent */
	DT_GETPAGE(ip, oxaddr, mp, PSIZE, p, rc);
	if (rc) {
		/* release the pinned parent page */
		DT_PUTPAGE(pmp);
		return rc;
	}

	/*
	 * read in sibling pages if any to update sibling pointers;
	 */
	rmp = NULL;
	if (p->header.next) {
		nextbn = le64_to_cpu(p->header.next);
		DT_GETPAGE(ip, nextbn, rmp, PSIZE, rp, rc);
		if (rc) {
			DT_PUTPAGE(mp);
			DT_PUTPAGE(pmp);
			return (rc);
		}
	}

	lmp = NULL;
	if (p->header.prev) {
		prevbn = le64_to_cpu(p->header.prev);
		DT_GETPAGE(ip, prevbn, lmp, PSIZE, lp, rc);
		if (rc) {
			DT_PUTPAGE(mp);
			DT_PUTPAGE(pmp);
			if (rmp)
				DT_PUTPAGE(rmp);
			return (rc);
		}
	}

	/* at this point, all xtpages to be updated are in memory */

	/*
	 * update sibling pointers of sibling dtpages if any;
	 */
	if (lmp) {
		tlck = txLock(tid, ip, lmp, tlckDTREE | tlckRELINK);
		dtlck = (struct dt_lock *) & tlck->lock;
		/* linelock header */
		ASSERT(dtlck->index == 0);
		lv = & dtlck->lv[0];
		lv->offset = 0;
		lv->length = 1;
		dtlck->index++;

		lp->header.next = cpu_to_le64(nxaddr);
		DT_PUTPAGE(lmp);
	}

	if (rmp) {
		tlck = txLock(tid, ip, rmp, tlckDTREE | tlckRELINK);
		dtlck = (struct dt_lock *) & tlck->lock;
		/* linelock header */
		ASSERT(dtlck->index == 0);
		lv = & dtlck->lv[0];
		lv->offset = 0;
		lv->length = 1;
		dtlck->index++;

		rp->header.prev = cpu_to_le64(nxaddr);
		DT_PUTPAGE(rmp);
	}

	/*
	 * update the target dtpage to be relocated
	 *
	 * write LOG_REDOPAGE of LOG_NEW type for dst page
	 * for the whole target page (logredo() will apply
	 * after image and update bmap for allocation of the
	 * dst extent), and update bmap for allocation of
	 * the dst extent;
	 */
	tlck = txLock(tid, ip, mp, tlckDTREE | tlckNEW);
	dtlck = (struct dt_lock *) & tlck->lock;
	/* linelock header */
	ASSERT(dtlck->index == 0);
	lv = & dtlck->lv[0];

	/* update the self address in the dtpage header */
	pxd = &p->header.self;
	PXDaddress(pxd, nxaddr);

	/* the dst page is the same as the src page, i.e.,
	 * linelock for afterimage of the whole page;
	 */
	lv->offset = 0;
	lv->length = p->header.maxslot;
	dtlck->index++;

	/* update the buffer extent descriptor of the dtpage */
	xsize = xlen << JFS_SBI(ip->i_sb)->l2bsize;

	/* unpin the relocated page */
	DT_PUTPAGE(mp);
	jfs_info("dtRelocate: target dtpage relocated.");

	/* the moved extent is dtpage, then a LOG_NOREDOPAGE log rec
	 * needs to be written (in logredo(), the LOG_NOREDOPAGE log rec
	 * will also force a bmap update ).
	 */

	/*
	 *	3. acquire maplock for the source extent to be freed;
	 */
	/* for dtpage relocation, write a LOG_NOREDOPAGE record
	 * for the source dtpage (logredo() will init NoRedoPage
	 * filter and will also update bmap for free of the source
	 * dtpage), and upadte bmap for free of the source dtpage;
	 */
	tlck = txMaplock(tid, ip, tlckDTREE | tlckFREE);
	pxdlock = (struct pxd_lock *) & tlck->lock;
	pxdlock->flag = mlckFREEPXD;
	PXDaddress(&pxdlock->pxd, oxaddr);
	PXDlength(&pxdlock->pxd, xlen);
	pxdlock->index = 1;

	/*
	 *	4. update the parent router entry for relocation;
	 *
	 * acquire tlck for the parent entry covering the target dtpage;
	 * write LOG_REDOPAGE to apply after image only;
	 */
	jfs_info("dtRelocate: update parent router entry.");
	tlck = txLock(tid, ip, pmp, tlckDTREE | tlckENTRY);
	dtlck = (struct dt_lock *) & tlck->lock;
	lv = & dtlck->lv[dtlck->index];

	/* update the PXD with the new address */
	stbl = DT_GETSTBL(pp);
	pxd = (pxd_t *) & pp->slot[stbl[index]];
	PXDaddress(pxd, nxaddr);
	lv->offset = stbl[index];
	lv->length = 1;
	dtlck->index++;

	/* unpin the parent dtpage */
	DT_PUTPAGE(pmp);

	return rc;
}

/*
 * NAME:	dtSearchNode()
 *
 * FUNCTION:	Search for an dtpage containing a specified address
 *		This function is mainly used by defragfs utility.
 *
 * NOTE:	Search result on stack, the found page is pinned at exit.
 *		The result page must be an internal dtpage.
 *		lmxaddr give the address of the left most page of the
 *		dtree level, in which the required dtpage resides.
 */
static int dtSearchNode(struct inode *ip, s64 lmxaddr, pxd_t * kpxd,
			struct btstack * btstack)
{
	int rc = 0;
	s64 bn;
	struct metapage *mp;
	dtpage_t *p;
	int psize = 288;	/* initial in-line directory */
	s8 *stbl;
	int i;
	pxd_t *pxd;
	struct btframe *btsp;

	BT_CLR(btstack);	/* reset stack */

	/*
	 *	descend tree to the level with specified leftmost page
	 *
	 *  by convention, root bn = 0.
	 */
	for (bn = 0;;) {
		/* get/pin the page to search */
		DT_GETPAGE(ip, bn, mp, psize, p, rc);
		if (rc)
			return rc;

		/* does the xaddr of leftmost page of the levevl
		 * matches levevl search key ?
		 */
		if (p->header.flag & BT_ROOT) {
			if (lmxaddr == 0)
				break;
		} else if (addressPXD(&p->header.self) == lmxaddr)
			break;

		/*
		 * descend down to leftmost child page
		 */
		if (p->header.flag & BT_LEAF) {
			DT_PUTPAGE(mp);
			return -ESTALE;
		}

		/* get the leftmost entry */
		stbl = DT_GETSTBL(p);
		pxd = (pxd_t *) & p->slot[stbl[0]];

		/* get the child page block address */
		bn = addressPXD(pxd);
		psize = lengthPXD(pxd) << JFS_SBI(ip->i_sb)->l2bsize;
		/* unpin the parent page */
		DT_PUTPAGE(mp);
	}

	/*
	 *	search each page at the current levevl
	 */
      loop:
	stbl = DT_GETSTBL(p);
	for (i = 0; i < p->header.nextindex; i++) {
		pxd = (pxd_t *) & p->slot[stbl[i]];

		/* found the specified router entry */
		if (addressPXD(pxd) == addressPXD(kpxd) &&
		    lengthPXD(pxd) == lengthPXD(kpxd)) {
			btsp = btstack->top;
			btsp->bn = bn;
			btsp->index = i;
			btsp->mp = mp;

			return 0;
		}
	}

	/* get the right sibling page if any */
	if (p->header.next)
		bn = le64_to_cpu(p->header.next);
	else {
		DT_PUTPAGE(mp);
		return -ESTALE;
	}

	/* unpin current page */
	DT_PUTPAGE(mp);

	/* get the right sibling page */
	DT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
	if (rc)
		return rc;

	goto loop;
}
#endif /* _NOTYET */

/*
 *	dtRelink()
 *
 * function:
 *	link around a freed page.
 *
 * parameter:
 *	fp:	page to be freed
 *
 * return:
 */
static int dtRelink(tid_t tid, struct inode *ip, dtpage_t * p)
{
	int rc;
	struct metapage *mp;
	s64 nextbn, prevbn;
	struct tlock *tlck;
	struct dt_lock *dtlck;
	struct lv *lv;

	nextbn = le64_to_cpu(p->header.next);
	prevbn = le64_to_cpu(p->header.prev);

	/* update prev pointer of the next page */
	if (nextbn != 0) {
		DT_GETPAGE(ip, nextbn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		BT_MARK_DIRTY(mp, ip);
		/*
		 * acquire a transaction lock on the next page
		 *
		 * action: update prev pointer;
		 */
		tlck = txLock(tid, ip, mp, tlckDTREE | tlckRELINK);
		jfs_info("dtRelink nextbn: tlck = 0x%p, ip = 0x%p, mp=0x%p",
			tlck, ip, mp);
		dtlck = (struct dt_lock *) & tlck->lock;

		/* linelock header */
		if (dtlck->index >= dtlck->maxcnt)
			dtlck = (struct dt_lock *) txLinelock(dtlck);
		lv = & dtlck->lv[dtlck->index];
		lv->offset = 0;
		lv->length = 1;
		dtlck->index++;

		p->header.prev = cpu_to_le64(prevbn);
		DT_PUTPAGE(mp);
	}

	/* update next pointer of the previous page */
	if (prevbn != 0) {
		DT_GETPAGE(ip, prevbn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		BT_MARK_DIRTY(mp, ip);
		/*
		 * acquire a transaction lock on the prev page
		 *
		 * action: update next pointer;
		 */
		tlck = txLock(tid, ip, mp, tlckDTREE | tlckRELINK);
		jfs_info("dtRelink prevbn: tlck = 0x%p, ip = 0x%p, mp=0x%p",
			tlck, ip, mp);
		dtlck = (struct dt_lock *) & tlck->lock;

		/* linelock header */
		if (dtlck->index >= dtlck->maxcnt)
			dtlck = (struct dt_lock *) txLinelock(dtlck);
		lv = & dtlck->lv[dtlck->index];
		lv->offset = 0;
		lv->length = 1;
		dtlck->index++;

		p->header.next = cpu_to_le64(nextbn);
		DT_PUTPAGE(mp);
	}

	return 0;
}


/*
 *	dtInitRoot()
 *
 * initialize directory root (inline in inode)
 */
void dtInitRoot(tid_t tid, struct inode *ip, u32 idotdot)
{
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	dtroot_t *p;
	int fsi;
	struct dtslot *f;
	struct tlock *tlck;
	struct dt_lock *dtlck;
	struct lv *lv;
	u16 xflag_save;

	/*
	 * If this was previously an non-empty directory, we need to remove
	 * the old directory table.
	 */
	if (DO_INDEX(ip)) {
		if (!jfs_dirtable_inline(ip)) {
			struct tblock *tblk = tid_to_tblock(tid);
			/*
			 * We're playing games with the tid's xflag.  If
			 * we're removing a regular file, the file's xtree
			 * is committed with COMMIT_PMAP, but we always
			 * commit the directories xtree with COMMIT_PWMAP.
			 */
			xflag_save = tblk->xflag;
			tblk->xflag = 0;
			/*
			 * xtTruncate isn't guaranteed to fully truncate
			 * the xtree.  The caller needs to check i_size
			 * after committing the transaction to see if
			 * additional truncation is needed.  The
			 * COMMIT_Stale flag tells caller that we
			 * initiated the truncation.
			 */
			xtTruncate(tid, ip, 0, COMMIT_PWMAP);
			set_cflag(COMMIT_Stale, ip);

			tblk->xflag = xflag_save;
		} else
			ip->i_size = 1;

		jfs_ip->next_index = 2;
	} else
		ip->i_size = IDATASIZE;

	/*
	 * acquire a transaction lock on the root
	 *
	 * action: directory initialization;
	 */
	tlck = txLock(tid, ip, (struct metapage *) & jfs_ip->bxflag,
		      tlckDTREE | tlckENTRY | tlckBTROOT);
	dtlck = (struct dt_lock *) & tlck->lock;

	/* linelock root */
	ASSERT(dtlck->index == 0);
	lv = & dtlck->lv[0];
	lv->offset = 0;
	lv->length = DTROOTMAXSLOT;
	dtlck->index++;

	p = &jfs_ip->i_dtroot;

	p->header.flag = DXD_INDEX | BT_ROOT | BT_LEAF;

	p->header.nextindex = 0;

	/* init freelist */
	fsi = 1;
	f = &p->slot[fsi];

	/* init data area of root */
	for (fsi++; fsi < DTROOTMAXSLOT; f++, fsi++)
		f->next = fsi;
	f->next = -1;

	p->header.freelist = 1;
	p->header.freecnt = 8;

	/* init '..' entry */
	p->header.idotdot = cpu_to_le32(idotdot);

	return;
}

/*
 *	add_missing_indices()
 *
 * function: Fix dtree page in which one or more entries has an invalid index.
 *	     fsck.jfs should really fix this, but it currently does not.
 *	     Called from jfs_readdir when bad index is detected.
 */
static void add_missing_indices(struct inode *inode, s64 bn)
{
	struct ldtentry *d;
	struct dt_lock *dtlck;
	int i;
	uint index;
	struct lv *lv;
	struct metapage *mp;
	dtpage_t *p;
	int rc;
	s8 *stbl;
	tid_t tid;
	struct tlock *tlck;

	tid = txBegin(inode->i_sb, 0);

	DT_GETPAGE(inode, bn, mp, PSIZE, p, rc);

	if (rc) {
		printk(KERN_ERR "DT_GETPAGE failed!\n");
		goto end;
	}
	BT_MARK_DIRTY(mp, inode);

	ASSERT(p->header.flag & BT_LEAF);

	tlck = txLock(tid, inode, mp, tlckDTREE | tlckENTRY);
	if (BT_IS_ROOT(mp))
		tlck->type |= tlckBTROOT;

	dtlck = (struct dt_lock *) &tlck->lock;

	stbl = DT_GETSTBL(p);
	for (i = 0; i < p->header.nextindex; i++) {
		d = (struct ldtentry *) &p->slot[stbl[i]];
		index = le32_to_cpu(d->index);
		if ((index < 2) || (index >= JFS_IP(inode)->next_index)) {
			d->index = cpu_to_le32(add_index(tid, inode, bn, i));
			if (dtlck->index >= dtlck->maxcnt)
				dtlck = (struct dt_lock *) txLinelock(dtlck);
			lv = &dtlck->lv[dtlck->index];
			lv->offset = stbl[i];
			lv->length = 1;
			dtlck->index++;
		}
	}

	DT_PUTPAGE(mp);
	(void) txCommit(tid, 1, &inode, 0);
end:
	txEnd(tid);
}

/*
 * Buffer to hold directory entry info while traversing a dtree page
 * before being fed to the filldir function
 */
struct jfs_dirent {
	loff_t position;
	int ino;
	u16 name_len;
	char name[0];
};

/*
 * function to determine next variable-sized jfs_dirent in buffer
 */
static inline struct jfs_dirent *next_jfs_dirent(struct jfs_dirent *dirent)
{
	return (struct jfs_dirent *)
		((char *)dirent +
		 ((sizeof (struct jfs_dirent) + dirent->name_len + 1 +
		   sizeof (loff_t) - 1) &
		  ~(sizeof (loff_t) - 1)));
}

/*
 *	jfs_readdir()
 *
 * function: read directory entries sequentially
 *	from the specified entry offset
 *
 * parameter:
 *
 * return: offset = (pn, index) of start entry
 *	of next jfs_readdir()/dtRead()
 */
int jfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *ip = file_inode(file);
	struct nls_table *codepage = JFS_SBI(ip->i_sb)->nls_tab;
	int rc = 0;
	loff_t dtpos;	/* legacy OS/2 style position */
	struct dtoffset {
		s16 pn;
		s16 index;
		s32 unused;
	} *dtoffset = (struct dtoffset *) &dtpos;
	s64 bn;
	struct metapage *mp;
	dtpage_t *p;
	int index;
	s8 *stbl;
	struct btstack btstack;
	int i, next;
	struct ldtentry *d;
	struct dtslot *t;
	int d_namleft, len, outlen;
	unsigned long dirent_buf;
	char *name_ptr;
	u32 dir_index;
	int do_index = 0;
	uint loop_count = 0;
	struct jfs_dirent *jfs_dirent;
	int jfs_dirents;
	int overflow, fix_page, page_fixed = 0;
	static int unique_pos = 2;	/* If we can't fix broken index */

	if (ctx->pos == DIREND)
		return 0;

	if (DO_INDEX(ip)) {
		/*
		 * persistent index is stored in directory entries.
		 * Special cases:	 0 = .
		 *			 1 = ..
		 *			-1 = End of directory
		 */
		do_index = 1;

		dir_index = (u32) ctx->pos;

		/*
		 * NFSv4 reserves cookies 1 and 2 for . and .. so the value
		 * we return to the vfs is one greater than the one we use
		 * internally.
		 */
		if (dir_index)
			dir_index--;

		if (dir_index > 1) {
			struct dir_table_slot dirtab_slot;

			if (dtEmpty(ip) ||
			    (dir_index >= JFS_IP(ip)->next_index)) {
				/* Stale position.  Directory has shrunk */
				ctx->pos = DIREND;
				return 0;
			}
		      repeat:
			rc = read_index(ip, dir_index, &dirtab_slot);
			if (rc) {
				ctx->pos = DIREND;
				return rc;
			}
			if (dirtab_slot.flag == DIR_INDEX_FREE) {
				if (loop_count++ > JFS_IP(ip)->next_index) {
					jfs_err("jfs_readdir detected "
						   "infinite loop!");
					ctx->pos = DIREND;
					return 0;
				}
				dir_index = le32_to_cpu(dirtab_slot.addr2);
				if (dir_index == -1) {
					ctx->pos = DIREND;
					return 0;
				}
				goto repeat;
			}
			bn = addressDTS(&dirtab_slot);
			index = dirtab_slot.slot;
			DT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
			if (rc) {
				ctx->pos = DIREND;
				return 0;
			}
			if (p->header.flag & BT_INTERNAL) {
				jfs_err("jfs_readdir: bad index table");
				DT_PUTPAGE(mp);
				ctx->pos = DIREND;
				return 0;
			}
		} else {
			if (dir_index == 0) {
				/*
				 * self "."
				 */
				ctx->pos = 1;
				if (!dir_emit(ctx, ".", 1, ip->i_ino, DT_DIR))
					return 0;
			}
			/*
			 * parent ".."
			 */
			ctx->pos = 2;
			if (!dir_emit(ctx, "..", 2, PARENT(ip), DT_DIR))
				return 0;

			/*
			 * Find first entry of left-most leaf
			 */
			if (dtEmpty(ip)) {
				ctx->pos = DIREND;
				return 0;
			}

			if ((rc = dtReadFirst(ip, &btstack)))
				return rc;

			DT_GETSEARCH(ip, btstack.top, bn, mp, p, index);
		}
	} else {
		/*
		 * Legacy filesystem - OS/2 & Linux JFS < 0.3.6
		 *
		 * pn = 0; index = 1:	First entry "."
		 * pn = 0; index = 2:	Second entry ".."
		 * pn > 0:		Real entries, pn=1 -> leftmost page
		 * pn = index = -1:	No more entries
		 */
		dtpos = ctx->pos;
		if (dtpos < 2) {
			/* build "." entry */
			ctx->pos = 1;
			if (!dir_emit(ctx, ".", 1, ip->i_ino, DT_DIR))
				return 0;
			dtoffset->index = 2;
			ctx->pos = dtpos;
		}

		if (dtoffset->pn == 0) {
			if (dtoffset->index == 2) {
				/* build ".." entry */
				if (!dir_emit(ctx, "..", 2, PARENT(ip), DT_DIR))
					return 0;
			} else {
				jfs_err("jfs_readdir called with "
					"invalid offset!");
			}
			dtoffset->pn = 1;
			dtoffset->index = 0;
			ctx->pos = dtpos;
		}

		if (dtEmpty(ip)) {
			ctx->pos = DIREND;
			return 0;
		}

		if ((rc = dtReadNext(ip, &ctx->pos, &btstack))) {
			jfs_err("jfs_readdir: unexpected rc = %d "
				"from dtReadNext", rc);
			ctx->pos = DIREND;
			return 0;
		}
		/* get start leaf page and index */
		DT_GETSEARCH(ip, btstack.top, bn, mp, p, index);

		/* offset beyond directory eof ? */
		if (bn < 0) {
			ctx->pos = DIREND;
			return 0;
		}
	}

	dirent_buf = __get_free_page(GFP_KERNEL);
	if (dirent_buf == 0) {
		DT_PUTPAGE(mp);
		jfs_warn("jfs_readdir: __get_free_page failed!");
		ctx->pos = DIREND;
		return -ENOMEM;
	}

	while (1) {
		jfs_dirent = (struct jfs_dirent *) dirent_buf;
		jfs_dirents = 0;
		overflow = fix_page = 0;

		stbl = DT_GETSTBL(p);

		for (i = index; i < p->header.nextindex; i++) {
			d = (struct ldtentry *) & p->slot[stbl[i]];

			if (((long) jfs_dirent + d->namlen + 1) >
			    (dirent_buf + PAGE_SIZE)) {
				/* DBCS codepages could overrun dirent_buf */
				index = i;
				overflow = 1;
				break;
			}

			d_namleft = d->namlen;
			name_ptr = jfs_dirent->name;
			jfs_dirent->ino = le32_to_cpu(d->inumber);

			if (do_index) {
				len = min(d_namleft, DTLHDRDATALEN);
				jfs_dirent->position = le32_to_cpu(d->index);
				/*
				 * d->index should always be valid, but it
				 * isn't.  fsck.jfs doesn't create the
				 * directory index for the lost+found
				 * directory.  Rather than let it go,
				 * we can try to fix it.
				 */
				if ((jfs_dirent->position < 2) ||
				    (jfs_dirent->position >=
				     JFS_IP(ip)->next_index)) {
					if (!page_fixed && !isReadOnly(ip)) {
						fix_page = 1;
						/*
						 * setting overflow and setting
						 * index to i will cause the
						 * same page to be processed
						 * again starting here
						 */
						overflow = 1;
						index = i;
						break;
					}
					jfs_dirent->position = unique_pos++;
				}
				/*
				 * We add 1 to the index because we may
				 * use a value of 2 internally, and NFSv4
				 * doesn't like that.
				 */
				jfs_dirent->position++;
			} else {
				jfs_dirent->position = dtpos;
				len = min(d_namleft, DTLHDRDATALEN_LEGACY);
			}

			/* copy the name of head/only segment */
			outlen = jfs_strfromUCS_le(name_ptr, d->name, len,
						   codepage);
			jfs_dirent->name_len = outlen;

			/* copy name in the additional segment(s) */
			next = d->next;
			while (next >= 0) {
				t = (struct dtslot *) & p->slot[next];
				name_ptr += outlen;
				d_namleft -= len;
				/* Sanity Check */
				if (d_namleft == 0) {
					jfs_error(ip->i_sb,
						  "JFS:Dtree error: ino = %ld, bn=%lld, index = %d\n",
						  (long)ip->i_ino,
						  (long long)bn,
						  i);
					goto skip_one;
				}
				len = min(d_namleft, DTSLOTDATALEN);
				outlen = jfs_strfromUCS_le(name_ptr, t->name,
							   len, codepage);
				jfs_dirent->name_len += outlen;

				next = t->next;
			}

			jfs_dirents++;
			jfs_dirent = next_jfs_dirent(jfs_dirent);
skip_one:
			if (!do_index)
				dtoffset->index++;
		}

		if (!overflow) {
			/* Point to next leaf page */
			if (p->header.flag & BT_ROOT)
				bn = 0;
			else {
				bn = le64_to_cpu(p->header.next);
				index = 0;
				/* update offset (pn:index) for new page */
				if (!do_index) {
					dtoffset->pn++;
					dtoffset->index = 0;
				}
			}
			page_fixed = 0;
		}

		/* unpin previous leaf page */
		DT_PUTPAGE(mp);

		jfs_dirent = (struct jfs_dirent *) dirent_buf;
		while (jfs_dirents--) {
			ctx->pos = jfs_dirent->position;
			if (!dir_emit(ctx, jfs_dirent->name,
				    jfs_dirent->name_len,
				    jfs_dirent->ino, DT_UNKNOWN))
				goto out;
			jfs_dirent = next_jfs_dirent(jfs_dirent);
		}

		if (fix_page) {
			add_missing_indices(ip, bn);
			page_fixed = 1;
		}

		if (!overflow && (bn == 0)) {
			ctx->pos = DIREND;
			break;
		}

		DT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc) {
			free_page(dirent_buf);
			return rc;
		}
	}

      out:
	free_page(dirent_buf);

	return rc;
}


/*
 *	dtReadFirst()
 *
 * function: get the leftmost page of the directory
 */
static int dtReadFirst(struct inode *ip, struct btstack * btstack)
{
	int rc = 0;
	s64 bn;
	int psize = 288;	/* initial in-line directory */
	struct metapage *mp;
	dtpage_t *p;
	s8 *stbl;
	struct btframe *btsp;
	pxd_t *xd;

	BT_CLR(btstack);	/* reset stack */

	/*
	 *	descend leftmost path of the tree
	 *
	 * by convention, root bn = 0.
	 */
	for (bn = 0;;) {
		DT_GETPAGE(ip, bn, mp, psize, p, rc);
		if (rc)
			return rc;

		/*
		 * leftmost leaf page
		 */
		if (p->header.flag & BT_LEAF) {
			/* return leftmost entry */
			btsp = btstack->top;
			btsp->bn = bn;
			btsp->index = 0;
			btsp->mp = mp;

			return 0;
		}

		/*
		 * descend down to leftmost child page
		 */
		if (BT_STACK_FULL(btstack)) {
			DT_PUTPAGE(mp);
			jfs_error(ip->i_sb, "btstack overrun\n");
			BT_STACK_DUMP(btstack);
			return -EIO;
		}
		/* push (bn, index) of the parent page/entry */
		BT_PUSH(btstack, bn, 0);

		/* get the leftmost entry */
		stbl = DT_GETSTBL(p);
		xd = (pxd_t *) & p->slot[stbl[0]];

		/* get the child page block address */
		bn = addressPXD(xd);
		psize = lengthPXD(xd) << JFS_SBI(ip->i_sb)->l2bsize;

		/* unpin the parent page */
		DT_PUTPAGE(mp);
	}
}


/*
 *	dtReadNext()
 *
 * function: get the page of the specified offset (pn:index)
 *
 * return: if (offset > eof), bn = -1;
 *
 * note: if index > nextindex of the target leaf page,
 * start with 1st entry of next leaf page;
 */
static int dtReadNext(struct inode *ip, loff_t * offset,
		      struct btstack * btstack)
{
	int rc = 0;
	struct dtoffset {
		s16 pn;
		s16 index;
		s32 unused;
	} *dtoffset = (struct dtoffset *) offset;
	s64 bn;
	struct metapage *mp;
	dtpage_t *p;
	int index;
	int pn;
	s8 *stbl;
	struct btframe *btsp, *parent;
	pxd_t *xd;

	/*
	 * get leftmost leaf page pinned
	 */
	if ((rc = dtReadFirst(ip, btstack)))
		return rc;

	/* get leaf page */
	DT_GETSEARCH(ip, btstack->top, bn, mp, p, index);

	/* get the start offset (pn:index) */
	pn = dtoffset->pn - 1;	/* Now pn = 0 represents leftmost leaf */
	index = dtoffset->index;

	/* start at leftmost page ? */
	if (pn == 0) {
		/* offset beyond eof ? */
		if (index < p->header.nextindex)
			goto out;

		if (p->header.flag & BT_ROOT) {
			bn = -1;
			goto out;
		}

		/* start with 1st entry of next leaf page */
		dtoffset->pn++;
		dtoffset->index = index = 0;
		goto a;
	}

	/* start at non-leftmost page: scan parent pages for large pn */
	if (p->header.flag & BT_ROOT) {
		bn = -1;
		goto out;
	}

	/* start after next leaf page ? */
	if (pn > 1)
		goto b;

	/* get leaf page pn = 1 */
      a:
	bn = le64_to_cpu(p->header.next);

	/* unpin leaf page */
	DT_PUTPAGE(mp);

	/* offset beyond eof ? */
	if (bn == 0) {
		bn = -1;
		goto out;
	}

	goto c;

	/*
	 * scan last internal page level to get target leaf page
	 */
      b:
	/* unpin leftmost leaf page */
	DT_PUTPAGE(mp);

	/* get left most parent page */
	btsp = btstack->top;
	parent = btsp - 1;
	bn = parent->bn;
	DT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
	if (rc)
		return rc;

	/* scan parent pages at last internal page level */
	while (pn >= p->header.nextindex) {
		pn -= p->header.nextindex;

		/* get next parent page address */
		bn = le64_to_cpu(p->header.next);

		/* unpin current parent page */
		DT_PUTPAGE(mp);

		/* offset beyond eof ? */
		if (bn == 0) {
			bn = -1;
			goto out;
		}

		/* get next parent page */
		DT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		/* update parent page stack frame */
		parent->bn = bn;
	}

	/* get leaf page address */
	stbl = DT_GETSTBL(p);
	xd = (pxd_t *) & p->slot[stbl[pn]];
	bn = addressPXD(xd);

	/* unpin parent page */
	DT_PUTPAGE(mp);

	/*
	 * get target leaf page
	 */
      c:
	DT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
	if (rc)
		return rc;

	/*
	 * leaf page has been completed:
	 * start with 1st entry of next leaf page
	 */
	if (index >= p->header.nextindex) {
		bn = le64_to_cpu(p->header.next);

		/* unpin leaf page */
		DT_PUTPAGE(mp);

		/* offset beyond eof ? */
		if (bn == 0) {
			bn = -1;
			goto out;
		}

		/* get next leaf page */
		DT_GETPAGE(ip, bn, mp, PSIZE, p, rc);
		if (rc)
			return rc;

		/* start with 1st entry of next leaf page */
		dtoffset->pn++;
		dtoffset->index = 0;
	}

      out:
	/* return target leaf page pinned */
	btsp = btstack->top;
	btsp->bn = bn;
	btsp->index = dtoffset->index;
	btsp->mp = mp;

	return 0;
}


/*
 *	dtCompare()
 *
 * function: compare search key with an internal entry
 *
 * return:
 *	< 0 if k is < record
 *	= 0 if k is = record
 *	> 0 if k is > record
 */
static int dtCompare(struct component_name * key,	/* search key */
		     dtpage_t * p,	/* directory page */
		     int si)
{				/* entry slot index */
	wchar_t *kname;
	__le16 *name;
	int klen, namlen, len, rc;
	struct idtentry *ih;
	struct dtslot *t;

	/*
	 * force the left-most key on internal pages, at any level of
	 * the tree, to be less than any search key.
	 * this obviates having to update the leftmost key on an internal
	 * page when the user inserts a new key in the tree smaller than
	 * anything that has been stored.
	 *
	 * (? if/when dtSearch() narrows down to 1st entry (index = 0),
	 * at any internal page at any level of the tree,
	 * it descends to child of the entry anyway -
	 * ? make the entry as min size dummy entry)
	 *
	 * if (e->index == 0 && h->prevpg == P_INVALID && !(h->flags & BT_LEAF))
	 * return (1);
	 */

	kname = key->name;
	klen = key->namlen;

	ih = (struct idtentry *) & p->slot[si];
	si = ih->next;
	name = ih->name;
	namlen = ih->namlen;
	len = min(namlen, DTIHDRDATALEN);

	/* compare with head/only segment */
	len = min(klen, len);
	if ((rc = UniStrncmp_le(kname, name, len)))
		return rc;

	klen -= len;
	namlen -= len;

	/* compare with additional segment(s) */
	kname += len;
	while (klen > 0 && namlen > 0) {
		/* compare with next name segment */
		t = (struct dtslot *) & p->slot[si];
		len = min(namlen, DTSLOTDATALEN);
		len = min(klen, len);
		name = t->name;
		if ((rc = UniStrncmp_le(kname, name, len)))
			return rc;

		klen -= len;
		namlen -= len;
		kname += len;
		si = t->next;
	}

	return (klen - namlen);
}




/*
 *	ciCompare()
 *
 * function: compare search key with an (leaf/internal) entry
 *
 * return:
 *	< 0 if k is < record
 *	= 0 if k is = record
 *	> 0 if k is > record
 */
static int ciCompare(struct component_name * key,	/* search key */
		     dtpage_t * p,	/* directory page */
		     int si,	/* entry slot index */
		     int flag)
{
	wchar_t *kname, x;
	__le16 *name;
	int klen, namlen, len, rc;
	struct ldtentry *lh;
	struct idtentry *ih;
	struct dtslot *t;
	int i;

	/*
	 * force the left-most key on internal pages, at any level of
	 * the tree, to be less than any search key.
	 * this obviates having to update the leftmost key on an internal
	 * page when the user inserts a new key in the tree smaller than
	 * anything that has been stored.
	 *
	 * (? if/when dtSearch() narrows down to 1st entry (index = 0),
	 * at any internal page at any level of the tree,
	 * it descends to child of the entry anyway -
	 * ? make the entry as min size dummy entry)
	 *
	 * if (e->index == 0 && h->prevpg == P_INVALID && !(h->flags & BT_LEAF))
	 * return (1);
	 */

	kname = key->name;
	klen = key->namlen;

	/*
	 * leaf page entry
	 */
	if (p->header.flag & BT_LEAF) {
		lh = (struct ldtentry *) & p->slot[si];
		si = lh->next;
		name = lh->name;
		namlen = lh->namlen;
		if (flag & JFS_DIR_INDEX)
			len = min(namlen, DTLHDRDATALEN);
		else
			len = min(namlen, DTLHDRDATALEN_LEGACY);
	}
	/*
	 * internal page entry
	 */
	else {
		ih = (struct idtentry *) & p->slot[si];
		si = ih->next;
		name = ih->name;
		namlen = ih->namlen;
		len = min(namlen, DTIHDRDATALEN);
	}

	/* compare with head/only segment */
	len = min(klen, len);
	for (i = 0; i < len; i++, kname++, name++) {
		/* only uppercase if case-insensitive support is on */
		if ((flag & JFS_OS2) == JFS_OS2)
			x = UniToupper(le16_to_cpu(*name));
		else
			x = le16_to_cpu(*name);
		if ((rc = *kname - x))
			return rc;
	}

	klen -= len;
	namlen -= len;

	/* compare with additional segment(s) */
	while (klen > 0 && namlen > 0) {
		/* compare with next name segment */
		t = (struct dtslot *) & p->slot[si];
		len = min(namlen, DTSLOTDATALEN);
		len = min(klen, len);
		name = t->name;
		for (i = 0; i < len; i++, kname++, name++) {
			/* only uppercase if case-insensitive support is on */
			if ((flag & JFS_OS2) == JFS_OS2)
				x = UniToupper(le16_to_cpu(*name));
			else
				x = le16_to_cpu(*name);

			if ((rc = *kname - x))
				return rc;
		}

		klen -= len;
		namlen -= len;
		si = t->next;
	}

	return (klen - namlen);
}


/*
 *	ciGetLeafPrefixKey()
 *
 * function: compute prefix of suffix compression
 *	     from two adjacent leaf entries
 *	     across page boundary
 *
 * return: non-zero on error
 *
 */
static int ciGetLeafPrefixKey(dtpage_t * lp, int li, dtpage_t * rp,
			       int ri, struct component_name * key, int flag)
{
	int klen, namlen;
	wchar_t *pl, *pr, *kname;
	struct component_name lkey;
	struct component_name rkey;

	lkey.name = kmalloc((JFS_NAME_MAX + 1) * sizeof(wchar_t),
					GFP_KERNEL);
	if (lkey.name == NULL)
		return -ENOMEM;

	rkey.name = kmalloc((JFS_NAME_MAX + 1) * sizeof(wchar_t),
					GFP_KERNEL);
	if (rkey.name == NULL) {
		kfree(lkey.name);
		return -ENOMEM;
	}

	/* get left and right key */
	dtGetKey(lp, li, &lkey, flag);
	lkey.name[lkey.namlen] = 0;

	if ((flag & JFS_OS2) == JFS_OS2)
		ciToUpper(&lkey);

	dtGetKey(rp, ri, &rkey, flag);
	rkey.name[rkey.namlen] = 0;


	if ((flag & JFS_OS2) == JFS_OS2)
		ciToUpper(&rkey);

	/* compute prefix */
	klen = 0;
	kname = key->name;
	namlen = min(lkey.namlen, rkey.namlen);
	for (pl = lkey.name, pr = rkey.name;
	     namlen; pl++, pr++, namlen--, klen++, kname++) {
		*kname = *pr;
		if (*pl != *pr) {
			key->namlen = klen + 1;
			goto free_names;
		}
	}

	/* l->namlen <= r->namlen since l <= r */
	if (lkey.namlen < rkey.namlen) {
		*kname = *pr;
		key->namlen = klen + 1;
	} else			/* l->namelen == r->namelen */
		key->namlen = klen;

free_names:
	kfree(lkey.name);
	kfree(rkey.name);
	return 0;
}



/*
 *	dtGetKey()
 *
 * function: get key of the entry
 */
static void dtGetKey(dtpage_t * p, int i,	/* entry index */
		     struct component_name * key, int flag)
{
	int si;
	s8 *stbl;
	struct ldtentry *lh;
	struct idtentry *ih;
	struct dtslot *t;
	int namlen, len;
	wchar_t *kname;
	__le16 *name;

	/* get entry */
	stbl = DT_GETSTBL(p);
	si = stbl[i];
	if (p->header.flag & BT_LEAF) {
		lh = (struct ldtentry *) & p->slot[si];
		si = lh->next;
		namlen = lh->namlen;
		name = lh->name;
		if (flag & JFS_DIR_INDEX)
			len = min(namlen, DTLHDRDATALEN);
		else
			len = min(namlen, DTLHDRDATALEN_LEGACY);
	} else {
		ih = (struct idtentry *) & p->slot[si];
		si = ih->next;
		namlen = ih->namlen;
		name = ih->name;
		len = min(namlen, DTIHDRDATALEN);
	}

	key->namlen = namlen;
	kname = key->name;

	/*
	 * move head/only segment
	 */
	UniStrncpy_from_le(kname, name, len);

	/*
	 * move additional segment(s)
	 */
	while (si >= 0) {
		/* get next segment */
		t = &p->slot[si];
		kname += len;
		namlen -= len;
		len = min(namlen, DTSLOTDATALEN);
		UniStrncpy_from_le(kname, t->name, len);

		si = t->next;
	}
}


/*
 *	dtInsertEntry()
 *
 * function: allocate free slot(s) and
 *	     write a leaf/internal entry
 *
 * return: entry slot index
 */
static void dtInsertEntry(dtpage_t * p, int index, struct component_name * key,
			  ddata_t * data, struct dt_lock ** dtlock)
{
	struct dtslot *h, *t;
	struct ldtentry *lh = NULL;
	struct idtentry *ih = NULL;
	int hsi, fsi, klen, len, nextindex;
	wchar_t *kname;
	__le16 *name;
	s8 *stbl;
	pxd_t *xd;
	struct dt_lock *dtlck = *dtlock;
	struct lv *lv;
	int xsi, n;
	s64 bn = 0;
	struct metapage *mp = NULL;

	klen = key->namlen;
	kname = key->name;

	/* allocate a free slot */
	hsi = fsi = p->header.freelist;
	h = &p->slot[fsi];
	p->header.freelist = h->next;
	--p->header.freecnt;

	/* open new linelock */
	if (dtlck->index >= dtlck->maxcnt)
		dtlck = (struct dt_lock *) txLinelock(dtlck);

	lv = & dtlck->lv[dtlck->index];
	lv->offset = hsi;

	/* write head/only segment */
	if (p->header.flag & BT_LEAF) {
		lh = (struct ldtentry *) h;
		lh->next = h->next;
		lh->inumber = cpu_to_le32(data->leaf.ino);
		lh->namlen = klen;
		name = lh->name;
		if (data->leaf.ip) {
			len = min(klen, DTLHDRDATALEN);
			if (!(p->header.flag & BT_ROOT))
				bn = addressPXD(&p->header.self);
			lh->index = cpu_to_le32(add_index(data->leaf.tid,
							  data->leaf.ip,
							  bn, index));
		} else
			len = min(klen, DTLHDRDATALEN_LEGACY);
	} else {
		ih = (struct idtentry *) h;
		ih->next = h->next;
		xd = (pxd_t *) ih;
		*xd = data->xd;
		ih->namlen = klen;
		name = ih->name;
		len = min(klen, DTIHDRDATALEN);
	}

	UniStrncpy_to_le(name, kname, len);

	n = 1;
	xsi = hsi;

	/* write additional segment(s) */
	t = h;
	klen -= len;
	while (klen) {
		/* get free slot */
		fsi = p->header.freelist;
		t = &p->slot[fsi];
		p->header.freelist = t->next;
		--p->header.freecnt;

		/* is next slot contiguous ? */
		if (fsi != xsi + 1) {
			/* close current linelock */
			lv->length = n;
			dtlck->index++;

			/* open new linelock */
			if (dtlck->index < dtlck->maxcnt)
				lv++;
			else {
				dtlck = (struct dt_lock *) txLinelock(dtlck);
				lv = & dtlck->lv[0];
			}

			lv->offset = fsi;
			n = 0;
		}

		kname += len;
		len = min(klen, DTSLOTDATALEN);
		UniStrncpy_to_le(t->name, kname, len);

		n++;
		xsi = fsi;
		klen -= len;
	}

	/* close current linelock */
	lv->length = n;
	dtlck->index++;

	*dtlock = dtlck;

	/* terminate last/only segment */
	if (h == t) {
		/* single segment entry */
		if (p->header.flag & BT_LEAF)
			lh->next = -1;
		else
			ih->next = -1;
	} else
		/* multi-segment entry */
		t->next = -1;

	/* if insert into middle, shift right succeeding entries in stbl */
	stbl = DT_GETSTBL(p);
	nextindex = p->header.nextindex;
	if (index < nextindex) {
		memmove(stbl + index + 1, stbl + index, nextindex - index);

		if ((p->header.flag & BT_LEAF) && data->leaf.ip) {
			s64 lblock;

			/*
			 * Need to update slot number for entries that moved
			 * in the stbl
			 */
			mp = NULL;
			for (n = index + 1; n <= nextindex; n++) {
				lh = (struct ldtentry *) & (p->slot[stbl[n]]);
				modify_index(data->leaf.tid, data->leaf.ip,
					     le32_to_cpu(lh->index), bn, n,
					     &mp, &lblock);
			}
			if (mp)
				release_metapage(mp);
		}
	}

	stbl[index] = hsi;

	/* advance next available entry index of stbl */
	++p->header.nextindex;
}


/*
 *	dtMoveEntry()
 *
 * function: move entries from split/left page to new/right page
 *
 *	nextindex of dst page and freelist/freecnt of both pages
 *	are updated.
 */
static void dtMoveEntry(dtpage_t * sp, int si, dtpage_t * dp,
			struct dt_lock ** sdtlock, struct dt_lock ** ddtlock,
			int do_index)
{
	int ssi, next;		/* src slot index */
	int di;			/* dst entry index */
	int dsi;		/* dst slot index */
	s8 *sstbl, *dstbl;	/* sorted entry table */
	int snamlen, len;
	struct ldtentry *slh, *dlh = NULL;
	struct idtentry *sih, *dih = NULL;
	struct dtslot *h, *s, *d;
	struct dt_lock *sdtlck = *sdtlock, *ddtlck = *ddtlock;
	struct lv *slv, *dlv;
	int xssi, ns, nd;
	int sfsi;

	sstbl = (s8 *) & sp->slot[sp->header.stblindex];
	dstbl = (s8 *) & dp->slot[dp->header.stblindex];

	dsi = dp->header.freelist;	/* first (whole page) free slot */
	sfsi = sp->header.freelist;

	/* linelock destination entry slot */
	dlv = & ddtlck->lv[ddtlck->index];
	dlv->offset = dsi;

	/* linelock source entry slot */
	slv = & sdtlck->lv[sdtlck->index];
	slv->offset = sstbl[si];
	xssi = slv->offset - 1;

	/*
	 * move entries
	 */
	ns = nd = 0;
	for (di = 0; si < sp->header.nextindex; si++, di++) {
		ssi = sstbl[si];
		dstbl[di] = dsi;

		/* is next slot contiguous ? */
		if (ssi != xssi + 1) {
			/* close current linelock */
			slv->length = ns;
			sdtlck->index++;

			/* open new linelock */
			if (sdtlck->index < sdtlck->maxcnt)
				slv++;
			else {
				sdtlck = (struct dt_lock *) txLinelock(sdtlck);
				slv = & sdtlck->lv[0];
			}

			slv->offset = ssi;
			ns = 0;
		}

		/*
		 * move head/only segment of an entry
		 */
		/* get dst slot */
		h = d = &dp->slot[dsi];

		/* get src slot and move */
		s = &sp->slot[ssi];
		if (sp->header.flag & BT_LEAF) {
			/* get source entry */
			slh = (struct ldtentry *) s;
			dlh = (struct ldtentry *) h;
			snamlen = slh->namlen;

			if (do_index) {
				len = min(snamlen, DTLHDRDATALEN);
				dlh->index = slh->index; /* little-endian */
			} else
				len = min(snamlen, DTLHDRDATALEN_LEGACY);

			memcpy(dlh, slh, 6 + len * 2);

			next = slh->next;

			/* update dst head/only segment next field */
			dsi++;
			dlh->next = dsi;
		} else {
			sih = (struct idtentry *) s;
			snamlen = sih->namlen;

			len = min(snamlen, DTIHDRDATALEN);
			dih = (struct idtentry *) h;
			memcpy(dih, sih, 10 + len * 2);
			next = sih->next;

			dsi++;
			dih->next = dsi;
		}

		/* free src head/only segment */
		s->next = sfsi;
		s->cnt = 1;
		sfsi = ssi;

		ns++;
		nd++;
		xssi = ssi;

		/*
		 * move additional segment(s) of the entry
		 */
		snamlen -= len;
		while ((ssi = next) >= 0) {
			/* is next slot contiguous ? */
			if (ssi != xssi + 1) {
				/* close current linelock */
				slv->length = ns;
				sdtlck->index++;

				/* open new linelock */
				if (sdtlck->index < sdtlck->maxcnt)
					slv++;
				else {
					sdtlck =
					    (struct dt_lock *)
					    txLinelock(sdtlck);
					slv = & sdtlck->lv[0];
				}

				slv->offset = ssi;
				ns = 0;
			}

			/* get next source segment */
			s = &sp->slot[ssi];

			/* get next destination free slot */
			d++;

			len = min(snamlen, DTSLOTDATALEN);
			UniStrncpy_le(d->name, s->name, len);

			ns++;
			nd++;
			xssi = ssi;

			dsi++;
			d->next = dsi;

			/* free source segment */
			next = s->next;
			s->next = sfsi;
			s->cnt = 1;
			sfsi = ssi;

			snamlen -= len;
		}		/* end while */

		/* terminate dst last/only segment */
		if (h == d) {
			/* single segment entry */
			if (dp->header.flag & BT_LEAF)
				dlh->next = -1;
			else
				dih->next = -1;
		} else
			/* multi-segment entry */
			d->next = -1;
	}			/* end for */

	/* close current linelock */
	slv->length = ns;
	sdtlck->index++;
	*sdtlock = sdtlck;

	dlv->length = nd;
	ddtlck->index++;
	*ddtlock = ddtlck;

	/* update source header */
	sp->header.freelist = sfsi;
	sp->header.freecnt += nd;

	/* update destination header */
	dp->header.nextindex = di;

	dp->header.freelist = dsi;
	dp->header.freecnt -= nd;
}


/*
 *	dtDeleteEntry()
 *
 * function: free a (leaf/internal) entry
 *
 * log freelist header, stbl, and each segment slot of entry
 * (even though last/only segment next field is modified,
 * physical image logging requires all segment slots of
 * the entry logged to avoid applying previous updates
 * to the same slots)
 */
static void dtDeleteEntry(dtpage_t * p, int fi, struct dt_lock ** dtlock)
{
	int fsi;		/* free entry slot index */
	s8 *stbl;
	struct dtslot *t;
	int si, freecnt;
	struct dt_lock *dtlck = *dtlock;
	struct lv *lv;
	int xsi, n;

	/* get free entry slot index */
	stbl = DT_GETSTBL(p);
	fsi = stbl[fi];

	/* open new linelock */
	if (dtlck->index >= dtlck->maxcnt)
		dtlck = (struct dt_lock *) txLinelock(dtlck);
	lv = & dtlck->lv[dtlck->index];

	lv->offset = fsi;

	/* get the head/only segment */
	t = &p->slot[fsi];
	if (p->header.flag & BT_LEAF)
		si = ((struct ldtentry *) t)->next;
	else
		si = ((struct idtentry *) t)->next;
	t->next = si;
	t->cnt = 1;

	n = freecnt = 1;
	xsi = fsi;

	/* find the last/only segment */
	while (si >= 0) {
		/* is next slot contiguous ? */
		if (si != xsi + 1) {
			/* close current linelock */
			lv->length = n;
			dtlck->index++;

			/* open new linelock */
			if (dtlck->index < dtlck->maxcnt)
				lv++;
			else {
				dtlck = (struct dt_lock *) txLinelock(dtlck);
				lv = & dtlck->lv[0];
			}

			lv->offset = si;
			n = 0;
		}

		n++;
		xsi = si;
		freecnt++;

		t = &p->slot[si];
		t->cnt = 1;
		si = t->next;
	}

	/* close current linelock */
	lv->length = n;
	dtlck->index++;

	*dtlock = dtlck;

	/* update freelist */
	t->next = p->header.freelist;
	p->header.freelist = fsi;
	p->header.freecnt += freecnt;

	/* if delete from middle,
	 * shift left the succedding entries in the stbl
	 */
	si = p->header.nextindex;
	if (fi < si - 1)
		memmove(&stbl[fi], &stbl[fi + 1], si - fi - 1);

	p->header.nextindex--;
}


/*
 *	dtTruncateEntry()
 *
 * function: truncate a (leaf/internal) entry
 *
 * log freelist header, stbl, and each segment slot of entry
 * (even though last/only segment next field is modified,
 * physical image logging requires all segment slots of
 * the entry logged to avoid applying previous updates
 * to the same slots)
 */
static void dtTruncateEntry(dtpage_t * p, int ti, struct dt_lock ** dtlock)
{
	int tsi;		/* truncate entry slot index */
	s8 *stbl;
	struct dtslot *t;
	int si, freecnt;
	struct dt_lock *dtlck = *dtlock;
	struct lv *lv;
	int fsi, xsi, n;

	/* get free entry slot index */
	stbl = DT_GETSTBL(p);
	tsi = stbl[ti];

	/* open new linelock */
	if (dtlck->index >= dtlck->maxcnt)
		dtlck = (struct dt_lock *) txLinelock(dtlck);
	lv = & dtlck->lv[dtlck->index];

	lv->offset = tsi;

	/* get the head/only segment */
	t = &p->slot[tsi];
	ASSERT(p->header.flag & BT_INTERNAL);
	((struct idtentry *) t)->namlen = 0;
	si = ((struct idtentry *) t)->next;
	((struct idtentry *) t)->next = -1;

	n = 1;
	freecnt = 0;
	fsi = si;
	xsi = tsi;

	/* find the last/only segment */
	while (si >= 0) {
		/* is next slot contiguous ? */
		if (si != xsi + 1) {
			/* close current linelock */
			lv->length = n;
			dtlck->index++;

			/* open new linelock */
			if (dtlck->index < dtlck->maxcnt)
				lv++;
			else {
				dtlck = (struct dt_lock *) txLinelock(dtlck);
				lv = & dtlck->lv[0];
			}

			lv->offset = si;
			n = 0;
		}

		n++;
		xsi = si;
		freecnt++;

		t = &p->slot[si];
		t->cnt = 1;
		si = t->next;
	}

	/* close current linelock */
	lv->length = n;
	dtlck->index++;

	*dtlock = dtlck;

	/* update freelist */
	if (freecnt == 0)
		return;
	t->next = p->header.freelist;
	p->header.freelist = fsi;
	p->header.freecnt += freecnt;
}


/*
 *	dtLinelockFreelist()
 */
static void dtLinelockFreelist(dtpage_t * p,	/* directory page */
			       int m,	/* max slot index */
			       struct dt_lock ** dtlock)
{
	int fsi;		/* free entry slot index */
	struct dtslot *t;
	int si;
	struct dt_lock *dtlck = *dtlock;
	struct lv *lv;
	int xsi, n;

	/* get free entry slot index */
	fsi = p->header.freelist;

	/* open new linelock */
	if (dtlck->index >= dtlck->maxcnt)
		dtlck = (struct dt_lock *) txLinelock(dtlck);
	lv = & dtlck->lv[dtlck->index];

	lv->offset = fsi;

	n = 1;
	xsi = fsi;

	t = &p->slot[fsi];
	si = t->next;

	/* find the last/only segment */
	while (si < m && si >= 0) {
		/* is next slot contiguous ? */
		if (si != xsi + 1) {
			/* close current linelock */
			lv->length = n;
			dtlck->index++;

			/* open new linelock */
			if (dtlck->index < dtlck->maxcnt)
				lv++;
			else {
				dtlck = (struct dt_lock *) txLinelock(dtlck);
				lv = & dtlck->lv[0];
			}

			lv->offset = si;
			n = 0;
		}

		n++;
		xsi = si;

		t = &p->slot[si];
		si = t->next;
	}

	/* close current linelock */
	lv->length = n;
	dtlck->index++;

	*dtlock = dtlck;
}


/*
 * NAME: dtModify
 *
 * FUNCTION: Modify the inode number part of a directory entry
 *
 * PARAMETERS:
 *	tid	- Transaction id
 *	ip	- Inode of parent directory
 *	key	- Name of entry to be modified
 *	orig_ino	- Original inode number expected in entry
 *	new_ino	- New inode number to put into entry
 *	flag	- JFS_RENAME
 *
 * RETURNS:
 *	-ESTALE	- If entry found does not match orig_ino passed in
 *	-ENOENT	- If no entry can be found to match key
 *	0	- If successfully modified entry
 */
int dtModify(tid_t tid, struct inode *ip,
	 struct component_name * key, ino_t * orig_ino, ino_t new_ino, int flag)
{
	int rc;
	s64 bn;
	struct metapage *mp;
	dtpage_t *p;
	int index;
	struct btstack btstack;
	struct tlock *tlck;
	struct dt_lock *dtlck;
	struct lv *lv;
	s8 *stbl;
	int entry_si;		/* entry slot index */
	struct ldtentry *entry;

	/*
	 *	search for the entry to modify:
	 *
	 * dtSearch() returns (leaf page pinned, index at which to modify).
	 */
	if ((rc = dtSearch(ip, key, orig_ino, &btstack, flag)))
		return rc;

	/* retrieve search result */
	DT_GETSEARCH(ip, btstack.top, bn, mp, p, index);

	BT_MARK_DIRTY(mp, ip);
	/*
	 * acquire a transaction lock on the leaf page of named entry
	 */
	tlck = txLock(tid, ip, mp, tlckDTREE | tlckENTRY);
	dtlck = (struct dt_lock *) & tlck->lock;

	/* get slot index of the entry */
	stbl = DT_GETSTBL(p);
	entry_si = stbl[index];

	/* linelock entry */
	ASSERT(dtlck->index == 0);
	lv = & dtlck->lv[0];
	lv->offset = entry_si;
	lv->length = 1;
	dtlck->index++;

	/* get the head/only segment */
	entry = (struct ldtentry *) & p->slot[entry_si];

	/* substitute the inode number of the entry */
	entry->inumber = cpu_to_le32(new_ino);

	/* unpin the leaf page */
	DT_PUTPAGE(mp);

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_dtree.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
// #include <linux/quotaops.h>
// #include "jfs_incore.h"
// #include "jfs_inode.h"
// #include "jfs_filsys.h"
// #include "jfs_imap.h"
// #include "jfs_dinode.h"
// #include "jfs_debug.h"


void jfs_set_inode_flags(struct inode *inode)
{
	unsigned int flags = JFS_IP(inode)->mode2;
	unsigned int new_fl = 0;

	if (flags & JFS_IMMUTABLE_FL)
		new_fl |= S_IMMUTABLE;
	if (flags & JFS_APPEND_FL)
		new_fl |= S_APPEND;
	if (flags & JFS_NOATIME_FL)
		new_fl |= S_NOATIME;
	if (flags & JFS_DIRSYNC_FL)
		new_fl |= S_DIRSYNC;
	if (flags & JFS_SYNC_FL)
		new_fl |= S_SYNC;
	inode_set_flags(inode, new_fl, S_IMMUTABLE | S_APPEND | S_NOATIME |
			S_DIRSYNC | S_SYNC);
}

void jfs_get_inode_flags(struct jfs_inode_info *jfs_ip)
{
	unsigned int flags = jfs_ip->vfs_inode.i_flags;

	jfs_ip->mode2 &= ~(JFS_IMMUTABLE_FL | JFS_APPEND_FL | JFS_NOATIME_FL |
			   JFS_DIRSYNC_FL | JFS_SYNC_FL);
	if (flags & S_IMMUTABLE)
		jfs_ip->mode2 |= JFS_IMMUTABLE_FL;
	if (flags & S_APPEND)
		jfs_ip->mode2 |= JFS_APPEND_FL;
	if (flags & S_NOATIME)
		jfs_ip->mode2 |= JFS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		jfs_ip->mode2 |= JFS_DIRSYNC_FL;
	if (flags & S_SYNC)
		jfs_ip->mode2 |= JFS_SYNC_FL;
}

/*
 * NAME:	ialloc()
 *
 * FUNCTION:	Allocate a new inode
 *
 */
struct inode *ialloc(struct inode *parent, umode_t mode)
{
	struct super_block *sb = parent->i_sb;
	struct inode *inode;
	struct jfs_inode_info *jfs_inode;
	int rc;

	inode = new_inode(sb);
	if (!inode) {
		jfs_warn("ialloc: new_inode returned NULL!");
		rc = -ENOMEM;
		goto fail;
	}

	jfs_inode = JFS_IP(inode);

	rc = diAlloc(parent, S_ISDIR(mode), inode);
	if (rc) {
		jfs_warn("ialloc: diAlloc returned %d!", rc);
		if (rc == -EIO)
			make_bad_inode(inode);
		goto fail_put;
	}

	if (insert_inode_locked(inode) < 0) {
		rc = -EINVAL;
		goto fail_put;
	}

	inode_init_owner(inode, parent, mode);
	/*
	 * New inodes need to save sane values on disk when
	 * uid & gid mount options are used
	 */
	jfs_inode->saved_uid = inode->i_uid;
	jfs_inode->saved_gid = inode->i_gid;

	/*
	 * Allocate inode to quota.
	 */
	dquot_initialize(inode);
	rc = dquot_alloc_inode(inode);
	if (rc)
		goto fail_drop;

	/* inherit flags from parent */
	jfs_inode->mode2 = JFS_IP(parent)->mode2 & JFS_FL_INHERIT;

	if (S_ISDIR(mode)) {
		jfs_inode->mode2 |= IDIRECTORY;
		jfs_inode->mode2 &= ~JFS_DIRSYNC_FL;
	}
	else {
		jfs_inode->mode2 |= INLINEEA | ISPARSE;
		if (S_ISLNK(mode))
			jfs_inode->mode2 &= ~(JFS_IMMUTABLE_FL|JFS_APPEND_FL);
	}
	jfs_inode->mode2 |= inode->i_mode;

	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;
	jfs_inode->otime = inode->i_ctime.tv_sec;
	inode->i_generation = JFS_SBI(sb)->gengen++;

	jfs_inode->cflag = 0;

	/* Zero remaining fields */
	memset(&jfs_inode->acl, 0, sizeof(dxd_t));
	memset(&jfs_inode->ea, 0, sizeof(dxd_t));
	jfs_inode->next_index = 0;
	jfs_inode->acltype = 0;
	jfs_inode->btorder = 0;
	jfs_inode->btindex = 0;
	jfs_inode->bxflag = 0;
	jfs_inode->blid = 0;
	jfs_inode->atlhead = 0;
	jfs_inode->atltail = 0;
	jfs_inode->xtlid = 0;
	jfs_set_inode_flags(inode);

	jfs_info("ialloc returns inode = 0x%p\n", inode);

	return inode;

fail_drop:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	clear_nlink(inode);
	unlock_new_inode(inode);
fail_put:
	iput(inode);
fail:
	return ERR_PTR(rc);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_inode.c */
/************************************************************/
/*
 *   Copyright (C) Tino Reichardt, 2012
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
// #include <linux/slab.h>
// #include <linux/blkdev.h>

// #include "jfs_incore.h"
// #include "jfs_superblock.h"
// #include "jfs_discard.h"
// #include "jfs_dmap.h"
// #include "jfs_debug.h"


/*
 * NAME:	jfs_issue_discard()
 *
 * FUNCTION:	TRIM the specified block range on device, if supported
 *
 * PARAMETERS:
 *	ip	- pointer to in-core inode
 *	blkno	- starting block number to be trimmed (0..N)
 *	nblocks	- number of blocks to be trimmed
 *
 * RETURN VALUES:
 *	none
 *
 * serialization: IREAD_LOCK(ipbmap) held on entry/exit;
 */
void jfs_issue_discard(struct inode *ip, u64 blkno, u64 nblocks)
{
	struct super_block *sb = ip->i_sb;
	int r = 0;

	r = sb_issue_discard(sb, blkno, nblocks, GFP_NOFS, 0);
	if (unlikely(r != 0)) {
		jfs_err("JFS: sb_issue_discard" \
			"(%p, %llu, %llu, GFP_NOFS, 0) = %d => failed!\n",
			sb, (unsigned long long)blkno,
			(unsigned long long)nblocks, r);
	}

	jfs_info("JFS: sb_issue_discard" \
		"(%p, %llu, %llu, GFP_NOFS, 0) = %d\n",
		sb, (unsigned long long)blkno,
		(unsigned long long)nblocks, r);

	return;
}

/*
 * NAME:	jfs_ioc_trim()
 *
 * FUNCTION:	attempt to discard (TRIM) all free blocks from the
 *              filesystem.
 *
 * PARAMETERS:
 *	ip	- pointer to in-core inode;
 *	range	- the range, given by user space
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error
 */
int jfs_ioc_trim(struct inode *ip, struct fstrim_range *range)
{
	struct inode *ipbmap = JFS_SBI(ip->i_sb)->ipbmap;
	struct bmap *bmp = JFS_SBI(ip->i_sb)->bmap;
	struct super_block *sb = ipbmap->i_sb;
	int agno, agno_end;
	u64 start, end, minlen;
	u64 trimmed = 0;

	/**
	 * convert byte values to block size of filesystem:
	 * start:	First Byte to trim
	 * len:		number of Bytes to trim from start
	 * minlen:	minimum extent length in Bytes
	 */
	start = range->start >> sb->s_blocksize_bits;
	end = start + (range->len >> sb->s_blocksize_bits) - 1;
	minlen = range->minlen >> sb->s_blocksize_bits;
	if (minlen == 0)
		minlen = 1;

	if (minlen > bmp->db_agsize ||
	    start >= bmp->db_mapsize ||
	    range->len < sb->s_blocksize)
		return -EINVAL;

	if (end >= bmp->db_mapsize)
		end = bmp->db_mapsize - 1;

	/**
	 * we trim all ag's within the range
	 */
	agno = BLKTOAG(start, JFS_SBI(ip->i_sb));
	agno_end = BLKTOAG(end, JFS_SBI(ip->i_sb));
	while (agno <= agno_end) {
		trimmed += dbDiscardAG(ip, agno, minlen);
		agno++;
	}
	range->len = trimmed << sb->s_blocksize_bits;

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_discard.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
// #include <linux/quotaops.h>
// #include "jfs_incore.h"
// #include "jfs_inode.h"
// #include "jfs_superblock.h"
// #include "jfs_dmap.h"
// #include "jfs_extent.h"
// #include "jfs_debug.h"

/*
 * forward references
 */
static int extBalloc(struct inode *, s64, s64 *, s64 *);
#ifdef _NOTYET
static int extBrealloc(struct inode *, s64, s64, s64 *, s64 *);
#endif
static s64 extRoundDown(s64 nb);

#define DPD(a)		(printk("(a): %d\n",(a)))
#define DPC(a)		(printk("(a): %c\n",(a)))
#define DPL1(a)					\
{						\
	if ((a) >> 32)				\
		printk("(a): %x%08x  ",(a));	\
	else					\
		printk("(a): %x  ",(a) << 32);	\
}
#define DPL(a)					\
{						\
	if ((a) >> 32)				\
		printk("(a): %x%08x\n",(a));	\
	else					\
		printk("(a): %x\n",(a) << 32);	\
}

#define DPD1(a)		(printk("(a): %d  ",(a)))
#define DPX(a)		(printk("(a): %08x\n",(a)))
#define DPX1(a)		(printk("(a): %08x  ",(a)))
#define DPS(a)		(printk("%s\n",(a)))
#define DPE(a)		(printk("\nENTERING: %s\n",(a)))
#define DPE1(a)		(printk("\nENTERING: %s",(a)))
#define DPS1(a)		(printk("  %s  ",(a)))


/*
 * NAME:	extAlloc()
 *
 * FUNCTION:	allocate an extent for a specified page range within a
 *		file.
 *
 * PARAMETERS:
 *	ip	- the inode of the file.
 *	xlen	- requested extent length.
 *	pno	- the starting page number with the file.
 *	xp	- pointer to an xad.  on entry, xad describes an
 *		  extent that is used as an allocation hint if the
 *		  xaddr of the xad is non-zero.  on successful exit,
 *		  the xad describes the newly allocated extent.
 *	abnr	- bool indicating whether the newly allocated extent
 *		  should be marked as allocated but not recorded.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 *	-ENOSPC	- insufficient disk resources.
 */
int
extAlloc(struct inode *ip, s64 xlen, s64 pno, xad_t * xp, bool abnr)
{
	struct jfs_sb_info *sbi = JFS_SBI(ip->i_sb);
	s64 nxlen, nxaddr, xoff, hint, xaddr = 0;
	int rc;
	int xflag;

	/* This blocks if we are low on resources */
	txBeginAnon(ip->i_sb);

	/* Avoid race with jfs_commit_inode() */
	mutex_lock(&JFS_IP(ip)->commit_mutex);

	/* validate extent length */
	if (xlen > MAXXLEN)
		xlen = MAXXLEN;

	/* get the page's starting extent offset */
	xoff = pno << sbi->l2nbperpage;

	/* check if an allocation hint was provided */
	if ((hint = addressXAD(xp))) {
		/* get the size of the extent described by the hint */
		nxlen = lengthXAD(xp);

		/* check if the hint is for the portion of the file
		 * immediately previous to the current allocation
		 * request and if hint extent has the same abnr
		 * value as the current request.  if so, we can
		 * extend the hint extent to include the current
		 * extent if we can allocate the blocks immediately
		 * following the hint extent.
		 */
		if (offsetXAD(xp) + nxlen == xoff &&
		    abnr == ((xp->flag & XAD_NOTRECORDED) ? true : false))
			xaddr = hint + nxlen;

		/* adjust the hint to the last block of the extent */
		hint += (nxlen - 1);
	}

	/* allocate the disk blocks for the extent.  initially, extBalloc()
	 * will try to allocate disk blocks for the requested size (xlen).
	 * if this fails (xlen contiguous free blocks not available), it'll
	 * try to allocate a smaller number of blocks (producing a smaller
	 * extent), with this smaller number of blocks consisting of the
	 * requested number of blocks rounded down to the next smaller
	 * power of 2 number (i.e. 16 -> 8).  it'll continue to round down
	 * and retry the allocation until the number of blocks to allocate
	 * is smaller than the number of blocks per page.
	 */
	nxlen = xlen;
	if ((rc = extBalloc(ip, hint ? hint : INOHINT(ip), &nxlen, &nxaddr))) {
		mutex_unlock(&JFS_IP(ip)->commit_mutex);
		return (rc);
	}

	/* Allocate blocks to quota. */
	rc = dquot_alloc_block(ip, nxlen);
	if (rc) {
		dbFree(ip, nxaddr, (s64) nxlen);
		mutex_unlock(&JFS_IP(ip)->commit_mutex);
		return rc;
	}

	/* determine the value of the extent flag */
	xflag = abnr ? XAD_NOTRECORDED : 0;

	/* if we can extend the hint extent to cover the current request,
	 * extend it.  otherwise, insert a new extent to
	 * cover the current request.
	 */
	if (xaddr && xaddr == nxaddr)
		rc = xtExtend(0, ip, xoff, (int) nxlen, 0);
	else
		rc = xtInsert(0, ip, xflag, xoff, (int) nxlen, &nxaddr, 0);

	/* if the extend or insert failed,
	 * free the newly allocated blocks and return the error.
	 */
	if (rc) {
		dbFree(ip, nxaddr, nxlen);
		dquot_free_block(ip, nxlen);
		mutex_unlock(&JFS_IP(ip)->commit_mutex);
		return (rc);
	}

	/* set the results of the extent allocation */
	XADaddress(xp, nxaddr);
	XADlength(xp, nxlen);
	XADoffset(xp, xoff);
	xp->flag = xflag;

	mark_inode_dirty(ip);

	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	/*
	 * COMMIT_SyncList flags an anonymous tlock on page that is on
	 * sync list.
	 * We need to commit the inode to get the page written disk.
	 */
	if (test_and_clear_cflag(COMMIT_Synclist,ip))
		jfs_commit_inode(ip, 0);

	return (0);
}


#ifdef _NOTYET
/*
 * NAME:	extRealloc()
 *
 * FUNCTION:	extend the allocation of a file extent containing a
 *		partial back last page.
 *
 * PARAMETERS:
 *	ip	- the inode of the file.
 *	cp	- cbuf for the partial backed last page.
 *	xlen	- request size of the resulting extent.
 *	xp	- pointer to an xad. on successful exit, the xad
 *		  describes the newly allocated extent.
 *	abnr	- bool indicating whether the newly allocated extent
 *		  should be marked as allocated but not recorded.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 *	-ENOSPC	- insufficient disk resources.
 */
int extRealloc(struct inode *ip, s64 nxlen, xad_t * xp, bool abnr)
{
	struct super_block *sb = ip->i_sb;
	s64 xaddr, xlen, nxaddr, delta, xoff;
	s64 ntail, nextend, ninsert;
	int rc, nbperpage = JFS_SBI(sb)->nbperpage;
	int xflag;

	/* This blocks if we are low on resources */
	txBeginAnon(ip->i_sb);

	mutex_lock(&JFS_IP(ip)->commit_mutex);
	/* validate extent length */
	if (nxlen > MAXXLEN)
		nxlen = MAXXLEN;

	/* get the extend (partial) page's disk block address and
	 * number of blocks.
	 */
	xaddr = addressXAD(xp);
	xlen = lengthXAD(xp);
	xoff = offsetXAD(xp);

	/* if the extend page is abnr and if the request is for
	 * the extent to be allocated and recorded,
	 * make the page allocated and recorded.
	 */
	if ((xp->flag & XAD_NOTRECORDED) && !abnr) {
		xp->flag = 0;
		if ((rc = xtUpdate(0, ip, xp)))
			goto exit;
	}

	/* try to allocated the request number of blocks for the
	 * extent.  dbRealloc() first tries to satisfy the request
	 * by extending the allocation in place. otherwise, it will
	 * try to allocate a new set of blocks large enough for the
	 * request.  in satisfying a request, dbReAlloc() may allocate
	 * less than what was request but will always allocate enough
	 * space as to satisfy the extend page.
	 */
	if ((rc = extBrealloc(ip, xaddr, xlen, &nxlen, &nxaddr)))
		goto exit;

	/* Allocat blocks to quota. */
	rc = dquot_alloc_block(ip, nxlen);
	if (rc) {
		dbFree(ip, nxaddr, (s64) nxlen);
		mutex_unlock(&JFS_IP(ip)->commit_mutex);
		return rc;
	}

	delta = nxlen - xlen;

	/* check if the extend page is not abnr but the request is abnr
	 * and the allocated disk space is for more than one page.  if this
	 * is the case, there is a miss match of abnr between the extend page
	 * and the one or more pages following the extend page.  as a result,
	 * two extents will have to be manipulated. the first will be that
	 * of the extent of the extend page and will be manipulated thru
	 * an xtExtend() or an xtTailgate(), depending upon whether the
	 * disk allocation occurred as an inplace extension.  the second
	 * extent will be manipulated (created) through an xtInsert() and
	 * will be for the pages following the extend page.
	 */
	if (abnr && (!(xp->flag & XAD_NOTRECORDED)) && (nxlen > nbperpage)) {
		ntail = nbperpage;
		nextend = ntail - xlen;
		ninsert = nxlen - nbperpage;

		xflag = XAD_NOTRECORDED;
	} else {
		ntail = nxlen;
		nextend = delta;
		ninsert = 0;

		xflag = xp->flag;
	}

	/* if we were able to extend the disk allocation in place,
	 * extend the extent.  otherwise, move the extent to a
	 * new disk location.
	 */
	if (xaddr == nxaddr) {
		/* extend the extent */
		if ((rc = xtExtend(0, ip, xoff + xlen, (int) nextend, 0))) {
			dbFree(ip, xaddr + xlen, delta);
			dquot_free_block(ip, nxlen);
			goto exit;
		}
	} else {
		/*
		 * move the extent to a new location:
		 *
		 * xtTailgate() accounts for relocated tail extent;
		 */
		if ((rc = xtTailgate(0, ip, xoff, (int) ntail, nxaddr, 0))) {
			dbFree(ip, nxaddr, nxlen);
			dquot_free_block(ip, nxlen);
			goto exit;
		}
	}


	/* check if we need to also insert a new extent */
	if (ninsert) {
		/* perform the insert.  if it fails, free the blocks
		 * to be inserted and make it appear that we only did
		 * the xtExtend() or xtTailgate() above.
		 */
		xaddr = nxaddr + ntail;
		if (xtInsert (0, ip, xflag, xoff + ntail, (int) ninsert,
			      &xaddr, 0)) {
			dbFree(ip, xaddr, (s64) ninsert);
			delta = nextend;
			nxlen = ntail;
			xflag = 0;
		}
	}

	/* set the return results */
	XADaddress(xp, nxaddr);
	XADlength(xp, nxlen);
	XADoffset(xp, xoff);
	xp->flag = xflag;

	mark_inode_dirty(ip);
exit:
	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	return (rc);
}
#endif			/* _NOTYET */


/*
 * NAME:	extHint()
 *
 * FUNCTION:	produce an extent allocation hint for a file offset.
 *
 * PARAMETERS:
 *	ip	- the inode of the file.
 *	offset  - file offset for which the hint is needed.
 *	xp	- pointer to the xad that is to be filled in with
 *		  the hint.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 */
int extHint(struct inode *ip, s64 offset, xad_t * xp)
{
	struct super_block *sb = ip->i_sb;
	int nbperpage = JFS_SBI(sb)->nbperpage;
	s64 prev;
	int rc = 0;
	s64 xaddr;
	int xlen;
	int xflag;

	/* init the hint as "no hint provided" */
	XADaddress(xp, 0);

	/* determine the starting extent offset of the page previous
	 * to the page containing the offset.
	 */
	prev = ((offset & ~POFFSET) >> JFS_SBI(sb)->l2bsize) - nbperpage;

	/* if the offset is in the first page of the file, no hint provided.
	 */
	if (prev < 0)
		goto out;

	rc = xtLookup(ip, prev, nbperpage, &xflag, &xaddr, &xlen, 0);

	if ((rc == 0) && xlen) {
		if (xlen != nbperpage) {
			jfs_error(ip->i_sb, "corrupt xtree\n");
			rc = -EIO;
		}
		XADaddress(xp, xaddr);
		XADlength(xp, xlen);
		XADoffset(xp, prev);
		/*
		 * only preserve the abnr flag within the xad flags
		 * of the returned hint.
		 */
		xp->flag  = xflag & XAD_NOTRECORDED;
	} else
		rc = 0;

out:
	return (rc);
}


/*
 * NAME:	extRecord()
 *
 * FUNCTION:	change a page with a file from not recorded to recorded.
 *
 * PARAMETERS:
 *	ip	- inode of the file.
 *	cp	- cbuf of the file page.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 *	-ENOSPC	- insufficient disk resources.
 */
int extRecord(struct inode *ip, xad_t * xp)
{
	int rc;

	txBeginAnon(ip->i_sb);

	mutex_lock(&JFS_IP(ip)->commit_mutex);

	/* update the extent */
	rc = xtUpdate(0, ip, xp);

	mutex_unlock(&JFS_IP(ip)->commit_mutex);
	return rc;
}


#ifdef _NOTYET
/*
 * NAME:	extFill()
 *
 * FUNCTION:	allocate disk space for a file page that represents
 *		a file hole.
 *
 * PARAMETERS:
 *	ip	- the inode of the file.
 *	cp	- cbuf of the file page represent the hole.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 *	-ENOSPC	- insufficient disk resources.
 */
int extFill(struct inode *ip, xad_t * xp)
{
	int rc, nbperpage = JFS_SBI(ip->i_sb)->nbperpage;
	s64 blkno = offsetXAD(xp) >> ip->i_blkbits;

//	assert(ISSPARSE(ip));

	/* initialize the extent allocation hint */
	XADaddress(xp, 0);

	/* allocate an extent to fill the hole */
	if ((rc = extAlloc(ip, nbperpage, blkno, xp, false)))
		return (rc);

	assert(lengthPXD(xp) == nbperpage);

	return (0);
}
#endif			/* _NOTYET */


/*
 * NAME:	extBalloc()
 *
 * FUNCTION:	allocate disk blocks to form an extent.
 *
 *		initially, we will try to allocate disk blocks for the
 *		requested size (nblocks).  if this fails (nblocks
 *		contiguous free blocks not available), we'll try to allocate
 *		a smaller number of blocks (producing a smaller extent), with
 *		this smaller number of blocks consisting of the requested
 *		number of blocks rounded down to the next smaller power of 2
 *		number (i.e. 16 -> 8).  we'll continue to round down and
 *		retry the allocation until the number of blocks to allocate
 *		is smaller than the number of blocks per page.
 *
 * PARAMETERS:
 *	ip	 - the inode of the file.
 *	hint	 - disk block number to be used as an allocation hint.
 *	*nblocks - pointer to an s64 value.  on entry, this value specifies
 *		   the desired number of block to be allocated. on successful
 *		   exit, this value is set to the number of blocks actually
 *		   allocated.
 *	blkno	 - pointer to a block address that is filled in on successful
 *		   return with the starting block number of the newly
 *		   allocated block range.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 *	-ENOSPC	- insufficient disk resources.
 */
static int
extBalloc(struct inode *ip, s64 hint, s64 * nblocks, s64 * blkno)
{
	struct jfs_inode_info *ji = JFS_IP(ip);
	struct jfs_sb_info *sbi = JFS_SBI(ip->i_sb);
	s64 nb, nblks, daddr, max;
	int rc, nbperpage = sbi->nbperpage;
	struct bmap *bmp = sbi->bmap;
	int ag;

	/* get the number of blocks to initially attempt to allocate.
	 * we'll first try the number of blocks requested unless this
	 * number is greater than the maximum number of contiguous free
	 * blocks in the map. in that case, we'll start off with the
	 * maximum free.
	 */
	max = (s64) 1 << bmp->db_maxfreebud;
	if (*nblocks >= max && *nblocks > nbperpage)
		nb = nblks = (max > nbperpage) ? max : nbperpage;
	else
		nb = nblks = *nblocks;

	/* try to allocate blocks */
	while ((rc = dbAlloc(ip, hint, nb, &daddr)) != 0) {
		/* if something other than an out of space error,
		 * stop and return this error.
		 */
		if (rc != -ENOSPC)
			return (rc);

		/* decrease the allocation request size */
		nb = min(nblks, extRoundDown(nb));

		/* give up if we cannot cover a page */
		if (nb < nbperpage)
			return (rc);
	}

	*nblocks = nb;
	*blkno = daddr;

	if (S_ISREG(ip->i_mode) && (ji->fileset == FILESYSTEM_I)) {
		ag = BLKTOAG(daddr, sbi);
		spin_lock_irq(&ji->ag_lock);
		if (ji->active_ag == -1) {
			atomic_inc(&bmp->db_active[ag]);
			ji->active_ag = ag;
		} else if (ji->active_ag != ag) {
			atomic_dec(&bmp->db_active[ji->active_ag]);
			atomic_inc(&bmp->db_active[ag]);
			ji->active_ag = ag;
		}
		spin_unlock_irq(&ji->ag_lock);
	}

	return (0);
}


#ifdef _NOTYET
/*
 * NAME:	extBrealloc()
 *
 * FUNCTION:	attempt to extend an extent's allocation.
 *
 *		Initially, we will try to extend the extent's allocation
 *		in place.  If this fails, we'll try to move the extent
 *		to a new set of blocks.  If moving the extent, we initially
 *		will try to allocate disk blocks for the requested size
 *		(newnblks).  if this fails (new contiguous free blocks not
 *		available), we'll try to allocate a smaller number of
 *		blocks (producing a smaller extent), with this smaller
 *		number of blocks consisting of the requested number of
 *		blocks rounded down to the next smaller power of 2
 *		number (i.e. 16 -> 8).  We'll continue to round down and
 *		retry the allocation until the number of blocks to allocate
 *		is smaller than the number of blocks per page.
 *
 * PARAMETERS:
 *	ip	 - the inode of the file.
 *	blkno	 - starting block number of the extents current allocation.
 *	nblks	 - number of blocks within the extents current allocation.
 *	newnblks - pointer to a s64 value.  on entry, this value is the
 *		   the new desired extent size (number of blocks).  on
 *		   successful exit, this value is set to the extent's actual
 *		   new size (new number of blocks).
 *	newblkno - the starting block number of the extents new allocation.
 *
 * RETURN VALUES:
 *	0	- success
 *	-EIO	- i/o error.
 *	-ENOSPC	- insufficient disk resources.
 */
static int
extBrealloc(struct inode *ip,
	    s64 blkno, s64 nblks, s64 * newnblks, s64 * newblkno)
{
	int rc;

	/* try to extend in place */
	if ((rc = dbExtend(ip, blkno, nblks, *newnblks - nblks)) == 0) {
		*newblkno = blkno;
		return (0);
	} else {
		if (rc != -ENOSPC)
			return (rc);
	}

	/* in place extension not possible.
	 * try to move the extent to a new set of blocks.
	 */
	return (extBalloc(ip, blkno, newnblks, newblkno));
}
#endif			/* _NOTYET */


/*
 * NAME:	extRoundDown()
 *
 * FUNCTION:	round down a specified number of blocks to the next
 *		smallest power of 2 number.
 *
 * PARAMETERS:
 *	nb	- the inode of the file.
 *
 * RETURN VALUES:
 *	next smallest power of 2 number.
 */
static s64 extRoundDown(s64 nb)
{
	int i;
	u64 m, k;

	for (i = 0, m = (u64) 1 << 63; i < 64; i++, m >>= 1) {
		if (m & nb)
			break;
	}

	i = 63 - i;
	k = (u64) 1 << i;
	k = ((k - 1) & nb) ? k : k >> 1;

	return (k);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_extent.c */
/************************************************************/
/*
 *   Copyright (C) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
// #include <linux/namei.h>
// #include "jfs_incore.h"
// #include "jfs_inode.h"
// #include "jfs_xattr.h"

static void *jfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *s = JFS_IP(dentry->d_inode)->i_inline;
	nd_set_link(nd, s);
	return NULL;
}

const struct inode_operations jfs_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= jfs_follow_link,
	.setattr	= jfs_setattr,
	.setxattr	= jfs_setxattr,
	.getxattr	= jfs_getxattr,
	.listxattr	= jfs_listxattr,
	.removexattr	= jfs_removexattr,
};

const struct inode_operations jfs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.setattr	= jfs_setattr,
	.setxattr	= jfs_setxattr,
	.getxattr	= jfs_getxattr,
	.listxattr	= jfs_listxattr,
	.removexattr	= jfs_removexattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/symlink.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2005
 *   Portions Copyright (C) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
// #include <linux/mm.h>
// #include <linux/module.h>
#include <linux/bio.h>
// #include <linux/slab.h>
#include <linux/init.h>
// #include <linux/buffer_head.h>
#include <linux/mempool.h>
// #include <linux/seq_file.h>
// #include "jfs_incore.h"
// #include "jfs_superblock.h"
// #include "jfs_filsys.h"
// #include "jfs_metapage.h"
// #include "jfs_txnmgr.h"
// #include "jfs_debug.h"
#include "../../inc/__fss.h"

#ifdef CONFIG_JFS_STATISTICS
static struct {
	uint	pagealloc;	/* # of page allocations */
	uint	pagefree;	/* # of page frees */
	uint	lockwait;	/* # of sleeping lock_metapage() calls */
} mpStat;
#endif

#define metapage_locked(mp) test_bit(META_locked, &(mp)->flag)
#define trylock_metapage(mp) test_and_set_bit_lock(META_locked, &(mp)->flag)

static inline void unlock_metapage(struct metapage *mp)
{
	clear_bit_unlock(META_locked, &mp->flag);
	wake_up(&mp->wait);
}

static inline void __lock_metapage(struct metapage *mp)
{
	DECLARE_WAITQUEUE(wait, current);
	INCREMENT(mpStat.lockwait);
	add_wait_queue_exclusive(&mp->wait, &wait);
	do {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (metapage_locked(mp)) {
			unlock_page(mp->page);
			io_schedule();
			lock_page(mp->page);
		}
	} while (trylock_metapage(mp));
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&mp->wait, &wait);
}

/*
 * Must have mp->page locked
 */
static inline void lock_metapage(struct metapage *mp)
{
	if (trylock_metapage(mp))
		__lock_metapage(mp);
}

#define METAPOOL_MIN_PAGES 32
static struct kmem_cache *metapage_cache;
static mempool_t *metapage_mempool;

#define MPS_PER_PAGE (PAGE_CACHE_SIZE >> L2PSIZE)

#if MPS_PER_PAGE > 1

struct meta_anchor {
	int mp_count;
	atomic_t io_count;
	struct metapage *mp[MPS_PER_PAGE];
};
#define mp_anchor(page) ((struct meta_anchor *)page_private(page))

static inline struct metapage *page_to_mp(struct page *page, int offset)
{
	if (!PagePrivate(page))
		return NULL;
	return mp_anchor(page)->mp[offset >> L2PSIZE];
}

static inline int insert_metapage(struct page *page, struct metapage *mp)
{
	struct meta_anchor *a;
	int index;
	int l2mp_blocks;	/* log2 blocks per metapage */

	if (PagePrivate(page))
		a = mp_anchor(page);
	else {
		a = kzalloc(sizeof(struct meta_anchor), GFP_NOFS);
		if (!a)
			return -ENOMEM;
		set_page_private(page, (unsigned long)a);
		SetPagePrivate(page);
		kmap(page);
	}

	if (mp) {
		l2mp_blocks = L2PSIZE - page->mapping->host->i_blkbits;
		index = (mp->index >> l2mp_blocks) & (MPS_PER_PAGE - 1);
		a->mp_count++;
		a->mp[index] = mp;
	}

	return 0;
}

static inline void remove_metapage(struct page *page, struct metapage *mp)
{
	struct meta_anchor *a = mp_anchor(page);
	int l2mp_blocks = L2PSIZE - page->mapping->host->i_blkbits;
	int index;

	index = (mp->index >> l2mp_blocks) & (MPS_PER_PAGE - 1);

	BUG_ON(a->mp[index] != mp);

	a->mp[index] = NULL;
	if (--a->mp_count == 0) {
		kfree(a);
		set_page_private(page, 0);
		ClearPagePrivate(page);
		kunmap(page);
	}
}

static inline void inc_io(struct page *page)
{
	atomic_inc(&mp_anchor(page)->io_count);
}

static inline void dec_io(struct page *page, void (*handler) (struct page *))
{
	if (atomic_dec_and_test(&mp_anchor(page)->io_count))
		handler(page);
}

#else
static inline struct metapage *page_to_mp(struct page *page, int offset)
{
	return PagePrivate(page) ? (struct metapage *)page_private(page) : NULL;
}

static inline int insert_metapage(struct page *page, struct metapage *mp)
{
	if (mp) {
		set_page_private(page, (unsigned long)mp);
		SetPagePrivate(page);
		kmap(page);
	}
	return 0;
}

static inline void remove_metapage(struct page *page, struct metapage *mp)
{
	set_page_private(page, 0);
	ClearPagePrivate(page);
	kunmap(page);
}

#define inc_io(page) do {} while(0)
#define dec_io(page, handler) handler(page)

#endif

static void init_once(void *foo)
{
	struct metapage *mp = (struct metapage *)foo;

	mp->lid = 0;
	mp->lsn = 0;
	mp->flag = 0;
	mp->data = NULL;
	mp->clsn = 0;
	mp->log = NULL;
	set_bit(META_free, &mp->flag);
	init_waitqueue_head(&mp->wait);
}

static inline struct metapage *alloc_metapage(gfp_t gfp_mask)
{
	return mempool_alloc(metapage_mempool, gfp_mask);
}

static inline void free_metapage(struct metapage *mp)
{
	mp->flag = 0;
	set_bit(META_free, &mp->flag);

	mempool_free(mp, metapage_mempool);
}

int __init metapage_init(void)
{
	/*
	 * Allocate the metapage structures
	 */
	metapage_cache = kmem_cache_create("jfs_mp", sizeof(struct metapage),
					   0, 0, init_once);
	if (metapage_cache == NULL)
		return -ENOMEM;

	metapage_mempool = mempool_create_slab_pool(METAPOOL_MIN_PAGES,
						    metapage_cache);

	if (metapage_mempool == NULL) {
		kmem_cache_destroy(metapage_cache);
		return -ENOMEM;
	}

	return 0;
}

void metapage_exit(void)
{
	mempool_destroy(metapage_mempool);
	kmem_cache_destroy(metapage_cache);
}

static inline void drop_metapage(struct page *page, struct metapage *mp)
{
	if (mp->count || mp->nohomeok || test_bit(META_dirty, &mp->flag) ||
	    test_bit(META_io, &mp->flag))
		return;
	remove_metapage(page, mp);
	INCREMENT(mpStat.pagefree);
	free_metapage(mp);
}

/*
 * Metapage address space operations
 */

static sector_t metapage_get_blocks(struct inode *inode, sector_t lblock,
				    int *len)
{
	int rc = 0;
	int xflag;
	s64 xaddr;
	sector_t file_blocks = (inode->i_size + inode->i_sb->s_blocksize - 1) >>
			       inode->i_blkbits;

	if (lblock >= file_blocks)
		return 0;
	if (lblock + *len > file_blocks)
		*len = file_blocks - lblock;

	if (inode->i_ino) {
		rc = xtLookup(inode, (s64)lblock, *len, &xflag, &xaddr, len, 0);
		if ((rc == 0) && *len)
			lblock = (sector_t)xaddr;
		else
			lblock = 0;
	} /* else no mapping */

	return lblock;
}

static void last_read_complete(struct page *page)
{
	if (!PageError(page))
		SetPageUptodate(page);
	unlock_page(page);
}

static void metapage_read_end_io(struct bio *bio, int err)
{
	struct page *page = bio->bi_private;

	if (!test_bit(BIO_UPTODATE, &bio->bi_flags)) {
		printk(KERN_ERR "metapage_read_end_io: I/O error\n");
		SetPageError(page);
	}

	dec_io(page, last_read_complete);
	bio_put(bio);
}

static void remove_from_logsync(struct metapage *mp)
{
	struct jfs_log *log = mp->log;
	unsigned long flags;
/*
 * This can race.  Recheck that log hasn't been set to null, and after
 * acquiring logsync lock, recheck lsn
 */
	if (!log)
		return;

	LOGSYNC_LOCK(log, flags);
	if (mp->lsn) {
		mp->log = NULL;
		mp->lsn = 0;
		mp->clsn = 0;
		log->count--;
		list_del(&mp->synclist);
	}
	LOGSYNC_UNLOCK(log, flags);
}

static void last_write_complete(struct page *page)
{
	struct metapage *mp;
	unsigned int offset;

	for (offset = 0; offset < PAGE_CACHE_SIZE; offset += PSIZE) {
		mp = page_to_mp(page, offset);
		if (mp && test_bit(META_io, &mp->flag)) {
			if (mp->lsn)
				remove_from_logsync(mp);
			clear_bit(META_io, &mp->flag);
		}
		/*
		 * I'd like to call drop_metapage here, but I don't think it's
		 * safe unless I have the page locked
		 */
	}
	end_page_writeback(page);
}

static void metapage_write_end_io(struct bio *bio, int err)
{
	struct page *page = bio->bi_private;

	BUG_ON(!PagePrivate(page));

	if (! test_bit(BIO_UPTODATE, &bio->bi_flags)) {
		printk(KERN_ERR "metapage_write_end_io: I/O error\n");
		SetPageError(page);
	}
	dec_io(page, last_write_complete);
	bio_put(bio);
}

static int metapage_writepage(struct page *page, struct writeback_control *wbc)
{
	struct bio *bio = NULL;
	int block_offset;	/* block offset of mp within page */
	struct inode *inode = page->mapping->host;
	int blocks_per_mp = JFS_SBI(inode->i_sb)->nbperpage;
	int len;
	int xlen;
	struct metapage *mp;
	int redirty = 0;
	sector_t lblock;
	int nr_underway = 0;
	sector_t pblock;
	sector_t next_block = 0;
	sector_t page_start;
	unsigned long bio_bytes = 0;
	unsigned long bio_offset = 0;
	int offset;
	int bad_blocks = 0;

	page_start = (sector_t)page->index <<
		     (PAGE_CACHE_SHIFT - inode->i_blkbits);
	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));
	set_page_writeback(page);

	for (offset = 0; offset < PAGE_CACHE_SIZE; offset += PSIZE) {
		mp = page_to_mp(page, offset);

		if (!mp || !test_bit(META_dirty, &mp->flag))
			continue;

		if (mp->nohomeok && !test_bit(META_forcewrite, &mp->flag)) {
			redirty = 1;
			/*
			 * Make sure this page isn't blocked indefinitely.
			 * If the journal isn't undergoing I/O, push it
			 */
			if (mp->log && !(mp->log->cflag & logGC_PAGEOUT))
				jfs_flush_journal(mp->log, 0);
			continue;
		}

		clear_bit(META_dirty, &mp->flag);
		set_bit(META_io, &mp->flag);
		block_offset = offset >> inode->i_blkbits;
		lblock = page_start + block_offset;
		if (bio) {
			if (xlen && lblock == next_block) {
				/* Contiguous, in memory & on disk */
				len = min(xlen, blocks_per_mp);
				xlen -= len;
				bio_bytes += len << inode->i_blkbits;
				continue;
			}
			/* Not contiguous */
			if (bio_add_page(bio, page, bio_bytes, bio_offset) <
			    bio_bytes)
				goto add_failed;
			/*
			 * Increment counter before submitting i/o to keep
			 * count from hitting zero before we're through
			 */
			inc_io(page);
			if (!bio->bi_iter.bi_size)
				goto dump_bio;
			submit_bio(WRITE, bio);
			nr_underway++;
			bio = NULL;
		} else
			inc_io(page);
		xlen = (PAGE_CACHE_SIZE - offset) >> inode->i_blkbits;
		pblock = metapage_get_blocks(inode, lblock, &xlen);
		if (!pblock) {
			printk(KERN_ERR "JFS: metapage_get_blocks failed\n");
			/*
			 * We already called inc_io(), but can't cancel it
			 * with dec_io() until we're done with the page
			 */
			bad_blocks++;
			continue;
		}
		len = min(xlen, (int)JFS_SBI(inode->i_sb)->nbperpage);

		bio = bio_alloc(GFP_NOFS, 1);
		bio->bi_bdev = inode->i_sb->s_bdev;
		bio->bi_iter.bi_sector = pblock << (inode->i_blkbits - 9);
		bio->bi_end_io = metapage_write_end_io;
		bio->bi_private = page;

		/* Don't call bio_add_page yet, we may add to this vec */
		bio_offset = offset;
		bio_bytes = len << inode->i_blkbits;

		xlen -= len;
		next_block = lblock + len;
	}
	if (bio) {
		if (bio_add_page(bio, page, bio_bytes, bio_offset) < bio_bytes)
				goto add_failed;
		if (!bio->bi_iter.bi_size)
			goto dump_bio;

		submit_bio(WRITE, bio);
		nr_underway++;
	}
	if (redirty)
		redirty_page_for_writepage(wbc, page);

	unlock_page(page);

	if (bad_blocks)
		goto err_out;

	if (nr_underway == 0)
		end_page_writeback(page);

	return 0;
add_failed:
	/* We should never reach here, since we're only adding one vec */
	printk(KERN_ERR "JFS: bio_add_page failed unexpectedly\n");
	goto skip;
dump_bio:
	print_hex_dump(KERN_ERR, "JFS: dump of bio: ", DUMP_PREFIX_ADDRESS, 16,
		       4, bio, sizeof(*bio), 0);
skip:
	bio_put(bio);
	unlock_page(page);
	dec_io(page, last_write_complete);
err_out:
	while (bad_blocks--)
		dec_io(page, last_write_complete);
	return -EIO;
}

static int metapage_readpage(struct file *fp, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct bio *bio = NULL;
	int block_offset;
	int blocks_per_page = PAGE_CACHE_SIZE >> inode->i_blkbits;
	sector_t page_start;	/* address of page in fs blocks */
	sector_t pblock;
	int xlen;
	unsigned int len;
	int offset;

	BUG_ON(!PageLocked(page));
	page_start = (sector_t)page->index <<
		     (PAGE_CACHE_SHIFT - inode->i_blkbits);

	block_offset = 0;
	while (block_offset < blocks_per_page) {
		xlen = blocks_per_page - block_offset;
		pblock = metapage_get_blocks(inode, page_start + block_offset,
					     &xlen);
		if (pblock) {
			if (!PagePrivate(page))
				insert_metapage(page, NULL);
			inc_io(page);
			if (bio)
				submit_bio(READ, bio);

			bio = bio_alloc(GFP_NOFS, 1);
			bio->bi_bdev = inode->i_sb->s_bdev;
			bio->bi_iter.bi_sector =
				pblock << (inode->i_blkbits - 9);
			bio->bi_end_io = metapage_read_end_io;
			bio->bi_private = page;
			len = xlen << inode->i_blkbits;
			offset = block_offset << inode->i_blkbits;
			if (bio_add_page(bio, page, len, offset) < len)
				goto add_failed;
			block_offset += xlen;
		} else
			block_offset++;
	}
	if (bio)
		submit_bio(READ, bio);
	else
		unlock_page(page);

	return 0;

add_failed:
	printk(KERN_ERR "JFS: bio_add_page failed unexpectedly\n");
	bio_put(bio);
	dec_io(page, last_read_complete);
	return -EIO;
}

static int metapage_releasepage(struct page *page, gfp_t gfp_mask)
{
	struct metapage *mp;
	int ret = 1;
	int offset;

	for (offset = 0; offset < PAGE_CACHE_SIZE; offset += PSIZE) {
		mp = page_to_mp(page, offset);

		if (!mp)
			continue;

		jfs_info("metapage_releasepage: mp = 0x%p", mp);
		if (mp->count || mp->nohomeok ||
		    test_bit(META_dirty, &mp->flag)) {
			jfs_info("count = %ld, nohomeok = %d", mp->count,
				 mp->nohomeok);
			ret = 0;
			continue;
		}
		if (mp->lsn)
			remove_from_logsync(mp);
		remove_metapage(page, mp);
		INCREMENT(mpStat.pagefree);
		free_metapage(mp);
	}
	return ret;
}

static void metapage_invalidatepage(struct page *page, unsigned int offset,
				    unsigned int length)
{
	BUG_ON(offset || length < PAGE_CACHE_SIZE);

	BUG_ON(PageWriteback(page));

	metapage_releasepage(page, 0);
}

const struct address_space_operations jfs_metapage_aops = {
	.readpage	= metapage_readpage,
	.writepage	= metapage_writepage,
	.releasepage	= metapage_releasepage,
	.invalidatepage	= metapage_invalidatepage,
	.set_page_dirty	= __set_page_dirty_nobuffers,
};

struct metapage *__get_metapage(struct inode *inode, unsigned long lblock,
				unsigned int size, int absolute,
				unsigned long new)
{
	int l2BlocksPerPage;
	int l2bsize;
	struct address_space *mapping;
	struct metapage *mp = NULL;
	struct page *page;
	unsigned long page_index;
	unsigned long page_offset;

	jfs_info("__get_metapage: ino = %ld, lblock = 0x%lx, abs=%d",
		 inode->i_ino, lblock, absolute);

	l2bsize = inode->i_blkbits;
	l2BlocksPerPage = PAGE_CACHE_SHIFT - l2bsize;
	page_index = lblock >> l2BlocksPerPage;
	page_offset = (lblock - (page_index << l2BlocksPerPage)) << l2bsize;
	if ((page_offset + size) > PAGE_CACHE_SIZE) {
		jfs_err("MetaData crosses page boundary!!");
		jfs_err("lblock = %lx, size  = %d", lblock, size);
		dump_stack();
		return NULL;
	}
	if (absolute)
		mapping = JFS_SBI(inode->i_sb)->direct_inode->i_mapping;
	else {
		/*
		 * If an nfs client tries to read an inode that is larger
		 * than any existing inodes, we may try to read past the
		 * end of the inode map
		 */
		if ((lblock << inode->i_blkbits) >= inode->i_size)
			return NULL;
		mapping = inode->i_mapping;
	}

	if (new && (PSIZE == PAGE_CACHE_SIZE)) {
		page = grab_cache_page(mapping, page_index);
		if (!page) {
			jfs_err("grab_cache_page failed!");
			return NULL;
		}
		SetPageUptodate(page);
	} else {
		page = read_mapping_page(mapping, page_index, NULL);
		if (IS_ERR(page) || !PageUptodate(page)) {
			jfs_err("read_mapping_page failed!");
			return NULL;
		}
		lock_page(page);
	}

	mp = page_to_mp(page, page_offset);
	if (mp) {
		if (mp->logical_size != size) {
			jfs_error(inode->i_sb,
				  "get_mp->logical_size != size\n");
			jfs_err("logical_size = %d, size = %d",
				mp->logical_size, size);
			dump_stack();
			goto unlock;
		}
		mp->count++;
		lock_metapage(mp);
		if (test_bit(META_discard, &mp->flag)) {
			if (!new) {
				jfs_error(inode->i_sb,
					  "using a discarded metapage\n");
				discard_metapage(mp);
				goto unlock;
			}
			clear_bit(META_discard, &mp->flag);
		}
	} else {
		INCREMENT(mpStat.pagealloc);
		mp = alloc_metapage(GFP_NOFS);
		mp->page = page;
		mp->flag = 0;
		mp->xflag = COMMIT_PAGE;
		mp->count = 1;
		mp->nohomeok = 0;
		mp->logical_size = size;
		mp->data = page_address(page) + page_offset;
		mp->index = lblock;
		if (unlikely(insert_metapage(page, mp))) {
			free_metapage(mp);
			goto unlock;
		}
		lock_metapage(mp);
	}

	if (new) {
		jfs_info("zeroing mp = 0x%p", mp);
		memset(mp->data, 0, PSIZE);
	}

	unlock_page(page);
	jfs_info("__get_metapage: returning = 0x%p data = 0x%p", mp, mp->data);
	return mp;

unlock:
	unlock_page(page);
	return NULL;
}

void grab_metapage(struct metapage * mp)
{
	jfs_info("grab_metapage: mp = 0x%p", mp);
	page_cache_get(mp->page);
	lock_page(mp->page);
	mp->count++;
	lock_metapage(mp);
	unlock_page(mp->page);
}

void force_metapage(struct metapage *mp)
{
	struct page *page = mp->page;
	jfs_info("force_metapage: mp = 0x%p", mp);
	set_bit(META_forcewrite, &mp->flag);
	clear_bit(META_sync, &mp->flag);
	page_cache_get(page);
	lock_page(page);
	set_page_dirty(page);
	write_one_page(page, 1);
	clear_bit(META_forcewrite, &mp->flag);
	page_cache_release(page);
}

void hold_metapage(struct metapage *mp)
{
	lock_page(mp->page);
}

void put_metapage(struct metapage *mp)
{
	if (mp->count || mp->nohomeok) {
		/* Someone else will release this */
		unlock_page(mp->page);
		return;
	}
	page_cache_get(mp->page);
	mp->count++;
	lock_metapage(mp);
	unlock_page(mp->page);
	release_metapage(mp);
}

void release_metapage(struct metapage * mp)
{
	struct page *page = mp->page;
	jfs_info("release_metapage: mp = 0x%p, flag = 0x%lx", mp, mp->flag);

	BUG_ON(!page);

	lock_page(page);
	unlock_metapage(mp);

	assert(mp->count);
	if (--mp->count || mp->nohomeok) {
		unlock_page(page);
		page_cache_release(page);
		return;
	}

	if (test_bit(META_dirty, &mp->flag)) {
		set_page_dirty(page);
		if (test_bit(META_sync, &mp->flag)) {
			clear_bit(META_sync, &mp->flag);
			write_one_page(page, 1);
			lock_page(page); /* write_one_page unlocks the page */
		}
	} else if (mp->lsn)	/* discard_metapage doesn't remove it */
		remove_from_logsync(mp);

	/* Try to keep metapages from using up too much memory */
	drop_metapage(page, mp);

	unlock_page(page);
	page_cache_release(page);
}

void __invalidate_metapages(struct inode *ip, s64 addr, int len)
{
	sector_t lblock;
	int l2BlocksPerPage = PAGE_CACHE_SHIFT - ip->i_blkbits;
	int BlocksPerPage = 1 << l2BlocksPerPage;
	/* All callers are interested in block device's mapping */
	struct address_space *mapping =
		JFS_SBI(ip->i_sb)->direct_inode->i_mapping;
	struct metapage *mp;
	struct page *page;
	unsigned int offset;

	/*
	 * Mark metapages to discard.  They will eventually be
	 * released, but should not be written.
	 */
	for (lblock = addr & ~(BlocksPerPage - 1); lblock < addr + len;
	     lblock += BlocksPerPage) {
		page = find_lock_page(mapping, lblock >> l2BlocksPerPage);
		if (!page)
			continue;
		for (offset = 0; offset < PAGE_CACHE_SIZE; offset += PSIZE) {
			mp = page_to_mp(page, offset);
			if (!mp)
				continue;
			if (mp->index < addr)
				continue;
			if (mp->index >= addr + len)
				break;

			clear_bit(META_dirty, &mp->flag);
			set_bit(META_discard, &mp->flag);
			if (mp->lsn)
				remove_from_logsync(mp);
		}
		unlock_page(page);
		page_cache_release(page);
	}
}

#ifdef CONFIG_JFS_STATISTICS
static int jfs_mpstat_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		       "JFS Metapage statistics\n"
		       "=======================\n"
		       "page allocations = %d\n"
		       "page frees = %d\n"
		       "lock waits = %d\n",
		       mpStat.pagealloc,
		       mpStat.pagefree,
		       mpStat.lockwait);
	return 0;
}

static int jfs_mpstat_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, jfs_mpstat_proc_show, NULL);
}

const struct file_operations jfs_mpstat_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= jfs_mpstat_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_metapage.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2004
 *   Portions Copyright (C) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 *	jfs_logmgr.c: log manager
 *
 * for related information, see transaction manager (jfs_txnmgr.c), and
 * recovery manager (jfs_logredo.c).
 *
 * note: for detail, RTFS.
 *
 *	log buffer manager:
 * special purpose buffer manager supporting log i/o requirements.
 * per log serial pageout of logpage
 * queuing i/o requests and redrive i/o at iodone
 * maintain current logpage buffer
 * no caching since append only
 * appropriate jfs buffer cache buffers as needed
 *
 *	group commit:
 * transactions which wrote COMMIT records in the same in-memory
 * log page during the pageout of previous/current log page(s) are
 * committed together by the pageout of the page.
 *
 *	TBD lazy commit:
 * transactions are committed asynchronously when the log page
 * containing it COMMIT is paged out when it becomes full;
 *
 *	serialization:
 * . a per log lock serialize log write.
 * . a per log lock serialize group commit.
 * . a per log lock serialize log open/close;
 *
 *	TBD log integrity:
 * careful-write (ping-pong) of last logpage to recover from crash
 * in overwrite.
 * detection of split (out-of-order) write of physical sectors
 * of last logpage via timestamp at end of each sector
 * with its mirror data array at trailer).
 *
 *	alternatives:
 * lsn - 64-bit monotonically increasing integer vs
 * 32-bit lspn and page eor.
 */

// #include <linux/fs.h>
// #include <linux/blkdev.h>
#include <linux/interrupt.h>
// #include <linux/completion.h>
// #include <linux/kthread.h>
// #include <linux/buffer_head.h>		/* for sync_blockdev() */
// #include <linux/bio.h>
#include <linux/freezer.h>
#include <linux/export.h>
#include <linux/delay.h>
#include <linux/mutex.h>
// #include <linux/seq_file.h>
// #include <linux/slab.h>
// #include "jfs_incore.h"
// #include "jfs_filsys.h"
// #include "jfs_metapage.h"
// #include "jfs_superblock.h"
// #include "jfs_txnmgr.h"
// #include "jfs_debug.h"
#include "../../inc/__fss.h"


/*
 * lbuf's ready to be redriven.  Protected by log_redrive_lock (jfsIO thread)
 */
static struct lbuf *log_redrive_list;
static DEFINE_SPINLOCK(log_redrive_lock);


/*
 *	log read/write serialization (per log)
 */
#define LOG_LOCK_INIT(log)	mutex_init(&(log)->loglock)
#define LOG_LOCK(log)		mutex_lock(&((log)->loglock))
#define LOG_UNLOCK(log)		mutex_unlock(&((log)->loglock))


/*
 *	log group commit serialization (per log)
 */

#define LOGGC_LOCK_INIT(log)	spin_lock_init(&(log)->gclock)
#define LOGGC_LOCK(log)		spin_lock_irq(&(log)->gclock)
#define LOGGC_UNLOCK(log)	spin_unlock_irq(&(log)->gclock)
#define LOGGC_WAKEUP(tblk)	wake_up_all(&(tblk)->gcwait)

/*
 *	log sync serialization (per log)
 */
#define	LOGSYNC_DELTA(logsize)		min((logsize)/8, 128*LOGPSIZE)
#define	LOGSYNC_BARRIER(logsize)	((logsize)/4)
/*
#define	LOGSYNC_DELTA(logsize)		min((logsize)/4, 256*LOGPSIZE)
#define	LOGSYNC_BARRIER(logsize)	((logsize)/2)
*/


/*
 *	log buffer cache synchronization
 */
static DEFINE_SPINLOCK(jfsLCacheLock);

#define	LCACHE_LOCK(flags)	spin_lock_irqsave(&jfsLCacheLock, flags)
#define	LCACHE_UNLOCK(flags)	spin_unlock_irqrestore(&jfsLCacheLock, flags)

/*
 * See __SLEEP_COND in jfs_locks.h
 */
#define LCACHE_SLEEP_COND(wq, cond, flags)	\
do {						\
	if (cond)				\
		break;				\
	__SLEEP_COND(wq, cond, LCACHE_LOCK(flags), LCACHE_UNLOCK(flags)); \
} while (0)

#define	LCACHE_WAKEUP(event)	wake_up(event)


/*
 *	lbuf buffer cache (lCache) control
 */
/* log buffer manager pageout control (cumulative, inclusive) */
#define	lbmREAD		0x0001
#define	lbmWRITE	0x0002	/* enqueue at tail of write queue;
				 * init pageout if at head of queue;
				 */
#define	lbmRELEASE	0x0004	/* remove from write queue
				 * at completion of pageout;
				 * do not free/recycle it yet:
				 * caller will free it;
				 */
#define	lbmSYNC		0x0008	/* do not return to freelist
				 * when removed from write queue;
				 */
#define lbmFREE		0x0010	/* return to freelist
				 * at completion of pageout;
				 * the buffer may be recycled;
				 */
#define	lbmDONE		0x0020
#define	lbmERROR	0x0040
#define lbmGC		0x0080	/* lbmIODone to perform post-GC processing
				 * of log page
				 */
#define lbmDIRECT	0x0100

/*
 * Global list of active external journals
 */
static LIST_HEAD(jfs_external_logs);
static struct jfs_log *dummy_log;
static DEFINE_MUTEX(jfs_log_mutex);

/*
 * forward references
 */
static int lmWriteRecord(struct jfs_log * log, struct tblock * tblk,
			 struct lrd * lrd, struct tlock * tlck);

static int lmNextPage(struct jfs_log * log);
static int lmLogFileSystem(struct jfs_log * log, struct jfs_sb_info *sbi,
			   int activate);

static int open_inline_log(struct super_block *sb);
static int open_dummy_log(struct super_block *sb);
static int lbmLogInit(struct jfs_log * log);
static void lbmLogShutdown(struct jfs_log * log);
static struct lbuf *lbmAllocate(struct jfs_log * log, int);
static void lbmFree(struct lbuf * bp);
static void lbmfree(struct lbuf * bp);
static int lbmRead(struct jfs_log * log, int pn, struct lbuf ** bpp);
static void lbmWrite(struct jfs_log * log, struct lbuf * bp, int flag, int cant_block);
static void lbmDirectWrite(struct jfs_log * log, struct lbuf * bp, int flag);
static int lbmIOWait(struct lbuf * bp, int flag);
static bio_end_io_t lbmIODone;
static void lbmStartIO(struct lbuf * bp);
static void lmGCwrite(struct jfs_log * log, int cant_block);
static int lmLogSync(struct jfs_log * log, int hard_sync);



/*
 *	statistics
 */
#ifdef CONFIG_JFS_STATISTICS
static struct lmStat {
	uint commit;		/* # of commit */
	uint pagedone;		/* # of page written */
	uint submitted;		/* # of pages submitted */
	uint full_page;		/* # of full pages submitted */
	uint partial_page;	/* # of partial pages submitted */
} lmStat;
#endif

static void write_special_inodes(struct jfs_log *log,
				 int (*writer)(struct address_space *))
{
	struct jfs_sb_info *sbi;

	list_for_each_entry(sbi, &log->sb_list, log_list) {
		writer(sbi->ipbmap->i_mapping);
		writer(sbi->ipimap->i_mapping);
		writer(sbi->direct_inode->i_mapping);
	}
}

/*
 * NAME:	lmLog()
 *
 * FUNCTION:	write a log record;
 *
 * PARAMETER:
 *
 * RETURN:	lsn - offset to the next log record to write (end-of-log);
 *		-1  - error;
 *
 * note: todo: log error handler
 */
int lmLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
	  struct tlock * tlck)
{
	int lsn;
	int diffp, difft;
	struct metapage *mp = NULL;
	unsigned long flags;

	jfs_info("lmLog: log:0x%p tblk:0x%p, lrd:0x%p tlck:0x%p",
		 log, tblk, lrd, tlck);

	LOG_LOCK(log);

	/* log by (out-of-transaction) JFS ? */
	if (tblk == NULL)
		goto writeRecord;

	/* log from page ? */
	if (tlck == NULL ||
	    tlck->type & tlckBTROOT || (mp = tlck->mp) == NULL)
		goto writeRecord;

	/*
	 *	initialize/update page/transaction recovery lsn
	 */
	lsn = log->lsn;

	LOGSYNC_LOCK(log, flags);

	/*
	 * initialize page lsn if first log write of the page
	 */
	if (mp->lsn == 0) {
		mp->log = log;
		mp->lsn = lsn;
		log->count++;

		/* insert page at tail of logsynclist */
		list_add_tail(&mp->synclist, &log->synclist);
	}

	/*
	 *	initialize/update lsn of tblock of the page
	 *
	 * transaction inherits oldest lsn of pages associated
	 * with allocation/deallocation of resources (their
	 * log records are used to reconstruct allocation map
	 * at recovery time: inode for inode allocation map,
	 * B+-tree index of extent descriptors for block
	 * allocation map);
	 * allocation map pages inherit transaction lsn at
	 * commit time to allow forwarding log syncpt past log
	 * records associated with allocation/deallocation of
	 * resources only after persistent map of these map pages
	 * have been updated and propagated to home.
	 */
	/*
	 * initialize transaction lsn:
	 */
	if (tblk->lsn == 0) {
		/* inherit lsn of its first page logged */
		tblk->lsn = mp->lsn;
		log->count++;

		/* insert tblock after the page on logsynclist */
		list_add(&tblk->synclist, &mp->synclist);
	}
	/*
	 * update transaction lsn:
	 */
	else {
		/* inherit oldest/smallest lsn of page */
		logdiff(diffp, mp->lsn, log);
		logdiff(difft, tblk->lsn, log);
		if (diffp < difft) {
			/* update tblock lsn with page lsn */
			tblk->lsn = mp->lsn;

			/* move tblock after page on logsynclist */
			list_move(&tblk->synclist, &mp->synclist);
		}
	}

	LOGSYNC_UNLOCK(log, flags);

	/*
	 *	write the log record
	 */
      writeRecord:
	lsn = lmWriteRecord(log, tblk, lrd, tlck);

	/*
	 * forward log syncpt if log reached next syncpt trigger
	 */
	logdiff(diffp, lsn, log);
	if (diffp >= log->nextsync)
		lsn = lmLogSync(log, 0);

	/* update end-of-log lsn */
	log->lsn = lsn;

	LOG_UNLOCK(log);

	/* return end-of-log address */
	return lsn;
}

/*
 * NAME:	lmWriteRecord()
 *
 * FUNCTION:	move the log record to current log page
 *
 * PARAMETER:	cd	- commit descriptor
 *
 * RETURN:	end-of-log address
 *
 * serialization: LOG_LOCK() held on entry/exit
 */
static int
lmWriteRecord(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
	      struct tlock * tlck)
{
	int lsn = 0;		/* end-of-log address */
	struct lbuf *bp;	/* dst log page buffer */
	struct logpage *lp;	/* dst log page */
	caddr_t dst;		/* destination address in log page */
	int dstoffset;		/* end-of-log offset in log page */
	int freespace;		/* free space in log page */
	caddr_t p;		/* src meta-data page */
	caddr_t src;
	int srclen;
	int nbytes;		/* number of bytes to move */
	int i;
	int len;
	struct linelock *linelock;
	struct lv *lv;
	struct lvd *lvd;
	int l2linesize;

	len = 0;

	/* retrieve destination log page to write */
	bp = (struct lbuf *) log->bp;
	lp = (struct logpage *) bp->l_ldata;
	dstoffset = log->eor;

	/* any log data to write ? */
	if (tlck == NULL)
		goto moveLrd;

	/*
	 *	move log record data
	 */
	/* retrieve source meta-data page to log */
	if (tlck->flag & tlckPAGELOCK) {
		p = (caddr_t) (tlck->mp->data);
		linelock = (struct linelock *) & tlck->lock;
	}
	/* retrieve source in-memory inode to log */
	else if (tlck->flag & tlckINODELOCK) {
		if (tlck->type & tlckDTREE)
			p = (caddr_t) &JFS_IP(tlck->ip)->i_dtroot;
		else
			p = (caddr_t) &JFS_IP(tlck->ip)->i_xtroot;
		linelock = (struct linelock *) & tlck->lock;
	}
#ifdef	_JFS_WIP
	else if (tlck->flag & tlckINLINELOCK) {

		inlinelock = (struct inlinelock *) & tlck;
		p = (caddr_t) & inlinelock->pxd;
		linelock = (struct linelock *) & tlck;
	}
#endif				/* _JFS_WIP */
	else {
		jfs_err("lmWriteRecord: UFO tlck:0x%p", tlck);
		return 0;	/* Probably should trap */
	}
	l2linesize = linelock->l2linesize;

      moveData:
	ASSERT(linelock->index <= linelock->maxcnt);

	lv = linelock->lv;
	for (i = 0; i < linelock->index; i++, lv++) {
		if (lv->length == 0)
			continue;

		/* is page full ? */
		if (dstoffset >= LOGPSIZE - LOGPTLRSIZE) {
			/* page become full: move on to next page */
			lmNextPage(log);

			bp = log->bp;
			lp = (struct logpage *) bp->l_ldata;
			dstoffset = LOGPHDRSIZE;
		}

		/*
		 * move log vector data
		 */
		src = (u8 *) p + (lv->offset << l2linesize);
		srclen = lv->length << l2linesize;
		len += srclen;
		while (srclen > 0) {
			freespace = (LOGPSIZE - LOGPTLRSIZE) - dstoffset;
			nbytes = min(freespace, srclen);
			dst = (caddr_t) lp + dstoffset;
			memcpy(dst, src, nbytes);
			dstoffset += nbytes;

			/* is page not full ? */
			if (dstoffset < LOGPSIZE - LOGPTLRSIZE)
				break;

			/* page become full: move on to next page */
			lmNextPage(log);

			bp = (struct lbuf *) log->bp;
			lp = (struct logpage *) bp->l_ldata;
			dstoffset = LOGPHDRSIZE;

			srclen -= nbytes;
			src += nbytes;
		}

		/*
		 * move log vector descriptor
		 */
		len += 4;
		lvd = (struct lvd *) ((caddr_t) lp + dstoffset);
		lvd->offset = cpu_to_le16(lv->offset);
		lvd->length = cpu_to_le16(lv->length);
		dstoffset += 4;
		jfs_info("lmWriteRecord: lv offset:%d length:%d",
			 lv->offset, lv->length);
	}

	if ((i = linelock->next)) {
		linelock = (struct linelock *) lid_to_tlock(i);
		goto moveData;
	}

	/*
	 *	move log record descriptor
	 */
      moveLrd:
	lrd->length = cpu_to_le16(len);

	src = (caddr_t) lrd;
	srclen = LOGRDSIZE;

	while (srclen > 0) {
		freespace = (LOGPSIZE - LOGPTLRSIZE) - dstoffset;
		nbytes = min(freespace, srclen);
		dst = (caddr_t) lp + dstoffset;
		memcpy(dst, src, nbytes);

		dstoffset += nbytes;
		srclen -= nbytes;

		/* are there more to move than freespace of page ? */
		if (srclen)
			goto pageFull;

		/*
		 * end of log record descriptor
		 */

		/* update last log record eor */
		log->eor = dstoffset;
		bp->l_eor = dstoffset;
		lsn = (log->page << L2LOGPSIZE) + dstoffset;

		if (lrd->type & cpu_to_le16(LOG_COMMIT)) {
			tblk->clsn = lsn;
			jfs_info("wr: tclsn:0x%x, beor:0x%x", tblk->clsn,
				 bp->l_eor);

			INCREMENT(lmStat.commit);	/* # of commit */

			/*
			 * enqueue tblock for group commit:
			 *
			 * enqueue tblock of non-trivial/synchronous COMMIT
			 * at tail of group commit queue
			 * (trivial/asynchronous COMMITs are ignored by
			 * group commit.)
			 */
			LOGGC_LOCK(log);

			/* init tblock gc state */
			tblk->flag = tblkGC_QUEUE;
			tblk->bp = log->bp;
			tblk->pn = log->page;
			tblk->eor = log->eor;

			/* enqueue transaction to commit queue */
			list_add_tail(&tblk->cqueue, &log->cqueue);

			LOGGC_UNLOCK(log);
		}

		jfs_info("lmWriteRecord: lrd:0x%04x bp:0x%p pn:%d eor:0x%x",
			le16_to_cpu(lrd->type), log->bp, log->page, dstoffset);

		/* page not full ? */
		if (dstoffset < LOGPSIZE - LOGPTLRSIZE)
			return lsn;

	      pageFull:
		/* page become full: move on to next page */
		lmNextPage(log);

		bp = (struct lbuf *) log->bp;
		lp = (struct logpage *) bp->l_ldata;
		dstoffset = LOGPHDRSIZE;
		src += nbytes;
	}

	return lsn;
}


/*
 * NAME:	lmNextPage()
 *
 * FUNCTION:	write current page and allocate next page.
 *
 * PARAMETER:	log
 *
 * RETURN:	0
 *
 * serialization: LOG_LOCK() held on entry/exit
 */
static int lmNextPage(struct jfs_log * log)
{
	struct logpage *lp;
	int lspn;		/* log sequence page number */
	int pn;			/* current page number */
	struct lbuf *bp;
	struct lbuf *nextbp;
	struct tblock *tblk;

	/* get current log page number and log sequence page number */
	pn = log->page;
	bp = log->bp;
	lp = (struct logpage *) bp->l_ldata;
	lspn = le32_to_cpu(lp->h.page);

	LOGGC_LOCK(log);

	/*
	 *	write or queue the full page at the tail of write queue
	 */
	/* get the tail tblk on commit queue */
	if (list_empty(&log->cqueue))
		tblk = NULL;
	else
		tblk = list_entry(log->cqueue.prev, struct tblock, cqueue);

	/* every tblk who has COMMIT record on the current page,
	 * and has not been committed, must be on commit queue
	 * since tblk is queued at commit queueu at the time
	 * of writing its COMMIT record on the page before
	 * page becomes full (even though the tblk thread
	 * who wrote COMMIT record may have been suspended
	 * currently);
	 */

	/* is page bound with outstanding tail tblk ? */
	if (tblk && tblk->pn == pn) {
		/* mark tblk for end-of-page */
		tblk->flag |= tblkGC_EOP;

		if (log->cflag & logGC_PAGEOUT) {
			/* if page is not already on write queue,
			 * just enqueue (no lbmWRITE to prevent redrive)
			 * buffer to wqueue to ensure correct serial order
			 * of the pages since log pages will be added
			 * continuously
			 */
			if (bp->l_wqnext == NULL)
				lbmWrite(log, bp, 0, 0);
		} else {
			/*
			 * No current GC leader, initiate group commit
			 */
			log->cflag |= logGC_PAGEOUT;
			lmGCwrite(log, 0);
		}
	}
	/* page is not bound with outstanding tblk:
	 * init write or mark it to be redriven (lbmWRITE)
	 */
	else {
		/* finalize the page */
		bp->l_ceor = bp->l_eor;
		lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_ceor);
		lbmWrite(log, bp, lbmWRITE | lbmRELEASE | lbmFREE, 0);
	}
	LOGGC_UNLOCK(log);

	/*
	 *	allocate/initialize next page
	 */
	/* if log wraps, the first data page of log is 2
	 * (0 never used, 1 is superblock).
	 */
	log->page = (pn == log->size - 1) ? 2 : pn + 1;
	log->eor = LOGPHDRSIZE;	/* ? valid page empty/full at logRedo() */

	/* allocate/initialize next log page buffer */
	nextbp = lbmAllocate(log, log->page);
	nextbp->l_eor = log->eor;
	log->bp = nextbp;

	/* initialize next log page */
	lp = (struct logpage *) nextbp->l_ldata;
	lp->h.page = lp->t.page = cpu_to_le32(lspn + 1);
	lp->h.eor = lp->t.eor = cpu_to_le16(LOGPHDRSIZE);

	return 0;
}


/*
 * NAME:	lmGroupCommit()
 *
 * FUNCTION:	group commit
 *	initiate pageout of the pages with COMMIT in the order of
 *	page number - redrive pageout of the page at the head of
 *	pageout queue until full page has been written.
 *
 * RETURN:
 *
 * NOTE:
 *	LOGGC_LOCK serializes log group commit queue, and
 *	transaction blocks on the commit queue.
 *	N.B. LOG_LOCK is NOT held during lmGroupCommit().
 */
int lmGroupCommit(struct jfs_log * log, struct tblock * tblk)
{
	int rc = 0;

	LOGGC_LOCK(log);

	/* group committed already ? */
	if (tblk->flag & tblkGC_COMMITTED) {
		if (tblk->flag & tblkGC_ERROR)
			rc = -EIO;

		LOGGC_UNLOCK(log);
		return rc;
	}
	jfs_info("lmGroup Commit: tblk = 0x%p, gcrtc = %d", tblk, log->gcrtc);

	if (tblk->xflag & COMMIT_LAZY)
		tblk->flag |= tblkGC_LAZY;

	if ((!(log->cflag & logGC_PAGEOUT)) && (!list_empty(&log->cqueue)) &&
	    (!(tblk->xflag & COMMIT_LAZY) || test_bit(log_FLUSH, &log->flag)
	     || jfs_tlocks_low)) {
		/*
		 * No pageout in progress
		 *
		 * start group commit as its group leader.
		 */
		log->cflag |= logGC_PAGEOUT;

		lmGCwrite(log, 0);
	}

	if (tblk->xflag & COMMIT_LAZY) {
		/*
		 * Lazy transactions can leave now
		 */
		LOGGC_UNLOCK(log);
		return 0;
	}

	/* lmGCwrite gives up LOGGC_LOCK, check again */

	if (tblk->flag & tblkGC_COMMITTED) {
		if (tblk->flag & tblkGC_ERROR)
			rc = -EIO;

		LOGGC_UNLOCK(log);
		return rc;
	}

	/* upcount transaction waiting for completion
	 */
	log->gcrtc++;
	tblk->flag |= tblkGC_READY;

	__SLEEP_COND(tblk->gcwait, (tblk->flag & tblkGC_COMMITTED),
		     LOGGC_LOCK(log), LOGGC_UNLOCK(log));

	/* removed from commit queue */
	if (tblk->flag & tblkGC_ERROR)
		rc = -EIO;

	LOGGC_UNLOCK(log);
	return rc;
}

/*
 * NAME:	lmGCwrite()
 *
 * FUNCTION:	group commit write
 *	initiate write of log page, building a group of all transactions
 *	with commit records on that page.
 *
 * RETURN:	None
 *
 * NOTE:
 *	LOGGC_LOCK must be held by caller.
 *	N.B. LOG_LOCK is NOT held during lmGroupCommit().
 */
static void lmGCwrite(struct jfs_log * log, int cant_write)
{
	struct lbuf *bp;
	struct logpage *lp;
	int gcpn;		/* group commit page number */
	struct tblock *tblk;
	struct tblock *xtblk = NULL;

	/*
	 * build the commit group of a log page
	 *
	 * scan commit queue and make a commit group of all
	 * transactions with COMMIT records on the same log page.
	 */
	/* get the head tblk on the commit queue */
	gcpn = list_entry(log->cqueue.next, struct tblock, cqueue)->pn;

	list_for_each_entry(tblk, &log->cqueue, cqueue) {
		if (tblk->pn != gcpn)
			break;

		xtblk = tblk;

		/* state transition: (QUEUE, READY) -> COMMIT */
		tblk->flag |= tblkGC_COMMIT;
	}
	tblk = xtblk;		/* last tblk of the page */

	/*
	 * pageout to commit transactions on the log page.
	 */
	bp = (struct lbuf *) tblk->bp;
	lp = (struct logpage *) bp->l_ldata;
	/* is page already full ? */
	if (tblk->flag & tblkGC_EOP) {
		/* mark page to free at end of group commit of the page */
		tblk->flag &= ~tblkGC_EOP;
		tblk->flag |= tblkGC_FREE;
		bp->l_ceor = bp->l_eor;
		lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_ceor);
		lbmWrite(log, bp, lbmWRITE | lbmRELEASE | lbmGC,
			 cant_write);
		INCREMENT(lmStat.full_page);
	}
	/* page is not yet full */
	else {
		bp->l_ceor = tblk->eor;	/* ? bp->l_ceor = bp->l_eor; */
		lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_ceor);
		lbmWrite(log, bp, lbmWRITE | lbmGC, cant_write);
		INCREMENT(lmStat.partial_page);
	}
}

/*
 * NAME:	lmPostGC()
 *
 * FUNCTION:	group commit post-processing
 *	Processes transactions after their commit records have been written
 *	to disk, redriving log I/O if necessary.
 *
 * RETURN:	None
 *
 * NOTE:
 *	This routine is called a interrupt time by lbmIODone
 */
static void lmPostGC(struct lbuf * bp)
{
	unsigned long flags;
	struct jfs_log *log = bp->l_log;
	struct logpage *lp;
	struct tblock *tblk, *temp;

	//LOGGC_LOCK(log);
	spin_lock_irqsave(&log->gclock, flags);
	/*
	 * current pageout of group commit completed.
	 *
	 * remove/wakeup transactions from commit queue who were
	 * group committed with the current log page
	 */
	list_for_each_entry_safe(tblk, temp, &log->cqueue, cqueue) {
		if (!(tblk->flag & tblkGC_COMMIT))
			break;
		/* if transaction was marked GC_COMMIT then
		 * it has been shipped in the current pageout
		 * and made it to disk - it is committed.
		 */

		if (bp->l_flag & lbmERROR)
			tblk->flag |= tblkGC_ERROR;

		/* remove it from the commit queue */
		list_del(&tblk->cqueue);
		tblk->flag &= ~tblkGC_QUEUE;

		if (tblk == log->flush_tblk) {
			/* we can stop flushing the log now */
			clear_bit(log_FLUSH, &log->flag);
			log->flush_tblk = NULL;
		}

		jfs_info("lmPostGC: tblk = 0x%p, flag = 0x%x", tblk,
			 tblk->flag);

		if (!(tblk->xflag & COMMIT_FORCE))
			/*
			 * Hand tblk over to lazy commit thread
			 */
			txLazyUnlock(tblk);
		else {
			/* state transition: COMMIT -> COMMITTED */
			tblk->flag |= tblkGC_COMMITTED;

			if (tblk->flag & tblkGC_READY)
				log->gcrtc--;

			LOGGC_WAKEUP(tblk);
		}

		/* was page full before pageout ?
		 * (and this is the last tblk bound with the page)
		 */
		if (tblk->flag & tblkGC_FREE)
			lbmFree(bp);
		/* did page become full after pageout ?
		 * (and this is the last tblk bound with the page)
		 */
		else if (tblk->flag & tblkGC_EOP) {
			/* finalize the page */
			lp = (struct logpage *) bp->l_ldata;
			bp->l_ceor = bp->l_eor;
			lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_eor);
			jfs_info("lmPostGC: calling lbmWrite");
			lbmWrite(log, bp, lbmWRITE | lbmRELEASE | lbmFREE,
				 1);
		}

	}

	/* are there any transactions who have entered lnGroupCommit()
	 * (whose COMMITs are after that of the last log page written.
	 * They are waiting for new group commit (above at (SLEEP 1))
	 * or lazy transactions are on a full (queued) log page,
	 * select the latest ready transaction as new group leader and
	 * wake her up to lead her group.
	 */
	if ((!list_empty(&log->cqueue)) &&
	    ((log->gcrtc > 0) || (tblk->bp->l_wqnext != NULL) ||
	     test_bit(log_FLUSH, &log->flag) || jfs_tlocks_low))
		/*
		 * Call lmGCwrite with new group leader
		 */
		lmGCwrite(log, 1);

	/* no transaction are ready yet (transactions are only just
	 * queued (GC_QUEUE) and not entered for group commit yet).
	 * the first transaction entering group commit
	 * will elect herself as new group leader.
	 */
	else
		log->cflag &= ~logGC_PAGEOUT;

	//LOGGC_UNLOCK(log);
	spin_unlock_irqrestore(&log->gclock, flags);
	return;
}

/*
 * NAME:	lmLogSync()
 *
 * FUNCTION:	write log SYNCPT record for specified log
 *	if new sync address is available
 *	(normally the case if sync() is executed by back-ground
 *	process).
 *	calculate new value of i_nextsync which determines when
 *	this code is called again.
 *
 * PARAMETERS:	log	- log structure
 *		hard_sync - 1 to force all metadata to be written
 *
 * RETURN:	0
 *
 * serialization: LOG_LOCK() held on entry/exit
 */
static int lmLogSync(struct jfs_log * log, int hard_sync)
{
	int logsize;
	int written;		/* written since last syncpt */
	int free;		/* free space left available */
	int delta;		/* additional delta to write normally */
	int more;		/* additional write granted */
	struct lrd lrd;
	int lsn;
	struct logsyncblk *lp;
	unsigned long flags;

	/* push dirty metapages out to disk */
	if (hard_sync)
		write_special_inodes(log, filemap_fdatawrite);
	else
		write_special_inodes(log, filemap_flush);

	/*
	 *	forward syncpt
	 */
	/* if last sync is same as last syncpt,
	 * invoke sync point forward processing to update sync.
	 */

	if (log->sync == log->syncpt) {
		LOGSYNC_LOCK(log, flags);
		if (list_empty(&log->synclist))
			log->sync = log->lsn;
		else {
			lp = list_entry(log->synclist.next,
					struct logsyncblk, synclist);
			log->sync = lp->lsn;
		}
		LOGSYNC_UNLOCK(log, flags);

	}

	/* if sync is different from last syncpt,
	 * write a SYNCPT record with syncpt = sync.
	 * reset syncpt = sync
	 */
	if (log->sync != log->syncpt) {
		lrd.logtid = 0;
		lrd.backchain = 0;
		lrd.type = cpu_to_le16(LOG_SYNCPT);
		lrd.length = 0;
		lrd.log.syncpt.sync = cpu_to_le32(log->sync);
		lsn = lmWriteRecord(log, NULL, &lrd, NULL);

		log->syncpt = log->sync;
	} else
		lsn = log->lsn;

	/*
	 *	setup next syncpt trigger (SWAG)
	 */
	logsize = log->logsize;

	logdiff(written, lsn, log);
	free = logsize - written;
	delta = LOGSYNC_DELTA(logsize);
	more = min(free / 2, delta);
	if (more < 2 * LOGPSIZE) {
		jfs_warn("\n ... Log Wrap ... Log Wrap ... Log Wrap ...\n");
		/*
		 *	log wrapping
		 *
		 * option 1 - panic ? No.!
		 * option 2 - shutdown file systems
		 *	      associated with log ?
		 * option 3 - extend log ?
		 * option 4 - second chance
		 *
		 * mark log wrapped, and continue.
		 * when all active transactions are completed,
		 * mark log valid for recovery.
		 * if crashed during invalid state, log state
		 * implies invalid log, forcing fsck().
		 */
		/* mark log state log wrap in log superblock */
		/* log->state = LOGWRAP; */

		/* reset sync point computation */
		log->syncpt = log->sync = lsn;
		log->nextsync = delta;
	} else
		/* next syncpt trigger = written + more */
		log->nextsync = written + more;

	/* if number of bytes written from last sync point is more
	 * than 1/4 of the log size, stop new transactions from
	 * starting until all current transactions are completed
	 * by setting syncbarrier flag.
	 */
	if (!test_bit(log_SYNCBARRIER, &log->flag) &&
	    (written > LOGSYNC_BARRIER(logsize)) && log->active) {
		set_bit(log_SYNCBARRIER, &log->flag);
		jfs_info("log barrier on: lsn=0x%x syncpt=0x%x", lsn,
			 log->syncpt);
		/*
		 * We may have to initiate group commit
		 */
		jfs_flush_journal(log, 0);
	}

	return lsn;
}

/*
 * NAME:	jfs_syncpt
 *
 * FUNCTION:	write log SYNCPT record for specified log
 *
 * PARAMETERS:	log	  - log structure
 *		hard_sync - set to 1 to force metadata to be written
 */
void jfs_syncpt(struct jfs_log *log, int hard_sync)
{	LOG_LOCK(log);
	if (!test_bit(log_QUIESCE, &log->flag))
		lmLogSync(log, hard_sync);
	LOG_UNLOCK(log);
}

/*
 * NAME:	lmLogOpen()
 *
 * FUNCTION:	open the log on first open;
 *	insert filesystem in the active list of the log.
 *
 * PARAMETER:	ipmnt	- file system mount inode
 *		iplog	- log inode (out)
 *
 * RETURN:
 *
 * serialization:
 */
int lmLogOpen(struct super_block *sb)
{
	int rc;
	struct block_device *bdev;
	struct jfs_log *log;
	struct jfs_sb_info *sbi = JFS_SBI(sb);

	if (sbi->flag & JFS_NOINTEGRITY)
		return open_dummy_log(sb);

	if (sbi->mntflag & JFS_INLINELOG)
		return open_inline_log(sb);

	mutex_lock(&jfs_log_mutex);
	list_for_each_entry(log, &jfs_external_logs, journal_list) {
		if (log->bdev->bd_dev == sbi->logdev) {
			if (memcmp(log->uuid, sbi->loguuid,
				   sizeof(log->uuid))) {
				jfs_warn("wrong uuid on JFS journal\n");
				mutex_unlock(&jfs_log_mutex);
				return -EINVAL;
			}
			/*
			 * add file system to log active file system list
			 */
			if ((rc = lmLogFileSystem(log, sbi, 1))) {
				mutex_unlock(&jfs_log_mutex);
				return rc;
			}
			goto journal_found;
		}
	}

	if (!(log = kzalloc(sizeof(struct jfs_log), GFP_KERNEL))) {
		mutex_unlock(&jfs_log_mutex);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&log->sb_list);
	init_waitqueue_head(&log->syncwait);

	/*
	 *	external log as separate logical volume
	 *
	 * file systems to log may have n-to-1 relationship;
	 */

	bdev = blkdev_get_by_dev(sbi->logdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL,
				 log);
	if (IS_ERR(bdev)) {
		rc = PTR_ERR(bdev);
		goto free;
	}

	log->bdev = bdev;
	memcpy(log->uuid, sbi->loguuid, sizeof(log->uuid));

	/*
	 * initialize log:
	 */
	if ((rc = lmLogInit(log)))
		goto close;

	list_add(&log->journal_list, &jfs_external_logs);

	/*
	 * add file system to log active file system list
	 */
	if ((rc = lmLogFileSystem(log, sbi, 1)))
		goto shutdown;

journal_found:
	LOG_LOCK(log);
	list_add(&sbi->log_list, &log->sb_list);
	sbi->log = log;
	LOG_UNLOCK(log);

	mutex_unlock(&jfs_log_mutex);
	return 0;

	/*
	 *	unwind on error
	 */
      shutdown:		/* unwind lbmLogInit() */
	list_del(&log->journal_list);
	lbmLogShutdown(log);

      close:		/* close external log device */
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

      free:		/* free log descriptor */
	mutex_unlock(&jfs_log_mutex);
	kfree(log);

	jfs_warn("lmLogOpen: exit(%d)", rc);
	return rc;
}

static int open_inline_log(struct super_block *sb)
{
	struct jfs_log *log;
	int rc;

	if (!(log = kzalloc(sizeof(struct jfs_log), GFP_KERNEL)))
		return -ENOMEM;
	INIT_LIST_HEAD(&log->sb_list);
	init_waitqueue_head(&log->syncwait);

	set_bit(log_INLINELOG, &log->flag);
	log->bdev = sb->s_bdev;
	log->base = addressPXD(&JFS_SBI(sb)->logpxd);
	log->size = lengthPXD(&JFS_SBI(sb)->logpxd) >>
	    (L2LOGPSIZE - sb->s_blocksize_bits);
	log->l2bsize = sb->s_blocksize_bits;
	ASSERT(L2LOGPSIZE >= sb->s_blocksize_bits);

	/*
	 * initialize log.
	 */
	if ((rc = lmLogInit(log))) {
		kfree(log);
		jfs_warn("lmLogOpen: exit(%d)", rc);
		return rc;
	}

	list_add(&JFS_SBI(sb)->log_list, &log->sb_list);
	JFS_SBI(sb)->log = log;

	return rc;
}

static int open_dummy_log(struct super_block *sb)
{
	int rc;

	mutex_lock(&jfs_log_mutex);
	if (!dummy_log) {
		dummy_log = kzalloc(sizeof(struct jfs_log), GFP_KERNEL);
		if (!dummy_log) {
			mutex_unlock(&jfs_log_mutex);
			return -ENOMEM;
		}
		INIT_LIST_HEAD(&dummy_log->sb_list);
		init_waitqueue_head(&dummy_log->syncwait);
		dummy_log->no_integrity = 1;
		/* Make up some stuff */
		dummy_log->base = 0;
		dummy_log->size = 1024;
		rc = lmLogInit(dummy_log);
		if (rc) {
			kfree(dummy_log);
			dummy_log = NULL;
			mutex_unlock(&jfs_log_mutex);
			return rc;
		}
	}

	LOG_LOCK(dummy_log);
	list_add(&JFS_SBI(sb)->log_list, &dummy_log->sb_list);
	JFS_SBI(sb)->log = dummy_log;
	LOG_UNLOCK(dummy_log);
	mutex_unlock(&jfs_log_mutex);

	return 0;
}

/*
 * NAME:	lmLogInit()
 *
 * FUNCTION:	log initialization at first log open.
 *
 *	logredo() (or logformat()) should have been run previously.
 *	initialize the log from log superblock.
 *	set the log state in the superblock to LOGMOUNT and
 *	write SYNCPT log record.
 *
 * PARAMETER:	log	- log structure
 *
 * RETURN:	0	- if ok
 *		-EINVAL	- bad log magic number or superblock dirty
 *		error returned from logwait()
 *
 * serialization: single first open thread
 */
int lmLogInit(struct jfs_log * log)
{
	int rc = 0;
	struct lrd lrd;
	struct logsuper *logsuper;
	struct lbuf *bpsuper;
	struct lbuf *bp;
	struct logpage *lp;
	int lsn = 0;

	jfs_info("lmLogInit: log:0x%p", log);

	/* initialize the group commit serialization lock */
	LOGGC_LOCK_INIT(log);

	/* allocate/initialize the log write serialization lock */
	LOG_LOCK_INIT(log);

	LOGSYNC_LOCK_INIT(log);

	INIT_LIST_HEAD(&log->synclist);

	INIT_LIST_HEAD(&log->cqueue);
	log->flush_tblk = NULL;

	log->count = 0;

	/*
	 * initialize log i/o
	 */
	if ((rc = lbmLogInit(log)))
		return rc;

	if (!test_bit(log_INLINELOG, &log->flag))
		log->l2bsize = L2LOGPSIZE;

	/* check for disabled journaling to disk */
	if (log->no_integrity) {
		/*
		 * Journal pages will still be filled.  When the time comes
		 * to actually do the I/O, the write is not done, and the
		 * endio routine is called directly.
		 */
		bp = lbmAllocate(log , 0);
		log->bp = bp;
		bp->l_pn = bp->l_eor = 0;
	} else {
		/*
		 * validate log superblock
		 */
		if ((rc = lbmRead(log, 1, &bpsuper)))
			goto errout10;

		logsuper = (struct logsuper *) bpsuper->l_ldata;

		if (logsuper->magic != cpu_to_le32(LOGMAGIC)) {
			jfs_warn("*** Log Format Error ! ***");
			rc = -EINVAL;
			goto errout20;
		}

		/* logredo() should have been run successfully. */
		if (logsuper->state != cpu_to_le32(LOGREDONE)) {
			jfs_warn("*** Log Is Dirty ! ***");
			rc = -EINVAL;
			goto errout20;
		}

		/* initialize log from log superblock */
		if (test_bit(log_INLINELOG,&log->flag)) {
			if (log->size != le32_to_cpu(logsuper->size)) {
				rc = -EINVAL;
				goto errout20;
			}
			jfs_info("lmLogInit: inline log:0x%p base:0x%Lx "
				 "size:0x%x", log,
				 (unsigned long long) log->base, log->size);
		} else {
			if (memcmp(logsuper->uuid, log->uuid, 16)) {
				jfs_warn("wrong uuid on JFS log device");
				goto errout20;
			}
			log->size = le32_to_cpu(logsuper->size);
			log->l2bsize = le32_to_cpu(logsuper->l2bsize);
			jfs_info("lmLogInit: external log:0x%p base:0x%Lx "
				 "size:0x%x", log,
				 (unsigned long long) log->base, log->size);
		}

		log->page = le32_to_cpu(logsuper->end) / LOGPSIZE;
		log->eor = le32_to_cpu(logsuper->end) - (LOGPSIZE * log->page);

		/*
		 * initialize for log append write mode
		 */
		/* establish current/end-of-log page/buffer */
		if ((rc = lbmRead(log, log->page, &bp)))
			goto errout20;

		lp = (struct logpage *) bp->l_ldata;

		jfs_info("lmLogInit: lsn:0x%x page:%d eor:%d:%d",
			 le32_to_cpu(logsuper->end), log->page, log->eor,
			 le16_to_cpu(lp->h.eor));

		log->bp = bp;
		bp->l_pn = log->page;
		bp->l_eor = log->eor;

		/* if current page is full, move on to next page */
		if (log->eor >= LOGPSIZE - LOGPTLRSIZE)
			lmNextPage(log);

		/*
		 * initialize log syncpoint
		 */
		/*
		 * write the first SYNCPT record with syncpoint = 0
		 * (i.e., log redo up to HERE !);
		 * remove current page from lbm write queue at end of pageout
		 * (to write log superblock update), but do not release to
		 * freelist;
		 */
		lrd.logtid = 0;
		lrd.backchain = 0;
		lrd.type = cpu_to_le16(LOG_SYNCPT);
		lrd.length = 0;
		lrd.log.syncpt.sync = 0;
		lsn = lmWriteRecord(log, NULL, &lrd, NULL);
		bp = log->bp;
		bp->l_ceor = bp->l_eor;
		lp = (struct logpage *) bp->l_ldata;
		lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_eor);
		lbmWrite(log, bp, lbmWRITE | lbmSYNC, 0);
		if ((rc = lbmIOWait(bp, 0)))
			goto errout30;

		/*
		 * update/write superblock
		 */
		logsuper->state = cpu_to_le32(LOGMOUNT);
		log->serial = le32_to_cpu(logsuper->serial) + 1;
		logsuper->serial = cpu_to_le32(log->serial);
		lbmDirectWrite(log, bpsuper, lbmWRITE | lbmRELEASE | lbmSYNC);
		if ((rc = lbmIOWait(bpsuper, lbmFREE)))
			goto errout30;
	}

	/* initialize logsync parameters */
	log->logsize = (log->size - 2) << L2LOGPSIZE;
	log->lsn = lsn;
	log->syncpt = lsn;
	log->sync = log->syncpt;
	log->nextsync = LOGSYNC_DELTA(log->logsize);

	jfs_info("lmLogInit: lsn:0x%x syncpt:0x%x sync:0x%x",
		 log->lsn, log->syncpt, log->sync);

	/*
	 * initialize for lazy/group commit
	 */
	log->clsn = lsn;

	return 0;

	/*
	 *	unwind on error
	 */
      errout30:		/* release log page */
	log->wqueue = NULL;
	bp->l_wqnext = NULL;
	lbmFree(bp);

      errout20:		/* release log superblock */
	lbmFree(bpsuper);

      errout10:		/* unwind lbmLogInit() */
	lbmLogShutdown(log);

	jfs_warn("lmLogInit: exit(%d)", rc);
	return rc;
}


/*
 * NAME:	lmLogClose()
 *
 * FUNCTION:	remove file system <ipmnt> from active list of log <iplog>
 *		and close it on last close.
 *
 * PARAMETER:	sb	- superblock
 *
 * RETURN:	errors from subroutines
 *
 * serialization:
 */
int lmLogClose(struct super_block *sb)
{
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct jfs_log *log = sbi->log;
	struct block_device *bdev;
	int rc = 0;

	jfs_info("lmLogClose: log:0x%p", log);

	mutex_lock(&jfs_log_mutex);
	LOG_LOCK(log);
	list_del(&sbi->log_list);
	LOG_UNLOCK(log);
	sbi->log = NULL;

	/*
	 * We need to make sure all of the "written" metapages
	 * actually make it to disk
	 */
	sync_blockdev(sb->s_bdev);

	if (test_bit(log_INLINELOG, &log->flag)) {
		/*
		 *	in-line log in host file system
		 */
		rc = lmLogShutdown(log);
		kfree(log);
		goto out;
	}

	if (!log->no_integrity)
		lmLogFileSystem(log, sbi, 0);

	if (!list_empty(&log->sb_list))
		goto out;

	/*
	 * TODO: ensure that the dummy_log is in a state to allow
	 * lbmLogShutdown to deallocate all the buffers and call
	 * kfree against dummy_log.  For now, leave dummy_log & its
	 * buffers in memory, and resuse if another no-integrity mount
	 * is requested.
	 */
	if (log->no_integrity)
		goto out;

	/*
	 *	external log as separate logical volume
	 */
	list_del(&log->journal_list);
	bdev = log->bdev;
	rc = lmLogShutdown(log);

	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

	kfree(log);

      out:
	mutex_unlock(&jfs_log_mutex);
	jfs_info("lmLogClose: exit(%d)", rc);
	return rc;
}


/*
 * NAME:	jfs_flush_journal()
 *
 * FUNCTION:	initiate write of any outstanding transactions to the journal
 *		and optionally wait until they are all written to disk
 *
 *		wait == 0  flush until latest txn is committed, don't wait
 *		wait == 1  flush until latest txn is committed, wait
 *		wait > 1   flush until all txn's are complete, wait
 */
void jfs_flush_journal(struct jfs_log *log, int wait)
{
	int i;
	struct tblock *target = NULL;

	/* jfs_write_inode may call us during read-only mount */
	if (!log)
		return;

	jfs_info("jfs_flush_journal: log:0x%p wait=%d", log, wait);

	LOGGC_LOCK(log);

	if (!list_empty(&log->cqueue)) {
		/*
		 * This ensures that we will keep writing to the journal as long
		 * as there are unwritten commit records
		 */
		target = list_entry(log->cqueue.prev, struct tblock, cqueue);

		if (test_bit(log_FLUSH, &log->flag)) {
			/*
			 * We're already flushing.
			 * if flush_tblk is NULL, we are flushing everything,
			 * so leave it that way.  Otherwise, update it to the
			 * latest transaction
			 */
			if (log->flush_tblk)
				log->flush_tblk = target;
		} else {
			/* Only flush until latest transaction is committed */
			log->flush_tblk = target;
			set_bit(log_FLUSH, &log->flag);

			/*
			 * Initiate I/O on outstanding transactions
			 */
			if (!(log->cflag & logGC_PAGEOUT)) {
				log->cflag |= logGC_PAGEOUT;
				lmGCwrite(log, 0);
			}
		}
	}
	if ((wait > 1) || test_bit(log_SYNCBARRIER, &log->flag)) {
		/* Flush until all activity complete */
		set_bit(log_FLUSH, &log->flag);
		log->flush_tblk = NULL;
	}

	if (wait && target && !(target->flag & tblkGC_COMMITTED)) {
		DECLARE_WAITQUEUE(__wait, current);

		add_wait_queue(&target->gcwait, &__wait);
		set_current_state(TASK_UNINTERRUPTIBLE);
		LOGGC_UNLOCK(log);
		schedule();
		LOGGC_LOCK(log);
		remove_wait_queue(&target->gcwait, &__wait);
	}
	LOGGC_UNLOCK(log);

	if (wait < 2)
		return;

	write_special_inodes(log, filemap_fdatawrite);

	/*
	 * If there was recent activity, we may need to wait
	 * for the lazycommit thread to catch up
	 */
	if ((!list_empty(&log->cqueue)) || !list_empty(&log->synclist)) {
		for (i = 0; i < 200; i++) {	/* Too much? */
			msleep(250);
			write_special_inodes(log, filemap_fdatawrite);
			if (list_empty(&log->cqueue) &&
			    list_empty(&log->synclist))
				break;
		}
	}
	assert(list_empty(&log->cqueue));

#ifdef CONFIG_JFS_DEBUG
	if (!list_empty(&log->synclist)) {
		struct logsyncblk *lp;

		printk(KERN_ERR "jfs_flush_journal: synclist not empty\n");
		list_for_each_entry(lp, &log->synclist, synclist) {
			if (lp->xflag & COMMIT_PAGE) {
				struct metapage *mp = (struct metapage *)lp;
				print_hex_dump(KERN_ERR, "metapage: ",
					       DUMP_PREFIX_ADDRESS, 16, 4,
					       mp, sizeof(struct metapage), 0);
				print_hex_dump(KERN_ERR, "page: ",
					       DUMP_PREFIX_ADDRESS, 16,
					       sizeof(long), mp->page,
					       sizeof(struct page), 0);
			} else
				print_hex_dump(KERN_ERR, "tblock:",
					       DUMP_PREFIX_ADDRESS, 16, 4,
					       lp, sizeof(struct tblock), 0);
		}
	}
#else
	WARN_ON(!list_empty(&log->synclist));
#endif
	clear_bit(log_FLUSH, &log->flag);
}

/*
 * NAME:	lmLogShutdown()
 *
 * FUNCTION:	log shutdown at last LogClose().
 *
 *		write log syncpt record.
 *		update super block to set redone flag to 0.
 *
 * PARAMETER:	log	- log inode
 *
 * RETURN:	0	- success
 *
 * serialization: single last close thread
 */
int lmLogShutdown(struct jfs_log * log)
{
	int rc;
	struct lrd lrd;
	int lsn;
	struct logsuper *logsuper;
	struct lbuf *bpsuper;
	struct lbuf *bp;
	struct logpage *lp;

	jfs_info("lmLogShutdown: log:0x%p", log);

	jfs_flush_journal(log, 2);

	/*
	 * write the last SYNCPT record with syncpoint = 0
	 * (i.e., log redo up to HERE !)
	 */
	lrd.logtid = 0;
	lrd.backchain = 0;
	lrd.type = cpu_to_le16(LOG_SYNCPT);
	lrd.length = 0;
	lrd.log.syncpt.sync = 0;

	lsn = lmWriteRecord(log, NULL, &lrd, NULL);
	bp = log->bp;
	lp = (struct logpage *) bp->l_ldata;
	lp->h.eor = lp->t.eor = cpu_to_le16(bp->l_eor);
	lbmWrite(log, log->bp, lbmWRITE | lbmRELEASE | lbmSYNC, 0);
	lbmIOWait(log->bp, lbmFREE);
	log->bp = NULL;

	/*
	 * synchronous update log superblock
	 * mark log state as shutdown cleanly
	 * (i.e., Log does not need to be replayed).
	 */
	if ((rc = lbmRead(log, 1, &bpsuper)))
		goto out;

	logsuper = (struct logsuper *) bpsuper->l_ldata;
	logsuper->state = cpu_to_le32(LOGREDONE);
	logsuper->end = cpu_to_le32(lsn);
	lbmDirectWrite(log, bpsuper, lbmWRITE | lbmRELEASE | lbmSYNC);
	rc = lbmIOWait(bpsuper, lbmFREE);

	jfs_info("lmLogShutdown: lsn:0x%x page:%d eor:%d",
		 lsn, log->page, log->eor);

      out:
	/*
	 * shutdown per log i/o
	 */
	lbmLogShutdown(log);

	if (rc) {
		jfs_warn("lmLogShutdown: exit(%d)", rc);
	}
	return rc;
}


/*
 * NAME:	lmLogFileSystem()
 *
 * FUNCTION:	insert (<activate> = true)/remove (<activate> = false)
 *	file system into/from log active file system list.
 *
 * PARAMETE:	log	- pointer to logs inode.
 *		fsdev	- kdev_t of filesystem.
 *		serial	- pointer to returned log serial number
 *		activate - insert/remove device from active list.
 *
 * RETURN:	0	- success
 *		errors returned by vms_iowait().
 */
static int lmLogFileSystem(struct jfs_log * log, struct jfs_sb_info *sbi,
			   int activate)
{
	int rc = 0;
	int i;
	struct logsuper *logsuper;
	struct lbuf *bpsuper;
	char *uuid = sbi->uuid;

	/*
	 * insert/remove file system device to log active file system list.
	 */
	if ((rc = lbmRead(log, 1, &bpsuper)))
		return rc;

	logsuper = (struct logsuper *) bpsuper->l_ldata;
	if (activate) {
		for (i = 0; i < MAX_ACTIVE; i++)
			if (!memcmp(logsuper->active[i].uuid, NULL_UUID, 16)) {
				memcpy(logsuper->active[i].uuid, uuid, 16);
				sbi->aggregate = i;
				break;
			}
		if (i == MAX_ACTIVE) {
			jfs_warn("Too many file systems sharing journal!");
			lbmFree(bpsuper);
			return -EMFILE;	/* Is there a better rc? */
		}
	} else {
		for (i = 0; i < MAX_ACTIVE; i++)
			if (!memcmp(logsuper->active[i].uuid, uuid, 16)) {
				memcpy(logsuper->active[i].uuid, NULL_UUID, 16);
				break;
			}
		if (i == MAX_ACTIVE) {
			jfs_warn("Somebody stomped on the journal!");
			lbmFree(bpsuper);
			return -EIO;
		}

	}

	/*
	 * synchronous write log superblock:
	 *
	 * write sidestream bypassing write queue:
	 * at file system mount, log super block is updated for
	 * activation of the file system before any log record
	 * (MOUNT record) of the file system, and at file system
	 * unmount, all meta data for the file system has been
	 * flushed before log super block is updated for deactivation
	 * of the file system.
	 */
	lbmDirectWrite(log, bpsuper, lbmWRITE | lbmRELEASE | lbmSYNC);
	rc = lbmIOWait(bpsuper, lbmFREE);

	return rc;
}

/*
 *		log buffer manager (lbm)
 *		------------------------
 *
 * special purpose buffer manager supporting log i/o requirements.
 *
 * per log write queue:
 * log pageout occurs in serial order by fifo write queue and
 * restricting to a single i/o in pregress at any one time.
 * a circular singly-linked list
 * (log->wrqueue points to the tail, and buffers are linked via
 * bp->wrqueue field), and
 * maintains log page in pageout ot waiting for pageout in serial pageout.
 */

/*
 *	lbmLogInit()
 *
 * initialize per log I/O setup at lmLogInit()
 */
static int lbmLogInit(struct jfs_log * log)
{				/* log inode */
	int i;
	struct lbuf *lbuf;

	jfs_info("lbmLogInit: log:0x%p", log);

	/* initialize current buffer cursor */
	log->bp = NULL;

	/* initialize log device write queue */
	log->wqueue = NULL;

	/*
	 * Each log has its own buffer pages allocated to it.  These are
	 * not managed by the page cache.  This ensures that a transaction
	 * writing to the log does not block trying to allocate a page from
	 * the page cache (for the log).  This would be bad, since page
	 * allocation waits on the kswapd thread that may be committing inodes
	 * which would cause log activity.  Was that clear?  I'm trying to
	 * avoid deadlock here.
	 */
	init_waitqueue_head(&log->free_wait);

	log->lbuf_free = NULL;

	for (i = 0; i < LOGPAGES;) {
		char *buffer;
		uint offset;
		struct page *page;

		buffer = (char *) get_zeroed_page(GFP_KERNEL);
		if (buffer == NULL)
			goto error;
		page = virt_to_page(buffer);
		for (offset = 0; offset < PAGE_SIZE; offset += LOGPSIZE) {
			lbuf = kmalloc(sizeof(struct lbuf), GFP_KERNEL);
			if (lbuf == NULL) {
				if (offset == 0)
					free_page((unsigned long) buffer);
				goto error;
			}
			if (offset) /* we already have one reference */
				get_page(page);
			lbuf->l_offset = offset;
			lbuf->l_ldata = buffer + offset;
			lbuf->l_page = page;
			lbuf->l_log = log;
			init_waitqueue_head(&lbuf->l_ioevent);

			lbuf->l_freelist = log->lbuf_free;
			log->lbuf_free = lbuf;
			i++;
		}
	}

	return (0);

      error:
	lbmLogShutdown(log);
	return -ENOMEM;
}


/*
 *	lbmLogShutdown()
 *
 * finalize per log I/O setup at lmLogShutdown()
 */
static void lbmLogShutdown(struct jfs_log * log)
{
	struct lbuf *lbuf;

	jfs_info("lbmLogShutdown: log:0x%p", log);

	lbuf = log->lbuf_free;
	while (lbuf) {
		struct lbuf *next = lbuf->l_freelist;
		__free_page(lbuf->l_page);
		kfree(lbuf);
		lbuf = next;
	}
}


/*
 *	lbmAllocate()
 *
 * allocate an empty log buffer
 */
static struct lbuf *lbmAllocate(struct jfs_log * log, int pn)
{
	struct lbuf *bp;
	unsigned long flags;

	/*
	 * recycle from log buffer freelist if any
	 */
	LCACHE_LOCK(flags);
	LCACHE_SLEEP_COND(log->free_wait, (bp = log->lbuf_free), flags);
	log->lbuf_free = bp->l_freelist;
	LCACHE_UNLOCK(flags);

	bp->l_flag = 0;

	bp->l_wqnext = NULL;
	bp->l_freelist = NULL;

	bp->l_pn = pn;
	bp->l_blkno = log->base + (pn << (L2LOGPSIZE - log->l2bsize));
	bp->l_ceor = 0;

	return bp;
}


/*
 *	lbmFree()
 *
 * release a log buffer to freelist
 */
static void lbmFree(struct lbuf * bp)
{
	unsigned long flags;

	LCACHE_LOCK(flags);

	lbmfree(bp);

	LCACHE_UNLOCK(flags);
}

static void lbmfree(struct lbuf * bp)
{
	struct jfs_log *log = bp->l_log;

	assert(bp->l_wqnext == NULL);

	/*
	 * return the buffer to head of freelist
	 */
	bp->l_freelist = log->lbuf_free;
	log->lbuf_free = bp;

	wake_up(&log->free_wait);
	return;
}


/*
 * NAME:	lbmRedrive
 *
 * FUNCTION:	add a log buffer to the log redrive list
 *
 * PARAMETER:
 *	bp	- log buffer
 *
 * NOTES:
 *	Takes log_redrive_lock.
 */
static inline void lbmRedrive(struct lbuf *bp)
{
	unsigned long flags;

	spin_lock_irqsave(&log_redrive_lock, flags);
	bp->l_redrive_next = log_redrive_list;
	log_redrive_list = bp;
	spin_unlock_irqrestore(&log_redrive_lock, flags);

	wake_up_process(jfsIOthread);
}


/*
 *	lbmRead()
 */
static int lbmRead(struct jfs_log * log, int pn, struct lbuf ** bpp)
{
	struct bio *bio;
	struct lbuf *bp;

	/*
	 * allocate a log buffer
	 */
	*bpp = bp = lbmAllocate(log, pn);
	jfs_info("lbmRead: bp:0x%p pn:0x%x", bp, pn);

	bp->l_flag |= lbmREAD;

	bio = bio_alloc(GFP_NOFS, 1);

	bio->bi_iter.bi_sector = bp->l_blkno << (log->l2bsize - 9);
	bio->bi_bdev = log->bdev;
	bio->bi_io_vec[0].bv_page = bp->l_page;
	bio->bi_io_vec[0].bv_len = LOGPSIZE;
	bio->bi_io_vec[0].bv_offset = bp->l_offset;

	bio->bi_vcnt = 1;
	bio->bi_iter.bi_size = LOGPSIZE;

	bio->bi_end_io = lbmIODone;
	bio->bi_private = bp;
	/*check if journaling to disk has been disabled*/
	if (log->no_integrity) {
		bio->bi_iter.bi_size = 0;
		lbmIODone(bio, 0);
	} else {
		submit_bio(READ_SYNC, bio);
	}

	wait_event(bp->l_ioevent, (bp->l_flag != lbmREAD));

	return 0;
}


/*
 *	lbmWrite()
 *
 * buffer at head of pageout queue stays after completion of
 * partial-page pageout and redriven by explicit initiation of
 * pageout by caller until full-page pageout is completed and
 * released.
 *
 * device driver i/o done redrives pageout of new buffer at
 * head of pageout queue when current buffer at head of pageout
 * queue is released at the completion of its full-page pageout.
 *
 * LOGGC_LOCK() serializes lbmWrite() by lmNextPage() and lmGroupCommit().
 * LCACHE_LOCK() serializes xflag between lbmWrite() and lbmIODone()
 */
static void lbmWrite(struct jfs_log * log, struct lbuf * bp, int flag,
		     int cant_block)
{
	struct lbuf *tail;
	unsigned long flags;

	jfs_info("lbmWrite: bp:0x%p flag:0x%x pn:0x%x", bp, flag, bp->l_pn);

	/* map the logical block address to physical block address */
	bp->l_blkno =
	    log->base + (bp->l_pn << (L2LOGPSIZE - log->l2bsize));

	LCACHE_LOCK(flags);		/* disable+lock */

	/*
	 * initialize buffer for device driver
	 */
	bp->l_flag = flag;

	/*
	 *	insert bp at tail of write queue associated with log
	 *
	 * (request is either for bp already/currently at head of queue
	 * or new bp to be inserted at tail)
	 */
	tail = log->wqueue;

	/* is buffer not already on write queue ? */
	if (bp->l_wqnext == NULL) {
		/* insert at tail of wqueue */
		if (tail == NULL) {
			log->wqueue = bp;
			bp->l_wqnext = bp;
		} else {
			log->wqueue = bp;
			bp->l_wqnext = tail->l_wqnext;
			tail->l_wqnext = bp;
		}

		tail = bp;
	}

	/* is buffer at head of wqueue and for write ? */
	if ((bp != tail->l_wqnext) || !(flag & lbmWRITE)) {
		LCACHE_UNLOCK(flags);	/* unlock+enable */
		return;
	}

	LCACHE_UNLOCK(flags);	/* unlock+enable */

	if (cant_block)
		lbmRedrive(bp);
	else if (flag & lbmSYNC)
		lbmStartIO(bp);
	else {
		LOGGC_UNLOCK(log);
		lbmStartIO(bp);
		LOGGC_LOCK(log);
	}
}


/*
 *	lbmDirectWrite()
 *
 * initiate pageout bypassing write queue for sidestream
 * (e.g., log superblock) write;
 */
static void lbmDirectWrite(struct jfs_log * log, struct lbuf * bp, int flag)
{
	jfs_info("lbmDirectWrite: bp:0x%p flag:0x%x pn:0x%x",
		 bp, flag, bp->l_pn);

	/*
	 * initialize buffer for device driver
	 */
	bp->l_flag = flag | lbmDIRECT;

	/* map the logical block address to physical block address */
	bp->l_blkno =
	    log->base + (bp->l_pn << (L2LOGPSIZE - log->l2bsize));

	/*
	 *	initiate pageout of the page
	 */
	lbmStartIO(bp);
}


/*
 * NAME:	lbmStartIO()
 *
 * FUNCTION:	Interface to DD strategy routine
 *
 * RETURN:	none
 *
 * serialization: LCACHE_LOCK() is NOT held during log i/o;
 */
static void lbmStartIO(struct lbuf * bp)
{
	struct bio *bio;
	struct jfs_log *log = bp->l_log;

	jfs_info("lbmStartIO\n");

	bio = bio_alloc(GFP_NOFS, 1);
	bio->bi_iter.bi_sector = bp->l_blkno << (log->l2bsize - 9);
	bio->bi_bdev = log->bdev;
	bio->bi_io_vec[0].bv_page = bp->l_page;
	bio->bi_io_vec[0].bv_len = LOGPSIZE;
	bio->bi_io_vec[0].bv_offset = bp->l_offset;

	bio->bi_vcnt = 1;
	bio->bi_iter.bi_size = LOGPSIZE;

	bio->bi_end_io = lbmIODone;
	bio->bi_private = bp;

	/* check if journaling to disk has been disabled */
	if (log->no_integrity) {
		bio->bi_iter.bi_size = 0;
		lbmIODone(bio, 0);
	} else {
		submit_bio(WRITE_SYNC, bio);
		INCREMENT(lmStat.submitted);
	}
}


/*
 *	lbmIOWait()
 */
static int lbmIOWait(struct lbuf * bp, int flag)
{
	unsigned long flags;
	int rc = 0;

	jfs_info("lbmIOWait1: bp:0x%p flag:0x%x:0x%x", bp, bp->l_flag, flag);

	LCACHE_LOCK(flags);		/* disable+lock */

	LCACHE_SLEEP_COND(bp->l_ioevent, (bp->l_flag & lbmDONE), flags);

	rc = (bp->l_flag & lbmERROR) ? -EIO : 0;

	if (flag & lbmFREE)
		lbmfree(bp);

	LCACHE_UNLOCK(flags);	/* unlock+enable */

	jfs_info("lbmIOWait2: bp:0x%p flag:0x%x:0x%x", bp, bp->l_flag, flag);
	return rc;
}

/*
 *	lbmIODone()
 *
 * executed at INTIODONE level
 */
static void lbmIODone(struct bio *bio, int error)
{
	struct lbuf *bp = bio->bi_private;
	struct lbuf *nextbp, *tail;
	struct jfs_log *log;
	unsigned long flags;

	/*
	 * get back jfs buffer bound to the i/o buffer
	 */
	jfs_info("lbmIODone: bp:0x%p flag:0x%x", bp, bp->l_flag);

	LCACHE_LOCK(flags);		/* disable+lock */

	bp->l_flag |= lbmDONE;

	if (!test_bit(BIO_UPTODATE, &bio->bi_flags)) {
		bp->l_flag |= lbmERROR;

		jfs_err("lbmIODone: I/O error in JFS log");
	}

	bio_put(bio);

	/*
	 *	pagein completion
	 */
	if (bp->l_flag & lbmREAD) {
		bp->l_flag &= ~lbmREAD;

		LCACHE_UNLOCK(flags);	/* unlock+enable */

		/* wakeup I/O initiator */
		LCACHE_WAKEUP(&bp->l_ioevent);

		return;
	}

	/*
	 *	pageout completion
	 *
	 * the bp at the head of write queue has completed pageout.
	 *
	 * if single-commit/full-page pageout, remove the current buffer
	 * from head of pageout queue, and redrive pageout with
	 * the new buffer at head of pageout queue;
	 * otherwise, the partial-page pageout buffer stays at
	 * the head of pageout queue to be redriven for pageout
	 * by lmGroupCommit() until full-page pageout is completed.
	 */
	bp->l_flag &= ~lbmWRITE;
	INCREMENT(lmStat.pagedone);

	/* update committed lsn */
	log = bp->l_log;
	log->clsn = (bp->l_pn << L2LOGPSIZE) + bp->l_ceor;

	if (bp->l_flag & lbmDIRECT) {
		LCACHE_WAKEUP(&bp->l_ioevent);
		LCACHE_UNLOCK(flags);
		return;
	}

	tail = log->wqueue;

	/* single element queue */
	if (bp == tail) {
		/* remove head buffer of full-page pageout
		 * from log device write queue
		 */
		if (bp->l_flag & lbmRELEASE) {
			log->wqueue = NULL;
			bp->l_wqnext = NULL;
		}
	}
	/* multi element queue */
	else {
		/* remove head buffer of full-page pageout
		 * from log device write queue
		 */
		if (bp->l_flag & lbmRELEASE) {
			nextbp = tail->l_wqnext = bp->l_wqnext;
			bp->l_wqnext = NULL;

			/*
			 * redrive pageout of next page at head of write queue:
			 * redrive next page without any bound tblk
			 * (i.e., page w/o any COMMIT records), or
			 * first page of new group commit which has been
			 * queued after current page (subsequent pageout
			 * is performed synchronously, except page without
			 * any COMMITs) by lmGroupCommit() as indicated
			 * by lbmWRITE flag;
			 */
			if (nextbp->l_flag & lbmWRITE) {
				/*
				 * We can't do the I/O at interrupt time.
				 * The jfsIO thread can do it
				 */
				lbmRedrive(nextbp);
			}
		}
	}

	/*
	 *	synchronous pageout:
	 *
	 * buffer has not necessarily been removed from write queue
	 * (e.g., synchronous write of partial-page with COMMIT):
	 * leave buffer for i/o initiator to dispose
	 */
	if (bp->l_flag & lbmSYNC) {
		LCACHE_UNLOCK(flags);	/* unlock+enable */

		/* wakeup I/O initiator */
		LCACHE_WAKEUP(&bp->l_ioevent);
	}

	/*
	 *	Group Commit pageout:
	 */
	else if (bp->l_flag & lbmGC) {
		LCACHE_UNLOCK(flags);
		lmPostGC(bp);
	}

	/*
	 *	asynchronous pageout:
	 *
	 * buffer must have been removed from write queue:
	 * insert buffer at head of freelist where it can be recycled
	 */
	else {
		assert(bp->l_flag & lbmRELEASE);
		assert(bp->l_flag & lbmFREE);
		lbmfree(bp);

		LCACHE_UNLOCK(flags);	/* unlock+enable */
	}
}

int jfsIOWait(void *arg)
{
	struct lbuf *bp;

	do {
		spin_lock_irq(&log_redrive_lock);
		while ((bp = log_redrive_list)) {
			log_redrive_list = bp->l_redrive_next;
			bp->l_redrive_next = NULL;
			spin_unlock_irq(&log_redrive_lock);
			lbmStartIO(bp);
			spin_lock_irq(&log_redrive_lock);
		}

		if (freezing(current)) {
			spin_unlock_irq(&log_redrive_lock);
			try_to_freeze();
		} else {
			set_current_state(TASK_INTERRUPTIBLE);
			spin_unlock_irq(&log_redrive_lock);
			schedule();
		}
	} while (!kthread_should_stop());

	jfs_info("jfsIOWait being killed!");
	return 0;
}

/*
 * NAME:	lmLogFormat()/jfs_logform()
 *
 * FUNCTION:	format file system log
 *
 * PARAMETERS:
 *	log	- volume log
 *	logAddress - start address of log space in FS block
 *	logSize	- length of log space in FS block;
 *
 * RETURN:	0	- success
 *		-EIO	- i/o error
 *
 * XXX: We're synchronously writing one page at a time.  This needs to
 *	be improved by writing multiple pages at once.
 */
int lmLogFormat(struct jfs_log *log, s64 logAddress, int logSize)
{
	int rc = -EIO;
	struct jfs_sb_info *sbi;
	struct logsuper *logsuper;
	struct logpage *lp;
	int lspn;		/* log sequence page number */
	struct lrd *lrd_ptr;
	int npages = 0;
	struct lbuf *bp;

	jfs_info("lmLogFormat: logAddress:%Ld logSize:%d",
		 (long long)logAddress, logSize);

	sbi = list_entry(log->sb_list.next, struct jfs_sb_info, log_list);

	/* allocate a log buffer */
	bp = lbmAllocate(log, 1);

	npages = logSize >> sbi->l2nbperpage;

	/*
	 *	log space:
	 *
	 * page 0 - reserved;
	 * page 1 - log superblock;
	 * page 2 - log data page: A SYNC log record is written
	 *	    into this page at logform time;
	 * pages 3-N - log data page: set to empty log data pages;
	 */
	/*
	 *	init log superblock: log page 1
	 */
	logsuper = (struct logsuper *) bp->l_ldata;

	logsuper->magic = cpu_to_le32(LOGMAGIC);
	logsuper->version = cpu_to_le32(LOGVERSION);
	logsuper->state = cpu_to_le32(LOGREDONE);
	logsuper->flag = cpu_to_le32(sbi->mntflag);	/* ? */
	logsuper->size = cpu_to_le32(npages);
	logsuper->bsize = cpu_to_le32(sbi->bsize);
	logsuper->l2bsize = cpu_to_le32(sbi->l2bsize);
	logsuper->end = cpu_to_le32(2 * LOGPSIZE + LOGPHDRSIZE + LOGRDSIZE);

	bp->l_flag = lbmWRITE | lbmSYNC | lbmDIRECT;
	bp->l_blkno = logAddress + sbi->nbperpage;
	lbmStartIO(bp);
	if ((rc = lbmIOWait(bp, 0)))
		goto exit;

	/*
	 *	init pages 2 to npages-1 as log data pages:
	 *
	 * log page sequence number (lpsn) initialization:
	 *
	 * pn:   0     1     2     3                 n-1
	 *       +-----+-----+=====+=====+===.....===+=====+
	 * lspn:             N-1   0     1           N-2
	 *                   <--- N page circular file ---->
	 *
	 * the N (= npages-2) data pages of the log is maintained as
	 * a circular file for the log records;
	 * lpsn grows by 1 monotonically as each log page is written
	 * to the circular file of the log;
	 * and setLogpage() will not reset the page number even if
	 * the eor is equal to LOGPHDRSIZE. In order for binary search
	 * still work in find log end process, we have to simulate the
	 * log wrap situation at the log format time.
	 * The 1st log page written will have the highest lpsn. Then
	 * the succeeding log pages will have ascending order of
	 * the lspn starting from 0, ... (N-2)
	 */
	lp = (struct logpage *) bp->l_ldata;
	/*
	 * initialize 1st log page to be written: lpsn = N - 1,
	 * write a SYNCPT log record is written to this page
	 */
	lp->h.page = lp->t.page = cpu_to_le32(npages - 3);
	lp->h.eor = lp->t.eor = cpu_to_le16(LOGPHDRSIZE + LOGRDSIZE);

	lrd_ptr = (struct lrd *) &lp->data;
	lrd_ptr->logtid = 0;
	lrd_ptr->backchain = 0;
	lrd_ptr->type = cpu_to_le16(LOG_SYNCPT);
	lrd_ptr->length = 0;
	lrd_ptr->log.syncpt.sync = 0;

	bp->l_blkno += sbi->nbperpage;
	bp->l_flag = lbmWRITE | lbmSYNC | lbmDIRECT;
	lbmStartIO(bp);
	if ((rc = lbmIOWait(bp, 0)))
		goto exit;

	/*
	 *	initialize succeeding log pages: lpsn = 0, 1, ..., (N-2)
	 */
	for (lspn = 0; lspn < npages - 3; lspn++) {
		lp->h.page = lp->t.page = cpu_to_le32(lspn);
		lp->h.eor = lp->t.eor = cpu_to_le16(LOGPHDRSIZE);

		bp->l_blkno += sbi->nbperpage;
		bp->l_flag = lbmWRITE | lbmSYNC | lbmDIRECT;
		lbmStartIO(bp);
		if ((rc = lbmIOWait(bp, 0)))
			goto exit;
	}

	rc = 0;
exit:
	/*
	 *	finalize log
	 */
	/* release the buffer */
	lbmFree(bp);

	return rc;
}

#ifdef CONFIG_JFS_STATISTICS
static int jfs_lmstats_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		       "JFS Logmgr stats\n"
		       "================\n"
		       "commits = %d\n"
		       "writes submitted = %d\n"
		       "writes completed = %d\n"
		       "full pages submitted = %d\n"
		       "partial pages submitted = %d\n",
		       lmStat.commit,
		       lmStat.submitted,
		       lmStat.pagedone,
		       lmStat.full_page,
		       lmStat.partial_page);
	return 0;
}

static int jfs_lmstats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, jfs_lmstats_proc_show, NULL);
}

const struct file_operations jfs_lmstats_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= jfs_lmstats_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif /* CONFIG_JFS_STATISTICS */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_logmgr.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2005
 *   Portions Copyright (C) Christoph Hellwig, 2001-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 *	jfs_txnmgr.c: transaction manager
 *
 * notes:
 * transaction starts with txBegin() and ends with txCommit()
 * or txAbort().
 *
 * tlock is acquired at the time of update;
 * (obviate scan at commit time for xtree and dtree)
 * tlock and mp points to each other;
 * (no hashlist for mp -> tlock).
 *
 * special cases:
 * tlock on in-memory inode:
 * in-place tlock in the in-memory inode itself;
 * converted to page lock by iWrite() at commit time.
 *
 * tlock during write()/mmap() under anonymous transaction (tid = 0):
 * transferred (?) to transaction at commit time.
 *
 * use the page itself to update allocation maps
 * (obviate intermediate replication of allocation/deallocation data)
 * hold on to mp+lock thru update of maps
 */

// #include <linux/fs.h>
#include <linux/vmalloc.h>
// #include <linux/completion.h>
// #include <linux/freezer.h>
// #include <linux/module.h>
// #include <linux/moduleparam.h>
// #include <linux/kthread.h>
// #include <linux/seq_file.h>
// #include "jfs_incore.h"
// #include "jfs_inode.h"
// #include "jfs_filsys.h"
// #include "jfs_metapage.h"
// #include "jfs_dinode.h"
// #include "jfs_imap.h"
// #include "jfs_dmap.h"
// #include "jfs_superblock.h"
// #include "jfs_debug.h"
#include "../../inc/__fss.h"

/*
 *	transaction management structures
 */
static struct {
	int freetid;		/* index of a free tid structure */
	int freelock;		/* index first free lock word */
	wait_queue_head_t freewait;	/* eventlist of free tblock */
	wait_queue_head_t freelockwait;	/* eventlist of free tlock */
	wait_queue_head_t lowlockwait;	/* eventlist of ample tlocks */
	int tlocksInUse;	/* Number of tlocks in use */
	spinlock_t LazyLock;	/* synchronize sync_queue & unlock_queue */
/*	struct tblock *sync_queue; * Transactions waiting for data sync */
	struct list_head unlock_queue;	/* Txns waiting to be released */
	struct list_head anon_list;	/* inodes having anonymous txns */
	struct list_head anon_list2;	/* inodes having anonymous txns
					   that couldn't be sync'ed */
} TxAnchor;

int jfs_tlocks_low;		/* Indicates low number of available tlocks */

#ifdef CONFIG_JFS_STATISTICS
static struct {
	uint txBegin;
	uint txBegin_barrier;
	uint txBegin_lockslow;
	uint txBegin_freetid;
	uint txBeginAnon;
	uint txBeginAnon_barrier;
	uint txBeginAnon_lockslow;
	uint txLockAlloc;
	uint txLockAlloc_freelock;
} TxStat;
#endif

static int nTxBlock = -1;	/* number of transaction blocks */
module_param(nTxBlock, int, 0);
MODULE_PARM_DESC(nTxBlock,
		 "Number of transaction blocks (max:65536)");

static int nTxLock = -1;	/* number of transaction locks */
module_param(nTxLock, int, 0);
MODULE_PARM_DESC(nTxLock,
		 "Number of transaction locks (max:65536)");

struct tblock *TxBlock;	/* transaction block table */
static int TxLockLWM;	/* Low water mark for number of txLocks used */
static int TxLockHWM;	/* High water mark for number of txLocks used */
static int TxLockVHWM;	/* Very High water mark */
struct tlock *TxLock;	/* transaction lock table */

/*
 *	transaction management lock
 */
static DEFINE_SPINLOCK(jfsTxnLock);

#define TXN_LOCK()		spin_lock(&jfsTxnLock)
#define TXN_UNLOCK()		spin_unlock(&jfsTxnLock)

#define LAZY_LOCK_INIT()	spin_lock_init(&TxAnchor.LazyLock);
#define LAZY_LOCK(flags)	spin_lock_irqsave(&TxAnchor.LazyLock, flags)
#define LAZY_UNLOCK(flags) spin_unlock_irqrestore(&TxAnchor.LazyLock, flags)

static DECLARE_WAIT_QUEUE_HEAD(jfs_commit_thread_wait);
static int jfs_commit_thread_waking;

/*
 * Retry logic exist outside these macros to protect from spurrious wakeups.
 */
static inline void TXN_SLEEP_DROP_LOCK(wait_queue_head_t * event)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(event, &wait);
	set_current_state(TASK_UNINTERRUPTIBLE);
	TXN_UNLOCK();
	io_schedule();
	remove_wait_queue(event, &wait);
}

#define TXN_SLEEP(event)\
{\
	TXN_SLEEP_DROP_LOCK(event);\
	TXN_LOCK();\
}

#define TXN_WAKEUP(event) wake_up_all(event)

/*
 *	statistics
 */
static struct {
	tid_t maxtid;		/* 4: biggest tid ever used */
	lid_t maxlid;		/* 4: biggest lid ever used */
	int ntid;		/* 4: # of transactions performed */
	int nlid;		/* 4: # of tlocks acquired */
	int waitlock;		/* 4: # of tlock wait */
} stattx;

/*
 * forward references
 */
static int diLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
		struct tlock * tlck, struct commit * cd);
static int dataLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
		struct tlock * tlck);
static void dtLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
		struct tlock * tlck);
static void mapLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
		struct tlock * tlck);
static void txAllocPMap(struct inode *ip, struct maplock * maplock,
		struct tblock * tblk);
static void txForce(struct tblock * tblk);
static int txLog(struct jfs_log * log, struct tblock * tblk,
		struct commit * cd);
static void txUpdateMap(struct tblock * tblk);
static void txRelease(struct tblock * tblk);
static void xtLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
	   struct tlock * tlck);
static void LogSyncRelease(struct metapage * mp);

/*
 *		transaction block/lock management
 *		---------------------------------
 */

/*
 * Get a transaction lock from the free list.  If the number in use is
 * greater than the high water mark, wake up the sync daemon.  This should
 * free some anonymous transaction locks.  (TXN_LOCK must be held.)
 */
static lid_t txLockAlloc(void)
{
	lid_t lid;

	INCREMENT(TxStat.txLockAlloc);
	if (!TxAnchor.freelock) {
		INCREMENT(TxStat.txLockAlloc_freelock);
	}

	while (!(lid = TxAnchor.freelock))
		TXN_SLEEP(&TxAnchor.freelockwait);
	TxAnchor.freelock = TxLock[lid].next;
	HIGHWATERMARK(stattx.maxlid, lid);
	if ((++TxAnchor.tlocksInUse > TxLockHWM) && (jfs_tlocks_low == 0)) {
		jfs_info("txLockAlloc tlocks low");
		jfs_tlocks_low = 1;
		wake_up_process(jfsSyncThread);
	}

	return lid;
}

static void txLockFree(lid_t lid)
{
	TxLock[lid].tid = 0;
	TxLock[lid].next = TxAnchor.freelock;
	TxAnchor.freelock = lid;
	TxAnchor.tlocksInUse--;
	if (jfs_tlocks_low && (TxAnchor.tlocksInUse < TxLockLWM)) {
		jfs_info("txLockFree jfs_tlocks_low no more");
		jfs_tlocks_low = 0;
		TXN_WAKEUP(&TxAnchor.lowlockwait);
	}
	TXN_WAKEUP(&TxAnchor.freelockwait);
}

/*
 * NAME:	txInit()
 *
 * FUNCTION:	initialize transaction management structures
 *
 * RETURN:
 *
 * serialization: single thread at jfs_init()
 */
int txInit(void)
{
	int k, size;
	struct sysinfo si;

	/* Set defaults for nTxLock and nTxBlock if unset */

	if (nTxLock == -1) {
		if (nTxBlock == -1) {
			/* Base default on memory size */
			si_meminfo(&si);
			if (si.totalram > (256 * 1024)) /* 1 GB */
				nTxLock = 64 * 1024;
			else
				nTxLock = si.totalram >> 2;
		} else if (nTxBlock > (8 * 1024))
			nTxLock = 64 * 1024;
		else
			nTxLock = nTxBlock << 3;
	}
	if (nTxBlock == -1)
		nTxBlock = nTxLock >> 3;

	/* Verify tunable parameters */
	if (nTxBlock < 16)
		nTxBlock = 16;	/* No one should set it this low */
	if (nTxBlock > 65536)
		nTxBlock = 65536;
	if (nTxLock < 256)
		nTxLock = 256;	/* No one should set it this low */
	if (nTxLock > 65536)
		nTxLock = 65536;

	printk(KERN_INFO "JFS: nTxBlock = %d, nTxLock = %d\n",
	       nTxBlock, nTxLock);
	/*
	 * initialize transaction block (tblock) table
	 *
	 * transaction id (tid) = tblock index
	 * tid = 0 is reserved.
	 */
	TxLockLWM = (nTxLock * 4) / 10;
	TxLockHWM = (nTxLock * 7) / 10;
	TxLockVHWM = (nTxLock * 8) / 10;

	size = sizeof(struct tblock) * nTxBlock;
	TxBlock = vmalloc(size);
	if (TxBlock == NULL)
		return -ENOMEM;

	for (k = 1; k < nTxBlock - 1; k++) {
		TxBlock[k].next = k + 1;
		init_waitqueue_head(&TxBlock[k].gcwait);
		init_waitqueue_head(&TxBlock[k].waitor);
	}
	TxBlock[k].next = 0;
	init_waitqueue_head(&TxBlock[k].gcwait);
	init_waitqueue_head(&TxBlock[k].waitor);

	TxAnchor.freetid = 1;
	init_waitqueue_head(&TxAnchor.freewait);

	stattx.maxtid = 1;	/* statistics */

	/*
	 * initialize transaction lock (tlock) table
	 *
	 * transaction lock id = tlock index
	 * tlock id = 0 is reserved.
	 */
	size = sizeof(struct tlock) * nTxLock;
	TxLock = vmalloc(size);
	if (TxLock == NULL) {
		vfree(TxBlock);
		return -ENOMEM;
	}

	/* initialize tlock table */
	for (k = 1; k < nTxLock - 1; k++)
		TxLock[k].next = k + 1;
	TxLock[k].next = 0;
	init_waitqueue_head(&TxAnchor.freelockwait);
	init_waitqueue_head(&TxAnchor.lowlockwait);

	TxAnchor.freelock = 1;
	TxAnchor.tlocksInUse = 0;
	INIT_LIST_HEAD(&TxAnchor.anon_list);
	INIT_LIST_HEAD(&TxAnchor.anon_list2);

	LAZY_LOCK_INIT();
	INIT_LIST_HEAD(&TxAnchor.unlock_queue);

	stattx.maxlid = 1;	/* statistics */

	return 0;
}

/*
 * NAME:	txExit()
 *
 * FUNCTION:	clean up when module is unloaded
 */
void txExit(void)
{
	vfree(TxLock);
	TxLock = NULL;
	vfree(TxBlock);
	TxBlock = NULL;
}

/*
 * NAME:	txBegin()
 *
 * FUNCTION:	start a transaction.
 *
 * PARAMETER:	sb	- superblock
 *		flag	- force for nested tx;
 *
 * RETURN:	tid	- transaction id
 *
 * note: flag force allows to start tx for nested tx
 * to prevent deadlock on logsync barrier;
 */
tid_t txBegin(struct super_block *sb, int flag)
{
	tid_t t;
	struct tblock *tblk;
	struct jfs_log *log;

	jfs_info("txBegin: flag = 0x%x", flag);
	log = JFS_SBI(sb)->log;

	TXN_LOCK();

	INCREMENT(TxStat.txBegin);

      retry:
	if (!(flag & COMMIT_FORCE)) {
		/*
		 * synchronize with logsync barrier
		 */
		if (test_bit(log_SYNCBARRIER, &log->flag) ||
		    test_bit(log_QUIESCE, &log->flag)) {
			INCREMENT(TxStat.txBegin_barrier);
			TXN_SLEEP(&log->syncwait);
			goto retry;
		}
	}
	if (flag == 0) {
		/*
		 * Don't begin transaction if we're getting starved for tlocks
		 * unless COMMIT_FORCE or COMMIT_INODE (which may ultimately
		 * free tlocks)
		 */
		if (TxAnchor.tlocksInUse > TxLockVHWM) {
			INCREMENT(TxStat.txBegin_lockslow);
			TXN_SLEEP(&TxAnchor.lowlockwait);
			goto retry;
		}
	}

	/*
	 * allocate transaction id/block
	 */
	if ((t = TxAnchor.freetid) == 0) {
		jfs_info("txBegin: waiting for free tid");
		INCREMENT(TxStat.txBegin_freetid);
		TXN_SLEEP(&TxAnchor.freewait);
		goto retry;
	}

	tblk = tid_to_tblock(t);

	if ((tblk->next == 0) && !(flag & COMMIT_FORCE)) {
		/* Don't let a non-forced transaction take the last tblk */
		jfs_info("txBegin: waiting for free tid");
		INCREMENT(TxStat.txBegin_freetid);
		TXN_SLEEP(&TxAnchor.freewait);
		goto retry;
	}

	TxAnchor.freetid = tblk->next;

	/*
	 * initialize transaction
	 */

	/*
	 * We can't zero the whole thing or we screw up another thread being
	 * awakened after sleeping on tblk->waitor
	 *
	 * memset(tblk, 0, sizeof(struct tblock));
	 */
	tblk->next = tblk->last = tblk->xflag = tblk->flag = tblk->lsn = 0;

	tblk->sb = sb;
	++log->logtid;
	tblk->logtid = log->logtid;

	++log->active;

	HIGHWATERMARK(stattx.maxtid, t);	/* statistics */
	INCREMENT(stattx.ntid);	/* statistics */

	TXN_UNLOCK();

	jfs_info("txBegin: returning tid = %d", t);

	return t;
}

/*
 * NAME:	txBeginAnon()
 *
 * FUNCTION:	start an anonymous transaction.
 *		Blocks if logsync or available tlocks are low to prevent
 *		anonymous tlocks from depleting supply.
 *
 * PARAMETER:	sb	- superblock
 *
 * RETURN:	none
 */
void txBeginAnon(struct super_block *sb)
{
	struct jfs_log *log;

	log = JFS_SBI(sb)->log;

	TXN_LOCK();
	INCREMENT(TxStat.txBeginAnon);

      retry:
	/*
	 * synchronize with logsync barrier
	 */
	if (test_bit(log_SYNCBARRIER, &log->flag) ||
	    test_bit(log_QUIESCE, &log->flag)) {
		INCREMENT(TxStat.txBeginAnon_barrier);
		TXN_SLEEP(&log->syncwait);
		goto retry;
	}

	/*
	 * Don't begin transaction if we're getting starved for tlocks
	 */
	if (TxAnchor.tlocksInUse > TxLockVHWM) {
		INCREMENT(TxStat.txBeginAnon_lockslow);
		TXN_SLEEP(&TxAnchor.lowlockwait);
		goto retry;
	}
	TXN_UNLOCK();
}

/*
 *	txEnd()
 *
 * function: free specified transaction block.
 *
 *	logsync barrier processing:
 *
 * serialization:
 */
void txEnd(tid_t tid)
{
	struct tblock *tblk = tid_to_tblock(tid);
	struct jfs_log *log;

	jfs_info("txEnd: tid = %d", tid);
	TXN_LOCK();

	/*
	 * wakeup transactions waiting on the page locked
	 * by the current transaction
	 */
	TXN_WAKEUP(&tblk->waitor);

	log = JFS_SBI(tblk->sb)->log;

	/*
	 * Lazy commit thread can't free this guy until we mark it UNLOCKED,
	 * otherwise, we would be left with a transaction that may have been
	 * reused.
	 *
	 * Lazy commit thread will turn off tblkGC_LAZY before calling this
	 * routine.
	 */
	if (tblk->flag & tblkGC_LAZY) {
		jfs_info("txEnd called w/lazy tid: %d, tblk = 0x%p", tid, tblk);
		TXN_UNLOCK();

		spin_lock_irq(&log->gclock);	// LOGGC_LOCK
		tblk->flag |= tblkGC_UNLOCKED;
		spin_unlock_irq(&log->gclock);	// LOGGC_UNLOCK
		return;
	}

	jfs_info("txEnd: tid: %d, tblk = 0x%p", tid, tblk);

	assert(tblk->next == 0);

	/*
	 * insert tblock back on freelist
	 */
	tblk->next = TxAnchor.freetid;
	TxAnchor.freetid = tid;

	/*
	 * mark the tblock not active
	 */
	if (--log->active == 0) {
		clear_bit(log_FLUSH, &log->flag);

		/*
		 * synchronize with logsync barrier
		 */
		if (test_bit(log_SYNCBARRIER, &log->flag)) {
			TXN_UNLOCK();

			/* write dirty metadata & forward log syncpt */
			jfs_syncpt(log, 1);

			jfs_info("log barrier off: 0x%x", log->lsn);

			/* enable new transactions start */
			clear_bit(log_SYNCBARRIER, &log->flag);

			/* wakeup all waitors for logsync barrier */
			TXN_WAKEUP(&log->syncwait);

			goto wakeup;
		}
	}

	TXN_UNLOCK();
wakeup:
	/*
	 * wakeup all waitors for a free tblock
	 */
	TXN_WAKEUP(&TxAnchor.freewait);
}

/*
 *	txLock()
 *
 * function: acquire a transaction lock on the specified <mp>
 *
 * parameter:
 *
 * return:	transaction lock id
 *
 * serialization:
 */
struct tlock *txLock(tid_t tid, struct inode *ip, struct metapage * mp,
		     int type)
{
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	int dir_xtree = 0;
	lid_t lid;
	tid_t xtid;
	struct tlock *tlck;
	struct xtlock *xtlck;
	struct linelock *linelock;
	xtpage_t *p;
	struct tblock *tblk;

	TXN_LOCK();

	if (S_ISDIR(ip->i_mode) && (type & tlckXTREE) &&
	    !(mp->xflag & COMMIT_PAGE)) {
		/*
		 * Directory inode is special.  It can have both an xtree tlock
		 * and a dtree tlock associated with it.
		 */
		dir_xtree = 1;
		lid = jfs_ip->xtlid;
	} else
		lid = mp->lid;

	/* is page not locked by a transaction ? */
	if (lid == 0)
		goto allocateLock;

	jfs_info("txLock: tid:%d ip:0x%p mp:0x%p lid:%d", tid, ip, mp, lid);

	/* is page locked by the requester transaction ? */
	tlck = lid_to_tlock(lid);
	if ((xtid = tlck->tid) == tid) {
		TXN_UNLOCK();
		goto grantLock;
	}

	/*
	 * is page locked by anonymous transaction/lock ?
	 *
	 * (page update without transaction (i.e., file write) is
	 * locked under anonymous transaction tid = 0:
	 * anonymous tlocks maintained on anonymous tlock list of
	 * the inode of the page and available to all anonymous
	 * transactions until txCommit() time at which point
	 * they are transferred to the transaction tlock list of
	 * the committing transaction of the inode)
	 */
	if (xtid == 0) {
		tlck->tid = tid;
		TXN_UNLOCK();
		tblk = tid_to_tblock(tid);
		/*
		 * The order of the tlocks in the transaction is important
		 * (during truncate, child xtree pages must be freed before
		 * parent's tlocks change the working map).
		 * Take tlock off anonymous list and add to tail of
		 * transaction list
		 *
		 * Note:  We really need to get rid of the tid & lid and
		 * use list_head's.  This code is getting UGLY!
		 */
		if (jfs_ip->atlhead == lid) {
			if (jfs_ip->atltail == lid) {
				/* only anonymous txn.
				 * Remove from anon_list
				 */
				TXN_LOCK();
				list_del_init(&jfs_ip->anon_inode_list);
				TXN_UNLOCK();
			}
			jfs_ip->atlhead = tlck->next;
		} else {
			lid_t last;
			for (last = jfs_ip->atlhead;
			     lid_to_tlock(last)->next != lid;
			     last = lid_to_tlock(last)->next) {
				assert(last);
			}
			lid_to_tlock(last)->next = tlck->next;
			if (jfs_ip->atltail == lid)
				jfs_ip->atltail = last;
		}

		/* insert the tlock at tail of transaction tlock list */

		if (tblk->next)
			lid_to_tlock(tblk->last)->next = lid;
		else
			tblk->next = lid;
		tlck->next = 0;
		tblk->last = lid;

		goto grantLock;
	}

	goto waitLock;

	/*
	 * allocate a tlock
	 */
      allocateLock:
	lid = txLockAlloc();
	tlck = lid_to_tlock(lid);

	/*
	 * initialize tlock
	 */
	tlck->tid = tid;

	TXN_UNLOCK();

	/* mark tlock for meta-data page */
	if (mp->xflag & COMMIT_PAGE) {

		tlck->flag = tlckPAGELOCK;

		/* mark the page dirty and nohomeok */
		metapage_nohomeok(mp);

		jfs_info("locking mp = 0x%p, nohomeok = %d tid = %d tlck = 0x%p",
			 mp, mp->nohomeok, tid, tlck);

		/* if anonymous transaction, and buffer is on the group
		 * commit synclist, mark inode to show this.  This will
		 * prevent the buffer from being marked nohomeok for too
		 * long a time.
		 */
		if ((tid == 0) && mp->lsn)
			set_cflag(COMMIT_Synclist, ip);
	}
	/* mark tlock for in-memory inode */
	else
		tlck->flag = tlckINODELOCK;

	if (S_ISDIR(ip->i_mode))
		tlck->flag |= tlckDIRECTORY;

	tlck->type = 0;

	/* bind the tlock and the page */
	tlck->ip = ip;
	tlck->mp = mp;
	if (dir_xtree)
		jfs_ip->xtlid = lid;
	else
		mp->lid = lid;

	/*
	 * enqueue transaction lock to transaction/inode
	 */
	/* insert the tlock at tail of transaction tlock list */
	if (tid) {
		tblk = tid_to_tblock(tid);
		if (tblk->next)
			lid_to_tlock(tblk->last)->next = lid;
		else
			tblk->next = lid;
		tlck->next = 0;
		tblk->last = lid;
	}
	/* anonymous transaction:
	 * insert the tlock at head of inode anonymous tlock list
	 */
	else {
		tlck->next = jfs_ip->atlhead;
		jfs_ip->atlhead = lid;
		if (tlck->next == 0) {
			/* This inode's first anonymous transaction */
			jfs_ip->atltail = lid;
			TXN_LOCK();
			list_add_tail(&jfs_ip->anon_inode_list,
				      &TxAnchor.anon_list);
			TXN_UNLOCK();
		}
	}

	/* initialize type dependent area for linelock */
	linelock = (struct linelock *) & tlck->lock;
	linelock->next = 0;
	linelock->flag = tlckLINELOCK;
	linelock->maxcnt = TLOCKSHORT;
	linelock->index = 0;

	switch (type & tlckTYPE) {
	case tlckDTREE:
		linelock->l2linesize = L2DTSLOTSIZE;
		break;

	case tlckXTREE:
		linelock->l2linesize = L2XTSLOTSIZE;

		xtlck = (struct xtlock *) linelock;
		xtlck->header.offset = 0;
		xtlck->header.length = 2;

		if (type & tlckNEW) {
			xtlck->lwm.offset = XTENTRYSTART;
		} else {
			if (mp->xflag & COMMIT_PAGE)
				p = (xtpage_t *) mp->data;
			else
				p = &jfs_ip->i_xtroot;
			xtlck->lwm.offset =
			    le16_to_cpu(p->header.nextindex);
		}
		xtlck->lwm.length = 0;	/* ! */
		xtlck->twm.offset = 0;
		xtlck->hwm.offset = 0;

		xtlck->index = 2;
		break;

	case tlckINODE:
		linelock->l2linesize = L2INODESLOTSIZE;
		break;

	case tlckDATA:
		linelock->l2linesize = L2DATASLOTSIZE;
		break;

	default:
		jfs_err("UFO tlock:0x%p", tlck);
	}

	/*
	 * update tlock vector
	 */
      grantLock:
	tlck->type |= type;

	return tlck;

	/*
	 * page is being locked by another transaction:
	 */
      waitLock:
	/* Only locks on ipimap or ipaimap should reach here */
	/* assert(jfs_ip->fileset == AGGREGATE_I); */
	if (jfs_ip->fileset != AGGREGATE_I) {
		printk(KERN_ERR "txLock: trying to lock locked page!");
		print_hex_dump(KERN_ERR, "ip: ", DUMP_PREFIX_ADDRESS, 16, 4,
			       ip, sizeof(*ip), 0);
		print_hex_dump(KERN_ERR, "mp: ", DUMP_PREFIX_ADDRESS, 16, 4,
			       mp, sizeof(*mp), 0);
		print_hex_dump(KERN_ERR, "Locker's tblock: ",
			       DUMP_PREFIX_ADDRESS, 16, 4, tid_to_tblock(tid),
			       sizeof(struct tblock), 0);
		print_hex_dump(KERN_ERR, "Tlock: ", DUMP_PREFIX_ADDRESS, 16, 4,
			       tlck, sizeof(*tlck), 0);
		BUG();
	}
	INCREMENT(stattx.waitlock);	/* statistics */
	TXN_UNLOCK();
	release_metapage(mp);
	TXN_LOCK();
	xtid = tlck->tid;	/* reacquire after dropping TXN_LOCK */

	jfs_info("txLock: in waitLock, tid = %d, xtid = %d, lid = %d",
		 tid, xtid, lid);

	/* Recheck everything since dropping TXN_LOCK */
	if (xtid && (tlck->mp == mp) && (mp->lid == lid))
		TXN_SLEEP_DROP_LOCK(&tid_to_tblock(xtid)->waitor);
	else
		TXN_UNLOCK();
	jfs_info("txLock: awakened     tid = %d, lid = %d", tid, lid);

	return NULL;
}

/*
 * NAME:	txRelease()
 *
 * FUNCTION:	Release buffers associated with transaction locks, but don't
 *		mark homeok yet.  The allows other transactions to modify
 *		buffers, but won't let them go to disk until commit record
 *		actually gets written.
 *
 * PARAMETER:
 *		tblk	-
 *
 * RETURN:	Errors from subroutines.
 */
static void txRelease(struct tblock * tblk)
{
	struct metapage *mp;
	lid_t lid;
	struct tlock *tlck;

	TXN_LOCK();

	for (lid = tblk->next; lid; lid = tlck->next) {
		tlck = lid_to_tlock(lid);
		if ((mp = tlck->mp) != NULL &&
		    (tlck->type & tlckBTROOT) == 0) {
			assert(mp->xflag & COMMIT_PAGE);
			mp->lid = 0;
		}
	}

	/*
	 * wakeup transactions waiting on a page locked
	 * by the current transaction
	 */
	TXN_WAKEUP(&tblk->waitor);

	TXN_UNLOCK();
}

/*
 * NAME:	txUnlock()
 *
 * FUNCTION:	Initiates pageout of pages modified by tid in journalled
 *		objects and frees their lockwords.
 */
static void txUnlock(struct tblock * tblk)
{
	struct tlock *tlck;
	struct linelock *linelock;
	lid_t lid, next, llid, k;
	struct metapage *mp;
	struct jfs_log *log;
	int difft, diffp;
	unsigned long flags;

	jfs_info("txUnlock: tblk = 0x%p", tblk);
	log = JFS_SBI(tblk->sb)->log;

	/*
	 * mark page under tlock homeok (its log has been written):
	 */
	for (lid = tblk->next; lid; lid = next) {
		tlck = lid_to_tlock(lid);
		next = tlck->next;

		jfs_info("unlocking lid = %d, tlck = 0x%p", lid, tlck);

		/* unbind page from tlock */
		if ((mp = tlck->mp) != NULL &&
		    (tlck->type & tlckBTROOT) == 0) {
			assert(mp->xflag & COMMIT_PAGE);

			/* hold buffer
			 */
			hold_metapage(mp);

			assert(mp->nohomeok > 0);
			_metapage_homeok(mp);

			/* inherit younger/larger clsn */
			LOGSYNC_LOCK(log, flags);
			if (mp->clsn) {
				logdiff(difft, tblk->clsn, log);
				logdiff(diffp, mp->clsn, log);
				if (difft > diffp)
					mp->clsn = tblk->clsn;
			} else
				mp->clsn = tblk->clsn;
			LOGSYNC_UNLOCK(log, flags);

			assert(!(tlck->flag & tlckFREEPAGE));

			put_metapage(mp);
		}

		/* insert tlock, and linelock(s) of the tlock if any,
		 * at head of freelist
		 */
		TXN_LOCK();

		llid = ((struct linelock *) & tlck->lock)->next;
		while (llid) {
			linelock = (struct linelock *) lid_to_tlock(llid);
			k = linelock->next;
			txLockFree(llid);
			llid = k;
		}
		txLockFree(lid);

		TXN_UNLOCK();
	}
	tblk->next = tblk->last = 0;

	/*
	 * remove tblock from logsynclist
	 * (allocation map pages inherited lsn of tblk and
	 * has been inserted in logsync list at txUpdateMap())
	 */
	if (tblk->lsn) {
		LOGSYNC_LOCK(log, flags);
		log->count--;
		list_del(&tblk->synclist);
		LOGSYNC_UNLOCK(log, flags);
	}
}

/*
 *	txMaplock()
 *
 * function: allocate a transaction lock for freed page/entry;
 *	for freed page, maplock is used as xtlock/dtlock type;
 */
struct tlock *txMaplock(tid_t tid, struct inode *ip, int type)
{
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	lid_t lid;
	struct tblock *tblk;
	struct tlock *tlck;
	struct maplock *maplock;

	TXN_LOCK();

	/*
	 * allocate a tlock
	 */
	lid = txLockAlloc();
	tlck = lid_to_tlock(lid);

	/*
	 * initialize tlock
	 */
	tlck->tid = tid;

	/* bind the tlock and the object */
	tlck->flag = tlckINODELOCK;
	if (S_ISDIR(ip->i_mode))
		tlck->flag |= tlckDIRECTORY;
	tlck->ip = ip;
	tlck->mp = NULL;

	tlck->type = type;

	/*
	 * enqueue transaction lock to transaction/inode
	 */
	/* insert the tlock at tail of transaction tlock list */
	if (tid) {
		tblk = tid_to_tblock(tid);
		if (tblk->next)
			lid_to_tlock(tblk->last)->next = lid;
		else
			tblk->next = lid;
		tlck->next = 0;
		tblk->last = lid;
	}
	/* anonymous transaction:
	 * insert the tlock at head of inode anonymous tlock list
	 */
	else {
		tlck->next = jfs_ip->atlhead;
		jfs_ip->atlhead = lid;
		if (tlck->next == 0) {
			/* This inode's first anonymous transaction */
			jfs_ip->atltail = lid;
			list_add_tail(&jfs_ip->anon_inode_list,
				      &TxAnchor.anon_list);
		}
	}

	TXN_UNLOCK();

	/* initialize type dependent area for maplock */
	maplock = (struct maplock *) & tlck->lock;
	maplock->next = 0;
	maplock->maxcnt = 0;
	maplock->index = 0;

	return tlck;
}

/*
 *	txLinelock()
 *
 * function: allocate a transaction lock for log vector list
 */
struct linelock *txLinelock(struct linelock * tlock)
{
	lid_t lid;
	struct tlock *tlck;
	struct linelock *linelock;

	TXN_LOCK();

	/* allocate a TxLock structure */
	lid = txLockAlloc();
	tlck = lid_to_tlock(lid);

	TXN_UNLOCK();

	/* initialize linelock */
	linelock = (struct linelock *) tlck;
	linelock->next = 0;
	linelock->flag = tlckLINELOCK;
	linelock->maxcnt = TLOCKLONG;
	linelock->index = 0;
	if (tlck->flag & tlckDIRECTORY)
		linelock->flag |= tlckDIRECTORY;

	/* append linelock after tlock */
	linelock->next = tlock->next;
	tlock->next = lid;

	return linelock;
}

/*
 *		transaction commit management
 *		-----------------------------
 */

/*
 * NAME:	txCommit()
 *
 * FUNCTION:	commit the changes to the objects specified in
 *		clist.  For journalled segments only the
 *		changes of the caller are committed, ie by tid.
 *		for non-journalled segments the data are flushed to
 *		disk and then the change to the disk inode and indirect
 *		blocks committed (so blocks newly allocated to the
 *		segment will be made a part of the segment atomically).
 *
 *		all of the segments specified in clist must be in
 *		one file system. no more than 6 segments are needed
 *		to handle all unix svcs.
 *
 *		if the i_nlink field (i.e. disk inode link count)
 *		is zero, and the type of inode is a regular file or
 *		directory, or symbolic link , the inode is truncated
 *		to zero length. the truncation is committed but the
 *		VM resources are unaffected until it is closed (see
 *		iput and iclose).
 *
 * PARAMETER:
 *
 * RETURN:
 *
 * serialization:
 *		on entry the inode lock on each segment is assumed
 *		to be held.
 *
 * i/o error:
 */
int txCommit(tid_t tid,		/* transaction identifier */
	     int nip,		/* number of inodes to commit */
	     struct inode **iplist,	/* list of inode to commit */
	     int flag)
{
	int rc = 0;
	struct commit cd;
	struct jfs_log *log;
	struct tblock *tblk;
	struct lrd *lrd;
	struct inode *ip;
	struct jfs_inode_info *jfs_ip;
	int k, n;
	ino_t top;
	struct super_block *sb;

	jfs_info("txCommit, tid = %d, flag = %d", tid, flag);
	/* is read-only file system ? */
	if (isReadOnly(iplist[0])) {
		rc = -EROFS;
		goto TheEnd;
	}

	sb = cd.sb = iplist[0]->i_sb;
	cd.tid = tid;

	if (tid == 0)
		tid = txBegin(sb, 0);
	tblk = tid_to_tblock(tid);

	/*
	 * initialize commit structure
	 */
	log = JFS_SBI(sb)->log;
	cd.log = log;

	/* initialize log record descriptor in commit */
	lrd = &cd.lrd;
	lrd->logtid = cpu_to_le32(tblk->logtid);
	lrd->backchain = 0;

	tblk->xflag |= flag;

	if ((flag & (COMMIT_FORCE | COMMIT_SYNC)) == 0)
		tblk->xflag |= COMMIT_LAZY;
	/*
	 *	prepare non-journaled objects for commit
	 *
	 * flush data pages of non-journaled file
	 * to prevent the file getting non-initialized disk blocks
	 * in case of crash.
	 * (new blocks - )
	 */
	cd.iplist = iplist;
	cd.nip = nip;

	/*
	 *	acquire transaction lock on (on-disk) inodes
	 *
	 * update on-disk inode from in-memory inode
	 * acquiring transaction locks for AFTER records
	 * on the on-disk inode of file object
	 *
	 * sort the inodes array by inode number in descending order
	 * to prevent deadlock when acquiring transaction lock
	 * of on-disk inodes on multiple on-disk inode pages by
	 * multiple concurrent transactions
	 */
	for (k = 0; k < cd.nip; k++) {
		top = (cd.iplist[k])->i_ino;
		for (n = k + 1; n < cd.nip; n++) {
			ip = cd.iplist[n];
			if (ip->i_ino > top) {
				top = ip->i_ino;
				cd.iplist[n] = cd.iplist[k];
				cd.iplist[k] = ip;
			}
		}

		ip = cd.iplist[k];
		jfs_ip = JFS_IP(ip);

		/*
		 * BUGBUG - This code has temporarily been removed.  The
		 * intent is to ensure that any file data is written before
		 * the metadata is committed to the journal.  This prevents
		 * uninitialized data from appearing in a file after the
		 * journal has been replayed.  (The uninitialized data
		 * could be sensitive data removed by another user.)
		 *
		 * The problem now is that we are holding the IWRITELOCK
		 * on the inode, and calling filemap_fdatawrite on an
		 * unmapped page will cause a deadlock in jfs_get_block.
		 *
		 * The long term solution is to pare down the use of
		 * IWRITELOCK.  We are currently holding it too long.
		 * We could also be smarter about which data pages need
		 * to be written before the transaction is committed and
		 * when we don't need to worry about it at all.
		 *
		 * if ((!S_ISDIR(ip->i_mode))
		 *    && (tblk->flag & COMMIT_DELETE) == 0)
		 *	filemap_write_and_wait(ip->i_mapping);
		 */

		/*
		 * Mark inode as not dirty.  It will still be on the dirty
		 * inode list, but we'll know not to commit it again unless
		 * it gets marked dirty again
		 */
		clear_cflag(COMMIT_Dirty, ip);

		/* inherit anonymous tlock(s) of inode */
		if (jfs_ip->atlhead) {
			lid_to_tlock(jfs_ip->atltail)->next = tblk->next;
			tblk->next = jfs_ip->atlhead;
			if (!tblk->last)
				tblk->last = jfs_ip->atltail;
			jfs_ip->atlhead = jfs_ip->atltail = 0;
			TXN_LOCK();
			list_del_init(&jfs_ip->anon_inode_list);
			TXN_UNLOCK();
		}

		/*
		 * acquire transaction lock on on-disk inode page
		 * (become first tlock of the tblk's tlock list)
		 */
		if (((rc = diWrite(tid, ip))))
			goto out;
	}

	/*
	 *	write log records from transaction locks
	 *
	 * txUpdateMap() resets XAD_NEW in XAD.
	 */
	if ((rc = txLog(log, tblk, &cd)))
		goto TheEnd;

	/*
	 * Ensure that inode isn't reused before
	 * lazy commit thread finishes processing
	 */
	if (tblk->xflag & COMMIT_DELETE) {
		ihold(tblk->u.ip);
		/*
		 * Avoid a rare deadlock
		 *
		 * If the inode is locked, we may be blocked in
		 * jfs_commit_inode.  If so, we don't want the
		 * lazy_commit thread doing the last iput() on the inode
		 * since that may block on the locked inode.  Instead,
		 * commit the transaction synchronously, so the last iput
		 * will be done by the calling thread (or later)
		 */
		/*
		 * I believe this code is no longer needed.  Splitting I_LOCK
		 * into two bits, I_NEW and I_SYNC should prevent this
		 * deadlock as well.  But since I don't have a JFS testload
		 * to verify this, only a trivial s/I_LOCK/I_SYNC/ was done.
		 * Joern
		 */
		if (tblk->u.ip->i_state & I_SYNC)
			tblk->xflag &= ~COMMIT_LAZY;
	}

	ASSERT((!(tblk->xflag & COMMIT_DELETE)) ||
	       ((tblk->u.ip->i_nlink == 0) &&
		!test_cflag(COMMIT_Nolink, tblk->u.ip)));

	/*
	 *	write COMMIT log record
	 */
	lrd->type = cpu_to_le16(LOG_COMMIT);
	lrd->length = 0;
	lmLog(log, tblk, lrd, NULL);

	lmGroupCommit(log, tblk);

	/*
	 *	- transaction is now committed -
	 */

	/*
	 * force pages in careful update
	 * (imap addressing structure update)
	 */
	if (flag & COMMIT_FORCE)
		txForce(tblk);

	/*
	 *	update allocation map.
	 *
	 * update inode allocation map and inode:
	 * free pager lock on memory object of inode if any.
	 * update block allocation map.
	 *
	 * txUpdateMap() resets XAD_NEW in XAD.
	 */
	if (tblk->xflag & COMMIT_FORCE)
		txUpdateMap(tblk);

	/*
	 *	free transaction locks and pageout/free pages
	 */
	txRelease(tblk);

	if ((tblk->flag & tblkGC_LAZY) == 0)
		txUnlock(tblk);


	/*
	 *	reset in-memory object state
	 */
	for (k = 0; k < cd.nip; k++) {
		ip = cd.iplist[k];
		jfs_ip = JFS_IP(ip);

		/*
		 * reset in-memory inode state
		 */
		jfs_ip->bxflag = 0;
		jfs_ip->blid = 0;
	}

      out:
	if (rc != 0)
		txAbort(tid, 1);

      TheEnd:
	jfs_info("txCommit: tid = %d, returning %d", tid, rc);
	return rc;
}

/*
 * NAME:	txLog()
 *
 * FUNCTION:	Writes AFTER log records for all lines modified
 *		by tid for segments specified by inodes in comdata.
 *		Code assumes only WRITELOCKS are recorded in lockwords.
 *
 * PARAMETERS:
 *
 * RETURN :
 */
static int txLog(struct jfs_log * log, struct tblock * tblk, struct commit * cd)
{
	int rc = 0;
	struct inode *ip;
	lid_t lid;
	struct tlock *tlck;
	struct lrd *lrd = &cd->lrd;

	/*
	 * write log record(s) for each tlock of transaction,
	 */
	for (lid = tblk->next; lid; lid = tlck->next) {
		tlck = lid_to_tlock(lid);

		tlck->flag |= tlckLOG;

		/* initialize lrd common */
		ip = tlck->ip;
		lrd->aggregate = cpu_to_le32(JFS_SBI(ip->i_sb)->aggregate);
		lrd->log.redopage.fileset = cpu_to_le32(JFS_IP(ip)->fileset);
		lrd->log.redopage.inode = cpu_to_le32(ip->i_ino);

		/* write log record of page from the tlock */
		switch (tlck->type & tlckTYPE) {
		case tlckXTREE:
			xtLog(log, tblk, lrd, tlck);
			break;

		case tlckDTREE:
			dtLog(log, tblk, lrd, tlck);
			break;

		case tlckINODE:
			diLog(log, tblk, lrd, tlck, cd);
			break;

		case tlckMAP:
			mapLog(log, tblk, lrd, tlck);
			break;

		case tlckDATA:
			dataLog(log, tblk, lrd, tlck);
			break;

		default:
			jfs_err("UFO tlock:0x%p", tlck);
		}
	}

	return rc;
}

/*
 *	diLog()
 *
 * function:	log inode tlock and format maplock to update bmap;
 */
static int diLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
		 struct tlock * tlck, struct commit * cd)
{
	int rc = 0;
	struct metapage *mp;
	pxd_t *pxd;
	struct pxd_lock *pxdlock;

	mp = tlck->mp;

	/* initialize as REDOPAGE record format */
	lrd->log.redopage.type = cpu_to_le16(LOG_INODE);
	lrd->log.redopage.l2linesize = cpu_to_le16(L2INODESLOTSIZE);

	pxd = &lrd->log.redopage.pxd;

	/*
	 *	inode after image
	 */
	if (tlck->type & tlckENTRY) {
		/* log after-image for logredo(): */
		lrd->type = cpu_to_le16(LOG_REDOPAGE);
		PXDaddress(pxd, mp->index);
		PXDlength(pxd,
			  mp->logical_size >> tblk->sb->s_blocksize_bits);
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, tlck));

		/* mark page as homeward bound */
		tlck->flag |= tlckWRITEPAGE;
	} else if (tlck->type & tlckFREE) {
		/*
		 *	free inode extent
		 *
		 * (pages of the freed inode extent have been invalidated and
		 * a maplock for free of the extent has been formatted at
		 * txLock() time);
		 *
		 * the tlock had been acquired on the inode allocation map page
		 * (iag) that specifies the freed extent, even though the map
		 * page is not itself logged, to prevent pageout of the map
		 * page before the log;
		 */

		/* log LOG_NOREDOINOEXT of the freed inode extent for
		 * logredo() to start NoRedoPage filters, and to update
		 * imap and bmap for free of the extent;
		 */
		lrd->type = cpu_to_le16(LOG_NOREDOINOEXT);
		/*
		 * For the LOG_NOREDOINOEXT record, we need
		 * to pass the IAG number and inode extent
		 * index (within that IAG) from which the
		 * the extent being released.  These have been
		 * passed to us in the iplist[1] and iplist[2].
		 */
		lrd->log.noredoinoext.iagnum =
		    cpu_to_le32((u32) (size_t) cd->iplist[1]);
		lrd->log.noredoinoext.inoext_idx =
		    cpu_to_le32((u32) (size_t) cd->iplist[2]);

		pxdlock = (struct pxd_lock *) & tlck->lock;
		*pxd = pxdlock->pxd;
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, NULL));

		/* update bmap */
		tlck->flag |= tlckUPDATEMAP;

		/* mark page as homeward bound */
		tlck->flag |= tlckWRITEPAGE;
	} else
		jfs_err("diLog: UFO type tlck:0x%p", tlck);
#ifdef  _JFS_WIP
	/*
	 *	alloc/free external EA extent
	 *
	 * a maplock for txUpdateMap() to update bPWMAP for alloc/free
	 * of the extent has been formatted at txLock() time;
	 */
	else {
		assert(tlck->type & tlckEA);

		/* log LOG_UPDATEMAP for logredo() to update bmap for
		 * alloc of new (and free of old) external EA extent;
		 */
		lrd->type = cpu_to_le16(LOG_UPDATEMAP);
		pxdlock = (struct pxd_lock *) & tlck->lock;
		nlock = pxdlock->index;
		for (i = 0; i < nlock; i++, pxdlock++) {
			if (pxdlock->flag & mlckALLOCPXD)
				lrd->log.updatemap.type =
				    cpu_to_le16(LOG_ALLOCPXD);
			else
				lrd->log.updatemap.type =
				    cpu_to_le16(LOG_FREEPXD);
			lrd->log.updatemap.nxd = cpu_to_le16(1);
			lrd->log.updatemap.pxd = pxdlock->pxd;
			lrd->backchain =
			    cpu_to_le32(lmLog(log, tblk, lrd, NULL));
		}

		/* update bmap */
		tlck->flag |= tlckUPDATEMAP;
	}
#endif				/* _JFS_WIP */

	return rc;
}

/*
 *	dataLog()
 *
 * function:	log data tlock
 */
static int dataLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
	    struct tlock * tlck)
{
	struct metapage *mp;
	pxd_t *pxd;

	mp = tlck->mp;

	/* initialize as REDOPAGE record format */
	lrd->log.redopage.type = cpu_to_le16(LOG_DATA);
	lrd->log.redopage.l2linesize = cpu_to_le16(L2DATASLOTSIZE);

	pxd = &lrd->log.redopage.pxd;

	/* log after-image for logredo(): */
	lrd->type = cpu_to_le16(LOG_REDOPAGE);

	if (jfs_dirtable_inline(tlck->ip)) {
		/*
		 * The table has been truncated, we've must have deleted
		 * the last entry, so don't bother logging this
		 */
		mp->lid = 0;
		grab_metapage(mp);
		metapage_homeok(mp);
		discard_metapage(mp);
		tlck->mp = NULL;
		return 0;
	}

	PXDaddress(pxd, mp->index);
	PXDlength(pxd, mp->logical_size >> tblk->sb->s_blocksize_bits);

	lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, tlck));

	/* mark page as homeward bound */
	tlck->flag |= tlckWRITEPAGE;

	return 0;
}

/*
 *	dtLog()
 *
 * function:	log dtree tlock and format maplock to update bmap;
 */
static void dtLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
	   struct tlock * tlck)
{
	struct metapage *mp;
	struct pxd_lock *pxdlock;
	pxd_t *pxd;

	mp = tlck->mp;

	/* initialize as REDOPAGE/NOREDOPAGE record format */
	lrd->log.redopage.type = cpu_to_le16(LOG_DTREE);
	lrd->log.redopage.l2linesize = cpu_to_le16(L2DTSLOTSIZE);

	pxd = &lrd->log.redopage.pxd;

	if (tlck->type & tlckBTROOT)
		lrd->log.redopage.type |= cpu_to_le16(LOG_BTROOT);

	/*
	 *	page extension via relocation: entry insertion;
	 *	page extension in-place: entry insertion;
	 *	new right page from page split, reinitialized in-line
	 *	root from root page split: entry insertion;
	 */
	if (tlck->type & (tlckNEW | tlckEXTEND)) {
		/* log after-image of the new page for logredo():
		 * mark log (LOG_NEW) for logredo() to initialize
		 * freelist and update bmap for alloc of the new page;
		 */
		lrd->type = cpu_to_le16(LOG_REDOPAGE);
		if (tlck->type & tlckEXTEND)
			lrd->log.redopage.type |= cpu_to_le16(LOG_EXTEND);
		else
			lrd->log.redopage.type |= cpu_to_le16(LOG_NEW);
		PXDaddress(pxd, mp->index);
		PXDlength(pxd,
			  mp->logical_size >> tblk->sb->s_blocksize_bits);
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, tlck));

		/* format a maplock for txUpdateMap() to update bPMAP for
		 * alloc of the new page;
		 */
		if (tlck->type & tlckBTROOT)
			return;
		tlck->flag |= tlckUPDATEMAP;
		pxdlock = (struct pxd_lock *) & tlck->lock;
		pxdlock->flag = mlckALLOCPXD;
		pxdlock->pxd = *pxd;

		pxdlock->index = 1;

		/* mark page as homeward bound */
		tlck->flag |= tlckWRITEPAGE;
		return;
	}

	/*
	 *	entry insertion/deletion,
	 *	sibling page link update (old right page before split);
	 */
	if (tlck->type & (tlckENTRY | tlckRELINK)) {
		/* log after-image for logredo(): */
		lrd->type = cpu_to_le16(LOG_REDOPAGE);
		PXDaddress(pxd, mp->index);
		PXDlength(pxd,
			  mp->logical_size >> tblk->sb->s_blocksize_bits);
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, tlck));

		/* mark page as homeward bound */
		tlck->flag |= tlckWRITEPAGE;
		return;
	}

	/*
	 *	page deletion: page has been invalidated
	 *	page relocation: source extent
	 *
	 *	a maplock for free of the page has been formatted
	 *	at txLock() time);
	 */
	if (tlck->type & (tlckFREE | tlckRELOCATE)) {
		/* log LOG_NOREDOPAGE of the deleted page for logredo()
		 * to start NoRedoPage filter and to update bmap for free
		 * of the deletd page
		 */
		lrd->type = cpu_to_le16(LOG_NOREDOPAGE);
		pxdlock = (struct pxd_lock *) & tlck->lock;
		*pxd = pxdlock->pxd;
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, NULL));

		/* a maplock for txUpdateMap() for free of the page
		 * has been formatted at txLock() time;
		 */
		tlck->flag |= tlckUPDATEMAP;
	}
	return;
}

/*
 *	xtLog()
 *
 * function:	log xtree tlock and format maplock to update bmap;
 */
static void xtLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
	   struct tlock * tlck)
{
	struct inode *ip;
	struct metapage *mp;
	xtpage_t *p;
	struct xtlock *xtlck;
	struct maplock *maplock;
	struct xdlistlock *xadlock;
	struct pxd_lock *pxdlock;
	pxd_t *page_pxd;
	int next, lwm, hwm;

	ip = tlck->ip;
	mp = tlck->mp;

	/* initialize as REDOPAGE/NOREDOPAGE record format */
	lrd->log.redopage.type = cpu_to_le16(LOG_XTREE);
	lrd->log.redopage.l2linesize = cpu_to_le16(L2XTSLOTSIZE);

	page_pxd = &lrd->log.redopage.pxd;

	if (tlck->type & tlckBTROOT) {
		lrd->log.redopage.type |= cpu_to_le16(LOG_BTROOT);
		p = &JFS_IP(ip)->i_xtroot;
		if (S_ISDIR(ip->i_mode))
			lrd->log.redopage.type |=
			    cpu_to_le16(LOG_DIR_XTREE);
	} else
		p = (xtpage_t *) mp->data;
	next = le16_to_cpu(p->header.nextindex);

	xtlck = (struct xtlock *) & tlck->lock;

	maplock = (struct maplock *) & tlck->lock;
	xadlock = (struct xdlistlock *) maplock;

	/*
	 *	entry insertion/extension;
	 *	sibling page link update (old right page before split);
	 */
	if (tlck->type & (tlckNEW | tlckGROW | tlckRELINK)) {
		/* log after-image for logredo():
		 * logredo() will update bmap for alloc of new/extended
		 * extents (XAD_NEW|XAD_EXTEND) of XAD[lwm:next) from
		 * after-image of XADlist;
		 * logredo() resets (XAD_NEW|XAD_EXTEND) flag when
		 * applying the after-image to the meta-data page.
		 */
		lrd->type = cpu_to_le16(LOG_REDOPAGE);
		PXDaddress(page_pxd, mp->index);
		PXDlength(page_pxd,
			  mp->logical_size >> tblk->sb->s_blocksize_bits);
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, tlck));

		/* format a maplock for txUpdateMap() to update bPMAP
		 * for alloc of new/extended extents of XAD[lwm:next)
		 * from the page itself;
		 * txUpdateMap() resets (XAD_NEW|XAD_EXTEND) flag.
		 */
		lwm = xtlck->lwm.offset;
		if (lwm == 0)
			lwm = XTPAGEMAXSLOT;

		if (lwm == next)
			goto out;
		if (lwm > next) {
			jfs_err("xtLog: lwm > next\n");
			goto out;
		}
		tlck->flag |= tlckUPDATEMAP;
		xadlock->flag = mlckALLOCXADLIST;
		xadlock->count = next - lwm;
		if ((xadlock->count <= 4) && (tblk->xflag & COMMIT_LAZY)) {
			int i;
			pxd_t *pxd;
			/*
			 * Lazy commit may allow xtree to be modified before
			 * txUpdateMap runs.  Copy xad into linelock to
			 * preserve correct data.
			 *
			 * We can fit twice as may pxd's as xads in the lock
			 */
			xadlock->flag = mlckALLOCPXDLIST;
			pxd = xadlock->xdlist = &xtlck->pxdlock;
			for (i = 0; i < xadlock->count; i++) {
				PXDaddress(pxd, addressXAD(&p->xad[lwm + i]));
				PXDlength(pxd, lengthXAD(&p->xad[lwm + i]));
				p->xad[lwm + i].flag &=
				    ~(XAD_NEW | XAD_EXTENDED);
				pxd++;
			}
		} else {
			/*
			 * xdlist will point to into inode's xtree, ensure
			 * that transaction is not committed lazily.
			 */
			xadlock->flag = mlckALLOCXADLIST;
			xadlock->xdlist = &p->xad[lwm];
			tblk->xflag &= ~COMMIT_LAZY;
		}
		jfs_info("xtLog: alloc ip:0x%p mp:0x%p tlck:0x%p lwm:%d "
			 "count:%d", tlck->ip, mp, tlck, lwm, xadlock->count);

		maplock->index = 1;

	      out:
		/* mark page as homeward bound */
		tlck->flag |= tlckWRITEPAGE;

		return;
	}

	/*
	 *	page deletion: file deletion/truncation (ref. xtTruncate())
	 *
	 * (page will be invalidated after log is written and bmap
	 * is updated from the page);
	 */
	if (tlck->type & tlckFREE) {
		/* LOG_NOREDOPAGE log for NoRedoPage filter:
		 * if page free from file delete, NoRedoFile filter from
		 * inode image of zero link count will subsume NoRedoPage
		 * filters for each page;
		 * if page free from file truncattion, write NoRedoPage
		 * filter;
		 *
		 * upadte of block allocation map for the page itself:
		 * if page free from deletion and truncation, LOG_UPDATEMAP
		 * log for the page itself is generated from processing
		 * its parent page xad entries;
		 */
		/* if page free from file truncation, log LOG_NOREDOPAGE
		 * of the deleted page for logredo() to start NoRedoPage
		 * filter for the page;
		 */
		if (tblk->xflag & COMMIT_TRUNCATE) {
			/* write NOREDOPAGE for the page */
			lrd->type = cpu_to_le16(LOG_NOREDOPAGE);
			PXDaddress(page_pxd, mp->index);
			PXDlength(page_pxd,
				  mp->logical_size >> tblk->sb->
				  s_blocksize_bits);
			lrd->backchain =
			    cpu_to_le32(lmLog(log, tblk, lrd, NULL));

			if (tlck->type & tlckBTROOT) {
				/* Empty xtree must be logged */
				lrd->type = cpu_to_le16(LOG_REDOPAGE);
				lrd->backchain =
				    cpu_to_le32(lmLog(log, tblk, lrd, tlck));
			}
		}

		/* init LOG_UPDATEMAP of the freed extents
		 * XAD[XTENTRYSTART:hwm) from the deleted page itself
		 * for logredo() to update bmap;
		 */
		lrd->type = cpu_to_le16(LOG_UPDATEMAP);
		lrd->log.updatemap.type = cpu_to_le16(LOG_FREEXADLIST);
		xtlck = (struct xtlock *) & tlck->lock;
		hwm = xtlck->hwm.offset;
		lrd->log.updatemap.nxd =
		    cpu_to_le16(hwm - XTENTRYSTART + 1);
		/* reformat linelock for lmLog() */
		xtlck->header.offset = XTENTRYSTART;
		xtlck->header.length = hwm - XTENTRYSTART + 1;
		xtlck->index = 1;
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, tlck));

		/* format a maplock for txUpdateMap() to update bmap
		 * to free extents of XAD[XTENTRYSTART:hwm) from the
		 * deleted page itself;
		 */
		tlck->flag |= tlckUPDATEMAP;
		xadlock->count = hwm - XTENTRYSTART + 1;
		if ((xadlock->count <= 4) && (tblk->xflag & COMMIT_LAZY)) {
			int i;
			pxd_t *pxd;
			/*
			 * Lazy commit may allow xtree to be modified before
			 * txUpdateMap runs.  Copy xad into linelock to
			 * preserve correct data.
			 *
			 * We can fit twice as may pxd's as xads in the lock
			 */
			xadlock->flag = mlckFREEPXDLIST;
			pxd = xadlock->xdlist = &xtlck->pxdlock;
			for (i = 0; i < xadlock->count; i++) {
				PXDaddress(pxd,
					addressXAD(&p->xad[XTENTRYSTART + i]));
				PXDlength(pxd,
					lengthXAD(&p->xad[XTENTRYSTART + i]));
				pxd++;
			}
		} else {
			/*
			 * xdlist will point to into inode's xtree, ensure
			 * that transaction is not committed lazily.
			 */
			xadlock->flag = mlckFREEXADLIST;
			xadlock->xdlist = &p->xad[XTENTRYSTART];
			tblk->xflag &= ~COMMIT_LAZY;
		}
		jfs_info("xtLog: free ip:0x%p mp:0x%p count:%d lwm:2",
			 tlck->ip, mp, xadlock->count);

		maplock->index = 1;

		/* mark page as invalid */
		if (((tblk->xflag & COMMIT_PWMAP) || S_ISDIR(ip->i_mode))
		    && !(tlck->type & tlckBTROOT))
			tlck->flag |= tlckFREEPAGE;
		/*
		   else (tblk->xflag & COMMIT_PMAP)
		   ? release the page;
		 */
		return;
	}

	/*
	 *	page/entry truncation: file truncation (ref. xtTruncate())
	 *
	 *	|----------+------+------+---------------|
	 *		   |      |      |
	 *		   |      |     hwm - hwm before truncation
	 *		   |     next - truncation point
	 *		  lwm - lwm before truncation
	 * header ?
	 */
	if (tlck->type & tlckTRUNCATE) {
		/* This odd declaration suppresses a bogus gcc warning */
		pxd_t pxd = pxd;	/* truncated extent of xad */
		int twm;

		/*
		 * For truncation the entire linelock may be used, so it would
		 * be difficult to store xad list in linelock itself.
		 * Therefore, we'll just force transaction to be committed
		 * synchronously, so that xtree pages won't be changed before
		 * txUpdateMap runs.
		 */
		tblk->xflag &= ~COMMIT_LAZY;
		lwm = xtlck->lwm.offset;
		if (lwm == 0)
			lwm = XTPAGEMAXSLOT;
		hwm = xtlck->hwm.offset;
		twm = xtlck->twm.offset;

		/*
		 *	write log records
		 */
		/* log after-image for logredo():
		 *
		 * logredo() will update bmap for alloc of new/extended
		 * extents (XAD_NEW|XAD_EXTEND) of XAD[lwm:next) from
		 * after-image of XADlist;
		 * logredo() resets (XAD_NEW|XAD_EXTEND) flag when
		 * applying the after-image to the meta-data page.
		 */
		lrd->type = cpu_to_le16(LOG_REDOPAGE);
		PXDaddress(page_pxd, mp->index);
		PXDlength(page_pxd,
			  mp->logical_size >> tblk->sb->s_blocksize_bits);
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, tlck));

		/*
		 * truncate entry XAD[twm == next - 1]:
		 */
		if (twm == next - 1) {
			/* init LOG_UPDATEMAP for logredo() to update bmap for
			 * free of truncated delta extent of the truncated
			 * entry XAD[next - 1]:
			 * (xtlck->pxdlock = truncated delta extent);
			 */
			pxdlock = (struct pxd_lock *) & xtlck->pxdlock;
			/* assert(pxdlock->type & tlckTRUNCATE); */
			lrd->type = cpu_to_le16(LOG_UPDATEMAP);
			lrd->log.updatemap.type = cpu_to_le16(LOG_FREEPXD);
			lrd->log.updatemap.nxd = cpu_to_le16(1);
			lrd->log.updatemap.pxd = pxdlock->pxd;
			pxd = pxdlock->pxd;	/* save to format maplock */
			lrd->backchain =
			    cpu_to_le32(lmLog(log, tblk, lrd, NULL));
		}

		/*
		 * free entries XAD[next:hwm]:
		 */
		if (hwm >= next) {
			/* init LOG_UPDATEMAP of the freed extents
			 * XAD[next:hwm] from the deleted page itself
			 * for logredo() to update bmap;
			 */
			lrd->type = cpu_to_le16(LOG_UPDATEMAP);
			lrd->log.updatemap.type =
			    cpu_to_le16(LOG_FREEXADLIST);
			xtlck = (struct xtlock *) & tlck->lock;
			hwm = xtlck->hwm.offset;
			lrd->log.updatemap.nxd =
			    cpu_to_le16(hwm - next + 1);
			/* reformat linelock for lmLog() */
			xtlck->header.offset = next;
			xtlck->header.length = hwm - next + 1;
			xtlck->index = 1;
			lrd->backchain =
			    cpu_to_le32(lmLog(log, tblk, lrd, tlck));
		}

		/*
		 *	format maplock(s) for txUpdateMap() to update bmap
		 */
		maplock->index = 0;

		/*
		 * allocate entries XAD[lwm:next):
		 */
		if (lwm < next) {
			/* format a maplock for txUpdateMap() to update bPMAP
			 * for alloc of new/extended extents of XAD[lwm:next)
			 * from the page itself;
			 * txUpdateMap() resets (XAD_NEW|XAD_EXTEND) flag.
			 */
			tlck->flag |= tlckUPDATEMAP;
			xadlock->flag = mlckALLOCXADLIST;
			xadlock->count = next - lwm;
			xadlock->xdlist = &p->xad[lwm];

			jfs_info("xtLog: alloc ip:0x%p mp:0x%p count:%d "
				 "lwm:%d next:%d",
				 tlck->ip, mp, xadlock->count, lwm, next);
			maplock->index++;
			xadlock++;
		}

		/*
		 * truncate entry XAD[twm == next - 1]:
		 */
		if (twm == next - 1) {
			/* format a maplock for txUpdateMap() to update bmap
			 * to free truncated delta extent of the truncated
			 * entry XAD[next - 1];
			 * (xtlck->pxdlock = truncated delta extent);
			 */
			tlck->flag |= tlckUPDATEMAP;
			pxdlock = (struct pxd_lock *) xadlock;
			pxdlock->flag = mlckFREEPXD;
			pxdlock->count = 1;
			pxdlock->pxd = pxd;

			jfs_info("xtLog: truncate ip:0x%p mp:0x%p count:%d "
				 "hwm:%d", ip, mp, pxdlock->count, hwm);
			maplock->index++;
			xadlock++;
		}

		/*
		 * free entries XAD[next:hwm]:
		 */
		if (hwm >= next) {
			/* format a maplock for txUpdateMap() to update bmap
			 * to free extents of XAD[next:hwm] from thedeleted
			 * page itself;
			 */
			tlck->flag |= tlckUPDATEMAP;
			xadlock->flag = mlckFREEXADLIST;
			xadlock->count = hwm - next + 1;
			xadlock->xdlist = &p->xad[next];

			jfs_info("xtLog: free ip:0x%p mp:0x%p count:%d "
				 "next:%d hwm:%d",
				 tlck->ip, mp, xadlock->count, next, hwm);
			maplock->index++;
		}

		/* mark page as homeward bound */
		tlck->flag |= tlckWRITEPAGE;
	}
	return;
}

/*
 *	mapLog()
 *
 * function:	log from maplock of freed data extents;
 */
static void mapLog(struct jfs_log * log, struct tblock * tblk, struct lrd * lrd,
		   struct tlock * tlck)
{
	struct pxd_lock *pxdlock;
	int i, nlock;
	pxd_t *pxd;

	/*
	 *	page relocation: free the source page extent
	 *
	 * a maplock for txUpdateMap() for free of the page
	 * has been formatted at txLock() time saving the src
	 * relocated page address;
	 */
	if (tlck->type & tlckRELOCATE) {
		/* log LOG_NOREDOPAGE of the old relocated page
		 * for logredo() to start NoRedoPage filter;
		 */
		lrd->type = cpu_to_le16(LOG_NOREDOPAGE);
		pxdlock = (struct pxd_lock *) & tlck->lock;
		pxd = &lrd->log.redopage.pxd;
		*pxd = pxdlock->pxd;
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, NULL));

		/* (N.B. currently, logredo() does NOT update bmap
		 * for free of the page itself for (LOG_XTREE|LOG_NOREDOPAGE);
		 * if page free from relocation, LOG_UPDATEMAP log is
		 * specifically generated now for logredo()
		 * to update bmap for free of src relocated page;
		 * (new flag LOG_RELOCATE may be introduced which will
		 * inform logredo() to start NORedoPage filter and also
		 * update block allocation map at the same time, thus
		 * avoiding an extra log write);
		 */
		lrd->type = cpu_to_le16(LOG_UPDATEMAP);
		lrd->log.updatemap.type = cpu_to_le16(LOG_FREEPXD);
		lrd->log.updatemap.nxd = cpu_to_le16(1);
		lrd->log.updatemap.pxd = pxdlock->pxd;
		lrd->backchain = cpu_to_le32(lmLog(log, tblk, lrd, NULL));

		/* a maplock for txUpdateMap() for free of the page
		 * has been formatted at txLock() time;
		 */
		tlck->flag |= tlckUPDATEMAP;
		return;
	}
	/*

	 * Otherwise it's not a relocate request
	 *
	 */
	else {
		/* log LOG_UPDATEMAP for logredo() to update bmap for
		 * free of truncated/relocated delta extent of the data;
		 * e.g.: external EA extent, relocated/truncated extent
		 * from xtTailgate();
		 */
		lrd->type = cpu_to_le16(LOG_UPDATEMAP);
		pxdlock = (struct pxd_lock *) & tlck->lock;
		nlock = pxdlock->index;
		for (i = 0; i < nlock; i++, pxdlock++) {
			if (pxdlock->flag & mlckALLOCPXD)
				lrd->log.updatemap.type =
				    cpu_to_le16(LOG_ALLOCPXD);
			else
				lrd->log.updatemap.type =
				    cpu_to_le16(LOG_FREEPXD);
			lrd->log.updatemap.nxd = cpu_to_le16(1);
			lrd->log.updatemap.pxd = pxdlock->pxd;
			lrd->backchain =
			    cpu_to_le32(lmLog(log, tblk, lrd, NULL));
			jfs_info("mapLog: xaddr:0x%lx xlen:0x%x",
				 (ulong) addressPXD(&pxdlock->pxd),
				 lengthPXD(&pxdlock->pxd));
		}

		/* update bmap */
		tlck->flag |= tlckUPDATEMAP;
	}
}

/*
 *	txEA()
 *
 * function:	acquire maplock for EA/ACL extents or
 *		set COMMIT_INLINE flag;
 */
void txEA(tid_t tid, struct inode *ip, dxd_t * oldea, dxd_t * newea)
{
	struct tlock *tlck = NULL;
	struct pxd_lock *maplock = NULL, *pxdlock = NULL;

	/*
	 * format maplock for alloc of new EA extent
	 */
	if (newea) {
		/* Since the newea could be a completely zeroed entry we need to
		 * check for the two flags which indicate we should actually
		 * commit new EA data
		 */
		if (newea->flag & DXD_EXTENT) {
			tlck = txMaplock(tid, ip, tlckMAP);
			maplock = (struct pxd_lock *) & tlck->lock;
			pxdlock = (struct pxd_lock *) maplock;
			pxdlock->flag = mlckALLOCPXD;
			PXDaddress(&pxdlock->pxd, addressDXD(newea));
			PXDlength(&pxdlock->pxd, lengthDXD(newea));
			pxdlock++;
			maplock->index = 1;
		} else if (newea->flag & DXD_INLINE) {
			tlck = NULL;

			set_cflag(COMMIT_Inlineea, ip);
		}
	}

	/*
	 * format maplock for free of old EA extent
	 */
	if (!test_cflag(COMMIT_Nolink, ip) && oldea->flag & DXD_EXTENT) {
		if (tlck == NULL) {
			tlck = txMaplock(tid, ip, tlckMAP);
			maplock = (struct pxd_lock *) & tlck->lock;
			pxdlock = (struct pxd_lock *) maplock;
			maplock->index = 0;
		}
		pxdlock->flag = mlckFREEPXD;
		PXDaddress(&pxdlock->pxd, addressDXD(oldea));
		PXDlength(&pxdlock->pxd, lengthDXD(oldea));
		maplock->index++;
	}
}

/*
 *	txForce()
 *
 * function: synchronously write pages locked by transaction
 *	     after txLog() but before txUpdateMap();
 */
static void txForce(struct tblock * tblk)
{
	struct tlock *tlck;
	lid_t lid, next;
	struct metapage *mp;

	/*
	 * reverse the order of transaction tlocks in
	 * careful update order of address index pages
	 * (right to left, bottom up)
	 */
	tlck = lid_to_tlock(tblk->next);
	lid = tlck->next;
	tlck->next = 0;
	while (lid) {
		tlck = lid_to_tlock(lid);
		next = tlck->next;
		tlck->next = tblk->next;
		tblk->next = lid;
		lid = next;
	}

	/*
	 * synchronously write the page, and
	 * hold the page for txUpdateMap();
	 */
	for (lid = tblk->next; lid; lid = next) {
		tlck = lid_to_tlock(lid);
		next = tlck->next;

		if ((mp = tlck->mp) != NULL &&
		    (tlck->type & tlckBTROOT) == 0) {
			assert(mp->xflag & COMMIT_PAGE);

			if (tlck->flag & tlckWRITEPAGE) {
				tlck->flag &= ~tlckWRITEPAGE;

				/* do not release page to freelist */
				force_metapage(mp);
#if 0
				/*
				 * The "right" thing to do here is to
				 * synchronously write the metadata.
				 * With the current implementation this
				 * is hard since write_metapage requires
				 * us to kunmap & remap the page.  If we
				 * have tlocks pointing into the metadata
				 * pages, we don't want to do this.  I think
				 * we can get by with synchronously writing
				 * the pages when they are released.
				 */
				assert(mp->nohomeok);
				set_bit(META_dirty, &mp->flag);
				set_bit(META_sync, &mp->flag);
#endif
			}
		}
	}
}

/*
 *	txUpdateMap()
 *
 * function:	update persistent allocation map (and working map
 *		if appropriate);
 *
 * parameter:
 */
static void txUpdateMap(struct tblock * tblk)
{
	struct inode *ip;
	struct inode *ipimap;
	lid_t lid;
	struct tlock *tlck;
	struct maplock *maplock;
	struct pxd_lock pxdlock;
	int maptype;
	int k, nlock;
	struct metapage *mp = NULL;

	ipimap = JFS_SBI(tblk->sb)->ipimap;

	maptype = (tblk->xflag & COMMIT_PMAP) ? COMMIT_PMAP : COMMIT_PWMAP;


	/*
	 *	update block allocation map
	 *
	 * update allocation state in pmap (and wmap) and
	 * update lsn of the pmap page;
	 */
	/*
	 * scan each tlock/page of transaction for block allocation/free:
	 *
	 * for each tlock/page of transaction, update map.
	 *  ? are there tlock for pmap and pwmap at the same time ?
	 */
	for (lid = tblk->next; lid; lid = tlck->next) {
		tlck = lid_to_tlock(lid);

		if ((tlck->flag & tlckUPDATEMAP) == 0)
			continue;

		if (tlck->flag & tlckFREEPAGE) {
			/*
			 * Another thread may attempt to reuse freed space
			 * immediately, so we want to get rid of the metapage
			 * before anyone else has a chance to get it.
			 * Lock metapage, update maps, then invalidate
			 * the metapage.
			 */
			mp = tlck->mp;
			ASSERT(mp->xflag & COMMIT_PAGE);
			grab_metapage(mp);
		}

		/*
		 * extent list:
		 * . in-line PXD list:
		 * . out-of-line XAD list:
		 */
		maplock = (struct maplock *) & tlck->lock;
		nlock = maplock->index;

		for (k = 0; k < nlock; k++, maplock++) {
			/*
			 * allocate blocks in persistent map:
			 *
			 * blocks have been allocated from wmap at alloc time;
			 */
			if (maplock->flag & mlckALLOC) {
				txAllocPMap(ipimap, maplock, tblk);
			}
			/*
			 * free blocks in persistent and working map:
			 * blocks will be freed in pmap and then in wmap;
			 *
			 * ? tblock specifies the PMAP/PWMAP based upon
			 * transaction
			 *
			 * free blocks in persistent map:
			 * blocks will be freed from wmap at last reference
			 * release of the object for regular files;
			 *
			 * Alway free blocks from both persistent & working
			 * maps for directories
			 */
			else {	/* (maplock->flag & mlckFREE) */

				if (tlck->flag & tlckDIRECTORY)
					txFreeMap(ipimap, maplock,
						  tblk, COMMIT_PWMAP);
				else
					txFreeMap(ipimap, maplock,
						  tblk, maptype);
			}
		}
		if (tlck->flag & tlckFREEPAGE) {
			if (!(tblk->flag & tblkGC_LAZY)) {
				/* This is equivalent to txRelease */
				ASSERT(mp->lid == lid);
				tlck->mp->lid = 0;
			}
			assert(mp->nohomeok == 1);
			metapage_homeok(mp);
			discard_metapage(mp);
			tlck->mp = NULL;
		}
	}
	/*
	 *	update inode allocation map
	 *
	 * update allocation state in pmap and
	 * update lsn of the pmap page;
	 * update in-memory inode flag/state
	 *
	 * unlock mapper/write lock
	 */
	if (tblk->xflag & COMMIT_CREATE) {
		diUpdatePMap(ipimap, tblk->ino, false, tblk);
		/* update persistent block allocation map
		 * for the allocation of inode extent;
		 */
		pxdlock.flag = mlckALLOCPXD;
		pxdlock.pxd = tblk->u.ixpxd;
		pxdlock.index = 1;
		txAllocPMap(ipimap, (struct maplock *) & pxdlock, tblk);
	} else if (tblk->xflag & COMMIT_DELETE) {
		ip = tblk->u.ip;
		diUpdatePMap(ipimap, ip->i_ino, true, tblk);
		iput(ip);
	}
}

/*
 *	txAllocPMap()
 *
 * function: allocate from persistent map;
 *
 * parameter:
 *	ipbmap	-
 *	malock	-
 *		xad list:
 *		pxd:
 *
 *	maptype -
 *		allocate from persistent map;
 *		free from persistent map;
 *		(e.g., tmp file - free from working map at releae
 *		 of last reference);
 *		free from persistent and working map;
 *
 *	lsn	- log sequence number;
 */
static void txAllocPMap(struct inode *ip, struct maplock * maplock,
			struct tblock * tblk)
{
	struct inode *ipbmap = JFS_SBI(ip->i_sb)->ipbmap;
	struct xdlistlock *xadlistlock;
	xad_t *xad;
	s64 xaddr;
	int xlen;
	struct pxd_lock *pxdlock;
	struct xdlistlock *pxdlistlock;
	pxd_t *pxd;
	int n;

	/*
	 * allocate from persistent map;
	 */
	if (maplock->flag & mlckALLOCXADLIST) {
		xadlistlock = (struct xdlistlock *) maplock;
		xad = xadlistlock->xdlist;
		for (n = 0; n < xadlistlock->count; n++, xad++) {
			if (xad->flag & (XAD_NEW | XAD_EXTENDED)) {
				xaddr = addressXAD(xad);
				xlen = lengthXAD(xad);
				dbUpdatePMap(ipbmap, false, xaddr,
					     (s64) xlen, tblk);
				xad->flag &= ~(XAD_NEW | XAD_EXTENDED);
				jfs_info("allocPMap: xaddr:0x%lx xlen:%d",
					 (ulong) xaddr, xlen);
			}
		}
	} else if (maplock->flag & mlckALLOCPXD) {
		pxdlock = (struct pxd_lock *) maplock;
		xaddr = addressPXD(&pxdlock->pxd);
		xlen = lengthPXD(&pxdlock->pxd);
		dbUpdatePMap(ipbmap, false, xaddr, (s64) xlen, tblk);
		jfs_info("allocPMap: xaddr:0x%lx xlen:%d", (ulong) xaddr, xlen);
	} else {		/* (maplock->flag & mlckALLOCPXDLIST) */

		pxdlistlock = (struct xdlistlock *) maplock;
		pxd = pxdlistlock->xdlist;
		for (n = 0; n < pxdlistlock->count; n++, pxd++) {
			xaddr = addressPXD(pxd);
			xlen = lengthPXD(pxd);
			dbUpdatePMap(ipbmap, false, xaddr, (s64) xlen,
				     tblk);
			jfs_info("allocPMap: xaddr:0x%lx xlen:%d",
				 (ulong) xaddr, xlen);
		}
	}
}

/*
 *	txFreeMap()
 *
 * function:	free from persistent and/or working map;
 *
 * todo: optimization
 */
void txFreeMap(struct inode *ip,
	       struct maplock * maplock, struct tblock * tblk, int maptype)
{
	struct inode *ipbmap = JFS_SBI(ip->i_sb)->ipbmap;
	struct xdlistlock *xadlistlock;
	xad_t *xad;
	s64 xaddr;
	int xlen;
	struct pxd_lock *pxdlock;
	struct xdlistlock *pxdlistlock;
	pxd_t *pxd;
	int n;

	jfs_info("txFreeMap: tblk:0x%p maplock:0x%p maptype:0x%x",
		 tblk, maplock, maptype);

	/*
	 * free from persistent map;
	 */
	if (maptype == COMMIT_PMAP || maptype == COMMIT_PWMAP) {
		if (maplock->flag & mlckFREEXADLIST) {
			xadlistlock = (struct xdlistlock *) maplock;
			xad = xadlistlock->xdlist;
			for (n = 0; n < xadlistlock->count; n++, xad++) {
				if (!(xad->flag & XAD_NEW)) {
					xaddr = addressXAD(xad);
					xlen = lengthXAD(xad);
					dbUpdatePMap(ipbmap, true, xaddr,
						     (s64) xlen, tblk);
					jfs_info("freePMap: xaddr:0x%lx "
						 "xlen:%d",
						 (ulong) xaddr, xlen);
				}
			}
		} else if (maplock->flag & mlckFREEPXD) {
			pxdlock = (struct pxd_lock *) maplock;
			xaddr = addressPXD(&pxdlock->pxd);
			xlen = lengthPXD(&pxdlock->pxd);
			dbUpdatePMap(ipbmap, true, xaddr, (s64) xlen,
				     tblk);
			jfs_info("freePMap: xaddr:0x%lx xlen:%d",
				 (ulong) xaddr, xlen);
		} else {	/* (maplock->flag & mlckALLOCPXDLIST) */

			pxdlistlock = (struct xdlistlock *) maplock;
			pxd = pxdlistlock->xdlist;
			for (n = 0; n < pxdlistlock->count; n++, pxd++) {
				xaddr = addressPXD(pxd);
				xlen = lengthPXD(pxd);
				dbUpdatePMap(ipbmap, true, xaddr,
					     (s64) xlen, tblk);
				jfs_info("freePMap: xaddr:0x%lx xlen:%d",
					 (ulong) xaddr, xlen);
			}
		}
	}

	/*
	 * free from working map;
	 */
	if (maptype == COMMIT_PWMAP || maptype == COMMIT_WMAP) {
		if (maplock->flag & mlckFREEXADLIST) {
			xadlistlock = (struct xdlistlock *) maplock;
			xad = xadlistlock->xdlist;
			for (n = 0; n < xadlistlock->count; n++, xad++) {
				xaddr = addressXAD(xad);
				xlen = lengthXAD(xad);
				dbFree(ip, xaddr, (s64) xlen);
				xad->flag = 0;
				jfs_info("freeWMap: xaddr:0x%lx xlen:%d",
					 (ulong) xaddr, xlen);
			}
		} else if (maplock->flag & mlckFREEPXD) {
			pxdlock = (struct pxd_lock *) maplock;
			xaddr = addressPXD(&pxdlock->pxd);
			xlen = lengthPXD(&pxdlock->pxd);
			dbFree(ip, xaddr, (s64) xlen);
			jfs_info("freeWMap: xaddr:0x%lx xlen:%d",
				 (ulong) xaddr, xlen);
		} else {	/* (maplock->flag & mlckFREEPXDLIST) */

			pxdlistlock = (struct xdlistlock *) maplock;
			pxd = pxdlistlock->xdlist;
			for (n = 0; n < pxdlistlock->count; n++, pxd++) {
				xaddr = addressPXD(pxd);
				xlen = lengthPXD(pxd);
				dbFree(ip, xaddr, (s64) xlen);
				jfs_info("freeWMap: xaddr:0x%lx xlen:%d",
					 (ulong) xaddr, xlen);
			}
		}
	}
}

/*
 *	txFreelock()
 *
 * function:	remove tlock from inode anonymous locklist
 */
void txFreelock(struct inode *ip)
{
	struct jfs_inode_info *jfs_ip = JFS_IP(ip);
	struct tlock *xtlck, *tlck;
	lid_t xlid = 0, lid;

	if (!jfs_ip->atlhead)
		return;

	TXN_LOCK();
	xtlck = (struct tlock *) &jfs_ip->atlhead;

	while ((lid = xtlck->next) != 0) {
		tlck = lid_to_tlock(lid);
		if (tlck->flag & tlckFREELOCK) {
			xtlck->next = tlck->next;
			txLockFree(lid);
		} else {
			xtlck = tlck;
			xlid = lid;
		}
	}

	if (jfs_ip->atlhead)
		jfs_ip->atltail = xlid;
	else {
		jfs_ip->atltail = 0;
		/*
		 * If inode was on anon_list, remove it
		 */
		list_del_init(&jfs_ip->anon_inode_list);
	}
	TXN_UNLOCK();
}

/*
 *	txAbort()
 *
 * function: abort tx before commit;
 *
 * frees line-locks and segment locks for all
 * segments in comdata structure.
 * Optionally sets state of file-system to FM_DIRTY in super-block.
 * log age of page-frames in memory for which caller has
 * are reset to 0 (to avoid logwarap).
 */
void txAbort(tid_t tid, int dirty)
{
	lid_t lid, next;
	struct metapage *mp;
	struct tblock *tblk = tid_to_tblock(tid);
	struct tlock *tlck;

	/*
	 * free tlocks of the transaction
	 */
	for (lid = tblk->next; lid; lid = next) {
		tlck = lid_to_tlock(lid);
		next = tlck->next;
		mp = tlck->mp;
		JFS_IP(tlck->ip)->xtlid = 0;

		if (mp) {
			mp->lid = 0;

			/*
			 * reset lsn of page to avoid logwarap:
			 *
			 * (page may have been previously committed by another
			 * transaction(s) but has not been paged, i.e.,
			 * it may be on logsync list even though it has not
			 * been logged for the current tx.)
			 */
			if (mp->xflag & COMMIT_PAGE && mp->lsn)
				LogSyncRelease(mp);
		}
		/* insert tlock at head of freelist */
		TXN_LOCK();
		txLockFree(lid);
		TXN_UNLOCK();
	}

	/* caller will free the transaction block */

	tblk->next = tblk->last = 0;

	/*
	 * mark filesystem dirty
	 */
	if (dirty)
		jfs_error(tblk->sb, "\n");

	return;
}

/*
 *	txLazyCommit(void)
 *
 *	All transactions except those changing ipimap (COMMIT_FORCE) are
 *	processed by this routine.  This insures that the inode and block
 *	allocation maps are updated in order.  For synchronous transactions,
 *	let the user thread finish processing after txUpdateMap() is called.
 */
static void txLazyCommit(struct tblock * tblk)
{
	struct jfs_log *log;

	while (((tblk->flag & tblkGC_READY) == 0) &&
	       ((tblk->flag & tblkGC_UNLOCKED) == 0)) {
		/* We must have gotten ahead of the user thread
		 */
		jfs_info("jfs_lazycommit: tblk 0x%p not unlocked", tblk);
		yield();
	}

	jfs_info("txLazyCommit: processing tblk 0x%p", tblk);

	txUpdateMap(tblk);

	log = (struct jfs_log *) JFS_SBI(tblk->sb)->log;

	spin_lock_irq(&log->gclock);	// LOGGC_LOCK

	tblk->flag |= tblkGC_COMMITTED;

	if (tblk->flag & tblkGC_READY)
		log->gcrtc--;

	wake_up_all(&tblk->gcwait);	// LOGGC_WAKEUP

	/*
	 * Can't release log->gclock until we've tested tblk->flag
	 */
	if (tblk->flag & tblkGC_LAZY) {
		spin_unlock_irq(&log->gclock);	// LOGGC_UNLOCK
		txUnlock(tblk);
		tblk->flag &= ~tblkGC_LAZY;
		txEnd(tblk - TxBlock);	/* Convert back to tid */
	} else
		spin_unlock_irq(&log->gclock);	// LOGGC_UNLOCK

	jfs_info("txLazyCommit: done: tblk = 0x%p", tblk);
}

/*
 *	jfs_lazycommit(void)
 *
 *	To be run as a kernel daemon.  If lbmIODone is called in an interrupt
 *	context, or where blocking is not wanted, this routine will process
 *	committed transactions from the unlock queue.
 */
int jfs_lazycommit(void *arg)
{
	int WorkDone;
	struct tblock *tblk;
	unsigned long flags;
	struct jfs_sb_info *sbi;

	do {
		LAZY_LOCK(flags);
		jfs_commit_thread_waking = 0;	/* OK to wake another thread */
		while (!list_empty(&TxAnchor.unlock_queue)) {
			WorkDone = 0;
			list_for_each_entry(tblk, &TxAnchor.unlock_queue,
					    cqueue) {

				sbi = JFS_SBI(tblk->sb);
				/*
				 * For each volume, the transactions must be
				 * handled in order.  If another commit thread
				 * is handling a tblk for this superblock,
				 * skip it
				 */
				if (sbi->commit_state & IN_LAZYCOMMIT)
					continue;

				sbi->commit_state |= IN_LAZYCOMMIT;
				WorkDone = 1;

				/*
				 * Remove transaction from queue
				 */
				list_del(&tblk->cqueue);

				LAZY_UNLOCK(flags);
				txLazyCommit(tblk);
				LAZY_LOCK(flags);

				sbi->commit_state &= ~IN_LAZYCOMMIT;
				/*
				 * Don't continue in the for loop.  (We can't
				 * anyway, it's unsafe!)  We want to go back to
				 * the beginning of the list.
				 */
				break;
			}

			/* If there was nothing to do, don't continue */
			if (!WorkDone)
				break;
		}
		/* In case a wakeup came while all threads were active */
		jfs_commit_thread_waking = 0;

		if (freezing(current)) {
			LAZY_UNLOCK(flags);
			try_to_freeze();
		} else {
			DECLARE_WAITQUEUE(wq, current);

			add_wait_queue(&jfs_commit_thread_wait, &wq);
			set_current_state(TASK_INTERRUPTIBLE);
			LAZY_UNLOCK(flags);
			schedule();
			remove_wait_queue(&jfs_commit_thread_wait, &wq);
		}
	} while (!kthread_should_stop());

	if (!list_empty(&TxAnchor.unlock_queue))
		jfs_err("jfs_lazycommit being killed w/pending transactions!");
	else
		jfs_info("jfs_lazycommit being killed\n");
	return 0;
}

void txLazyUnlock(struct tblock * tblk)
{
	unsigned long flags;

	LAZY_LOCK(flags);

	list_add_tail(&tblk->cqueue, &TxAnchor.unlock_queue);
	/*
	 * Don't wake up a commit thread if there is already one servicing
	 * this superblock, or if the last one we woke up hasn't started yet.
	 */
	if (!(JFS_SBI(tblk->sb)->commit_state & IN_LAZYCOMMIT) &&
	    !jfs_commit_thread_waking) {
		jfs_commit_thread_waking = 1;
		wake_up(&jfs_commit_thread_wait);
	}
	LAZY_UNLOCK(flags);
}

static void LogSyncRelease(struct metapage * mp)
{
	struct jfs_log *log = mp->log;

	assert(mp->nohomeok);
	assert(log);
	metapage_homeok(mp);
}

/*
 *	txQuiesce
 *
 *	Block all new transactions and push anonymous transactions to
 *	completion
 *
 *	This does almost the same thing as jfs_sync below.  We don't
 *	worry about deadlocking when jfs_tlocks_low is set, since we would
 *	expect jfs_sync to get us out of that jam.
 */
void txQuiesce(struct super_block *sb)
{
	struct inode *ip;
	struct jfs_inode_info *jfs_ip;
	struct jfs_log *log = JFS_SBI(sb)->log;
	tid_t tid;

	set_bit(log_QUIESCE, &log->flag);

	TXN_LOCK();
restart:
	while (!list_empty(&TxAnchor.anon_list)) {
		jfs_ip = list_entry(TxAnchor.anon_list.next,
				    struct jfs_inode_info,
				    anon_inode_list);
		ip = &jfs_ip->vfs_inode;

		/*
		 * inode will be removed from anonymous list
		 * when it is committed
		 */
		TXN_UNLOCK();
		tid = txBegin(ip->i_sb, COMMIT_INODE | COMMIT_FORCE);
		mutex_lock(&jfs_ip->commit_mutex);
		txCommit(tid, 1, &ip, 0);
		txEnd(tid);
		mutex_unlock(&jfs_ip->commit_mutex);
		/*
		 * Just to be safe.  I don't know how
		 * long we can run without blocking
		 */
		cond_resched();
		TXN_LOCK();
	}

	/*
	 * If jfs_sync is running in parallel, there could be some inodes
	 * on anon_list2.  Let's check.
	 */
	if (!list_empty(&TxAnchor.anon_list2)) {
		list_splice(&TxAnchor.anon_list2, &TxAnchor.anon_list);
		INIT_LIST_HEAD(&TxAnchor.anon_list2);
		goto restart;
	}
	TXN_UNLOCK();

	/*
	 * We may need to kick off the group commit
	 */
	jfs_flush_journal(log, 0);
}

/*
 * txResume()
 *
 * Allows transactions to start again following txQuiesce
 */
void txResume(struct super_block *sb)
{
	struct jfs_log *log = JFS_SBI(sb)->log;

	clear_bit(log_QUIESCE, &log->flag);
	TXN_WAKEUP(&log->syncwait);
}

/*
 *	jfs_sync(void)
 *
 *	To be run as a kernel daemon.  This is awakened when tlocks run low.
 *	We write any inodes that have anonymous tlocks so they will become
 *	available.
 */
int jfs_sync(void *arg)
{
	struct inode *ip;
	struct jfs_inode_info *jfs_ip;
	tid_t tid;

	do {
		/*
		 * write each inode on the anonymous inode list
		 */
		TXN_LOCK();
		while (jfs_tlocks_low && !list_empty(&TxAnchor.anon_list)) {
			jfs_ip = list_entry(TxAnchor.anon_list.next,
					    struct jfs_inode_info,
					    anon_inode_list);
			ip = &jfs_ip->vfs_inode;

			if (! igrab(ip)) {
				/*
				 * Inode is being freed
				 */
				list_del_init(&jfs_ip->anon_inode_list);
			} else if (mutex_trylock(&jfs_ip->commit_mutex)) {
				/*
				 * inode will be removed from anonymous list
				 * when it is committed
				 */
				TXN_UNLOCK();
				tid = txBegin(ip->i_sb, COMMIT_INODE);
				txCommit(tid, 1, &ip, 0);
				txEnd(tid);
				mutex_unlock(&jfs_ip->commit_mutex);

				iput(ip);
				/*
				 * Just to be safe.  I don't know how
				 * long we can run without blocking
				 */
				cond_resched();
				TXN_LOCK();
			} else {
				/* We can't get the commit mutex.  It may
				 * be held by a thread waiting for tlock's
				 * so let's not block here.  Save it to
				 * put back on the anon_list.
				 */

				/* Move from anon_list to anon_list2 */
				list_move(&jfs_ip->anon_inode_list,
					  &TxAnchor.anon_list2);

				TXN_UNLOCK();
				iput(ip);
				TXN_LOCK();
			}
		}
		/* Add anon_list2 back to anon_list */
		list_splice_init(&TxAnchor.anon_list2, &TxAnchor.anon_list);

		if (freezing(current)) {
			TXN_UNLOCK();
			try_to_freeze();
		} else {
			set_current_state(TASK_INTERRUPTIBLE);
			TXN_UNLOCK();
			schedule();
		}
	} while (!kthread_should_stop());

	jfs_info("jfs_sync being killed");
	return 0;
}

#if defined(CONFIG_PROC_FS) && defined(CONFIG_JFS_DEBUG)
static int jfs_txanchor_proc_show(struct seq_file *m, void *v)
{
	char *freewait;
	char *freelockwait;
	char *lowlockwait;

	freewait =
	    waitqueue_active(&TxAnchor.freewait) ? "active" : "empty";
	freelockwait =
	    waitqueue_active(&TxAnchor.freelockwait) ? "active" : "empty";
	lowlockwait =
	    waitqueue_active(&TxAnchor.lowlockwait) ? "active" : "empty";

	seq_printf(m,
		       "JFS TxAnchor\n"
		       "============\n"
		       "freetid = %d\n"
		       "freewait = %s\n"
		       "freelock = %d\n"
		       "freelockwait = %s\n"
		       "lowlockwait = %s\n"
		       "tlocksInUse = %d\n"
		       "jfs_tlocks_low = %d\n"
		       "unlock_queue is %sempty\n",
		       TxAnchor.freetid,
		       freewait,
		       TxAnchor.freelock,
		       freelockwait,
		       lowlockwait,
		       TxAnchor.tlocksInUse,
		       jfs_tlocks_low,
		       list_empty(&TxAnchor.unlock_queue) ? "" : "not ");
	return 0;
}

static int jfs_txanchor_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, jfs_txanchor_proc_show, NULL);
}

const struct file_operations jfs_txanchor_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= jfs_txanchor_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

#if defined(CONFIG_PROC_FS) && defined(CONFIG_JFS_STATISTICS)
static int jfs_txstats_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		       "JFS TxStats\n"
		       "===========\n"
		       "calls to txBegin = %d\n"
		       "txBegin blocked by sync barrier = %d\n"
		       "txBegin blocked by tlocks low = %d\n"
		       "txBegin blocked by no free tid = %d\n"
		       "calls to txBeginAnon = %d\n"
		       "txBeginAnon blocked by sync barrier = %d\n"
		       "txBeginAnon blocked by tlocks low = %d\n"
		       "calls to txLockAlloc = %d\n"
		       "tLockAlloc blocked by no free lock = %d\n",
		       TxStat.txBegin,
		       TxStat.txBegin_barrier,
		       TxStat.txBegin_lockslow,
		       TxStat.txBegin_freetid,
		       TxStat.txBeginAnon,
		       TxStat.txBeginAnon_barrier,
		       TxStat.txBeginAnon_lockslow,
		       TxStat.txLockAlloc,
		       TxStat.txLockAlloc_freelock);
	return 0;
}

static int jfs_txstats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, jfs_txstats_proc_show, NULL);
}

const struct file_operations jfs_txstats_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= jfs_txstats_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_txnmgr.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines Corp., 2000-2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/fs.h>
// #include "jfs_unicode.h"

/*
 * Latin upper case
 */
signed char UniUpperTable[512] = {
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 000-00f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 010-01f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 020-02f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 030-03f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 040-04f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 050-05f */
   0,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 060-06f */
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,  0,  0,  0,  0,  0, /* 070-07f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 080-08f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 090-09f */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 0a0-0af */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 0b0-0bf */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 0c0-0cf */
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 0d0-0df */
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 0e0-0ef */
 -32,-32,-32,-32,-32,-32,-32,  0,-32,-32,-32,-32,-32,-32,-32,121, /* 0f0-0ff */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 100-10f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 110-11f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 120-12f */
   0,  0,  0, -1,  0, -1,  0, -1,  0,  0, -1,  0, -1,  0, -1,  0, /* 130-13f */
  -1,  0, -1,  0, -1,  0, -1,  0, -1,  0,  0, -1,  0, -1,  0, -1, /* 140-14f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 150-15f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 160-16f */
   0, -1,  0, -1,  0, -1,  0, -1,  0,  0, -1,  0, -1,  0, -1,  0, /* 170-17f */
   0,  0,  0, -1,  0, -1,  0,  0, -1,  0,  0,  0, -1,  0,  0,  0, /* 180-18f */
   0,  0, -1,  0,  0,  0,  0,  0,  0, -1,  0,  0,  0,  0,  0,  0, /* 190-19f */
   0, -1,  0, -1,  0, -1,  0,  0, -1,  0,  0,  0,  0, -1,  0,  0, /* 1a0-1af */
  -1,  0,  0,  0, -1,  0, -1,  0,  0, -1,  0,  0,  0, -1,  0,  0, /* 1b0-1bf */
   0,  0,  0,  0,  0, -1, -2,  0, -1, -2,  0, -1, -2,  0, -1,  0, /* 1c0-1cf */
  -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,-79,  0, -1, /* 1d0-1df */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e0-1ef */
   0,  0, -1, -2,  0, -1,  0,  0,  0, -1,  0, -1,  0, -1,  0, -1, /* 1f0-1ff */
};

/* Upper case range - Greek */
static signed char UniCaseRangeU03a0[47] = {
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,-38,-37,-37,-37, /* 3a0-3af */
   0,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 3b0-3bf */
 -32,-32,-31,-32,-32,-32,-32,-32,-32,-32,-32,-32,-64,-63,-63,
};

/* Upper case range - Cyrillic */
static signed char UniCaseRangeU0430[48] = {
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 430-43f */
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* 440-44f */
   0,-80,-80,-80,-80,-80,-80,-80,-80,-80,-80,-80,-80,  0,-80,-80, /* 450-45f */
};

/* Upper case range - Extended cyrillic */
static signed char UniCaseRangeU0490[61] = {
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 490-49f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 4a0-4af */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 4b0-4bf */
   0,  0, -1,  0, -1,  0,  0,  0, -1,  0,  0,  0, -1,
};

/* Upper case range - Extended latin and greek */
static signed char UniCaseRangeU1e00[509] = {
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e00-1e0f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e10-1e1f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e20-1e2f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e30-1e3f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e40-1e4f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e50-1e5f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e60-1e6f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e70-1e7f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1e80-1e8f */
   0, -1,  0, -1,  0, -1,  0,  0,  0,  0,  0,-59,  0, -1,  0, -1, /* 1e90-1e9f */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1ea0-1eaf */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1eb0-1ebf */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1ec0-1ecf */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1ed0-1edf */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0, -1, /* 1ee0-1eef */
   0, -1,  0, -1,  0, -1,  0, -1,  0, -1,  0,  0,  0,  0,  0,  0, /* 1ef0-1eff */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f00-1f0f */
   8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f10-1f1f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f20-1f2f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f30-1f3f */
   8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f40-1f4f */
   0,  8,  0,  8,  0,  8,  0,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f50-1f5f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f60-1f6f */
  74, 74, 86, 86, 86, 86,100,100,  0,  0,112,112,126,126,  0,  0, /* 1f70-1f7f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f80-1f8f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1f90-1f9f */
   8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fa0-1faf */
   8,  8,  0,  9,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fb0-1fbf */
   0,  0,  0,  9,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fc0-1fcf */
   8,  8,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fd0-1fdf */
   8,  8,  0,  0,  0,  7,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, /* 1fe0-1fef */
   0,  0,  0,  9,  0,  0,  0,  0,  0,  0,  0,  0,  0,
};

/* Upper case range - Wide latin */
static signed char UniCaseRangeUff40[27] = {
   0,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32, /* ff40-ff4f */
 -32,-32,-32,-32,-32,-32,-32,-32,-32,-32,-32,
};

/*
 * Upper Case Range
 */
UNICASERANGE UniUpperRange[] = {
    { 0x03a0,  0x03ce,  UniCaseRangeU03a0 },
    { 0x0430,  0x045f,  UniCaseRangeU0430 },
    { 0x0490,  0x04cc,  UniCaseRangeU0490 },
    { 0x1e00,  0x1ffc,  UniCaseRangeU1e00 },
    { 0xff40,  0xff5a,  UniCaseRangeUff40 },
    { 0 }
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/jfs_uniupr.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines  Corp., 2000-2004
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include <linux/quotaops.h>
// #include "jfs_incore.h"
// #include "jfs_filsys.h"
// #include "jfs_metapage.h"
// #include "jfs_dinode.h"
// #include "jfs_imap.h"
// #include "jfs_dmap.h"
// #include "jfs_superblock.h"
// #include "jfs_txnmgr.h"
// #include "jfs_debug.h"

#define BITSPERPAGE	(PSIZE << 3)
#define L2MEGABYTE	20
#define MEGABYTE	(1 << L2MEGABYTE)
#define MEGABYTE32	(MEGABYTE << 5)

/* convert block number to bmap file page number */
#define BLKTODMAPN(b)\
	(((b) >> 13) + ((b) >> 23) + ((b) >> 33) + 3 + 1)

/*
 *	jfs_extendfs()
 *
 * function: extend file system;
 *
 *   |-------------------------------|----------|----------|
 *   file system space               fsck       inline log
 *                                   workspace  space
 *
 * input:
 *	new LVSize: in LV blocks (required)
 *	new LogSize: in LV blocks (optional)
 *	new FSSize: in LV blocks (optional)
 *
 * new configuration:
 * 1. set new LogSize as specified or default from new LVSize;
 * 2. compute new FSCKSize from new LVSize;
 * 3. set new FSSize as MIN(FSSize, LVSize-(LogSize+FSCKSize)) where
 *    assert(new FSSize >= old FSSize),
 *    i.e., file system must not be shrunk;
 */
int jfs_extendfs(struct super_block *sb, s64 newLVSize, int newLogSize)
{
	int rc = 0;
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	struct inode *ipbmap = sbi->ipbmap;
	struct inode *ipbmap2;
	struct inode *ipimap = sbi->ipimap;
	struct jfs_log *log = sbi->log;
	struct bmap *bmp = sbi->bmap;
	s64 newLogAddress, newFSCKAddress;
	int newFSCKSize;
	s64 newMapSize = 0, mapSize;
	s64 XAddress, XSize, nblocks, xoff, xaddr, t64;
	s64 oldLVSize;
	s64 newFSSize;
	s64 VolumeSize;
	int newNpages = 0, nPages, newPage, xlen, t32;
	int tid;
	int log_formatted = 0;
	struct inode *iplist[1];
	struct jfs_superblock *j_sb, *j_sb2;
	s64 old_agsize;
	int agsizechanged = 0;
	struct buffer_head *bh, *bh2;

	/* If the volume hasn't grown, get out now */

	if (sbi->mntflag & JFS_INLINELOG)
		oldLVSize = addressPXD(&sbi->logpxd) + lengthPXD(&sbi->logpxd);
	else
		oldLVSize = addressPXD(&sbi->fsckpxd) +
		    lengthPXD(&sbi->fsckpxd);

	if (oldLVSize >= newLVSize) {
		printk(KERN_WARNING
		       "jfs_extendfs: volume hasn't grown, returning\n");
		goto out;
	}

	VolumeSize = sb->s_bdev->bd_inode->i_size >> sb->s_blocksize_bits;

	if (VolumeSize) {
		if (newLVSize > VolumeSize) {
			printk(KERN_WARNING "jfs_extendfs: invalid size\n");
			rc = -EINVAL;
			goto out;
		}
	} else {
		/* check the device */
		bh = sb_bread(sb, newLVSize - 1);
		if (!bh) {
			printk(KERN_WARNING "jfs_extendfs: invalid size\n");
			rc = -EINVAL;
			goto out;
		}
		bforget(bh);
	}

	/* Can't extend write-protected drive */

	if (isReadOnly(ipbmap)) {
		printk(KERN_WARNING "jfs_extendfs: read-only file system\n");
		rc = -EROFS;
		goto out;
	}

	/*
	 *	reconfigure LV spaces
	 *	---------------------
	 *
	 * validate new size, or, if not specified, determine new size
	 */

	/*
	 * reconfigure inline log space:
	 */
	if ((sbi->mntflag & JFS_INLINELOG)) {
		if (newLogSize == 0) {
			/*
			 * no size specified: default to 1/256 of aggregate
			 * size; rounded up to a megabyte boundary;
			 */
			newLogSize = newLVSize >> 8;
			t32 = (1 << (20 - sbi->l2bsize)) - 1;
			newLogSize = (newLogSize + t32) & ~t32;
			newLogSize =
			    min(newLogSize, MEGABYTE32 >> sbi->l2bsize);
		} else {
			/*
			 * convert the newLogSize to fs blocks.
			 *
			 * Since this is given in megabytes, it will always be
			 * an even number of pages.
			 */
			newLogSize = (newLogSize * MEGABYTE) >> sbi->l2bsize;
		}

	} else
		newLogSize = 0;

	newLogAddress = newLVSize - newLogSize;

	/*
	 * reconfigure fsck work space:
	 *
	 * configure it to the end of the logical volume regardless of
	 * whether file system extends to the end of the aggregate;
	 * Need enough 4k pages to cover:
	 *  - 1 bit per block in aggregate rounded up to BPERDMAP boundary
	 *  - 1 extra page to handle control page and intermediate level pages
	 *  - 50 extra pages for the chkdsk service log
	 */
	t64 = ((newLVSize - newLogSize + BPERDMAP - 1) >> L2BPERDMAP)
	    << L2BPERDMAP;
	t32 = DIV_ROUND_UP(t64, BITSPERPAGE) + 1 + 50;
	newFSCKSize = t32 << sbi->l2nbperpage;
	newFSCKAddress = newLogAddress - newFSCKSize;

	/*
	 * compute new file system space;
	 */
	newFSSize = newLVSize - newLogSize - newFSCKSize;

	/* file system cannot be shrunk */
	if (newFSSize < bmp->db_mapsize) {
		rc = -EINVAL;
		goto out;
	}

	/*
	 * If we're expanding enough that the inline log does not overlap
	 * the old one, we can format the new log before we quiesce the
	 * filesystem.
	 */
	if ((sbi->mntflag & JFS_INLINELOG) && (newLogAddress > oldLVSize)) {
		if ((rc = lmLogFormat(log, newLogAddress, newLogSize)))
			goto out;
		log_formatted = 1;
	}
	/*
	 *	quiesce file system
	 *
	 * (prepare to move the inline log and to prevent map update)
	 *
	 * block any new transactions and wait for completion of
	 * all wip transactions and flush modified pages s.t.
	 * on-disk file system is in consistent state and
	 * log is not required for recovery.
	 */
	txQuiesce(sb);

	/* Reset size of direct inode */
	sbi->direct_inode->i_size =  sb->s_bdev->bd_inode->i_size;

	if (sbi->mntflag & JFS_INLINELOG) {
		/*
		 * deactivate old inline log
		 */
		lmLogShutdown(log);

		/*
		 * mark on-disk super block for fs in transition;
		 *
		 * update on-disk superblock for the new space configuration
		 * of inline log space and fsck work space descriptors:
		 * N.B. FS descriptor is NOT updated;
		 *
		 * crash recovery:
		 * logredo(): if FM_EXTENDFS, return to fsck() for cleanup;
		 * fsck(): if FM_EXTENDFS, reformat inline log and fsck
		 * workspace from superblock inline log descriptor and fsck
		 * workspace descriptor;
		 */

		/* read in superblock */
		if ((rc = readSuper(sb, &bh)))
			goto error_out;
		j_sb = (struct jfs_superblock *)bh->b_data;

		/* mark extendfs() in progress */
		j_sb->s_state |= cpu_to_le32(FM_EXTENDFS);
		j_sb->s_xsize = cpu_to_le64(newFSSize);
		PXDaddress(&j_sb->s_xfsckpxd, newFSCKAddress);
		PXDlength(&j_sb->s_xfsckpxd, newFSCKSize);
		PXDaddress(&j_sb->s_xlogpxd, newLogAddress);
		PXDlength(&j_sb->s_xlogpxd, newLogSize);

		/* synchronously update superblock */
		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);

		/*
		 * format new inline log synchronously;
		 *
		 * crash recovery: if log move in progress,
		 * reformat log and exit success;
		 */
		if (!log_formatted)
			if ((rc = lmLogFormat(log, newLogAddress, newLogSize)))
				goto error_out;

		/*
		 * activate new log
		 */
		log->base = newLogAddress;
		log->size = newLogSize >> (L2LOGPSIZE - sb->s_blocksize_bits);
		if ((rc = lmLogInit(log)))
			goto error_out;
	}

	/*
	 *	extend block allocation map
	 *	---------------------------
	 *
	 * extendfs() for new extension, retry after crash recovery;
	 *
	 * note: both logredo() and fsck() rebuild map from
	 * the bitmap and configuration parameter from superblock
	 * (disregarding all other control information in the map);
	 *
	 * superblock:
	 *  s_size: aggregate size in physical blocks;
	 */
	/*
	 *	compute the new block allocation map configuration
	 *
	 * map dinode:
	 *  di_size: map file size in byte;
	 *  di_nblocks: number of blocks allocated for map file;
	 *  di_mapsize: number of blocks in aggregate (covered by map);
	 * map control page:
	 *  db_mapsize: number of blocks in aggregate (covered by map);
	 */
	newMapSize = newFSSize;
	/* number of data pages of new bmap file:
	 * roundup new size to full dmap page boundary and
	 * add 1 extra dmap page for next extendfs()
	 */
	t64 = (newMapSize - 1) + BPERDMAP;
	newNpages = BLKTODMAPN(t64) + 1;

	/*
	 *	extend map from current map (WITHOUT growing mapfile)
	 *
	 * map new extension with unmapped part of the last partial
	 * dmap page, if applicable, and extra page(s) allocated
	 * at end of bmap by mkfs() or previous extendfs();
	 */
      extendBmap:
	/* compute number of blocks requested to extend */
	mapSize = bmp->db_mapsize;
	XAddress = mapSize;	/* eXtension Address */
	XSize = newMapSize - mapSize;	/* eXtension Size */
	old_agsize = bmp->db_agsize;	/* We need to know if this changes */

	/* compute number of blocks that can be extended by current mapfile */
	t64 = dbMapFileSizeToMapSize(ipbmap);
	if (mapSize > t64) {
		printk(KERN_ERR "jfs_extendfs: mapSize (0x%Lx) > t64 (0x%Lx)\n",
		       (long long) mapSize, (long long) t64);
		rc = -EIO;
		goto error_out;
	}
	nblocks = min(t64 - mapSize, XSize);

	/*
	 * update map pages for new extension:
	 *
	 * update/init dmap and bubble up the control hierarchy
	 * incrementally fold up dmaps into upper levels;
	 * update bmap control page;
	 */
	if ((rc = dbExtendFS(ipbmap, XAddress, nblocks)))
		goto error_out;

	agsizechanged |= (bmp->db_agsize != old_agsize);

	/*
	 * the map now has extended to cover additional nblocks:
	 * dn_mapsize = oldMapsize + nblocks;
	 */
	/* ipbmap->i_mapsize += nblocks; */
	XSize -= nblocks;

	/*
	 *	grow map file to cover remaining extension
	 *	and/or one extra dmap page for next extendfs();
	 *
	 * allocate new map pages and its backing blocks, and
	 * update map file xtree
	 */
	/* compute number of data pages of current bmap file */
	nPages = ipbmap->i_size >> L2PSIZE;

	/* need to grow map file ? */
	if (nPages == newNpages)
		goto finalizeBmap;

	/*
	 * grow bmap file for the new map pages required:
	 *
	 * allocate growth at the start of newly extended region;
	 * bmap file only grows sequentially, i.e., both data pages
	 * and possibly xtree index pages may grow in append mode,
	 * s.t. logredo() can reconstruct pre-extension state
	 * by washing away bmap file of pages outside s_size boundary;
	 */
	/*
	 * journal map file growth as if a regular file growth:
	 * (note: bmap is created with di_mode = IFJOURNAL|IFREG);
	 *
	 * journaling of bmap file growth is not required since
	 * logredo() do/can not use log records of bmap file growth
	 * but it provides careful write semantics, pmap update, etc.;
	 */
	/* synchronous write of data pages: bmap data pages are
	 * cached in meta-data cache, and not written out
	 * by txCommit();
	 */
	filemap_fdatawait(ipbmap->i_mapping);
	filemap_write_and_wait(ipbmap->i_mapping);
	diWriteSpecial(ipbmap, 0);

	newPage = nPages;	/* first new page number */
	xoff = newPage << sbi->l2nbperpage;
	xlen = (newNpages - nPages) << sbi->l2nbperpage;
	xlen = min(xlen, (int) nblocks) & ~(sbi->nbperpage - 1);
	xaddr = XAddress;

	tid = txBegin(sb, COMMIT_FORCE);

	if ((rc = xtAppend(tid, ipbmap, 0, xoff, nblocks, &xlen, &xaddr, 0))) {
		txEnd(tid);
		goto error_out;
	}
	/* update bmap file size */
	ipbmap->i_size += xlen << sbi->l2bsize;
	inode_add_bytes(ipbmap, xlen << sbi->l2bsize);

	iplist[0] = ipbmap;
	rc = txCommit(tid, 1, &iplist[0], COMMIT_FORCE);

	txEnd(tid);

	if (rc)
		goto error_out;

	/*
	 * map file has been grown now to cover extension to further out;
	 * di_size = new map file size;
	 *
	 * if huge extension, the previous extension based on previous
	 * map file size may not have been sufficient to cover whole extension
	 * (it could have been used up for new map pages),
	 * but the newly grown map file now covers lot bigger new free space
	 * available for further extension of map;
	 */
	/* any more blocks to extend ? */
	if (XSize)
		goto extendBmap;

      finalizeBmap:
	/* finalize bmap */
	dbFinalizeBmap(ipbmap);

	/*
	 *	update inode allocation map
	 *	---------------------------
	 *
	 * move iag lists from old to new iag;
	 * agstart field is not updated for logredo() to reconstruct
	 * iag lists if system crash occurs.
	 * (computation of ag number from agstart based on agsize
	 * will correctly identify the new ag);
	 */
	/* if new AG size the same as old AG size, done! */
	if (agsizechanged) {
		if ((rc = diExtendFS(ipimap, ipbmap)))
			goto error_out;

		/* finalize imap */
		if ((rc = diSync(ipimap)))
			goto error_out;
	}

	/*
	 *	finalize
	 *	--------
	 *
	 * extension is committed when on-disk super block is
	 * updated with new descriptors: logredo will recover
	 * crash before it to pre-extension state;
	 */

	/* sync log to skip log replay of bmap file growth transaction; */
	/* lmLogSync(log, 1); */

	/*
	 * synchronous write bmap global control page;
	 * for crash before completion of write
	 * logredo() will recover to pre-extendfs state;
	 * for crash after completion of write,
	 * logredo() will recover post-extendfs state;
	 */
	if ((rc = dbSync(ipbmap)))
		goto error_out;

	/*
	 * copy primary bmap inode to secondary bmap inode
	 */

	ipbmap2 = diReadSpecial(sb, BMAP_I, 1);
	if (ipbmap2 == NULL) {
		printk(KERN_ERR "jfs_extendfs: diReadSpecial(bmap) failed\n");
		goto error_out;
	}
	memcpy(&JFS_IP(ipbmap2)->i_xtroot, &JFS_IP(ipbmap)->i_xtroot, 288);
	ipbmap2->i_size = ipbmap->i_size;
	ipbmap2->i_blocks = ipbmap->i_blocks;

	diWriteSpecial(ipbmap2, 1);
	diFreeSpecial(ipbmap2);

	/*
	 *	update superblock
	 */
	if ((rc = readSuper(sb, &bh)))
		goto error_out;
	j_sb = (struct jfs_superblock *)bh->b_data;

	/* mark extendfs() completion */
	j_sb->s_state &= cpu_to_le32(~FM_EXTENDFS);
	j_sb->s_size = cpu_to_le64(bmp->db_mapsize <<
				   le16_to_cpu(j_sb->s_l2bfactor));
	j_sb->s_agsize = cpu_to_le32(bmp->db_agsize);

	/* update inline log space descriptor */
	if (sbi->mntflag & JFS_INLINELOG) {
		PXDaddress(&(j_sb->s_logpxd), newLogAddress);
		PXDlength(&(j_sb->s_logpxd), newLogSize);
	}

	/* record log's mount serial number */
	j_sb->s_logserial = cpu_to_le32(log->serial);

	/* update fsck work space descriptor */
	PXDaddress(&(j_sb->s_fsckpxd), newFSCKAddress);
	PXDlength(&(j_sb->s_fsckpxd), newFSCKSize);
	j_sb->s_fscklog = 1;
	/* sb->s_fsckloglen remains the same */

	/* Update secondary superblock */
	bh2 = sb_bread(sb, SUPER2_OFF >> sb->s_blocksize_bits);
	if (bh2) {
		j_sb2 = (struct jfs_superblock *)bh2->b_data;
		memcpy(j_sb2, j_sb, sizeof (struct jfs_superblock));

		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh2);
		brelse(bh2);
	}

	/* write primary superblock */
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	goto resume;

      error_out:
	jfs_error(sb, "\n");

      resume:
	/*
	 *	resume file system transactions
	 */
	txResume(sb);

      out:
	return rc;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/resize.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines  Corp., 2000-2004
 *   Copyright (C) Christoph Hellwig, 2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/capability.h>
// #include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>
// #include <linux/slab.h>
// #include <linux/quotaops.h>
#include <linux/security.h>
// #include "jfs_incore.h"
// #include "jfs_superblock.h"
// #include "jfs_dmap.h"
// #include "jfs_debug.h"
// #include "jfs_dinode.h"
// #include "jfs_extent.h"
// #include "jfs_metapage.h"
// #include "jfs_xattr.h"
// #include "jfs_acl.h"
#include "../../inc/__fss.h"

/*
 *	jfs_xattr.c: extended attribute service
 *
 * Overall design --
 *
 * Format:
 *
 *   Extended attribute lists (jfs_ea_list) consist of an overall size (32 bit
 *   value) and a variable (0 or more) number of extended attribute
 *   entries.  Each extended attribute entry (jfs_ea) is a <name,value> double
 *   where <name> is constructed from a null-terminated ascii string
 *   (1 ... 255 bytes in the name) and <value> is arbitrary 8 bit data
 *   (1 ... 65535 bytes).  The in-memory format is
 *
 *   0       1        2        4                4 + namelen + 1
 *   +-------+--------+--------+----------------+-------------------+
 *   | Flags | Name   | Value  | Name String \0 | Data . . . .      |
 *   |       | Length | Length |                |                   |
 *   +-------+--------+--------+----------------+-------------------+
 *
 *   A jfs_ea_list then is structured as
 *
 *   0            4                   4 + EA_SIZE(ea1)
 *   +------------+-------------------+--------------------+-----
 *   | Overall EA | First FEA Element | Second FEA Element | .....
 *   | List Size  |                   |                    |
 *   +------------+-------------------+--------------------+-----
 *
 *   On-disk:
 *
 *	FEALISTs are stored on disk using blocks allocated by dbAlloc() and
 *	written directly. An EA list may be in-lined in the inode if there is
 *	sufficient room available.
 */

struct ea_buffer {
	int flag;		/* Indicates what storage xattr points to */
	int max_size;		/* largest xattr that fits in current buffer */
	dxd_t new_ea;		/* dxd to replace ea when modifying xattr */
	struct metapage *mp;	/* metapage containing ea list */
	struct jfs_ea_list *xattr;	/* buffer containing ea list */
};

/*
 * ea_buffer.flag values
 */
#define EA_INLINE	0x0001
#define EA_EXTENT	0x0002
#define EA_NEW		0x0004
#define EA_MALLOC	0x0008


static int is_known_namespace(const char *name)
{
	if (strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN) &&
	    strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN) &&
	    strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN) &&
	    strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN))
		return false;

	return true;
}

/*
 * These three routines are used to recognize on-disk extended attributes
 * that are in a recognized namespace.  If the attribute is not recognized,
 * "os2." is prepended to the name
 */
static int is_os2_xattr(struct jfs_ea *ea)
{
	return !is_known_namespace(ea->name);
}

static inline int name_size(struct jfs_ea *ea)
{
	if (is_os2_xattr(ea))
		return ea->namelen + XATTR_OS2_PREFIX_LEN;
	else
		return ea->namelen;
}

static inline int copy_name(char *buffer, struct jfs_ea *ea)
{
	int len = ea->namelen;

	if (is_os2_xattr(ea)) {
		memcpy(buffer, XATTR_OS2_PREFIX, XATTR_OS2_PREFIX_LEN);
		buffer += XATTR_OS2_PREFIX_LEN;
		len += XATTR_OS2_PREFIX_LEN;
	}
	memcpy(buffer, ea->name, ea->namelen);
	buffer[ea->namelen] = 0;

	return len;
}

/* Forward references */
static void ea_release(struct inode *inode, struct ea_buffer *ea_buf);

/*
 * NAME: ea_write_inline
 *
 * FUNCTION: Attempt to write an EA inline if area is available
 *
 * PRE CONDITIONS:
 *	Already verified that the specified EA is small enough to fit inline
 *
 * PARAMETERS:
 *	ip	- Inode pointer
 *	ealist	- EA list pointer
 *	size	- size of ealist in bytes
 *	ea	- dxd_t structure to be filled in with necessary EA information
 *		  if we successfully copy the EA inline
 *
 * NOTES:
 *	Checks if the inode's inline area is available.  If so, copies EA inline
 *	and sets <ea> fields appropriately.  Otherwise, returns failure, EA will
 *	have to be put into an extent.
 *
 * RETURNS: 0 for successful copy to inline area; -1 if area not available
 */
static int ea_write_inline(struct inode *ip, struct jfs_ea_list *ealist,
			   int size, dxd_t * ea)
{
	struct jfs_inode_info *ji = JFS_IP(ip);

	/*
	 * Make sure we have an EA -- the NULL EA list is valid, but you
	 * can't copy it!
	 */
	if (ealist && size > sizeof (struct jfs_ea_list)) {
		assert(size <= sizeof (ji->i_inline_ea));

		/*
		 * See if the space is available or if it is already being
		 * used for an inline EA.
		 */
		if (!(ji->mode2 & INLINEEA) && !(ji->ea.flag & DXD_INLINE))
			return -EPERM;

		DXDsize(ea, size);
		DXDlength(ea, 0);
		DXDaddress(ea, 0);
		memcpy(ji->i_inline_ea, ealist, size);
		ea->flag = DXD_INLINE;
		ji->mode2 &= ~INLINEEA;
	} else {
		ea->flag = 0;
		DXDsize(ea, 0);
		DXDlength(ea, 0);
		DXDaddress(ea, 0);

		/* Free up INLINE area */
		if (ji->ea.flag & DXD_INLINE)
			ji->mode2 |= INLINEEA;
	}

	return 0;
}

/*
 * NAME: ea_write
 *
 * FUNCTION: Write an EA for an inode
 *
 * PRE CONDITIONS: EA has been verified
 *
 * PARAMETERS:
 *	ip	- Inode pointer
 *	ealist	- EA list pointer
 *	size	- size of ealist in bytes
 *	ea	- dxd_t structure to be filled in appropriately with where the
 *		  EA was copied
 *
 * NOTES: Will write EA inline if able to, otherwise allocates blocks for an
 *	extent and synchronously writes it to those blocks.
 *
 * RETURNS: 0 for success; Anything else indicates failure
 */
static int ea_write(struct inode *ip, struct jfs_ea_list *ealist, int size,
		       dxd_t * ea)
{
	struct super_block *sb = ip->i_sb;
	struct jfs_inode_info *ji = JFS_IP(ip);
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	int nblocks;
	s64 blkno;
	int rc = 0, i;
	char *cp;
	s32 nbytes, nb;
	s32 bytes_to_write;
	struct metapage *mp;

	/*
	 * Quick check to see if this is an in-linable EA.  Short EAs
	 * and empty EAs are all in-linable, provided the space exists.
	 */
	if (!ealist || size <= sizeof (ji->i_inline_ea)) {
		if (!ea_write_inline(ip, ealist, size, ea))
			return 0;
	}

	/* figure out how many blocks we need */
	nblocks = (size + (sb->s_blocksize - 1)) >> sb->s_blocksize_bits;

	/* Allocate new blocks to quota. */
	rc = dquot_alloc_block(ip, nblocks);
	if (rc)
		return rc;

	rc = dbAlloc(ip, INOHINT(ip), nblocks, &blkno);
	if (rc) {
		/*Rollback quota allocation. */
		dquot_free_block(ip, nblocks);
		return rc;
	}

	/*
	 * Now have nblocks worth of storage to stuff into the FEALIST.
	 * loop over the FEALIST copying data into the buffer one page at
	 * a time.
	 */
	cp = (char *) ealist;
	nbytes = size;
	for (i = 0; i < nblocks; i += sbi->nbperpage) {
		/*
		 * Determine how many bytes for this request, and round up to
		 * the nearest aggregate block size
		 */
		nb = min(PSIZE, nbytes);
		bytes_to_write =
		    ((((nb + sb->s_blocksize - 1)) >> sb->s_blocksize_bits))
		    << sb->s_blocksize_bits;

		if (!(mp = get_metapage(ip, blkno + i, bytes_to_write, 1))) {
			rc = -EIO;
			goto failed;
		}

		memcpy(mp->data, cp, nb);

		/*
		 * We really need a way to propagate errors for
		 * forced writes like this one.  --hch
		 *
		 * (__write_metapage => release_metapage => flush_metapage)
		 */
#ifdef _JFS_FIXME
		if ((rc = flush_metapage(mp))) {
			/*
			 * the write failed -- this means that the buffer
			 * is still assigned and the blocks are not being
			 * used.  this seems like the best error recovery
			 * we can get ...
			 */
			goto failed;
		}
#else
		flush_metapage(mp);
#endif

		cp += PSIZE;
		nbytes -= nb;
	}

	ea->flag = DXD_EXTENT;
	DXDsize(ea, le32_to_cpu(ealist->size));
	DXDlength(ea, nblocks);
	DXDaddress(ea, blkno);

	/* Free up INLINE area */
	if (ji->ea.flag & DXD_INLINE)
		ji->mode2 |= INLINEEA;

	return 0;

      failed:
	/* Rollback quota allocation. */
	dquot_free_block(ip, nblocks);

	dbFree(ip, blkno, nblocks);
	return rc;
}

/*
 * NAME: ea_read_inline
 *
 * FUNCTION: Read an inlined EA into user's buffer
 *
 * PARAMETERS:
 *	ip	- Inode pointer
 *	ealist	- Pointer to buffer to fill in with EA
 *
 * RETURNS: 0
 */
static int ea_read_inline(struct inode *ip, struct jfs_ea_list *ealist)
{
	struct jfs_inode_info *ji = JFS_IP(ip);
	int ea_size = sizeDXD(&ji->ea);

	if (ea_size == 0) {
		ealist->size = 0;
		return 0;
	}

	/* Sanity Check */
	if ((sizeDXD(&ji->ea) > sizeof (ji->i_inline_ea)))
		return -EIO;
	if (le32_to_cpu(((struct jfs_ea_list *) &ji->i_inline_ea)->size)
	    != ea_size)
		return -EIO;

	memcpy(ealist, ji->i_inline_ea, ea_size);
	return 0;
}

/*
 * NAME: ea_read
 *
 * FUNCTION: copy EA data into user's buffer
 *
 * PARAMETERS:
 *	ip	- Inode pointer
 *	ealist	- Pointer to buffer to fill in with EA
 *
 * NOTES:  If EA is inline calls ea_read_inline() to copy EA.
 *
 * RETURNS: 0 for success; other indicates failure
 */
static int ea_read(struct inode *ip, struct jfs_ea_list *ealist)
{
	struct super_block *sb = ip->i_sb;
	struct jfs_inode_info *ji = JFS_IP(ip);
	struct jfs_sb_info *sbi = JFS_SBI(sb);
	int nblocks;
	s64 blkno;
	char *cp = (char *) ealist;
	int i;
	int nbytes, nb;
	s32 bytes_to_read;
	struct metapage *mp;

	/* quick check for in-line EA */
	if (ji->ea.flag & DXD_INLINE)
		return ea_read_inline(ip, ealist);

	nbytes = sizeDXD(&ji->ea);
	if (!nbytes) {
		jfs_error(sb, "nbytes is 0\n");
		return -EIO;
	}

	/*
	 * Figure out how many blocks were allocated when this EA list was
	 * originally written to disk.
	 */
	nblocks = lengthDXD(&ji->ea) << sbi->l2nbperpage;
	blkno = addressDXD(&ji->ea) << sbi->l2nbperpage;

	/*
	 * I have found the disk blocks which were originally used to store
	 * the FEALIST.  now i loop over each contiguous block copying the
	 * data into the buffer.
	 */
	for (i = 0; i < nblocks; i += sbi->nbperpage) {
		/*
		 * Determine how many bytes for this request, and round up to
		 * the nearest aggregate block size
		 */
		nb = min(PSIZE, nbytes);
		bytes_to_read =
		    ((((nb + sb->s_blocksize - 1)) >> sb->s_blocksize_bits))
		    << sb->s_blocksize_bits;

		if (!(mp = read_metapage(ip, blkno + i, bytes_to_read, 1)))
			return -EIO;

		memcpy(cp, mp->data, nb);
		release_metapage(mp);

		cp += PSIZE;
		nbytes -= nb;
	}

	return 0;
}

/*
 * NAME: ea_get
 *
 * FUNCTION: Returns buffer containing existing extended attributes.
 *	     The size of the buffer will be the larger of the existing
 *	     attributes size, or min_size.
 *
 *	     The buffer, which may be inlined in the inode or in the
 *	     page cache must be release by calling ea_release or ea_put
 *
 * PARAMETERS:
 *	inode	- Inode pointer
 *	ea_buf	- Structure to be populated with ealist and its metadata
 *	min_size- minimum size of buffer to be returned
 *
 * RETURNS: 0 for success; Other indicates failure
 */
static int ea_get(struct inode *inode, struct ea_buffer *ea_buf, int min_size)
{
	struct jfs_inode_info *ji = JFS_IP(inode);
	struct super_block *sb = inode->i_sb;
	int size;
	int ea_size = sizeDXD(&ji->ea);
	int blocks_needed, current_blocks;
	s64 blkno;
	int rc;
	int quota_allocation = 0;

	/* When fsck.jfs clears a bad ea, it doesn't clear the size */
	if (ji->ea.flag == 0)
		ea_size = 0;

	if (ea_size == 0) {
		if (min_size == 0) {
			ea_buf->flag = 0;
			ea_buf->max_size = 0;
			ea_buf->xattr = NULL;
			return 0;
		}
		if ((min_size <= sizeof (ji->i_inline_ea)) &&
		    (ji->mode2 & INLINEEA)) {
			ea_buf->flag = EA_INLINE | EA_NEW;
			ea_buf->max_size = sizeof (ji->i_inline_ea);
			ea_buf->xattr = (struct jfs_ea_list *) ji->i_inline_ea;
			DXDlength(&ea_buf->new_ea, 0);
			DXDaddress(&ea_buf->new_ea, 0);
			ea_buf->new_ea.flag = DXD_INLINE;
			DXDsize(&ea_buf->new_ea, min_size);
			return 0;
		}
		current_blocks = 0;
	} else if (ji->ea.flag & DXD_INLINE) {
		if (min_size <= sizeof (ji->i_inline_ea)) {
			ea_buf->flag = EA_INLINE;
			ea_buf->max_size = sizeof (ji->i_inline_ea);
			ea_buf->xattr = (struct jfs_ea_list *) ji->i_inline_ea;
			goto size_check;
		}
		current_blocks = 0;
	} else {
		if (!(ji->ea.flag & DXD_EXTENT)) {
			jfs_error(sb, "invalid ea.flag\n");
			return -EIO;
		}
		current_blocks = (ea_size + sb->s_blocksize - 1) >>
		    sb->s_blocksize_bits;
	}
	size = max(min_size, ea_size);

	if (size > PSIZE) {
		/*
		 * To keep the rest of the code simple.  Allocate a
		 * contiguous buffer to work with
		 */
		ea_buf->xattr = kmalloc(size, GFP_KERNEL);
		if (ea_buf->xattr == NULL)
			return -ENOMEM;

		ea_buf->flag = EA_MALLOC;
		ea_buf->max_size = (size + sb->s_blocksize - 1) &
		    ~(sb->s_blocksize - 1);

		if (ea_size == 0)
			return 0;

		if ((rc = ea_read(inode, ea_buf->xattr))) {
			kfree(ea_buf->xattr);
			ea_buf->xattr = NULL;
			return rc;
		}
		goto size_check;
	}
	blocks_needed = (min_size + sb->s_blocksize - 1) >>
	    sb->s_blocksize_bits;

	if (blocks_needed > current_blocks) {
		/* Allocate new blocks to quota. */
		rc = dquot_alloc_block(inode, blocks_needed);
		if (rc)
			return -EDQUOT;

		quota_allocation = blocks_needed;

		rc = dbAlloc(inode, INOHINT(inode), (s64) blocks_needed,
			     &blkno);
		if (rc)
			goto clean_up;

		DXDlength(&ea_buf->new_ea, blocks_needed);
		DXDaddress(&ea_buf->new_ea, blkno);
		ea_buf->new_ea.flag = DXD_EXTENT;
		DXDsize(&ea_buf->new_ea, min_size);

		ea_buf->flag = EA_EXTENT | EA_NEW;

		ea_buf->mp = get_metapage(inode, blkno,
					  blocks_needed << sb->s_blocksize_bits,
					  1);
		if (ea_buf->mp == NULL) {
			dbFree(inode, blkno, (s64) blocks_needed);
			rc = -EIO;
			goto clean_up;
		}
		ea_buf->xattr = ea_buf->mp->data;
		ea_buf->max_size = (min_size + sb->s_blocksize - 1) &
		    ~(sb->s_blocksize - 1);
		if (ea_size == 0)
			return 0;
		if ((rc = ea_read(inode, ea_buf->xattr))) {
			discard_metapage(ea_buf->mp);
			dbFree(inode, blkno, (s64) blocks_needed);
			goto clean_up;
		}
		goto size_check;
	}
	ea_buf->flag = EA_EXTENT;
	ea_buf->mp = read_metapage(inode, addressDXD(&ji->ea),
				   lengthDXD(&ji->ea) << sb->s_blocksize_bits,
				   1);
	if (ea_buf->mp == NULL) {
		rc = -EIO;
		goto clean_up;
	}
	ea_buf->xattr = ea_buf->mp->data;
	ea_buf->max_size = (ea_size + sb->s_blocksize - 1) &
	    ~(sb->s_blocksize - 1);

      size_check:
	if (EALIST_SIZE(ea_buf->xattr) != ea_size) {
		printk(KERN_ERR "ea_get: invalid extended attribute\n");
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 16, 1,
				     ea_buf->xattr, ea_size, 1);
		ea_release(inode, ea_buf);
		rc = -EIO;
		goto clean_up;
	}

	return ea_size;

      clean_up:
	/* Rollback quota allocation */
	if (quota_allocation)
		dquot_free_block(inode, quota_allocation);

	return (rc);
}

static void ea_release(struct inode *inode, struct ea_buffer *ea_buf)
{
	if (ea_buf->flag & EA_MALLOC)
		kfree(ea_buf->xattr);
	else if (ea_buf->flag & EA_EXTENT) {
		assert(ea_buf->mp);
		release_metapage(ea_buf->mp);

		if (ea_buf->flag & EA_NEW)
			dbFree(inode, addressDXD(&ea_buf->new_ea),
			       lengthDXD(&ea_buf->new_ea));
	}
}

static int ea_put(tid_t tid, struct inode *inode, struct ea_buffer *ea_buf,
		  int new_size)
{
	struct jfs_inode_info *ji = JFS_IP(inode);
	unsigned long old_blocks, new_blocks;
	int rc = 0;

	if (new_size == 0) {
		ea_release(inode, ea_buf);
		ea_buf = NULL;
	} else if (ea_buf->flag & EA_INLINE) {
		assert(new_size <= sizeof (ji->i_inline_ea));
		ji->mode2 &= ~INLINEEA;
		ea_buf->new_ea.flag = DXD_INLINE;
		DXDsize(&ea_buf->new_ea, new_size);
		DXDaddress(&ea_buf->new_ea, 0);
		DXDlength(&ea_buf->new_ea, 0);
	} else if (ea_buf->flag & EA_MALLOC) {
		rc = ea_write(inode, ea_buf->xattr, new_size, &ea_buf->new_ea);
		kfree(ea_buf->xattr);
	} else if (ea_buf->flag & EA_NEW) {
		/* We have already allocated a new dxd */
		flush_metapage(ea_buf->mp);
	} else {
		/* ->xattr must point to original ea's metapage */
		rc = ea_write(inode, ea_buf->xattr, new_size, &ea_buf->new_ea);
		discard_metapage(ea_buf->mp);
	}
	if (rc)
		return rc;

	old_blocks = new_blocks = 0;

	if (ji->ea.flag & DXD_EXTENT) {
		invalidate_dxd_metapages(inode, ji->ea);
		old_blocks = lengthDXD(&ji->ea);
	}

	if (ea_buf) {
		txEA(tid, inode, &ji->ea, &ea_buf->new_ea);
		if (ea_buf->new_ea.flag & DXD_EXTENT) {
			new_blocks = lengthDXD(&ea_buf->new_ea);
			if (ji->ea.flag & DXD_INLINE)
				ji->mode2 |= INLINEEA;
		}
		ji->ea = ea_buf->new_ea;
	} else {
		txEA(tid, inode, &ji->ea, NULL);
		if (ji->ea.flag & DXD_INLINE)
			ji->mode2 |= INLINEEA;
		ji->ea.flag = 0;
		ji->ea.size = 0;
	}

	/* If old blocks exist, they must be removed from quota allocation. */
	if (old_blocks)
		dquot_free_block(inode, old_blocks);

	inode->i_ctime = CURRENT_TIME;

	return 0;
}

/*
 * Most of the permission checking is done by xattr_permission in the vfs.
 * We also need to verify that this is a namespace that we recognize.
 */
static int can_set_xattr(struct inode *inode, const char *name,
			 const void *value, size_t value_len)
{
	if (!strncmp(name, XATTR_OS2_PREFIX, XATTR_OS2_PREFIX_LEN)) {
		/*
		 * This makes sure that we aren't trying to set an
		 * attribute in a different namespace by prefixing it
		 * with "os2."
		 */
		if (is_known_namespace(name + XATTR_OS2_PREFIX_LEN))
			return -EOPNOTSUPP;
		return 0;
	}

	/*
	 * Don't allow setting an attribute in an unknown namespace.
	 */
	if (strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN) &&
	    strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN) &&
	    strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))
		return -EOPNOTSUPP;

	return 0;
}

int __jfs_setxattr(tid_t tid, struct inode *inode, const char *name,
		   const void *value, size_t value_len, int flags)
{
	struct jfs_ea_list *ealist;
	struct jfs_ea *ea, *old_ea = NULL, *next_ea = NULL;
	struct ea_buffer ea_buf;
	int old_ea_size = 0;
	int xattr_size;
	int new_size;
	int namelen = strlen(name);
	char *os2name = NULL;
	int found = 0;
	int rc;
	int length;

	if (strncmp(name, XATTR_OS2_PREFIX, XATTR_OS2_PREFIX_LEN) == 0) {
		os2name = kmalloc(namelen - XATTR_OS2_PREFIX_LEN + 1,
				  GFP_KERNEL);
		if (!os2name)
			return -ENOMEM;
		strcpy(os2name, name + XATTR_OS2_PREFIX_LEN);
		name = os2name;
		namelen -= XATTR_OS2_PREFIX_LEN;
	}

	down_write(&JFS_IP(inode)->xattr_sem);

	xattr_size = ea_get(inode, &ea_buf, 0);
	if (xattr_size < 0) {
		rc = xattr_size;
		goto out;
	}

      again:
	ealist = (struct jfs_ea_list *) ea_buf.xattr;
	new_size = sizeof (struct jfs_ea_list);

	if (xattr_size) {
		for (ea = FIRST_EA(ealist); ea < END_EALIST(ealist);
		     ea = NEXT_EA(ea)) {
			if ((namelen == ea->namelen) &&
			    (memcmp(name, ea->name, namelen) == 0)) {
				found = 1;
				if (flags & XATTR_CREATE) {
					rc = -EEXIST;
					goto release;
				}
				old_ea = ea;
				old_ea_size = EA_SIZE(ea);
				next_ea = NEXT_EA(ea);
			} else
				new_size += EA_SIZE(ea);
		}
	}

	if (!found) {
		if (flags & XATTR_REPLACE) {
			rc = -ENODATA;
			goto release;
		}
		if (value == NULL) {
			rc = 0;
			goto release;
		}
	}
	if (value)
		new_size += sizeof (struct jfs_ea) + namelen + 1 + value_len;

	if (new_size > ea_buf.max_size) {
		/*
		 * We need to allocate more space for merged ea list.
		 * We should only have loop to again: once.
		 */
		ea_release(inode, &ea_buf);
		xattr_size = ea_get(inode, &ea_buf, new_size);
		if (xattr_size < 0) {
			rc = xattr_size;
			goto out;
		}
		goto again;
	}

	/* Remove old ea of the same name */
	if (found) {
		/* number of bytes following target EA */
		length = (char *) END_EALIST(ealist) - (char *) next_ea;
		if (length > 0)
			memmove(old_ea, next_ea, length);
		xattr_size -= old_ea_size;
	}

	/* Add new entry to the end */
	if (value) {
		if (xattr_size == 0)
			/* Completely new ea list */
			xattr_size = sizeof (struct jfs_ea_list);

		/*
		 * The size of EA value is limitted by on-disk format up to
		 *  __le16, there would be an overflow if the size is equal
		 * to XATTR_SIZE_MAX (65536).  In order to avoid this issue,
		 * we can pre-checkup the value size against USHRT_MAX, and
		 * return -E2BIG in this case, which is consistent with the
		 * VFS setxattr interface.
		 */
		if (value_len >= USHRT_MAX) {
			rc = -E2BIG;
			goto release;
		}

		ea = (struct jfs_ea *) ((char *) ealist + xattr_size);
		ea->flag = 0;
		ea->namelen = namelen;
		ea->valuelen = (cpu_to_le16(value_len));
		memcpy(ea->name, name, namelen);
		ea->name[namelen] = 0;
		if (value_len)
			memcpy(&ea->name[namelen + 1], value, value_len);
		xattr_size += EA_SIZE(ea);
	}

	/* DEBUG - If we did this right, these number match */
	if (xattr_size != new_size) {
		printk(KERN_ERR
		       "__jfs_setxattr: xattr_size = %d, new_size = %d\n",
		       xattr_size, new_size);

		rc = -EINVAL;
		goto release;
	}

	/*
	 * If we're left with an empty list, there's no ea
	 */
	if (new_size == sizeof (struct jfs_ea_list))
		new_size = 0;

	ealist->size = cpu_to_le32(new_size);

	rc = ea_put(tid, inode, &ea_buf, new_size);

	goto out;
      release:
	ea_release(inode, &ea_buf);
      out:
	up_write(&JFS_IP(inode)->xattr_sem);

	kfree(os2name);

	return rc;
}

int jfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		 size_t value_len, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct jfs_inode_info *ji = JFS_IP(inode);
	int rc;
	tid_t tid;

	/*
	 * If this is a request for a synthetic attribute in the system.*
	 * namespace use the generic infrastructure to resolve a handler
	 * for it via sb->s_xattr.
	 */
	if (!strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return generic_setxattr(dentry, name, value, value_len, flags);

	if ((rc = can_set_xattr(inode, name, value, value_len)))
		return rc;

	if (value == NULL) {	/* empty EA, do not remove */
		value = "";
		value_len = 0;
	}

	tid = txBegin(inode->i_sb, 0);
	mutex_lock(&ji->commit_mutex);
	rc = __jfs_setxattr(tid, dentry->d_inode, name, value, value_len,
			    flags);
	if (!rc)
		rc = txCommit(tid, 1, &inode, 0);
	txEnd(tid);
	mutex_unlock(&ji->commit_mutex);

	return rc;
}

ssize_t __jfs_getxattr(struct inode *inode, const char *name, void *data,
		       size_t buf_size)
{
	struct jfs_ea_list *ealist;
	struct jfs_ea *ea;
	struct ea_buffer ea_buf;
	int xattr_size;
	ssize_t size;
	int namelen = strlen(name);
	char *value;

	down_read(&JFS_IP(inode)->xattr_sem);

	xattr_size = ea_get(inode, &ea_buf, 0);

	if (xattr_size < 0) {
		size = xattr_size;
		goto out;
	}

	if (xattr_size == 0)
		goto not_found;

	ealist = (struct jfs_ea_list *) ea_buf.xattr;

	/* Find the named attribute */
	for (ea = FIRST_EA(ealist); ea < END_EALIST(ealist); ea = NEXT_EA(ea))
		if ((namelen == ea->namelen) &&
		    memcmp(name, ea->name, namelen) == 0) {
			/* Found it */
			size = le16_to_cpu(ea->valuelen);
			if (!data)
				goto release;
			else if (size > buf_size) {
				size = -ERANGE;
				goto release;
			}
			value = ((char *) &ea->name) + ea->namelen + 1;
			memcpy(data, value, size);
			goto release;
		}
      not_found:
	size = -ENODATA;
      release:
	ea_release(inode, &ea_buf);
      out:
	up_read(&JFS_IP(inode)->xattr_sem);

	return size;
}

ssize_t jfs_getxattr(struct dentry *dentry, const char *name, void *data,
		     size_t buf_size)
{
	int err;

	/*
	 * If this is a request for a synthetic attribute in the system.*
	 * namespace use the generic infrastructure to resolve a handler
	 * for it via sb->s_xattr.
	 */
	if (!strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return generic_getxattr(dentry, name, data, buf_size);

	if (strncmp(name, XATTR_OS2_PREFIX, XATTR_OS2_PREFIX_LEN) == 0) {
		/*
		 * skip past "os2." prefix
		 */
		name += XATTR_OS2_PREFIX_LEN;
		/*
		 * Don't allow retrieving properly prefixed attributes
		 * by prepending them with "os2."
		 */
		if (is_known_namespace(name))
			return -EOPNOTSUPP;
	}

	err = __jfs_getxattr(dentry->d_inode, name, data, buf_size);

	return err;
}

/*
 * No special permissions are needed to list attributes except for trusted.*
 */
static inline int can_list(struct jfs_ea *ea)
{
	return (strncmp(ea->name, XATTR_TRUSTED_PREFIX,
			    XATTR_TRUSTED_PREFIX_LEN) ||
		capable(CAP_SYS_ADMIN));
}

ssize_t jfs_listxattr(struct dentry * dentry, char *data, size_t buf_size)
{
	struct inode *inode = dentry->d_inode;
	char *buffer;
	ssize_t size = 0;
	int xattr_size;
	struct jfs_ea_list *ealist;
	struct jfs_ea *ea;
	struct ea_buffer ea_buf;

	down_read(&JFS_IP(inode)->xattr_sem);

	xattr_size = ea_get(inode, &ea_buf, 0);
	if (xattr_size < 0) {
		size = xattr_size;
		goto out;
	}

	if (xattr_size == 0)
		goto release;

	ealist = (struct jfs_ea_list *) ea_buf.xattr;

	/* compute required size of list */
	for (ea = FIRST_EA(ealist); ea < END_EALIST(ealist); ea = NEXT_EA(ea)) {
		if (can_list(ea))
			size += name_size(ea) + 1;
	}

	if (!data)
		goto release;

	if (size > buf_size) {
		size = -ERANGE;
		goto release;
	}

	/* Copy attribute names to buffer */
	buffer = data;
	for (ea = FIRST_EA(ealist); ea < END_EALIST(ealist); ea = NEXT_EA(ea)) {
		if (can_list(ea)) {
			int namelen = copy_name(buffer, ea);
			buffer += namelen + 1;
		}
	}

      release:
	ea_release(inode, &ea_buf);
      out:
	up_read(&JFS_IP(inode)->xattr_sem);
	return size;
}

int jfs_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;
	struct jfs_inode_info *ji = JFS_IP(inode);
	int rc;
	tid_t tid;

	/*
	 * If this is a request for a synthetic attribute in the system.*
	 * namespace use the generic infrastructure to resolve a handler
	 * for it via sb->s_xattr.
	 */
	if (!strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return generic_removexattr(dentry, name);

	if ((rc = can_set_xattr(inode, name, NULL, 0)))
		return rc;

	tid = txBegin(inode->i_sb, 0);
	mutex_lock(&ji->commit_mutex);
	rc = __jfs_setxattr(tid, dentry->d_inode, name, NULL, 0, XATTR_REPLACE);
	if (!rc)
		rc = txCommit(tid, 1, &inode, 0);
	txEnd(tid);
	mutex_unlock(&ji->commit_mutex);

	return rc;
}

/*
 * List of handlers for synthetic system.* attributes.  All real ondisk
 * attributes are handled directly.
 */
const struct xattr_handler *jfs_xattr_handlers[] = {
#ifdef CONFIG_JFS_POSIX_ACL
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
	NULL,
};


#ifdef CONFIG_JFS_SECURITY
static int jfs_initxattrs(struct inode *inode, const struct xattr *xattr_array,
			  void *fs_info)
{
	const struct xattr *xattr;
	tid_t *tid = fs_info;
	char *name;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		name = kmalloc(XATTR_SECURITY_PREFIX_LEN +
			       strlen(xattr->name) + 1, GFP_NOFS);
		if (!name) {
			err = -ENOMEM;
			break;
		}
		strcpy(name, XATTR_SECURITY_PREFIX);
		strcpy(name + XATTR_SECURITY_PREFIX_LEN, xattr->name);

		err = __jfs_setxattr(*tid, inode, name,
				     xattr->value, xattr->value_len, 0);
		kfree(name);
		if (err < 0)
			break;
	}
	return err;
}

int jfs_init_security(tid_t tid, struct inode *inode, struct inode *dir,
		      const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &jfs_initxattrs, &tid);
}
#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/xattr.c */
/************************************************************/
/*
 * linux/fs/jfs/ioctl.c
 *
 * Copyright (C) 2006 Herbert Poetzl
 * adapted from Remy Card's ext2/ioctl.c
 */

// #include <linux/fs.h>
// #include <linux/ctype.h>
// #include <linux/capability.h>
// #include <linux/mount.h>
#include <linux/time.h>
#include <linux/sched.h>
// #include <linux/blkdev.h>
#include <asm/current.h>
// #include <asm/uaccess.h>
#include "../../inc/__fss.h"

// #include "jfs_filsys.h"
// #include "jfs_debug.h"
// #include "jfs_incore.h"
// #include "jfs_dinode.h"
// #include "jfs_inode.h"
// #include "jfs_dmap.h"
// #include "jfs_discard.h"

static struct {
	long jfs_flag;
	long ext2_flag;
} jfs_map[] = {
	{JFS_NOATIME_FL,	FS_NOATIME_FL},
	{JFS_DIRSYNC_FL,	FS_DIRSYNC_FL},
	{JFS_SYNC_FL,		FS_SYNC_FL},
	{JFS_SECRM_FL,		FS_SECRM_FL},
	{JFS_UNRM_FL,		FS_UNRM_FL},
	{JFS_APPEND_FL,		FS_APPEND_FL},
	{JFS_IMMUTABLE_FL,	FS_IMMUTABLE_FL},
	{0, 0},
};

static long jfs_map_ext2(unsigned long flags, int from)
{
	int index=0;
	long mapped=0;

	while (jfs_map[index].jfs_flag) {
		if (from) {
			if (jfs_map[index].ext2_flag & flags)
				mapped |= jfs_map[index].jfs_flag;
		} else {
			if (jfs_map[index].jfs_flag & flags)
				mapped |= jfs_map[index].ext2_flag;
		}
		index++;
	}
	return mapped;
}


long jfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct jfs_inode_info *jfs_inode = JFS_IP(inode);
	unsigned int flags;

	switch (cmd) {
	case JFS_IOC_GETFLAGS:
		jfs_get_inode_flags(jfs_inode);
		flags = jfs_inode->mode2 & JFS_FL_USER_VISIBLE;
		flags = jfs_map_ext2(flags, 0);
		return put_user(flags, (int __user *) arg);
	case JFS_IOC_SETFLAGS: {
		unsigned int oldflags;
		int err;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		if (!inode_owner_or_capable(inode)) {
			err = -EACCES;
			goto setflags_out;
		}
		if (get_user(flags, (int __user *) arg)) {
			err = -EFAULT;
			goto setflags_out;
		}

		flags = jfs_map_ext2(flags, 1);
		if (!S_ISDIR(inode->i_mode))
			flags &= ~JFS_DIRSYNC_FL;

		/* Is it quota file? Do not allow user to mess with it */
		if (IS_NOQUOTA(inode)) {
			err = -EPERM;
			goto setflags_out;
		}

		/* Lock against other parallel changes of flags */
		mutex_lock(&inode->i_mutex);

		jfs_get_inode_flags(jfs_inode);
		oldflags = jfs_inode->mode2;

		/*
		 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
		 * the relevant capability.
		 */
		if ((oldflags & JFS_IMMUTABLE_FL) ||
			((flags ^ oldflags) &
			(JFS_APPEND_FL | JFS_IMMUTABLE_FL))) {
			if (!capable(CAP_LINUX_IMMUTABLE)) {
				mutex_unlock(&inode->i_mutex);
				err = -EPERM;
				goto setflags_out;
			}
		}

		flags = flags & JFS_FL_USER_MODIFIABLE;
		flags |= oldflags & ~JFS_FL_USER_MODIFIABLE;
		jfs_inode->mode2 = flags;

		jfs_set_inode_flags(inode);
		mutex_unlock(&inode->i_mutex);
		inode->i_ctime = CURRENT_TIME_SEC;
		mark_inode_dirty(inode);
setflags_out:
		mnt_drop_write_file(filp);
		return err;
	}

	case FITRIM:
	{
		struct super_block *sb = inode->i_sb;
		struct request_queue *q = bdev_get_queue(sb->s_bdev);
		struct fstrim_range range;
		s64 ret = 0;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (!blk_queue_discard(q)) {
			jfs_warn("FITRIM not supported on device");
			return -EOPNOTSUPP;
		}

		if (copy_from_user(&range, (struct fstrim_range __user *)arg,
		    sizeof(range)))
			return -EFAULT;

		range.minlen = max_t(unsigned int, range.minlen,
			q->limits.discard_granularity);

		ret = jfs_ioc_trim(inode, &range);
		if (ret < 0)
			return ret;

		if (copy_to_user((struct fstrim_range __user *)arg, &range,
		    sizeof(range)))
			return -EFAULT;

		return 0;
	}

	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long jfs_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* While these ioctl numbers defined with 'long' and have different
	 * numbers than the 64bit ABI,
	 * the actual implementation only deals with ints and is compatible.
	 */
	switch (cmd) {
	case JFS_IOC_GETFLAGS32:
		cmd = JFS_IOC_GETFLAGS;
		break;
	case JFS_IOC_SETFLAGS32:
		cmd = JFS_IOC_SETFLAGS;
		break;
	case FITRIM:
		cmd = FITRIM;
		break;
	}
	return jfs_ioctl(filp, cmd, arg);
}
#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/ioctl.c */
/************************************************************/
/*
 *   Copyright (C) International Business Machines  Corp., 2002-2004
 *   Copyright (C) Andreas Gruenbacher, 2001
 *   Copyright (C) Linus Torvalds, 1991, 1992
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/fs.h>
// #include <linux/posix_acl_xattr.h>
// #include "jfs_incore.h"
// #include "jfs_txnmgr.h"
// #include "jfs_xattr.h"
// #include "jfs_acl.h"

struct posix_acl *jfs_get_acl(struct inode *inode, int type)
{
	struct posix_acl *acl;
	char *ea_name;
	int size;
	char *value = NULL;

	acl = get_cached_acl(inode, type);
	if (acl != ACL_NOT_CACHED)
		return acl;

	switch(type) {
		case ACL_TYPE_ACCESS:
			ea_name = POSIX_ACL_XATTR_ACCESS;
			break;
		case ACL_TYPE_DEFAULT:
			ea_name = POSIX_ACL_XATTR_DEFAULT;
			break;
		default:
			return ERR_PTR(-EINVAL);
	}

	size = __jfs_getxattr(inode, ea_name, NULL, 0);

	if (size > 0) {
		value = kmalloc(size, GFP_KERNEL);
		if (!value)
			return ERR_PTR(-ENOMEM);
		size = __jfs_getxattr(inode, ea_name, value, size);
	}

	if (size < 0) {
		if (size == -ENODATA)
			acl = NULL;
		else
			acl = ERR_PTR(size);
	} else {
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
	}
	kfree(value);
	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);
	return acl;
}

static int __jfs_set_acl(tid_t tid, struct inode *inode, int type,
		       struct posix_acl *acl)
{
	char *ea_name;
	int rc;
	int size = 0;
	char *value = NULL;

	switch (type) {
	case ACL_TYPE_ACCESS:
		ea_name = POSIX_ACL_XATTR_ACCESS;
		if (acl) {
			rc = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (rc < 0)
				return rc;
			inode->i_ctime = CURRENT_TIME;
			mark_inode_dirty(inode);
			if (rc == 0)
				acl = NULL;
		}
		break;
	case ACL_TYPE_DEFAULT:
		ea_name = POSIX_ACL_XATTR_DEFAULT;
		break;
	default:
		return -EINVAL;
	}

	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(size, GFP_KERNEL);
		if (!value)
			return -ENOMEM;
		rc = posix_acl_to_xattr(&init_user_ns, acl, value, size);
		if (rc < 0)
			goto out;
	}
	rc = __jfs_setxattr(tid, inode, ea_name, value, size, 0);
out:
	kfree(value);

	if (!rc)
		set_cached_acl(inode, type, acl);

	return rc;
}

int jfs_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int rc;
	tid_t tid;

	tid = txBegin(inode->i_sb, 0);
	mutex_lock(&JFS_IP(inode)->commit_mutex);
	rc = __jfs_set_acl(tid, inode, type, acl);
	if (!rc)
		rc = txCommit(tid, 1, &inode, 0);
	txEnd(tid);
	mutex_unlock(&JFS_IP(inode)->commit_mutex);
	return rc;
}

int jfs_init_acl(tid_t tid, struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int rc = 0;

	rc = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (rc)
		return rc;

	if (default_acl) {
		rc = __jfs_set_acl(tid, inode, ACL_TYPE_DEFAULT, default_acl);
		posix_acl_release(default_acl);
	}

	if (acl) {
		if (!rc)
			rc = __jfs_set_acl(tid, inode, ACL_TYPE_ACCESS, acl);
		posix_acl_release(acl);
	}

	JFS_IP(inode)->mode2 = (JFS_IP(inode)->mode2 & 0xffff0000) |
			       inode->i_mode;

	return rc;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/jfs/acl.c */
/************************************************************/
