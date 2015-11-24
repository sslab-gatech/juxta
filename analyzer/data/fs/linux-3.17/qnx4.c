/*
 * QNX4 file system, Linux implementation.
 *
 * Version : 0.2.1
 *
 * Using parts of the xiafs filesystem.
 *
 * History :
 *
 * 01-06-1998 by Richard Frowijn : first release.
 * 20-06-1998 by Frank Denis : Linux 2.1.99+ support, boot signature, misc.
 * 30-06-1998 by Frank Denis : first step to write inodes.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/statfs.h>
#include "qnx4.h"

#define QNX4_VERSION  4
#define QNX4_BMNAME   ".bitmap"

static const struct super_operations qnx4_sops;

static struct inode *qnx4_alloc_inode(struct super_block *sb);
static void qnx4_destroy_inode(struct inode *inode);
static int qnx4_remount(struct super_block *sb, int *flags, char *data);
static int qnx4_statfs(struct dentry *, struct kstatfs *);

static const struct super_operations qnx4_sops =
{
	.alloc_inode	= qnx4_alloc_inode,
	.destroy_inode	= qnx4_destroy_inode,
	.statfs		= qnx4_statfs,
	.remount_fs	= qnx4_remount,
};

static int qnx4_remount(struct super_block *sb, int *flags, char *data)
{
	struct qnx4_sb_info *qs;

	sync_filesystem(sb);
	qs = qnx4_sb(sb);
	qs->Version = QNX4_VERSION;
	*flags |= MS_RDONLY;
	return 0;
}

static int qnx4_get_block( struct inode *inode, sector_t iblock, struct buffer_head *bh, int create )
{
	unsigned long phys;

	QNX4DEBUG((KERN_INFO "qnx4: qnx4_get_block inode=[%ld] iblock=[%ld]\n",inode->i_ino,iblock));

	phys = qnx4_block_map( inode, iblock );
	if ( phys ) {
		// logical block is before EOF
		map_bh(bh, inode->i_sb, phys);
	}
	return 0;
}

static inline u32 try_extent(qnx4_xtnt_t *extent, u32 *offset)
{
	u32 size = le32_to_cpu(extent->xtnt_size);
	if (*offset < size)
		return le32_to_cpu(extent->xtnt_blk) + *offset - 1;
	*offset -= size;
	return 0;
}

unsigned long qnx4_block_map( struct inode *inode, long iblock )
{
	int ix;
	long i_xblk;
	struct buffer_head *bh = NULL;
	struct qnx4_xblk *xblk = NULL;
	struct qnx4_inode_entry *qnx4_inode = qnx4_raw_inode(inode);
	u16 nxtnt = le16_to_cpu(qnx4_inode->di_num_xtnts);
	u32 offset = iblock;
	u32 block = try_extent(&qnx4_inode->di_first_xtnt, &offset);

	if (block) {
		// iblock is in the first extent. This is easy.
	} else {
		// iblock is beyond first extent. We have to follow the extent chain.
		i_xblk = le32_to_cpu(qnx4_inode->di_xblk);
		ix = 0;
		while ( --nxtnt > 0 ) {
			if ( ix == 0 ) {
				// read next xtnt block.
				bh = sb_bread(inode->i_sb, i_xblk - 1);
				if ( !bh ) {
					QNX4DEBUG((KERN_ERR "qnx4: I/O error reading xtnt block [%ld])\n", i_xblk - 1));
					return -EIO;
				}
				xblk = (struct qnx4_xblk*)bh->b_data;
				if ( memcmp( xblk->xblk_signature, "IamXblk", 7 ) ) {
					QNX4DEBUG((KERN_ERR "qnx4: block at %ld is not a valid xtnt\n", qnx4_inode->i_xblk));
					return -EIO;
				}
			}
			block = try_extent(&xblk->xblk_xtnts[ix], &offset);
			if (block) {
				// got it!
				break;
			}
			if ( ++ix >= xblk->xblk_num_xtnts ) {
				i_xblk = le32_to_cpu(xblk->xblk_next_xblk);
				ix = 0;
				brelse( bh );
				bh = NULL;
			}
		}
		if ( bh )
			brelse( bh );
	}

	QNX4DEBUG((KERN_INFO "qnx4: mapping block %ld of inode %ld = %ld\n",iblock,inode->i_ino,block));
	return block;
}

static int qnx4_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type    = sb->s_magic;
	buf->f_bsize   = sb->s_blocksize;
	buf->f_blocks  = le32_to_cpu(qnx4_sb(sb)->BitMap->di_size) * 8;
	buf->f_bfree   = qnx4_count_free_blocks(sb);
	buf->f_bavail  = buf->f_bfree;
	buf->f_namelen = QNX4_NAME_MAX;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}

/*
 * Check the root directory of the filesystem to make sure
 * it really _is_ a qnx4 filesystem, and to check the size
 * of the directory entry.
 */
static const char *qnx4_checkroot(struct super_block *sb,
				  struct qnx4_super_block *s)
{
	struct buffer_head *bh;
	struct qnx4_inode_entry *rootdir;
	int rd, rl;
	int i, j;

	if (s->RootDir.di_fname[0] != '/' || s->RootDir.di_fname[1] != '\0')
		return "no qnx4 filesystem (no root dir).";
	QNX4DEBUG((KERN_NOTICE "QNX4 filesystem found on dev %s.\n", sb->s_id));
	rd = le32_to_cpu(s->RootDir.di_first_xtnt.xtnt_blk) - 1;
	rl = le32_to_cpu(s->RootDir.di_first_xtnt.xtnt_size);
	for (j = 0; j < rl; j++) {
		bh = sb_bread(sb, rd + j);	/* root dir, first block */
		if (bh == NULL)
			return "unable to read root entry.";
		rootdir = (struct qnx4_inode_entry *) bh->b_data;
		for (i = 0; i < QNX4_INODES_PER_BLOCK; i++, rootdir++) {
			QNX4DEBUG((KERN_INFO "rootdir entry found : [%s]\n", rootdir->di_fname));
			if (strcmp(rootdir->di_fname, QNX4_BMNAME) != 0)
				continue;
			qnx4_sb(sb)->BitMap = kmemdup(rootdir,
						      sizeof(struct qnx4_inode_entry),
						      GFP_KERNEL);
			brelse(bh);
			if (!qnx4_sb(sb)->BitMap)
				return "not enough memory for bitmap inode";
			/* keep bitmap inode known */
			return NULL;
		}
		brelse(bh);
	}
	return "bitmap file not found.";
}

static int qnx4_fill_super(struct super_block *s, void *data, int silent)
{
	struct buffer_head *bh;
	struct inode *root;
	const char *errmsg;
	struct qnx4_sb_info *qs;

	qs = kzalloc(sizeof(struct qnx4_sb_info), GFP_KERNEL);
	if (!qs)
		return -ENOMEM;
	s->s_fs_info = qs;

	sb_set_blocksize(s, QNX4_BLOCK_SIZE);

	s->s_op = &qnx4_sops;
	s->s_magic = QNX4_SUPER_MAGIC;
	s->s_flags |= MS_RDONLY;	/* Yup, read-only yet */

	/* Check the superblock signature. Since the qnx4 code is
	   dangerous, we should leave as quickly as possible
	   if we don't belong here... */
	bh = sb_bread(s, 1);
	if (!bh) {
		printk(KERN_ERR "qnx4: unable to read the superblock\n");
		return -EINVAL;
	}

 	/* check before allocating dentries, inodes, .. */
	errmsg = qnx4_checkroot(s, (struct qnx4_super_block *) bh->b_data);
	brelse(bh);
	if (errmsg != NULL) {
 		if (!silent)
			printk(KERN_ERR "qnx4: %s\n", errmsg);
		return -EINVAL;
	}

 	/* does root not have inode number QNX4_ROOT_INO ?? */
	root = qnx4_iget(s, QNX4_ROOT_INO * QNX4_INODES_PER_BLOCK);
	if (IS_ERR(root)) {
		printk(KERN_ERR "qnx4: get inode failed\n");
		return PTR_ERR(root);
 	}

 	s->s_root = d_make_root(root);
 	if (s->s_root == NULL)
 		return -ENOMEM;

	return 0;
}

static void qnx4_kill_sb(struct super_block *sb)
{
	struct qnx4_sb_info *qs = qnx4_sb(sb);
	kill_block_super(sb);
	if (qs) {
		kfree(qs->BitMap);
		kfree(qs);
	}
}

static int qnx4_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page,qnx4_get_block);
}

static sector_t qnx4_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,qnx4_get_block);
}
static const struct address_space_operations qnx4_aops = {
	.readpage	= qnx4_readpage,
	.bmap		= qnx4_bmap
};

struct inode *qnx4_iget(struct super_block *sb, unsigned long ino)
{
	struct buffer_head *bh;
	struct qnx4_inode_entry *raw_inode;
	int block;
	struct qnx4_inode_entry *qnx4_inode;
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	qnx4_inode = qnx4_raw_inode(inode);
	inode->i_mode = 0;

	QNX4DEBUG((KERN_INFO "reading inode : [%d]\n", ino));
	if (!ino) {
		printk(KERN_ERR "qnx4: bad inode number on dev %s: %lu is "
				"out of range\n",
		       sb->s_id, ino);
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}
	block = ino / QNX4_INODES_PER_BLOCK;

	if (!(bh = sb_bread(sb, block))) {
		printk(KERN_ERR "qnx4: major problem: unable to read inode from dev "
		       "%s\n", sb->s_id);
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}
	raw_inode = ((struct qnx4_inode_entry *) bh->b_data) +
	    (ino % QNX4_INODES_PER_BLOCK);

	inode->i_mode    = le16_to_cpu(raw_inode->di_mode);
	i_uid_write(inode, (uid_t)le16_to_cpu(raw_inode->di_uid));
	i_gid_write(inode, (gid_t)le16_to_cpu(raw_inode->di_gid));
	set_nlink(inode, le16_to_cpu(raw_inode->di_nlink));
	inode->i_size    = le32_to_cpu(raw_inode->di_size);
	inode->i_mtime.tv_sec   = le32_to_cpu(raw_inode->di_mtime);
	inode->i_mtime.tv_nsec = 0;
	inode->i_atime.tv_sec   = le32_to_cpu(raw_inode->di_atime);
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_sec   = le32_to_cpu(raw_inode->di_ctime);
	inode->i_ctime.tv_nsec = 0;
	inode->i_blocks  = le32_to_cpu(raw_inode->di_first_xtnt.xtnt_size);

	memcpy(qnx4_inode, raw_inode, QNX4_DIR_ENTRY_SIZE);
	if (S_ISREG(inode->i_mode)) {
		inode->i_fop = &generic_ro_fops;
		inode->i_mapping->a_ops = &qnx4_aops;
		qnx4_i(inode)->mmu_private = inode->i_size;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &qnx4_dir_inode_operations;
		inode->i_fop = &qnx4_dir_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &page_symlink_inode_operations;
		inode->i_mapping->a_ops = &qnx4_aops;
		qnx4_i(inode)->mmu_private = inode->i_size;
	} else {
		printk(KERN_ERR "qnx4: bad inode %lu on dev %s\n",
			ino, sb->s_id);
		iget_failed(inode);
		brelse(bh);
		return ERR_PTR(-EIO);
	}
	brelse(bh);
	unlock_new_inode(inode);
	return inode;
}

static struct kmem_cache *qnx4_inode_cachep;

static struct inode *qnx4_alloc_inode(struct super_block *sb)
{
	struct qnx4_inode_info *ei;
	ei = kmem_cache_alloc(qnx4_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void qnx4_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(qnx4_inode_cachep, qnx4_i(inode));
}

static void qnx4_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, qnx4_i_callback);
}

static void init_once(void *foo)
{
	struct qnx4_inode_info *ei = (struct qnx4_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int init_inodecache(void)
{
	qnx4_inode_cachep = kmem_cache_create("qnx4_inode_cache",
					     sizeof(struct qnx4_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (qnx4_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(qnx4_inode_cachep);
}

static struct dentry *qnx4_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, qnx4_fill_super);
}

static struct file_system_type qnx4_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "qnx4",
	.mount		= qnx4_mount,
	.kill_sb	= qnx4_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("qnx4");

static int __init init_qnx4_fs(void)
{
	int err;

	err = init_inodecache();
	if (err)
		return err;

	err = register_filesystem(&qnx4_fs_type);
	if (err) {
		destroy_inodecache();
		return err;
	}

	printk(KERN_INFO "QNX4 filesystem 0.2.3 registered.\n");
	return 0;
}

static void __exit exit_qnx4_fs(void)
{
	unregister_filesystem(&qnx4_fs_type);
	destroy_inodecache();
}

module_init(init_qnx4_fs)
module_exit(exit_qnx4_fs)
MODULE_LICENSE("GPL");
/************************************************************/
/* ../linux-3.17/fs/qnx4/inode.c */
/************************************************************/
/*
 * QNX4 file system, Linux implementation.
 *
 * Version : 0.2.1
 *
 * Using parts of the xiafs filesystem.
 *
 * History :
 *
 * 28-05-1998 by Richard Frowijn : first release.
 * 20-06-1998 by Frank Denis : Linux 2.1.99+ & dcache support.
 */

// #include <linux/buffer_head.h>
// #include "qnx4.h"

static int qnx4_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	unsigned int offset;
	struct buffer_head *bh;
	struct qnx4_inode_entry *de;
	struct qnx4_link_info *le;
	unsigned long blknum;
	int ix, ino;
	int size;

	QNX4DEBUG((KERN_INFO "qnx4_readdir:i_size = %ld\n", (long) inode->i_size));
	QNX4DEBUG((KERN_INFO "pos                 = %ld\n", (long) ctx->pos));

	while (ctx->pos < inode->i_size) {
		blknum = qnx4_block_map(inode, ctx->pos >> QNX4_BLOCK_SIZE_BITS);
		bh = sb_bread(inode->i_sb, blknum);
		if (bh == NULL) {
			printk(KERN_ERR "qnx4_readdir: bread failed (%ld)\n", blknum);
			return 0;
		}
		ix = (ctx->pos >> QNX4_DIR_ENTRY_SIZE_BITS) % QNX4_INODES_PER_BLOCK;
		for (; ix < QNX4_INODES_PER_BLOCK; ix++, ctx->pos += QNX4_DIR_ENTRY_SIZE) {
			offset = ix * QNX4_DIR_ENTRY_SIZE;
			de = (struct qnx4_inode_entry *) (bh->b_data + offset);
			if (!de->di_fname[0])
				continue;
			if (!(de->di_status & (QNX4_FILE_USED|QNX4_FILE_LINK)))
				continue;
			if (!(de->di_status & QNX4_FILE_LINK))
				size = QNX4_SHORT_NAME_MAX;
			else
				size = QNX4_NAME_MAX;
			size = strnlen(de->di_fname, size);
			QNX4DEBUG((KERN_INFO "qnx4_readdir:%.*s\n", size, de->di_fname));
			if (!(de->di_status & QNX4_FILE_LINK))
				ino = blknum * QNX4_INODES_PER_BLOCK + ix - 1;
			else {
				le  = (struct qnx4_link_info*)de;
				ino = ( le32_to_cpu(le->dl_inode_blk) - 1 ) *
					QNX4_INODES_PER_BLOCK +
					le->dl_inode_ndx;
			}
			if (!dir_emit(ctx, de->di_fname, size, ino, DT_UNKNOWN)) {
				brelse(bh);
				return 0;
			}
		}
		brelse(bh);
	}
	return 0;
}

const struct file_operations qnx4_dir_operations =
{
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= qnx4_readdir,
	.fsync		= generic_file_fsync,
};

const struct inode_operations qnx4_dir_inode_operations =
{
	.lookup		= qnx4_lookup,
};
/************************************************************/
/* ../linux-3.17/fs/qnx4/dir.c */
/************************************************************/
/*
 * QNX4 file system, Linux implementation.
 *
 * Version : 0.2.1
 *
 * Using parts of the xiafs filesystem.
 *
 * History :
 *
 * 01-06-1998 by Richard Frowijn : first release.
 * 21-06-1998 by Frank Denis : dcache support, fixed error codes.
 * 04-07-1998 by Frank Denis : first step for rmdir/unlink.
 */

// #include <linux/buffer_head.h>
// #include "qnx4.h"


/*
 * check if the filename is correct. For some obscure reason, qnx writes a
 * new file twice in the directory entry, first with all possible options at 0
 * and for a second time the way it is, they want us not to access the qnx
 * filesystem when whe are using linux.
 */
static int qnx4_match(int len, const char *name,
		      struct buffer_head *bh, unsigned long *offset)
{
	struct qnx4_inode_entry *de;
	int namelen, thislen;

	if (bh == NULL) {
		printk(KERN_WARNING "qnx4: matching unassigned buffer !\n");
		return 0;
	}
	de = (struct qnx4_inode_entry *) (bh->b_data + *offset);
	*offset += QNX4_DIR_ENTRY_SIZE;
	if ((de->di_status & QNX4_FILE_LINK) != 0) {
		namelen = QNX4_NAME_MAX;
	} else {
		namelen = QNX4_SHORT_NAME_MAX;
	}
	thislen = strlen( de->di_fname );
	if ( thislen > namelen )
		thislen = namelen;
	if (len != thislen) {
		return 0;
	}
	if (strncmp(name, de->di_fname, len) == 0) {
		if ((de->di_status & (QNX4_FILE_USED|QNX4_FILE_LINK)) != 0) {
			return 1;
		}
	}
	return 0;
}

static struct buffer_head *qnx4_find_entry(int len, struct inode *dir,
	   const char *name, struct qnx4_inode_entry **res_dir, int *ino)
{
	unsigned long block, offset, blkofs;
	struct buffer_head *bh;

	*res_dir = NULL;
	bh = NULL;
	block = offset = blkofs = 0;
	while (blkofs * QNX4_BLOCK_SIZE + offset < dir->i_size) {
		if (!bh) {
			block = qnx4_block_map(dir, blkofs);
			if (block)
				bh = sb_bread(dir->i_sb, block);
			if (!bh) {
				blkofs++;
				continue;
			}
		}
		*res_dir = (struct qnx4_inode_entry *) (bh->b_data + offset);
		if (qnx4_match(len, name, bh, &offset)) {
			*ino = block * QNX4_INODES_PER_BLOCK +
			    (offset / QNX4_DIR_ENTRY_SIZE) - 1;
			return bh;
		}
		if (offset < bh->b_size) {
			continue;
		}
		brelse(bh);
		bh = NULL;
		offset = 0;
		blkofs++;
	}
	brelse(bh);
	*res_dir = NULL;
	return NULL;
}

struct dentry * qnx4_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	int ino;
	struct qnx4_inode_entry *de;
	struct qnx4_link_info *lnk;
	struct buffer_head *bh;
	const char *name = dentry->d_name.name;
	int len = dentry->d_name.len;
	struct inode *foundinode = NULL;

	if (!(bh = qnx4_find_entry(len, dir, name, &de, &ino)))
		goto out;
	/* The entry is linked, let's get the real info */
	if ((de->di_status & QNX4_FILE_LINK) == QNX4_FILE_LINK) {
		lnk = (struct qnx4_link_info *) de;
		ino = (le32_to_cpu(lnk->dl_inode_blk) - 1) *
                    QNX4_INODES_PER_BLOCK +
		    lnk->dl_inode_ndx;
	}
	brelse(bh);

	foundinode = qnx4_iget(dir->i_sb, ino);
	if (IS_ERR(foundinode)) {
		QNX4DEBUG((KERN_ERR "qnx4: lookup->iget -> error %ld\n",
			   PTR_ERR(foundinode)));
		return ERR_CAST(foundinode);
	}
out:
	d_add(dentry, foundinode);

	return NULL;
}
/************************************************************/
/* ../linux-3.17/fs/qnx4/namei.c */
/************************************************************/
/*
 * QNX4 file system, Linux implementation.
 *
 * Version : 0.2.1
 *
 * Using parts of the xiafs filesystem.
 *
 * History :
 *
 * 28-05-1998 by Richard Frowijn : first release.
 * 20-06-1998 by Frank Denis : basic optimisations.
 * 25-06-1998 by Frank Denis : qnx4_is_free, qnx4_set_bitmap, qnx4_bmap .
 * 28-06-1998 by Frank Denis : qnx4_free_inode (to be fixed) .
 */

// #include <linux/buffer_head.h>
#include <linux/bitops.h>
// #include "qnx4.h"

unsigned long qnx4_count_free_blocks(struct super_block *sb)
{
	int start = le32_to_cpu(qnx4_sb(sb)->BitMap->di_first_xtnt.xtnt_blk) - 1;
	int total = 0;
	int total_free = 0;
	int offset = 0;
	int size = le32_to_cpu(qnx4_sb(sb)->BitMap->di_size);
	struct buffer_head *bh;

	while (total < size) {
		int bytes = min(size - total, QNX4_BLOCK_SIZE);

		if ((bh = sb_bread(sb, start + offset)) == NULL) {
			printk(KERN_ERR "qnx4: I/O error in counting free blocks\n");
			break;
		}
		total_free += bytes * BITS_PER_BYTE -
				memweight(bh->b_data, bytes);
		brelse(bh);
		total += bytes;
		offset++;
	}

	return total_free;
}
/************************************************************/
/* ../linux-3.17/fs/qnx4/bitmap.c */
/************************************************************/
