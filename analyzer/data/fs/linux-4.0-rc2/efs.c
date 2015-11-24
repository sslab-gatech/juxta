/*
 * super.c
 *
 * Copyright (c) 1999 Al Smith
 *
 * Portions derived from work (c) 1995,1996 Christian Vogelgsang.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/exportfs.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/vfs.h>
#include "../../inc/__fss.h"

#include "efs.h"
#include <linux/efs_vh.h>
#include <linux/efs_fs_sb.h>
#include "../../inc/__fss.h"

static int efs_statfs(struct dentry *dentry, struct kstatfs *buf);
static int efs_fill_super(struct super_block *s, void *d, int silent);

static struct dentry *efs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, efs_fill_super);
}

static void efs_kill_sb(struct super_block *s)
{
	struct efs_sb_info *sbi = SUPER_INFO(s);
	kill_block_super(s);
	kfree(sbi);
}

static struct file_system_type efs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "efs",
	.mount		= efs_mount,
	.kill_sb	= efs_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("efs");

static struct pt_types sgi_pt_types[] = {
	{0x00,		"SGI vh"},
	{0x01,		"SGI trkrepl"},
	{0x02,		"SGI secrepl"},
	{0x03,		"SGI raw"},
	{0x04,		"SGI bsd"},
	{SGI_SYSV,	"SGI sysv"},
	{0x06,		"SGI vol"},
	{SGI_EFS,	"SGI efs"},
	{0x08,		"SGI lv"},
	{0x09,		"SGI rlv"},
	{0x0A,		"SGI xfs"},
	{0x0B,		"SGI xfslog"},
	{0x0C,		"SGI xlv"},
	{0x82,		"Linux swap"},
	{0x83,		"Linux native"},
	{0,		NULL}
};


static struct kmem_cache * efs_inode_cachep;

static struct inode *efs_alloc_inode(struct super_block *sb)
{
	struct efs_inode_info *ei;
	ei = (struct efs_inode_info *)kmem_cache_alloc(efs_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void efs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(efs_inode_cachep, INODE_INFO(inode));
}

static void efs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, efs_i_callback);
}

static void init_once(void *foo)
{
	struct efs_inode_info *ei = (struct efs_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	efs_inode_cachep = kmem_cache_create("efs_inode_cache",
				sizeof(struct efs_inode_info),
				0, SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD,
				init_once);
	if (efs_inode_cachep == NULL)
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
	kmem_cache_destroy(efs_inode_cachep);
}

static int efs_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	*flags |= MS_RDONLY;
	return 0;
}

static const struct super_operations efs_superblock_operations = {
	.alloc_inode	= efs_alloc_inode,
	.destroy_inode	= efs_destroy_inode,
	.statfs		= efs_statfs,
	.remount_fs	= efs_remount,
};

static const struct export_operations efs_export_ops = {
	.fh_to_dentry	= efs_fh_to_dentry,
	.fh_to_parent	= efs_fh_to_parent,
	.get_parent	= efs_get_parent,
};

static int __init init_efs_fs(void) {
	int err;
	pr_info(EFS_VERSION" - http://aeschi.ch.eu.org/efs/\n");
	err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&efs_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_efs_fs(void) {
	unregister_filesystem(&efs_fs_type);
	destroy_inodecache();
}

module_init(init_efs_fs)
module_exit(exit_efs_fs)

static efs_block_t efs_validate_vh(struct volume_header *vh) {
	int		i;
	__be32		cs, *ui;
	int		csum;
	efs_block_t	sblock = 0; /* shuts up gcc */
	struct pt_types	*pt_entry;
	int		pt_type, slice = -1;

	if (be32_to_cpu(vh->vh_magic) != VHMAGIC) {
		/*
		 * assume that we're dealing with a partition and allow
		 * read_super() to try and detect a valid superblock
		 * on the next block.
		 */
		return 0;
	}

	ui = ((__be32 *) (vh + 1)) - 1;
	for(csum = 0; ui >= ((__be32 *) vh);) {
		cs = *ui--;
		csum += be32_to_cpu(cs);
	}
	if (csum) {
		pr_warn("SGI disklabel: checksum bad, label corrupted\n");
		return 0;
	}

#ifdef DEBUG
	pr_debug("bf: \"%16s\"\n", vh->vh_bootfile);

	for(i = 0; i < NVDIR; i++) {
		int	j;
		char	name[VDNAMESIZE+1];

		for(j = 0; j < VDNAMESIZE; j++) {
			name[j] = vh->vh_vd[i].vd_name[j];
		}
		name[j] = (char) 0;

		if (name[0]) {
			pr_debug("vh: %8s block: 0x%08x size: 0x%08x\n",
				name, (int) be32_to_cpu(vh->vh_vd[i].vd_lbn),
				(int) be32_to_cpu(vh->vh_vd[i].vd_nbytes));
		}
	}
#endif

	for(i = 0; i < NPARTAB; i++) {
		pt_type = (int) be32_to_cpu(vh->vh_pt[i].pt_type);
		for(pt_entry = sgi_pt_types; pt_entry->pt_name; pt_entry++) {
			if (pt_type == pt_entry->pt_type) break;
		}
#ifdef DEBUG
		if (be32_to_cpu(vh->vh_pt[i].pt_nblks)) {
			pr_debug("pt %2d: start: %08d size: %08d type: 0x%02x (%s)\n",
				 i, (int)be32_to_cpu(vh->vh_pt[i].pt_firstlbn),
				 (int)be32_to_cpu(vh->vh_pt[i].pt_nblks),
				 pt_type, (pt_entry->pt_name) ?
				 pt_entry->pt_name : "unknown");
		}
#endif
		if (IS_EFS(pt_type)) {
			sblock = be32_to_cpu(vh->vh_pt[i].pt_firstlbn);
			slice = i;
		}
	}

	if (slice == -1) {
		pr_notice("partition table contained no EFS partitions\n");
#ifdef DEBUG
	} else {
		pr_info("using slice %d (type %s, offset 0x%x)\n", slice,
			(pt_entry->pt_name) ? pt_entry->pt_name : "unknown",
			sblock);
#endif
	}
	return sblock;
}

static int efs_validate_super(struct efs_sb_info *sb, struct efs_super *super) {

	if (!IS_EFS_MAGIC(be32_to_cpu(super->fs_magic)))
		return -1;

	sb->fs_magic     = be32_to_cpu(super->fs_magic);
	sb->total_blocks = be32_to_cpu(super->fs_size);
	sb->first_block  = be32_to_cpu(super->fs_firstcg);
	sb->group_size   = be32_to_cpu(super->fs_cgfsize);
	sb->data_free    = be32_to_cpu(super->fs_tfree);
	sb->inode_free   = be32_to_cpu(super->fs_tinode);
	sb->inode_blocks = be16_to_cpu(super->fs_cgisize);
	sb->total_groups = be16_to_cpu(super->fs_ncg);
    
	return 0;    
}

static int efs_fill_super(struct super_block *s, void *d, int silent)
{
	struct efs_sb_info *sb;
	struct buffer_head *bh;
	struct inode *root;

 	sb = kzalloc(sizeof(struct efs_sb_info), GFP_KERNEL);
	if (!sb)
		return -ENOMEM;
	s->s_fs_info = sb;
 
	s->s_magic		= EFS_SUPER_MAGIC;
	if (!sb_set_blocksize(s, EFS_BLOCKSIZE)) {
		pr_err("device does not support %d byte blocks\n",
			EFS_BLOCKSIZE);
		return -EINVAL;
	}
  
	/* read the vh (volume header) block */
	bh = sb_bread(s, 0);

	if (!bh) {
		pr_err("cannot read volume header\n");
		return -EINVAL;
	}

	/*
	 * if this returns zero then we didn't find any partition table.
	 * this isn't (yet) an error - just assume for the moment that
	 * the device is valid and go on to search for a superblock.
	 */
	sb->fs_start = efs_validate_vh((struct volume_header *) bh->b_data);
	brelse(bh);

	if (sb->fs_start == -1) {
		return -EINVAL;
	}

	bh = sb_bread(s, sb->fs_start + EFS_SUPER);
	if (!bh) {
		pr_err("cannot read superblock\n");
		return -EINVAL;
	}
		
	if (efs_validate_super(sb, (struct efs_super *) bh->b_data)) {
#ifdef DEBUG
		pr_warn("invalid superblock at block %u\n",
			sb->fs_start + EFS_SUPER);
#endif
		brelse(bh);
		return -EINVAL;
	}
	brelse(bh);

	if (!(s->s_flags & MS_RDONLY)) {
#ifdef DEBUG
		pr_info("forcing read-only mode\n");
#endif
		s->s_flags |= MS_RDONLY;
	}
	s->s_op   = &efs_superblock_operations;
	s->s_export_op = &efs_export_ops;
	root = efs_iget(s, EFS_ROOTINODE);
	if (IS_ERR(root)) {
		pr_err("get root inode failed\n");
		return PTR_ERR(root);
	}

	s->s_root = d_make_root(root);
	if (!(s->s_root)) {
		pr_err("get root dentry failed\n");
		return -ENOMEM;
	}

	return 0;
}

static int efs_statfs(struct dentry *dentry, struct kstatfs *buf) {
	struct super_block *sb = dentry->d_sb;
	struct efs_sb_info *sbi = SUPER_INFO(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type    = EFS_SUPER_MAGIC;	/* efs magic number */
	buf->f_bsize   = EFS_BLOCKSIZE;		/* blocksize */
	buf->f_blocks  = sbi->total_groups *	/* total data blocks */
			(sbi->group_size - sbi->inode_blocks);
	buf->f_bfree   = sbi->data_free;	/* free data blocks */
	buf->f_bavail  = sbi->data_free;	/* free blocks for non-root */
	buf->f_files   = sbi->total_groups *	/* total inodes */
			sbi->inode_blocks *
			(EFS_BLOCKSIZE / sizeof(struct efs_dinode));
	buf->f_ffree   = sbi->inode_free;	/* free inodes */
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen = EFS_MAXNAMELEN;	/* max filename length */

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/efs/super.c */
/************************************************************/
/*
 * inode.c
 *
 * Copyright (c) 1999 Al Smith
 *
 * Portions derived from work (c) 1995,1996 Christian Vogelgsang,
 *              and from work (c) 1998 Mike Shaver.
 */

// #include <linux/buffer_head.h>
// #include <linux/module.h>
#include <linux/fs.h>
// #include "efs.h"
// #include <linux/efs_fs_sb.h>
#include "../../inc/__fss.h"

static int efs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page,efs_get_block);
}
static sector_t _efs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,efs_get_block);
}
static const struct address_space_operations efs_aops = {
	.readpage = efs_readpage,
	.bmap = _efs_bmap
};

static inline void extent_copy(efs_extent *src, efs_extent *dst) {
	/*
	 * this is slightly evil. it doesn't just copy
	 * efs_extent from src to dst, it also mangles
	 * the bits so that dst ends up in cpu byte-order.
	 */

	dst->cooked.ex_magic  =  (unsigned int) src->raw[0];
	dst->cooked.ex_bn     = ((unsigned int) src->raw[1] << 16) |
				((unsigned int) src->raw[2] <<  8) |
				((unsigned int) src->raw[3] <<  0);
	dst->cooked.ex_length =  (unsigned int) src->raw[4];
	dst->cooked.ex_offset = ((unsigned int) src->raw[5] << 16) |
				((unsigned int) src->raw[6] <<  8) |
				((unsigned int) src->raw[7] <<  0);
	return;
}

struct inode *efs_iget(struct super_block *super, unsigned long ino)
{
	int i, inode_index;
	dev_t device;
	u32 rdev;
	struct buffer_head *bh;
	struct efs_sb_info    *sb = SUPER_INFO(super);
	struct efs_inode_info *in;
	efs_block_t block, offset;
	struct efs_dinode *efs_inode;
	struct inode *inode;

	inode = iget_locked(super, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	in = INODE_INFO(inode);

	/*
	** EFS layout:
	**
	** |   cylinder group    |   cylinder group    |   cylinder group ..etc
	** |inodes|data          |inodes|data          |inodes|data       ..etc
	**
	** work out the inode block index, (considering initially that the
	** inodes are stored as consecutive blocks). then work out the block
	** number of that inode given the above layout, and finally the
	** offset of the inode within that block.
	*/

	inode_index = inode->i_ino /
		(EFS_BLOCKSIZE / sizeof(struct efs_dinode));

	block = sb->fs_start + sb->first_block + 
		(sb->group_size * (inode_index / sb->inode_blocks)) +
		(inode_index % sb->inode_blocks);

	offset = (inode->i_ino %
			(EFS_BLOCKSIZE / sizeof(struct efs_dinode))) *
		sizeof(struct efs_dinode);

	bh = sb_bread(inode->i_sb, block);
	if (!bh) {
		pr_warn("%s() failed at block %d\n", __func__, block);
		goto read_inode_error;
	}

	efs_inode = (struct efs_dinode *) (bh->b_data + offset);
    
	inode->i_mode  = be16_to_cpu(efs_inode->di_mode);
	set_nlink(inode, be16_to_cpu(efs_inode->di_nlink));
	i_uid_write(inode, (uid_t)be16_to_cpu(efs_inode->di_uid));
	i_gid_write(inode, (gid_t)be16_to_cpu(efs_inode->di_gid));
	inode->i_size  = be32_to_cpu(efs_inode->di_size);
	inode->i_atime.tv_sec = be32_to_cpu(efs_inode->di_atime);
	inode->i_mtime.tv_sec = be32_to_cpu(efs_inode->di_mtime);
	inode->i_ctime.tv_sec = be32_to_cpu(efs_inode->di_ctime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;

	/* this is the number of blocks in the file */
	if (inode->i_size == 0) {
		inode->i_blocks = 0;
	} else {
		inode->i_blocks = ((inode->i_size - 1) >> EFS_BLOCKSIZE_BITS) + 1;
	}

	rdev = be16_to_cpu(efs_inode->di_u.di_dev.odev);
	if (rdev == 0xffff) {
		rdev = be32_to_cpu(efs_inode->di_u.di_dev.ndev);
		if (sysv_major(rdev) > 0xfff)
			device = 0;
		else
			device = MKDEV(sysv_major(rdev), sysv_minor(rdev));
	} else
		device = old_decode_dev(rdev);

	/* get the number of extents for this object */
	in->numextents = be16_to_cpu(efs_inode->di_numextents);
	in->lastextent = 0;

	/* copy the extents contained within the inode to memory */
	for(i = 0; i < EFS_DIRECTEXTENTS; i++) {
		extent_copy(&(efs_inode->di_u.di_extents[i]), &(in->extents[i]));
		if (i < in->numextents && in->extents[i].cooked.ex_magic != 0) {
			pr_warn("extent %d has bad magic number in inode %lu\n",
				i, inode->i_ino);
			brelse(bh);
			goto read_inode_error;
		}
	}

	brelse(bh);
	pr_debug("efs_iget(): inode %lu, extents %d, mode %o\n",
		 inode->i_ino, in->numextents, inode->i_mode);
	switch (inode->i_mode & S_IFMT) {
		case S_IFDIR: 
			inode->i_op = &efs_dir_inode_operations; 
			inode->i_fop = &efs_dir_operations; 
			break;
		case S_IFREG:
			inode->i_fop = &generic_ro_fops;
			inode->i_data.a_ops = &efs_aops;
			break;
		case S_IFLNK:
			inode->i_op = &page_symlink_inode_operations;
			inode->i_data.a_ops = &efs_symlink_aops;
			break;
		case S_IFCHR:
		case S_IFBLK:
		case S_IFIFO:
			init_special_inode(inode, inode->i_mode, device);
			break;
		default:
			pr_warn("unsupported inode mode %o\n", inode->i_mode);
			goto read_inode_error;
			break;
	}

	unlock_new_inode(inode);
	return inode;
        
read_inode_error:
	pr_warn("failed to read inode %lu\n", inode->i_ino);
	iget_failed(inode);
	return ERR_PTR(-EIO);
}

static inline efs_block_t
efs_extent_check(efs_extent *ptr, efs_block_t block, struct efs_sb_info *sb) {
	efs_block_t start;
	efs_block_t length;
	efs_block_t offset;

	/*
	 * given an extent and a logical block within a file,
	 * can this block be found within this extent ?
	 */
	start  = ptr->cooked.ex_bn;
	length = ptr->cooked.ex_length;
	offset = ptr->cooked.ex_offset;

	if ((block >= offset) && (block < offset+length)) {
		return(sb->fs_start + start + block - offset);
	} else {
		return 0;
	}
}

efs_block_t efs_map_block(struct inode *inode, efs_block_t block) {
	struct efs_sb_info    *sb = SUPER_INFO(inode->i_sb);
	struct efs_inode_info *in = INODE_INFO(inode);
	struct buffer_head    *bh = NULL;

	int cur, last, first = 1;
	int ibase, ioffset, dirext, direxts, indext, indexts;
	efs_block_t iblock, result = 0, lastblock = 0;
	efs_extent ext, *exts;

	last = in->lastextent;

	if (in->numextents <= EFS_DIRECTEXTENTS) {
		/* first check the last extent we returned */
		if ((result = efs_extent_check(&in->extents[last], block, sb)))
			return result;
    
		/* if we only have one extent then nothing can be found */
		if (in->numextents == 1) {
			pr_err("%s() failed to map (1 extent)\n", __func__);
			return 0;
		}

		direxts = in->numextents;

		/*
		 * check the stored extents in the inode
		 * start with next extent and check forwards
		 */
		for(dirext = 1; dirext < direxts; dirext++) {
			cur = (last + dirext) % in->numextents;
			if ((result = efs_extent_check(&in->extents[cur], block, sb))) {
				in->lastextent = cur;
				return result;
			}
		}

		pr_err("%s() failed to map block %u (dir)\n", __func__, block);
		return 0;
	}

	pr_debug("%s(): indirect search for logical block %u\n",
		 __func__, block);
	direxts = in->extents[0].cooked.ex_offset;
	indexts = in->numextents;

	for(indext = 0; indext < indexts; indext++) {
		cur = (last + indext) % indexts;

		/*
		 * work out which direct extent contains `cur'.
		 *
		 * also compute ibase: i.e. the number of the first
		 * indirect extent contained within direct extent `cur'.
		 *
		 */
		ibase = 0;
		for(dirext = 0; cur < ibase && dirext < direxts; dirext++) {
			ibase += in->extents[dirext].cooked.ex_length *
				(EFS_BLOCKSIZE / sizeof(efs_extent));
		}

		if (dirext == direxts) {
			/* should never happen */
			pr_err("couldn't find direct extent for indirect extent %d (block %u)\n",
			       cur, block);
			if (bh) brelse(bh);
			return 0;
		}
		
		/* work out block number and offset of this indirect extent */
		iblock = sb->fs_start + in->extents[dirext].cooked.ex_bn +
			(cur - ibase) /
			(EFS_BLOCKSIZE / sizeof(efs_extent));
		ioffset = (cur - ibase) %
			(EFS_BLOCKSIZE / sizeof(efs_extent));

		if (first || lastblock != iblock) {
			if (bh) brelse(bh);

			bh = sb_bread(inode->i_sb, iblock);
			if (!bh) {
				pr_err("%s() failed at block %d\n",
				       __func__, iblock);
				return 0;
			}
			pr_debug("%s(): read indirect extent block %d\n",
				 __func__, iblock);
			first = 0;
			lastblock = iblock;
		}

		exts = (efs_extent *) bh->b_data;

		extent_copy(&(exts[ioffset]), &ext);

		if (ext.cooked.ex_magic != 0) {
			pr_err("extent %d has bad magic number in block %d\n",
			       cur, iblock);
			if (bh) brelse(bh);
			return 0;
		}

		if ((result = efs_extent_check(&ext, block, sb))) {
			if (bh) brelse(bh);
			in->lastextent = cur;
			return result;
		}
	}
	if (bh) brelse(bh);
	pr_err("%s() failed to map block %u (indir)\n", __func__, block);
	return 0;
}  

MODULE_LICENSE("GPL");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/efs/inode.c */
/************************************************************/
/*
 * namei.c
 *
 * Copyright (c) 1999 Al Smith
 *
 * Portions derived from work (c) 1995,1996 Christian Vogelgsang.
 */

// #include <linux/buffer_head.h>
#include <linux/string.h>
// #include <linux/exportfs.h>
// #include "efs.h"
#include "../../inc/__fss.h"


static efs_ino_t efs_find_entry(struct inode *inode, const char *name, int len)
{
	struct buffer_head *bh;

	int			slot, namelen;
	char			*nameptr;
	struct efs_dir		*dirblock;
	struct efs_dentry	*dirslot;
	efs_ino_t		inodenum;
	efs_block_t		block;
 
	if (inode->i_size & (EFS_DIRBSIZE-1))
		pr_warn("%s(): directory size not a multiple of EFS_DIRBSIZE\n",
			__func__);

	for(block = 0; block < inode->i_blocks; block++) {

		bh = sb_bread(inode->i_sb, efs_bmap(inode, block));
		if (!bh) {
			pr_err("%s(): failed to read dir block %d\n",
			       __func__, block);
			return 0;
		}
    
		dirblock = (struct efs_dir *) bh->b_data;

		if (be16_to_cpu(dirblock->magic) != EFS_DIRBLK_MAGIC) {
			pr_err("%s(): invalid directory block\n", __func__);
			brelse(bh);
			return 0;
		}

		for (slot = 0; slot < dirblock->slots; slot++) {
			dirslot  = (struct efs_dentry *) (((char *) bh->b_data) + EFS_SLOTAT(dirblock, slot));

			namelen  = dirslot->namelen;
			nameptr  = dirslot->name;

			if ((namelen == len) && (!memcmp(name, nameptr, len))) {
				inodenum = be32_to_cpu(dirslot->inode);
				brelse(bh);
				return inodenum;
			}
		}
		brelse(bh);
	}
	return 0;
}

struct dentry *efs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	efs_ino_t inodenum;
	struct inode *inode = NULL;

	inodenum = efs_find_entry(dir, dentry->d_name.name, dentry->d_name.len);
	if (inodenum)
		inode = efs_iget(dir->i_sb, inodenum);

	return d_splice_alias(inode, dentry);
}

static struct inode *efs_nfs_get_inode(struct super_block *sb, u64 ino,
		u32 generation)
{
	struct inode *inode;

	if (ino == 0)
		return ERR_PTR(-ESTALE);
	inode = efs_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

struct dentry *efs_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    efs_nfs_get_inode);
}

struct dentry *efs_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    efs_nfs_get_inode);
}

struct dentry *efs_get_parent(struct dentry *child)
{
	struct dentry *parent = ERR_PTR(-ENOENT);
	efs_ino_t ino;

	ino = efs_find_entry(child->d_inode, "..", 2);
	if (ino)
		parent = d_obtain_alias(efs_iget(child->d_inode->i_sb, ino));

	return parent;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/efs/namei.c */
/************************************************************/
/*
 * dir.c
 *
 * Copyright (c) 1999 Al Smith
 */

// #include <linux/buffer_head.h>
// #include "efs.h"

static int efs_readdir(struct file *, struct dir_context *);

const struct file_operations efs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= efs_readdir,
};

const struct inode_operations efs_dir_inode_operations = {
	.lookup		= efs_lookup,
};

static int efs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	efs_block_t		block;
	int			slot;

	if (inode->i_size & (EFS_DIRBSIZE-1))
		pr_warn("%s(): directory size not a multiple of EFS_DIRBSIZE\n",
			__func__);

	/* work out where this entry can be found */
	block = ctx->pos >> EFS_DIRBSIZE_BITS;

	/* each block contains at most 256 slots */
	slot  = ctx->pos & 0xff;

	/* look at all blocks */
	while (block < inode->i_blocks) {
		struct efs_dir		*dirblock;
		struct buffer_head *bh;

		/* read the dir block */
		bh = sb_bread(inode->i_sb, efs_bmap(inode, block));

		if (!bh) {
			pr_err("%s(): failed to read dir block %d\n",
			       __func__, block);
			break;
		}

		dirblock = (struct efs_dir *) bh->b_data; 

		if (be16_to_cpu(dirblock->magic) != EFS_DIRBLK_MAGIC) {
			pr_err("%s(): invalid directory block\n", __func__);
			brelse(bh);
			break;
		}

		for (; slot < dirblock->slots; slot++) {
			struct efs_dentry *dirslot;
			efs_ino_t inodenum;
			const char *nameptr;
			int namelen;

			if (dirblock->space[slot] == 0)
				continue;

			dirslot  = (struct efs_dentry *) (((char *) bh->b_data) + EFS_SLOTAT(dirblock, slot));

			inodenum = be32_to_cpu(dirslot->inode);
			namelen  = dirslot->namelen;
			nameptr  = dirslot->name;
			pr_debug("%s(): block %d slot %d/%d: inode %u, name \"%s\", namelen %u\n",
				 __func__, block, slot, dirblock->slots-1,
				 inodenum, nameptr, namelen);
			if (!namelen)
				continue;
			/* found the next entry */
			ctx->pos = (block << EFS_DIRBSIZE_BITS) | slot;

			/* sanity check */
			if (nameptr - (char *) dirblock + namelen > EFS_DIRBSIZE) {
				pr_warn("directory entry %d exceeds directory block\n",
					slot);
				continue;
			}

			/* copy filename and data in dirslot */
			if (!dir_emit(ctx, nameptr, namelen, inodenum, DT_UNKNOWN)) {
				brelse(bh);
				return 0;
			}
		}
		brelse(bh);

		slot = 0;
		block++;
	}
	ctx->pos = (block << EFS_DIRBSIZE_BITS) | slot;
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/efs/dir.c */
/************************************************************/
/*
 * file.c
 *
 * Copyright (c) 1999 Al Smith
 *
 * Portions derived from work (c) 1995,1996 Christian Vogelgsang.
 */

// #include <linux/buffer_head.h>
// #include "efs.h"

int efs_get_block(struct inode *inode, sector_t iblock,
		  struct buffer_head *bh_result, int create)
{
	int error = -EROFS;
	long phys;

	if (create)
		return error;
	if (iblock >= inode->i_blocks) {
#ifdef DEBUG
		/*
		 * i have no idea why this happens as often as it does
		 */
		pr_warn("%s(): block %d >= %ld (filesize %ld)\n",
			__func__, block, inode->i_blocks, inode->i_size);
#endif
		return 0;
	}
	phys = efs_map_block(inode, iblock);
	if (phys)
		map_bh(bh_result, inode->i_sb, phys);
	return 0;
}

int efs_bmap(struct inode *inode, efs_block_t block) {

	if (block < 0) {
		pr_warn("%s(): block < 0\n", __func__);
		return 0;
	}

	/* are we about to read past the end of a file ? */
	if (!(block < inode->i_blocks)) {
#ifdef DEBUG
		/*
		 * i have no idea why this happens as often as it does
		 */
		pr_warn("%s(): block %d >= %ld (filesize %ld)\n",
			__func__, block, inode->i_blocks, inode->i_size);
#endif
		return 0;
	}

	return efs_map_block(inode, block);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/efs/file.c */
/************************************************************/
/*
 * symlink.c
 *
 * Copyright (c) 1999 Al Smith
 *
 * Portions derived from work (c) 1995,1996 Christian Vogelgsang.
 */

// #include <linux/string.h>
#include <linux/pagemap.h>
// #include <linux/buffer_head.h>
// #include "efs.h"
#include "../../inc/__fss.h"

static int efs_symlink_readpage(struct file *file, struct page *page)
{
	char *link = kmap(page);
	struct buffer_head * bh;
	struct inode * inode = page->mapping->host;
	efs_block_t size = inode->i_size;
	int err;
  
	err = -ENAMETOOLONG;
	if (size > 2 * EFS_BLOCKSIZE)
		goto fail;
  
	/* read first 512 bytes of link target */
	err = -EIO;
	bh = sb_bread(inode->i_sb, efs_bmap(inode, 0));
	if (!bh)
		goto fail;
	memcpy(link, bh->b_data, (size > EFS_BLOCKSIZE) ? EFS_BLOCKSIZE : size);
	brelse(bh);
	if (size > EFS_BLOCKSIZE) {
		bh = sb_bread(inode->i_sb, efs_bmap(inode, 1));
		if (!bh)
			goto fail;
		memcpy(link + EFS_BLOCKSIZE, bh->b_data, size - EFS_BLOCKSIZE);
		brelse(bh);
	}
	link[size] = '\0';
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);
	return 0;
fail:
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	return err;
}

const struct address_space_operations efs_symlink_aops = {
	.readpage	= efs_symlink_readpage
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/efs/symlink.c */
/************************************************************/
