/*
 * QNX6 file system, Linux implementation.
 *
 * Version : 1.0.0
 *
 * History :
 *
 * 01-02-2012 by Kai Bankett (chaosman@ontika.net) : first release.
 * 16-02-2012 pagemap extension by Al Viro
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/statfs.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/crc32.h>
#include <linux/mpage.h>
#include "qnx6.h"

static const struct super_operations qnx6_sops;

static void qnx6_put_super(struct super_block *sb);
static struct inode *qnx6_alloc_inode(struct super_block *sb);
static void qnx6_destroy_inode(struct inode *inode);
static int qnx6_remount(struct super_block *sb, int *flags, char *data);
static int qnx6_statfs(struct dentry *dentry, struct kstatfs *buf);
static int qnx6_show_options(struct seq_file *seq, struct dentry *root);

static const struct super_operations qnx6_sops = {
	.alloc_inode	= qnx6_alloc_inode,
	.destroy_inode	= qnx6_destroy_inode,
	.put_super	= qnx6_put_super,
	.statfs		= qnx6_statfs,
	.remount_fs	= qnx6_remount,
	.show_options	= qnx6_show_options,
};

static int qnx6_show_options(struct seq_file *seq, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct qnx6_sb_info *sbi = QNX6_SB(sb);

	if (sbi->s_mount_opt & QNX6_MOUNT_MMI_FS)
		seq_puts(seq, ",mmi_fs");
	return 0;
}

static int qnx6_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	*flags |= MS_RDONLY;
	return 0;
}

static unsigned qnx6_get_devblock(struct super_block *sb, __fs32 block)
{
	struct qnx6_sb_info *sbi = QNX6_SB(sb);
	return fs32_to_cpu(sbi, block) + sbi->s_blks_off;
}

static unsigned qnx6_block_map(struct inode *inode, unsigned iblock);

static int qnx6_get_block(struct inode *inode, sector_t iblock,
			struct buffer_head *bh, int create)
{
	unsigned phys;

	pr_debug("qnx6_get_block inode=[%ld] iblock=[%ld]\n",
		 inode->i_ino, (unsigned long)iblock);

	phys = qnx6_block_map(inode, iblock);
	if (phys) {
		/* logical block is before EOF */
		map_bh(bh, inode->i_sb, phys);
	}
	return 0;
}

static int qnx6_check_blockptr(__fs32 ptr)
{
	if (ptr == ~(__fs32)0) {
		pr_err("hit unused blockpointer.\n");
		return 0;
	}
	return 1;
}

static int qnx6_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, qnx6_get_block);
}

static int qnx6_readpages(struct file *file, struct address_space *mapping,
		   struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, qnx6_get_block);
}

/*
 * returns the block number for the no-th element in the tree
 * inodebits requred as there are multiple inodes in one inode block
 */
static unsigned qnx6_block_map(struct inode *inode, unsigned no)
{
	struct super_block *s = inode->i_sb;
	struct qnx6_sb_info *sbi = QNX6_SB(s);
	struct qnx6_inode_info *ei = QNX6_I(inode);
	unsigned block = 0;
	struct buffer_head *bh;
	__fs32 ptr;
	int levelptr;
	int ptrbits = sbi->s_ptrbits;
	int bitdelta;
	u32 mask = (1 << ptrbits) - 1;
	int depth = ei->di_filelevels;
	int i;

	bitdelta = ptrbits * depth;
	levelptr = no >> bitdelta;

	if (levelptr > QNX6_NO_DIRECT_POINTERS - 1) {
		pr_err("Requested file block number (%u) too big.", no);
		return 0;
	}

	block = qnx6_get_devblock(s, ei->di_block_ptr[levelptr]);

	for (i = 0; i < depth; i++) {
		bh = sb_bread(s, block);
		if (!bh) {
			pr_err("Error reading block (%u)\n", block);
			return 0;
		}
		bitdelta -= ptrbits;
		levelptr = (no >> bitdelta) & mask;
		ptr = ((__fs32 *)bh->b_data)[levelptr];

		if (!qnx6_check_blockptr(ptr))
			return 0;

		block = qnx6_get_devblock(s, ptr);
		brelse(bh);
	}
	return block;
}

static int qnx6_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct qnx6_sb_info *sbi = QNX6_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type    = sb->s_magic;
	buf->f_bsize   = sb->s_blocksize;
	buf->f_blocks  = fs32_to_cpu(sbi, sbi->sb->sb_num_blocks);
	buf->f_bfree   = fs32_to_cpu(sbi, sbi->sb->sb_free_blocks);
	buf->f_files   = fs32_to_cpu(sbi, sbi->sb->sb_num_inodes);
	buf->f_ffree   = fs32_to_cpu(sbi, sbi->sb->sb_free_inodes);
	buf->f_bavail  = buf->f_bfree;
	buf->f_namelen = QNX6_LONG_NAME_MAX;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}

/*
 * Check the root directory of the filesystem to make sure
 * it really _is_ a qnx6 filesystem, and to check the size
 * of the directory entry.
 */
static const char *qnx6_checkroot(struct super_block *s)
{
	static char match_root[2][3] = {".\0\0", "..\0"};
	int i, error = 0;
	struct qnx6_dir_entry *dir_entry;
	struct inode *root = s->s_root->d_inode;
	struct address_space *mapping = root->i_mapping;
	struct page *page = read_mapping_page(mapping, 0, NULL);
	if (IS_ERR(page))
		return "error reading root directory";
	kmap(page);
	dir_entry = page_address(page);
	for (i = 0; i < 2; i++) {
		/* maximum 3 bytes - due to match_root limitation */
		if (strncmp(dir_entry[i].de_fname, match_root[i], 3))
			error = 1;
	}
	qnx6_put_page(page);
	if (error)
		return "error reading root directory.";
	return NULL;
}

#ifdef CONFIG_QNX6FS_DEBUG
void qnx6_superblock_debug(struct qnx6_super_block *sb, struct super_block *s)
{
	struct qnx6_sb_info *sbi = QNX6_SB(s);

	pr_debug("magic: %08x\n", fs32_to_cpu(sbi, sb->sb_magic));
	pr_debug("checksum: %08x\n", fs32_to_cpu(sbi, sb->sb_checksum));
	pr_debug("serial: %llx\n", fs64_to_cpu(sbi, sb->sb_serial));
	pr_debug("flags: %08x\n", fs32_to_cpu(sbi, sb->sb_flags));
	pr_debug("blocksize: %08x\n", fs32_to_cpu(sbi, sb->sb_blocksize));
	pr_debug("num_inodes: %08x\n", fs32_to_cpu(sbi, sb->sb_num_inodes));
	pr_debug("free_inodes: %08x\n", fs32_to_cpu(sbi, sb->sb_free_inodes));
	pr_debug("num_blocks: %08x\n", fs32_to_cpu(sbi, sb->sb_num_blocks));
	pr_debug("free_blocks: %08x\n", fs32_to_cpu(sbi, sb->sb_free_blocks));
	pr_debug("inode_levels: %02x\n", sb->Inode.levels);
}
#endif

enum {
	Opt_mmifs,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_mmifs, "mmi_fs"},
	{Opt_err, NULL}
};

static int qnx6_parse_options(char *options, struct super_block *sb)
{
	char *p;
	struct qnx6_sb_info *sbi = QNX6_SB(sb);
	substring_t args[MAX_OPT_ARGS];

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_mmifs:
			set_opt(sbi->s_mount_opt, MMI_FS);
			break;
		default:
			return 0;
		}
	}
	return 1;
}

static struct buffer_head *qnx6_check_first_superblock(struct super_block *s,
				int offset, int silent)
{
	struct qnx6_sb_info *sbi = QNX6_SB(s);
	struct buffer_head *bh;
	struct qnx6_super_block *sb;

	/* Check the superblock signatures
	   start with the first superblock */
	bh = sb_bread(s, offset);
	if (!bh) {
		pr_err("unable to read the first superblock\n");
		return NULL;
	}
	sb = (struct qnx6_super_block *)bh->b_data;
	if (fs32_to_cpu(sbi, sb->sb_magic) != QNX6_SUPER_MAGIC) {
		sbi->s_bytesex = BYTESEX_BE;
		if (fs32_to_cpu(sbi, sb->sb_magic) == QNX6_SUPER_MAGIC) {
			/* we got a big endian fs */
			pr_debug("fs got different endianness.\n");
			return bh;
		} else
			sbi->s_bytesex = BYTESEX_LE;
		if (!silent) {
			if (offset == 0) {
				pr_err("wrong signature (magic) in superblock #1.\n");
			} else {
				pr_info("wrong signature (magic) at position (0x%lx) - will try alternative position (0x0000).\n",
					offset * s->s_blocksize);
			}
		}
		brelse(bh);
		return NULL;
	}
	return bh;
}

static struct inode *qnx6_private_inode(struct super_block *s,
					struct qnx6_root_node *p);

static int qnx6_fill_super(struct super_block *s, void *data, int silent)
{
	struct buffer_head *bh1 = NULL, *bh2 = NULL;
	struct qnx6_super_block *sb1 = NULL, *sb2 = NULL;
	struct qnx6_sb_info *sbi;
	struct inode *root;
	const char *errmsg;
	struct qnx6_sb_info *qs;
	int ret = -EINVAL;
	u64 offset;
	int bootblock_offset = QNX6_BOOTBLOCK_SIZE;

	qs = kzalloc(sizeof(struct qnx6_sb_info), GFP_KERNEL);
	if (!qs)
		return -ENOMEM;
	s->s_fs_info = qs;

	/* Superblock always is 512 Byte long */
	if (!sb_set_blocksize(s, QNX6_SUPERBLOCK_SIZE)) {
		pr_err("unable to set blocksize\n");
		goto outnobh;
	}

	/* parse the mount-options */
	if (!qnx6_parse_options((char *) data, s)) {
		pr_err("invalid mount options.\n");
		goto outnobh;
	}
	if (test_opt(s, MMI_FS)) {
		sb1 = qnx6_mmi_fill_super(s, silent);
		if (sb1)
			goto mmi_success;
		else
			goto outnobh;
	}
	sbi = QNX6_SB(s);
	sbi->s_bytesex = BYTESEX_LE;
	/* Check the superblock signatures
	   start with the first superblock */
	bh1 = qnx6_check_first_superblock(s,
		bootblock_offset / QNX6_SUPERBLOCK_SIZE, silent);
	if (!bh1) {
		/* try again without bootblock offset */
		bh1 = qnx6_check_first_superblock(s, 0, silent);
		if (!bh1) {
			pr_err("unable to read the first superblock\n");
			goto outnobh;
		}
		/* seems that no bootblock at partition start */
		bootblock_offset = 0;
	}
	sb1 = (struct qnx6_super_block *)bh1->b_data;

#ifdef CONFIG_QNX6FS_DEBUG
	qnx6_superblock_debug(sb1, s);
#endif

	/* checksum check - start at byte 8 and end at byte 512 */
	if (fs32_to_cpu(sbi, sb1->sb_checksum) !=
			crc32_be(0, (char *)(bh1->b_data + 8), 504)) {
		pr_err("superblock #1 checksum error\n");
		goto out;
	}

	/* set new blocksize */
	if (!sb_set_blocksize(s, fs32_to_cpu(sbi, sb1->sb_blocksize))) {
		pr_err("unable to set blocksize\n");
		goto out;
	}
	/* blocksize invalidates bh - pull it back in */
	brelse(bh1);
	bh1 = sb_bread(s, bootblock_offset >> s->s_blocksize_bits);
	if (!bh1)
		goto outnobh;
	sb1 = (struct qnx6_super_block *)bh1->b_data;

	/* calculate second superblock blocknumber */
	offset = fs32_to_cpu(sbi, sb1->sb_num_blocks) +
		(bootblock_offset >> s->s_blocksize_bits) +
		(QNX6_SUPERBLOCK_AREA >> s->s_blocksize_bits);

	/* set bootblock offset */
	sbi->s_blks_off = (bootblock_offset >> s->s_blocksize_bits) +
			  (QNX6_SUPERBLOCK_AREA >> s->s_blocksize_bits);

	/* next the second superblock */
	bh2 = sb_bread(s, offset);
	if (!bh2) {
		pr_err("unable to read the second superblock\n");
		goto out;
	}
	sb2 = (struct qnx6_super_block *)bh2->b_data;
	if (fs32_to_cpu(sbi, sb2->sb_magic) != QNX6_SUPER_MAGIC) {
		if (!silent)
			pr_err("wrong signature (magic) in superblock #2.\n");
		goto out;
	}

	/* checksum check - start at byte 8 and end at byte 512 */
	if (fs32_to_cpu(sbi, sb2->sb_checksum) !=
				crc32_be(0, (char *)(bh2->b_data + 8), 504)) {
		pr_err("superblock #2 checksum error\n");
		goto out;
	}

	if (fs64_to_cpu(sbi, sb1->sb_serial) >=
					fs64_to_cpu(sbi, sb2->sb_serial)) {
		/* superblock #1 active */
		sbi->sb_buf = bh1;
		sbi->sb = (struct qnx6_super_block *)bh1->b_data;
		brelse(bh2);
		pr_info("superblock #1 active\n");
	} else {
		/* superblock #2 active */
		sbi->sb_buf = bh2;
		sbi->sb = (struct qnx6_super_block *)bh2->b_data;
		brelse(bh1);
		pr_info("superblock #2 active\n");
	}
mmi_success:
	/* sanity check - limit maximum indirect pointer levels */
	if (sb1->Inode.levels > QNX6_PTR_MAX_LEVELS) {
		pr_err("too many inode levels (max %i, sb %i)\n",
		       QNX6_PTR_MAX_LEVELS, sb1->Inode.levels);
		goto out;
	}
	if (sb1->Longfile.levels > QNX6_PTR_MAX_LEVELS) {
		pr_err("too many longfilename levels (max %i, sb %i)\n",
		       QNX6_PTR_MAX_LEVELS, sb1->Longfile.levels);
		goto out;
	}
	s->s_op = &qnx6_sops;
	s->s_magic = QNX6_SUPER_MAGIC;
	s->s_flags |= MS_RDONLY;        /* Yup, read-only yet */

	/* ease the later tree level calculations */
	sbi = QNX6_SB(s);
	sbi->s_ptrbits = ilog2(s->s_blocksize / 4);
	sbi->inodes = qnx6_private_inode(s, &sb1->Inode);
	if (!sbi->inodes)
		goto out;
	sbi->longfile = qnx6_private_inode(s, &sb1->Longfile);
	if (!sbi->longfile)
		goto out1;

	/* prefetch root inode */
	root = qnx6_iget(s, QNX6_ROOT_INO);
	if (IS_ERR(root)) {
		pr_err("get inode failed\n");
		ret = PTR_ERR(root);
		goto out2;
	}

	ret = -ENOMEM;
	s->s_root = d_make_root(root);
	if (!s->s_root)
		goto out2;

	ret = -EINVAL;
	errmsg = qnx6_checkroot(s);
	if (errmsg != NULL) {
		if (!silent)
			pr_err("%s\n", errmsg);
		goto out3;
	}
	return 0;

out3:
	dput(s->s_root);
	s->s_root = NULL;
out2:
	iput(sbi->longfile);
out1:
	iput(sbi->inodes);
out:
	if (bh1)
		brelse(bh1);
	if (bh2)
		brelse(bh2);
outnobh:
	kfree(qs);
	s->s_fs_info = NULL;
	return ret;
}

static void qnx6_put_super(struct super_block *sb)
{
	struct qnx6_sb_info *qs = QNX6_SB(sb);
	brelse(qs->sb_buf);
	iput(qs->longfile);
	iput(qs->inodes);
	kfree(qs);
	sb->s_fs_info = NULL;
	return;
}

static sector_t qnx6_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, qnx6_get_block);
}
static const struct address_space_operations qnx6_aops = {
	.readpage	= qnx6_readpage,
	.readpages	= qnx6_readpages,
	.bmap		= qnx6_bmap
};

static struct inode *qnx6_private_inode(struct super_block *s,
					struct qnx6_root_node *p)
{
	struct inode *inode = new_inode(s);
	if (inode) {
		struct qnx6_inode_info *ei = QNX6_I(inode);
		struct qnx6_sb_info *sbi = QNX6_SB(s);
		inode->i_size = fs64_to_cpu(sbi, p->size);
		memcpy(ei->di_block_ptr, p->ptr, sizeof(p->ptr));
		ei->di_filelevels = p->levels;
		inode->i_mode = S_IFREG | S_IRUSR; /* probably wrong */
		inode->i_mapping->a_ops = &qnx6_aops;
	}
	return inode;
}

struct inode *qnx6_iget(struct super_block *sb, unsigned ino)
{
	struct qnx6_sb_info *sbi = QNX6_SB(sb);
	struct qnx6_inode_entry *raw_inode;
	struct inode *inode;
	struct qnx6_inode_info	*ei;
	struct address_space *mapping;
	struct page *page;
	u32 n, offs;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ei = QNX6_I(inode);

	inode->i_mode = 0;

	if (ino == 0) {
		pr_err("bad inode number on dev %s: %u is out of range\n",
		       sb->s_id, ino);
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}
	n = (ino - 1) >> (PAGE_CACHE_SHIFT - QNX6_INODE_SIZE_BITS);
	offs = (ino - 1) & (~PAGE_CACHE_MASK >> QNX6_INODE_SIZE_BITS);
	mapping = sbi->inodes->i_mapping;
	page = read_mapping_page(mapping, n, NULL);
	if (IS_ERR(page)) {
		pr_err("major problem: unable to read inode from dev %s\n",
		       sb->s_id);
		iget_failed(inode);
		return ERR_CAST(page);
	}
	kmap(page);
	raw_inode = ((struct qnx6_inode_entry *)page_address(page)) + offs;

	inode->i_mode    = fs16_to_cpu(sbi, raw_inode->di_mode);
	i_uid_write(inode, (uid_t)fs32_to_cpu(sbi, raw_inode->di_uid));
	i_gid_write(inode, (gid_t)fs32_to_cpu(sbi, raw_inode->di_gid));
	inode->i_size    = fs64_to_cpu(sbi, raw_inode->di_size);
	inode->i_mtime.tv_sec   = fs32_to_cpu(sbi, raw_inode->di_mtime);
	inode->i_mtime.tv_nsec = 0;
	inode->i_atime.tv_sec   = fs32_to_cpu(sbi, raw_inode->di_atime);
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_sec   = fs32_to_cpu(sbi, raw_inode->di_ctime);
	inode->i_ctime.tv_nsec = 0;

	/* calc blocks based on 512 byte blocksize */
	inode->i_blocks = (inode->i_size + 511) >> 9;

	memcpy(&ei->di_block_ptr, &raw_inode->di_block_ptr,
				sizeof(raw_inode->di_block_ptr));
	ei->di_filelevels = raw_inode->di_filelevels;

	if (S_ISREG(inode->i_mode)) {
		inode->i_fop = &generic_ro_fops;
		inode->i_mapping->a_ops = &qnx6_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &qnx6_dir_inode_operations;
		inode->i_fop = &qnx6_dir_operations;
		inode->i_mapping->a_ops = &qnx6_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &page_symlink_inode_operations;
		inode->i_mapping->a_ops = &qnx6_aops;
	} else
		init_special_inode(inode, inode->i_mode, 0);
	qnx6_put_page(page);
	unlock_new_inode(inode);
	return inode;
}

static struct kmem_cache *qnx6_inode_cachep;

static struct inode *qnx6_alloc_inode(struct super_block *sb)
{
	struct qnx6_inode_info *ei;
	ei = kmem_cache_alloc(qnx6_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void qnx6_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(qnx6_inode_cachep, QNX6_I(inode));
}

static void qnx6_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, qnx6_i_callback);
}

static void init_once(void *foo)
{
	struct qnx6_inode_info *ei = (struct qnx6_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int init_inodecache(void)
{
	qnx6_inode_cachep = kmem_cache_create("qnx6_inode_cache",
					     sizeof(struct qnx6_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (!qnx6_inode_cachep)
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
	kmem_cache_destroy(qnx6_inode_cachep);
}

static struct dentry *qnx6_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, qnx6_fill_super);
}

static struct file_system_type qnx6_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "qnx6",
	.mount		= qnx6_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("qnx6");

static int __init init_qnx6_fs(void)
{
	int err;

	err = init_inodecache();
	if (err)
		return err;

	err = register_filesystem(&qnx6_fs_type);
	if (err) {
		destroy_inodecache();
		return err;
	}

	pr_info("QNX6 filesystem 1.0.0 registered.\n");
	return 0;
}

static void __exit exit_qnx6_fs(void)
{
	unregister_filesystem(&qnx6_fs_type);
	destroy_inodecache();
}

module_init(init_qnx6_fs)
module_exit(exit_qnx6_fs)
MODULE_LICENSE("GPL");
/************************************************************/
/* ../linux-3.17/fs/qnx6/inode.c */
/************************************************************/
/*
 * QNX6 file system, Linux implementation.
 *
 * Version : 1.0.0
 *
 * History :
 *
 * 01-02-2012 by Kai Bankett (chaosman@ontika.net) : first release.
 * 16-02-2012 pagemap extension by Al Viro
 *
 */

// #include "qnx6.h"

static unsigned qnx6_lfile_checksum(char *name, unsigned size)
{
	unsigned crc = 0;
	char *end = name + size;
	while (name < end) {
		crc = ((crc >> 1) + *(name++)) ^
			((crc & 0x00000001) ? 0x80000000 : 0);
	}
	return crc;
}

static struct page *qnx6_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);
	if (!IS_ERR(page))
		kmap(page);
	return page;
}

static inline unsigned long dir_pages(struct inode *inode)
{
	return (inode->i_size+PAGE_CACHE_SIZE-1)>>PAGE_CACHE_SHIFT;
}

static unsigned last_entry(struct inode *inode, unsigned long page_nr)
{
	unsigned long last_byte = inode->i_size;
	last_byte -= page_nr << PAGE_CACHE_SHIFT;
	if (last_byte > PAGE_CACHE_SIZE)
		last_byte = PAGE_CACHE_SIZE;
	return last_byte / QNX6_DIR_ENTRY_SIZE;
}

static struct qnx6_long_filename *qnx6_longname(struct super_block *sb,
					 struct qnx6_long_dir_entry *de,
					 struct page **p)
{
	struct qnx6_sb_info *sbi = QNX6_SB(sb);
	u32 s = fs32_to_cpu(sbi, de->de_long_inode); /* in block units */
	u32 n = s >> (PAGE_CACHE_SHIFT - sb->s_blocksize_bits); /* in pages */
	/* within page */
	u32 offs = (s << sb->s_blocksize_bits) & ~PAGE_CACHE_MASK;
	struct address_space *mapping = sbi->longfile->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);
	if (IS_ERR(page))
		return ERR_CAST(page);
	kmap(*p = page);
	return (struct qnx6_long_filename *)(page_address(page) + offs);
}

static int qnx6_dir_longfilename(struct inode *inode,
			struct qnx6_long_dir_entry *de,
			struct dir_context *ctx,
			unsigned de_inode)
{
	struct qnx6_long_filename *lf;
	struct super_block *s = inode->i_sb;
	struct qnx6_sb_info *sbi = QNX6_SB(s);
	struct page *page;
	int lf_size;

	if (de->de_size != 0xff) {
		/* error - long filename entries always have size 0xff
		   in direntry */
		pr_err("invalid direntry size (%i).\n", de->de_size);
		return 0;
	}
	lf = qnx6_longname(s, de, &page);
	if (IS_ERR(lf)) {
		pr_err("Error reading longname\n");
		return 0;
	}

	lf_size = fs16_to_cpu(sbi, lf->lf_size);

	if (lf_size > QNX6_LONG_NAME_MAX) {
		pr_debug("file %s\n", lf->lf_fname);
		pr_err("Filename too long (%i)\n", lf_size);
		qnx6_put_page(page);
		return 0;
	}

	/* calc & validate longfilename checksum
	   mmi 3g filesystem does not have that checksum */
	if (!test_opt(s, MMI_FS) && fs32_to_cpu(sbi, de->de_checksum) !=
			qnx6_lfile_checksum(lf->lf_fname, lf_size))
		pr_info("long filename checksum error.\n");

	pr_debug("qnx6_readdir:%.*s inode:%u\n",
		 lf_size, lf->lf_fname, de_inode);
	if (!dir_emit(ctx, lf->lf_fname, lf_size, de_inode, DT_UNKNOWN)) {
		qnx6_put_page(page);
		return 0;
	}

	qnx6_put_page(page);
	/* success */
	return 1;
}

static int qnx6_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *s = inode->i_sb;
	struct qnx6_sb_info *sbi = QNX6_SB(s);
	loff_t pos = ctx->pos & ~(QNX6_DIR_ENTRY_SIZE - 1);
	unsigned long npages = dir_pages(inode);
	unsigned long n = pos >> PAGE_CACHE_SHIFT;
	unsigned start = (pos & ~PAGE_CACHE_MASK) / QNX6_DIR_ENTRY_SIZE;
	bool done = false;

	ctx->pos = pos;
	if (ctx->pos >= inode->i_size)
		return 0;

	for ( ; !done && n < npages; n++, start = 0) {
		struct page *page = qnx6_get_page(inode, n);
		int limit = last_entry(inode, n);
		struct qnx6_dir_entry *de;
		int i = start;

		if (IS_ERR(page)) {
			pr_err("%s(): read failed\n", __func__);
			ctx->pos = (n + 1) << PAGE_CACHE_SHIFT;
			return PTR_ERR(page);
		}
		de = ((struct qnx6_dir_entry *)page_address(page)) + start;
		for (; i < limit; i++, de++, ctx->pos += QNX6_DIR_ENTRY_SIZE) {
			int size = de->de_size;
			u32 no_inode = fs32_to_cpu(sbi, de->de_inode);

			if (!no_inode || !size)
				continue;

			if (size > QNX6_SHORT_NAME_MAX) {
				/* long filename detected
				   get the filename from long filename
				   structure / block */
				if (!qnx6_dir_longfilename(inode,
					(struct qnx6_long_dir_entry *)de,
					ctx, no_inode)) {
					done = true;
					break;
				}
			} else {
				pr_debug("%s():%.*s inode:%u\n",
					 __func__, size, de->de_fname,
					 no_inode);
				if (!dir_emit(ctx, de->de_fname, size,
				      no_inode, DT_UNKNOWN)) {
					done = true;
					break;
				}
			}
		}
		qnx6_put_page(page);
	}
	return 0;
}

/*
 * check if the long filename is correct.
 */
static unsigned qnx6_long_match(int len, const char *name,
			struct qnx6_long_dir_entry *de, struct inode *dir)
{
	struct super_block *s = dir->i_sb;
	struct qnx6_sb_info *sbi = QNX6_SB(s);
	struct page *page;
	int thislen;
	struct qnx6_long_filename *lf = qnx6_longname(s, de, &page);

	if (IS_ERR(lf))
		return 0;

	thislen = fs16_to_cpu(sbi, lf->lf_size);
	if (len != thislen) {
		qnx6_put_page(page);
		return 0;
	}
	if (memcmp(name, lf->lf_fname, len) == 0) {
		qnx6_put_page(page);
		return fs32_to_cpu(sbi, de->de_inode);
	}
	qnx6_put_page(page);
	return 0;
}

/*
 * check if the filename is correct.
 */
static unsigned qnx6_match(struct super_block *s, int len, const char *name,
			struct qnx6_dir_entry *de)
{
	struct qnx6_sb_info *sbi = QNX6_SB(s);
	if (memcmp(name, de->de_fname, len) == 0)
		return fs32_to_cpu(sbi, de->de_inode);
	return 0;
}


unsigned qnx6_find_entry(int len, struct inode *dir, const char *name,
			 struct page **res_page)
{
	struct super_block *s = dir->i_sb;
	struct qnx6_inode_info *ei = QNX6_I(dir);
	struct page *page = NULL;
	unsigned long start, n;
	unsigned long npages = dir_pages(dir);
	unsigned ino;
	struct qnx6_dir_entry *de;
	struct qnx6_long_dir_entry *lde;

	*res_page = NULL;

	if (npages == 0)
		return 0;
	start = ei->i_dir_start_lookup;
	if (start >= npages)
		start = 0;
	n = start;

	do {
		page = qnx6_get_page(dir, n);
		if (!IS_ERR(page)) {
			int limit = last_entry(dir, n);
			int i;

			de = (struct qnx6_dir_entry *)page_address(page);
			for (i = 0; i < limit; i++, de++) {
				if (len <= QNX6_SHORT_NAME_MAX) {
					/* short filename */
					if (len != de->de_size)
						continue;
					ino = qnx6_match(s, len, name, de);
					if (ino)
						goto found;
				} else if (de->de_size == 0xff) {
					/* deal with long filename */
					lde = (struct qnx6_long_dir_entry *)de;
					ino = qnx6_long_match(len,
								name, lde, dir);
					if (ino)
						goto found;
				} else
					pr_err("undefined filename size in inode.\n");
			}
			qnx6_put_page(page);
		}

		if (++n >= npages)
			n = 0;
	} while (n != start);
	return 0;

found:
	*res_page = page;
	ei->i_dir_start_lookup = n;
	return ino;
}

const struct file_operations qnx6_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= qnx6_readdir,
	.fsync		= generic_file_fsync,
};

const struct inode_operations qnx6_dir_inode_operations = {
	.lookup		= qnx6_lookup,
};
/************************************************************/
/* ../linux-3.17/fs/qnx6/dir.c */
/************************************************************/
/*
 * QNX6 file system, Linux implementation.
 *
 * Version : 1.0.0
 *
 * History :
 *
 * 01-02-2012 by Kai Bankett (chaosman@ontika.net) : first release.
 * 16-02-2012 pagemap extension by Al Viro
 *
 */

// #include "qnx6.h"

struct dentry *qnx6_lookup(struct inode *dir, struct dentry *dentry,
				unsigned int flags)
{
	unsigned ino;
	struct page *page;
	struct inode *foundinode = NULL;
	const char *name = dentry->d_name.name;
	int len = dentry->d_name.len;

	if (len > QNX6_LONG_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	ino = qnx6_find_entry(len, dir, name, &page);
	if (ino) {
		foundinode = qnx6_iget(dir->i_sb, ino);
		qnx6_put_page(page);
		if (IS_ERR(foundinode)) {
			pr_debug("lookup->iget ->  error %ld\n",
				 PTR_ERR(foundinode));
			return ERR_CAST(foundinode);
		}
	} else {
		pr_debug("%s(): not found %s\n", __func__, name);
		return NULL;
	}
	d_add(dentry, foundinode);
	return NULL;
}
/************************************************************/
/* ../linux-3.17/fs/qnx6/namei.c */
/************************************************************/
/*
 * QNX6 file system, Linux implementation.
 *
 * Version : 1.0.0
 *
 * History :
 *
 * 01-02-2012 by Kai Bankett (chaosman@ontika.net) : first release.
 *
 */

// #include <linux/buffer_head.h>
// #include <linux/slab.h>
// #include <linux/crc32.h>
// #include "qnx6.h"

static void qnx6_mmi_copy_sb(struct qnx6_super_block *qsb,
		struct qnx6_mmi_super_block *sb)
{
	qsb->sb_magic = sb->sb_magic;
	qsb->sb_checksum = sb->sb_checksum;
	qsb->sb_serial = sb->sb_serial;
	qsb->sb_blocksize = sb->sb_blocksize;
	qsb->sb_num_inodes = sb->sb_num_inodes;
	qsb->sb_free_inodes = sb->sb_free_inodes;
	qsb->sb_num_blocks = sb->sb_num_blocks;
	qsb->sb_free_blocks = sb->sb_free_blocks;

	/* the rest of the superblock is the same */
	memcpy(&qsb->Inode, &sb->Inode, sizeof(sb->Inode));
	memcpy(&qsb->Bitmap, &sb->Bitmap, sizeof(sb->Bitmap));
	memcpy(&qsb->Longfile, &sb->Longfile, sizeof(sb->Longfile));
}

struct qnx6_super_block *qnx6_mmi_fill_super(struct super_block *s, int silent)
{
	struct buffer_head *bh1, *bh2 = NULL;
	struct qnx6_mmi_super_block *sb1, *sb2;
	struct qnx6_super_block *qsb = NULL;
	struct qnx6_sb_info *sbi;
	__u64 offset;

	/* Check the superblock signatures
	   start with the first superblock */
	bh1 = sb_bread(s, 0);
	if (!bh1) {
		pr_err("Unable to read first mmi superblock\n");
		return NULL;
	}
	sb1 = (struct qnx6_mmi_super_block *)bh1->b_data;
	sbi = QNX6_SB(s);
	if (fs32_to_cpu(sbi, sb1->sb_magic) != QNX6_SUPER_MAGIC) {
		if (!silent) {
			pr_err("wrong signature (magic) in superblock #1.\n");
			goto out;
		}
	}

	/* checksum check - start at byte 8 and end at byte 512 */
	if (fs32_to_cpu(sbi, sb1->sb_checksum) !=
				crc32_be(0, (char *)(bh1->b_data + 8), 504)) {
		pr_err("superblock #1 checksum error\n");
		goto out;
	}

	/* calculate second superblock blocknumber */
	offset = fs32_to_cpu(sbi, sb1->sb_num_blocks) + QNX6_SUPERBLOCK_AREA /
					fs32_to_cpu(sbi, sb1->sb_blocksize);

	/* set new blocksize */
	if (!sb_set_blocksize(s, fs32_to_cpu(sbi, sb1->sb_blocksize))) {
		pr_err("unable to set blocksize\n");
		goto out;
	}
	/* blocksize invalidates bh - pull it back in */
	brelse(bh1);
	bh1 = sb_bread(s, 0);
	if (!bh1)
		goto out;
	sb1 = (struct qnx6_mmi_super_block *)bh1->b_data;

	/* read second superblock */
	bh2 = sb_bread(s, offset);
	if (!bh2) {
		pr_err("unable to read the second superblock\n");
		goto out;
	}
	sb2 = (struct qnx6_mmi_super_block *)bh2->b_data;
	if (fs32_to_cpu(sbi, sb2->sb_magic) != QNX6_SUPER_MAGIC) {
		if (!silent)
			pr_err("wrong signature (magic) in superblock #2.\n");
		goto out;
	}

	/* checksum check - start at byte 8 and end at byte 512 */
	if (fs32_to_cpu(sbi, sb2->sb_checksum)
			!= crc32_be(0, (char *)(bh2->b_data + 8), 504)) {
		pr_err("superblock #1 checksum error\n");
		goto out;
	}

	qsb = kmalloc(sizeof(*qsb), GFP_KERNEL);
	if (!qsb) {
		pr_err("unable to allocate memory.\n");
		goto out;
	}

	if (fs64_to_cpu(sbi, sb1->sb_serial) >
					fs64_to_cpu(sbi, sb2->sb_serial)) {
		/* superblock #1 active */
		qnx6_mmi_copy_sb(qsb, sb1);
#ifdef CONFIG_QNX6FS_DEBUG
		qnx6_superblock_debug(qsb, s);
#endif
		memcpy(bh1->b_data, qsb, sizeof(struct qnx6_super_block));

		sbi->sb_buf = bh1;
		sbi->sb = (struct qnx6_super_block *)bh1->b_data;
		brelse(bh2);
		pr_info("superblock #1 active\n");
	} else {
		/* superblock #2 active */
		qnx6_mmi_copy_sb(qsb, sb2);
#ifdef CONFIG_QNX6FS_DEBUG
		qnx6_superblock_debug(qsb, s);
#endif
		memcpy(bh2->b_data, qsb, sizeof(struct qnx6_super_block));

		sbi->sb_buf = bh2;
		sbi->sb = (struct qnx6_super_block *)bh2->b_data;
		brelse(bh1);
		pr_info("superblock #2 active\n");
	}
	kfree(qsb);

	/* offset for mmi_fs is just SUPERBLOCK_AREA bytes */
	sbi->s_blks_off = QNX6_SUPERBLOCK_AREA / s->s_blocksize;

	/* success */
	return sbi->sb;

out:
	if (bh1 != NULL)
		brelse(bh1);
	if (bh2 != NULL)
		brelse(bh2);
	return NULL;
}
/************************************************************/
/* ../linux-3.17/fs/qnx6/super_mmi.c */
/************************************************************/
