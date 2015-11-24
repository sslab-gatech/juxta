/*
 *	fs/bfs/inode.c
 *	BFS superblock and inode operations.
 *	Copyright (C) 1999-2006 Tigran Aivazian <tigran@aivazian.fsnet.co.uk>
 *	From fs/minix, Copyright (C) 1991, 1992 Linus Torvalds.
 *
 *      Made endianness-clean by Andrew Stribblehill <ads@wompom.org>, 2005.
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/vfs.h>
#include <linux/writeback.h>
#include <asm/uaccess.h>
#include "bfs.h"

MODULE_AUTHOR("Tigran Aivazian <tigran@aivazian.fsnet.co.uk>");
MODULE_DESCRIPTION("SCO UnixWare BFS filesystem for Linux");
MODULE_LICENSE("GPL");

#undef DEBUG

#ifdef DEBUG
#define dprintf(x...)	printf(x)
#else
#define dprintf(x...)
#endif

struct inode *bfs_iget(struct super_block *sb, unsigned long ino)
{
	struct bfs_inode *di;
	struct inode *inode;
	struct buffer_head *bh;
	int block, off;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	if ((ino < BFS_ROOT_INO) || (ino > BFS_SB(inode->i_sb)->si_lasti)) {
		printf("Bad inode number %s:%08lx\n", inode->i_sb->s_id, ino);
		goto error;
	}

	block = (ino - BFS_ROOT_INO) / BFS_INODES_PER_BLOCK + 1;
	bh = sb_bread(inode->i_sb, block);
	if (!bh) {
		printf("Unable to read inode %s:%08lx\n", inode->i_sb->s_id,
									ino);
		goto error;
	}

	off = (ino - BFS_ROOT_INO) % BFS_INODES_PER_BLOCK;
	di = (struct bfs_inode *)bh->b_data + off;

	inode->i_mode = 0x0000FFFF & le32_to_cpu(di->i_mode);
	if (le32_to_cpu(di->i_vtype) == BFS_VDIR) {
		inode->i_mode |= S_IFDIR;
		inode->i_op = &bfs_dir_inops;
		inode->i_fop = &bfs_dir_operations;
	} else if (le32_to_cpu(di->i_vtype) == BFS_VREG) {
		inode->i_mode |= S_IFREG;
		inode->i_op = &bfs_file_inops;
		inode->i_fop = &bfs_file_operations;
		inode->i_mapping->a_ops = &bfs_aops;
	}

	BFS_I(inode)->i_sblock =  le32_to_cpu(di->i_sblock);
	BFS_I(inode)->i_eblock =  le32_to_cpu(di->i_eblock);
	BFS_I(inode)->i_dsk_ino = le16_to_cpu(di->i_ino);
	i_uid_write(inode, le32_to_cpu(di->i_uid));
	i_gid_write(inode,  le32_to_cpu(di->i_gid));
	set_nlink(inode, le32_to_cpu(di->i_nlink));
	inode->i_size = BFS_FILESIZE(di);
	inode->i_blocks = BFS_FILEBLOCKS(di);
	inode->i_atime.tv_sec =  le32_to_cpu(di->i_atime);
	inode->i_mtime.tv_sec =  le32_to_cpu(di->i_mtime);
	inode->i_ctime.tv_sec =  le32_to_cpu(di->i_ctime);
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;

	brelse(bh);
	unlock_new_inode(inode);
	return inode;

error:
	iget_failed(inode);
	return ERR_PTR(-EIO);
}

static struct bfs_inode *find_inode(struct super_block *sb, u16 ino, struct buffer_head **p)
{
	if ((ino < BFS_ROOT_INO) || (ino > BFS_SB(sb)->si_lasti)) {
		printf("Bad inode number %s:%08x\n", sb->s_id, ino);
		return ERR_PTR(-EIO);
	}

	ino -= BFS_ROOT_INO;

	*p = sb_bread(sb, 1 + ino / BFS_INODES_PER_BLOCK);
	if (!*p) {
		printf("Unable to read inode %s:%08x\n", sb->s_id, ino);
		return ERR_PTR(-EIO);
	}

	return (struct bfs_inode *)(*p)->b_data +  ino % BFS_INODES_PER_BLOCK;
}

static int bfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct bfs_sb_info *info = BFS_SB(inode->i_sb);
	unsigned int ino = (u16)inode->i_ino;
        unsigned long i_sblock;
	struct bfs_inode *di;
	struct buffer_head *bh;
	int err = 0;

        dprintf("ino=%08x\n", ino);

	di = find_inode(inode->i_sb, ino, &bh);
	if (IS_ERR(di))
		return PTR_ERR(di);

	mutex_lock(&info->bfs_lock);

	if (ino == BFS_ROOT_INO)
		di->i_vtype = cpu_to_le32(BFS_VDIR);
	else
		di->i_vtype = cpu_to_le32(BFS_VREG);

	di->i_ino = cpu_to_le16(ino);
	di->i_mode = cpu_to_le32(inode->i_mode);
	di->i_uid = cpu_to_le32(i_uid_read(inode));
	di->i_gid = cpu_to_le32(i_gid_read(inode));
	di->i_nlink = cpu_to_le32(inode->i_nlink);
	di->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	di->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	di->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
        i_sblock = BFS_I(inode)->i_sblock;
	di->i_sblock = cpu_to_le32(i_sblock);
	di->i_eblock = cpu_to_le32(BFS_I(inode)->i_eblock);
	di->i_eoffset = cpu_to_le32(i_sblock * BFS_BSIZE + inode->i_size - 1);

	mark_buffer_dirty(bh);
	if (wbc->sync_mode == WB_SYNC_ALL) {
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh))
			err = -EIO;
	}
	brelse(bh);
	mutex_unlock(&info->bfs_lock);
	return err;
}

static void bfs_evict_inode(struct inode *inode)
{
	unsigned long ino = inode->i_ino;
	struct bfs_inode *di;
	struct buffer_head *bh;
	struct super_block *s = inode->i_sb;
	struct bfs_sb_info *info = BFS_SB(s);
	struct bfs_inode_info *bi = BFS_I(inode);

	dprintf("ino=%08lx\n", ino);

	truncate_inode_pages_final(&inode->i_data);
	invalidate_inode_buffers(inode);
	clear_inode(inode);

	if (inode->i_nlink)
		return;

	di = find_inode(s, inode->i_ino, &bh);
	if (IS_ERR(di))
		return;

	mutex_lock(&info->bfs_lock);
	/* clear on-disk inode */
	memset(di, 0, sizeof(struct bfs_inode));
	mark_buffer_dirty(bh);
	brelse(bh);

        if (bi->i_dsk_ino) {
		if (bi->i_sblock)
			info->si_freeb += bi->i_eblock + 1 - bi->i_sblock;
		info->si_freei++;
		clear_bit(ino, info->si_imap);
		bfs_dump_imap("delete_inode", s);
        }

	/*
	 * If this was the last file, make the previous block
	 * "last block of the last file" even if there is no
	 * real file there, saves us 1 gap.
	 */
	if (info->si_lf_eblk == bi->i_eblock)
		info->si_lf_eblk = bi->i_sblock - 1;
	mutex_unlock(&info->bfs_lock);
}

static void bfs_put_super(struct super_block *s)
{
	struct bfs_sb_info *info = BFS_SB(s);

	if (!info)
		return;

	mutex_destroy(&info->bfs_lock);
	kfree(info->si_imap);
	kfree(info);
	s->s_fs_info = NULL;
}

static int bfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *s = dentry->d_sb;
	struct bfs_sb_info *info = BFS_SB(s);
	u64 id = huge_encode_dev(s->s_bdev->bd_dev);
	buf->f_type = BFS_MAGIC;
	buf->f_bsize = s->s_blocksize;
	buf->f_blocks = info->si_blocks;
	buf->f_bfree = buf->f_bavail = info->si_freeb;
	buf->f_files = info->si_lasti + 1 - BFS_ROOT_INO;
	buf->f_ffree = info->si_freei;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen = BFS_NAMELEN;
	return 0;
}

static struct kmem_cache *bfs_inode_cachep;

static struct inode *bfs_alloc_inode(struct super_block *sb)
{
	struct bfs_inode_info *bi;
	bi = kmem_cache_alloc(bfs_inode_cachep, GFP_KERNEL);
	if (!bi)
		return NULL;
	return &bi->vfs_inode;
}

static void bfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(bfs_inode_cachep, BFS_I(inode));
}

static void bfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, bfs_i_callback);
}

static void init_once(void *foo)
{
	struct bfs_inode_info *bi = foo;

	inode_init_once(&bi->vfs_inode);
}

static int __init init_inodecache(void)
{
	bfs_inode_cachep = kmem_cache_create("bfs_inode_cache",
					     sizeof(struct bfs_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (bfs_inode_cachep == NULL)
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
	kmem_cache_destroy(bfs_inode_cachep);
}

static const struct super_operations bfs_sops = {
	.alloc_inode	= bfs_alloc_inode,
	.destroy_inode	= bfs_destroy_inode,
	.write_inode	= bfs_write_inode,
	.evict_inode	= bfs_evict_inode,
	.put_super	= bfs_put_super,
	.statfs		= bfs_statfs,
};

void bfs_dump_imap(const char *prefix, struct super_block *s)
{
#ifdef DEBUG
	int i;
	char *tmpbuf = (char *)get_zeroed_page(GFP_KERNEL);

	if (!tmpbuf)
		return;
	for (i = BFS_SB(s)->si_lasti; i >= 0; i--) {
		if (i > PAGE_SIZE - 100) break;
		if (test_bit(i, BFS_SB(s)->si_imap))
			strcat(tmpbuf, "1");
		else
			strcat(tmpbuf, "0");
	}
	printf("BFS-fs: %s: lasti=%08lx <%s>\n",
				prefix, BFS_SB(s)->si_lasti, tmpbuf);
	free_page((unsigned long)tmpbuf);
#endif
}

static int bfs_fill_super(struct super_block *s, void *data, int silent)
{
	struct buffer_head *bh, *sbh;
	struct bfs_super_block *bfs_sb;
	struct inode *inode;
	unsigned i, imap_len;
	struct bfs_sb_info *info;
	int ret = -EINVAL;
	unsigned long i_sblock, i_eblock, i_eoff, s_size;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	mutex_init(&info->bfs_lock);
	s->s_fs_info = info;

	sb_set_blocksize(s, BFS_BSIZE);

	sbh = sb_bread(s, 0);
	if (!sbh)
		goto out;
	bfs_sb = (struct bfs_super_block *)sbh->b_data;
	if (le32_to_cpu(bfs_sb->s_magic) != BFS_MAGIC) {
		if (!silent)
			printf("No BFS filesystem on %s (magic=%08x)\n",
				s->s_id,  le32_to_cpu(bfs_sb->s_magic));
		goto out1;
	}
	if (BFS_UNCLEAN(bfs_sb, s) && !silent)
		printf("%s is unclean, continuing\n", s->s_id);

	s->s_magic = BFS_MAGIC;

	if (le32_to_cpu(bfs_sb->s_start) > le32_to_cpu(bfs_sb->s_end)) {
		printf("Superblock is corrupted\n");
		goto out1;
	}

	info->si_lasti = (le32_to_cpu(bfs_sb->s_start) - BFS_BSIZE) /
					sizeof(struct bfs_inode)
					+ BFS_ROOT_INO - 1;
	imap_len = (info->si_lasti / 8) + 1;
	info->si_imap = kzalloc(imap_len, GFP_KERNEL);
	if (!info->si_imap)
		goto out1;
	for (i = 0; i < BFS_ROOT_INO; i++)
		set_bit(i, info->si_imap);

	s->s_op = &bfs_sops;
	inode = bfs_iget(s, BFS_ROOT_INO);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out2;
	}
	s->s_root = d_make_root(inode);
	if (!s->s_root) {
		ret = -ENOMEM;
		goto out2;
	}

	info->si_blocks = (le32_to_cpu(bfs_sb->s_end) + 1) >> BFS_BSIZE_BITS;
	info->si_freeb = (le32_to_cpu(bfs_sb->s_end) + 1
			- le32_to_cpu(bfs_sb->s_start)) >> BFS_BSIZE_BITS;
	info->si_freei = 0;
	info->si_lf_eblk = 0;

	/* can we read the last block? */
	bh = sb_bread(s, info->si_blocks - 1);
	if (!bh) {
		printf("Last block not available: %lu\n", info->si_blocks - 1);
		ret = -EIO;
		goto out3;
	}
	brelse(bh);

	bh = NULL;
	for (i = BFS_ROOT_INO; i <= info->si_lasti; i++) {
		struct bfs_inode *di;
		int block = (i - BFS_ROOT_INO) / BFS_INODES_PER_BLOCK + 1;
		int off = (i - BFS_ROOT_INO) % BFS_INODES_PER_BLOCK;
		unsigned long eblock;

		if (!off) {
			brelse(bh);
			bh = sb_bread(s, block);
		}

		if (!bh)
			continue;

		di = (struct bfs_inode *)bh->b_data + off;

		/* test if filesystem is not corrupted */

		i_eoff = le32_to_cpu(di->i_eoffset);
		i_sblock = le32_to_cpu(di->i_sblock);
		i_eblock = le32_to_cpu(di->i_eblock);
		s_size = le32_to_cpu(bfs_sb->s_end);

		if (i_sblock > info->si_blocks ||
			i_eblock > info->si_blocks ||
			i_sblock > i_eblock ||
			i_eoff > s_size ||
			i_sblock * BFS_BSIZE > i_eoff) {

			printf("Inode 0x%08x corrupted\n", i);

			brelse(bh);
			ret = -EIO;
			goto out3;
		}

		if (!di->i_ino) {
			info->si_freei++;
			continue;
		}
		set_bit(i, info->si_imap);
		info->si_freeb -= BFS_FILEBLOCKS(di);

		eblock =  le32_to_cpu(di->i_eblock);
		if (eblock > info->si_lf_eblk)
			info->si_lf_eblk = eblock;
	}
	brelse(bh);
	brelse(sbh);
	bfs_dump_imap("read_super", s);
	return 0;

out3:
	dput(s->s_root);
	s->s_root = NULL;
out2:
	kfree(info->si_imap);
out1:
	brelse(sbh);
out:
	mutex_destroy(&info->bfs_lock);
	kfree(info);
	s->s_fs_info = NULL;
	return ret;
}

static struct dentry *bfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, bfs_fill_super);
}

static struct file_system_type bfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bfs",
	.mount		= bfs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("bfs");

static int __init init_bfs_fs(void)
{
	int err = init_inodecache();
	if (err)
		goto out1;
        err = register_filesystem(&bfs_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_bfs_fs(void)
{
	unregister_filesystem(&bfs_fs_type);
	destroy_inodecache();
}

module_init(init_bfs_fs)
module_exit(exit_bfs_fs)
/************************************************************/
/* ../linux-3.17/fs/bfs/inode.c */
/************************************************************/
/*
 *	fs/bfs/file.c
 *	BFS file operations.
 *	Copyright (C) 1999,2000 Tigran Aivazian <tigran@veritas.com>
 *
 *	Make the file block allocation algorithm understand the size
 *	of the underlying block device.
 *	Copyright (C) 2007 Dmitri Vorobiev <dmitri.vorobiev@gmail.com>
 *
 */

// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include "bfs.h"

#undef DEBUG

#ifdef DEBUG
#define dprintf(x...)	printf(x)
#else
#define dprintf(x...)
#endif

const struct file_operations bfs_file_operations = {
	.llseek 	= generic_file_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.splice_read	= generic_file_splice_read,
};

static int bfs_move_block(unsigned long from, unsigned long to,
					struct super_block *sb)
{
	struct buffer_head *bh, *new;

	bh = sb_bread(sb, from);
	if (!bh)
		return -EIO;
	new = sb_getblk(sb, to);
	memcpy(new->b_data, bh->b_data, bh->b_size);
	mark_buffer_dirty(new);
	bforget(bh);
	brelse(new);
	return 0;
}

static int bfs_move_blocks(struct super_block *sb, unsigned long start,
				unsigned long end, unsigned long where)
{
	unsigned long i;

	dprintf("%08lx-%08lx->%08lx\n", start, end, where);
	for (i = start; i <= end; i++)
		if(bfs_move_block(i, where + i, sb)) {
			dprintf("failed to move block %08lx -> %08lx\n", i,
								where + i);
			return -EIO;
		}
	return 0;
}

static int bfs_get_block(struct inode *inode, sector_t block,
			struct buffer_head *bh_result, int create)
{
	unsigned long phys;
	int err;
	struct super_block *sb = inode->i_sb;
	struct bfs_sb_info *info = BFS_SB(sb);
	struct bfs_inode_info *bi = BFS_I(inode);

	phys = bi->i_sblock + block;
	if (!create) {
		if (phys <= bi->i_eblock) {
			dprintf("c=%d, b=%08lx, phys=%09lx (granted)\n",
                                create, (unsigned long)block, phys);
			map_bh(bh_result, sb, phys);
		}
		return 0;
	}

	/*
	 * If the file is not empty and the requested block is within the
	 * range of blocks allocated for this file, we can grant it.
	 */
	if (bi->i_sblock && (phys <= bi->i_eblock)) {
		dprintf("c=%d, b=%08lx, phys=%08lx (interim block granted)\n",
				create, (unsigned long)block, phys);
		map_bh(bh_result, sb, phys);
		return 0;
	}

	/* The file will be extended, so let's see if there is enough space. */
	if (phys >= info->si_blocks)
		return -ENOSPC;

	/* The rest has to be protected against itself. */
	mutex_lock(&info->bfs_lock);

	/*
	 * If the last data block for this file is the last allocated
	 * block, we can extend the file trivially, without moving it
	 * anywhere.
	 */
	if (bi->i_eblock == info->si_lf_eblk) {
		dprintf("c=%d, b=%08lx, phys=%08lx (simple extension)\n",
				create, (unsigned long)block, phys);
		map_bh(bh_result, sb, phys);
		info->si_freeb -= phys - bi->i_eblock;
		info->si_lf_eblk = bi->i_eblock = phys;
		mark_inode_dirty(inode);
		err = 0;
		goto out;
	}

	/* Ok, we have to move this entire file to the next free block. */
	phys = info->si_lf_eblk + 1;
	if (phys + block >= info->si_blocks) {
		err = -ENOSPC;
		goto out;
	}

	if (bi->i_sblock) {
		err = bfs_move_blocks(inode->i_sb, bi->i_sblock,
						bi->i_eblock, phys);
		if (err) {
			dprintf("failed to move ino=%08lx -> fs corruption\n",
								inode->i_ino);
			goto out;
		}
	} else
		err = 0;

	dprintf("c=%d, b=%08lx, phys=%08lx (moved)\n",
                create, (unsigned long)block, phys);
	bi->i_sblock = phys;
	phys += block;
	info->si_lf_eblk = bi->i_eblock = phys;

	/*
	 * This assumes nothing can write the inode back while we are here
	 * and thus update inode->i_blocks! (XXX)
	 */
	info->si_freeb -= bi->i_eblock - bi->i_sblock + 1 - inode->i_blocks;
	mark_inode_dirty(inode);
	map_bh(bh_result, sb, phys);
out:
	mutex_unlock(&info->bfs_lock);
	return err;
}

static int bfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, bfs_get_block, wbc);
}

static int bfs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, bfs_get_block);
}

static void bfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size)
		truncate_pagecache(inode, inode->i_size);
}

static int bfs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep,
				bfs_get_block);
	if (unlikely(ret))
		bfs_write_failed(mapping, pos + len);

	return ret;
}

static sector_t bfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, bfs_get_block);
}

const struct address_space_operations bfs_aops = {
	.readpage	= bfs_readpage,
	.writepage	= bfs_writepage,
	.write_begin	= bfs_write_begin,
	.write_end	= generic_write_end,
	.bmap		= bfs_bmap,
};

const struct inode_operations bfs_file_inops;
/************************************************************/
/* ../linux-3.17/fs/bfs/file.c */
/************************************************************/
/*
 *	fs/bfs/dir.c
 *	BFS directory operations.
 *	Copyright (C) 1999,2000  Tigran Aivazian <tigran@veritas.com>
 *      Made endianness-clean by Andrew Stribblehill <ads@wompom.org> 2005
 */

#include <linux/time.h>
#include <linux/string.h>
// #include <linux/fs.h>
// #include <linux/buffer_head.h>
#include <linux/sched.h>
// #include "bfs.h"

#undef DEBUG

#ifdef DEBUG
#define dprintf(x...)	printf(x)
#else
#define dprintf(x...)
#endif

static int bfs_add_entry(struct inode *dir, const unsigned char *name,
						int namelen, int ino);
static struct buffer_head *bfs_find_entry(struct inode *dir,
				const unsigned char *name, int namelen,
				struct bfs_dirent **res_dir);

static int bfs_readdir(struct file *f, struct dir_context *ctx)
{
	struct inode *dir = file_inode(f);
	struct buffer_head *bh;
	struct bfs_dirent *de;
	unsigned int offset;
	int block;

	if (ctx->pos & (BFS_DIRENT_SIZE - 1)) {
		printf("Bad f_pos=%08lx for %s:%08lx\n",
					(unsigned long)ctx->pos,
					dir->i_sb->s_id, dir->i_ino);
		return -EINVAL;
	}

	while (ctx->pos < dir->i_size) {
		offset = ctx->pos & (BFS_BSIZE - 1);
		block = BFS_I(dir)->i_sblock + (ctx->pos >> BFS_BSIZE_BITS);
		bh = sb_bread(dir->i_sb, block);
		if (!bh) {
			ctx->pos += BFS_BSIZE - offset;
			continue;
		}
		do {
			de = (struct bfs_dirent *)(bh->b_data + offset);
			if (de->ino) {
				int size = strnlen(de->name, BFS_NAMELEN);
				if (!dir_emit(ctx, de->name, size,
						le16_to_cpu(de->ino),
						DT_UNKNOWN)) {
					brelse(bh);
					return 0;
				}
			}
			offset += BFS_DIRENT_SIZE;
			ctx->pos += BFS_DIRENT_SIZE;
		} while ((offset < BFS_BSIZE) && (ctx->pos < dir->i_size));
		brelse(bh);
	}
	return 0;
}

const struct file_operations bfs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= bfs_readdir,
	.fsync		= generic_file_fsync,
	.llseek		= generic_file_llseek,
};

static int bfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
						bool excl)
{
	int err;
	struct inode *inode;
	struct super_block *s = dir->i_sb;
	struct bfs_sb_info *info = BFS_SB(s);
	unsigned long ino;

	inode = new_inode(s);
	if (!inode)
		return -ENOSPC;
	mutex_lock(&info->bfs_lock);
	ino = find_first_zero_bit(info->si_imap, info->si_lasti + 1);
	if (ino > info->si_lasti) {
		mutex_unlock(&info->bfs_lock);
		iput(inode);
		return -ENOSPC;
	}
	set_bit(ino, info->si_imap);
	info->si_freei--;
	inode_init_owner(inode, dir, mode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME_SEC;
	inode->i_blocks = 0;
	inode->i_op = &bfs_file_inops;
	inode->i_fop = &bfs_file_operations;
	inode->i_mapping->a_ops = &bfs_aops;
	inode->i_ino = ino;
	BFS_I(inode)->i_dsk_ino = ino;
	BFS_I(inode)->i_sblock = 0;
	BFS_I(inode)->i_eblock = 0;
	insert_inode_hash(inode);
        mark_inode_dirty(inode);
	bfs_dump_imap("create", s);

	err = bfs_add_entry(dir, dentry->d_name.name, dentry->d_name.len,
							inode->i_ino);
	if (err) {
		inode_dec_link_count(inode);
		mutex_unlock(&info->bfs_lock);
		iput(inode);
		return err;
	}
	mutex_unlock(&info->bfs_lock);
	d_instantiate(dentry, inode);
	return 0;
}

static struct dentry *bfs_lookup(struct inode *dir, struct dentry *dentry,
						unsigned int flags)
{
	struct inode *inode = NULL;
	struct buffer_head *bh;
	struct bfs_dirent *de;
	struct bfs_sb_info *info = BFS_SB(dir->i_sb);

	if (dentry->d_name.len > BFS_NAMELEN)
		return ERR_PTR(-ENAMETOOLONG);

	mutex_lock(&info->bfs_lock);
	bh = bfs_find_entry(dir, dentry->d_name.name, dentry->d_name.len, &de);
	if (bh) {
		unsigned long ino = (unsigned long)le16_to_cpu(de->ino);
		brelse(bh);
		inode = bfs_iget(dir->i_sb, ino);
		if (IS_ERR(inode)) {
			mutex_unlock(&info->bfs_lock);
			return ERR_CAST(inode);
		}
	}
	mutex_unlock(&info->bfs_lock);
	d_add(dentry, inode);
	return NULL;
}

static int bfs_link(struct dentry *old, struct inode *dir,
						struct dentry *new)
{
	struct inode *inode = old->d_inode;
	struct bfs_sb_info *info = BFS_SB(inode->i_sb);
	int err;

	mutex_lock(&info->bfs_lock);
	err = bfs_add_entry(dir, new->d_name.name, new->d_name.len,
							inode->i_ino);
	if (err) {
		mutex_unlock(&info->bfs_lock);
		return err;
	}
	inc_nlink(inode);
	inode->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(inode);
	ihold(inode);
	d_instantiate(new, inode);
	mutex_unlock(&info->bfs_lock);
	return 0;
}

static int bfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int error = -ENOENT;
	struct inode *inode = dentry->d_inode;
	struct buffer_head *bh;
	struct bfs_dirent *de;
	struct bfs_sb_info *info = BFS_SB(inode->i_sb);

	mutex_lock(&info->bfs_lock);
	bh = bfs_find_entry(dir, dentry->d_name.name, dentry->d_name.len, &de);
	if (!bh || (le16_to_cpu(de->ino) != inode->i_ino))
		goto out_brelse;

	if (!inode->i_nlink) {
		printf("unlinking non-existent file %s:%lu (nlink=%d)\n",
					inode->i_sb->s_id, inode->i_ino,
					inode->i_nlink);
		set_nlink(inode, 1);
	}
	de->ino = 0;
	mark_buffer_dirty_inode(bh, dir);
	dir->i_ctime = dir->i_mtime = CURRENT_TIME_SEC;
	mark_inode_dirty(dir);
	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);
	error = 0;

out_brelse:
	brelse(bh);
	mutex_unlock(&info->bfs_lock);
	return error;
}

static int bfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *old_inode, *new_inode;
	struct buffer_head *old_bh, *new_bh;
	struct bfs_dirent *old_de, *new_de;
	struct bfs_sb_info *info;
	int error = -ENOENT;

	old_bh = new_bh = NULL;
	old_inode = old_dentry->d_inode;
	if (S_ISDIR(old_inode->i_mode))
		return -EINVAL;

	info = BFS_SB(old_inode->i_sb);

	mutex_lock(&info->bfs_lock);
	old_bh = bfs_find_entry(old_dir,
				old_dentry->d_name.name,
				old_dentry->d_name.len, &old_de);

	if (!old_bh || (le16_to_cpu(old_de->ino) != old_inode->i_ino))
		goto end_rename;

	error = -EPERM;
	new_inode = new_dentry->d_inode;
	new_bh = bfs_find_entry(new_dir,
				new_dentry->d_name.name,
				new_dentry->d_name.len, &new_de);

	if (new_bh && !new_inode) {
		brelse(new_bh);
		new_bh = NULL;
	}
	if (!new_bh) {
		error = bfs_add_entry(new_dir,
					new_dentry->d_name.name,
					new_dentry->d_name.len,
					old_inode->i_ino);
		if (error)
			goto end_rename;
	}
	old_de->ino = 0;
	old_dir->i_ctime = old_dir->i_mtime = CURRENT_TIME_SEC;
	mark_inode_dirty(old_dir);
	if (new_inode) {
		new_inode->i_ctime = CURRENT_TIME_SEC;
		inode_dec_link_count(new_inode);
	}
	mark_buffer_dirty_inode(old_bh, old_dir);
	error = 0;

end_rename:
	mutex_unlock(&info->bfs_lock);
	brelse(old_bh);
	brelse(new_bh);
	return error;
}

const struct inode_operations bfs_dir_inops = {
	.create			= bfs_create,
	.lookup			= bfs_lookup,
	.link			= bfs_link,
	.unlink			= bfs_unlink,
	.rename			= bfs_rename,
};

static int bfs_add_entry(struct inode *dir, const unsigned char *name,
							int namelen, int ino)
{
	struct buffer_head *bh;
	struct bfs_dirent *de;
	int block, sblock, eblock, off, pos;
	int i;

	dprintf("name=%s, namelen=%d\n", name, namelen);

	if (!namelen)
		return -ENOENT;
	if (namelen > BFS_NAMELEN)
		return -ENAMETOOLONG;

	sblock = BFS_I(dir)->i_sblock;
	eblock = BFS_I(dir)->i_eblock;
	for (block = sblock; block <= eblock; block++) {
		bh = sb_bread(dir->i_sb, block);
		if (!bh)
			return -ENOSPC;
		for (off = 0; off < BFS_BSIZE; off += BFS_DIRENT_SIZE) {
			de = (struct bfs_dirent *)(bh->b_data + off);
			if (!de->ino) {
				pos = (block - sblock) * BFS_BSIZE + off;
				if (pos >= dir->i_size) {
					dir->i_size += BFS_DIRENT_SIZE;
					dir->i_ctime = CURRENT_TIME_SEC;
				}
				dir->i_mtime = CURRENT_TIME_SEC;
				mark_inode_dirty(dir);
				de->ino = cpu_to_le16((u16)ino);
				for (i = 0; i < BFS_NAMELEN; i++)
					de->name[i] =
						(i < namelen) ? name[i] : 0;
				mark_buffer_dirty_inode(bh, dir);
				brelse(bh);
				return 0;
			}
		}
		brelse(bh);
	}
	return -ENOSPC;
}

static inline int bfs_namecmp(int len, const unsigned char *name,
							const char *buffer)
{
	if ((len < BFS_NAMELEN) && buffer[len])
		return 0;
	return !memcmp(name, buffer, len);
}

static struct buffer_head *bfs_find_entry(struct inode *dir,
			const unsigned char *name, int namelen,
			struct bfs_dirent **res_dir)
{
	unsigned long block = 0, offset = 0;
	struct buffer_head *bh = NULL;
	struct bfs_dirent *de;

	*res_dir = NULL;
	if (namelen > BFS_NAMELEN)
		return NULL;

	while (block * BFS_BSIZE + offset < dir->i_size) {
		if (!bh) {
			bh = sb_bread(dir->i_sb, BFS_I(dir)->i_sblock + block);
			if (!bh) {
				block++;
				continue;
			}
		}
		de = (struct bfs_dirent *)(bh->b_data + offset);
		offset += BFS_DIRENT_SIZE;
		if (le16_to_cpu(de->ino) &&
				bfs_namecmp(namelen, name, de->name)) {
			*res_dir = de;
			return bh;
		}
		if (offset < bh->b_size)
			continue;
		brelse(bh);
		bh = NULL;
		offset = 0;
		block++;
	}
	brelse(bh);
	return NULL;
}
/************************************************************/
/* ../linux-3.17/fs/bfs/dir.c */
/************************************************************/
