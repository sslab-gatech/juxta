/*
 * inode.c - NILFS inode operations.
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 *
 */

#include <linux/buffer_head.h>
#include <linux/gfp.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/aio.h>
#include "nilfs.h"
#include "btnode.h"
#include "segment.h"
#include "page.h"
#include "mdt.h"
#include "cpfile.h"
#include "ifile.h"

/**
 * struct nilfs_iget_args - arguments used during comparison between inodes
 * @ino: inode number
 * @cno: checkpoint number
 * @root: pointer on NILFS root object (mounted checkpoint)
 * @for_gc: inode for GC flag
 */
struct nilfs_iget_args {
	u64 ino;
	__u64 cno;
	struct nilfs_root *root;
	int for_gc;
};

void nilfs_inode_add_blocks(struct inode *inode, int n)
{
	struct nilfs_root *root = NILFS_I(inode)->i_root;

	inode_add_bytes(inode, (1 << inode->i_blkbits) * n);
	if (root)
		atomic64_add(n, &root->blocks_count);
}

void nilfs_inode_sub_blocks(struct inode *inode, int n)
{
	struct nilfs_root *root = NILFS_I(inode)->i_root;

	inode_sub_bytes(inode, (1 << inode->i_blkbits) * n);
	if (root)
		atomic64_sub(n, &root->blocks_count);
}

/**
 * nilfs_get_block() - get a file block on the filesystem (callback function)
 * @inode - inode struct of the target file
 * @blkoff - file block number
 * @bh_result - buffer head to be mapped on
 * @create - indicate whether allocating the block or not when it has not
 *      been allocated yet.
 *
 * This function does not issue actual read request of the specified data
 * block. It is done by VFS.
 */
int nilfs_get_block(struct inode *inode, sector_t blkoff,
		    struct buffer_head *bh_result, int create)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	__u64 blknum = 0;
	int err = 0, ret;
	unsigned maxblocks = bh_result->b_size >> inode->i_blkbits;

	down_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);
	ret = nilfs_bmap_lookup_contig(ii->i_bmap, blkoff, &blknum, maxblocks);
	up_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);
	if (ret >= 0) {	/* found */
		map_bh(bh_result, inode->i_sb, blknum);
		if (ret > 0)
			bh_result->b_size = (ret << inode->i_blkbits);
		goto out;
	}
	/* data block was not found */
	if (ret == -ENOENT && create) {
		struct nilfs_transaction_info ti;

		bh_result->b_blocknr = 0;
		err = nilfs_transaction_begin(inode->i_sb, &ti, 1);
		if (unlikely(err))
			goto out;
		err = nilfs_bmap_insert(ii->i_bmap, (unsigned long)blkoff,
					(unsigned long)bh_result);
		if (unlikely(err != 0)) {
			if (err == -EEXIST) {
				/*
				 * The get_block() function could be called
				 * from multiple callers for an inode.
				 * However, the page having this block must
				 * be locked in this case.
				 */
				printk(KERN_WARNING
				       "nilfs_get_block: a race condition "
				       "while inserting a data block. "
				       "(inode number=%lu, file block "
				       "offset=%llu)\n",
				       inode->i_ino,
				       (unsigned long long)blkoff);
				err = 0;
			}
			nilfs_transaction_abort(inode->i_sb);
			goto out;
		}
		nilfs_mark_inode_dirty(inode);
		nilfs_transaction_commit(inode->i_sb); /* never fails */
		/* Error handling should be detailed */
		set_buffer_new(bh_result);
		set_buffer_delay(bh_result);
		map_bh(bh_result, inode->i_sb, 0); /* dbn must be changed
						      to proper value */
	} else if (ret == -ENOENT) {
		/* not found is not error (e.g. hole); must return without
		   the mapped state flag. */
		;
	} else {
		err = ret;
	}

 out:
	return err;
}

/**
 * nilfs_readpage() - implement readpage() method of nilfs_aops {}
 * address_space_operations.
 * @file - file struct of the file to be read
 * @page - the page to be read
 */
static int nilfs_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, nilfs_get_block);
}

/**
 * nilfs_readpages() - implement readpages() method of nilfs_aops {}
 * address_space_operations.
 * @file - file struct of the file to be read
 * @mapping - address_space struct used for reading multiple pages
 * @pages - the pages to be read
 * @nr_pages - number of pages to be read
 */
static int nilfs_readpages(struct file *file, struct address_space *mapping,
			   struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, nilfs_get_block);
}

static int nilfs_writepages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	int err = 0;

	if (inode->i_sb->s_flags & MS_RDONLY) {
		nilfs_clear_dirty_pages(mapping, false);
		return -EROFS;
	}

	if (wbc->sync_mode == WB_SYNC_ALL)
		err = nilfs_construct_dsync_segment(inode->i_sb, inode,
						    wbc->range_start,
						    wbc->range_end);
	return err;
}

static int nilfs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	int err;

	if (inode->i_sb->s_flags & MS_RDONLY) {
		/*
		 * It means that filesystem was remounted in read-only
		 * mode because of error or metadata corruption. But we
		 * have dirty pages that try to be flushed in background.
		 * So, here we simply discard this dirty page.
		 */
		nilfs_clear_dirty_page(page, false);
		unlock_page(page);
		return -EROFS;
	}

	redirty_page_for_writepage(wbc, page);
	unlock_page(page);

	if (wbc->sync_mode == WB_SYNC_ALL) {
		err = nilfs_construct_segment(inode->i_sb);
		if (unlikely(err))
			return err;
	} else if (wbc->for_reclaim)
		nilfs_flush_segment(inode->i_sb, inode->i_ino);

	return 0;
}

static int nilfs_set_page_dirty(struct page *page)
{
	int ret = __set_page_dirty_nobuffers(page);

	if (page_has_buffers(page)) {
		struct inode *inode = page->mapping->host;
		unsigned nr_dirty = 0;
		struct buffer_head *bh, *head;

		/*
		 * This page is locked by callers, and no other thread
		 * concurrently marks its buffers dirty since they are
		 * only dirtied through routines in fs/buffer.c in
		 * which call sites of mark_buffer_dirty are protected
		 * by page lock.
		 */
		bh = head = page_buffers(page);
		do {
			/* Do not mark hole blocks dirty */
			if (buffer_dirty(bh) || !buffer_mapped(bh))
				continue;

			set_buffer_dirty(bh);
			nr_dirty++;
		} while (bh = bh->b_this_page, bh != head);

		if (nr_dirty)
			nilfs_set_file_dirty(inode, nr_dirty);
	}
	return ret;
}

void nilfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		nilfs_truncate(inode);
	}
}

static int nilfs_write_begin(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned flags,
			     struct page **pagep, void **fsdata)

{
	struct inode *inode = mapping->host;
	int err = nilfs_transaction_begin(inode->i_sb, NULL, 1);

	if (unlikely(err))
		return err;

	err = block_write_begin(mapping, pos, len, flags, pagep,
				nilfs_get_block);
	if (unlikely(err)) {
		nilfs_write_failed(mapping, pos + len);
		nilfs_transaction_abort(inode->i_sb);
	}
	return err;
}

static int nilfs_write_end(struct file *file, struct address_space *mapping,
			   loff_t pos, unsigned len, unsigned copied,
			   struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	unsigned start = pos & (PAGE_CACHE_SIZE - 1);
	unsigned nr_dirty;
	int err;

	nr_dirty = nilfs_page_count_clean_buffers(page, start,
						  start + copied);
	copied = generic_write_end(file, mapping, pos, len, copied, page,
				   fsdata);
	nilfs_set_file_dirty(inode, nr_dirty);
	err = nilfs_transaction_commit(inode->i_sb);
	return err ? : copied;
}

static ssize_t
nilfs_direct_IO(int rw, struct kiocb *iocb, struct iov_iter *iter,
		loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file->f_mapping->host;
	size_t count = iov_iter_count(iter);
	ssize_t size;

	if (rw == WRITE)
		return 0;

	/* Needs synchronization with the cleaner */
	size = blockdev_direct_IO(rw, iocb, inode, iter, offset,
				  nilfs_get_block);

	/*
	 * In case of error extending write may have instantiated a few
	 * blocks outside i_size. Trim these off again.
	 */
	if (unlikely((rw & WRITE) && size < 0)) {
		loff_t isize = i_size_read(inode);
		loff_t end = offset + count;

		if (end > isize)
			nilfs_write_failed(mapping, end);
	}

	return size;
}

const struct address_space_operations nilfs_aops = {
	.writepage		= nilfs_writepage,
	.readpage		= nilfs_readpage,
	.writepages		= nilfs_writepages,
	.set_page_dirty		= nilfs_set_page_dirty,
	.readpages		= nilfs_readpages,
	.write_begin		= nilfs_write_begin,
	.write_end		= nilfs_write_end,
	/* .releasepage		= nilfs_releasepage, */
	.invalidatepage		= block_invalidatepage,
	.direct_IO		= nilfs_direct_IO,
	.is_partially_uptodate  = block_is_partially_uptodate,
};

struct inode *nilfs_new_inode(struct inode *dir, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct inode *inode;
	struct nilfs_inode_info *ii;
	struct nilfs_root *root;
	int err = -ENOMEM;
	ino_t ino;

	inode = new_inode(sb);
	if (unlikely(!inode))
		goto failed;

	mapping_set_gfp_mask(inode->i_mapping,
			     mapping_gfp_mask(inode->i_mapping) & ~__GFP_FS);

	root = NILFS_I(dir)->i_root;
	ii = NILFS_I(inode);
	ii->i_state = 1 << NILFS_I_NEW;
	ii->i_root = root;

	err = nilfs_ifile_create_inode(root->ifile, &ino, &ii->i_bh);
	if (unlikely(err))
		goto failed_ifile_create_inode;
	/* reference count of i_bh inherits from nilfs_mdt_read_block() */

	atomic64_inc(&root->inodes_count);
	inode_init_owner(inode, dir, mode);
	inode->i_ino = ino;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	if (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)) {
		err = nilfs_bmap_read(ii->i_bmap, NULL);
		if (err < 0)
			goto failed_bmap;

		set_bit(NILFS_I_BMAP, &ii->i_state);
		/* No lock is needed; iget() ensures it. */
	}

	ii->i_flags = nilfs_mask_flags(
		mode, NILFS_I(dir)->i_flags & NILFS_FL_INHERITED);

	/* ii->i_file_acl = 0; */
	/* ii->i_dir_acl = 0; */
	ii->i_dir_start_lookup = 0;
	nilfs_set_inode_flags(inode);
	spin_lock(&nilfs->ns_next_gen_lock);
	inode->i_generation = nilfs->ns_next_generation++;
	spin_unlock(&nilfs->ns_next_gen_lock);
	insert_inode_hash(inode);

	err = nilfs_init_acl(inode, dir);
	if (unlikely(err))
		goto failed_acl; /* never occur. When supporting
				    nilfs_init_acl(), proper cancellation of
				    above jobs should be considered */

	return inode;

 failed_acl:
 failed_bmap:
	clear_nlink(inode);
	iput(inode);  /* raw_inode will be deleted through
			 generic_delete_inode() */
	goto failed;

 failed_ifile_create_inode:
	make_bad_inode(inode);
	iput(inode);  /* if i_nlink == 1, generic_forget_inode() will be
			 called */
 failed:
	return ERR_PTR(err);
}

void nilfs_set_inode_flags(struct inode *inode)
{
	unsigned int flags = NILFS_I(inode)->i_flags;

	inode->i_flags &= ~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME |
			    S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	mapping_set_gfp_mask(inode->i_mapping,
			     mapping_gfp_mask(inode->i_mapping) & ~__GFP_FS);
}

int nilfs_read_inode_common(struct inode *inode,
			    struct nilfs_inode *raw_inode)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int err;

	inode->i_mode = le16_to_cpu(raw_inode->i_mode);
	i_uid_write(inode, le32_to_cpu(raw_inode->i_uid));
	i_gid_write(inode, le32_to_cpu(raw_inode->i_gid));
	set_nlink(inode, le16_to_cpu(raw_inode->i_links_count));
	inode->i_size = le64_to_cpu(raw_inode->i_size);
	inode->i_atime.tv_sec = le64_to_cpu(raw_inode->i_mtime);
	inode->i_ctime.tv_sec = le64_to_cpu(raw_inode->i_ctime);
	inode->i_mtime.tv_sec = le64_to_cpu(raw_inode->i_mtime);
	inode->i_atime.tv_nsec = le32_to_cpu(raw_inode->i_mtime_nsec);
	inode->i_ctime.tv_nsec = le32_to_cpu(raw_inode->i_ctime_nsec);
	inode->i_mtime.tv_nsec = le32_to_cpu(raw_inode->i_mtime_nsec);
	if (inode->i_nlink == 0 && inode->i_mode == 0)
		return -EINVAL; /* this inode is deleted */

	inode->i_blocks = le64_to_cpu(raw_inode->i_blocks);
	ii->i_flags = le32_to_cpu(raw_inode->i_flags);
#if 0
	ii->i_file_acl = le32_to_cpu(raw_inode->i_file_acl);
	ii->i_dir_acl = S_ISREG(inode->i_mode) ?
		0 : le32_to_cpu(raw_inode->i_dir_acl);
#endif
	ii->i_dir_start_lookup = 0;
	inode->i_generation = le32_to_cpu(raw_inode->i_generation);

	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	    S_ISLNK(inode->i_mode)) {
		err = nilfs_bmap_read(ii->i_bmap, raw_inode);
		if (err < 0)
			return err;
		set_bit(NILFS_I_BMAP, &ii->i_state);
		/* No lock is needed; iget() ensures it. */
	}
	return 0;
}

static int __nilfs_read_inode(struct super_block *sb,
			      struct nilfs_root *root, unsigned long ino,
			      struct inode *inode)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct buffer_head *bh;
	struct nilfs_inode *raw_inode;
	int err;

	down_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);
	err = nilfs_ifile_get_inode_block(root->ifile, ino, &bh);
	if (unlikely(err))
		goto bad_inode;

	raw_inode = nilfs_ifile_map_inode(root->ifile, ino, bh);

	err = nilfs_read_inode_common(inode, raw_inode);
	if (err)
		goto failed_unmap;

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &nilfs_file_inode_operations;
		inode->i_fop = &nilfs_file_operations;
		inode->i_mapping->a_ops = &nilfs_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &nilfs_dir_inode_operations;
		inode->i_fop = &nilfs_dir_operations;
		inode->i_mapping->a_ops = &nilfs_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &nilfs_symlink_inode_operations;
		inode->i_mapping->a_ops = &nilfs_aops;
	} else {
		inode->i_op = &nilfs_special_inode_operations;
		init_special_inode(
			inode, inode->i_mode,
			huge_decode_dev(le64_to_cpu(raw_inode->i_device_code)));
	}
	nilfs_ifile_unmap_inode(root->ifile, ino, bh);
	brelse(bh);
	up_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);
	nilfs_set_inode_flags(inode);
	return 0;

 failed_unmap:
	nilfs_ifile_unmap_inode(root->ifile, ino, bh);
	brelse(bh);

 bad_inode:
	up_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);
	return err;
}

static int nilfs_iget_test(struct inode *inode, void *opaque)
{
	struct nilfs_iget_args *args = opaque;
	struct nilfs_inode_info *ii;

	if (args->ino != inode->i_ino || args->root != NILFS_I(inode)->i_root)
		return 0;

	ii = NILFS_I(inode);
	if (!test_bit(NILFS_I_GCINODE, &ii->i_state))
		return !args->for_gc;

	return args->for_gc && args->cno == ii->i_cno;
}

static int nilfs_iget_set(struct inode *inode, void *opaque)
{
	struct nilfs_iget_args *args = opaque;

	inode->i_ino = args->ino;
	if (args->for_gc) {
		NILFS_I(inode)->i_state = 1 << NILFS_I_GCINODE;
		NILFS_I(inode)->i_cno = args->cno;
		NILFS_I(inode)->i_root = NULL;
	} else {
		if (args->root && args->ino == NILFS_ROOT_INO)
			nilfs_get_root(args->root);
		NILFS_I(inode)->i_root = args->root;
	}
	return 0;
}

struct inode *nilfs_ilookup(struct super_block *sb, struct nilfs_root *root,
			    unsigned long ino)
{
	struct nilfs_iget_args args = {
		.ino = ino, .root = root, .cno = 0, .for_gc = 0
	};

	return ilookup5(sb, ino, nilfs_iget_test, &args);
}

struct inode *nilfs_iget_locked(struct super_block *sb, struct nilfs_root *root,
				unsigned long ino)
{
	struct nilfs_iget_args args = {
		.ino = ino, .root = root, .cno = 0, .for_gc = 0
	};

	return iget5_locked(sb, ino, nilfs_iget_test, nilfs_iget_set, &args);
}

struct inode *nilfs_iget(struct super_block *sb, struct nilfs_root *root,
			 unsigned long ino)
{
	struct inode *inode;
	int err;

	inode = nilfs_iget_locked(sb, root, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	err = __nilfs_read_inode(sb, root, ino, inode);
	if (unlikely(err)) {
		iget_failed(inode);
		return ERR_PTR(err);
	}
	unlock_new_inode(inode);
	return inode;
}

struct inode *nilfs_iget_for_gc(struct super_block *sb, unsigned long ino,
				__u64 cno)
{
	struct nilfs_iget_args args = {
		.ino = ino, .root = NULL, .cno = cno, .for_gc = 1
	};
	struct inode *inode;
	int err;

	inode = iget5_locked(sb, ino, nilfs_iget_test, nilfs_iget_set, &args);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	err = nilfs_init_gcinode(inode);
	if (unlikely(err)) {
		iget_failed(inode);
		return ERR_PTR(err);
	}
	unlock_new_inode(inode);
	return inode;
}

void nilfs_write_inode_common(struct inode *inode,
			      struct nilfs_inode *raw_inode, int has_bmap)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);

	raw_inode->i_mode = cpu_to_le16(inode->i_mode);
	raw_inode->i_uid = cpu_to_le32(i_uid_read(inode));
	raw_inode->i_gid = cpu_to_le32(i_gid_read(inode));
	raw_inode->i_links_count = cpu_to_le16(inode->i_nlink);
	raw_inode->i_size = cpu_to_le64(inode->i_size);
	raw_inode->i_ctime = cpu_to_le64(inode->i_ctime.tv_sec);
	raw_inode->i_mtime = cpu_to_le64(inode->i_mtime.tv_sec);
	raw_inode->i_ctime_nsec = cpu_to_le32(inode->i_ctime.tv_nsec);
	raw_inode->i_mtime_nsec = cpu_to_le32(inode->i_mtime.tv_nsec);
	raw_inode->i_blocks = cpu_to_le64(inode->i_blocks);

	raw_inode->i_flags = cpu_to_le32(ii->i_flags);
	raw_inode->i_generation = cpu_to_le32(inode->i_generation);

	if (NILFS_ROOT_METADATA_FILE(inode->i_ino)) {
		struct the_nilfs *nilfs = inode->i_sb->s_fs_info;

		/* zero-fill unused portion in the case of super root block */
		raw_inode->i_xattr = 0;
		raw_inode->i_pad = 0;
		memset((void *)raw_inode + sizeof(*raw_inode), 0,
		       nilfs->ns_inode_size - sizeof(*raw_inode));
	}

	if (has_bmap)
		nilfs_bmap_write(ii->i_bmap, raw_inode);
	else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		raw_inode->i_device_code =
			cpu_to_le64(huge_encode_dev(inode->i_rdev));
	/* When extending inode, nilfs->ns_inode_size should be checked
	   for substitutions of appended fields */
}

void nilfs_update_inode(struct inode *inode, struct buffer_head *ibh)
{
	ino_t ino = inode->i_ino;
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct inode *ifile = ii->i_root->ifile;
	struct nilfs_inode *raw_inode;

	raw_inode = nilfs_ifile_map_inode(ifile, ino, ibh);

	if (test_and_clear_bit(NILFS_I_NEW, &ii->i_state))
		memset(raw_inode, 0, NILFS_MDT(ifile)->mi_entry_size);
	set_bit(NILFS_I_INODE_DIRTY, &ii->i_state);

	nilfs_write_inode_common(inode, raw_inode, 0);
		/* XXX: call with has_bmap = 0 is a workaround to avoid
		   deadlock of bmap. This delays update of i_bmap to just
		   before writing */
	nilfs_ifile_unmap_inode(ifile, ino, ibh);
}

#define NILFS_MAX_TRUNCATE_BLOCKS	16384  /* 64MB for 4KB block */

static void nilfs_truncate_bmap(struct nilfs_inode_info *ii,
				unsigned long from)
{
	unsigned long b;
	int ret;

	if (!test_bit(NILFS_I_BMAP, &ii->i_state))
		return;
repeat:
	ret = nilfs_bmap_last_key(ii->i_bmap, &b);
	if (ret == -ENOENT)
		return;
	else if (ret < 0)
		goto failed;

	if (b < from)
		return;

	b -= min_t(unsigned long, NILFS_MAX_TRUNCATE_BLOCKS, b - from);
	ret = nilfs_bmap_truncate(ii->i_bmap, b);
	nilfs_relax_pressure_in_lock(ii->vfs_inode.i_sb);
	if (!ret || (ret == -ENOMEM &&
		     nilfs_bmap_truncate(ii->i_bmap, b) == 0))
		goto repeat;

failed:
	nilfs_warning(ii->vfs_inode.i_sb, __func__,
		      "failed to truncate bmap (ino=%lu, err=%d)",
		      ii->vfs_inode.i_ino, ret);
}

void nilfs_truncate(struct inode *inode)
{
	unsigned long blkoff;
	unsigned int blocksize;
	struct nilfs_transaction_info ti;
	struct super_block *sb = inode->i_sb;
	struct nilfs_inode_info *ii = NILFS_I(inode);

	if (!test_bit(NILFS_I_BMAP, &ii->i_state))
		return;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return;

	blocksize = sb->s_blocksize;
	blkoff = (inode->i_size + blocksize - 1) >> sb->s_blocksize_bits;
	nilfs_transaction_begin(sb, &ti, 0); /* never fails */

	block_truncate_page(inode->i_mapping, inode->i_size, nilfs_get_block);

	nilfs_truncate_bmap(ii, blkoff);

	inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	if (IS_SYNC(inode))
		nilfs_set_transaction_flag(NILFS_TI_SYNC);

	nilfs_mark_inode_dirty(inode);
	nilfs_set_file_dirty(inode, 0);
	nilfs_transaction_commit(sb);
	/* May construct a logical segment and may fail in sync mode.
	   But truncate has no return value. */
}

static void nilfs_clear_inode(struct inode *inode)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct nilfs_mdt_info *mdi = NILFS_MDT(inode);

	/*
	 * Free resources allocated in nilfs_read_inode(), here.
	 */
	BUG_ON(!list_empty(&ii->i_dirty));
	brelse(ii->i_bh);
	ii->i_bh = NULL;

	if (mdi && mdi->mi_palloc_cache)
		nilfs_palloc_destroy_cache(inode);

	if (test_bit(NILFS_I_BMAP, &ii->i_state))
		nilfs_bmap_clear(ii->i_bmap);

	nilfs_btnode_cache_clear(&ii->i_btnode_cache);

	if (ii->i_root && inode->i_ino == NILFS_ROOT_INO)
		nilfs_put_root(ii->i_root);
}

void nilfs_evict_inode(struct inode *inode)
{
	struct nilfs_transaction_info ti;
	struct super_block *sb = inode->i_sb;
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int ret;

	if (inode->i_nlink || !ii->i_root || unlikely(is_bad_inode(inode))) {
		truncate_inode_pages_final(&inode->i_data);
		clear_inode(inode);
		nilfs_clear_inode(inode);
		return;
	}
	nilfs_transaction_begin(sb, &ti, 0); /* never fails */

	truncate_inode_pages_final(&inode->i_data);

	/* TODO: some of the following operations may fail.  */
	nilfs_truncate_bmap(ii, 0);
	nilfs_mark_inode_dirty(inode);
	clear_inode(inode);

	ret = nilfs_ifile_delete_inode(ii->i_root->ifile, inode->i_ino);
	if (!ret)
		atomic64_dec(&ii->i_root->inodes_count);

	nilfs_clear_inode(inode);

	if (IS_SYNC(inode))
		nilfs_set_transaction_flag(NILFS_TI_SYNC);
	nilfs_transaction_commit(sb);
	/* May construct a logical segment and may fail in sync mode.
	   But delete_inode has no return value. */
}

int nilfs_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct nilfs_transaction_info ti;
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	int err;

	err = inode_change_ok(inode, iattr);
	if (err)
		return err;

	err = nilfs_transaction_begin(sb, &ti, 0);
	if (unlikely(err))
		return err;

	if ((iattr->ia_valid & ATTR_SIZE) &&
	    iattr->ia_size != i_size_read(inode)) {
		inode_dio_wait(inode);
		truncate_setsize(inode, iattr->ia_size);
		nilfs_truncate(inode);
	}

	setattr_copy(inode, iattr);
	mark_inode_dirty(inode);

	if (iattr->ia_valid & ATTR_MODE) {
		err = nilfs_acl_chmod(inode);
		if (unlikely(err))
			goto out_err;
	}

	return nilfs_transaction_commit(sb);

out_err:
	nilfs_transaction_abort(sb);
	return err;
}

int nilfs_permission(struct inode *inode, int mask)
{
	struct nilfs_root *root = NILFS_I(inode)->i_root;
	if ((mask & MAY_WRITE) && root &&
	    root->cno != NILFS_CPTREE_CURRENT_CNO)
		return -EROFS; /* snapshot is not writable */

	return generic_permission(inode, mask);
}

int nilfs_load_inode_block(struct inode *inode, struct buffer_head **pbh)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int err;

	spin_lock(&nilfs->ns_inode_lock);
	if (ii->i_bh == NULL) {
		spin_unlock(&nilfs->ns_inode_lock);
		err = nilfs_ifile_get_inode_block(ii->i_root->ifile,
						  inode->i_ino, pbh);
		if (unlikely(err))
			return err;
		spin_lock(&nilfs->ns_inode_lock);
		if (ii->i_bh == NULL)
			ii->i_bh = *pbh;
		else {
			brelse(*pbh);
			*pbh = ii->i_bh;
		}
	} else
		*pbh = ii->i_bh;

	get_bh(*pbh);
	spin_unlock(&nilfs->ns_inode_lock);
	return 0;
}

int nilfs_inode_dirty(struct inode *inode)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	int ret = 0;

	if (!list_empty(&ii->i_dirty)) {
		spin_lock(&nilfs->ns_inode_lock);
		ret = test_bit(NILFS_I_DIRTY, &ii->i_state) ||
			test_bit(NILFS_I_BUSY, &ii->i_state);
		spin_unlock(&nilfs->ns_inode_lock);
	}
	return ret;
}

int nilfs_set_file_dirty(struct inode *inode, unsigned nr_dirty)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;

	atomic_add(nr_dirty, &nilfs->ns_ndirtyblks);

	if (test_and_set_bit(NILFS_I_DIRTY, &ii->i_state))
		return 0;

	spin_lock(&nilfs->ns_inode_lock);
	if (!test_bit(NILFS_I_QUEUED, &ii->i_state) &&
	    !test_bit(NILFS_I_BUSY, &ii->i_state)) {
		/* Because this routine may race with nilfs_dispose_list(),
		   we have to check NILFS_I_QUEUED here, too. */
		if (list_empty(&ii->i_dirty) && igrab(inode) == NULL) {
			/* This will happen when somebody is freeing
			   this inode. */
			nilfs_warning(inode->i_sb, __func__,
				      "cannot get inode (ino=%lu)\n",
				      inode->i_ino);
			spin_unlock(&nilfs->ns_inode_lock);
			return -EINVAL; /* NILFS_I_DIRTY may remain for
					   freeing inode */
		}
		list_move_tail(&ii->i_dirty, &nilfs->ns_dirty_files);
		set_bit(NILFS_I_QUEUED, &ii->i_state);
	}
	spin_unlock(&nilfs->ns_inode_lock);
	return 0;
}

int nilfs_mark_inode_dirty(struct inode *inode)
{
	struct buffer_head *ibh;
	int err;

	err = nilfs_load_inode_block(inode, &ibh);
	if (unlikely(err)) {
		nilfs_warning(inode->i_sb, __func__,
			      "failed to reget inode block.\n");
		return err;
	}
	nilfs_update_inode(inode, ibh);
	mark_buffer_dirty(ibh);
	nilfs_mdt_mark_dirty(NILFS_I(inode)->i_root->ifile);
	brelse(ibh);
	return 0;
}

/**
 * nilfs_dirty_inode - reflect changes on given inode to an inode block.
 * @inode: inode of the file to be registered.
 *
 * nilfs_dirty_inode() loads a inode block containing the specified
 * @inode and copies data from a nilfs_inode to a corresponding inode
 * entry in the inode block. This operation is excluded from the segment
 * construction. This function can be called both as a single operation
 * and as a part of indivisible file operations.
 */
void nilfs_dirty_inode(struct inode *inode, int flags)
{
	struct nilfs_transaction_info ti;
	struct nilfs_mdt_info *mdi = NILFS_MDT(inode);

	if (is_bad_inode(inode)) {
		nilfs_warning(inode->i_sb, __func__,
			      "tried to mark bad_inode dirty. ignored.\n");
		dump_stack();
		return;
	}
	if (mdi) {
		nilfs_mdt_mark_dirty(inode);
		return;
	}
	nilfs_transaction_begin(inode->i_sb, &ti, 0);
	nilfs_mark_inode_dirty(inode);
	nilfs_transaction_commit(inode->i_sb); /* never fails */
}

int nilfs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		 __u64 start, __u64 len)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	__u64 logical = 0, phys = 0, size = 0;
	__u32 flags = 0;
	loff_t isize;
	sector_t blkoff, end_blkoff;
	sector_t delalloc_blkoff;
	unsigned long delalloc_blklen;
	unsigned int blkbits = inode->i_blkbits;
	int ret, n;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	mutex_lock(&inode->i_mutex);

	isize = i_size_read(inode);

	blkoff = start >> blkbits;
	end_blkoff = (start + len - 1) >> blkbits;

	delalloc_blklen = nilfs_find_uncommitted_extent(inode, blkoff,
							&delalloc_blkoff);

	do {
		__u64 blkphy;
		unsigned int maxblocks;

		if (delalloc_blklen && blkoff == delalloc_blkoff) {
			if (size) {
				/* End of the current extent */
				ret = fiemap_fill_next_extent(
					fieinfo, logical, phys, size, flags);
				if (ret)
					break;
			}
			if (blkoff > end_blkoff)
				break;

			flags = FIEMAP_EXTENT_MERGED | FIEMAP_EXTENT_DELALLOC;
			logical = blkoff << blkbits;
			phys = 0;
			size = delalloc_blklen << blkbits;

			blkoff = delalloc_blkoff + delalloc_blklen;
			delalloc_blklen = nilfs_find_uncommitted_extent(
				inode, blkoff, &delalloc_blkoff);
			continue;
		}

		/*
		 * Limit the number of blocks that we look up so as
		 * not to get into the next delayed allocation extent.
		 */
		maxblocks = INT_MAX;
		if (delalloc_blklen)
			maxblocks = min_t(sector_t, delalloc_blkoff - blkoff,
					  maxblocks);
		blkphy = 0;

		down_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);
		n = nilfs_bmap_lookup_contig(
			NILFS_I(inode)->i_bmap, blkoff, &blkphy, maxblocks);
		up_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);

		if (n < 0) {
			int past_eof;

			if (unlikely(n != -ENOENT))
				break; /* error */

			/* HOLE */
			blkoff++;
			past_eof = ((blkoff << blkbits) >= isize);

			if (size) {
				/* End of the current extent */

				if (past_eof)
					flags |= FIEMAP_EXTENT_LAST;

				ret = fiemap_fill_next_extent(
					fieinfo, logical, phys, size, flags);
				if (ret)
					break;
				size = 0;
			}
			if (blkoff > end_blkoff || past_eof)
				break;
		} else {
			if (size) {
				if (phys && blkphy << blkbits == phys + size) {
					/* The current extent goes on */
					size += n << blkbits;
				} else {
					/* Terminate the current extent */
					ret = fiemap_fill_next_extent(
						fieinfo, logical, phys, size,
						flags);
					if (ret || blkoff > end_blkoff)
						break;

					/* Start another extent */
					flags = FIEMAP_EXTENT_MERGED;
					logical = blkoff << blkbits;
					phys = blkphy << blkbits;
					size = n << blkbits;
				}
			} else {
				/* Start a new extent */
				flags = FIEMAP_EXTENT_MERGED;
				logical = blkoff << blkbits;
				phys = blkphy << blkbits;
				size = n << blkbits;
			}
			blkoff += n;
		}
		cond_resched();
	} while (true);

	/* If ret is 1 then we just hit the end of the extent array */
	if (ret == 1)
		ret = 0;

	mutex_unlock(&inode->i_mutex);
	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/inode.c */
/************************************************************/
/*
 * file.c - NILFS regular file handling primitives including fsync().
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Amagai Yoshiji <amagai@osrg.net>,
 *            Ryusuke Konishi <ryusuke@osrg.net>
 */

#include <linux/fs.h>
#include <linux/mm.h>
// #include <linux/writeback.h>
// #include "nilfs.h"
// #include "segment.h"

int nilfs_sync_file(struct file *file, loff_t start, loff_t end, int datasync)
{
	/*
	 * Called from fsync() system call
	 * This is the only entry point that can catch write and synch
	 * timing for both data blocks and intermediate blocks.
	 *
	 * This function should be implemented when the writeback function
	 * will be implemented.
	 */
	struct the_nilfs *nilfs;
	struct inode *inode = file->f_mapping->host;
	int err;

	err = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (err)
		return err;
	mutex_lock(&inode->i_mutex);

	if (nilfs_inode_dirty(inode)) {
		if (datasync)
			err = nilfs_construct_dsync_segment(inode->i_sb, inode,
							    0, LLONG_MAX);
		else
			err = nilfs_construct_segment(inode->i_sb);
	}
	mutex_unlock(&inode->i_mutex);

	nilfs = inode->i_sb->s_fs_info;
	if (!err && nilfs_test_opt(nilfs, BARRIER)) {
		err = blkdev_issue_flush(inode->i_sb->s_bdev, GFP_KERNEL, NULL);
		if (err != -EIO)
			err = 0;
	}
	return err;
}

static int nilfs_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	struct nilfs_transaction_info ti;
	int ret = 0;

	if (unlikely(nilfs_near_disk_full(inode->i_sb->s_fs_info)))
		return VM_FAULT_SIGBUS; /* -ENOSPC */

	sb_start_pagefault(inode->i_sb);
	lock_page(page);
	if (page->mapping != inode->i_mapping ||
	    page_offset(page) >= i_size_read(inode) || !PageUptodate(page)) {
		unlock_page(page);
		ret = -EFAULT;	/* make the VM retry the fault */
		goto out;
	}

	/*
	 * check to see if the page is mapped already (no holes)
	 */
	if (PageMappedToDisk(page))
		goto mapped;

	if (page_has_buffers(page)) {
		struct buffer_head *bh, *head;
		int fully_mapped = 1;

		bh = head = page_buffers(page);
		do {
			if (!buffer_mapped(bh)) {
				fully_mapped = 0;
				break;
			}
		} while (bh = bh->b_this_page, bh != head);

		if (fully_mapped) {
			SetPageMappedToDisk(page);
			goto mapped;
		}
	}
	unlock_page(page);

	/*
	 * fill hole blocks
	 */
	ret = nilfs_transaction_begin(inode->i_sb, &ti, 1);
	/* never returns -ENOMEM, but may return -ENOSPC */
	if (unlikely(ret))
		goto out;

	file_update_time(vma->vm_file);
	ret = __block_page_mkwrite(vma, vmf, nilfs_get_block);
	if (ret) {
		nilfs_transaction_abort(inode->i_sb);
		goto out;
	}
	nilfs_set_file_dirty(inode, 1 << (PAGE_SHIFT - inode->i_blkbits));
	nilfs_transaction_commit(inode->i_sb);

 mapped:
	wait_for_stable_page(page);
 out:
	sb_end_pagefault(inode->i_sb);
	return block_page_mkwrite_return(ret);
}

static const struct vm_operations_struct nilfs_file_vm_ops = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= nilfs_page_mkwrite,
	.remap_pages	= generic_file_remap_pages,
};

static int nilfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_ops = &nilfs_file_vm_ops;
	return 0;
}

/*
 * We have mostly NULL's here: the current defaults are ok for
 * the nilfs filesystem.
 */
const struct file_operations nilfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.write		= new_sync_write,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.unlocked_ioctl	= nilfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= nilfs_compat_ioctl,
#endif	/* CONFIG_COMPAT */
	.mmap		= nilfs_file_mmap,
	.open		= generic_file_open,
	/* .release	= nilfs_release_file, */
	.fsync		= nilfs_sync_file,
	.splice_read	= generic_file_splice_read,
};

const struct inode_operations nilfs_file_inode_operations = {
	.setattr	= nilfs_setattr,
	.permission     = nilfs_permission,
	.fiemap		= nilfs_fiemap,
};

/* end of file */
/************************************************************/
/* ../linux-3.17/fs/nilfs2/file.c */
/************************************************************/
/*
 * dir.c - NILFS directory entry operations
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Modified for NILFS by Amagai Yoshiji <amagai@osrg.net>
 */
/*
 *  linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * All code that works with directory layout had been switched to pagecache
 * and moved here. AV
 */

#include <linux/pagemap.h>
// #include "nilfs.h"
// #include "page.h"

/*
 * nilfs uses block-sized chunks. Arguably, sector-sized ones would be
 * more robust, but we have what we have
 */
static inline unsigned nilfs_chunk_size(struct inode *inode)
{
	return inode->i_sb->s_blocksize;
}

static inline void nilfs_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

static inline unsigned long dir_pages(struct inode *inode)
{
	return (inode->i_size+PAGE_CACHE_SIZE-1)>>PAGE_CACHE_SHIFT;
}

/*
 * Return the offset into page `page_nr' of the last valid
 * byte in that page, plus one.
 */
static unsigned nilfs_last_byte(struct inode *inode, unsigned long page_nr)
{
	unsigned last_byte = inode->i_size;

	last_byte -= page_nr << PAGE_CACHE_SHIFT;
	if (last_byte > PAGE_CACHE_SIZE)
		last_byte = PAGE_CACHE_SIZE;
	return last_byte;
}

static int nilfs_prepare_chunk(struct page *page, unsigned from, unsigned to)
{
	loff_t pos = page_offset(page) + from;
	return __block_write_begin(page, pos, to - from, nilfs_get_block);
}

static void nilfs_commit_chunk(struct page *page,
			       struct address_space *mapping,
			       unsigned from, unsigned to)
{
	struct inode *dir = mapping->host;
	loff_t pos = page_offset(page) + from;
	unsigned len = to - from;
	unsigned nr_dirty, copied;
	int err;

	nr_dirty = nilfs_page_count_clean_buffers(page, from, to);
	copied = block_write_end(NULL, mapping, pos, len, len, page, NULL);
	if (pos + copied > dir->i_size)
		i_size_write(dir, pos + copied);
	if (IS_DIRSYNC(dir))
		nilfs_set_transaction_flag(NILFS_TI_SYNC);
	err = nilfs_set_file_dirty(dir, nr_dirty);
	WARN_ON(err); /* do not happen */
	unlock_page(page);
}

static void nilfs_check_page(struct page *page)
{
	struct inode *dir = page->mapping->host;
	struct super_block *sb = dir->i_sb;
	unsigned chunk_size = nilfs_chunk_size(dir);
	char *kaddr = page_address(page);
	unsigned offs, rec_len;
	unsigned limit = PAGE_CACHE_SIZE;
	struct nilfs_dir_entry *p;
	char *error;

	if ((dir->i_size >> PAGE_CACHE_SHIFT) == page->index) {
		limit = dir->i_size & ~PAGE_CACHE_MASK;
		if (limit & (chunk_size - 1))
			goto Ebadsize;
		if (!limit)
			goto out;
	}
	for (offs = 0; offs <= limit - NILFS_DIR_REC_LEN(1); offs += rec_len) {
		p = (struct nilfs_dir_entry *)(kaddr + offs);
		rec_len = nilfs_rec_len_from_disk(p->rec_len);

		if (rec_len < NILFS_DIR_REC_LEN(1))
			goto Eshort;
		if (rec_len & 3)
			goto Ealign;
		if (rec_len < NILFS_DIR_REC_LEN(p->name_len))
			goto Enamelen;
		if (((offs + rec_len - 1) ^ offs) & ~(chunk_size-1))
			goto Espan;
	}
	if (offs != limit)
		goto Eend;
out:
	SetPageChecked(page);
	return;

	/* Too bad, we had an error */

Ebadsize:
	nilfs_error(sb, "nilfs_check_page",
		    "size of directory #%lu is not a multiple of chunk size",
		    dir->i_ino
	);
	goto fail;
Eshort:
	error = "rec_len is smaller than minimal";
	goto bad_entry;
Ealign:
	error = "unaligned directory entry";
	goto bad_entry;
Enamelen:
	error = "rec_len is too small for name_len";
	goto bad_entry;
Espan:
	error = "directory entry across blocks";
bad_entry:
	nilfs_error(sb, "nilfs_check_page", "bad entry in directory #%lu: %s - "
		    "offset=%lu, inode=%lu, rec_len=%d, name_len=%d",
		    dir->i_ino, error, (page->index<<PAGE_CACHE_SHIFT)+offs,
		    (unsigned long) le64_to_cpu(p->inode),
		    rec_len, p->name_len);
	goto fail;
Eend:
	p = (struct nilfs_dir_entry *)(kaddr + offs);
	nilfs_error(sb, "nilfs_check_page",
		    "entry in directory #%lu spans the page boundary"
		    "offset=%lu, inode=%lu",
		    dir->i_ino, (page->index<<PAGE_CACHE_SHIFT)+offs,
		    (unsigned long) le64_to_cpu(p->inode));
fail:
	SetPageChecked(page);
	SetPageError(page);
}

static struct page *nilfs_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);

	if (!IS_ERR(page)) {
		kmap(page);
		if (!PageChecked(page))
			nilfs_check_page(page);
		if (PageError(page))
			goto fail;
	}
	return page;

fail:
	nilfs_put_page(page);
	return ERR_PTR(-EIO);
}

/*
 * NOTE! unlike strncmp, nilfs_match returns 1 for success, 0 for failure.
 *
 * len <= NILFS_NAME_LEN and de != NULL are guaranteed by caller.
 */
static int
nilfs_match(int len, const unsigned char *name, struct nilfs_dir_entry *de)
{
	if (len != de->name_len)
		return 0;
	if (!de->inode)
		return 0;
	return !memcmp(name, de->name, len);
}

/*
 * p is at least 6 bytes before the end of page
 */
static struct nilfs_dir_entry *nilfs_next_entry(struct nilfs_dir_entry *p)
{
	return (struct nilfs_dir_entry *)((char *)p +
					  nilfs_rec_len_from_disk(p->rec_len));
}

static unsigned char
nilfs_filetype_table[NILFS_FT_MAX] = {
	[NILFS_FT_UNKNOWN]	= DT_UNKNOWN,
	[NILFS_FT_REG_FILE]	= DT_REG,
	[NILFS_FT_DIR]		= DT_DIR,
	[NILFS_FT_CHRDEV]	= DT_CHR,
	[NILFS_FT_BLKDEV]	= DT_BLK,
	[NILFS_FT_FIFO]		= DT_FIFO,
	[NILFS_FT_SOCK]		= DT_SOCK,
	[NILFS_FT_SYMLINK]	= DT_LNK,
};

#define S_SHIFT 12
static unsigned char
nilfs_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= NILFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= NILFS_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= NILFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= NILFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= NILFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= NILFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= NILFS_FT_SYMLINK,
};

static void nilfs_set_de_type(struct nilfs_dir_entry *de, struct inode *inode)
{
	umode_t mode = inode->i_mode;

	de->file_type = nilfs_type_by_mode[(mode & S_IFMT)>>S_SHIFT];
}

static int nilfs_readdir(struct file *file, struct dir_context *ctx)
{
	loff_t pos = ctx->pos;
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	unsigned int offset = pos & ~PAGE_CACHE_MASK;
	unsigned long n = pos >> PAGE_CACHE_SHIFT;
	unsigned long npages = dir_pages(inode);
/*	unsigned chunk_mask = ~(nilfs_chunk_size(inode)-1); */

	if (pos > inode->i_size - NILFS_DIR_REC_LEN(1))
		return 0;

	for ( ; n < npages; n++, offset = 0) {
		char *kaddr, *limit;
		struct nilfs_dir_entry *de;
		struct page *page = nilfs_get_page(inode, n);

		if (IS_ERR(page)) {
			nilfs_error(sb, __func__, "bad page in #%lu",
				    inode->i_ino);
			ctx->pos += PAGE_CACHE_SIZE - offset;
			return -EIO;
		}
		kaddr = page_address(page);
		de = (struct nilfs_dir_entry *)(kaddr + offset);
		limit = kaddr + nilfs_last_byte(inode, n) -
			NILFS_DIR_REC_LEN(1);
		for ( ; (char *)de <= limit; de = nilfs_next_entry(de)) {
			if (de->rec_len == 0) {
				nilfs_error(sb, __func__,
					    "zero-length directory entry");
				nilfs_put_page(page);
				return -EIO;
			}
			if (de->inode) {
				unsigned char t;

				if (de->file_type < NILFS_FT_MAX)
					t = nilfs_filetype_table[de->file_type];
				else
					t = DT_UNKNOWN;

				if (!dir_emit(ctx, de->name, de->name_len,
						le64_to_cpu(de->inode), t)) {
					nilfs_put_page(page);
					return 0;
				}
			}
			ctx->pos += nilfs_rec_len_from_disk(de->rec_len);
		}
		nilfs_put_page(page);
	}
	return 0;
}

/*
 *	nilfs_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the page in which the entry was found, and the entry itself
 * (as a parameter - res_dir). Page is returned mapped and unlocked.
 * Entry is guaranteed to be valid.
 */
struct nilfs_dir_entry *
nilfs_find_entry(struct inode *dir, const struct qstr *qstr,
		 struct page **res_page)
{
	const unsigned char *name = qstr->name;
	int namelen = qstr->len;
	unsigned reclen = NILFS_DIR_REC_LEN(namelen);
	unsigned long start, n;
	unsigned long npages = dir_pages(dir);
	struct page *page = NULL;
	struct nilfs_inode_info *ei = NILFS_I(dir);
	struct nilfs_dir_entry *de;

	if (npages == 0)
		goto out;

	/* OFFSET_CACHE */
	*res_page = NULL;

	start = ei->i_dir_start_lookup;
	if (start >= npages)
		start = 0;
	n = start;
	do {
		char *kaddr;
		page = nilfs_get_page(dir, n);
		if (!IS_ERR(page)) {
			kaddr = page_address(page);
			de = (struct nilfs_dir_entry *)kaddr;
			kaddr += nilfs_last_byte(dir, n) - reclen;
			while ((char *) de <= kaddr) {
				if (de->rec_len == 0) {
					nilfs_error(dir->i_sb, __func__,
						"zero-length directory entry");
					nilfs_put_page(page);
					goto out;
				}
				if (nilfs_match(namelen, name, de))
					goto found;
				de = nilfs_next_entry(de);
			}
			nilfs_put_page(page);
		}
		if (++n >= npages)
			n = 0;
		/* next page is past the blocks we've got */
		if (unlikely(n > (dir->i_blocks >> (PAGE_CACHE_SHIFT - 9)))) {
			nilfs_error(dir->i_sb, __func__,
			       "dir %lu size %lld exceeds block count %llu",
			       dir->i_ino, dir->i_size,
			       (unsigned long long)dir->i_blocks);
			goto out;
		}
	} while (n != start);
out:
	return NULL;

found:
	*res_page = page;
	ei->i_dir_start_lookup = n;
	return de;
}

struct nilfs_dir_entry *nilfs_dotdot(struct inode *dir, struct page **p)
{
	struct page *page = nilfs_get_page(dir, 0);
	struct nilfs_dir_entry *de = NULL;

	if (!IS_ERR(page)) {
		de = nilfs_next_entry(
			(struct nilfs_dir_entry *)page_address(page));
		*p = page;
	}
	return de;
}

ino_t nilfs_inode_by_name(struct inode *dir, const struct qstr *qstr)
{
	ino_t res = 0;
	struct nilfs_dir_entry *de;
	struct page *page;

	de = nilfs_find_entry(dir, qstr, &page);
	if (de) {
		res = le64_to_cpu(de->inode);
		kunmap(page);
		page_cache_release(page);
	}
	return res;
}

/* Releases the page */
void nilfs_set_link(struct inode *dir, struct nilfs_dir_entry *de,
		    struct page *page, struct inode *inode)
{
	unsigned from = (char *) de - (char *) page_address(page);
	unsigned to = from + nilfs_rec_len_from_disk(de->rec_len);
	struct address_space *mapping = page->mapping;
	int err;

	lock_page(page);
	err = nilfs_prepare_chunk(page, from, to);
	BUG_ON(err);
	de->inode = cpu_to_le64(inode->i_ino);
	nilfs_set_de_type(de, inode);
	nilfs_commit_chunk(page, mapping, from, to);
	nilfs_put_page(page);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
}

/*
 *	Parent is locked.
 */
int nilfs_add_link(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = dentry->d_parent->d_inode;
	const unsigned char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	unsigned chunk_size = nilfs_chunk_size(dir);
	unsigned reclen = NILFS_DIR_REC_LEN(namelen);
	unsigned short rec_len, name_len;
	struct page *page = NULL;
	struct nilfs_dir_entry *de;
	unsigned long npages = dir_pages(dir);
	unsigned long n;
	char *kaddr;
	unsigned from, to;
	int err;

	/*
	 * We take care of directory expansion in the same loop.
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	for (n = 0; n <= npages; n++) {
		char *dir_end;

		page = nilfs_get_page(dir, n);
		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto out;
		lock_page(page);
		kaddr = page_address(page);
		dir_end = kaddr + nilfs_last_byte(dir, n);
		de = (struct nilfs_dir_entry *)kaddr;
		kaddr += PAGE_CACHE_SIZE - reclen;
		while ((char *)de <= kaddr) {
			if ((char *)de == dir_end) {
				/* We hit i_size */
				name_len = 0;
				rec_len = chunk_size;
				de->rec_len = nilfs_rec_len_to_disk(chunk_size);
				de->inode = 0;
				goto got_it;
			}
			if (de->rec_len == 0) {
				nilfs_error(dir->i_sb, __func__,
					    "zero-length directory entry");
				err = -EIO;
				goto out_unlock;
			}
			err = -EEXIST;
			if (nilfs_match(namelen, name, de))
				goto out_unlock;
			name_len = NILFS_DIR_REC_LEN(de->name_len);
			rec_len = nilfs_rec_len_from_disk(de->rec_len);
			if (!de->inode && rec_len >= reclen)
				goto got_it;
			if (rec_len >= name_len + reclen)
				goto got_it;
			de = (struct nilfs_dir_entry *)((char *)de + rec_len);
		}
		unlock_page(page);
		nilfs_put_page(page);
	}
	BUG();
	return -EINVAL;

got_it:
	from = (char *)de - (char *)page_address(page);
	to = from + rec_len;
	err = nilfs_prepare_chunk(page, from, to);
	if (err)
		goto out_unlock;
	if (de->inode) {
		struct nilfs_dir_entry *de1;

		de1 = (struct nilfs_dir_entry *)((char *)de + name_len);
		de1->rec_len = nilfs_rec_len_to_disk(rec_len - name_len);
		de->rec_len = nilfs_rec_len_to_disk(name_len);
		de = de1;
	}
	de->name_len = namelen;
	memcpy(de->name, name, namelen);
	de->inode = cpu_to_le64(inode->i_ino);
	nilfs_set_de_type(de, inode);
	nilfs_commit_chunk(page, page->mapping, from, to);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	nilfs_mark_inode_dirty(dir);
	/* OFFSET_CACHE */
out_put:
	nilfs_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_put;
}

/*
 * nilfs_delete_entry deletes a directory entry by merging it with the
 * previous entry. Page is up-to-date. Releases the page.
 */
int nilfs_delete_entry(struct nilfs_dir_entry *dir, struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	char *kaddr = page_address(page);
	unsigned from = ((char *)dir - kaddr) & ~(nilfs_chunk_size(inode) - 1);
	unsigned to = ((char *)dir - kaddr) +
		nilfs_rec_len_from_disk(dir->rec_len);
	struct nilfs_dir_entry *pde = NULL;
	struct nilfs_dir_entry *de = (struct nilfs_dir_entry *)(kaddr + from);
	int err;

	while ((char *)de < (char *)dir) {
		if (de->rec_len == 0) {
			nilfs_error(inode->i_sb, __func__,
				    "zero-length directory entry");
			err = -EIO;
			goto out;
		}
		pde = de;
		de = nilfs_next_entry(de);
	}
	if (pde)
		from = (char *)pde - (char *)page_address(page);
	lock_page(page);
	err = nilfs_prepare_chunk(page, from, to);
	BUG_ON(err);
	if (pde)
		pde->rec_len = nilfs_rec_len_to_disk(to - from);
	dir->inode = 0;
	nilfs_commit_chunk(page, mapping, from, to);
	inode->i_ctime = inode->i_mtime = CURRENT_TIME;
out:
	nilfs_put_page(page);
	return err;
}

/*
 * Set the first fragment of directory.
 */
int nilfs_make_empty(struct inode *inode, struct inode *parent)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page = grab_cache_page(mapping, 0);
	unsigned chunk_size = nilfs_chunk_size(inode);
	struct nilfs_dir_entry *de;
	int err;
	void *kaddr;

	if (!page)
		return -ENOMEM;

	err = nilfs_prepare_chunk(page, 0, chunk_size);
	if (unlikely(err)) {
		unlock_page(page);
		goto fail;
	}
	kaddr = kmap_atomic(page);
	memset(kaddr, 0, chunk_size);
	de = (struct nilfs_dir_entry *)kaddr;
	de->name_len = 1;
	de->rec_len = nilfs_rec_len_to_disk(NILFS_DIR_REC_LEN(1));
	memcpy(de->name, ".\0\0", 4);
	de->inode = cpu_to_le64(inode->i_ino);
	nilfs_set_de_type(de, inode);

	de = (struct nilfs_dir_entry *)(kaddr + NILFS_DIR_REC_LEN(1));
	de->name_len = 2;
	de->rec_len = nilfs_rec_len_to_disk(chunk_size - NILFS_DIR_REC_LEN(1));
	de->inode = cpu_to_le64(parent->i_ino);
	memcpy(de->name, "..\0", 4);
	nilfs_set_de_type(de, inode);
	kunmap_atomic(kaddr);
	nilfs_commit_chunk(page, mapping, 0, chunk_size);
fail:
	page_cache_release(page);
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
int nilfs_empty_dir(struct inode *inode)
{
	struct page *page = NULL;
	unsigned long i, npages = dir_pages(inode);

	for (i = 0; i < npages; i++) {
		char *kaddr;
		struct nilfs_dir_entry *de;

		page = nilfs_get_page(inode, i);
		if (IS_ERR(page))
			continue;

		kaddr = page_address(page);
		de = (struct nilfs_dir_entry *)kaddr;
		kaddr += nilfs_last_byte(inode, i) - NILFS_DIR_REC_LEN(1);

		while ((char *)de <= kaddr) {
			if (de->rec_len == 0) {
				nilfs_error(inode->i_sb, __func__,
					    "zero-length directory entry "
					    "(kaddr=%p, de=%p)\n", kaddr, de);
				goto not_empty;
			}
			if (de->inode != 0) {
				/* check for . and .. */
				if (de->name[0] != '.')
					goto not_empty;
				if (de->name_len > 2)
					goto not_empty;
				if (de->name_len < 2) {
					if (de->inode !=
					    cpu_to_le64(inode->i_ino))
						goto not_empty;
				} else if (de->name[1] != '.')
					goto not_empty;
			}
			de = nilfs_next_entry(de);
		}
		nilfs_put_page(page);
	}
	return 1;

not_empty:
	nilfs_put_page(page);
	return 0;
}

const struct file_operations nilfs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= nilfs_readdir,
	.unlocked_ioctl	= nilfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= nilfs_compat_ioctl,
#endif	/* CONFIG_COMPAT */
	.fsync		= nilfs_sync_file,

};
/************************************************************/
/* ../linux-3.17/fs/nilfs2/dir.c */
/************************************************************/
/*
 * super.c - NILFS module and super block management.
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 */
/*
 *  linux/fs/ext2/super.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/crc32.h>
#include <linux/vfs.h>
// #include <linux/writeback.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
// #include "nilfs.h"
#include "export.h"
// #include "mdt.h"
#include "alloc.h"
#include "btree.h"
// #include "btnode.h"
// #include "page.h"
// #include "cpfile.h"
#include "sufile.h" /* nilfs_sufile_resize(), nilfs_sufile_set_alloc_range() */
// #include "ifile.h"
#include "dat.h"
// #include "segment.h"
#include "segbuf.h"

MODULE_AUTHOR("NTT Corp.");
MODULE_DESCRIPTION("A New Implementation of the Log-structured Filesystem "
		   "(NILFS)");
MODULE_LICENSE("GPL");

static struct kmem_cache *nilfs_inode_cachep;
struct kmem_cache *nilfs_transaction_cachep;
struct kmem_cache *nilfs_segbuf_cachep;
struct kmem_cache *nilfs_btree_path_cache;

static int nilfs_setup_super(struct super_block *sb, int is_mount);
static int nilfs_remount(struct super_block *sb, int *flags, char *data);

static void nilfs_set_error(struct super_block *sb)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_super_block **sbp;

	down_write(&nilfs->ns_sem);
	if (!(nilfs->ns_mount_state & NILFS_ERROR_FS)) {
		nilfs->ns_mount_state |= NILFS_ERROR_FS;
		sbp = nilfs_prepare_super(sb, 0);
		if (likely(sbp)) {
			sbp[0]->s_state |= cpu_to_le16(NILFS_ERROR_FS);
			if (sbp[1])
				sbp[1]->s_state |= cpu_to_le16(NILFS_ERROR_FS);
			nilfs_commit_super(sb, NILFS_SB_COMMIT_ALL);
		}
	}
	up_write(&nilfs->ns_sem);
}

/**
 * nilfs_error() - report failure condition on a filesystem
 *
 * nilfs_error() sets an ERROR_FS flag on the superblock as well as
 * reporting an error message.  It should be called when NILFS detects
 * incoherences or defects of meta data on disk.  As for sustainable
 * errors such as a single-shot I/O error, nilfs_warning() or the printk()
 * function should be used instead.
 *
 * The segment constructor must not call this function because it can
 * kill itself.
 */
void nilfs_error(struct super_block *sb, const char *function,
		 const char *fmt, ...)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	printk(KERN_CRIT "NILFS error (device %s): %s: %pV\n",
	       sb->s_id, function, &vaf);

	va_end(args);

	if (!(sb->s_flags & MS_RDONLY)) {
		nilfs_set_error(sb);

		if (nilfs_test_opt(nilfs, ERRORS_RO)) {
			printk(KERN_CRIT "Remounting filesystem read-only\n");
			sb->s_flags |= MS_RDONLY;
		}
	}

	if (nilfs_test_opt(nilfs, ERRORS_PANIC))
		panic("NILFS (device %s): panic forced after error\n",
		      sb->s_id);
}

void nilfs_warning(struct super_block *sb, const char *function,
		   const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	printk(KERN_WARNING "NILFS warning (device %s): %s: %pV\n",
	       sb->s_id, function, &vaf);

	va_end(args);
}


struct inode *nilfs_alloc_inode(struct super_block *sb)
{
	struct nilfs_inode_info *ii;

	ii = kmem_cache_alloc(nilfs_inode_cachep, GFP_NOFS);
	if (!ii)
		return NULL;
	ii->i_bh = NULL;
	ii->i_state = 0;
	ii->i_cno = 0;
	ii->vfs_inode.i_version = 1;
	nilfs_mapping_init(&ii->i_btnode_cache, &ii->vfs_inode, sb->s_bdi);
	return &ii->vfs_inode;
}

static void nilfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct nilfs_mdt_info *mdi = NILFS_MDT(inode);

	if (mdi) {
		kfree(mdi->mi_bgl); /* kfree(NULL) is safe */
		kfree(mdi);
	}
	kmem_cache_free(nilfs_inode_cachep, NILFS_I(inode));
}

void nilfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, nilfs_i_callback);
}

static int nilfs_sync_super(struct super_block *sb, int flag)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	int err;

 retry:
	set_buffer_dirty(nilfs->ns_sbh[0]);
	if (nilfs_test_opt(nilfs, BARRIER)) {
		err = __sync_dirty_buffer(nilfs->ns_sbh[0],
					  WRITE_SYNC | WRITE_FLUSH_FUA);
	} else {
		err = sync_dirty_buffer(nilfs->ns_sbh[0]);
	}

	if (unlikely(err)) {
		printk(KERN_ERR
		       "NILFS: unable to write superblock (err=%d)\n", err);
		if (err == -EIO && nilfs->ns_sbh[1]) {
			/*
			 * sbp[0] points to newer log than sbp[1],
			 * so copy sbp[0] to sbp[1] to take over sbp[0].
			 */
			memcpy(nilfs->ns_sbp[1], nilfs->ns_sbp[0],
			       nilfs->ns_sbsize);
			nilfs_fall_back_super_block(nilfs);
			goto retry;
		}
	} else {
		struct nilfs_super_block *sbp = nilfs->ns_sbp[0];

		nilfs->ns_sbwcount++;

		/*
		 * The latest segment becomes trailable from the position
		 * written in superblock.
		 */
		clear_nilfs_discontinued(nilfs);

		/* update GC protection for recent segments */
		if (nilfs->ns_sbh[1]) {
			if (flag == NILFS_SB_COMMIT_ALL) {
				set_buffer_dirty(nilfs->ns_sbh[1]);
				if (sync_dirty_buffer(nilfs->ns_sbh[1]) < 0)
					goto out;
			}
			if (le64_to_cpu(nilfs->ns_sbp[1]->s_last_cno) <
			    le64_to_cpu(nilfs->ns_sbp[0]->s_last_cno))
				sbp = nilfs->ns_sbp[1];
		}

		spin_lock(&nilfs->ns_last_segment_lock);
		nilfs->ns_prot_seq = le64_to_cpu(sbp->s_last_seq);
		spin_unlock(&nilfs->ns_last_segment_lock);
	}
 out:
	return err;
}

void nilfs_set_log_cursor(struct nilfs_super_block *sbp,
			  struct the_nilfs *nilfs)
{
	sector_t nfreeblocks;

	/* nilfs->ns_sem must be locked by the caller. */
	nilfs_count_free_blocks(nilfs, &nfreeblocks);
	sbp->s_free_blocks_count = cpu_to_le64(nfreeblocks);

	spin_lock(&nilfs->ns_last_segment_lock);
	sbp->s_last_seq = cpu_to_le64(nilfs->ns_last_seq);
	sbp->s_last_pseg = cpu_to_le64(nilfs->ns_last_pseg);
	sbp->s_last_cno = cpu_to_le64(nilfs->ns_last_cno);
	spin_unlock(&nilfs->ns_last_segment_lock);
}

struct nilfs_super_block **nilfs_prepare_super(struct super_block *sb,
					       int flip)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_super_block **sbp = nilfs->ns_sbp;

	/* nilfs->ns_sem must be locked by the caller. */
	if (sbp[0]->s_magic != cpu_to_le16(NILFS_SUPER_MAGIC)) {
		if (sbp[1] &&
		    sbp[1]->s_magic == cpu_to_le16(NILFS_SUPER_MAGIC)) {
			memcpy(sbp[0], sbp[1], nilfs->ns_sbsize);
		} else {
			printk(KERN_CRIT "NILFS: superblock broke on dev %s\n",
			       sb->s_id);
			return NULL;
		}
	} else if (sbp[1] &&
		   sbp[1]->s_magic != cpu_to_le16(NILFS_SUPER_MAGIC)) {
			memcpy(sbp[1], sbp[0], nilfs->ns_sbsize);
	}

	if (flip && sbp[1])
		nilfs_swap_super_block(nilfs);

	return sbp;
}

int nilfs_commit_super(struct super_block *sb, int flag)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_super_block **sbp = nilfs->ns_sbp;
	time_t t;

	/* nilfs->ns_sem must be locked by the caller. */
	t = get_seconds();
	nilfs->ns_sbwtime = t;
	sbp[0]->s_wtime = cpu_to_le64(t);
	sbp[0]->s_sum = 0;
	sbp[0]->s_sum = cpu_to_le32(crc32_le(nilfs->ns_crc_seed,
					     (unsigned char *)sbp[0],
					     nilfs->ns_sbsize));
	if (flag == NILFS_SB_COMMIT_ALL && sbp[1]) {
		sbp[1]->s_wtime = sbp[0]->s_wtime;
		sbp[1]->s_sum = 0;
		sbp[1]->s_sum = cpu_to_le32(crc32_le(nilfs->ns_crc_seed,
					    (unsigned char *)sbp[1],
					    nilfs->ns_sbsize));
	}
	clear_nilfs_sb_dirty(nilfs);
	return nilfs_sync_super(sb, flag);
}

/**
 * nilfs_cleanup_super() - write filesystem state for cleanup
 * @sb: super block instance to be unmounted or degraded to read-only
 *
 * This function restores state flags in the on-disk super block.
 * This will set "clean" flag (i.e. NILFS_VALID_FS) unless the
 * filesystem was not clean previously.
 */
int nilfs_cleanup_super(struct super_block *sb)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_super_block **sbp;
	int flag = NILFS_SB_COMMIT;
	int ret = -EIO;

	sbp = nilfs_prepare_super(sb, 0);
	if (sbp) {
		sbp[0]->s_state = cpu_to_le16(nilfs->ns_mount_state);
		nilfs_set_log_cursor(sbp[0], nilfs);
		if (sbp[1] && sbp[0]->s_last_cno == sbp[1]->s_last_cno) {
			/*
			 * make the "clean" flag also to the opposite
			 * super block if both super blocks point to
			 * the same checkpoint.
			 */
			sbp[1]->s_state = sbp[0]->s_state;
			flag = NILFS_SB_COMMIT_ALL;
		}
		ret = nilfs_commit_super(sb, flag);
	}
	return ret;
}

/**
 * nilfs_move_2nd_super - relocate secondary super block
 * @sb: super block instance
 * @sb2off: new offset of the secondary super block (in bytes)
 */
static int nilfs_move_2nd_super(struct super_block *sb, loff_t sb2off)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct buffer_head *nsbh;
	struct nilfs_super_block *nsbp;
	sector_t blocknr, newblocknr;
	unsigned long offset;
	int sb2i = -1;  /* array index of the secondary superblock */
	int ret = 0;

	/* nilfs->ns_sem must be locked by the caller. */
	if (nilfs->ns_sbh[1] &&
	    nilfs->ns_sbh[1]->b_blocknr > nilfs->ns_first_data_block) {
		sb2i = 1;
		blocknr = nilfs->ns_sbh[1]->b_blocknr;
	} else if (nilfs->ns_sbh[0]->b_blocknr > nilfs->ns_first_data_block) {
		sb2i = 0;
		blocknr = nilfs->ns_sbh[0]->b_blocknr;
	}
	if (sb2i >= 0 && (u64)blocknr << nilfs->ns_blocksize_bits == sb2off)
		goto out;  /* super block location is unchanged */

	/* Get new super block buffer */
	newblocknr = sb2off >> nilfs->ns_blocksize_bits;
	offset = sb2off & (nilfs->ns_blocksize - 1);
	nsbh = sb_getblk(sb, newblocknr);
	if (!nsbh) {
		printk(KERN_WARNING
		       "NILFS warning: unable to move secondary superblock "
		       "to block %llu\n", (unsigned long long)newblocknr);
		ret = -EIO;
		goto out;
	}
	nsbp = (void *)nsbh->b_data + offset;
	memset(nsbp, 0, nilfs->ns_blocksize);

	if (sb2i >= 0) {
		memcpy(nsbp, nilfs->ns_sbp[sb2i], nilfs->ns_sbsize);
		brelse(nilfs->ns_sbh[sb2i]);
		nilfs->ns_sbh[sb2i] = nsbh;
		nilfs->ns_sbp[sb2i] = nsbp;
	} else if (nilfs->ns_sbh[0]->b_blocknr < nilfs->ns_first_data_block) {
		/* secondary super block will be restored to index 1 */
		nilfs->ns_sbh[1] = nsbh;
		nilfs->ns_sbp[1] = nsbp;
	} else {
		brelse(nsbh);
	}
out:
	return ret;
}

/**
 * nilfs_resize_fs - resize the filesystem
 * @sb: super block instance
 * @newsize: new size of the filesystem (in bytes)
 */
int nilfs_resize_fs(struct super_block *sb, __u64 newsize)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_super_block **sbp;
	__u64 devsize, newnsegs;
	loff_t sb2off;
	int ret;

	ret = -ERANGE;
	devsize = i_size_read(sb->s_bdev->bd_inode);
	if (newsize > devsize)
		goto out;

	/*
	 * Write lock is required to protect some functions depending
	 * on the number of segments, the number of reserved segments,
	 * and so forth.
	 */
	down_write(&nilfs->ns_segctor_sem);

	sb2off = NILFS_SB2_OFFSET_BYTES(newsize);
	newnsegs = sb2off >> nilfs->ns_blocksize_bits;
	do_div(newnsegs, nilfs->ns_blocks_per_segment);

	ret = nilfs_sufile_resize(nilfs->ns_sufile, newnsegs);
	up_write(&nilfs->ns_segctor_sem);
	if (ret < 0)
		goto out;

	ret = nilfs_construct_segment(sb);
	if (ret < 0)
		goto out;

	down_write(&nilfs->ns_sem);
	nilfs_move_2nd_super(sb, sb2off);
	ret = -EIO;
	sbp = nilfs_prepare_super(sb, 0);
	if (likely(sbp)) {
		nilfs_set_log_cursor(sbp[0], nilfs);
		/*
		 * Drop NILFS_RESIZE_FS flag for compatibility with
		 * mount-time resize which may be implemented in a
		 * future release.
		 */
		sbp[0]->s_state = cpu_to_le16(le16_to_cpu(sbp[0]->s_state) &
					      ~NILFS_RESIZE_FS);
		sbp[0]->s_dev_size = cpu_to_le64(newsize);
		sbp[0]->s_nsegments = cpu_to_le64(nilfs->ns_nsegments);
		if (sbp[1])
			memcpy(sbp[1], sbp[0], nilfs->ns_sbsize);
		ret = nilfs_commit_super(sb, NILFS_SB_COMMIT_ALL);
	}
	up_write(&nilfs->ns_sem);

	/*
	 * Reset the range of allocatable segments last.  This order
	 * is important in the case of expansion because the secondary
	 * superblock must be protected from log write until migration
	 * completes.
	 */
	if (!ret)
		nilfs_sufile_set_alloc_range(nilfs->ns_sufile, 0, newnsegs - 1);
out:
	return ret;
}

static void nilfs_put_super(struct super_block *sb)
{
	struct the_nilfs *nilfs = sb->s_fs_info;

	nilfs_detach_log_writer(sb);

	if (!(sb->s_flags & MS_RDONLY)) {
		down_write(&nilfs->ns_sem);
		nilfs_cleanup_super(sb);
		up_write(&nilfs->ns_sem);
	}

	iput(nilfs->ns_sufile);
	iput(nilfs->ns_cpfile);
	iput(nilfs->ns_dat);

	destroy_nilfs(nilfs);
	sb->s_fs_info = NULL;
}

static int nilfs_sync_fs(struct super_block *sb, int wait)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_super_block **sbp;
	int err = 0;

	/* This function is called when super block should be written back */
	if (wait)
		err = nilfs_construct_segment(sb);

	down_write(&nilfs->ns_sem);
	if (nilfs_sb_dirty(nilfs)) {
		sbp = nilfs_prepare_super(sb, nilfs_sb_will_flip(nilfs));
		if (likely(sbp)) {
			nilfs_set_log_cursor(sbp[0], nilfs);
			nilfs_commit_super(sb, NILFS_SB_COMMIT);
		}
	}
	up_write(&nilfs->ns_sem);

	return err;
}

int nilfs_attach_checkpoint(struct super_block *sb, __u64 cno, int curr_mnt,
			    struct nilfs_root **rootp)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_root *root;
	struct nilfs_checkpoint *raw_cp;
	struct buffer_head *bh_cp;
	int err = -ENOMEM;

	root = nilfs_find_or_create_root(
		nilfs, curr_mnt ? NILFS_CPTREE_CURRENT_CNO : cno);
	if (!root)
		return err;

	if (root->ifile)
		goto reuse; /* already attached checkpoint */

	down_read(&nilfs->ns_segctor_sem);
	err = nilfs_cpfile_get_checkpoint(nilfs->ns_cpfile, cno, 0, &raw_cp,
					  &bh_cp);
	up_read(&nilfs->ns_segctor_sem);
	if (unlikely(err)) {
		if (err == -ENOENT || err == -EINVAL) {
			printk(KERN_ERR
			       "NILFS: Invalid checkpoint "
			       "(checkpoint number=%llu)\n",
			       (unsigned long long)cno);
			err = -EINVAL;
		}
		goto failed;
	}

	err = nilfs_ifile_read(sb, root, nilfs->ns_inode_size,
			       &raw_cp->cp_ifile_inode, &root->ifile);
	if (err)
		goto failed_bh;

	atomic64_set(&root->inodes_count,
			le64_to_cpu(raw_cp->cp_inodes_count));
	atomic64_set(&root->blocks_count,
			le64_to_cpu(raw_cp->cp_blocks_count));

	nilfs_cpfile_put_checkpoint(nilfs->ns_cpfile, cno, bh_cp);

 reuse:
	*rootp = root;
	return 0;

 failed_bh:
	nilfs_cpfile_put_checkpoint(nilfs->ns_cpfile, cno, bh_cp);
 failed:
	nilfs_put_root(root);

	return err;
}

static int nilfs_freeze(struct super_block *sb)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	int err;

	if (sb->s_flags & MS_RDONLY)
		return 0;

	/* Mark super block clean */
	down_write(&nilfs->ns_sem);
	err = nilfs_cleanup_super(sb);
	up_write(&nilfs->ns_sem);
	return err;
}

static int nilfs_unfreeze(struct super_block *sb)
{
	struct the_nilfs *nilfs = sb->s_fs_info;

	if (sb->s_flags & MS_RDONLY)
		return 0;

	down_write(&nilfs->ns_sem);
	nilfs_setup_super(sb, false);
	up_write(&nilfs->ns_sem);
	return 0;
}

static int nilfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct nilfs_root *root = NILFS_I(dentry->d_inode)->i_root;
	struct the_nilfs *nilfs = root->nilfs;
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);
	unsigned long long blocks;
	unsigned long overhead;
	unsigned long nrsvblocks;
	sector_t nfreeblocks;
	u64 nmaxinodes, nfreeinodes;
	int err;

	/*
	 * Compute all of the segment blocks
	 *
	 * The blocks before first segment and after last segment
	 * are excluded.
	 */
	blocks = nilfs->ns_blocks_per_segment * nilfs->ns_nsegments
		- nilfs->ns_first_data_block;
	nrsvblocks = nilfs->ns_nrsvsegs * nilfs->ns_blocks_per_segment;

	/*
	 * Compute the overhead
	 *
	 * When distributing meta data blocks outside segment structure,
	 * We must count them as the overhead.
	 */
	overhead = 0;

	err = nilfs_count_free_blocks(nilfs, &nfreeblocks);
	if (unlikely(err))
		return err;

	err = nilfs_ifile_count_free_inodes(root->ifile,
					    &nmaxinodes, &nfreeinodes);
	if (unlikely(err)) {
		printk(KERN_WARNING
			"NILFS warning: fail to count free inodes: err %d.\n",
			err);
		if (err == -ERANGE) {
			/*
			 * If nilfs_palloc_count_max_entries() returns
			 * -ERANGE error code then we simply treat
			 * curent inodes count as maximum possible and
			 * zero as free inodes value.
			 */
			nmaxinodes = atomic64_read(&root->inodes_count);
			nfreeinodes = 0;
			err = 0;
		} else
			return err;
	}

	buf->f_type = NILFS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = blocks - overhead;
	buf->f_bfree = nfreeblocks;
	buf->f_bavail = (buf->f_bfree >= nrsvblocks) ?
		(buf->f_bfree - nrsvblocks) : 0;
	buf->f_files = nmaxinodes;
	buf->f_ffree = nfreeinodes;
	buf->f_namelen = NILFS_NAME_LEN;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}

static int nilfs_show_options(struct seq_file *seq, struct dentry *dentry)
{
	struct super_block *sb = dentry->d_sb;
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_root *root = NILFS_I(dentry->d_inode)->i_root;

	if (!nilfs_test_opt(nilfs, BARRIER))
		seq_puts(seq, ",nobarrier");
	if (root->cno != NILFS_CPTREE_CURRENT_CNO)
		seq_printf(seq, ",cp=%llu", (unsigned long long)root->cno);
	if (nilfs_test_opt(nilfs, ERRORS_PANIC))
		seq_puts(seq, ",errors=panic");
	if (nilfs_test_opt(nilfs, ERRORS_CONT))
		seq_puts(seq, ",errors=continue");
	if (nilfs_test_opt(nilfs, STRICT_ORDER))
		seq_puts(seq, ",order=strict");
	if (nilfs_test_opt(nilfs, NORECOVERY))
		seq_puts(seq, ",norecovery");
	if (nilfs_test_opt(nilfs, DISCARD))
		seq_puts(seq, ",discard");

	return 0;
}

static const struct super_operations nilfs_sops = {
	.alloc_inode    = nilfs_alloc_inode,
	.destroy_inode  = nilfs_destroy_inode,
	.dirty_inode    = nilfs_dirty_inode,
	.evict_inode    = nilfs_evict_inode,
	.put_super      = nilfs_put_super,
	.sync_fs        = nilfs_sync_fs,
	.freeze_fs	= nilfs_freeze,
	.unfreeze_fs	= nilfs_unfreeze,
	.statfs         = nilfs_statfs,
	.remount_fs     = nilfs_remount,
	.show_options = nilfs_show_options
};

enum {
	Opt_err_cont, Opt_err_panic, Opt_err_ro,
	Opt_barrier, Opt_nobarrier, Opt_snapshot, Opt_order, Opt_norecovery,
	Opt_discard, Opt_nodiscard, Opt_err,
};

static match_table_t tokens = {
	{Opt_err_cont, "errors=continue"},
	{Opt_err_panic, "errors=panic"},
	{Opt_err_ro, "errors=remount-ro"},
	{Opt_barrier, "barrier"},
	{Opt_nobarrier, "nobarrier"},
	{Opt_snapshot, "cp=%u"},
	{Opt_order, "order=%s"},
	{Opt_norecovery, "norecovery"},
	{Opt_discard, "discard"},
	{Opt_nodiscard, "nodiscard"},
	{Opt_err, NULL}
};

static int parse_options(char *options, struct super_block *sb, int is_remount)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	char *p;
	substring_t args[MAX_OPT_ARGS];

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_barrier:
			nilfs_set_opt(nilfs, BARRIER);
			break;
		case Opt_nobarrier:
			nilfs_clear_opt(nilfs, BARRIER);
			break;
		case Opt_order:
			if (strcmp(args[0].from, "relaxed") == 0)
				/* Ordered data semantics */
				nilfs_clear_opt(nilfs, STRICT_ORDER);
			else if (strcmp(args[0].from, "strict") == 0)
				/* Strict in-order semantics */
				nilfs_set_opt(nilfs, STRICT_ORDER);
			else
				return 0;
			break;
		case Opt_err_panic:
			nilfs_write_opt(nilfs, ERROR_MODE, ERRORS_PANIC);
			break;
		case Opt_err_ro:
			nilfs_write_opt(nilfs, ERROR_MODE, ERRORS_RO);
			break;
		case Opt_err_cont:
			nilfs_write_opt(nilfs, ERROR_MODE, ERRORS_CONT);
			break;
		case Opt_snapshot:
			if (is_remount) {
				printk(KERN_ERR
				       "NILFS: \"%s\" option is invalid "
				       "for remount.\n", p);
				return 0;
			}
			break;
		case Opt_norecovery:
			nilfs_set_opt(nilfs, NORECOVERY);
			break;
		case Opt_discard:
			nilfs_set_opt(nilfs, DISCARD);
			break;
		case Opt_nodiscard:
			nilfs_clear_opt(nilfs, DISCARD);
			break;
		default:
			printk(KERN_ERR
			       "NILFS: Unrecognized mount option \"%s\"\n", p);
			return 0;
		}
	}
	return 1;
}

static inline void
nilfs_set_default_options(struct super_block *sb,
			  struct nilfs_super_block *sbp)
{
	struct the_nilfs *nilfs = sb->s_fs_info;

	nilfs->ns_mount_opt =
		NILFS_MOUNT_ERRORS_RO | NILFS_MOUNT_BARRIER;
}

static int nilfs_setup_super(struct super_block *sb, int is_mount)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_super_block **sbp;
	int max_mnt_count;
	int mnt_count;

	/* nilfs->ns_sem must be locked by the caller. */
	sbp = nilfs_prepare_super(sb, 0);
	if (!sbp)
		return -EIO;

	if (!is_mount)
		goto skip_mount_setup;

	max_mnt_count = le16_to_cpu(sbp[0]->s_max_mnt_count);
	mnt_count = le16_to_cpu(sbp[0]->s_mnt_count);

	if (nilfs->ns_mount_state & NILFS_ERROR_FS) {
		printk(KERN_WARNING
		       "NILFS warning: mounting fs with errors\n");
#if 0
	} else if (max_mnt_count >= 0 && mnt_count >= max_mnt_count) {
		printk(KERN_WARNING
		       "NILFS warning: maximal mount count reached\n");
#endif
	}
	if (!max_mnt_count)
		sbp[0]->s_max_mnt_count = cpu_to_le16(NILFS_DFL_MAX_MNT_COUNT);

	sbp[0]->s_mnt_count = cpu_to_le16(mnt_count + 1);
	sbp[0]->s_mtime = cpu_to_le64(get_seconds());

skip_mount_setup:
	sbp[0]->s_state =
		cpu_to_le16(le16_to_cpu(sbp[0]->s_state) & ~NILFS_VALID_FS);
	/* synchronize sbp[1] with sbp[0] */
	if (sbp[1])
		memcpy(sbp[1], sbp[0], nilfs->ns_sbsize);
	return nilfs_commit_super(sb, NILFS_SB_COMMIT_ALL);
}

struct nilfs_super_block *nilfs_read_super_block(struct super_block *sb,
						 u64 pos, int blocksize,
						 struct buffer_head **pbh)
{
	unsigned long long sb_index = pos;
	unsigned long offset;

	offset = do_div(sb_index, blocksize);
	*pbh = sb_bread(sb, sb_index);
	if (!*pbh)
		return NULL;
	return (struct nilfs_super_block *)((char *)(*pbh)->b_data + offset);
}

int nilfs_store_magic_and_option(struct super_block *sb,
				 struct nilfs_super_block *sbp,
				 char *data)
{
	struct the_nilfs *nilfs = sb->s_fs_info;

	sb->s_magic = le16_to_cpu(sbp->s_magic);

	/* FS independent flags */
#ifdef NILFS_ATIME_DISABLE
	sb->s_flags |= MS_NOATIME;
#endif

	nilfs_set_default_options(sb, sbp);

	nilfs->ns_resuid = le16_to_cpu(sbp->s_def_resuid);
	nilfs->ns_resgid = le16_to_cpu(sbp->s_def_resgid);
	nilfs->ns_interval = le32_to_cpu(sbp->s_c_interval);
	nilfs->ns_watermark = le32_to_cpu(sbp->s_c_block_max);

	return !parse_options(data, sb, 0) ? -EINVAL : 0 ;
}

int nilfs_check_feature_compatibility(struct super_block *sb,
				      struct nilfs_super_block *sbp)
{
	__u64 features;

	features = le64_to_cpu(sbp->s_feature_incompat) &
		~NILFS_FEATURE_INCOMPAT_SUPP;
	if (features) {
		printk(KERN_ERR "NILFS: couldn't mount because of unsupported "
		       "optional features (%llx)\n",
		       (unsigned long long)features);
		return -EINVAL;
	}
	features = le64_to_cpu(sbp->s_feature_compat_ro) &
		~NILFS_FEATURE_COMPAT_RO_SUPP;
	if (!(sb->s_flags & MS_RDONLY) && features) {
		printk(KERN_ERR "NILFS: couldn't mount RDWR because of "
		       "unsupported optional features (%llx)\n",
		       (unsigned long long)features);
		return -EINVAL;
	}
	return 0;
}

static int nilfs_get_root_dentry(struct super_block *sb,
				 struct nilfs_root *root,
				 struct dentry **root_dentry)
{
	struct inode *inode;
	struct dentry *dentry;
	int ret = 0;

	inode = nilfs_iget(sb, root, NILFS_ROOT_INO);
	if (IS_ERR(inode)) {
		printk(KERN_ERR "NILFS: get root inode failed\n");
		ret = PTR_ERR(inode);
		goto out;
	}
	if (!S_ISDIR(inode->i_mode) || !inode->i_blocks || !inode->i_size) {
		iput(inode);
		printk(KERN_ERR "NILFS: corrupt root inode.\n");
		ret = -EINVAL;
		goto out;
	}

	if (root->cno == NILFS_CPTREE_CURRENT_CNO) {
		dentry = d_find_alias(inode);
		if (!dentry) {
			dentry = d_make_root(inode);
			if (!dentry) {
				ret = -ENOMEM;
				goto failed_dentry;
			}
		} else {
			iput(inode);
		}
	} else {
		dentry = d_obtain_root(inode);
		if (IS_ERR(dentry)) {
			ret = PTR_ERR(dentry);
			goto failed_dentry;
		}
	}
	*root_dentry = dentry;
 out:
	return ret;

 failed_dentry:
	printk(KERN_ERR "NILFS: get root dentry failed\n");
	goto out;
}

static int nilfs_attach_snapshot(struct super_block *s, __u64 cno,
				 struct dentry **root_dentry)
{
	struct the_nilfs *nilfs = s->s_fs_info;
	struct nilfs_root *root;
	int ret;

	mutex_lock(&nilfs->ns_snapshot_mount_mutex);

	down_read(&nilfs->ns_segctor_sem);
	ret = nilfs_cpfile_is_snapshot(nilfs->ns_cpfile, cno);
	up_read(&nilfs->ns_segctor_sem);
	if (ret < 0) {
		ret = (ret == -ENOENT) ? -EINVAL : ret;
		goto out;
	} else if (!ret) {
		printk(KERN_ERR "NILFS: The specified checkpoint is "
		       "not a snapshot (checkpoint number=%llu).\n",
		       (unsigned long long)cno);
		ret = -EINVAL;
		goto out;
	}

	ret = nilfs_attach_checkpoint(s, cno, false, &root);
	if (ret) {
		printk(KERN_ERR "NILFS: error loading snapshot "
		       "(checkpoint number=%llu).\n",
	       (unsigned long long)cno);
		goto out;
	}
	ret = nilfs_get_root_dentry(s, root, root_dentry);
	nilfs_put_root(root);
 out:
	mutex_unlock(&nilfs->ns_snapshot_mount_mutex);
	return ret;
}

/**
 * nilfs_tree_is_busy() - try to shrink dentries of a checkpoint
 * @root_dentry: root dentry of the tree to be shrunk
 *
 * This function returns true if the tree was in-use.
 */
static bool nilfs_tree_is_busy(struct dentry *root_dentry)
{
	shrink_dcache_parent(root_dentry);
	return d_count(root_dentry) > 1;
}

int nilfs_checkpoint_is_mounted(struct super_block *sb, __u64 cno)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_root *root;
	struct inode *inode;
	struct dentry *dentry;
	int ret;

	if (cno < 0 || cno > nilfs->ns_cno)
		return false;

	if (cno >= nilfs_last_cno(nilfs))
		return true;	/* protect recent checkpoints */

	ret = false;
	root = nilfs_lookup_root(nilfs, cno);
	if (root) {
		inode = nilfs_ilookup(sb, root, NILFS_ROOT_INO);
		if (inode) {
			dentry = d_find_alias(inode);
			if (dentry) {
				ret = nilfs_tree_is_busy(dentry);
				dput(dentry);
			}
			iput(inode);
		}
		nilfs_put_root(root);
	}
	return ret;
}

/**
 * nilfs_fill_super() - initialize a super block instance
 * @sb: super_block
 * @data: mount options
 * @silent: silent mode flag
 *
 * This function is called exclusively by nilfs->ns_mount_mutex.
 * So, the recovery process is protected from other simultaneous mounts.
 */
static int
nilfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct the_nilfs *nilfs;
	struct nilfs_root *fsroot;
	struct backing_dev_info *bdi;
	__u64 cno;
	int err;

	nilfs = alloc_nilfs(sb->s_bdev);
	if (!nilfs)
		return -ENOMEM;

	sb->s_fs_info = nilfs;

	err = init_nilfs(nilfs, sb, (char *)data);
	if (err)
		goto failed_nilfs;

	sb->s_op = &nilfs_sops;
	sb->s_export_op = &nilfs_export_ops;
	sb->s_root = NULL;
	sb->s_time_gran = 1;
	sb->s_max_links = NILFS_LINK_MAX;

	bdi = sb->s_bdev->bd_inode->i_mapping->backing_dev_info;
	sb->s_bdi = bdi ? : &default_backing_dev_info;

	err = load_nilfs(nilfs, sb);
	if (err)
		goto failed_nilfs;

	cno = nilfs_last_cno(nilfs);
	err = nilfs_attach_checkpoint(sb, cno, true, &fsroot);
	if (err) {
		printk(KERN_ERR "NILFS: error loading last checkpoint "
		       "(checkpoint number=%llu).\n", (unsigned long long)cno);
		goto failed_unload;
	}

	if (!(sb->s_flags & MS_RDONLY)) {
		err = nilfs_attach_log_writer(sb, fsroot);
		if (err)
			goto failed_checkpoint;
	}

	err = nilfs_get_root_dentry(sb, fsroot, &sb->s_root);
	if (err)
		goto failed_segctor;

	nilfs_put_root(fsroot);

	if (!(sb->s_flags & MS_RDONLY)) {
		down_write(&nilfs->ns_sem);
		nilfs_setup_super(sb, true);
		up_write(&nilfs->ns_sem);
	}

	return 0;

 failed_segctor:
	nilfs_detach_log_writer(sb);

 failed_checkpoint:
	nilfs_put_root(fsroot);

 failed_unload:
	iput(nilfs->ns_sufile);
	iput(nilfs->ns_cpfile);
	iput(nilfs->ns_dat);

 failed_nilfs:
	destroy_nilfs(nilfs);
	return err;
}

static int nilfs_remount(struct super_block *sb, int *flags, char *data)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	unsigned long old_sb_flags;
	unsigned long old_mount_opt;
	int err;

	sync_filesystem(sb);
	old_sb_flags = sb->s_flags;
	old_mount_opt = nilfs->ns_mount_opt;

	if (!parse_options(data, sb, 1)) {
		err = -EINVAL;
		goto restore_opts;
	}
	sb->s_flags = (sb->s_flags & ~MS_POSIXACL);

	err = -EINVAL;

	if (!nilfs_valid_fs(nilfs)) {
		printk(KERN_WARNING "NILFS (device %s): couldn't "
		       "remount because the filesystem is in an "
		       "incomplete recovery state.\n", sb->s_id);
		goto restore_opts;
	}

	if ((*flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY))
		goto out;
	if (*flags & MS_RDONLY) {
		/* Shutting down log writer */
		nilfs_detach_log_writer(sb);
		sb->s_flags |= MS_RDONLY;

		/*
		 * Remounting a valid RW partition RDONLY, so set
		 * the RDONLY flag and then mark the partition as valid again.
		 */
		down_write(&nilfs->ns_sem);
		nilfs_cleanup_super(sb);
		up_write(&nilfs->ns_sem);
	} else {
		__u64 features;
		struct nilfs_root *root;

		/*
		 * Mounting a RDONLY partition read-write, so reread and
		 * store the current valid flag.  (It may have been changed
		 * by fsck since we originally mounted the partition.)
		 */
		down_read(&nilfs->ns_sem);
		features = le64_to_cpu(nilfs->ns_sbp[0]->s_feature_compat_ro) &
			~NILFS_FEATURE_COMPAT_RO_SUPP;
		up_read(&nilfs->ns_sem);
		if (features) {
			printk(KERN_WARNING "NILFS (device %s): couldn't "
			       "remount RDWR because of unsupported optional "
			       "features (%llx)\n",
			       sb->s_id, (unsigned long long)features);
			err = -EROFS;
			goto restore_opts;
		}

		sb->s_flags &= ~MS_RDONLY;

		root = NILFS_I(sb->s_root->d_inode)->i_root;
		err = nilfs_attach_log_writer(sb, root);
		if (err)
			goto restore_opts;

		down_write(&nilfs->ns_sem);
		nilfs_setup_super(sb, true);
		up_write(&nilfs->ns_sem);
	}
 out:
	return 0;

 restore_opts:
	sb->s_flags = old_sb_flags;
	nilfs->ns_mount_opt = old_mount_opt;
	return err;
}

struct nilfs_super_data {
	struct block_device *bdev;
	__u64 cno;
	int flags;
};

/**
 * nilfs_identify - pre-read mount options needed to identify mount instance
 * @data: mount options
 * @sd: nilfs_super_data
 */
static int nilfs_identify(char *data, struct nilfs_super_data *sd)
{
	char *p, *options = data;
	substring_t args[MAX_OPT_ARGS];
	int token;
	int ret = 0;

	do {
		p = strsep(&options, ",");
		if (p != NULL && *p) {
			token = match_token(p, tokens, args);
			if (token == Opt_snapshot) {
				if (!(sd->flags & MS_RDONLY)) {
					ret++;
				} else {
					sd->cno = simple_strtoull(args[0].from,
								  NULL, 0);
					/*
					 * No need to see the end pointer;
					 * match_token() has done syntax
					 * checking.
					 */
					if (sd->cno == 0)
						ret++;
				}
			}
			if (ret)
				printk(KERN_ERR
				       "NILFS: invalid mount option: %s\n", p);
		}
		if (!options)
			break;
		BUG_ON(options == data);
		*(options - 1) = ',';
	} while (!ret);
	return ret;
}

static int nilfs_set_bdev_super(struct super_block *s, void *data)
{
	s->s_bdev = data;
	s->s_dev = s->s_bdev->bd_dev;
	return 0;
}

static int nilfs_test_bdev_super(struct super_block *s, void *data)
{
	return (void *)s->s_bdev == data;
}

static struct dentry *
nilfs_mount(struct file_system_type *fs_type, int flags,
	     const char *dev_name, void *data)
{
	struct nilfs_super_data sd;
	struct super_block *s;
	fmode_t mode = FMODE_READ | FMODE_EXCL;
	struct dentry *root_dentry;
	int err, s_new = false;

	if (!(flags & MS_RDONLY))
		mode |= FMODE_WRITE;

	sd.bdev = blkdev_get_by_path(dev_name, mode, fs_type);
	if (IS_ERR(sd.bdev))
		return ERR_CAST(sd.bdev);

	sd.cno = 0;
	sd.flags = flags;
	if (nilfs_identify((char *)data, &sd)) {
		err = -EINVAL;
		goto failed;
	}

	/*
	 * once the super is inserted into the list by sget, s_umount
	 * will protect the lockfs code from trying to start a snapshot
	 * while we are mounting
	 */
	mutex_lock(&sd.bdev->bd_fsfreeze_mutex);
	if (sd.bdev->bd_fsfreeze_count > 0) {
		mutex_unlock(&sd.bdev->bd_fsfreeze_mutex);
		err = -EBUSY;
		goto failed;
	}
	s = sget(fs_type, nilfs_test_bdev_super, nilfs_set_bdev_super, flags,
		 sd.bdev);
	mutex_unlock(&sd.bdev->bd_fsfreeze_mutex);
	if (IS_ERR(s)) {
		err = PTR_ERR(s);
		goto failed;
	}

	if (!s->s_root) {
		char b[BDEVNAME_SIZE];

		s_new = true;

		/* New superblock instance created */
		s->s_mode = mode;
		strlcpy(s->s_id, bdevname(sd.bdev, b), sizeof(s->s_id));
		sb_set_blocksize(s, block_size(sd.bdev));

		err = nilfs_fill_super(s, data, flags & MS_SILENT ? 1 : 0);
		if (err)
			goto failed_super;

		s->s_flags |= MS_ACTIVE;
	} else if (!sd.cno) {
		if (nilfs_tree_is_busy(s->s_root)) {
			if ((flags ^ s->s_flags) & MS_RDONLY) {
				printk(KERN_ERR "NILFS: the device already "
				       "has a %s mount.\n",
				       (s->s_flags & MS_RDONLY) ?
				       "read-only" : "read/write");
				err = -EBUSY;
				goto failed_super;
			}
		} else {
			/*
			 * Try remount to setup mount states if the current
			 * tree is not mounted and only snapshots use this sb.
			 */
			err = nilfs_remount(s, &flags, data);
			if (err)
				goto failed_super;
		}
	}

	if (sd.cno) {
		err = nilfs_attach_snapshot(s, sd.cno, &root_dentry);
		if (err)
			goto failed_super;
	} else {
		root_dentry = dget(s->s_root);
	}

	if (!s_new)
		blkdev_put(sd.bdev, mode);

	return root_dentry;

 failed_super:
	deactivate_locked_super(s);

 failed:
	if (!s_new)
		blkdev_put(sd.bdev, mode);
	return ERR_PTR(err);
}

struct file_system_type nilfs_fs_type = {
	.owner    = THIS_MODULE,
	.name     = "nilfs2",
	.mount    = nilfs_mount,
	.kill_sb  = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("nilfs2");

static void nilfs_inode_init_once(void *obj)
{
	struct nilfs_inode_info *ii = obj;

	INIT_LIST_HEAD(&ii->i_dirty);
#ifdef CONFIG_NILFS_XATTR
	init_rwsem(&ii->xattr_sem);
#endif
	address_space_init_once(&ii->i_btnode_cache);
	ii->i_bmap = &ii->i_bmap_data;
	inode_init_once(&ii->vfs_inode);
}

static void nilfs_segbuf_init_once(void *obj)
{
	memset(obj, 0, sizeof(struct nilfs_segment_buffer));
}

static void nilfs_destroy_cachep(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();

	if (nilfs_inode_cachep)
		kmem_cache_destroy(nilfs_inode_cachep);
	if (nilfs_transaction_cachep)
		kmem_cache_destroy(nilfs_transaction_cachep);
	if (nilfs_segbuf_cachep)
		kmem_cache_destroy(nilfs_segbuf_cachep);
	if (nilfs_btree_path_cache)
		kmem_cache_destroy(nilfs_btree_path_cache);
}

static int __init nilfs_init_cachep(void)
{
	nilfs_inode_cachep = kmem_cache_create("nilfs2_inode_cache",
			sizeof(struct nilfs_inode_info), 0,
			SLAB_RECLAIM_ACCOUNT, nilfs_inode_init_once);
	if (!nilfs_inode_cachep)
		goto fail;

	nilfs_transaction_cachep = kmem_cache_create("nilfs2_transaction_cache",
			sizeof(struct nilfs_transaction_info), 0,
			SLAB_RECLAIM_ACCOUNT, NULL);
	if (!nilfs_transaction_cachep)
		goto fail;

	nilfs_segbuf_cachep = kmem_cache_create("nilfs2_segbuf_cache",
			sizeof(struct nilfs_segment_buffer), 0,
			SLAB_RECLAIM_ACCOUNT, nilfs_segbuf_init_once);
	if (!nilfs_segbuf_cachep)
		goto fail;

	nilfs_btree_path_cache = kmem_cache_create("nilfs2_btree_path_cache",
			sizeof(struct nilfs_btree_path) * NILFS_BTREE_LEVEL_MAX,
			0, 0, NULL);
	if (!nilfs_btree_path_cache)
		goto fail;

	return 0;

fail:
	nilfs_destroy_cachep();
	return -ENOMEM;
}

static int __init init_nilfs_fs(void)
{
	int err;

	err = nilfs_init_cachep();
	if (err)
		goto fail;

	err = nilfs_sysfs_init();
	if (err)
		goto free_cachep;

	err = register_filesystem(&nilfs_fs_type);
	if (err)
		goto deinit_sysfs_entry;

	printk(KERN_INFO "NILFS version 2 loaded\n");
	return 0;

deinit_sysfs_entry:
	nilfs_sysfs_exit();
free_cachep:
	nilfs_destroy_cachep();
fail:
	return err;
}

static void __exit exit_nilfs_fs(void)
{
	nilfs_destroy_cachep();
	nilfs_sysfs_exit();
	unregister_filesystem(&nilfs_fs_type);
}

module_init(init_nilfs_fs)
module_exit(exit_nilfs_fs)
/************************************************************/
/* ../linux-3.17/fs/nilfs2/super.c */
/************************************************************/
/*
 * namei.c - NILFS pathname lookup operations.
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Modified for NILFS by Amagai Yoshiji <amagai@osrg.net>,
 *                       Ryusuke Konishi <ryusuke@osrg.net>
 */
/*
 *  linux/fs/ext2/namei.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

// #include <linux/pagemap.h>
// #include "nilfs.h"
// #include "export.h"

#define NILFS_FID_SIZE_NON_CONNECTABLE \
	(offsetof(struct nilfs_fid, parent_gen) / 4)
#define NILFS_FID_SIZE_CONNECTABLE	(sizeof(struct nilfs_fid) / 4)

static inline int nilfs_add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err = nilfs_add_link(dentry, inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(inode);
	return err;
}

/*
 * Methods themselves.
 */

static struct dentry *
nilfs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct inode *inode;
	ino_t ino;

	if (dentry->d_name.len > NILFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = nilfs_inode_by_name(dir, &dentry->d_name);
	inode = ino ? nilfs_iget(dir->i_sb, NILFS_I(dir)->i_root, ino) : NULL;
	return d_splice_alias(inode, dentry);
}

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int nilfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			bool excl)
{
	struct inode *inode;
	struct nilfs_transaction_info ti;
	int err;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;
	inode = nilfs_new_inode(dir, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		inode->i_op = &nilfs_file_inode_operations;
		inode->i_fop = &nilfs_file_operations;
		inode->i_mapping->a_ops = &nilfs_aops;
		nilfs_mark_inode_dirty(inode);
		err = nilfs_add_nondir(dentry, inode);
	}
	if (!err)
		err = nilfs_transaction_commit(dir->i_sb);
	else
		nilfs_transaction_abort(dir->i_sb);

	return err;
}

static int
nilfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct inode *inode;
	struct nilfs_transaction_info ti;
	int err;

	if (!new_valid_dev(rdev))
		return -EINVAL;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;
	inode = nilfs_new_inode(dir, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		init_special_inode(inode, inode->i_mode, rdev);
		nilfs_mark_inode_dirty(inode);
		err = nilfs_add_nondir(dentry, inode);
	}
	if (!err)
		err = nilfs_transaction_commit(dir->i_sb);
	else
		nilfs_transaction_abort(dir->i_sb);

	return err;
}

static int nilfs_symlink(struct inode *dir, struct dentry *dentry,
			 const char *symname)
{
	struct nilfs_transaction_info ti;
	struct super_block *sb = dir->i_sb;
	unsigned l = strlen(symname)+1;
	struct inode *inode;
	int err;

	if (l > sb->s_blocksize)
		return -ENAMETOOLONG;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;

	inode = nilfs_new_inode(dir, S_IFLNK | S_IRWXUGO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

	/* slow symlink */
	inode->i_op = &nilfs_symlink_inode_operations;
	inode->i_mapping->a_ops = &nilfs_aops;
	err = page_symlink(inode, symname, l);
	if (err)
		goto out_fail;

	/* mark_inode_dirty(inode); */
	/* page_symlink() do this */

	err = nilfs_add_nondir(dentry, inode);
out:
	if (!err)
		err = nilfs_transaction_commit(dir->i_sb);
	else
		nilfs_transaction_abort(dir->i_sb);

	return err;

out_fail:
	drop_nlink(inode);
	nilfs_mark_inode_dirty(inode);
	iput(inode);
	goto out;
}

static int nilfs_link(struct dentry *old_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	struct nilfs_transaction_info ti;
	int err;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;

	inode->i_ctime = CURRENT_TIME;
	inode_inc_link_count(inode);
	ihold(inode);

	err = nilfs_add_nondir(dentry, inode);
	if (!err)
		err = nilfs_transaction_commit(dir->i_sb);
	else
		nilfs_transaction_abort(dir->i_sb);

	return err;
}

static int nilfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	struct nilfs_transaction_info ti;
	int err;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 1);
	if (err)
		return err;

	inc_nlink(dir);

	inode = nilfs_new_inode(dir, S_IFDIR | mode);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	inode->i_op = &nilfs_dir_inode_operations;
	inode->i_fop = &nilfs_dir_operations;
	inode->i_mapping->a_ops = &nilfs_aops;

	inc_nlink(inode);

	err = nilfs_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = nilfs_add_link(dentry, inode);
	if (err)
		goto out_fail;

	nilfs_mark_inode_dirty(inode);
	d_instantiate(dentry, inode);
out:
	if (!err)
		err = nilfs_transaction_commit(dir->i_sb);
	else
		nilfs_transaction_abort(dir->i_sb);

	return err;

out_fail:
	drop_nlink(inode);
	drop_nlink(inode);
	nilfs_mark_inode_dirty(inode);
	iput(inode);
out_dir:
	drop_nlink(dir);
	nilfs_mark_inode_dirty(dir);
	goto out;
}

static int nilfs_do_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode;
	struct nilfs_dir_entry *de;
	struct page *page;
	int err;

	err = -ENOENT;
	de = nilfs_find_entry(dir, &dentry->d_name, &page);
	if (!de)
		goto out;

	inode = dentry->d_inode;
	err = -EIO;
	if (le64_to_cpu(de->inode) != inode->i_ino)
		goto out;

	if (!inode->i_nlink) {
		nilfs_warning(inode->i_sb, __func__,
			      "deleting nonexistent file (%lu), %d\n",
			      inode->i_ino, inode->i_nlink);
		set_nlink(inode, 1);
	}
	err = nilfs_delete_entry(de, page);
	if (err)
		goto out;

	inode->i_ctime = dir->i_ctime;
	drop_nlink(inode);
	err = 0;
out:
	return err;
}

static int nilfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct nilfs_transaction_info ti;
	int err;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 0);
	if (err)
		return err;

	err = nilfs_do_unlink(dir, dentry);

	if (!err) {
		nilfs_mark_inode_dirty(dir);
		nilfs_mark_inode_dirty(dentry->d_inode);
		err = nilfs_transaction_commit(dir->i_sb);
	} else
		nilfs_transaction_abort(dir->i_sb);

	return err;
}

static int nilfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct nilfs_transaction_info ti;
	int err;

	err = nilfs_transaction_begin(dir->i_sb, &ti, 0);
	if (err)
		return err;

	err = -ENOTEMPTY;
	if (nilfs_empty_dir(inode)) {
		err = nilfs_do_unlink(dir, dentry);
		if (!err) {
			inode->i_size = 0;
			drop_nlink(inode);
			nilfs_mark_inode_dirty(inode);
			drop_nlink(dir);
			nilfs_mark_inode_dirty(dir);
		}
	}
	if (!err)
		err = nilfs_transaction_commit(dir->i_sb);
	else
		nilfs_transaction_abort(dir->i_sb);

	return err;
}

static int nilfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir,	struct dentry *new_dentry)
{
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct page *dir_page = NULL;
	struct nilfs_dir_entry *dir_de = NULL;
	struct page *old_page;
	struct nilfs_dir_entry *old_de;
	struct nilfs_transaction_info ti;
	int err;

	err = nilfs_transaction_begin(old_dir->i_sb, &ti, 1);
	if (unlikely(err))
		return err;

	err = -ENOENT;
	old_de = nilfs_find_entry(old_dir, &old_dentry->d_name, &old_page);
	if (!old_de)
		goto out;

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_de = nilfs_dotdot(old_inode, &dir_page);
		if (!dir_de)
			goto out_old;
	}

	if (new_inode) {
		struct page *new_page;
		struct nilfs_dir_entry *new_de;

		err = -ENOTEMPTY;
		if (dir_de && !nilfs_empty_dir(new_inode))
			goto out_dir;

		err = -ENOENT;
		new_de = nilfs_find_entry(new_dir, &new_dentry->d_name, &new_page);
		if (!new_de)
			goto out_dir;
		nilfs_set_link(new_dir, new_de, new_page, old_inode);
		nilfs_mark_inode_dirty(new_dir);
		new_inode->i_ctime = CURRENT_TIME;
		if (dir_de)
			drop_nlink(new_inode);
		drop_nlink(new_inode);
		nilfs_mark_inode_dirty(new_inode);
	} else {
		err = nilfs_add_link(new_dentry, old_inode);
		if (err)
			goto out_dir;
		if (dir_de) {
			inc_nlink(new_dir);
			nilfs_mark_inode_dirty(new_dir);
		}
	}

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
	 * rename.
	 */
	old_inode->i_ctime = CURRENT_TIME;

	nilfs_delete_entry(old_de, old_page);

	if (dir_de) {
		nilfs_set_link(old_inode, dir_de, dir_page, new_dir);
		drop_nlink(old_dir);
	}
	nilfs_mark_inode_dirty(old_dir);
	nilfs_mark_inode_dirty(old_inode);

	err = nilfs_transaction_commit(old_dir->i_sb);
	return err;

out_dir:
	if (dir_de) {
		kunmap(dir_page);
		page_cache_release(dir_page);
	}
out_old:
	kunmap(old_page);
	page_cache_release(old_page);
out:
	nilfs_transaction_abort(old_dir->i_sb);
	return err;
}

/*
 * Export operations
 */
static struct dentry *nilfs_get_parent(struct dentry *child)
{
	unsigned long ino;
	struct inode *inode;
	struct qstr dotdot = QSTR_INIT("..", 2);
	struct nilfs_root *root;

	ino = nilfs_inode_by_name(child->d_inode, &dotdot);
	if (!ino)
		return ERR_PTR(-ENOENT);

	root = NILFS_I(child->d_inode)->i_root;

	inode = nilfs_iget(child->d_inode->i_sb, root, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	return d_obtain_alias(inode);
}

static struct dentry *nilfs_get_dentry(struct super_block *sb, u64 cno,
				       u64 ino, u32 gen)
{
	struct nilfs_root *root;
	struct inode *inode;

	if (ino < NILFS_FIRST_INO(sb) && ino != NILFS_ROOT_INO)
		return ERR_PTR(-ESTALE);

	root = nilfs_lookup_root(sb->s_fs_info, cno);
	if (!root)
		return ERR_PTR(-ESTALE);

	inode = nilfs_iget(sb, root, ino);
	nilfs_put_root(root);

	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (gen && inode->i_generation != gen) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}
	return d_obtain_alias(inode);
}

static struct dentry *nilfs_fh_to_dentry(struct super_block *sb, struct fid *fh,
					 int fh_len, int fh_type)
{
	struct nilfs_fid *fid = (struct nilfs_fid *)fh;

	if ((fh_len != NILFS_FID_SIZE_NON_CONNECTABLE &&
	     fh_len != NILFS_FID_SIZE_CONNECTABLE) ||
	    (fh_type != FILEID_NILFS_WITH_PARENT &&
	     fh_type != FILEID_NILFS_WITHOUT_PARENT))
		return NULL;

	return nilfs_get_dentry(sb, fid->cno, fid->ino, fid->gen);
}

static struct dentry *nilfs_fh_to_parent(struct super_block *sb, struct fid *fh,
					 int fh_len, int fh_type)
{
	struct nilfs_fid *fid = (struct nilfs_fid *)fh;

	if (fh_len != NILFS_FID_SIZE_CONNECTABLE ||
	    fh_type != FILEID_NILFS_WITH_PARENT)
		return NULL;

	return nilfs_get_dentry(sb, fid->cno, fid->parent_ino, fid->parent_gen);
}

static int nilfs_encode_fh(struct inode *inode, __u32 *fh, int *lenp,
			   struct inode *parent)
{
	struct nilfs_fid *fid = (struct nilfs_fid *)fh;
	struct nilfs_root *root = NILFS_I(inode)->i_root;
	int type;

	if (parent && *lenp < NILFS_FID_SIZE_CONNECTABLE) {
		*lenp = NILFS_FID_SIZE_CONNECTABLE;
		return FILEID_INVALID;
	}
	if (*lenp < NILFS_FID_SIZE_NON_CONNECTABLE) {
		*lenp = NILFS_FID_SIZE_NON_CONNECTABLE;
		return FILEID_INVALID;
	}

	fid->cno = root->cno;
	fid->ino = inode->i_ino;
	fid->gen = inode->i_generation;

	if (parent) {
		fid->parent_ino = parent->i_ino;
		fid->parent_gen = parent->i_generation;
		type = FILEID_NILFS_WITH_PARENT;
		*lenp = NILFS_FID_SIZE_CONNECTABLE;
	} else {
		type = FILEID_NILFS_WITHOUT_PARENT;
		*lenp = NILFS_FID_SIZE_NON_CONNECTABLE;
	}

	return type;
}

const struct inode_operations nilfs_dir_inode_operations = {
	.create		= nilfs_create,
	.lookup		= nilfs_lookup,
	.link		= nilfs_link,
	.unlink		= nilfs_unlink,
	.symlink	= nilfs_symlink,
	.mkdir		= nilfs_mkdir,
	.rmdir		= nilfs_rmdir,
	.mknod		= nilfs_mknod,
	.rename		= nilfs_rename,
	.setattr	= nilfs_setattr,
	.permission	= nilfs_permission,
	.fiemap		= nilfs_fiemap,
};

const struct inode_operations nilfs_special_inode_operations = {
	.setattr	= nilfs_setattr,
	.permission	= nilfs_permission,
};

const struct inode_operations nilfs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.permission     = nilfs_permission,
};

const struct export_operations nilfs_export_ops = {
	.encode_fh = nilfs_encode_fh,
	.fh_to_dentry = nilfs_fh_to_dentry,
	.fh_to_parent = nilfs_fh_to_parent,
	.get_parent = nilfs_get_parent,
};
/************************************************************/
/* ../linux-3.17/fs/nilfs2/namei.c */
/************************************************************/
/*
 * page.c - buffer/page management specific to NILFS
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>,
 *            Seiji Kihara <kihara@osrg.net>.
 */

// #include <linux/pagemap.h>
// #include <linux/writeback.h>
#include <linux/swap.h>
#include <linux/bitops.h>
#include <linux/page-flags.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <linux/pagevec.h>
// #include <linux/gfp.h>
// #include "nilfs.h"
// #include "page.h"
// #include "mdt.h"


#define NILFS_BUFFER_INHERENT_BITS  \
	((1UL << BH_Uptodate) | (1UL << BH_Mapped) | (1UL << BH_NILFS_Node) | \
	 (1UL << BH_NILFS_Volatile) | (1UL << BH_NILFS_Checked))

static struct buffer_head *
__nilfs_get_page_block(struct page *page, unsigned long block, pgoff_t index,
		       int blkbits, unsigned long b_state)

{
	unsigned long first_block;
	struct buffer_head *bh;

	if (!page_has_buffers(page))
		create_empty_buffers(page, 1 << blkbits, b_state);

	first_block = (unsigned long)index << (PAGE_CACHE_SHIFT - blkbits);
	bh = nilfs_page_get_nth_block(page, block - first_block);

	touch_buffer(bh);
	wait_on_buffer(bh);
	return bh;
}

struct buffer_head *nilfs_grab_buffer(struct inode *inode,
				      struct address_space *mapping,
				      unsigned long blkoff,
				      unsigned long b_state)
{
	int blkbits = inode->i_blkbits;
	pgoff_t index = blkoff >> (PAGE_CACHE_SHIFT - blkbits);
	struct page *page;
	struct buffer_head *bh;

	page = grab_cache_page(mapping, index);
	if (unlikely(!page))
		return NULL;

	bh = __nilfs_get_page_block(page, blkoff, index, blkbits, b_state);
	if (unlikely(!bh)) {
		unlock_page(page);
		page_cache_release(page);
		return NULL;
	}
	return bh;
}

/**
 * nilfs_forget_buffer - discard dirty state
 * @inode: owner inode of the buffer
 * @bh: buffer head of the buffer to be discarded
 */
void nilfs_forget_buffer(struct buffer_head *bh)
{
	struct page *page = bh->b_page;

	lock_buffer(bh);
	clear_buffer_nilfs_volatile(bh);
	clear_buffer_nilfs_checked(bh);
	clear_buffer_nilfs_redirected(bh);
	clear_buffer_async_write(bh);
	clear_buffer_dirty(bh);
	if (nilfs_page_buffers_clean(page))
		__nilfs_clear_page_dirty(page);

	clear_buffer_uptodate(bh);
	clear_buffer_mapped(bh);
	bh->b_blocknr = -1;
	ClearPageUptodate(page);
	ClearPageMappedToDisk(page);
	unlock_buffer(bh);
	brelse(bh);
}

/**
 * nilfs_copy_buffer -- copy buffer data and flags
 * @dbh: destination buffer
 * @sbh: source buffer
 */
void nilfs_copy_buffer(struct buffer_head *dbh, struct buffer_head *sbh)
{
	void *kaddr0, *kaddr1;
	unsigned long bits;
	struct page *spage = sbh->b_page, *dpage = dbh->b_page;
	struct buffer_head *bh;

	kaddr0 = kmap_atomic(spage);
	kaddr1 = kmap_atomic(dpage);
	memcpy(kaddr1 + bh_offset(dbh), kaddr0 + bh_offset(sbh), sbh->b_size);
	kunmap_atomic(kaddr1);
	kunmap_atomic(kaddr0);

	dbh->b_state = sbh->b_state & NILFS_BUFFER_INHERENT_BITS;
	dbh->b_blocknr = sbh->b_blocknr;
	dbh->b_bdev = sbh->b_bdev;

	bh = dbh;
	bits = sbh->b_state & ((1UL << BH_Uptodate) | (1UL << BH_Mapped));
	while ((bh = bh->b_this_page) != dbh) {
		lock_buffer(bh);
		bits &= bh->b_state;
		unlock_buffer(bh);
	}
	if (bits & (1UL << BH_Uptodate))
		SetPageUptodate(dpage);
	else
		ClearPageUptodate(dpage);
	if (bits & (1UL << BH_Mapped))
		SetPageMappedToDisk(dpage);
	else
		ClearPageMappedToDisk(dpage);
}

/**
 * nilfs_page_buffers_clean - check if a page has dirty buffers or not.
 * @page: page to be checked
 *
 * nilfs_page_buffers_clean() returns zero if the page has dirty buffers.
 * Otherwise, it returns non-zero value.
 */
int nilfs_page_buffers_clean(struct page *page)
{
	struct buffer_head *bh, *head;

	bh = head = page_buffers(page);
	do {
		if (buffer_dirty(bh))
			return 0;
		bh = bh->b_this_page;
	} while (bh != head);
	return 1;
}

void nilfs_page_bug(struct page *page)
{
	struct address_space *m;
	unsigned long ino;

	if (unlikely(!page)) {
		printk(KERN_CRIT "NILFS_PAGE_BUG(NULL)\n");
		return;
	}

	m = page->mapping;
	ino = m ? m->host->i_ino : 0;

	printk(KERN_CRIT "NILFS_PAGE_BUG(%p): cnt=%d index#=%llu flags=0x%lx "
	       "mapping=%p ino=%lu\n",
	       page, atomic_read(&page->_count),
	       (unsigned long long)page->index, page->flags, m, ino);

	if (page_has_buffers(page)) {
		struct buffer_head *bh, *head;
		int i = 0;

		bh = head = page_buffers(page);
		do {
			printk(KERN_CRIT
			       " BH[%d] %p: cnt=%d block#=%llu state=0x%lx\n",
			       i++, bh, atomic_read(&bh->b_count),
			       (unsigned long long)bh->b_blocknr, bh->b_state);
			bh = bh->b_this_page;
		} while (bh != head);
	}
}

/**
 * nilfs_copy_page -- copy the page with buffers
 * @dst: destination page
 * @src: source page
 * @copy_dirty: flag whether to copy dirty states on the page's buffer heads.
 *
 * This function is for both data pages and btnode pages.  The dirty flag
 * should be treated by caller.  The page must not be under i/o.
 * Both src and dst page must be locked
 */
static void nilfs_copy_page(struct page *dst, struct page *src, int copy_dirty)
{
	struct buffer_head *dbh, *dbufs, *sbh, *sbufs;
	unsigned long mask = NILFS_BUFFER_INHERENT_BITS;

	BUG_ON(PageWriteback(dst));

	sbh = sbufs = page_buffers(src);
	if (!page_has_buffers(dst))
		create_empty_buffers(dst, sbh->b_size, 0);

	if (copy_dirty)
		mask |= (1UL << BH_Dirty);

	dbh = dbufs = page_buffers(dst);
	do {
		lock_buffer(sbh);
		lock_buffer(dbh);
		dbh->b_state = sbh->b_state & mask;
		dbh->b_blocknr = sbh->b_blocknr;
		dbh->b_bdev = sbh->b_bdev;
		sbh = sbh->b_this_page;
		dbh = dbh->b_this_page;
	} while (dbh != dbufs);

	copy_highpage(dst, src);

	if (PageUptodate(src) && !PageUptodate(dst))
		SetPageUptodate(dst);
	else if (!PageUptodate(src) && PageUptodate(dst))
		ClearPageUptodate(dst);
	if (PageMappedToDisk(src) && !PageMappedToDisk(dst))
		SetPageMappedToDisk(dst);
	else if (!PageMappedToDisk(src) && PageMappedToDisk(dst))
		ClearPageMappedToDisk(dst);

	do {
		unlock_buffer(sbh);
		unlock_buffer(dbh);
		sbh = sbh->b_this_page;
		dbh = dbh->b_this_page;
	} while (dbh != dbufs);
}

int nilfs_copy_dirty_pages(struct address_space *dmap,
			   struct address_space *smap)
{
	struct pagevec pvec;
	unsigned int i;
	pgoff_t index = 0;
	int err = 0;

	pagevec_init(&pvec, 0);
repeat:
	if (!pagevec_lookup_tag(&pvec, smap, &index, PAGECACHE_TAG_DIRTY,
				PAGEVEC_SIZE))
		return 0;

	for (i = 0; i < pagevec_count(&pvec); i++) {
		struct page *page = pvec.pages[i], *dpage;

		lock_page(page);
		if (unlikely(!PageDirty(page)))
			NILFS_PAGE_BUG(page, "inconsistent dirty state");

		dpage = grab_cache_page(dmap, page->index);
		if (unlikely(!dpage)) {
			/* No empty page is added to the page cache */
			err = -ENOMEM;
			unlock_page(page);
			break;
		}
		if (unlikely(!page_has_buffers(page)))
			NILFS_PAGE_BUG(page,
				       "found empty page in dat page cache");

		nilfs_copy_page(dpage, page, 1);
		__set_page_dirty_nobuffers(dpage);

		unlock_page(dpage);
		page_cache_release(dpage);
		unlock_page(page);
	}
	pagevec_release(&pvec);
	cond_resched();

	if (likely(!err))
		goto repeat;
	return err;
}

/**
 * nilfs_copy_back_pages -- copy back pages to original cache from shadow cache
 * @dmap: destination page cache
 * @smap: source page cache
 *
 * No pages must no be added to the cache during this process.
 * This must be ensured by the caller.
 */
void nilfs_copy_back_pages(struct address_space *dmap,
			   struct address_space *smap)
{
	struct pagevec pvec;
	unsigned int i, n;
	pgoff_t index = 0;
	int err;

	pagevec_init(&pvec, 0);
repeat:
	n = pagevec_lookup(&pvec, smap, index, PAGEVEC_SIZE);
	if (!n)
		return;
	index = pvec.pages[n - 1]->index + 1;

	for (i = 0; i < pagevec_count(&pvec); i++) {
		struct page *page = pvec.pages[i], *dpage;
		pgoff_t offset = page->index;

		lock_page(page);
		dpage = find_lock_page(dmap, offset);
		if (dpage) {
			/* override existing page on the destination cache */
			WARN_ON(PageDirty(dpage));
			nilfs_copy_page(dpage, page, 0);
			unlock_page(dpage);
			page_cache_release(dpage);
		} else {
			struct page *page2;

			/* move the page to the destination cache */
			spin_lock_irq(&smap->tree_lock);
			page2 = radix_tree_delete(&smap->page_tree, offset);
			WARN_ON(page2 != page);

			smap->nrpages--;
			spin_unlock_irq(&smap->tree_lock);

			spin_lock_irq(&dmap->tree_lock);
			err = radix_tree_insert(&dmap->page_tree, offset, page);
			if (unlikely(err < 0)) {
				WARN_ON(err == -EEXIST);
				page->mapping = NULL;
				page_cache_release(page); /* for cache */
			} else {
				page->mapping = dmap;
				dmap->nrpages++;
				if (PageDirty(page))
					radix_tree_tag_set(&dmap->page_tree,
							   offset,
							   PAGECACHE_TAG_DIRTY);
			}
			spin_unlock_irq(&dmap->tree_lock);
		}
		unlock_page(page);
	}
	pagevec_release(&pvec);
	cond_resched();

	goto repeat;
}

/**
 * nilfs_clear_dirty_pages - discard dirty pages in address space
 * @mapping: address space with dirty pages for discarding
 * @silent: suppress [true] or print [false] warning messages
 */
void nilfs_clear_dirty_pages(struct address_space *mapping, bool silent)
{
	struct pagevec pvec;
	unsigned int i;
	pgoff_t index = 0;

	pagevec_init(&pvec, 0);

	while (pagevec_lookup_tag(&pvec, mapping, &index, PAGECACHE_TAG_DIRTY,
				  PAGEVEC_SIZE)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			lock_page(page);
			nilfs_clear_dirty_page(page, silent);
			unlock_page(page);
		}
		pagevec_release(&pvec);
		cond_resched();
	}
}

/**
 * nilfs_clear_dirty_page - discard dirty page
 * @page: dirty page that will be discarded
 * @silent: suppress [true] or print [false] warning messages
 */
void nilfs_clear_dirty_page(struct page *page, bool silent)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;

	BUG_ON(!PageLocked(page));

	if (!silent) {
		nilfs_warning(sb, __func__,
				"discard page: offset %lld, ino %lu",
				page_offset(page), inode->i_ino);
	}

	ClearPageUptodate(page);
	ClearPageMappedToDisk(page);

	if (page_has_buffers(page)) {
		struct buffer_head *bh, *head;

		bh = head = page_buffers(page);
		do {
			lock_buffer(bh);
			if (!silent) {
				nilfs_warning(sb, __func__,
					"discard block %llu, size %zu",
					(u64)bh->b_blocknr, bh->b_size);
			}
			clear_buffer_async_write(bh);
			clear_buffer_dirty(bh);
			clear_buffer_nilfs_volatile(bh);
			clear_buffer_nilfs_checked(bh);
			clear_buffer_nilfs_redirected(bh);
			clear_buffer_uptodate(bh);
			clear_buffer_mapped(bh);
			unlock_buffer(bh);
		} while (bh = bh->b_this_page, bh != head);
	}

	__nilfs_clear_page_dirty(page);
}

unsigned nilfs_page_count_clean_buffers(struct page *page,
					unsigned from, unsigned to)
{
	unsigned block_start, block_end;
	struct buffer_head *bh, *head;
	unsigned nc = 0;

	for (bh = head = page_buffers(page), block_start = 0;
	     bh != head || !block_start;
	     block_start = block_end, bh = bh->b_this_page) {
		block_end = block_start + bh->b_size;
		if (block_end > from && block_start < to && !buffer_dirty(bh))
			nc++;
	}
	return nc;
}

void nilfs_mapping_init(struct address_space *mapping, struct inode *inode,
			struct backing_dev_info *bdi)
{
	mapping->host = inode;
	mapping->flags = 0;
	mapping_set_gfp_mask(mapping, GFP_NOFS);
	mapping->private_data = NULL;
	mapping->backing_dev_info = bdi;
	mapping->a_ops = &empty_aops;
}

/*
 * NILFS2 needs clear_page_dirty() in the following two cases:
 *
 * 1) For B-tree node pages and data pages of the dat/gcdat, NILFS2 clears
 *    page dirty flags when it copies back pages from the shadow cache
 *    (gcdat->{i_mapping,i_btnode_cache}) to its original cache
 *    (dat->{i_mapping,i_btnode_cache}).
 *
 * 2) Some B-tree operations like insertion or deletion may dispose buffers
 *    in dirty state, and this needs to cancel the dirty state of their pages.
 */
int __nilfs_clear_page_dirty(struct page *page)
{
	struct address_space *mapping = page->mapping;

	if (mapping) {
		spin_lock_irq(&mapping->tree_lock);
		if (test_bit(PG_dirty, &page->flags)) {
			radix_tree_tag_clear(&mapping->page_tree,
					     page_index(page),
					     PAGECACHE_TAG_DIRTY);
			spin_unlock_irq(&mapping->tree_lock);
			return clear_page_dirty_for_io(page);
		}
		spin_unlock_irq(&mapping->tree_lock);
		return 0;
	}
	return TestClearPageDirty(page);
}

/**
 * nilfs_find_uncommitted_extent - find extent of uncommitted data
 * @inode: inode
 * @start_blk: start block offset (in)
 * @blkoff: start offset of the found extent (out)
 *
 * This function searches an extent of buffers marked "delayed" which
 * starts from a block offset equal to or larger than @start_blk.  If
 * such an extent was found, this will store the start offset in
 * @blkoff and return its length in blocks.  Otherwise, zero is
 * returned.
 */
unsigned long nilfs_find_uncommitted_extent(struct inode *inode,
					    sector_t start_blk,
					    sector_t *blkoff)
{
	unsigned int i;
	pgoff_t index;
	unsigned int nblocks_in_page;
	unsigned long length = 0;
	sector_t b;
	struct pagevec pvec;
	struct page *page;

	if (inode->i_mapping->nrpages == 0)
		return 0;

	index = start_blk >> (PAGE_CACHE_SHIFT - inode->i_blkbits);
	nblocks_in_page = 1U << (PAGE_CACHE_SHIFT - inode->i_blkbits);

	pagevec_init(&pvec, 0);

repeat:
	pvec.nr = find_get_pages_contig(inode->i_mapping, index, PAGEVEC_SIZE,
					pvec.pages);
	if (pvec.nr == 0)
		return length;

	if (length > 0 && pvec.pages[0]->index > index)
		goto out;

	b = pvec.pages[0]->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	i = 0;
	do {
		page = pvec.pages[i];

		lock_page(page);
		if (page_has_buffers(page)) {
			struct buffer_head *bh, *head;

			bh = head = page_buffers(page);
			do {
				if (b < start_blk)
					continue;
				if (buffer_delay(bh)) {
					if (length == 0)
						*blkoff = b;
					length++;
				} else if (length > 0) {
					goto out_locked;
				}
			} while (++b, bh = bh->b_this_page, bh != head);
		} else {
			if (length > 0)
				goto out_locked;

			b += nblocks_in_page;
		}
		unlock_page(page);

	} while (++i < pagevec_count(&pvec));

	index = page->index + 1;
	pagevec_release(&pvec);
	cond_resched();
	goto repeat;

out_locked:
	unlock_page(page);
out:
	pagevec_release(&pvec);
	return length;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/page.c */
/************************************************************/
/*
 * mdt.c - meta data file for NILFS
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 */

// #include <linux/buffer_head.h>
// #include <linux/mpage.h>
// #include <linux/mm.h>
// #include <linux/writeback.h>
#include <linux/backing-dev.h>
// #include <linux/swap.h>
// #include <linux/slab.h>
// #include "nilfs.h"
// #include "btnode.h"
// #include "segment.h"
// #include "page.h"
// #include "mdt.h"


#define NILFS_MDT_MAX_RA_BLOCKS		(16 - 1)


static int
nilfs_mdt_insert_new_block(struct inode *inode, unsigned long block,
			   struct buffer_head *bh,
			   void (*init_block)(struct inode *,
					      struct buffer_head *, void *))
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	void *kaddr;
	int ret;

	/* Caller exclude read accesses using page lock */

	/* set_buffer_new(bh); */
	bh->b_blocknr = 0;

	ret = nilfs_bmap_insert(ii->i_bmap, block, (unsigned long)bh);
	if (unlikely(ret))
		return ret;

	set_buffer_mapped(bh);

	kaddr = kmap_atomic(bh->b_page);
	memset(kaddr + bh_offset(bh), 0, 1 << inode->i_blkbits);
	if (init_block)
		init_block(inode, bh, kaddr);
	flush_dcache_page(bh->b_page);
	kunmap_atomic(kaddr);

	set_buffer_uptodate(bh);
	mark_buffer_dirty(bh);
	nilfs_mdt_mark_dirty(inode);
	return 0;
}

static int nilfs_mdt_create_block(struct inode *inode, unsigned long block,
				  struct buffer_head **out_bh,
				  void (*init_block)(struct inode *,
						     struct buffer_head *,
						     void *))
{
	struct super_block *sb = inode->i_sb;
	struct nilfs_transaction_info ti;
	struct buffer_head *bh;
	int err;

	nilfs_transaction_begin(sb, &ti, 0);

	err = -ENOMEM;
	bh = nilfs_grab_buffer(inode, inode->i_mapping, block, 0);
	if (unlikely(!bh))
		goto failed_unlock;

	err = -EEXIST;
	if (buffer_uptodate(bh))
		goto failed_bh;

	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		goto failed_bh;

	bh->b_bdev = sb->s_bdev;
	err = nilfs_mdt_insert_new_block(inode, block, bh, init_block);
	if (likely(!err)) {
		get_bh(bh);
		*out_bh = bh;
	}

 failed_bh:
	unlock_page(bh->b_page);
	page_cache_release(bh->b_page);
	brelse(bh);

 failed_unlock:
	if (likely(!err))
		err = nilfs_transaction_commit(sb);
	else
		nilfs_transaction_abort(sb);

	return err;
}

static int
nilfs_mdt_submit_block(struct inode *inode, unsigned long blkoff,
		       int mode, struct buffer_head **out_bh)
{
	struct buffer_head *bh;
	__u64 blknum = 0;
	int ret = -ENOMEM;

	bh = nilfs_grab_buffer(inode, inode->i_mapping, blkoff, 0);
	if (unlikely(!bh))
		goto failed;

	ret = -EEXIST; /* internal code */
	if (buffer_uptodate(bh))
		goto out;

	if (mode == READA) {
		if (!trylock_buffer(bh)) {
			ret = -EBUSY;
			goto failed_bh;
		}
	} else /* mode == READ */
		lock_buffer(bh);

	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		goto out;
	}

	ret = nilfs_bmap_lookup(NILFS_I(inode)->i_bmap, blkoff, &blknum);
	if (unlikely(ret)) {
		unlock_buffer(bh);
		goto failed_bh;
	}
	map_bh(bh, inode->i_sb, (sector_t)blknum);

	bh->b_end_io = end_buffer_read_sync;
	get_bh(bh);
	submit_bh(mode, bh);
	ret = 0;
 out:
	get_bh(bh);
	*out_bh = bh;

 failed_bh:
	unlock_page(bh->b_page);
	page_cache_release(bh->b_page);
	brelse(bh);
 failed:
	return ret;
}

static int nilfs_mdt_read_block(struct inode *inode, unsigned long block,
				int readahead, struct buffer_head **out_bh)
{
	struct buffer_head *first_bh, *bh;
	unsigned long blkoff;
	int i, nr_ra_blocks = NILFS_MDT_MAX_RA_BLOCKS;
	int err;

	err = nilfs_mdt_submit_block(inode, block, READ, &first_bh);
	if (err == -EEXIST) /* internal code */
		goto out;

	if (unlikely(err))
		goto failed;

	if (readahead) {
		blkoff = block + 1;
		for (i = 0; i < nr_ra_blocks; i++, blkoff++) {
			err = nilfs_mdt_submit_block(inode, blkoff, READA, &bh);
			if (likely(!err || err == -EEXIST))
				brelse(bh);
			else if (err != -EBUSY)
				break;
				/* abort readahead if bmap lookup failed */
			if (!buffer_locked(first_bh))
				goto out_no_wait;
		}
	}

	wait_on_buffer(first_bh);

 out_no_wait:
	err = -EIO;
	if (!buffer_uptodate(first_bh))
		goto failed_bh;
 out:
	*out_bh = first_bh;
	return 0;

 failed_bh:
	brelse(first_bh);
 failed:
	return err;
}

/**
 * nilfs_mdt_get_block - read or create a buffer on meta data file.
 * @inode: inode of the meta data file
 * @blkoff: block offset
 * @create: create flag
 * @init_block: initializer used for newly allocated block
 * @out_bh: output of a pointer to the buffer_head
 *
 * nilfs_mdt_get_block() looks up the specified buffer and tries to create
 * a new buffer if @create is not zero.  On success, the returned buffer is
 * assured to be either existing or formatted using a buffer lock on success.
 * @out_bh is substituted only when zero is returned.
 *
 * Return Value: On success, it returns 0. On error, the following negative
 * error code is returned.
 *
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 *
 * %-ENOENT - the specified block does not exist (hole block)
 *
 * %-EROFS - Read only filesystem (for create mode)
 */
int nilfs_mdt_get_block(struct inode *inode, unsigned long blkoff, int create,
			void (*init_block)(struct inode *,
					   struct buffer_head *, void *),
			struct buffer_head **out_bh)
{
	int ret;

	/* Should be rewritten with merging nilfs_mdt_read_block() */
 retry:
	ret = nilfs_mdt_read_block(inode, blkoff, !create, out_bh);
	if (!create || ret != -ENOENT)
		return ret;

	ret = nilfs_mdt_create_block(inode, blkoff, out_bh, init_block);
	if (unlikely(ret == -EEXIST)) {
		/* create = 0; */  /* limit read-create loop retries */
		goto retry;
	}
	return ret;
}

/**
 * nilfs_mdt_delete_block - make a hole on the meta data file.
 * @inode: inode of the meta data file
 * @block: block offset
 *
 * Return Value: On success, zero is returned.
 * On error, one of the following negative error code is returned.
 *
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 */
int nilfs_mdt_delete_block(struct inode *inode, unsigned long block)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	int err;

	err = nilfs_bmap_delete(ii->i_bmap, block);
	if (!err || err == -ENOENT) {
		nilfs_mdt_mark_dirty(inode);
		nilfs_mdt_forget_block(inode, block);
	}
	return err;
}

/**
 * nilfs_mdt_forget_block - discard dirty state and try to remove the page
 * @inode: inode of the meta data file
 * @block: block offset
 *
 * nilfs_mdt_forget_block() clears a dirty flag of the specified buffer, and
 * tries to release the page including the buffer from a page cache.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error code is returned.
 *
 * %-EBUSY - page has an active buffer.
 *
 * %-ENOENT - page cache has no page addressed by the offset.
 */
int nilfs_mdt_forget_block(struct inode *inode, unsigned long block)
{
	pgoff_t index = (pgoff_t)block >>
		(PAGE_CACHE_SHIFT - inode->i_blkbits);
	struct page *page;
	unsigned long first_block;
	int ret = 0;
	int still_dirty;

	page = find_lock_page(inode->i_mapping, index);
	if (!page)
		return -ENOENT;

	wait_on_page_writeback(page);

	first_block = (unsigned long)index <<
		(PAGE_CACHE_SHIFT - inode->i_blkbits);
	if (page_has_buffers(page)) {
		struct buffer_head *bh;

		bh = nilfs_page_get_nth_block(page, block - first_block);
		nilfs_forget_buffer(bh);
	}
	still_dirty = PageDirty(page);
	unlock_page(page);
	page_cache_release(page);

	if (still_dirty ||
	    invalidate_inode_pages2_range(inode->i_mapping, index, index) != 0)
		ret = -EBUSY;
	return ret;
}

/**
 * nilfs_mdt_mark_block_dirty - mark a block on the meta data file dirty.
 * @inode: inode of the meta data file
 * @block: block offset
 *
 * Return Value: On success, it returns 0. On error, the following negative
 * error code is returned.
 *
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 *
 * %-ENOENT - the specified block does not exist (hole block)
 */
int nilfs_mdt_mark_block_dirty(struct inode *inode, unsigned long block)
{
	struct buffer_head *bh;
	int err;

	err = nilfs_mdt_read_block(inode, block, 0, &bh);
	if (unlikely(err))
		return err;
	mark_buffer_dirty(bh);
	nilfs_mdt_mark_dirty(inode);
	brelse(bh);
	return 0;
}

int nilfs_mdt_fetch_dirty(struct inode *inode)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);

	if (nilfs_bmap_test_and_clear_dirty(ii->i_bmap)) {
		set_bit(NILFS_I_DIRTY, &ii->i_state);
		return 1;
	}
	return test_bit(NILFS_I_DIRTY, &ii->i_state);
}

static int
nilfs_mdt_write_page(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb;
	int err = 0;

	if (inode && (inode->i_sb->s_flags & MS_RDONLY)) {
		/*
		 * It means that filesystem was remounted in read-only
		 * mode because of error or metadata corruption. But we
		 * have dirty pages that try to be flushed in background.
		 * So, here we simply discard this dirty page.
		 */
		nilfs_clear_dirty_page(page, false);
		unlock_page(page);
		return -EROFS;
	}

	redirty_page_for_writepage(wbc, page);
	unlock_page(page);

	if (!inode)
		return 0;

	sb = inode->i_sb;

	if (wbc->sync_mode == WB_SYNC_ALL)
		err = nilfs_construct_segment(sb);
	else if (wbc->for_reclaim)
		nilfs_flush_segment(sb, inode->i_ino);

	return err;
}


static const struct address_space_operations def_mdt_aops = {
	.writepage		= nilfs_mdt_write_page,
};

static const struct inode_operations def_mdt_iops;
static const struct file_operations def_mdt_fops;


int nilfs_mdt_init(struct inode *inode, gfp_t gfp_mask, size_t objsz)
{
	struct nilfs_mdt_info *mi;

	mi = kzalloc(max(sizeof(*mi), objsz), GFP_NOFS);
	if (!mi)
		return -ENOMEM;

	init_rwsem(&mi->mi_sem);
	inode->i_private = mi;

	inode->i_mode = S_IFREG;
	mapping_set_gfp_mask(inode->i_mapping, gfp_mask);
	inode->i_mapping->backing_dev_info = inode->i_sb->s_bdi;

	inode->i_op = &def_mdt_iops;
	inode->i_fop = &def_mdt_fops;
	inode->i_mapping->a_ops = &def_mdt_aops;

	return 0;
}

void nilfs_mdt_set_entry_size(struct inode *inode, unsigned entry_size,
			      unsigned header_size)
{
	struct nilfs_mdt_info *mi = NILFS_MDT(inode);

	mi->mi_entry_size = entry_size;
	mi->mi_entries_per_block = (1 << inode->i_blkbits) / entry_size;
	mi->mi_first_entry_offset = DIV_ROUND_UP(header_size, entry_size);
}

/**
 * nilfs_mdt_setup_shadow_map - setup shadow map and bind it to metadata file
 * @inode: inode of the metadata file
 * @shadow: shadow mapping
 */
int nilfs_mdt_setup_shadow_map(struct inode *inode,
			       struct nilfs_shadow_map *shadow)
{
	struct nilfs_mdt_info *mi = NILFS_MDT(inode);
	struct backing_dev_info *bdi = inode->i_sb->s_bdi;

	INIT_LIST_HEAD(&shadow->frozen_buffers);
	address_space_init_once(&shadow->frozen_data);
	nilfs_mapping_init(&shadow->frozen_data, inode, bdi);
	address_space_init_once(&shadow->frozen_btnodes);
	nilfs_mapping_init(&shadow->frozen_btnodes, inode, bdi);
	mi->mi_shadow = shadow;
	return 0;
}

/**
 * nilfs_mdt_save_to_shadow_map - copy bmap and dirty pages to shadow map
 * @inode: inode of the metadata file
 */
int nilfs_mdt_save_to_shadow_map(struct inode *inode)
{
	struct nilfs_mdt_info *mi = NILFS_MDT(inode);
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct nilfs_shadow_map *shadow = mi->mi_shadow;
	int ret;

	ret = nilfs_copy_dirty_pages(&shadow->frozen_data, inode->i_mapping);
	if (ret)
		goto out;

	ret = nilfs_copy_dirty_pages(&shadow->frozen_btnodes,
				     &ii->i_btnode_cache);
	if (ret)
		goto out;

	nilfs_bmap_save(ii->i_bmap, &shadow->bmap_store);
 out:
	return ret;
}

int nilfs_mdt_freeze_buffer(struct inode *inode, struct buffer_head *bh)
{
	struct nilfs_shadow_map *shadow = NILFS_MDT(inode)->mi_shadow;
	struct buffer_head *bh_frozen;
	struct page *page;
	int blkbits = inode->i_blkbits;

	page = grab_cache_page(&shadow->frozen_data, bh->b_page->index);
	if (!page)
		return -ENOMEM;

	if (!page_has_buffers(page))
		create_empty_buffers(page, 1 << blkbits, 0);

	bh_frozen = nilfs_page_get_nth_block(page, bh_offset(bh) >> blkbits);

	if (!buffer_uptodate(bh_frozen))
		nilfs_copy_buffer(bh_frozen, bh);
	if (list_empty(&bh_frozen->b_assoc_buffers)) {
		list_add_tail(&bh_frozen->b_assoc_buffers,
			      &shadow->frozen_buffers);
		set_buffer_nilfs_redirected(bh);
	} else {
		brelse(bh_frozen); /* already frozen */
	}

	unlock_page(page);
	page_cache_release(page);
	return 0;
}

struct buffer_head *
nilfs_mdt_get_frozen_buffer(struct inode *inode, struct buffer_head *bh)
{
	struct nilfs_shadow_map *shadow = NILFS_MDT(inode)->mi_shadow;
	struct buffer_head *bh_frozen = NULL;
	struct page *page;
	int n;

	page = find_lock_page(&shadow->frozen_data, bh->b_page->index);
	if (page) {
		if (page_has_buffers(page)) {
			n = bh_offset(bh) >> inode->i_blkbits;
			bh_frozen = nilfs_page_get_nth_block(page, n);
		}
		unlock_page(page);
		page_cache_release(page);
	}
	return bh_frozen;
}

static void nilfs_release_frozen_buffers(struct nilfs_shadow_map *shadow)
{
	struct list_head *head = &shadow->frozen_buffers;
	struct buffer_head *bh;

	while (!list_empty(head)) {
		bh = list_first_entry(head, struct buffer_head,
				      b_assoc_buffers);
		list_del_init(&bh->b_assoc_buffers);
		brelse(bh); /* drop ref-count to make it releasable */
	}
}

/**
 * nilfs_mdt_restore_from_shadow_map - restore dirty pages and bmap state
 * @inode: inode of the metadata file
 */
void nilfs_mdt_restore_from_shadow_map(struct inode *inode)
{
	struct nilfs_mdt_info *mi = NILFS_MDT(inode);
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct nilfs_shadow_map *shadow = mi->mi_shadow;

	down_write(&mi->mi_sem);

	if (mi->mi_palloc_cache)
		nilfs_palloc_clear_cache(inode);

	nilfs_clear_dirty_pages(inode->i_mapping, true);
	nilfs_copy_back_pages(inode->i_mapping, &shadow->frozen_data);

	nilfs_clear_dirty_pages(&ii->i_btnode_cache, true);
	nilfs_copy_back_pages(&ii->i_btnode_cache, &shadow->frozen_btnodes);

	nilfs_bmap_restore(ii->i_bmap, &shadow->bmap_store);

	up_write(&mi->mi_sem);
}

/**
 * nilfs_mdt_clear_shadow_map - truncate pages in shadow map caches
 * @inode: inode of the metadata file
 */
void nilfs_mdt_clear_shadow_map(struct inode *inode)
{
	struct nilfs_mdt_info *mi = NILFS_MDT(inode);
	struct nilfs_shadow_map *shadow = mi->mi_shadow;

	down_write(&mi->mi_sem);
	nilfs_release_frozen_buffers(shadow);
	truncate_inode_pages(&shadow->frozen_data, 0);
	truncate_inode_pages(&shadow->frozen_btnodes, 0);
	up_write(&mi->mi_sem);
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/mdt.c */
/************************************************************/
/*
 * btnode.c - NILFS B-tree node cache
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * This file was originally written by Seiji Kihara <kihara@osrg.net>
 * and fully revised by Ryusuke Konishi <ryusuke@osrg.net> for
 * stabilization and simplification.
 *
 */

#include <linux/types.h>
// #include <linux/buffer_head.h>
// #include <linux/mm.h>
// #include <linux/backing-dev.h>
// #include <linux/gfp.h>
// #include "nilfs.h"
// #include "mdt.h"
// #include "dat.h"
// #include "page.h"
// #include "btnode.h"

void nilfs_btnode_cache_clear(struct address_space *btnc)
{
	invalidate_mapping_pages(btnc, 0, -1);
	truncate_inode_pages(btnc, 0);
}

struct buffer_head *
nilfs_btnode_create_block(struct address_space *btnc, __u64 blocknr)
{
	struct inode *inode = NILFS_BTNC_I(btnc);
	struct buffer_head *bh;

	bh = nilfs_grab_buffer(inode, btnc, blocknr, 1 << BH_NILFS_Node);
	if (unlikely(!bh))
		return NULL;

	if (unlikely(buffer_mapped(bh) || buffer_uptodate(bh) ||
		     buffer_dirty(bh))) {
		brelse(bh);
		BUG();
	}
	memset(bh->b_data, 0, 1 << inode->i_blkbits);
	bh->b_bdev = inode->i_sb->s_bdev;
	bh->b_blocknr = blocknr;
	set_buffer_mapped(bh);
	set_buffer_uptodate(bh);

	unlock_page(bh->b_page);
	page_cache_release(bh->b_page);
	return bh;
}

int nilfs_btnode_submit_block(struct address_space *btnc, __u64 blocknr,
			      sector_t pblocknr, int mode,
			      struct buffer_head **pbh, sector_t *submit_ptr)
{
	struct buffer_head *bh;
	struct inode *inode = NILFS_BTNC_I(btnc);
	struct page *page;
	int err;

	bh = nilfs_grab_buffer(inode, btnc, blocknr, 1 << BH_NILFS_Node);
	if (unlikely(!bh))
		return -ENOMEM;

	err = -EEXIST; /* internal code */
	page = bh->b_page;

	if (buffer_uptodate(bh) || buffer_dirty(bh))
		goto found;

	if (pblocknr == 0) {
		pblocknr = blocknr;
		if (inode->i_ino != NILFS_DAT_INO) {
			struct the_nilfs *nilfs = inode->i_sb->s_fs_info;

			/* blocknr is a virtual block number */
			err = nilfs_dat_translate(nilfs->ns_dat, blocknr,
						  &pblocknr);
			if (unlikely(err)) {
				brelse(bh);
				goto out_locked;
			}
		}
	}

	if (mode == READA) {
		if (pblocknr != *submit_ptr + 1 || !trylock_buffer(bh)) {
			err = -EBUSY; /* internal code */
			brelse(bh);
			goto out_locked;
		}
	} else { /* mode == READ */
		lock_buffer(bh);
	}
	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		err = -EEXIST; /* internal code */
		goto found;
	}
	set_buffer_mapped(bh);
	bh->b_bdev = inode->i_sb->s_bdev;
	bh->b_blocknr = pblocknr; /* set block address for read */
	bh->b_end_io = end_buffer_read_sync;
	get_bh(bh);
	submit_bh(mode, bh);
	bh->b_blocknr = blocknr; /* set back to the given block address */
	*submit_ptr = pblocknr;
	err = 0;
found:
	*pbh = bh;

out_locked:
	unlock_page(page);
	page_cache_release(page);
	return err;
}

/**
 * nilfs_btnode_delete - delete B-tree node buffer
 * @bh: buffer to be deleted
 *
 * nilfs_btnode_delete() invalidates the specified buffer and delete the page
 * including the buffer if the page gets unbusy.
 */
void nilfs_btnode_delete(struct buffer_head *bh)
{
	struct address_space *mapping;
	struct page *page = bh->b_page;
	pgoff_t index = page_index(page);
	int still_dirty;

	page_cache_get(page);
	lock_page(page);
	wait_on_page_writeback(page);

	nilfs_forget_buffer(bh);
	still_dirty = PageDirty(page);
	mapping = page->mapping;
	unlock_page(page);
	page_cache_release(page);

	if (!still_dirty && mapping)
		invalidate_inode_pages2_range(mapping, index, index);
}

/**
 * nilfs_btnode_prepare_change_key
 *  prepare to move contents of the block for old key to one of new key.
 *  the old buffer will not be removed, but might be reused for new buffer.
 *  it might return -ENOMEM because of memory allocation errors,
 *  and might return -EIO because of disk read errors.
 */
int nilfs_btnode_prepare_change_key(struct address_space *btnc,
				    struct nilfs_btnode_chkey_ctxt *ctxt)
{
	struct buffer_head *obh, *nbh;
	struct inode *inode = NILFS_BTNC_I(btnc);
	__u64 oldkey = ctxt->oldkey, newkey = ctxt->newkey;
	int err;

	if (oldkey == newkey)
		return 0;

	obh = ctxt->bh;
	ctxt->newbh = NULL;

	if (inode->i_blkbits == PAGE_CACHE_SHIFT) {
		lock_page(obh->b_page);
		/*
		 * We cannot call radix_tree_preload for the kernels older
		 * than 2.6.23, because it is not exported for modules.
		 */
retry:
		err = radix_tree_preload(GFP_NOFS & ~__GFP_HIGHMEM);
		if (err)
			goto failed_unlock;
		/* BUG_ON(oldkey != obh->b_page->index); */
		if (unlikely(oldkey != obh->b_page->index))
			NILFS_PAGE_BUG(obh->b_page,
				       "invalid oldkey %lld (newkey=%lld)",
				       (unsigned long long)oldkey,
				       (unsigned long long)newkey);

		spin_lock_irq(&btnc->tree_lock);
		err = radix_tree_insert(&btnc->page_tree, newkey, obh->b_page);
		spin_unlock_irq(&btnc->tree_lock);
		/*
		 * Note: page->index will not change to newkey until
		 * nilfs_btnode_commit_change_key() will be called.
		 * To protect the page in intermediate state, the page lock
		 * is held.
		 */
		radix_tree_preload_end();
		if (!err)
			return 0;
		else if (err != -EEXIST)
			goto failed_unlock;

		err = invalidate_inode_pages2_range(btnc, newkey, newkey);
		if (!err)
			goto retry;
		/* fallback to copy mode */
		unlock_page(obh->b_page);
	}

	nbh = nilfs_btnode_create_block(btnc, newkey);
	if (!nbh)
		return -ENOMEM;

	BUG_ON(nbh == obh);
	ctxt->newbh = nbh;
	return 0;

 failed_unlock:
	unlock_page(obh->b_page);
	return err;
}

/**
 * nilfs_btnode_commit_change_key
 *  commit the change_key operation prepared by prepare_change_key().
 */
void nilfs_btnode_commit_change_key(struct address_space *btnc,
				    struct nilfs_btnode_chkey_ctxt *ctxt)
{
	struct buffer_head *obh = ctxt->bh, *nbh = ctxt->newbh;
	__u64 oldkey = ctxt->oldkey, newkey = ctxt->newkey;
	struct page *opage;

	if (oldkey == newkey)
		return;

	if (nbh == NULL) {	/* blocksize == pagesize */
		opage = obh->b_page;
		if (unlikely(oldkey != opage->index))
			NILFS_PAGE_BUG(opage,
				       "invalid oldkey %lld (newkey=%lld)",
				       (unsigned long long)oldkey,
				       (unsigned long long)newkey);
		mark_buffer_dirty(obh);

		spin_lock_irq(&btnc->tree_lock);
		radix_tree_delete(&btnc->page_tree, oldkey);
		radix_tree_tag_set(&btnc->page_tree, newkey,
				   PAGECACHE_TAG_DIRTY);
		spin_unlock_irq(&btnc->tree_lock);

		opage->index = obh->b_blocknr = newkey;
		unlock_page(opage);
	} else {
		nilfs_copy_buffer(nbh, obh);
		mark_buffer_dirty(nbh);

		nbh->b_blocknr = newkey;
		ctxt->bh = nbh;
		nilfs_btnode_delete(obh); /* will decrement bh->b_count */
	}
}

/**
 * nilfs_btnode_abort_change_key
 *  abort the change_key operation prepared by prepare_change_key().
 */
void nilfs_btnode_abort_change_key(struct address_space *btnc,
				   struct nilfs_btnode_chkey_ctxt *ctxt)
{
	struct buffer_head *nbh = ctxt->newbh;
	__u64 oldkey = ctxt->oldkey, newkey = ctxt->newkey;

	if (oldkey == newkey)
		return;

	if (nbh == NULL) {	/* blocksize == pagesize */
		spin_lock_irq(&btnc->tree_lock);
		radix_tree_delete(&btnc->page_tree, newkey);
		spin_unlock_irq(&btnc->tree_lock);
		unlock_page(ctxt->bh->b_page);
	} else
		brelse(nbh);
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/btnode.c */
/************************************************************/
/*
 * bmap.c - NILFS block mapping.
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Koji Sato <koji@osrg.net>.
 */

// #include <linux/fs.h>
// #include <linux/string.h>
#include <linux/errno.h>
// #include "nilfs.h"
#include "bmap.h"
// #include "btree.h"
#include "direct.h"
// #include "btnode.h"
// #include "mdt.h"
// #include "dat.h"
// #include "alloc.h"

struct inode *nilfs_bmap_get_dat(const struct nilfs_bmap *bmap)
{
	struct the_nilfs *nilfs = bmap->b_inode->i_sb->s_fs_info;

	return nilfs->ns_dat;
}

static int nilfs_bmap_convert_error(struct nilfs_bmap *bmap,
				     const char *fname, int err)
{
	struct inode *inode = bmap->b_inode;

	if (err == -EINVAL) {
		nilfs_error(inode->i_sb, fname,
			    "broken bmap (inode number=%lu)\n", inode->i_ino);
		err = -EIO;
	}
	return err;
}

/**
 * nilfs_bmap_lookup_at_level - find a data block or node block
 * @bmap: bmap
 * @key: key
 * @level: level
 * @ptrp: place to store the value associated to @key
 *
 * Description: nilfs_bmap_lookup_at_level() finds a record whose key
 * matches @key in the block at @level of the bmap.
 *
 * Return Value: On success, 0 is returned and the record associated with @key
 * is stored in the place pointed by @ptrp. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - A record associated with @key does not exist.
 */
int nilfs_bmap_lookup_at_level(struct nilfs_bmap *bmap, __u64 key, int level,
			       __u64 *ptrp)
{
	sector_t blocknr;
	int ret;

	down_read(&bmap->b_sem);
	ret = bmap->b_ops->bop_lookup(bmap, key, level, ptrp);
	if (ret < 0) {
		ret = nilfs_bmap_convert_error(bmap, __func__, ret);
		goto out;
	}
	if (NILFS_BMAP_USE_VBN(bmap)) {
		ret = nilfs_dat_translate(nilfs_bmap_get_dat(bmap), *ptrp,
					  &blocknr);
		if (!ret)
			*ptrp = blocknr;
	}

 out:
	up_read(&bmap->b_sem);
	return ret;
}

int nilfs_bmap_lookup_contig(struct nilfs_bmap *bmap, __u64 key, __u64 *ptrp,
			     unsigned maxblocks)
{
	int ret;

	down_read(&bmap->b_sem);
	ret = bmap->b_ops->bop_lookup_contig(bmap, key, ptrp, maxblocks);
	up_read(&bmap->b_sem);

	return nilfs_bmap_convert_error(bmap, __func__, ret);
}

static int nilfs_bmap_do_insert(struct nilfs_bmap *bmap, __u64 key, __u64 ptr)
{
	__u64 keys[NILFS_BMAP_SMALL_HIGH + 1];
	__u64 ptrs[NILFS_BMAP_SMALL_HIGH + 1];
	int ret, n;

	if (bmap->b_ops->bop_check_insert != NULL) {
		ret = bmap->b_ops->bop_check_insert(bmap, key);
		if (ret > 0) {
			n = bmap->b_ops->bop_gather_data(
				bmap, keys, ptrs, NILFS_BMAP_SMALL_HIGH + 1);
			if (n < 0)
				return n;
			ret = nilfs_btree_convert_and_insert(
				bmap, key, ptr, keys, ptrs, n);
			if (ret == 0)
				bmap->b_u.u_flags |= NILFS_BMAP_LARGE;

			return ret;
		} else if (ret < 0)
			return ret;
	}

	return bmap->b_ops->bop_insert(bmap, key, ptr);
}

/**
 * nilfs_bmap_insert - insert a new key-record pair into a bmap
 * @bmap: bmap
 * @key: key
 * @rec: record
 *
 * Description: nilfs_bmap_insert() inserts the new key-record pair specified
 * by @key and @rec into @bmap.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EEXIST - A record associated with @key already exist.
 */
int nilfs_bmap_insert(struct nilfs_bmap *bmap,
		      unsigned long key,
		      unsigned long rec)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = nilfs_bmap_do_insert(bmap, key, rec);
	up_write(&bmap->b_sem);

	return nilfs_bmap_convert_error(bmap, __func__, ret);
}

static int nilfs_bmap_do_delete(struct nilfs_bmap *bmap, __u64 key)
{
	__u64 keys[NILFS_BMAP_LARGE_LOW + 1];
	__u64 ptrs[NILFS_BMAP_LARGE_LOW + 1];
	int ret, n;

	if (bmap->b_ops->bop_check_delete != NULL) {
		ret = bmap->b_ops->bop_check_delete(bmap, key);
		if (ret > 0) {
			n = bmap->b_ops->bop_gather_data(
				bmap, keys, ptrs, NILFS_BMAP_LARGE_LOW + 1);
			if (n < 0)
				return n;
			ret = nilfs_direct_delete_and_convert(
				bmap, key, keys, ptrs, n);
			if (ret == 0)
				bmap->b_u.u_flags &= ~NILFS_BMAP_LARGE;

			return ret;
		} else if (ret < 0)
			return ret;
	}

	return bmap->b_ops->bop_delete(bmap, key);
}

int nilfs_bmap_last_key(struct nilfs_bmap *bmap, unsigned long *key)
{
	__u64 lastkey;
	int ret;

	down_read(&bmap->b_sem);
	ret = bmap->b_ops->bop_last_key(bmap, &lastkey);
	up_read(&bmap->b_sem);

	if (ret < 0)
		ret = nilfs_bmap_convert_error(bmap, __func__, ret);
	else
		*key = lastkey;
	return ret;
}

/**
 * nilfs_bmap_delete - delete a key-record pair from a bmap
 * @bmap: bmap
 * @key: key
 *
 * Description: nilfs_bmap_delete() deletes the key-record pair specified by
 * @key from @bmap.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - A record associated with @key does not exist.
 */
int nilfs_bmap_delete(struct nilfs_bmap *bmap, unsigned long key)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = nilfs_bmap_do_delete(bmap, key);
	up_write(&bmap->b_sem);

	return nilfs_bmap_convert_error(bmap, __func__, ret);
}

static int nilfs_bmap_do_truncate(struct nilfs_bmap *bmap, unsigned long key)
{
	__u64 lastkey;
	int ret;

	ret = bmap->b_ops->bop_last_key(bmap, &lastkey);
	if (ret < 0) {
		if (ret == -ENOENT)
			ret = 0;
		return ret;
	}

	while (key <= lastkey) {
		ret = nilfs_bmap_do_delete(bmap, lastkey);
		if (ret < 0)
			return ret;
		ret = bmap->b_ops->bop_last_key(bmap, &lastkey);
		if (ret < 0) {
			if (ret == -ENOENT)
				ret = 0;
			return ret;
		}
	}
	return 0;
}

/**
 * nilfs_bmap_truncate - truncate a bmap to a specified key
 * @bmap: bmap
 * @key: key
 *
 * Description: nilfs_bmap_truncate() removes key-record pairs whose keys are
 * greater than or equal to @key from @bmap.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_truncate(struct nilfs_bmap *bmap, unsigned long key)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = nilfs_bmap_do_truncate(bmap, key);
	up_write(&bmap->b_sem);

	return nilfs_bmap_convert_error(bmap, __func__, ret);
}

/**
 * nilfs_bmap_clear - free resources a bmap holds
 * @bmap: bmap
 *
 * Description: nilfs_bmap_clear() frees resources associated with @bmap.
 */
void nilfs_bmap_clear(struct nilfs_bmap *bmap)
{
	down_write(&bmap->b_sem);
	if (bmap->b_ops->bop_clear != NULL)
		bmap->b_ops->bop_clear(bmap);
	up_write(&bmap->b_sem);
}

/**
 * nilfs_bmap_propagate - propagate dirty state
 * @bmap: bmap
 * @bh: buffer head
 *
 * Description: nilfs_bmap_propagate() marks the buffers that directly or
 * indirectly refer to the block specified by @bh dirty.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_propagate(struct nilfs_bmap *bmap, struct buffer_head *bh)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = bmap->b_ops->bop_propagate(bmap, bh);
	up_write(&bmap->b_sem);

	return nilfs_bmap_convert_error(bmap, __func__, ret);
}

/**
 * nilfs_bmap_lookup_dirty_buffers -
 * @bmap: bmap
 * @listp: pointer to buffer head list
 */
void nilfs_bmap_lookup_dirty_buffers(struct nilfs_bmap *bmap,
				     struct list_head *listp)
{
	if (bmap->b_ops->bop_lookup_dirty_buffers != NULL)
		bmap->b_ops->bop_lookup_dirty_buffers(bmap, listp);
}

/**
 * nilfs_bmap_assign - assign a new block number to a block
 * @bmap: bmap
 * @bhp: pointer to buffer head
 * @blocknr: block number
 * @binfo: block information
 *
 * Description: nilfs_bmap_assign() assigns the block number @blocknr to the
 * buffer specified by @bh.
 *
 * Return Value: On success, 0 is returned and the buffer head of a newly
 * create buffer and the block information associated with the buffer are
 * stored in the place pointed by @bh and @binfo, respectively. On error, one
 * of the following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_assign(struct nilfs_bmap *bmap,
		      struct buffer_head **bh,
		      unsigned long blocknr,
		      union nilfs_binfo *binfo)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = bmap->b_ops->bop_assign(bmap, bh, blocknr, binfo);
	up_write(&bmap->b_sem);

	return nilfs_bmap_convert_error(bmap, __func__, ret);
}

/**
 * nilfs_bmap_mark - mark block dirty
 * @bmap: bmap
 * @key: key
 * @level: level
 *
 * Description: nilfs_bmap_mark() marks the block specified by @key and @level
 * as dirty.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_mark(struct nilfs_bmap *bmap, __u64 key, int level)
{
	int ret;

	if (bmap->b_ops->bop_mark == NULL)
		return 0;

	down_write(&bmap->b_sem);
	ret = bmap->b_ops->bop_mark(bmap, key, level);
	up_write(&bmap->b_sem);

	return nilfs_bmap_convert_error(bmap, __func__, ret);
}

/**
 * nilfs_bmap_test_and_clear_dirty - test and clear a bmap dirty state
 * @bmap: bmap
 *
 * Description: nilfs_test_and_clear() is the atomic operation to test and
 * clear the dirty state of @bmap.
 *
 * Return Value: 1 is returned if @bmap is dirty, or 0 if clear.
 */
int nilfs_bmap_test_and_clear_dirty(struct nilfs_bmap *bmap)
{
	int ret;

	down_write(&bmap->b_sem);
	ret = nilfs_bmap_dirty(bmap);
	nilfs_bmap_clear_dirty(bmap);
	up_write(&bmap->b_sem);
	return ret;
}


/*
 * Internal use only
 */
__u64 nilfs_bmap_data_get_key(const struct nilfs_bmap *bmap,
			      const struct buffer_head *bh)
{
	struct buffer_head *pbh;
	__u64 key;

	key = page_index(bh->b_page) << (PAGE_CACHE_SHIFT -
					 bmap->b_inode->i_blkbits);
	for (pbh = page_buffers(bh->b_page); pbh != bh; pbh = pbh->b_this_page)
		key++;

	return key;
}

__u64 nilfs_bmap_find_target_seq(const struct nilfs_bmap *bmap, __u64 key)
{
	__s64 diff;

	diff = key - bmap->b_last_allocated_key;
	if ((nilfs_bmap_keydiff_abs(diff) < NILFS_INODE_BMAP_SIZE) &&
	    (bmap->b_last_allocated_ptr != NILFS_BMAP_INVALID_PTR) &&
	    (bmap->b_last_allocated_ptr + diff > 0))
		return bmap->b_last_allocated_ptr + diff;
	else
		return NILFS_BMAP_INVALID_PTR;
}

#define NILFS_BMAP_GROUP_DIV	8
__u64 nilfs_bmap_find_target_in_group(const struct nilfs_bmap *bmap)
{
	struct inode *dat = nilfs_bmap_get_dat(bmap);
	unsigned long entries_per_group = nilfs_palloc_entries_per_group(dat);
	unsigned long group = bmap->b_inode->i_ino / entries_per_group;

	return group * entries_per_group +
		(bmap->b_inode->i_ino % NILFS_BMAP_GROUP_DIV) *
		(entries_per_group / NILFS_BMAP_GROUP_DIV);
}

static struct lock_class_key nilfs_bmap_dat_lock_key;
static struct lock_class_key nilfs_bmap_mdt_lock_key;

/**
 * nilfs_bmap_read - read a bmap from an inode
 * @bmap: bmap
 * @raw_inode: on-disk inode
 *
 * Description: nilfs_bmap_read() initializes the bmap @bmap.
 *
 * Return Value: On success, 0 is returned. On error, the following negative
 * error code is returned.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_bmap_read(struct nilfs_bmap *bmap, struct nilfs_inode *raw_inode)
{
	if (raw_inode == NULL)
		memset(bmap->b_u.u_data, 0, NILFS_BMAP_SIZE);
	else
		memcpy(bmap->b_u.u_data, raw_inode->i_bmap, NILFS_BMAP_SIZE);

	init_rwsem(&bmap->b_sem);
	bmap->b_state = 0;
	bmap->b_inode = &NILFS_BMAP_I(bmap)->vfs_inode;
	switch (bmap->b_inode->i_ino) {
	case NILFS_DAT_INO:
		bmap->b_ptr_type = NILFS_BMAP_PTR_P;
		bmap->b_last_allocated_key = 0;
		bmap->b_last_allocated_ptr = NILFS_BMAP_NEW_PTR_INIT;
		lockdep_set_class(&bmap->b_sem, &nilfs_bmap_dat_lock_key);
		break;
	case NILFS_CPFILE_INO:
	case NILFS_SUFILE_INO:
		bmap->b_ptr_type = NILFS_BMAP_PTR_VS;
		bmap->b_last_allocated_key = 0;
		bmap->b_last_allocated_ptr = NILFS_BMAP_INVALID_PTR;
		lockdep_set_class(&bmap->b_sem, &nilfs_bmap_mdt_lock_key);
		break;
	case NILFS_IFILE_INO:
		lockdep_set_class(&bmap->b_sem, &nilfs_bmap_mdt_lock_key);
		/* Fall through */
	default:
		bmap->b_ptr_type = NILFS_BMAP_PTR_VM;
		bmap->b_last_allocated_key = 0;
		bmap->b_last_allocated_ptr = NILFS_BMAP_INVALID_PTR;
		break;
	}

	return (bmap->b_u.u_flags & NILFS_BMAP_LARGE) ?
		nilfs_btree_init(bmap) : nilfs_direct_init(bmap);
}

/**
 * nilfs_bmap_write - write back a bmap to an inode
 * @bmap: bmap
 * @raw_inode: on-disk inode
 *
 * Description: nilfs_bmap_write() stores @bmap in @raw_inode.
 */
void nilfs_bmap_write(struct nilfs_bmap *bmap, struct nilfs_inode *raw_inode)
{
	down_write(&bmap->b_sem);
	memcpy(raw_inode->i_bmap, bmap->b_u.u_data,
	       NILFS_INODE_BMAP_SIZE * sizeof(__le64));
	if (bmap->b_inode->i_ino == NILFS_DAT_INO)
		bmap->b_last_allocated_ptr = NILFS_BMAP_NEW_PTR_INIT;

	up_write(&bmap->b_sem);
}

void nilfs_bmap_init_gc(struct nilfs_bmap *bmap)
{
	memset(&bmap->b_u, 0, NILFS_BMAP_SIZE);
	init_rwsem(&bmap->b_sem);
	bmap->b_inode = &NILFS_BMAP_I(bmap)->vfs_inode;
	bmap->b_ptr_type = NILFS_BMAP_PTR_U;
	bmap->b_last_allocated_key = 0;
	bmap->b_last_allocated_ptr = NILFS_BMAP_INVALID_PTR;
	bmap->b_state = 0;
	nilfs_btree_init_gc(bmap);
}

void nilfs_bmap_save(const struct nilfs_bmap *bmap,
		     struct nilfs_bmap_store *store)
{
	memcpy(store->data, bmap->b_u.u_data, sizeof(store->data));
	store->last_allocated_key = bmap->b_last_allocated_key;
	store->last_allocated_ptr = bmap->b_last_allocated_ptr;
	store->state = bmap->b_state;
}

void nilfs_bmap_restore(struct nilfs_bmap *bmap,
			const struct nilfs_bmap_store *store)
{
	memcpy(bmap->b_u.u_data, store->data, sizeof(store->data));
	bmap->b_last_allocated_key = store->last_allocated_key;
	bmap->b_last_allocated_ptr = store->last_allocated_ptr;
	bmap->b_state = store->state;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/bmap.c */
/************************************************************/
/*
 * btree.c - NILFS B-tree.
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Koji Sato <koji@osrg.net>.
 */

// #include <linux/slab.h>
// #include <linux/string.h>
// #include <linux/errno.h>
// #include <linux/pagevec.h>
// #include "nilfs.h"
// #include "page.h"
// #include "btnode.h"
// #include "btree.h"
// #include "alloc.h"
// #include "dat.h"

static struct nilfs_btree_path *nilfs_btree_alloc_path(void)
{
	struct nilfs_btree_path *path;
	int level = NILFS_BTREE_LEVEL_DATA;

	path = kmem_cache_alloc(nilfs_btree_path_cache, GFP_NOFS);
	if (path == NULL)
		goto out;

	for (; level < NILFS_BTREE_LEVEL_MAX; level++) {
		path[level].bp_bh = NULL;
		path[level].bp_sib_bh = NULL;
		path[level].bp_index = 0;
		path[level].bp_oldreq.bpr_ptr = NILFS_BMAP_INVALID_PTR;
		path[level].bp_newreq.bpr_ptr = NILFS_BMAP_INVALID_PTR;
		path[level].bp_op = NULL;
	}

out:
	return path;
}

static void nilfs_btree_free_path(struct nilfs_btree_path *path)
{
	int level = NILFS_BTREE_LEVEL_DATA;

	for (; level < NILFS_BTREE_LEVEL_MAX; level++)
		brelse(path[level].bp_bh);

	kmem_cache_free(nilfs_btree_path_cache, path);
}

/*
 * B-tree node operations
 */
static int nilfs_btree_get_new_block(const struct nilfs_bmap *btree,
				     __u64 ptr, struct buffer_head **bhp)
{
	struct address_space *btnc = &NILFS_BMAP_I(btree)->i_btnode_cache;
	struct buffer_head *bh;

	bh = nilfs_btnode_create_block(btnc, ptr);
	if (!bh)
		return -ENOMEM;

	set_buffer_nilfs_volatile(bh);
	*bhp = bh;
	return 0;
}

static int nilfs_btree_node_get_flags(const struct nilfs_btree_node *node)
{
	return node->bn_flags;
}

static void
nilfs_btree_node_set_flags(struct nilfs_btree_node *node, int flags)
{
	node->bn_flags = flags;
}

static int nilfs_btree_node_root(const struct nilfs_btree_node *node)
{
	return nilfs_btree_node_get_flags(node) & NILFS_BTREE_NODE_ROOT;
}

static int nilfs_btree_node_get_level(const struct nilfs_btree_node *node)
{
	return node->bn_level;
}

static void
nilfs_btree_node_set_level(struct nilfs_btree_node *node, int level)
{
	node->bn_level = level;
}

static int nilfs_btree_node_get_nchildren(const struct nilfs_btree_node *node)
{
	return le16_to_cpu(node->bn_nchildren);
}

static void
nilfs_btree_node_set_nchildren(struct nilfs_btree_node *node, int nchildren)
{
	node->bn_nchildren = cpu_to_le16(nchildren);
}

static int nilfs_btree_node_size(const struct nilfs_bmap *btree)
{
	return 1 << btree->b_inode->i_blkbits;
}

static int nilfs_btree_nchildren_per_block(const struct nilfs_bmap *btree)
{
	return btree->b_nchildren_per_block;
}

static __le64 *
nilfs_btree_node_dkeys(const struct nilfs_btree_node *node)
{
	return (__le64 *)((char *)(node + 1) +
			  (nilfs_btree_node_root(node) ?
			   0 : NILFS_BTREE_NODE_EXTRA_PAD_SIZE));
}

static __le64 *
nilfs_btree_node_dptrs(const struct nilfs_btree_node *node, int ncmax)
{
	return (__le64 *)(nilfs_btree_node_dkeys(node) + ncmax);
}

static __u64
nilfs_btree_node_get_key(const struct nilfs_btree_node *node, int index)
{
	return le64_to_cpu(*(nilfs_btree_node_dkeys(node) + index));
}

static void
nilfs_btree_node_set_key(struct nilfs_btree_node *node, int index, __u64 key)
{
	*(nilfs_btree_node_dkeys(node) + index) = cpu_to_le64(key);
}

static __u64
nilfs_btree_node_get_ptr(const struct nilfs_btree_node *node, int index,
			 int ncmax)
{
	return le64_to_cpu(*(nilfs_btree_node_dptrs(node, ncmax) + index));
}

static void
nilfs_btree_node_set_ptr(struct nilfs_btree_node *node, int index, __u64 ptr,
			 int ncmax)
{
	*(nilfs_btree_node_dptrs(node, ncmax) + index) = cpu_to_le64(ptr);
}

static void nilfs_btree_node_init(struct nilfs_btree_node *node, int flags,
				  int level, int nchildren, int ncmax,
				  const __u64 *keys, const __u64 *ptrs)
{
	__le64 *dkeys;
	__le64 *dptrs;
	int i;

	nilfs_btree_node_set_flags(node, flags);
	nilfs_btree_node_set_level(node, level);
	nilfs_btree_node_set_nchildren(node, nchildren);

	dkeys = nilfs_btree_node_dkeys(node);
	dptrs = nilfs_btree_node_dptrs(node, ncmax);
	for (i = 0; i < nchildren; i++) {
		dkeys[i] = cpu_to_le64(keys[i]);
		dptrs[i] = cpu_to_le64(ptrs[i]);
	}
}

/* Assume the buffer heads corresponding to left and right are locked. */
static void nilfs_btree_node_move_left(struct nilfs_btree_node *left,
				       struct nilfs_btree_node *right,
				       int n, int lncmax, int rncmax)
{
	__le64 *ldkeys, *rdkeys;
	__le64 *ldptrs, *rdptrs;
	int lnchildren, rnchildren;

	ldkeys = nilfs_btree_node_dkeys(left);
	ldptrs = nilfs_btree_node_dptrs(left, lncmax);
	lnchildren = nilfs_btree_node_get_nchildren(left);

	rdkeys = nilfs_btree_node_dkeys(right);
	rdptrs = nilfs_btree_node_dptrs(right, rncmax);
	rnchildren = nilfs_btree_node_get_nchildren(right);

	memcpy(ldkeys + lnchildren, rdkeys, n * sizeof(*rdkeys));
	memcpy(ldptrs + lnchildren, rdptrs, n * sizeof(*rdptrs));
	memmove(rdkeys, rdkeys + n, (rnchildren - n) * sizeof(*rdkeys));
	memmove(rdptrs, rdptrs + n, (rnchildren - n) * sizeof(*rdptrs));

	lnchildren += n;
	rnchildren -= n;
	nilfs_btree_node_set_nchildren(left, lnchildren);
	nilfs_btree_node_set_nchildren(right, rnchildren);
}

/* Assume that the buffer heads corresponding to left and right are locked. */
static void nilfs_btree_node_move_right(struct nilfs_btree_node *left,
					struct nilfs_btree_node *right,
					int n, int lncmax, int rncmax)
{
	__le64 *ldkeys, *rdkeys;
	__le64 *ldptrs, *rdptrs;
	int lnchildren, rnchildren;

	ldkeys = nilfs_btree_node_dkeys(left);
	ldptrs = nilfs_btree_node_dptrs(left, lncmax);
	lnchildren = nilfs_btree_node_get_nchildren(left);

	rdkeys = nilfs_btree_node_dkeys(right);
	rdptrs = nilfs_btree_node_dptrs(right, rncmax);
	rnchildren = nilfs_btree_node_get_nchildren(right);

	memmove(rdkeys + n, rdkeys, rnchildren * sizeof(*rdkeys));
	memmove(rdptrs + n, rdptrs, rnchildren * sizeof(*rdptrs));
	memcpy(rdkeys, ldkeys + lnchildren - n, n * sizeof(*rdkeys));
	memcpy(rdptrs, ldptrs + lnchildren - n, n * sizeof(*rdptrs));

	lnchildren -= n;
	rnchildren += n;
	nilfs_btree_node_set_nchildren(left, lnchildren);
	nilfs_btree_node_set_nchildren(right, rnchildren);
}

/* Assume that the buffer head corresponding to node is locked. */
static void nilfs_btree_node_insert(struct nilfs_btree_node *node, int index,
				    __u64 key, __u64 ptr, int ncmax)
{
	__le64 *dkeys;
	__le64 *dptrs;
	int nchildren;

	dkeys = nilfs_btree_node_dkeys(node);
	dptrs = nilfs_btree_node_dptrs(node, ncmax);
	nchildren = nilfs_btree_node_get_nchildren(node);
	if (index < nchildren) {
		memmove(dkeys + index + 1, dkeys + index,
			(nchildren - index) * sizeof(*dkeys));
		memmove(dptrs + index + 1, dptrs + index,
			(nchildren - index) * sizeof(*dptrs));
	}
	dkeys[index] = cpu_to_le64(key);
	dptrs[index] = cpu_to_le64(ptr);
	nchildren++;
	nilfs_btree_node_set_nchildren(node, nchildren);
}

/* Assume that the buffer head corresponding to node is locked. */
static void nilfs_btree_node_delete(struct nilfs_btree_node *node, int index,
				    __u64 *keyp, __u64 *ptrp, int ncmax)
{
	__u64 key;
	__u64 ptr;
	__le64 *dkeys;
	__le64 *dptrs;
	int nchildren;

	dkeys = nilfs_btree_node_dkeys(node);
	dptrs = nilfs_btree_node_dptrs(node, ncmax);
	key = le64_to_cpu(dkeys[index]);
	ptr = le64_to_cpu(dptrs[index]);
	nchildren = nilfs_btree_node_get_nchildren(node);
	if (keyp != NULL)
		*keyp = key;
	if (ptrp != NULL)
		*ptrp = ptr;

	if (index < nchildren - 1) {
		memmove(dkeys + index, dkeys + index + 1,
			(nchildren - index - 1) * sizeof(*dkeys));
		memmove(dptrs + index, dptrs + index + 1,
			(nchildren - index - 1) * sizeof(*dptrs));
	}
	nchildren--;
	nilfs_btree_node_set_nchildren(node, nchildren);
}

static int nilfs_btree_node_lookup(const struct nilfs_btree_node *node,
				   __u64 key, int *indexp)
{
	__u64 nkey;
	int index, low, high, s;

	/* binary search */
	low = 0;
	high = nilfs_btree_node_get_nchildren(node) - 1;
	index = 0;
	s = 0;
	while (low <= high) {
		index = (low + high) / 2;
		nkey = nilfs_btree_node_get_key(node, index);
		if (nkey == key) {
			s = 0;
			goto out;
		} else if (nkey < key) {
			low = index + 1;
			s = -1;
		} else {
			high = index - 1;
			s = 1;
		}
	}

	/* adjust index */
	if (nilfs_btree_node_get_level(node) > NILFS_BTREE_LEVEL_NODE_MIN) {
		if (s > 0 && index > 0)
			index--;
	} else if (s < 0)
		index++;

 out:
	*indexp = index;

	return s == 0;
}

/**
 * nilfs_btree_node_broken - verify consistency of btree node
 * @node: btree node block to be examined
 * @size: node size (in bytes)
 * @blocknr: block number
 *
 * Return Value: If node is broken, 1 is returned. Otherwise, 0 is returned.
 */
static int nilfs_btree_node_broken(const struct nilfs_btree_node *node,
				   size_t size, sector_t blocknr)
{
	int level, flags, nchildren;
	int ret = 0;

	level = nilfs_btree_node_get_level(node);
	flags = nilfs_btree_node_get_flags(node);
	nchildren = nilfs_btree_node_get_nchildren(node);

	if (unlikely(level < NILFS_BTREE_LEVEL_NODE_MIN ||
		     level >= NILFS_BTREE_LEVEL_MAX ||
		     (flags & NILFS_BTREE_NODE_ROOT) ||
		     nchildren < 0 ||
		     nchildren > NILFS_BTREE_NODE_NCHILDREN_MAX(size))) {
		printk(KERN_CRIT "NILFS: bad btree node (blocknr=%llu): "
		       "level = %d, flags = 0x%x, nchildren = %d\n",
		       (unsigned long long)blocknr, level, flags, nchildren);
		ret = 1;
	}
	return ret;
}

int nilfs_btree_broken_node_block(struct buffer_head *bh)
{
	int ret;

	if (buffer_nilfs_checked(bh))
		return 0;

	ret = nilfs_btree_node_broken((struct nilfs_btree_node *)bh->b_data,
				       bh->b_size, bh->b_blocknr);
	if (likely(!ret))
		set_buffer_nilfs_checked(bh);
	return ret;
}

static struct nilfs_btree_node *
nilfs_btree_get_root(const struct nilfs_bmap *btree)
{
	return (struct nilfs_btree_node *)btree->b_u.u_data;
}

static struct nilfs_btree_node *
nilfs_btree_get_nonroot_node(const struct nilfs_btree_path *path, int level)
{
	return (struct nilfs_btree_node *)path[level].bp_bh->b_data;
}

static struct nilfs_btree_node *
nilfs_btree_get_sib_node(const struct nilfs_btree_path *path, int level)
{
	return (struct nilfs_btree_node *)path[level].bp_sib_bh->b_data;
}

static int nilfs_btree_height(const struct nilfs_bmap *btree)
{
	return nilfs_btree_node_get_level(nilfs_btree_get_root(btree)) + 1;
}

static struct nilfs_btree_node *
nilfs_btree_get_node(const struct nilfs_bmap *btree,
		     const struct nilfs_btree_path *path,
		     int level, int *ncmaxp)
{
	struct nilfs_btree_node *node;

	if (level == nilfs_btree_height(btree) - 1) {
		node = nilfs_btree_get_root(btree);
		*ncmaxp = NILFS_BTREE_ROOT_NCHILDREN_MAX;
	} else {
		node = nilfs_btree_get_nonroot_node(path, level);
		*ncmaxp = nilfs_btree_nchildren_per_block(btree);
	}
	return node;
}

static int
nilfs_btree_bad_node(struct nilfs_btree_node *node, int level)
{
	if (unlikely(nilfs_btree_node_get_level(node) != level)) {
		dump_stack();
		printk(KERN_CRIT "NILFS: btree level mismatch: %d != %d\n",
		       nilfs_btree_node_get_level(node), level);
		return 1;
	}
	return 0;
}

struct nilfs_btree_readahead_info {
	struct nilfs_btree_node *node;	/* parent node */
	int max_ra_blocks;		/* max nof blocks to read ahead */
	int index;			/* current index on the parent node */
	int ncmax;			/* nof children in the parent node */
};

static int __nilfs_btree_get_block(const struct nilfs_bmap *btree, __u64 ptr,
				   struct buffer_head **bhp,
				   const struct nilfs_btree_readahead_info *ra)
{
	struct address_space *btnc = &NILFS_BMAP_I(btree)->i_btnode_cache;
	struct buffer_head *bh, *ra_bh;
	sector_t submit_ptr = 0;
	int ret;

	ret = nilfs_btnode_submit_block(btnc, ptr, 0, READ, &bh, &submit_ptr);
	if (ret) {
		if (ret != -EEXIST)
			return ret;
		goto out_check;
	}

	if (ra) {
		int i, n;
		__u64 ptr2;

		/* read ahead sibling nodes */
		for (n = ra->max_ra_blocks, i = ra->index + 1;
		     n > 0 && i < ra->ncmax; n--, i++) {
			ptr2 = nilfs_btree_node_get_ptr(ra->node, i, ra->ncmax);

			ret = nilfs_btnode_submit_block(btnc, ptr2, 0, READA,
							&ra_bh, &submit_ptr);
			if (likely(!ret || ret == -EEXIST))
				brelse(ra_bh);
			else if (ret != -EBUSY)
				break;
			if (!buffer_locked(bh))
				goto out_no_wait;
		}
	}

	wait_on_buffer(bh);

 out_no_wait:
	if (!buffer_uptodate(bh)) {
		brelse(bh);
		return -EIO;
	}

 out_check:
	if (nilfs_btree_broken_node_block(bh)) {
		clear_buffer_uptodate(bh);
		brelse(bh);
		return -EINVAL;
	}

	*bhp = bh;
	return 0;
}

static int nilfs_btree_get_block(const struct nilfs_bmap *btree, __u64 ptr,
				   struct buffer_head **bhp)
{
	return __nilfs_btree_get_block(btree, ptr, bhp, NULL);
}

static int nilfs_btree_do_lookup(const struct nilfs_bmap *btree,
				 struct nilfs_btree_path *path,
				 __u64 key, __u64 *ptrp, int minlevel,
				 int readahead)
{
	struct nilfs_btree_node *node;
	struct nilfs_btree_readahead_info p, *ra;
	__u64 ptr;
	int level, index, found, ncmax, ret;

	node = nilfs_btree_get_root(btree);
	level = nilfs_btree_node_get_level(node);
	if (level < minlevel || nilfs_btree_node_get_nchildren(node) <= 0)
		return -ENOENT;

	found = nilfs_btree_node_lookup(node, key, &index);
	ptr = nilfs_btree_node_get_ptr(node, index,
				       NILFS_BTREE_ROOT_NCHILDREN_MAX);
	path[level].bp_bh = NULL;
	path[level].bp_index = index;

	ncmax = nilfs_btree_nchildren_per_block(btree);

	while (--level >= minlevel) {
		ra = NULL;
		if (level == NILFS_BTREE_LEVEL_NODE_MIN && readahead) {
			p.node = nilfs_btree_get_node(btree, path, level + 1,
						      &p.ncmax);
			p.index = index;
			p.max_ra_blocks = 7;
			ra = &p;
		}
		ret = __nilfs_btree_get_block(btree, ptr, &path[level].bp_bh,
					      ra);
		if (ret < 0)
			return ret;

		node = nilfs_btree_get_nonroot_node(path, level);
		if (nilfs_btree_bad_node(node, level))
			return -EINVAL;
		if (!found)
			found = nilfs_btree_node_lookup(node, key, &index);
		else
			index = 0;
		if (index < ncmax) {
			ptr = nilfs_btree_node_get_ptr(node, index, ncmax);
		} else {
			WARN_ON(found || level != NILFS_BTREE_LEVEL_NODE_MIN);
			/* insert */
			ptr = NILFS_BMAP_INVALID_PTR;
		}
		path[level].bp_index = index;
	}
	if (!found)
		return -ENOENT;

	if (ptrp != NULL)
		*ptrp = ptr;

	return 0;
}

static int nilfs_btree_do_lookup_last(const struct nilfs_bmap *btree,
				      struct nilfs_btree_path *path,
				      __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node;
	__u64 ptr;
	int index, level, ncmax, ret;

	node = nilfs_btree_get_root(btree);
	index = nilfs_btree_node_get_nchildren(node) - 1;
	if (index < 0)
		return -ENOENT;
	level = nilfs_btree_node_get_level(node);
	ptr = nilfs_btree_node_get_ptr(node, index,
				       NILFS_BTREE_ROOT_NCHILDREN_MAX);
	path[level].bp_bh = NULL;
	path[level].bp_index = index;
	ncmax = nilfs_btree_nchildren_per_block(btree);

	for (level--; level > 0; level--) {
		ret = nilfs_btree_get_block(btree, ptr, &path[level].bp_bh);
		if (ret < 0)
			return ret;
		node = nilfs_btree_get_nonroot_node(path, level);
		if (nilfs_btree_bad_node(node, level))
			return -EINVAL;
		index = nilfs_btree_node_get_nchildren(node) - 1;
		ptr = nilfs_btree_node_get_ptr(node, index, ncmax);
		path[level].bp_index = index;
	}

	if (keyp != NULL)
		*keyp = nilfs_btree_node_get_key(node, index);
	if (ptrp != NULL)
		*ptrp = ptr;

	return 0;
}

static int nilfs_btree_lookup(const struct nilfs_bmap *btree,
			      __u64 key, int level, __u64 *ptrp)
{
	struct nilfs_btree_path *path;
	int ret;

	path = nilfs_btree_alloc_path();
	if (path == NULL)
		return -ENOMEM;

	ret = nilfs_btree_do_lookup(btree, path, key, ptrp, level, 0);

	nilfs_btree_free_path(path);

	return ret;
}

static int nilfs_btree_lookup_contig(const struct nilfs_bmap *btree,
				     __u64 key, __u64 *ptrp, unsigned maxblocks)
{
	struct nilfs_btree_path *path;
	struct nilfs_btree_node *node;
	struct inode *dat = NULL;
	__u64 ptr, ptr2;
	sector_t blocknr;
	int level = NILFS_BTREE_LEVEL_NODE_MIN;
	int ret, cnt, index, maxlevel, ncmax;
	struct nilfs_btree_readahead_info p;

	path = nilfs_btree_alloc_path();
	if (path == NULL)
		return -ENOMEM;

	ret = nilfs_btree_do_lookup(btree, path, key, &ptr, level, 1);
	if (ret < 0)
		goto out;

	if (NILFS_BMAP_USE_VBN(btree)) {
		dat = nilfs_bmap_get_dat(btree);
		ret = nilfs_dat_translate(dat, ptr, &blocknr);
		if (ret < 0)
			goto out;
		ptr = blocknr;
	}
	cnt = 1;
	if (cnt == maxblocks)
		goto end;

	maxlevel = nilfs_btree_height(btree) - 1;
	node = nilfs_btree_get_node(btree, path, level, &ncmax);
	index = path[level].bp_index + 1;
	for (;;) {
		while (index < nilfs_btree_node_get_nchildren(node)) {
			if (nilfs_btree_node_get_key(node, index) !=
			    key + cnt)
				goto end;
			ptr2 = nilfs_btree_node_get_ptr(node, index, ncmax);
			if (dat) {
				ret = nilfs_dat_translate(dat, ptr2, &blocknr);
				if (ret < 0)
					goto out;
				ptr2 = blocknr;
			}
			if (ptr2 != ptr + cnt || ++cnt == maxblocks)
				goto end;
			index++;
			continue;
		}
		if (level == maxlevel)
			break;

		/* look-up right sibling node */
		p.node = nilfs_btree_get_node(btree, path, level + 1, &p.ncmax);
		p.index = path[level + 1].bp_index + 1;
		p.max_ra_blocks = 7;
		if (p.index >= nilfs_btree_node_get_nchildren(p.node) ||
		    nilfs_btree_node_get_key(p.node, p.index) != key + cnt)
			break;
		ptr2 = nilfs_btree_node_get_ptr(p.node, p.index, p.ncmax);
		path[level + 1].bp_index = p.index;

		brelse(path[level].bp_bh);
		path[level].bp_bh = NULL;

		ret = __nilfs_btree_get_block(btree, ptr2, &path[level].bp_bh,
					      &p);
		if (ret < 0)
			goto out;
		node = nilfs_btree_get_nonroot_node(path, level);
		ncmax = nilfs_btree_nchildren_per_block(btree);
		index = 0;
		path[level].bp_index = index;
	}
 end:
	*ptrp = ptr;
	ret = cnt;
 out:
	nilfs_btree_free_path(path);
	return ret;
}

static void nilfs_btree_promote_key(struct nilfs_bmap *btree,
				    struct nilfs_btree_path *path,
				    int level, __u64 key)
{
	if (level < nilfs_btree_height(btree) - 1) {
		do {
			nilfs_btree_node_set_key(
				nilfs_btree_get_nonroot_node(path, level),
				path[level].bp_index, key);
			if (!buffer_dirty(path[level].bp_bh))
				mark_buffer_dirty(path[level].bp_bh);
		} while ((path[level].bp_index == 0) &&
			 (++level < nilfs_btree_height(btree) - 1));
	}

	/* root */
	if (level == nilfs_btree_height(btree) - 1) {
		nilfs_btree_node_set_key(nilfs_btree_get_root(btree),
					 path[level].bp_index, key);
	}
}

static void nilfs_btree_do_insert(struct nilfs_bmap *btree,
				  struct nilfs_btree_path *path,
				  int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node;
	int ncblk;

	if (level < nilfs_btree_height(btree) - 1) {
		node = nilfs_btree_get_nonroot_node(path, level);
		ncblk = nilfs_btree_nchildren_per_block(btree);
		nilfs_btree_node_insert(node, path[level].bp_index,
					*keyp, *ptrp, ncblk);
		if (!buffer_dirty(path[level].bp_bh))
			mark_buffer_dirty(path[level].bp_bh);

		if (path[level].bp_index == 0)
			nilfs_btree_promote_key(btree, path, level + 1,
						nilfs_btree_node_get_key(node,
									 0));
	} else {
		node = nilfs_btree_get_root(btree);
		nilfs_btree_node_insert(node, path[level].bp_index,
					*keyp, *ptrp,
					NILFS_BTREE_ROOT_NCHILDREN_MAX);
	}
}

static void nilfs_btree_carry_left(struct nilfs_bmap *btree,
				   struct nilfs_btree_path *path,
				   int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node, *left;
	int nchildren, lnchildren, n, move, ncblk;

	node = nilfs_btree_get_nonroot_node(path, level);
	left = nilfs_btree_get_sib_node(path, level);
	nchildren = nilfs_btree_node_get_nchildren(node);
	lnchildren = nilfs_btree_node_get_nchildren(left);
	ncblk = nilfs_btree_nchildren_per_block(btree);
	move = 0;

	n = (nchildren + lnchildren + 1) / 2 - lnchildren;
	if (n > path[level].bp_index) {
		/* move insert point */
		n--;
		move = 1;
	}

	nilfs_btree_node_move_left(left, node, n, ncblk, ncblk);

	if (!buffer_dirty(path[level].bp_bh))
		mark_buffer_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		mark_buffer_dirty(path[level].bp_sib_bh);

	nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(node, 0));

	if (move) {
		brelse(path[level].bp_bh);
		path[level].bp_bh = path[level].bp_sib_bh;
		path[level].bp_sib_bh = NULL;
		path[level].bp_index += lnchildren;
		path[level + 1].bp_index--;
	} else {
		brelse(path[level].bp_sib_bh);
		path[level].bp_sib_bh = NULL;
		path[level].bp_index -= n;
	}

	nilfs_btree_do_insert(btree, path, level, keyp, ptrp);
}

static void nilfs_btree_carry_right(struct nilfs_bmap *btree,
				    struct nilfs_btree_path *path,
				    int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node, *right;
	int nchildren, rnchildren, n, move, ncblk;

	node = nilfs_btree_get_nonroot_node(path, level);
	right = nilfs_btree_get_sib_node(path, level);
	nchildren = nilfs_btree_node_get_nchildren(node);
	rnchildren = nilfs_btree_node_get_nchildren(right);
	ncblk = nilfs_btree_nchildren_per_block(btree);
	move = 0;

	n = (nchildren + rnchildren + 1) / 2 - rnchildren;
	if (n > nchildren - path[level].bp_index) {
		/* move insert point */
		n--;
		move = 1;
	}

	nilfs_btree_node_move_right(node, right, n, ncblk, ncblk);

	if (!buffer_dirty(path[level].bp_bh))
		mark_buffer_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		mark_buffer_dirty(path[level].bp_sib_bh);

	path[level + 1].bp_index++;
	nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(right, 0));
	path[level + 1].bp_index--;

	if (move) {
		brelse(path[level].bp_bh);
		path[level].bp_bh = path[level].bp_sib_bh;
		path[level].bp_sib_bh = NULL;
		path[level].bp_index -= nilfs_btree_node_get_nchildren(node);
		path[level + 1].bp_index++;
	} else {
		brelse(path[level].bp_sib_bh);
		path[level].bp_sib_bh = NULL;
	}

	nilfs_btree_do_insert(btree, path, level, keyp, ptrp);
}

static void nilfs_btree_split(struct nilfs_bmap *btree,
			      struct nilfs_btree_path *path,
			      int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node, *right;
	__u64 newkey;
	__u64 newptr;
	int nchildren, n, move, ncblk;

	node = nilfs_btree_get_nonroot_node(path, level);
	right = nilfs_btree_get_sib_node(path, level);
	nchildren = nilfs_btree_node_get_nchildren(node);
	ncblk = nilfs_btree_nchildren_per_block(btree);
	move = 0;

	n = (nchildren + 1) / 2;
	if (n > nchildren - path[level].bp_index) {
		n--;
		move = 1;
	}

	nilfs_btree_node_move_right(node, right, n, ncblk, ncblk);

	if (!buffer_dirty(path[level].bp_bh))
		mark_buffer_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		mark_buffer_dirty(path[level].bp_sib_bh);

	newkey = nilfs_btree_node_get_key(right, 0);
	newptr = path[level].bp_newreq.bpr_ptr;

	if (move) {
		path[level].bp_index -= nilfs_btree_node_get_nchildren(node);
		nilfs_btree_node_insert(right, path[level].bp_index,
					*keyp, *ptrp, ncblk);

		*keyp = nilfs_btree_node_get_key(right, 0);
		*ptrp = path[level].bp_newreq.bpr_ptr;

		brelse(path[level].bp_bh);
		path[level].bp_bh = path[level].bp_sib_bh;
		path[level].bp_sib_bh = NULL;
	} else {
		nilfs_btree_do_insert(btree, path, level, keyp, ptrp);

		*keyp = nilfs_btree_node_get_key(right, 0);
		*ptrp = path[level].bp_newreq.bpr_ptr;

		brelse(path[level].bp_sib_bh);
		path[level].bp_sib_bh = NULL;
	}

	path[level + 1].bp_index++;
}

static void nilfs_btree_grow(struct nilfs_bmap *btree,
			     struct nilfs_btree_path *path,
			     int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *root, *child;
	int n, ncblk;

	root = nilfs_btree_get_root(btree);
	child = nilfs_btree_get_sib_node(path, level);
	ncblk = nilfs_btree_nchildren_per_block(btree);

	n = nilfs_btree_node_get_nchildren(root);

	nilfs_btree_node_move_right(root, child, n,
				    NILFS_BTREE_ROOT_NCHILDREN_MAX, ncblk);
	nilfs_btree_node_set_level(root, level + 1);

	if (!buffer_dirty(path[level].bp_sib_bh))
		mark_buffer_dirty(path[level].bp_sib_bh);

	path[level].bp_bh = path[level].bp_sib_bh;
	path[level].bp_sib_bh = NULL;

	nilfs_btree_do_insert(btree, path, level, keyp, ptrp);

	*keyp = nilfs_btree_node_get_key(child, 0);
	*ptrp = path[level].bp_newreq.bpr_ptr;
}

static __u64 nilfs_btree_find_near(const struct nilfs_bmap *btree,
				   const struct nilfs_btree_path *path)
{
	struct nilfs_btree_node *node;
	int level, ncmax;

	if (path == NULL)
		return NILFS_BMAP_INVALID_PTR;

	/* left sibling */
	level = NILFS_BTREE_LEVEL_NODE_MIN;
	if (path[level].bp_index > 0) {
		node = nilfs_btree_get_node(btree, path, level, &ncmax);
		return nilfs_btree_node_get_ptr(node,
						path[level].bp_index - 1,
						ncmax);
	}

	/* parent */
	level = NILFS_BTREE_LEVEL_NODE_MIN + 1;
	if (level <= nilfs_btree_height(btree) - 1) {
		node = nilfs_btree_get_node(btree, path, level, &ncmax);
		return nilfs_btree_node_get_ptr(node, path[level].bp_index,
						ncmax);
	}

	return NILFS_BMAP_INVALID_PTR;
}

static __u64 nilfs_btree_find_target_v(const struct nilfs_bmap *btree,
				       const struct nilfs_btree_path *path,
				       __u64 key)
{
	__u64 ptr;

	ptr = nilfs_bmap_find_target_seq(btree, key);
	if (ptr != NILFS_BMAP_INVALID_PTR)
		/* sequential access */
		return ptr;
	else {
		ptr = nilfs_btree_find_near(btree, path);
		if (ptr != NILFS_BMAP_INVALID_PTR)
			/* near */
			return ptr;
	}
	/* block group */
	return nilfs_bmap_find_target_in_group(btree);
}

static int nilfs_btree_prepare_insert(struct nilfs_bmap *btree,
				      struct nilfs_btree_path *path,
				      int *levelp, __u64 key, __u64 ptr,
				      struct nilfs_bmap_stats *stats)
{
	struct buffer_head *bh;
	struct nilfs_btree_node *node, *parent, *sib;
	__u64 sibptr;
	int pindex, level, ncmax, ncblk, ret;
	struct inode *dat = NULL;

	stats->bs_nblocks = 0;
	level = NILFS_BTREE_LEVEL_DATA;

	/* allocate a new ptr for data block */
	if (NILFS_BMAP_USE_VBN(btree)) {
		path[level].bp_newreq.bpr_ptr =
			nilfs_btree_find_target_v(btree, path, key);
		dat = nilfs_bmap_get_dat(btree);
	}

	ret = nilfs_bmap_prepare_alloc_ptr(btree, &path[level].bp_newreq, dat);
	if (ret < 0)
		goto err_out_data;

	ncblk = nilfs_btree_nchildren_per_block(btree);

	for (level = NILFS_BTREE_LEVEL_NODE_MIN;
	     level < nilfs_btree_height(btree) - 1;
	     level++) {
		node = nilfs_btree_get_nonroot_node(path, level);
		if (nilfs_btree_node_get_nchildren(node) < ncblk) {
			path[level].bp_op = nilfs_btree_do_insert;
			stats->bs_nblocks++;
			goto out;
		}

		parent = nilfs_btree_get_node(btree, path, level + 1, &ncmax);
		pindex = path[level + 1].bp_index;

		/* left sibling */
		if (pindex > 0) {
			sibptr = nilfs_btree_node_get_ptr(parent, pindex - 1,
							  ncmax);
			ret = nilfs_btree_get_block(btree, sibptr, &bh);
			if (ret < 0)
				goto err_out_child_node;
			sib = (struct nilfs_btree_node *)bh->b_data;
			if (nilfs_btree_node_get_nchildren(sib) < ncblk) {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_carry_left;
				stats->bs_nblocks++;
				goto out;
			} else {
				brelse(bh);
			}
		}

		/* right sibling */
		if (pindex < nilfs_btree_node_get_nchildren(parent) - 1) {
			sibptr = nilfs_btree_node_get_ptr(parent, pindex + 1,
							  ncmax);
			ret = nilfs_btree_get_block(btree, sibptr, &bh);
			if (ret < 0)
				goto err_out_child_node;
			sib = (struct nilfs_btree_node *)bh->b_data;
			if (nilfs_btree_node_get_nchildren(sib) < ncblk) {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_carry_right;
				stats->bs_nblocks++;
				goto out;
			} else {
				brelse(bh);
			}
		}

		/* split */
		path[level].bp_newreq.bpr_ptr =
			path[level - 1].bp_newreq.bpr_ptr + 1;
		ret = nilfs_bmap_prepare_alloc_ptr(btree,
						   &path[level].bp_newreq, dat);
		if (ret < 0)
			goto err_out_child_node;
		ret = nilfs_btree_get_new_block(btree,
						path[level].bp_newreq.bpr_ptr,
						&bh);
		if (ret < 0)
			goto err_out_curr_node;

		stats->bs_nblocks++;

		sib = (struct nilfs_btree_node *)bh->b_data;
		nilfs_btree_node_init(sib, 0, level, 0, ncblk, NULL, NULL);
		path[level].bp_sib_bh = bh;
		path[level].bp_op = nilfs_btree_split;
	}

	/* root */
	node = nilfs_btree_get_root(btree);
	if (nilfs_btree_node_get_nchildren(node) <
	    NILFS_BTREE_ROOT_NCHILDREN_MAX) {
		path[level].bp_op = nilfs_btree_do_insert;
		stats->bs_nblocks++;
		goto out;
	}

	/* grow */
	path[level].bp_newreq.bpr_ptr = path[level - 1].bp_newreq.bpr_ptr + 1;
	ret = nilfs_bmap_prepare_alloc_ptr(btree, &path[level].bp_newreq, dat);
	if (ret < 0)
		goto err_out_child_node;
	ret = nilfs_btree_get_new_block(btree, path[level].bp_newreq.bpr_ptr,
					&bh);
	if (ret < 0)
		goto err_out_curr_node;

	nilfs_btree_node_init((struct nilfs_btree_node *)bh->b_data,
			      0, level, 0, ncblk, NULL, NULL);
	path[level].bp_sib_bh = bh;
	path[level].bp_op = nilfs_btree_grow;

	level++;
	path[level].bp_op = nilfs_btree_do_insert;

	/* a newly-created node block and a data block are added */
	stats->bs_nblocks += 2;

	/* success */
 out:
	*levelp = level;
	return ret;

	/* error */
 err_out_curr_node:
	nilfs_bmap_abort_alloc_ptr(btree, &path[level].bp_newreq, dat);
 err_out_child_node:
	for (level--; level > NILFS_BTREE_LEVEL_DATA; level--) {
		nilfs_btnode_delete(path[level].bp_sib_bh);
		nilfs_bmap_abort_alloc_ptr(btree, &path[level].bp_newreq, dat);

	}

	nilfs_bmap_abort_alloc_ptr(btree, &path[level].bp_newreq, dat);
 err_out_data:
	*levelp = level;
	stats->bs_nblocks = 0;
	return ret;
}

static void nilfs_btree_commit_insert(struct nilfs_bmap *btree,
				      struct nilfs_btree_path *path,
				      int maxlevel, __u64 key, __u64 ptr)
{
	struct inode *dat = NULL;
	int level;

	set_buffer_nilfs_volatile((struct buffer_head *)((unsigned long)ptr));
	ptr = path[NILFS_BTREE_LEVEL_DATA].bp_newreq.bpr_ptr;
	if (NILFS_BMAP_USE_VBN(btree)) {
		nilfs_bmap_set_target_v(btree, key, ptr);
		dat = nilfs_bmap_get_dat(btree);
	}

	for (level = NILFS_BTREE_LEVEL_NODE_MIN; level <= maxlevel; level++) {
		nilfs_bmap_commit_alloc_ptr(btree,
					    &path[level - 1].bp_newreq, dat);
		path[level].bp_op(btree, path, level, &key, &ptr);
	}

	if (!nilfs_bmap_dirty(btree))
		nilfs_bmap_set_dirty(btree);
}

static int nilfs_btree_insert(struct nilfs_bmap *btree, __u64 key, __u64 ptr)
{
	struct nilfs_btree_path *path;
	struct nilfs_bmap_stats stats;
	int level, ret;

	path = nilfs_btree_alloc_path();
	if (path == NULL)
		return -ENOMEM;

	ret = nilfs_btree_do_lookup(btree, path, key, NULL,
				    NILFS_BTREE_LEVEL_NODE_MIN, 0);
	if (ret != -ENOENT) {
		if (ret == 0)
			ret = -EEXIST;
		goto out;
	}

	ret = nilfs_btree_prepare_insert(btree, path, &level, key, ptr, &stats);
	if (ret < 0)
		goto out;
	nilfs_btree_commit_insert(btree, path, level, key, ptr);
	nilfs_inode_add_blocks(btree->b_inode, stats.bs_nblocks);

 out:
	nilfs_btree_free_path(path);
	return ret;
}

static void nilfs_btree_do_delete(struct nilfs_bmap *btree,
				  struct nilfs_btree_path *path,
				  int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node;
	int ncblk;

	if (level < nilfs_btree_height(btree) - 1) {
		node = nilfs_btree_get_nonroot_node(path, level);
		ncblk = nilfs_btree_nchildren_per_block(btree);
		nilfs_btree_node_delete(node, path[level].bp_index,
					keyp, ptrp, ncblk);
		if (!buffer_dirty(path[level].bp_bh))
			mark_buffer_dirty(path[level].bp_bh);
		if (path[level].bp_index == 0)
			nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(node, 0));
	} else {
		node = nilfs_btree_get_root(btree);
		nilfs_btree_node_delete(node, path[level].bp_index,
					keyp, ptrp,
					NILFS_BTREE_ROOT_NCHILDREN_MAX);
	}
}

static void nilfs_btree_borrow_left(struct nilfs_bmap *btree,
				    struct nilfs_btree_path *path,
				    int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node, *left;
	int nchildren, lnchildren, n, ncblk;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	node = nilfs_btree_get_nonroot_node(path, level);
	left = nilfs_btree_get_sib_node(path, level);
	nchildren = nilfs_btree_node_get_nchildren(node);
	lnchildren = nilfs_btree_node_get_nchildren(left);
	ncblk = nilfs_btree_nchildren_per_block(btree);

	n = (nchildren + lnchildren) / 2 - nchildren;

	nilfs_btree_node_move_right(left, node, n, ncblk, ncblk);

	if (!buffer_dirty(path[level].bp_bh))
		mark_buffer_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		mark_buffer_dirty(path[level].bp_sib_bh);

	nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(node, 0));

	brelse(path[level].bp_sib_bh);
	path[level].bp_sib_bh = NULL;
	path[level].bp_index += n;
}

static void nilfs_btree_borrow_right(struct nilfs_bmap *btree,
				     struct nilfs_btree_path *path,
				     int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node, *right;
	int nchildren, rnchildren, n, ncblk;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	node = nilfs_btree_get_nonroot_node(path, level);
	right = nilfs_btree_get_sib_node(path, level);
	nchildren = nilfs_btree_node_get_nchildren(node);
	rnchildren = nilfs_btree_node_get_nchildren(right);
	ncblk = nilfs_btree_nchildren_per_block(btree);

	n = (nchildren + rnchildren) / 2 - nchildren;

	nilfs_btree_node_move_left(node, right, n, ncblk, ncblk);

	if (!buffer_dirty(path[level].bp_bh))
		mark_buffer_dirty(path[level].bp_bh);
	if (!buffer_dirty(path[level].bp_sib_bh))
		mark_buffer_dirty(path[level].bp_sib_bh);

	path[level + 1].bp_index++;
	nilfs_btree_promote_key(btree, path, level + 1,
				nilfs_btree_node_get_key(right, 0));
	path[level + 1].bp_index--;

	brelse(path[level].bp_sib_bh);
	path[level].bp_sib_bh = NULL;
}

static void nilfs_btree_concat_left(struct nilfs_bmap *btree,
				    struct nilfs_btree_path *path,
				    int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node, *left;
	int n, ncblk;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	node = nilfs_btree_get_nonroot_node(path, level);
	left = nilfs_btree_get_sib_node(path, level);
	ncblk = nilfs_btree_nchildren_per_block(btree);

	n = nilfs_btree_node_get_nchildren(node);

	nilfs_btree_node_move_left(left, node, n, ncblk, ncblk);

	if (!buffer_dirty(path[level].bp_sib_bh))
		mark_buffer_dirty(path[level].bp_sib_bh);

	nilfs_btnode_delete(path[level].bp_bh);
	path[level].bp_bh = path[level].bp_sib_bh;
	path[level].bp_sib_bh = NULL;
	path[level].bp_index += nilfs_btree_node_get_nchildren(left);
}

static void nilfs_btree_concat_right(struct nilfs_bmap *btree,
				     struct nilfs_btree_path *path,
				     int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *node, *right;
	int n, ncblk;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	node = nilfs_btree_get_nonroot_node(path, level);
	right = nilfs_btree_get_sib_node(path, level);
	ncblk = nilfs_btree_nchildren_per_block(btree);

	n = nilfs_btree_node_get_nchildren(right);

	nilfs_btree_node_move_left(node, right, n, ncblk, ncblk);

	if (!buffer_dirty(path[level].bp_bh))
		mark_buffer_dirty(path[level].bp_bh);

	nilfs_btnode_delete(path[level].bp_sib_bh);
	path[level].bp_sib_bh = NULL;
	path[level + 1].bp_index++;
}

static void nilfs_btree_shrink(struct nilfs_bmap *btree,
			       struct nilfs_btree_path *path,
			       int level, __u64 *keyp, __u64 *ptrp)
{
	struct nilfs_btree_node *root, *child;
	int n, ncblk;

	nilfs_btree_do_delete(btree, path, level, keyp, ptrp);

	root = nilfs_btree_get_root(btree);
	child = nilfs_btree_get_nonroot_node(path, level);
	ncblk = nilfs_btree_nchildren_per_block(btree);

	nilfs_btree_node_delete(root, 0, NULL, NULL,
				NILFS_BTREE_ROOT_NCHILDREN_MAX);
	nilfs_btree_node_set_level(root, level);
	n = nilfs_btree_node_get_nchildren(child);
	nilfs_btree_node_move_left(root, child, n,
				   NILFS_BTREE_ROOT_NCHILDREN_MAX, ncblk);

	nilfs_btnode_delete(path[level].bp_bh);
	path[level].bp_bh = NULL;
}

static void nilfs_btree_nop(struct nilfs_bmap *btree,
			    struct nilfs_btree_path *path,
			    int level, __u64 *keyp, __u64 *ptrp)
{
}

static int nilfs_btree_prepare_delete(struct nilfs_bmap *btree,
				      struct nilfs_btree_path *path,
				      int *levelp,
				      struct nilfs_bmap_stats *stats,
				      struct inode *dat)
{
	struct buffer_head *bh;
	struct nilfs_btree_node *node, *parent, *sib;
	__u64 sibptr;
	int pindex, dindex, level, ncmin, ncmax, ncblk, ret;

	ret = 0;
	stats->bs_nblocks = 0;
	ncmin = NILFS_BTREE_NODE_NCHILDREN_MIN(nilfs_btree_node_size(btree));
	ncblk = nilfs_btree_nchildren_per_block(btree);

	for (level = NILFS_BTREE_LEVEL_NODE_MIN, dindex = path[level].bp_index;
	     level < nilfs_btree_height(btree) - 1;
	     level++) {
		node = nilfs_btree_get_nonroot_node(path, level);
		path[level].bp_oldreq.bpr_ptr =
			nilfs_btree_node_get_ptr(node, dindex, ncblk);
		ret = nilfs_bmap_prepare_end_ptr(btree,
						 &path[level].bp_oldreq, dat);
		if (ret < 0)
			goto err_out_child_node;

		if (nilfs_btree_node_get_nchildren(node) > ncmin) {
			path[level].bp_op = nilfs_btree_do_delete;
			stats->bs_nblocks++;
			goto out;
		}

		parent = nilfs_btree_get_node(btree, path, level + 1, &ncmax);
		pindex = path[level + 1].bp_index;
		dindex = pindex;

		if (pindex > 0) {
			/* left sibling */
			sibptr = nilfs_btree_node_get_ptr(parent, pindex - 1,
							  ncmax);
			ret = nilfs_btree_get_block(btree, sibptr, &bh);
			if (ret < 0)
				goto err_out_curr_node;
			sib = (struct nilfs_btree_node *)bh->b_data;
			if (nilfs_btree_node_get_nchildren(sib) > ncmin) {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_borrow_left;
				stats->bs_nblocks++;
				goto out;
			} else {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_concat_left;
				stats->bs_nblocks++;
				/* continue; */
			}
		} else if (pindex <
			   nilfs_btree_node_get_nchildren(parent) - 1) {
			/* right sibling */
			sibptr = nilfs_btree_node_get_ptr(parent, pindex + 1,
							  ncmax);
			ret = nilfs_btree_get_block(btree, sibptr, &bh);
			if (ret < 0)
				goto err_out_curr_node;
			sib = (struct nilfs_btree_node *)bh->b_data;
			if (nilfs_btree_node_get_nchildren(sib) > ncmin) {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_borrow_right;
				stats->bs_nblocks++;
				goto out;
			} else {
				path[level].bp_sib_bh = bh;
				path[level].bp_op = nilfs_btree_concat_right;
				stats->bs_nblocks++;
				/*
				 * When merging right sibling node
				 * into the current node, pointer to
				 * the right sibling node must be
				 * terminated instead.  The adjustment
				 * below is required for that.
				 */
				dindex = pindex + 1;
				/* continue; */
			}
		} else {
			/* no siblings */
			/* the only child of the root node */
			WARN_ON(level != nilfs_btree_height(btree) - 2);
			if (nilfs_btree_node_get_nchildren(node) - 1 <=
			    NILFS_BTREE_ROOT_NCHILDREN_MAX) {
				path[level].bp_op = nilfs_btree_shrink;
				stats->bs_nblocks += 2;
				level++;
				path[level].bp_op = nilfs_btree_nop;
				goto shrink_root_child;
			} else {
				path[level].bp_op = nilfs_btree_do_delete;
				stats->bs_nblocks++;
				goto out;
			}
		}
	}

	/* child of the root node is deleted */
	path[level].bp_op = nilfs_btree_do_delete;
	stats->bs_nblocks++;

shrink_root_child:
	node = nilfs_btree_get_root(btree);
	path[level].bp_oldreq.bpr_ptr =
		nilfs_btree_node_get_ptr(node, dindex,
					 NILFS_BTREE_ROOT_NCHILDREN_MAX);

	ret = nilfs_bmap_prepare_end_ptr(btree, &path[level].bp_oldreq, dat);
	if (ret < 0)
		goto err_out_child_node;

	/* success */
 out:
	*levelp = level;
	return ret;

	/* error */
 err_out_curr_node:
	nilfs_bmap_abort_end_ptr(btree, &path[level].bp_oldreq, dat);
 err_out_child_node:
	for (level--; level >= NILFS_BTREE_LEVEL_NODE_MIN; level--) {
		brelse(path[level].bp_sib_bh);
		nilfs_bmap_abort_end_ptr(btree, &path[level].bp_oldreq, dat);
	}
	*levelp = level;
	stats->bs_nblocks = 0;
	return ret;
}

static void nilfs_btree_commit_delete(struct nilfs_bmap *btree,
				      struct nilfs_btree_path *path,
				      int maxlevel, struct inode *dat)
{
	int level;

	for (level = NILFS_BTREE_LEVEL_NODE_MIN; level <= maxlevel; level++) {
		nilfs_bmap_commit_end_ptr(btree, &path[level].bp_oldreq, dat);
		path[level].bp_op(btree, path, level, NULL, NULL);
	}

	if (!nilfs_bmap_dirty(btree))
		nilfs_bmap_set_dirty(btree);
}

static int nilfs_btree_delete(struct nilfs_bmap *btree, __u64 key)

{
	struct nilfs_btree_path *path;
	struct nilfs_bmap_stats stats;
	struct inode *dat;
	int level, ret;

	path = nilfs_btree_alloc_path();
	if (path == NULL)
		return -ENOMEM;

	ret = nilfs_btree_do_lookup(btree, path, key, NULL,
				    NILFS_BTREE_LEVEL_NODE_MIN, 0);
	if (ret < 0)
		goto out;


	dat = NILFS_BMAP_USE_VBN(btree) ? nilfs_bmap_get_dat(btree) : NULL;

	ret = nilfs_btree_prepare_delete(btree, path, &level, &stats, dat);
	if (ret < 0)
		goto out;
	nilfs_btree_commit_delete(btree, path, level, dat);
	nilfs_inode_sub_blocks(btree->b_inode, stats.bs_nblocks);

out:
	nilfs_btree_free_path(path);
	return ret;
}

static int nilfs_btree_last_key(const struct nilfs_bmap *btree, __u64 *keyp)
{
	struct nilfs_btree_path *path;
	int ret;

	path = nilfs_btree_alloc_path();
	if (path == NULL)
		return -ENOMEM;

	ret = nilfs_btree_do_lookup_last(btree, path, keyp, NULL);

	nilfs_btree_free_path(path);

	return ret;
}

static int nilfs_btree_check_delete(struct nilfs_bmap *btree, __u64 key)
{
	struct buffer_head *bh;
	struct nilfs_btree_node *root, *node;
	__u64 maxkey, nextmaxkey;
	__u64 ptr;
	int nchildren, ret;

	root = nilfs_btree_get_root(btree);
	switch (nilfs_btree_height(btree)) {
	case 2:
		bh = NULL;
		node = root;
		break;
	case 3:
		nchildren = nilfs_btree_node_get_nchildren(root);
		if (nchildren > 1)
			return 0;
		ptr = nilfs_btree_node_get_ptr(root, nchildren - 1,
					       NILFS_BTREE_ROOT_NCHILDREN_MAX);
		ret = nilfs_btree_get_block(btree, ptr, &bh);
		if (ret < 0)
			return ret;
		node = (struct nilfs_btree_node *)bh->b_data;
		break;
	default:
		return 0;
	}

	nchildren = nilfs_btree_node_get_nchildren(node);
	maxkey = nilfs_btree_node_get_key(node, nchildren - 1);
	nextmaxkey = (nchildren > 1) ?
		nilfs_btree_node_get_key(node, nchildren - 2) : 0;
	if (bh != NULL)
		brelse(bh);

	return (maxkey == key) && (nextmaxkey < NILFS_BMAP_LARGE_LOW);
}

static int nilfs_btree_gather_data(struct nilfs_bmap *btree,
				   __u64 *keys, __u64 *ptrs, int nitems)
{
	struct buffer_head *bh;
	struct nilfs_btree_node *node, *root;
	__le64 *dkeys;
	__le64 *dptrs;
	__u64 ptr;
	int nchildren, ncmax, i, ret;

	root = nilfs_btree_get_root(btree);
	switch (nilfs_btree_height(btree)) {
	case 2:
		bh = NULL;
		node = root;
		ncmax = NILFS_BTREE_ROOT_NCHILDREN_MAX;
		break;
	case 3:
		nchildren = nilfs_btree_node_get_nchildren(root);
		WARN_ON(nchildren > 1);
		ptr = nilfs_btree_node_get_ptr(root, nchildren - 1,
					       NILFS_BTREE_ROOT_NCHILDREN_MAX);
		ret = nilfs_btree_get_block(btree, ptr, &bh);
		if (ret < 0)
			return ret;
		node = (struct nilfs_btree_node *)bh->b_data;
		ncmax = nilfs_btree_nchildren_per_block(btree);
		break;
	default:
		node = NULL;
		return -EINVAL;
	}

	nchildren = nilfs_btree_node_get_nchildren(node);
	if (nchildren < nitems)
		nitems = nchildren;
	dkeys = nilfs_btree_node_dkeys(node);
	dptrs = nilfs_btree_node_dptrs(node, ncmax);
	for (i = 0; i < nitems; i++) {
		keys[i] = le64_to_cpu(dkeys[i]);
		ptrs[i] = le64_to_cpu(dptrs[i]);
	}

	if (bh != NULL)
		brelse(bh);

	return nitems;
}

static int
nilfs_btree_prepare_convert_and_insert(struct nilfs_bmap *btree, __u64 key,
				       union nilfs_bmap_ptr_req *dreq,
				       union nilfs_bmap_ptr_req *nreq,
				       struct buffer_head **bhp,
				       struct nilfs_bmap_stats *stats)
{
	struct buffer_head *bh;
	struct inode *dat = NULL;
	int ret;

	stats->bs_nblocks = 0;

	/* for data */
	/* cannot find near ptr */
	if (NILFS_BMAP_USE_VBN(btree)) {
		dreq->bpr_ptr = nilfs_btree_find_target_v(btree, NULL, key);
		dat = nilfs_bmap_get_dat(btree);
	}

	ret = nilfs_bmap_prepare_alloc_ptr(btree, dreq, dat);
	if (ret < 0)
		return ret;

	*bhp = NULL;
	stats->bs_nblocks++;
	if (nreq != NULL) {
		nreq->bpr_ptr = dreq->bpr_ptr + 1;
		ret = nilfs_bmap_prepare_alloc_ptr(btree, nreq, dat);
		if (ret < 0)
			goto err_out_dreq;

		ret = nilfs_btree_get_new_block(btree, nreq->bpr_ptr, &bh);
		if (ret < 0)
			goto err_out_nreq;

		*bhp = bh;
		stats->bs_nblocks++;
	}

	/* success */
	return 0;

	/* error */
 err_out_nreq:
	nilfs_bmap_abort_alloc_ptr(btree, nreq, dat);
 err_out_dreq:
	nilfs_bmap_abort_alloc_ptr(btree, dreq, dat);
	stats->bs_nblocks = 0;
	return ret;

}

static void
nilfs_btree_commit_convert_and_insert(struct nilfs_bmap *btree,
				      __u64 key, __u64 ptr,
				      const __u64 *keys, const __u64 *ptrs,
				      int n,
				      union nilfs_bmap_ptr_req *dreq,
				      union nilfs_bmap_ptr_req *nreq,
				      struct buffer_head *bh)
{
	struct nilfs_btree_node *node;
	struct inode *dat;
	__u64 tmpptr;
	int ncblk;

	/* free resources */
	if (btree->b_ops->bop_clear != NULL)
		btree->b_ops->bop_clear(btree);

	/* ptr must be a pointer to a buffer head. */
	set_buffer_nilfs_volatile((struct buffer_head *)((unsigned long)ptr));

	/* convert and insert */
	dat = NILFS_BMAP_USE_VBN(btree) ? nilfs_bmap_get_dat(btree) : NULL;
	nilfs_btree_init(btree);
	if (nreq != NULL) {
		nilfs_bmap_commit_alloc_ptr(btree, dreq, dat);
		nilfs_bmap_commit_alloc_ptr(btree, nreq, dat);

		/* create child node at level 1 */
		node = (struct nilfs_btree_node *)bh->b_data;
		ncblk = nilfs_btree_nchildren_per_block(btree);
		nilfs_btree_node_init(node, 0, 1, n, ncblk, keys, ptrs);
		nilfs_btree_node_insert(node, n, key, dreq->bpr_ptr, ncblk);
		if (!buffer_dirty(bh))
			mark_buffer_dirty(bh);
		if (!nilfs_bmap_dirty(btree))
			nilfs_bmap_set_dirty(btree);

		brelse(bh);

		/* create root node at level 2 */
		node = nilfs_btree_get_root(btree);
		tmpptr = nreq->bpr_ptr;
		nilfs_btree_node_init(node, NILFS_BTREE_NODE_ROOT, 2, 1,
				      NILFS_BTREE_ROOT_NCHILDREN_MAX,
				      &keys[0], &tmpptr);
	} else {
		nilfs_bmap_commit_alloc_ptr(btree, dreq, dat);

		/* create root node at level 1 */
		node = nilfs_btree_get_root(btree);
		nilfs_btree_node_init(node, NILFS_BTREE_NODE_ROOT, 1, n,
				      NILFS_BTREE_ROOT_NCHILDREN_MAX,
				      keys, ptrs);
		nilfs_btree_node_insert(node, n, key, dreq->bpr_ptr,
					NILFS_BTREE_ROOT_NCHILDREN_MAX);
		if (!nilfs_bmap_dirty(btree))
			nilfs_bmap_set_dirty(btree);
	}

	if (NILFS_BMAP_USE_VBN(btree))
		nilfs_bmap_set_target_v(btree, key, dreq->bpr_ptr);
}

/**
 * nilfs_btree_convert_and_insert -
 * @bmap:
 * @key:
 * @ptr:
 * @keys:
 * @ptrs:
 * @n:
 */
int nilfs_btree_convert_and_insert(struct nilfs_bmap *btree,
				   __u64 key, __u64 ptr,
				   const __u64 *keys, const __u64 *ptrs, int n)
{
	struct buffer_head *bh;
	union nilfs_bmap_ptr_req dreq, nreq, *di, *ni;
	struct nilfs_bmap_stats stats;
	int ret;

	if (n + 1 <= NILFS_BTREE_ROOT_NCHILDREN_MAX) {
		di = &dreq;
		ni = NULL;
	} else if ((n + 1) <= NILFS_BTREE_NODE_NCHILDREN_MAX(
			   1 << btree->b_inode->i_blkbits)) {
		di = &dreq;
		ni = &nreq;
	} else {
		di = NULL;
		ni = NULL;
		BUG();
	}

	ret = nilfs_btree_prepare_convert_and_insert(btree, key, di, ni, &bh,
						     &stats);
	if (ret < 0)
		return ret;
	nilfs_btree_commit_convert_and_insert(btree, key, ptr, keys, ptrs, n,
					      di, ni, bh);
	nilfs_inode_add_blocks(btree->b_inode, stats.bs_nblocks);
	return 0;
}

static int nilfs_btree_propagate_p(struct nilfs_bmap *btree,
				   struct nilfs_btree_path *path,
				   int level,
				   struct buffer_head *bh)
{
	while ((++level < nilfs_btree_height(btree) - 1) &&
	       !buffer_dirty(path[level].bp_bh))
		mark_buffer_dirty(path[level].bp_bh);

	return 0;
}

static int nilfs_btree_prepare_update_v(struct nilfs_bmap *btree,
					struct nilfs_btree_path *path,
					int level, struct inode *dat)
{
	struct nilfs_btree_node *parent;
	int ncmax, ret;

	parent = nilfs_btree_get_node(btree, path, level + 1, &ncmax);
	path[level].bp_oldreq.bpr_ptr =
		nilfs_btree_node_get_ptr(parent, path[level + 1].bp_index,
					 ncmax);
	path[level].bp_newreq.bpr_ptr = path[level].bp_oldreq.bpr_ptr + 1;
	ret = nilfs_dat_prepare_update(dat, &path[level].bp_oldreq.bpr_req,
				       &path[level].bp_newreq.bpr_req);
	if (ret < 0)
		return ret;

	if (buffer_nilfs_node(path[level].bp_bh)) {
		path[level].bp_ctxt.oldkey = path[level].bp_oldreq.bpr_ptr;
		path[level].bp_ctxt.newkey = path[level].bp_newreq.bpr_ptr;
		path[level].bp_ctxt.bh = path[level].bp_bh;
		ret = nilfs_btnode_prepare_change_key(
			&NILFS_BMAP_I(btree)->i_btnode_cache,
			&path[level].bp_ctxt);
		if (ret < 0) {
			nilfs_dat_abort_update(dat,
					       &path[level].bp_oldreq.bpr_req,
					       &path[level].bp_newreq.bpr_req);
			return ret;
		}
	}

	return 0;
}

static void nilfs_btree_commit_update_v(struct nilfs_bmap *btree,
					struct nilfs_btree_path *path,
					int level, struct inode *dat)
{
	struct nilfs_btree_node *parent;
	int ncmax;

	nilfs_dat_commit_update(dat, &path[level].bp_oldreq.bpr_req,
				&path[level].bp_newreq.bpr_req,
				btree->b_ptr_type == NILFS_BMAP_PTR_VS);

	if (buffer_nilfs_node(path[level].bp_bh)) {
		nilfs_btnode_commit_change_key(
			&NILFS_BMAP_I(btree)->i_btnode_cache,
			&path[level].bp_ctxt);
		path[level].bp_bh = path[level].bp_ctxt.bh;
	}
	set_buffer_nilfs_volatile(path[level].bp_bh);

	parent = nilfs_btree_get_node(btree, path, level + 1, &ncmax);
	nilfs_btree_node_set_ptr(parent, path[level + 1].bp_index,
				 path[level].bp_newreq.bpr_ptr, ncmax);
}

static void nilfs_btree_abort_update_v(struct nilfs_bmap *btree,
				       struct nilfs_btree_path *path,
				       int level, struct inode *dat)
{
	nilfs_dat_abort_update(dat, &path[level].bp_oldreq.bpr_req,
			       &path[level].bp_newreq.bpr_req);
	if (buffer_nilfs_node(path[level].bp_bh))
		nilfs_btnode_abort_change_key(
			&NILFS_BMAP_I(btree)->i_btnode_cache,
			&path[level].bp_ctxt);
}

static int nilfs_btree_prepare_propagate_v(struct nilfs_bmap *btree,
					   struct nilfs_btree_path *path,
					   int minlevel, int *maxlevelp,
					   struct inode *dat)
{
	int level, ret;

	level = minlevel;
	if (!buffer_nilfs_volatile(path[level].bp_bh)) {
		ret = nilfs_btree_prepare_update_v(btree, path, level, dat);
		if (ret < 0)
			return ret;
	}
	while ((++level < nilfs_btree_height(btree) - 1) &&
	       !buffer_dirty(path[level].bp_bh)) {

		WARN_ON(buffer_nilfs_volatile(path[level].bp_bh));
		ret = nilfs_btree_prepare_update_v(btree, path, level, dat);
		if (ret < 0)
			goto out;
	}

	/* success */
	*maxlevelp = level - 1;
	return 0;

	/* error */
 out:
	while (--level > minlevel)
		nilfs_btree_abort_update_v(btree, path, level, dat);
	if (!buffer_nilfs_volatile(path[level].bp_bh))
		nilfs_btree_abort_update_v(btree, path, level, dat);
	return ret;
}

static void nilfs_btree_commit_propagate_v(struct nilfs_bmap *btree,
					   struct nilfs_btree_path *path,
					   int minlevel, int maxlevel,
					   struct buffer_head *bh,
					   struct inode *dat)
{
	int level;

	if (!buffer_nilfs_volatile(path[minlevel].bp_bh))
		nilfs_btree_commit_update_v(btree, path, minlevel, dat);

	for (level = minlevel + 1; level <= maxlevel; level++)
		nilfs_btree_commit_update_v(btree, path, level, dat);
}

static int nilfs_btree_propagate_v(struct nilfs_bmap *btree,
				   struct nilfs_btree_path *path,
				   int level, struct buffer_head *bh)
{
	int maxlevel = 0, ret;
	struct nilfs_btree_node *parent;
	struct inode *dat = nilfs_bmap_get_dat(btree);
	__u64 ptr;
	int ncmax;

	get_bh(bh);
	path[level].bp_bh = bh;
	ret = nilfs_btree_prepare_propagate_v(btree, path, level, &maxlevel,
					      dat);
	if (ret < 0)
		goto out;

	if (buffer_nilfs_volatile(path[level].bp_bh)) {
		parent = nilfs_btree_get_node(btree, path, level + 1, &ncmax);
		ptr = nilfs_btree_node_get_ptr(parent,
					       path[level + 1].bp_index,
					       ncmax);
		ret = nilfs_dat_mark_dirty(dat, ptr);
		if (ret < 0)
			goto out;
	}

	nilfs_btree_commit_propagate_v(btree, path, level, maxlevel, bh, dat);

 out:
	brelse(path[level].bp_bh);
	path[level].bp_bh = NULL;
	return ret;
}

static int nilfs_btree_propagate(struct nilfs_bmap *btree,
				 struct buffer_head *bh)
{
	struct nilfs_btree_path *path;
	struct nilfs_btree_node *node;
	__u64 key;
	int level, ret;

	WARN_ON(!buffer_dirty(bh));

	path = nilfs_btree_alloc_path();
	if (path == NULL)
		return -ENOMEM;

	if (buffer_nilfs_node(bh)) {
		node = (struct nilfs_btree_node *)bh->b_data;
		key = nilfs_btree_node_get_key(node, 0);
		level = nilfs_btree_node_get_level(node);
	} else {
		key = nilfs_bmap_data_get_key(btree, bh);
		level = NILFS_BTREE_LEVEL_DATA;
	}

	ret = nilfs_btree_do_lookup(btree, path, key, NULL, level + 1, 0);
	if (ret < 0) {
		if (unlikely(ret == -ENOENT))
			printk(KERN_CRIT "%s: key = %llu, level == %d\n",
			       __func__, (unsigned long long)key, level);
		goto out;
	}

	ret = NILFS_BMAP_USE_VBN(btree) ?
		nilfs_btree_propagate_v(btree, path, level, bh) :
		nilfs_btree_propagate_p(btree, path, level, bh);

 out:
	nilfs_btree_free_path(path);

	return ret;
}

static int nilfs_btree_propagate_gc(struct nilfs_bmap *btree,
				    struct buffer_head *bh)
{
	return nilfs_dat_mark_dirty(nilfs_bmap_get_dat(btree), bh->b_blocknr);
}

static void nilfs_btree_add_dirty_buffer(struct nilfs_bmap *btree,
					 struct list_head *lists,
					 struct buffer_head *bh)
{
	struct list_head *head;
	struct buffer_head *cbh;
	struct nilfs_btree_node *node, *cnode;
	__u64 key, ckey;
	int level;

	get_bh(bh);
	node = (struct nilfs_btree_node *)bh->b_data;
	key = nilfs_btree_node_get_key(node, 0);
	level = nilfs_btree_node_get_level(node);
	if (level < NILFS_BTREE_LEVEL_NODE_MIN ||
	    level >= NILFS_BTREE_LEVEL_MAX) {
		dump_stack();
		printk(KERN_WARNING
		       "%s: invalid btree level: %d (key=%llu, ino=%lu, "
		       "blocknr=%llu)\n",
		       __func__, level, (unsigned long long)key,
		       NILFS_BMAP_I(btree)->vfs_inode.i_ino,
		       (unsigned long long)bh->b_blocknr);
		return;
	}

	list_for_each(head, &lists[level]) {
		cbh = list_entry(head, struct buffer_head, b_assoc_buffers);
		cnode = (struct nilfs_btree_node *)cbh->b_data;
		ckey = nilfs_btree_node_get_key(cnode, 0);
		if (key < ckey)
			break;
	}
	list_add_tail(&bh->b_assoc_buffers, head);
}

static void nilfs_btree_lookup_dirty_buffers(struct nilfs_bmap *btree,
					     struct list_head *listp)
{
	struct address_space *btcache = &NILFS_BMAP_I(btree)->i_btnode_cache;
	struct list_head lists[NILFS_BTREE_LEVEL_MAX];
	struct pagevec pvec;
	struct buffer_head *bh, *head;
	pgoff_t index = 0;
	int level, i;

	for (level = NILFS_BTREE_LEVEL_NODE_MIN;
	     level < NILFS_BTREE_LEVEL_MAX;
	     level++)
		INIT_LIST_HEAD(&lists[level]);

	pagevec_init(&pvec, 0);

	while (pagevec_lookup_tag(&pvec, btcache, &index, PAGECACHE_TAG_DIRTY,
				  PAGEVEC_SIZE)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			bh = head = page_buffers(pvec.pages[i]);
			do {
				if (buffer_dirty(bh))
					nilfs_btree_add_dirty_buffer(btree,
								     lists, bh);
			} while ((bh = bh->b_this_page) != head);
		}
		pagevec_release(&pvec);
		cond_resched();
	}

	for (level = NILFS_BTREE_LEVEL_NODE_MIN;
	     level < NILFS_BTREE_LEVEL_MAX;
	     level++)
		list_splice_tail(&lists[level], listp);
}

static int nilfs_btree_assign_p(struct nilfs_bmap *btree,
				struct nilfs_btree_path *path,
				int level,
				struct buffer_head **bh,
				sector_t blocknr,
				union nilfs_binfo *binfo)
{
	struct nilfs_btree_node *parent;
	__u64 key;
	__u64 ptr;
	int ncmax, ret;

	parent = nilfs_btree_get_node(btree, path, level + 1, &ncmax);
	ptr = nilfs_btree_node_get_ptr(parent, path[level + 1].bp_index,
				       ncmax);
	if (buffer_nilfs_node(*bh)) {
		path[level].bp_ctxt.oldkey = ptr;
		path[level].bp_ctxt.newkey = blocknr;
		path[level].bp_ctxt.bh = *bh;
		ret = nilfs_btnode_prepare_change_key(
			&NILFS_BMAP_I(btree)->i_btnode_cache,
			&path[level].bp_ctxt);
		if (ret < 0)
			return ret;
		nilfs_btnode_commit_change_key(
			&NILFS_BMAP_I(btree)->i_btnode_cache,
			&path[level].bp_ctxt);
		*bh = path[level].bp_ctxt.bh;
	}

	nilfs_btree_node_set_ptr(parent, path[level + 1].bp_index, blocknr,
				 ncmax);

	key = nilfs_btree_node_get_key(parent, path[level + 1].bp_index);
	/* on-disk format */
	binfo->bi_dat.bi_blkoff = cpu_to_le64(key);
	binfo->bi_dat.bi_level = level;

	return 0;
}

static int nilfs_btree_assign_v(struct nilfs_bmap *btree,
				struct nilfs_btree_path *path,
				int level,
				struct buffer_head **bh,
				sector_t blocknr,
				union nilfs_binfo *binfo)
{
	struct nilfs_btree_node *parent;
	struct inode *dat = nilfs_bmap_get_dat(btree);
	__u64 key;
	__u64 ptr;
	union nilfs_bmap_ptr_req req;
	int ncmax, ret;

	parent = nilfs_btree_get_node(btree, path, level + 1, &ncmax);
	ptr = nilfs_btree_node_get_ptr(parent, path[level + 1].bp_index,
				       ncmax);
	req.bpr_ptr = ptr;
	ret = nilfs_dat_prepare_start(dat, &req.bpr_req);
	if (ret < 0)
		return ret;
	nilfs_dat_commit_start(dat, &req.bpr_req, blocknr);

	key = nilfs_btree_node_get_key(parent, path[level + 1].bp_index);
	/* on-disk format */
	binfo->bi_v.bi_vblocknr = cpu_to_le64(ptr);
	binfo->bi_v.bi_blkoff = cpu_to_le64(key);

	return 0;
}

static int nilfs_btree_assign(struct nilfs_bmap *btree,
			      struct buffer_head **bh,
			      sector_t blocknr,
			      union nilfs_binfo *binfo)
{
	struct nilfs_btree_path *path;
	struct nilfs_btree_node *node;
	__u64 key;
	int level, ret;

	path = nilfs_btree_alloc_path();
	if (path == NULL)
		return -ENOMEM;

	if (buffer_nilfs_node(*bh)) {
		node = (struct nilfs_btree_node *)(*bh)->b_data;
		key = nilfs_btree_node_get_key(node, 0);
		level = nilfs_btree_node_get_level(node);
	} else {
		key = nilfs_bmap_data_get_key(btree, *bh);
		level = NILFS_BTREE_LEVEL_DATA;
	}

	ret = nilfs_btree_do_lookup(btree, path, key, NULL, level + 1, 0);
	if (ret < 0) {
		WARN_ON(ret == -ENOENT);
		goto out;
	}

	ret = NILFS_BMAP_USE_VBN(btree) ?
		nilfs_btree_assign_v(btree, path, level, bh, blocknr, binfo) :
		nilfs_btree_assign_p(btree, path, level, bh, blocknr, binfo);

 out:
	nilfs_btree_free_path(path);

	return ret;
}

static int nilfs_btree_assign_gc(struct nilfs_bmap *btree,
				 struct buffer_head **bh,
				 sector_t blocknr,
				 union nilfs_binfo *binfo)
{
	struct nilfs_btree_node *node;
	__u64 key;
	int ret;

	ret = nilfs_dat_move(nilfs_bmap_get_dat(btree), (*bh)->b_blocknr,
			     blocknr);
	if (ret < 0)
		return ret;

	if (buffer_nilfs_node(*bh)) {
		node = (struct nilfs_btree_node *)(*bh)->b_data;
		key = nilfs_btree_node_get_key(node, 0);
	} else
		key = nilfs_bmap_data_get_key(btree, *bh);

	/* on-disk format */
	binfo->bi_v.bi_vblocknr = cpu_to_le64((*bh)->b_blocknr);
	binfo->bi_v.bi_blkoff = cpu_to_le64(key);

	return 0;
}

static int nilfs_btree_mark(struct nilfs_bmap *btree, __u64 key, int level)
{
	struct buffer_head *bh;
	struct nilfs_btree_path *path;
	__u64 ptr;
	int ret;

	path = nilfs_btree_alloc_path();
	if (path == NULL)
		return -ENOMEM;

	ret = nilfs_btree_do_lookup(btree, path, key, &ptr, level + 1, 0);
	if (ret < 0) {
		WARN_ON(ret == -ENOENT);
		goto out;
	}
	ret = nilfs_btree_get_block(btree, ptr, &bh);
	if (ret < 0) {
		WARN_ON(ret == -ENOENT);
		goto out;
	}

	if (!buffer_dirty(bh))
		mark_buffer_dirty(bh);
	brelse(bh);
	if (!nilfs_bmap_dirty(btree))
		nilfs_bmap_set_dirty(btree);

 out:
	nilfs_btree_free_path(path);
	return ret;
}

static const struct nilfs_bmap_operations nilfs_btree_ops = {
	.bop_lookup		=	nilfs_btree_lookup,
	.bop_lookup_contig	=	nilfs_btree_lookup_contig,
	.bop_insert		=	nilfs_btree_insert,
	.bop_delete		=	nilfs_btree_delete,
	.bop_clear		=	NULL,

	.bop_propagate		=	nilfs_btree_propagate,

	.bop_lookup_dirty_buffers =	nilfs_btree_lookup_dirty_buffers,

	.bop_assign		=	nilfs_btree_assign,
	.bop_mark		=	nilfs_btree_mark,

	.bop_last_key		=	nilfs_btree_last_key,
	.bop_check_insert	=	NULL,
	.bop_check_delete	=	nilfs_btree_check_delete,
	.bop_gather_data	=	nilfs_btree_gather_data,
};

static const struct nilfs_bmap_operations nilfs_btree_ops_gc = {
	.bop_lookup		=	NULL,
	.bop_lookup_contig	=	NULL,
	.bop_insert		=	NULL,
	.bop_delete		=	NULL,
	.bop_clear		=	NULL,

	.bop_propagate		=	nilfs_btree_propagate_gc,

	.bop_lookup_dirty_buffers =	nilfs_btree_lookup_dirty_buffers,

	.bop_assign		=	nilfs_btree_assign_gc,
	.bop_mark		=	NULL,

	.bop_last_key		=	NULL,
	.bop_check_insert	=	NULL,
	.bop_check_delete	=	NULL,
	.bop_gather_data	=	NULL,
};

int nilfs_btree_init(struct nilfs_bmap *bmap)
{
	bmap->b_ops = &nilfs_btree_ops;
	bmap->b_nchildren_per_block =
		NILFS_BTREE_NODE_NCHILDREN_MAX(nilfs_btree_node_size(bmap));
	return 0;
}

void nilfs_btree_init_gc(struct nilfs_bmap *bmap)
{
	bmap->b_ops = &nilfs_btree_ops_gc;
	bmap->b_nchildren_per_block =
		NILFS_BTREE_NODE_NCHILDREN_MAX(nilfs_btree_node_size(bmap));
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/btree.c */
/************************************************************/
/*
 * direct.c - NILFS direct block pointer.
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Koji Sato <koji@osrg.net>.
 */

// #include <linux/errno.h>
// #include "nilfs.h"
// #include "page.h"
// #include "direct.h"
// #include "alloc.h"
// #include "dat.h"

static inline __le64 *nilfs_direct_dptrs(const struct nilfs_bmap *direct)
{
	return (__le64 *)
		((struct nilfs_direct_node *)direct->b_u.u_data + 1);
}

static inline __u64
nilfs_direct_get_ptr(const struct nilfs_bmap *direct, __u64 key)
{
	return le64_to_cpu(*(nilfs_direct_dptrs(direct) + key));
}

static inline void nilfs_direct_set_ptr(struct nilfs_bmap *direct,
					__u64 key, __u64 ptr)
{
	*(nilfs_direct_dptrs(direct) + key) = cpu_to_le64(ptr);
}

static int nilfs_direct_lookup(const struct nilfs_bmap *direct,
			       __u64 key, int level, __u64 *ptrp)
{
	__u64 ptr;

	if (key > NILFS_DIRECT_KEY_MAX || level != 1)
		return -ENOENT;
	ptr = nilfs_direct_get_ptr(direct, key);
	if (ptr == NILFS_BMAP_INVALID_PTR)
		return -ENOENT;

	*ptrp = ptr;
	return 0;
}

static int nilfs_direct_lookup_contig(const struct nilfs_bmap *direct,
				      __u64 key, __u64 *ptrp,
				      unsigned maxblocks)
{
	struct inode *dat = NULL;
	__u64 ptr, ptr2;
	sector_t blocknr;
	int ret, cnt;

	if (key > NILFS_DIRECT_KEY_MAX)
		return -ENOENT;
	ptr = nilfs_direct_get_ptr(direct, key);
	if (ptr == NILFS_BMAP_INVALID_PTR)
		return -ENOENT;

	if (NILFS_BMAP_USE_VBN(direct)) {
		dat = nilfs_bmap_get_dat(direct);
		ret = nilfs_dat_translate(dat, ptr, &blocknr);
		if (ret < 0)
			return ret;
		ptr = blocknr;
	}

	maxblocks = min_t(unsigned, maxblocks, NILFS_DIRECT_KEY_MAX - key + 1);
	for (cnt = 1; cnt < maxblocks &&
		     (ptr2 = nilfs_direct_get_ptr(direct, key + cnt)) !=
		     NILFS_BMAP_INVALID_PTR;
	     cnt++) {
		if (dat) {
			ret = nilfs_dat_translate(dat, ptr2, &blocknr);
			if (ret < 0)
				return ret;
			ptr2 = blocknr;
		}
		if (ptr2 != ptr + cnt)
			break;
	}
	*ptrp = ptr;
	return cnt;
}

static __u64
nilfs_direct_find_target_v(const struct nilfs_bmap *direct, __u64 key)
{
	__u64 ptr;

	ptr = nilfs_bmap_find_target_seq(direct, key);
	if (ptr != NILFS_BMAP_INVALID_PTR)
		/* sequential access */
		return ptr;
	else
		/* block group */
		return nilfs_bmap_find_target_in_group(direct);
}

static int nilfs_direct_insert(struct nilfs_bmap *bmap, __u64 key, __u64 ptr)
{
	union nilfs_bmap_ptr_req req;
	struct inode *dat = NULL;
	struct buffer_head *bh;
	int ret;

	if (key > NILFS_DIRECT_KEY_MAX)
		return -ENOENT;
	if (nilfs_direct_get_ptr(bmap, key) != NILFS_BMAP_INVALID_PTR)
		return -EEXIST;

	if (NILFS_BMAP_USE_VBN(bmap)) {
		req.bpr_ptr = nilfs_direct_find_target_v(bmap, key);
		dat = nilfs_bmap_get_dat(bmap);
	}
	ret = nilfs_bmap_prepare_alloc_ptr(bmap, &req, dat);
	if (!ret) {
		/* ptr must be a pointer to a buffer head. */
		bh = (struct buffer_head *)((unsigned long)ptr);
		set_buffer_nilfs_volatile(bh);

		nilfs_bmap_commit_alloc_ptr(bmap, &req, dat);
		nilfs_direct_set_ptr(bmap, key, req.bpr_ptr);

		if (!nilfs_bmap_dirty(bmap))
			nilfs_bmap_set_dirty(bmap);

		if (NILFS_BMAP_USE_VBN(bmap))
			nilfs_bmap_set_target_v(bmap, key, req.bpr_ptr);

		nilfs_inode_add_blocks(bmap->b_inode, 1);
	}
	return ret;
}

static int nilfs_direct_delete(struct nilfs_bmap *bmap, __u64 key)
{
	union nilfs_bmap_ptr_req req;
	struct inode *dat;
	int ret;

	if (key > NILFS_DIRECT_KEY_MAX ||
	    nilfs_direct_get_ptr(bmap, key) == NILFS_BMAP_INVALID_PTR)
		return -ENOENT;

	dat = NILFS_BMAP_USE_VBN(bmap) ? nilfs_bmap_get_dat(bmap) : NULL;
	req.bpr_ptr = nilfs_direct_get_ptr(bmap, key);

	ret = nilfs_bmap_prepare_end_ptr(bmap, &req, dat);
	if (!ret) {
		nilfs_bmap_commit_end_ptr(bmap, &req, dat);
		nilfs_direct_set_ptr(bmap, key, NILFS_BMAP_INVALID_PTR);
		nilfs_inode_sub_blocks(bmap->b_inode, 1);
	}
	return ret;
}

static int nilfs_direct_last_key(const struct nilfs_bmap *direct, __u64 *keyp)
{
	__u64 key, lastkey;

	lastkey = NILFS_DIRECT_KEY_MAX + 1;
	for (key = NILFS_DIRECT_KEY_MIN; key <= NILFS_DIRECT_KEY_MAX; key++)
		if (nilfs_direct_get_ptr(direct, key) !=
		    NILFS_BMAP_INVALID_PTR)
			lastkey = key;

	if (lastkey == NILFS_DIRECT_KEY_MAX + 1)
		return -ENOENT;

	*keyp = lastkey;

	return 0;
}

static int nilfs_direct_check_insert(const struct nilfs_bmap *bmap, __u64 key)
{
	return key > NILFS_DIRECT_KEY_MAX;
}

static int nilfs_direct_gather_data(struct nilfs_bmap *direct,
				    __u64 *keys, __u64 *ptrs, int nitems)
{
	__u64 key;
	__u64 ptr;
	int n;

	if (nitems > NILFS_DIRECT_NBLOCKS)
		nitems = NILFS_DIRECT_NBLOCKS;
	n = 0;
	for (key = 0; key < nitems; key++) {
		ptr = nilfs_direct_get_ptr(direct, key);
		if (ptr != NILFS_BMAP_INVALID_PTR) {
			keys[n] = key;
			ptrs[n] = ptr;
			n++;
		}
	}
	return n;
}

int nilfs_direct_delete_and_convert(struct nilfs_bmap *bmap,
				    __u64 key, __u64 *keys, __u64 *ptrs, int n)
{
	__le64 *dptrs;
	int ret, i, j;

	/* no need to allocate any resource for conversion */

	/* delete */
	ret = bmap->b_ops->bop_delete(bmap, key);
	if (ret < 0)
		return ret;

	/* free resources */
	if (bmap->b_ops->bop_clear != NULL)
		bmap->b_ops->bop_clear(bmap);

	/* convert */
	dptrs = nilfs_direct_dptrs(bmap);
	for (i = 0, j = 0; i < NILFS_DIRECT_NBLOCKS; i++) {
		if ((j < n) && (i == keys[j])) {
			dptrs[i] = (i != key) ?
				cpu_to_le64(ptrs[j]) :
				NILFS_BMAP_INVALID_PTR;
			j++;
		} else
			dptrs[i] = NILFS_BMAP_INVALID_PTR;
	}

	nilfs_direct_init(bmap);
	return 0;
}

static int nilfs_direct_propagate(struct nilfs_bmap *bmap,
				  struct buffer_head *bh)
{
	struct nilfs_palloc_req oldreq, newreq;
	struct inode *dat;
	__u64 key;
	__u64 ptr;
	int ret;

	if (!NILFS_BMAP_USE_VBN(bmap))
		return 0;

	dat = nilfs_bmap_get_dat(bmap);
	key = nilfs_bmap_data_get_key(bmap, bh);
	ptr = nilfs_direct_get_ptr(bmap, key);
	if (!buffer_nilfs_volatile(bh)) {
		oldreq.pr_entry_nr = ptr;
		newreq.pr_entry_nr = ptr;
		ret = nilfs_dat_prepare_update(dat, &oldreq, &newreq);
		if (ret < 0)
			return ret;
		nilfs_dat_commit_update(dat, &oldreq, &newreq,
					bmap->b_ptr_type == NILFS_BMAP_PTR_VS);
		set_buffer_nilfs_volatile(bh);
		nilfs_direct_set_ptr(bmap, key, newreq.pr_entry_nr);
	} else
		ret = nilfs_dat_mark_dirty(dat, ptr);

	return ret;
}

static int nilfs_direct_assign_v(struct nilfs_bmap *direct,
				 __u64 key, __u64 ptr,
				 struct buffer_head **bh,
				 sector_t blocknr,
				 union nilfs_binfo *binfo)
{
	struct inode *dat = nilfs_bmap_get_dat(direct);
	union nilfs_bmap_ptr_req req;
	int ret;

	req.bpr_ptr = ptr;
	ret = nilfs_dat_prepare_start(dat, &req.bpr_req);
	if (!ret) {
		nilfs_dat_commit_start(dat, &req.bpr_req, blocknr);
		binfo->bi_v.bi_vblocknr = cpu_to_le64(ptr);
		binfo->bi_v.bi_blkoff = cpu_to_le64(key);
	}
	return ret;
}

static int nilfs_direct_assign_p(struct nilfs_bmap *direct,
				 __u64 key, __u64 ptr,
				 struct buffer_head **bh,
				 sector_t blocknr,
				 union nilfs_binfo *binfo)
{
	nilfs_direct_set_ptr(direct, key, blocknr);

	binfo->bi_dat.bi_blkoff = cpu_to_le64(key);
	binfo->bi_dat.bi_level = 0;

	return 0;
}

static int nilfs_direct_assign(struct nilfs_bmap *bmap,
			       struct buffer_head **bh,
			       sector_t blocknr,
			       union nilfs_binfo *binfo)
{
	__u64 key;
	__u64 ptr;

	key = nilfs_bmap_data_get_key(bmap, *bh);
	if (unlikely(key > NILFS_DIRECT_KEY_MAX)) {
		printk(KERN_CRIT "%s: invalid key: %llu\n", __func__,
		       (unsigned long long)key);
		return -EINVAL;
	}
	ptr = nilfs_direct_get_ptr(bmap, key);
	if (unlikely(ptr == NILFS_BMAP_INVALID_PTR)) {
		printk(KERN_CRIT "%s: invalid pointer: %llu\n", __func__,
		       (unsigned long long)ptr);
		return -EINVAL;
	}

	return NILFS_BMAP_USE_VBN(bmap) ?
		nilfs_direct_assign_v(bmap, key, ptr, bh, blocknr, binfo) :
		nilfs_direct_assign_p(bmap, key, ptr, bh, blocknr, binfo);
}

static const struct nilfs_bmap_operations nilfs_direct_ops = {
	.bop_lookup		=	nilfs_direct_lookup,
	.bop_lookup_contig	=	nilfs_direct_lookup_contig,
	.bop_insert		=	nilfs_direct_insert,
	.bop_delete		=	nilfs_direct_delete,
	.bop_clear		=	NULL,

	.bop_propagate		=	nilfs_direct_propagate,

	.bop_lookup_dirty_buffers	=	NULL,

	.bop_assign		=	nilfs_direct_assign,
	.bop_mark		=	NULL,

	.bop_last_key		=	nilfs_direct_last_key,
	.bop_check_insert	=	nilfs_direct_check_insert,
	.bop_check_delete	=	NULL,
	.bop_gather_data	=	nilfs_direct_gather_data,
};


int nilfs_direct_init(struct nilfs_bmap *bmap)
{
	bmap->b_ops = &nilfs_direct_ops;
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/direct.c */
/************************************************************/
/*
 * dat.c - NILFS disk address translation.
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Koji Sato <koji@osrg.net>.
 */

// #include <linux/types.h>
// #include <linux/buffer_head.h>
// #include <linux/string.h>
// #include <linux/errno.h>
// #include "nilfs.h"
// #include "mdt.h"
// #include "alloc.h"
// #include "dat.h"


#define NILFS_CNO_MIN	((__u64)1)
#define NILFS_CNO_MAX	(~(__u64)0)

/**
 * struct nilfs_dat_info - on-memory private data of DAT file
 * @mi: on-memory private data of metadata file
 * @palloc_cache: persistent object allocator cache of DAT file
 * @shadow: shadow map of DAT file
 */
struct nilfs_dat_info {
	struct nilfs_mdt_info mi;
	struct nilfs_palloc_cache palloc_cache;
	struct nilfs_shadow_map shadow;
};

static inline struct nilfs_dat_info *NILFS_DAT_I(struct inode *dat)
{
	return (struct nilfs_dat_info *)NILFS_MDT(dat);
}

static int nilfs_dat_prepare_entry(struct inode *dat,
				   struct nilfs_palloc_req *req, int create)
{
	return nilfs_palloc_get_entry_block(dat, req->pr_entry_nr,
					    create, &req->pr_entry_bh);
}

static void nilfs_dat_commit_entry(struct inode *dat,
				   struct nilfs_palloc_req *req)
{
	mark_buffer_dirty(req->pr_entry_bh);
	nilfs_mdt_mark_dirty(dat);
	brelse(req->pr_entry_bh);
}

static void nilfs_dat_abort_entry(struct inode *dat,
				  struct nilfs_palloc_req *req)
{
	brelse(req->pr_entry_bh);
}

int nilfs_dat_prepare_alloc(struct inode *dat, struct nilfs_palloc_req *req)
{
	int ret;

	ret = nilfs_palloc_prepare_alloc_entry(dat, req);
	if (ret < 0)
		return ret;

	ret = nilfs_dat_prepare_entry(dat, req, 1);
	if (ret < 0)
		nilfs_palloc_abort_alloc_entry(dat, req);

	return ret;
}

void nilfs_dat_commit_alloc(struct inode *dat, struct nilfs_palloc_req *req)
{
	struct nilfs_dat_entry *entry;
	void *kaddr;

	kaddr = kmap_atomic(req->pr_entry_bh->b_page);
	entry = nilfs_palloc_block_get_entry(dat, req->pr_entry_nr,
					     req->pr_entry_bh, kaddr);
	entry->de_start = cpu_to_le64(NILFS_CNO_MIN);
	entry->de_end = cpu_to_le64(NILFS_CNO_MAX);
	entry->de_blocknr = cpu_to_le64(0);
	kunmap_atomic(kaddr);

	nilfs_palloc_commit_alloc_entry(dat, req);
	nilfs_dat_commit_entry(dat, req);
}

void nilfs_dat_abort_alloc(struct inode *dat, struct nilfs_palloc_req *req)
{
	nilfs_dat_abort_entry(dat, req);
	nilfs_palloc_abort_alloc_entry(dat, req);
}

static void nilfs_dat_commit_free(struct inode *dat,
				  struct nilfs_palloc_req *req)
{
	struct nilfs_dat_entry *entry;
	void *kaddr;

	kaddr = kmap_atomic(req->pr_entry_bh->b_page);
	entry = nilfs_palloc_block_get_entry(dat, req->pr_entry_nr,
					     req->pr_entry_bh, kaddr);
	entry->de_start = cpu_to_le64(NILFS_CNO_MIN);
	entry->de_end = cpu_to_le64(NILFS_CNO_MIN);
	entry->de_blocknr = cpu_to_le64(0);
	kunmap_atomic(kaddr);

	nilfs_dat_commit_entry(dat, req);
	nilfs_palloc_commit_free_entry(dat, req);
}

int nilfs_dat_prepare_start(struct inode *dat, struct nilfs_palloc_req *req)
{
	int ret;

	ret = nilfs_dat_prepare_entry(dat, req, 0);
	WARN_ON(ret == -ENOENT);
	return ret;
}

void nilfs_dat_commit_start(struct inode *dat, struct nilfs_palloc_req *req,
			    sector_t blocknr)
{
	struct nilfs_dat_entry *entry;
	void *kaddr;

	kaddr = kmap_atomic(req->pr_entry_bh->b_page);
	entry = nilfs_palloc_block_get_entry(dat, req->pr_entry_nr,
					     req->pr_entry_bh, kaddr);
	entry->de_start = cpu_to_le64(nilfs_mdt_cno(dat));
	entry->de_blocknr = cpu_to_le64(blocknr);
	kunmap_atomic(kaddr);

	nilfs_dat_commit_entry(dat, req);
}

int nilfs_dat_prepare_end(struct inode *dat, struct nilfs_palloc_req *req)
{
	struct nilfs_dat_entry *entry;
	__u64 start;
	sector_t blocknr;
	void *kaddr;
	int ret;

	ret = nilfs_dat_prepare_entry(dat, req, 0);
	if (ret < 0) {
		WARN_ON(ret == -ENOENT);
		return ret;
	}

	kaddr = kmap_atomic(req->pr_entry_bh->b_page);
	entry = nilfs_palloc_block_get_entry(dat, req->pr_entry_nr,
					     req->pr_entry_bh, kaddr);
	start = le64_to_cpu(entry->de_start);
	blocknr = le64_to_cpu(entry->de_blocknr);
	kunmap_atomic(kaddr);

	if (blocknr == 0) {
		ret = nilfs_palloc_prepare_free_entry(dat, req);
		if (ret < 0) {
			nilfs_dat_abort_entry(dat, req);
			return ret;
		}
	}

	return 0;
}

void nilfs_dat_commit_end(struct inode *dat, struct nilfs_palloc_req *req,
			  int dead)
{
	struct nilfs_dat_entry *entry;
	__u64 start, end;
	sector_t blocknr;
	void *kaddr;

	kaddr = kmap_atomic(req->pr_entry_bh->b_page);
	entry = nilfs_palloc_block_get_entry(dat, req->pr_entry_nr,
					     req->pr_entry_bh, kaddr);
	end = start = le64_to_cpu(entry->de_start);
	if (!dead) {
		end = nilfs_mdt_cno(dat);
		WARN_ON(start > end);
	}
	entry->de_end = cpu_to_le64(end);
	blocknr = le64_to_cpu(entry->de_blocknr);
	kunmap_atomic(kaddr);

	if (blocknr == 0)
		nilfs_dat_commit_free(dat, req);
	else
		nilfs_dat_commit_entry(dat, req);
}

void nilfs_dat_abort_end(struct inode *dat, struct nilfs_palloc_req *req)
{
	struct nilfs_dat_entry *entry;
	__u64 start;
	sector_t blocknr;
	void *kaddr;

	kaddr = kmap_atomic(req->pr_entry_bh->b_page);
	entry = nilfs_palloc_block_get_entry(dat, req->pr_entry_nr,
					     req->pr_entry_bh, kaddr);
	start = le64_to_cpu(entry->de_start);
	blocknr = le64_to_cpu(entry->de_blocknr);
	kunmap_atomic(kaddr);

	if (start == nilfs_mdt_cno(dat) && blocknr == 0)
		nilfs_palloc_abort_free_entry(dat, req);
	nilfs_dat_abort_entry(dat, req);
}

int nilfs_dat_prepare_update(struct inode *dat,
			     struct nilfs_palloc_req *oldreq,
			     struct nilfs_palloc_req *newreq)
{
	int ret;

	ret = nilfs_dat_prepare_end(dat, oldreq);
	if (!ret) {
		ret = nilfs_dat_prepare_alloc(dat, newreq);
		if (ret < 0)
			nilfs_dat_abort_end(dat, oldreq);
	}
	return ret;
}

void nilfs_dat_commit_update(struct inode *dat,
			     struct nilfs_palloc_req *oldreq,
			     struct nilfs_palloc_req *newreq, int dead)
{
	nilfs_dat_commit_end(dat, oldreq, dead);
	nilfs_dat_commit_alloc(dat, newreq);
}

void nilfs_dat_abort_update(struct inode *dat,
			    struct nilfs_palloc_req *oldreq,
			    struct nilfs_palloc_req *newreq)
{
	nilfs_dat_abort_end(dat, oldreq);
	nilfs_dat_abort_alloc(dat, newreq);
}

/**
 * nilfs_dat_mark_dirty -
 * @dat: DAT file inode
 * @vblocknr: virtual block number
 *
 * Description:
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_dat_mark_dirty(struct inode *dat, __u64 vblocknr)
{
	struct nilfs_palloc_req req;
	int ret;

	req.pr_entry_nr = vblocknr;
	ret = nilfs_dat_prepare_entry(dat, &req, 0);
	if (ret == 0)
		nilfs_dat_commit_entry(dat, &req);
	return ret;
}

/**
 * nilfs_dat_freev - free virtual block numbers
 * @dat: DAT file inode
 * @vblocknrs: array of virtual block numbers
 * @nitems: number of virtual block numbers
 *
 * Description: nilfs_dat_freev() frees the virtual block numbers specified by
 * @vblocknrs and @nitems.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - The virtual block number have not been allocated.
 */
int nilfs_dat_freev(struct inode *dat, __u64 *vblocknrs, size_t nitems)
{
	return nilfs_palloc_freev(dat, vblocknrs, nitems);
}

/**
 * nilfs_dat_move - change a block number
 * @dat: DAT file inode
 * @vblocknr: virtual block number
 * @blocknr: block number
 *
 * Description: nilfs_dat_move() changes the block number associated with
 * @vblocknr to @blocknr.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_dat_move(struct inode *dat, __u64 vblocknr, sector_t blocknr)
{
	struct buffer_head *entry_bh;
	struct nilfs_dat_entry *entry;
	void *kaddr;
	int ret;

	ret = nilfs_palloc_get_entry_block(dat, vblocknr, 0, &entry_bh);
	if (ret < 0)
		return ret;

	/*
	 * The given disk block number (blocknr) is not yet written to
	 * the device at this point.
	 *
	 * To prevent nilfs_dat_translate() from returning the
	 * uncommitted block number, this makes a copy of the entry
	 * buffer and redirects nilfs_dat_translate() to the copy.
	 */
	if (!buffer_nilfs_redirected(entry_bh)) {
		ret = nilfs_mdt_freeze_buffer(dat, entry_bh);
		if (ret) {
			brelse(entry_bh);
			return ret;
		}
	}

	kaddr = kmap_atomic(entry_bh->b_page);
	entry = nilfs_palloc_block_get_entry(dat, vblocknr, entry_bh, kaddr);
	if (unlikely(entry->de_blocknr == cpu_to_le64(0))) {
		printk(KERN_CRIT "%s: vbn = %llu, [%llu, %llu)\n", __func__,
		       (unsigned long long)vblocknr,
		       (unsigned long long)le64_to_cpu(entry->de_start),
		       (unsigned long long)le64_to_cpu(entry->de_end));
		kunmap_atomic(kaddr);
		brelse(entry_bh);
		return -EINVAL;
	}
	WARN_ON(blocknr == 0);
	entry->de_blocknr = cpu_to_le64(blocknr);
	kunmap_atomic(kaddr);

	mark_buffer_dirty(entry_bh);
	nilfs_mdt_mark_dirty(dat);

	brelse(entry_bh);

	return 0;
}

/**
 * nilfs_dat_translate - translate a virtual block number to a block number
 * @dat: DAT file inode
 * @vblocknr: virtual block number
 * @blocknrp: pointer to a block number
 *
 * Description: nilfs_dat_translate() maps the virtual block number @vblocknr
 * to the corresponding block number.
 *
 * Return Value: On success, 0 is returned and the block number associated
 * with @vblocknr is stored in the place pointed by @blocknrp. On error, one
 * of the following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - A block number associated with @vblocknr does not exist.
 */
int nilfs_dat_translate(struct inode *dat, __u64 vblocknr, sector_t *blocknrp)
{
	struct buffer_head *entry_bh, *bh;
	struct nilfs_dat_entry *entry;
	sector_t blocknr;
	void *kaddr;
	int ret;

	ret = nilfs_palloc_get_entry_block(dat, vblocknr, 0, &entry_bh);
	if (ret < 0)
		return ret;

	if (!nilfs_doing_gc() && buffer_nilfs_redirected(entry_bh)) {
		bh = nilfs_mdt_get_frozen_buffer(dat, entry_bh);
		if (bh) {
			WARN_ON(!buffer_uptodate(bh));
			brelse(entry_bh);
			entry_bh = bh;
		}
	}

	kaddr = kmap_atomic(entry_bh->b_page);
	entry = nilfs_palloc_block_get_entry(dat, vblocknr, entry_bh, kaddr);
	blocknr = le64_to_cpu(entry->de_blocknr);
	if (blocknr == 0) {
		ret = -ENOENT;
		goto out;
	}
	*blocknrp = blocknr;

 out:
	kunmap_atomic(kaddr);
	brelse(entry_bh);
	return ret;
}

ssize_t nilfs_dat_get_vinfo(struct inode *dat, void *buf, unsigned visz,
			    size_t nvi)
{
	struct buffer_head *entry_bh;
	struct nilfs_dat_entry *entry;
	struct nilfs_vinfo *vinfo = buf;
	__u64 first, last;
	void *kaddr;
	unsigned long entries_per_block = NILFS_MDT(dat)->mi_entries_per_block;
	int i, j, n, ret;

	for (i = 0; i < nvi; i += n) {
		ret = nilfs_palloc_get_entry_block(dat, vinfo->vi_vblocknr,
						   0, &entry_bh);
		if (ret < 0)
			return ret;
		kaddr = kmap_atomic(entry_bh->b_page);
		/* last virtual block number in this block */
		first = vinfo->vi_vblocknr;
		do_div(first, entries_per_block);
		first *= entries_per_block;
		last = first + entries_per_block - 1;
		for (j = i, n = 0;
		     j < nvi && vinfo->vi_vblocknr >= first &&
			     vinfo->vi_vblocknr <= last;
		     j++, n++, vinfo = (void *)vinfo + visz) {
			entry = nilfs_palloc_block_get_entry(
				dat, vinfo->vi_vblocknr, entry_bh, kaddr);
			vinfo->vi_start = le64_to_cpu(entry->de_start);
			vinfo->vi_end = le64_to_cpu(entry->de_end);
			vinfo->vi_blocknr = le64_to_cpu(entry->de_blocknr);
		}
		kunmap_atomic(kaddr);
		brelse(entry_bh);
	}

	return nvi;
}

/**
 * nilfs_dat_read - read or get dat inode
 * @sb: super block instance
 * @entry_size: size of a dat entry
 * @raw_inode: on-disk dat inode
 * @inodep: buffer to store the inode
 */
int nilfs_dat_read(struct super_block *sb, size_t entry_size,
		   struct nilfs_inode *raw_inode, struct inode **inodep)
{
	static struct lock_class_key dat_lock_key;
	struct inode *dat;
	struct nilfs_dat_info *di;
	int err;

	if (entry_size > sb->s_blocksize) {
		printk(KERN_ERR
		       "NILFS: too large DAT entry size: %zu bytes.\n",
		       entry_size);
		return -EINVAL;
	} else if (entry_size < NILFS_MIN_DAT_ENTRY_SIZE) {
		printk(KERN_ERR
		       "NILFS: too small DAT entry size: %zu bytes.\n",
		       entry_size);
		return -EINVAL;
	}

	dat = nilfs_iget_locked(sb, NULL, NILFS_DAT_INO);
	if (unlikely(!dat))
		return -ENOMEM;
	if (!(dat->i_state & I_NEW))
		goto out;

	err = nilfs_mdt_init(dat, NILFS_MDT_GFP, sizeof(*di));
	if (err)
		goto failed;

	err = nilfs_palloc_init_blockgroup(dat, entry_size);
	if (err)
		goto failed;

	di = NILFS_DAT_I(dat);
	lockdep_set_class(&di->mi.mi_sem, &dat_lock_key);
	nilfs_palloc_setup_cache(dat, &di->palloc_cache);
	nilfs_mdt_setup_shadow_map(dat, &di->shadow);

	err = nilfs_read_inode_common(dat, raw_inode);
	if (err)
		goto failed;

	unlock_new_inode(dat);
 out:
	*inodep = dat;
	return 0;
 failed:
	iget_failed(dat);
	return err;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/dat.c */
/************************************************************/
/*
 * recovery.c - NILFS recovery logic
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 */

// #include <linux/buffer_head.h>
// #include <linux/blkdev.h>
// #include <linux/swap.h>
// #include <linux/slab.h>
// #include <linux/crc32.h>
// #include "nilfs.h"
// #include "segment.h"
// #include "sufile.h"
// #include "page.h"
// #include "segbuf.h"

/*
 * Segment check result
 */
enum {
	NILFS_SEG_VALID,
	NILFS_SEG_NO_SUPER_ROOT,
	NILFS_SEG_FAIL_IO,
	NILFS_SEG_FAIL_MAGIC,
	NILFS_SEG_FAIL_SEQ,
	NILFS_SEG_FAIL_CHECKSUM_SUPER_ROOT,
	NILFS_SEG_FAIL_CHECKSUM_FULL,
	NILFS_SEG_FAIL_CONSISTENCY,
};

/* work structure for recovery */
struct nilfs_recovery_block {
	ino_t ino;		/* Inode number of the file that this block
				   belongs to */
	sector_t blocknr;	/* block number */
	__u64 vblocknr;		/* virtual block number */
	unsigned long blkoff;	/* File offset of the data block (per block) */
	struct list_head list;
};


static int nilfs_warn_segment_error(int err)
{
	switch (err) {
	case NILFS_SEG_FAIL_IO:
		printk(KERN_WARNING
		       "NILFS warning: I/O error on loading last segment\n");
		return -EIO;
	case NILFS_SEG_FAIL_MAGIC:
		printk(KERN_WARNING
		       "NILFS warning: Segment magic number invalid\n");
		break;
	case NILFS_SEG_FAIL_SEQ:
		printk(KERN_WARNING
		       "NILFS warning: Sequence number mismatch\n");
		break;
	case NILFS_SEG_FAIL_CHECKSUM_SUPER_ROOT:
		printk(KERN_WARNING
		       "NILFS warning: Checksum error in super root\n");
		break;
	case NILFS_SEG_FAIL_CHECKSUM_FULL:
		printk(KERN_WARNING
		       "NILFS warning: Checksum error in segment payload\n");
		break;
	case NILFS_SEG_FAIL_CONSISTENCY:
		printk(KERN_WARNING
		       "NILFS warning: Inconsistent segment\n");
		break;
	case NILFS_SEG_NO_SUPER_ROOT:
		printk(KERN_WARNING
		       "NILFS warning: No super root in the last segment\n");
		break;
	}
	return -EINVAL;
}

/**
 * nilfs_compute_checksum - compute checksum of blocks continuously
 * @nilfs: nilfs object
 * @bhs: buffer head of start block
 * @sum: place to store result
 * @offset: offset bytes in the first block
 * @check_bytes: number of bytes to be checked
 * @start: DBN of start block
 * @nblock: number of blocks to be checked
 */
static int nilfs_compute_checksum(struct the_nilfs *nilfs,
				  struct buffer_head *bhs, u32 *sum,
				  unsigned long offset, u64 check_bytes,
				  sector_t start, unsigned long nblock)
{
	unsigned int blocksize = nilfs->ns_blocksize;
	unsigned long size;
	u32 crc;

	BUG_ON(offset >= blocksize);
	check_bytes -= offset;
	size = min_t(u64, check_bytes, blocksize - offset);
	crc = crc32_le(nilfs->ns_crc_seed,
		       (unsigned char *)bhs->b_data + offset, size);
	if (--nblock > 0) {
		do {
			struct buffer_head *bh;

			bh = __bread(nilfs->ns_bdev, ++start, blocksize);
			if (!bh)
				return -EIO;
			check_bytes -= size;
			size = min_t(u64, check_bytes, blocksize);
			crc = crc32_le(crc, bh->b_data, size);
			brelse(bh);
		} while (--nblock > 0);
	}
	*sum = crc;
	return 0;
}

/**
 * nilfs_read_super_root_block - read super root block
 * @nilfs: nilfs object
 * @sr_block: disk block number of the super root block
 * @pbh: address of a buffer_head pointer to return super root buffer
 * @check: CRC check flag
 */
int nilfs_read_super_root_block(struct the_nilfs *nilfs, sector_t sr_block,
				struct buffer_head **pbh, int check)
{
	struct buffer_head *bh_sr;
	struct nilfs_super_root *sr;
	u32 crc;
	int ret;

	*pbh = NULL;
	bh_sr = __bread(nilfs->ns_bdev, sr_block, nilfs->ns_blocksize);
	if (unlikely(!bh_sr)) {
		ret = NILFS_SEG_FAIL_IO;
		goto failed;
	}

	sr = (struct nilfs_super_root *)bh_sr->b_data;
	if (check) {
		unsigned bytes = le16_to_cpu(sr->sr_bytes);

		if (bytes == 0 || bytes > nilfs->ns_blocksize) {
			ret = NILFS_SEG_FAIL_CHECKSUM_SUPER_ROOT;
			goto failed_bh;
		}
		if (nilfs_compute_checksum(
			    nilfs, bh_sr, &crc, sizeof(sr->sr_sum), bytes,
			    sr_block, 1)) {
			ret = NILFS_SEG_FAIL_IO;
			goto failed_bh;
		}
		if (crc != le32_to_cpu(sr->sr_sum)) {
			ret = NILFS_SEG_FAIL_CHECKSUM_SUPER_ROOT;
			goto failed_bh;
		}
	}
	*pbh = bh_sr;
	return 0;

 failed_bh:
	brelse(bh_sr);

 failed:
	return nilfs_warn_segment_error(ret);
}

/**
 * nilfs_read_log_header - read summary header of the specified log
 * @nilfs: nilfs object
 * @start_blocknr: start block number of the log
 * @sum: pointer to return segment summary structure
 */
static struct buffer_head *
nilfs_read_log_header(struct the_nilfs *nilfs, sector_t start_blocknr,
		      struct nilfs_segment_summary **sum)
{
	struct buffer_head *bh_sum;

	bh_sum = __bread(nilfs->ns_bdev, start_blocknr, nilfs->ns_blocksize);
	if (bh_sum)
		*sum = (struct nilfs_segment_summary *)bh_sum->b_data;
	return bh_sum;
}

/**
 * nilfs_validate_log - verify consistency of log
 * @nilfs: nilfs object
 * @seg_seq: sequence number of segment
 * @bh_sum: buffer head of summary block
 * @sum: segment summary struct
 */
static int nilfs_validate_log(struct the_nilfs *nilfs, u64 seg_seq,
			      struct buffer_head *bh_sum,
			      struct nilfs_segment_summary *sum)
{
	unsigned long nblock;
	u32 crc;
	int ret;

	ret = NILFS_SEG_FAIL_MAGIC;
	if (le32_to_cpu(sum->ss_magic) != NILFS_SEGSUM_MAGIC)
		goto out;

	ret = NILFS_SEG_FAIL_SEQ;
	if (le64_to_cpu(sum->ss_seq) != seg_seq)
		goto out;

	nblock = le32_to_cpu(sum->ss_nblocks);
	ret = NILFS_SEG_FAIL_CONSISTENCY;
	if (unlikely(nblock == 0 || nblock > nilfs->ns_blocks_per_segment))
		/* This limits the number of blocks read in the CRC check */
		goto out;

	ret = NILFS_SEG_FAIL_IO;
	if (nilfs_compute_checksum(nilfs, bh_sum, &crc, sizeof(sum->ss_datasum),
				   ((u64)nblock << nilfs->ns_blocksize_bits),
				   bh_sum->b_blocknr, nblock))
		goto out;

	ret = NILFS_SEG_FAIL_CHECKSUM_FULL;
	if (crc != le32_to_cpu(sum->ss_datasum))
		goto out;
	ret = 0;
out:
	return ret;
}

/**
 * nilfs_read_summary_info - read an item on summary blocks of a log
 * @nilfs: nilfs object
 * @pbh: the current buffer head on summary blocks [in, out]
 * @offset: the current byte offset on summary blocks [in, out]
 * @bytes: byte size of the item to be read
 */
static void *nilfs_read_summary_info(struct the_nilfs *nilfs,
				     struct buffer_head **pbh,
				     unsigned int *offset, unsigned int bytes)
{
	void *ptr;
	sector_t blocknr;

	BUG_ON((*pbh)->b_size < *offset);
	if (bytes > (*pbh)->b_size - *offset) {
		blocknr = (*pbh)->b_blocknr;
		brelse(*pbh);
		*pbh = __bread(nilfs->ns_bdev, blocknr + 1,
			       nilfs->ns_blocksize);
		if (unlikely(!*pbh))
			return NULL;
		*offset = 0;
	}
	ptr = (*pbh)->b_data + *offset;
	*offset += bytes;
	return ptr;
}

/**
 * nilfs_skip_summary_info - skip items on summary blocks of a log
 * @nilfs: nilfs object
 * @pbh: the current buffer head on summary blocks [in, out]
 * @offset: the current byte offset on summary blocks [in, out]
 * @bytes: byte size of the item to be skipped
 * @count: number of items to be skipped
 */
static void nilfs_skip_summary_info(struct the_nilfs *nilfs,
				    struct buffer_head **pbh,
				    unsigned int *offset, unsigned int bytes,
				    unsigned long count)
{
	unsigned int rest_item_in_current_block
		= ((*pbh)->b_size - *offset) / bytes;

	if (count <= rest_item_in_current_block) {
		*offset += bytes * count;
	} else {
		sector_t blocknr = (*pbh)->b_blocknr;
		unsigned int nitem_per_block = (*pbh)->b_size / bytes;
		unsigned int bcnt;

		count -= rest_item_in_current_block;
		bcnt = DIV_ROUND_UP(count, nitem_per_block);
		*offset = bytes * (count - (bcnt - 1) * nitem_per_block);

		brelse(*pbh);
		*pbh = __bread(nilfs->ns_bdev, blocknr + bcnt,
			       nilfs->ns_blocksize);
	}
}

/**
 * nilfs_scan_dsync_log - get block information of a log written for data sync
 * @nilfs: nilfs object
 * @start_blocknr: start block number of the log
 * @sum: log summary information
 * @head: list head to add nilfs_recovery_block struct
 */
static int nilfs_scan_dsync_log(struct the_nilfs *nilfs, sector_t start_blocknr,
				struct nilfs_segment_summary *sum,
				struct list_head *head)
{
	struct buffer_head *bh;
	unsigned int offset;
	u32 nfinfo, sumbytes;
	sector_t blocknr;
	ino_t ino;
	int err = -EIO;

	nfinfo = le32_to_cpu(sum->ss_nfinfo);
	if (!nfinfo)
		return 0;

	sumbytes = le32_to_cpu(sum->ss_sumbytes);
	blocknr = start_blocknr + DIV_ROUND_UP(sumbytes, nilfs->ns_blocksize);
	bh = __bread(nilfs->ns_bdev, start_blocknr, nilfs->ns_blocksize);
	if (unlikely(!bh))
		goto out;

	offset = le16_to_cpu(sum->ss_bytes);
	for (;;) {
		unsigned long nblocks, ndatablk, nnodeblk;
		struct nilfs_finfo *finfo;

		finfo = nilfs_read_summary_info(nilfs, &bh, &offset,
						sizeof(*finfo));
		if (unlikely(!finfo))
			goto out;

		ino = le64_to_cpu(finfo->fi_ino);
		nblocks = le32_to_cpu(finfo->fi_nblocks);
		ndatablk = le32_to_cpu(finfo->fi_ndatablk);
		nnodeblk = nblocks - ndatablk;

		while (ndatablk-- > 0) {
			struct nilfs_recovery_block *rb;
			struct nilfs_binfo_v *binfo;

			binfo = nilfs_read_summary_info(nilfs, &bh, &offset,
							sizeof(*binfo));
			if (unlikely(!binfo))
				goto out;

			rb = kmalloc(sizeof(*rb), GFP_NOFS);
			if (unlikely(!rb)) {
				err = -ENOMEM;
				goto out;
			}
			rb->ino = ino;
			rb->blocknr = blocknr++;
			rb->vblocknr = le64_to_cpu(binfo->bi_vblocknr);
			rb->blkoff = le64_to_cpu(binfo->bi_blkoff);
			/* INIT_LIST_HEAD(&rb->list); */
			list_add_tail(&rb->list, head);
		}
		if (--nfinfo == 0)
			break;
		blocknr += nnodeblk; /* always 0 for data sync logs */
		nilfs_skip_summary_info(nilfs, &bh, &offset, sizeof(__le64),
					nnodeblk);
		if (unlikely(!bh))
			goto out;
	}
	err = 0;
 out:
	brelse(bh);   /* brelse(NULL) is just ignored */
	return err;
}

static void dispose_recovery_list(struct list_head *head)
{
	while (!list_empty(head)) {
		struct nilfs_recovery_block *rb;

		rb = list_first_entry(head, struct nilfs_recovery_block, list);
		list_del(&rb->list);
		kfree(rb);
	}
}

struct nilfs_segment_entry {
	struct list_head	list;
	__u64			segnum;
};

static int nilfs_segment_list_add(struct list_head *head, __u64 segnum)
{
	struct nilfs_segment_entry *ent = kmalloc(sizeof(*ent), GFP_NOFS);

	if (unlikely(!ent))
		return -ENOMEM;

	ent->segnum = segnum;
	INIT_LIST_HEAD(&ent->list);
	list_add_tail(&ent->list, head);
	return 0;
}

void nilfs_dispose_segment_list(struct list_head *head)
{
	while (!list_empty(head)) {
		struct nilfs_segment_entry *ent;

		ent = list_first_entry(head, struct nilfs_segment_entry, list);
		list_del(&ent->list);
		kfree(ent);
	}
}

static int nilfs_prepare_segment_for_recovery(struct the_nilfs *nilfs,
					      struct super_block *sb,
					      struct nilfs_recovery_info *ri)
{
	struct list_head *head = &ri->ri_used_segments;
	struct nilfs_segment_entry *ent, *n;
	struct inode *sufile = nilfs->ns_sufile;
	__u64 segnum[4];
	int err;
	int i;

	segnum[0] = nilfs->ns_segnum;
	segnum[1] = nilfs->ns_nextnum;
	segnum[2] = ri->ri_segnum;
	segnum[3] = ri->ri_nextnum;

	/*
	 * Releasing the next segment of the latest super root.
	 * The next segment is invalidated by this recovery.
	 */
	err = nilfs_sufile_free(sufile, segnum[1]);
	if (unlikely(err))
		goto failed;

	for (i = 1; i < 4; i++) {
		err = nilfs_segment_list_add(head, segnum[i]);
		if (unlikely(err))
			goto failed;
	}

	/*
	 * Collecting segments written after the latest super root.
	 * These are marked dirty to avoid being reallocated in the next write.
	 */
	list_for_each_entry_safe(ent, n, head, list) {
		if (ent->segnum != segnum[0]) {
			err = nilfs_sufile_scrap(sufile, ent->segnum);
			if (unlikely(err))
				goto failed;
		}
		list_del(&ent->list);
		kfree(ent);
	}

	/* Allocate new segments for recovery */
	err = nilfs_sufile_alloc(sufile, &segnum[0]);
	if (unlikely(err))
		goto failed;

	nilfs->ns_pseg_offset = 0;
	nilfs->ns_seg_seq = ri->ri_seq + 2;
	nilfs->ns_nextnum = nilfs->ns_segnum = segnum[0];

 failed:
	/* No need to recover sufile because it will be destroyed on error */
	return err;
}

static int nilfs_recovery_copy_block(struct the_nilfs *nilfs,
				     struct nilfs_recovery_block *rb,
				     struct page *page)
{
	struct buffer_head *bh_org;
	void *kaddr;

	bh_org = __bread(nilfs->ns_bdev, rb->blocknr, nilfs->ns_blocksize);
	if (unlikely(!bh_org))
		return -EIO;

	kaddr = kmap_atomic(page);
	memcpy(kaddr + bh_offset(bh_org), bh_org->b_data, bh_org->b_size);
	kunmap_atomic(kaddr);
	brelse(bh_org);
	return 0;
}

static int nilfs_recover_dsync_blocks(struct the_nilfs *nilfs,
				      struct super_block *sb,
				      struct nilfs_root *root,
				      struct list_head *head,
				      unsigned long *nr_salvaged_blocks)
{
	struct inode *inode;
	struct nilfs_recovery_block *rb, *n;
	unsigned blocksize = nilfs->ns_blocksize;
	struct page *page;
	loff_t pos;
	int err = 0, err2 = 0;

	list_for_each_entry_safe(rb, n, head, list) {
		inode = nilfs_iget(sb, root, rb->ino);
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			inode = NULL;
			goto failed_inode;
		}

		pos = rb->blkoff << inode->i_blkbits;
		err = block_write_begin(inode->i_mapping, pos, blocksize,
					0, &page, nilfs_get_block);
		if (unlikely(err)) {
			loff_t isize = inode->i_size;
			if (pos + blocksize > isize)
				nilfs_write_failed(inode->i_mapping,
							pos + blocksize);
			goto failed_inode;
		}

		err = nilfs_recovery_copy_block(nilfs, rb, page);
		if (unlikely(err))
			goto failed_page;

		err = nilfs_set_file_dirty(inode, 1);
		if (unlikely(err))
			goto failed_page;

		block_write_end(NULL, inode->i_mapping, pos, blocksize,
				blocksize, page, NULL);

		unlock_page(page);
		page_cache_release(page);

		(*nr_salvaged_blocks)++;
		goto next;

 failed_page:
		unlock_page(page);
		page_cache_release(page);

 failed_inode:
		printk(KERN_WARNING
		       "NILFS warning: error recovering data block "
		       "(err=%d, ino=%lu, block-offset=%llu)\n",
		       err, (unsigned long)rb->ino,
		       (unsigned long long)rb->blkoff);
		if (!err2)
			err2 = err;
 next:
		iput(inode); /* iput(NULL) is just ignored */
		list_del_init(&rb->list);
		kfree(rb);
	}
	return err2;
}

/**
 * nilfs_do_roll_forward - salvage logical segments newer than the latest
 * checkpoint
 * @nilfs: nilfs object
 * @sb: super block instance
 * @ri: pointer to a nilfs_recovery_info
 */
static int nilfs_do_roll_forward(struct the_nilfs *nilfs,
				 struct super_block *sb,
				 struct nilfs_root *root,
				 struct nilfs_recovery_info *ri)
{
	struct buffer_head *bh_sum = NULL;
	struct nilfs_segment_summary *sum;
	sector_t pseg_start;
	sector_t seg_start, seg_end;  /* Starting/ending DBN of full segment */
	unsigned long nsalvaged_blocks = 0;
	unsigned int flags;
	u64 seg_seq;
	__u64 segnum, nextnum = 0;
	int empty_seg = 0;
	int err = 0, ret;
	LIST_HEAD(dsync_blocks);  /* list of data blocks to be recovered */
	enum {
		RF_INIT_ST,
		RF_DSYNC_ST,   /* scanning data-sync segments */
	};
	int state = RF_INIT_ST;

	pseg_start = ri->ri_lsegs_start;
	seg_seq = ri->ri_lsegs_start_seq;
	segnum = nilfs_get_segnum_of_block(nilfs, pseg_start);
	nilfs_get_segment_range(nilfs, segnum, &seg_start, &seg_end);

	while (segnum != ri->ri_segnum || pseg_start <= ri->ri_pseg_start) {
		brelse(bh_sum);
		bh_sum = nilfs_read_log_header(nilfs, pseg_start, &sum);
		if (!bh_sum) {
			err = -EIO;
			goto failed;
		}

		ret = nilfs_validate_log(nilfs, seg_seq, bh_sum, sum);
		if (ret) {
			if (ret == NILFS_SEG_FAIL_IO) {
				err = -EIO;
				goto failed;
			}
			goto strayed;
		}

		flags = le16_to_cpu(sum->ss_flags);
		if (flags & NILFS_SS_SR)
			goto confused;

		/* Found a valid partial segment; do recovery actions */
		nextnum = nilfs_get_segnum_of_block(nilfs,
						    le64_to_cpu(sum->ss_next));
		empty_seg = 0;
		nilfs->ns_ctime = le64_to_cpu(sum->ss_create);
		if (!(flags & NILFS_SS_GC))
			nilfs->ns_nongc_ctime = nilfs->ns_ctime;

		switch (state) {
		case RF_INIT_ST:
			if (!(flags & NILFS_SS_LOGBGN) ||
			    !(flags & NILFS_SS_SYNDT))
				goto try_next_pseg;
			state = RF_DSYNC_ST;
			/* Fall through */
		case RF_DSYNC_ST:
			if (!(flags & NILFS_SS_SYNDT))
				goto confused;

			err = nilfs_scan_dsync_log(nilfs, pseg_start, sum,
						   &dsync_blocks);
			if (unlikely(err))
				goto failed;
			if (flags & NILFS_SS_LOGEND) {
				err = nilfs_recover_dsync_blocks(
					nilfs, sb, root, &dsync_blocks,
					&nsalvaged_blocks);
				if (unlikely(err))
					goto failed;
				state = RF_INIT_ST;
			}
			break; /* Fall through to try_next_pseg */
		}

 try_next_pseg:
		if (pseg_start == ri->ri_lsegs_end)
			break;
		pseg_start += le32_to_cpu(sum->ss_nblocks);
		if (pseg_start < seg_end)
			continue;
		goto feed_segment;

 strayed:
		if (pseg_start == ri->ri_lsegs_end)
			break;

 feed_segment:
		/* Looking to the next full segment */
		if (empty_seg++)
			break;
		seg_seq++;
		segnum = nextnum;
		nilfs_get_segment_range(nilfs, segnum, &seg_start, &seg_end);
		pseg_start = seg_start;
	}

	if (nsalvaged_blocks) {
		printk(KERN_INFO "NILFS (device %s): salvaged %lu blocks\n",
		       sb->s_id, nsalvaged_blocks);
		ri->ri_need_recovery = NILFS_RECOVERY_ROLLFORWARD_DONE;
	}
 out:
	brelse(bh_sum);
	dispose_recovery_list(&dsync_blocks);
	return err;

 confused:
	err = -EINVAL;
 failed:
	printk(KERN_ERR
	       "NILFS (device %s): Error roll-forwarding "
	       "(err=%d, pseg block=%llu). ",
	       sb->s_id, err, (unsigned long long)pseg_start);
	goto out;
}

static void nilfs_finish_roll_forward(struct the_nilfs *nilfs,
				      struct nilfs_recovery_info *ri)
{
	struct buffer_head *bh;
	int err;

	if (nilfs_get_segnum_of_block(nilfs, ri->ri_lsegs_start) !=
	    nilfs_get_segnum_of_block(nilfs, ri->ri_super_root))
		return;

	bh = __getblk(nilfs->ns_bdev, ri->ri_lsegs_start, nilfs->ns_blocksize);
	BUG_ON(!bh);
	memset(bh->b_data, 0, bh->b_size);
	set_buffer_dirty(bh);
	err = sync_dirty_buffer(bh);
	if (unlikely(err))
		printk(KERN_WARNING
		       "NILFS warning: buffer sync write failed during "
		       "post-cleaning of recovery.\n");
	brelse(bh);
}

/**
 * nilfs_salvage_orphan_logs - salvage logs written after the latest checkpoint
 * @nilfs: nilfs object
 * @sb: super block instance
 * @ri: pointer to a nilfs_recovery_info struct to store search results.
 *
 * Return Value: On success, 0 is returned.  On error, one of the following
 * negative error code is returned.
 *
 * %-EINVAL - Inconsistent filesystem state.
 *
 * %-EIO - I/O error
 *
 * %-ENOSPC - No space left on device (only in a panic state).
 *
 * %-ERESTARTSYS - Interrupted.
 *
 * %-ENOMEM - Insufficient memory available.
 */
int nilfs_salvage_orphan_logs(struct the_nilfs *nilfs,
			      struct super_block *sb,
			      struct nilfs_recovery_info *ri)
{
	struct nilfs_root *root;
	int err;

	if (ri->ri_lsegs_start == 0 || ri->ri_lsegs_end == 0)
		return 0;

	err = nilfs_attach_checkpoint(sb, ri->ri_cno, true, &root);
	if (unlikely(err)) {
		printk(KERN_ERR
		       "NILFS: error loading the latest checkpoint.\n");
		return err;
	}

	err = nilfs_do_roll_forward(nilfs, sb, root, ri);
	if (unlikely(err))
		goto failed;

	if (ri->ri_need_recovery == NILFS_RECOVERY_ROLLFORWARD_DONE) {
		err = nilfs_prepare_segment_for_recovery(nilfs, sb, ri);
		if (unlikely(err)) {
			printk(KERN_ERR "NILFS: Error preparing segments for "
			       "recovery.\n");
			goto failed;
		}

		err = nilfs_attach_log_writer(sb, root);
		if (unlikely(err))
			goto failed;

		set_nilfs_discontinued(nilfs);
		err = nilfs_construct_segment(sb);
		nilfs_detach_log_writer(sb);

		if (unlikely(err)) {
			printk(KERN_ERR "NILFS: Oops! recovery failed. "
			       "(err=%d)\n", err);
			goto failed;
		}

		nilfs_finish_roll_forward(nilfs, ri);
	}

 failed:
	nilfs_put_root(root);
	return err;
}

/**
 * nilfs_search_super_root - search the latest valid super root
 * @nilfs: the_nilfs
 * @ri: pointer to a nilfs_recovery_info struct to store search results.
 *
 * nilfs_search_super_root() looks for the latest super-root from a partial
 * segment pointed by the superblock.  It sets up struct the_nilfs through
 * this search. It fills nilfs_recovery_info (ri) required for recovery.
 *
 * Return Value: On success, 0 is returned.  On error, one of the following
 * negative error code is returned.
 *
 * %-EINVAL - No valid segment found
 *
 * %-EIO - I/O error
 *
 * %-ENOMEM - Insufficient memory available.
 */
int nilfs_search_super_root(struct the_nilfs *nilfs,
			    struct nilfs_recovery_info *ri)
{
	struct buffer_head *bh_sum = NULL;
	struct nilfs_segment_summary *sum;
	sector_t pseg_start, pseg_end, sr_pseg_start = 0;
	sector_t seg_start, seg_end; /* range of full segment (block number) */
	sector_t b, end;
	unsigned long nblocks;
	unsigned int flags;
	u64 seg_seq;
	__u64 segnum, nextnum = 0;
	__u64 cno;
	LIST_HEAD(segments);
	int empty_seg = 0, scan_newer = 0;
	int ret;

	pseg_start = nilfs->ns_last_pseg;
	seg_seq = nilfs->ns_last_seq;
	cno = nilfs->ns_last_cno;
	segnum = nilfs_get_segnum_of_block(nilfs, pseg_start);

	/* Calculate range of segment */
	nilfs_get_segment_range(nilfs, segnum, &seg_start, &seg_end);

	/* Read ahead segment */
	b = seg_start;
	while (b <= seg_end)
		__breadahead(nilfs->ns_bdev, b++, nilfs->ns_blocksize);

	for (;;) {
		brelse(bh_sum);
		ret = NILFS_SEG_FAIL_IO;
		bh_sum = nilfs_read_log_header(nilfs, pseg_start, &sum);
		if (!bh_sum)
			goto failed;

		ret = nilfs_validate_log(nilfs, seg_seq, bh_sum, sum);
		if (ret) {
			if (ret == NILFS_SEG_FAIL_IO)
				goto failed;
			goto strayed;
		}

		nblocks = le32_to_cpu(sum->ss_nblocks);
		pseg_end = pseg_start + nblocks - 1;
		if (unlikely(pseg_end > seg_end)) {
			ret = NILFS_SEG_FAIL_CONSISTENCY;
			goto strayed;
		}

		/* A valid partial segment */
		ri->ri_pseg_start = pseg_start;
		ri->ri_seq = seg_seq;
		ri->ri_segnum = segnum;
		nextnum = nilfs_get_segnum_of_block(nilfs,
						    le64_to_cpu(sum->ss_next));
		ri->ri_nextnum = nextnum;
		empty_seg = 0;

		flags = le16_to_cpu(sum->ss_flags);
		if (!(flags & NILFS_SS_SR) && !scan_newer) {
			/* This will never happen because a superblock
			   (last_segment) always points to a pseg
			   having a super root. */
			ret = NILFS_SEG_FAIL_CONSISTENCY;
			goto failed;
		}

		if (pseg_start == seg_start) {
			nilfs_get_segment_range(nilfs, nextnum, &b, &end);
			while (b <= end)
				__breadahead(nilfs->ns_bdev, b++,
					     nilfs->ns_blocksize);
		}
		if (!(flags & NILFS_SS_SR)) {
			if (!ri->ri_lsegs_start && (flags & NILFS_SS_LOGBGN)) {
				ri->ri_lsegs_start = pseg_start;
				ri->ri_lsegs_start_seq = seg_seq;
			}
			if (flags & NILFS_SS_LOGEND)
				ri->ri_lsegs_end = pseg_start;
			goto try_next_pseg;
		}

		/* A valid super root was found. */
		ri->ri_cno = cno++;
		ri->ri_super_root = pseg_end;
		ri->ri_lsegs_start = ri->ri_lsegs_end = 0;

		nilfs_dispose_segment_list(&segments);
		sr_pseg_start = pseg_start;
		nilfs->ns_pseg_offset = pseg_start + nblocks - seg_start;
		nilfs->ns_seg_seq = seg_seq;
		nilfs->ns_segnum = segnum;
		nilfs->ns_cno = cno;  /* nilfs->ns_cno = ri->ri_cno + 1 */
		nilfs->ns_ctime = le64_to_cpu(sum->ss_create);
		nilfs->ns_nextnum = nextnum;

		if (scan_newer)
			ri->ri_need_recovery = NILFS_RECOVERY_SR_UPDATED;
		else {
			if (nilfs->ns_mount_state & NILFS_VALID_FS)
				goto super_root_found;
			scan_newer = 1;
		}

 try_next_pseg:
		/* Standing on a course, or met an inconsistent state */
		pseg_start += nblocks;
		if (pseg_start < seg_end)
			continue;
		goto feed_segment;

 strayed:
		/* Off the trail */
		if (!scan_newer)
			/*
			 * This can happen if a checkpoint was written without
			 * barriers, or as a result of an I/O failure.
			 */
			goto failed;

 feed_segment:
		/* Looking to the next full segment */
		if (empty_seg++)
			goto super_root_found; /* found a valid super root */

		ret = nilfs_segment_list_add(&segments, segnum);
		if (unlikely(ret))
			goto failed;

		seg_seq++;
		segnum = nextnum;
		nilfs_get_segment_range(nilfs, segnum, &seg_start, &seg_end);
		pseg_start = seg_start;
	}

 super_root_found:
	/* Updating pointers relating to the latest checkpoint */
	brelse(bh_sum);
	list_splice_tail(&segments, &ri->ri_used_segments);
	nilfs->ns_last_pseg = sr_pseg_start;
	nilfs->ns_last_seq = nilfs->ns_seg_seq;
	nilfs->ns_last_cno = ri->ri_cno;
	return 0;

 failed:
	brelse(bh_sum);
	nilfs_dispose_segment_list(&segments);
	return (ret < 0) ? ret : nilfs_warn_segment_error(ret);
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/recovery.c */
/************************************************************/
/*
 * the_nilfs.c - the_nilfs shared structure.
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 *
 */

// #include <linux/buffer_head.h>
// #include <linux/slab.h>
// #include <linux/blkdev.h>
// #include <linux/backing-dev.h>
#include <linux/random.h>
// #include <linux/crc32.h>
// #include "nilfs.h"
// #include "segment.h"
// #include "alloc.h"
// #include "cpfile.h"
// #include "sufile.h"
// #include "dat.h"
// #include "segbuf.h"


static int nilfs_valid_sb(struct nilfs_super_block *sbp);

void nilfs_set_last_segment(struct the_nilfs *nilfs,
			    sector_t start_blocknr, u64 seq, __u64 cno)
{
	spin_lock(&nilfs->ns_last_segment_lock);
	nilfs->ns_last_pseg = start_blocknr;
	nilfs->ns_last_seq = seq;
	nilfs->ns_last_cno = cno;

	if (!nilfs_sb_dirty(nilfs)) {
		if (nilfs->ns_prev_seq == nilfs->ns_last_seq)
			goto stay_cursor;

		set_nilfs_sb_dirty(nilfs);
	}
	nilfs->ns_prev_seq = nilfs->ns_last_seq;

 stay_cursor:
	spin_unlock(&nilfs->ns_last_segment_lock);
}

/**
 * alloc_nilfs - allocate a nilfs object
 * @bdev: block device to which the_nilfs is related
 *
 * Return Value: On success, pointer to the_nilfs is returned.
 * On error, NULL is returned.
 */
struct the_nilfs *alloc_nilfs(struct block_device *bdev)
{
	struct the_nilfs *nilfs;

	nilfs = kzalloc(sizeof(*nilfs), GFP_KERNEL);
	if (!nilfs)
		return NULL;

	nilfs->ns_bdev = bdev;
	atomic_set(&nilfs->ns_ndirtyblks, 0);
	init_rwsem(&nilfs->ns_sem);
	mutex_init(&nilfs->ns_snapshot_mount_mutex);
	INIT_LIST_HEAD(&nilfs->ns_dirty_files);
	INIT_LIST_HEAD(&nilfs->ns_gc_inodes);
	spin_lock_init(&nilfs->ns_inode_lock);
	spin_lock_init(&nilfs->ns_next_gen_lock);
	spin_lock_init(&nilfs->ns_last_segment_lock);
	nilfs->ns_cptree = RB_ROOT;
	spin_lock_init(&nilfs->ns_cptree_lock);
	init_rwsem(&nilfs->ns_segctor_sem);
	nilfs->ns_sb_update_freq = NILFS_SB_FREQ;

	return nilfs;
}

/**
 * destroy_nilfs - destroy nilfs object
 * @nilfs: nilfs object to be released
 */
void destroy_nilfs(struct the_nilfs *nilfs)
{
	might_sleep();
	if (nilfs_init(nilfs)) {
		nilfs_sysfs_delete_device_group(nilfs);
		brelse(nilfs->ns_sbh[0]);
		brelse(nilfs->ns_sbh[1]);
	}
	kfree(nilfs);
}

static int nilfs_load_super_root(struct the_nilfs *nilfs,
				 struct super_block *sb, sector_t sr_block)
{
	struct buffer_head *bh_sr;
	struct nilfs_super_root *raw_sr;
	struct nilfs_super_block **sbp = nilfs->ns_sbp;
	struct nilfs_inode *rawi;
	unsigned dat_entry_size, segment_usage_size, checkpoint_size;
	unsigned inode_size;
	int err;

	err = nilfs_read_super_root_block(nilfs, sr_block, &bh_sr, 1);
	if (unlikely(err))
		return err;

	down_read(&nilfs->ns_sem);
	dat_entry_size = le16_to_cpu(sbp[0]->s_dat_entry_size);
	checkpoint_size = le16_to_cpu(sbp[0]->s_checkpoint_size);
	segment_usage_size = le16_to_cpu(sbp[0]->s_segment_usage_size);
	up_read(&nilfs->ns_sem);

	inode_size = nilfs->ns_inode_size;

	rawi = (void *)bh_sr->b_data + NILFS_SR_DAT_OFFSET(inode_size);
	err = nilfs_dat_read(sb, dat_entry_size, rawi, &nilfs->ns_dat);
	if (err)
		goto failed;

	rawi = (void *)bh_sr->b_data + NILFS_SR_CPFILE_OFFSET(inode_size);
	err = nilfs_cpfile_read(sb, checkpoint_size, rawi, &nilfs->ns_cpfile);
	if (err)
		goto failed_dat;

	rawi = (void *)bh_sr->b_data + NILFS_SR_SUFILE_OFFSET(inode_size);
	err = nilfs_sufile_read(sb, segment_usage_size, rawi,
				&nilfs->ns_sufile);
	if (err)
		goto failed_cpfile;

	raw_sr = (struct nilfs_super_root *)bh_sr->b_data;
	nilfs->ns_nongc_ctime = le64_to_cpu(raw_sr->sr_nongc_ctime);

 failed:
	brelse(bh_sr);
	return err;

 failed_cpfile:
	iput(nilfs->ns_cpfile);

 failed_dat:
	iput(nilfs->ns_dat);
	goto failed;
}

static void nilfs_init_recovery_info(struct nilfs_recovery_info *ri)
{
	memset(ri, 0, sizeof(*ri));
	INIT_LIST_HEAD(&ri->ri_used_segments);
}

static void nilfs_clear_recovery_info(struct nilfs_recovery_info *ri)
{
	nilfs_dispose_segment_list(&ri->ri_used_segments);
}

/**
 * nilfs_store_log_cursor - load log cursor from a super block
 * @nilfs: nilfs object
 * @sbp: buffer storing super block to be read
 *
 * nilfs_store_log_cursor() reads the last position of the log
 * containing a super root from a given super block, and initializes
 * relevant information on the nilfs object preparatory for log
 * scanning and recovery.
 */
static int nilfs_store_log_cursor(struct the_nilfs *nilfs,
				  struct nilfs_super_block *sbp)
{
	int ret = 0;

	nilfs->ns_last_pseg = le64_to_cpu(sbp->s_last_pseg);
	nilfs->ns_last_cno = le64_to_cpu(sbp->s_last_cno);
	nilfs->ns_last_seq = le64_to_cpu(sbp->s_last_seq);

	nilfs->ns_prev_seq = nilfs->ns_last_seq;
	nilfs->ns_seg_seq = nilfs->ns_last_seq;
	nilfs->ns_segnum =
		nilfs_get_segnum_of_block(nilfs, nilfs->ns_last_pseg);
	nilfs->ns_cno = nilfs->ns_last_cno + 1;
	if (nilfs->ns_segnum >= nilfs->ns_nsegments) {
		printk(KERN_ERR "NILFS invalid last segment number.\n");
		ret = -EINVAL;
	}
	return ret;
}

/**
 * load_nilfs - load and recover the nilfs
 * @nilfs: the_nilfs structure to be released
 * @sb: super block isntance used to recover past segment
 *
 * load_nilfs() searches and load the latest super root,
 * attaches the last segment, and does recovery if needed.
 * The caller must call this exclusively for simultaneous mounts.
 */
int load_nilfs(struct the_nilfs *nilfs, struct super_block *sb)
{
	struct nilfs_recovery_info ri;
	unsigned int s_flags = sb->s_flags;
	int really_read_only = bdev_read_only(nilfs->ns_bdev);
	int valid_fs = nilfs_valid_fs(nilfs);
	int err;

	if (!valid_fs) {
		printk(KERN_WARNING "NILFS warning: mounting unchecked fs\n");
		if (s_flags & MS_RDONLY) {
			printk(KERN_INFO "NILFS: INFO: recovery "
			       "required for readonly filesystem.\n");
			printk(KERN_INFO "NILFS: write access will "
			       "be enabled during recovery.\n");
		}
	}

	nilfs_init_recovery_info(&ri);

	err = nilfs_search_super_root(nilfs, &ri);
	if (unlikely(err)) {
		struct nilfs_super_block **sbp = nilfs->ns_sbp;
		int blocksize;

		if (err != -EINVAL)
			goto scan_error;

		if (!nilfs_valid_sb(sbp[1])) {
			printk(KERN_WARNING
			       "NILFS warning: unable to fall back to spare"
			       "super block\n");
			goto scan_error;
		}
		printk(KERN_INFO
		       "NILFS: try rollback from an earlier position\n");

		/*
		 * restore super block with its spare and reconfigure
		 * relevant states of the nilfs object.
		 */
		memcpy(sbp[0], sbp[1], nilfs->ns_sbsize);
		nilfs->ns_crc_seed = le32_to_cpu(sbp[0]->s_crc_seed);
		nilfs->ns_sbwtime = le64_to_cpu(sbp[0]->s_wtime);

		/* verify consistency between two super blocks */
		blocksize = BLOCK_SIZE << le32_to_cpu(sbp[0]->s_log_block_size);
		if (blocksize != nilfs->ns_blocksize) {
			printk(KERN_WARNING
			       "NILFS warning: blocksize differs between "
			       "two super blocks (%d != %d)\n",
			       blocksize, nilfs->ns_blocksize);
			goto scan_error;
		}

		err = nilfs_store_log_cursor(nilfs, sbp[0]);
		if (err)
			goto scan_error;

		/* drop clean flag to allow roll-forward and recovery */
		nilfs->ns_mount_state &= ~NILFS_VALID_FS;
		valid_fs = 0;

		err = nilfs_search_super_root(nilfs, &ri);
		if (err)
			goto scan_error;
	}

	err = nilfs_load_super_root(nilfs, sb, ri.ri_super_root);
	if (unlikely(err)) {
		printk(KERN_ERR "NILFS: error loading super root.\n");
		goto failed;
	}

	if (valid_fs)
		goto skip_recovery;

	if (s_flags & MS_RDONLY) {
		__u64 features;

		if (nilfs_test_opt(nilfs, NORECOVERY)) {
			printk(KERN_INFO "NILFS: norecovery option specified. "
			       "skipping roll-forward recovery\n");
			goto skip_recovery;
		}
		features = le64_to_cpu(nilfs->ns_sbp[0]->s_feature_compat_ro) &
			~NILFS_FEATURE_COMPAT_RO_SUPP;
		if (features) {
			printk(KERN_ERR "NILFS: couldn't proceed with "
			       "recovery because of unsupported optional "
			       "features (%llx)\n",
			       (unsigned long long)features);
			err = -EROFS;
			goto failed_unload;
		}
		if (really_read_only) {
			printk(KERN_ERR "NILFS: write access "
			       "unavailable, cannot proceed.\n");
			err = -EROFS;
			goto failed_unload;
		}
		sb->s_flags &= ~MS_RDONLY;
	} else if (nilfs_test_opt(nilfs, NORECOVERY)) {
		printk(KERN_ERR "NILFS: recovery cancelled because norecovery "
		       "option was specified for a read/write mount\n");
		err = -EINVAL;
		goto failed_unload;
	}

	err = nilfs_salvage_orphan_logs(nilfs, sb, &ri);
	if (err)
		goto failed_unload;

	down_write(&nilfs->ns_sem);
	nilfs->ns_mount_state |= NILFS_VALID_FS; /* set "clean" flag */
	err = nilfs_cleanup_super(sb);
	up_write(&nilfs->ns_sem);

	if (err) {
		printk(KERN_ERR "NILFS: failed to update super block. "
		       "recovery unfinished.\n");
		goto failed_unload;
	}
	printk(KERN_INFO "NILFS: recovery complete.\n");

 skip_recovery:
	nilfs_clear_recovery_info(&ri);
	sb->s_flags = s_flags;
	return 0;

 scan_error:
	printk(KERN_ERR "NILFS: error searching super root.\n");
	goto failed;

 failed_unload:
	iput(nilfs->ns_cpfile);
	iput(nilfs->ns_sufile);
	iput(nilfs->ns_dat);

 failed:
	nilfs_clear_recovery_info(&ri);
	sb->s_flags = s_flags;
	return err;
}

static unsigned long long nilfs_max_size(unsigned int blkbits)
{
	unsigned int max_bits;
	unsigned long long res = MAX_LFS_FILESIZE; /* page cache limit */

	max_bits = blkbits + NILFS_BMAP_KEY_BIT; /* bmap size limit */
	if (max_bits < 64)
		res = min_t(unsigned long long, res, (1ULL << max_bits) - 1);
	return res;
}

/**
 * nilfs_nrsvsegs - calculate the number of reserved segments
 * @nilfs: nilfs object
 * @nsegs: total number of segments
 */
unsigned long nilfs_nrsvsegs(struct the_nilfs *nilfs, unsigned long nsegs)
{
	return max_t(unsigned long, NILFS_MIN_NRSVSEGS,
		     DIV_ROUND_UP(nsegs * nilfs->ns_r_segments_percentage,
				  100));
}

void nilfs_set_nsegments(struct the_nilfs *nilfs, unsigned long nsegs)
{
	nilfs->ns_nsegments = nsegs;
	nilfs->ns_nrsvsegs = nilfs_nrsvsegs(nilfs, nsegs);
}

static int nilfs_store_disk_layout(struct the_nilfs *nilfs,
				   struct nilfs_super_block *sbp)
{
	if (le32_to_cpu(sbp->s_rev_level) < NILFS_MIN_SUPP_REV) {
		printk(KERN_ERR "NILFS: unsupported revision "
		       "(superblock rev.=%d.%d, current rev.=%d.%d). "
		       "Please check the version of mkfs.nilfs.\n",
		       le32_to_cpu(sbp->s_rev_level),
		       le16_to_cpu(sbp->s_minor_rev_level),
		       NILFS_CURRENT_REV, NILFS_MINOR_REV);
		return -EINVAL;
	}
	nilfs->ns_sbsize = le16_to_cpu(sbp->s_bytes);
	if (nilfs->ns_sbsize > BLOCK_SIZE)
		return -EINVAL;

	nilfs->ns_inode_size = le16_to_cpu(sbp->s_inode_size);
	if (nilfs->ns_inode_size > nilfs->ns_blocksize) {
		printk(KERN_ERR "NILFS: too large inode size: %d bytes.\n",
		       nilfs->ns_inode_size);
		return -EINVAL;
	} else if (nilfs->ns_inode_size < NILFS_MIN_INODE_SIZE) {
		printk(KERN_ERR "NILFS: too small inode size: %d bytes.\n",
		       nilfs->ns_inode_size);
		return -EINVAL;
	}

	nilfs->ns_first_ino = le32_to_cpu(sbp->s_first_ino);

	nilfs->ns_blocks_per_segment = le32_to_cpu(sbp->s_blocks_per_segment);
	if (nilfs->ns_blocks_per_segment < NILFS_SEG_MIN_BLOCKS) {
		printk(KERN_ERR "NILFS: too short segment.\n");
		return -EINVAL;
	}

	nilfs->ns_first_data_block = le64_to_cpu(sbp->s_first_data_block);
	nilfs->ns_r_segments_percentage =
		le32_to_cpu(sbp->s_r_segments_percentage);
	if (nilfs->ns_r_segments_percentage < 1 ||
	    nilfs->ns_r_segments_percentage > 99) {
		printk(KERN_ERR "NILFS: invalid reserved segments percentage.\n");
		return -EINVAL;
	}

	nilfs_set_nsegments(nilfs, le64_to_cpu(sbp->s_nsegments));
	nilfs->ns_crc_seed = le32_to_cpu(sbp->s_crc_seed);
	return 0;
}

static int nilfs_valid_sb(struct nilfs_super_block *sbp)
{
	static unsigned char sum[4];
	const int sumoff = offsetof(struct nilfs_super_block, s_sum);
	size_t bytes;
	u32 crc;

	if (!sbp || le16_to_cpu(sbp->s_magic) != NILFS_SUPER_MAGIC)
		return 0;
	bytes = le16_to_cpu(sbp->s_bytes);
	if (bytes > BLOCK_SIZE)
		return 0;
	crc = crc32_le(le32_to_cpu(sbp->s_crc_seed), (unsigned char *)sbp,
		       sumoff);
	crc = crc32_le(crc, sum, 4);
	crc = crc32_le(crc, (unsigned char *)sbp + sumoff + 4,
		       bytes - sumoff - 4);
	return crc == le32_to_cpu(sbp->s_sum);
}

static int nilfs_sb2_bad_offset(struct nilfs_super_block *sbp, u64 offset)
{
	return offset < ((le64_to_cpu(sbp->s_nsegments) *
			  le32_to_cpu(sbp->s_blocks_per_segment)) <<
			 (le32_to_cpu(sbp->s_log_block_size) + 10));
}

static void nilfs_release_super_block(struct the_nilfs *nilfs)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (nilfs->ns_sbp[i]) {
			brelse(nilfs->ns_sbh[i]);
			nilfs->ns_sbh[i] = NULL;
			nilfs->ns_sbp[i] = NULL;
		}
	}
}

void nilfs_fall_back_super_block(struct the_nilfs *nilfs)
{
	brelse(nilfs->ns_sbh[0]);
	nilfs->ns_sbh[0] = nilfs->ns_sbh[1];
	nilfs->ns_sbp[0] = nilfs->ns_sbp[1];
	nilfs->ns_sbh[1] = NULL;
	nilfs->ns_sbp[1] = NULL;
}

void nilfs_swap_super_block(struct the_nilfs *nilfs)
{
	struct buffer_head *tsbh = nilfs->ns_sbh[0];
	struct nilfs_super_block *tsbp = nilfs->ns_sbp[0];

	nilfs->ns_sbh[0] = nilfs->ns_sbh[1];
	nilfs->ns_sbp[0] = nilfs->ns_sbp[1];
	nilfs->ns_sbh[1] = tsbh;
	nilfs->ns_sbp[1] = tsbp;
}

static int nilfs_load_super_block(struct the_nilfs *nilfs,
				  struct super_block *sb, int blocksize,
				  struct nilfs_super_block **sbpp)
{
	struct nilfs_super_block **sbp = nilfs->ns_sbp;
	struct buffer_head **sbh = nilfs->ns_sbh;
	u64 sb2off = NILFS_SB2_OFFSET_BYTES(nilfs->ns_bdev->bd_inode->i_size);
	int valid[2], swp = 0;

	sbp[0] = nilfs_read_super_block(sb, NILFS_SB_OFFSET_BYTES, blocksize,
					&sbh[0]);
	sbp[1] = nilfs_read_super_block(sb, sb2off, blocksize, &sbh[1]);

	if (!sbp[0]) {
		if (!sbp[1]) {
			printk(KERN_ERR "NILFS: unable to read superblock\n");
			return -EIO;
		}
		printk(KERN_WARNING
		       "NILFS warning: unable to read primary superblock "
		       "(blocksize = %d)\n", blocksize);
	} else if (!sbp[1]) {
		printk(KERN_WARNING
		       "NILFS warning: unable to read secondary superblock "
		       "(blocksize = %d)\n", blocksize);
	}

	/*
	 * Compare two super blocks and set 1 in swp if the secondary
	 * super block is valid and newer.  Otherwise, set 0 in swp.
	 */
	valid[0] = nilfs_valid_sb(sbp[0]);
	valid[1] = nilfs_valid_sb(sbp[1]);
	swp = valid[1] && (!valid[0] ||
			   le64_to_cpu(sbp[1]->s_last_cno) >
			   le64_to_cpu(sbp[0]->s_last_cno));

	if (valid[swp] && nilfs_sb2_bad_offset(sbp[swp], sb2off)) {
		brelse(sbh[1]);
		sbh[1] = NULL;
		sbp[1] = NULL;
		valid[1] = 0;
		swp = 0;
	}
	if (!valid[swp]) {
		nilfs_release_super_block(nilfs);
		printk(KERN_ERR "NILFS: Can't find nilfs on dev %s.\n",
		       sb->s_id);
		return -EINVAL;
	}

	if (!valid[!swp])
		printk(KERN_WARNING "NILFS warning: broken superblock. "
		       "using spare superblock (blocksize = %d).\n", blocksize);
	if (swp)
		nilfs_swap_super_block(nilfs);

	nilfs->ns_sbwcount = 0;
	nilfs->ns_sbwtime = le64_to_cpu(sbp[0]->s_wtime);
	nilfs->ns_prot_seq = le64_to_cpu(sbp[valid[1] & !swp]->s_last_seq);
	*sbpp = sbp[0];
	return 0;
}

/**
 * init_nilfs - initialize a NILFS instance.
 * @nilfs: the_nilfs structure
 * @sb: super block
 * @data: mount options
 *
 * init_nilfs() performs common initialization per block device (e.g.
 * reading the super block, getting disk layout information, initializing
 * shared fields in the_nilfs).
 *
 * Return Value: On success, 0 is returned. On error, a negative error
 * code is returned.
 */
int init_nilfs(struct the_nilfs *nilfs, struct super_block *sb, char *data)
{
	struct nilfs_super_block *sbp;
	int blocksize;
	int err;

	down_write(&nilfs->ns_sem);

	blocksize = sb_min_blocksize(sb, NILFS_MIN_BLOCK_SIZE);
	if (!blocksize) {
		printk(KERN_ERR "NILFS: unable to set blocksize\n");
		err = -EINVAL;
		goto out;
	}
	err = nilfs_load_super_block(nilfs, sb, blocksize, &sbp);
	if (err)
		goto out;

	err = nilfs_store_magic_and_option(sb, sbp, data);
	if (err)
		goto failed_sbh;

	err = nilfs_check_feature_compatibility(sb, sbp);
	if (err)
		goto failed_sbh;

	blocksize = BLOCK_SIZE << le32_to_cpu(sbp->s_log_block_size);
	if (blocksize < NILFS_MIN_BLOCK_SIZE ||
	    blocksize > NILFS_MAX_BLOCK_SIZE) {
		printk(KERN_ERR "NILFS: couldn't mount because of unsupported "
		       "filesystem blocksize %d\n", blocksize);
		err = -EINVAL;
		goto failed_sbh;
	}
	if (sb->s_blocksize != blocksize) {
		int hw_blocksize = bdev_logical_block_size(sb->s_bdev);

		if (blocksize < hw_blocksize) {
			printk(KERN_ERR
			       "NILFS: blocksize %d too small for device "
			       "(sector-size = %d).\n",
			       blocksize, hw_blocksize);
			err = -EINVAL;
			goto failed_sbh;
		}
		nilfs_release_super_block(nilfs);
		sb_set_blocksize(sb, blocksize);

		err = nilfs_load_super_block(nilfs, sb, blocksize, &sbp);
		if (err)
			goto out;
			/* not failed_sbh; sbh is released automatically
			   when reloading fails. */
	}
	nilfs->ns_blocksize_bits = sb->s_blocksize_bits;
	nilfs->ns_blocksize = blocksize;

	get_random_bytes(&nilfs->ns_next_generation,
			 sizeof(nilfs->ns_next_generation));

	err = nilfs_store_disk_layout(nilfs, sbp);
	if (err)
		goto failed_sbh;

	sb->s_maxbytes = nilfs_max_size(sb->s_blocksize_bits);

	nilfs->ns_mount_state = le16_to_cpu(sbp->s_state);

	err = nilfs_store_log_cursor(nilfs, sbp);
	if (err)
		goto failed_sbh;

	err = nilfs_sysfs_create_device_group(sb);
	if (err)
		goto failed_sbh;

	set_nilfs_init(nilfs);
	err = 0;
 out:
	up_write(&nilfs->ns_sem);
	return err;

 failed_sbh:
	nilfs_release_super_block(nilfs);
	goto out;
}

int nilfs_discard_segments(struct the_nilfs *nilfs, __u64 *segnump,
			    size_t nsegs)
{
	sector_t seg_start, seg_end;
	sector_t start = 0, nblocks = 0;
	unsigned int sects_per_block;
	__u64 *sn;
	int ret = 0;

	sects_per_block = (1 << nilfs->ns_blocksize_bits) /
		bdev_logical_block_size(nilfs->ns_bdev);
	for (sn = segnump; sn < segnump + nsegs; sn++) {
		nilfs_get_segment_range(nilfs, *sn, &seg_start, &seg_end);

		if (!nblocks) {
			start = seg_start;
			nblocks = seg_end - seg_start + 1;
		} else if (start + nblocks == seg_start) {
			nblocks += seg_end - seg_start + 1;
		} else {
			ret = blkdev_issue_discard(nilfs->ns_bdev,
						   start * sects_per_block,
						   nblocks * sects_per_block,
						   GFP_NOFS, 0);
			if (ret < 0)
				return ret;
			nblocks = 0;
		}
	}
	if (nblocks)
		ret = blkdev_issue_discard(nilfs->ns_bdev,
					   start * sects_per_block,
					   nblocks * sects_per_block,
					   GFP_NOFS, 0);
	return ret;
}

int nilfs_count_free_blocks(struct the_nilfs *nilfs, sector_t *nblocks)
{
	unsigned long ncleansegs;

	down_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);
	ncleansegs = nilfs_sufile_get_ncleansegs(nilfs->ns_sufile);
	up_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);
	*nblocks = (sector_t)ncleansegs * nilfs->ns_blocks_per_segment;
	return 0;
}

int nilfs_near_disk_full(struct the_nilfs *nilfs)
{
	unsigned long ncleansegs, nincsegs;

	ncleansegs = nilfs_sufile_get_ncleansegs(nilfs->ns_sufile);
	nincsegs = atomic_read(&nilfs->ns_ndirtyblks) /
		nilfs->ns_blocks_per_segment + 1;

	return ncleansegs <= nilfs->ns_nrsvsegs + nincsegs;
}

struct nilfs_root *nilfs_lookup_root(struct the_nilfs *nilfs, __u64 cno)
{
	struct rb_node *n;
	struct nilfs_root *root;

	spin_lock(&nilfs->ns_cptree_lock);
	n = nilfs->ns_cptree.rb_node;
	while (n) {
		root = rb_entry(n, struct nilfs_root, rb_node);

		if (cno < root->cno) {
			n = n->rb_left;
		} else if (cno > root->cno) {
			n = n->rb_right;
		} else {
			atomic_inc(&root->count);
			spin_unlock(&nilfs->ns_cptree_lock);
			return root;
		}
	}
	spin_unlock(&nilfs->ns_cptree_lock);

	return NULL;
}

struct nilfs_root *
nilfs_find_or_create_root(struct the_nilfs *nilfs, __u64 cno)
{
	struct rb_node **p, *parent;
	struct nilfs_root *root, *new;
	int err;

	root = nilfs_lookup_root(nilfs, cno);
	if (root)
		return root;

	new = kzalloc(sizeof(*root), GFP_KERNEL);
	if (!new)
		return NULL;

	spin_lock(&nilfs->ns_cptree_lock);

	p = &nilfs->ns_cptree.rb_node;
	parent = NULL;

	while (*p) {
		parent = *p;
		root = rb_entry(parent, struct nilfs_root, rb_node);

		if (cno < root->cno) {
			p = &(*p)->rb_left;
		} else if (cno > root->cno) {
			p = &(*p)->rb_right;
		} else {
			atomic_inc(&root->count);
			spin_unlock(&nilfs->ns_cptree_lock);
			kfree(new);
			return root;
		}
	}

	new->cno = cno;
	new->ifile = NULL;
	new->nilfs = nilfs;
	atomic_set(&new->count, 1);
	atomic64_set(&new->inodes_count, 0);
	atomic64_set(&new->blocks_count, 0);

	rb_link_node(&new->rb_node, parent, p);
	rb_insert_color(&new->rb_node, &nilfs->ns_cptree);

	spin_unlock(&nilfs->ns_cptree_lock);

	err = nilfs_sysfs_create_snapshot_group(new);
	if (err) {
		kfree(new);
		new = NULL;
	}

	return new;
}

void nilfs_put_root(struct nilfs_root *root)
{
	if (atomic_dec_and_test(&root->count)) {
		struct the_nilfs *nilfs = root->nilfs;

		nilfs_sysfs_delete_snapshot_group(root);

		spin_lock(&nilfs->ns_cptree_lock);
		rb_erase(&root->rb_node, &nilfs->ns_cptree);
		spin_unlock(&nilfs->ns_cptree_lock);
		if (root->ifile)
			iput(root->ifile);

		kfree(root);
	}
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/the_nilfs.c */
/************************************************************/
/*
 * segbuf.c - NILFS segment buffer
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 *
 */

// #include <linux/buffer_head.h>
// #include <linux/writeback.h>
// #include <linux/crc32.h>
// #include <linux/backing-dev.h>
// #include <linux/slab.h>
// #include "page.h"
// #include "segbuf.h"


struct nilfs_write_info {
	struct the_nilfs       *nilfs;
	struct bio	       *bio;
	int			start, end; /* The region to be submitted */
	int			rest_blocks;
	int			max_pages;
	int			nr_vecs;
	sector_t		blocknr;
};

static int nilfs_segbuf_write(struct nilfs_segment_buffer *segbuf,
			      struct the_nilfs *nilfs);
static int nilfs_segbuf_wait(struct nilfs_segment_buffer *segbuf);

struct nilfs_segment_buffer *nilfs_segbuf_new(struct super_block *sb)
{
	struct nilfs_segment_buffer *segbuf;

	segbuf = kmem_cache_alloc(nilfs_segbuf_cachep, GFP_NOFS);
	if (unlikely(!segbuf))
		return NULL;

	segbuf->sb_super = sb;
	INIT_LIST_HEAD(&segbuf->sb_list);
	INIT_LIST_HEAD(&segbuf->sb_segsum_buffers);
	INIT_LIST_HEAD(&segbuf->sb_payload_buffers);
	segbuf->sb_super_root = NULL;

	init_completion(&segbuf->sb_bio_event);
	atomic_set(&segbuf->sb_err, 0);
	segbuf->sb_nbio = 0;

	return segbuf;
}

void nilfs_segbuf_free(struct nilfs_segment_buffer *segbuf)
{
	kmem_cache_free(nilfs_segbuf_cachep, segbuf);
}

void nilfs_segbuf_map(struct nilfs_segment_buffer *segbuf, __u64 segnum,
		     unsigned long offset, struct the_nilfs *nilfs)
{
	segbuf->sb_segnum = segnum;
	nilfs_get_segment_range(nilfs, segnum, &segbuf->sb_fseg_start,
				&segbuf->sb_fseg_end);

	segbuf->sb_pseg_start = segbuf->sb_fseg_start + offset;
	segbuf->sb_rest_blocks =
		segbuf->sb_fseg_end - segbuf->sb_pseg_start + 1;
}

/**
 * nilfs_segbuf_map_cont - map a new log behind a given log
 * @segbuf: new segment buffer
 * @prev: segment buffer containing a log to be continued
 */
void nilfs_segbuf_map_cont(struct nilfs_segment_buffer *segbuf,
			   struct nilfs_segment_buffer *prev)
{
	segbuf->sb_segnum = prev->sb_segnum;
	segbuf->sb_fseg_start = prev->sb_fseg_start;
	segbuf->sb_fseg_end = prev->sb_fseg_end;
	segbuf->sb_pseg_start = prev->sb_pseg_start + prev->sb_sum.nblocks;
	segbuf->sb_rest_blocks =
		segbuf->sb_fseg_end - segbuf->sb_pseg_start + 1;
}

void nilfs_segbuf_set_next_segnum(struct nilfs_segment_buffer *segbuf,
				  __u64 nextnum, struct the_nilfs *nilfs)
{
	segbuf->sb_nextnum = nextnum;
	segbuf->sb_sum.next = nilfs_get_segment_start_blocknr(nilfs, nextnum);
}

int nilfs_segbuf_extend_segsum(struct nilfs_segment_buffer *segbuf)
{
	struct buffer_head *bh;

	bh = sb_getblk(segbuf->sb_super,
		       segbuf->sb_pseg_start + segbuf->sb_sum.nsumblk);
	if (unlikely(!bh))
		return -ENOMEM;

	nilfs_segbuf_add_segsum_buffer(segbuf, bh);
	return 0;
}

int nilfs_segbuf_extend_payload(struct nilfs_segment_buffer *segbuf,
				struct buffer_head **bhp)
{
	struct buffer_head *bh;

	bh = sb_getblk(segbuf->sb_super,
		       segbuf->sb_pseg_start + segbuf->sb_sum.nblocks);
	if (unlikely(!bh))
		return -ENOMEM;

	nilfs_segbuf_add_payload_buffer(segbuf, bh);
	*bhp = bh;
	return 0;
}

int nilfs_segbuf_reset(struct nilfs_segment_buffer *segbuf, unsigned flags,
		       time_t ctime, __u64 cno)
{
	int err;

	segbuf->sb_sum.nblocks = segbuf->sb_sum.nsumblk = 0;
	err = nilfs_segbuf_extend_segsum(segbuf);
	if (unlikely(err))
		return err;

	segbuf->sb_sum.flags = flags;
	segbuf->sb_sum.sumbytes = sizeof(struct nilfs_segment_summary);
	segbuf->sb_sum.nfinfo = segbuf->sb_sum.nfileblk = 0;
	segbuf->sb_sum.ctime = ctime;
	segbuf->sb_sum.cno = cno;
	return 0;
}

/*
 * Setup segment summary
 */
void nilfs_segbuf_fill_in_segsum(struct nilfs_segment_buffer *segbuf)
{
	struct nilfs_segment_summary *raw_sum;
	struct buffer_head *bh_sum;

	bh_sum = list_entry(segbuf->sb_segsum_buffers.next,
			    struct buffer_head, b_assoc_buffers);
	raw_sum = (struct nilfs_segment_summary *)bh_sum->b_data;

	raw_sum->ss_magic    = cpu_to_le32(NILFS_SEGSUM_MAGIC);
	raw_sum->ss_bytes    = cpu_to_le16(sizeof(*raw_sum));
	raw_sum->ss_flags    = cpu_to_le16(segbuf->sb_sum.flags);
	raw_sum->ss_seq      = cpu_to_le64(segbuf->sb_sum.seg_seq);
	raw_sum->ss_create   = cpu_to_le64(segbuf->sb_sum.ctime);
	raw_sum->ss_next     = cpu_to_le64(segbuf->sb_sum.next);
	raw_sum->ss_nblocks  = cpu_to_le32(segbuf->sb_sum.nblocks);
	raw_sum->ss_nfinfo   = cpu_to_le32(segbuf->sb_sum.nfinfo);
	raw_sum->ss_sumbytes = cpu_to_le32(segbuf->sb_sum.sumbytes);
	raw_sum->ss_pad      = 0;
	raw_sum->ss_cno      = cpu_to_le64(segbuf->sb_sum.cno);
}

/*
 * CRC calculation routines
 */
static void
nilfs_segbuf_fill_in_segsum_crc(struct nilfs_segment_buffer *segbuf, u32 seed)
{
	struct buffer_head *bh;
	struct nilfs_segment_summary *raw_sum;
	unsigned long size, bytes = segbuf->sb_sum.sumbytes;
	u32 crc;

	bh = list_entry(segbuf->sb_segsum_buffers.next, struct buffer_head,
			b_assoc_buffers);

	raw_sum = (struct nilfs_segment_summary *)bh->b_data;
	size = min_t(unsigned long, bytes, bh->b_size);
	crc = crc32_le(seed,
		       (unsigned char *)raw_sum +
		       sizeof(raw_sum->ss_datasum) + sizeof(raw_sum->ss_sumsum),
		       size - (sizeof(raw_sum->ss_datasum) +
			       sizeof(raw_sum->ss_sumsum)));

	list_for_each_entry_continue(bh, &segbuf->sb_segsum_buffers,
				     b_assoc_buffers) {
		bytes -= size;
		size = min_t(unsigned long, bytes, bh->b_size);
		crc = crc32_le(crc, bh->b_data, size);
	}
	raw_sum->ss_sumsum = cpu_to_le32(crc);
}

static void nilfs_segbuf_fill_in_data_crc(struct nilfs_segment_buffer *segbuf,
					  u32 seed)
{
	struct buffer_head *bh;
	struct nilfs_segment_summary *raw_sum;
	void *kaddr;
	u32 crc;

	bh = list_entry(segbuf->sb_segsum_buffers.next, struct buffer_head,
			b_assoc_buffers);
	raw_sum = (struct nilfs_segment_summary *)bh->b_data;
	crc = crc32_le(seed,
		       (unsigned char *)raw_sum + sizeof(raw_sum->ss_datasum),
		       bh->b_size - sizeof(raw_sum->ss_datasum));

	list_for_each_entry_continue(bh, &segbuf->sb_segsum_buffers,
				     b_assoc_buffers) {
		crc = crc32_le(crc, bh->b_data, bh->b_size);
	}
	list_for_each_entry(bh, &segbuf->sb_payload_buffers, b_assoc_buffers) {
		kaddr = kmap_atomic(bh->b_page);
		crc = crc32_le(crc, kaddr + bh_offset(bh), bh->b_size);
		kunmap_atomic(kaddr);
	}
	raw_sum->ss_datasum = cpu_to_le32(crc);
}

static void
nilfs_segbuf_fill_in_super_root_crc(struct nilfs_segment_buffer *segbuf,
				    u32 seed)
{
	struct nilfs_super_root *raw_sr;
	struct the_nilfs *nilfs = segbuf->sb_super->s_fs_info;
	unsigned srsize;
	u32 crc;

	raw_sr = (struct nilfs_super_root *)segbuf->sb_super_root->b_data;
	srsize = NILFS_SR_BYTES(nilfs->ns_inode_size);
	crc = crc32_le(seed,
		       (unsigned char *)raw_sr + sizeof(raw_sr->sr_sum),
		       srsize - sizeof(raw_sr->sr_sum));
	raw_sr->sr_sum = cpu_to_le32(crc);
}

static void nilfs_release_buffers(struct list_head *list)
{
	struct buffer_head *bh, *n;

	list_for_each_entry_safe(bh, n, list, b_assoc_buffers) {
		list_del_init(&bh->b_assoc_buffers);
		brelse(bh);
	}
}

static void nilfs_segbuf_clear(struct nilfs_segment_buffer *segbuf)
{
	nilfs_release_buffers(&segbuf->sb_segsum_buffers);
	nilfs_release_buffers(&segbuf->sb_payload_buffers);
	segbuf->sb_super_root = NULL;
}

/*
 * Iterators for segment buffers
 */
void nilfs_clear_logs(struct list_head *logs)
{
	struct nilfs_segment_buffer *segbuf;

	list_for_each_entry(segbuf, logs, sb_list)
		nilfs_segbuf_clear(segbuf);
}

void nilfs_truncate_logs(struct list_head *logs,
			 struct nilfs_segment_buffer *last)
{
	struct nilfs_segment_buffer *n, *segbuf;

	segbuf = list_prepare_entry(last, logs, sb_list);
	list_for_each_entry_safe_continue(segbuf, n, logs, sb_list) {
		list_del_init(&segbuf->sb_list);
		nilfs_segbuf_clear(segbuf);
		nilfs_segbuf_free(segbuf);
	}
}

int nilfs_write_logs(struct list_head *logs, struct the_nilfs *nilfs)
{
	struct nilfs_segment_buffer *segbuf;
	int ret = 0;

	list_for_each_entry(segbuf, logs, sb_list) {
		ret = nilfs_segbuf_write(segbuf, nilfs);
		if (ret)
			break;
	}
	return ret;
}

int nilfs_wait_on_logs(struct list_head *logs)
{
	struct nilfs_segment_buffer *segbuf;
	int err, ret = 0;

	list_for_each_entry(segbuf, logs, sb_list) {
		err = nilfs_segbuf_wait(segbuf);
		if (err && !ret)
			ret = err;
	}
	return ret;
}

/**
 * nilfs_add_checksums_on_logs - add checksums on the logs
 * @logs: list of segment buffers storing target logs
 * @seed: checksum seed value
 */
void nilfs_add_checksums_on_logs(struct list_head *logs, u32 seed)
{
	struct nilfs_segment_buffer *segbuf;

	list_for_each_entry(segbuf, logs, sb_list) {
		if (segbuf->sb_super_root)
			nilfs_segbuf_fill_in_super_root_crc(segbuf, seed);
		nilfs_segbuf_fill_in_segsum_crc(segbuf, seed);
		nilfs_segbuf_fill_in_data_crc(segbuf, seed);
	}
}

/*
 * BIO operations
 */
static void nilfs_end_bio_write(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct nilfs_segment_buffer *segbuf = bio->bi_private;

	if (err == -EOPNOTSUPP) {
		set_bit(BIO_EOPNOTSUPP, &bio->bi_flags);
		/* to be detected by nilfs_segbuf_submit_bio() */
	}

	if (!uptodate)
		atomic_inc(&segbuf->sb_err);

	bio_put(bio);
	complete(&segbuf->sb_bio_event);
}

static int nilfs_segbuf_submit_bio(struct nilfs_segment_buffer *segbuf,
				   struct nilfs_write_info *wi, int mode)
{
	struct bio *bio = wi->bio;
	int err;

	if (segbuf->sb_nbio > 0 &&
	    bdi_write_congested(segbuf->sb_super->s_bdi)) {
		wait_for_completion(&segbuf->sb_bio_event);
		segbuf->sb_nbio--;
		if (unlikely(atomic_read(&segbuf->sb_err))) {
			bio_put(bio);
			err = -EIO;
			goto failed;
		}
	}

	bio->bi_end_io = nilfs_end_bio_write;
	bio->bi_private = segbuf;
	bio_get(bio);
	submit_bio(mode, bio);
	segbuf->sb_nbio++;
	if (bio_flagged(bio, BIO_EOPNOTSUPP)) {
		bio_put(bio);
		err = -EOPNOTSUPP;
		goto failed;
	}
	bio_put(bio);

	wi->bio = NULL;
	wi->rest_blocks -= wi->end - wi->start;
	wi->nr_vecs = min(wi->max_pages, wi->rest_blocks);
	wi->start = wi->end;
	return 0;

 failed:
	wi->bio = NULL;
	return err;
}

/**
 * nilfs_alloc_seg_bio - allocate a new bio for writing log
 * @nilfs: nilfs object
 * @start: start block number of the bio
 * @nr_vecs: request size of page vector.
 *
 * Return Value: On success, pointer to the struct bio is returned.
 * On error, NULL is returned.
 */
static struct bio *nilfs_alloc_seg_bio(struct the_nilfs *nilfs, sector_t start,
				       int nr_vecs)
{
	struct bio *bio;

	bio = bio_alloc(GFP_NOIO, nr_vecs);
	if (bio == NULL) {
		while (!bio && (nr_vecs >>= 1))
			bio = bio_alloc(GFP_NOIO, nr_vecs);
	}
	if (likely(bio)) {
		bio->bi_bdev = nilfs->ns_bdev;
		bio->bi_iter.bi_sector =
			start << (nilfs->ns_blocksize_bits - 9);
	}
	return bio;
}

static void nilfs_segbuf_prepare_write(struct nilfs_segment_buffer *segbuf,
				       struct nilfs_write_info *wi)
{
	wi->bio = NULL;
	wi->rest_blocks = segbuf->sb_sum.nblocks;
	wi->max_pages = bio_get_nr_vecs(wi->nilfs->ns_bdev);
	wi->nr_vecs = min(wi->max_pages, wi->rest_blocks);
	wi->start = wi->end = 0;
	wi->blocknr = segbuf->sb_pseg_start;
}

static int nilfs_segbuf_submit_bh(struct nilfs_segment_buffer *segbuf,
				  struct nilfs_write_info *wi,
				  struct buffer_head *bh, int mode)
{
	int len, err;

	BUG_ON(wi->nr_vecs <= 0);
 repeat:
	if (!wi->bio) {
		wi->bio = nilfs_alloc_seg_bio(wi->nilfs, wi->blocknr + wi->end,
					      wi->nr_vecs);
		if (unlikely(!wi->bio))
			return -ENOMEM;
	}

	len = bio_add_page(wi->bio, bh->b_page, bh->b_size, bh_offset(bh));
	if (len == bh->b_size) {
		wi->end++;
		return 0;
	}
	/* bio is FULL */
	err = nilfs_segbuf_submit_bio(segbuf, wi, mode);
	/* never submit current bh */
	if (likely(!err))
		goto repeat;
	return err;
}

/**
 * nilfs_segbuf_write - submit write requests of a log
 * @segbuf: buffer storing a log to be written
 * @nilfs: nilfs object
 *
 * Return Value: On Success, 0 is returned. On Error, one of the following
 * negative error code is returned.
 *
 * %-EIO - I/O error
 *
 * %-ENOMEM - Insufficient memory available.
 */
static int nilfs_segbuf_write(struct nilfs_segment_buffer *segbuf,
			      struct the_nilfs *nilfs)
{
	struct nilfs_write_info wi;
	struct buffer_head *bh;
	int res = 0, rw = WRITE;

	wi.nilfs = nilfs;
	nilfs_segbuf_prepare_write(segbuf, &wi);

	list_for_each_entry(bh, &segbuf->sb_segsum_buffers, b_assoc_buffers) {
		res = nilfs_segbuf_submit_bh(segbuf, &wi, bh, rw);
		if (unlikely(res))
			goto failed_bio;
	}

	list_for_each_entry(bh, &segbuf->sb_payload_buffers, b_assoc_buffers) {
		res = nilfs_segbuf_submit_bh(segbuf, &wi, bh, rw);
		if (unlikely(res))
			goto failed_bio;
	}

	if (wi.bio) {
		/*
		 * Last BIO is always sent through the following
		 * submission.
		 */
		rw |= REQ_SYNC;
		res = nilfs_segbuf_submit_bio(segbuf, &wi, rw);
	}

 failed_bio:
	return res;
}

/**
 * nilfs_segbuf_wait - wait for completion of requested BIOs
 * @segbuf: segment buffer
 *
 * Return Value: On Success, 0 is returned. On Error, one of the following
 * negative error code is returned.
 *
 * %-EIO - I/O error
 */
static int nilfs_segbuf_wait(struct nilfs_segment_buffer *segbuf)
{
	int err = 0;

	if (!segbuf->sb_nbio)
		return 0;

	do {
		wait_for_completion(&segbuf->sb_bio_event);
	} while (--segbuf->sb_nbio > 0);

	if (unlikely(atomic_read(&segbuf->sb_err) > 0)) {
		printk(KERN_ERR "NILFS: IO error writing segment\n");
		err = -EIO;
	}
	return err;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/segbuf.c */
/************************************************************/
/*
 * segment.c - NILFS segment constructor.
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Ryusuke Konishi <ryusuke@osrg.net>
 *
 */

// #include <linux/pagemap.h>
// #include <linux/buffer_head.h>
// #include <linux/writeback.h>
#include <linux/bio.h>
#include <linux/completion.h>
// #include <linux/blkdev.h>
// #include <linux/backing-dev.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
// #include <linux/crc32.h>
// #include <linux/pagevec.h>
// #include <linux/slab.h>
// #include "nilfs.h"
// #include "btnode.h"
// #include "page.h"
// #include "segment.h"
// #include "sufile.h"
// #include "cpfile.h"
// #include "ifile.h"
// #include "segbuf.h"


/*
 * Segment constructor
 */
#define SC_N_INODEVEC	16   /* Size of locally allocated inode vector */

#define SC_MAX_SEGDELTA 64   /* Upper limit of the number of segments
				appended in collection retry loop */

/* Construction mode */
enum {
	SC_LSEG_SR = 1,	/* Make a logical segment having a super root */
	SC_LSEG_DSYNC,	/* Flush data blocks of a given file and make
			   a logical segment without a super root */
	SC_FLUSH_FILE,	/* Flush data files, leads to segment writes without
			   creating a checkpoint */
	SC_FLUSH_DAT,	/* Flush DAT file. This also creates segments without
			   a checkpoint */
};

/* Stage numbers of dirty block collection */
enum {
	NILFS_ST_INIT = 0,
	NILFS_ST_GC,		/* Collecting dirty blocks for GC */
	NILFS_ST_FILE,
	NILFS_ST_IFILE,
	NILFS_ST_CPFILE,
	NILFS_ST_SUFILE,
	NILFS_ST_DAT,
	NILFS_ST_SR,		/* Super root */
	NILFS_ST_DSYNC,		/* Data sync blocks */
	NILFS_ST_DONE,
};

/* State flags of collection */
#define NILFS_CF_NODE		0x0001	/* Collecting node blocks */
#define NILFS_CF_IFILE_STARTED	0x0002	/* IFILE stage has started */
#define NILFS_CF_SUFREED	0x0004	/* segment usages has been freed */
#define NILFS_CF_HISTORY_MASK	(NILFS_CF_IFILE_STARTED | NILFS_CF_SUFREED)

/* Operations depending on the construction mode and file type */
struct nilfs_sc_operations {
	int (*collect_data)(struct nilfs_sc_info *, struct buffer_head *,
			    struct inode *);
	int (*collect_node)(struct nilfs_sc_info *, struct buffer_head *,
			    struct inode *);
	int (*collect_bmap)(struct nilfs_sc_info *, struct buffer_head *,
			    struct inode *);
	void (*write_data_binfo)(struct nilfs_sc_info *,
				 struct nilfs_segsum_pointer *,
				 union nilfs_binfo *);
	void (*write_node_binfo)(struct nilfs_sc_info *,
				 struct nilfs_segsum_pointer *,
				 union nilfs_binfo *);
};

/*
 * Other definitions
 */
static void nilfs_segctor_start_timer(struct nilfs_sc_info *);
static void nilfs_segctor_do_flush(struct nilfs_sc_info *, int);
static void nilfs_segctor_do_immediate_flush(struct nilfs_sc_info *);
static void nilfs_dispose_list(struct the_nilfs *, struct list_head *, int);

#define nilfs_cnt32_gt(a, b)   \
	(typecheck(__u32, a) && typecheck(__u32, b) && \
	 ((__s32)(b) - (__s32)(a) < 0))
#define nilfs_cnt32_ge(a, b)   \
	(typecheck(__u32, a) && typecheck(__u32, b) && \
	 ((__s32)(a) - (__s32)(b) >= 0))
#define nilfs_cnt32_lt(a, b)  nilfs_cnt32_gt(b, a)
#define nilfs_cnt32_le(a, b)  nilfs_cnt32_ge(b, a)

static int nilfs_prepare_segment_lock(struct nilfs_transaction_info *ti)
{
	struct nilfs_transaction_info *cur_ti = current->journal_info;
	void *save = NULL;

	if (cur_ti) {
		if (cur_ti->ti_magic == NILFS_TI_MAGIC)
			return ++cur_ti->ti_count;
		else {
			/*
			 * If journal_info field is occupied by other FS,
			 * it is saved and will be restored on
			 * nilfs_transaction_commit().
			 */
			printk(KERN_WARNING
			       "NILFS warning: journal info from a different "
			       "FS\n");
			save = current->journal_info;
		}
	}
	if (!ti) {
		ti = kmem_cache_alloc(nilfs_transaction_cachep, GFP_NOFS);
		if (!ti)
			return -ENOMEM;
		ti->ti_flags = NILFS_TI_DYNAMIC_ALLOC;
	} else {
		ti->ti_flags = 0;
	}
	ti->ti_count = 0;
	ti->ti_save = save;
	ti->ti_magic = NILFS_TI_MAGIC;
	current->journal_info = ti;
	return 0;
}

/**
 * nilfs_transaction_begin - start indivisible file operations.
 * @sb: super block
 * @ti: nilfs_transaction_info
 * @vacancy_check: flags for vacancy rate checks
 *
 * nilfs_transaction_begin() acquires a reader/writer semaphore, called
 * the segment semaphore, to make a segment construction and write tasks
 * exclusive.  The function is used with nilfs_transaction_commit() in pairs.
 * The region enclosed by these two functions can be nested.  To avoid a
 * deadlock, the semaphore is only acquired or released in the outermost call.
 *
 * This function allocates a nilfs_transaction_info struct to keep context
 * information on it.  It is initialized and hooked onto the current task in
 * the outermost call.  If a pre-allocated struct is given to @ti, it is used
 * instead; otherwise a new struct is assigned from a slab.
 *
 * When @vacancy_check flag is set, this function will check the amount of
 * free space, and will wait for the GC to reclaim disk space if low capacity.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error code is returned.
 *
 * %-ENOMEM - Insufficient memory available.
 *
 * %-ENOSPC - No space left on device
 */
int nilfs_transaction_begin(struct super_block *sb,
			    struct nilfs_transaction_info *ti,
			    int vacancy_check)
{
	struct the_nilfs *nilfs;
	int ret = nilfs_prepare_segment_lock(ti);

	if (unlikely(ret < 0))
		return ret;
	if (ret > 0)
		return 0;

	sb_start_intwrite(sb);

	nilfs = sb->s_fs_info;
	down_read(&nilfs->ns_segctor_sem);
	if (vacancy_check && nilfs_near_disk_full(nilfs)) {
		up_read(&nilfs->ns_segctor_sem);
		ret = -ENOSPC;
		goto failed;
	}
	return 0;

 failed:
	ti = current->journal_info;
	current->journal_info = ti->ti_save;
	if (ti->ti_flags & NILFS_TI_DYNAMIC_ALLOC)
		kmem_cache_free(nilfs_transaction_cachep, ti);
	sb_end_intwrite(sb);
	return ret;
}

/**
 * nilfs_transaction_commit - commit indivisible file operations.
 * @sb: super block
 *
 * nilfs_transaction_commit() releases the read semaphore which is
 * acquired by nilfs_transaction_begin(). This is only performed
 * in outermost call of this function.  If a commit flag is set,
 * nilfs_transaction_commit() sets a timer to start the segment
 * constructor.  If a sync flag is set, it starts construction
 * directly.
 */
int nilfs_transaction_commit(struct super_block *sb)
{
	struct nilfs_transaction_info *ti = current->journal_info;
	struct the_nilfs *nilfs = sb->s_fs_info;
	int err = 0;

	BUG_ON(ti == NULL || ti->ti_magic != NILFS_TI_MAGIC);
	ti->ti_flags |= NILFS_TI_COMMIT;
	if (ti->ti_count > 0) {
		ti->ti_count--;
		return 0;
	}
	if (nilfs->ns_writer) {
		struct nilfs_sc_info *sci = nilfs->ns_writer;

		if (ti->ti_flags & NILFS_TI_COMMIT)
			nilfs_segctor_start_timer(sci);
		if (atomic_read(&nilfs->ns_ndirtyblks) > sci->sc_watermark)
			nilfs_segctor_do_flush(sci, 0);
	}
	up_read(&nilfs->ns_segctor_sem);
	current->journal_info = ti->ti_save;

	if (ti->ti_flags & NILFS_TI_SYNC)
		err = nilfs_construct_segment(sb);
	if (ti->ti_flags & NILFS_TI_DYNAMIC_ALLOC)
		kmem_cache_free(nilfs_transaction_cachep, ti);
	sb_end_intwrite(sb);
	return err;
}

void nilfs_transaction_abort(struct super_block *sb)
{
	struct nilfs_transaction_info *ti = current->journal_info;
	struct the_nilfs *nilfs = sb->s_fs_info;

	BUG_ON(ti == NULL || ti->ti_magic != NILFS_TI_MAGIC);
	if (ti->ti_count > 0) {
		ti->ti_count--;
		return;
	}
	up_read(&nilfs->ns_segctor_sem);

	current->journal_info = ti->ti_save;
	if (ti->ti_flags & NILFS_TI_DYNAMIC_ALLOC)
		kmem_cache_free(nilfs_transaction_cachep, ti);
	sb_end_intwrite(sb);
}

void nilfs_relax_pressure_in_lock(struct super_block *sb)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_sc_info *sci = nilfs->ns_writer;

	if (!sci || !sci->sc_flush_request)
		return;

	set_bit(NILFS_SC_PRIOR_FLUSH, &sci->sc_flags);
	up_read(&nilfs->ns_segctor_sem);

	down_write(&nilfs->ns_segctor_sem);
	if (sci->sc_flush_request &&
	    test_bit(NILFS_SC_PRIOR_FLUSH, &sci->sc_flags)) {
		struct nilfs_transaction_info *ti = current->journal_info;

		ti->ti_flags |= NILFS_TI_WRITER;
		nilfs_segctor_do_immediate_flush(sci);
		ti->ti_flags &= ~NILFS_TI_WRITER;
	}
	downgrade_write(&nilfs->ns_segctor_sem);
}

static void nilfs_transaction_lock(struct super_block *sb,
				   struct nilfs_transaction_info *ti,
				   int gcflag)
{
	struct nilfs_transaction_info *cur_ti = current->journal_info;
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_sc_info *sci = nilfs->ns_writer;

	WARN_ON(cur_ti);
	ti->ti_flags = NILFS_TI_WRITER;
	ti->ti_count = 0;
	ti->ti_save = cur_ti;
	ti->ti_magic = NILFS_TI_MAGIC;
	INIT_LIST_HEAD(&ti->ti_garbage);
	current->journal_info = ti;

	for (;;) {
		down_write(&nilfs->ns_segctor_sem);
		if (!test_bit(NILFS_SC_PRIOR_FLUSH, &sci->sc_flags))
			break;

		nilfs_segctor_do_immediate_flush(sci);

		up_write(&nilfs->ns_segctor_sem);
		yield();
	}
	if (gcflag)
		ti->ti_flags |= NILFS_TI_GC;
}

static void nilfs_transaction_unlock(struct super_block *sb)
{
	struct nilfs_transaction_info *ti = current->journal_info;
	struct the_nilfs *nilfs = sb->s_fs_info;

	BUG_ON(ti == NULL || ti->ti_magic != NILFS_TI_MAGIC);
	BUG_ON(ti->ti_count > 0);

	up_write(&nilfs->ns_segctor_sem);
	current->journal_info = ti->ti_save;
	if (!list_empty(&ti->ti_garbage))
		nilfs_dispose_list(nilfs, &ti->ti_garbage, 0);
}

static void *nilfs_segctor_map_segsum_entry(struct nilfs_sc_info *sci,
					    struct nilfs_segsum_pointer *ssp,
					    unsigned bytes)
{
	struct nilfs_segment_buffer *segbuf = sci->sc_curseg;
	unsigned blocksize = sci->sc_super->s_blocksize;
	void *p;

	if (unlikely(ssp->offset + bytes > blocksize)) {
		ssp->offset = 0;
		BUG_ON(NILFS_SEGBUF_BH_IS_LAST(ssp->bh,
					       &segbuf->sb_segsum_buffers));
		ssp->bh = NILFS_SEGBUF_NEXT_BH(ssp->bh);
	}
	p = ssp->bh->b_data + ssp->offset;
	ssp->offset += bytes;
	return p;
}

/**
 * nilfs_segctor_reset_segment_buffer - reset the current segment buffer
 * @sci: nilfs_sc_info
 */
static int nilfs_segctor_reset_segment_buffer(struct nilfs_sc_info *sci)
{
	struct nilfs_segment_buffer *segbuf = sci->sc_curseg;
	struct buffer_head *sumbh;
	unsigned sumbytes;
	unsigned flags = 0;
	int err;

	if (nilfs_doing_gc())
		flags = NILFS_SS_GC;
	err = nilfs_segbuf_reset(segbuf, flags, sci->sc_seg_ctime, sci->sc_cno);
	if (unlikely(err))
		return err;

	sumbh = NILFS_SEGBUF_FIRST_BH(&segbuf->sb_segsum_buffers);
	sumbytes = segbuf->sb_sum.sumbytes;
	sci->sc_finfo_ptr.bh = sumbh;  sci->sc_finfo_ptr.offset = sumbytes;
	sci->sc_binfo_ptr.bh = sumbh;  sci->sc_binfo_ptr.offset = sumbytes;
	sci->sc_blk_cnt = sci->sc_datablk_cnt = 0;
	return 0;
}

static int nilfs_segctor_feed_segment(struct nilfs_sc_info *sci)
{
	sci->sc_nblk_this_inc += sci->sc_curseg->sb_sum.nblocks;
	if (NILFS_SEGBUF_IS_LAST(sci->sc_curseg, &sci->sc_segbufs))
		return -E2BIG; /* The current segment is filled up
				  (internal code) */
	sci->sc_curseg = NILFS_NEXT_SEGBUF(sci->sc_curseg);
	return nilfs_segctor_reset_segment_buffer(sci);
}

static int nilfs_segctor_add_super_root(struct nilfs_sc_info *sci)
{
	struct nilfs_segment_buffer *segbuf = sci->sc_curseg;
	int err;

	if (segbuf->sb_sum.nblocks >= segbuf->sb_rest_blocks) {
		err = nilfs_segctor_feed_segment(sci);
		if (err)
			return err;
		segbuf = sci->sc_curseg;
	}
	err = nilfs_segbuf_extend_payload(segbuf, &segbuf->sb_super_root);
	if (likely(!err))
		segbuf->sb_sum.flags |= NILFS_SS_SR;
	return err;
}

/*
 * Functions for making segment summary and payloads
 */
static int nilfs_segctor_segsum_block_required(
	struct nilfs_sc_info *sci, const struct nilfs_segsum_pointer *ssp,
	unsigned binfo_size)
{
	unsigned blocksize = sci->sc_super->s_blocksize;
	/* Size of finfo and binfo is enough small against blocksize */

	return ssp->offset + binfo_size +
		(!sci->sc_blk_cnt ? sizeof(struct nilfs_finfo) : 0) >
		blocksize;
}

static void nilfs_segctor_begin_finfo(struct nilfs_sc_info *sci,
				      struct inode *inode)
{
	sci->sc_curseg->sb_sum.nfinfo++;
	sci->sc_binfo_ptr = sci->sc_finfo_ptr;
	nilfs_segctor_map_segsum_entry(
		sci, &sci->sc_binfo_ptr, sizeof(struct nilfs_finfo));

	if (NILFS_I(inode)->i_root &&
	    !test_bit(NILFS_SC_HAVE_DELTA, &sci->sc_flags))
		set_bit(NILFS_SC_HAVE_DELTA, &sci->sc_flags);
	/* skip finfo */
}

static void nilfs_segctor_end_finfo(struct nilfs_sc_info *sci,
				    struct inode *inode)
{
	struct nilfs_finfo *finfo;
	struct nilfs_inode_info *ii;
	struct nilfs_segment_buffer *segbuf;
	__u64 cno;

	if (sci->sc_blk_cnt == 0)
		return;

	ii = NILFS_I(inode);

	if (test_bit(NILFS_I_GCINODE, &ii->i_state))
		cno = ii->i_cno;
	else if (NILFS_ROOT_METADATA_FILE(inode->i_ino))
		cno = 0;
	else
		cno = sci->sc_cno;

	finfo = nilfs_segctor_map_segsum_entry(sci, &sci->sc_finfo_ptr,
						 sizeof(*finfo));
	finfo->fi_ino = cpu_to_le64(inode->i_ino);
	finfo->fi_nblocks = cpu_to_le32(sci->sc_blk_cnt);
	finfo->fi_ndatablk = cpu_to_le32(sci->sc_datablk_cnt);
	finfo->fi_cno = cpu_to_le64(cno);

	segbuf = sci->sc_curseg;
	segbuf->sb_sum.sumbytes = sci->sc_binfo_ptr.offset +
		sci->sc_super->s_blocksize * (segbuf->sb_sum.nsumblk - 1);
	sci->sc_finfo_ptr = sci->sc_binfo_ptr;
	sci->sc_blk_cnt = sci->sc_datablk_cnt = 0;
}

static int nilfs_segctor_add_file_block(struct nilfs_sc_info *sci,
					struct buffer_head *bh,
					struct inode *inode,
					unsigned binfo_size)
{
	struct nilfs_segment_buffer *segbuf;
	int required, err = 0;

 retry:
	segbuf = sci->sc_curseg;
	required = nilfs_segctor_segsum_block_required(
		sci, &sci->sc_binfo_ptr, binfo_size);
	if (segbuf->sb_sum.nblocks + required + 1 > segbuf->sb_rest_blocks) {
		nilfs_segctor_end_finfo(sci, inode);
		err = nilfs_segctor_feed_segment(sci);
		if (err)
			return err;
		goto retry;
	}
	if (unlikely(required)) {
		err = nilfs_segbuf_extend_segsum(segbuf);
		if (unlikely(err))
			goto failed;
	}
	if (sci->sc_blk_cnt == 0)
		nilfs_segctor_begin_finfo(sci, inode);

	nilfs_segctor_map_segsum_entry(sci, &sci->sc_binfo_ptr, binfo_size);
	/* Substitution to vblocknr is delayed until update_blocknr() */
	nilfs_segbuf_add_file_buffer(segbuf, bh);
	sci->sc_blk_cnt++;
 failed:
	return err;
}

/*
 * Callback functions that enumerate, mark, and collect dirty blocks
 */
static int nilfs_collect_file_data(struct nilfs_sc_info *sci,
				   struct buffer_head *bh, struct inode *inode)
{
	int err;

	err = nilfs_bmap_propagate(NILFS_I(inode)->i_bmap, bh);
	if (err < 0)
		return err;

	err = nilfs_segctor_add_file_block(sci, bh, inode,
					   sizeof(struct nilfs_binfo_v));
	if (!err)
		sci->sc_datablk_cnt++;
	return err;
}

static int nilfs_collect_file_node(struct nilfs_sc_info *sci,
				   struct buffer_head *bh,
				   struct inode *inode)
{
	return nilfs_bmap_propagate(NILFS_I(inode)->i_bmap, bh);
}

static int nilfs_collect_file_bmap(struct nilfs_sc_info *sci,
				   struct buffer_head *bh,
				   struct inode *inode)
{
	WARN_ON(!buffer_dirty(bh));
	return nilfs_segctor_add_file_block(sci, bh, inode, sizeof(__le64));
}

static void nilfs_write_file_data_binfo(struct nilfs_sc_info *sci,
					struct nilfs_segsum_pointer *ssp,
					union nilfs_binfo *binfo)
{
	struct nilfs_binfo_v *binfo_v = nilfs_segctor_map_segsum_entry(
		sci, ssp, sizeof(*binfo_v));
	*binfo_v = binfo->bi_v;
}

static void nilfs_write_file_node_binfo(struct nilfs_sc_info *sci,
					struct nilfs_segsum_pointer *ssp,
					union nilfs_binfo *binfo)
{
	__le64 *vblocknr = nilfs_segctor_map_segsum_entry(
		sci, ssp, sizeof(*vblocknr));
	*vblocknr = binfo->bi_v.bi_vblocknr;
}

static struct nilfs_sc_operations nilfs_sc_file_ops = {
	.collect_data = nilfs_collect_file_data,
	.collect_node = nilfs_collect_file_node,
	.collect_bmap = nilfs_collect_file_bmap,
	.write_data_binfo = nilfs_write_file_data_binfo,
	.write_node_binfo = nilfs_write_file_node_binfo,
};

static int nilfs_collect_dat_data(struct nilfs_sc_info *sci,
				  struct buffer_head *bh, struct inode *inode)
{
	int err;

	err = nilfs_bmap_propagate(NILFS_I(inode)->i_bmap, bh);
	if (err < 0)
		return err;

	err = nilfs_segctor_add_file_block(sci, bh, inode, sizeof(__le64));
	if (!err)
		sci->sc_datablk_cnt++;
	return err;
}

static int nilfs_collect_dat_bmap(struct nilfs_sc_info *sci,
				  struct buffer_head *bh, struct inode *inode)
{
	WARN_ON(!buffer_dirty(bh));
	return nilfs_segctor_add_file_block(sci, bh, inode,
					    sizeof(struct nilfs_binfo_dat));
}

static void nilfs_write_dat_data_binfo(struct nilfs_sc_info *sci,
				       struct nilfs_segsum_pointer *ssp,
				       union nilfs_binfo *binfo)
{
	__le64 *blkoff = nilfs_segctor_map_segsum_entry(sci, ssp,
							  sizeof(*blkoff));
	*blkoff = binfo->bi_dat.bi_blkoff;
}

static void nilfs_write_dat_node_binfo(struct nilfs_sc_info *sci,
				       struct nilfs_segsum_pointer *ssp,
				       union nilfs_binfo *binfo)
{
	struct nilfs_binfo_dat *binfo_dat =
		nilfs_segctor_map_segsum_entry(sci, ssp, sizeof(*binfo_dat));
	*binfo_dat = binfo->bi_dat;
}

static struct nilfs_sc_operations nilfs_sc_dat_ops = {
	.collect_data = nilfs_collect_dat_data,
	.collect_node = nilfs_collect_file_node,
	.collect_bmap = nilfs_collect_dat_bmap,
	.write_data_binfo = nilfs_write_dat_data_binfo,
	.write_node_binfo = nilfs_write_dat_node_binfo,
};

static struct nilfs_sc_operations nilfs_sc_dsync_ops = {
	.collect_data = nilfs_collect_file_data,
	.collect_node = NULL,
	.collect_bmap = NULL,
	.write_data_binfo = nilfs_write_file_data_binfo,
	.write_node_binfo = NULL,
};

static size_t nilfs_lookup_dirty_data_buffers(struct inode *inode,
					      struct list_head *listp,
					      size_t nlimit,
					      loff_t start, loff_t end)
{
	struct address_space *mapping = inode->i_mapping;
	struct pagevec pvec;
	pgoff_t index = 0, last = ULONG_MAX;
	size_t ndirties = 0;
	int i;

	if (unlikely(start != 0 || end != LLONG_MAX)) {
		/*
		 * A valid range is given for sync-ing data pages. The
		 * range is rounded to per-page; extra dirty buffers
		 * may be included if blocksize < pagesize.
		 */
		index = start >> PAGE_SHIFT;
		last = end >> PAGE_SHIFT;
	}
	pagevec_init(&pvec, 0);
 repeat:
	if (unlikely(index > last) ||
	    !pagevec_lookup_tag(&pvec, mapping, &index, PAGECACHE_TAG_DIRTY,
				min_t(pgoff_t, last - index,
				      PAGEVEC_SIZE - 1) + 1))
		return ndirties;

	for (i = 0; i < pagevec_count(&pvec); i++) {
		struct buffer_head *bh, *head;
		struct page *page = pvec.pages[i];

		if (unlikely(page->index > last))
			break;

		lock_page(page);
		if (!page_has_buffers(page))
			create_empty_buffers(page, 1 << inode->i_blkbits, 0);
		unlock_page(page);

		bh = head = page_buffers(page);
		do {
			if (!buffer_dirty(bh) || buffer_async_write(bh))
				continue;
			get_bh(bh);
			list_add_tail(&bh->b_assoc_buffers, listp);
			ndirties++;
			if (unlikely(ndirties >= nlimit)) {
				pagevec_release(&pvec);
				cond_resched();
				return ndirties;
			}
		} while (bh = bh->b_this_page, bh != head);
	}
	pagevec_release(&pvec);
	cond_resched();
	goto repeat;
}

static void nilfs_lookup_dirty_node_buffers(struct inode *inode,
					    struct list_head *listp)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);
	struct address_space *mapping = &ii->i_btnode_cache;
	struct pagevec pvec;
	struct buffer_head *bh, *head;
	unsigned int i;
	pgoff_t index = 0;

	pagevec_init(&pvec, 0);

	while (pagevec_lookup_tag(&pvec, mapping, &index, PAGECACHE_TAG_DIRTY,
				  PAGEVEC_SIZE)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			bh = head = page_buffers(pvec.pages[i]);
			do {
				if (buffer_dirty(bh) &&
						!buffer_async_write(bh)) {
					get_bh(bh);
					list_add_tail(&bh->b_assoc_buffers,
						      listp);
				}
				bh = bh->b_this_page;
			} while (bh != head);
		}
		pagevec_release(&pvec);
		cond_resched();
	}
}

static void nilfs_dispose_list(struct the_nilfs *nilfs,
			       struct list_head *head, int force)
{
	struct nilfs_inode_info *ii, *n;
	struct nilfs_inode_info *ivec[SC_N_INODEVEC], **pii;
	unsigned nv = 0;

	while (!list_empty(head)) {
		spin_lock(&nilfs->ns_inode_lock);
		list_for_each_entry_safe(ii, n, head, i_dirty) {
			list_del_init(&ii->i_dirty);
			if (force) {
				if (unlikely(ii->i_bh)) {
					brelse(ii->i_bh);
					ii->i_bh = NULL;
				}
			} else if (test_bit(NILFS_I_DIRTY, &ii->i_state)) {
				set_bit(NILFS_I_QUEUED, &ii->i_state);
				list_add_tail(&ii->i_dirty,
					      &nilfs->ns_dirty_files);
				continue;
			}
			ivec[nv++] = ii;
			if (nv == SC_N_INODEVEC)
				break;
		}
		spin_unlock(&nilfs->ns_inode_lock);

		for (pii = ivec; nv > 0; pii++, nv--)
			iput(&(*pii)->vfs_inode);
	}
}

static int nilfs_test_metadata_dirty(struct the_nilfs *nilfs,
				     struct nilfs_root *root)
{
	int ret = 0;

	if (nilfs_mdt_fetch_dirty(root->ifile))
		ret++;
	if (nilfs_mdt_fetch_dirty(nilfs->ns_cpfile))
		ret++;
	if (nilfs_mdt_fetch_dirty(nilfs->ns_sufile))
		ret++;
	if ((ret || nilfs_doing_gc()) && nilfs_mdt_fetch_dirty(nilfs->ns_dat))
		ret++;
	return ret;
}

static int nilfs_segctor_clean(struct nilfs_sc_info *sci)
{
	return list_empty(&sci->sc_dirty_files) &&
		!test_bit(NILFS_SC_DIRTY, &sci->sc_flags) &&
		sci->sc_nfreesegs == 0 &&
		(!nilfs_doing_gc() || list_empty(&sci->sc_gc_inodes));
}

static int nilfs_segctor_confirm(struct nilfs_sc_info *sci)
{
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;
	int ret = 0;

	if (nilfs_test_metadata_dirty(nilfs, sci->sc_root))
		set_bit(NILFS_SC_DIRTY, &sci->sc_flags);

	spin_lock(&nilfs->ns_inode_lock);
	if (list_empty(&nilfs->ns_dirty_files) && nilfs_segctor_clean(sci))
		ret++;

	spin_unlock(&nilfs->ns_inode_lock);
	return ret;
}

static void nilfs_segctor_clear_metadata_dirty(struct nilfs_sc_info *sci)
{
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;

	nilfs_mdt_clear_dirty(sci->sc_root->ifile);
	nilfs_mdt_clear_dirty(nilfs->ns_cpfile);
	nilfs_mdt_clear_dirty(nilfs->ns_sufile);
	nilfs_mdt_clear_dirty(nilfs->ns_dat);
}

static int nilfs_segctor_create_checkpoint(struct nilfs_sc_info *sci)
{
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;
	struct buffer_head *bh_cp;
	struct nilfs_checkpoint *raw_cp;
	int err;

	/* XXX: this interface will be changed */
	err = nilfs_cpfile_get_checkpoint(nilfs->ns_cpfile, nilfs->ns_cno, 1,
					  &raw_cp, &bh_cp);
	if (likely(!err)) {
		/* The following code is duplicated with cpfile.  But, it is
		   needed to collect the checkpoint even if it was not newly
		   created */
		mark_buffer_dirty(bh_cp);
		nilfs_mdt_mark_dirty(nilfs->ns_cpfile);
		nilfs_cpfile_put_checkpoint(
			nilfs->ns_cpfile, nilfs->ns_cno, bh_cp);
	} else
		WARN_ON(err == -EINVAL || err == -ENOENT);

	return err;
}

static int nilfs_segctor_fill_in_checkpoint(struct nilfs_sc_info *sci)
{
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;
	struct buffer_head *bh_cp;
	struct nilfs_checkpoint *raw_cp;
	int err;

	err = nilfs_cpfile_get_checkpoint(nilfs->ns_cpfile, nilfs->ns_cno, 0,
					  &raw_cp, &bh_cp);
	if (unlikely(err)) {
		WARN_ON(err == -EINVAL || err == -ENOENT);
		goto failed_ibh;
	}
	raw_cp->cp_snapshot_list.ssl_next = 0;
	raw_cp->cp_snapshot_list.ssl_prev = 0;
	raw_cp->cp_inodes_count =
		cpu_to_le64(atomic64_read(&sci->sc_root->inodes_count));
	raw_cp->cp_blocks_count =
		cpu_to_le64(atomic64_read(&sci->sc_root->blocks_count));
	raw_cp->cp_nblk_inc =
		cpu_to_le64(sci->sc_nblk_inc + sci->sc_nblk_this_inc);
	raw_cp->cp_create = cpu_to_le64(sci->sc_seg_ctime);
	raw_cp->cp_cno = cpu_to_le64(nilfs->ns_cno);

	if (test_bit(NILFS_SC_HAVE_DELTA, &sci->sc_flags))
		nilfs_checkpoint_clear_minor(raw_cp);
	else
		nilfs_checkpoint_set_minor(raw_cp);

	nilfs_write_inode_common(sci->sc_root->ifile,
				 &raw_cp->cp_ifile_inode, 1);
	nilfs_cpfile_put_checkpoint(nilfs->ns_cpfile, nilfs->ns_cno, bh_cp);
	return 0;

 failed_ibh:
	return err;
}

static void nilfs_fill_in_file_bmap(struct inode *ifile,
				    struct nilfs_inode_info *ii)

{
	struct buffer_head *ibh;
	struct nilfs_inode *raw_inode;

	if (test_bit(NILFS_I_BMAP, &ii->i_state)) {
		ibh = ii->i_bh;
		BUG_ON(!ibh);
		raw_inode = nilfs_ifile_map_inode(ifile, ii->vfs_inode.i_ino,
						  ibh);
		nilfs_bmap_write(ii->i_bmap, raw_inode);
		nilfs_ifile_unmap_inode(ifile, ii->vfs_inode.i_ino, ibh);
	}
}

static void nilfs_segctor_fill_in_file_bmap(struct nilfs_sc_info *sci)
{
	struct nilfs_inode_info *ii;

	list_for_each_entry(ii, &sci->sc_dirty_files, i_dirty) {
		nilfs_fill_in_file_bmap(sci->sc_root->ifile, ii);
		set_bit(NILFS_I_COLLECTED, &ii->i_state);
	}
}

static void nilfs_segctor_fill_in_super_root(struct nilfs_sc_info *sci,
					     struct the_nilfs *nilfs)
{
	struct buffer_head *bh_sr;
	struct nilfs_super_root *raw_sr;
	unsigned isz, srsz;

	bh_sr = NILFS_LAST_SEGBUF(&sci->sc_segbufs)->sb_super_root;
	raw_sr = (struct nilfs_super_root *)bh_sr->b_data;
	isz = nilfs->ns_inode_size;
	srsz = NILFS_SR_BYTES(isz);

	raw_sr->sr_bytes = cpu_to_le16(srsz);
	raw_sr->sr_nongc_ctime
		= cpu_to_le64(nilfs_doing_gc() ?
			      nilfs->ns_nongc_ctime : sci->sc_seg_ctime);
	raw_sr->sr_flags = 0;

	nilfs_write_inode_common(nilfs->ns_dat, (void *)raw_sr +
				 NILFS_SR_DAT_OFFSET(isz), 1);
	nilfs_write_inode_common(nilfs->ns_cpfile, (void *)raw_sr +
				 NILFS_SR_CPFILE_OFFSET(isz), 1);
	nilfs_write_inode_common(nilfs->ns_sufile, (void *)raw_sr +
				 NILFS_SR_SUFILE_OFFSET(isz), 1);
	memset((void *)raw_sr + srsz, 0, nilfs->ns_blocksize - srsz);
}

static void nilfs_redirty_inodes(struct list_head *head)
{
	struct nilfs_inode_info *ii;

	list_for_each_entry(ii, head, i_dirty) {
		if (test_bit(NILFS_I_COLLECTED, &ii->i_state))
			clear_bit(NILFS_I_COLLECTED, &ii->i_state);
	}
}

static void nilfs_drop_collected_inodes(struct list_head *head)
{
	struct nilfs_inode_info *ii;

	list_for_each_entry(ii, head, i_dirty) {
		if (!test_and_clear_bit(NILFS_I_COLLECTED, &ii->i_state))
			continue;

		clear_bit(NILFS_I_INODE_DIRTY, &ii->i_state);
		set_bit(NILFS_I_UPDATED, &ii->i_state);
	}
}

static int nilfs_segctor_apply_buffers(struct nilfs_sc_info *sci,
				       struct inode *inode,
				       struct list_head *listp,
				       int (*collect)(struct nilfs_sc_info *,
						      struct buffer_head *,
						      struct inode *))
{
	struct buffer_head *bh, *n;
	int err = 0;

	if (collect) {
		list_for_each_entry_safe(bh, n, listp, b_assoc_buffers) {
			list_del_init(&bh->b_assoc_buffers);
			err = collect(sci, bh, inode);
			brelse(bh);
			if (unlikely(err))
				goto dispose_buffers;
		}
		return 0;
	}

 dispose_buffers:
	while (!list_empty(listp)) {
		bh = list_first_entry(listp, struct buffer_head,
				      b_assoc_buffers);
		list_del_init(&bh->b_assoc_buffers);
		brelse(bh);
	}
	return err;
}

static size_t nilfs_segctor_buffer_rest(struct nilfs_sc_info *sci)
{
	/* Remaining number of blocks within segment buffer */
	return sci->sc_segbuf_nblocks -
		(sci->sc_nblk_this_inc + sci->sc_curseg->sb_sum.nblocks);
}

static int nilfs_segctor_scan_file(struct nilfs_sc_info *sci,
				   struct inode *inode,
				   struct nilfs_sc_operations *sc_ops)
{
	LIST_HEAD(data_buffers);
	LIST_HEAD(node_buffers);
	int err;

	if (!(sci->sc_stage.flags & NILFS_CF_NODE)) {
		size_t n, rest = nilfs_segctor_buffer_rest(sci);

		n = nilfs_lookup_dirty_data_buffers(
			inode, &data_buffers, rest + 1, 0, LLONG_MAX);
		if (n > rest) {
			err = nilfs_segctor_apply_buffers(
				sci, inode, &data_buffers,
				sc_ops->collect_data);
			BUG_ON(!err); /* always receive -E2BIG or true error */
			goto break_or_fail;
		}
	}
	nilfs_lookup_dirty_node_buffers(inode, &node_buffers);

	if (!(sci->sc_stage.flags & NILFS_CF_NODE)) {
		err = nilfs_segctor_apply_buffers(
			sci, inode, &data_buffers, sc_ops->collect_data);
		if (unlikely(err)) {
			/* dispose node list */
			nilfs_segctor_apply_buffers(
				sci, inode, &node_buffers, NULL);
			goto break_or_fail;
		}
		sci->sc_stage.flags |= NILFS_CF_NODE;
	}
	/* Collect node */
	err = nilfs_segctor_apply_buffers(
		sci, inode, &node_buffers, sc_ops->collect_node);
	if (unlikely(err))
		goto break_or_fail;

	nilfs_bmap_lookup_dirty_buffers(NILFS_I(inode)->i_bmap, &node_buffers);
	err = nilfs_segctor_apply_buffers(
		sci, inode, &node_buffers, sc_ops->collect_bmap);
	if (unlikely(err))
		goto break_or_fail;

	nilfs_segctor_end_finfo(sci, inode);
	sci->sc_stage.flags &= ~NILFS_CF_NODE;

 break_or_fail:
	return err;
}

static int nilfs_segctor_scan_file_dsync(struct nilfs_sc_info *sci,
					 struct inode *inode)
{
	LIST_HEAD(data_buffers);
	size_t n, rest = nilfs_segctor_buffer_rest(sci);
	int err;

	n = nilfs_lookup_dirty_data_buffers(inode, &data_buffers, rest + 1,
					    sci->sc_dsync_start,
					    sci->sc_dsync_end);

	err = nilfs_segctor_apply_buffers(sci, inode, &data_buffers,
					  nilfs_collect_file_data);
	if (!err) {
		nilfs_segctor_end_finfo(sci, inode);
		BUG_ON(n > rest);
		/* always receive -E2BIG or true error if n > rest */
	}
	return err;
}

static int nilfs_segctor_collect_blocks(struct nilfs_sc_info *sci, int mode)
{
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;
	struct list_head *head;
	struct nilfs_inode_info *ii;
	size_t ndone;
	int err = 0;

	switch (sci->sc_stage.scnt) {
	case NILFS_ST_INIT:
		/* Pre-processes */
		sci->sc_stage.flags = 0;

		if (!test_bit(NILFS_SC_UNCLOSED, &sci->sc_flags)) {
			sci->sc_nblk_inc = 0;
			sci->sc_curseg->sb_sum.flags = NILFS_SS_LOGBGN;
			if (mode == SC_LSEG_DSYNC) {
				sci->sc_stage.scnt = NILFS_ST_DSYNC;
				goto dsync_mode;
			}
		}

		sci->sc_stage.dirty_file_ptr = NULL;
		sci->sc_stage.gc_inode_ptr = NULL;
		if (mode == SC_FLUSH_DAT) {
			sci->sc_stage.scnt = NILFS_ST_DAT;
			goto dat_stage;
		}
		sci->sc_stage.scnt++;  /* Fall through */
	case NILFS_ST_GC:
		if (nilfs_doing_gc()) {
			head = &sci->sc_gc_inodes;
			ii = list_prepare_entry(sci->sc_stage.gc_inode_ptr,
						head, i_dirty);
			list_for_each_entry_continue(ii, head, i_dirty) {
				err = nilfs_segctor_scan_file(
					sci, &ii->vfs_inode,
					&nilfs_sc_file_ops);
				if (unlikely(err)) {
					sci->sc_stage.gc_inode_ptr = list_entry(
						ii->i_dirty.prev,
						struct nilfs_inode_info,
						i_dirty);
					goto break_or_fail;
				}
				set_bit(NILFS_I_COLLECTED, &ii->i_state);
			}
			sci->sc_stage.gc_inode_ptr = NULL;
		}
		sci->sc_stage.scnt++;  /* Fall through */
	case NILFS_ST_FILE:
		head = &sci->sc_dirty_files;
		ii = list_prepare_entry(sci->sc_stage.dirty_file_ptr, head,
					i_dirty);
		list_for_each_entry_continue(ii, head, i_dirty) {
			clear_bit(NILFS_I_DIRTY, &ii->i_state);

			err = nilfs_segctor_scan_file(sci, &ii->vfs_inode,
						      &nilfs_sc_file_ops);
			if (unlikely(err)) {
				sci->sc_stage.dirty_file_ptr =
					list_entry(ii->i_dirty.prev,
						   struct nilfs_inode_info,
						   i_dirty);
				goto break_or_fail;
			}
			/* sci->sc_stage.dirty_file_ptr = NILFS_I(inode); */
			/* XXX: required ? */
		}
		sci->sc_stage.dirty_file_ptr = NULL;
		if (mode == SC_FLUSH_FILE) {
			sci->sc_stage.scnt = NILFS_ST_DONE;
			return 0;
		}
		sci->sc_stage.scnt++;
		sci->sc_stage.flags |= NILFS_CF_IFILE_STARTED;
		/* Fall through */
	case NILFS_ST_IFILE:
		err = nilfs_segctor_scan_file(sci, sci->sc_root->ifile,
					      &nilfs_sc_file_ops);
		if (unlikely(err))
			break;
		sci->sc_stage.scnt++;
		/* Creating a checkpoint */
		err = nilfs_segctor_create_checkpoint(sci);
		if (unlikely(err))
			break;
		/* Fall through */
	case NILFS_ST_CPFILE:
		err = nilfs_segctor_scan_file(sci, nilfs->ns_cpfile,
					      &nilfs_sc_file_ops);
		if (unlikely(err))
			break;
		sci->sc_stage.scnt++;  /* Fall through */
	case NILFS_ST_SUFILE:
		err = nilfs_sufile_freev(nilfs->ns_sufile, sci->sc_freesegs,
					 sci->sc_nfreesegs, &ndone);
		if (unlikely(err)) {
			nilfs_sufile_cancel_freev(nilfs->ns_sufile,
						  sci->sc_freesegs, ndone,
						  NULL);
			break;
		}
		sci->sc_stage.flags |= NILFS_CF_SUFREED;

		err = nilfs_segctor_scan_file(sci, nilfs->ns_sufile,
					      &nilfs_sc_file_ops);
		if (unlikely(err))
			break;
		sci->sc_stage.scnt++;  /* Fall through */
	case NILFS_ST_DAT:
 dat_stage:
		err = nilfs_segctor_scan_file(sci, nilfs->ns_dat,
					      &nilfs_sc_dat_ops);
		if (unlikely(err))
			break;
		if (mode == SC_FLUSH_DAT) {
			sci->sc_stage.scnt = NILFS_ST_DONE;
			return 0;
		}
		sci->sc_stage.scnt++;  /* Fall through */
	case NILFS_ST_SR:
		if (mode == SC_LSEG_SR) {
			/* Appending a super root */
			err = nilfs_segctor_add_super_root(sci);
			if (unlikely(err))
				break;
		}
		/* End of a logical segment */
		sci->sc_curseg->sb_sum.flags |= NILFS_SS_LOGEND;
		sci->sc_stage.scnt = NILFS_ST_DONE;
		return 0;
	case NILFS_ST_DSYNC:
 dsync_mode:
		sci->sc_curseg->sb_sum.flags |= NILFS_SS_SYNDT;
		ii = sci->sc_dsync_inode;
		if (!test_bit(NILFS_I_BUSY, &ii->i_state))
			break;

		err = nilfs_segctor_scan_file_dsync(sci, &ii->vfs_inode);
		if (unlikely(err))
			break;
		sci->sc_curseg->sb_sum.flags |= NILFS_SS_LOGEND;
		sci->sc_stage.scnt = NILFS_ST_DONE;
		return 0;
	case NILFS_ST_DONE:
		return 0;
	default:
		BUG();
	}

 break_or_fail:
	return err;
}

/**
 * nilfs_segctor_begin_construction - setup segment buffer to make a new log
 * @sci: nilfs_sc_info
 * @nilfs: nilfs object
 */
static int nilfs_segctor_begin_construction(struct nilfs_sc_info *sci,
					    struct the_nilfs *nilfs)
{
	struct nilfs_segment_buffer *segbuf, *prev;
	__u64 nextnum;
	int err, alloc = 0;

	segbuf = nilfs_segbuf_new(sci->sc_super);
	if (unlikely(!segbuf))
		return -ENOMEM;

	if (list_empty(&sci->sc_write_logs)) {
		nilfs_segbuf_map(segbuf, nilfs->ns_segnum,
				 nilfs->ns_pseg_offset, nilfs);
		if (segbuf->sb_rest_blocks < NILFS_PSEG_MIN_BLOCKS) {
			nilfs_shift_to_next_segment(nilfs);
			nilfs_segbuf_map(segbuf, nilfs->ns_segnum, 0, nilfs);
		}

		segbuf->sb_sum.seg_seq = nilfs->ns_seg_seq;
		nextnum = nilfs->ns_nextnum;

		if (nilfs->ns_segnum == nilfs->ns_nextnum)
			/* Start from the head of a new full segment */
			alloc++;
	} else {
		/* Continue logs */
		prev = NILFS_LAST_SEGBUF(&sci->sc_write_logs);
		nilfs_segbuf_map_cont(segbuf, prev);
		segbuf->sb_sum.seg_seq = prev->sb_sum.seg_seq;
		nextnum = prev->sb_nextnum;

		if (segbuf->sb_rest_blocks < NILFS_PSEG_MIN_BLOCKS) {
			nilfs_segbuf_map(segbuf, prev->sb_nextnum, 0, nilfs);
			segbuf->sb_sum.seg_seq++;
			alloc++;
		}
	}

	err = nilfs_sufile_mark_dirty(nilfs->ns_sufile, segbuf->sb_segnum);
	if (err)
		goto failed;

	if (alloc) {
		err = nilfs_sufile_alloc(nilfs->ns_sufile, &nextnum);
		if (err)
			goto failed;
	}
	nilfs_segbuf_set_next_segnum(segbuf, nextnum, nilfs);

	BUG_ON(!list_empty(&sci->sc_segbufs));
	list_add_tail(&segbuf->sb_list, &sci->sc_segbufs);
	sci->sc_segbuf_nblocks = segbuf->sb_rest_blocks;
	return 0;

 failed:
	nilfs_segbuf_free(segbuf);
	return err;
}

static int nilfs_segctor_extend_segments(struct nilfs_sc_info *sci,
					 struct the_nilfs *nilfs, int nadd)
{
	struct nilfs_segment_buffer *segbuf, *prev;
	struct inode *sufile = nilfs->ns_sufile;
	__u64 nextnextnum;
	LIST_HEAD(list);
	int err, ret, i;

	prev = NILFS_LAST_SEGBUF(&sci->sc_segbufs);
	/*
	 * Since the segment specified with nextnum might be allocated during
	 * the previous construction, the buffer including its segusage may
	 * not be dirty.  The following call ensures that the buffer is dirty
	 * and will pin the buffer on memory until the sufile is written.
	 */
	err = nilfs_sufile_mark_dirty(sufile, prev->sb_nextnum);
	if (unlikely(err))
		return err;

	for (i = 0; i < nadd; i++) {
		/* extend segment info */
		err = -ENOMEM;
		segbuf = nilfs_segbuf_new(sci->sc_super);
		if (unlikely(!segbuf))
			goto failed;

		/* map this buffer to region of segment on-disk */
		nilfs_segbuf_map(segbuf, prev->sb_nextnum, 0, nilfs);
		sci->sc_segbuf_nblocks += segbuf->sb_rest_blocks;

		/* allocate the next next full segment */
		err = nilfs_sufile_alloc(sufile, &nextnextnum);
		if (unlikely(err))
			goto failed_segbuf;

		segbuf->sb_sum.seg_seq = prev->sb_sum.seg_seq + 1;
		nilfs_segbuf_set_next_segnum(segbuf, nextnextnum, nilfs);

		list_add_tail(&segbuf->sb_list, &list);
		prev = segbuf;
	}
	list_splice_tail(&list, &sci->sc_segbufs);
	return 0;

 failed_segbuf:
	nilfs_segbuf_free(segbuf);
 failed:
	list_for_each_entry(segbuf, &list, sb_list) {
		ret = nilfs_sufile_free(sufile, segbuf->sb_nextnum);
		WARN_ON(ret); /* never fails */
	}
	nilfs_destroy_logs(&list);
	return err;
}

static void nilfs_free_incomplete_logs(struct list_head *logs,
				       struct the_nilfs *nilfs)
{
	struct nilfs_segment_buffer *segbuf, *prev;
	struct inode *sufile = nilfs->ns_sufile;
	int ret;

	segbuf = NILFS_FIRST_SEGBUF(logs);
	if (nilfs->ns_nextnum != segbuf->sb_nextnum) {
		ret = nilfs_sufile_free(sufile, segbuf->sb_nextnum);
		WARN_ON(ret); /* never fails */
	}
	if (atomic_read(&segbuf->sb_err)) {
		/* Case 1: The first segment failed */
		if (segbuf->sb_pseg_start != segbuf->sb_fseg_start)
			/* Case 1a:  Partial segment appended into an existing
			   segment */
			nilfs_terminate_segment(nilfs, segbuf->sb_fseg_start,
						segbuf->sb_fseg_end);
		else /* Case 1b:  New full segment */
			set_nilfs_discontinued(nilfs);
	}

	prev = segbuf;
	list_for_each_entry_continue(segbuf, logs, sb_list) {
		if (prev->sb_nextnum != segbuf->sb_nextnum) {
			ret = nilfs_sufile_free(sufile, segbuf->sb_nextnum);
			WARN_ON(ret); /* never fails */
		}
		if (atomic_read(&segbuf->sb_err) &&
		    segbuf->sb_segnum != nilfs->ns_nextnum)
			/* Case 2: extended segment (!= next) failed */
			nilfs_sufile_set_error(sufile, segbuf->sb_segnum);
		prev = segbuf;
	}
}

static void nilfs_segctor_update_segusage(struct nilfs_sc_info *sci,
					  struct inode *sufile)
{
	struct nilfs_segment_buffer *segbuf;
	unsigned long live_blocks;
	int ret;

	list_for_each_entry(segbuf, &sci->sc_segbufs, sb_list) {
		live_blocks = segbuf->sb_sum.nblocks +
			(segbuf->sb_pseg_start - segbuf->sb_fseg_start);
		ret = nilfs_sufile_set_segment_usage(sufile, segbuf->sb_segnum,
						     live_blocks,
						     sci->sc_seg_ctime);
		WARN_ON(ret); /* always succeed because the segusage is dirty */
	}
}

static void nilfs_cancel_segusage(struct list_head *logs, struct inode *sufile)
{
	struct nilfs_segment_buffer *segbuf;
	int ret;

	segbuf = NILFS_FIRST_SEGBUF(logs);
	ret = nilfs_sufile_set_segment_usage(sufile, segbuf->sb_segnum,
					     segbuf->sb_pseg_start -
					     segbuf->sb_fseg_start, 0);
	WARN_ON(ret); /* always succeed because the segusage is dirty */

	list_for_each_entry_continue(segbuf, logs, sb_list) {
		ret = nilfs_sufile_set_segment_usage(sufile, segbuf->sb_segnum,
						     0, 0);
		WARN_ON(ret); /* always succeed */
	}
}

static void nilfs_segctor_truncate_segments(struct nilfs_sc_info *sci,
					    struct nilfs_segment_buffer *last,
					    struct inode *sufile)
{
	struct nilfs_segment_buffer *segbuf = last;
	int ret;

	list_for_each_entry_continue(segbuf, &sci->sc_segbufs, sb_list) {
		sci->sc_segbuf_nblocks -= segbuf->sb_rest_blocks;
		ret = nilfs_sufile_free(sufile, segbuf->sb_nextnum);
		WARN_ON(ret);
	}
	nilfs_truncate_logs(&sci->sc_segbufs, last);
}


static int nilfs_segctor_collect(struct nilfs_sc_info *sci,
				 struct the_nilfs *nilfs, int mode)
{
	struct nilfs_cstage prev_stage = sci->sc_stage;
	int err, nadd = 1;

	/* Collection retry loop */
	for (;;) {
		sci->sc_nblk_this_inc = 0;
		sci->sc_curseg = NILFS_FIRST_SEGBUF(&sci->sc_segbufs);

		err = nilfs_segctor_reset_segment_buffer(sci);
		if (unlikely(err))
			goto failed;

		err = nilfs_segctor_collect_blocks(sci, mode);
		sci->sc_nblk_this_inc += sci->sc_curseg->sb_sum.nblocks;
		if (!err)
			break;

		if (unlikely(err != -E2BIG))
			goto failed;

		/* The current segment is filled up */
		if (mode != SC_LSEG_SR || sci->sc_stage.scnt < NILFS_ST_CPFILE)
			break;

		nilfs_clear_logs(&sci->sc_segbufs);

		if (sci->sc_stage.flags & NILFS_CF_SUFREED) {
			err = nilfs_sufile_cancel_freev(nilfs->ns_sufile,
							sci->sc_freesegs,
							sci->sc_nfreesegs,
							NULL);
			WARN_ON(err); /* do not happen */
			sci->sc_stage.flags &= ~NILFS_CF_SUFREED;
		}

		err = nilfs_segctor_extend_segments(sci, nilfs, nadd);
		if (unlikely(err))
			return err;

		nadd = min_t(int, nadd << 1, SC_MAX_SEGDELTA);
		sci->sc_stage = prev_stage;
	}
	nilfs_segctor_truncate_segments(sci, sci->sc_curseg, nilfs->ns_sufile);
	return 0;

 failed:
	return err;
}

static void nilfs_list_replace_buffer(struct buffer_head *old_bh,
				      struct buffer_head *new_bh)
{
	BUG_ON(!list_empty(&new_bh->b_assoc_buffers));

	list_replace_init(&old_bh->b_assoc_buffers, &new_bh->b_assoc_buffers);
	/* The caller must release old_bh */
}

static int
nilfs_segctor_update_payload_blocknr(struct nilfs_sc_info *sci,
				     struct nilfs_segment_buffer *segbuf,
				     int mode)
{
	struct inode *inode = NULL;
	sector_t blocknr;
	unsigned long nfinfo = segbuf->sb_sum.nfinfo;
	unsigned long nblocks = 0, ndatablk = 0;
	struct nilfs_sc_operations *sc_op = NULL;
	struct nilfs_segsum_pointer ssp;
	struct nilfs_finfo *finfo = NULL;
	union nilfs_binfo binfo;
	struct buffer_head *bh, *bh_org;
	ino_t ino = 0;
	int err = 0;

	if (!nfinfo)
		goto out;

	blocknr = segbuf->sb_pseg_start + segbuf->sb_sum.nsumblk;
	ssp.bh = NILFS_SEGBUF_FIRST_BH(&segbuf->sb_segsum_buffers);
	ssp.offset = sizeof(struct nilfs_segment_summary);

	list_for_each_entry(bh, &segbuf->sb_payload_buffers, b_assoc_buffers) {
		if (bh == segbuf->sb_super_root)
			break;
		if (!finfo) {
			finfo =	nilfs_segctor_map_segsum_entry(
				sci, &ssp, sizeof(*finfo));
			ino = le64_to_cpu(finfo->fi_ino);
			nblocks = le32_to_cpu(finfo->fi_nblocks);
			ndatablk = le32_to_cpu(finfo->fi_ndatablk);

			inode = bh->b_page->mapping->host;

			if (mode == SC_LSEG_DSYNC)
				sc_op = &nilfs_sc_dsync_ops;
			else if (ino == NILFS_DAT_INO)
				sc_op = &nilfs_sc_dat_ops;
			else /* file blocks */
				sc_op = &nilfs_sc_file_ops;
		}
		bh_org = bh;
		get_bh(bh_org);
		err = nilfs_bmap_assign(NILFS_I(inode)->i_bmap, &bh, blocknr,
					&binfo);
		if (bh != bh_org)
			nilfs_list_replace_buffer(bh_org, bh);
		brelse(bh_org);
		if (unlikely(err))
			goto failed_bmap;

		if (ndatablk > 0)
			sc_op->write_data_binfo(sci, &ssp, &binfo);
		else
			sc_op->write_node_binfo(sci, &ssp, &binfo);

		blocknr++;
		if (--nblocks == 0) {
			finfo = NULL;
			if (--nfinfo == 0)
				break;
		} else if (ndatablk > 0)
			ndatablk--;
	}
 out:
	return 0;

 failed_bmap:
	return err;
}

static int nilfs_segctor_assign(struct nilfs_sc_info *sci, int mode)
{
	struct nilfs_segment_buffer *segbuf;
	int err;

	list_for_each_entry(segbuf, &sci->sc_segbufs, sb_list) {
		err = nilfs_segctor_update_payload_blocknr(sci, segbuf, mode);
		if (unlikely(err))
			return err;
		nilfs_segbuf_fill_in_segsum(segbuf);
	}
	return 0;
}

static void nilfs_begin_page_io(struct page *page)
{
	if (!page || PageWriteback(page))
		/* For split b-tree node pages, this function may be called
		   twice.  We ignore the 2nd or later calls by this check. */
		return;

	lock_page(page);
	clear_page_dirty_for_io(page);
	set_page_writeback(page);
	unlock_page(page);
}

static void nilfs_segctor_prepare_write(struct nilfs_sc_info *sci)
{
	struct nilfs_segment_buffer *segbuf;
	struct page *bd_page = NULL, *fs_page = NULL;

	list_for_each_entry(segbuf, &sci->sc_segbufs, sb_list) {
		struct buffer_head *bh;

		list_for_each_entry(bh, &segbuf->sb_segsum_buffers,
				    b_assoc_buffers) {
			set_buffer_async_write(bh);
			if (bh->b_page != bd_page) {
				if (bd_page) {
					lock_page(bd_page);
					clear_page_dirty_for_io(bd_page);
					set_page_writeback(bd_page);
					unlock_page(bd_page);
				}
				bd_page = bh->b_page;
			}
		}

		list_for_each_entry(bh, &segbuf->sb_payload_buffers,
				    b_assoc_buffers) {
			set_buffer_async_write(bh);
			if (bh == segbuf->sb_super_root) {
				if (bh->b_page != bd_page) {
					lock_page(bd_page);
					clear_page_dirty_for_io(bd_page);
					set_page_writeback(bd_page);
					unlock_page(bd_page);
					bd_page = bh->b_page;
				}
				break;
			}
			if (bh->b_page != fs_page) {
				nilfs_begin_page_io(fs_page);
				fs_page = bh->b_page;
			}
		}
	}
	if (bd_page) {
		lock_page(bd_page);
		clear_page_dirty_for_io(bd_page);
		set_page_writeback(bd_page);
		unlock_page(bd_page);
	}
	nilfs_begin_page_io(fs_page);
}

static int nilfs_segctor_write(struct nilfs_sc_info *sci,
			       struct the_nilfs *nilfs)
{
	int ret;

	ret = nilfs_write_logs(&sci->sc_segbufs, nilfs);
	list_splice_tail_init(&sci->sc_segbufs, &sci->sc_write_logs);
	return ret;
}

static void nilfs_end_page_io(struct page *page, int err)
{
	if (!page)
		return;

	if (buffer_nilfs_node(page_buffers(page)) && !PageWriteback(page)) {
		/*
		 * For b-tree node pages, this function may be called twice
		 * or more because they might be split in a segment.
		 */
		if (PageDirty(page)) {
			/*
			 * For pages holding split b-tree node buffers, dirty
			 * flag on the buffers may be cleared discretely.
			 * In that case, the page is once redirtied for
			 * remaining buffers, and it must be cancelled if
			 * all the buffers get cleaned later.
			 */
			lock_page(page);
			if (nilfs_page_buffers_clean(page))
				__nilfs_clear_page_dirty(page);
			unlock_page(page);
		}
		return;
	}

	if (!err) {
		if (!nilfs_page_buffers_clean(page))
			__set_page_dirty_nobuffers(page);
		ClearPageError(page);
	} else {
		__set_page_dirty_nobuffers(page);
		SetPageError(page);
	}

	end_page_writeback(page);
}

static void nilfs_abort_logs(struct list_head *logs, int err)
{
	struct nilfs_segment_buffer *segbuf;
	struct page *bd_page = NULL, *fs_page = NULL;
	struct buffer_head *bh;

	if (list_empty(logs))
		return;

	list_for_each_entry(segbuf, logs, sb_list) {
		list_for_each_entry(bh, &segbuf->sb_segsum_buffers,
				    b_assoc_buffers) {
			clear_buffer_async_write(bh);
			if (bh->b_page != bd_page) {
				if (bd_page)
					end_page_writeback(bd_page);
				bd_page = bh->b_page;
			}
		}

		list_for_each_entry(bh, &segbuf->sb_payload_buffers,
				    b_assoc_buffers) {
			clear_buffer_async_write(bh);
			if (bh == segbuf->sb_super_root) {
				if (bh->b_page != bd_page) {
					end_page_writeback(bd_page);
					bd_page = bh->b_page;
				}
				break;
			}
			if (bh->b_page != fs_page) {
				nilfs_end_page_io(fs_page, err);
				fs_page = bh->b_page;
			}
		}
	}
	if (bd_page)
		end_page_writeback(bd_page);

	nilfs_end_page_io(fs_page, err);
}

static void nilfs_segctor_abort_construction(struct nilfs_sc_info *sci,
					     struct the_nilfs *nilfs, int err)
{
	LIST_HEAD(logs);
	int ret;

	list_splice_tail_init(&sci->sc_write_logs, &logs);
	ret = nilfs_wait_on_logs(&logs);
	nilfs_abort_logs(&logs, ret ? : err);

	list_splice_tail_init(&sci->sc_segbufs, &logs);
	nilfs_cancel_segusage(&logs, nilfs->ns_sufile);
	nilfs_free_incomplete_logs(&logs, nilfs);

	if (sci->sc_stage.flags & NILFS_CF_SUFREED) {
		ret = nilfs_sufile_cancel_freev(nilfs->ns_sufile,
						sci->sc_freesegs,
						sci->sc_nfreesegs,
						NULL);
		WARN_ON(ret); /* do not happen */
	}

	nilfs_destroy_logs(&logs);
}

static void nilfs_set_next_segment(struct the_nilfs *nilfs,
				   struct nilfs_segment_buffer *segbuf)
{
	nilfs->ns_segnum = segbuf->sb_segnum;
	nilfs->ns_nextnum = segbuf->sb_nextnum;
	nilfs->ns_pseg_offset = segbuf->sb_pseg_start - segbuf->sb_fseg_start
		+ segbuf->sb_sum.nblocks;
	nilfs->ns_seg_seq = segbuf->sb_sum.seg_seq;
	nilfs->ns_ctime = segbuf->sb_sum.ctime;
}

static void nilfs_segctor_complete_write(struct nilfs_sc_info *sci)
{
	struct nilfs_segment_buffer *segbuf;
	struct page *bd_page = NULL, *fs_page = NULL;
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;
	int update_sr = false;

	list_for_each_entry(segbuf, &sci->sc_write_logs, sb_list) {
		struct buffer_head *bh;

		list_for_each_entry(bh, &segbuf->sb_segsum_buffers,
				    b_assoc_buffers) {
			set_buffer_uptodate(bh);
			clear_buffer_dirty(bh);
			clear_buffer_async_write(bh);
			if (bh->b_page != bd_page) {
				if (bd_page)
					end_page_writeback(bd_page);
				bd_page = bh->b_page;
			}
		}
		/*
		 * We assume that the buffers which belong to the same page
		 * continue over the buffer list.
		 * Under this assumption, the last BHs of pages is
		 * identifiable by the discontinuity of bh->b_page
		 * (page != fs_page).
		 *
		 * For B-tree node blocks, however, this assumption is not
		 * guaranteed.  The cleanup code of B-tree node pages needs
		 * special care.
		 */
		list_for_each_entry(bh, &segbuf->sb_payload_buffers,
				    b_assoc_buffers) {
			set_buffer_uptodate(bh);
			clear_buffer_dirty(bh);
			clear_buffer_async_write(bh);
			clear_buffer_delay(bh);
			clear_buffer_nilfs_volatile(bh);
			clear_buffer_nilfs_redirected(bh);
			if (bh == segbuf->sb_super_root) {
				if (bh->b_page != bd_page) {
					end_page_writeback(bd_page);
					bd_page = bh->b_page;
				}
				update_sr = true;
				break;
			}
			if (bh->b_page != fs_page) {
				nilfs_end_page_io(fs_page, 0);
				fs_page = bh->b_page;
			}
		}

		if (!nilfs_segbuf_simplex(segbuf)) {
			if (segbuf->sb_sum.flags & NILFS_SS_LOGBGN) {
				set_bit(NILFS_SC_UNCLOSED, &sci->sc_flags);
				sci->sc_lseg_stime = jiffies;
			}
			if (segbuf->sb_sum.flags & NILFS_SS_LOGEND)
				clear_bit(NILFS_SC_UNCLOSED, &sci->sc_flags);
		}
	}
	/*
	 * Since pages may continue over multiple segment buffers,
	 * end of the last page must be checked outside of the loop.
	 */
	if (bd_page)
		end_page_writeback(bd_page);

	nilfs_end_page_io(fs_page, 0);

	nilfs_drop_collected_inodes(&sci->sc_dirty_files);

	if (nilfs_doing_gc())
		nilfs_drop_collected_inodes(&sci->sc_gc_inodes);
	else
		nilfs->ns_nongc_ctime = sci->sc_seg_ctime;

	sci->sc_nblk_inc += sci->sc_nblk_this_inc;

	segbuf = NILFS_LAST_SEGBUF(&sci->sc_write_logs);
	nilfs_set_next_segment(nilfs, segbuf);

	if (update_sr) {
		nilfs_set_last_segment(nilfs, segbuf->sb_pseg_start,
				       segbuf->sb_sum.seg_seq, nilfs->ns_cno++);

		clear_bit(NILFS_SC_HAVE_DELTA, &sci->sc_flags);
		clear_bit(NILFS_SC_DIRTY, &sci->sc_flags);
		set_bit(NILFS_SC_SUPER_ROOT, &sci->sc_flags);
		nilfs_segctor_clear_metadata_dirty(sci);
	} else
		clear_bit(NILFS_SC_SUPER_ROOT, &sci->sc_flags);
}

static int nilfs_segctor_wait(struct nilfs_sc_info *sci)
{
	int ret;

	ret = nilfs_wait_on_logs(&sci->sc_write_logs);
	if (!ret) {
		nilfs_segctor_complete_write(sci);
		nilfs_destroy_logs(&sci->sc_write_logs);
	}
	return ret;
}

static int nilfs_segctor_collect_dirty_files(struct nilfs_sc_info *sci,
					     struct the_nilfs *nilfs)
{
	struct nilfs_inode_info *ii, *n;
	struct inode *ifile = sci->sc_root->ifile;

	spin_lock(&nilfs->ns_inode_lock);
 retry:
	list_for_each_entry_safe(ii, n, &nilfs->ns_dirty_files, i_dirty) {
		if (!ii->i_bh) {
			struct buffer_head *ibh;
			int err;

			spin_unlock(&nilfs->ns_inode_lock);
			err = nilfs_ifile_get_inode_block(
				ifile, ii->vfs_inode.i_ino, &ibh);
			if (unlikely(err)) {
				nilfs_warning(sci->sc_super, __func__,
					      "failed to get inode block.\n");
				return err;
			}
			mark_buffer_dirty(ibh);
			nilfs_mdt_mark_dirty(ifile);
			spin_lock(&nilfs->ns_inode_lock);
			if (likely(!ii->i_bh))
				ii->i_bh = ibh;
			else
				brelse(ibh);
			goto retry;
		}

		clear_bit(NILFS_I_QUEUED, &ii->i_state);
		set_bit(NILFS_I_BUSY, &ii->i_state);
		list_move_tail(&ii->i_dirty, &sci->sc_dirty_files);
	}
	spin_unlock(&nilfs->ns_inode_lock);

	return 0;
}

static void nilfs_segctor_drop_written_files(struct nilfs_sc_info *sci,
					     struct the_nilfs *nilfs)
{
	struct nilfs_transaction_info *ti = current->journal_info;
	struct nilfs_inode_info *ii, *n;

	spin_lock(&nilfs->ns_inode_lock);
	list_for_each_entry_safe(ii, n, &sci->sc_dirty_files, i_dirty) {
		if (!test_and_clear_bit(NILFS_I_UPDATED, &ii->i_state) ||
		    test_bit(NILFS_I_DIRTY, &ii->i_state))
			continue;

		clear_bit(NILFS_I_BUSY, &ii->i_state);
		brelse(ii->i_bh);
		ii->i_bh = NULL;
		list_move_tail(&ii->i_dirty, &ti->ti_garbage);
	}
	spin_unlock(&nilfs->ns_inode_lock);
}

/*
 * Main procedure of segment constructor
 */
static int nilfs_segctor_do_construct(struct nilfs_sc_info *sci, int mode)
{
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;
	int err;

	sci->sc_stage.scnt = NILFS_ST_INIT;
	sci->sc_cno = nilfs->ns_cno;

	err = nilfs_segctor_collect_dirty_files(sci, nilfs);
	if (unlikely(err))
		goto out;

	if (nilfs_test_metadata_dirty(nilfs, sci->sc_root))
		set_bit(NILFS_SC_DIRTY, &sci->sc_flags);

	if (nilfs_segctor_clean(sci))
		goto out;

	do {
		sci->sc_stage.flags &= ~NILFS_CF_HISTORY_MASK;

		err = nilfs_segctor_begin_construction(sci, nilfs);
		if (unlikely(err))
			goto out;

		/* Update time stamp */
		sci->sc_seg_ctime = get_seconds();

		err = nilfs_segctor_collect(sci, nilfs, mode);
		if (unlikely(err))
			goto failed;

		/* Avoid empty segment */
		if (sci->sc_stage.scnt == NILFS_ST_DONE &&
		    nilfs_segbuf_empty(sci->sc_curseg)) {
			nilfs_segctor_abort_construction(sci, nilfs, 1);
			goto out;
		}

		err = nilfs_segctor_assign(sci, mode);
		if (unlikely(err))
			goto failed;

		if (sci->sc_stage.flags & NILFS_CF_IFILE_STARTED)
			nilfs_segctor_fill_in_file_bmap(sci);

		if (mode == SC_LSEG_SR &&
		    sci->sc_stage.scnt >= NILFS_ST_CPFILE) {
			err = nilfs_segctor_fill_in_checkpoint(sci);
			if (unlikely(err))
				goto failed_to_write;

			nilfs_segctor_fill_in_super_root(sci, nilfs);
		}
		nilfs_segctor_update_segusage(sci, nilfs->ns_sufile);

		/* Write partial segments */
		nilfs_segctor_prepare_write(sci);

		nilfs_add_checksums_on_logs(&sci->sc_segbufs,
					    nilfs->ns_crc_seed);

		err = nilfs_segctor_write(sci, nilfs);
		if (unlikely(err))
			goto failed_to_write;

		if (sci->sc_stage.scnt == NILFS_ST_DONE ||
		    nilfs->ns_blocksize_bits != PAGE_CACHE_SHIFT) {
			/*
			 * At this point, we avoid double buffering
			 * for blocksize < pagesize because page dirty
			 * flag is turned off during write and dirty
			 * buffers are not properly collected for
			 * pages crossing over segments.
			 */
			err = nilfs_segctor_wait(sci);
			if (err)
				goto failed_to_write;
		}
	} while (sci->sc_stage.scnt != NILFS_ST_DONE);

 out:
	nilfs_segctor_drop_written_files(sci, nilfs);
	return err;

 failed_to_write:
	if (sci->sc_stage.flags & NILFS_CF_IFILE_STARTED)
		nilfs_redirty_inodes(&sci->sc_dirty_files);

 failed:
	if (nilfs_doing_gc())
		nilfs_redirty_inodes(&sci->sc_gc_inodes);
	nilfs_segctor_abort_construction(sci, nilfs, err);
	goto out;
}

/**
 * nilfs_segctor_start_timer - set timer of background write
 * @sci: nilfs_sc_info
 *
 * If the timer has already been set, it ignores the new request.
 * This function MUST be called within a section locking the segment
 * semaphore.
 */
static void nilfs_segctor_start_timer(struct nilfs_sc_info *sci)
{
	spin_lock(&sci->sc_state_lock);
	if (!(sci->sc_state & NILFS_SEGCTOR_COMMIT)) {
		sci->sc_timer.expires = jiffies + sci->sc_interval;
		add_timer(&sci->sc_timer);
		sci->sc_state |= NILFS_SEGCTOR_COMMIT;
	}
	spin_unlock(&sci->sc_state_lock);
}

static void nilfs_segctor_do_flush(struct nilfs_sc_info *sci, int bn)
{
	spin_lock(&sci->sc_state_lock);
	if (!(sci->sc_flush_request & (1 << bn))) {
		unsigned long prev_req = sci->sc_flush_request;

		sci->sc_flush_request |= (1 << bn);
		if (!prev_req)
			wake_up(&sci->sc_wait_daemon);
	}
	spin_unlock(&sci->sc_state_lock);
}

/**
 * nilfs_flush_segment - trigger a segment construction for resource control
 * @sb: super block
 * @ino: inode number of the file to be flushed out.
 */
void nilfs_flush_segment(struct super_block *sb, ino_t ino)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_sc_info *sci = nilfs->ns_writer;

	if (!sci || nilfs_doing_construction())
		return;
	nilfs_segctor_do_flush(sci, NILFS_MDT_INODE(sb, ino) ? ino : 0);
					/* assign bit 0 to data files */
}

struct nilfs_segctor_wait_request {
	wait_queue_t	wq;
	__u32		seq;
	int		err;
	atomic_t	done;
};

static int nilfs_segctor_sync(struct nilfs_sc_info *sci)
{
	struct nilfs_segctor_wait_request wait_req;
	int err = 0;

	spin_lock(&sci->sc_state_lock);
	init_wait(&wait_req.wq);
	wait_req.err = 0;
	atomic_set(&wait_req.done, 0);
	wait_req.seq = ++sci->sc_seq_request;
	spin_unlock(&sci->sc_state_lock);

	init_waitqueue_entry(&wait_req.wq, current);
	add_wait_queue(&sci->sc_wait_request, &wait_req.wq);
	set_current_state(TASK_INTERRUPTIBLE);
	wake_up(&sci->sc_wait_daemon);

	for (;;) {
		if (atomic_read(&wait_req.done)) {
			err = wait_req.err;
			break;
		}
		if (!signal_pending(current)) {
			schedule();
			continue;
		}
		err = -ERESTARTSYS;
		break;
	}
	finish_wait(&sci->sc_wait_request, &wait_req.wq);
	return err;
}

static void nilfs_segctor_wakeup(struct nilfs_sc_info *sci, int err)
{
	struct nilfs_segctor_wait_request *wrq, *n;
	unsigned long flags;

	spin_lock_irqsave(&sci->sc_wait_request.lock, flags);
	list_for_each_entry_safe(wrq, n, &sci->sc_wait_request.task_list,
				 wq.task_list) {
		if (!atomic_read(&wrq->done) &&
		    nilfs_cnt32_ge(sci->sc_seq_done, wrq->seq)) {
			wrq->err = err;
			atomic_set(&wrq->done, 1);
		}
		if (atomic_read(&wrq->done)) {
			wrq->wq.func(&wrq->wq,
				     TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE,
				     0, NULL);
		}
	}
	spin_unlock_irqrestore(&sci->sc_wait_request.lock, flags);
}

/**
 * nilfs_construct_segment - construct a logical segment
 * @sb: super block
 *
 * Return Value: On success, 0 is retured. On errors, one of the following
 * negative error code is returned.
 *
 * %-EROFS - Read only filesystem.
 *
 * %-EIO - I/O error
 *
 * %-ENOSPC - No space left on device (only in a panic state).
 *
 * %-ERESTARTSYS - Interrupted.
 *
 * %-ENOMEM - Insufficient memory available.
 */
int nilfs_construct_segment(struct super_block *sb)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_sc_info *sci = nilfs->ns_writer;
	struct nilfs_transaction_info *ti;
	int err;

	if (!sci)
		return -EROFS;

	/* A call inside transactions causes a deadlock. */
	BUG_ON((ti = current->journal_info) && ti->ti_magic == NILFS_TI_MAGIC);

	err = nilfs_segctor_sync(sci);
	return err;
}

/**
 * nilfs_construct_dsync_segment - construct a data-only logical segment
 * @sb: super block
 * @inode: inode whose data blocks should be written out
 * @start: start byte offset
 * @end: end byte offset (inclusive)
 *
 * Return Value: On success, 0 is retured. On errors, one of the following
 * negative error code is returned.
 *
 * %-EROFS - Read only filesystem.
 *
 * %-EIO - I/O error
 *
 * %-ENOSPC - No space left on device (only in a panic state).
 *
 * %-ERESTARTSYS - Interrupted.
 *
 * %-ENOMEM - Insufficient memory available.
 */
int nilfs_construct_dsync_segment(struct super_block *sb, struct inode *inode,
				  loff_t start, loff_t end)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_sc_info *sci = nilfs->ns_writer;
	struct nilfs_inode_info *ii;
	struct nilfs_transaction_info ti;
	int err = 0;

	if (!sci)
		return -EROFS;

	nilfs_transaction_lock(sb, &ti, 0);

	ii = NILFS_I(inode);
	if (test_bit(NILFS_I_INODE_DIRTY, &ii->i_state) ||
	    nilfs_test_opt(nilfs, STRICT_ORDER) ||
	    test_bit(NILFS_SC_UNCLOSED, &sci->sc_flags) ||
	    nilfs_discontinued(nilfs)) {
		nilfs_transaction_unlock(sb);
		err = nilfs_segctor_sync(sci);
		return err;
	}

	spin_lock(&nilfs->ns_inode_lock);
	if (!test_bit(NILFS_I_QUEUED, &ii->i_state) &&
	    !test_bit(NILFS_I_BUSY, &ii->i_state)) {
		spin_unlock(&nilfs->ns_inode_lock);
		nilfs_transaction_unlock(sb);
		return 0;
	}
	spin_unlock(&nilfs->ns_inode_lock);
	sci->sc_dsync_inode = ii;
	sci->sc_dsync_start = start;
	sci->sc_dsync_end = end;

	err = nilfs_segctor_do_construct(sci, SC_LSEG_DSYNC);

	nilfs_transaction_unlock(sb);
	return err;
}

#define FLUSH_FILE_BIT	(0x1) /* data file only */
#define FLUSH_DAT_BIT	(1 << NILFS_DAT_INO) /* DAT only */

/**
 * nilfs_segctor_accept - record accepted sequence count of log-write requests
 * @sci: segment constructor object
 */
static void nilfs_segctor_accept(struct nilfs_sc_info *sci)
{
	spin_lock(&sci->sc_state_lock);
	sci->sc_seq_accepted = sci->sc_seq_request;
	spin_unlock(&sci->sc_state_lock);
	del_timer_sync(&sci->sc_timer);
}

/**
 * nilfs_segctor_notify - notify the result of request to caller threads
 * @sci: segment constructor object
 * @mode: mode of log forming
 * @err: error code to be notified
 */
static void nilfs_segctor_notify(struct nilfs_sc_info *sci, int mode, int err)
{
	/* Clear requests (even when the construction failed) */
	spin_lock(&sci->sc_state_lock);

	if (mode == SC_LSEG_SR) {
		sci->sc_state &= ~NILFS_SEGCTOR_COMMIT;
		sci->sc_seq_done = sci->sc_seq_accepted;
		nilfs_segctor_wakeup(sci, err);
		sci->sc_flush_request = 0;
	} else {
		if (mode == SC_FLUSH_FILE)
			sci->sc_flush_request &= ~FLUSH_FILE_BIT;
		else if (mode == SC_FLUSH_DAT)
			sci->sc_flush_request &= ~FLUSH_DAT_BIT;

		/* re-enable timer if checkpoint creation was not done */
		if ((sci->sc_state & NILFS_SEGCTOR_COMMIT) &&
		    time_before(jiffies, sci->sc_timer.expires))
			add_timer(&sci->sc_timer);
	}
	spin_unlock(&sci->sc_state_lock);
}

/**
 * nilfs_segctor_construct - form logs and write them to disk
 * @sci: segment constructor object
 * @mode: mode of log forming
 */
static int nilfs_segctor_construct(struct nilfs_sc_info *sci, int mode)
{
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;
	struct nilfs_super_block **sbp;
	int err = 0;

	nilfs_segctor_accept(sci);

	if (nilfs_discontinued(nilfs))
		mode = SC_LSEG_SR;
	if (!nilfs_segctor_confirm(sci))
		err = nilfs_segctor_do_construct(sci, mode);

	if (likely(!err)) {
		if (mode != SC_FLUSH_DAT)
			atomic_set(&nilfs->ns_ndirtyblks, 0);
		if (test_bit(NILFS_SC_SUPER_ROOT, &sci->sc_flags) &&
		    nilfs_discontinued(nilfs)) {
			down_write(&nilfs->ns_sem);
			err = -EIO;
			sbp = nilfs_prepare_super(sci->sc_super,
						  nilfs_sb_will_flip(nilfs));
			if (likely(sbp)) {
				nilfs_set_log_cursor(sbp[0], nilfs);
				err = nilfs_commit_super(sci->sc_super,
							 NILFS_SB_COMMIT);
			}
			up_write(&nilfs->ns_sem);
		}
	}

	nilfs_segctor_notify(sci, mode, err);
	return err;
}

static void nilfs_construction_timeout(unsigned long data)
{
	struct task_struct *p = (struct task_struct *)data;
	wake_up_process(p);
}

static void
nilfs_remove_written_gcinodes(struct the_nilfs *nilfs, struct list_head *head)
{
	struct nilfs_inode_info *ii, *n;

	list_for_each_entry_safe(ii, n, head, i_dirty) {
		if (!test_bit(NILFS_I_UPDATED, &ii->i_state))
			continue;
		list_del_init(&ii->i_dirty);
		truncate_inode_pages(&ii->vfs_inode.i_data, 0);
		nilfs_btnode_cache_clear(&ii->i_btnode_cache);
		iput(&ii->vfs_inode);
	}
}

int nilfs_clean_segments(struct super_block *sb, struct nilfs_argv *argv,
			 void **kbufs)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_sc_info *sci = nilfs->ns_writer;
	struct nilfs_transaction_info ti;
	int err;

	if (unlikely(!sci))
		return -EROFS;

	nilfs_transaction_lock(sb, &ti, 1);

	err = nilfs_mdt_save_to_shadow_map(nilfs->ns_dat);
	if (unlikely(err))
		goto out_unlock;

	err = nilfs_ioctl_prepare_clean_segments(nilfs, argv, kbufs);
	if (unlikely(err)) {
		nilfs_mdt_restore_from_shadow_map(nilfs->ns_dat);
		goto out_unlock;
	}

	sci->sc_freesegs = kbufs[4];
	sci->sc_nfreesegs = argv[4].v_nmembs;
	list_splice_tail_init(&nilfs->ns_gc_inodes, &sci->sc_gc_inodes);

	for (;;) {
		err = nilfs_segctor_construct(sci, SC_LSEG_SR);
		nilfs_remove_written_gcinodes(nilfs, &sci->sc_gc_inodes);

		if (likely(!err))
			break;

		nilfs_warning(sb, __func__,
			      "segment construction failed. (err=%d)", err);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(sci->sc_interval);
	}
	if (nilfs_test_opt(nilfs, DISCARD)) {
		int ret = nilfs_discard_segments(nilfs, sci->sc_freesegs,
						 sci->sc_nfreesegs);
		if (ret) {
			printk(KERN_WARNING
			       "NILFS warning: error %d on discard request, "
			       "turning discards off for the device\n", ret);
			nilfs_clear_opt(nilfs, DISCARD);
		}
	}

 out_unlock:
	sci->sc_freesegs = NULL;
	sci->sc_nfreesegs = 0;
	nilfs_mdt_clear_shadow_map(nilfs->ns_dat);
	nilfs_transaction_unlock(sb);
	return err;
}

static void nilfs_segctor_thread_construct(struct nilfs_sc_info *sci, int mode)
{
	struct nilfs_transaction_info ti;

	nilfs_transaction_lock(sci->sc_super, &ti, 0);
	nilfs_segctor_construct(sci, mode);

	/*
	 * Unclosed segment should be retried.  We do this using sc_timer.
	 * Timeout of sc_timer will invoke complete construction which leads
	 * to close the current logical segment.
	 */
	if (test_bit(NILFS_SC_UNCLOSED, &sci->sc_flags))
		nilfs_segctor_start_timer(sci);

	nilfs_transaction_unlock(sci->sc_super);
}

static void nilfs_segctor_do_immediate_flush(struct nilfs_sc_info *sci)
{
	int mode = 0;
	int err;

	spin_lock(&sci->sc_state_lock);
	mode = (sci->sc_flush_request & FLUSH_DAT_BIT) ?
		SC_FLUSH_DAT : SC_FLUSH_FILE;
	spin_unlock(&sci->sc_state_lock);

	if (mode) {
		err = nilfs_segctor_do_construct(sci, mode);

		spin_lock(&sci->sc_state_lock);
		sci->sc_flush_request &= (mode == SC_FLUSH_FILE) ?
			~FLUSH_FILE_BIT : ~FLUSH_DAT_BIT;
		spin_unlock(&sci->sc_state_lock);
	}
	clear_bit(NILFS_SC_PRIOR_FLUSH, &sci->sc_flags);
}

static int nilfs_segctor_flush_mode(struct nilfs_sc_info *sci)
{
	if (!test_bit(NILFS_SC_UNCLOSED, &sci->sc_flags) ||
	    time_before(jiffies, sci->sc_lseg_stime + sci->sc_mjcp_freq)) {
		if (!(sci->sc_flush_request & ~FLUSH_FILE_BIT))
			return SC_FLUSH_FILE;
		else if (!(sci->sc_flush_request & ~FLUSH_DAT_BIT))
			return SC_FLUSH_DAT;
	}
	return SC_LSEG_SR;
}

/**
 * nilfs_segctor_thread - main loop of the segment constructor thread.
 * @arg: pointer to a struct nilfs_sc_info.
 *
 * nilfs_segctor_thread() initializes a timer and serves as a daemon
 * to execute segment constructions.
 */
static int nilfs_segctor_thread(void *arg)
{
	struct nilfs_sc_info *sci = (struct nilfs_sc_info *)arg;
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;
	int timeout = 0;

	sci->sc_timer.data = (unsigned long)current;
	sci->sc_timer.function = nilfs_construction_timeout;

	/* start sync. */
	sci->sc_task = current;
	wake_up(&sci->sc_wait_task); /* for nilfs_segctor_start_thread() */
	printk(KERN_INFO
	       "segctord starting. Construction interval = %lu seconds, "
	       "CP frequency < %lu seconds\n",
	       sci->sc_interval / HZ, sci->sc_mjcp_freq / HZ);

	spin_lock(&sci->sc_state_lock);
 loop:
	for (;;) {
		int mode;

		if (sci->sc_state & NILFS_SEGCTOR_QUIT)
			goto end_thread;

		if (timeout || sci->sc_seq_request != sci->sc_seq_done)
			mode = SC_LSEG_SR;
		else if (!sci->sc_flush_request)
			break;
		else
			mode = nilfs_segctor_flush_mode(sci);

		spin_unlock(&sci->sc_state_lock);
		nilfs_segctor_thread_construct(sci, mode);
		spin_lock(&sci->sc_state_lock);
		timeout = 0;
	}


	if (freezing(current)) {
		spin_unlock(&sci->sc_state_lock);
		try_to_freeze();
		spin_lock(&sci->sc_state_lock);
	} else {
		DEFINE_WAIT(wait);
		int should_sleep = 1;

		prepare_to_wait(&sci->sc_wait_daemon, &wait,
				TASK_INTERRUPTIBLE);

		if (sci->sc_seq_request != sci->sc_seq_done)
			should_sleep = 0;
		else if (sci->sc_flush_request)
			should_sleep = 0;
		else if (sci->sc_state & NILFS_SEGCTOR_COMMIT)
			should_sleep = time_before(jiffies,
					sci->sc_timer.expires);

		if (should_sleep) {
			spin_unlock(&sci->sc_state_lock);
			schedule();
			spin_lock(&sci->sc_state_lock);
		}
		finish_wait(&sci->sc_wait_daemon, &wait);
		timeout = ((sci->sc_state & NILFS_SEGCTOR_COMMIT) &&
			   time_after_eq(jiffies, sci->sc_timer.expires));

		if (nilfs_sb_dirty(nilfs) && nilfs_sb_need_update(nilfs))
			set_nilfs_discontinued(nilfs);
	}
	goto loop;

 end_thread:
	spin_unlock(&sci->sc_state_lock);

	/* end sync. */
	sci->sc_task = NULL;
	wake_up(&sci->sc_wait_task); /* for nilfs_segctor_kill_thread() */
	return 0;
}

static int nilfs_segctor_start_thread(struct nilfs_sc_info *sci)
{
	struct task_struct *t;

	t = kthread_run(nilfs_segctor_thread, sci, "segctord");
	if (IS_ERR(t)) {
		int err = PTR_ERR(t);

		printk(KERN_ERR "NILFS: error %d creating segctord thread\n",
		       err);
		return err;
	}
	wait_event(sci->sc_wait_task, sci->sc_task != NULL);
	return 0;
}

static void nilfs_segctor_kill_thread(struct nilfs_sc_info *sci)
	__acquires(&sci->sc_state_lock)
	__releases(&sci->sc_state_lock)
{
	sci->sc_state |= NILFS_SEGCTOR_QUIT;

	while (sci->sc_task) {
		wake_up(&sci->sc_wait_daemon);
		spin_unlock(&sci->sc_state_lock);
		wait_event(sci->sc_wait_task, sci->sc_task == NULL);
		spin_lock(&sci->sc_state_lock);
	}
}

/*
 * Setup & clean-up functions
 */
static struct nilfs_sc_info *nilfs_segctor_new(struct super_block *sb,
					       struct nilfs_root *root)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct nilfs_sc_info *sci;

	sci = kzalloc(sizeof(*sci), GFP_KERNEL);
	if (!sci)
		return NULL;

	sci->sc_super = sb;

	nilfs_get_root(root);
	sci->sc_root = root;

	init_waitqueue_head(&sci->sc_wait_request);
	init_waitqueue_head(&sci->sc_wait_daemon);
	init_waitqueue_head(&sci->sc_wait_task);
	spin_lock_init(&sci->sc_state_lock);
	INIT_LIST_HEAD(&sci->sc_dirty_files);
	INIT_LIST_HEAD(&sci->sc_segbufs);
	INIT_LIST_HEAD(&sci->sc_write_logs);
	INIT_LIST_HEAD(&sci->sc_gc_inodes);
	init_timer(&sci->sc_timer);

	sci->sc_interval = HZ * NILFS_SC_DEFAULT_TIMEOUT;
	sci->sc_mjcp_freq = HZ * NILFS_SC_DEFAULT_SR_FREQ;
	sci->sc_watermark = NILFS_SC_DEFAULT_WATERMARK;

	if (nilfs->ns_interval)
		sci->sc_interval = HZ * nilfs->ns_interval;
	if (nilfs->ns_watermark)
		sci->sc_watermark = nilfs->ns_watermark;
	return sci;
}

static void nilfs_segctor_write_out(struct nilfs_sc_info *sci)
{
	int ret, retrycount = NILFS_SC_CLEANUP_RETRY;

	/* The segctord thread was stopped and its timer was removed.
	   But some tasks remain. */
	do {
		struct nilfs_transaction_info ti;

		nilfs_transaction_lock(sci->sc_super, &ti, 0);
		ret = nilfs_segctor_construct(sci, SC_LSEG_SR);
		nilfs_transaction_unlock(sci->sc_super);

	} while (ret && retrycount-- > 0);
}

/**
 * nilfs_segctor_destroy - destroy the segment constructor.
 * @sci: nilfs_sc_info
 *
 * nilfs_segctor_destroy() kills the segctord thread and frees
 * the nilfs_sc_info struct.
 * Caller must hold the segment semaphore.
 */
static void nilfs_segctor_destroy(struct nilfs_sc_info *sci)
{
	struct the_nilfs *nilfs = sci->sc_super->s_fs_info;
	int flag;

	up_write(&nilfs->ns_segctor_sem);

	spin_lock(&sci->sc_state_lock);
	nilfs_segctor_kill_thread(sci);
	flag = ((sci->sc_state & NILFS_SEGCTOR_COMMIT) || sci->sc_flush_request
		|| sci->sc_seq_request != sci->sc_seq_done);
	spin_unlock(&sci->sc_state_lock);

	if (flag || !nilfs_segctor_confirm(sci))
		nilfs_segctor_write_out(sci);

	if (!list_empty(&sci->sc_dirty_files)) {
		nilfs_warning(sci->sc_super, __func__,
			      "dirty file(s) after the final construction\n");
		nilfs_dispose_list(nilfs, &sci->sc_dirty_files, 1);
	}

	WARN_ON(!list_empty(&sci->sc_segbufs));
	WARN_ON(!list_empty(&sci->sc_write_logs));

	nilfs_put_root(sci->sc_root);

	down_write(&nilfs->ns_segctor_sem);

	del_timer_sync(&sci->sc_timer);
	kfree(sci);
}

/**
 * nilfs_attach_log_writer - attach log writer
 * @sb: super block instance
 * @root: root object of the current filesystem tree
 *
 * This allocates a log writer object, initializes it, and starts the
 * log writer.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error code is returned.
 *
 * %-ENOMEM - Insufficient memory available.
 */
int nilfs_attach_log_writer(struct super_block *sb, struct nilfs_root *root)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	int err;

	if (nilfs->ns_writer) {
		/*
		 * This happens if the filesystem was remounted
		 * read/write after nilfs_error degenerated it into a
		 * read-only mount.
		 */
		nilfs_detach_log_writer(sb);
	}

	nilfs->ns_writer = nilfs_segctor_new(sb, root);
	if (!nilfs->ns_writer)
		return -ENOMEM;

	err = nilfs_segctor_start_thread(nilfs->ns_writer);
	if (err) {
		kfree(nilfs->ns_writer);
		nilfs->ns_writer = NULL;
	}
	return err;
}

/**
 * nilfs_detach_log_writer - destroy log writer
 * @sb: super block instance
 *
 * This kills log writer daemon, frees the log writer object, and
 * destroys list of dirty files.
 */
void nilfs_detach_log_writer(struct super_block *sb)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	LIST_HEAD(garbage_list);

	down_write(&nilfs->ns_segctor_sem);
	if (nilfs->ns_writer) {
		nilfs_segctor_destroy(nilfs->ns_writer);
		nilfs->ns_writer = NULL;
	}

	/* Force to free the list of dirty files */
	spin_lock(&nilfs->ns_inode_lock);
	if (!list_empty(&nilfs->ns_dirty_files)) {
		list_splice_init(&nilfs->ns_dirty_files, &garbage_list);
		nilfs_warning(sb, __func__,
			      "Hit dirty file after stopped log writer\n");
	}
	spin_unlock(&nilfs->ns_inode_lock);
	up_write(&nilfs->ns_segctor_sem);

	nilfs_dispose_list(nilfs, &garbage_list, 1);
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/segment.c */
/************************************************************/
/*
 * cpfile.c - NILFS checkpoint file.
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Koji Sato <koji@osrg.net>.
 */

#include <linux/kernel.h>
// #include <linux/fs.h>
// #include <linux/string.h>
// #include <linux/buffer_head.h>
// #include <linux/errno.h>
#include <linux/nilfs2_fs.h>
// #include "mdt.h"
// #include "cpfile.h"


static inline unsigned long
nilfs_cpfile_checkpoints_per_block(const struct inode *cpfile)
{
	return NILFS_MDT(cpfile)->mi_entries_per_block;
}

/* block number from the beginning of the file */
static unsigned long
nilfs_cpfile_get_blkoff(const struct inode *cpfile, __u64 cno)
{
	__u64 tcno = cno + NILFS_MDT(cpfile)->mi_first_entry_offset - 1;
	do_div(tcno, nilfs_cpfile_checkpoints_per_block(cpfile));
	return (unsigned long)tcno;
}

/* offset in block */
static unsigned long
nilfs_cpfile_get_offset(const struct inode *cpfile, __u64 cno)
{
	__u64 tcno = cno + NILFS_MDT(cpfile)->mi_first_entry_offset - 1;
	return do_div(tcno, nilfs_cpfile_checkpoints_per_block(cpfile));
}

static unsigned long
nilfs_cpfile_checkpoints_in_block(const struct inode *cpfile,
				  __u64 curr,
				  __u64 max)
{
	return min_t(__u64,
		     nilfs_cpfile_checkpoints_per_block(cpfile) -
		     nilfs_cpfile_get_offset(cpfile, curr),
		     max - curr);
}

static inline int nilfs_cpfile_is_in_first(const struct inode *cpfile,
					   __u64 cno)
{
	return nilfs_cpfile_get_blkoff(cpfile, cno) == 0;
}

static unsigned int
nilfs_cpfile_block_add_valid_checkpoints(const struct inode *cpfile,
					 struct buffer_head *bh,
					 void *kaddr,
					 unsigned int n)
{
	struct nilfs_checkpoint *cp = kaddr + bh_offset(bh);
	unsigned int count;

	count = le32_to_cpu(cp->cp_checkpoints_count) + n;
	cp->cp_checkpoints_count = cpu_to_le32(count);
	return count;
}

static unsigned int
nilfs_cpfile_block_sub_valid_checkpoints(const struct inode *cpfile,
					 struct buffer_head *bh,
					 void *kaddr,
					 unsigned int n)
{
	struct nilfs_checkpoint *cp = kaddr + bh_offset(bh);
	unsigned int count;

	WARN_ON(le32_to_cpu(cp->cp_checkpoints_count) < n);
	count = le32_to_cpu(cp->cp_checkpoints_count) - n;
	cp->cp_checkpoints_count = cpu_to_le32(count);
	return count;
}

static inline struct nilfs_cpfile_header *
nilfs_cpfile_block_get_header(const struct inode *cpfile,
			      struct buffer_head *bh,
			      void *kaddr)
{
	return kaddr + bh_offset(bh);
}

static struct nilfs_checkpoint *
nilfs_cpfile_block_get_checkpoint(const struct inode *cpfile, __u64 cno,
				  struct buffer_head *bh,
				  void *kaddr)
{
	return kaddr + bh_offset(bh) + nilfs_cpfile_get_offset(cpfile, cno) *
		NILFS_MDT(cpfile)->mi_entry_size;
}

static void nilfs_cpfile_block_init(struct inode *cpfile,
				    struct buffer_head *bh,
				    void *kaddr)
{
	struct nilfs_checkpoint *cp = kaddr + bh_offset(bh);
	size_t cpsz = NILFS_MDT(cpfile)->mi_entry_size;
	int n = nilfs_cpfile_checkpoints_per_block(cpfile);

	while (n-- > 0) {
		nilfs_checkpoint_set_invalid(cp);
		cp = (void *)cp + cpsz;
	}
}

static inline int nilfs_cpfile_get_header_block(struct inode *cpfile,
						struct buffer_head **bhp)
{
	return nilfs_mdt_get_block(cpfile, 0, 0, NULL, bhp);
}

static inline int nilfs_cpfile_get_checkpoint_block(struct inode *cpfile,
						    __u64 cno,
						    int create,
						    struct buffer_head **bhp)
{
	return nilfs_mdt_get_block(cpfile,
				   nilfs_cpfile_get_blkoff(cpfile, cno),
				   create, nilfs_cpfile_block_init, bhp);
}

static inline int nilfs_cpfile_delete_checkpoint_block(struct inode *cpfile,
						       __u64 cno)
{
	return nilfs_mdt_delete_block(cpfile,
				      nilfs_cpfile_get_blkoff(cpfile, cno));
}

/**
 * nilfs_cpfile_get_checkpoint - get a checkpoint
 * @cpfile: inode of checkpoint file
 * @cno: checkpoint number
 * @create: create flag
 * @cpp: pointer to a checkpoint
 * @bhp: pointer to a buffer head
 *
 * Description: nilfs_cpfile_get_checkpoint() acquires the checkpoint
 * specified by @cno. A new checkpoint will be created if @cno is the current
 * checkpoint number and @create is nonzero.
 *
 * Return Value: On success, 0 is returned, and the checkpoint and the
 * buffer head of the buffer on which the checkpoint is located are stored in
 * the place pointed by @cpp and @bhp, respectively. On error, one of the
 * following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - No such checkpoint.
 *
 * %-EINVAL - invalid checkpoint.
 */
int nilfs_cpfile_get_checkpoint(struct inode *cpfile,
				__u64 cno,
				int create,
				struct nilfs_checkpoint **cpp,
				struct buffer_head **bhp)
{
	struct buffer_head *header_bh, *cp_bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	void *kaddr;
	int ret;

	if (unlikely(cno < 1 || cno > nilfs_mdt_cno(cpfile) ||
		     (cno < nilfs_mdt_cno(cpfile) && create)))
		return -EINVAL;

	down_write(&NILFS_MDT(cpfile)->mi_sem);

	ret = nilfs_cpfile_get_header_block(cpfile, &header_bh);
	if (ret < 0)
		goto out_sem;
	ret = nilfs_cpfile_get_checkpoint_block(cpfile, cno, create, &cp_bh);
	if (ret < 0)
		goto out_header;
	kaddr = kmap(cp_bh->b_page);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	if (nilfs_checkpoint_invalid(cp)) {
		if (!create) {
			kunmap(cp_bh->b_page);
			brelse(cp_bh);
			ret = -ENOENT;
			goto out_header;
		}
		/* a newly-created checkpoint */
		nilfs_checkpoint_clear_invalid(cp);
		if (!nilfs_cpfile_is_in_first(cpfile, cno))
			nilfs_cpfile_block_add_valid_checkpoints(cpfile, cp_bh,
								 kaddr, 1);
		mark_buffer_dirty(cp_bh);

		kaddr = kmap_atomic(header_bh->b_page);
		header = nilfs_cpfile_block_get_header(cpfile, header_bh,
						       kaddr);
		le64_add_cpu(&header->ch_ncheckpoints, 1);
		kunmap_atomic(kaddr);
		mark_buffer_dirty(header_bh);
		nilfs_mdt_mark_dirty(cpfile);
	}

	if (cpp != NULL)
		*cpp = cp;
	*bhp = cp_bh;

 out_header:
	brelse(header_bh);

 out_sem:
	up_write(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_put_checkpoint - put a checkpoint
 * @cpfile: inode of checkpoint file
 * @cno: checkpoint number
 * @bh: buffer head
 *
 * Description: nilfs_cpfile_put_checkpoint() releases the checkpoint
 * specified by @cno. @bh must be the buffer head which has been returned by
 * a previous call to nilfs_cpfile_get_checkpoint() with @cno.
 */
void nilfs_cpfile_put_checkpoint(struct inode *cpfile, __u64 cno,
				 struct buffer_head *bh)
{
	kunmap(bh->b_page);
	brelse(bh);
}

/**
 * nilfs_cpfile_delete_checkpoints - delete checkpoints
 * @cpfile: inode of checkpoint file
 * @start: start checkpoint number
 * @end: end checkpoint numer
 *
 * Description: nilfs_cpfile_delete_checkpoints() deletes the checkpoints in
 * the period from @start to @end, excluding @end itself. The checkpoints
 * which have been already deleted are ignored.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EINVAL - invalid checkpoints.
 */
int nilfs_cpfile_delete_checkpoints(struct inode *cpfile,
				    __u64 start,
				    __u64 end)
{
	struct buffer_head *header_bh, *cp_bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	size_t cpsz = NILFS_MDT(cpfile)->mi_entry_size;
	__u64 cno;
	void *kaddr;
	unsigned long tnicps;
	int ret, ncps, nicps, nss, count, i;

	if (unlikely(start == 0 || start > end)) {
		printk(KERN_ERR "%s: invalid range of checkpoint numbers: "
		       "[%llu, %llu)\n", __func__,
		       (unsigned long long)start, (unsigned long long)end);
		return -EINVAL;
	}

	down_write(&NILFS_MDT(cpfile)->mi_sem);

	ret = nilfs_cpfile_get_header_block(cpfile, &header_bh);
	if (ret < 0)
		goto out_sem;
	tnicps = 0;
	nss = 0;

	for (cno = start; cno < end; cno += ncps) {
		ncps = nilfs_cpfile_checkpoints_in_block(cpfile, cno, end);
		ret = nilfs_cpfile_get_checkpoint_block(cpfile, cno, 0, &cp_bh);
		if (ret < 0) {
			if (ret != -ENOENT)
				break;
			/* skip hole */
			ret = 0;
			continue;
		}

		kaddr = kmap_atomic(cp_bh->b_page);
		cp = nilfs_cpfile_block_get_checkpoint(
			cpfile, cno, cp_bh, kaddr);
		nicps = 0;
		for (i = 0; i < ncps; i++, cp = (void *)cp + cpsz) {
			if (nilfs_checkpoint_snapshot(cp)) {
				nss++;
			} else if (!nilfs_checkpoint_invalid(cp)) {
				nilfs_checkpoint_set_invalid(cp);
				nicps++;
			}
		}
		if (nicps > 0) {
			tnicps += nicps;
			mark_buffer_dirty(cp_bh);
			nilfs_mdt_mark_dirty(cpfile);
			if (!nilfs_cpfile_is_in_first(cpfile, cno)) {
				count =
				  nilfs_cpfile_block_sub_valid_checkpoints(
						cpfile, cp_bh, kaddr, nicps);
				if (count == 0) {
					/* make hole */
					kunmap_atomic(kaddr);
					brelse(cp_bh);
					ret =
					  nilfs_cpfile_delete_checkpoint_block(
								   cpfile, cno);
					if (ret == 0)
						continue;
					printk(KERN_ERR
					       "%s: cannot delete block\n",
					       __func__);
					break;
				}
			}
		}

		kunmap_atomic(kaddr);
		brelse(cp_bh);
	}

	if (tnicps > 0) {
		kaddr = kmap_atomic(header_bh->b_page);
		header = nilfs_cpfile_block_get_header(cpfile, header_bh,
						       kaddr);
		le64_add_cpu(&header->ch_ncheckpoints, -(u64)tnicps);
		mark_buffer_dirty(header_bh);
		nilfs_mdt_mark_dirty(cpfile);
		kunmap_atomic(kaddr);
	}

	brelse(header_bh);
	if (nss > 0)
		ret = -EBUSY;

 out_sem:
	up_write(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

static void nilfs_cpfile_checkpoint_to_cpinfo(struct inode *cpfile,
					      struct nilfs_checkpoint *cp,
					      struct nilfs_cpinfo *ci)
{
	ci->ci_flags = le32_to_cpu(cp->cp_flags);
	ci->ci_cno = le64_to_cpu(cp->cp_cno);
	ci->ci_create = le64_to_cpu(cp->cp_create);
	ci->ci_nblk_inc = le64_to_cpu(cp->cp_nblk_inc);
	ci->ci_inodes_count = le64_to_cpu(cp->cp_inodes_count);
	ci->ci_blocks_count = le64_to_cpu(cp->cp_blocks_count);
	ci->ci_next = le64_to_cpu(cp->cp_snapshot_list.ssl_next);
}

static ssize_t nilfs_cpfile_do_get_cpinfo(struct inode *cpfile, __u64 *cnop,
					  void *buf, unsigned cisz, size_t nci)
{
	struct nilfs_checkpoint *cp;
	struct nilfs_cpinfo *ci = buf;
	struct buffer_head *bh;
	size_t cpsz = NILFS_MDT(cpfile)->mi_entry_size;
	__u64 cur_cno = nilfs_mdt_cno(cpfile), cno = *cnop;
	void *kaddr;
	int n, ret;
	int ncps, i;

	if (cno == 0)
		return -ENOENT; /* checkpoint number 0 is invalid */
	down_read(&NILFS_MDT(cpfile)->mi_sem);

	for (n = 0; cno < cur_cno && n < nci; cno += ncps) {
		ncps = nilfs_cpfile_checkpoints_in_block(cpfile, cno, cur_cno);
		ret = nilfs_cpfile_get_checkpoint_block(cpfile, cno, 0, &bh);
		if (ret < 0) {
			if (ret != -ENOENT)
				goto out;
			continue; /* skip hole */
		}

		kaddr = kmap_atomic(bh->b_page);
		cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, bh, kaddr);
		for (i = 0; i < ncps && n < nci; i++, cp = (void *)cp + cpsz) {
			if (!nilfs_checkpoint_invalid(cp)) {
				nilfs_cpfile_checkpoint_to_cpinfo(cpfile, cp,
								  ci);
				ci = (void *)ci + cisz;
				n++;
			}
		}
		kunmap_atomic(kaddr);
		brelse(bh);
	}

	ret = n;
	if (n > 0) {
		ci = (void *)ci - cisz;
		*cnop = ci->ci_cno + 1;
	}

 out:
	up_read(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

static ssize_t nilfs_cpfile_do_get_ssinfo(struct inode *cpfile, __u64 *cnop,
					  void *buf, unsigned cisz, size_t nci)
{
	struct buffer_head *bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	struct nilfs_cpinfo *ci = buf;
	__u64 curr = *cnop, next;
	unsigned long curr_blkoff, next_blkoff;
	void *kaddr;
	int n = 0, ret;

	down_read(&NILFS_MDT(cpfile)->mi_sem);

	if (curr == 0) {
		ret = nilfs_cpfile_get_header_block(cpfile, &bh);
		if (ret < 0)
			goto out;
		kaddr = kmap_atomic(bh->b_page);
		header = nilfs_cpfile_block_get_header(cpfile, bh, kaddr);
		curr = le64_to_cpu(header->ch_snapshot_list.ssl_next);
		kunmap_atomic(kaddr);
		brelse(bh);
		if (curr == 0) {
			ret = 0;
			goto out;
		}
	} else if (unlikely(curr == ~(__u64)0)) {
		ret = 0;
		goto out;
	}

	curr_blkoff = nilfs_cpfile_get_blkoff(cpfile, curr);
	ret = nilfs_cpfile_get_checkpoint_block(cpfile, curr, 0, &bh);
	if (unlikely(ret < 0)) {
		if (ret == -ENOENT)
			ret = 0; /* No snapshots (started from a hole block) */
		goto out;
	}
	kaddr = kmap_atomic(bh->b_page);
	while (n < nci) {
		cp = nilfs_cpfile_block_get_checkpoint(cpfile, curr, bh, kaddr);
		curr = ~(__u64)0; /* Terminator */
		if (unlikely(nilfs_checkpoint_invalid(cp) ||
			     !nilfs_checkpoint_snapshot(cp)))
			break;
		nilfs_cpfile_checkpoint_to_cpinfo(cpfile, cp, ci);
		ci = (void *)ci + cisz;
		n++;
		next = le64_to_cpu(cp->cp_snapshot_list.ssl_next);
		if (next == 0)
			break; /* reach end of the snapshot list */

		next_blkoff = nilfs_cpfile_get_blkoff(cpfile, next);
		if (curr_blkoff != next_blkoff) {
			kunmap_atomic(kaddr);
			brelse(bh);
			ret = nilfs_cpfile_get_checkpoint_block(cpfile, next,
								0, &bh);
			if (unlikely(ret < 0)) {
				WARN_ON(ret == -ENOENT);
				goto out;
			}
			kaddr = kmap_atomic(bh->b_page);
		}
		curr = next;
		curr_blkoff = next_blkoff;
	}
	kunmap_atomic(kaddr);
	brelse(bh);
	*cnop = curr;
	ret = n;

 out:
	up_read(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_get_cpinfo -
 * @cpfile:
 * @cno:
 * @ci:
 * @nci:
 */

ssize_t nilfs_cpfile_get_cpinfo(struct inode *cpfile, __u64 *cnop, int mode,
				void *buf, unsigned cisz, size_t nci)
{
	switch (mode) {
	case NILFS_CHECKPOINT:
		return nilfs_cpfile_do_get_cpinfo(cpfile, cnop, buf, cisz, nci);
	case NILFS_SNAPSHOT:
		return nilfs_cpfile_do_get_ssinfo(cpfile, cnop, buf, cisz, nci);
	default:
		return -EINVAL;
	}
}

/**
 * nilfs_cpfile_delete_checkpoint -
 * @cpfile:
 * @cno:
 */
int nilfs_cpfile_delete_checkpoint(struct inode *cpfile, __u64 cno)
{
	struct nilfs_cpinfo ci;
	__u64 tcno = cno;
	ssize_t nci;

	nci = nilfs_cpfile_do_get_cpinfo(cpfile, &tcno, &ci, sizeof(ci), 1);
	if (nci < 0)
		return nci;
	else if (nci == 0 || ci.ci_cno != cno)
		return -ENOENT;
	else if (nilfs_cpinfo_snapshot(&ci))
		return -EBUSY;

	return nilfs_cpfile_delete_checkpoints(cpfile, cno, cno + 1);
}

static struct nilfs_snapshot_list *
nilfs_cpfile_block_get_snapshot_list(const struct inode *cpfile,
				     __u64 cno,
				     struct buffer_head *bh,
				     void *kaddr)
{
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	struct nilfs_snapshot_list *list;

	if (cno != 0) {
		cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, bh, kaddr);
		list = &cp->cp_snapshot_list;
	} else {
		header = nilfs_cpfile_block_get_header(cpfile, bh, kaddr);
		list = &header->ch_snapshot_list;
	}
	return list;
}

static int nilfs_cpfile_set_snapshot(struct inode *cpfile, __u64 cno)
{
	struct buffer_head *header_bh, *curr_bh, *prev_bh, *cp_bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	struct nilfs_snapshot_list *list;
	__u64 curr, prev;
	unsigned long curr_blkoff, prev_blkoff;
	void *kaddr;
	int ret;

	if (cno == 0)
		return -ENOENT; /* checkpoint number 0 is invalid */
	down_write(&NILFS_MDT(cpfile)->mi_sem);

	ret = nilfs_cpfile_get_checkpoint_block(cpfile, cno, 0, &cp_bh);
	if (ret < 0)
		goto out_sem;
	kaddr = kmap_atomic(cp_bh->b_page);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	if (nilfs_checkpoint_invalid(cp)) {
		ret = -ENOENT;
		kunmap_atomic(kaddr);
		goto out_cp;
	}
	if (nilfs_checkpoint_snapshot(cp)) {
		ret = 0;
		kunmap_atomic(kaddr);
		goto out_cp;
	}
	kunmap_atomic(kaddr);

	ret = nilfs_cpfile_get_header_block(cpfile, &header_bh);
	if (ret < 0)
		goto out_cp;
	kaddr = kmap_atomic(header_bh->b_page);
	header = nilfs_cpfile_block_get_header(cpfile, header_bh, kaddr);
	list = &header->ch_snapshot_list;
	curr_bh = header_bh;
	get_bh(curr_bh);
	curr = 0;
	curr_blkoff = 0;
	prev = le64_to_cpu(list->ssl_prev);
	while (prev > cno) {
		prev_blkoff = nilfs_cpfile_get_blkoff(cpfile, prev);
		curr = prev;
		if (curr_blkoff != prev_blkoff) {
			kunmap_atomic(kaddr);
			brelse(curr_bh);
			ret = nilfs_cpfile_get_checkpoint_block(cpfile, curr,
								0, &curr_bh);
			if (ret < 0)
				goto out_header;
			kaddr = kmap_atomic(curr_bh->b_page);
		}
		curr_blkoff = prev_blkoff;
		cp = nilfs_cpfile_block_get_checkpoint(
			cpfile, curr, curr_bh, kaddr);
		list = &cp->cp_snapshot_list;
		prev = le64_to_cpu(list->ssl_prev);
	}
	kunmap_atomic(kaddr);

	if (prev != 0) {
		ret = nilfs_cpfile_get_checkpoint_block(cpfile, prev, 0,
							&prev_bh);
		if (ret < 0)
			goto out_curr;
	} else {
		prev_bh = header_bh;
		get_bh(prev_bh);
	}

	kaddr = kmap_atomic(curr_bh->b_page);
	list = nilfs_cpfile_block_get_snapshot_list(
		cpfile, curr, curr_bh, kaddr);
	list->ssl_prev = cpu_to_le64(cno);
	kunmap_atomic(kaddr);

	kaddr = kmap_atomic(cp_bh->b_page);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	cp->cp_snapshot_list.ssl_next = cpu_to_le64(curr);
	cp->cp_snapshot_list.ssl_prev = cpu_to_le64(prev);
	nilfs_checkpoint_set_snapshot(cp);
	kunmap_atomic(kaddr);

	kaddr = kmap_atomic(prev_bh->b_page);
	list = nilfs_cpfile_block_get_snapshot_list(
		cpfile, prev, prev_bh, kaddr);
	list->ssl_next = cpu_to_le64(cno);
	kunmap_atomic(kaddr);

	kaddr = kmap_atomic(header_bh->b_page);
	header = nilfs_cpfile_block_get_header(cpfile, header_bh, kaddr);
	le64_add_cpu(&header->ch_nsnapshots, 1);
	kunmap_atomic(kaddr);

	mark_buffer_dirty(prev_bh);
	mark_buffer_dirty(curr_bh);
	mark_buffer_dirty(cp_bh);
	mark_buffer_dirty(header_bh);
	nilfs_mdt_mark_dirty(cpfile);

	brelse(prev_bh);

 out_curr:
	brelse(curr_bh);

 out_header:
	brelse(header_bh);

 out_cp:
	brelse(cp_bh);

 out_sem:
	up_write(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

static int nilfs_cpfile_clear_snapshot(struct inode *cpfile, __u64 cno)
{
	struct buffer_head *header_bh, *next_bh, *prev_bh, *cp_bh;
	struct nilfs_cpfile_header *header;
	struct nilfs_checkpoint *cp;
	struct nilfs_snapshot_list *list;
	__u64 next, prev;
	void *kaddr;
	int ret;

	if (cno == 0)
		return -ENOENT; /* checkpoint number 0 is invalid */
	down_write(&NILFS_MDT(cpfile)->mi_sem);

	ret = nilfs_cpfile_get_checkpoint_block(cpfile, cno, 0, &cp_bh);
	if (ret < 0)
		goto out_sem;
	kaddr = kmap_atomic(cp_bh->b_page);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	if (nilfs_checkpoint_invalid(cp)) {
		ret = -ENOENT;
		kunmap_atomic(kaddr);
		goto out_cp;
	}
	if (!nilfs_checkpoint_snapshot(cp)) {
		ret = 0;
		kunmap_atomic(kaddr);
		goto out_cp;
	}

	list = &cp->cp_snapshot_list;
	next = le64_to_cpu(list->ssl_next);
	prev = le64_to_cpu(list->ssl_prev);
	kunmap_atomic(kaddr);

	ret = nilfs_cpfile_get_header_block(cpfile, &header_bh);
	if (ret < 0)
		goto out_cp;
	if (next != 0) {
		ret = nilfs_cpfile_get_checkpoint_block(cpfile, next, 0,
							&next_bh);
		if (ret < 0)
			goto out_header;
	} else {
		next_bh = header_bh;
		get_bh(next_bh);
	}
	if (prev != 0) {
		ret = nilfs_cpfile_get_checkpoint_block(cpfile, prev, 0,
							&prev_bh);
		if (ret < 0)
			goto out_next;
	} else {
		prev_bh = header_bh;
		get_bh(prev_bh);
	}

	kaddr = kmap_atomic(next_bh->b_page);
	list = nilfs_cpfile_block_get_snapshot_list(
		cpfile, next, next_bh, kaddr);
	list->ssl_prev = cpu_to_le64(prev);
	kunmap_atomic(kaddr);

	kaddr = kmap_atomic(prev_bh->b_page);
	list = nilfs_cpfile_block_get_snapshot_list(
		cpfile, prev, prev_bh, kaddr);
	list->ssl_next = cpu_to_le64(next);
	kunmap_atomic(kaddr);

	kaddr = kmap_atomic(cp_bh->b_page);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, cp_bh, kaddr);
	cp->cp_snapshot_list.ssl_next = cpu_to_le64(0);
	cp->cp_snapshot_list.ssl_prev = cpu_to_le64(0);
	nilfs_checkpoint_clear_snapshot(cp);
	kunmap_atomic(kaddr);

	kaddr = kmap_atomic(header_bh->b_page);
	header = nilfs_cpfile_block_get_header(cpfile, header_bh, kaddr);
	le64_add_cpu(&header->ch_nsnapshots, -1);
	kunmap_atomic(kaddr);

	mark_buffer_dirty(next_bh);
	mark_buffer_dirty(prev_bh);
	mark_buffer_dirty(cp_bh);
	mark_buffer_dirty(header_bh);
	nilfs_mdt_mark_dirty(cpfile);

	brelse(prev_bh);

 out_next:
	brelse(next_bh);

 out_header:
	brelse(header_bh);

 out_cp:
	brelse(cp_bh);

 out_sem:
	up_write(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_is_snapshot -
 * @cpfile: inode of checkpoint file
 * @cno: checkpoint number
 *
 * Description:
 *
 * Return Value: On success, 1 is returned if the checkpoint specified by
 * @cno is a snapshot, or 0 if not. On error, one of the following negative
 * error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - No such checkpoint.
 */
int nilfs_cpfile_is_snapshot(struct inode *cpfile, __u64 cno)
{
	struct buffer_head *bh;
	struct nilfs_checkpoint *cp;
	void *kaddr;
	int ret;

	/* CP number is invalid if it's zero or larger than the
	largest	exist one.*/
	if (cno == 0 || cno >= nilfs_mdt_cno(cpfile))
		return -ENOENT;
	down_read(&NILFS_MDT(cpfile)->mi_sem);

	ret = nilfs_cpfile_get_checkpoint_block(cpfile, cno, 0, &bh);
	if (ret < 0)
		goto out;
	kaddr = kmap_atomic(bh->b_page);
	cp = nilfs_cpfile_block_get_checkpoint(cpfile, cno, bh, kaddr);
	if (nilfs_checkpoint_invalid(cp))
		ret = -ENOENT;
	else
		ret = nilfs_checkpoint_snapshot(cp);
	kunmap_atomic(kaddr);
	brelse(bh);

 out:
	up_read(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_change_cpmode - change checkpoint mode
 * @cpfile: inode of checkpoint file
 * @cno: checkpoint number
 * @status: mode of checkpoint
 *
 * Description: nilfs_change_cpmode() changes the mode of the checkpoint
 * specified by @cno. The mode @mode is NILFS_CHECKPOINT or NILFS_SNAPSHOT.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - No such checkpoint.
 */
int nilfs_cpfile_change_cpmode(struct inode *cpfile, __u64 cno, int mode)
{
	int ret;

	switch (mode) {
	case NILFS_CHECKPOINT:
		if (nilfs_checkpoint_is_mounted(cpfile->i_sb, cno))
			/*
			 * Current implementation does not have to protect
			 * plain read-only mounts since they are exclusive
			 * with a read/write mount and are protected from the
			 * cleaner.
			 */
			ret = -EBUSY;
		else
			ret = nilfs_cpfile_clear_snapshot(cpfile, cno);
		return ret;
	case NILFS_SNAPSHOT:
		return nilfs_cpfile_set_snapshot(cpfile, cno);
	default:
		return -EINVAL;
	}
}

/**
 * nilfs_cpfile_get_stat - get checkpoint statistics
 * @cpfile: inode of checkpoint file
 * @stat: pointer to a structure of checkpoint statistics
 *
 * Description: nilfs_cpfile_get_stat() returns information about checkpoints.
 *
 * Return Value: On success, 0 is returned, and checkpoints information is
 * stored in the place pointed by @stat. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_cpfile_get_stat(struct inode *cpfile, struct nilfs_cpstat *cpstat)
{
	struct buffer_head *bh;
	struct nilfs_cpfile_header *header;
	void *kaddr;
	int ret;

	down_read(&NILFS_MDT(cpfile)->mi_sem);

	ret = nilfs_cpfile_get_header_block(cpfile, &bh);
	if (ret < 0)
		goto out_sem;
	kaddr = kmap_atomic(bh->b_page);
	header = nilfs_cpfile_block_get_header(cpfile, bh, kaddr);
	cpstat->cs_cno = nilfs_mdt_cno(cpfile);
	cpstat->cs_ncps = le64_to_cpu(header->ch_ncheckpoints);
	cpstat->cs_nsss = le64_to_cpu(header->ch_nsnapshots);
	kunmap_atomic(kaddr);
	brelse(bh);

 out_sem:
	up_read(&NILFS_MDT(cpfile)->mi_sem);
	return ret;
}

/**
 * nilfs_cpfile_read - read or get cpfile inode
 * @sb: super block instance
 * @cpsize: size of a checkpoint entry
 * @raw_inode: on-disk cpfile inode
 * @inodep: buffer to store the inode
 */
int nilfs_cpfile_read(struct super_block *sb, size_t cpsize,
		      struct nilfs_inode *raw_inode, struct inode **inodep)
{
	struct inode *cpfile;
	int err;

	if (cpsize > sb->s_blocksize) {
		printk(KERN_ERR
		       "NILFS: too large checkpoint size: %zu bytes.\n",
		       cpsize);
		return -EINVAL;
	} else if (cpsize < NILFS_MIN_CHECKPOINT_SIZE) {
		printk(KERN_ERR
		       "NILFS: too small checkpoint size: %zu bytes.\n",
		       cpsize);
		return -EINVAL;
	}

	cpfile = nilfs_iget_locked(sb, NULL, NILFS_CPFILE_INO);
	if (unlikely(!cpfile))
		return -ENOMEM;
	if (!(cpfile->i_state & I_NEW))
		goto out;

	err = nilfs_mdt_init(cpfile, NILFS_MDT_GFP, 0);
	if (err)
		goto failed;

	nilfs_mdt_set_entry_size(cpfile, cpsize,
				 sizeof(struct nilfs_cpfile_header));

	err = nilfs_read_inode_common(cpfile, raw_inode);
	if (err)
		goto failed;

	unlock_new_inode(cpfile);
 out:
	*inodep = cpfile;
	return 0;
 failed:
	iget_failed(cpfile);
	return err;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/cpfile.c */
/************************************************************/
/*
 * sufile.c - NILFS segment usage file.
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Koji Sato <koji@osrg.net>.
 * Revised by Ryusuke Konishi <ryusuke@osrg.net>.
 */

// #include <linux/kernel.h>
// #include <linux/fs.h>
// #include <linux/string.h>
// #include <linux/buffer_head.h>
// #include <linux/errno.h>
// #include <linux/nilfs2_fs.h>
// #include "mdt.h"
// #include "sufile.h"

/**
 * struct nilfs_sufile_info - on-memory private data of sufile
 * @mi: on-memory private data of metadata file
 * @ncleansegs: number of clean segments
 * @allocmin: lower limit of allocatable segment range
 * @allocmax: upper limit of allocatable segment range
 */
struct nilfs_sufile_info {
	struct nilfs_mdt_info mi;
	unsigned long ncleansegs;/* number of clean segments */
	__u64 allocmin;		/* lower limit of allocatable segment range */
	__u64 allocmax;		/* upper limit of allocatable segment range */
};

static inline struct nilfs_sufile_info *NILFS_SUI(struct inode *sufile)
{
	return (struct nilfs_sufile_info *)NILFS_MDT(sufile);
}

static inline unsigned long
nilfs_sufile_segment_usages_per_block(const struct inode *sufile)
{
	return NILFS_MDT(sufile)->mi_entries_per_block;
}

static unsigned long
nilfs_sufile_get_blkoff(const struct inode *sufile, __u64 segnum)
{
	__u64 t = segnum + NILFS_MDT(sufile)->mi_first_entry_offset;
	do_div(t, nilfs_sufile_segment_usages_per_block(sufile));
	return (unsigned long)t;
}

static unsigned long
nilfs_sufile_get_offset(const struct inode *sufile, __u64 segnum)
{
	__u64 t = segnum + NILFS_MDT(sufile)->mi_first_entry_offset;
	return do_div(t, nilfs_sufile_segment_usages_per_block(sufile));
}

static unsigned long
nilfs_sufile_segment_usages_in_block(const struct inode *sufile, __u64 curr,
				     __u64 max)
{
	return min_t(unsigned long,
		     nilfs_sufile_segment_usages_per_block(sufile) -
		     nilfs_sufile_get_offset(sufile, curr),
		     max - curr + 1);
}

static struct nilfs_segment_usage *
nilfs_sufile_block_get_segment_usage(const struct inode *sufile, __u64 segnum,
				     struct buffer_head *bh, void *kaddr)
{
	return kaddr + bh_offset(bh) +
		nilfs_sufile_get_offset(sufile, segnum) *
		NILFS_MDT(sufile)->mi_entry_size;
}

static inline int nilfs_sufile_get_header_block(struct inode *sufile,
						struct buffer_head **bhp)
{
	return nilfs_mdt_get_block(sufile, 0, 0, NULL, bhp);
}

static inline int
nilfs_sufile_get_segment_usage_block(struct inode *sufile, __u64 segnum,
				     int create, struct buffer_head **bhp)
{
	return nilfs_mdt_get_block(sufile,
				   nilfs_sufile_get_blkoff(sufile, segnum),
				   create, NULL, bhp);
}

static int nilfs_sufile_delete_segment_usage_block(struct inode *sufile,
						   __u64 segnum)
{
	return nilfs_mdt_delete_block(sufile,
				      nilfs_sufile_get_blkoff(sufile, segnum));
}

static void nilfs_sufile_mod_counter(struct buffer_head *header_bh,
				     u64 ncleanadd, u64 ndirtyadd)
{
	struct nilfs_sufile_header *header;
	void *kaddr;

	kaddr = kmap_atomic(header_bh->b_page);
	header = kaddr + bh_offset(header_bh);
	le64_add_cpu(&header->sh_ncleansegs, ncleanadd);
	le64_add_cpu(&header->sh_ndirtysegs, ndirtyadd);
	kunmap_atomic(kaddr);

	mark_buffer_dirty(header_bh);
}

/**
 * nilfs_sufile_get_ncleansegs - return the number of clean segments
 * @sufile: inode of segment usage file
 */
unsigned long nilfs_sufile_get_ncleansegs(struct inode *sufile)
{
	return NILFS_SUI(sufile)->ncleansegs;
}

/**
 * nilfs_sufile_updatev - modify multiple segment usages at a time
 * @sufile: inode of segment usage file
 * @segnumv: array of segment numbers
 * @nsegs: size of @segnumv array
 * @create: creation flag
 * @ndone: place to store number of modified segments on @segnumv
 * @dofunc: primitive operation for the update
 *
 * Description: nilfs_sufile_updatev() repeatedly calls @dofunc
 * against the given array of segments.  The @dofunc is called with
 * buffers of a header block and the sufile block in which the target
 * segment usage entry is contained.  If @ndone is given, the number
 * of successfully modified segments from the head is stored in the
 * place @ndone points to.
 *
 * Return Value: On success, zero is returned.  On error, one of the
 * following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - Given segment usage is in hole block (may be returned if
 *            @create is zero)
 *
 * %-EINVAL - Invalid segment usage number
 */
int nilfs_sufile_updatev(struct inode *sufile, __u64 *segnumv, size_t nsegs,
			 int create, size_t *ndone,
			 void (*dofunc)(struct inode *, __u64,
					struct buffer_head *,
					struct buffer_head *))
{
	struct buffer_head *header_bh, *bh;
	unsigned long blkoff, prev_blkoff;
	__u64 *seg;
	size_t nerr = 0, n = 0;
	int ret = 0;

	if (unlikely(nsegs == 0))
		goto out;

	down_write(&NILFS_MDT(sufile)->mi_sem);
	for (seg = segnumv; seg < segnumv + nsegs; seg++) {
		if (unlikely(*seg >= nilfs_sufile_get_nsegments(sufile))) {
			printk(KERN_WARNING
			       "%s: invalid segment number: %llu\n", __func__,
			       (unsigned long long)*seg);
			nerr++;
		}
	}
	if (nerr > 0) {
		ret = -EINVAL;
		goto out_sem;
	}

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_sem;

	seg = segnumv;
	blkoff = nilfs_sufile_get_blkoff(sufile, *seg);
	ret = nilfs_mdt_get_block(sufile, blkoff, create, NULL, &bh);
	if (ret < 0)
		goto out_header;

	for (;;) {
		dofunc(sufile, *seg, header_bh, bh);

		if (++seg >= segnumv + nsegs)
			break;
		prev_blkoff = blkoff;
		blkoff = nilfs_sufile_get_blkoff(sufile, *seg);
		if (blkoff == prev_blkoff)
			continue;

		/* get different block */
		brelse(bh);
		ret = nilfs_mdt_get_block(sufile, blkoff, create, NULL, &bh);
		if (unlikely(ret < 0))
			goto out_header;
	}
	brelse(bh);

 out_header:
	n = seg - segnumv;
	brelse(header_bh);
 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
 out:
	if (ndone)
		*ndone = n;
	return ret;
}

int nilfs_sufile_update(struct inode *sufile, __u64 segnum, int create,
			void (*dofunc)(struct inode *, __u64,
				       struct buffer_head *,
				       struct buffer_head *))
{
	struct buffer_head *header_bh, *bh;
	int ret;

	if (unlikely(segnum >= nilfs_sufile_get_nsegments(sufile))) {
		printk(KERN_WARNING "%s: invalid segment number: %llu\n",
		       __func__, (unsigned long long)segnum);
		return -EINVAL;
	}
	down_write(&NILFS_MDT(sufile)->mi_sem);

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_sem;

	ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, create, &bh);
	if (!ret) {
		dofunc(sufile, segnum, header_bh, bh);
		brelse(bh);
	}
	brelse(header_bh);

 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_set_alloc_range - limit range of segment to be allocated
 * @sufile: inode of segment usage file
 * @start: minimum segment number of allocatable region (inclusive)
 * @end: maximum segment number of allocatable region (inclusive)
 *
 * Return Value: On success, 0 is returned.  On error, one of the
 * following negative error codes is returned.
 *
 * %-ERANGE - invalid segment region
 */
int nilfs_sufile_set_alloc_range(struct inode *sufile, __u64 start, __u64 end)
{
	struct nilfs_sufile_info *sui = NILFS_SUI(sufile);
	__u64 nsegs;
	int ret = -ERANGE;

	down_write(&NILFS_MDT(sufile)->mi_sem);
	nsegs = nilfs_sufile_get_nsegments(sufile);

	if (start <= end && end < nsegs) {
		sui->allocmin = start;
		sui->allocmax = end;
		ret = 0;
	}
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_alloc - allocate a segment
 * @sufile: inode of segment usage file
 * @segnump: pointer to segment number
 *
 * Description: nilfs_sufile_alloc() allocates a clean segment.
 *
 * Return Value: On success, 0 is returned and the segment number of the
 * allocated segment is stored in the place pointed by @segnump. On error, one
 * of the following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOSPC - No clean segment left.
 */
int nilfs_sufile_alloc(struct inode *sufile, __u64 *segnump)
{
	struct buffer_head *header_bh, *su_bh;
	struct nilfs_sufile_header *header;
	struct nilfs_segment_usage *su;
	struct nilfs_sufile_info *sui = NILFS_SUI(sufile);
	size_t susz = NILFS_MDT(sufile)->mi_entry_size;
	__u64 segnum, maxsegnum, last_alloc;
	void *kaddr;
	unsigned long nsegments, ncleansegs, nsus, cnt;
	int ret, j;

	down_write(&NILFS_MDT(sufile)->mi_sem);

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_sem;
	kaddr = kmap_atomic(header_bh->b_page);
	header = kaddr + bh_offset(header_bh);
	ncleansegs = le64_to_cpu(header->sh_ncleansegs);
	last_alloc = le64_to_cpu(header->sh_last_alloc);
	kunmap_atomic(kaddr);

	nsegments = nilfs_sufile_get_nsegments(sufile);
	maxsegnum = sui->allocmax;
	segnum = last_alloc + 1;
	if (segnum < sui->allocmin || segnum > sui->allocmax)
		segnum = sui->allocmin;

	for (cnt = 0; cnt < nsegments; cnt += nsus) {
		if (segnum > maxsegnum) {
			if (cnt < sui->allocmax - sui->allocmin + 1) {
				/*
				 * wrap around in the limited region.
				 * if allocation started from
				 * sui->allocmin, this never happens.
				 */
				segnum = sui->allocmin;
				maxsegnum = last_alloc;
			} else if (segnum > sui->allocmin &&
				   sui->allocmax + 1 < nsegments) {
				segnum = sui->allocmax + 1;
				maxsegnum = nsegments - 1;
			} else if (sui->allocmin > 0)  {
				segnum = 0;
				maxsegnum = sui->allocmin - 1;
			} else {
				break; /* never happens */
			}
		}
		ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 1,
							   &su_bh);
		if (ret < 0)
			goto out_header;
		kaddr = kmap_atomic(su_bh->b_page);
		su = nilfs_sufile_block_get_segment_usage(
			sufile, segnum, su_bh, kaddr);

		nsus = nilfs_sufile_segment_usages_in_block(
			sufile, segnum, maxsegnum);
		for (j = 0; j < nsus; j++, su = (void *)su + susz, segnum++) {
			if (!nilfs_segment_usage_clean(su))
				continue;
			/* found a clean segment */
			nilfs_segment_usage_set_dirty(su);
			kunmap_atomic(kaddr);

			kaddr = kmap_atomic(header_bh->b_page);
			header = kaddr + bh_offset(header_bh);
			le64_add_cpu(&header->sh_ncleansegs, -1);
			le64_add_cpu(&header->sh_ndirtysegs, 1);
			header->sh_last_alloc = cpu_to_le64(segnum);
			kunmap_atomic(kaddr);

			sui->ncleansegs--;
			mark_buffer_dirty(header_bh);
			mark_buffer_dirty(su_bh);
			nilfs_mdt_mark_dirty(sufile);
			brelse(su_bh);
			*segnump = segnum;
			goto out_header;
		}

		kunmap_atomic(kaddr);
		brelse(su_bh);
	}

	/* no segments left */
	ret = -ENOSPC;

 out_header:
	brelse(header_bh);

 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

void nilfs_sufile_do_cancel_free(struct inode *sufile, __u64 segnum,
				 struct buffer_head *header_bh,
				 struct buffer_head *su_bh)
{
	struct nilfs_segment_usage *su;
	void *kaddr;

	kaddr = kmap_atomic(su_bh->b_page);
	su = nilfs_sufile_block_get_segment_usage(sufile, segnum, su_bh, kaddr);
	if (unlikely(!nilfs_segment_usage_clean(su))) {
		printk(KERN_WARNING "%s: segment %llu must be clean\n",
		       __func__, (unsigned long long)segnum);
		kunmap_atomic(kaddr);
		return;
	}
	nilfs_segment_usage_set_dirty(su);
	kunmap_atomic(kaddr);

	nilfs_sufile_mod_counter(header_bh, -1, 1);
	NILFS_SUI(sufile)->ncleansegs--;

	mark_buffer_dirty(su_bh);
	nilfs_mdt_mark_dirty(sufile);
}

void nilfs_sufile_do_scrap(struct inode *sufile, __u64 segnum,
			   struct buffer_head *header_bh,
			   struct buffer_head *su_bh)
{
	struct nilfs_segment_usage *su;
	void *kaddr;
	int clean, dirty;

	kaddr = kmap_atomic(su_bh->b_page);
	su = nilfs_sufile_block_get_segment_usage(sufile, segnum, su_bh, kaddr);
	if (su->su_flags == cpu_to_le32(1UL << NILFS_SEGMENT_USAGE_DIRTY) &&
	    su->su_nblocks == cpu_to_le32(0)) {
		kunmap_atomic(kaddr);
		return;
	}
	clean = nilfs_segment_usage_clean(su);
	dirty = nilfs_segment_usage_dirty(su);

	/* make the segment garbage */
	su->su_lastmod = cpu_to_le64(0);
	su->su_nblocks = cpu_to_le32(0);
	su->su_flags = cpu_to_le32(1UL << NILFS_SEGMENT_USAGE_DIRTY);
	kunmap_atomic(kaddr);

	nilfs_sufile_mod_counter(header_bh, clean ? (u64)-1 : 0, dirty ? 0 : 1);
	NILFS_SUI(sufile)->ncleansegs -= clean;

	mark_buffer_dirty(su_bh);
	nilfs_mdt_mark_dirty(sufile);
}

void nilfs_sufile_do_free(struct inode *sufile, __u64 segnum,
			  struct buffer_head *header_bh,
			  struct buffer_head *su_bh)
{
	struct nilfs_segment_usage *su;
	void *kaddr;
	int sudirty;

	kaddr = kmap_atomic(su_bh->b_page);
	su = nilfs_sufile_block_get_segment_usage(sufile, segnum, su_bh, kaddr);
	if (nilfs_segment_usage_clean(su)) {
		printk(KERN_WARNING "%s: segment %llu is already clean\n",
		       __func__, (unsigned long long)segnum);
		kunmap_atomic(kaddr);
		return;
	}
	WARN_ON(nilfs_segment_usage_error(su));
	WARN_ON(!nilfs_segment_usage_dirty(su));

	sudirty = nilfs_segment_usage_dirty(su);
	nilfs_segment_usage_set_clean(su);
	kunmap_atomic(kaddr);
	mark_buffer_dirty(su_bh);

	nilfs_sufile_mod_counter(header_bh, 1, sudirty ? (u64)-1 : 0);
	NILFS_SUI(sufile)->ncleansegs++;

	nilfs_mdt_mark_dirty(sufile);
}

/**
 * nilfs_sufile_mark_dirty - mark the buffer having a segment usage dirty
 * @sufile: inode of segment usage file
 * @segnum: segment number
 */
int nilfs_sufile_mark_dirty(struct inode *sufile, __u64 segnum)
{
	struct buffer_head *bh;
	int ret;

	ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 0, &bh);
	if (!ret) {
		mark_buffer_dirty(bh);
		nilfs_mdt_mark_dirty(sufile);
		brelse(bh);
	}
	return ret;
}

/**
 * nilfs_sufile_set_segment_usage - set usage of a segment
 * @sufile: inode of segment usage file
 * @segnum: segment number
 * @nblocks: number of live blocks in the segment
 * @modtime: modification time (option)
 */
int nilfs_sufile_set_segment_usage(struct inode *sufile, __u64 segnum,
				   unsigned long nblocks, time_t modtime)
{
	struct buffer_head *bh;
	struct nilfs_segment_usage *su;
	void *kaddr;
	int ret;

	down_write(&NILFS_MDT(sufile)->mi_sem);
	ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 0, &bh);
	if (ret < 0)
		goto out_sem;

	kaddr = kmap_atomic(bh->b_page);
	su = nilfs_sufile_block_get_segment_usage(sufile, segnum, bh, kaddr);
	WARN_ON(nilfs_segment_usage_error(su));
	if (modtime)
		su->su_lastmod = cpu_to_le64(modtime);
	su->su_nblocks = cpu_to_le32(nblocks);
	kunmap_atomic(kaddr);

	mark_buffer_dirty(bh);
	nilfs_mdt_mark_dirty(sufile);
	brelse(bh);

 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_get_stat - get segment usage statistics
 * @sufile: inode of segment usage file
 * @stat: pointer to a structure of segment usage statistics
 *
 * Description: nilfs_sufile_get_stat() returns information about segment
 * usage.
 *
 * Return Value: On success, 0 is returned, and segment usage information is
 * stored in the place pointed by @stat. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_sufile_get_stat(struct inode *sufile, struct nilfs_sustat *sustat)
{
	struct buffer_head *header_bh;
	struct nilfs_sufile_header *header;
	struct the_nilfs *nilfs = sufile->i_sb->s_fs_info;
	void *kaddr;
	int ret;

	down_read(&NILFS_MDT(sufile)->mi_sem);

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_sem;

	kaddr = kmap_atomic(header_bh->b_page);
	header = kaddr + bh_offset(header_bh);
	sustat->ss_nsegs = nilfs_sufile_get_nsegments(sufile);
	sustat->ss_ncleansegs = le64_to_cpu(header->sh_ncleansegs);
	sustat->ss_ndirtysegs = le64_to_cpu(header->sh_ndirtysegs);
	sustat->ss_ctime = nilfs->ns_ctime;
	sustat->ss_nongc_ctime = nilfs->ns_nongc_ctime;
	spin_lock(&nilfs->ns_last_segment_lock);
	sustat->ss_prot_seq = nilfs->ns_prot_seq;
	spin_unlock(&nilfs->ns_last_segment_lock);
	kunmap_atomic(kaddr);
	brelse(header_bh);

 out_sem:
	up_read(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

void nilfs_sufile_do_set_error(struct inode *sufile, __u64 segnum,
			       struct buffer_head *header_bh,
			       struct buffer_head *su_bh)
{
	struct nilfs_segment_usage *su;
	void *kaddr;
	int suclean;

	kaddr = kmap_atomic(su_bh->b_page);
	su = nilfs_sufile_block_get_segment_usage(sufile, segnum, su_bh, kaddr);
	if (nilfs_segment_usage_error(su)) {
		kunmap_atomic(kaddr);
		return;
	}
	suclean = nilfs_segment_usage_clean(su);
	nilfs_segment_usage_set_error(su);
	kunmap_atomic(kaddr);

	if (suclean) {
		nilfs_sufile_mod_counter(header_bh, -1, 0);
		NILFS_SUI(sufile)->ncleansegs--;
	}
	mark_buffer_dirty(su_bh);
	nilfs_mdt_mark_dirty(sufile);
}

/**
  * nilfs_sufile_truncate_range - truncate range of segment array
  * @sufile: inode of segment usage file
  * @start: start segment number (inclusive)
  * @end: end segment number (inclusive)
  *
  * Return Value: On success, 0 is returned.  On error, one of the
  * following negative error codes is returned.
  *
  * %-EIO - I/O error.
  *
  * %-ENOMEM - Insufficient amount of memory available.
  *
  * %-EINVAL - Invalid number of segments specified
  *
  * %-EBUSY - Dirty or active segments are present in the range
  */
static int nilfs_sufile_truncate_range(struct inode *sufile,
				       __u64 start, __u64 end)
{
	struct the_nilfs *nilfs = sufile->i_sb->s_fs_info;
	struct buffer_head *header_bh;
	struct buffer_head *su_bh;
	struct nilfs_segment_usage *su, *su2;
	size_t susz = NILFS_MDT(sufile)->mi_entry_size;
	unsigned long segusages_per_block;
	unsigned long nsegs, ncleaned;
	__u64 segnum;
	void *kaddr;
	ssize_t n, nc;
	int ret;
	int j;

	nsegs = nilfs_sufile_get_nsegments(sufile);

	ret = -EINVAL;
	if (start > end || start >= nsegs)
		goto out;

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out;

	segusages_per_block = nilfs_sufile_segment_usages_per_block(sufile);
	ncleaned = 0;

	for (segnum = start; segnum <= end; segnum += n) {
		n = min_t(unsigned long,
			  segusages_per_block -
				  nilfs_sufile_get_offset(sufile, segnum),
			  end - segnum + 1);
		ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 0,
							   &su_bh);
		if (ret < 0) {
			if (ret != -ENOENT)
				goto out_header;
			/* hole */
			continue;
		}
		kaddr = kmap_atomic(su_bh->b_page);
		su = nilfs_sufile_block_get_segment_usage(
			sufile, segnum, su_bh, kaddr);
		su2 = su;
		for (j = 0; j < n; j++, su = (void *)su + susz) {
			if ((le32_to_cpu(su->su_flags) &
			     ~(1UL << NILFS_SEGMENT_USAGE_ERROR)) ||
			    nilfs_segment_is_active(nilfs, segnum + j)) {
				ret = -EBUSY;
				kunmap_atomic(kaddr);
				brelse(su_bh);
				goto out_header;
			}
		}
		nc = 0;
		for (su = su2, j = 0; j < n; j++, su = (void *)su + susz) {
			if (nilfs_segment_usage_error(su)) {
				nilfs_segment_usage_set_clean(su);
				nc++;
			}
		}
		kunmap_atomic(kaddr);
		if (nc > 0) {
			mark_buffer_dirty(su_bh);
			ncleaned += nc;
		}
		brelse(su_bh);

		if (n == segusages_per_block) {
			/* make hole */
			nilfs_sufile_delete_segment_usage_block(sufile, segnum);
		}
	}
	ret = 0;

out_header:
	if (ncleaned > 0) {
		NILFS_SUI(sufile)->ncleansegs += ncleaned;
		nilfs_sufile_mod_counter(header_bh, ncleaned, 0);
		nilfs_mdt_mark_dirty(sufile);
	}
	brelse(header_bh);
out:
	return ret;
}

/**
 * nilfs_sufile_resize - resize segment array
 * @sufile: inode of segment usage file
 * @newnsegs: new number of segments
 *
 * Return Value: On success, 0 is returned.  On error, one of the
 * following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOSPC - Enough free space is not left for shrinking
 *
 * %-EBUSY - Dirty or active segments exist in the region to be truncated
 */
int nilfs_sufile_resize(struct inode *sufile, __u64 newnsegs)
{
	struct the_nilfs *nilfs = sufile->i_sb->s_fs_info;
	struct buffer_head *header_bh;
	struct nilfs_sufile_header *header;
	struct nilfs_sufile_info *sui = NILFS_SUI(sufile);
	void *kaddr;
	unsigned long nsegs, nrsvsegs;
	int ret = 0;

	down_write(&NILFS_MDT(sufile)->mi_sem);

	nsegs = nilfs_sufile_get_nsegments(sufile);
	if (nsegs == newnsegs)
		goto out;

	ret = -ENOSPC;
	nrsvsegs = nilfs_nrsvsegs(nilfs, newnsegs);
	if (newnsegs < nsegs && nsegs - newnsegs + nrsvsegs > sui->ncleansegs)
		goto out;

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out;

	if (newnsegs > nsegs) {
		sui->ncleansegs += newnsegs - nsegs;
	} else /* newnsegs < nsegs */ {
		ret = nilfs_sufile_truncate_range(sufile, newnsegs, nsegs - 1);
		if (ret < 0)
			goto out_header;

		sui->ncleansegs -= nsegs - newnsegs;
	}

	kaddr = kmap_atomic(header_bh->b_page);
	header = kaddr + bh_offset(header_bh);
	header->sh_ncleansegs = cpu_to_le64(sui->ncleansegs);
	kunmap_atomic(kaddr);

	mark_buffer_dirty(header_bh);
	nilfs_mdt_mark_dirty(sufile);
	nilfs_set_nsegments(nilfs, newnsegs);

out_header:
	brelse(header_bh);
out:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_get_suinfo -
 * @sufile: inode of segment usage file
 * @segnum: segment number to start looking
 * @buf: array of suinfo
 * @sisz: byte size of suinfo
 * @nsi: size of suinfo array
 *
 * Description:
 *
 * Return Value: On success, 0 is returned and .... On error, one of the
 * following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
ssize_t nilfs_sufile_get_suinfo(struct inode *sufile, __u64 segnum, void *buf,
				unsigned sisz, size_t nsi)
{
	struct buffer_head *su_bh;
	struct nilfs_segment_usage *su;
	struct nilfs_suinfo *si = buf;
	size_t susz = NILFS_MDT(sufile)->mi_entry_size;
	struct the_nilfs *nilfs = sufile->i_sb->s_fs_info;
	void *kaddr;
	unsigned long nsegs, segusages_per_block;
	ssize_t n;
	int ret, i, j;

	down_read(&NILFS_MDT(sufile)->mi_sem);

	segusages_per_block = nilfs_sufile_segment_usages_per_block(sufile);
	nsegs = min_t(unsigned long,
		      nilfs_sufile_get_nsegments(sufile) - segnum,
		      nsi);
	for (i = 0; i < nsegs; i += n, segnum += n) {
		n = min_t(unsigned long,
			  segusages_per_block -
				  nilfs_sufile_get_offset(sufile, segnum),
			  nsegs - i);
		ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 0,
							   &su_bh);
		if (ret < 0) {
			if (ret != -ENOENT)
				goto out;
			/* hole */
			memset(si, 0, sisz * n);
			si = (void *)si + sisz * n;
			continue;
		}

		kaddr = kmap_atomic(su_bh->b_page);
		su = nilfs_sufile_block_get_segment_usage(
			sufile, segnum, su_bh, kaddr);
		for (j = 0; j < n;
		     j++, su = (void *)su + susz, si = (void *)si + sisz) {
			si->sui_lastmod = le64_to_cpu(su->su_lastmod);
			si->sui_nblocks = le32_to_cpu(su->su_nblocks);
			si->sui_flags = le32_to_cpu(su->su_flags) &
				~(1UL << NILFS_SEGMENT_USAGE_ACTIVE);
			if (nilfs_segment_is_active(nilfs, segnum + j))
				si->sui_flags |=
					(1UL << NILFS_SEGMENT_USAGE_ACTIVE);
		}
		kunmap_atomic(kaddr);
		brelse(su_bh);
	}
	ret = nsegs;

 out:
	up_read(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_set_suinfo - sets segment usage info
 * @sufile: inode of segment usage file
 * @buf: array of suinfo_update
 * @supsz: byte size of suinfo_update
 * @nsup: size of suinfo_update array
 *
 * Description: Takes an array of nilfs_suinfo_update structs and updates
 * segment usage accordingly. Only the fields indicated by the sup_flags
 * are updated.
 *
 * Return Value: On success, 0 is returned. On error, one of the
 * following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EINVAL - Invalid values in input (segment number, flags or nblocks)
 */
ssize_t nilfs_sufile_set_suinfo(struct inode *sufile, void *buf,
				unsigned supsz, size_t nsup)
{
	struct the_nilfs *nilfs = sufile->i_sb->s_fs_info;
	struct buffer_head *header_bh, *bh;
	struct nilfs_suinfo_update *sup, *supend = buf + supsz * nsup;
	struct nilfs_segment_usage *su;
	void *kaddr;
	unsigned long blkoff, prev_blkoff;
	int cleansi, cleansu, dirtysi, dirtysu;
	long ncleaned = 0, ndirtied = 0;
	int ret = 0;

	if (unlikely(nsup == 0))
		return ret;

	for (sup = buf; sup < supend; sup = (void *)sup + supsz) {
		if (sup->sup_segnum >= nilfs->ns_nsegments
			|| (sup->sup_flags &
				(~0UL << __NR_NILFS_SUINFO_UPDATE_FIELDS))
			|| (nilfs_suinfo_update_nblocks(sup) &&
				sup->sup_sui.sui_nblocks >
				nilfs->ns_blocks_per_segment))
			return -EINVAL;
	}

	down_write(&NILFS_MDT(sufile)->mi_sem);

	ret = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (ret < 0)
		goto out_sem;

	sup = buf;
	blkoff = nilfs_sufile_get_blkoff(sufile, sup->sup_segnum);
	ret = nilfs_mdt_get_block(sufile, blkoff, 1, NULL, &bh);
	if (ret < 0)
		goto out_header;

	for (;;) {
		kaddr = kmap_atomic(bh->b_page);
		su = nilfs_sufile_block_get_segment_usage(
			sufile, sup->sup_segnum, bh, kaddr);

		if (nilfs_suinfo_update_lastmod(sup))
			su->su_lastmod = cpu_to_le64(sup->sup_sui.sui_lastmod);

		if (nilfs_suinfo_update_nblocks(sup))
			su->su_nblocks = cpu_to_le32(sup->sup_sui.sui_nblocks);

		if (nilfs_suinfo_update_flags(sup)) {
			/*
			 * Active flag is a virtual flag projected by running
			 * nilfs kernel code - drop it not to write it to
			 * disk.
			 */
			sup->sup_sui.sui_flags &=
					~(1UL << NILFS_SEGMENT_USAGE_ACTIVE);

			cleansi = nilfs_suinfo_clean(&sup->sup_sui);
			cleansu = nilfs_segment_usage_clean(su);
			dirtysi = nilfs_suinfo_dirty(&sup->sup_sui);
			dirtysu = nilfs_segment_usage_dirty(su);

			if (cleansi && !cleansu)
				++ncleaned;
			else if (!cleansi && cleansu)
				--ncleaned;

			if (dirtysi && !dirtysu)
				++ndirtied;
			else if (!dirtysi && dirtysu)
				--ndirtied;

			su->su_flags = cpu_to_le32(sup->sup_sui.sui_flags);
		}

		kunmap_atomic(kaddr);

		sup = (void *)sup + supsz;
		if (sup >= supend)
			break;

		prev_blkoff = blkoff;
		blkoff = nilfs_sufile_get_blkoff(sufile, sup->sup_segnum);
		if (blkoff == prev_blkoff)
			continue;

		/* get different block */
		mark_buffer_dirty(bh);
		put_bh(bh);
		ret = nilfs_mdt_get_block(sufile, blkoff, 1, NULL, &bh);
		if (unlikely(ret < 0))
			goto out_mark;
	}
	mark_buffer_dirty(bh);
	put_bh(bh);

 out_mark:
	if (ncleaned || ndirtied) {
		nilfs_sufile_mod_counter(header_bh, (u64)ncleaned,
				(u64)ndirtied);
		NILFS_SUI(sufile)->ncleansegs += ncleaned;
	}
	nilfs_mdt_mark_dirty(sufile);
 out_header:
	put_bh(header_bh);
 out_sem:
	up_write(&NILFS_MDT(sufile)->mi_sem);
	return ret;
}

/**
 * nilfs_sufile_trim_fs() - trim ioctl handle function
 * @sufile: inode of segment usage file
 * @range: fstrim_range structure
 *
 * start:	First Byte to trim
 * len:		number of Bytes to trim from start
 * minlen:	minimum extent length in Bytes
 *
 * Decription: nilfs_sufile_trim_fs goes through all segments containing bytes
 * from start to start+len. start is rounded up to the next block boundary
 * and start+len is rounded down. For each clean segment blkdev_issue_discard
 * function is invoked.
 *
 * Return Value: On success, 0 is returned or negative error code, otherwise.
 */
int nilfs_sufile_trim_fs(struct inode *sufile, struct fstrim_range *range)
{
	struct the_nilfs *nilfs = sufile->i_sb->s_fs_info;
	struct buffer_head *su_bh;
	struct nilfs_segment_usage *su;
	void *kaddr;
	size_t n, i, susz = NILFS_MDT(sufile)->mi_entry_size;
	sector_t seg_start, seg_end, start_block, end_block;
	sector_t start = 0, nblocks = 0;
	u64 segnum, segnum_end, minlen, len, max_blocks, ndiscarded = 0;
	int ret = 0;
	unsigned int sects_per_block;

	sects_per_block = (1 << nilfs->ns_blocksize_bits) /
			bdev_logical_block_size(nilfs->ns_bdev);
	len = range->len >> nilfs->ns_blocksize_bits;
	minlen = range->minlen >> nilfs->ns_blocksize_bits;
	max_blocks = ((u64)nilfs->ns_nsegments * nilfs->ns_blocks_per_segment);

	if (!len || range->start >= max_blocks << nilfs->ns_blocksize_bits)
		return -EINVAL;

	start_block = (range->start + nilfs->ns_blocksize - 1) >>
			nilfs->ns_blocksize_bits;

	/*
	 * range->len can be very large (actually, it is set to
	 * ULLONG_MAX by default) - truncate upper end of the range
	 * carefully so as not to overflow.
	 */
	if (max_blocks - start_block < len)
		end_block = max_blocks - 1;
	else
		end_block = start_block + len - 1;

	segnum = nilfs_get_segnum_of_block(nilfs, start_block);
	segnum_end = nilfs_get_segnum_of_block(nilfs, end_block);

	down_read(&NILFS_MDT(sufile)->mi_sem);

	while (segnum <= segnum_end) {
		n = nilfs_sufile_segment_usages_in_block(sufile, segnum,
				segnum_end);

		ret = nilfs_sufile_get_segment_usage_block(sufile, segnum, 0,
							   &su_bh);
		if (ret < 0) {
			if (ret != -ENOENT)
				goto out_sem;
			/* hole */
			segnum += n;
			continue;
		}

		kaddr = kmap_atomic(su_bh->b_page);
		su = nilfs_sufile_block_get_segment_usage(sufile, segnum,
				su_bh, kaddr);
		for (i = 0; i < n; ++i, ++segnum, su = (void *)su + susz) {
			if (!nilfs_segment_usage_clean(su))
				continue;

			nilfs_get_segment_range(nilfs, segnum, &seg_start,
						&seg_end);

			if (!nblocks) {
				/* start new extent */
				start = seg_start;
				nblocks = seg_end - seg_start + 1;
				continue;
			}

			if (start + nblocks == seg_start) {
				/* add to previous extent */
				nblocks += seg_end - seg_start + 1;
				continue;
			}

			/* discard previous extent */
			if (start < start_block) {
				nblocks -= start_block - start;
				start = start_block;
			}

			if (nblocks >= minlen) {
				kunmap_atomic(kaddr);

				ret = blkdev_issue_discard(nilfs->ns_bdev,
						start * sects_per_block,
						nblocks * sects_per_block,
						GFP_NOFS, 0);
				if (ret < 0) {
					put_bh(su_bh);
					goto out_sem;
				}

				ndiscarded += nblocks;
				kaddr = kmap_atomic(su_bh->b_page);
				su = nilfs_sufile_block_get_segment_usage(
					sufile, segnum, su_bh, kaddr);
			}

			/* start new extent */
			start = seg_start;
			nblocks = seg_end - seg_start + 1;
		}
		kunmap_atomic(kaddr);
		put_bh(su_bh);
	}


	if (nblocks) {
		/* discard last extent */
		if (start < start_block) {
			nblocks -= start_block - start;
			start = start_block;
		}
		if (start + nblocks > end_block + 1)
			nblocks = end_block - start + 1;

		if (nblocks >= minlen) {
			ret = blkdev_issue_discard(nilfs->ns_bdev,
					start * sects_per_block,
					nblocks * sects_per_block,
					GFP_NOFS, 0);
			if (!ret)
				ndiscarded += nblocks;
		}
	}

out_sem:
	up_read(&NILFS_MDT(sufile)->mi_sem);

	range->len = ndiscarded << nilfs->ns_blocksize_bits;
	return ret;
}

/**
 * nilfs_sufile_read - read or get sufile inode
 * @sb: super block instance
 * @susize: size of a segment usage entry
 * @raw_inode: on-disk sufile inode
 * @inodep: buffer to store the inode
 */
int nilfs_sufile_read(struct super_block *sb, size_t susize,
		      struct nilfs_inode *raw_inode, struct inode **inodep)
{
	struct inode *sufile;
	struct nilfs_sufile_info *sui;
	struct buffer_head *header_bh;
	struct nilfs_sufile_header *header;
	void *kaddr;
	int err;

	if (susize > sb->s_blocksize) {
		printk(KERN_ERR
		       "NILFS: too large segment usage size: %zu bytes.\n",
		       susize);
		return -EINVAL;
	} else if (susize < NILFS_MIN_SEGMENT_USAGE_SIZE) {
		printk(KERN_ERR
		       "NILFS: too small segment usage size: %zu bytes.\n",
		       susize);
		return -EINVAL;
	}

	sufile = nilfs_iget_locked(sb, NULL, NILFS_SUFILE_INO);
	if (unlikely(!sufile))
		return -ENOMEM;
	if (!(sufile->i_state & I_NEW))
		goto out;

	err = nilfs_mdt_init(sufile, NILFS_MDT_GFP, sizeof(*sui));
	if (err)
		goto failed;

	nilfs_mdt_set_entry_size(sufile, susize,
				 sizeof(struct nilfs_sufile_header));

	err = nilfs_read_inode_common(sufile, raw_inode);
	if (err)
		goto failed;

	err = nilfs_sufile_get_header_block(sufile, &header_bh);
	if (err)
		goto failed;

	sui = NILFS_SUI(sufile);
	kaddr = kmap_atomic(header_bh->b_page);
	header = kaddr + bh_offset(header_bh);
	sui->ncleansegs = le64_to_cpu(header->sh_ncleansegs);
	kunmap_atomic(kaddr);
	brelse(header_bh);

	sui->allocmax = nilfs_sufile_get_nsegments(sufile) - 1;
	sui->allocmin = 0;

	unlock_new_inode(sufile);
 out:
	*inodep = sufile;
	return 0;
 failed:
	iget_failed(sufile);
	return err;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/sufile.c */
/************************************************************/
/*
 * ifile.c - NILFS inode file
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Amagai Yoshiji <amagai@osrg.net>.
 * Revised by Ryusuke Konishi <ryusuke@osrg.net>.
 *
 */

// #include <linux/types.h>
// #include <linux/buffer_head.h>
// #include "nilfs.h"
// #include "mdt.h"
// #include "alloc.h"
// #include "ifile.h"

/**
 * struct nilfs_ifile_info - on-memory private data of ifile
 * @mi: on-memory private data of metadata file
 * @palloc_cache: persistent object allocator cache of ifile
 */
struct nilfs_ifile_info {
	struct nilfs_mdt_info mi;
	struct nilfs_palloc_cache palloc_cache;
};

static inline struct nilfs_ifile_info *NILFS_IFILE_I(struct inode *ifile)
{
	return (struct nilfs_ifile_info *)NILFS_MDT(ifile);
}

/**
 * nilfs_ifile_create_inode - create a new disk inode
 * @ifile: ifile inode
 * @out_ino: pointer to a variable to store inode number
 * @out_bh: buffer_head contains newly allocated disk inode
 *
 * Return Value: On success, 0 is returned and the newly allocated inode
 * number is stored in the place pointed by @ino, and buffer_head pointer
 * that contains newly allocated disk inode structure is stored in the
 * place pointed by @out_bh
 * On error, one of the following negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOSPC - No inode left.
 */
int nilfs_ifile_create_inode(struct inode *ifile, ino_t *out_ino,
			     struct buffer_head **out_bh)
{
	struct nilfs_palloc_req req;
	int ret;

	req.pr_entry_nr = 0;  /* 0 says find free inode from beginning of
				 a group. dull code!! */
	req.pr_entry_bh = NULL;

	ret = nilfs_palloc_prepare_alloc_entry(ifile, &req);
	if (!ret) {
		ret = nilfs_palloc_get_entry_block(ifile, req.pr_entry_nr, 1,
						   &req.pr_entry_bh);
		if (ret < 0)
			nilfs_palloc_abort_alloc_entry(ifile, &req);
	}
	if (ret < 0) {
		brelse(req.pr_entry_bh);
		return ret;
	}
	nilfs_palloc_commit_alloc_entry(ifile, &req);
	mark_buffer_dirty(req.pr_entry_bh);
	nilfs_mdt_mark_dirty(ifile);
	*out_ino = (ino_t)req.pr_entry_nr;
	*out_bh = req.pr_entry_bh;
	return 0;
}

/**
 * nilfs_ifile_delete_inode - delete a disk inode
 * @ifile: ifile inode
 * @ino: inode number
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - The inode number @ino have not been allocated.
 */
int nilfs_ifile_delete_inode(struct inode *ifile, ino_t ino)
{
	struct nilfs_palloc_req req = {
		.pr_entry_nr = ino, .pr_entry_bh = NULL
	};
	struct nilfs_inode *raw_inode;
	void *kaddr;
	int ret;

	ret = nilfs_palloc_prepare_free_entry(ifile, &req);
	if (!ret) {
		ret = nilfs_palloc_get_entry_block(ifile, req.pr_entry_nr, 0,
						   &req.pr_entry_bh);
		if (ret < 0)
			nilfs_palloc_abort_free_entry(ifile, &req);
	}
	if (ret < 0) {
		brelse(req.pr_entry_bh);
		return ret;
	}

	kaddr = kmap_atomic(req.pr_entry_bh->b_page);
	raw_inode = nilfs_palloc_block_get_entry(ifile, req.pr_entry_nr,
						 req.pr_entry_bh, kaddr);
	raw_inode->i_flags = 0;
	kunmap_atomic(kaddr);

	mark_buffer_dirty(req.pr_entry_bh);
	brelse(req.pr_entry_bh);

	nilfs_palloc_commit_free_entry(ifile, &req);

	return 0;
}

int nilfs_ifile_get_inode_block(struct inode *ifile, ino_t ino,
				struct buffer_head **out_bh)
{
	struct super_block *sb = ifile->i_sb;
	int err;

	if (unlikely(!NILFS_VALID_INODE(sb, ino))) {
		nilfs_error(sb, __func__, "bad inode number: %lu",
			    (unsigned long) ino);
		return -EINVAL;
	}

	err = nilfs_palloc_get_entry_block(ifile, ino, 0, out_bh);
	if (unlikely(err))
		nilfs_warning(sb, __func__, "unable to read inode: %lu",
			      (unsigned long) ino);
	return err;
}

/**
 * nilfs_ifile_count_free_inodes - calculate free inodes count
 * @ifile: ifile inode
 * @nmaxinodes: current maximum of available inodes count [out]
 * @nfreeinodes: free inodes count [out]
 */
int nilfs_ifile_count_free_inodes(struct inode *ifile,
				    u64 *nmaxinodes, u64 *nfreeinodes)
{
	u64 nused;
	int err;

	*nmaxinodes = 0;
	*nfreeinodes = 0;

	nused = atomic64_read(&NILFS_I(ifile)->i_root->inodes_count);
	err = nilfs_palloc_count_max_entries(ifile, nused, nmaxinodes);
	if (likely(!err))
		*nfreeinodes = *nmaxinodes - nused;
	return err;
}

/**
 * nilfs_ifile_read - read or get ifile inode
 * @sb: super block instance
 * @root: root object
 * @inode_size: size of an inode
 * @raw_inode: on-disk ifile inode
 * @inodep: buffer to store the inode
 */
int nilfs_ifile_read(struct super_block *sb, struct nilfs_root *root,
		     size_t inode_size, struct nilfs_inode *raw_inode,
		     struct inode **inodep)
{
	struct inode *ifile;
	int err;

	ifile = nilfs_iget_locked(sb, root, NILFS_IFILE_INO);
	if (unlikely(!ifile))
		return -ENOMEM;
	if (!(ifile->i_state & I_NEW))
		goto out;

	err = nilfs_mdt_init(ifile, NILFS_MDT_GFP,
			     sizeof(struct nilfs_ifile_info));
	if (err)
		goto failed;

	err = nilfs_palloc_init_blockgroup(ifile, inode_size);
	if (err)
		goto failed;

	nilfs_palloc_setup_cache(ifile, &NILFS_IFILE_I(ifile)->palloc_cache);

	err = nilfs_read_inode_common(ifile, raw_inode);
	if (err)
		goto failed;

	unlock_new_inode(ifile);
 out:
	*inodep = ifile;
	return 0;
 failed:
	iget_failed(ifile);
	return err;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/ifile.c */
/************************************************************/
/*
 * alloc.c - NILFS dat/inode allocator
 *
 * Copyright (C) 2006-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Original code was written by Koji Sato <koji@osrg.net>.
 * Two allocators were unified by Ryusuke Konishi <ryusuke@osrg.net>,
 *                                Amagai Yoshiji <amagai@osrg.net>.
 */

// #include <linux/types.h>
// #include <linux/buffer_head.h>
// #include <linux/fs.h>
// #include <linux/bitops.h>
// #include <linux/slab.h>
// #include "mdt.h"
// #include "alloc.h"


/**
 * nilfs_palloc_groups_per_desc_block - get the number of groups that a group
 *					descriptor block can maintain
 * @inode: inode of metadata file using this allocator
 */
static inline unsigned long
nilfs_palloc_groups_per_desc_block(const struct inode *inode)
{
	return (1UL << inode->i_blkbits) /
		sizeof(struct nilfs_palloc_group_desc);
}

/**
 * nilfs_palloc_groups_count - get maximum number of groups
 * @inode: inode of metadata file using this allocator
 */
static inline unsigned long
nilfs_palloc_groups_count(const struct inode *inode)
{
	return 1UL << (BITS_PER_LONG - (inode->i_blkbits + 3 /* log2(8) */));
}

/**
 * nilfs_palloc_init_blockgroup - initialize private variables for allocator
 * @inode: inode of metadata file using this allocator
 * @entry_size: size of the persistent object
 */
int nilfs_palloc_init_blockgroup(struct inode *inode, unsigned entry_size)
{
	struct nilfs_mdt_info *mi = NILFS_MDT(inode);

	mi->mi_bgl = kmalloc(sizeof(*mi->mi_bgl), GFP_NOFS);
	if (!mi->mi_bgl)
		return -ENOMEM;

	bgl_lock_init(mi->mi_bgl);

	nilfs_mdt_set_entry_size(inode, entry_size, 0);

	mi->mi_blocks_per_group =
		DIV_ROUND_UP(nilfs_palloc_entries_per_group(inode),
			     mi->mi_entries_per_block) + 1;
		/* Number of blocks in a group including entry blocks and
		   a bitmap block */
	mi->mi_blocks_per_desc_block =
		nilfs_palloc_groups_per_desc_block(inode) *
		mi->mi_blocks_per_group + 1;
		/* Number of blocks per descriptor including the
		   descriptor block */
	return 0;
}

/**
 * nilfs_palloc_group - get group number and offset from an entry number
 * @inode: inode of metadata file using this allocator
 * @nr: serial number of the entry (e.g. inode number)
 * @offset: pointer to store offset number in the group
 */
static unsigned long nilfs_palloc_group(const struct inode *inode, __u64 nr,
					unsigned long *offset)
{
	__u64 group = nr;

	*offset = do_div(group, nilfs_palloc_entries_per_group(inode));
	return group;
}

/**
 * nilfs_palloc_desc_blkoff - get block offset of a group descriptor block
 * @inode: inode of metadata file using this allocator
 * @group: group number
 *
 * nilfs_palloc_desc_blkoff() returns block offset of the descriptor
 * block which contains a descriptor of the specified group.
 */
static unsigned long
nilfs_palloc_desc_blkoff(const struct inode *inode, unsigned long group)
{
	unsigned long desc_block =
		group / nilfs_palloc_groups_per_desc_block(inode);
	return desc_block * NILFS_MDT(inode)->mi_blocks_per_desc_block;
}

/**
 * nilfs_palloc_bitmap_blkoff - get block offset of a bitmap block
 * @inode: inode of metadata file using this allocator
 * @group: group number
 *
 * nilfs_palloc_bitmap_blkoff() returns block offset of the bitmap
 * block used to allocate/deallocate entries in the specified group.
 */
static unsigned long
nilfs_palloc_bitmap_blkoff(const struct inode *inode, unsigned long group)
{
	unsigned long desc_offset =
		group % nilfs_palloc_groups_per_desc_block(inode);
	return nilfs_palloc_desc_blkoff(inode, group) + 1 +
		desc_offset * NILFS_MDT(inode)->mi_blocks_per_group;
}

/**
 * nilfs_palloc_group_desc_nfrees - get the number of free entries in a group
 * @inode: inode of metadata file using this allocator
 * @group: group number
 * @desc: pointer to descriptor structure for the group
 */
static unsigned long
nilfs_palloc_group_desc_nfrees(struct inode *inode, unsigned long group,
			       const struct nilfs_palloc_group_desc *desc)
{
	unsigned long nfree;

	spin_lock(nilfs_mdt_bgl_lock(inode, group));
	nfree = le32_to_cpu(desc->pg_nfrees);
	spin_unlock(nilfs_mdt_bgl_lock(inode, group));
	return nfree;
}

/**
 * nilfs_palloc_group_desc_add_entries - adjust count of free entries
 * @inode: inode of metadata file using this allocator
 * @group: group number
 * @desc: pointer to descriptor structure for the group
 * @n: delta to be added
 */
static void
nilfs_palloc_group_desc_add_entries(struct inode *inode,
				    unsigned long group,
				    struct nilfs_palloc_group_desc *desc,
				    u32 n)
{
	spin_lock(nilfs_mdt_bgl_lock(inode, group));
	le32_add_cpu(&desc->pg_nfrees, n);
	spin_unlock(nilfs_mdt_bgl_lock(inode, group));
}

/**
 * nilfs_palloc_entry_blkoff - get block offset of an entry block
 * @inode: inode of metadata file using this allocator
 * @nr: serial number of the entry (e.g. inode number)
 */
static unsigned long
nilfs_palloc_entry_blkoff(const struct inode *inode, __u64 nr)
{
	unsigned long group, group_offset;

	group = nilfs_palloc_group(inode, nr, &group_offset);

	return nilfs_palloc_bitmap_blkoff(inode, group) + 1 +
		group_offset / NILFS_MDT(inode)->mi_entries_per_block;
}

/**
 * nilfs_palloc_desc_block_init - initialize buffer of a group descriptor block
 * @inode: inode of metadata file
 * @bh: buffer head of the buffer to be initialized
 * @kaddr: kernel address mapped for the page including the buffer
 */
static void nilfs_palloc_desc_block_init(struct inode *inode,
					 struct buffer_head *bh, void *kaddr)
{
	struct nilfs_palloc_group_desc *desc = kaddr + bh_offset(bh);
	unsigned long n = nilfs_palloc_groups_per_desc_block(inode);
	__le32 nfrees;

	nfrees = cpu_to_le32(nilfs_palloc_entries_per_group(inode));
	while (n-- > 0) {
		desc->pg_nfrees = nfrees;
		desc++;
	}
}

static int nilfs_palloc_get_block(struct inode *inode, unsigned long blkoff,
				  int create,
				  void (*init_block)(struct inode *,
						     struct buffer_head *,
						     void *),
				  struct buffer_head **bhp,
				  struct nilfs_bh_assoc *prev,
				  spinlock_t *lock)
{
	int ret;

	spin_lock(lock);
	if (prev->bh && blkoff == prev->blkoff) {
		get_bh(prev->bh);
		*bhp = prev->bh;
		spin_unlock(lock);
		return 0;
	}
	spin_unlock(lock);

	ret = nilfs_mdt_get_block(inode, blkoff, create, init_block, bhp);
	if (!ret) {
		spin_lock(lock);
		/*
		 * The following code must be safe for change of the
		 * cache contents during the get block call.
		 */
		brelse(prev->bh);
		get_bh(*bhp);
		prev->bh = *bhp;
		prev->blkoff = blkoff;
		spin_unlock(lock);
	}
	return ret;
}

/**
 * nilfs_palloc_get_desc_block - get buffer head of a group descriptor block
 * @inode: inode of metadata file using this allocator
 * @group: group number
 * @create: create flag
 * @bhp: pointer to store the resultant buffer head
 */
static int nilfs_palloc_get_desc_block(struct inode *inode,
				       unsigned long group,
				       int create, struct buffer_head **bhp)
{
	struct nilfs_palloc_cache *cache = NILFS_MDT(inode)->mi_palloc_cache;

	return nilfs_palloc_get_block(inode,
				      nilfs_palloc_desc_blkoff(inode, group),
				      create, nilfs_palloc_desc_block_init,
				      bhp, &cache->prev_desc, &cache->lock);
}

/**
 * nilfs_palloc_get_bitmap_block - get buffer head of a bitmap block
 * @inode: inode of metadata file using this allocator
 * @group: group number
 * @create: create flag
 * @bhp: pointer to store the resultant buffer head
 */
static int nilfs_palloc_get_bitmap_block(struct inode *inode,
					 unsigned long group,
					 int create, struct buffer_head **bhp)
{
	struct nilfs_palloc_cache *cache = NILFS_MDT(inode)->mi_palloc_cache;

	return nilfs_palloc_get_block(inode,
				      nilfs_palloc_bitmap_blkoff(inode, group),
				      create, NULL, bhp,
				      &cache->prev_bitmap, &cache->lock);
}

/**
 * nilfs_palloc_get_entry_block - get buffer head of an entry block
 * @inode: inode of metadata file using this allocator
 * @nr: serial number of the entry (e.g. inode number)
 * @create: create flag
 * @bhp: pointer to store the resultant buffer head
 */
int nilfs_palloc_get_entry_block(struct inode *inode, __u64 nr,
				 int create, struct buffer_head **bhp)
{
	struct nilfs_palloc_cache *cache = NILFS_MDT(inode)->mi_palloc_cache;

	return nilfs_palloc_get_block(inode,
				      nilfs_palloc_entry_blkoff(inode, nr),
				      create, NULL, bhp,
				      &cache->prev_entry, &cache->lock);
}

/**
 * nilfs_palloc_block_get_group_desc - get kernel address of a group descriptor
 * @inode: inode of metadata file using this allocator
 * @group: group number
 * @bh: buffer head of the buffer storing the group descriptor block
 * @kaddr: kernel address mapped for the page including the buffer
 */
static struct nilfs_palloc_group_desc *
nilfs_palloc_block_get_group_desc(const struct inode *inode,
				  unsigned long group,
				  const struct buffer_head *bh, void *kaddr)
{
	return (struct nilfs_palloc_group_desc *)(kaddr + bh_offset(bh)) +
		group % nilfs_palloc_groups_per_desc_block(inode);
}

/**
 * nilfs_palloc_block_get_entry - get kernel address of an entry
 * @inode: inode of metadata file using this allocator
 * @nr: serial number of the entry (e.g. inode number)
 * @bh: buffer head of the buffer storing the entry block
 * @kaddr: kernel address mapped for the page including the buffer
 */
void *nilfs_palloc_block_get_entry(const struct inode *inode, __u64 nr,
				   const struct buffer_head *bh, void *kaddr)
{
	unsigned long entry_offset, group_offset;

	nilfs_palloc_group(inode, nr, &group_offset);
	entry_offset = group_offset % NILFS_MDT(inode)->mi_entries_per_block;

	return kaddr + bh_offset(bh) +
		entry_offset * NILFS_MDT(inode)->mi_entry_size;
}

/**
 * nilfs_palloc_find_available_slot - find available slot in a group
 * @inode: inode of metadata file using this allocator
 * @group: group number
 * @target: offset number of an entry in the group (start point)
 * @bitmap: bitmap of the group
 * @bsize: size in bits
 */
static int nilfs_palloc_find_available_slot(struct inode *inode,
					    unsigned long group,
					    unsigned long target,
					    unsigned char *bitmap,
					    int bsize)
{
	int curr, pos, end, i;

	if (target > 0) {
		end = (target + BITS_PER_LONG - 1) & ~(BITS_PER_LONG - 1);
		if (end > bsize)
			end = bsize;
		pos = nilfs_find_next_zero_bit(bitmap, end, target);
		if (pos < end &&
		    !nilfs_set_bit_atomic(
			    nilfs_mdt_bgl_lock(inode, group), pos, bitmap))
			return pos;
	} else
		end = 0;

	for (i = 0, curr = end;
	     i < bsize;
	     i += BITS_PER_LONG, curr += BITS_PER_LONG) {
		/* wrap around */
		if (curr >= bsize)
			curr = 0;
		while (*((unsigned long *)bitmap + curr / BITS_PER_LONG)
		       != ~0UL) {
			end = curr + BITS_PER_LONG;
			if (end > bsize)
				end = bsize;
			pos = nilfs_find_next_zero_bit(bitmap, end, curr);
			if ((pos < end) &&
			    !nilfs_set_bit_atomic(
				    nilfs_mdt_bgl_lock(inode, group), pos,
				    bitmap))
				return pos;
		}
	}
	return -ENOSPC;
}

/**
 * nilfs_palloc_rest_groups_in_desc_block - get the remaining number of groups
 *					    in a group descriptor block
 * @inode: inode of metadata file using this allocator
 * @curr: current group number
 * @max: maximum number of groups
 */
static unsigned long
nilfs_palloc_rest_groups_in_desc_block(const struct inode *inode,
				       unsigned long curr, unsigned long max)
{
	return min_t(unsigned long,
		     nilfs_palloc_groups_per_desc_block(inode) -
		     curr % nilfs_palloc_groups_per_desc_block(inode),
		     max - curr + 1);
}

/**
 * nilfs_palloc_count_desc_blocks - count descriptor blocks number
 * @inode: inode of metadata file using this allocator
 * @desc_blocks: descriptor blocks number [out]
 */
static int nilfs_palloc_count_desc_blocks(struct inode *inode,
					    unsigned long *desc_blocks)
{
	unsigned long blknum;
	int ret;

	ret = nilfs_bmap_last_key(NILFS_I(inode)->i_bmap, &blknum);
	if (likely(!ret))
		*desc_blocks = DIV_ROUND_UP(
			blknum, NILFS_MDT(inode)->mi_blocks_per_desc_block);
	return ret;
}

/**
 * nilfs_palloc_mdt_file_can_grow - check potential opportunity for
 *					MDT file growing
 * @inode: inode of metadata file using this allocator
 * @desc_blocks: known current descriptor blocks count
 */
static inline bool nilfs_palloc_mdt_file_can_grow(struct inode *inode,
						    unsigned long desc_blocks)
{
	return (nilfs_palloc_groups_per_desc_block(inode) * desc_blocks) <
			nilfs_palloc_groups_count(inode);
}

/**
 * nilfs_palloc_count_max_entries - count max number of entries that can be
 *					described by descriptor blocks count
 * @inode: inode of metadata file using this allocator
 * @nused: current number of used entries
 * @nmaxp: max number of entries [out]
 */
int nilfs_palloc_count_max_entries(struct inode *inode, u64 nused, u64 *nmaxp)
{
	unsigned long desc_blocks = 0;
	u64 entries_per_desc_block, nmax;
	int err;

	err = nilfs_palloc_count_desc_blocks(inode, &desc_blocks);
	if (unlikely(err))
		return err;

	entries_per_desc_block = (u64)nilfs_palloc_entries_per_group(inode) *
				nilfs_palloc_groups_per_desc_block(inode);
	nmax = entries_per_desc_block * desc_blocks;

	if (nused == nmax &&
			nilfs_palloc_mdt_file_can_grow(inode, desc_blocks))
		nmax += entries_per_desc_block;

	if (nused > nmax)
		return -ERANGE;

	*nmaxp = nmax;
	return 0;
}

/**
 * nilfs_palloc_prepare_alloc_entry - prepare to allocate a persistent object
 * @inode: inode of metadata file using this allocator
 * @req: nilfs_palloc_req structure exchanged for the allocation
 */
int nilfs_palloc_prepare_alloc_entry(struct inode *inode,
				     struct nilfs_palloc_req *req)
{
	struct buffer_head *desc_bh, *bitmap_bh;
	struct nilfs_palloc_group_desc *desc;
	unsigned char *bitmap;
	void *desc_kaddr, *bitmap_kaddr;
	unsigned long group, maxgroup, ngroups;
	unsigned long group_offset, maxgroup_offset;
	unsigned long n, entries_per_group, groups_per_desc_block;
	unsigned long i, j;
	int pos, ret;

	ngroups = nilfs_palloc_groups_count(inode);
	maxgroup = ngroups - 1;
	group = nilfs_palloc_group(inode, req->pr_entry_nr, &group_offset);
	entries_per_group = nilfs_palloc_entries_per_group(inode);
	groups_per_desc_block = nilfs_palloc_groups_per_desc_block(inode);

	for (i = 0; i < ngroups; i += n) {
		if (group >= ngroups) {
			/* wrap around */
			group = 0;
			maxgroup = nilfs_palloc_group(inode, req->pr_entry_nr,
						      &maxgroup_offset) - 1;
		}
		ret = nilfs_palloc_get_desc_block(inode, group, 1, &desc_bh);
		if (ret < 0)
			return ret;
		desc_kaddr = kmap(desc_bh->b_page);
		desc = nilfs_palloc_block_get_group_desc(
			inode, group, desc_bh, desc_kaddr);
		n = nilfs_palloc_rest_groups_in_desc_block(inode, group,
							   maxgroup);
		for (j = 0; j < n; j++, desc++, group++) {
			if (nilfs_palloc_group_desc_nfrees(inode, group, desc)
			    > 0) {
				ret = nilfs_palloc_get_bitmap_block(
					inode, group, 1, &bitmap_bh);
				if (ret < 0)
					goto out_desc;
				bitmap_kaddr = kmap(bitmap_bh->b_page);
				bitmap = bitmap_kaddr + bh_offset(bitmap_bh);
				pos = nilfs_palloc_find_available_slot(
					inode, group, group_offset, bitmap,
					entries_per_group);
				if (pos >= 0) {
					/* found a free entry */
					nilfs_palloc_group_desc_add_entries(
						inode, group, desc, -1);
					req->pr_entry_nr =
						entries_per_group * group + pos;
					kunmap(desc_bh->b_page);
					kunmap(bitmap_bh->b_page);

					req->pr_desc_bh = desc_bh;
					req->pr_bitmap_bh = bitmap_bh;
					return 0;
				}
				kunmap(bitmap_bh->b_page);
				brelse(bitmap_bh);
			}

			group_offset = 0;
		}

		kunmap(desc_bh->b_page);
		brelse(desc_bh);
	}

	/* no entries left */
	return -ENOSPC;

 out_desc:
	kunmap(desc_bh->b_page);
	brelse(desc_bh);
	return ret;
}

/**
 * nilfs_palloc_commit_alloc_entry - finish allocation of a persistent object
 * @inode: inode of metadata file using this allocator
 * @req: nilfs_palloc_req structure exchanged for the allocation
 */
void nilfs_palloc_commit_alloc_entry(struct inode *inode,
				     struct nilfs_palloc_req *req)
{
	mark_buffer_dirty(req->pr_bitmap_bh);
	mark_buffer_dirty(req->pr_desc_bh);
	nilfs_mdt_mark_dirty(inode);

	brelse(req->pr_bitmap_bh);
	brelse(req->pr_desc_bh);
}

/**
 * nilfs_palloc_commit_free_entry - finish deallocating a persistent object
 * @inode: inode of metadata file using this allocator
 * @req: nilfs_palloc_req structure exchanged for the removal
 */
void nilfs_palloc_commit_free_entry(struct inode *inode,
				    struct nilfs_palloc_req *req)
{
	struct nilfs_palloc_group_desc *desc;
	unsigned long group, group_offset;
	unsigned char *bitmap;
	void *desc_kaddr, *bitmap_kaddr;

	group = nilfs_palloc_group(inode, req->pr_entry_nr, &group_offset);
	desc_kaddr = kmap(req->pr_desc_bh->b_page);
	desc = nilfs_palloc_block_get_group_desc(inode, group,
						 req->pr_desc_bh, desc_kaddr);
	bitmap_kaddr = kmap(req->pr_bitmap_bh->b_page);
	bitmap = bitmap_kaddr + bh_offset(req->pr_bitmap_bh);

	if (!nilfs_clear_bit_atomic(nilfs_mdt_bgl_lock(inode, group),
				    group_offset, bitmap))
		printk(KERN_WARNING "%s: entry number %llu already freed\n",
		       __func__, (unsigned long long)req->pr_entry_nr);
	else
		nilfs_palloc_group_desc_add_entries(inode, group, desc, 1);

	kunmap(req->pr_bitmap_bh->b_page);
	kunmap(req->pr_desc_bh->b_page);

	mark_buffer_dirty(req->pr_desc_bh);
	mark_buffer_dirty(req->pr_bitmap_bh);
	nilfs_mdt_mark_dirty(inode);

	brelse(req->pr_bitmap_bh);
	brelse(req->pr_desc_bh);
}

/**
 * nilfs_palloc_abort_alloc_entry - cancel allocation of a persistent object
 * @inode: inode of metadata file using this allocator
 * @req: nilfs_palloc_req structure exchanged for the allocation
 */
void nilfs_palloc_abort_alloc_entry(struct inode *inode,
				    struct nilfs_palloc_req *req)
{
	struct nilfs_palloc_group_desc *desc;
	void *desc_kaddr, *bitmap_kaddr;
	unsigned char *bitmap;
	unsigned long group, group_offset;

	group = nilfs_palloc_group(inode, req->pr_entry_nr, &group_offset);
	desc_kaddr = kmap(req->pr_desc_bh->b_page);
	desc = nilfs_palloc_block_get_group_desc(inode, group,
						 req->pr_desc_bh, desc_kaddr);
	bitmap_kaddr = kmap(req->pr_bitmap_bh->b_page);
	bitmap = bitmap_kaddr + bh_offset(req->pr_bitmap_bh);
	if (!nilfs_clear_bit_atomic(nilfs_mdt_bgl_lock(inode, group),
				    group_offset, bitmap))
		printk(KERN_WARNING "%s: entry number %llu already freed\n",
		       __func__, (unsigned long long)req->pr_entry_nr);
	else
		nilfs_palloc_group_desc_add_entries(inode, group, desc, 1);

	kunmap(req->pr_bitmap_bh->b_page);
	kunmap(req->pr_desc_bh->b_page);

	brelse(req->pr_bitmap_bh);
	brelse(req->pr_desc_bh);

	req->pr_entry_nr = 0;
	req->pr_bitmap_bh = NULL;
	req->pr_desc_bh = NULL;
}

/**
 * nilfs_palloc_prepare_free_entry - prepare to deallocate a persistent object
 * @inode: inode of metadata file using this allocator
 * @req: nilfs_palloc_req structure exchanged for the removal
 */
int nilfs_palloc_prepare_free_entry(struct inode *inode,
				    struct nilfs_palloc_req *req)
{
	struct buffer_head *desc_bh, *bitmap_bh;
	unsigned long group, group_offset;
	int ret;

	group = nilfs_palloc_group(inode, req->pr_entry_nr, &group_offset);
	ret = nilfs_palloc_get_desc_block(inode, group, 1, &desc_bh);
	if (ret < 0)
		return ret;
	ret = nilfs_palloc_get_bitmap_block(inode, group, 1, &bitmap_bh);
	if (ret < 0) {
		brelse(desc_bh);
		return ret;
	}

	req->pr_desc_bh = desc_bh;
	req->pr_bitmap_bh = bitmap_bh;
	return 0;
}

/**
 * nilfs_palloc_abort_free_entry - cancel deallocating a persistent object
 * @inode: inode of metadata file using this allocator
 * @req: nilfs_palloc_req structure exchanged for the removal
 */
void nilfs_palloc_abort_free_entry(struct inode *inode,
				   struct nilfs_palloc_req *req)
{
	brelse(req->pr_bitmap_bh);
	brelse(req->pr_desc_bh);

	req->pr_entry_nr = 0;
	req->pr_bitmap_bh = NULL;
	req->pr_desc_bh = NULL;
}

/**
 * nilfs_palloc_group_is_in - judge if an entry is in a group
 * @inode: inode of metadata file using this allocator
 * @group: group number
 * @nr: serial number of the entry (e.g. inode number)
 */
static int
nilfs_palloc_group_is_in(struct inode *inode, unsigned long group, __u64 nr)
{
	__u64 first, last;

	first = group * nilfs_palloc_entries_per_group(inode);
	last = first + nilfs_palloc_entries_per_group(inode) - 1;
	return (nr >= first) && (nr <= last);
}

/**
 * nilfs_palloc_freev - deallocate a set of persistent objects
 * @inode: inode of metadata file using this allocator
 * @entry_nrs: array of entry numbers to be deallocated
 * @nitems: number of entries stored in @entry_nrs
 */
int nilfs_palloc_freev(struct inode *inode, __u64 *entry_nrs, size_t nitems)
{
	struct buffer_head *desc_bh, *bitmap_bh;
	struct nilfs_palloc_group_desc *desc;
	unsigned char *bitmap;
	void *desc_kaddr, *bitmap_kaddr;
	unsigned long group, group_offset;
	int i, j, n, ret;

	for (i = 0; i < nitems; i = j) {
		group = nilfs_palloc_group(inode, entry_nrs[i], &group_offset);
		ret = nilfs_palloc_get_desc_block(inode, group, 0, &desc_bh);
		if (ret < 0)
			return ret;
		ret = nilfs_palloc_get_bitmap_block(inode, group, 0,
						    &bitmap_bh);
		if (ret < 0) {
			brelse(desc_bh);
			return ret;
		}
		desc_kaddr = kmap(desc_bh->b_page);
		desc = nilfs_palloc_block_get_group_desc(
			inode, group, desc_bh, desc_kaddr);
		bitmap_kaddr = kmap(bitmap_bh->b_page);
		bitmap = bitmap_kaddr + bh_offset(bitmap_bh);
		for (j = i, n = 0;
		     (j < nitems) && nilfs_palloc_group_is_in(inode, group,
							      entry_nrs[j]);
		     j++) {
			nilfs_palloc_group(inode, entry_nrs[j], &group_offset);
			if (!nilfs_clear_bit_atomic(
				    nilfs_mdt_bgl_lock(inode, group),
				    group_offset, bitmap)) {
				printk(KERN_WARNING
				       "%s: entry number %llu already freed\n",
				       __func__,
				       (unsigned long long)entry_nrs[j]);
			} else {
				n++;
			}
		}
		nilfs_palloc_group_desc_add_entries(inode, group, desc, n);

		kunmap(bitmap_bh->b_page);
		kunmap(desc_bh->b_page);

		mark_buffer_dirty(desc_bh);
		mark_buffer_dirty(bitmap_bh);
		nilfs_mdt_mark_dirty(inode);

		brelse(bitmap_bh);
		brelse(desc_bh);
	}
	return 0;
}

void nilfs_palloc_setup_cache(struct inode *inode,
			      struct nilfs_palloc_cache *cache)
{
	NILFS_MDT(inode)->mi_palloc_cache = cache;
	spin_lock_init(&cache->lock);
}

void nilfs_palloc_clear_cache(struct inode *inode)
{
	struct nilfs_palloc_cache *cache = NILFS_MDT(inode)->mi_palloc_cache;

	spin_lock(&cache->lock);
	brelse(cache->prev_desc.bh);
	brelse(cache->prev_bitmap.bh);
	brelse(cache->prev_entry.bh);
	cache->prev_desc.bh = NULL;
	cache->prev_bitmap.bh = NULL;
	cache->prev_entry.bh = NULL;
	spin_unlock(&cache->lock);
}

void nilfs_palloc_destroy_cache(struct inode *inode)
{
	nilfs_palloc_clear_cache(inode);
	NILFS_MDT(inode)->mi_palloc_cache = NULL;
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/alloc.c */
/************************************************************/
/*
 * gcinode.c - dummy inodes to buffer blocks for garbage collection
 *
 * Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Seiji Kihara <kihara@osrg.net>, Amagai Yoshiji <amagai@osrg.net>,
 *            and Ryusuke Konishi <ryusuke@osrg.net>.
 * Revised by Ryusuke Konishi <ryusuke@osrg.net>.
 *
 */
/*
 * This file adds the cache of on-disk blocks to be moved in garbage
 * collection.  The disk blocks are held with dummy inodes (called
 * gcinodes), and this file provides lookup function of the dummy
 * inodes and their buffer read function.
 *
 * Buffers and pages held by the dummy inodes will be released each
 * time after they are copied to a new log.  Dirty blocks made on the
 * current generation and the blocks to be moved by GC never overlap
 * because the dirty blocks make a new generation; they rather must be
 * written individually.
 */

// #include <linux/buffer_head.h>
// #include <linux/mpage.h>
#include <linux/hash.h>
// #include <linux/slab.h>
// #include <linux/swap.h>
// #include "nilfs.h"
// #include "btree.h"
// #include "btnode.h"
// #include "page.h"
// #include "mdt.h"
// #include "dat.h"
// #include "ifile.h"

/*
 * nilfs_gccache_submit_read_data() - add data buffer and submit read request
 * @inode - gc inode
 * @blkoff - dummy offset treated as the key for the page cache
 * @pbn - physical block number of the block
 * @vbn - virtual block number of the block, 0 for non-virtual block
 * @out_bh - indirect pointer to a buffer_head struct to receive the results
 *
 * Description: nilfs_gccache_submit_read_data() registers the data buffer
 * specified by @pbn to the GC pagecache with the key @blkoff.
 * This function sets @vbn (@pbn if @vbn is zero) in b_blocknr of the buffer.
 *
 * Return Value: On success, 0 is returned. On Error, one of the following
 * negative error code is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - The block specified with @pbn does not exist.
 */
int nilfs_gccache_submit_read_data(struct inode *inode, sector_t blkoff,
				   sector_t pbn, __u64 vbn,
				   struct buffer_head **out_bh)
{
	struct buffer_head *bh;
	int err;

	bh = nilfs_grab_buffer(inode, inode->i_mapping, blkoff, 0);
	if (unlikely(!bh))
		return -ENOMEM;

	if (buffer_uptodate(bh))
		goto out;

	if (pbn == 0) {
		struct the_nilfs *nilfs = inode->i_sb->s_fs_info;

		err = nilfs_dat_translate(nilfs->ns_dat, vbn, &pbn);
		if (unlikely(err)) { /* -EIO, -ENOMEM, -ENOENT */
			brelse(bh);
			goto failed;
		}
	}

	lock_buffer(bh);
	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		goto out;
	}

	if (!buffer_mapped(bh)) {
		bh->b_bdev = inode->i_sb->s_bdev;
		set_buffer_mapped(bh);
	}
	bh->b_blocknr = pbn;
	bh->b_end_io = end_buffer_read_sync;
	get_bh(bh);
	submit_bh(READ, bh);
	if (vbn)
		bh->b_blocknr = vbn;
 out:
	err = 0;
	*out_bh = bh;

 failed:
	unlock_page(bh->b_page);
	page_cache_release(bh->b_page);
	return err;
}

/*
 * nilfs_gccache_submit_read_node() - add node buffer and submit read request
 * @inode - gc inode
 * @pbn - physical block number for the block
 * @vbn - virtual block number for the block
 * @out_bh - indirect pointer to a buffer_head struct to receive the results
 *
 * Description: nilfs_gccache_submit_read_node() registers the node buffer
 * specified by @vbn to the GC pagecache.  @pbn can be supplied by the
 * caller to avoid translation of the disk block address.
 *
 * Return Value: On success, 0 is returned. On Error, one of the following
 * negative error code is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 */
int nilfs_gccache_submit_read_node(struct inode *inode, sector_t pbn,
				   __u64 vbn, struct buffer_head **out_bh)
{
	int ret;

	ret = nilfs_btnode_submit_block(&NILFS_I(inode)->i_btnode_cache,
					vbn ? : pbn, pbn, READ, out_bh, &pbn);
	if (ret == -EEXIST) /* internal code (cache hit) */
		ret = 0;
	return ret;
}

int nilfs_gccache_wait_and_mark_dirty(struct buffer_head *bh)
{
	wait_on_buffer(bh);
	if (!buffer_uptodate(bh))
		return -EIO;
	if (buffer_dirty(bh))
		return -EEXIST;

	if (buffer_nilfs_node(bh) && nilfs_btree_broken_node_block(bh)) {
		clear_buffer_uptodate(bh);
		return -EIO;
	}
	mark_buffer_dirty(bh);
	return 0;
}

int nilfs_init_gcinode(struct inode *inode)
{
	struct nilfs_inode_info *ii = NILFS_I(inode);

	inode->i_mode = S_IFREG;
	mapping_set_gfp_mask(inode->i_mapping, GFP_NOFS);
	inode->i_mapping->a_ops = &empty_aops;
	inode->i_mapping->backing_dev_info = inode->i_sb->s_bdi;

	ii->i_flags = 0;
	nilfs_bmap_init_gc(ii->i_bmap);

	return 0;
}

/**
 * nilfs_remove_all_gcinodes() - remove all unprocessed gc inodes
 */
void nilfs_remove_all_gcinodes(struct the_nilfs *nilfs)
{
	struct list_head *head = &nilfs->ns_gc_inodes;
	struct nilfs_inode_info *ii;

	while (!list_empty(head)) {
		ii = list_first_entry(head, struct nilfs_inode_info, i_dirty);
		list_del_init(&ii->i_dirty);
		truncate_inode_pages(&ii->vfs_inode.i_data, 0);
		nilfs_btnode_cache_clear(&ii->i_btnode_cache);
		iput(&ii->vfs_inode);
	}
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/gcinode.c */
/************************************************************/
/*
 * ioctl.c - NILFS ioctl operations.
 *
 * Copyright (C) 2007, 2008 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by Koji Sato <koji@osrg.net>.
 */

// #include <linux/fs.h>
#include <linux/wait.h>
// #include <linux/slab.h>
#include <linux/capability.h>	/* capable() */
#include <linux/uaccess.h>	/* copy_from_user(), copy_to_user() */
#include <linux/vmalloc.h>
#include <linux/compat.h>	/* compat_ptr() */
// #include <linux/mount.h>	/* mnt_want_write_file(), mnt_drop_write_file() */
// #include <linux/buffer_head.h>
// #include <linux/nilfs2_fs.h>
// #include "nilfs.h"
// #include "segment.h"
// #include "bmap.h"
// #include "cpfile.h"
// #include "sufile.h"
// #include "dat.h"

/**
 * nilfs_ioctl_wrap_copy - wrapping function of get/set metadata info
 * @nilfs: nilfs object
 * @argv: vector of arguments from userspace
 * @dir: set of direction flags
 * @dofunc: concrete function of get/set metadata info
 *
 * Description: nilfs_ioctl_wrap_copy() gets/sets metadata info by means of
 * calling dofunc() function on the basis of @argv argument.
 *
 * Return Value: On success, 0 is returned and requested metadata info
 * is copied into userspace. On error, one of the following
 * negative error codes is returned.
 *
 * %-EINVAL - Invalid arguments from userspace.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EFAULT - Failure during execution of requested operation.
 */
static int nilfs_ioctl_wrap_copy(struct the_nilfs *nilfs,
				 struct nilfs_argv *argv, int dir,
				 ssize_t (*dofunc)(struct the_nilfs *,
						   __u64 *, int,
						   void *, size_t, size_t))
{
	void *buf;
	void __user *base = (void __user *)(unsigned long)argv->v_base;
	size_t maxmembs, total, n;
	ssize_t nr;
	int ret, i;
	__u64 pos, ppos;

	if (argv->v_nmembs == 0)
		return 0;

	if (argv->v_size > PAGE_SIZE)
		return -EINVAL;

	/*
	 * Reject pairs of a start item position (argv->v_index) and a
	 * total count (argv->v_nmembs) which leads position 'pos' to
	 * overflow by the increment at the end of the loop.
	 */
	if (argv->v_index > ~(__u64)0 - argv->v_nmembs)
		return -EINVAL;

	buf = (void *)__get_free_pages(GFP_NOFS, 0);
	if (unlikely(!buf))
		return -ENOMEM;
	maxmembs = PAGE_SIZE / argv->v_size;

	ret = 0;
	total = 0;
	pos = argv->v_index;
	for (i = 0; i < argv->v_nmembs; i += n) {
		n = (argv->v_nmembs - i < maxmembs) ?
			argv->v_nmembs - i : maxmembs;
		if ((dir & _IOC_WRITE) &&
		    copy_from_user(buf, base + argv->v_size * i,
				   argv->v_size * n)) {
			ret = -EFAULT;
			break;
		}
		ppos = pos;
		nr = dofunc(nilfs, &pos, argv->v_flags, buf, argv->v_size,
			       n);
		if (nr < 0) {
			ret = nr;
			break;
		}
		if ((dir & _IOC_READ) &&
		    copy_to_user(base + argv->v_size * i, buf,
				 argv->v_size * nr)) {
			ret = -EFAULT;
			break;
		}
		total += nr;
		if ((size_t)nr < n)
			break;
		if (pos == ppos)
			pos += n;
	}
	argv->v_nmembs = total;

	free_pages((unsigned long)buf, 0);
	return ret;
}

/**
 * nilfs_ioctl_getflags - ioctl to support lsattr
 */
static int nilfs_ioctl_getflags(struct inode *inode, void __user *argp)
{
	unsigned int flags = NILFS_I(inode)->i_flags & FS_FL_USER_VISIBLE;

	return put_user(flags, (int __user *)argp);
}

/**
 * nilfs_ioctl_setflags - ioctl to support chattr
 */
static int nilfs_ioctl_setflags(struct inode *inode, struct file *filp,
				void __user *argp)
{
	struct nilfs_transaction_info ti;
	unsigned int flags, oldflags;
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (get_user(flags, (int __user *)argp))
		return -EFAULT;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	flags = nilfs_mask_flags(inode->i_mode, flags);

	mutex_lock(&inode->i_mutex);

	oldflags = NILFS_I(inode)->i_flags;

	/*
	 * The IMMUTABLE and APPEND_ONLY flags can only be changed by the
	 * relevant capability.
	 */
	ret = -EPERM;
	if (((flags ^ oldflags) & (FS_APPEND_FL | FS_IMMUTABLE_FL)) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		goto out;

	ret = nilfs_transaction_begin(inode->i_sb, &ti, 0);
	if (ret)
		goto out;

	NILFS_I(inode)->i_flags = (oldflags & ~FS_FL_USER_MODIFIABLE) |
		(flags & FS_FL_USER_MODIFIABLE);

	nilfs_set_inode_flags(inode);
	inode->i_ctime = CURRENT_TIME;
	if (IS_SYNC(inode))
		nilfs_set_transaction_flag(NILFS_TI_SYNC);

	nilfs_mark_inode_dirty(inode);
	ret = nilfs_transaction_commit(inode->i_sb);
out:
	mutex_unlock(&inode->i_mutex);
	mnt_drop_write_file(filp);
	return ret;
}

/**
 * nilfs_ioctl_getversion - get info about a file's version (generation number)
 */
static int nilfs_ioctl_getversion(struct inode *inode, void __user *argp)
{
	return put_user(inode->i_generation, (int __user *)argp);
}

/**
 * nilfs_ioctl_change_cpmode - change checkpoint mode (checkpoint/snapshot)
 * @inode: inode object
 * @filp: file object
 * @cmd: ioctl's request code
 * @argp: pointer on argument from userspace
 *
 * Description: nilfs_ioctl_change_cpmode() function changes mode of
 * given checkpoint between checkpoint and snapshot state. This ioctl
 * is used in chcp and mkcp utilities.
 *
 * Return Value: On success, 0 is returned and mode of a checkpoint is
 * changed. On error, one of the following negative error codes
 * is returned.
 *
 * %-EPERM - Operation not permitted.
 *
 * %-EFAULT - Failure during checkpoint mode changing.
 */
static int nilfs_ioctl_change_cpmode(struct inode *inode, struct file *filp,
				     unsigned int cmd, void __user *argp)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	struct nilfs_transaction_info ti;
	struct nilfs_cpmode cpmode;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = -EFAULT;
	if (copy_from_user(&cpmode, argp, sizeof(cpmode)))
		goto out;

	mutex_lock(&nilfs->ns_snapshot_mount_mutex);

	nilfs_transaction_begin(inode->i_sb, &ti, 0);
	ret = nilfs_cpfile_change_cpmode(
		nilfs->ns_cpfile, cpmode.cm_cno, cpmode.cm_mode);
	if (unlikely(ret < 0))
		nilfs_transaction_abort(inode->i_sb);
	else
		nilfs_transaction_commit(inode->i_sb); /* never fails */

	mutex_unlock(&nilfs->ns_snapshot_mount_mutex);
out:
	mnt_drop_write_file(filp);
	return ret;
}

/**
 * nilfs_ioctl_delete_checkpoint - remove checkpoint
 * @inode: inode object
 * @filp: file object
 * @cmd: ioctl's request code
 * @argp: pointer on argument from userspace
 *
 * Description: nilfs_ioctl_delete_checkpoint() function removes
 * checkpoint from NILFS2 file system. This ioctl is used in rmcp
 * utility.
 *
 * Return Value: On success, 0 is returned and a checkpoint is
 * removed. On error, one of the following negative error codes
 * is returned.
 *
 * %-EPERM - Operation not permitted.
 *
 * %-EFAULT - Failure during checkpoint removing.
 */
static int
nilfs_ioctl_delete_checkpoint(struct inode *inode, struct file *filp,
			      unsigned int cmd, void __user *argp)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	struct nilfs_transaction_info ti;
	__u64 cno;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = -EFAULT;
	if (copy_from_user(&cno, argp, sizeof(cno)))
		goto out;

	nilfs_transaction_begin(inode->i_sb, &ti, 0);
	ret = nilfs_cpfile_delete_checkpoint(nilfs->ns_cpfile, cno);
	if (unlikely(ret < 0))
		nilfs_transaction_abort(inode->i_sb);
	else
		nilfs_transaction_commit(inode->i_sb); /* never fails */
out:
	mnt_drop_write_file(filp);
	return ret;
}

/**
 * nilfs_ioctl_do_get_cpinfo - callback method getting info about checkpoints
 * @nilfs: nilfs object
 * @posp: pointer on array of checkpoint's numbers
 * @flags: checkpoint mode (checkpoint or snapshot)
 * @buf: buffer for storing checkponts' info
 * @size: size in bytes of one checkpoint info item in array
 * @nmembs: number of checkpoints in array (numbers and infos)
 *
 * Description: nilfs_ioctl_do_get_cpinfo() function returns info about
 * requested checkpoints. The NILFS_IOCTL_GET_CPINFO ioctl is used in
 * lscp utility and by nilfs_cleanerd daemon.
 *
 * Return value: count of nilfs_cpinfo structures in output buffer.
 */
static ssize_t
nilfs_ioctl_do_get_cpinfo(struct the_nilfs *nilfs, __u64 *posp, int flags,
			  void *buf, size_t size, size_t nmembs)
{
	int ret;

	down_read(&nilfs->ns_segctor_sem);
	ret = nilfs_cpfile_get_cpinfo(nilfs->ns_cpfile, posp, flags, buf,
				      size, nmembs);
	up_read(&nilfs->ns_segctor_sem);
	return ret;
}

/**
 * nilfs_ioctl_get_cpstat - get checkpoints statistics
 * @inode: inode object
 * @filp: file object
 * @cmd: ioctl's request code
 * @argp: pointer on argument from userspace
 *
 * Description: nilfs_ioctl_get_cpstat() returns information about checkpoints.
 * The NILFS_IOCTL_GET_CPSTAT ioctl is used by lscp, rmcp utilities
 * and by nilfs_cleanerd daemon.
 *
 * Return Value: On success, 0 is returned, and checkpoints information is
 * copied into userspace pointer @argp. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EFAULT - Failure during getting checkpoints statistics.
 */
static int nilfs_ioctl_get_cpstat(struct inode *inode, struct file *filp,
				  unsigned int cmd, void __user *argp)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	struct nilfs_cpstat cpstat;
	int ret;

	down_read(&nilfs->ns_segctor_sem);
	ret = nilfs_cpfile_get_stat(nilfs->ns_cpfile, &cpstat);
	up_read(&nilfs->ns_segctor_sem);
	if (ret < 0)
		return ret;

	if (copy_to_user(argp, &cpstat, sizeof(cpstat)))
		ret = -EFAULT;
	return ret;
}

/**
 * nilfs_ioctl_do_get_suinfo - callback method getting segment usage info
 * @nilfs: nilfs object
 * @posp: pointer on array of segment numbers
 * @flags: *not used*
 * @buf: buffer for storing suinfo array
 * @size: size in bytes of one suinfo item in array
 * @nmembs: count of segment numbers and suinfos in array
 *
 * Description: nilfs_ioctl_do_get_suinfo() function returns segment usage
 * info about requested segments. The NILFS_IOCTL_GET_SUINFO ioctl is used
 * in lssu, nilfs_resize utilities and by nilfs_cleanerd daemon.
 *
 * Return value: count of nilfs_suinfo structures in output buffer.
 */
static ssize_t
nilfs_ioctl_do_get_suinfo(struct the_nilfs *nilfs, __u64 *posp, int flags,
			  void *buf, size_t size, size_t nmembs)
{
	int ret;

	down_read(&nilfs->ns_segctor_sem);
	ret = nilfs_sufile_get_suinfo(nilfs->ns_sufile, *posp, buf, size,
				      nmembs);
	up_read(&nilfs->ns_segctor_sem);
	return ret;
}

/**
 * nilfs_ioctl_get_sustat - get segment usage statistics
 * @inode: inode object
 * @filp: file object
 * @cmd: ioctl's request code
 * @argp: pointer on argument from userspace
 *
 * Description: nilfs_ioctl_get_sustat() returns segment usage statistics.
 * The NILFS_IOCTL_GET_SUSTAT ioctl is used in lssu, nilfs_resize utilities
 * and by nilfs_cleanerd daemon.
 *
 * Return Value: On success, 0 is returned, and segment usage information is
 * copied into userspace pointer @argp. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EFAULT - Failure during getting segment usage statistics.
 */
static int nilfs_ioctl_get_sustat(struct inode *inode, struct file *filp,
				  unsigned int cmd, void __user *argp)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	struct nilfs_sustat sustat;
	int ret;

	down_read(&nilfs->ns_segctor_sem);
	ret = nilfs_sufile_get_stat(nilfs->ns_sufile, &sustat);
	up_read(&nilfs->ns_segctor_sem);
	if (ret < 0)
		return ret;

	if (copy_to_user(argp, &sustat, sizeof(sustat)))
		ret = -EFAULT;
	return ret;
}

/**
 * nilfs_ioctl_do_get_vinfo - callback method getting virtual blocks info
 * @nilfs: nilfs object
 * @posp: *not used*
 * @flags: *not used*
 * @buf: buffer for storing array of nilfs_vinfo structures
 * @size: size in bytes of one vinfo item in array
 * @nmembs: count of vinfos in array
 *
 * Description: nilfs_ioctl_do_get_vinfo() function returns information
 * on virtual block addresses. The NILFS_IOCTL_GET_VINFO ioctl is used
 * by nilfs_cleanerd daemon.
 *
 * Return value: count of nilfs_vinfo structures in output buffer.
 */
static ssize_t
nilfs_ioctl_do_get_vinfo(struct the_nilfs *nilfs, __u64 *posp, int flags,
			 void *buf, size_t size, size_t nmembs)
{
	int ret;

	down_read(&nilfs->ns_segctor_sem);
	ret = nilfs_dat_get_vinfo(nilfs->ns_dat, buf, size, nmembs);
	up_read(&nilfs->ns_segctor_sem);
	return ret;
}

/**
 * nilfs_ioctl_do_get_bdescs - callback method getting disk block descriptors
 * @nilfs: nilfs object
 * @posp: *not used*
 * @flags: *not used*
 * @buf: buffer for storing array of nilfs_bdesc structures
 * @size: size in bytes of one bdesc item in array
 * @nmembs: count of bdescs in array
 *
 * Description: nilfs_ioctl_do_get_bdescs() function returns information
 * about descriptors of disk block numbers. The NILFS_IOCTL_GET_BDESCS ioctl
 * is used by nilfs_cleanerd daemon.
 *
 * Return value: count of nilfs_bdescs structures in output buffer.
 */
static ssize_t
nilfs_ioctl_do_get_bdescs(struct the_nilfs *nilfs, __u64 *posp, int flags,
			  void *buf, size_t size, size_t nmembs)
{
	struct nilfs_bmap *bmap = NILFS_I(nilfs->ns_dat)->i_bmap;
	struct nilfs_bdesc *bdescs = buf;
	int ret, i;

	down_read(&nilfs->ns_segctor_sem);
	for (i = 0; i < nmembs; i++) {
		ret = nilfs_bmap_lookup_at_level(bmap,
						 bdescs[i].bd_offset,
						 bdescs[i].bd_level + 1,
						 &bdescs[i].bd_blocknr);
		if (ret < 0) {
			if (ret != -ENOENT) {
				up_read(&nilfs->ns_segctor_sem);
				return ret;
			}
			bdescs[i].bd_blocknr = 0;
		}
	}
	up_read(&nilfs->ns_segctor_sem);
	return nmembs;
}

/**
 * nilfs_ioctl_get_bdescs - get disk block descriptors
 * @inode: inode object
 * @filp: file object
 * @cmd: ioctl's request code
 * @argp: pointer on argument from userspace
 *
 * Description: nilfs_ioctl_do_get_bdescs() function returns information
 * about descriptors of disk block numbers. The NILFS_IOCTL_GET_BDESCS ioctl
 * is used by nilfs_cleanerd daemon.
 *
 * Return Value: On success, 0 is returned, and disk block descriptors are
 * copied into userspace pointer @argp. On error, one of the following
 * negative error codes is returned.
 *
 * %-EINVAL - Invalid arguments from userspace.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EFAULT - Failure during getting disk block descriptors.
 */
static int nilfs_ioctl_get_bdescs(struct inode *inode, struct file *filp,
				  unsigned int cmd, void __user *argp)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	struct nilfs_argv argv;
	int ret;

	if (copy_from_user(&argv, argp, sizeof(argv)))
		return -EFAULT;

	if (argv.v_size != sizeof(struct nilfs_bdesc))
		return -EINVAL;

	ret = nilfs_ioctl_wrap_copy(nilfs, &argv, _IOC_DIR(cmd),
				    nilfs_ioctl_do_get_bdescs);
	if (ret < 0)
		return ret;

	if (copy_to_user(argp, &argv, sizeof(argv)))
		ret = -EFAULT;
	return ret;
}

/**
 * nilfs_ioctl_move_inode_block - prepare data/node block for moving by GC
 * @inode: inode object
 * @vdesc: descriptor of virtual block number
 * @buffers: list of moving buffers
 *
 * Description: nilfs_ioctl_move_inode_block() function registers data/node
 * buffer in the GC pagecache and submit read request.
 *
 * Return Value: On success, 0 is returned. On error, one of the following
 * negative error codes is returned.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - Requested block doesn't exist.
 *
 * %-EEXIST - Blocks conflict is detected.
 */
static int nilfs_ioctl_move_inode_block(struct inode *inode,
					struct nilfs_vdesc *vdesc,
					struct list_head *buffers)
{
	struct buffer_head *bh;
	int ret;

	if (vdesc->vd_flags == 0)
		ret = nilfs_gccache_submit_read_data(
			inode, vdesc->vd_offset, vdesc->vd_blocknr,
			vdesc->vd_vblocknr, &bh);
	else
		ret = nilfs_gccache_submit_read_node(
			inode, vdesc->vd_blocknr, vdesc->vd_vblocknr, &bh);

	if (unlikely(ret < 0)) {
		if (ret == -ENOENT)
			printk(KERN_CRIT
			       "%s: invalid virtual block address (%s): "
			       "ino=%llu, cno=%llu, offset=%llu, "
			       "blocknr=%llu, vblocknr=%llu\n",
			       __func__, vdesc->vd_flags ? "node" : "data",
			       (unsigned long long)vdesc->vd_ino,
			       (unsigned long long)vdesc->vd_cno,
			       (unsigned long long)vdesc->vd_offset,
			       (unsigned long long)vdesc->vd_blocknr,
			       (unsigned long long)vdesc->vd_vblocknr);
		return ret;
	}
	if (unlikely(!list_empty(&bh->b_assoc_buffers))) {
		printk(KERN_CRIT "%s: conflicting %s buffer: ino=%llu, "
		       "cno=%llu, offset=%llu, blocknr=%llu, vblocknr=%llu\n",
		       __func__, vdesc->vd_flags ? "node" : "data",
		       (unsigned long long)vdesc->vd_ino,
		       (unsigned long long)vdesc->vd_cno,
		       (unsigned long long)vdesc->vd_offset,
		       (unsigned long long)vdesc->vd_blocknr,
		       (unsigned long long)vdesc->vd_vblocknr);
		brelse(bh);
		return -EEXIST;
	}
	list_add_tail(&bh->b_assoc_buffers, buffers);
	return 0;
}

/**
 * nilfs_ioctl_move_blocks - move valid inode's blocks during garbage collection
 * @sb: superblock object
 * @argv: vector of arguments from userspace
 * @buf: array of nilfs_vdesc structures
 *
 * Description: nilfs_ioctl_move_blocks() function reads valid data/node
 * blocks that garbage collector specified with the array of nilfs_vdesc
 * structures and stores them into page caches of GC inodes.
 *
 * Return Value: Number of processed nilfs_vdesc structures or
 * error code, otherwise.
 */
static int nilfs_ioctl_move_blocks(struct super_block *sb,
				   struct nilfs_argv *argv, void *buf)
{
	size_t nmembs = argv->v_nmembs;
	struct the_nilfs *nilfs = sb->s_fs_info;
	struct inode *inode;
	struct nilfs_vdesc *vdesc;
	struct buffer_head *bh, *n;
	LIST_HEAD(buffers);
	ino_t ino;
	__u64 cno;
	int i, ret;

	for (i = 0, vdesc = buf; i < nmembs; ) {
		ino = vdesc->vd_ino;
		cno = vdesc->vd_cno;
		inode = nilfs_iget_for_gc(sb, ino, cno);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			goto failed;
		}
		if (list_empty(&NILFS_I(inode)->i_dirty)) {
			/*
			 * Add the inode to GC inode list. Garbage Collection
			 * is serialized and no two processes manipulate the
			 * list simultaneously.
			 */
			igrab(inode);
			list_add(&NILFS_I(inode)->i_dirty,
				 &nilfs->ns_gc_inodes);
		}

		do {
			ret = nilfs_ioctl_move_inode_block(inode, vdesc,
							   &buffers);
			if (unlikely(ret < 0)) {
				iput(inode);
				goto failed;
			}
			vdesc++;
		} while (++i < nmembs &&
			 vdesc->vd_ino == ino && vdesc->vd_cno == cno);

		iput(inode); /* The inode still remains in GC inode list */
	}

	list_for_each_entry_safe(bh, n, &buffers, b_assoc_buffers) {
		ret = nilfs_gccache_wait_and_mark_dirty(bh);
		if (unlikely(ret < 0)) {
			WARN_ON(ret == -EEXIST);
			goto failed;
		}
		list_del_init(&bh->b_assoc_buffers);
		brelse(bh);
	}
	return nmembs;

 failed:
	list_for_each_entry_safe(bh, n, &buffers, b_assoc_buffers) {
		list_del_init(&bh->b_assoc_buffers);
		brelse(bh);
	}
	return ret;
}

/**
 * nilfs_ioctl_delete_checkpoints - delete checkpoints
 * @nilfs: nilfs object
 * @argv: vector of arguments from userspace
 * @buf: array of periods of checkpoints numbers
 *
 * Description: nilfs_ioctl_delete_checkpoints() function deletes checkpoints
 * in the period from p_start to p_end, excluding p_end itself. The checkpoints
 * which have been already deleted are ignored.
 *
 * Return Value: Number of processed nilfs_period structures or
 * error code, otherwise.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EINVAL - invalid checkpoints.
 */
static int nilfs_ioctl_delete_checkpoints(struct the_nilfs *nilfs,
					  struct nilfs_argv *argv, void *buf)
{
	size_t nmembs = argv->v_nmembs;
	struct inode *cpfile = nilfs->ns_cpfile;
	struct nilfs_period *periods = buf;
	int ret, i;

	for (i = 0; i < nmembs; i++) {
		ret = nilfs_cpfile_delete_checkpoints(
			cpfile, periods[i].p_start, periods[i].p_end);
		if (ret < 0)
			return ret;
	}
	return nmembs;
}

/**
 * nilfs_ioctl_free_vblocknrs - free virtual block numbers
 * @nilfs: nilfs object
 * @argv: vector of arguments from userspace
 * @buf: array of virtual block numbers
 *
 * Description: nilfs_ioctl_free_vblocknrs() function frees
 * the virtual block numbers specified by @buf and @argv->v_nmembs.
 *
 * Return Value: Number of processed virtual block numbers or
 * error code, otherwise.
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-ENOENT - The virtual block number have not been allocated.
 */
static int nilfs_ioctl_free_vblocknrs(struct the_nilfs *nilfs,
				      struct nilfs_argv *argv, void *buf)
{
	size_t nmembs = argv->v_nmembs;
	int ret;

	ret = nilfs_dat_freev(nilfs->ns_dat, buf, nmembs);

	return (ret < 0) ? ret : nmembs;
}

/**
 * nilfs_ioctl_mark_blocks_dirty - mark blocks dirty
 * @nilfs: nilfs object
 * @argv: vector of arguments from userspace
 * @buf: array of block descriptors
 *
 * Description: nilfs_ioctl_mark_blocks_dirty() function marks
 * metadata file or data blocks as dirty.
 *
 * Return Value: Number of processed block descriptors or
 * error code, otherwise.
 *
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EIO - I/O error
 *
 * %-ENOENT - the specified block does not exist (hole block)
 */
static int nilfs_ioctl_mark_blocks_dirty(struct the_nilfs *nilfs,
					 struct nilfs_argv *argv, void *buf)
{
	size_t nmembs = argv->v_nmembs;
	struct nilfs_bmap *bmap = NILFS_I(nilfs->ns_dat)->i_bmap;
	struct nilfs_bdesc *bdescs = buf;
	int ret, i;

	for (i = 0; i < nmembs; i++) {
		/* XXX: use macro or inline func to check liveness */
		ret = nilfs_bmap_lookup_at_level(bmap,
						 bdescs[i].bd_offset,
						 bdescs[i].bd_level + 1,
						 &bdescs[i].bd_blocknr);
		if (ret < 0) {
			if (ret != -ENOENT)
				return ret;
			bdescs[i].bd_blocknr = 0;
		}
		if (bdescs[i].bd_blocknr != bdescs[i].bd_oblocknr)
			/* skip dead block */
			continue;
		if (bdescs[i].bd_level == 0) {
			ret = nilfs_mdt_mark_block_dirty(nilfs->ns_dat,
							 bdescs[i].bd_offset);
			if (ret < 0) {
				WARN_ON(ret == -ENOENT);
				return ret;
			}
		} else {
			ret = nilfs_bmap_mark(bmap, bdescs[i].bd_offset,
					      bdescs[i].bd_level);
			if (ret < 0) {
				WARN_ON(ret == -ENOENT);
				return ret;
			}
		}
	}
	return nmembs;
}

int nilfs_ioctl_prepare_clean_segments(struct the_nilfs *nilfs,
				       struct nilfs_argv *argv, void **kbufs)
{
	const char *msg;
	int ret;

	ret = nilfs_ioctl_delete_checkpoints(nilfs, &argv[1], kbufs[1]);
	if (ret < 0) {
		/*
		 * can safely abort because checkpoints can be removed
		 * independently.
		 */
		msg = "cannot delete checkpoints";
		goto failed;
	}
	ret = nilfs_ioctl_free_vblocknrs(nilfs, &argv[2], kbufs[2]);
	if (ret < 0) {
		/*
		 * can safely abort because DAT file is updated atomically
		 * using a copy-on-write technique.
		 */
		msg = "cannot delete virtual blocks from DAT file";
		goto failed;
	}
	ret = nilfs_ioctl_mark_blocks_dirty(nilfs, &argv[3], kbufs[3]);
	if (ret < 0) {
		/*
		 * can safely abort because the operation is nondestructive.
		 */
		msg = "cannot mark copying blocks dirty";
		goto failed;
	}
	return 0;

 failed:
	printk(KERN_ERR "NILFS: GC failed during preparation: %s: err=%d\n",
	       msg, ret);
	return ret;
}

/**
 * nilfs_ioctl_clean_segments - clean segments
 * @inode: inode object
 * @filp: file object
 * @cmd: ioctl's request code
 * @argp: pointer on argument from userspace
 *
 * Description: nilfs_ioctl_clean_segments() function makes garbage
 * collection operation in the environment of requested parameters
 * from userspace. The NILFS_IOCTL_CLEAN_SEGMENTS ioctl is used by
 * nilfs_cleanerd daemon.
 *
 * Return Value: On success, 0 is returned or error code, otherwise.
 */
static int nilfs_ioctl_clean_segments(struct inode *inode, struct file *filp,
				      unsigned int cmd, void __user *argp)
{
	struct nilfs_argv argv[5];
	static const size_t argsz[5] = {
		sizeof(struct nilfs_vdesc),
		sizeof(struct nilfs_period),
		sizeof(__u64),
		sizeof(struct nilfs_bdesc),
		sizeof(__u64),
	};
	void __user *base;
	void *kbufs[5];
	struct the_nilfs *nilfs;
	size_t len, nsegs;
	int n, ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = -EFAULT;
	if (copy_from_user(argv, argp, sizeof(argv)))
		goto out;

	ret = -EINVAL;
	nsegs = argv[4].v_nmembs;
	if (argv[4].v_size != argsz[4])
		goto out;
	if (nsegs > UINT_MAX / sizeof(__u64))
		goto out;

	/*
	 * argv[4] points to segment numbers this ioctl cleans.  We
	 * use kmalloc() for its buffer because memory used for the
	 * segment numbers is enough small.
	 */
	kbufs[4] = memdup_user((void __user *)(unsigned long)argv[4].v_base,
			       nsegs * sizeof(__u64));
	if (IS_ERR(kbufs[4])) {
		ret = PTR_ERR(kbufs[4]);
		goto out;
	}
	nilfs = inode->i_sb->s_fs_info;

	for (n = 0; n < 4; n++) {
		ret = -EINVAL;
		if (argv[n].v_size != argsz[n])
			goto out_free;

		if (argv[n].v_nmembs > nsegs * nilfs->ns_blocks_per_segment)
			goto out_free;

		if (argv[n].v_nmembs >= UINT_MAX / argv[n].v_size)
			goto out_free;

		len = argv[n].v_size * argv[n].v_nmembs;
		base = (void __user *)(unsigned long)argv[n].v_base;
		if (len == 0) {
			kbufs[n] = NULL;
			continue;
		}

		kbufs[n] = vmalloc(len);
		if (!kbufs[n]) {
			ret = -ENOMEM;
			goto out_free;
		}
		if (copy_from_user(kbufs[n], base, len)) {
			ret = -EFAULT;
			vfree(kbufs[n]);
			goto out_free;
		}
	}

	/*
	 * nilfs_ioctl_move_blocks() will call nilfs_iget_for_gc(),
	 * which will operates an inode list without blocking.
	 * To protect the list from concurrent operations,
	 * nilfs_ioctl_move_blocks should be atomic operation.
	 */
	if (test_and_set_bit(THE_NILFS_GC_RUNNING, &nilfs->ns_flags)) {
		ret = -EBUSY;
		goto out_free;
	}

	ret = nilfs_ioctl_move_blocks(inode->i_sb, &argv[0], kbufs[0]);
	if (ret < 0)
		printk(KERN_ERR "NILFS: GC failed during preparation: "
			"cannot read source blocks: err=%d\n", ret);
	else {
		if (nilfs_sb_need_update(nilfs))
			set_nilfs_discontinued(nilfs);
		ret = nilfs_clean_segments(inode->i_sb, argv, kbufs);
	}

	nilfs_remove_all_gcinodes(nilfs);
	clear_nilfs_gc_running(nilfs);

out_free:
	while (--n >= 0)
		vfree(kbufs[n]);
	kfree(kbufs[4]);
out:
	mnt_drop_write_file(filp);
	return ret;
}

/**
 * nilfs_ioctl_sync - make a checkpoint
 * @inode: inode object
 * @filp: file object
 * @cmd: ioctl's request code
 * @argp: pointer on argument from userspace
 *
 * Description: nilfs_ioctl_sync() function constructs a logical segment
 * for checkpointing.  This function guarantees that all modified data
 * and metadata are written out to the device when it successfully
 * returned.
 *
 * Return Value: On success, 0 is retured. On errors, one of the following
 * negative error code is returned.
 *
 * %-EROFS - Read only filesystem.
 *
 * %-EIO - I/O error
 *
 * %-ENOSPC - No space left on device (only in a panic state).
 *
 * %-ERESTARTSYS - Interrupted.
 *
 * %-ENOMEM - Insufficient memory available.
 *
 * %-EFAULT - Failure during execution of requested operation.
 */
static int nilfs_ioctl_sync(struct inode *inode, struct file *filp,
			    unsigned int cmd, void __user *argp)
{
	__u64 cno;
	int ret;
	struct the_nilfs *nilfs;

	ret = nilfs_construct_segment(inode->i_sb);
	if (ret < 0)
		return ret;

	nilfs = inode->i_sb->s_fs_info;
	if (nilfs_test_opt(nilfs, BARRIER)) {
		ret = blkdev_issue_flush(inode->i_sb->s_bdev, GFP_KERNEL, NULL);
		if (ret == -EIO)
			return ret;
	}

	if (argp != NULL) {
		down_read(&nilfs->ns_segctor_sem);
		cno = nilfs->ns_cno - 1;
		up_read(&nilfs->ns_segctor_sem);
		if (copy_to_user(argp, &cno, sizeof(cno)))
			return -EFAULT;
	}
	return 0;
}

/**
 * nilfs_ioctl_resize - resize NILFS2 volume
 * @inode: inode object
 * @filp: file object
 * @argp: pointer on argument from userspace
 *
 * Return Value: On success, 0 is returned or error code, otherwise.
 */
static int nilfs_ioctl_resize(struct inode *inode, struct file *filp,
			      void __user *argp)
{
	__u64 newsize;
	int ret = -EPERM;

	if (!capable(CAP_SYS_ADMIN))
		goto out;

	ret = mnt_want_write_file(filp);
	if (ret)
		goto out;

	ret = -EFAULT;
	if (copy_from_user(&newsize, argp, sizeof(newsize)))
		goto out_drop_write;

	ret = nilfs_resize_fs(inode->i_sb, newsize);

out_drop_write:
	mnt_drop_write_file(filp);
out:
	return ret;
}

/**
 * nilfs_ioctl_trim_fs() - trim ioctl handle function
 * @inode: inode object
 * @argp: pointer on argument from userspace
 *
 * Decription: nilfs_ioctl_trim_fs is the FITRIM ioctl handle function. It
 * checks the arguments from userspace and calls nilfs_sufile_trim_fs, which
 * performs the actual trim operation.
 *
 * Return Value: On success, 0 is returned or negative error code, otherwise.
 */
static int nilfs_ioctl_trim_fs(struct inode *inode, void __user *argp)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	struct request_queue *q = bdev_get_queue(nilfs->ns_bdev);
	struct fstrim_range range;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!blk_queue_discard(q))
		return -EOPNOTSUPP;

	if (copy_from_user(&range, argp, sizeof(range)))
		return -EFAULT;

	range.minlen = max_t(u64, range.minlen, q->limits.discard_granularity);

	down_read(&nilfs->ns_segctor_sem);
	ret = nilfs_sufile_trim_fs(nilfs->ns_sufile, &range);
	up_read(&nilfs->ns_segctor_sem);

	if (ret < 0)
		return ret;

	if (copy_to_user(argp, &range, sizeof(range)))
		return -EFAULT;

	return 0;
}

/**
 * nilfs_ioctl_set_alloc_range - limit range of segments to be allocated
 * @inode: inode object
 * @argp: pointer on argument from userspace
 *
 * Decription: nilfs_ioctl_set_alloc_range() function defines lower limit
 * of segments in bytes and upper limit of segments in bytes.
 * The NILFS_IOCTL_SET_ALLOC_RANGE is used by nilfs_resize utility.
 *
 * Return Value: On success, 0 is returned or error code, otherwise.
 */
static int nilfs_ioctl_set_alloc_range(struct inode *inode, void __user *argp)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	__u64 range[2];
	__u64 minseg, maxseg;
	unsigned long segbytes;
	int ret = -EPERM;

	if (!capable(CAP_SYS_ADMIN))
		goto out;

	ret = -EFAULT;
	if (copy_from_user(range, argp, sizeof(__u64[2])))
		goto out;

	ret = -ERANGE;
	if (range[1] > i_size_read(inode->i_sb->s_bdev->bd_inode))
		goto out;

	segbytes = nilfs->ns_blocks_per_segment * nilfs->ns_blocksize;

	minseg = range[0] + segbytes - 1;
	do_div(minseg, segbytes);
	maxseg = NILFS_SB2_OFFSET_BYTES(range[1]);
	do_div(maxseg, segbytes);
	maxseg--;

	ret = nilfs_sufile_set_alloc_range(nilfs->ns_sufile, minseg, maxseg);
out:
	return ret;
}

/**
 * nilfs_ioctl_get_info - wrapping function of get metadata info
 * @inode: inode object
 * @filp: file object
 * @cmd: ioctl's request code
 * @argp: pointer on argument from userspace
 * @membsz: size of an item in bytes
 * @dofunc: concrete function of getting metadata info
 *
 * Description: nilfs_ioctl_get_info() gets metadata info by means of
 * calling dofunc() function.
 *
 * Return Value: On success, 0 is returned and requested metadata info
 * is copied into userspace. On error, one of the following
 * negative error codes is returned.
 *
 * %-EINVAL - Invalid arguments from userspace.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EFAULT - Failure during execution of requested operation.
 */
static int nilfs_ioctl_get_info(struct inode *inode, struct file *filp,
				unsigned int cmd, void __user *argp,
				size_t membsz,
				ssize_t (*dofunc)(struct the_nilfs *,
						  __u64 *, int,
						  void *, size_t, size_t))

{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	struct nilfs_argv argv;
	int ret;

	if (copy_from_user(&argv, argp, sizeof(argv)))
		return -EFAULT;

	if (argv.v_size < membsz)
		return -EINVAL;

	ret = nilfs_ioctl_wrap_copy(nilfs, &argv, _IOC_DIR(cmd), dofunc);
	if (ret < 0)
		return ret;

	if (copy_to_user(argp, &argv, sizeof(argv)))
		ret = -EFAULT;
	return ret;
}

/**
 * nilfs_ioctl_set_suinfo - set segment usage info
 * @inode: inode object
 * @filp: file object
 * @cmd: ioctl's request code
 * @argp: pointer on argument from userspace
 *
 * Description: Expects an array of nilfs_suinfo_update structures
 * encapsulated in nilfs_argv and updates the segment usage info
 * according to the flags in nilfs_suinfo_update.
 *
 * Return Value: On success, 0 is returned. On error, one of the
 * following negative error codes is returned.
 *
 * %-EPERM - Not enough permissions
 *
 * %-EFAULT - Error copying input data
 *
 * %-EIO - I/O error.
 *
 * %-ENOMEM - Insufficient amount of memory available.
 *
 * %-EINVAL - Invalid values in input (segment number, flags or nblocks)
 */
static int nilfs_ioctl_set_suinfo(struct inode *inode, struct file *filp,
				unsigned int cmd, void __user *argp)
{
	struct the_nilfs *nilfs = inode->i_sb->s_fs_info;
	struct nilfs_transaction_info ti;
	struct nilfs_argv argv;
	size_t len;
	void __user *base;
	void *kbuf;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = -EFAULT;
	if (copy_from_user(&argv, argp, sizeof(argv)))
		goto out;

	ret = -EINVAL;
	if (argv.v_size < sizeof(struct nilfs_suinfo_update))
		goto out;

	if (argv.v_nmembs > nilfs->ns_nsegments)
		goto out;

	if (argv.v_nmembs >= UINT_MAX / argv.v_size)
		goto out;

	len = argv.v_size * argv.v_nmembs;
	if (!len) {
		ret = 0;
		goto out;
	}

	base = (void __user *)(unsigned long)argv.v_base;
	kbuf = vmalloc(len);
	if (!kbuf) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(kbuf, base, len)) {
		ret = -EFAULT;
		goto out_free;
	}

	nilfs_transaction_begin(inode->i_sb, &ti, 0);
	ret = nilfs_sufile_set_suinfo(nilfs->ns_sufile, kbuf, argv.v_size,
			argv.v_nmembs);
	if (unlikely(ret < 0))
		nilfs_transaction_abort(inode->i_sb);
	else
		nilfs_transaction_commit(inode->i_sb); /* never fails */

out_free:
	vfree(kbuf);
out:
	mnt_drop_write_file(filp);
	return ret;
}

long nilfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		return nilfs_ioctl_getflags(inode, argp);
	case FS_IOC_SETFLAGS:
		return nilfs_ioctl_setflags(inode, filp, argp);
	case FS_IOC_GETVERSION:
		return nilfs_ioctl_getversion(inode, argp);
	case NILFS_IOCTL_CHANGE_CPMODE:
		return nilfs_ioctl_change_cpmode(inode, filp, cmd, argp);
	case NILFS_IOCTL_DELETE_CHECKPOINT:
		return nilfs_ioctl_delete_checkpoint(inode, filp, cmd, argp);
	case NILFS_IOCTL_GET_CPINFO:
		return nilfs_ioctl_get_info(inode, filp, cmd, argp,
					    sizeof(struct nilfs_cpinfo),
					    nilfs_ioctl_do_get_cpinfo);
	case NILFS_IOCTL_GET_CPSTAT:
		return nilfs_ioctl_get_cpstat(inode, filp, cmd, argp);
	case NILFS_IOCTL_GET_SUINFO:
		return nilfs_ioctl_get_info(inode, filp, cmd, argp,
					    sizeof(struct nilfs_suinfo),
					    nilfs_ioctl_do_get_suinfo);
	case NILFS_IOCTL_SET_SUINFO:
		return nilfs_ioctl_set_suinfo(inode, filp, cmd, argp);
	case NILFS_IOCTL_GET_SUSTAT:
		return nilfs_ioctl_get_sustat(inode, filp, cmd, argp);
	case NILFS_IOCTL_GET_VINFO:
		return nilfs_ioctl_get_info(inode, filp, cmd, argp,
					    sizeof(struct nilfs_vinfo),
					    nilfs_ioctl_do_get_vinfo);
	case NILFS_IOCTL_GET_BDESCS:
		return nilfs_ioctl_get_bdescs(inode, filp, cmd, argp);
	case NILFS_IOCTL_CLEAN_SEGMENTS:
		return nilfs_ioctl_clean_segments(inode, filp, cmd, argp);
	case NILFS_IOCTL_SYNC:
		return nilfs_ioctl_sync(inode, filp, cmd, argp);
	case NILFS_IOCTL_RESIZE:
		return nilfs_ioctl_resize(inode, filp, argp);
	case NILFS_IOCTL_SET_ALLOC_RANGE:
		return nilfs_ioctl_set_alloc_range(inode, argp);
	case FITRIM:
		return nilfs_ioctl_trim_fs(inode, argp);
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long nilfs_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	case FS_IOC32_GETVERSION:
		cmd = FS_IOC_GETVERSION;
		break;
	case NILFS_IOCTL_CHANGE_CPMODE:
	case NILFS_IOCTL_DELETE_CHECKPOINT:
	case NILFS_IOCTL_GET_CPINFO:
	case NILFS_IOCTL_GET_CPSTAT:
	case NILFS_IOCTL_GET_SUINFO:
	case NILFS_IOCTL_SET_SUINFO:
	case NILFS_IOCTL_GET_SUSTAT:
	case NILFS_IOCTL_GET_VINFO:
	case NILFS_IOCTL_GET_BDESCS:
	case NILFS_IOCTL_CLEAN_SEGMENTS:
	case NILFS_IOCTL_SYNC:
	case NILFS_IOCTL_RESIZE:
	case NILFS_IOCTL_SET_ALLOC_RANGE:
	case FITRIM:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return nilfs_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif
/************************************************************/
/* ../linux-3.17/fs/nilfs2/ioctl.c */
/************************************************************/
/*
 * sysfs.c - sysfs support implementation.
 *
 * Copyright (C) 2005-2014 Nippon Telegraph and Telephone Corporation.
 * Copyright (C) 2014 HGST, Inc., a Western Digital Company.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Written by Vyacheslav Dubeyko <Vyacheslav.Dubeyko@hgst.com>
 */

#include <linux/kobject.h>

// #include "nilfs.h"
// #include "mdt.h"
// #include "sufile.h"
// #include "cpfile.h"
#include "sysfs.h"

/* /sys/fs/<nilfs>/ */
static struct kset *nilfs_kset;

#define NILFS_SHOW_TIME(time_t_val, buf) ({ \
		struct tm res; \
		int count = 0; \
		time_to_tm(time_t_val, 0, &res); \
		res.tm_year += 1900; \
		res.tm_mon += 1; \
		count = scnprintf(buf, PAGE_SIZE, \
				    "%ld-%.2d-%.2d %.2d:%.2d:%.2d\n", \
				    res.tm_year, res.tm_mon, res.tm_mday, \
				    res.tm_hour, res.tm_min, res.tm_sec);\
		count; \
})

#define NILFS_DEV_INT_GROUP_OPS(name, parent_name) \
static ssize_t nilfs_##name##_attr_show(struct kobject *kobj, \
					struct attribute *attr, char *buf) \
{ \
	struct the_nilfs *nilfs = container_of(kobj->parent, \
						struct the_nilfs, \
						ns_##parent_name##_kobj); \
	struct nilfs_##name##_attr *a = container_of(attr, \
						struct nilfs_##name##_attr, \
						attr); \
	return a->show ? a->show(a, nilfs, buf) : 0; \
} \
static ssize_t nilfs_##name##_attr_store(struct kobject *kobj, \
					 struct attribute *attr, \
					 const char *buf, size_t len) \
{ \
	struct the_nilfs *nilfs = container_of(kobj->parent, \
						struct the_nilfs, \
						ns_##parent_name##_kobj); \
	struct nilfs_##name##_attr *a = container_of(attr, \
						struct nilfs_##name##_attr, \
						attr); \
	return a->store ? a->store(a, nilfs, buf, len) : 0; \
} \
static const struct sysfs_ops nilfs_##name##_attr_ops = { \
	.show	= nilfs_##name##_attr_show, \
	.store	= nilfs_##name##_attr_store, \
};

#define NILFS_DEV_INT_GROUP_TYPE(name, parent_name) \
static void nilfs_##name##_attr_release(struct kobject *kobj) \
{ \
	struct nilfs_sysfs_##parent_name##_subgroups *subgroups; \
	struct the_nilfs *nilfs = container_of(kobj->parent, \
						struct the_nilfs, \
						ns_##parent_name##_kobj); \
	subgroups = nilfs->ns_##parent_name##_subgroups; \
	complete(&subgroups->sg_##name##_kobj_unregister); \
} \
static struct kobj_type nilfs_##name##_ktype = { \
	.default_attrs	= nilfs_##name##_attrs, \
	.sysfs_ops	= &nilfs_##name##_attr_ops, \
	.release	= nilfs_##name##_attr_release, \
};

#define NILFS_DEV_INT_GROUP_FNS(name, parent_name) \
static int nilfs_sysfs_create_##name##_group(struct the_nilfs *nilfs) \
{ \
	struct kobject *parent; \
	struct kobject *kobj; \
	struct completion *kobj_unregister; \
	struct nilfs_sysfs_##parent_name##_subgroups *subgroups; \
	int err; \
	subgroups = nilfs->ns_##parent_name##_subgroups; \
	kobj = &subgroups->sg_##name##_kobj; \
	kobj_unregister = &subgroups->sg_##name##_kobj_unregister; \
	parent = &nilfs->ns_##parent_name##_kobj; \
	kobj->kset = nilfs_kset; \
	init_completion(kobj_unregister); \
	err = kobject_init_and_add(kobj, &nilfs_##name##_ktype, parent, \
				    #name); \
	if (err) \
		return err; \
	return 0; \
} \
static void nilfs_sysfs_delete_##name##_group(struct the_nilfs *nilfs) \
{ \
	kobject_del(&nilfs->ns_##parent_name##_subgroups->sg_##name##_kobj); \
}

/************************************************************************
 *                        NILFS snapshot attrs                          *
 ************************************************************************/

static ssize_t
nilfs_snapshot_inodes_count_show(struct nilfs_snapshot_attr *attr,
				 struct nilfs_root *root, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n",
			(unsigned long long)atomic64_read(&root->inodes_count));
}

static ssize_t
nilfs_snapshot_blocks_count_show(struct nilfs_snapshot_attr *attr,
				 struct nilfs_root *root, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%llu\n",
			(unsigned long long)atomic64_read(&root->blocks_count));
}

static const char snapshot_readme_str[] =
	"The group contains details about mounted snapshot.\n\n"
	"(1) inodes_count\n\tshow number of inodes for snapshot.\n\n"
	"(2) blocks_count\n\tshow number of blocks for snapshot.\n\n";

static ssize_t
nilfs_snapshot_README_show(struct nilfs_snapshot_attr *attr,
			    struct nilfs_root *root, char *buf)
{
	return snprintf(buf, PAGE_SIZE, snapshot_readme_str);
}

NILFS_SNAPSHOT_RO_ATTR(inodes_count);
NILFS_SNAPSHOT_RO_ATTR(blocks_count);
NILFS_SNAPSHOT_RO_ATTR(README);

static struct attribute *nilfs_snapshot_attrs[] = {
	NILFS_SNAPSHOT_ATTR_LIST(inodes_count),
	NILFS_SNAPSHOT_ATTR_LIST(blocks_count),
	NILFS_SNAPSHOT_ATTR_LIST(README),
	NULL,
};

static ssize_t nilfs_snapshot_attr_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct nilfs_root *root =
			container_of(kobj, struct nilfs_root, snapshot_kobj);
	struct nilfs_snapshot_attr *a =
			container_of(attr, struct nilfs_snapshot_attr, attr);

	return a->show ? a->show(a, root, buf) : 0;
}

static ssize_t nilfs_snapshot_attr_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buf, size_t len)
{
	struct nilfs_root *root =
			container_of(kobj, struct nilfs_root, snapshot_kobj);
	struct nilfs_snapshot_attr *a =
			container_of(attr, struct nilfs_snapshot_attr, attr);

	return a->store ? a->store(a, root, buf, len) : 0;
}

static void nilfs_snapshot_attr_release(struct kobject *kobj)
{
	struct nilfs_root *root = container_of(kobj, struct nilfs_root,
						snapshot_kobj);
	complete(&root->snapshot_kobj_unregister);
}

static const struct sysfs_ops nilfs_snapshot_attr_ops = {
	.show	= nilfs_snapshot_attr_show,
	.store	= nilfs_snapshot_attr_store,
};

static struct kobj_type nilfs_snapshot_ktype = {
	.default_attrs	= nilfs_snapshot_attrs,
	.sysfs_ops	= &nilfs_snapshot_attr_ops,
	.release	= nilfs_snapshot_attr_release,
};

int nilfs_sysfs_create_snapshot_group(struct nilfs_root *root)
{
	struct the_nilfs *nilfs;
	struct kobject *parent;
	int err;

	nilfs = root->nilfs;
	parent = &nilfs->ns_dev_subgroups->sg_mounted_snapshots_kobj;
	root->snapshot_kobj.kset = nilfs_kset;
	init_completion(&root->snapshot_kobj_unregister);

	if (root->cno == NILFS_CPTREE_CURRENT_CNO) {
		err = kobject_init_and_add(&root->snapshot_kobj,
					    &nilfs_snapshot_ktype,
					    &nilfs->ns_dev_kobj,
					    "current_checkpoint");
	} else {
		err = kobject_init_and_add(&root->snapshot_kobj,
					    &nilfs_snapshot_ktype,
					    parent,
					    "%llu", root->cno);
	}

	if (err)
		return err;

	return 0;
}

void nilfs_sysfs_delete_snapshot_group(struct nilfs_root *root)
{
	kobject_del(&root->snapshot_kobj);
}

/************************************************************************
 *                    NILFS mounted snapshots attrs                     *
 ************************************************************************/

static const char mounted_snapshots_readme_str[] =
	"The mounted_snapshots group contains group for\n"
	"every mounted snapshot.\n";

static ssize_t
nilfs_mounted_snapshots_README_show(struct nilfs_mounted_snapshots_attr *attr,
				    struct the_nilfs *nilfs, char *buf)
{
	return snprintf(buf, PAGE_SIZE, mounted_snapshots_readme_str);
}

NILFS_MOUNTED_SNAPSHOTS_RO_ATTR(README);

static struct attribute *nilfs_mounted_snapshots_attrs[] = {
	NILFS_MOUNTED_SNAPSHOTS_ATTR_LIST(README),
	NULL,
};

NILFS_DEV_INT_GROUP_OPS(mounted_snapshots, dev);
NILFS_DEV_INT_GROUP_TYPE(mounted_snapshots, dev);
NILFS_DEV_INT_GROUP_FNS(mounted_snapshots, dev);

/************************************************************************
 *                      NILFS checkpoints attrs                         *
 ************************************************************************/

static ssize_t
nilfs_checkpoints_checkpoints_number_show(struct nilfs_checkpoints_attr *attr,
					    struct the_nilfs *nilfs,
					    char *buf)
{
	__u64 ncheckpoints;
	struct nilfs_cpstat cpstat;
	int err;

	down_read(&nilfs->ns_segctor_sem);
	err = nilfs_cpfile_get_stat(nilfs->ns_cpfile, &cpstat);
	up_read(&nilfs->ns_segctor_sem);
	if (err < 0) {
		printk(KERN_ERR "NILFS: unable to get checkpoint stat: err=%d\n",
			err);
		return err;
	}

	ncheckpoints = cpstat.cs_ncps;

	return snprintf(buf, PAGE_SIZE, "%llu\n", ncheckpoints);
}

static ssize_t
nilfs_checkpoints_snapshots_number_show(struct nilfs_checkpoints_attr *attr,
					struct the_nilfs *nilfs,
					char *buf)
{
	__u64 nsnapshots;
	struct nilfs_cpstat cpstat;
	int err;

	down_read(&nilfs->ns_segctor_sem);
	err = nilfs_cpfile_get_stat(nilfs->ns_cpfile, &cpstat);
	up_read(&nilfs->ns_segctor_sem);
	if (err < 0) {
		printk(KERN_ERR "NILFS: unable to get checkpoint stat: err=%d\n",
			err);
		return err;
	}

	nsnapshots = cpstat.cs_nsss;

	return snprintf(buf, PAGE_SIZE, "%llu\n", nsnapshots);
}

static ssize_t
nilfs_checkpoints_last_seg_checkpoint_show(struct nilfs_checkpoints_attr *attr,
					    struct the_nilfs *nilfs,
					    char *buf)
{
	__u64 last_cno;

	spin_lock(&nilfs->ns_last_segment_lock);
	last_cno = nilfs->ns_last_cno;
	spin_unlock(&nilfs->ns_last_segment_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", last_cno);
}

static ssize_t
nilfs_checkpoints_next_checkpoint_show(struct nilfs_checkpoints_attr *attr,
					struct the_nilfs *nilfs,
					char *buf)
{
	__u64 cno;

	down_read(&nilfs->ns_sem);
	cno = nilfs->ns_cno;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%llu\n", cno);
}

static const char checkpoints_readme_str[] =
	"The checkpoints group contains attributes that describe\n"
	"details about volume's checkpoints.\n\n"
	"(1) checkpoints_number\n\tshow number of checkpoints on volume.\n\n"
	"(2) snapshots_number\n\tshow number of snapshots on volume.\n\n"
	"(3) last_seg_checkpoint\n"
	"\tshow checkpoint number of the latest segment.\n\n"
	"(4) next_checkpoint\n\tshow next checkpoint number.\n\n";

static ssize_t
nilfs_checkpoints_README_show(struct nilfs_checkpoints_attr *attr,
				struct the_nilfs *nilfs, char *buf)
{
	return snprintf(buf, PAGE_SIZE, checkpoints_readme_str);
}

NILFS_CHECKPOINTS_RO_ATTR(checkpoints_number);
NILFS_CHECKPOINTS_RO_ATTR(snapshots_number);
NILFS_CHECKPOINTS_RO_ATTR(last_seg_checkpoint);
NILFS_CHECKPOINTS_RO_ATTR(next_checkpoint);
NILFS_CHECKPOINTS_RO_ATTR(README);

static struct attribute *nilfs_checkpoints_attrs[] = {
	NILFS_CHECKPOINTS_ATTR_LIST(checkpoints_number),
	NILFS_CHECKPOINTS_ATTR_LIST(snapshots_number),
	NILFS_CHECKPOINTS_ATTR_LIST(last_seg_checkpoint),
	NILFS_CHECKPOINTS_ATTR_LIST(next_checkpoint),
	NILFS_CHECKPOINTS_ATTR_LIST(README),
	NULL,
};

NILFS_DEV_INT_GROUP_OPS(checkpoints, dev);
NILFS_DEV_INT_GROUP_TYPE(checkpoints, dev);
NILFS_DEV_INT_GROUP_FNS(checkpoints, dev);

/************************************************************************
 *                        NILFS segments attrs                          *
 ************************************************************************/

static ssize_t
nilfs_segments_segments_number_show(struct nilfs_segments_attr *attr,
				     struct the_nilfs *nilfs,
				     char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%lu\n", nilfs->ns_nsegments);
}

static ssize_t
nilfs_segments_blocks_per_segment_show(struct nilfs_segments_attr *attr,
					struct the_nilfs *nilfs,
					char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%lu\n", nilfs->ns_blocks_per_segment);
}

static ssize_t
nilfs_segments_clean_segments_show(struct nilfs_segments_attr *attr,
				    struct the_nilfs *nilfs,
				    char *buf)
{
	unsigned long ncleansegs;

	down_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);
	ncleansegs = nilfs_sufile_get_ncleansegs(nilfs->ns_sufile);
	up_read(&NILFS_MDT(nilfs->ns_dat)->mi_sem);

	return snprintf(buf, PAGE_SIZE, "%lu\n", ncleansegs);
}

static ssize_t
nilfs_segments_dirty_segments_show(struct nilfs_segments_attr *attr,
				    struct the_nilfs *nilfs,
				    char *buf)
{
	struct nilfs_sustat sustat;
	int err;

	down_read(&nilfs->ns_segctor_sem);
	err = nilfs_sufile_get_stat(nilfs->ns_sufile, &sustat);
	up_read(&nilfs->ns_segctor_sem);
	if (err < 0) {
		printk(KERN_ERR "NILFS: unable to get segment stat: err=%d\n",
			err);
		return err;
	}

	return snprintf(buf, PAGE_SIZE, "%llu\n", sustat.ss_ndirtysegs);
}

static const char segments_readme_str[] =
	"The segments group contains attributes that describe\n"
	"details about volume's segments.\n\n"
	"(1) segments_number\n\tshow number of segments on volume.\n\n"
	"(2) blocks_per_segment\n\tshow number of blocks in segment.\n\n"
	"(3) clean_segments\n\tshow count of clean segments.\n\n"
	"(4) dirty_segments\n\tshow count of dirty segments.\n\n";

static ssize_t
nilfs_segments_README_show(struct nilfs_segments_attr *attr,
			    struct the_nilfs *nilfs,
			    char *buf)
{
	return snprintf(buf, PAGE_SIZE, segments_readme_str);
}

NILFS_SEGMENTS_RO_ATTR(segments_number);
NILFS_SEGMENTS_RO_ATTR(blocks_per_segment);
NILFS_SEGMENTS_RO_ATTR(clean_segments);
NILFS_SEGMENTS_RO_ATTR(dirty_segments);
NILFS_SEGMENTS_RO_ATTR(README);

static struct attribute *nilfs_segments_attrs[] = {
	NILFS_SEGMENTS_ATTR_LIST(segments_number),
	NILFS_SEGMENTS_ATTR_LIST(blocks_per_segment),
	NILFS_SEGMENTS_ATTR_LIST(clean_segments),
	NILFS_SEGMENTS_ATTR_LIST(dirty_segments),
	NILFS_SEGMENTS_ATTR_LIST(README),
	NULL,
};

NILFS_DEV_INT_GROUP_OPS(segments, dev);
NILFS_DEV_INT_GROUP_TYPE(segments, dev);
NILFS_DEV_INT_GROUP_FNS(segments, dev);

/************************************************************************
 *                        NILFS segctor attrs                           *
 ************************************************************************/

static ssize_t
nilfs_segctor_last_pseg_block_show(struct nilfs_segctor_attr *attr,
				    struct the_nilfs *nilfs,
				    char *buf)
{
	sector_t last_pseg;

	spin_lock(&nilfs->ns_last_segment_lock);
	last_pseg = nilfs->ns_last_pseg;
	spin_unlock(&nilfs->ns_last_segment_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n",
			(unsigned long long)last_pseg);
}

static ssize_t
nilfs_segctor_last_seg_sequence_show(struct nilfs_segctor_attr *attr,
					struct the_nilfs *nilfs,
					char *buf)
{
	u64 last_seq;

	spin_lock(&nilfs->ns_last_segment_lock);
	last_seq = nilfs->ns_last_seq;
	spin_unlock(&nilfs->ns_last_segment_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", last_seq);
}

static ssize_t
nilfs_segctor_last_seg_checkpoint_show(struct nilfs_segctor_attr *attr,
					struct the_nilfs *nilfs,
					char *buf)
{
	__u64 last_cno;

	spin_lock(&nilfs->ns_last_segment_lock);
	last_cno = nilfs->ns_last_cno;
	spin_unlock(&nilfs->ns_last_segment_lock);

	return snprintf(buf, PAGE_SIZE, "%llu\n", last_cno);
}

static ssize_t
nilfs_segctor_current_seg_sequence_show(struct nilfs_segctor_attr *attr,
					struct the_nilfs *nilfs,
					char *buf)
{
	u64 seg_seq;

	down_read(&nilfs->ns_sem);
	seg_seq = nilfs->ns_seg_seq;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%llu\n", seg_seq);
}

static ssize_t
nilfs_segctor_current_last_full_seg_show(struct nilfs_segctor_attr *attr,
					 struct the_nilfs *nilfs,
					 char *buf)
{
	__u64 segnum;

	down_read(&nilfs->ns_sem);
	segnum = nilfs->ns_segnum;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%llu\n", segnum);
}

static ssize_t
nilfs_segctor_next_full_seg_show(struct nilfs_segctor_attr *attr,
				 struct the_nilfs *nilfs,
				 char *buf)
{
	__u64 nextnum;

	down_read(&nilfs->ns_sem);
	nextnum = nilfs->ns_nextnum;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%llu\n", nextnum);
}

static ssize_t
nilfs_segctor_next_pseg_offset_show(struct nilfs_segctor_attr *attr,
					struct the_nilfs *nilfs,
					char *buf)
{
	unsigned long pseg_offset;

	down_read(&nilfs->ns_sem);
	pseg_offset = nilfs->ns_pseg_offset;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%lu\n", pseg_offset);
}

static ssize_t
nilfs_segctor_next_checkpoint_show(struct nilfs_segctor_attr *attr,
					struct the_nilfs *nilfs,
					char *buf)
{
	__u64 cno;

	down_read(&nilfs->ns_sem);
	cno = nilfs->ns_cno;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%llu\n", cno);
}

static ssize_t
nilfs_segctor_last_seg_write_time_show(struct nilfs_segctor_attr *attr,
					struct the_nilfs *nilfs,
					char *buf)
{
	time_t ctime;

	down_read(&nilfs->ns_sem);
	ctime = nilfs->ns_ctime;
	up_read(&nilfs->ns_sem);

	return NILFS_SHOW_TIME(ctime, buf);
}

static ssize_t
nilfs_segctor_last_seg_write_time_secs_show(struct nilfs_segctor_attr *attr,
					    struct the_nilfs *nilfs,
					    char *buf)
{
	time_t ctime;

	down_read(&nilfs->ns_sem);
	ctime = nilfs->ns_ctime;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%llu\n", (unsigned long long)ctime);
}

static ssize_t
nilfs_segctor_last_nongc_write_time_show(struct nilfs_segctor_attr *attr,
					 struct the_nilfs *nilfs,
					 char *buf)
{
	time_t nongc_ctime;

	down_read(&nilfs->ns_sem);
	nongc_ctime = nilfs->ns_nongc_ctime;
	up_read(&nilfs->ns_sem);

	return NILFS_SHOW_TIME(nongc_ctime, buf);
}

static ssize_t
nilfs_segctor_last_nongc_write_time_secs_show(struct nilfs_segctor_attr *attr,
						struct the_nilfs *nilfs,
						char *buf)
{
	time_t nongc_ctime;

	down_read(&nilfs->ns_sem);
	nongc_ctime = nilfs->ns_nongc_ctime;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%llu\n",
			(unsigned long long)nongc_ctime);
}

static ssize_t
nilfs_segctor_dirty_data_blocks_count_show(struct nilfs_segctor_attr *attr,
					    struct the_nilfs *nilfs,
					    char *buf)
{
	u32 ndirtyblks;

	down_read(&nilfs->ns_sem);
	ndirtyblks = atomic_read(&nilfs->ns_ndirtyblks);
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%u\n", ndirtyblks);
}

static const char segctor_readme_str[] =
	"The segctor group contains attributes that describe\n"
	"segctor thread activity details.\n\n"
	"(1) last_pseg_block\n"
	"\tshow start block number of the latest segment.\n\n"
	"(2) last_seg_sequence\n"
	"\tshow sequence value of the latest segment.\n\n"
	"(3) last_seg_checkpoint\n"
	"\tshow checkpoint number of the latest segment.\n\n"
	"(4) current_seg_sequence\n\tshow segment sequence counter.\n\n"
	"(5) current_last_full_seg\n"
	"\tshow index number of the latest full segment.\n\n"
	"(6) next_full_seg\n"
	"\tshow index number of the full segment index to be used next.\n\n"
	"(7) next_pseg_offset\n"
	"\tshow offset of next partial segment in the current full segment.\n\n"
	"(8) next_checkpoint\n\tshow next checkpoint number.\n\n"
	"(9) last_seg_write_time\n"
	"\tshow write time of the last segment in human-readable format.\n\n"
	"(10) last_seg_write_time_secs\n"
	"\tshow write time of the last segment in seconds.\n\n"
	"(11) last_nongc_write_time\n"
	"\tshow write time of the last segment not for cleaner operation "
	"in human-readable format.\n\n"
	"(12) last_nongc_write_time_secs\n"
	"\tshow write time of the last segment not for cleaner operation "
	"in seconds.\n\n"
	"(13) dirty_data_blocks_count\n"
	"\tshow number of dirty data blocks.\n\n";

static ssize_t
nilfs_segctor_README_show(struct nilfs_segctor_attr *attr,
			  struct the_nilfs *nilfs, char *buf)
{
	return snprintf(buf, PAGE_SIZE, segctor_readme_str);
}

NILFS_SEGCTOR_RO_ATTR(last_pseg_block);
NILFS_SEGCTOR_RO_ATTR(last_seg_sequence);
NILFS_SEGCTOR_RO_ATTR(last_seg_checkpoint);
NILFS_SEGCTOR_RO_ATTR(current_seg_sequence);
NILFS_SEGCTOR_RO_ATTR(current_last_full_seg);
NILFS_SEGCTOR_RO_ATTR(next_full_seg);
NILFS_SEGCTOR_RO_ATTR(next_pseg_offset);
NILFS_SEGCTOR_RO_ATTR(next_checkpoint);
NILFS_SEGCTOR_RO_ATTR(last_seg_write_time);
NILFS_SEGCTOR_RO_ATTR(last_seg_write_time_secs);
NILFS_SEGCTOR_RO_ATTR(last_nongc_write_time);
NILFS_SEGCTOR_RO_ATTR(last_nongc_write_time_secs);
NILFS_SEGCTOR_RO_ATTR(dirty_data_blocks_count);
NILFS_SEGCTOR_RO_ATTR(README);

static struct attribute *nilfs_segctor_attrs[] = {
	NILFS_SEGCTOR_ATTR_LIST(last_pseg_block),
	NILFS_SEGCTOR_ATTR_LIST(last_seg_sequence),
	NILFS_SEGCTOR_ATTR_LIST(last_seg_checkpoint),
	NILFS_SEGCTOR_ATTR_LIST(current_seg_sequence),
	NILFS_SEGCTOR_ATTR_LIST(current_last_full_seg),
	NILFS_SEGCTOR_ATTR_LIST(next_full_seg),
	NILFS_SEGCTOR_ATTR_LIST(next_pseg_offset),
	NILFS_SEGCTOR_ATTR_LIST(next_checkpoint),
	NILFS_SEGCTOR_ATTR_LIST(last_seg_write_time),
	NILFS_SEGCTOR_ATTR_LIST(last_seg_write_time_secs),
	NILFS_SEGCTOR_ATTR_LIST(last_nongc_write_time),
	NILFS_SEGCTOR_ATTR_LIST(last_nongc_write_time_secs),
	NILFS_SEGCTOR_ATTR_LIST(dirty_data_blocks_count),
	NILFS_SEGCTOR_ATTR_LIST(README),
	NULL,
};

NILFS_DEV_INT_GROUP_OPS(segctor, dev);
NILFS_DEV_INT_GROUP_TYPE(segctor, dev);
NILFS_DEV_INT_GROUP_FNS(segctor, dev);

/************************************************************************
 *                        NILFS superblock attrs                        *
 ************************************************************************/

static ssize_t
nilfs_superblock_sb_write_time_show(struct nilfs_superblock_attr *attr,
				     struct the_nilfs *nilfs,
				     char *buf)
{
	time_t sbwtime;

	down_read(&nilfs->ns_sem);
	sbwtime = nilfs->ns_sbwtime;
	up_read(&nilfs->ns_sem);

	return NILFS_SHOW_TIME(sbwtime, buf);
}

static ssize_t
nilfs_superblock_sb_write_time_secs_show(struct nilfs_superblock_attr *attr,
					 struct the_nilfs *nilfs,
					 char *buf)
{
	time_t sbwtime;

	down_read(&nilfs->ns_sem);
	sbwtime = nilfs->ns_sbwtime;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%llu\n", (unsigned long long)sbwtime);
}

static ssize_t
nilfs_superblock_sb_write_count_show(struct nilfs_superblock_attr *attr,
				      struct the_nilfs *nilfs,
				      char *buf)
{
	unsigned sbwcount;

	down_read(&nilfs->ns_sem);
	sbwcount = nilfs->ns_sbwcount;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%u\n", sbwcount);
}

static ssize_t
nilfs_superblock_sb_update_frequency_show(struct nilfs_superblock_attr *attr,
					    struct the_nilfs *nilfs,
					    char *buf)
{
	unsigned sb_update_freq;

	down_read(&nilfs->ns_sem);
	sb_update_freq = nilfs->ns_sb_update_freq;
	up_read(&nilfs->ns_sem);

	return snprintf(buf, PAGE_SIZE, "%u\n", sb_update_freq);
}

static ssize_t
nilfs_superblock_sb_update_frequency_store(struct nilfs_superblock_attr *attr,
					    struct the_nilfs *nilfs,
					    const char *buf, size_t count)
{
	unsigned val;
	int err;

	err = kstrtouint(skip_spaces(buf), 0, &val);
	if (err) {
		printk(KERN_ERR "NILFS: unable to convert string: err=%d\n",
			err);
		return err;
	}

	if (val < NILFS_SB_FREQ) {
		val = NILFS_SB_FREQ;
		printk(KERN_WARNING "NILFS: superblock update frequency cannot be lesser than 10 seconds\n");
	}

	down_write(&nilfs->ns_sem);
	nilfs->ns_sb_update_freq = val;
	up_write(&nilfs->ns_sem);

	return count;
}

static const char sb_readme_str[] =
	"The superblock group contains attributes that describe\n"
	"superblock's details.\n\n"
	"(1) sb_write_time\n\tshow previous write time of super block "
	"in human-readable format.\n\n"
	"(2) sb_write_time_secs\n\tshow previous write time of super block "
	"in seconds.\n\n"
	"(3) sb_write_count\n\tshow write count of super block.\n\n"
	"(4) sb_update_frequency\n"
	"\tshow/set interval of periodical update of superblock (in seconds).\n\n"
	"\tYou can set preferable frequency of superblock update by command:\n\n"
	"\t'echo <val> > /sys/fs/<nilfs>/<dev>/superblock/sb_update_frequency'\n";

static ssize_t
nilfs_superblock_README_show(struct nilfs_superblock_attr *attr,
				struct the_nilfs *nilfs, char *buf)
{
	return snprintf(buf, PAGE_SIZE, sb_readme_str);
}

NILFS_SUPERBLOCK_RO_ATTR(sb_write_time);
NILFS_SUPERBLOCK_RO_ATTR(sb_write_time_secs);
NILFS_SUPERBLOCK_RO_ATTR(sb_write_count);
NILFS_SUPERBLOCK_RW_ATTR(sb_update_frequency);
NILFS_SUPERBLOCK_RO_ATTR(README);

static struct attribute *nilfs_superblock_attrs[] = {
	NILFS_SUPERBLOCK_ATTR_LIST(sb_write_time),
	NILFS_SUPERBLOCK_ATTR_LIST(sb_write_time_secs),
	NILFS_SUPERBLOCK_ATTR_LIST(sb_write_count),
	NILFS_SUPERBLOCK_ATTR_LIST(sb_update_frequency),
	NILFS_SUPERBLOCK_ATTR_LIST(README),
	NULL,
};

NILFS_DEV_INT_GROUP_OPS(superblock, dev);
NILFS_DEV_INT_GROUP_TYPE(superblock, dev);
NILFS_DEV_INT_GROUP_FNS(superblock, dev);

/************************************************************************
 *                        NILFS device attrs                            *
 ************************************************************************/

static
ssize_t nilfs_dev_revision_show(struct nilfs_dev_attr *attr,
				struct the_nilfs *nilfs,
				char *buf)
{
	struct nilfs_super_block **sbp = nilfs->ns_sbp;
	u32 major = le32_to_cpu(sbp[0]->s_rev_level);
	u16 minor = le16_to_cpu(sbp[0]->s_minor_rev_level);

	return snprintf(buf, PAGE_SIZE, "%d.%d\n", major, minor);
}

static
ssize_t nilfs_dev_blocksize_show(struct nilfs_dev_attr *attr,
				 struct the_nilfs *nilfs,
				 char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", nilfs->ns_blocksize);
}

static
ssize_t nilfs_dev_device_size_show(struct nilfs_dev_attr *attr,
				    struct the_nilfs *nilfs,
				    char *buf)
{
	struct nilfs_super_block **sbp = nilfs->ns_sbp;
	u64 dev_size = le64_to_cpu(sbp[0]->s_dev_size);

	return snprintf(buf, PAGE_SIZE, "%llu\n", dev_size);
}

static
ssize_t nilfs_dev_free_blocks_show(struct nilfs_dev_attr *attr,
				   struct the_nilfs *nilfs,
				   char *buf)
{
	sector_t free_blocks = 0;

	nilfs_count_free_blocks(nilfs, &free_blocks);
	return snprintf(buf, PAGE_SIZE, "%llu\n",
			(unsigned long long)free_blocks);
}

static
ssize_t nilfs_dev_uuid_show(struct nilfs_dev_attr *attr,
			    struct the_nilfs *nilfs,
			    char *buf)
{
	struct nilfs_super_block **sbp = nilfs->ns_sbp;

	return snprintf(buf, PAGE_SIZE, "%pUb\n", sbp[0]->s_uuid);
}

static
ssize_t nilfs_dev_volume_name_show(struct nilfs_dev_attr *attr,
				    struct the_nilfs *nilfs,
				    char *buf)
{
	struct nilfs_super_block **sbp = nilfs->ns_sbp;

	return scnprintf(buf, sizeof(sbp[0]->s_volume_name), "%s\n",
			 sbp[0]->s_volume_name);
}

static const char dev_readme_str[] =
	"The <device> group contains attributes that describe file system\n"
	"partition's details.\n\n"
	"(1) revision\n\tshow NILFS file system revision.\n\n"
	"(2) blocksize\n\tshow volume block size in bytes.\n\n"
	"(3) device_size\n\tshow volume size in bytes.\n\n"
	"(4) free_blocks\n\tshow count of free blocks on volume.\n\n"
	"(5) uuid\n\tshow volume's UUID.\n\n"
	"(6) volume_name\n\tshow volume's name.\n\n";

static ssize_t nilfs_dev_README_show(struct nilfs_dev_attr *attr,
				     struct the_nilfs *nilfs,
				     char *buf)
{
	return snprintf(buf, PAGE_SIZE, dev_readme_str);
}

NILFS_DEV_RO_ATTR(revision);
NILFS_DEV_RO_ATTR(blocksize);
NILFS_DEV_RO_ATTR(device_size);
NILFS_DEV_RO_ATTR(free_blocks);
NILFS_DEV_RO_ATTR(uuid);
NILFS_DEV_RO_ATTR(volume_name);
NILFS_DEV_RO_ATTR(README);

static struct attribute *nilfs_dev_attrs[] = {
	NILFS_DEV_ATTR_LIST(revision),
	NILFS_DEV_ATTR_LIST(blocksize),
	NILFS_DEV_ATTR_LIST(device_size),
	NILFS_DEV_ATTR_LIST(free_blocks),
	NILFS_DEV_ATTR_LIST(uuid),
	NILFS_DEV_ATTR_LIST(volume_name),
	NILFS_DEV_ATTR_LIST(README),
	NULL,
};

static ssize_t nilfs_dev_attr_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct the_nilfs *nilfs = container_of(kobj, struct the_nilfs,
						ns_dev_kobj);
	struct nilfs_dev_attr *a = container_of(attr, struct nilfs_dev_attr,
						attr);

	return a->show ? a->show(a, nilfs, buf) : 0;
}

static ssize_t nilfs_dev_attr_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf, size_t len)
{
	struct the_nilfs *nilfs = container_of(kobj, struct the_nilfs,
						ns_dev_kobj);
	struct nilfs_dev_attr *a = container_of(attr, struct nilfs_dev_attr,
						attr);

	return a->store ? a->store(a, nilfs, buf, len) : 0;
}

static void nilfs_dev_attr_release(struct kobject *kobj)
{
	struct the_nilfs *nilfs = container_of(kobj, struct the_nilfs,
						ns_dev_kobj);
	complete(&nilfs->ns_dev_kobj_unregister);
}

static const struct sysfs_ops nilfs_dev_attr_ops = {
	.show	= nilfs_dev_attr_show,
	.store	= nilfs_dev_attr_store,
};

static struct kobj_type nilfs_dev_ktype = {
	.default_attrs	= nilfs_dev_attrs,
	.sysfs_ops	= &nilfs_dev_attr_ops,
	.release	= nilfs_dev_attr_release,
};

int nilfs_sysfs_create_device_group(struct super_block *sb)
{
	struct the_nilfs *nilfs = sb->s_fs_info;
	size_t devgrp_size = sizeof(struct nilfs_sysfs_dev_subgroups);
	int err;

	nilfs->ns_dev_subgroups = kzalloc(devgrp_size, GFP_KERNEL);
	if (unlikely(!nilfs->ns_dev_subgroups)) {
		err = -ENOMEM;
		printk(KERN_ERR "NILFS: unable to allocate memory for device group\n");
		goto failed_create_device_group;
	}

	nilfs->ns_dev_kobj.kset = nilfs_kset;
	init_completion(&nilfs->ns_dev_kobj_unregister);
	err = kobject_init_and_add(&nilfs->ns_dev_kobj, &nilfs_dev_ktype, NULL,
				    "%s", sb->s_id);
	if (err)
		goto free_dev_subgroups;

	err = nilfs_sysfs_create_mounted_snapshots_group(nilfs);
	if (err)
		goto cleanup_dev_kobject;

	err = nilfs_sysfs_create_checkpoints_group(nilfs);
	if (err)
		goto delete_mounted_snapshots_group;

	err = nilfs_sysfs_create_segments_group(nilfs);
	if (err)
		goto delete_checkpoints_group;

	err = nilfs_sysfs_create_superblock_group(nilfs);
	if (err)
		goto delete_segments_group;

	err = nilfs_sysfs_create_segctor_group(nilfs);
	if (err)
		goto delete_superblock_group;

	return 0;

delete_superblock_group:
	nilfs_sysfs_delete_superblock_group(nilfs);

delete_segments_group:
	nilfs_sysfs_delete_segments_group(nilfs);

delete_checkpoints_group:
	nilfs_sysfs_delete_checkpoints_group(nilfs);

delete_mounted_snapshots_group:
	nilfs_sysfs_delete_mounted_snapshots_group(nilfs);

cleanup_dev_kobject:
	kobject_del(&nilfs->ns_dev_kobj);

free_dev_subgroups:
	kfree(nilfs->ns_dev_subgroups);

failed_create_device_group:
	return err;
}

void nilfs_sysfs_delete_device_group(struct the_nilfs *nilfs)
{
	nilfs_sysfs_delete_mounted_snapshots_group(nilfs);
	nilfs_sysfs_delete_checkpoints_group(nilfs);
	nilfs_sysfs_delete_segments_group(nilfs);
	nilfs_sysfs_delete_superblock_group(nilfs);
	nilfs_sysfs_delete_segctor_group(nilfs);
	kobject_del(&nilfs->ns_dev_kobj);
	kfree(nilfs->ns_dev_subgroups);
}

/************************************************************************
 *                        NILFS feature attrs                           *
 ************************************************************************/

static ssize_t nilfs_feature_revision_show(struct kobject *kobj,
					    struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d.%d\n",
			NILFS_CURRENT_REV, NILFS_MINOR_REV);
}

static const char features_readme_str[] =
	"The features group contains attributes that describe NILFS file\n"
	"system driver features.\n\n"
	"(1) revision\n\tshow current revision of NILFS file system driver.\n";

static ssize_t nilfs_feature_README_show(struct kobject *kobj,
					 struct attribute *attr,
					 char *buf)
{
	return snprintf(buf, PAGE_SIZE, features_readme_str);
}

NILFS_FEATURE_RO_ATTR(revision);
NILFS_FEATURE_RO_ATTR(README);

static struct attribute *nilfs_feature_attrs[] = {
	NILFS_FEATURE_ATTR_LIST(revision),
	NILFS_FEATURE_ATTR_LIST(README),
	NULL,
};

static const struct attribute_group nilfs_feature_attr_group = {
	.name = "features",
	.attrs = nilfs_feature_attrs,
};

int __init nilfs_sysfs_init(void)
{
	int err;

	nilfs_kset = kset_create_and_add(NILFS_ROOT_GROUP_NAME, NULL, fs_kobj);
	if (!nilfs_kset) {
		err = -ENOMEM;
		printk(KERN_ERR "NILFS: unable to create sysfs entry: err %d\n",
			err);
		goto failed_sysfs_init;
	}

	err = sysfs_create_group(&nilfs_kset->kobj, &nilfs_feature_attr_group);
	if (unlikely(err)) {
		printk(KERN_ERR "NILFS: unable to create feature group: err %d\n",
			err);
		goto cleanup_sysfs_init;
	}

	return 0;

cleanup_sysfs_init:
	kset_unregister(nilfs_kset);

failed_sysfs_init:
	return err;
}

void nilfs_sysfs_exit(void)
{
	sysfs_remove_group(&nilfs_kset->kobj, &nilfs_feature_attr_group);
	kset_unregister(nilfs_kset);
}
/************************************************************/
/* ../linux-3.17/fs/nilfs2/sysfs.c */
/************************************************************/
