/************************************************************/
/* ../linux-3.17/fs/gfs2/acl.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <linux/gfs2_ondisk.h>

#include "gfs2.h"
#include "incore.h"
#include "acl.h"
#include "xattr.h"
#include "glock.h"
#include "inode.h"
#include "meta_io.h"
#include "trans.h"
#include "util.h"

static const char *gfs2_acl_name(int type)
{
	switch (type) {
	case ACL_TYPE_ACCESS:
		return GFS2_POSIX_ACL_ACCESS;
	case ACL_TYPE_DEFAULT:
		return GFS2_POSIX_ACL_DEFAULT;
	}
	return NULL;
}

struct posix_acl *gfs2_get_acl(struct inode *inode, int type)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct posix_acl *acl;
	const char *name;
	char *data;
	int len;

	if (!ip->i_eattr)
		return NULL;

	name = gfs2_acl_name(type);
	if (name == NULL)
		return ERR_PTR(-EINVAL);

	len = gfs2_xattr_acl_get(ip, name, &data);
	if (len < 0)
		return ERR_PTR(len);
	if (len == 0)
		return NULL;

	acl = posix_acl_from_xattr(&init_user_ns, data, len);
	kfree(data);
	return acl;
}

int gfs2_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int error;
	int len;
	char *data;
	const char *name = gfs2_acl_name(type);

	BUG_ON(name == NULL);

	if (acl->a_count > GFS2_ACL_MAX_ENTRIES(GFS2_SB(inode)))
		return -E2BIG;

	if (type == ACL_TYPE_ACCESS) {
		umode_t mode = inode->i_mode;

		error = posix_acl_equiv_mode(acl, &mode);
		if (error < 0)
			return error;

		if (error == 0)
			acl = NULL;

		if (mode != inode->i_mode) {
			inode->i_mode = mode;
			mark_inode_dirty(inode);
		}
	}

	if (acl) {
		len = posix_acl_to_xattr(&init_user_ns, acl, NULL, 0);
		if (len == 0)
			return 0;
		data = kmalloc(len, GFP_NOFS);
		if (data == NULL)
			return -ENOMEM;
		error = posix_acl_to_xattr(&init_user_ns, acl, data, len);
		if (error < 0)
			goto out;
	} else {
		data = NULL;
		len = 0;
	}

	error = __gfs2_xattr_set(inode, name, data, len, 0, GFS2_EATYPE_SYS);
	if (error)
		goto out;

	if (acl)
		set_cached_acl(inode, type, acl);
	else
		forget_cached_acl(inode, type);
out:
	kfree(data);
	return error;
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/bmap.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
#include <linux/blkdev.h>
// #include <linux/gfs2_ondisk.h>
#include <linux/crc32.h>

// #include "gfs2.h"
// #include "incore.h"
#include "bmap.h"
// #include "glock.h"
// #include "inode.h"
// #include "meta_io.h"
#include "quota.h"
#include "rgrp.h"
#include "log.h"
#include "super.h"
// #include "trans.h"
#include "dir.h"
// #include "util.h"
#include "trace_gfs2.h"

/* This doesn't need to be that large as max 64 bit pointers in a 4k
 * block is 512, so __u16 is fine for that. It saves stack space to
 * keep it small.
 */
struct metapath {
	struct buffer_head *mp_bh[GFS2_MAX_META_HEIGHT];
	__u16 mp_list[GFS2_MAX_META_HEIGHT];
};

struct strip_mine {
	int sm_first;
	unsigned int sm_height;
};

/**
 * gfs2_unstuffer_page - unstuff a stuffed inode into a block cached by a page
 * @ip: the inode
 * @dibh: the dinode buffer
 * @block: the block number that was allocated
 * @page: The (optional) page. This is looked up if @page is NULL
 *
 * Returns: errno
 */

static int gfs2_unstuffer_page(struct gfs2_inode *ip, struct buffer_head *dibh,
			       u64 block, struct page *page)
{
	struct inode *inode = &ip->i_inode;
	struct buffer_head *bh;
	int release = 0;

	if (!page || page->index) {
		page = find_or_create_page(inode->i_mapping, 0, GFP_NOFS);
		if (!page)
			return -ENOMEM;
		release = 1;
	}

	if (!PageUptodate(page)) {
		void *kaddr = kmap(page);
		u64 dsize = i_size_read(inode);

		if (dsize > (dibh->b_size - sizeof(struct gfs2_dinode)))
			dsize = dibh->b_size - sizeof(struct gfs2_dinode);

		memcpy(kaddr, dibh->b_data + sizeof(struct gfs2_dinode), dsize);
		memset(kaddr + dsize, 0, PAGE_CACHE_SIZE - dsize);
		kunmap(page);

		SetPageUptodate(page);
	}

	if (!page_has_buffers(page))
		create_empty_buffers(page, 1 << inode->i_blkbits,
				     (1 << BH_Uptodate));

	bh = page_buffers(page);

	if (!buffer_mapped(bh))
		map_bh(bh, inode->i_sb, block);

	set_buffer_uptodate(bh);
	if (!gfs2_is_jdata(ip))
		mark_buffer_dirty(bh);
	if (!gfs2_is_writeback(ip))
		gfs2_trans_add_data(ip->i_gl, bh);

	if (release) {
		unlock_page(page);
		page_cache_release(page);
	}

	return 0;
}

/**
 * gfs2_unstuff_dinode - Unstuff a dinode when the data has grown too big
 * @ip: The GFS2 inode to unstuff
 * @page: The (optional) page. This is looked up if the @page is NULL
 *
 * This routine unstuffs a dinode and returns it to a "normal" state such
 * that the height can be grown in the traditional way.
 *
 * Returns: errno
 */

int gfs2_unstuff_dinode(struct gfs2_inode *ip, struct page *page)
{
	struct buffer_head *bh, *dibh;
	struct gfs2_dinode *di;
	u64 block = 0;
	int isdir = gfs2_is_dir(ip);
	int error;

	down_write(&ip->i_rw_mutex);

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out;

	if (i_size_read(&ip->i_inode)) {
		/* Get a free block, fill it with the stuffed data,
		   and write it out to disk */

		unsigned int n = 1;
		error = gfs2_alloc_blocks(ip, &block, &n, 0, NULL);
		if (error)
			goto out_brelse;
		if (isdir) {
			gfs2_trans_add_unrevoke(GFS2_SB(&ip->i_inode), block, 1);
			error = gfs2_dir_get_new_buffer(ip, block, &bh);
			if (error)
				goto out_brelse;
			gfs2_buffer_copy_tail(bh, sizeof(struct gfs2_meta_header),
					      dibh, sizeof(struct gfs2_dinode));
			brelse(bh);
		} else {
			error = gfs2_unstuffer_page(ip, dibh, block, page);
			if (error)
				goto out_brelse;
		}
	}

	/*  Set up the pointer to the new block  */

	gfs2_trans_add_meta(ip->i_gl, dibh);
	di = (struct gfs2_dinode *)dibh->b_data;
	gfs2_buffer_clear_tail(dibh, sizeof(struct gfs2_dinode));

	if (i_size_read(&ip->i_inode)) {
		*(__be64 *)(di + 1) = cpu_to_be64(block);
		gfs2_add_inode_blocks(&ip->i_inode, 1);
		di->di_blocks = cpu_to_be64(gfs2_get_inode_blocks(&ip->i_inode));
	}

	ip->i_height = 1;
	di->di_height = cpu_to_be16(1);

out_brelse:
	brelse(dibh);
out:
	up_write(&ip->i_rw_mutex);
	return error;
}


/**
 * find_metapath - Find path through the metadata tree
 * @sdp: The superblock
 * @mp: The metapath to return the result in
 * @block: The disk block to look up
 * @height: The pre-calculated height of the metadata tree
 *
 *   This routine returns a struct metapath structure that defines a path
 *   through the metadata of inode "ip" to get to block "block".
 *
 *   Example:
 *   Given:  "ip" is a height 3 file, "offset" is 101342453, and this is a
 *   filesystem with a blocksize of 4096.
 *
 *   find_metapath() would return a struct metapath structure set to:
 *   mp_offset = 101342453, mp_height = 3, mp_list[0] = 0, mp_list[1] = 48,
 *   and mp_list[2] = 165.
 *
 *   That means that in order to get to the block containing the byte at
 *   offset 101342453, we would load the indirect block pointed to by pointer
 *   0 in the dinode.  We would then load the indirect block pointed to by
 *   pointer 48 in that indirect block.  We would then load the data block
 *   pointed to by pointer 165 in that indirect block.
 *
 *             ----------------------------------------
 *             | Dinode |                             |
 *             |        |                            4|
 *             |        |0 1 2 3 4 5                 9|
 *             |        |                            6|
 *             ----------------------------------------
 *                       |
 *                       |
 *                       V
 *             ----------------------------------------
 *             | Indirect Block                       |
 *             |                                     5|
 *             |            4 4 4 4 4 5 5            1|
 *             |0           5 6 7 8 9 0 1            2|
 *             ----------------------------------------
 *                                |
 *                                |
 *                                V
 *             ----------------------------------------
 *             | Indirect Block                       |
 *             |                         1 1 1 1 1   5|
 *             |                         6 6 6 6 6   1|
 *             |0                        3 4 5 6 7   2|
 *             ----------------------------------------
 *                                           |
 *                                           |
 *                                           V
 *             ----------------------------------------
 *             | Data block containing offset         |
 *             |            101342453                 |
 *             |                                      |
 *             |                                      |
 *             ----------------------------------------
 *
 */

static void find_metapath(const struct gfs2_sbd *sdp, u64 block,
			  struct metapath *mp, unsigned int height)
{
	unsigned int i;

	for (i = height; i--;)
		mp->mp_list[i] = do_div(block, sdp->sd_inptrs);

}

static inline unsigned int metapath_branch_start(const struct metapath *mp)
{
	if (mp->mp_list[0] == 0)
		return 2;
	return 1;
}

/**
 * metapointer - Return pointer to start of metadata in a buffer
 * @height: The metadata height (0 = dinode)
 * @mp: The metapath
 *
 * Return a pointer to the block number of the next height of the metadata
 * tree given a buffer containing the pointer to the current height of the
 * metadata tree.
 */

static inline __be64 *metapointer(unsigned int height, const struct metapath *mp)
{
	struct buffer_head *bh = mp->mp_bh[height];
	unsigned int head_size = (height > 0) ?
		sizeof(struct gfs2_meta_header) : sizeof(struct gfs2_dinode);
	return ((__be64 *)(bh->b_data + head_size)) + mp->mp_list[height];
}

static void gfs2_metapath_ra(struct gfs2_glock *gl,
			     const struct buffer_head *bh, const __be64 *pos)
{
	struct buffer_head *rabh;
	const __be64 *endp = (const __be64 *)(bh->b_data + bh->b_size);
	const __be64 *t;

	for (t = pos; t < endp; t++) {
		if (!*t)
			continue;

		rabh = gfs2_getbuf(gl, be64_to_cpu(*t), CREATE);
		if (trylock_buffer(rabh)) {
			if (!buffer_uptodate(rabh)) {
				rabh->b_end_io = end_buffer_read_sync;
				submit_bh(READA | REQ_META, rabh);
				continue;
			}
			unlock_buffer(rabh);
		}
		brelse(rabh);
	}
}

/**
 * lookup_metapath - Walk the metadata tree to a specific point
 * @ip: The inode
 * @mp: The metapath
 *
 * Assumes that the inode's buffer has already been looked up and
 * hooked onto mp->mp_bh[0] and that the metapath has been initialised
 * by find_metapath().
 *
 * If this function encounters part of the tree which has not been
 * allocated, it returns the current height of the tree at the point
 * at which it found the unallocated block. Blocks which are found are
 * added to the mp->mp_bh[] list.
 *
 * Returns: error or height of metadata tree
 */

static int lookup_metapath(struct gfs2_inode *ip, struct metapath *mp)
{
	unsigned int end_of_metadata = ip->i_height - 1;
	unsigned int x;
	__be64 *ptr;
	u64 dblock;
	int ret;

	for (x = 0; x < end_of_metadata; x++) {
		ptr = metapointer(x, mp);
		dblock = be64_to_cpu(*ptr);
		if (!dblock)
			return x + 1;

		ret = gfs2_meta_indirect_buffer(ip, x+1, dblock, &mp->mp_bh[x+1]);
		if (ret)
			return ret;
	}

	return ip->i_height;
}

static inline void release_metapath(struct metapath *mp)
{
	int i;

	for (i = 0; i < GFS2_MAX_META_HEIGHT; i++) {
		if (mp->mp_bh[i] == NULL)
			break;
		brelse(mp->mp_bh[i]);
	}
}

/**
 * gfs2_extent_length - Returns length of an extent of blocks
 * @start: Start of the buffer
 * @len: Length of the buffer in bytes
 * @ptr: Current position in the buffer
 * @limit: Max extent length to return (0 = unlimited)
 * @eob: Set to 1 if we hit "end of block"
 *
 * If the first block is zero (unallocated) it will return the number of
 * unallocated blocks in the extent, otherwise it will return the number
 * of contiguous blocks in the extent.
 *
 * Returns: The length of the extent (minimum of one block)
 */

static inline unsigned int gfs2_extent_length(void *start, unsigned int len, __be64 *ptr, unsigned limit, int *eob)
{
	const __be64 *end = (start + len);
	const __be64 *first = ptr;
	u64 d = be64_to_cpu(*ptr);

	*eob = 0;
	do {
		ptr++;
		if (ptr >= end)
			break;
		if (limit && --limit == 0)
			break;
		if (d)
			d++;
	} while(be64_to_cpu(*ptr) == d);
	if (ptr >= end)
		*eob = 1;
	return (ptr - first);
}

static inline void bmap_lock(struct gfs2_inode *ip, int create)
{
	if (create)
		down_write(&ip->i_rw_mutex);
	else
		down_read(&ip->i_rw_mutex);
}

static inline void bmap_unlock(struct gfs2_inode *ip, int create)
{
	if (create)
		up_write(&ip->i_rw_mutex);
	else
		up_read(&ip->i_rw_mutex);
}

static inline __be64 *gfs2_indirect_init(struct metapath *mp,
					 struct gfs2_glock *gl, unsigned int i,
					 unsigned offset, u64 bn)
{
	__be64 *ptr = (__be64 *)(mp->mp_bh[i - 1]->b_data +
		       ((i > 1) ? sizeof(struct gfs2_meta_header) :
				 sizeof(struct gfs2_dinode)));
	BUG_ON(i < 1);
	BUG_ON(mp->mp_bh[i] != NULL);
	mp->mp_bh[i] = gfs2_meta_new(gl, bn);
	gfs2_trans_add_meta(gl, mp->mp_bh[i]);
	gfs2_metatype_set(mp->mp_bh[i], GFS2_METATYPE_IN, GFS2_FORMAT_IN);
	gfs2_buffer_clear_tail(mp->mp_bh[i], sizeof(struct gfs2_meta_header));
	ptr += offset;
	*ptr = cpu_to_be64(bn);
	return ptr;
}

enum alloc_state {
	ALLOC_DATA = 0,
	ALLOC_GROW_DEPTH = 1,
	ALLOC_GROW_HEIGHT = 2,
	/* ALLOC_UNSTUFF = 3,   TBD and rather complicated */
};

/**
 * gfs2_bmap_alloc - Build a metadata tree of the requested height
 * @inode: The GFS2 inode
 * @lblock: The logical starting block of the extent
 * @bh_map: This is used to return the mapping details
 * @mp: The metapath
 * @sheight: The starting height (i.e. whats already mapped)
 * @height: The height to build to
 * @maxlen: The max number of data blocks to alloc
 *
 * In this routine we may have to alloc:
 *   i) Indirect blocks to grow the metadata tree height
 *  ii) Indirect blocks to fill in lower part of the metadata tree
 * iii) Data blocks
 *
 * The function is in two parts. The first part works out the total
 * number of blocks which we need. The second part does the actual
 * allocation asking for an extent at a time (if enough contiguous free
 * blocks are available, there will only be one request per bmap call)
 * and uses the state machine to initialise the blocks in order.
 *
 * Returns: errno on error
 */

static int gfs2_bmap_alloc(struct inode *inode, const sector_t lblock,
			   struct buffer_head *bh_map, struct metapath *mp,
			   const unsigned int sheight,
			   const unsigned int height,
			   const unsigned int maxlen)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct super_block *sb = sdp->sd_vfs;
	struct buffer_head *dibh = mp->mp_bh[0];
	u64 bn, dblock = 0;
	unsigned n, i, blks, alloced = 0, iblks = 0, branch_start = 0;
	unsigned dblks = 0;
	unsigned ptrs_per_blk;
	const unsigned end_of_metadata = height - 1;
	int ret;
	int eob = 0;
	enum alloc_state state;
	__be64 *ptr;
	__be64 zero_bn = 0;

	BUG_ON(sheight < 1);
	BUG_ON(dibh == NULL);

	gfs2_trans_add_meta(ip->i_gl, dibh);

	if (height == sheight) {
		struct buffer_head *bh;
		/* Bottom indirect block exists, find unalloced extent size */
		ptr = metapointer(end_of_metadata, mp);
		bh = mp->mp_bh[end_of_metadata];
		dblks = gfs2_extent_length(bh->b_data, bh->b_size, ptr, maxlen,
					   &eob);
		BUG_ON(dblks < 1);
		state = ALLOC_DATA;
	} else {
		/* Need to allocate indirect blocks */
		ptrs_per_blk = height > 1 ? sdp->sd_inptrs : sdp->sd_diptrs;
		dblks = min(maxlen, ptrs_per_blk - mp->mp_list[end_of_metadata]);
		if (height == ip->i_height) {
			/* Writing into existing tree, extend tree down */
			iblks = height - sheight;
			state = ALLOC_GROW_DEPTH;
		} else {
			/* Building up tree height */
			state = ALLOC_GROW_HEIGHT;
			iblks = height - ip->i_height;
			branch_start = metapath_branch_start(mp);
			iblks += (height - branch_start);
		}
	}

	/* start of the second part of the function (state machine) */

	blks = dblks + iblks;
	i = sheight;
	do {
		int error;
		n = blks - alloced;
		error = gfs2_alloc_blocks(ip, &bn, &n, 0, NULL);
		if (error)
			return error;
		alloced += n;
		if (state != ALLOC_DATA || gfs2_is_jdata(ip))
			gfs2_trans_add_unrevoke(sdp, bn, n);
		switch (state) {
		/* Growing height of tree */
		case ALLOC_GROW_HEIGHT:
			if (i == 1) {
				ptr = (__be64 *)(dibh->b_data +
						 sizeof(struct gfs2_dinode));
				zero_bn = *ptr;
			}
			for (; i - 1 < height - ip->i_height && n > 0; i++, n--)
				gfs2_indirect_init(mp, ip->i_gl, i, 0, bn++);
			if (i - 1 == height - ip->i_height) {
				i--;
				gfs2_buffer_copy_tail(mp->mp_bh[i],
						sizeof(struct gfs2_meta_header),
						dibh, sizeof(struct gfs2_dinode));
				gfs2_buffer_clear_tail(dibh,
						sizeof(struct gfs2_dinode) +
						sizeof(__be64));
				ptr = (__be64 *)(mp->mp_bh[i]->b_data +
					sizeof(struct gfs2_meta_header));
				*ptr = zero_bn;
				state = ALLOC_GROW_DEPTH;
				for(i = branch_start; i < height; i++) {
					if (mp->mp_bh[i] == NULL)
						break;
					brelse(mp->mp_bh[i]);
					mp->mp_bh[i] = NULL;
				}
				i = branch_start;
			}
			if (n == 0)
				break;
		/* Branching from existing tree */
		case ALLOC_GROW_DEPTH:
			if (i > 1 && i < height)
				gfs2_trans_add_meta(ip->i_gl, mp->mp_bh[i-1]);
			for (; i < height && n > 0; i++, n--)
				gfs2_indirect_init(mp, ip->i_gl, i,
						   mp->mp_list[i-1], bn++);
			if (i == height)
				state = ALLOC_DATA;
			if (n == 0)
				break;
		/* Tree complete, adding data blocks */
		case ALLOC_DATA:
			BUG_ON(n > dblks);
			BUG_ON(mp->mp_bh[end_of_metadata] == NULL);
			gfs2_trans_add_meta(ip->i_gl, mp->mp_bh[end_of_metadata]);
			dblks = n;
			ptr = metapointer(end_of_metadata, mp);
			dblock = bn;
			while (n-- > 0)
				*ptr++ = cpu_to_be64(bn++);
			if (buffer_zeronew(bh_map)) {
				ret = sb_issue_zeroout(sb, dblock, dblks,
						       GFP_NOFS);
				if (ret) {
					fs_err(sdp,
					       "Failed to zero data buffers\n");
					clear_buffer_zeronew(bh_map);
				}
			}
			break;
		}
	} while ((state != ALLOC_DATA) || !dblock);

	ip->i_height = height;
	gfs2_add_inode_blocks(&ip->i_inode, alloced);
	gfs2_dinode_out(ip, mp->mp_bh[0]->b_data);
	map_bh(bh_map, inode->i_sb, dblock);
	bh_map->b_size = dblks << inode->i_blkbits;
	set_buffer_new(bh_map);
	return 0;
}

/**
 * gfs2_block_map - Map a block from an inode to a disk block
 * @inode: The inode
 * @lblock: The logical block number
 * @bh_map: The bh to be mapped
 * @create: True if its ok to alloc blocks to satify the request
 *
 * Sets buffer_mapped() if successful, sets buffer_boundary() if a
 * read of metadata will be required before the next block can be
 * mapped. Sets buffer_new() if new blocks were allocated.
 *
 * Returns: errno
 */

int gfs2_block_map(struct inode *inode, sector_t lblock,
		   struct buffer_head *bh_map, int create)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	unsigned int bsize = sdp->sd_sb.sb_bsize;
	const unsigned int maxlen = bh_map->b_size >> inode->i_blkbits;
	const u64 *arr = sdp->sd_heightsize;
	__be64 *ptr;
	u64 size;
	struct metapath mp;
	int ret;
	int eob;
	unsigned int len;
	struct buffer_head *bh;
	u8 height;

	BUG_ON(maxlen == 0);

	memset(mp.mp_bh, 0, sizeof(mp.mp_bh));
	bmap_lock(ip, create);
	clear_buffer_mapped(bh_map);
	clear_buffer_new(bh_map);
	clear_buffer_boundary(bh_map);
	trace_gfs2_bmap(ip, bh_map, lblock, create, 1);
	if (gfs2_is_dir(ip)) {
		bsize = sdp->sd_jbsize;
		arr = sdp->sd_jheightsize;
	}

	ret = gfs2_meta_inode_buffer(ip, &mp.mp_bh[0]);
	if (ret)
		goto out;

	height = ip->i_height;
	size = (lblock + 1) * bsize;
	while (size > arr[height])
		height++;
	find_metapath(sdp, lblock, &mp, height);
	ret = 1;
	if (height > ip->i_height || gfs2_is_stuffed(ip))
		goto do_alloc;
	ret = lookup_metapath(ip, &mp);
	if (ret < 0)
		goto out;
	if (ret != ip->i_height)
		goto do_alloc;
	ptr = metapointer(ip->i_height - 1, &mp);
	if (*ptr == 0)
		goto do_alloc;
	map_bh(bh_map, inode->i_sb, be64_to_cpu(*ptr));
	bh = mp.mp_bh[ip->i_height - 1];
	len = gfs2_extent_length(bh->b_data, bh->b_size, ptr, maxlen, &eob);
	bh_map->b_size = (len << inode->i_blkbits);
	if (eob)
		set_buffer_boundary(bh_map);
	ret = 0;
out:
	release_metapath(&mp);
	trace_gfs2_bmap(ip, bh_map, lblock, create, ret);
	bmap_unlock(ip, create);
	return ret;

do_alloc:
	/* All allocations are done here, firstly check create flag */
	if (!create) {
		BUG_ON(gfs2_is_stuffed(ip));
		ret = 0;
		goto out;
	}

	/* At this point ret is the tree depth of already allocated blocks */
	ret = gfs2_bmap_alloc(inode, lblock, bh_map, &mp, ret, height, maxlen);
	goto out;
}

/*
 * Deprecated: do not use in new code
 */
int gfs2_extent_map(struct inode *inode, u64 lblock, int *new, u64 *dblock, unsigned *extlen)
{
	struct buffer_head bh = { .b_state = 0, .b_blocknr = 0 };
	int ret;
	int create = *new;

	BUG_ON(!extlen);
	BUG_ON(!dblock);
	BUG_ON(!new);

	bh.b_size = 1 << (inode->i_blkbits + (create ? 0 : 5));
	ret = gfs2_block_map(inode, lblock, &bh, create);
	*extlen = bh.b_size >> inode->i_blkbits;
	*dblock = bh.b_blocknr;
	if (buffer_new(&bh))
		*new = 1;
	else
		*new = 0;
	return ret;
}

/**
 * do_strip - Look for a layer a particular layer of the file and strip it off
 * @ip: the inode
 * @dibh: the dinode buffer
 * @bh: A buffer of pointers
 * @top: The first pointer in the buffer
 * @bottom: One more than the last pointer
 * @height: the height this buffer is at
 * @sm: a pointer to a struct strip_mine
 *
 * Returns: errno
 */

static int do_strip(struct gfs2_inode *ip, struct buffer_head *dibh,
		    struct buffer_head *bh, __be64 *top, __be64 *bottom,
		    unsigned int height, struct strip_mine *sm)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_rgrp_list rlist;
	u64 bn, bstart;
	u32 blen, btotal;
	__be64 *p;
	unsigned int rg_blocks = 0;
	int metadata;
	unsigned int revokes = 0;
	int x;
	int error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	if (!*top)
		sm->sm_first = 0;

	if (height != sm->sm_height)
		return 0;

	if (sm->sm_first) {
		top++;
		sm->sm_first = 0;
	}

	metadata = (height != ip->i_height - 1);
	if (metadata)
		revokes = (height) ? sdp->sd_inptrs : sdp->sd_diptrs;
	else if (ip->i_depth)
		revokes = sdp->sd_inptrs;

	memset(&rlist, 0, sizeof(struct gfs2_rgrp_list));
	bstart = 0;
	blen = 0;

	for (p = top; p < bottom; p++) {
		if (!*p)
			continue;

		bn = be64_to_cpu(*p);

		if (bstart + blen == bn)
			blen++;
		else {
			if (bstart)
				gfs2_rlist_add(ip, &rlist, bstart);

			bstart = bn;
			blen = 1;
		}
	}

	if (bstart)
		gfs2_rlist_add(ip, &rlist, bstart);
	else
		goto out; /* Nothing to do */

	gfs2_rlist_alloc(&rlist, LM_ST_EXCLUSIVE);

	for (x = 0; x < rlist.rl_rgrps; x++) {
		struct gfs2_rgrpd *rgd;
		rgd = rlist.rl_ghs[x].gh_gl->gl_object;
		rg_blocks += rgd->rd_length;
	}

	error = gfs2_glock_nq_m(rlist.rl_rgrps, rlist.rl_ghs);
	if (error)
		goto out_rlist;

	if (gfs2_rs_active(ip->i_res)) /* needs to be done with the rgrp glock held */
		gfs2_rs_deltree(ip->i_res);

	error = gfs2_trans_begin(sdp, rg_blocks + RES_DINODE +
				 RES_INDIRECT + RES_STATFS + RES_QUOTA,
				 revokes);
	if (error)
		goto out_rg_gunlock;

	down_write(&ip->i_rw_mutex);

	gfs2_trans_add_meta(ip->i_gl, dibh);
	gfs2_trans_add_meta(ip->i_gl, bh);

	bstart = 0;
	blen = 0;
	btotal = 0;

	for (p = top; p < bottom; p++) {
		if (!*p)
			continue;

		bn = be64_to_cpu(*p);

		if (bstart + blen == bn)
			blen++;
		else {
			if (bstart) {
				__gfs2_free_blocks(ip, bstart, blen, metadata);
				btotal += blen;
			}

			bstart = bn;
			blen = 1;
		}

		*p = 0;
		gfs2_add_inode_blocks(&ip->i_inode, -1);
	}
	if (bstart) {
		__gfs2_free_blocks(ip, bstart, blen, metadata);
		btotal += blen;
	}

	gfs2_statfs_change(sdp, 0, +btotal, 0);
	gfs2_quota_change(ip, -(s64)btotal, ip->i_inode.i_uid,
			  ip->i_inode.i_gid);

	ip->i_inode.i_mtime = ip->i_inode.i_ctime = CURRENT_TIME;

	gfs2_dinode_out(ip, dibh->b_data);

	up_write(&ip->i_rw_mutex);

	gfs2_trans_end(sdp);

out_rg_gunlock:
	gfs2_glock_dq_m(rlist.rl_rgrps, rlist.rl_ghs);
out_rlist:
	gfs2_rlist_free(&rlist);
out:
	return error;
}

/**
 * recursive_scan - recursively scan through the end of a file
 * @ip: the inode
 * @dibh: the dinode buffer
 * @mp: the path through the metadata to the point to start
 * @height: the height the recursion is at
 * @block: the indirect block to look at
 * @first: 1 if this is the first block
 * @sm: data opaque to this function to pass to @bc
 *
 * When this is first called @height and @block should be zero and
 * @first should be 1.
 *
 * Returns: errno
 */

static int recursive_scan(struct gfs2_inode *ip, struct buffer_head *dibh,
			  struct metapath *mp, unsigned int height,
			  u64 block, int first, struct strip_mine *sm)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head *bh = NULL;
	__be64 *top, *bottom;
	u64 bn;
	int error;
	int mh_size = sizeof(struct gfs2_meta_header);

	if (!height) {
		error = gfs2_meta_inode_buffer(ip, &bh);
		if (error)
			return error;
		dibh = bh;

		top = (__be64 *)(bh->b_data + sizeof(struct gfs2_dinode)) + mp->mp_list[0];
		bottom = (__be64 *)(bh->b_data + sizeof(struct gfs2_dinode)) + sdp->sd_diptrs;
	} else {
		error = gfs2_meta_indirect_buffer(ip, height, block, &bh);
		if (error)
			return error;

		top = (__be64 *)(bh->b_data + mh_size) +
				  (first ? mp->mp_list[height] : 0);

		bottom = (__be64 *)(bh->b_data + mh_size) + sdp->sd_inptrs;
	}

	error = do_strip(ip, dibh, bh, top, bottom, height, sm);
	if (error)
		goto out;

	if (height < ip->i_height - 1) {

		gfs2_metapath_ra(ip->i_gl, bh, top);

		for (; top < bottom; top++, first = 0) {
			if (!*top)
				continue;

			bn = be64_to_cpu(*top);

			error = recursive_scan(ip, dibh, mp, height + 1, bn,
					       first, sm);
			if (error)
				break;
		}
	}
out:
	brelse(bh);
	return error;
}


/**
 * gfs2_block_truncate_page - Deal with zeroing out data for truncate
 *
 * This is partly borrowed from ext3.
 */
static int gfs2_block_truncate_page(struct address_space *mapping, loff_t from)
{
	struct inode *inode = mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);
	unsigned long index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned blocksize, iblock, length, pos;
	struct buffer_head *bh;
	struct page *page;
	int err;

	page = find_or_create_page(mapping, index, GFP_NOFS);
	if (!page)
		return 0;

	blocksize = inode->i_sb->s_blocksize;
	length = blocksize - (offset & (blocksize - 1));
	iblock = index << (PAGE_CACHE_SHIFT - inode->i_sb->s_blocksize_bits);

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	/* Find the buffer that contains "offset" */
	bh = page_buffers(page);
	pos = blocksize;
	while (offset >= pos) {
		bh = bh->b_this_page;
		iblock++;
		pos += blocksize;
	}

	err = 0;

	if (!buffer_mapped(bh)) {
		gfs2_block_map(inode, iblock, bh, 0);
		/* unmapped? It's a hole - nothing to do */
		if (!buffer_mapped(bh))
			goto unlock;
	}

	/* Ok, it's mapped. Make sure it's up-to-date */
	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!buffer_uptodate(bh)) {
		err = -EIO;
		ll_rw_block(READ, 1, &bh);
		wait_on_buffer(bh);
		/* Uhhuh. Read error. Complain and punt. */
		if (!buffer_uptodate(bh))
			goto unlock;
		err = 0;
	}

	if (!gfs2_is_writeback(ip))
		gfs2_trans_add_data(ip->i_gl, bh);

	zero_user(page, offset, length);
	mark_buffer_dirty(bh);
unlock:
	unlock_page(page);
	page_cache_release(page);
	return err;
}

#define GFS2_JTRUNC_REVOKES 8192

/**
 * gfs2_journaled_truncate - Wrapper for truncate_pagecache for jdata files
 * @inode: The inode being truncated
 * @oldsize: The original (larger) size
 * @newsize: The new smaller size
 *
 * With jdata files, we have to journal a revoke for each block which is
 * truncated. As a result, we need to split this into separate transactions
 * if the number of pages being truncated gets too large.
 */

static int gfs2_journaled_truncate(struct inode *inode, u64 oldsize, u64 newsize)
{
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	u64 max_chunk = GFS2_JTRUNC_REVOKES * sdp->sd_vfs->s_blocksize;
	u64 chunk;
	int error;

	while (oldsize != newsize) {
		chunk = oldsize - newsize;
		if (chunk > max_chunk)
			chunk = max_chunk;
		truncate_pagecache(inode, oldsize - chunk);
		oldsize -= chunk;
		gfs2_trans_end(sdp);
		error = gfs2_trans_begin(sdp, RES_DINODE, GFS2_JTRUNC_REVOKES);
		if (error)
			return error;
	}

	return 0;
}

static int trunc_start(struct inode *inode, u64 oldsize, u64 newsize)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct address_space *mapping = inode->i_mapping;
	struct buffer_head *dibh;
	int journaled = gfs2_is_jdata(ip);
	int error;

	if (journaled)
		error = gfs2_trans_begin(sdp, RES_DINODE + RES_JDATA, GFS2_JTRUNC_REVOKES);
	else
		error = gfs2_trans_begin(sdp, RES_DINODE, 0);
	if (error)
		return error;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out;

	gfs2_trans_add_meta(ip->i_gl, dibh);

	if (gfs2_is_stuffed(ip)) {
		gfs2_buffer_clear_tail(dibh, sizeof(struct gfs2_dinode) + newsize);
	} else {
		if (newsize & (u64)(sdp->sd_sb.sb_bsize - 1)) {
			error = gfs2_block_truncate_page(mapping, newsize);
			if (error)
				goto out_brelse;
		}
		ip->i_diskflags |= GFS2_DIF_TRUNC_IN_PROG;
	}

	i_size_write(inode, newsize);
	ip->i_inode.i_mtime = ip->i_inode.i_ctime = CURRENT_TIME;
	gfs2_dinode_out(ip, dibh->b_data);

	if (journaled)
		error = gfs2_journaled_truncate(inode, oldsize, newsize);
	else
		truncate_pagecache(inode, newsize);

	if (error) {
		brelse(dibh);
		return error;
	}

out_brelse:
	brelse(dibh);
out:
	gfs2_trans_end(sdp);
	return error;
}

static int trunc_dealloc(struct gfs2_inode *ip, u64 size)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	unsigned int height = ip->i_height;
	u64 lblock;
	struct metapath mp;
	int error;

	if (!size)
		lblock = 0;
	else
		lblock = (size - 1) >> sdp->sd_sb.sb_bsize_shift;

	find_metapath(sdp, lblock, &mp, ip->i_height);
	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = gfs2_quota_hold(ip, NO_UID_QUOTA_CHANGE, NO_GID_QUOTA_CHANGE);
	if (error)
		return error;

	while (height--) {
		struct strip_mine sm;
		sm.sm_first = !!size;
		sm.sm_height = height;

		error = recursive_scan(ip, NULL, &mp, 0, 0, 1, &sm);
		if (error)
			break;
	}

	gfs2_quota_unhold(ip);

	return error;
}

static int trunc_end(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head *dibh;
	int error;

	error = gfs2_trans_begin(sdp, RES_DINODE, 0);
	if (error)
		return error;

	down_write(&ip->i_rw_mutex);

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out;

	if (!i_size_read(&ip->i_inode)) {
		ip->i_height = 0;
		ip->i_goal = ip->i_no_addr;
		gfs2_buffer_clear_tail(dibh, sizeof(struct gfs2_dinode));
		gfs2_ordered_del_inode(ip);
	}
	ip->i_inode.i_mtime = ip->i_inode.i_ctime = CURRENT_TIME;
	ip->i_diskflags &= ~GFS2_DIF_TRUNC_IN_PROG;

	gfs2_trans_add_meta(ip->i_gl, dibh);
	gfs2_dinode_out(ip, dibh->b_data);
	brelse(dibh);

out:
	up_write(&ip->i_rw_mutex);
	gfs2_trans_end(sdp);
	return error;
}

/**
 * do_shrink - make a file smaller
 * @inode: the inode
 * @oldsize: the current inode size
 * @newsize: the size to make the file
 *
 * Called with an exclusive lock on @inode. The @size must
 * be equal to or smaller than the current inode size.
 *
 * Returns: errno
 */

static int do_shrink(struct inode *inode, u64 oldsize, u64 newsize)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	int error;

	error = trunc_start(inode, oldsize, newsize);
	if (error < 0)
		return error;
	if (gfs2_is_stuffed(ip))
		return 0;

	error = trunc_dealloc(ip, newsize);
	if (error == 0)
		error = trunc_end(ip);

	return error;
}

void gfs2_trim_blocks(struct inode *inode)
{
	u64 size = inode->i_size;
	int ret;

	ret = do_shrink(inode, size, size);
	WARN_ON(ret != 0);
}

/**
 * do_grow - Touch and update inode size
 * @inode: The inode
 * @size: The new size
 *
 * This function updates the timestamps on the inode and
 * may also increase the size of the inode. This function
 * must not be called with @size any smaller than the current
 * inode size.
 *
 * Although it is not strictly required to unstuff files here,
 * earlier versions of GFS2 have a bug in the stuffed file reading
 * code which will result in a buffer overrun if the size is larger
 * than the max stuffed file size. In order to prevent this from
 * occurring, such files are unstuffed, but in other cases we can
 * just update the inode size directly.
 *
 * Returns: 0 on success, or -ve on error
 */

static int do_grow(struct inode *inode, u64 size)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_alloc_parms ap = { .target = 1, };
	struct buffer_head *dibh;
	int error;
	int unstuff = 0;

	if (gfs2_is_stuffed(ip) &&
	    (size > (sdp->sd_sb.sb_bsize - sizeof(struct gfs2_dinode)))) {
		error = gfs2_quota_lock_check(ip);
		if (error)
			return error;

		error = gfs2_inplace_reserve(ip, &ap);
		if (error)
			goto do_grow_qunlock;
		unstuff = 1;
	}

	error = gfs2_trans_begin(sdp, RES_DINODE + RES_STATFS + RES_RG_BIT +
				 (sdp->sd_args.ar_quota == GFS2_QUOTA_OFF ?
				  0 : RES_QUOTA), 0);
	if (error)
		goto do_grow_release;

	if (unstuff) {
		error = gfs2_unstuff_dinode(ip, NULL);
		if (error)
			goto do_end_trans;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto do_end_trans;

	i_size_write(inode, size);
	ip->i_inode.i_mtime = ip->i_inode.i_ctime = CURRENT_TIME;
	gfs2_trans_add_meta(ip->i_gl, dibh);
	gfs2_dinode_out(ip, dibh->b_data);
	brelse(dibh);

do_end_trans:
	gfs2_trans_end(sdp);
do_grow_release:
	if (unstuff) {
		gfs2_inplace_release(ip);
do_grow_qunlock:
		gfs2_quota_unlock(ip);
	}
	return error;
}

/**
 * gfs2_setattr_size - make a file a given size
 * @inode: the inode
 * @newsize: the size to make the file
 *
 * The file size can grow, shrink, or stay the same size. This
 * is called holding i_mutex and an exclusive glock on the inode
 * in question.
 *
 * Returns: errno
 */

int gfs2_setattr_size(struct inode *inode, u64 newsize)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	int ret;
	u64 oldsize;

	BUG_ON(!S_ISREG(inode->i_mode));

	ret = inode_newsize_ok(inode, newsize);
	if (ret)
		return ret;

	ret = get_write_access(inode);
	if (ret)
		return ret;

	inode_dio_wait(inode);

	ret = gfs2_rs_alloc(ip);
	if (ret)
		goto out;

	oldsize = inode->i_size;
	if (newsize >= oldsize) {
		ret = do_grow(inode, newsize);
		goto out;
	}

	gfs2_rs_deltree(ip->i_res);
	ret = do_shrink(inode, oldsize, newsize);
out:
	put_write_access(inode);
	return ret;
}

int gfs2_truncatei_resume(struct gfs2_inode *ip)
{
	int error;
	error = trunc_dealloc(ip, i_size_read(&ip->i_inode));
	if (!error)
		error = trunc_end(ip);
	return error;
}

int gfs2_file_dealloc(struct gfs2_inode *ip)
{
	return trunc_dealloc(ip, 0);
}

/**
 * gfs2_free_journal_extents - Free cached journal bmap info
 * @jd: The journal
 *
 */

void gfs2_free_journal_extents(struct gfs2_jdesc *jd)
{
	struct gfs2_journal_extent *jext;

	while(!list_empty(&jd->extent_list)) {
		jext = list_entry(jd->extent_list.next, struct gfs2_journal_extent, list);
		list_del(&jext->list);
		kfree(jext);
	}
}

/**
 * gfs2_add_jextent - Add or merge a new extent to extent cache
 * @jd: The journal descriptor
 * @lblock: The logical block at start of new extent
 * @dblock: The physical block at start of new extent
 * @blocks: Size of extent in fs blocks
 *
 * Returns: 0 on success or -ENOMEM
 */

static int gfs2_add_jextent(struct gfs2_jdesc *jd, u64 lblock, u64 dblock, u64 blocks)
{
	struct gfs2_journal_extent *jext;

	if (!list_empty(&jd->extent_list)) {
		jext = list_entry(jd->extent_list.prev, struct gfs2_journal_extent, list);
		if ((jext->dblock + jext->blocks) == dblock) {
			jext->blocks += blocks;
			return 0;
		}
	}

	jext = kzalloc(sizeof(struct gfs2_journal_extent), GFP_NOFS);
	if (jext == NULL)
		return -ENOMEM;
	jext->dblock = dblock;
	jext->lblock = lblock;
	jext->blocks = blocks;
	list_add_tail(&jext->list, &jd->extent_list);
	jd->nr_extents++;
	return 0;
}

/**
 * gfs2_map_journal_extents - Cache journal bmap info
 * @sdp: The super block
 * @jd: The journal to map
 *
 * Create a reusable "extent" mapping from all logical
 * blocks to all physical blocks for the given journal.  This will save
 * us time when writing journal blocks.  Most journals will have only one
 * extent that maps all their logical blocks.  That's because gfs2.mkfs
 * arranges the journal blocks sequentially to maximize performance.
 * So the extent would map the first block for the entire file length.
 * However, gfs2_jadd can happen while file activity is happening, so
 * those journals may not be sequential.  Less likely is the case where
 * the users created their own journals by mounting the metafs and
 * laying it out.  But it's still possible.  These journals might have
 * several extents.
 *
 * Returns: 0 on success, or error on failure
 */

int gfs2_map_journal_extents(struct gfs2_sbd *sdp, struct gfs2_jdesc *jd)
{
	u64 lblock = 0;
	u64 lblock_stop;
	struct gfs2_inode *ip = GFS2_I(jd->jd_inode);
	struct buffer_head bh;
	unsigned int shift = sdp->sd_sb.sb_bsize_shift;
	u64 size;
	int rc;

	lblock_stop = i_size_read(jd->jd_inode) >> shift;
	size = (lblock_stop - lblock) << shift;
	jd->nr_extents = 0;
	WARN_ON(!list_empty(&jd->extent_list));

	do {
		bh.b_state = 0;
		bh.b_blocknr = 0;
		bh.b_size = size;
		rc = gfs2_block_map(jd->jd_inode, lblock, &bh, 0);
		if (rc || !buffer_mapped(&bh))
			goto fail;
		rc = gfs2_add_jextent(jd, lblock, bh.b_blocknr, bh.b_size >> shift);
		if (rc)
			goto fail;
		size -= bh.b_size;
		lblock += (bh.b_size >> ip->i_inode.i_blkbits);
	} while(size > 0);

	fs_info(sdp, "journal %d mapped with %u extents\n", jd->jd_jid,
		jd->nr_extents);
	return 0;

fail:
	fs_warn(sdp, "error %d mapping journal %u at offset %llu (extent %u)\n",
		rc, jd->jd_jid,
		(unsigned long long)(i_size_read(jd->jd_inode) - size),
		jd->nr_extents);
	fs_warn(sdp, "bmap=%d lblock=%llu block=%llu, state=0x%08lx, size=%llu\n",
		rc, (unsigned long long)lblock, (unsigned long long)bh.b_blocknr,
		bh.b_state, (unsigned long long)bh.b_size);
	gfs2_free_journal_extents(jd);
	return rc;
}

/**
 * gfs2_write_alloc_required - figure out if a write will require an allocation
 * @ip: the file being written to
 * @offset: the offset to write to
 * @len: the number of bytes being written
 *
 * Returns: 1 if an alloc is required, 0 otherwise
 */

int gfs2_write_alloc_required(struct gfs2_inode *ip, u64 offset,
			      unsigned int len)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head bh;
	unsigned int shift;
	u64 lblock, lblock_stop, size;
	u64 end_of_file;

	if (!len)
		return 0;

	if (gfs2_is_stuffed(ip)) {
		if (offset + len >
		    sdp->sd_sb.sb_bsize - sizeof(struct gfs2_dinode))
			return 1;
		return 0;
	}

	shift = sdp->sd_sb.sb_bsize_shift;
	BUG_ON(gfs2_is_dir(ip));
	end_of_file = (i_size_read(&ip->i_inode) + sdp->sd_sb.sb_bsize - 1) >> shift;
	lblock = offset >> shift;
	lblock_stop = (offset + len + sdp->sd_sb.sb_bsize - 1) >> shift;
	if (lblock_stop > end_of_file)
		return 1;

	size = (lblock_stop - lblock) << shift;
	do {
		bh.b_state = 0;
		bh.b_size = size;
		gfs2_block_map(&ip->i_inode, lblock, &bh, 0);
		if (!buffer_mapped(&bh))
			return 1;
		size -= bh.b_size;
		lblock += (bh.b_size >> ip->i_inode.i_blkbits);
	} while(size > 0);

	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/dir.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

/*
 * Implements Extendible Hashing as described in:
 *   "Extendible Hashing" by Fagin, et al in
 *     __ACM Trans. on Database Systems__, Sept 1979.
 *
 *
 * Here's the layout of dirents which is essentially the same as that of ext2
 * within a single block. The field de_name_len is the number of bytes
 * actually required for the name (no null terminator). The field de_rec_len
 * is the number of bytes allocated to the dirent. The offset of the next
 * dirent in the block is (dirent + dirent->de_rec_len). When a dirent is
 * deleted, the preceding dirent inherits its allocated space, ie
 * prev->de_rec_len += deleted->de_rec_len. Since the next dirent is obtained
 * by adding de_rec_len to the current dirent, this essentially causes the
 * deleted dirent to get jumped over when iterating through all the dirents.
 *
 * When deleting the first dirent in a block, there is no previous dirent so
 * the field de_ino is set to zero to designate it as deleted. When allocating
 * a dirent, gfs2_dirent_alloc iterates through the dirents in a block. If the
 * first dirent has (de_ino == 0) and de_rec_len is large enough, this first
 * dirent is allocated. Otherwise it must go through all the 'used' dirents
 * searching for one in which the amount of total space minus the amount of
 * used space will provide enough space for the new dirent.
 *
 * There are two types of blocks in which dirents reside. In a stuffed dinode,
 * the dirents begin at offset sizeof(struct gfs2_dinode) from the beginning of
 * the block.  In leaves, they begin at offset sizeof(struct gfs2_leaf) from the
 * beginning of the leaf block. The dirents reside in leaves when
 *
 * dip->i_diskflags & GFS2_DIF_EXHASH is true
 *
 * Otherwise, the dirents are "linear", within a single stuffed dinode block.
 *
 * When the dirents are in leaves, the actual contents of the directory file are
 * used as an array of 64-bit block pointers pointing to the leaf blocks. The
 * dirents are NOT in the directory file itself. There can be more than one
 * block pointer in the array that points to the same leaf. In fact, when a
 * directory is first converted from linear to exhash, all of the pointers
 * point to the same leaf.
 *
 * When a leaf is completely full, the size of the hash table can be
 * doubled unless it is already at the maximum size which is hard coded into
 * GFS2_DIR_MAX_DEPTH. After that, leaves are chained together in a linked list,
 * but never before the maximum hash table size has been reached.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/buffer_head.h>
#include <linux/sort.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/crc32.h>
#include <linux/vmalloc.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "dir.h"
// #include "glock.h"
// #include "inode.h"
// #include "meta_io.h"
// #include "quota.h"
// #include "rgrp.h"
// #include "trans.h"
// #include "bmap.h"
// #include "util.h"

#define IS_LEAF     1 /* Hashed (leaf) directory */
#define IS_DINODE   2 /* Linear (stuffed dinode block) directory */

#define MAX_RA_BLOCKS 32 /* max read-ahead blocks */

#define gfs2_disk_hash2offset(h) (((u64)(h)) >> 1)
#define gfs2_dir_offset2hash(p) ((u32)(((u64)(p)) << 1))

struct qstr gfs2_qdot __read_mostly;
struct qstr gfs2_qdotdot __read_mostly;

typedef int (*gfs2_dscan_t)(const struct gfs2_dirent *dent,
			    const struct qstr *name, void *opaque);

int gfs2_dir_get_new_buffer(struct gfs2_inode *ip, u64 block,
			    struct buffer_head **bhp)
{
	struct buffer_head *bh;

	bh = gfs2_meta_new(ip->i_gl, block);
	gfs2_trans_add_meta(ip->i_gl, bh);
	gfs2_metatype_set(bh, GFS2_METATYPE_JD, GFS2_FORMAT_JD);
	gfs2_buffer_clear_tail(bh, sizeof(struct gfs2_meta_header));
	*bhp = bh;
	return 0;
}

static int gfs2_dir_get_existing_buffer(struct gfs2_inode *ip, u64 block,
					struct buffer_head **bhp)
{
	struct buffer_head *bh;
	int error;

	error = gfs2_meta_read(ip->i_gl, block, DIO_WAIT, &bh);
	if (error)
		return error;
	if (gfs2_metatype_check(GFS2_SB(&ip->i_inode), bh, GFS2_METATYPE_JD)) {
		brelse(bh);
		return -EIO;
	}
	*bhp = bh;
	return 0;
}

static int gfs2_dir_write_stuffed(struct gfs2_inode *ip, const char *buf,
				  unsigned int offset, unsigned int size)
{
	struct buffer_head *dibh;
	int error;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		return error;

	gfs2_trans_add_meta(ip->i_gl, dibh);
	memcpy(dibh->b_data + offset + sizeof(struct gfs2_dinode), buf, size);
	if (ip->i_inode.i_size < offset + size)
		i_size_write(&ip->i_inode, offset + size);
	ip->i_inode.i_mtime = ip->i_inode.i_ctime = CURRENT_TIME;
	gfs2_dinode_out(ip, dibh->b_data);

	brelse(dibh);

	return size;
}



/**
 * gfs2_dir_write_data - Write directory information to the inode
 * @ip: The GFS2 inode
 * @buf: The buffer containing information to be written
 * @offset: The file offset to start writing at
 * @size: The amount of data to write
 *
 * Returns: The number of bytes correctly written or error code
 */
static int gfs2_dir_write_data(struct gfs2_inode *ip, const char *buf,
			       u64 offset, unsigned int size)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head *dibh;
	u64 lblock, dblock;
	u32 extlen = 0;
	unsigned int o;
	int copied = 0;
	int error = 0;
	int new = 0;

	if (!size)
		return 0;

	if (gfs2_is_stuffed(ip) &&
	    offset + size <= sdp->sd_sb.sb_bsize - sizeof(struct gfs2_dinode))
		return gfs2_dir_write_stuffed(ip, buf, (unsigned int)offset,
					      size);

	if (gfs2_assert_warn(sdp, gfs2_is_jdata(ip)))
		return -EINVAL;

	if (gfs2_is_stuffed(ip)) {
		error = gfs2_unstuff_dinode(ip, NULL);
		if (error)
			return error;
	}

	lblock = offset;
	o = do_div(lblock, sdp->sd_jbsize) + sizeof(struct gfs2_meta_header);

	while (copied < size) {
		unsigned int amount;
		struct buffer_head *bh;

		amount = size - copied;
		if (amount > sdp->sd_sb.sb_bsize - o)
			amount = sdp->sd_sb.sb_bsize - o;

		if (!extlen) {
			new = 1;
			error = gfs2_extent_map(&ip->i_inode, lblock, &new,
						&dblock, &extlen);
			if (error)
				goto fail;
			error = -EIO;
			if (gfs2_assert_withdraw(sdp, dblock))
				goto fail;
		}

		if (amount == sdp->sd_jbsize || new)
			error = gfs2_dir_get_new_buffer(ip, dblock, &bh);
		else
			error = gfs2_dir_get_existing_buffer(ip, dblock, &bh);

		if (error)
			goto fail;

		gfs2_trans_add_meta(ip->i_gl, bh);
		memcpy(bh->b_data + o, buf, amount);
		brelse(bh);

		buf += amount;
		copied += amount;
		lblock++;
		dblock++;
		extlen--;

		o = sizeof(struct gfs2_meta_header);
	}

out:
	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		return error;

	if (ip->i_inode.i_size < offset + copied)
		i_size_write(&ip->i_inode, offset + copied);
	ip->i_inode.i_mtime = ip->i_inode.i_ctime = CURRENT_TIME;

	gfs2_trans_add_meta(ip->i_gl, dibh);
	gfs2_dinode_out(ip, dibh->b_data);
	brelse(dibh);

	return copied;
fail:
	if (copied)
		goto out;
	return error;
}

static int gfs2_dir_read_stuffed(struct gfs2_inode *ip, __be64 *buf,
				 unsigned int size)
{
	struct buffer_head *dibh;
	int error;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (!error) {
		memcpy(buf, dibh->b_data + sizeof(struct gfs2_dinode), size);
		brelse(dibh);
	}

	return (error) ? error : size;
}


/**
 * gfs2_dir_read_data - Read a data from a directory inode
 * @ip: The GFS2 Inode
 * @buf: The buffer to place result into
 * @size: Amount of data to transfer
 *
 * Returns: The amount of data actually copied or the error
 */
static int gfs2_dir_read_data(struct gfs2_inode *ip, __be64 *buf,
			      unsigned int size)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	u64 lblock, dblock;
	u32 extlen = 0;
	unsigned int o;
	int copied = 0;
	int error = 0;

	if (gfs2_is_stuffed(ip))
		return gfs2_dir_read_stuffed(ip, buf, size);

	if (gfs2_assert_warn(sdp, gfs2_is_jdata(ip)))
		return -EINVAL;

	lblock = 0;
	o = do_div(lblock, sdp->sd_jbsize) + sizeof(struct gfs2_meta_header);

	while (copied < size) {
		unsigned int amount;
		struct buffer_head *bh;
		int new;

		amount = size - copied;
		if (amount > sdp->sd_sb.sb_bsize - o)
			amount = sdp->sd_sb.sb_bsize - o;

		if (!extlen) {
			new = 0;
			error = gfs2_extent_map(&ip->i_inode, lblock, &new,
						&dblock, &extlen);
			if (error || !dblock)
				goto fail;
			BUG_ON(extlen < 1);
			bh = gfs2_meta_ra(ip->i_gl, dblock, extlen);
		} else {
			error = gfs2_meta_read(ip->i_gl, dblock, DIO_WAIT, &bh);
			if (error)
				goto fail;
		}
		error = gfs2_metatype_check(sdp, bh, GFS2_METATYPE_JD);
		if (error) {
			brelse(bh);
			goto fail;
		}
		dblock++;
		extlen--;
		memcpy(buf, bh->b_data + o, amount);
		brelse(bh);
		buf += (amount/sizeof(__be64));
		copied += amount;
		lblock++;
		o = sizeof(struct gfs2_meta_header);
	}

	return copied;
fail:
	return (copied) ? copied : error;
}

/**
 * gfs2_dir_get_hash_table - Get pointer to the dir hash table
 * @ip: The inode in question
 *
 * Returns: The hash table or an error
 */

static __be64 *gfs2_dir_get_hash_table(struct gfs2_inode *ip)
{
	struct inode *inode = &ip->i_inode;
	int ret;
	u32 hsize;
	__be64 *hc;

	BUG_ON(!(ip->i_diskflags & GFS2_DIF_EXHASH));

	hc = ip->i_hash_cache;
	if (hc)
		return hc;

	hsize = 1 << ip->i_depth;
	hsize *= sizeof(__be64);
	if (hsize != i_size_read(&ip->i_inode)) {
		gfs2_consist_inode(ip);
		return ERR_PTR(-EIO);
	}

	hc = kmalloc(hsize, GFP_NOFS | __GFP_NOWARN);
	if (hc == NULL)
		hc = __vmalloc(hsize, GFP_NOFS, PAGE_KERNEL);

	if (hc == NULL)
		return ERR_PTR(-ENOMEM);

	ret = gfs2_dir_read_data(ip, hc, hsize);
	if (ret < 0) {
		if (is_vmalloc_addr(hc))
			vfree(hc);
		else
			kfree(hc);
		return ERR_PTR(ret);
	}

	spin_lock(&inode->i_lock);
	if (ip->i_hash_cache) {
		if (is_vmalloc_addr(hc))
			vfree(hc);
		else
			kfree(hc);
	} else {
		ip->i_hash_cache = hc;
	}
	spin_unlock(&inode->i_lock);

	return ip->i_hash_cache;
}

/**
 * gfs2_dir_hash_inval - Invalidate dir hash
 * @ip: The directory inode
 *
 * Must be called with an exclusive glock, or during glock invalidation.
 */
void gfs2_dir_hash_inval(struct gfs2_inode *ip)
{
	__be64 *hc = ip->i_hash_cache;
	ip->i_hash_cache = NULL;
	if (is_vmalloc_addr(hc))
		vfree(hc);
	else
		kfree(hc);
}

static inline int gfs2_dirent_sentinel(const struct gfs2_dirent *dent)
{
	return dent->de_inum.no_addr == 0 || dent->de_inum.no_formal_ino == 0;
}

static inline int __gfs2_dirent_find(const struct gfs2_dirent *dent,
				     const struct qstr *name, int ret)
{
	if (!gfs2_dirent_sentinel(dent) &&
	    be32_to_cpu(dent->de_hash) == name->hash &&
	    be16_to_cpu(dent->de_name_len) == name->len &&
	    memcmp(dent+1, name->name, name->len) == 0)
		return ret;
	return 0;
}

static int gfs2_dirent_find(const struct gfs2_dirent *dent,
			    const struct qstr *name,
			    void *opaque)
{
	return __gfs2_dirent_find(dent, name, 1);
}

static int gfs2_dirent_prev(const struct gfs2_dirent *dent,
			    const struct qstr *name,
			    void *opaque)
{
	return __gfs2_dirent_find(dent, name, 2);
}

/*
 * name->name holds ptr to start of block.
 * name->len holds size of block.
 */
static int gfs2_dirent_last(const struct gfs2_dirent *dent,
			    const struct qstr *name,
			    void *opaque)
{
	const char *start = name->name;
	const char *end = (const char *)dent + be16_to_cpu(dent->de_rec_len);
	if (name->len == (end - start))
		return 1;
	return 0;
}

static int gfs2_dirent_find_space(const struct gfs2_dirent *dent,
				  const struct qstr *name,
				  void *opaque)
{
	unsigned required = GFS2_DIRENT_SIZE(name->len);
	unsigned actual = GFS2_DIRENT_SIZE(be16_to_cpu(dent->de_name_len));
	unsigned totlen = be16_to_cpu(dent->de_rec_len);

	if (gfs2_dirent_sentinel(dent))
		actual = 0;
	if (totlen - actual >= required)
		return 1;
	return 0;
}

struct dirent_gather {
	const struct gfs2_dirent **pdent;
	unsigned offset;
};

static int gfs2_dirent_gather(const struct gfs2_dirent *dent,
			      const struct qstr *name,
			      void *opaque)
{
	struct dirent_gather *g = opaque;
	if (!gfs2_dirent_sentinel(dent)) {
		g->pdent[g->offset++] = dent;
	}
	return 0;
}

/*
 * Other possible things to check:
 * - Inode located within filesystem size (and on valid block)
 * - Valid directory entry type
 * Not sure how heavy-weight we want to make this... could also check
 * hash is correct for example, but that would take a lot of extra time.
 * For now the most important thing is to check that the various sizes
 * are correct.
 */
static int gfs2_check_dirent(struct gfs2_dirent *dent, unsigned int offset,
			     unsigned int size, unsigned int len, int first)
{
	const char *msg = "gfs2_dirent too small";
	if (unlikely(size < sizeof(struct gfs2_dirent)))
		goto error;
	msg = "gfs2_dirent misaligned";
	if (unlikely(offset & 0x7))
		goto error;
	msg = "gfs2_dirent points beyond end of block";
	if (unlikely(offset + size > len))
		goto error;
	msg = "zero inode number";
	if (unlikely(!first && gfs2_dirent_sentinel(dent)))
		goto error;
	msg = "name length is greater than space in dirent";
	if (!gfs2_dirent_sentinel(dent) &&
	    unlikely(sizeof(struct gfs2_dirent)+be16_to_cpu(dent->de_name_len) >
		     size))
		goto error;
	return 0;
error:
	pr_warn("%s: %s (%s)\n",
		__func__, msg, first ? "first in block" : "not first in block");
	return -EIO;
}

static int gfs2_dirent_offset(const void *buf)
{
	const struct gfs2_meta_header *h = buf;
	int offset;

	BUG_ON(buf == NULL);

	switch(be32_to_cpu(h->mh_type)) {
	case GFS2_METATYPE_LF:
		offset = sizeof(struct gfs2_leaf);
		break;
	case GFS2_METATYPE_DI:
		offset = sizeof(struct gfs2_dinode);
		break;
	default:
		goto wrong_type;
	}
	return offset;
wrong_type:
	pr_warn("%s: wrong block type %u\n", __func__, be32_to_cpu(h->mh_type));
	return -1;
}

static struct gfs2_dirent *gfs2_dirent_scan(struct inode *inode, void *buf,
					    unsigned int len, gfs2_dscan_t scan,
					    const struct qstr *name,
					    void *opaque)
{
	struct gfs2_dirent *dent, *prev;
	unsigned offset;
	unsigned size;
	int ret = 0;

	ret = gfs2_dirent_offset(buf);
	if (ret < 0)
		goto consist_inode;

	offset = ret;
	prev = NULL;
	dent = buf + offset;
	size = be16_to_cpu(dent->de_rec_len);
	if (gfs2_check_dirent(dent, offset, size, len, 1))
		goto consist_inode;
	do {
		ret = scan(dent, name, opaque);
		if (ret)
			break;
		offset += size;
		if (offset == len)
			break;
		prev = dent;
		dent = buf + offset;
		size = be16_to_cpu(dent->de_rec_len);
		if (gfs2_check_dirent(dent, offset, size, len, 0))
			goto consist_inode;
	} while(1);

	switch(ret) {
	case 0:
		return NULL;
	case 1:
		return dent;
	case 2:
		return prev ? prev : dent;
	default:
		BUG_ON(ret > 0);
		return ERR_PTR(ret);
	}

consist_inode:
	gfs2_consist_inode(GFS2_I(inode));
	return ERR_PTR(-EIO);
}

static int dirent_check_reclen(struct gfs2_inode *dip,
			       const struct gfs2_dirent *d, const void *end_p)
{
	const void *ptr = d;
	u16 rec_len = be16_to_cpu(d->de_rec_len);

	if (unlikely(rec_len < sizeof(struct gfs2_dirent)))
		goto broken;
	ptr += rec_len;
	if (ptr < end_p)
		return rec_len;
	if (ptr == end_p)
		return -ENOENT;
broken:
	gfs2_consist_inode(dip);
	return -EIO;
}

/**
 * dirent_next - Next dirent
 * @dip: the directory
 * @bh: The buffer
 * @dent: Pointer to list of dirents
 *
 * Returns: 0 on success, error code otherwise
 */

static int dirent_next(struct gfs2_inode *dip, struct buffer_head *bh,
		       struct gfs2_dirent **dent)
{
	struct gfs2_dirent *cur = *dent, *tmp;
	char *bh_end = bh->b_data + bh->b_size;
	int ret;

	ret = dirent_check_reclen(dip, cur, bh_end);
	if (ret < 0)
		return ret;

	tmp = (void *)cur + ret;
	ret = dirent_check_reclen(dip, tmp, bh_end);
	if (ret == -EIO)
		return ret;

        /* Only the first dent could ever have de_inum.no_addr == 0 */
	if (gfs2_dirent_sentinel(tmp)) {
		gfs2_consist_inode(dip);
		return -EIO;
	}

	*dent = tmp;
	return 0;
}

/**
 * dirent_del - Delete a dirent
 * @dip: The GFS2 inode
 * @bh: The buffer
 * @prev: The previous dirent
 * @cur: The current dirent
 *
 */

static void dirent_del(struct gfs2_inode *dip, struct buffer_head *bh,
		       struct gfs2_dirent *prev, struct gfs2_dirent *cur)
{
	u16 cur_rec_len, prev_rec_len;

	if (gfs2_dirent_sentinel(cur)) {
		gfs2_consist_inode(dip);
		return;
	}

	gfs2_trans_add_meta(dip->i_gl, bh);

	/* If there is no prev entry, this is the first entry in the block.
	   The de_rec_len is already as big as it needs to be.  Just zero
	   out the inode number and return.  */

	if (!prev) {
		cur->de_inum.no_addr = 0;
		cur->de_inum.no_formal_ino = 0;
		return;
	}

	/*  Combine this dentry with the previous one.  */

	prev_rec_len = be16_to_cpu(prev->de_rec_len);
	cur_rec_len = be16_to_cpu(cur->de_rec_len);

	if ((char *)prev + prev_rec_len != (char *)cur)
		gfs2_consist_inode(dip);
	if ((char *)cur + cur_rec_len > bh->b_data + bh->b_size)
		gfs2_consist_inode(dip);

	prev_rec_len += cur_rec_len;
	prev->de_rec_len = cpu_to_be16(prev_rec_len);
}

/*
 * Takes a dent from which to grab space as an argument. Returns the
 * newly created dent.
 */
static struct gfs2_dirent *gfs2_init_dirent(struct inode *inode,
					    struct gfs2_dirent *dent,
					    const struct qstr *name,
					    struct buffer_head *bh)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_dirent *ndent;
	unsigned offset = 0, totlen;

	if (!gfs2_dirent_sentinel(dent))
		offset = GFS2_DIRENT_SIZE(be16_to_cpu(dent->de_name_len));
	totlen = be16_to_cpu(dent->de_rec_len);
	BUG_ON(offset + name->len > totlen);
	gfs2_trans_add_meta(ip->i_gl, bh);
	ndent = (struct gfs2_dirent *)((char *)dent + offset);
	dent->de_rec_len = cpu_to_be16(offset);
	gfs2_qstr2dirent(name, totlen - offset, ndent);
	return ndent;
}

static struct gfs2_dirent *gfs2_dirent_alloc(struct inode *inode,
					     struct buffer_head *bh,
					     const struct qstr *name)
{
	struct gfs2_dirent *dent;
	dent = gfs2_dirent_scan(inode, bh->b_data, bh->b_size,
				gfs2_dirent_find_space, name, NULL);
	if (!dent || IS_ERR(dent))
		return dent;
	return gfs2_init_dirent(inode, dent, name, bh);
}

static int get_leaf(struct gfs2_inode *dip, u64 leaf_no,
		    struct buffer_head **bhp)
{
	int error;

	error = gfs2_meta_read(dip->i_gl, leaf_no, DIO_WAIT, bhp);
	if (!error && gfs2_metatype_check(GFS2_SB(&dip->i_inode), *bhp, GFS2_METATYPE_LF)) {
		/* pr_info("block num=%llu\n", leaf_no); */
		error = -EIO;
	}

	return error;
}

/**
 * get_leaf_nr - Get a leaf number associated with the index
 * @dip: The GFS2 inode
 * @index:
 * @leaf_out:
 *
 * Returns: 0 on success, error code otherwise
 */

static int get_leaf_nr(struct gfs2_inode *dip, u32 index,
		       u64 *leaf_out)
{
	__be64 *hash;

	hash = gfs2_dir_get_hash_table(dip);
	if (IS_ERR(hash))
		return PTR_ERR(hash);
	*leaf_out = be64_to_cpu(*(hash + index));
	return 0;
}

static int get_first_leaf(struct gfs2_inode *dip, u32 index,
			  struct buffer_head **bh_out)
{
	u64 leaf_no;
	int error;

	error = get_leaf_nr(dip, index, &leaf_no);
	if (!error)
		error = get_leaf(dip, leaf_no, bh_out);

	return error;
}

static struct gfs2_dirent *gfs2_dirent_search(struct inode *inode,
					      const struct qstr *name,
					      gfs2_dscan_t scan,
					      struct buffer_head **pbh)
{
	struct buffer_head *bh;
	struct gfs2_dirent *dent;
	struct gfs2_inode *ip = GFS2_I(inode);
	int error;

	if (ip->i_diskflags & GFS2_DIF_EXHASH) {
		struct gfs2_leaf *leaf;
		unsigned hsize = 1 << ip->i_depth;
		unsigned index;
		u64 ln;
		if (hsize * sizeof(u64) != i_size_read(inode)) {
			gfs2_consist_inode(ip);
			return ERR_PTR(-EIO);
		}

		index = name->hash >> (32 - ip->i_depth);
		error = get_first_leaf(ip, index, &bh);
		if (error)
			return ERR_PTR(error);
		do {
			dent = gfs2_dirent_scan(inode, bh->b_data, bh->b_size,
						scan, name, NULL);
			if (dent)
				goto got_dent;
			leaf = (struct gfs2_leaf *)bh->b_data;
			ln = be64_to_cpu(leaf->lf_next);
			brelse(bh);
			if (!ln)
				break;

			error = get_leaf(ip, ln, &bh);
		} while(!error);

		return error ? ERR_PTR(error) : NULL;
	}


	error = gfs2_meta_inode_buffer(ip, &bh);
	if (error)
		return ERR_PTR(error);
	dent = gfs2_dirent_scan(inode, bh->b_data, bh->b_size, scan, name, NULL);
got_dent:
	if (unlikely(dent == NULL || IS_ERR(dent))) {
		brelse(bh);
		bh = NULL;
	}
	*pbh = bh;
	return dent;
}

static struct gfs2_leaf *new_leaf(struct inode *inode, struct buffer_head **pbh, u16 depth)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	unsigned int n = 1;
	u64 bn;
	int error;
	struct buffer_head *bh;
	struct gfs2_leaf *leaf;
	struct gfs2_dirent *dent;
	struct qstr name = { .name = "" };
	struct timespec tv = CURRENT_TIME;

	error = gfs2_alloc_blocks(ip, &bn, &n, 0, NULL);
	if (error)
		return NULL;
	bh = gfs2_meta_new(ip->i_gl, bn);
	if (!bh)
		return NULL;

	gfs2_trans_add_unrevoke(GFS2_SB(inode), bn, 1);
	gfs2_trans_add_meta(ip->i_gl, bh);
	gfs2_metatype_set(bh, GFS2_METATYPE_LF, GFS2_FORMAT_LF);
	leaf = (struct gfs2_leaf *)bh->b_data;
	leaf->lf_depth = cpu_to_be16(depth);
	leaf->lf_entries = 0;
	leaf->lf_dirent_format = cpu_to_be32(GFS2_FORMAT_DE);
	leaf->lf_next = 0;
	leaf->lf_inode = cpu_to_be64(ip->i_no_addr);
	leaf->lf_dist = cpu_to_be32(1);
	leaf->lf_nsec = cpu_to_be32(tv.tv_nsec);
	leaf->lf_sec = cpu_to_be64(tv.tv_sec);
	memset(leaf->lf_reserved2, 0, sizeof(leaf->lf_reserved2));
	dent = (struct gfs2_dirent *)(leaf+1);
	gfs2_qstr2dirent(&name, bh->b_size - sizeof(struct gfs2_leaf), dent);
	*pbh = bh;
	return leaf;
}

/**
 * dir_make_exhash - Convert a stuffed directory into an ExHash directory
 * @dip: The GFS2 inode
 *
 * Returns: 0 on success, error code otherwise
 */

static int dir_make_exhash(struct inode *inode)
{
	struct gfs2_inode *dip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_dirent *dent;
	struct qstr args;
	struct buffer_head *bh, *dibh;
	struct gfs2_leaf *leaf;
	int y;
	u32 x;
	__be64 *lp;
	u64 bn;
	int error;

	error = gfs2_meta_inode_buffer(dip, &dibh);
	if (error)
		return error;

	/*  Turn over a new leaf  */

	leaf = new_leaf(inode, &bh, 0);
	if (!leaf)
		return -ENOSPC;
	bn = bh->b_blocknr;

	gfs2_assert(sdp, dip->i_entries < (1 << 16));
	leaf->lf_entries = cpu_to_be16(dip->i_entries);

	/*  Copy dirents  */

	gfs2_buffer_copy_tail(bh, sizeof(struct gfs2_leaf), dibh,
			     sizeof(struct gfs2_dinode));

	/*  Find last entry  */

	x = 0;
	args.len = bh->b_size - sizeof(struct gfs2_dinode) +
		   sizeof(struct gfs2_leaf);
	args.name = bh->b_data;
	dent = gfs2_dirent_scan(&dip->i_inode, bh->b_data, bh->b_size,
				gfs2_dirent_last, &args, NULL);
	if (!dent) {
		brelse(bh);
		brelse(dibh);
		return -EIO;
	}
	if (IS_ERR(dent)) {
		brelse(bh);
		brelse(dibh);
		return PTR_ERR(dent);
	}

	/*  Adjust the last dirent's record length
	   (Remember that dent still points to the last entry.)  */

	dent->de_rec_len = cpu_to_be16(be16_to_cpu(dent->de_rec_len) +
		sizeof(struct gfs2_dinode) -
		sizeof(struct gfs2_leaf));

	brelse(bh);

	/*  We're done with the new leaf block, now setup the new
	    hash table.  */

	gfs2_trans_add_meta(dip->i_gl, dibh);
	gfs2_buffer_clear_tail(dibh, sizeof(struct gfs2_dinode));

	lp = (__be64 *)(dibh->b_data + sizeof(struct gfs2_dinode));

	for (x = sdp->sd_hash_ptrs; x--; lp++)
		*lp = cpu_to_be64(bn);

	i_size_write(inode, sdp->sd_sb.sb_bsize / 2);
	gfs2_add_inode_blocks(&dip->i_inode, 1);
	dip->i_diskflags |= GFS2_DIF_EXHASH;

	for (x = sdp->sd_hash_ptrs, y = -1; x; x >>= 1, y++) ;
	dip->i_depth = y;

	gfs2_dinode_out(dip, dibh->b_data);

	brelse(dibh);

	return 0;
}

/**
 * dir_split_leaf - Split a leaf block into two
 * @dip: The GFS2 inode
 * @index:
 * @leaf_no:
 *
 * Returns: 0 on success, error code on failure
 */

static int dir_split_leaf(struct inode *inode, const struct qstr *name)
{
	struct gfs2_inode *dip = GFS2_I(inode);
	struct buffer_head *nbh, *obh, *dibh;
	struct gfs2_leaf *nleaf, *oleaf;
	struct gfs2_dirent *dent = NULL, *prev = NULL, *next = NULL, *new;
	u32 start, len, half_len, divider;
	u64 bn, leaf_no;
	__be64 *lp;
	u32 index;
	int x, moved = 0;
	int error;

	index = name->hash >> (32 - dip->i_depth);
	error = get_leaf_nr(dip, index, &leaf_no);
	if (error)
		return error;

	/*  Get the old leaf block  */
	error = get_leaf(dip, leaf_no, &obh);
	if (error)
		return error;

	oleaf = (struct gfs2_leaf *)obh->b_data;
	if (dip->i_depth == be16_to_cpu(oleaf->lf_depth)) {
		brelse(obh);
		return 1; /* can't split */
	}

	gfs2_trans_add_meta(dip->i_gl, obh);

	nleaf = new_leaf(inode, &nbh, be16_to_cpu(oleaf->lf_depth) + 1);
	if (!nleaf) {
		brelse(obh);
		return -ENOSPC;
	}
	bn = nbh->b_blocknr;

	/*  Compute the start and len of leaf pointers in the hash table.  */
	len = 1 << (dip->i_depth - be16_to_cpu(oleaf->lf_depth));
	half_len = len >> 1;
	if (!half_len) {
		pr_warn("i_depth %u lf_depth %u index %u\n",
			dip->i_depth, be16_to_cpu(oleaf->lf_depth), index);
		gfs2_consist_inode(dip);
		error = -EIO;
		goto fail_brelse;
	}

	start = (index & ~(len - 1));

	/* Change the pointers.
	   Don't bother distinguishing stuffed from non-stuffed.
	   This code is complicated enough already. */
	lp = kmalloc(half_len * sizeof(__be64), GFP_NOFS);
	if (!lp) {
		error = -ENOMEM;
		goto fail_brelse;
	}

	/*  Change the pointers  */
	for (x = 0; x < half_len; x++)
		lp[x] = cpu_to_be64(bn);

	gfs2_dir_hash_inval(dip);

	error = gfs2_dir_write_data(dip, (char *)lp, start * sizeof(u64),
				    half_len * sizeof(u64));
	if (error != half_len * sizeof(u64)) {
		if (error >= 0)
			error = -EIO;
		goto fail_lpfree;
	}

	kfree(lp);

	/*  Compute the divider  */
	divider = (start + half_len) << (32 - dip->i_depth);

	/*  Copy the entries  */
	dent = (struct gfs2_dirent *)(obh->b_data + sizeof(struct gfs2_leaf));

	do {
		next = dent;
		if (dirent_next(dip, obh, &next))
			next = NULL;

		if (!gfs2_dirent_sentinel(dent) &&
		    be32_to_cpu(dent->de_hash) < divider) {
			struct qstr str;
			str.name = (char*)(dent+1);
			str.len = be16_to_cpu(dent->de_name_len);
			str.hash = be32_to_cpu(dent->de_hash);
			new = gfs2_dirent_alloc(inode, nbh, &str);
			if (IS_ERR(new)) {
				error = PTR_ERR(new);
				break;
			}

			new->de_inum = dent->de_inum; /* No endian worries */
			new->de_type = dent->de_type; /* No endian worries */
			be16_add_cpu(&nleaf->lf_entries, 1);

			dirent_del(dip, obh, prev, dent);

			if (!oleaf->lf_entries)
				gfs2_consist_inode(dip);
			be16_add_cpu(&oleaf->lf_entries, -1);

			if (!prev)
				prev = dent;

			moved = 1;
		} else {
			prev = dent;
		}
		dent = next;
	} while (dent);

	oleaf->lf_depth = nleaf->lf_depth;

	error = gfs2_meta_inode_buffer(dip, &dibh);
	if (!gfs2_assert_withdraw(GFS2_SB(&dip->i_inode), !error)) {
		gfs2_trans_add_meta(dip->i_gl, dibh);
		gfs2_add_inode_blocks(&dip->i_inode, 1);
		gfs2_dinode_out(dip, dibh->b_data);
		brelse(dibh);
	}

	brelse(obh);
	brelse(nbh);

	return error;

fail_lpfree:
	kfree(lp);

fail_brelse:
	brelse(obh);
	brelse(nbh);
	return error;
}

/**
 * dir_double_exhash - Double size of ExHash table
 * @dip: The GFS2 dinode
 *
 * Returns: 0 on success, error code on failure
 */

static int dir_double_exhash(struct gfs2_inode *dip)
{
	struct buffer_head *dibh;
	u32 hsize;
	u32 hsize_bytes;
	__be64 *hc;
	__be64 *hc2, *h;
	int x;
	int error = 0;

	hsize = 1 << dip->i_depth;
	hsize_bytes = hsize * sizeof(__be64);

	hc = gfs2_dir_get_hash_table(dip);
	if (IS_ERR(hc))
		return PTR_ERR(hc);

	hc2 = kmalloc(hsize_bytes * 2, GFP_NOFS | __GFP_NOWARN);
	if (hc2 == NULL)
		hc2 = __vmalloc(hsize_bytes * 2, GFP_NOFS, PAGE_KERNEL);

	if (!hc2)
		return -ENOMEM;

	h = hc2;
	error = gfs2_meta_inode_buffer(dip, &dibh);
	if (error)
		goto out_kfree;

	for (x = 0; x < hsize; x++) {
		*h++ = *hc;
		*h++ = *hc;
		hc++;
	}

	error = gfs2_dir_write_data(dip, (char *)hc2, 0, hsize_bytes * 2);
	if (error != (hsize_bytes * 2))
		goto fail;

	gfs2_dir_hash_inval(dip);
	dip->i_hash_cache = hc2;
	dip->i_depth++;
	gfs2_dinode_out(dip, dibh->b_data);
	brelse(dibh);
	return 0;

fail:
	/* Replace original hash table & size */
	gfs2_dir_write_data(dip, (char *)hc, 0, hsize_bytes);
	i_size_write(&dip->i_inode, hsize_bytes);
	gfs2_dinode_out(dip, dibh->b_data);
	brelse(dibh);
out_kfree:
	if (is_vmalloc_addr(hc2))
		vfree(hc2);
	else
		kfree(hc2);
	return error;
}

/**
 * compare_dents - compare directory entries by hash value
 * @a: first dent
 * @b: second dent
 *
 * When comparing the hash entries of @a to @b:
 *   gt: returns 1
 *   lt: returns -1
 *   eq: returns 0
 */

static int compare_dents(const void *a, const void *b)
{
	const struct gfs2_dirent *dent_a, *dent_b;
	u32 hash_a, hash_b;
	int ret = 0;

	dent_a = *(const struct gfs2_dirent **)a;
	hash_a = be32_to_cpu(dent_a->de_hash);

	dent_b = *(const struct gfs2_dirent **)b;
	hash_b = be32_to_cpu(dent_b->de_hash);

	if (hash_a > hash_b)
		ret = 1;
	else if (hash_a < hash_b)
		ret = -1;
	else {
		unsigned int len_a = be16_to_cpu(dent_a->de_name_len);
		unsigned int len_b = be16_to_cpu(dent_b->de_name_len);

		if (len_a > len_b)
			ret = 1;
		else if (len_a < len_b)
			ret = -1;
		else
			ret = memcmp(dent_a + 1, dent_b + 1, len_a);
	}

	return ret;
}

/**
 * do_filldir_main - read out directory entries
 * @dip: The GFS2 inode
 * @ctx: what to feed the entries to
 * @darr: an array of struct gfs2_dirent pointers to read
 * @entries: the number of entries in darr
 * @copied: pointer to int that's non-zero if a entry has been copied out
 *
 * Jump through some hoops to make sure that if there are hash collsions,
 * they are read out at the beginning of a buffer.  We want to minimize
 * the possibility that they will fall into different readdir buffers or
 * that someone will want to seek to that location.
 *
 * Returns: errno, >0 if the actor tells you to stop
 */

static int do_filldir_main(struct gfs2_inode *dip, struct dir_context *ctx,
			   const struct gfs2_dirent **darr, u32 entries,
			   int *copied)
{
	const struct gfs2_dirent *dent, *dent_next;
	u64 off, off_next;
	unsigned int x, y;
	int run = 0;

	sort(darr, entries, sizeof(struct gfs2_dirent *), compare_dents, NULL);

	dent_next = darr[0];
	off_next = be32_to_cpu(dent_next->de_hash);
	off_next = gfs2_disk_hash2offset(off_next);

	for (x = 0, y = 1; x < entries; x++, y++) {
		dent = dent_next;
		off = off_next;

		if (y < entries) {
			dent_next = darr[y];
			off_next = be32_to_cpu(dent_next->de_hash);
			off_next = gfs2_disk_hash2offset(off_next);

			if (off < ctx->pos)
				continue;
			ctx->pos = off;

			if (off_next == off) {
				if (*copied && !run)
					return 1;
				run = 1;
			} else
				run = 0;
		} else {
			if (off < ctx->pos)
				continue;
			ctx->pos = off;
		}

		if (!dir_emit(ctx, (const char *)(dent + 1),
				be16_to_cpu(dent->de_name_len),
				be64_to_cpu(dent->de_inum.no_addr),
				be16_to_cpu(dent->de_type)))
			return 1;

		*copied = 1;
	}

	/* Increment the ctx->pos by one, so the next time we come into the
	   do_filldir fxn, we get the next entry instead of the last one in the
	   current leaf */

	ctx->pos++;

	return 0;
}

static void *gfs2_alloc_sort_buffer(unsigned size)
{
	void *ptr = NULL;

	if (size < KMALLOC_MAX_SIZE)
		ptr = kmalloc(size, GFP_NOFS | __GFP_NOWARN);
	if (!ptr)
		ptr = __vmalloc(size, GFP_NOFS, PAGE_KERNEL);
	return ptr;
}

static void gfs2_free_sort_buffer(void *ptr)
{
	if (is_vmalloc_addr(ptr))
		vfree(ptr);
	else
		kfree(ptr);
}

static int gfs2_dir_read_leaf(struct inode *inode, struct dir_context *ctx,
			      int *copied, unsigned *depth,
			      u64 leaf_no)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct buffer_head *bh;
	struct gfs2_leaf *lf;
	unsigned entries = 0, entries2 = 0;
	unsigned leaves = 0;
	const struct gfs2_dirent **darr, *dent;
	struct dirent_gather g;
	struct buffer_head **larr;
	int leaf = 0;
	int error, i;
	u64 lfn = leaf_no;

	do {
		error = get_leaf(ip, lfn, &bh);
		if (error)
			goto out;
		lf = (struct gfs2_leaf *)bh->b_data;
		if (leaves == 0)
			*depth = be16_to_cpu(lf->lf_depth);
		entries += be16_to_cpu(lf->lf_entries);
		leaves++;
		lfn = be64_to_cpu(lf->lf_next);
		brelse(bh);
	} while(lfn);

	if (!entries)
		return 0;

	error = -ENOMEM;
	/*
	 * The extra 99 entries are not normally used, but are a buffer
	 * zone in case the number of entries in the leaf is corrupt.
	 * 99 is the maximum number of entries that can fit in a single
	 * leaf block.
	 */
	larr = gfs2_alloc_sort_buffer((leaves + entries + 99) * sizeof(void *));
	if (!larr)
		goto out;
	darr = (const struct gfs2_dirent **)(larr + leaves);
	g.pdent = darr;
	g.offset = 0;
	lfn = leaf_no;

	do {
		error = get_leaf(ip, lfn, &bh);
		if (error)
			goto out_free;
		lf = (struct gfs2_leaf *)bh->b_data;
		lfn = be64_to_cpu(lf->lf_next);
		if (lf->lf_entries) {
			entries2 += be16_to_cpu(lf->lf_entries);
			dent = gfs2_dirent_scan(inode, bh->b_data, bh->b_size,
						gfs2_dirent_gather, NULL, &g);
			error = PTR_ERR(dent);
			if (IS_ERR(dent))
				goto out_free;
			if (entries2 != g.offset) {
				fs_warn(sdp, "Number of entries corrupt in dir "
						"leaf %llu, entries2 (%u) != "
						"g.offset (%u)\n",
					(unsigned long long)bh->b_blocknr,
					entries2, g.offset);

				error = -EIO;
				goto out_free;
			}
			error = 0;
			larr[leaf++] = bh;
		} else {
			brelse(bh);
		}
	} while(lfn);

	BUG_ON(entries2 != entries);
	error = do_filldir_main(ip, ctx, darr, entries, copied);
out_free:
	for(i = 0; i < leaf; i++)
		brelse(larr[i]);
	gfs2_free_sort_buffer(larr);
out:
	return error;
}

/**
 * gfs2_dir_readahead - Issue read-ahead requests for leaf blocks.
 *
 * Note: we can't calculate each index like dir_e_read can because we don't
 * have the leaf, and therefore we don't have the depth, and therefore we
 * don't have the length. So we have to just read enough ahead to make up
 * for the loss of information.
 */
static void gfs2_dir_readahead(struct inode *inode, unsigned hsize, u32 index,
			       struct file_ra_state *f_ra)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_glock *gl = ip->i_gl;
	struct buffer_head *bh;
	u64 blocknr = 0, last;
	unsigned count;

	/* First check if we've already read-ahead for the whole range. */
	if (index + MAX_RA_BLOCKS < f_ra->start)
		return;

	f_ra->start = max((pgoff_t)index, f_ra->start);
	for (count = 0; count < MAX_RA_BLOCKS; count++) {
		if (f_ra->start >= hsize) /* if exceeded the hash table */
			break;

		last = blocknr;
		blocknr = be64_to_cpu(ip->i_hash_cache[f_ra->start]);
		f_ra->start++;
		if (blocknr == last)
			continue;

		bh = gfs2_getbuf(gl, blocknr, 1);
		if (trylock_buffer(bh)) {
			if (buffer_uptodate(bh)) {
				unlock_buffer(bh);
				brelse(bh);
				continue;
			}
			bh->b_end_io = end_buffer_read_sync;
			submit_bh(READA | REQ_META, bh);
			continue;
		}
		brelse(bh);
	}
}

/**
 * dir_e_read - Reads the entries from a directory into a filldir buffer
 * @dip: dinode pointer
 * @ctx: actor to feed the entries to
 *
 * Returns: errno
 */

static int dir_e_read(struct inode *inode, struct dir_context *ctx,
		      struct file_ra_state *f_ra)
{
	struct gfs2_inode *dip = GFS2_I(inode);
	u32 hsize, len = 0;
	u32 hash, index;
	__be64 *lp;
	int copied = 0;
	int error = 0;
	unsigned depth = 0;

	hsize = 1 << dip->i_depth;
	hash = gfs2_dir_offset2hash(ctx->pos);
	index = hash >> (32 - dip->i_depth);

	if (dip->i_hash_cache == NULL)
		f_ra->start = 0;
	lp = gfs2_dir_get_hash_table(dip);
	if (IS_ERR(lp))
		return PTR_ERR(lp);

	gfs2_dir_readahead(inode, hsize, index, f_ra);

	while (index < hsize) {
		error = gfs2_dir_read_leaf(inode, ctx,
					   &copied, &depth,
					   be64_to_cpu(lp[index]));
		if (error)
			break;

		len = 1 << (dip->i_depth - depth);
		index = (index & ~(len - 1)) + len;
	}

	if (error > 0)
		error = 0;
	return error;
}

int gfs2_dir_read(struct inode *inode, struct dir_context *ctx,
		  struct file_ra_state *f_ra)
{
	struct gfs2_inode *dip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct dirent_gather g;
	const struct gfs2_dirent **darr, *dent;
	struct buffer_head *dibh;
	int copied = 0;
	int error;

	if (!dip->i_entries)
		return 0;

	if (dip->i_diskflags & GFS2_DIF_EXHASH)
		return dir_e_read(inode, ctx, f_ra);

	if (!gfs2_is_stuffed(dip)) {
		gfs2_consist_inode(dip);
		return -EIO;
	}

	error = gfs2_meta_inode_buffer(dip, &dibh);
	if (error)
		return error;

	error = -ENOMEM;
	/* 96 is max number of dirents which can be stuffed into an inode */
	darr = kmalloc(96 * sizeof(struct gfs2_dirent *), GFP_NOFS);
	if (darr) {
		g.pdent = darr;
		g.offset = 0;
		dent = gfs2_dirent_scan(inode, dibh->b_data, dibh->b_size,
					gfs2_dirent_gather, NULL, &g);
		if (IS_ERR(dent)) {
			error = PTR_ERR(dent);
			goto out;
		}
		if (dip->i_entries != g.offset) {
			fs_warn(sdp, "Number of entries corrupt in dir %llu, "
				"ip->i_entries (%u) != g.offset (%u)\n",
				(unsigned long long)dip->i_no_addr,
				dip->i_entries,
				g.offset);
			error = -EIO;
			goto out;
		}
		error = do_filldir_main(dip, ctx, darr,
					dip->i_entries, &copied);
out:
		kfree(darr);
	}

	if (error > 0)
		error = 0;

	brelse(dibh);

	return error;
}

/**
 * gfs2_dir_search - Search a directory
 * @dip: The GFS2 dir inode
 * @name: The name we are looking up
 * @fail_on_exist: Fail if the name exists rather than looking it up
 *
 * This routine searches a directory for a file or another directory.
 * Assumes a glock is held on dip.
 *
 * Returns: errno
 */

struct inode *gfs2_dir_search(struct inode *dir, const struct qstr *name,
			      bool fail_on_exist)
{
	struct buffer_head *bh;
	struct gfs2_dirent *dent;
	u64 addr, formal_ino;
	u16 dtype;

	dent = gfs2_dirent_search(dir, name, gfs2_dirent_find, &bh);
	if (dent) {
		if (IS_ERR(dent))
			return ERR_CAST(dent);
		dtype = be16_to_cpu(dent->de_type);
		addr = be64_to_cpu(dent->de_inum.no_addr);
		formal_ino = be64_to_cpu(dent->de_inum.no_formal_ino);
		brelse(bh);
		if (fail_on_exist)
			return ERR_PTR(-EEXIST);
		return gfs2_inode_lookup(dir->i_sb, dtype, addr, formal_ino, 0);
	}
	return ERR_PTR(-ENOENT);
}

int gfs2_dir_check(struct inode *dir, const struct qstr *name,
		   const struct gfs2_inode *ip)
{
	struct buffer_head *bh;
	struct gfs2_dirent *dent;
	int ret = -ENOENT;

	dent = gfs2_dirent_search(dir, name, gfs2_dirent_find, &bh);
	if (dent) {
		if (IS_ERR(dent))
			return PTR_ERR(dent);
		if (ip) {
			if (be64_to_cpu(dent->de_inum.no_addr) != ip->i_no_addr)
				goto out;
			if (be64_to_cpu(dent->de_inum.no_formal_ino) !=
			    ip->i_no_formal_ino)
				goto out;
			if (unlikely(IF2DT(ip->i_inode.i_mode) !=
			    be16_to_cpu(dent->de_type))) {
				gfs2_consist_inode(GFS2_I(dir));
				ret = -EIO;
				goto out;
			}
		}
		ret = 0;
out:
		brelse(bh);
	}
	return ret;
}

/**
 * dir_new_leaf - Add a new leaf onto hash chain
 * @inode: The directory
 * @name: The name we are adding
 *
 * This adds a new dir leaf onto an existing leaf when there is not
 * enough space to add a new dir entry. This is a last resort after
 * we've expanded the hash table to max size and also split existing
 * leaf blocks, so it will only occur for very large directories.
 *
 * The dist parameter is set to 1 for leaf blocks directly attached
 * to the hash table, 2 for one layer of indirection, 3 for two layers
 * etc. We are thus able to tell the difference between an old leaf
 * with dist set to zero (i.e. "don't know") and a new one where we
 * set this information for debug/fsck purposes.
 *
 * Returns: 0 on success, or -ve on error
 */

static int dir_new_leaf(struct inode *inode, const struct qstr *name)
{
	struct buffer_head *bh, *obh;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_leaf *leaf, *oleaf;
	u32 dist = 1;
	int error;
	u32 index;
	u64 bn;

	index = name->hash >> (32 - ip->i_depth);
	error = get_first_leaf(ip, index, &obh);
	if (error)
		return error;
	do {
		dist++;
		oleaf = (struct gfs2_leaf *)obh->b_data;
		bn = be64_to_cpu(oleaf->lf_next);
		if (!bn)
			break;
		brelse(obh);
		error = get_leaf(ip, bn, &obh);
		if (error)
			return error;
	} while(1);

	gfs2_trans_add_meta(ip->i_gl, obh);

	leaf = new_leaf(inode, &bh, be16_to_cpu(oleaf->lf_depth));
	if (!leaf) {
		brelse(obh);
		return -ENOSPC;
	}
	leaf->lf_dist = cpu_to_be32(dist);
	oleaf->lf_next = cpu_to_be64(bh->b_blocknr);
	brelse(bh);
	brelse(obh);

	error = gfs2_meta_inode_buffer(ip, &bh);
	if (error)
		return error;
	gfs2_trans_add_meta(ip->i_gl, bh);
	gfs2_add_inode_blocks(&ip->i_inode, 1);
	gfs2_dinode_out(ip, bh->b_data);
	brelse(bh);
	return 0;
}

static u16 gfs2_inode_ra_len(const struct gfs2_inode *ip)
{
	u64 where = ip->i_no_addr + 1;
	if (ip->i_eattr == where)
		return 1;
	return 0;
}

/**
 * gfs2_dir_add - Add new filename into directory
 * @inode: The directory inode
 * @name: The new name
 * @nip: The GFS2 inode to be linked in to the directory
 * @da: The directory addition info
 *
 * If the call to gfs2_diradd_alloc_required resulted in there being
 * no need to allocate any new directory blocks, then it will contain
 * a pointer to the directory entry and the bh in which it resides. We
 * can use that without having to repeat the search. If there was no
 * free space, then we must now create more space.
 *
 * Returns: 0 on success, error code on failure
 */

int gfs2_dir_add(struct inode *inode, const struct qstr *name,
		 const struct gfs2_inode *nip, struct gfs2_diradd *da)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct buffer_head *bh = da->bh;
	struct gfs2_dirent *dent = da->dent;
	struct timespec tv;
	struct gfs2_leaf *leaf;
	int error;

	while(1) {
		if (da->bh == NULL) {
			dent = gfs2_dirent_search(inode, name,
						  gfs2_dirent_find_space, &bh);
		}
		if (dent) {
			if (IS_ERR(dent))
				return PTR_ERR(dent);
			dent = gfs2_init_dirent(inode, dent, name, bh);
			gfs2_inum_out(nip, dent);
			dent->de_type = cpu_to_be16(IF2DT(nip->i_inode.i_mode));
			dent->de_rahead = cpu_to_be16(gfs2_inode_ra_len(nip));
			tv = CURRENT_TIME;
			if (ip->i_diskflags & GFS2_DIF_EXHASH) {
				leaf = (struct gfs2_leaf *)bh->b_data;
				be16_add_cpu(&leaf->lf_entries, 1);
				leaf->lf_nsec = cpu_to_be32(tv.tv_nsec);
				leaf->lf_sec = cpu_to_be64(tv.tv_sec);
			}
			da->dent = NULL;
			da->bh = NULL;
			brelse(bh);
			ip->i_entries++;
			ip->i_inode.i_mtime = ip->i_inode.i_ctime = tv;
			if (S_ISDIR(nip->i_inode.i_mode))
				inc_nlink(&ip->i_inode);
			mark_inode_dirty(inode);
			error = 0;
			break;
		}
		if (!(ip->i_diskflags & GFS2_DIF_EXHASH)) {
			error = dir_make_exhash(inode);
			if (error)
				break;
			continue;
		}
		error = dir_split_leaf(inode, name);
		if (error == 0)
			continue;
		if (error < 0)
			break;
		if (ip->i_depth < GFS2_DIR_MAX_DEPTH) {
			error = dir_double_exhash(ip);
			if (error)
				break;
			error = dir_split_leaf(inode, name);
			if (error < 0)
				break;
			if (error == 0)
				continue;
		}
		error = dir_new_leaf(inode, name);
		if (!error)
			continue;
		error = -ENOSPC;
		break;
	}
	return error;
}


/**
 * gfs2_dir_del - Delete a directory entry
 * @dip: The GFS2 inode
 * @filename: The filename
 *
 * Returns: 0 on success, error code on failure
 */

int gfs2_dir_del(struct gfs2_inode *dip, const struct dentry *dentry)
{
	const struct qstr *name = &dentry->d_name;
	struct gfs2_dirent *dent, *prev = NULL;
	struct buffer_head *bh;
	struct timespec tv = CURRENT_TIME;

	/* Returns _either_ the entry (if its first in block) or the
	   previous entry otherwise */
	dent = gfs2_dirent_search(&dip->i_inode, name, gfs2_dirent_prev, &bh);
	if (!dent) {
		gfs2_consist_inode(dip);
		return -EIO;
	}
	if (IS_ERR(dent)) {
		gfs2_consist_inode(dip);
		return PTR_ERR(dent);
	}
	/* If not first in block, adjust pointers accordingly */
	if (gfs2_dirent_find(dent, name, NULL) == 0) {
		prev = dent;
		dent = (struct gfs2_dirent *)((char *)dent + be16_to_cpu(prev->de_rec_len));
	}

	dirent_del(dip, bh, prev, dent);
	if (dip->i_diskflags & GFS2_DIF_EXHASH) {
		struct gfs2_leaf *leaf = (struct gfs2_leaf *)bh->b_data;
		u16 entries = be16_to_cpu(leaf->lf_entries);
		if (!entries)
			gfs2_consist_inode(dip);
		leaf->lf_entries = cpu_to_be16(--entries);
		leaf->lf_nsec = cpu_to_be32(tv.tv_nsec);
		leaf->lf_sec = cpu_to_be64(tv.tv_sec);
	}
	brelse(bh);

	if (!dip->i_entries)
		gfs2_consist_inode(dip);
	dip->i_entries--;
	dip->i_inode.i_mtime = dip->i_inode.i_ctime = tv;
	if (S_ISDIR(dentry->d_inode->i_mode))
		drop_nlink(&dip->i_inode);
	mark_inode_dirty(&dip->i_inode);

	return 0;
}

/**
 * gfs2_dir_mvino - Change inode number of directory entry
 * @dip: The GFS2 inode
 * @filename:
 * @new_inode:
 *
 * This routine changes the inode number of a directory entry.  It's used
 * by rename to change ".." when a directory is moved.
 * Assumes a glock is held on dvp.
 *
 * Returns: errno
 */

int gfs2_dir_mvino(struct gfs2_inode *dip, const struct qstr *filename,
		   const struct gfs2_inode *nip, unsigned int new_type)
{
	struct buffer_head *bh;
	struct gfs2_dirent *dent;
	int error;

	dent = gfs2_dirent_search(&dip->i_inode, filename, gfs2_dirent_find, &bh);
	if (!dent) {
		gfs2_consist_inode(dip);
		return -EIO;
	}
	if (IS_ERR(dent))
		return PTR_ERR(dent);

	gfs2_trans_add_meta(dip->i_gl, bh);
	gfs2_inum_out(nip, dent);
	dent->de_type = cpu_to_be16(new_type);

	if (dip->i_diskflags & GFS2_DIF_EXHASH) {
		brelse(bh);
		error = gfs2_meta_inode_buffer(dip, &bh);
		if (error)
			return error;
		gfs2_trans_add_meta(dip->i_gl, bh);
	}

	dip->i_inode.i_mtime = dip->i_inode.i_ctime = CURRENT_TIME;
	gfs2_dinode_out(dip, bh->b_data);
	brelse(bh);
	return 0;
}

/**
 * leaf_dealloc - Deallocate a directory leaf
 * @dip: the directory
 * @index: the hash table offset in the directory
 * @len: the number of pointers to this leaf
 * @leaf_no: the leaf number
 * @leaf_bh: buffer_head for the starting leaf
 * last_dealloc: 1 if this is the final dealloc for the leaf, else 0
 *
 * Returns: errno
 */

static int leaf_dealloc(struct gfs2_inode *dip, u32 index, u32 len,
			u64 leaf_no, struct buffer_head *leaf_bh,
			int last_dealloc)
{
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	struct gfs2_leaf *tmp_leaf;
	struct gfs2_rgrp_list rlist;
	struct buffer_head *bh, *dibh;
	u64 blk, nblk;
	unsigned int rg_blocks = 0, l_blocks = 0;
	char *ht;
	unsigned int x, size = len * sizeof(u64);
	int error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	memset(&rlist, 0, sizeof(struct gfs2_rgrp_list));

	ht = kzalloc(size, GFP_NOFS | __GFP_NOWARN);
	if (ht == NULL)
		ht = vzalloc(size);
	if (!ht)
		return -ENOMEM;

	error = gfs2_quota_hold(dip, NO_UID_QUOTA_CHANGE, NO_GID_QUOTA_CHANGE);
	if (error)
		goto out;

	/*  Count the number of leaves  */
	bh = leaf_bh;

	for (blk = leaf_no; blk; blk = nblk) {
		if (blk != leaf_no) {
			error = get_leaf(dip, blk, &bh);
			if (error)
				goto out_rlist;
		}
		tmp_leaf = (struct gfs2_leaf *)bh->b_data;
		nblk = be64_to_cpu(tmp_leaf->lf_next);
		if (blk != leaf_no)
			brelse(bh);

		gfs2_rlist_add(dip, &rlist, blk);
		l_blocks++;
	}

	gfs2_rlist_alloc(&rlist, LM_ST_EXCLUSIVE);

	for (x = 0; x < rlist.rl_rgrps; x++) {
		struct gfs2_rgrpd *rgd;
		rgd = rlist.rl_ghs[x].gh_gl->gl_object;
		rg_blocks += rgd->rd_length;
	}

	error = gfs2_glock_nq_m(rlist.rl_rgrps, rlist.rl_ghs);
	if (error)
		goto out_rlist;

	error = gfs2_trans_begin(sdp,
			rg_blocks + (DIV_ROUND_UP(size, sdp->sd_jbsize) + 1) +
			RES_DINODE + RES_STATFS + RES_QUOTA, l_blocks);
	if (error)
		goto out_rg_gunlock;

	bh = leaf_bh;

	for (blk = leaf_no; blk; blk = nblk) {
		if (blk != leaf_no) {
			error = get_leaf(dip, blk, &bh);
			if (error)
				goto out_end_trans;
		}
		tmp_leaf = (struct gfs2_leaf *)bh->b_data;
		nblk = be64_to_cpu(tmp_leaf->lf_next);
		if (blk != leaf_no)
			brelse(bh);

		gfs2_free_meta(dip, blk, 1);
		gfs2_add_inode_blocks(&dip->i_inode, -1);
	}

	error = gfs2_dir_write_data(dip, ht, index * sizeof(u64), size);
	if (error != size) {
		if (error >= 0)
			error = -EIO;
		goto out_end_trans;
	}

	error = gfs2_meta_inode_buffer(dip, &dibh);
	if (error)
		goto out_end_trans;

	gfs2_trans_add_meta(dip->i_gl, dibh);
	/* On the last dealloc, make this a regular file in case we crash.
	   (We don't want to free these blocks a second time.)  */
	if (last_dealloc)
		dip->i_inode.i_mode = S_IFREG;
	gfs2_dinode_out(dip, dibh->b_data);
	brelse(dibh);

out_end_trans:
	gfs2_trans_end(sdp);
out_rg_gunlock:
	gfs2_glock_dq_m(rlist.rl_rgrps, rlist.rl_ghs);
out_rlist:
	gfs2_rlist_free(&rlist);
	gfs2_quota_unhold(dip);
out:
	if (is_vmalloc_addr(ht))
		vfree(ht);
	else
		kfree(ht);
	return error;
}

/**
 * gfs2_dir_exhash_dealloc - free all the leaf blocks in a directory
 * @dip: the directory
 *
 * Dealloc all on-disk directory leaves to FREEMETA state
 * Change on-disk inode type to "regular file"
 *
 * Returns: errno
 */

int gfs2_dir_exhash_dealloc(struct gfs2_inode *dip)
{
	struct buffer_head *bh;
	struct gfs2_leaf *leaf;
	u32 hsize, len;
	u32 index = 0, next_index;
	__be64 *lp;
	u64 leaf_no;
	int error = 0, last;

	hsize = 1 << dip->i_depth;

	lp = gfs2_dir_get_hash_table(dip);
	if (IS_ERR(lp))
		return PTR_ERR(lp);

	while (index < hsize) {
		leaf_no = be64_to_cpu(lp[index]);
		if (leaf_no) {
			error = get_leaf(dip, leaf_no, &bh);
			if (error)
				goto out;
			leaf = (struct gfs2_leaf *)bh->b_data;
			len = 1 << (dip->i_depth - be16_to_cpu(leaf->lf_depth));

			next_index = (index & ~(len - 1)) + len;
			last = ((next_index >= hsize) ? 1 : 0);
			error = leaf_dealloc(dip, index, len, leaf_no, bh,
					     last);
			brelse(bh);
			if (error)
				goto out;
			index = next_index;
		} else
			index++;
	}

	if (index != hsize) {
		gfs2_consist_inode(dip);
		error = -EIO;
	}

out:

	return error;
}

/**
 * gfs2_diradd_alloc_required - find if adding entry will require an allocation
 * @ip: the file being written to
 * @filname: the filename that's going to be added
 * @da: The structure to return dir alloc info
 *
 * Returns: 0 if ok, -ve on error
 */

int gfs2_diradd_alloc_required(struct inode *inode, const struct qstr *name,
			       struct gfs2_diradd *da)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	const unsigned int extra = sizeof(struct gfs2_dinode) - sizeof(struct gfs2_leaf);
	struct gfs2_dirent *dent;
	struct buffer_head *bh;

	da->nr_blocks = 0;
	da->bh = NULL;
	da->dent = NULL;

	dent = gfs2_dirent_search(inode, name, gfs2_dirent_find_space, &bh);
	if (!dent) {
		da->nr_blocks = sdp->sd_max_dirres;
		if (!(ip->i_diskflags & GFS2_DIF_EXHASH) &&
		    (GFS2_DIRENT_SIZE(name->len) < extra))
			da->nr_blocks = 1;
		return 0;
	}
	if (IS_ERR(dent))
		return PTR_ERR(dent);
	da->bh = bh;
	da->dent = dent;
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/xattr.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/xattr.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/posix_acl_xattr.h>
#include <asm/uaccess.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "acl.h"
// #include "xattr.h"
// #include "glock.h"
// #include "inode.h"
// #include "meta_io.h"
// #include "quota.h"
// #include "rgrp.h"
// #include "trans.h"
// #include "util.h"

/**
 * ea_calc_size - returns the acutal number of bytes the request will take up
 *                (not counting any unstuffed data blocks)
 * @sdp:
 * @er:
 * @size:
 *
 * Returns: 1 if the EA should be stuffed
 */

static int ea_calc_size(struct gfs2_sbd *sdp, unsigned int nsize, size_t dsize,
			unsigned int *size)
{
	unsigned int jbsize = sdp->sd_jbsize;

	/* Stuffed */
	*size = ALIGN(sizeof(struct gfs2_ea_header) + nsize + dsize, 8);

	if (*size <= jbsize)
		return 1;

	/* Unstuffed */
	*size = ALIGN(sizeof(struct gfs2_ea_header) + nsize +
		      (sizeof(__be64) * DIV_ROUND_UP(dsize, jbsize)), 8);

	return 0;
}

static int ea_check_size(struct gfs2_sbd *sdp, unsigned int nsize, size_t dsize)
{
	unsigned int size;

	if (dsize > GFS2_EA_MAX_DATA_LEN)
		return -ERANGE;

	ea_calc_size(sdp, nsize, dsize, &size);

	/* This can only happen with 512 byte blocks */
	if (size > sdp->sd_jbsize)
		return -ERANGE;

	return 0;
}

typedef int (*ea_call_t) (struct gfs2_inode *ip, struct buffer_head *bh,
			  struct gfs2_ea_header *ea,
			  struct gfs2_ea_header *prev, void *private);

static int ea_foreach_i(struct gfs2_inode *ip, struct buffer_head *bh,
			ea_call_t ea_call, void *data)
{
	struct gfs2_ea_header *ea, *prev = NULL;
	int error = 0;

	if (gfs2_metatype_check(GFS2_SB(&ip->i_inode), bh, GFS2_METATYPE_EA))
		return -EIO;

	for (ea = GFS2_EA_BH2FIRST(bh);; prev = ea, ea = GFS2_EA2NEXT(ea)) {
		if (!GFS2_EA_REC_LEN(ea))
			goto fail;
		if (!(bh->b_data <= (char *)ea && (char *)GFS2_EA2NEXT(ea) <=
						  bh->b_data + bh->b_size))
			goto fail;
		if (!GFS2_EATYPE_VALID(ea->ea_type))
			goto fail;

		error = ea_call(ip, bh, ea, prev, data);
		if (error)
			return error;

		if (GFS2_EA_IS_LAST(ea)) {
			if ((char *)GFS2_EA2NEXT(ea) !=
			    bh->b_data + bh->b_size)
				goto fail;
			break;
		}
	}

	return error;

fail:
	gfs2_consist_inode(ip);
	return -EIO;
}

static int ea_foreach(struct gfs2_inode *ip, ea_call_t ea_call, void *data)
{
	struct buffer_head *bh, *eabh;
	__be64 *eablk, *end;
	int error;

	error = gfs2_meta_read(ip->i_gl, ip->i_eattr, DIO_WAIT, &bh);
	if (error)
		return error;

	if (!(ip->i_diskflags & GFS2_DIF_EA_INDIRECT)) {
		error = ea_foreach_i(ip, bh, ea_call, data);
		goto out;
	}

	if (gfs2_metatype_check(GFS2_SB(&ip->i_inode), bh, GFS2_METATYPE_IN)) {
		error = -EIO;
		goto out;
	}

	eablk = (__be64 *)(bh->b_data + sizeof(struct gfs2_meta_header));
	end = eablk + GFS2_SB(&ip->i_inode)->sd_inptrs;

	for (; eablk < end; eablk++) {
		u64 bn;

		if (!*eablk)
			break;
		bn = be64_to_cpu(*eablk);

		error = gfs2_meta_read(ip->i_gl, bn, DIO_WAIT, &eabh);
		if (error)
			break;
		error = ea_foreach_i(ip, eabh, ea_call, data);
		brelse(eabh);
		if (error)
			break;
	}
out:
	brelse(bh);
	return error;
}

struct ea_find {
	int type;
	const char *name;
	size_t namel;
	struct gfs2_ea_location *ef_el;
};

static int ea_find_i(struct gfs2_inode *ip, struct buffer_head *bh,
		     struct gfs2_ea_header *ea, struct gfs2_ea_header *prev,
		     void *private)
{
	struct ea_find *ef = private;

	if (ea->ea_type == GFS2_EATYPE_UNUSED)
		return 0;

	if (ea->ea_type == ef->type) {
		if (ea->ea_name_len == ef->namel &&
		    !memcmp(GFS2_EA2NAME(ea), ef->name, ea->ea_name_len)) {
			struct gfs2_ea_location *el = ef->ef_el;
			get_bh(bh);
			el->el_bh = bh;
			el->el_ea = ea;
			el->el_prev = prev;
			return 1;
		}
	}

	return 0;
}

static int gfs2_ea_find(struct gfs2_inode *ip, int type, const char *name,
			struct gfs2_ea_location *el)
{
	struct ea_find ef;
	int error;

	ef.type = type;
	ef.name = name;
	ef.namel = strlen(name);
	ef.ef_el = el;

	memset(el, 0, sizeof(struct gfs2_ea_location));

	error = ea_foreach(ip, ea_find_i, &ef);
	if (error > 0)
		return 0;

	return error;
}

/**
 * ea_dealloc_unstuffed -
 * @ip:
 * @bh:
 * @ea:
 * @prev:
 * @private:
 *
 * Take advantage of the fact that all unstuffed blocks are
 * allocated from the same RG.  But watch, this may not always
 * be true.
 *
 * Returns: errno
 */

static int ea_dealloc_unstuffed(struct gfs2_inode *ip, struct buffer_head *bh,
				struct gfs2_ea_header *ea,
				struct gfs2_ea_header *prev, void *private)
{
	int *leave = private;
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_rgrpd *rgd;
	struct gfs2_holder rg_gh;
	struct buffer_head *dibh;
	__be64 *dataptrs;
	u64 bn = 0;
	u64 bstart = 0;
	unsigned int blen = 0;
	unsigned int blks = 0;
	unsigned int x;
	int error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	if (GFS2_EA_IS_STUFFED(ea))
		return 0;

	dataptrs = GFS2_EA2DATAPTRS(ea);
	for (x = 0; x < ea->ea_num_ptrs; x++, dataptrs++) {
		if (*dataptrs) {
			blks++;
			bn = be64_to_cpu(*dataptrs);
		}
	}
	if (!blks)
		return 0;

	rgd = gfs2_blk2rgrpd(sdp, bn, 1);
	if (!rgd) {
		gfs2_consist_inode(ip);
		return -EIO;
	}

	error = gfs2_glock_nq_init(rgd->rd_gl, LM_ST_EXCLUSIVE, 0, &rg_gh);
	if (error)
		return error;

	error = gfs2_trans_begin(sdp, rgd->rd_length + RES_DINODE +
				 RES_EATTR + RES_STATFS + RES_QUOTA, blks);
	if (error)
		goto out_gunlock;

	gfs2_trans_add_meta(ip->i_gl, bh);

	dataptrs = GFS2_EA2DATAPTRS(ea);
	for (x = 0; x < ea->ea_num_ptrs; x++, dataptrs++) {
		if (!*dataptrs)
			break;
		bn = be64_to_cpu(*dataptrs);

		if (bstart + blen == bn)
			blen++;
		else {
			if (bstart)
				gfs2_free_meta(ip, bstart, blen);
			bstart = bn;
			blen = 1;
		}

		*dataptrs = 0;
		gfs2_add_inode_blocks(&ip->i_inode, -1);
	}
	if (bstart)
		gfs2_free_meta(ip, bstart, blen);

	if (prev && !leave) {
		u32 len;

		len = GFS2_EA_REC_LEN(prev) + GFS2_EA_REC_LEN(ea);
		prev->ea_rec_len = cpu_to_be32(len);

		if (GFS2_EA_IS_LAST(ea))
			prev->ea_flags |= GFS2_EAFLAG_LAST;
	} else {
		ea->ea_type = GFS2_EATYPE_UNUSED;
		ea->ea_num_ptrs = 0;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (!error) {
		ip->i_inode.i_ctime = CURRENT_TIME;
		gfs2_trans_add_meta(ip->i_gl, dibh);
		gfs2_dinode_out(ip, dibh->b_data);
		brelse(dibh);
	}

	gfs2_trans_end(sdp);

out_gunlock:
	gfs2_glock_dq_uninit(&rg_gh);
	return error;
}

static int ea_remove_unstuffed(struct gfs2_inode *ip, struct buffer_head *bh,
			       struct gfs2_ea_header *ea,
			       struct gfs2_ea_header *prev, int leave)
{
	int error;

	error = gfs2_rindex_update(GFS2_SB(&ip->i_inode));
	if (error)
		return error;

	error = gfs2_quota_hold(ip, NO_UID_QUOTA_CHANGE, NO_GID_QUOTA_CHANGE);
	if (error)
		goto out_alloc;

	error = ea_dealloc_unstuffed(ip, bh, ea, prev, (leave) ? &error : NULL);

	gfs2_quota_unhold(ip);
out_alloc:
	return error;
}

struct ea_list {
	struct gfs2_ea_request *ei_er;
	unsigned int ei_size;
};

static inline unsigned int gfs2_ea_strlen(struct gfs2_ea_header *ea)
{
	switch (ea->ea_type) {
	case GFS2_EATYPE_USR:
		return 5 + ea->ea_name_len + 1;
	case GFS2_EATYPE_SYS:
		return 7 + ea->ea_name_len + 1;
	case GFS2_EATYPE_SECURITY:
		return 9 + ea->ea_name_len + 1;
	default:
		return 0;
	}
}

static int ea_list_i(struct gfs2_inode *ip, struct buffer_head *bh,
		     struct gfs2_ea_header *ea, struct gfs2_ea_header *prev,
		     void *private)
{
	struct ea_list *ei = private;
	struct gfs2_ea_request *er = ei->ei_er;
	unsigned int ea_size = gfs2_ea_strlen(ea);

	if (ea->ea_type == GFS2_EATYPE_UNUSED)
		return 0;

	if (er->er_data_len) {
		char *prefix = NULL;
		unsigned int l = 0;
		char c = 0;

		if (ei->ei_size + ea_size > er->er_data_len)
			return -ERANGE;

		switch (ea->ea_type) {
		case GFS2_EATYPE_USR:
			prefix = "user.";
			l = 5;
			break;
		case GFS2_EATYPE_SYS:
			prefix = "system.";
			l = 7;
			break;
		case GFS2_EATYPE_SECURITY:
			prefix = "security.";
			l = 9;
			break;
		}

		BUG_ON(l == 0);

		memcpy(er->er_data + ei->ei_size, prefix, l);
		memcpy(er->er_data + ei->ei_size + l, GFS2_EA2NAME(ea),
		       ea->ea_name_len);
		memcpy(er->er_data + ei->ei_size + ea_size - 1, &c, 1);
	}

	ei->ei_size += ea_size;

	return 0;
}

/**
 * gfs2_listxattr - List gfs2 extended attributes
 * @dentry: The dentry whose inode we are interested in
 * @buffer: The buffer to write the results
 * @size: The size of the buffer
 *
 * Returns: actual size of data on success, -errno on error
 */

ssize_t gfs2_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct gfs2_inode *ip = GFS2_I(dentry->d_inode);
	struct gfs2_ea_request er;
	struct gfs2_holder i_gh;
	int error;

	memset(&er, 0, sizeof(struct gfs2_ea_request));
	if (size) {
		er.er_data = buffer;
		er.er_data_len = size;
	}

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY, &i_gh);
	if (error)
		return error;

	if (ip->i_eattr) {
		struct ea_list ei = { .ei_er = &er, .ei_size = 0 };

		error = ea_foreach(ip, ea_list_i, &ei);
		if (!error)
			error = ei.ei_size;
	}

	gfs2_glock_dq_uninit(&i_gh);

	return error;
}

/**
 * ea_iter_unstuffed - copies the unstuffed xattr data to/from the
 *                     request buffer
 * @ip: The GFS2 inode
 * @ea: The extended attribute header structure
 * @din: The data to be copied in
 * @dout: The data to be copied out (one of din,dout will be NULL)
 *
 * Returns: errno
 */

static int gfs2_iter_unstuffed(struct gfs2_inode *ip, struct gfs2_ea_header *ea,
			       const char *din, char *dout)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head **bh;
	unsigned int amount = GFS2_EA_DATA_LEN(ea);
	unsigned int nptrs = DIV_ROUND_UP(amount, sdp->sd_jbsize);
	__be64 *dataptrs = GFS2_EA2DATAPTRS(ea);
	unsigned int x;
	int error = 0;
	unsigned char *pos;
	unsigned cp_size;

	bh = kcalloc(nptrs, sizeof(struct buffer_head *), GFP_NOFS);
	if (!bh)
		return -ENOMEM;

	for (x = 0; x < nptrs; x++) {
		error = gfs2_meta_read(ip->i_gl, be64_to_cpu(*dataptrs), 0,
				       bh + x);
		if (error) {
			while (x--)
				brelse(bh[x]);
			goto out;
		}
		dataptrs++;
	}

	for (x = 0; x < nptrs; x++) {
		error = gfs2_meta_wait(sdp, bh[x]);
		if (error) {
			for (; x < nptrs; x++)
				brelse(bh[x]);
			goto out;
		}
		if (gfs2_metatype_check(sdp, bh[x], GFS2_METATYPE_ED)) {
			for (; x < nptrs; x++)
				brelse(bh[x]);
			error = -EIO;
			goto out;
		}

		pos = bh[x]->b_data + sizeof(struct gfs2_meta_header);
		cp_size = (sdp->sd_jbsize > amount) ? amount : sdp->sd_jbsize;

		if (dout) {
			memcpy(dout, pos, cp_size);
			dout += sdp->sd_jbsize;
		}

		if (din) {
			gfs2_trans_add_meta(ip->i_gl, bh[x]);
			memcpy(pos, din, cp_size);
			din += sdp->sd_jbsize;
		}

		amount -= sdp->sd_jbsize;
		brelse(bh[x]);
	}

out:
	kfree(bh);
	return error;
}

static int gfs2_ea_get_copy(struct gfs2_inode *ip, struct gfs2_ea_location *el,
			    char *data, size_t size)
{
	int ret;
	size_t len = GFS2_EA_DATA_LEN(el->el_ea);
	if (len > size)
		return -ERANGE;

	if (GFS2_EA_IS_STUFFED(el->el_ea)) {
		memcpy(data, GFS2_EA2DATA(el->el_ea), len);
		return len;
	}
	ret = gfs2_iter_unstuffed(ip, el->el_ea, NULL, data);
	if (ret < 0)
		return ret;
	return len;
}

int gfs2_xattr_acl_get(struct gfs2_inode *ip, const char *name, char **ppdata)
{
	struct gfs2_ea_location el;
	int error;
	int len;
	char *data;

	error = gfs2_ea_find(ip, GFS2_EATYPE_SYS, name, &el);
	if (error)
		return error;
	if (!el.el_ea)
		goto out;
	if (!GFS2_EA_DATA_LEN(el.el_ea))
		goto out;

	len = GFS2_EA_DATA_LEN(el.el_ea);
	data = kmalloc(len, GFP_NOFS);
	error = -ENOMEM;
	if (data == NULL)
		goto out;

	error = gfs2_ea_get_copy(ip, &el, data, len);
	if (error < 0)
		kfree(data);
	else
		*ppdata = data;
out:
	brelse(el.el_bh);
	return error;
}

/**
 * gfs2_xattr_get - Get a GFS2 extended attribute
 * @inode: The inode
 * @name: The name of the extended attribute
 * @buffer: The buffer to write the result into
 * @size: The size of the buffer
 * @type: The type of extended attribute
 *
 * Returns: actual size of data on success, -errno on error
 */
static int gfs2_xattr_get(struct dentry *dentry, const char *name,
		void *buffer, size_t size, int type)
{
	struct gfs2_inode *ip = GFS2_I(dentry->d_inode);
	struct gfs2_ea_location el;
	int error;

	if (!ip->i_eattr)
		return -ENODATA;
	if (strlen(name) > GFS2_EA_MAX_NAME_LEN)
		return -EINVAL;

	error = gfs2_ea_find(ip, type, name, &el);
	if (error)
		return error;
	if (!el.el_ea)
		return -ENODATA;
	if (size)
		error = gfs2_ea_get_copy(ip, &el, buffer, size);
	else
		error = GFS2_EA_DATA_LEN(el.el_ea);
	brelse(el.el_bh);

	return error;
}

/**
 * ea_alloc_blk - allocates a new block for extended attributes.
 * @ip: A pointer to the inode that's getting extended attributes
 * @bhp: Pointer to pointer to a struct buffer_head
 *
 * Returns: errno
 */

static int ea_alloc_blk(struct gfs2_inode *ip, struct buffer_head **bhp)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_ea_header *ea;
	unsigned int n = 1;
	u64 block;
	int error;

	error = gfs2_alloc_blocks(ip, &block, &n, 0, NULL);
	if (error)
		return error;
	gfs2_trans_add_unrevoke(sdp, block, 1);
	*bhp = gfs2_meta_new(ip->i_gl, block);
	gfs2_trans_add_meta(ip->i_gl, *bhp);
	gfs2_metatype_set(*bhp, GFS2_METATYPE_EA, GFS2_FORMAT_EA);
	gfs2_buffer_clear_tail(*bhp, sizeof(struct gfs2_meta_header));

	ea = GFS2_EA_BH2FIRST(*bhp);
	ea->ea_rec_len = cpu_to_be32(sdp->sd_jbsize);
	ea->ea_type = GFS2_EATYPE_UNUSED;
	ea->ea_flags = GFS2_EAFLAG_LAST;
	ea->ea_num_ptrs = 0;

	gfs2_add_inode_blocks(&ip->i_inode, 1);

	return 0;
}

/**
 * ea_write - writes the request info to an ea, creating new blocks if
 *            necessary
 * @ip: inode that is being modified
 * @ea: the location of the new ea in a block
 * @er: the write request
 *
 * Note: does not update ea_rec_len or the GFS2_EAFLAG_LAST bin of ea_flags
 *
 * returns : errno
 */

static int ea_write(struct gfs2_inode *ip, struct gfs2_ea_header *ea,
		    struct gfs2_ea_request *er)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	int error;

	ea->ea_data_len = cpu_to_be32(er->er_data_len);
	ea->ea_name_len = er->er_name_len;
	ea->ea_type = er->er_type;
	ea->__pad = 0;

	memcpy(GFS2_EA2NAME(ea), er->er_name, er->er_name_len);

	if (GFS2_EAREQ_SIZE_STUFFED(er) <= sdp->sd_jbsize) {
		ea->ea_num_ptrs = 0;
		memcpy(GFS2_EA2DATA(ea), er->er_data, er->er_data_len);
	} else {
		__be64 *dataptr = GFS2_EA2DATAPTRS(ea);
		const char *data = er->er_data;
		unsigned int data_len = er->er_data_len;
		unsigned int copy;
		unsigned int x;

		ea->ea_num_ptrs = DIV_ROUND_UP(er->er_data_len, sdp->sd_jbsize);
		for (x = 0; x < ea->ea_num_ptrs; x++) {
			struct buffer_head *bh;
			u64 block;
			int mh_size = sizeof(struct gfs2_meta_header);
			unsigned int n = 1;

			error = gfs2_alloc_blocks(ip, &block, &n, 0, NULL);
			if (error)
				return error;
			gfs2_trans_add_unrevoke(sdp, block, 1);
			bh = gfs2_meta_new(ip->i_gl, block);
			gfs2_trans_add_meta(ip->i_gl, bh);
			gfs2_metatype_set(bh, GFS2_METATYPE_ED, GFS2_FORMAT_ED);

			gfs2_add_inode_blocks(&ip->i_inode, 1);

			copy = data_len > sdp->sd_jbsize ? sdp->sd_jbsize :
							   data_len;
			memcpy(bh->b_data + mh_size, data, copy);
			if (copy < sdp->sd_jbsize)
				memset(bh->b_data + mh_size + copy, 0,
				       sdp->sd_jbsize - copy);

			*dataptr++ = cpu_to_be64(bh->b_blocknr);
			data += copy;
			data_len -= copy;

			brelse(bh);
		}

		gfs2_assert_withdraw(sdp, !data_len);
	}

	return 0;
}

typedef int (*ea_skeleton_call_t) (struct gfs2_inode *ip,
				   struct gfs2_ea_request *er, void *private);

static int ea_alloc_skeleton(struct gfs2_inode *ip, struct gfs2_ea_request *er,
			     unsigned int blks,
			     ea_skeleton_call_t skeleton_call, void *private)
{
	struct gfs2_alloc_parms ap = { .target = blks };
	struct buffer_head *dibh;
	int error;

	error = gfs2_rindex_update(GFS2_SB(&ip->i_inode));
	if (error)
		return error;

	error = gfs2_quota_lock_check(ip);
	if (error)
		return error;

	error = gfs2_inplace_reserve(ip, &ap);
	if (error)
		goto out_gunlock_q;

	error = gfs2_trans_begin(GFS2_SB(&ip->i_inode),
				 blks + gfs2_rg_blocks(ip, blks) +
				 RES_DINODE + RES_STATFS + RES_QUOTA, 0);
	if (error)
		goto out_ipres;

	error = skeleton_call(ip, er, private);
	if (error)
		goto out_end_trans;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (!error) {
		ip->i_inode.i_ctime = CURRENT_TIME;
		gfs2_trans_add_meta(ip->i_gl, dibh);
		gfs2_dinode_out(ip, dibh->b_data);
		brelse(dibh);
	}

out_end_trans:
	gfs2_trans_end(GFS2_SB(&ip->i_inode));
out_ipres:
	gfs2_inplace_release(ip);
out_gunlock_q:
	gfs2_quota_unlock(ip);
	return error;
}

static int ea_init_i(struct gfs2_inode *ip, struct gfs2_ea_request *er,
		     void *private)
{
	struct buffer_head *bh;
	int error;

	error = ea_alloc_blk(ip, &bh);
	if (error)
		return error;

	ip->i_eattr = bh->b_blocknr;
	error = ea_write(ip, GFS2_EA_BH2FIRST(bh), er);

	brelse(bh);

	return error;
}

/**
 * ea_init - initializes a new eattr block
 * @ip:
 * @er:
 *
 * Returns: errno
 */

static int ea_init(struct gfs2_inode *ip, int type, const char *name,
		   const void *data, size_t size)
{
	struct gfs2_ea_request er;
	unsigned int jbsize = GFS2_SB(&ip->i_inode)->sd_jbsize;
	unsigned int blks = 1;

	er.er_type = type;
	er.er_name = name;
	er.er_name_len = strlen(name);
	er.er_data = (void *)data;
	er.er_data_len = size;

	if (GFS2_EAREQ_SIZE_STUFFED(&er) > jbsize)
		blks += DIV_ROUND_UP(er.er_data_len, jbsize);

	return ea_alloc_skeleton(ip, &er, blks, ea_init_i, NULL);
}

static struct gfs2_ea_header *ea_split_ea(struct gfs2_ea_header *ea)
{
	u32 ea_size = GFS2_EA_SIZE(ea);
	struct gfs2_ea_header *new = (struct gfs2_ea_header *)((char *)ea +
				     ea_size);
	u32 new_size = GFS2_EA_REC_LEN(ea) - ea_size;
	int last = ea->ea_flags & GFS2_EAFLAG_LAST;

	ea->ea_rec_len = cpu_to_be32(ea_size);
	ea->ea_flags ^= last;

	new->ea_rec_len = cpu_to_be32(new_size);
	new->ea_flags = last;

	return new;
}

static void ea_set_remove_stuffed(struct gfs2_inode *ip,
				  struct gfs2_ea_location *el)
{
	struct gfs2_ea_header *ea = el->el_ea;
	struct gfs2_ea_header *prev = el->el_prev;
	u32 len;

	gfs2_trans_add_meta(ip->i_gl, el->el_bh);

	if (!prev || !GFS2_EA_IS_STUFFED(ea)) {
		ea->ea_type = GFS2_EATYPE_UNUSED;
		return;
	} else if (GFS2_EA2NEXT(prev) != ea) {
		prev = GFS2_EA2NEXT(prev);
		gfs2_assert_withdraw(GFS2_SB(&ip->i_inode), GFS2_EA2NEXT(prev) == ea);
	}

	len = GFS2_EA_REC_LEN(prev) + GFS2_EA_REC_LEN(ea);
	prev->ea_rec_len = cpu_to_be32(len);

	if (GFS2_EA_IS_LAST(ea))
		prev->ea_flags |= GFS2_EAFLAG_LAST;
}

struct ea_set {
	int ea_split;

	struct gfs2_ea_request *es_er;
	struct gfs2_ea_location *es_el;

	struct buffer_head *es_bh;
	struct gfs2_ea_header *es_ea;
};

static int ea_set_simple_noalloc(struct gfs2_inode *ip, struct buffer_head *bh,
				 struct gfs2_ea_header *ea, struct ea_set *es)
{
	struct gfs2_ea_request *er = es->es_er;
	struct buffer_head *dibh;
	int error;

	error = gfs2_trans_begin(GFS2_SB(&ip->i_inode), RES_DINODE + 2 * RES_EATTR, 0);
	if (error)
		return error;

	gfs2_trans_add_meta(ip->i_gl, bh);

	if (es->ea_split)
		ea = ea_split_ea(ea);

	ea_write(ip, ea, er);

	if (es->es_el)
		ea_set_remove_stuffed(ip, es->es_el);

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out;
	ip->i_inode.i_ctime = CURRENT_TIME;
	gfs2_trans_add_meta(ip->i_gl, dibh);
	gfs2_dinode_out(ip, dibh->b_data);
	brelse(dibh);
out:
	gfs2_trans_end(GFS2_SB(&ip->i_inode));
	return error;
}

static int ea_set_simple_alloc(struct gfs2_inode *ip,
			       struct gfs2_ea_request *er, void *private)
{
	struct ea_set *es = private;
	struct gfs2_ea_header *ea = es->es_ea;
	int error;

	gfs2_trans_add_meta(ip->i_gl, es->es_bh);

	if (es->ea_split)
		ea = ea_split_ea(ea);

	error = ea_write(ip, ea, er);
	if (error)
		return error;

	if (es->es_el)
		ea_set_remove_stuffed(ip, es->es_el);

	return 0;
}

static int ea_set_simple(struct gfs2_inode *ip, struct buffer_head *bh,
			 struct gfs2_ea_header *ea, struct gfs2_ea_header *prev,
			 void *private)
{
	struct ea_set *es = private;
	unsigned int size;
	int stuffed;
	int error;

	stuffed = ea_calc_size(GFS2_SB(&ip->i_inode), es->es_er->er_name_len,
			       es->es_er->er_data_len, &size);

	if (ea->ea_type == GFS2_EATYPE_UNUSED) {
		if (GFS2_EA_REC_LEN(ea) < size)
			return 0;
		if (!GFS2_EA_IS_STUFFED(ea)) {
			error = ea_remove_unstuffed(ip, bh, ea, prev, 1);
			if (error)
				return error;
		}
		es->ea_split = 0;
	} else if (GFS2_EA_REC_LEN(ea) - GFS2_EA_SIZE(ea) >= size)
		es->ea_split = 1;
	else
		return 0;

	if (stuffed) {
		error = ea_set_simple_noalloc(ip, bh, ea, es);
		if (error)
			return error;
	} else {
		unsigned int blks;

		es->es_bh = bh;
		es->es_ea = ea;
		blks = 2 + DIV_ROUND_UP(es->es_er->er_data_len,
					GFS2_SB(&ip->i_inode)->sd_jbsize);

		error = ea_alloc_skeleton(ip, es->es_er, blks,
					  ea_set_simple_alloc, es);
		if (error)
			return error;
	}

	return 1;
}

static int ea_set_block(struct gfs2_inode *ip, struct gfs2_ea_request *er,
			void *private)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head *indbh, *newbh;
	__be64 *eablk;
	int error;
	int mh_size = sizeof(struct gfs2_meta_header);

	if (ip->i_diskflags & GFS2_DIF_EA_INDIRECT) {
		__be64 *end;

		error = gfs2_meta_read(ip->i_gl, ip->i_eattr, DIO_WAIT,
				       &indbh);
		if (error)
			return error;

		if (gfs2_metatype_check(sdp, indbh, GFS2_METATYPE_IN)) {
			error = -EIO;
			goto out;
		}

		eablk = (__be64 *)(indbh->b_data + mh_size);
		end = eablk + sdp->sd_inptrs;

		for (; eablk < end; eablk++)
			if (!*eablk)
				break;

		if (eablk == end) {
			error = -ENOSPC;
			goto out;
		}

		gfs2_trans_add_meta(ip->i_gl, indbh);
	} else {
		u64 blk;
		unsigned int n = 1;
		error = gfs2_alloc_blocks(ip, &blk, &n, 0, NULL);
		if (error)
			return error;
		gfs2_trans_add_unrevoke(sdp, blk, 1);
		indbh = gfs2_meta_new(ip->i_gl, blk);
		gfs2_trans_add_meta(ip->i_gl, indbh);
		gfs2_metatype_set(indbh, GFS2_METATYPE_IN, GFS2_FORMAT_IN);
		gfs2_buffer_clear_tail(indbh, mh_size);

		eablk = (__be64 *)(indbh->b_data + mh_size);
		*eablk = cpu_to_be64(ip->i_eattr);
		ip->i_eattr = blk;
		ip->i_diskflags |= GFS2_DIF_EA_INDIRECT;
		gfs2_add_inode_blocks(&ip->i_inode, 1);

		eablk++;
	}

	error = ea_alloc_blk(ip, &newbh);
	if (error)
		goto out;

	*eablk = cpu_to_be64((u64)newbh->b_blocknr);
	error = ea_write(ip, GFS2_EA_BH2FIRST(newbh), er);
	brelse(newbh);
	if (error)
		goto out;

	if (private)
		ea_set_remove_stuffed(ip, private);

out:
	brelse(indbh);
	return error;
}

static int ea_set_i(struct gfs2_inode *ip, int type, const char *name,
		    const void *value, size_t size, struct gfs2_ea_location *el)
{
	struct gfs2_ea_request er;
	struct ea_set es;
	unsigned int blks = 2;
	int error;

	er.er_type = type;
	er.er_name = name;
	er.er_data = (void *)value;
	er.er_name_len = strlen(name);
	er.er_data_len = size;

	memset(&es, 0, sizeof(struct ea_set));
	es.es_er = &er;
	es.es_el = el;

	error = ea_foreach(ip, ea_set_simple, &es);
	if (error > 0)
		return 0;
	if (error)
		return error;

	if (!(ip->i_diskflags & GFS2_DIF_EA_INDIRECT))
		blks++;
	if (GFS2_EAREQ_SIZE_STUFFED(&er) > GFS2_SB(&ip->i_inode)->sd_jbsize)
		blks += DIV_ROUND_UP(er.er_data_len, GFS2_SB(&ip->i_inode)->sd_jbsize);

	return ea_alloc_skeleton(ip, &er, blks, ea_set_block, el);
}

static int ea_set_remove_unstuffed(struct gfs2_inode *ip,
				   struct gfs2_ea_location *el)
{
	if (el->el_prev && GFS2_EA2NEXT(el->el_prev) != el->el_ea) {
		el->el_prev = GFS2_EA2NEXT(el->el_prev);
		gfs2_assert_withdraw(GFS2_SB(&ip->i_inode),
				     GFS2_EA2NEXT(el->el_prev) == el->el_ea);
	}

	return ea_remove_unstuffed(ip, el->el_bh, el->el_ea, el->el_prev, 0);
}

static int ea_remove_stuffed(struct gfs2_inode *ip, struct gfs2_ea_location *el)
{
	struct gfs2_ea_header *ea = el->el_ea;
	struct gfs2_ea_header *prev = el->el_prev;
	struct buffer_head *dibh;
	int error;

	error = gfs2_trans_begin(GFS2_SB(&ip->i_inode), RES_DINODE + RES_EATTR, 0);
	if (error)
		return error;

	gfs2_trans_add_meta(ip->i_gl, el->el_bh);

	if (prev) {
		u32 len;

		len = GFS2_EA_REC_LEN(prev) + GFS2_EA_REC_LEN(ea);
		prev->ea_rec_len = cpu_to_be32(len);

		if (GFS2_EA_IS_LAST(ea))
			prev->ea_flags |= GFS2_EAFLAG_LAST;
	} else {
		ea->ea_type = GFS2_EATYPE_UNUSED;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (!error) {
		ip->i_inode.i_ctime = CURRENT_TIME;
		gfs2_trans_add_meta(ip->i_gl, dibh);
		gfs2_dinode_out(ip, dibh->b_data);
		brelse(dibh);
	}

	gfs2_trans_end(GFS2_SB(&ip->i_inode));

	return error;
}

/**
 * gfs2_xattr_remove - Remove a GFS2 extended attribute
 * @ip: The inode
 * @type: The type of the extended attribute
 * @name: The name of the extended attribute
 *
 * This is not called directly by the VFS since we use the (common)
 * scheme of making a "set with NULL data" mean a remove request. Note
 * that this is different from a set with zero length data.
 *
 * Returns: 0, or errno on failure
 */

static int gfs2_xattr_remove(struct gfs2_inode *ip, int type, const char *name)
{
	struct gfs2_ea_location el;
	int error;

	if (!ip->i_eattr)
		return -ENODATA;

	error = gfs2_ea_find(ip, type, name, &el);
	if (error)
		return error;
	if (!el.el_ea)
		return -ENODATA;

	if (GFS2_EA_IS_STUFFED(el.el_ea))
		error = ea_remove_stuffed(ip, &el);
	else
		error = ea_remove_unstuffed(ip, el.el_bh, el.el_ea, el.el_prev, 0);

	brelse(el.el_bh);

	return error;
}

/**
 * __gfs2_xattr_set - Set (or remove) a GFS2 extended attribute
 * @ip: The inode
 * @name: The name of the extended attribute
 * @value: The value of the extended attribute (NULL for remove)
 * @size: The size of the @value argument
 * @flags: Create or Replace
 * @type: The type of the extended attribute
 *
 * See gfs2_xattr_remove() for details of the removal of xattrs.
 *
 * Returns: 0 or errno on failure
 */

int __gfs2_xattr_set(struct inode *inode, const char *name,
		   const void *value, size_t size, int flags, int type)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_ea_location el;
	unsigned int namel = strlen(name);
	int error;

	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		return -EPERM;
	if (namel > GFS2_EA_MAX_NAME_LEN)
		return -ERANGE;

	if (value == NULL)
		return gfs2_xattr_remove(ip, type, name);

	if (ea_check_size(sdp, namel, size))
		return -ERANGE;

	if (!ip->i_eattr) {
		if (flags & XATTR_REPLACE)
			return -ENODATA;
		return ea_init(ip, type, name, value, size);
	}

	error = gfs2_ea_find(ip, type, name, &el);
	if (error)
		return error;

	if (el.el_ea) {
		if (ip->i_diskflags & GFS2_DIF_APPENDONLY) {
			brelse(el.el_bh);
			return -EPERM;
		}

		error = -EEXIST;
		if (!(flags & XATTR_CREATE)) {
			int unstuffed = !GFS2_EA_IS_STUFFED(el.el_ea);
			error = ea_set_i(ip, type, name, value, size, &el);
			if (!error && unstuffed)
				ea_set_remove_unstuffed(ip, &el);
		}

		brelse(el.el_bh);
		return error;
	}

	error = -ENODATA;
	if (!(flags & XATTR_REPLACE))
		error = ea_set_i(ip, type, name, value, size, NULL);

	return error;
}

static int gfs2_xattr_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	return __gfs2_xattr_set(dentry->d_inode, name, value,
				size, flags, type);
}


static int ea_acl_chmod_unstuffed(struct gfs2_inode *ip,
				  struct gfs2_ea_header *ea, char *data)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	unsigned int amount = GFS2_EA_DATA_LEN(ea);
	unsigned int nptrs = DIV_ROUND_UP(amount, sdp->sd_jbsize);
	int ret;

	ret = gfs2_trans_begin(sdp, nptrs + RES_DINODE, 0);
	if (ret)
		return ret;

	ret = gfs2_iter_unstuffed(ip, ea, data, NULL);
	gfs2_trans_end(sdp);

	return ret;
}

int gfs2_xattr_acl_chmod(struct gfs2_inode *ip, struct iattr *attr, char *data)
{
	struct inode *inode = &ip->i_inode;
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_ea_location el;
	int error;

	error = gfs2_ea_find(ip, GFS2_EATYPE_SYS, GFS2_POSIX_ACL_ACCESS, &el);
	if (error)
		return error;

	if (GFS2_EA_IS_STUFFED(el.el_ea)) {
		error = gfs2_trans_begin(sdp, RES_DINODE + RES_EATTR, 0);
		if (error == 0) {
			gfs2_trans_add_meta(ip->i_gl, el.el_bh);
			memcpy(GFS2_EA2DATA(el.el_ea), data,
			       GFS2_EA_DATA_LEN(el.el_ea));
		}
	} else {
		error = ea_acl_chmod_unstuffed(ip, el.el_ea, data);
	}

	brelse(el.el_bh);
	if (error)
		return error;

	error = gfs2_setattr_simple(inode, attr);
	gfs2_trans_end(sdp);
	return error;
}

static int ea_dealloc_indirect(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_rgrp_list rlist;
	struct buffer_head *indbh, *dibh;
	__be64 *eablk, *end;
	unsigned int rg_blocks = 0;
	u64 bstart = 0;
	unsigned int blen = 0;
	unsigned int blks = 0;
	unsigned int x;
	int error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	memset(&rlist, 0, sizeof(struct gfs2_rgrp_list));

	error = gfs2_meta_read(ip->i_gl, ip->i_eattr, DIO_WAIT, &indbh);
	if (error)
		return error;

	if (gfs2_metatype_check(sdp, indbh, GFS2_METATYPE_IN)) {
		error = -EIO;
		goto out;
	}

	eablk = (__be64 *)(indbh->b_data + sizeof(struct gfs2_meta_header));
	end = eablk + sdp->sd_inptrs;

	for (; eablk < end; eablk++) {
		u64 bn;

		if (!*eablk)
			break;
		bn = be64_to_cpu(*eablk);

		if (bstart + blen == bn)
			blen++;
		else {
			if (bstart)
				gfs2_rlist_add(ip, &rlist, bstart);
			bstart = bn;
			blen = 1;
		}
		blks++;
	}
	if (bstart)
		gfs2_rlist_add(ip, &rlist, bstart);
	else
		goto out;

	gfs2_rlist_alloc(&rlist, LM_ST_EXCLUSIVE);

	for (x = 0; x < rlist.rl_rgrps; x++) {
		struct gfs2_rgrpd *rgd;
		rgd = rlist.rl_ghs[x].gh_gl->gl_object;
		rg_blocks += rgd->rd_length;
	}

	error = gfs2_glock_nq_m(rlist.rl_rgrps, rlist.rl_ghs);
	if (error)
		goto out_rlist_free;

	error = gfs2_trans_begin(sdp, rg_blocks + RES_DINODE + RES_INDIRECT +
				 RES_STATFS + RES_QUOTA, blks);
	if (error)
		goto out_gunlock;

	gfs2_trans_add_meta(ip->i_gl, indbh);

	eablk = (__be64 *)(indbh->b_data + sizeof(struct gfs2_meta_header));
	bstart = 0;
	blen = 0;

	for (; eablk < end; eablk++) {
		u64 bn;

		if (!*eablk)
			break;
		bn = be64_to_cpu(*eablk);

		if (bstart + blen == bn)
			blen++;
		else {
			if (bstart)
				gfs2_free_meta(ip, bstart, blen);
			bstart = bn;
			blen = 1;
		}

		*eablk = 0;
		gfs2_add_inode_blocks(&ip->i_inode, -1);
	}
	if (bstart)
		gfs2_free_meta(ip, bstart, blen);

	ip->i_diskflags &= ~GFS2_DIF_EA_INDIRECT;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (!error) {
		gfs2_trans_add_meta(ip->i_gl, dibh);
		gfs2_dinode_out(ip, dibh->b_data);
		brelse(dibh);
	}

	gfs2_trans_end(sdp);

out_gunlock:
	gfs2_glock_dq_m(rlist.rl_rgrps, rlist.rl_ghs);
out_rlist_free:
	gfs2_rlist_free(&rlist);
out:
	brelse(indbh);
	return error;
}

static int ea_dealloc_block(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_rgrpd *rgd;
	struct buffer_head *dibh;
	struct gfs2_holder gh;
	int error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	rgd = gfs2_blk2rgrpd(sdp, ip->i_eattr, 1);
	if (!rgd) {
		gfs2_consist_inode(ip);
		return -EIO;
	}

	error = gfs2_glock_nq_init(rgd->rd_gl, LM_ST_EXCLUSIVE, 0, &gh);
	if (error)
		return error;

	error = gfs2_trans_begin(sdp, RES_RG_BIT + RES_DINODE + RES_STATFS +
				 RES_QUOTA, 1);
	if (error)
		goto out_gunlock;

	gfs2_free_meta(ip, ip->i_eattr, 1);

	ip->i_eattr = 0;
	gfs2_add_inode_blocks(&ip->i_inode, -1);

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (!error) {
		gfs2_trans_add_meta(ip->i_gl, dibh);
		gfs2_dinode_out(ip, dibh->b_data);
		brelse(dibh);
	}

	gfs2_trans_end(sdp);

out_gunlock:
	gfs2_glock_dq_uninit(&gh);
	return error;
}

/**
 * gfs2_ea_dealloc - deallocate the extended attribute fork
 * @ip: the inode
 *
 * Returns: errno
 */

int gfs2_ea_dealloc(struct gfs2_inode *ip)
{
	int error;

	error = gfs2_rindex_update(GFS2_SB(&ip->i_inode));
	if (error)
		return error;

	error = gfs2_quota_hold(ip, NO_UID_QUOTA_CHANGE, NO_GID_QUOTA_CHANGE);
	if (error)
		return error;

	error = ea_foreach(ip, ea_dealloc_unstuffed, NULL);
	if (error)
		goto out_quota;

	if (ip->i_diskflags & GFS2_DIF_EA_INDIRECT) {
		error = ea_dealloc_indirect(ip);
		if (error)
			goto out_quota;
	}

	error = ea_dealloc_block(ip);

out_quota:
	gfs2_quota_unhold(ip);
	return error;
}

static const struct xattr_handler gfs2_xattr_user_handler = {
	.prefix = XATTR_USER_PREFIX,
	.flags  = GFS2_EATYPE_USR,
	.get    = gfs2_xattr_get,
	.set    = gfs2_xattr_set,
};

static const struct xattr_handler gfs2_xattr_security_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.flags  = GFS2_EATYPE_SECURITY,
	.get    = gfs2_xattr_get,
	.set    = gfs2_xattr_set,
};

const struct xattr_handler *gfs2_xattr_handlers[] = {
	&gfs2_xattr_user_handler,
	&gfs2_xattr_security_handler,
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
	NULL,
};
/************************************************************/
/* ../linux-3.17/fs/gfs2/glock.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/buffer_head.h>
#include <linux/delay.h>
// #include <linux/sort.h>
#include <linux/jhash.h>
#include <linux/kallsyms.h>
// #include <linux/gfs2_ondisk.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/module.h>
// #include <asm/uaccess.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/rcupdate.h>
#include <linux/rculist_bl.h>
#include <linux/bit_spinlock.h>
#include <linux/percpu.h>
#include <linux/list_sort.h>
#include <linux/lockref.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "glock.h"
#include "glops.h"
// #include "inode.h"
#include "lops.h"
// #include "meta_io.h"
// #include "quota.h"
// #include "super.h"
// #include "util.h"
// #include "bmap.h"
#define CREATE_TRACE_POINTS
// #include "trace_gfs2.h"

struct gfs2_glock_iter {
	int hash;			/* hash bucket index           */
	unsigned nhash;			/* Index within current bucket */
	struct gfs2_sbd *sdp;		/* incore superblock           */
	struct gfs2_glock *gl;		/* current glock struct        */
	loff_t last_pos;		/* last position               */
};

typedef void (*glock_examiner) (struct gfs2_glock * gl);

static void do_xmote(struct gfs2_glock *gl, struct gfs2_holder *gh, unsigned int target);

static struct dentry *gfs2_root;
static struct workqueue_struct *glock_workqueue;
struct workqueue_struct *gfs2_delete_workqueue;
static LIST_HEAD(lru_list);
static atomic_t lru_count = ATOMIC_INIT(0);
static DEFINE_SPINLOCK(lru_lock);

#define GFS2_GL_HASH_SHIFT      15
#define GFS2_GL_HASH_SIZE       (1 << GFS2_GL_HASH_SHIFT)
#define GFS2_GL_HASH_MASK       (GFS2_GL_HASH_SIZE - 1)

static struct hlist_bl_head gl_hash_table[GFS2_GL_HASH_SIZE];
static struct dentry *gfs2_root;

/**
 * gl_hash() - Turn glock number into hash bucket number
 * @lock: The glock number
 *
 * Returns: The number of the corresponding hash bucket
 */

static unsigned int gl_hash(const struct gfs2_sbd *sdp,
			    const struct lm_lockname *name)
{
	unsigned int h;

	h = jhash(&name->ln_number, sizeof(u64), 0);
	h = jhash(&name->ln_type, sizeof(unsigned int), h);
	h = jhash(&sdp, sizeof(struct gfs2_sbd *), h);
	h &= GFS2_GL_HASH_MASK;

	return h;
}

static inline void spin_lock_bucket_glock_c(unsigned int hash)
{
	hlist_bl_lock(&gl_hash_table[hash]);
}

static inline void spin_unlock_bucket_glock_c(unsigned int hash)
{
	hlist_bl_unlock(&gl_hash_table[hash]);
}

static void gfs2_glock_dealloc(struct rcu_head *rcu)
{
	struct gfs2_glock *gl = container_of(rcu, struct gfs2_glock, gl_rcu);

	if (gl->gl_ops->go_flags & GLOF_ASPACE) {
		kmem_cache_free(gfs2_glock_aspace_cachep, gl);
	} else {
		kfree(gl->gl_lksb.sb_lvbptr);
		kmem_cache_free(gfs2_glock_cachep, gl);
	}
}

void gfs2_glock_free(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;

	call_rcu(&gl->gl_rcu, gfs2_glock_dealloc);
	if (atomic_dec_and_test(&sdp->sd_glock_disposal))
		wake_up(&sdp->sd_glock_wait);
}

/**
 * gfs2_glock_hold() - increment reference count on glock
 * @gl: The glock to hold
 *
 */

static void gfs2_glock_hold(struct gfs2_glock *gl)
{
	GLOCK_BUG_ON(gl, __lockref_is_dead(&gl->gl_lockref));
	lockref_get(&gl->gl_lockref);
}

/**
 * demote_ok - Check to see if it's ok to unlock a glock
 * @gl: the glock
 *
 * Returns: 1 if it's ok
 */

static int demote_ok(const struct gfs2_glock *gl)
{
	const struct gfs2_glock_operations *glops = gl->gl_ops;

	if (gl->gl_state == LM_ST_UNLOCKED)
		return 0;
	if (!list_empty(&gl->gl_holders))
		return 0;
	if (glops->go_demote_ok)
		return glops->go_demote_ok(gl);
	return 1;
}


void gfs2_glock_add_to_lru(struct gfs2_glock *gl)
{
	spin_lock(&lru_lock);

	if (!list_empty(&gl->gl_lru))
		list_del_init(&gl->gl_lru);
	else
		atomic_inc(&lru_count);

	list_add_tail(&gl->gl_lru, &lru_list);
	set_bit(GLF_LRU, &gl->gl_flags);
	spin_unlock(&lru_lock);
}

static void __gfs2_glock_remove_from_lru(struct gfs2_glock *gl)
{
	if (!list_empty(&gl->gl_lru)) {
		list_del_init(&gl->gl_lru);
		atomic_dec(&lru_count);
		clear_bit(GLF_LRU, &gl->gl_flags);
	}
}

static void gfs2_glock_remove_from_lru(struct gfs2_glock *gl)
{
	spin_lock(&lru_lock);
	__gfs2_glock_remove_from_lru(gl);
	spin_unlock(&lru_lock);
}

/**
 * gfs2_glock_put() - Decrement reference count on glock
 * @gl: The glock to put
 *
 */

void gfs2_glock_put(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct address_space *mapping = gfs2_glock2aspace(gl);

	if (lockref_put_or_lock(&gl->gl_lockref))
		return;

	lockref_mark_dead(&gl->gl_lockref);

	spin_lock(&lru_lock);
	__gfs2_glock_remove_from_lru(gl);
	spin_unlock(&lru_lock);
	spin_unlock(&gl->gl_lockref.lock);
	spin_lock_bucket_glock_c(gl->gl_hash);
	hlist_bl_del_rcu(&gl->gl_list);
	spin_unlock_bucket_glock_c(gl->gl_hash);
	GLOCK_BUG_ON(gl, !list_empty(&gl->gl_holders));
	GLOCK_BUG_ON(gl, mapping && mapping->nrpages);
	trace_gfs2_glock_put(gl);
	sdp->sd_lockstruct.ls_ops->lm_put_lock(gl);
}

/**
 * search_bucket() - Find struct gfs2_glock by lock number
 * @bucket: the bucket to search
 * @name: The lock name
 *
 * Returns: NULL, or the struct gfs2_glock with the requested number
 */

static struct gfs2_glock *search_bucket(unsigned int hash,
					const struct gfs2_sbd *sdp,
					const struct lm_lockname *name)
{
	struct gfs2_glock *gl;
	struct hlist_bl_node *h;

	hlist_bl_for_each_entry_rcu(gl, h, &gl_hash_table[hash], gl_list) {
		if (!lm_name_equal(&gl->gl_name, name))
			continue;
		if (gl->gl_sbd != sdp)
			continue;
		if (lockref_get_not_dead(&gl->gl_lockref))
			return gl;
	}

	return NULL;
}

/**
 * may_grant - check if its ok to grant a new lock
 * @gl: The glock
 * @gh: The lock request which we wish to grant
 *
 * Returns: true if its ok to grant the lock
 */

static inline int may_grant(const struct gfs2_glock *gl, const struct gfs2_holder *gh)
{
	const struct gfs2_holder *gh_head = list_entry(gl->gl_holders.next, const struct gfs2_holder, gh_list);
	if ((gh->gh_state == LM_ST_EXCLUSIVE ||
	     gh_head->gh_state == LM_ST_EXCLUSIVE) && gh != gh_head)
		return 0;
	if (gl->gl_state == gh->gh_state)
		return 1;
	if (gh->gh_flags & GL_EXACT)
		return 0;
	if (gl->gl_state == LM_ST_EXCLUSIVE) {
		if (gh->gh_state == LM_ST_SHARED && gh_head->gh_state == LM_ST_SHARED)
			return 1;
		if (gh->gh_state == LM_ST_DEFERRED && gh_head->gh_state == LM_ST_DEFERRED)
			return 1;
	}
	if (gl->gl_state != LM_ST_UNLOCKED && (gh->gh_flags & LM_FLAG_ANY))
		return 1;
	return 0;
}

static void gfs2_holder_wake(struct gfs2_holder *gh)
{
	clear_bit(HIF_WAIT, &gh->gh_iflags);
	smp_mb__after_atomic();
	wake_up_bit(&gh->gh_iflags, HIF_WAIT);
}

/**
 * do_error - Something unexpected has happened during a lock request
 *
 */

static inline void do_error(struct gfs2_glock *gl, const int ret)
{
	struct gfs2_holder *gh, *tmp;

	list_for_each_entry_safe(gh, tmp, &gl->gl_holders, gh_list) {
		if (test_bit(HIF_HOLDER, &gh->gh_iflags))
			continue;
		if (ret & LM_OUT_ERROR)
			gh->gh_error = -EIO;
		else if (gh->gh_flags & (LM_FLAG_TRY | LM_FLAG_TRY_1CB))
			gh->gh_error = GLR_TRYFAILED;
		else
			continue;
		list_del_init(&gh->gh_list);
		trace_gfs2_glock_queue(gh, 0);
		gfs2_holder_wake(gh);
	}
}

/**
 * do_promote - promote as many requests as possible on the current queue
 * @gl: The glock
 *
 * Returns: 1 if there is a blocked holder at the head of the list, or 2
 *          if a type specific operation is underway.
 */

static int do_promote(struct gfs2_glock *gl)
__releases(&gl->gl_spin)
__acquires(&gl->gl_spin)
{
	const struct gfs2_glock_operations *glops = gl->gl_ops;
	struct gfs2_holder *gh, *tmp;
	int ret;

restart:
	list_for_each_entry_safe(gh, tmp, &gl->gl_holders, gh_list) {
		if (test_bit(HIF_HOLDER, &gh->gh_iflags))
			continue;
		if (may_grant(gl, gh)) {
			if (gh->gh_list.prev == &gl->gl_holders &&
			    glops->go_lock) {
				spin_unlock(&gl->gl_spin);
				/* FIXME: eliminate this eventually */
				ret = glops->go_lock(gh);
				spin_lock(&gl->gl_spin);
				if (ret) {
					if (ret == 1)
						return 2;
					gh->gh_error = ret;
					list_del_init(&gh->gh_list);
					trace_gfs2_glock_queue(gh, 0);
					gfs2_holder_wake(gh);
					goto restart;
				}
				set_bit(HIF_HOLDER, &gh->gh_iflags);
				trace_gfs2_promote(gh, 1);
				gfs2_holder_wake(gh);
				goto restart;
			}
			set_bit(HIF_HOLDER, &gh->gh_iflags);
			trace_gfs2_promote(gh, 0);
			gfs2_holder_wake(gh);
			continue;
		}
		if (gh->gh_list.prev == &gl->gl_holders)
			return 1;
		do_error(gl, 0);
		break;
	}
	return 0;
}

/**
 * find_first_waiter - find the first gh that's waiting for the glock
 * @gl: the glock
 */

static inline struct gfs2_holder *find_first_waiter(const struct gfs2_glock *gl)
{
	struct gfs2_holder *gh;

	list_for_each_entry(gh, &gl->gl_holders, gh_list) {
		if (!test_bit(HIF_HOLDER, &gh->gh_iflags))
			return gh;
	}
	return NULL;
}

/**
 * state_change - record that the glock is now in a different state
 * @gl: the glock
 * @new_state the new state
 *
 */

static void state_change(struct gfs2_glock *gl, unsigned int new_state)
{
	int held1, held2;

	held1 = (gl->gl_state != LM_ST_UNLOCKED);
	held2 = (new_state != LM_ST_UNLOCKED);

	if (held1 != held2) {
		GLOCK_BUG_ON(gl, __lockref_is_dead(&gl->gl_lockref));
		if (held2)
			gl->gl_lockref.count++;
		else
			gl->gl_lockref.count--;
	}
	if (held1 && held2 && list_empty(&gl->gl_holders))
		clear_bit(GLF_QUEUED, &gl->gl_flags);

	if (new_state != gl->gl_target)
		/* shorten our minimum hold time */
		gl->gl_hold_time = max(gl->gl_hold_time - GL_GLOCK_HOLD_DECR,
				       GL_GLOCK_MIN_HOLD);
	gl->gl_state = new_state;
	gl->gl_tchange = jiffies;
}

static void gfs2_demote_wake(struct gfs2_glock *gl)
{
	gl->gl_demote_state = LM_ST_EXCLUSIVE;
	clear_bit(GLF_DEMOTE, &gl->gl_flags);
	smp_mb__after_atomic();
	wake_up_bit(&gl->gl_flags, GLF_DEMOTE);
}

/**
 * finish_xmote - The DLM has replied to one of our lock requests
 * @gl: The glock
 * @ret: The status from the DLM
 *
 */

static void finish_xmote(struct gfs2_glock *gl, unsigned int ret)
{
	const struct gfs2_glock_operations *glops = gl->gl_ops;
	struct gfs2_holder *gh;
	unsigned state = ret & LM_OUT_ST_MASK;
	int rv;

	spin_lock(&gl->gl_spin);
	trace_gfs2_glock_state_change(gl, state);
	state_change(gl, state);
	gh = find_first_waiter(gl);

	/* Demote to UN request arrived during demote to SH or DF */
	if (test_bit(GLF_DEMOTE_IN_PROGRESS, &gl->gl_flags) &&
	    state != LM_ST_UNLOCKED && gl->gl_demote_state == LM_ST_UNLOCKED)
		gl->gl_target = LM_ST_UNLOCKED;

	/* Check for state != intended state */
	if (unlikely(state != gl->gl_target)) {
		if (gh && !test_bit(GLF_DEMOTE_IN_PROGRESS, &gl->gl_flags)) {
			/* move to back of queue and try next entry */
			if (ret & LM_OUT_CANCELED) {
				if ((gh->gh_flags & LM_FLAG_PRIORITY) == 0)
					list_move_tail(&gh->gh_list, &gl->gl_holders);
				gh = find_first_waiter(gl);
				gl->gl_target = gh->gh_state;
				goto retry;
			}
			/* Some error or failed "try lock" - report it */
			if ((ret & LM_OUT_ERROR) ||
			    (gh->gh_flags & (LM_FLAG_TRY | LM_FLAG_TRY_1CB))) {
				gl->gl_target = gl->gl_state;
				do_error(gl, ret);
				goto out;
			}
		}
		switch(state) {
		/* Unlocked due to conversion deadlock, try again */
		case LM_ST_UNLOCKED:
retry:
			do_xmote(gl, gh, gl->gl_target);
			break;
		/* Conversion fails, unlock and try again */
		case LM_ST_SHARED:
		case LM_ST_DEFERRED:
			do_xmote(gl, gh, LM_ST_UNLOCKED);
			break;
		default: /* Everything else */
			pr_err("wanted %u got %u\n", gl->gl_target, state);
			GLOCK_BUG_ON(gl, 1);
		}
		spin_unlock(&gl->gl_spin);
		return;
	}

	/* Fast path - we got what we asked for */
	if (test_and_clear_bit(GLF_DEMOTE_IN_PROGRESS, &gl->gl_flags))
		gfs2_demote_wake(gl);
	if (state != LM_ST_UNLOCKED) {
		if (glops->go_xmote_bh) {
			spin_unlock(&gl->gl_spin);
			rv = glops->go_xmote_bh(gl, gh);
			spin_lock(&gl->gl_spin);
			if (rv) {
				do_error(gl, rv);
				goto out;
			}
		}
		rv = do_promote(gl);
		if (rv == 2)
			goto out_locked;
	}
out:
	clear_bit(GLF_LOCK, &gl->gl_flags);
out_locked:
	spin_unlock(&gl->gl_spin);
}

/**
 * do_xmote - Calls the DLM to change the state of a lock
 * @gl: The lock state
 * @gh: The holder (only for promotes)
 * @target: The target lock state
 *
 */

static void do_xmote(struct gfs2_glock *gl, struct gfs2_holder *gh, unsigned int target)
__releases(&gl->gl_spin)
__acquires(&gl->gl_spin)
{
	const struct gfs2_glock_operations *glops = gl->gl_ops;
	struct gfs2_sbd *sdp = gl->gl_sbd;
	unsigned int lck_flags = gh ? gh->gh_flags : 0;
	int ret;

	lck_flags &= (LM_FLAG_TRY | LM_FLAG_TRY_1CB | LM_FLAG_NOEXP |
		      LM_FLAG_PRIORITY);
	GLOCK_BUG_ON(gl, gl->gl_state == target);
	GLOCK_BUG_ON(gl, gl->gl_state == gl->gl_target);
	if ((target == LM_ST_UNLOCKED || target == LM_ST_DEFERRED) &&
	    glops->go_inval) {
		set_bit(GLF_INVALIDATE_IN_PROGRESS, &gl->gl_flags);
		do_error(gl, 0); /* Fail queued try locks */
	}
	gl->gl_req = target;
	set_bit(GLF_BLOCKING, &gl->gl_flags);
	if ((gl->gl_req == LM_ST_UNLOCKED) ||
	    (gl->gl_state == LM_ST_EXCLUSIVE) ||
	    (lck_flags & (LM_FLAG_TRY|LM_FLAG_TRY_1CB)))
		clear_bit(GLF_BLOCKING, &gl->gl_flags);
	spin_unlock(&gl->gl_spin);
	if (glops->go_sync)
		glops->go_sync(gl);
	if (test_bit(GLF_INVALIDATE_IN_PROGRESS, &gl->gl_flags))
		glops->go_inval(gl, target == LM_ST_DEFERRED ? 0 : DIO_METADATA);
	clear_bit(GLF_INVALIDATE_IN_PROGRESS, &gl->gl_flags);

	gfs2_glock_hold(gl);
	if (sdp->sd_lockstruct.ls_ops->lm_lock)	{
		/* lock_dlm */
		ret = sdp->sd_lockstruct.ls_ops->lm_lock(gl, target, lck_flags);
		if (ret) {
			pr_err("lm_lock ret %d\n", ret);
			GLOCK_BUG_ON(gl, 1);
		}
	} else { /* lock_nolock */
		finish_xmote(gl, target);
		if (queue_delayed_work(glock_workqueue, &gl->gl_work, 0) == 0)
			gfs2_glock_put(gl);
	}

	spin_lock(&gl->gl_spin);
}

/**
 * find_first_holder - find the first "holder" gh
 * @gl: the glock
 */

static inline struct gfs2_holder *find_first_holder(const struct gfs2_glock *gl)
{
	struct gfs2_holder *gh;

	if (!list_empty(&gl->gl_holders)) {
		gh = list_entry(gl->gl_holders.next, struct gfs2_holder, gh_list);
		if (test_bit(HIF_HOLDER, &gh->gh_iflags))
			return gh;
	}
	return NULL;
}

/**
 * run_queue - do all outstanding tasks related to a glock
 * @gl: The glock in question
 * @nonblock: True if we must not block in run_queue
 *
 */

static void run_queue(struct gfs2_glock *gl, const int nonblock)
__releases(&gl->gl_spin)
__acquires(&gl->gl_spin)
{
	struct gfs2_holder *gh = NULL;
	int ret;

	if (test_and_set_bit(GLF_LOCK, &gl->gl_flags))
		return;

	GLOCK_BUG_ON(gl, test_bit(GLF_DEMOTE_IN_PROGRESS, &gl->gl_flags));

	if (test_bit(GLF_DEMOTE, &gl->gl_flags) &&
	    gl->gl_demote_state != gl->gl_state) {
		if (find_first_holder(gl))
			goto out_unlock;
		if (nonblock)
			goto out_sched;
		set_bit(GLF_DEMOTE_IN_PROGRESS, &gl->gl_flags);
		GLOCK_BUG_ON(gl, gl->gl_demote_state == LM_ST_EXCLUSIVE);
		gl->gl_target = gl->gl_demote_state;
	} else {
		if (test_bit(GLF_DEMOTE, &gl->gl_flags))
			gfs2_demote_wake(gl);
		ret = do_promote(gl);
		if (ret == 0)
			goto out_unlock;
		if (ret == 2)
			goto out;
		gh = find_first_waiter(gl);
		gl->gl_target = gh->gh_state;
		if (!(gh->gh_flags & (LM_FLAG_TRY | LM_FLAG_TRY_1CB)))
			do_error(gl, 0); /* Fail queued try locks */
	}
	do_xmote(gl, gh, gl->gl_target);
out:
	return;

out_sched:
	clear_bit(GLF_LOCK, &gl->gl_flags);
	smp_mb__after_atomic();
	gl->gl_lockref.count++;
	if (queue_delayed_work(glock_workqueue, &gl->gl_work, 0) == 0)
		gl->gl_lockref.count--;
	return;

out_unlock:
	clear_bit(GLF_LOCK, &gl->gl_flags);
	smp_mb__after_atomic();
	return;
}

static void delete_work_func(struct work_struct *work)
{
	struct gfs2_glock *gl = container_of(work, struct gfs2_glock, gl_delete);
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_inode *ip;
	struct inode *inode;
	u64 no_addr = gl->gl_name.ln_number;

	ip = gl->gl_object;
	/* Note: Unsafe to dereference ip as we don't hold right refs/locks */

	if (ip)
		inode = gfs2_ilookup(sdp->sd_vfs, no_addr, 1);
	else
		inode = gfs2_lookup_by_inum(sdp, no_addr, NULL, GFS2_BLKST_UNLINKED);
	if (inode && !IS_ERR(inode)) {
		d_prune_aliases(inode);
		iput(inode);
	}
	gfs2_glock_put(gl);
}

static void glock_work_func(struct work_struct *work)
{
	unsigned long delay = 0;
	struct gfs2_glock *gl = container_of(work, struct gfs2_glock, gl_work.work);
	int drop_ref = 0;

	if (test_and_clear_bit(GLF_REPLY_PENDING, &gl->gl_flags)) {
		finish_xmote(gl, gl->gl_reply);
		drop_ref = 1;
	}
	spin_lock(&gl->gl_spin);
	if (test_bit(GLF_PENDING_DEMOTE, &gl->gl_flags) &&
	    gl->gl_state != LM_ST_UNLOCKED &&
	    gl->gl_demote_state != LM_ST_EXCLUSIVE) {
		unsigned long holdtime, now = jiffies;

		holdtime = gl->gl_tchange + gl->gl_hold_time;
		if (time_before(now, holdtime))
			delay = holdtime - now;

		if (!delay) {
			clear_bit(GLF_PENDING_DEMOTE, &gl->gl_flags);
			set_bit(GLF_DEMOTE, &gl->gl_flags);
		}
	}
	run_queue(gl, 0);
	spin_unlock(&gl->gl_spin);
	if (!delay)
		gfs2_glock_put(gl);
	else {
		if (gl->gl_name.ln_type != LM_TYPE_INODE)
			delay = 0;
		if (queue_delayed_work(glock_workqueue, &gl->gl_work, delay) == 0)
			gfs2_glock_put(gl);
	}
	if (drop_ref)
		gfs2_glock_put(gl);
}

/**
 * gfs2_glock_get() - Get a glock, or create one if one doesn't exist
 * @sdp: The GFS2 superblock
 * @number: the lock number
 * @glops: The glock_operations to use
 * @create: If 0, don't create the glock if it doesn't exist
 * @glp: the glock is returned here
 *
 * This does not lock a glock, just finds/creates structures for one.
 *
 * Returns: errno
 */

int gfs2_glock_get(struct gfs2_sbd *sdp, u64 number,
		   const struct gfs2_glock_operations *glops, int create,
		   struct gfs2_glock **glp)
{
	struct super_block *s = sdp->sd_vfs;
	struct lm_lockname name = { .ln_number = number, .ln_type = glops->go_type };
	struct gfs2_glock *gl, *tmp;
	unsigned int hash = gl_hash(sdp, &name);
	struct address_space *mapping;
	struct kmem_cache *cachep;

	rcu_read_lock();
	gl = search_bucket(hash, sdp, &name);
	rcu_read_unlock();

	*glp = gl;
	if (gl)
		return 0;
	if (!create)
		return -ENOENT;

	if (glops->go_flags & GLOF_ASPACE)
		cachep = gfs2_glock_aspace_cachep;
	else
		cachep = gfs2_glock_cachep;
	gl = kmem_cache_alloc(cachep, GFP_NOFS);
	if (!gl)
		return -ENOMEM;

	memset(&gl->gl_lksb, 0, sizeof(struct dlm_lksb));

	if (glops->go_flags & GLOF_LVB) {
		gl->gl_lksb.sb_lvbptr = kzalloc(GFS2_MIN_LVB_SIZE, GFP_NOFS);
		if (!gl->gl_lksb.sb_lvbptr) {
			kmem_cache_free(cachep, gl);
			return -ENOMEM;
		}
	}

	atomic_inc(&sdp->sd_glock_disposal);
	gl->gl_sbd = sdp;
	gl->gl_flags = 0;
	gl->gl_name = name;
	gl->gl_lockref.count = 1;
	gl->gl_state = LM_ST_UNLOCKED;
	gl->gl_target = LM_ST_UNLOCKED;
	gl->gl_demote_state = LM_ST_EXCLUSIVE;
	gl->gl_hash = hash;
	gl->gl_ops = glops;
	gl->gl_dstamp = ktime_set(0, 0);
	preempt_disable();
	/* We use the global stats to estimate the initial per-glock stats */
	gl->gl_stats = this_cpu_ptr(sdp->sd_lkstats)->lkstats[glops->go_type];
	preempt_enable();
	gl->gl_stats.stats[GFS2_LKS_DCOUNT] = 0;
	gl->gl_stats.stats[GFS2_LKS_QCOUNT] = 0;
	gl->gl_tchange = jiffies;
	gl->gl_object = NULL;
	gl->gl_hold_time = GL_GLOCK_DFT_HOLD;
	INIT_DELAYED_WORK(&gl->gl_work, glock_work_func);
	INIT_WORK(&gl->gl_delete, delete_work_func);

	mapping = gfs2_glock2aspace(gl);
	if (mapping) {
                mapping->a_ops = &gfs2_meta_aops;
		mapping->host = s->s_bdev->bd_inode;
		mapping->flags = 0;
		mapping_set_gfp_mask(mapping, GFP_NOFS);
		mapping->private_data = NULL;
		mapping->backing_dev_info = s->s_bdi;
		mapping->writeback_index = 0;
	}

	spin_lock_bucket_glock_c(hash);
	tmp = search_bucket(hash, sdp, &name);
	if (tmp) {
		spin_unlock_bucket_glock_c(hash);
		kfree(gl->gl_lksb.sb_lvbptr);
		kmem_cache_free(cachep, gl);
		atomic_dec(&sdp->sd_glock_disposal);
		gl = tmp;
	} else {
		hlist_bl_add_head_rcu(&gl->gl_list, &gl_hash_table[hash]);
		spin_unlock_bucket_glock_c(hash);
	}

	*glp = gl;

	return 0;
}

/**
 * gfs2_holder_init - initialize a struct gfs2_holder in the default way
 * @gl: the glock
 * @state: the state we're requesting
 * @flags: the modifier flags
 * @gh: the holder structure
 *
 */

void gfs2_holder_init(struct gfs2_glock *gl, unsigned int state, unsigned flags,
		      struct gfs2_holder *gh)
{
	INIT_LIST_HEAD(&gh->gh_list);
	gh->gh_gl = gl;
	gh->gh_ip = (unsigned long)__builtin_return_address(0);
	gh->gh_owner_pid = get_pid(task_pid(current));
	gh->gh_state = state;
	gh->gh_flags = flags;
	gh->gh_error = 0;
	gh->gh_iflags = 0;
	gfs2_glock_hold(gl);
}

/**
 * gfs2_holder_reinit - reinitialize a struct gfs2_holder so we can requeue it
 * @state: the state we're requesting
 * @flags: the modifier flags
 * @gh: the holder structure
 *
 * Don't mess with the glock.
 *
 */

void gfs2_holder_reinit(unsigned int state, unsigned flags, struct gfs2_holder *gh)
{
	gh->gh_state = state;
	gh->gh_flags = flags;
	gh->gh_iflags = 0;
	gh->gh_ip = (unsigned long)__builtin_return_address(0);
	if (gh->gh_owner_pid)
		put_pid(gh->gh_owner_pid);
	gh->gh_owner_pid = get_pid(task_pid(current));
}

/**
 * gfs2_holder_uninit - uninitialize a holder structure (drop glock reference)
 * @gh: the holder structure
 *
 */

void gfs2_holder_uninit(struct gfs2_holder *gh)
{
	put_pid(gh->gh_owner_pid);
	gfs2_glock_put(gh->gh_gl);
	gh->gh_gl = NULL;
	gh->gh_ip = 0;
}

/**
 * gfs2_glock_wait - wait on a glock acquisition
 * @gh: the glock holder
 *
 * Returns: 0 on success
 */

int gfs2_glock_wait(struct gfs2_holder *gh)
{
	unsigned long time1 = jiffies;

	might_sleep();
	wait_on_bit(&gh->gh_iflags, HIF_WAIT, TASK_UNINTERRUPTIBLE);
	if (time_after(jiffies, time1 + HZ)) /* have we waited > a second? */
		/* Lengthen the minimum hold time. */
		gh->gh_gl->gl_hold_time = min(gh->gh_gl->gl_hold_time +
					      GL_GLOCK_HOLD_INCR,
					      GL_GLOCK_MAX_HOLD);
	return gh->gh_error;
}

/**
 * handle_callback - process a demote request
 * @gl: the glock
 * @state: the state the caller wants us to change to
 *
 * There are only two requests that we are going to see in actual
 * practise: LM_ST_SHARED and LM_ST_UNLOCKED
 */

static void handle_callback(struct gfs2_glock *gl, unsigned int state,
			    unsigned long delay, bool remote)
{
	int bit = delay ? GLF_PENDING_DEMOTE : GLF_DEMOTE;

	set_bit(bit, &gl->gl_flags);
	if (gl->gl_demote_state == LM_ST_EXCLUSIVE) {
		gl->gl_demote_state = state;
		gl->gl_demote_time = jiffies;
	} else if (gl->gl_demote_state != LM_ST_UNLOCKED &&
			gl->gl_demote_state != state) {
		gl->gl_demote_state = LM_ST_UNLOCKED;
	}
	if (gl->gl_ops->go_callback)
		gl->gl_ops->go_callback(gl, remote);
	trace_gfs2_demote_rq(gl, remote);
}

void gfs2_print_dbg(struct seq_file *seq, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	if (seq) {
		seq_vprintf(seq, fmt, args);
	} else {
		vaf.fmt = fmt;
		vaf.va = &args;

		pr_err("%pV", &vaf);
	}

	va_end(args);
}

/**
 * add_to_queue - Add a holder to the wait queue (but look for recursion)
 * @gh: the holder structure to add
 *
 * Eventually we should move the recursive locking trap to a
 * debugging option or something like that. This is the fast
 * path and needs to have the minimum number of distractions.
 *
 */

static inline void add_to_queue(struct gfs2_holder *gh)
__releases(&gl->gl_spin)
__acquires(&gl->gl_spin)
{
	struct gfs2_glock *gl = gh->gh_gl;
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct list_head *insert_pt = NULL;
	struct gfs2_holder *gh2;
	int try_futile = 0;

	BUG_ON(gh->gh_owner_pid == NULL);
	if (test_and_set_bit(HIF_WAIT, &gh->gh_iflags))
		BUG();

	if (gh->gh_flags & (LM_FLAG_TRY | LM_FLAG_TRY_1CB)) {
		if (test_bit(GLF_LOCK, &gl->gl_flags))
			try_futile = !may_grant(gl, gh);
		if (test_bit(GLF_INVALIDATE_IN_PROGRESS, &gl->gl_flags))
			goto fail;
	}

	list_for_each_entry(gh2, &gl->gl_holders, gh_list) {
		if (unlikely(gh2->gh_owner_pid == gh->gh_owner_pid &&
		    (gh->gh_gl->gl_ops->go_type != LM_TYPE_FLOCK)))
			goto trap_recursive;
		if (try_futile &&
		    !(gh2->gh_flags & (LM_FLAG_TRY | LM_FLAG_TRY_1CB))) {
fail:
			gh->gh_error = GLR_TRYFAILED;
			gfs2_holder_wake(gh);
			return;
		}
		if (test_bit(HIF_HOLDER, &gh2->gh_iflags))
			continue;
		if (unlikely((gh->gh_flags & LM_FLAG_PRIORITY) && !insert_pt))
			insert_pt = &gh2->gh_list;
	}
	set_bit(GLF_QUEUED, &gl->gl_flags);
	trace_gfs2_glock_queue(gh, 1);
	gfs2_glstats_inc(gl, GFS2_LKS_QCOUNT);
	gfs2_sbstats_inc(gl, GFS2_LKS_QCOUNT);
	if (likely(insert_pt == NULL)) {
		list_add_tail(&gh->gh_list, &gl->gl_holders);
		if (unlikely(gh->gh_flags & LM_FLAG_PRIORITY))
			goto do_cancel;
		return;
	}
	list_add_tail(&gh->gh_list, insert_pt);
do_cancel:
	gh = list_entry(gl->gl_holders.next, struct gfs2_holder, gh_list);
	if (!(gh->gh_flags & LM_FLAG_PRIORITY)) {
		spin_unlock(&gl->gl_spin);
		if (sdp->sd_lockstruct.ls_ops->lm_cancel)
			sdp->sd_lockstruct.ls_ops->lm_cancel(gl);
		spin_lock(&gl->gl_spin);
	}
	return;

trap_recursive:
	pr_err("original: %pSR\n", (void *)gh2->gh_ip);
	pr_err("pid: %d\n", pid_nr(gh2->gh_owner_pid));
	pr_err("lock type: %d req lock state : %d\n",
	       gh2->gh_gl->gl_name.ln_type, gh2->gh_state);
	pr_err("new: %pSR\n", (void *)gh->gh_ip);
	pr_err("pid: %d\n", pid_nr(gh->gh_owner_pid));
	pr_err("lock type: %d req lock state : %d\n",
	       gh->gh_gl->gl_name.ln_type, gh->gh_state);
	gfs2_dump_glock(NULL, gl);
	BUG();
}

/**
 * gfs2_glock_nq - enqueue a struct gfs2_holder onto a glock (acquire a glock)
 * @gh: the holder structure
 *
 * if (gh->gh_flags & GL_ASYNC), this never returns an error
 *
 * Returns: 0, GLR_TRYFAILED, or errno on failure
 */

int gfs2_glock_nq(struct gfs2_holder *gh)
{
	struct gfs2_glock *gl = gh->gh_gl;
	struct gfs2_sbd *sdp = gl->gl_sbd;
	int error = 0;

	if (unlikely(test_bit(SDF_SHUTDOWN, &sdp->sd_flags)))
		return -EIO;

	if (test_bit(GLF_LRU, &gl->gl_flags))
		gfs2_glock_remove_from_lru(gl);

	spin_lock(&gl->gl_spin);
	add_to_queue(gh);
	if (unlikely((LM_FLAG_NOEXP & gh->gh_flags) &&
		     test_and_clear_bit(GLF_FROZEN, &gl->gl_flags))) {
		set_bit(GLF_REPLY_PENDING, &gl->gl_flags);
		gl->gl_lockref.count++;
		if (queue_delayed_work(glock_workqueue, &gl->gl_work, 0) == 0)
			gl->gl_lockref.count--;
	}
	run_queue(gl, 1);
	spin_unlock(&gl->gl_spin);

	if (!(gh->gh_flags & GL_ASYNC))
		error = gfs2_glock_wait(gh);

	return error;
}

/**
 * gfs2_glock_poll - poll to see if an async request has been completed
 * @gh: the holder
 *
 * Returns: 1 if the request is ready to be gfs2_glock_wait()ed on
 */

int gfs2_glock_poll(struct gfs2_holder *gh)
{
	return test_bit(HIF_WAIT, &gh->gh_iflags) ? 0 : 1;
}

/**
 * gfs2_glock_dq - dequeue a struct gfs2_holder from a glock (release a glock)
 * @gh: the glock holder
 *
 */

void gfs2_glock_dq(struct gfs2_holder *gh)
{
	struct gfs2_glock *gl = gh->gh_gl;
	const struct gfs2_glock_operations *glops = gl->gl_ops;
	unsigned delay = 0;
	int fast_path = 0;

	spin_lock(&gl->gl_spin);
	if (gh->gh_flags & GL_NOCACHE)
		handle_callback(gl, LM_ST_UNLOCKED, 0, false);

	list_del_init(&gh->gh_list);
	if (find_first_holder(gl) == NULL) {
		if (glops->go_unlock) {
			GLOCK_BUG_ON(gl, test_and_set_bit(GLF_LOCK, &gl->gl_flags));
			spin_unlock(&gl->gl_spin);
			glops->go_unlock(gh);
			spin_lock(&gl->gl_spin);
			clear_bit(GLF_LOCK, &gl->gl_flags);
		}
		if (list_empty(&gl->gl_holders) &&
		    !test_bit(GLF_PENDING_DEMOTE, &gl->gl_flags) &&
		    !test_bit(GLF_DEMOTE, &gl->gl_flags))
			fast_path = 1;
	}
	if (!test_bit(GLF_LFLUSH, &gl->gl_flags) && demote_ok(gl))
		gfs2_glock_add_to_lru(gl);

	trace_gfs2_glock_queue(gh, 0);
	spin_unlock(&gl->gl_spin);
	if (likely(fast_path))
		return;

	gfs2_glock_hold(gl);
	if (test_bit(GLF_PENDING_DEMOTE, &gl->gl_flags) &&
	    !test_bit(GLF_DEMOTE, &gl->gl_flags) &&
	    gl->gl_name.ln_type == LM_TYPE_INODE)
		delay = gl->gl_hold_time;
	if (queue_delayed_work(glock_workqueue, &gl->gl_work, delay) == 0)
		gfs2_glock_put(gl);
}

void gfs2_glock_dq_wait(struct gfs2_holder *gh)
{
	struct gfs2_glock *gl = gh->gh_gl;
	gfs2_glock_dq(gh);
	might_sleep();
	wait_on_bit(&gl->gl_flags, GLF_DEMOTE, TASK_UNINTERRUPTIBLE);
}

/**
 * gfs2_glock_dq_uninit - dequeue a holder from a glock and initialize it
 * @gh: the holder structure
 *
 */

void gfs2_glock_dq_uninit(struct gfs2_holder *gh)
{
	gfs2_glock_dq(gh);
	gfs2_holder_uninit(gh);
}

/**
 * gfs2_glock_nq_num - acquire a glock based on lock number
 * @sdp: the filesystem
 * @number: the lock number
 * @glops: the glock operations for the type of glock
 * @state: the state to acquire the glock in
 * @flags: modifier flags for the acquisition
 * @gh: the struct gfs2_holder
 *
 * Returns: errno
 */

int gfs2_glock_nq_num(struct gfs2_sbd *sdp, u64 number,
		      const struct gfs2_glock_operations *glops,
		      unsigned int state, int flags, struct gfs2_holder *gh)
{
	struct gfs2_glock *gl;
	int error;

	error = gfs2_glock_get(sdp, number, glops, CREATE, &gl);
	if (!error) {
		error = gfs2_glock_nq_init(gl, state, flags, gh);
		gfs2_glock_put(gl);
	}

	return error;
}

/**
 * glock_compare - Compare two struct gfs2_glock structures for sorting
 * @arg_a: the first structure
 * @arg_b: the second structure
 *
 */

static int glock_compare(const void *arg_a, const void *arg_b)
{
	const struct gfs2_holder *gh_a = *(const struct gfs2_holder **)arg_a;
	const struct gfs2_holder *gh_b = *(const struct gfs2_holder **)arg_b;
	const struct lm_lockname *a = &gh_a->gh_gl->gl_name;
	const struct lm_lockname *b = &gh_b->gh_gl->gl_name;

	if (a->ln_number > b->ln_number)
		return 1;
	if (a->ln_number < b->ln_number)
		return -1;
	BUG_ON(gh_a->gh_gl->gl_ops->go_type == gh_b->gh_gl->gl_ops->go_type);
	return 0;
}

/**
 * nq_m_sync - synchonously acquire more than one glock in deadlock free order
 * @num_gh: the number of structures
 * @ghs: an array of struct gfs2_holder structures
 *
 * Returns: 0 on success (all glocks acquired),
 *          errno on failure (no glocks acquired)
 */

static int nq_m_sync(unsigned int num_gh, struct gfs2_holder *ghs,
		     struct gfs2_holder **p)
{
	unsigned int x;
	int error = 0;

	for (x = 0; x < num_gh; x++)
		p[x] = &ghs[x];

	sort(p, num_gh, sizeof(struct gfs2_holder *), glock_compare, NULL);

	for (x = 0; x < num_gh; x++) {
		p[x]->gh_flags &= ~(LM_FLAG_TRY | GL_ASYNC);

		error = gfs2_glock_nq(p[x]);
		if (error) {
			while (x--)
				gfs2_glock_dq(p[x]);
			break;
		}
	}

	return error;
}

/**
 * gfs2_glock_nq_m - acquire multiple glocks
 * @num_gh: the number of structures
 * @ghs: an array of struct gfs2_holder structures
 *
 *
 * Returns: 0 on success (all glocks acquired),
 *          errno on failure (no glocks acquired)
 */

int gfs2_glock_nq_m(unsigned int num_gh, struct gfs2_holder *ghs)
{
	struct gfs2_holder *tmp[4];
	struct gfs2_holder **pph = tmp;
	int error = 0;

	switch(num_gh) {
	case 0:
		return 0;
	case 1:
		ghs->gh_flags &= ~(LM_FLAG_TRY | GL_ASYNC);
		return gfs2_glock_nq(ghs);
	default:
		if (num_gh <= 4)
			break;
		pph = kmalloc(num_gh * sizeof(struct gfs2_holder *), GFP_NOFS);
		if (!pph)
			return -ENOMEM;
	}

	error = nq_m_sync(num_gh, ghs, pph);

	if (pph != tmp)
		kfree(pph);

	return error;
}

/**
 * gfs2_glock_dq_m - release multiple glocks
 * @num_gh: the number of structures
 * @ghs: an array of struct gfs2_holder structures
 *
 */

void gfs2_glock_dq_m(unsigned int num_gh, struct gfs2_holder *ghs)
{
	while (num_gh--)
		gfs2_glock_dq(&ghs[num_gh]);
}

void gfs2_glock_cb(struct gfs2_glock *gl, unsigned int state)
{
	unsigned long delay = 0;
	unsigned long holdtime;
	unsigned long now = jiffies;

	gfs2_glock_hold(gl);
	holdtime = gl->gl_tchange + gl->gl_hold_time;
	if (test_bit(GLF_QUEUED, &gl->gl_flags) &&
	    gl->gl_name.ln_type == LM_TYPE_INODE) {
		if (time_before(now, holdtime))
			delay = holdtime - now;
		if (test_bit(GLF_REPLY_PENDING, &gl->gl_flags))
			delay = gl->gl_hold_time;
	}

	spin_lock(&gl->gl_spin);
	handle_callback(gl, state, delay, true);
	spin_unlock(&gl->gl_spin);
	if (queue_delayed_work(glock_workqueue, &gl->gl_work, delay) == 0)
		gfs2_glock_put(gl);
}

/**
 * gfs2_should_freeze - Figure out if glock should be frozen
 * @gl: The glock in question
 *
 * Glocks are not frozen if (a) the result of the dlm operation is
 * an error, (b) the locking operation was an unlock operation or
 * (c) if there is a "noexp" flagged request anywhere in the queue
 *
 * Returns: 1 if freezing should occur, 0 otherwise
 */

static int gfs2_should_freeze(const struct gfs2_glock *gl)
{
	const struct gfs2_holder *gh;

	if (gl->gl_reply & ~LM_OUT_ST_MASK)
		return 0;
	if (gl->gl_target == LM_ST_UNLOCKED)
		return 0;

	list_for_each_entry(gh, &gl->gl_holders, gh_list) {
		if (test_bit(HIF_HOLDER, &gh->gh_iflags))
			continue;
		if (LM_FLAG_NOEXP & gh->gh_flags)
			return 0;
	}

	return 1;
}

/**
 * gfs2_glock_complete - Callback used by locking
 * @gl: Pointer to the glock
 * @ret: The return value from the dlm
 *
 * The gl_reply field is under the gl_spin lock so that it is ok
 * to use a bitfield shared with other glock state fields.
 */

void gfs2_glock_complete(struct gfs2_glock *gl, int ret)
{
	struct lm_lockstruct *ls = &gl->gl_sbd->sd_lockstruct;

	spin_lock(&gl->gl_spin);
	gl->gl_reply = ret;

	if (unlikely(test_bit(DFL_BLOCK_LOCKS, &ls->ls_recover_flags))) {
		if (gfs2_should_freeze(gl)) {
			set_bit(GLF_FROZEN, &gl->gl_flags);
			spin_unlock(&gl->gl_spin);
			return;
		}
	}

	gl->gl_lockref.count++;
	set_bit(GLF_REPLY_PENDING, &gl->gl_flags);
	spin_unlock(&gl->gl_spin);

	if (queue_delayed_work(glock_workqueue, &gl->gl_work, 0) == 0)
		gfs2_glock_put(gl);
}

static int glock_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct gfs2_glock *gla, *glb;

	gla = list_entry(a, struct gfs2_glock, gl_lru);
	glb = list_entry(b, struct gfs2_glock, gl_lru);

	if (gla->gl_name.ln_number > glb->gl_name.ln_number)
		return 1;
	if (gla->gl_name.ln_number < glb->gl_name.ln_number)
		return -1;

	return 0;
}

/**
 * gfs2_dispose_glock_lru - Demote a list of glocks
 * @list: The list to dispose of
 *
 * Disposing of glocks may involve disk accesses, so that here we sort
 * the glocks by number (i.e. disk location of the inodes) so that if
 * there are any such accesses, they'll be sent in order (mostly).
 *
 * Must be called under the lru_lock, but may drop and retake this
 * lock. While the lru_lock is dropped, entries may vanish from the
 * list, but no new entries will appear on the list (since it is
 * private)
 */

static void gfs2_dispose_glock_lru(struct list_head *list)
__releases(&lru_lock)
__acquires(&lru_lock)
{
	struct gfs2_glock *gl;

	list_sort(NULL, list, glock_cmp);

	while(!list_empty(list)) {
		gl = list_entry(list->next, struct gfs2_glock, gl_lru);
		list_del_init(&gl->gl_lru);
		if (!spin_trylock(&gl->gl_spin)) {
add_back_to_lru:
			list_add(&gl->gl_lru, &lru_list);
			atomic_inc(&lru_count);
			continue;
		}
		if (test_and_set_bit(GLF_LOCK, &gl->gl_flags)) {
			spin_unlock(&gl->gl_spin);
			goto add_back_to_lru;
		}
		clear_bit(GLF_LRU, &gl->gl_flags);
		gl->gl_lockref.count++;
		if (demote_ok(gl))
			handle_callback(gl, LM_ST_UNLOCKED, 0, false);
		WARN_ON(!test_and_clear_bit(GLF_LOCK, &gl->gl_flags));
		if (queue_delayed_work(glock_workqueue, &gl->gl_work, 0) == 0)
			gl->gl_lockref.count--;
		spin_unlock(&gl->gl_spin);
		cond_resched_lock(&lru_lock);
	}
}

/**
 * gfs2_scan_glock_lru - Scan the LRU looking for locks to demote
 * @nr: The number of entries to scan
 *
 * This function selects the entries on the LRU which are able to
 * be demoted, and then kicks off the process by calling
 * gfs2_dispose_glock_lru() above.
 */

static long gfs2_scan_glock_lru(int nr)
{
	struct gfs2_glock *gl;
	LIST_HEAD(skipped);
	LIST_HEAD(dispose);
	long freed = 0;

	spin_lock(&lru_lock);
	while ((nr-- >= 0) && !list_empty(&lru_list)) {
		gl = list_entry(lru_list.next, struct gfs2_glock, gl_lru);

		/* Test for being demotable */
		if (!test_bit(GLF_LOCK, &gl->gl_flags)) {
			list_move(&gl->gl_lru, &dispose);
			atomic_dec(&lru_count);
			freed++;
			continue;
		}

		list_move(&gl->gl_lru, &skipped);
	}
	list_splice(&skipped, &lru_list);
	if (!list_empty(&dispose))
		gfs2_dispose_glock_lru(&dispose);
	spin_unlock(&lru_lock);

	return freed;
}

static unsigned long gfs2_glock_shrink_scan(struct shrinker *shrink,
					    struct shrink_control *sc)
{
	if (!(sc->gfp_mask & __GFP_FS))
		return SHRINK_STOP;
	return gfs2_scan_glock_lru(sc->nr_to_scan);
}

static unsigned long gfs2_glock_shrink_count(struct shrinker *shrink,
					     struct shrink_control *sc)
{
	return vfs_pressure_ratio(atomic_read(&lru_count));
}

static struct shrinker glock_shrinker = {
	.seeks = DEFAULT_SEEKS,
	.count_objects = gfs2_glock_shrink_count,
	.scan_objects = gfs2_glock_shrink_scan,
};

/**
 * examine_bucket - Call a function for glock in a hash bucket
 * @examiner: the function
 * @sdp: the filesystem
 * @bucket: the bucket
 *
 */

static void examine_bucket(glock_examiner examiner, const struct gfs2_sbd *sdp,
			  unsigned int hash)
{
	struct gfs2_glock *gl;
	struct hlist_bl_head *head = &gl_hash_table[hash];
	struct hlist_bl_node *pos;

	rcu_read_lock();
	hlist_bl_for_each_entry_rcu(gl, pos, head, gl_list) {
		if ((gl->gl_sbd == sdp) && lockref_get_not_dead(&gl->gl_lockref))
			examiner(gl);
	}
	rcu_read_unlock();
	cond_resched();
}

static void glock_hash_walk(glock_examiner examiner, const struct gfs2_sbd *sdp)
{
	unsigned x;

	for (x = 0; x < GFS2_GL_HASH_SIZE; x++)
		examine_bucket(examiner, sdp, x);
}


/**
 * thaw_glock - thaw out a glock which has an unprocessed reply waiting
 * @gl: The glock to thaw
 *
 */

static void thaw_glock(struct gfs2_glock *gl)
{
	if (!test_and_clear_bit(GLF_FROZEN, &gl->gl_flags))
		goto out;
	set_bit(GLF_REPLY_PENDING, &gl->gl_flags);
	if (queue_delayed_work(glock_workqueue, &gl->gl_work, 0) == 0) {
out:
		gfs2_glock_put(gl);
	}
}

/**
 * clear_glock - look at a glock and see if we can free it from glock cache
 * @gl: the glock to look at
 *
 */

static void clear_glock(struct gfs2_glock *gl)
{
	gfs2_glock_remove_from_lru(gl);

	spin_lock(&gl->gl_spin);
	if (gl->gl_state != LM_ST_UNLOCKED)
		handle_callback(gl, LM_ST_UNLOCKED, 0, false);
	spin_unlock(&gl->gl_spin);
	if (queue_delayed_work(glock_workqueue, &gl->gl_work, 0) == 0)
		gfs2_glock_put(gl);
}

/**
 * gfs2_glock_thaw - Thaw any frozen glocks
 * @sdp: The super block
 *
 */

void gfs2_glock_thaw(struct gfs2_sbd *sdp)
{
	glock_hash_walk(thaw_glock, sdp);
}

static void dump_glock(struct seq_file *seq, struct gfs2_glock *gl)
{
	spin_lock(&gl->gl_spin);
	gfs2_dump_glock(seq, gl);
	spin_unlock(&gl->gl_spin);
}

static void dump_glock_func(struct gfs2_glock *gl)
{
	dump_glock(NULL, gl);
}

/**
 * gfs2_gl_hash_clear - Empty out the glock hash table
 * @sdp: the filesystem
 * @wait: wait until it's all gone
 *
 * Called when unmounting the filesystem.
 */

void gfs2_gl_hash_clear(struct gfs2_sbd *sdp)
{
	set_bit(SDF_SKIP_DLM_UNLOCK, &sdp->sd_flags);
	flush_workqueue(glock_workqueue);
	glock_hash_walk(clear_glock, sdp);
	flush_workqueue(glock_workqueue);
	wait_event(sdp->sd_glock_wait, atomic_read(&sdp->sd_glock_disposal) == 0);
	glock_hash_walk(dump_glock_func, sdp);
}

void gfs2_glock_finish_truncate(struct gfs2_inode *ip)
{
	struct gfs2_glock *gl = ip->i_gl;
	int ret;

	ret = gfs2_truncatei_resume(ip);
	gfs2_assert_withdraw(gl->gl_sbd, ret == 0);

	spin_lock(&gl->gl_spin);
	clear_bit(GLF_LOCK, &gl->gl_flags);
	run_queue(gl, 1);
	spin_unlock(&gl->gl_spin);
}

static const char *state2str(unsigned state)
{
	switch(state) {
	case LM_ST_UNLOCKED:
		return "UN";
	case LM_ST_SHARED:
		return "SH";
	case LM_ST_DEFERRED:
		return "DF";
	case LM_ST_EXCLUSIVE:
		return "EX";
	}
	return "??";
}

static const char *hflags2str(char *buf, unsigned flags, unsigned long iflags)
{
	char *p = buf;
	if (flags & LM_FLAG_TRY)
		*p++ = 't';
	if (flags & LM_FLAG_TRY_1CB)
		*p++ = 'T';
	if (flags & LM_FLAG_NOEXP)
		*p++ = 'e';
	if (flags & LM_FLAG_ANY)
		*p++ = 'A';
	if (flags & LM_FLAG_PRIORITY)
		*p++ = 'p';
	if (flags & GL_ASYNC)
		*p++ = 'a';
	if (flags & GL_EXACT)
		*p++ = 'E';
	if (flags & GL_NOCACHE)
		*p++ = 'c';
	if (test_bit(HIF_HOLDER, &iflags))
		*p++ = 'H';
	if (test_bit(HIF_WAIT, &iflags))
		*p++ = 'W';
	if (test_bit(HIF_FIRST, &iflags))
		*p++ = 'F';
	*p = 0;
	return buf;
}

/**
 * dump_holder - print information about a glock holder
 * @seq: the seq_file struct
 * @gh: the glock holder
 *
 */

static void dump_holder(struct seq_file *seq, const struct gfs2_holder *gh)
{
	struct task_struct *gh_owner = NULL;
	char flags_buf[32];

	rcu_read_lock();
	if (gh->gh_owner_pid)
		gh_owner = pid_task(gh->gh_owner_pid, PIDTYPE_PID);
	gfs2_print_dbg(seq, " H: s:%s f:%s e:%d p:%ld [%s] %pS\n",
		       state2str(gh->gh_state),
		       hflags2str(flags_buf, gh->gh_flags, gh->gh_iflags),
		       gh->gh_error,
		       gh->gh_owner_pid ? (long)pid_nr(gh->gh_owner_pid) : -1,
		       gh_owner ? gh_owner->comm : "(ended)",
		       (void *)gh->gh_ip);
	rcu_read_unlock();
}

static const char *gflags2str(char *buf, const struct gfs2_glock *gl)
{
	const unsigned long *gflags = &gl->gl_flags;
	char *p = buf;

	if (test_bit(GLF_LOCK, gflags))
		*p++ = 'l';
	if (test_bit(GLF_DEMOTE, gflags))
		*p++ = 'D';
	if (test_bit(GLF_PENDING_DEMOTE, gflags))
		*p++ = 'd';
	if (test_bit(GLF_DEMOTE_IN_PROGRESS, gflags))
		*p++ = 'p';
	if (test_bit(GLF_DIRTY, gflags))
		*p++ = 'y';
	if (test_bit(GLF_LFLUSH, gflags))
		*p++ = 'f';
	if (test_bit(GLF_INVALIDATE_IN_PROGRESS, gflags))
		*p++ = 'i';
	if (test_bit(GLF_REPLY_PENDING, gflags))
		*p++ = 'r';
	if (test_bit(GLF_INITIAL, gflags))
		*p++ = 'I';
	if (test_bit(GLF_FROZEN, gflags))
		*p++ = 'F';
	if (test_bit(GLF_QUEUED, gflags))
		*p++ = 'q';
	if (test_bit(GLF_LRU, gflags))
		*p++ = 'L';
	if (gl->gl_object)
		*p++ = 'o';
	if (test_bit(GLF_BLOCKING, gflags))
		*p++ = 'b';
	*p = 0;
	return buf;
}

/**
 * gfs2_dump_glock - print information about a glock
 * @seq: The seq_file struct
 * @gl: the glock
 *
 * The file format is as follows:
 * One line per object, capital letters are used to indicate objects
 * G = glock, I = Inode, R = rgrp, H = holder. Glocks are not indented,
 * other objects are indented by a single space and follow the glock to
 * which they are related. Fields are indicated by lower case letters
 * followed by a colon and the field value, except for strings which are in
 * [] so that its possible to see if they are composed of spaces for
 * example. The field's are n = number (id of the object), f = flags,
 * t = type, s = state, r = refcount, e = error, p = pid.
 *
 */

void gfs2_dump_glock(struct seq_file *seq, const struct gfs2_glock *gl)
{
	const struct gfs2_glock_operations *glops = gl->gl_ops;
	unsigned long long dtime;
	const struct gfs2_holder *gh;
	char gflags_buf[32];

	dtime = jiffies - gl->gl_demote_time;
	dtime *= 1000000/HZ; /* demote time in uSec */
	if (!test_bit(GLF_DEMOTE, &gl->gl_flags))
		dtime = 0;
	gfs2_print_dbg(seq, "G:  s:%s n:%u/%llx f:%s t:%s d:%s/%llu a:%d v:%d r:%d m:%ld\n",
		  state2str(gl->gl_state),
		  gl->gl_name.ln_type,
		  (unsigned long long)gl->gl_name.ln_number,
		  gflags2str(gflags_buf, gl),
		  state2str(gl->gl_target),
		  state2str(gl->gl_demote_state), dtime,
		  atomic_read(&gl->gl_ail_count),
		  atomic_read(&gl->gl_revokes),
		  (int)gl->gl_lockref.count, gl->gl_hold_time);

	list_for_each_entry(gh, &gl->gl_holders, gh_list)
		dump_holder(seq, gh);

	if (gl->gl_state != LM_ST_UNLOCKED && glops->go_dump)
		glops->go_dump(seq, gl);
}

static int gfs2_glstats_seq_show(struct seq_file *seq, void *iter_ptr)
{
	struct gfs2_glock *gl = iter_ptr;

	seq_printf(seq, "G: n:%u/%llx rtt:%lld/%lld rttb:%lld/%lld irt:%lld/%lld dcnt: %lld qcnt: %lld\n",
		   gl->gl_name.ln_type,
		   (unsigned long long)gl->gl_name.ln_number,
		   (long long)gl->gl_stats.stats[GFS2_LKS_SRTT],
		   (long long)gl->gl_stats.stats[GFS2_LKS_SRTTVAR],
		   (long long)gl->gl_stats.stats[GFS2_LKS_SRTTB],
		   (long long)gl->gl_stats.stats[GFS2_LKS_SRTTVARB],
		   (long long)gl->gl_stats.stats[GFS2_LKS_SIRT],
		   (long long)gl->gl_stats.stats[GFS2_LKS_SIRTVAR],
		   (long long)gl->gl_stats.stats[GFS2_LKS_DCOUNT],
		   (long long)gl->gl_stats.stats[GFS2_LKS_QCOUNT]);
	return 0;
}

static const char *gfs2_gltype[] = {
	"type",
	"reserved",
	"nondisk",
	"inode",
	"rgrp",
	"meta",
	"iopen",
	"flock",
	"plock",
	"quota",
	"journal",
};

static const char *gfs2_stype[] = {
	[GFS2_LKS_SRTT]		= "srtt",
	[GFS2_LKS_SRTTVAR]	= "srttvar",
	[GFS2_LKS_SRTTB]	= "srttb",
	[GFS2_LKS_SRTTVARB]	= "srttvarb",
	[GFS2_LKS_SIRT]		= "sirt",
	[GFS2_LKS_SIRTVAR]	= "sirtvar",
	[GFS2_LKS_DCOUNT]	= "dlm",
	[GFS2_LKS_QCOUNT]	= "queue",
};

#define GFS2_NR_SBSTATS (ARRAY_SIZE(gfs2_gltype) * ARRAY_SIZE(gfs2_stype))

static int gfs2_sbstats_seq_show(struct seq_file *seq, void *iter_ptr)
{
	struct gfs2_glock_iter *gi = seq->private;
	struct gfs2_sbd *sdp = gi->sdp;
	unsigned index = gi->hash >> 3;
	unsigned subindex = gi->hash & 0x07;
	s64 value;
	int i;

	if (index == 0 && subindex != 0)
		return 0;

	seq_printf(seq, "%-10s %8s:", gfs2_gltype[index],
		   (index == 0) ? "cpu": gfs2_stype[subindex]);

	for_each_possible_cpu(i) {
                const struct gfs2_pcpu_lkstats *lkstats = per_cpu_ptr(sdp->sd_lkstats, i);
		if (index == 0) {
			value = i;
		} else {
			value = lkstats->lkstats[index - 1].stats[subindex];
		}
		seq_printf(seq, " %15lld", (long long)value);
	}
	seq_putc(seq, '\n');
	return 0;
}

int __init gfs2_glock_init(void)
{
	unsigned i;
	for(i = 0; i < GFS2_GL_HASH_SIZE; i++) {
		INIT_HLIST_BL_HEAD(&gl_hash_table[i]);
	}

	glock_workqueue = alloc_workqueue("glock_workqueue", WQ_MEM_RECLAIM |
					  WQ_HIGHPRI | WQ_FREEZABLE, 0);
	if (!glock_workqueue)
		return -ENOMEM;
	gfs2_delete_workqueue = alloc_workqueue("delete_workqueue",
						WQ_MEM_RECLAIM | WQ_FREEZABLE,
						0);
	if (!gfs2_delete_workqueue) {
		destroy_workqueue(glock_workqueue);
		return -ENOMEM;
	}

	register_shrinker(&glock_shrinker);

	return 0;
}

void gfs2_glock_exit(void)
{
	unregister_shrinker(&glock_shrinker);
	destroy_workqueue(glock_workqueue);
	destroy_workqueue(gfs2_delete_workqueue);
}

static inline struct gfs2_glock *glock_hash_chain(unsigned hash)
{
	return hlist_bl_entry(hlist_bl_first_rcu(&gl_hash_table[hash]),
			      struct gfs2_glock, gl_list);
}

static inline struct gfs2_glock *glock_hash_next(struct gfs2_glock *gl)
{
	return hlist_bl_entry(rcu_dereference(gl->gl_list.next),
			      struct gfs2_glock, gl_list);
}

static int gfs2_glock_iter_next(struct gfs2_glock_iter *gi)
{
	struct gfs2_glock *gl;

	do {
		gl = gi->gl;
		if (gl) {
			gi->gl = glock_hash_next(gl);
			gi->nhash++;
		} else {
			if (gi->hash >= GFS2_GL_HASH_SIZE) {
				rcu_read_unlock();
				return 1;
			}
			gi->gl = glock_hash_chain(gi->hash);
			gi->nhash = 0;
		}
		while (gi->gl == NULL) {
			gi->hash++;
			if (gi->hash >= GFS2_GL_HASH_SIZE) {
				rcu_read_unlock();
				return 1;
			}
			gi->gl = glock_hash_chain(gi->hash);
			gi->nhash = 0;
		}
	/* Skip entries for other sb and dead entries */
	} while (gi->sdp != gi->gl->gl_sbd ||
		 __lockref_is_dead(&gi->gl->gl_lockref));

	return 0;
}

static void *gfs2_glock_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct gfs2_glock_iter *gi = seq->private;
	loff_t n = *pos;

	if (gi->last_pos <= *pos)
		n = gi->nhash + (*pos - gi->last_pos);
	else
		gi->hash = 0;

	gi->nhash = 0;
	rcu_read_lock();

	do {
		if (gfs2_glock_iter_next(gi))
			return NULL;
	} while (n--);

	gi->last_pos = *pos;
	return gi->gl;
}

static void *gfs2_glock_seq_next(struct seq_file *seq, void *iter_ptr,
				 loff_t *pos)
{
	struct gfs2_glock_iter *gi = seq->private;

	(*pos)++;
	gi->last_pos = *pos;
	if (gfs2_glock_iter_next(gi))
		return NULL;

	return gi->gl;
}

static void gfs2_glock_seq_stop(struct seq_file *seq, void *iter_ptr)
{
	struct gfs2_glock_iter *gi = seq->private;

	if (gi->gl)
		rcu_read_unlock();
	gi->gl = NULL;
}

static int gfs2_glock_seq_show(struct seq_file *seq, void *iter_ptr)
{
	dump_glock(seq, iter_ptr);
	return 0;
}

static void *gfs2_sbstats_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct gfs2_glock_iter *gi = seq->private;

	gi->hash = *pos;
	if (*pos >= GFS2_NR_SBSTATS)
		return NULL;
	preempt_disable();
	return SEQ_START_TOKEN;
}

static void *gfs2_sbstats_seq_next(struct seq_file *seq, void *iter_ptr,
				   loff_t *pos)
{
	struct gfs2_glock_iter *gi = seq->private;
	(*pos)++;
	gi->hash++;
	if (gi->hash >= GFS2_NR_SBSTATS) {
		preempt_enable();
		return NULL;
	}
	return SEQ_START_TOKEN;
}

static void gfs2_sbstats_seq_stop(struct seq_file *seq, void *iter_ptr)
{
	preempt_enable();
}

static const struct seq_operations gfs2_glock_seq_ops = {
	.start = gfs2_glock_seq_start,
	.next  = gfs2_glock_seq_next,
	.stop  = gfs2_glock_seq_stop,
	.show  = gfs2_glock_seq_show,
};

static const struct seq_operations gfs2_glstats_seq_ops = {
	.start = gfs2_glock_seq_start,
	.next  = gfs2_glock_seq_next,
	.stop  = gfs2_glock_seq_stop,
	.show  = gfs2_glstats_seq_show,
};

static const struct seq_operations gfs2_sbstats_seq_ops = {
	.start = gfs2_sbstats_seq_start,
	.next  = gfs2_sbstats_seq_next,
	.stop  = gfs2_sbstats_seq_stop,
	.show  = gfs2_sbstats_seq_show,
};

#define GFS2_SEQ_GOODSIZE min(PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER, 65536UL)

static int gfs2_glocks_open(struct inode *inode, struct file *file)
{
	int ret = seq_open_private(file, &gfs2_glock_seq_ops,
				   sizeof(struct gfs2_glock_iter));
	if (ret == 0) {
		struct seq_file *seq = file->private_data;
		struct gfs2_glock_iter *gi = seq->private;
		gi->sdp = inode->i_private;
		seq->buf = kmalloc(GFS2_SEQ_GOODSIZE, GFP_KERNEL | __GFP_NOWARN);
		if (seq->buf)
			seq->size = GFS2_SEQ_GOODSIZE;
	}
	return ret;
}

static int gfs2_glstats_open(struct inode *inode, struct file *file)
{
	int ret = seq_open_private(file, &gfs2_glstats_seq_ops,
				   sizeof(struct gfs2_glock_iter));
	if (ret == 0) {
		struct seq_file *seq = file->private_data;
		struct gfs2_glock_iter *gi = seq->private;
		gi->sdp = inode->i_private;
		seq->buf = kmalloc(GFS2_SEQ_GOODSIZE, GFP_KERNEL | __GFP_NOWARN);
		if (seq->buf)
			seq->size = GFS2_SEQ_GOODSIZE;
	}
	return ret;
}

static int gfs2_sbstats_open(struct inode *inode, struct file *file)
{
	int ret = seq_open_private(file, &gfs2_sbstats_seq_ops,
				   sizeof(struct gfs2_glock_iter));
	if (ret == 0) {
		struct seq_file *seq = file->private_data;
		struct gfs2_glock_iter *gi = seq->private;
		gi->sdp = inode->i_private;
	}
	return ret;
}

static const struct file_operations gfs2_glocks_fops = {
	.owner   = THIS_MODULE,
	.open    = gfs2_glocks_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
};

static const struct file_operations gfs2_glstats_fops = {
	.owner   = THIS_MODULE,
	.open    = gfs2_glstats_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
};

static const struct file_operations gfs2_sbstats_fops = {
	.owner   = THIS_MODULE,
	.open	 = gfs2_sbstats_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private,
};

int gfs2_create_debugfs_file(struct gfs2_sbd *sdp)
{
	sdp->debugfs_dir = debugfs_create_dir(sdp->sd_table_name, gfs2_root);
	if (!sdp->debugfs_dir)
		return -ENOMEM;
	sdp->debugfs_dentry_glocks = debugfs_create_file("glocks",
							 S_IFREG | S_IRUGO,
							 sdp->debugfs_dir, sdp,
							 &gfs2_glocks_fops);
	if (!sdp->debugfs_dentry_glocks)
		goto fail;

	sdp->debugfs_dentry_glstats = debugfs_create_file("glstats",
							S_IFREG | S_IRUGO,
							sdp->debugfs_dir, sdp,
							&gfs2_glstats_fops);
	if (!sdp->debugfs_dentry_glstats)
		goto fail;

	sdp->debugfs_dentry_sbstats = debugfs_create_file("sbstats",
							S_IFREG | S_IRUGO,
							sdp->debugfs_dir, sdp,
							&gfs2_sbstats_fops);
	if (!sdp->debugfs_dentry_sbstats)
		goto fail;

	return 0;
fail:
	gfs2_delete_debugfs_file(sdp);
	return -ENOMEM;
}

void gfs2_delete_debugfs_file(struct gfs2_sbd *sdp)
{
	if (sdp->debugfs_dir) {
		if (sdp->debugfs_dentry_glocks) {
			debugfs_remove(sdp->debugfs_dentry_glocks);
			sdp->debugfs_dentry_glocks = NULL;
		}
		if (sdp->debugfs_dentry_glstats) {
			debugfs_remove(sdp->debugfs_dentry_glstats);
			sdp->debugfs_dentry_glstats = NULL;
		}
		if (sdp->debugfs_dentry_sbstats) {
			debugfs_remove(sdp->debugfs_dentry_sbstats);
			sdp->debugfs_dentry_sbstats = NULL;
		}
		debugfs_remove(sdp->debugfs_dir);
		sdp->debugfs_dir = NULL;
	}
}

int gfs2_register_debugfs(void)
{
	gfs2_root = debugfs_create_dir("gfs2", NULL);
	return gfs2_root ? 0 : -ENOMEM;
}

void gfs2_unregister_debugfs(void)
{
	debugfs_remove(gfs2_root);
	gfs2_root = NULL;
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/glops.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/gfs2_ondisk.h>
#include <linux/bio.h>
// #include <linux/posix_acl.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "bmap.h"
// #include "glock.h"
// #include "glops.h"
// #include "inode.h"
// #include "log.h"
// #include "meta_io.h"
#include "recovery.h"
// #include "rgrp.h"
// #include "util.h"
// #include "trans.h"
// #include "dir.h"

static void gfs2_ail_error(struct gfs2_glock *gl, const struct buffer_head *bh)
{
	fs_err(gl->gl_sbd, "AIL buffer %p: blocknr %llu state 0x%08lx mapping %p page state 0x%lx\n",
	       bh, (unsigned long long)bh->b_blocknr, bh->b_state,
	       bh->b_page->mapping, bh->b_page->flags);
	fs_err(gl->gl_sbd, "AIL glock %u:%llu mapping %p\n",
	       gl->gl_name.ln_type, gl->gl_name.ln_number,
	       gfs2_glock2aspace(gl));
	gfs2_lm_withdraw(gl->gl_sbd, "AIL error\n");
}

/**
 * __gfs2_ail_flush - remove all buffers for a given lock from the AIL
 * @gl: the glock
 * @fsync: set when called from fsync (not all buffers will be clean)
 *
 * None of the buffers should be dirty, locked, or pinned.
 */

static void __gfs2_ail_flush(struct gfs2_glock *gl, bool fsync,
			     unsigned int nr_revokes)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct list_head *head = &gl->gl_ail_list;
	struct gfs2_bufdata *bd, *tmp;
	struct buffer_head *bh;
	const unsigned long b_state = (1UL << BH_Dirty)|(1UL << BH_Pinned)|(1UL << BH_Lock);

	gfs2_log_lock(sdp);
	spin_lock(&sdp->sd_ail_lock);
	list_for_each_entry_safe_reverse(bd, tmp, head, bd_ail_gl_list) {
		if (nr_revokes == 0)
			break;
		bh = bd->bd_bh;
		if (bh->b_state & b_state) {
			if (fsync)
				continue;
			gfs2_ail_error(gl, bh);
		}
		gfs2_trans_add_revoke(sdp, bd);
		nr_revokes--;
	}
	GLOCK_BUG_ON(gl, !fsync && atomic_read(&gl->gl_ail_count));
	spin_unlock(&sdp->sd_ail_lock);
	gfs2_log_unlock(sdp);
}


static void gfs2_ail_empty_gl(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_trans tr;

	memset(&tr, 0, sizeof(tr));
	INIT_LIST_HEAD(&tr.tr_buf);
	INIT_LIST_HEAD(&tr.tr_databuf);
	tr.tr_revokes = atomic_read(&gl->gl_ail_count);

	if (!tr.tr_revokes)
		return;

	/* A shortened, inline version of gfs2_trans_begin()
         * tr->alloced is not set since the transaction structure is
         * on the stack */
	tr.tr_reserved = 1 + gfs2_struct2blk(sdp, tr.tr_revokes, sizeof(u64));
	tr.tr_ip = (unsigned long)__builtin_return_address(0);
	sb_start_intwrite(sdp->sd_vfs);
	if (gfs2_log_reserve(sdp, tr.tr_reserved) < 0) {
		sb_end_intwrite(sdp->sd_vfs);
		return;
	}
	WARN_ON_ONCE(current->journal_info);
	current->journal_info = &tr;

	__gfs2_ail_flush(gl, 0, tr.tr_revokes);

	gfs2_trans_end(sdp);
	gfs2_log_flush(sdp, NULL, NORMAL_FLUSH);
}

void gfs2_ail_flush(struct gfs2_glock *gl, bool fsync)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	unsigned int revokes = atomic_read(&gl->gl_ail_count);
	unsigned int max_revokes = (sdp->sd_sb.sb_bsize - sizeof(struct gfs2_log_descriptor)) / sizeof(u64);
	int ret;

	if (!revokes)
		return;

	while (revokes > max_revokes)
		max_revokes += (sdp->sd_sb.sb_bsize - sizeof(struct gfs2_meta_header)) / sizeof(u64);

	ret = gfs2_trans_begin(sdp, 0, max_revokes);
	if (ret)
		return;
	__gfs2_ail_flush(gl, fsync, max_revokes);
	gfs2_trans_end(sdp);
	gfs2_log_flush(sdp, NULL, NORMAL_FLUSH);
}

/**
 * rgrp_go_sync - sync out the metadata for this glock
 * @gl: the glock
 *
 * Called when demoting or unlocking an EX glock.  We must flush
 * to disk all dirty buffers/pages relating to this glock, and must not
 * not return to caller to demote/unlock the glock until I/O is complete.
 */

static void rgrp_go_sync(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct address_space *mapping = &sdp->sd_aspace;
	struct gfs2_rgrpd *rgd;
	int error;

	if (!test_and_clear_bit(GLF_DIRTY, &gl->gl_flags))
		return;
	GLOCK_BUG_ON(gl, gl->gl_state != LM_ST_EXCLUSIVE);

	gfs2_log_flush(sdp, gl, NORMAL_FLUSH);
	filemap_fdatawrite_range(mapping, gl->gl_vm.start, gl->gl_vm.end);
	error = filemap_fdatawait_range(mapping, gl->gl_vm.start, gl->gl_vm.end);
	mapping_set_error(mapping, error);
	gfs2_ail_empty_gl(gl);

	spin_lock(&gl->gl_spin);
	rgd = gl->gl_object;
	if (rgd)
		gfs2_free_clones(rgd);
	spin_unlock(&gl->gl_spin);
}

/**
 * rgrp_go_inval - invalidate the metadata for this glock
 * @gl: the glock
 * @flags:
 *
 * We never used LM_ST_DEFERRED with resource groups, so that we
 * should always see the metadata flag set here.
 *
 */

static void rgrp_go_inval(struct gfs2_glock *gl, int flags)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct address_space *mapping = &sdp->sd_aspace;

	WARN_ON_ONCE(!(flags & DIO_METADATA));
	gfs2_assert_withdraw(sdp, !atomic_read(&gl->gl_ail_count));
	truncate_inode_pages_range(mapping, gl->gl_vm.start, gl->gl_vm.end);

	if (gl->gl_object) {
		struct gfs2_rgrpd *rgd = (struct gfs2_rgrpd *)gl->gl_object;
		rgd->rd_flags &= ~GFS2_RDF_UPTODATE;
	}
}

/**
 * inode_go_sync - Sync the dirty data and/or metadata for an inode glock
 * @gl: the glock protecting the inode
 *
 */

static void inode_go_sync(struct gfs2_glock *gl)
{
	struct gfs2_inode *ip = gl->gl_object;
	struct address_space *metamapping = gfs2_glock2aspace(gl);
	int error;

	if (ip && !S_ISREG(ip->i_inode.i_mode))
		ip = NULL;
	if (ip) {
		if (test_and_clear_bit(GIF_SW_PAGED, &ip->i_flags))
			unmap_shared_mapping_range(ip->i_inode.i_mapping, 0, 0);
		inode_dio_wait(&ip->i_inode);
	}
	if (!test_and_clear_bit(GLF_DIRTY, &gl->gl_flags))
		return;

	GLOCK_BUG_ON(gl, gl->gl_state != LM_ST_EXCLUSIVE);

	gfs2_log_flush(gl->gl_sbd, gl, NORMAL_FLUSH);
	filemap_fdatawrite(metamapping);
	if (ip) {
		struct address_space *mapping = ip->i_inode.i_mapping;
		filemap_fdatawrite(mapping);
		error = filemap_fdatawait(mapping);
		mapping_set_error(mapping, error);
	}
	error = filemap_fdatawait(metamapping);
	mapping_set_error(metamapping, error);
	gfs2_ail_empty_gl(gl);
	/*
	 * Writeback of the data mapping may cause the dirty flag to be set
	 * so we have to clear it again here.
	 */
	smp_mb__before_atomic();
	clear_bit(GLF_DIRTY, &gl->gl_flags);
}

/**
 * inode_go_inval - prepare a inode glock to be released
 * @gl: the glock
 * @flags:
 *
 * Normally we invalidate everything, but if we are moving into
 * LM_ST_DEFERRED from LM_ST_SHARED or LM_ST_EXCLUSIVE then we
 * can keep hold of the metadata, since it won't have changed.
 *
 */

static void inode_go_inval(struct gfs2_glock *gl, int flags)
{
	struct gfs2_inode *ip = gl->gl_object;

	gfs2_assert_withdraw(gl->gl_sbd, !atomic_read(&gl->gl_ail_count));

	if (flags & DIO_METADATA) {
		struct address_space *mapping = gfs2_glock2aspace(gl);
		truncate_inode_pages(mapping, 0);
		if (ip) {
			set_bit(GIF_INVALID, &ip->i_flags);
			forget_all_cached_acls(&ip->i_inode);
			gfs2_dir_hash_inval(ip);
		}
	}

	if (ip == GFS2_I(gl->gl_sbd->sd_rindex)) {
		gfs2_log_flush(gl->gl_sbd, NULL, NORMAL_FLUSH);
		gl->gl_sbd->sd_rindex_uptodate = 0;
	}
	if (ip && S_ISREG(ip->i_inode.i_mode))
		truncate_inode_pages(ip->i_inode.i_mapping, 0);
}

/**
 * inode_go_demote_ok - Check to see if it's ok to unlock an inode glock
 * @gl: the glock
 *
 * Returns: 1 if it's ok
 */

static int inode_go_demote_ok(const struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_holder *gh;

	if (sdp->sd_jindex == gl->gl_object || sdp->sd_rindex == gl->gl_object)
		return 0;

	if (!list_empty(&gl->gl_holders)) {
		gh = list_entry(gl->gl_holders.next, struct gfs2_holder, gh_list);
		if (gh->gh_list.next != &gl->gl_holders)
			return 0;
	}

	return 1;
}

/**
 * gfs2_set_nlink - Set the inode's link count based on on-disk info
 * @inode: The inode in question
 * @nlink: The link count
 *
 * If the link count has hit zero, it must never be raised, whatever the
 * on-disk inode might say. When new struct inodes are created the link
 * count is set to 1, so that we can safely use this test even when reading
 * in on disk information for the first time.
 */

static void gfs2_set_nlink(struct inode *inode, u32 nlink)
{
	/*
	 * We will need to review setting the nlink count here in the
	 * light of the forthcoming ro bind mount work. This is a reminder
	 * to do that.
	 */
	if ((inode->i_nlink != nlink) && (inode->i_nlink != 0)) {
		if (nlink == 0)
			clear_nlink(inode);
		else
			set_nlink(inode, nlink);
	}
}

static int gfs2_dinode_in(struct gfs2_inode *ip, const void *buf)
{
	const struct gfs2_dinode *str = buf;
	struct timespec atime;
	u16 height, depth;

	if (unlikely(ip->i_no_addr != be64_to_cpu(str->di_num.no_addr)))
		goto corrupt;
	ip->i_no_formal_ino = be64_to_cpu(str->di_num.no_formal_ino);
	ip->i_inode.i_mode = be32_to_cpu(str->di_mode);
	ip->i_inode.i_rdev = 0;
	switch (ip->i_inode.i_mode & S_IFMT) {
	case S_IFBLK:
	case S_IFCHR:
		ip->i_inode.i_rdev = MKDEV(be32_to_cpu(str->di_major),
					   be32_to_cpu(str->di_minor));
		break;
	};

	i_uid_write(&ip->i_inode, be32_to_cpu(str->di_uid));
	i_gid_write(&ip->i_inode, be32_to_cpu(str->di_gid));
	gfs2_set_nlink(&ip->i_inode, be32_to_cpu(str->di_nlink));
	i_size_write(&ip->i_inode, be64_to_cpu(str->di_size));
	gfs2_set_inode_blocks(&ip->i_inode, be64_to_cpu(str->di_blocks));
	atime.tv_sec = be64_to_cpu(str->di_atime);
	atime.tv_nsec = be32_to_cpu(str->di_atime_nsec);
	if (timespec_compare(&ip->i_inode.i_atime, &atime) < 0)
		ip->i_inode.i_atime = atime;
	ip->i_inode.i_mtime.tv_sec = be64_to_cpu(str->di_mtime);
	ip->i_inode.i_mtime.tv_nsec = be32_to_cpu(str->di_mtime_nsec);
	ip->i_inode.i_ctime.tv_sec = be64_to_cpu(str->di_ctime);
	ip->i_inode.i_ctime.tv_nsec = be32_to_cpu(str->di_ctime_nsec);

	ip->i_goal = be64_to_cpu(str->di_goal_meta);
	ip->i_generation = be64_to_cpu(str->di_generation);

	ip->i_diskflags = be32_to_cpu(str->di_flags);
	ip->i_eattr = be64_to_cpu(str->di_eattr);
	/* i_diskflags and i_eattr must be set before gfs2_set_inode_flags() */
	gfs2_set_inode_flags(&ip->i_inode);
	height = be16_to_cpu(str->di_height);
	if (unlikely(height > GFS2_MAX_META_HEIGHT))
		goto corrupt;
	ip->i_height = (u8)height;

	depth = be16_to_cpu(str->di_depth);
	if (unlikely(depth > GFS2_DIR_MAX_DEPTH))
		goto corrupt;
	ip->i_depth = (u8)depth;
	ip->i_entries = be32_to_cpu(str->di_entries);

	if (S_ISREG(ip->i_inode.i_mode))
		gfs2_set_aops(&ip->i_inode);

	return 0;
corrupt:
	gfs2_consist_inode(ip);
	return -EIO;
}

/**
 * gfs2_inode_refresh - Refresh the incore copy of the dinode
 * @ip: The GFS2 inode
 *
 * Returns: errno
 */

int gfs2_inode_refresh(struct gfs2_inode *ip)
{
	struct buffer_head *dibh;
	int error;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		return error;

	error = gfs2_dinode_in(ip, dibh->b_data);
	brelse(dibh);
	clear_bit(GIF_INVALID, &ip->i_flags);

	return error;
}

/**
 * inode_go_lock - operation done after an inode lock is locked by a process
 * @gl: the glock
 * @flags:
 *
 * Returns: errno
 */

static int inode_go_lock(struct gfs2_holder *gh)
{
	struct gfs2_glock *gl = gh->gh_gl;
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_inode *ip = gl->gl_object;
	int error = 0;

	if (!ip || (gh->gh_flags & GL_SKIP))
		return 0;

	if (test_bit(GIF_INVALID, &ip->i_flags)) {
		error = gfs2_inode_refresh(ip);
		if (error)
			return error;
	}

	if (gh->gh_state != LM_ST_DEFERRED)
		inode_dio_wait(&ip->i_inode);

	if ((ip->i_diskflags & GFS2_DIF_TRUNC_IN_PROG) &&
	    (gl->gl_state == LM_ST_EXCLUSIVE) &&
	    (gh->gh_state == LM_ST_EXCLUSIVE)) {
		spin_lock(&sdp->sd_trunc_lock);
		if (list_empty(&ip->i_trunc_list))
			list_add(&sdp->sd_trunc_list, &ip->i_trunc_list);
		spin_unlock(&sdp->sd_trunc_lock);
		wake_up(&sdp->sd_quota_wait);
		return 1;
	}

	return error;
}

/**
 * inode_go_dump - print information about an inode
 * @seq: The iterator
 * @ip: the inode
 *
 */

static void inode_go_dump(struct seq_file *seq, const struct gfs2_glock *gl)
{
	const struct gfs2_inode *ip = gl->gl_object;
	if (ip == NULL)
		return;
	gfs2_print_dbg(seq, " I: n:%llu/%llu t:%u f:0x%02lx d:0x%08x s:%llu\n",
		  (unsigned long long)ip->i_no_formal_ino,
		  (unsigned long long)ip->i_no_addr,
		  IF2DT(ip->i_inode.i_mode), ip->i_flags,
		  (unsigned int)ip->i_diskflags,
		  (unsigned long long)i_size_read(&ip->i_inode));
}

/**
 * freeze_go_sync - promote/demote the freeze glock
 * @gl: the glock
 * @state: the requested state
 * @flags:
 *
 */

static void freeze_go_sync(struct gfs2_glock *gl)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	DEFINE_WAIT(wait);

	if (gl->gl_state == LM_ST_SHARED &&
	    test_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags)) {
		atomic_set(&sdp->sd_log_freeze, 1);
		wake_up(&sdp->sd_logd_waitq);
		do {
			prepare_to_wait(&sdp->sd_log_frozen_wait, &wait,
					TASK_UNINTERRUPTIBLE);
			if (atomic_read(&sdp->sd_log_freeze))
				io_schedule();
		} while(atomic_read(&sdp->sd_log_freeze));
		finish_wait(&sdp->sd_log_frozen_wait, &wait);
	}
}

/**
 * freeze_go_xmote_bh - After promoting/demoting the freeze glock
 * @gl: the glock
 *
 */

static int freeze_go_xmote_bh(struct gfs2_glock *gl, struct gfs2_holder *gh)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_inode *ip = GFS2_I(sdp->sd_jdesc->jd_inode);
	struct gfs2_glock *j_gl = ip->i_gl;
	struct gfs2_log_header_host head;
	int error;

	if (test_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags)) {
		j_gl->gl_ops->go_inval(j_gl, DIO_METADATA);

		error = gfs2_find_jhead(sdp->sd_jdesc, &head);
		if (error)
			gfs2_consist(sdp);
		if (!(head.lh_flags & GFS2_LOG_HEAD_UNMOUNT))
			gfs2_consist(sdp);

		/*  Initialize some head of the log stuff  */
		if (!test_bit(SDF_SHUTDOWN, &sdp->sd_flags)) {
			sdp->sd_log_sequence = head.lh_sequence + 1;
			gfs2_log_pointers_init(sdp, head.lh_blkno);
		}
	}
	return 0;
}

/**
 * trans_go_demote_ok
 * @gl: the glock
 *
 * Always returns 0
 */

static int freeze_go_demote_ok(const struct gfs2_glock *gl)
{
	return 0;
}

/**
 * iopen_go_callback - schedule the dcache entry for the inode to be deleted
 * @gl: the glock
 *
 * gl_spin lock is held while calling this
 */
static void iopen_go_callback(struct gfs2_glock *gl, bool remote)
{
	struct gfs2_inode *ip = (struct gfs2_inode *)gl->gl_object;
	struct gfs2_sbd *sdp = gl->gl_sbd;

	if (!remote || (sdp->sd_vfs->s_flags & MS_RDONLY))
		return;

	if (gl->gl_demote_state == LM_ST_UNLOCKED &&
	    gl->gl_state == LM_ST_SHARED && ip) {
		gl->gl_lockref.count++;
		if (queue_work(gfs2_delete_workqueue, &gl->gl_delete) == 0)
			gl->gl_lockref.count--;
	}
}

const struct gfs2_glock_operations gfs2_meta_glops = {
	.go_type = LM_TYPE_META,
};

const struct gfs2_glock_operations gfs2_inode_glops = {
	.go_sync = inode_go_sync,
	.go_inval = inode_go_inval,
	.go_demote_ok = inode_go_demote_ok,
	.go_lock = inode_go_lock,
	.go_dump = inode_go_dump,
	.go_type = LM_TYPE_INODE,
	.go_flags = GLOF_ASPACE,
};

const struct gfs2_glock_operations gfs2_rgrp_glops = {
	.go_sync = rgrp_go_sync,
	.go_inval = rgrp_go_inval,
	.go_lock = gfs2_rgrp_go_lock,
	.go_unlock = gfs2_rgrp_go_unlock,
	.go_dump = gfs2_rgrp_dump,
	.go_type = LM_TYPE_RGRP,
	.go_flags = GLOF_LVB,
};

const struct gfs2_glock_operations gfs2_freeze_glops = {
	.go_sync = freeze_go_sync,
	.go_xmote_bh = freeze_go_xmote_bh,
	.go_demote_ok = freeze_go_demote_ok,
	.go_type = LM_TYPE_NONDISK,
};

const struct gfs2_glock_operations gfs2_iopen_glops = {
	.go_type = LM_TYPE_IOPEN,
	.go_callback = iopen_go_callback,
};

const struct gfs2_glock_operations gfs2_flock_glops = {
	.go_type = LM_TYPE_FLOCK,
};

const struct gfs2_glock_operations gfs2_nondisk_glops = {
	.go_type = LM_TYPE_NONDISK,
};

const struct gfs2_glock_operations gfs2_quota_glops = {
	.go_type = LM_TYPE_QUOTA,
	.go_flags = GLOF_LVB,
};

const struct gfs2_glock_operations gfs2_journal_glops = {
	.go_type = LM_TYPE_JOURNAL,
};

const struct gfs2_glock_operations *gfs2_glops_list[] = {
	[LM_TYPE_META] = &gfs2_meta_glops,
	[LM_TYPE_INODE] = &gfs2_inode_glops,
	[LM_TYPE_RGRP] = &gfs2_rgrp_glops,
	[LM_TYPE_IOPEN] = &gfs2_iopen_glops,
	[LM_TYPE_FLOCK] = &gfs2_flock_glops,
	[LM_TYPE_NONDISK] = &gfs2_nondisk_glops,
	[LM_TYPE_QUOTA] = &gfs2_quota_glops,
	[LM_TYPE_JOURNAL] = &gfs2_journal_glops,
};
/************************************************************/
/* ../linux-3.17/fs/gfs2/log.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2007 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/crc32.h>
// #include <linux/delay.h>
// #include <linux/kthread.h>
// #include <linux/freezer.h>
// #include <linux/bio.h>
// #include <linux/blkdev.h>
#include <linux/writeback.h>
// #include <linux/list_sort.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "bmap.h"
// #include "glock.h"
// #include "log.h"
// #include "lops.h"
// #include "meta_io.h"
// #include "util.h"
// #include "dir.h"
// #include "trace_gfs2.h"

/**
 * gfs2_struct2blk - compute stuff
 * @sdp: the filesystem
 * @nstruct: the number of structures
 * @ssize: the size of the structures
 *
 * Compute the number of log descriptor blocks needed to hold a certain number
 * of structures of a certain size.
 *
 * Returns: the number of blocks needed (minimum is always 1)
 */

unsigned int gfs2_struct2blk(struct gfs2_sbd *sdp, unsigned int nstruct,
			     unsigned int ssize)
{
	unsigned int blks;
	unsigned int first, second;

	blks = 1;
	first = (sdp->sd_sb.sb_bsize - sizeof(struct gfs2_log_descriptor)) / ssize;

	if (nstruct > first) {
		second = (sdp->sd_sb.sb_bsize -
			  sizeof(struct gfs2_meta_header)) / ssize;
		blks += DIV_ROUND_UP(nstruct - first, second);
	}

	return blks;
}

/**
 * gfs2_remove_from_ail - Remove an entry from the ail lists, updating counters
 * @mapping: The associated mapping (maybe NULL)
 * @bd: The gfs2_bufdata to remove
 *
 * The ail lock _must_ be held when calling this function
 *
 */

void gfs2_remove_from_ail(struct gfs2_bufdata *bd)
{
	bd->bd_tr = NULL;
	list_del_init(&bd->bd_ail_st_list);
	list_del_init(&bd->bd_ail_gl_list);
	atomic_dec(&bd->bd_gl->gl_ail_count);
	brelse(bd->bd_bh);
}

/**
 * gfs2_ail1_start_one - Start I/O on a part of the AIL
 * @sdp: the filesystem
 * @wbc: The writeback control structure
 * @ai: The ail structure
 *
 */

static int gfs2_ail1_start_one(struct gfs2_sbd *sdp,
			       struct writeback_control *wbc,
			       struct gfs2_trans *tr)
__releases(&sdp->sd_ail_lock)
__acquires(&sdp->sd_ail_lock)
{
	struct gfs2_glock *gl = NULL;
	struct address_space *mapping;
	struct gfs2_bufdata *bd, *s;
	struct buffer_head *bh;

	list_for_each_entry_safe_reverse(bd, s, &tr->tr_ail1_list, bd_ail_st_list) {
		bh = bd->bd_bh;

		gfs2_assert(sdp, bd->bd_tr == tr);

		if (!buffer_busy(bh)) {
			if (!buffer_uptodate(bh))
				gfs2_io_error_bh(sdp, bh);
			list_move(&bd->bd_ail_st_list, &tr->tr_ail2_list);
			continue;
		}

		if (!buffer_dirty(bh))
			continue;
		if (gl == bd->bd_gl)
			continue;
		gl = bd->bd_gl;
		list_move(&bd->bd_ail_st_list, &tr->tr_ail1_list);
		mapping = bh->b_page->mapping;
		if (!mapping)
			continue;
		spin_unlock(&sdp->sd_ail_lock);
		generic_writepages(mapping, wbc);
		spin_lock(&sdp->sd_ail_lock);
		if (wbc->nr_to_write <= 0)
			break;
		return 1;
	}

	return 0;
}


/**
 * gfs2_ail1_flush - start writeback of some ail1 entries
 * @sdp: The super block
 * @wbc: The writeback control structure
 *
 * Writes back some ail1 entries, according to the limits in the
 * writeback control structure
 */

void gfs2_ail1_flush(struct gfs2_sbd *sdp, struct writeback_control *wbc)
{
	struct list_head *head = &sdp->sd_ail1_list;
	struct gfs2_trans *tr;
	struct blk_plug plug;

	trace_gfs2_ail_flush(sdp, wbc, 1);
	blk_start_plug(&plug);
	spin_lock(&sdp->sd_ail_lock);
restart:
	list_for_each_entry_reverse(tr, head, tr_list) {
		if (wbc->nr_to_write <= 0)
			break;
		if (gfs2_ail1_start_one(sdp, wbc, tr))
			goto restart;
	}
	spin_unlock(&sdp->sd_ail_lock);
	blk_finish_plug(&plug);
	trace_gfs2_ail_flush(sdp, wbc, 0);
}

/**
 * gfs2_ail1_start - start writeback of all ail1 entries
 * @sdp: The superblock
 */

static void gfs2_ail1_start(struct gfs2_sbd *sdp)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_NONE,
		.nr_to_write = LONG_MAX,
		.range_start = 0,
		.range_end = LLONG_MAX,
	};

	return gfs2_ail1_flush(sdp, &wbc);
}

/**
 * gfs2_ail1_empty_one - Check whether or not a trans in the AIL has been synced
 * @sdp: the filesystem
 * @ai: the AIL entry
 *
 */

static void gfs2_ail1_empty_one(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	struct gfs2_bufdata *bd, *s;
	struct buffer_head *bh;

	list_for_each_entry_safe_reverse(bd, s, &tr->tr_ail1_list,
					 bd_ail_st_list) {
		bh = bd->bd_bh;
		gfs2_assert(sdp, bd->bd_tr == tr);
		if (buffer_busy(bh))
			continue;
		if (!buffer_uptodate(bh))
			gfs2_io_error_bh(sdp, bh);
		list_move(&bd->bd_ail_st_list, &tr->tr_ail2_list);
	}

}

/**
 * gfs2_ail1_empty - Try to empty the ail1 lists
 * @sdp: The superblock
 *
 * Tries to empty the ail1 lists, starting with the oldest first
 */

static int gfs2_ail1_empty(struct gfs2_sbd *sdp)
{
	struct gfs2_trans *tr, *s;
	int oldest_tr = 1;
	int ret;

	spin_lock(&sdp->sd_ail_lock);
	list_for_each_entry_safe_reverse(tr, s, &sdp->sd_ail1_list, tr_list) {
		gfs2_ail1_empty_one(sdp, tr);
		if (list_empty(&tr->tr_ail1_list) && oldest_tr)
			list_move(&tr->tr_list, &sdp->sd_ail2_list);
		else
			oldest_tr = 0;
	}
	ret = list_empty(&sdp->sd_ail1_list);
	spin_unlock(&sdp->sd_ail_lock);

	return ret;
}

static void gfs2_ail1_wait(struct gfs2_sbd *sdp)
{
	struct gfs2_trans *tr;
	struct gfs2_bufdata *bd;
	struct buffer_head *bh;

	spin_lock(&sdp->sd_ail_lock);
	list_for_each_entry_reverse(tr, &sdp->sd_ail1_list, tr_list) {
		list_for_each_entry(bd, &tr->tr_ail1_list, bd_ail_st_list) {
			bh = bd->bd_bh;
			if (!buffer_locked(bh))
				continue;
			get_bh(bh);
			spin_unlock(&sdp->sd_ail_lock);
			wait_on_buffer(bh);
			brelse(bh);
			return;
		}
	}
	spin_unlock(&sdp->sd_ail_lock);
}

/**
 * gfs2_ail2_empty_one - Check whether or not a trans in the AIL has been synced
 * @sdp: the filesystem
 * @ai: the AIL entry
 *
 */

static void gfs2_ail2_empty_one(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	struct list_head *head = &tr->tr_ail2_list;
	struct gfs2_bufdata *bd;

	while (!list_empty(head)) {
		bd = list_entry(head->prev, struct gfs2_bufdata,
				bd_ail_st_list);
		gfs2_assert(sdp, bd->bd_tr == tr);
		gfs2_remove_from_ail(bd);
	}
}

static void ail2_empty(struct gfs2_sbd *sdp, unsigned int new_tail)
{
	struct gfs2_trans *tr, *safe;
	unsigned int old_tail = sdp->sd_log_tail;
	int wrap = (new_tail < old_tail);
	int a, b, rm;

	spin_lock(&sdp->sd_ail_lock);

	list_for_each_entry_safe(tr, safe, &sdp->sd_ail2_list, tr_list) {
		a = (old_tail <= tr->tr_first);
		b = (tr->tr_first < new_tail);
		rm = (wrap) ? (a || b) : (a && b);
		if (!rm)
			continue;

		gfs2_ail2_empty_one(sdp, tr);
		list_del(&tr->tr_list);
		gfs2_assert_warn(sdp, list_empty(&tr->tr_ail1_list));
		gfs2_assert_warn(sdp, list_empty(&tr->tr_ail2_list));
		kfree(tr);
	}

	spin_unlock(&sdp->sd_ail_lock);
}

/**
 * gfs2_log_release - Release a given number of log blocks
 * @sdp: The GFS2 superblock
 * @blks: The number of blocks
 *
 */

void gfs2_log_release(struct gfs2_sbd *sdp, unsigned int blks)
{

	atomic_add(blks, &sdp->sd_log_blks_free);
	trace_gfs2_log_blocks(sdp, blks);
	gfs2_assert_withdraw(sdp, atomic_read(&sdp->sd_log_blks_free) <=
				  sdp->sd_jdesc->jd_blocks);
	up_read(&sdp->sd_log_flush_lock);
}

/**
 * gfs2_log_reserve - Make a log reservation
 * @sdp: The GFS2 superblock
 * @blks: The number of blocks to reserve
 *
 * Note that we never give out the last few blocks of the journal. Thats
 * due to the fact that there is a small number of header blocks
 * associated with each log flush. The exact number can't be known until
 * flush time, so we ensure that we have just enough free blocks at all
 * times to avoid running out during a log flush.
 *
 * We no longer flush the log here, instead we wake up logd to do that
 * for us. To avoid the thundering herd and to ensure that we deal fairly
 * with queued waiters, we use an exclusive wait. This means that when we
 * get woken with enough journal space to get our reservation, we need to
 * wake the next waiter on the list.
 *
 * Returns: errno
 */

int gfs2_log_reserve(struct gfs2_sbd *sdp, unsigned int blks)
{
	unsigned reserved_blks = 7 * (4096 / sdp->sd_vfs->s_blocksize);
	unsigned wanted = blks + reserved_blks;
	DEFINE_WAIT(wait);
	int did_wait = 0;
	unsigned int free_blocks;

	if (gfs2_assert_warn(sdp, blks) ||
	    gfs2_assert_warn(sdp, blks <= sdp->sd_jdesc->jd_blocks))
		return -EINVAL;
retry:
	free_blocks = atomic_read(&sdp->sd_log_blks_free);
	if (unlikely(free_blocks <= wanted)) {
		do {
			prepare_to_wait_exclusive(&sdp->sd_log_waitq, &wait,
					TASK_UNINTERRUPTIBLE);
			wake_up(&sdp->sd_logd_waitq);
			did_wait = 1;
			if (atomic_read(&sdp->sd_log_blks_free) <= wanted)
				io_schedule();
			free_blocks = atomic_read(&sdp->sd_log_blks_free);
		} while(free_blocks <= wanted);
		finish_wait(&sdp->sd_log_waitq, &wait);
	}
	if (atomic_cmpxchg(&sdp->sd_log_blks_free, free_blocks,
				free_blocks - blks) != free_blocks)
		goto retry;
	trace_gfs2_log_blocks(sdp, -blks);

	/*
	 * If we waited, then so might others, wake them up _after_ we get
	 * our share of the log.
	 */
	if (unlikely(did_wait))
		wake_up(&sdp->sd_log_waitq);

	down_read(&sdp->sd_log_flush_lock);
	if (unlikely(!test_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags))) {
		gfs2_log_release(sdp, blks);
		return -EROFS;
	}
	return 0;
}

/**
 * log_distance - Compute distance between two journal blocks
 * @sdp: The GFS2 superblock
 * @newer: The most recent journal block of the pair
 * @older: The older journal block of the pair
 *
 *   Compute the distance (in the journal direction) between two
 *   blocks in the journal
 *
 * Returns: the distance in blocks
 */

static inline unsigned int log_distance(struct gfs2_sbd *sdp, unsigned int newer,
					unsigned int older)
{
	int dist;

	dist = newer - older;
	if (dist < 0)
		dist += sdp->sd_jdesc->jd_blocks;

	return dist;
}

/**
 * calc_reserved - Calculate the number of blocks to reserve when
 *                 refunding a transaction's unused buffers.
 * @sdp: The GFS2 superblock
 *
 * This is complex.  We need to reserve room for all our currently used
 * metadata buffers (e.g. normal file I/O rewriting file time stamps) and
 * all our journaled data buffers for journaled files (e.g. files in the
 * meta_fs like rindex, or files for which chattr +j was done.)
 * If we don't reserve enough space, gfs2_log_refund and gfs2_log_flush
 * will count it as free space (sd_log_blks_free) and corruption will follow.
 *
 * We can have metadata bufs and jdata bufs in the same journal.  So each
 * type gets its own log header, for which we need to reserve a block.
 * In fact, each type has the potential for needing more than one header
 * in cases where we have more buffers than will fit on a journal page.
 * Metadata journal entries take up half the space of journaled buffer entries.
 * Thus, metadata entries have buf_limit (502) and journaled buffers have
 * databuf_limit (251) before they cause a wrap around.
 *
 * Also, we need to reserve blocks for revoke journal entries and one for an
 * overall header for the lot.
 *
 * Returns: the number of blocks reserved
 */
static unsigned int calc_reserved(struct gfs2_sbd *sdp)
{
	unsigned int reserved = 0;
	unsigned int mbuf;
	unsigned int dbuf;
	struct gfs2_trans *tr = sdp->sd_log_tr;

	if (tr) {
		mbuf = tr->tr_num_buf_new - tr->tr_num_buf_rm;
		dbuf = tr->tr_num_databuf_new - tr->tr_num_databuf_rm;
		reserved = mbuf + dbuf;
		/* Account for header blocks */
		reserved += DIV_ROUND_UP(mbuf, buf_limit(sdp));
		reserved += DIV_ROUND_UP(dbuf, databuf_limit(sdp));
	}

	if (sdp->sd_log_commited_revoke > 0)
		reserved += gfs2_struct2blk(sdp, sdp->sd_log_commited_revoke,
					  sizeof(u64));
	/* One for the overall header */
	if (reserved)
		reserved++;
	return reserved;
}

static unsigned int current_tail(struct gfs2_sbd *sdp)
{
	struct gfs2_trans *tr;
	unsigned int tail;

	spin_lock(&sdp->sd_ail_lock);

	if (list_empty(&sdp->sd_ail1_list)) {
		tail = sdp->sd_log_head;
	} else {
		tr = list_entry(sdp->sd_ail1_list.prev, struct gfs2_trans,
				tr_list);
		tail = tr->tr_first;
	}

	spin_unlock(&sdp->sd_ail_lock);

	return tail;
}

static void log_pull_tail(struct gfs2_sbd *sdp, unsigned int new_tail)
{
	unsigned int dist = log_distance(sdp, new_tail, sdp->sd_log_tail);

	ail2_empty(sdp, new_tail);

	atomic_add(dist, &sdp->sd_log_blks_free);
	trace_gfs2_log_blocks(sdp, dist);
	gfs2_assert_withdraw(sdp, atomic_read(&sdp->sd_log_blks_free) <=
			     sdp->sd_jdesc->jd_blocks);

	sdp->sd_log_tail = new_tail;
}


static void log_flush_wait(struct gfs2_sbd *sdp)
{
	DEFINE_WAIT(wait);

	if (atomic_read(&sdp->sd_log_in_flight)) {
		do {
			prepare_to_wait(&sdp->sd_log_flush_wait, &wait,
					TASK_UNINTERRUPTIBLE);
			if (atomic_read(&sdp->sd_log_in_flight))
				io_schedule();
		} while(atomic_read(&sdp->sd_log_in_flight));
		finish_wait(&sdp->sd_log_flush_wait, &wait);
	}
}

static int ip_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct gfs2_inode *ipa, *ipb;

	ipa = list_entry(a, struct gfs2_inode, i_ordered);
	ipb = list_entry(b, struct gfs2_inode, i_ordered);

	if (ipa->i_no_addr < ipb->i_no_addr)
		return -1;
	if (ipa->i_no_addr > ipb->i_no_addr)
		return 1;
	return 0;
}

static void gfs2_ordered_write(struct gfs2_sbd *sdp)
{
	struct gfs2_inode *ip;
	LIST_HEAD(written);

	spin_lock(&sdp->sd_ordered_lock);
	list_sort(NULL, &sdp->sd_log_le_ordered, &ip_cmp);
	while (!list_empty(&sdp->sd_log_le_ordered)) {
		ip = list_entry(sdp->sd_log_le_ordered.next, struct gfs2_inode, i_ordered);
		list_move(&ip->i_ordered, &written);
		if (ip->i_inode.i_mapping->nrpages == 0)
			continue;
		spin_unlock(&sdp->sd_ordered_lock);
		filemap_fdatawrite(ip->i_inode.i_mapping);
		spin_lock(&sdp->sd_ordered_lock);
	}
	list_splice(&written, &sdp->sd_log_le_ordered);
	spin_unlock(&sdp->sd_ordered_lock);
}

static void gfs2_ordered_wait(struct gfs2_sbd *sdp)
{
	struct gfs2_inode *ip;

	spin_lock(&sdp->sd_ordered_lock);
	while (!list_empty(&sdp->sd_log_le_ordered)) {
		ip = list_entry(sdp->sd_log_le_ordered.next, struct gfs2_inode, i_ordered);
		list_del(&ip->i_ordered);
		WARN_ON(!test_and_clear_bit(GIF_ORDERED, &ip->i_flags));
		if (ip->i_inode.i_mapping->nrpages == 0)
			continue;
		spin_unlock(&sdp->sd_ordered_lock);
		filemap_fdatawait(ip->i_inode.i_mapping);
		spin_lock(&sdp->sd_ordered_lock);
	}
	spin_unlock(&sdp->sd_ordered_lock);
}

void gfs2_ordered_del_inode(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);

	spin_lock(&sdp->sd_ordered_lock);
	if (test_and_clear_bit(GIF_ORDERED, &ip->i_flags))
		list_del(&ip->i_ordered);
	spin_unlock(&sdp->sd_ordered_lock);
}

void gfs2_add_revoke(struct gfs2_sbd *sdp, struct gfs2_bufdata *bd)
{
	struct buffer_head *bh = bd->bd_bh;
	struct gfs2_glock *gl = bd->bd_gl;

	bh->b_private = NULL;
	bd->bd_blkno = bh->b_blocknr;
	gfs2_remove_from_ail(bd); /* drops ref on bh */
	bd->bd_bh = NULL;
	bd->bd_ops = &gfs2_revoke_lops;
	sdp->sd_log_num_revoke++;
	atomic_inc(&gl->gl_revokes);
	set_bit(GLF_LFLUSH, &gl->gl_flags);
	list_add(&bd->bd_list, &sdp->sd_log_le_revoke);
}

void gfs2_write_revokes(struct gfs2_sbd *sdp)
{
	struct gfs2_trans *tr;
	struct gfs2_bufdata *bd, *tmp;
	int have_revokes = 0;
	int max_revokes = (sdp->sd_sb.sb_bsize - sizeof(struct gfs2_log_descriptor)) / sizeof(u64);

	gfs2_ail1_empty(sdp);
	spin_lock(&sdp->sd_ail_lock);
	list_for_each_entry(tr, &sdp->sd_ail1_list, tr_list) {
		list_for_each_entry(bd, &tr->tr_ail2_list, bd_ail_st_list) {
			if (list_empty(&bd->bd_list)) {
				have_revokes = 1;
				goto done;
			}
		}
	}
done:
	spin_unlock(&sdp->sd_ail_lock);
	if (have_revokes == 0)
		return;
	while (sdp->sd_log_num_revoke > max_revokes)
		max_revokes += (sdp->sd_sb.sb_bsize - sizeof(struct gfs2_meta_header)) / sizeof(u64);
	max_revokes -= sdp->sd_log_num_revoke;
	if (!sdp->sd_log_num_revoke) {
		atomic_dec(&sdp->sd_log_blks_free);
		/* If no blocks have been reserved, we need to also
		 * reserve a block for the header */
		if (!sdp->sd_log_blks_reserved)
			atomic_dec(&sdp->sd_log_blks_free);
	}
	gfs2_log_lock(sdp);
	spin_lock(&sdp->sd_ail_lock);
	list_for_each_entry(tr, &sdp->sd_ail1_list, tr_list) {
		list_for_each_entry_safe(bd, tmp, &tr->tr_ail2_list, bd_ail_st_list) {
			if (max_revokes == 0)
				goto out_of_blocks;
			if (!list_empty(&bd->bd_list))
				continue;
			gfs2_add_revoke(sdp, bd);
			max_revokes--;
		}
	}
out_of_blocks:
	spin_unlock(&sdp->sd_ail_lock);
	gfs2_log_unlock(sdp);

	if (!sdp->sd_log_num_revoke) {
		atomic_inc(&sdp->sd_log_blks_free);
		if (!sdp->sd_log_blks_reserved)
			atomic_inc(&sdp->sd_log_blks_free);
	}
}

/**
 * log_write_header - Get and initialize a journal header buffer
 * @sdp: The GFS2 superblock
 *
 * Returns: the initialized log buffer descriptor
 */

static void log_write_header(struct gfs2_sbd *sdp, u32 flags)
{
	struct gfs2_log_header *lh;
	unsigned int tail;
	u32 hash;
	int rw = WRITE_FLUSH_FUA | REQ_META;
	struct page *page = mempool_alloc(gfs2_page_pool, GFP_NOIO);
	lh = page_address(page);
	clear_page(lh);

	tail = current_tail(sdp);

	lh->lh_header.mh_magic = cpu_to_be32(GFS2_MAGIC);
	lh->lh_header.mh_type = cpu_to_be32(GFS2_METATYPE_LH);
	lh->lh_header.__pad0 = cpu_to_be64(0);
	lh->lh_header.mh_format = cpu_to_be32(GFS2_FORMAT_LH);
	lh->lh_header.mh_jid = cpu_to_be32(sdp->sd_jdesc->jd_jid);
	lh->lh_sequence = cpu_to_be64(sdp->sd_log_sequence++);
	lh->lh_flags = cpu_to_be32(flags);
	lh->lh_tail = cpu_to_be32(tail);
	lh->lh_blkno = cpu_to_be32(sdp->sd_log_flush_head);
	hash = gfs2_disk_hash(page_address(page), sizeof(struct gfs2_log_header));
	lh->lh_hash = cpu_to_be32(hash);

	if (test_bit(SDF_NOBARRIERS, &sdp->sd_flags)) {
		gfs2_ordered_wait(sdp);
		log_flush_wait(sdp);
		rw = WRITE_SYNC | REQ_META | REQ_PRIO;
	}

	sdp->sd_log_idle = (tail == sdp->sd_log_flush_head);
	gfs2_log_write_page(sdp, page);
	gfs2_log_flush_bio(sdp, rw);
	log_flush_wait(sdp);

	if (sdp->sd_log_tail != tail)
		log_pull_tail(sdp, tail);
}

/**
 * gfs2_log_flush - flush incore transaction(s)
 * @sdp: the filesystem
 * @gl: The glock structure to flush.  If NULL, flush the whole incore log
 *
 */

void gfs2_log_flush(struct gfs2_sbd *sdp, struct gfs2_glock *gl,
		    enum gfs2_flush_type type)
{
	struct gfs2_trans *tr;

	down_write(&sdp->sd_log_flush_lock);

	/* Log might have been flushed while we waited for the flush lock */
	if (gl && !test_bit(GLF_LFLUSH, &gl->gl_flags)) {
		up_write(&sdp->sd_log_flush_lock);
		return;
	}
	trace_gfs2_log_flush(sdp, 1);

	sdp->sd_log_flush_head = sdp->sd_log_head;
	sdp->sd_log_flush_wrapped = 0;
	tr = sdp->sd_log_tr;
	if (tr) {
		sdp->sd_log_tr = NULL;
		INIT_LIST_HEAD(&tr->tr_ail1_list);
		INIT_LIST_HEAD(&tr->tr_ail2_list);
		tr->tr_first = sdp->sd_log_flush_head;
	}

	gfs2_assert_withdraw(sdp,
			sdp->sd_log_num_revoke == sdp->sd_log_commited_revoke);

	gfs2_ordered_write(sdp);
	lops_before_commit(sdp, tr);
	gfs2_log_flush_bio(sdp, WRITE);

	if (sdp->sd_log_head != sdp->sd_log_flush_head) {
		log_flush_wait(sdp);
		log_write_header(sdp, 0);
	} else if (sdp->sd_log_tail != current_tail(sdp) && !sdp->sd_log_idle){
		atomic_dec(&sdp->sd_log_blks_free); /* Adjust for unreserved buffer */
		trace_gfs2_log_blocks(sdp, -1);
		log_write_header(sdp, 0);
	}
	lops_after_commit(sdp, tr);

	gfs2_log_lock(sdp);
	sdp->sd_log_head = sdp->sd_log_flush_head;
	sdp->sd_log_blks_reserved = 0;
	sdp->sd_log_commited_revoke = 0;

	spin_lock(&sdp->sd_ail_lock);
	if (tr && !list_empty(&tr->tr_ail1_list)) {
		list_add(&tr->tr_list, &sdp->sd_ail1_list);
		tr = NULL;
	}
	spin_unlock(&sdp->sd_ail_lock);
	gfs2_log_unlock(sdp);

	if (atomic_read(&sdp->sd_log_freeze))
		type = FREEZE_FLUSH;
	if (type != NORMAL_FLUSH) {
		if (!sdp->sd_log_idle) {
			for (;;) {
				gfs2_ail1_start(sdp);
				gfs2_ail1_wait(sdp);
				if (gfs2_ail1_empty(sdp))
					break;
			}
			atomic_dec(&sdp->sd_log_blks_free); /* Adjust for unreserved buffer */
			trace_gfs2_log_blocks(sdp, -1);
			sdp->sd_log_flush_wrapped = 0;
			log_write_header(sdp, 0);
			sdp->sd_log_head = sdp->sd_log_flush_head;
		}
		if (type == SHUTDOWN_FLUSH || type == FREEZE_FLUSH)
			gfs2_log_shutdown(sdp);
		if (type == FREEZE_FLUSH) {
			int error;

			atomic_set(&sdp->sd_log_freeze, 0);
			wake_up(&sdp->sd_log_frozen_wait);
			error = gfs2_glock_nq_init(sdp->sd_freeze_gl,
						   LM_ST_SHARED, 0,
						   &sdp->sd_thaw_gh);
			if (error) {
				printk(KERN_INFO "GFS2: couln't get freeze lock : %d\n", error);
				gfs2_assert_withdraw(sdp, 0);
			}
			else
				gfs2_glock_dq_uninit(&sdp->sd_thaw_gh);
		}
	}

	trace_gfs2_log_flush(sdp, 0);
	up_write(&sdp->sd_log_flush_lock);

	kfree(tr);
}

/**
 * gfs2_merge_trans - Merge a new transaction into a cached transaction
 * @old: Original transaction to be expanded
 * @new: New transaction to be merged
 */

static void gfs2_merge_trans(struct gfs2_trans *old, struct gfs2_trans *new)
{
	WARN_ON_ONCE(old->tr_attached != 1);

	old->tr_num_buf_new	+= new->tr_num_buf_new;
	old->tr_num_databuf_new	+= new->tr_num_databuf_new;
	old->tr_num_buf_rm	+= new->tr_num_buf_rm;
	old->tr_num_databuf_rm	+= new->tr_num_databuf_rm;
	old->tr_num_revoke	+= new->tr_num_revoke;
	old->tr_num_revoke_rm	+= new->tr_num_revoke_rm;

	list_splice_tail_init(&new->tr_databuf, &old->tr_databuf);
	list_splice_tail_init(&new->tr_buf, &old->tr_buf);
}

static void log_refund(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	unsigned int reserved;
	unsigned int unused;
	unsigned int maxres;

	gfs2_log_lock(sdp);

	if (sdp->sd_log_tr) {
		gfs2_merge_trans(sdp->sd_log_tr, tr);
	} else if (tr->tr_num_buf_new || tr->tr_num_databuf_new) {
		gfs2_assert_withdraw(sdp, tr->tr_alloced);
		sdp->sd_log_tr = tr;
		tr->tr_attached = 1;
	}

	sdp->sd_log_commited_revoke += tr->tr_num_revoke - tr->tr_num_revoke_rm;
	reserved = calc_reserved(sdp);
	maxres = sdp->sd_log_blks_reserved + tr->tr_reserved;
	gfs2_assert_withdraw(sdp, maxres >= reserved);
	unused = maxres - reserved;
	atomic_add(unused, &sdp->sd_log_blks_free);
	trace_gfs2_log_blocks(sdp, unused);
	gfs2_assert_withdraw(sdp, atomic_read(&sdp->sd_log_blks_free) <=
			     sdp->sd_jdesc->jd_blocks);
	sdp->sd_log_blks_reserved = reserved;

	gfs2_log_unlock(sdp);
}

/**
 * gfs2_log_commit - Commit a transaction to the log
 * @sdp: the filesystem
 * @tr: the transaction
 *
 * We wake up gfs2_logd if the number of pinned blocks exceed thresh1
 * or the total number of used blocks (pinned blocks plus AIL blocks)
 * is greater than thresh2.
 *
 * At mount time thresh1 is 1/3rd of journal size, thresh2 is 2/3rd of
 * journal size.
 *
 * Returns: errno
 */

void gfs2_log_commit(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	log_refund(sdp, tr);

	if (atomic_read(&sdp->sd_log_pinned) > atomic_read(&sdp->sd_log_thresh1) ||
	    ((sdp->sd_jdesc->jd_blocks - atomic_read(&sdp->sd_log_blks_free)) >
	    atomic_read(&sdp->sd_log_thresh2)))
		wake_up(&sdp->sd_logd_waitq);
}

/**
 * gfs2_log_shutdown - write a shutdown header into a journal
 * @sdp: the filesystem
 *
 */

void gfs2_log_shutdown(struct gfs2_sbd *sdp)
{
	gfs2_assert_withdraw(sdp, !sdp->sd_log_blks_reserved);
	gfs2_assert_withdraw(sdp, !sdp->sd_log_num_revoke);
	gfs2_assert_withdraw(sdp, list_empty(&sdp->sd_ail1_list));

	sdp->sd_log_flush_head = sdp->sd_log_head;
	sdp->sd_log_flush_wrapped = 0;

	log_write_header(sdp, GFS2_LOG_HEAD_UNMOUNT);

	gfs2_assert_warn(sdp, sdp->sd_log_head == sdp->sd_log_tail);
	gfs2_assert_warn(sdp, list_empty(&sdp->sd_ail2_list));

	sdp->sd_log_head = sdp->sd_log_flush_head;
	sdp->sd_log_tail = sdp->sd_log_head;
}

static inline int gfs2_jrnl_flush_reqd(struct gfs2_sbd *sdp)
{
	return (atomic_read(&sdp->sd_log_pinned) >= atomic_read(&sdp->sd_log_thresh1) || atomic_read(&sdp->sd_log_freeze));
}

static inline int gfs2_ail_flush_reqd(struct gfs2_sbd *sdp)
{
	unsigned int used_blocks = sdp->sd_jdesc->jd_blocks - atomic_read(&sdp->sd_log_blks_free);
	return used_blocks >= atomic_read(&sdp->sd_log_thresh2);
}

/**
 * gfs2_logd - Update log tail as Active Items get flushed to in-place blocks
 * @sdp: Pointer to GFS2 superblock
 *
 * Also, periodically check to make sure that we're using the most recent
 * journal index.
 */

int gfs2_logd(void *data)
{
	struct gfs2_sbd *sdp = data;
	unsigned long t = 1;
	DEFINE_WAIT(wait);

	while (!kthread_should_stop()) {

		if (gfs2_jrnl_flush_reqd(sdp) || t == 0) {
			gfs2_ail1_empty(sdp);
			gfs2_log_flush(sdp, NULL, NORMAL_FLUSH);
		}

		if (gfs2_ail_flush_reqd(sdp)) {
			gfs2_ail1_start(sdp);
			gfs2_ail1_wait(sdp);
			gfs2_ail1_empty(sdp);
			gfs2_log_flush(sdp, NULL, NORMAL_FLUSH);
		}

		if (!gfs2_ail_flush_reqd(sdp))
			wake_up(&sdp->sd_log_waitq);

		t = gfs2_tune_get(sdp, gt_logd_secs) * HZ;

		try_to_freeze();

		do {
			prepare_to_wait(&sdp->sd_logd_waitq, &wait,
					TASK_INTERRUPTIBLE);
			if (!gfs2_ail_flush_reqd(sdp) &&
			    !gfs2_jrnl_flush_reqd(sdp) &&
			    !kthread_should_stop())
				t = schedule_timeout(t);
		} while(t && !gfs2_ail_flush_reqd(sdp) &&
			!gfs2_jrnl_flush_reqd(sdp) &&
			!kthread_should_stop());
		finish_wait(&sdp->sd_logd_waitq, &wait);
	}

	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/lops.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
#include <linux/mempool.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/bio.h>
#include <linux/fs.h>
// #include <linux/list_sort.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "inode.h"
// #include "glock.h"
// #include "log.h"
// #include "lops.h"
// #include "meta_io.h"
// #include "recovery.h"
// #include "rgrp.h"
// #include "trans.h"
// #include "util.h"
// #include "trace_gfs2.h"

/**
 * gfs2_pin - Pin a buffer in memory
 * @sdp: The superblock
 * @bh: The buffer to be pinned
 *
 * The log lock must be held when calling this function
 */
void gfs2_pin(struct gfs2_sbd *sdp, struct buffer_head *bh)
{
	struct gfs2_bufdata *bd;

	BUG_ON(!current->journal_info);

	clear_buffer_dirty(bh);
	if (test_set_buffer_pinned(bh))
		gfs2_assert_withdraw(sdp, 0);
	if (!buffer_uptodate(bh))
		gfs2_io_error_bh(sdp, bh);
	bd = bh->b_private;
	/* If this buffer is in the AIL and it has already been written
	 * to in-place disk block, remove it from the AIL.
	 */
	spin_lock(&sdp->sd_ail_lock);
	if (bd->bd_tr)
		list_move(&bd->bd_ail_st_list, &bd->bd_tr->tr_ail2_list);
	spin_unlock(&sdp->sd_ail_lock);
	get_bh(bh);
	atomic_inc(&sdp->sd_log_pinned);
	trace_gfs2_pin(bd, 1);
}

static bool buffer_is_rgrp(const struct gfs2_bufdata *bd)
{
	return bd->bd_gl->gl_name.ln_type == LM_TYPE_RGRP;
}

static void maybe_release_space(struct gfs2_bufdata *bd)
{
	struct gfs2_glock *gl = bd->bd_gl;
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_rgrpd *rgd = gl->gl_object;
	unsigned int index = bd->bd_bh->b_blocknr - gl->gl_name.ln_number;
	struct gfs2_bitmap *bi = rgd->rd_bits + index;

	if (bi->bi_clone == NULL)
		return;
	if (sdp->sd_args.ar_discard)
		gfs2_rgrp_send_discards(sdp, rgd->rd_data0, bd->bd_bh, bi, 1, NULL);
	memcpy(bi->bi_clone + bi->bi_offset,
	       bd->bd_bh->b_data + bi->bi_offset, bi->bi_len);
	clear_bit(GBF_FULL, &bi->bi_flags);
	rgd->rd_free_clone = rgd->rd_free;
	rgd->rd_extfail_pt = rgd->rd_free;
}

/**
 * gfs2_unpin - Unpin a buffer
 * @sdp: the filesystem the buffer belongs to
 * @bh: The buffer to unpin
 * @ai:
 * @flags: The inode dirty flags
 *
 */

static void gfs2_unpin(struct gfs2_sbd *sdp, struct buffer_head *bh,
		       struct gfs2_trans *tr)
{
	struct gfs2_bufdata *bd = bh->b_private;

	BUG_ON(!buffer_uptodate(bh));
	BUG_ON(!buffer_pinned(bh));

	lock_buffer(bh);
	mark_buffer_dirty(bh);
	clear_buffer_pinned(bh);

	if (buffer_is_rgrp(bd))
		maybe_release_space(bd);

	spin_lock(&sdp->sd_ail_lock);
	if (bd->bd_tr) {
		list_del(&bd->bd_ail_st_list);
		brelse(bh);
	} else {
		struct gfs2_glock *gl = bd->bd_gl;
		list_add(&bd->bd_ail_gl_list, &gl->gl_ail_list);
		atomic_inc(&gl->gl_ail_count);
	}
	bd->bd_tr = tr;
	list_add(&bd->bd_ail_st_list, &tr->tr_ail1_list);
	spin_unlock(&sdp->sd_ail_lock);

	clear_bit(GLF_LFLUSH, &bd->bd_gl->gl_flags);
	trace_gfs2_pin(bd, 0);
	unlock_buffer(bh);
	atomic_dec(&sdp->sd_log_pinned);
}

static void gfs2_log_incr_head(struct gfs2_sbd *sdp)
{
	BUG_ON((sdp->sd_log_flush_head == sdp->sd_log_tail) &&
	       (sdp->sd_log_flush_head != sdp->sd_log_head));

	if (++sdp->sd_log_flush_head == sdp->sd_jdesc->jd_blocks) {
		sdp->sd_log_flush_head = 0;
		sdp->sd_log_flush_wrapped = 1;
	}
}

static u64 gfs2_log_bmap(struct gfs2_sbd *sdp)
{
	unsigned int lbn = sdp->sd_log_flush_head;
	struct gfs2_journal_extent *je;
	u64 block;

	list_for_each_entry(je, &sdp->sd_jdesc->extent_list, list) {
		if ((lbn >= je->lblock) && (lbn < (je->lblock + je->blocks))) {
			block = je->dblock + lbn - je->lblock;
			gfs2_log_incr_head(sdp);
			return block;
		}
	}

	return -1;
}

/**
 * gfs2_end_log_write_bh - end log write of pagecache data with buffers
 * @sdp: The superblock
 * @bvec: The bio_vec
 * @error: The i/o status
 *
 * This finds the relavent buffers and unlocks then and sets the
 * error flag according to the status of the i/o request. This is
 * used when the log is writing data which has an in-place version
 * that is pinned in the pagecache.
 */

static void gfs2_end_log_write_bh(struct gfs2_sbd *sdp, struct bio_vec *bvec,
				  int error)
{
	struct buffer_head *bh, *next;
	struct page *page = bvec->bv_page;
	unsigned size;

	bh = page_buffers(page);
	size = bvec->bv_len;
	while (bh_offset(bh) < bvec->bv_offset)
		bh = bh->b_this_page;
	do {
		if (error)
			set_buffer_write_io_error(bh);
		unlock_buffer(bh);
		next = bh->b_this_page;
		size -= bh->b_size;
		brelse(bh);
		bh = next;
	} while(bh && size);
}

/**
 * gfs2_end_log_write - end of i/o to the log
 * @bio: The bio
 * @error: Status of i/o request
 *
 * Each bio_vec contains either data from the pagecache or data
 * relating to the log itself. Here we iterate over the bio_vec
 * array, processing both kinds of data.
 *
 */

static void gfs2_end_log_write(struct bio *bio, int error)
{
	struct gfs2_sbd *sdp = bio->bi_private;
	struct bio_vec *bvec;
	struct page *page;
	int i;

	if (error) {
		sdp->sd_log_error = error;
		fs_err(sdp, "Error %d writing to log\n", error);
	}

	bio_for_each_segment_all(bvec, bio, i) {
		page = bvec->bv_page;
		if (page_has_buffers(page))
			gfs2_end_log_write_bh(sdp, bvec, error);
		else
			mempool_free(page, gfs2_page_pool);
	}

	bio_put(bio);
	if (atomic_dec_and_test(&sdp->sd_log_in_flight))
		wake_up(&sdp->sd_log_flush_wait);
}

/**
 * gfs2_log_flush_bio - Submit any pending log bio
 * @sdp: The superblock
 * @rw: The rw flags
 *
 * Submit any pending part-built or full bio to the block device. If
 * there is no pending bio, then this is a no-op.
 */

void gfs2_log_flush_bio(struct gfs2_sbd *sdp, int rw)
{
	if (sdp->sd_log_bio) {
		atomic_inc(&sdp->sd_log_in_flight);
		submit_bio(rw, sdp->sd_log_bio);
		sdp->sd_log_bio = NULL;
	}
}

/**
 * gfs2_log_alloc_bio - Allocate a new bio for log writing
 * @sdp: The superblock
 * @blkno: The next device block number we want to write to
 *
 * This should never be called when there is a cached bio in the
 * super block. When it returns, there will be a cached bio in the
 * super block which will have as many bio_vecs as the device is
 * happy to handle.
 *
 * Returns: Newly allocated bio
 */

static struct bio *gfs2_log_alloc_bio(struct gfs2_sbd *sdp, u64 blkno)
{
	struct super_block *sb = sdp->sd_vfs;
	unsigned nrvecs = bio_get_nr_vecs(sb->s_bdev);
	struct bio *bio;

	BUG_ON(sdp->sd_log_bio);

	while (1) {
		bio = bio_alloc(GFP_NOIO, nrvecs);
		if (likely(bio))
			break;
		nrvecs = max(nrvecs/2, 1U);
	}

	bio->bi_iter.bi_sector = blkno * (sb->s_blocksize >> 9);
	bio->bi_bdev = sb->s_bdev;
	bio->bi_end_io = gfs2_end_log_write;
	bio->bi_private = sdp;

	sdp->sd_log_bio = bio;

	return bio;
}

/**
 * gfs2_log_get_bio - Get cached log bio, or allocate a new one
 * @sdp: The superblock
 * @blkno: The device block number we want to write to
 *
 * If there is a cached bio, then if the next block number is sequential
 * with the previous one, return it, otherwise flush the bio to the
 * device. If there is not a cached bio, or we just flushed it, then
 * allocate a new one.
 *
 * Returns: The bio to use for log writes
 */

static struct bio *gfs2_log_get_bio(struct gfs2_sbd *sdp, u64 blkno)
{
	struct bio *bio = sdp->sd_log_bio;
	u64 nblk;

	if (bio) {
		nblk = bio_end_sector(bio);
		nblk >>= sdp->sd_fsb2bb_shift;
		if (blkno == nblk)
			return bio;
		gfs2_log_flush_bio(sdp, WRITE);
	}

	return gfs2_log_alloc_bio(sdp, blkno);
}


/**
 * gfs2_log_write - write to log
 * @sdp: the filesystem
 * @page: the page to write
 * @size: the size of the data to write
 * @offset: the offset within the page
 *
 * Try and add the page segment to the current bio. If that fails,
 * submit the current bio to the device and create a new one, and
 * then add the page segment to that.
 */

static void gfs2_log_write(struct gfs2_sbd *sdp, struct page *page,
			   unsigned size, unsigned offset)
{
	u64 blkno = gfs2_log_bmap(sdp);
	struct bio *bio;
	int ret;

	bio = gfs2_log_get_bio(sdp, blkno);
	ret = bio_add_page(bio, page, size, offset);
	if (ret == 0) {
		gfs2_log_flush_bio(sdp, WRITE);
		bio = gfs2_log_alloc_bio(sdp, blkno);
		ret = bio_add_page(bio, page, size, offset);
		WARN_ON(ret == 0);
	}
}

/**
 * gfs2_log_write_bh - write a buffer's content to the log
 * @sdp: The super block
 * @bh: The buffer pointing to the in-place location
 *
 * This writes the content of the buffer to the next available location
 * in the log. The buffer will be unlocked once the i/o to the log has
 * completed.
 */

static void gfs2_log_write_bh(struct gfs2_sbd *sdp, struct buffer_head *bh)
{
	gfs2_log_write(sdp, bh->b_page, bh->b_size, bh_offset(bh));
}

/**
 * gfs2_log_write_page - write one block stored in a page, into the log
 * @sdp: The superblock
 * @page: The struct page
 *
 * This writes the first block-sized part of the page into the log. Note
 * that the page must have been allocated from the gfs2_page_pool mempool
 * and that after this has been called, ownership has been transferred and
 * the page may be freed at any time.
 */

void gfs2_log_write_page(struct gfs2_sbd *sdp, struct page *page)
{
	struct super_block *sb = sdp->sd_vfs;
	gfs2_log_write(sdp, page, sb->s_blocksize, 0);
}

static struct page *gfs2_get_log_desc(struct gfs2_sbd *sdp, u32 ld_type,
				      u32 ld_length, u32 ld_data1)
{
	struct page *page = mempool_alloc(gfs2_page_pool, GFP_NOIO);
	struct gfs2_log_descriptor *ld = page_address(page);
	clear_page(ld);
	ld->ld_header.mh_magic = cpu_to_be32(GFS2_MAGIC);
	ld->ld_header.mh_type = cpu_to_be32(GFS2_METATYPE_LD);
	ld->ld_header.mh_format = cpu_to_be32(GFS2_FORMAT_LD);
	ld->ld_type = cpu_to_be32(ld_type);
	ld->ld_length = cpu_to_be32(ld_length);
	ld->ld_data1 = cpu_to_be32(ld_data1);
	ld->ld_data2 = 0;
	return page;
}

static void gfs2_check_magic(struct buffer_head *bh)
{
	void *kaddr;
	__be32 *ptr;

	clear_buffer_escaped(bh);
	kaddr = kmap_atomic(bh->b_page);
	ptr = kaddr + bh_offset(bh);
	if (*ptr == cpu_to_be32(GFS2_MAGIC))
		set_buffer_escaped(bh);
	kunmap_atomic(kaddr);
}

static int blocknr_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct gfs2_bufdata *bda, *bdb;

	bda = list_entry(a, struct gfs2_bufdata, bd_list);
	bdb = list_entry(b, struct gfs2_bufdata, bd_list);

	if (bda->bd_bh->b_blocknr < bdb->bd_bh->b_blocknr)
		return -1;
	if (bda->bd_bh->b_blocknr > bdb->bd_bh->b_blocknr)
		return 1;
	return 0;
}

static void gfs2_before_commit(struct gfs2_sbd *sdp, unsigned int limit,
				unsigned int total, struct list_head *blist,
				bool is_databuf)
{
	struct gfs2_log_descriptor *ld;
	struct gfs2_bufdata *bd1 = NULL, *bd2;
	struct page *page;
	unsigned int num;
	unsigned n;
	__be64 *ptr;

	gfs2_log_lock(sdp);
	list_sort(NULL, blist, blocknr_cmp);
	bd1 = bd2 = list_prepare_entry(bd1, blist, bd_list);
	while(total) {
		num = total;
		if (total > limit)
			num = limit;
		gfs2_log_unlock(sdp);
		page = gfs2_get_log_desc(sdp,
					 is_databuf ? GFS2_LOG_DESC_JDATA :
					 GFS2_LOG_DESC_METADATA, num + 1, num);
		ld = page_address(page);
		gfs2_log_lock(sdp);
		ptr = (__be64 *)(ld + 1);

		n = 0;
		list_for_each_entry_continue(bd1, blist, bd_list) {
			*ptr++ = cpu_to_be64(bd1->bd_bh->b_blocknr);
			if (is_databuf) {
				gfs2_check_magic(bd1->bd_bh);
				*ptr++ = cpu_to_be64(buffer_escaped(bd1->bd_bh) ? 1 : 0);
			}
			if (++n >= num)
				break;
		}

		gfs2_log_unlock(sdp);
		gfs2_log_write_page(sdp, page);
		gfs2_log_lock(sdp);

		n = 0;
		list_for_each_entry_continue(bd2, blist, bd_list) {
			get_bh(bd2->bd_bh);
			gfs2_log_unlock(sdp);
			lock_buffer(bd2->bd_bh);

			if (buffer_escaped(bd2->bd_bh)) {
				void *kaddr;
				page = mempool_alloc(gfs2_page_pool, GFP_NOIO);
				ptr = page_address(page);
				kaddr = kmap_atomic(bd2->bd_bh->b_page);
				memcpy(ptr, kaddr + bh_offset(bd2->bd_bh),
				       bd2->bd_bh->b_size);
				kunmap_atomic(kaddr);
				*(__be32 *)ptr = 0;
				clear_buffer_escaped(bd2->bd_bh);
				unlock_buffer(bd2->bd_bh);
				brelse(bd2->bd_bh);
				gfs2_log_write_page(sdp, page);
			} else {
				gfs2_log_write_bh(sdp, bd2->bd_bh);
			}
			gfs2_log_lock(sdp);
			if (++n >= num)
				break;
		}

		BUG_ON(total < num);
		total -= num;
	}
	gfs2_log_unlock(sdp);
}

static void buf_lo_before_commit(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	unsigned int limit = buf_limit(sdp); /* 503 for 4k blocks */
	unsigned int nbuf;
	if (tr == NULL)
		return;
	nbuf = tr->tr_num_buf_new - tr->tr_num_buf_rm;
	gfs2_before_commit(sdp, limit, nbuf, &tr->tr_buf, 0);
}

static void buf_lo_after_commit(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	struct list_head *head;
	struct gfs2_bufdata *bd;

	if (tr == NULL)
		return;

	head = &tr->tr_buf;
	while (!list_empty(head)) {
		bd = list_entry(head->next, struct gfs2_bufdata, bd_list);
		list_del_init(&bd->bd_list);
		gfs2_unpin(sdp, bd->bd_bh, tr);
	}
}

static void buf_lo_before_scan(struct gfs2_jdesc *jd,
			       struct gfs2_log_header_host *head, int pass)
{
	if (pass != 0)
		return;

	jd->jd_found_blocks = 0;
	jd->jd_replayed_blocks = 0;
}

static int buf_lo_scan_elements(struct gfs2_jdesc *jd, unsigned int start,
				struct gfs2_log_descriptor *ld, __be64 *ptr,
				int pass)
{
	struct gfs2_inode *ip = GFS2_I(jd->jd_inode);
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);
	struct gfs2_glock *gl = ip->i_gl;
	unsigned int blks = be32_to_cpu(ld->ld_data1);
	struct buffer_head *bh_log, *bh_ip;
	u64 blkno;
	int error = 0;

	if (pass != 1 || be32_to_cpu(ld->ld_type) != GFS2_LOG_DESC_METADATA)
		return 0;

	gfs2_replay_incr_blk(sdp, &start);

	for (; blks; gfs2_replay_incr_blk(sdp, &start), blks--) {
		blkno = be64_to_cpu(*ptr++);

		jd->jd_found_blocks++;

		if (gfs2_revoke_check(jd, blkno, start))
			continue;

		error = gfs2_replay_read_block(jd, start, &bh_log);
		if (error)
			return error;

		bh_ip = gfs2_meta_new(gl, blkno);
		memcpy(bh_ip->b_data, bh_log->b_data, bh_log->b_size);

		if (gfs2_meta_check(sdp, bh_ip))
			error = -EIO;
		else
			mark_buffer_dirty(bh_ip);

		brelse(bh_log);
		brelse(bh_ip);

		if (error)
			break;

		jd->jd_replayed_blocks++;
	}

	return error;
}

/**
 * gfs2_meta_sync - Sync all buffers associated with a glock
 * @gl: The glock
 *
 */

static void gfs2_meta_sync(struct gfs2_glock *gl)
{
	struct address_space *mapping = gfs2_glock2aspace(gl);
	struct gfs2_sbd *sdp = gl->gl_sbd;
	int error;

	if (mapping == NULL)
		mapping = &sdp->sd_aspace;

	filemap_fdatawrite(mapping);
	error = filemap_fdatawait(mapping);

	if (error)
		gfs2_io_error(gl->gl_sbd);
}

static void buf_lo_after_scan(struct gfs2_jdesc *jd, int error, int pass)
{
	struct gfs2_inode *ip = GFS2_I(jd->jd_inode);
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);

	if (error) {
		gfs2_meta_sync(ip->i_gl);
		return;
	}
	if (pass != 1)
		return;

	gfs2_meta_sync(ip->i_gl);

	fs_info(sdp, "jid=%u: Replayed %u of %u blocks\n",
	        jd->jd_jid, jd->jd_replayed_blocks, jd->jd_found_blocks);
}

static void revoke_lo_before_commit(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	struct gfs2_meta_header *mh;
	unsigned int offset;
	struct list_head *head = &sdp->sd_log_le_revoke;
	struct gfs2_bufdata *bd;
	struct page *page;
	unsigned int length;

	gfs2_write_revokes(sdp);
	if (!sdp->sd_log_num_revoke)
		return;

	length = gfs2_struct2blk(sdp, sdp->sd_log_num_revoke, sizeof(u64));
	page = gfs2_get_log_desc(sdp, GFS2_LOG_DESC_REVOKE, length, sdp->sd_log_num_revoke);
	offset = sizeof(struct gfs2_log_descriptor);

	list_for_each_entry(bd, head, bd_list) {
		sdp->sd_log_num_revoke--;

		if (offset + sizeof(u64) > sdp->sd_sb.sb_bsize) {

			gfs2_log_write_page(sdp, page);
			page = mempool_alloc(gfs2_page_pool, GFP_NOIO);
			mh = page_address(page);
			clear_page(mh);
			mh->mh_magic = cpu_to_be32(GFS2_MAGIC);
			mh->mh_type = cpu_to_be32(GFS2_METATYPE_LB);
			mh->mh_format = cpu_to_be32(GFS2_FORMAT_LB);
			offset = sizeof(struct gfs2_meta_header);
		}

		*(__be64 *)(page_address(page) + offset) = cpu_to_be64(bd->bd_blkno);
		offset += sizeof(u64);
	}
	gfs2_assert_withdraw(sdp, !sdp->sd_log_num_revoke);

	gfs2_log_write_page(sdp, page);
}

static void revoke_lo_after_commit(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	struct list_head *head = &sdp->sd_log_le_revoke;
	struct gfs2_bufdata *bd;
	struct gfs2_glock *gl;

	while (!list_empty(head)) {
		bd = list_entry(head->next, struct gfs2_bufdata, bd_list);
		list_del_init(&bd->bd_list);
		gl = bd->bd_gl;
		atomic_dec(&gl->gl_revokes);
		clear_bit(GLF_LFLUSH, &gl->gl_flags);
		kmem_cache_free(gfs2_bufdata_cachep, bd);
	}
}

static void revoke_lo_before_scan(struct gfs2_jdesc *jd,
				  struct gfs2_log_header_host *head, int pass)
{
	if (pass != 0)
		return;

	jd->jd_found_revokes = 0;
	jd->jd_replay_tail = head->lh_tail;
}

static int revoke_lo_scan_elements(struct gfs2_jdesc *jd, unsigned int start,
				   struct gfs2_log_descriptor *ld, __be64 *ptr,
				   int pass)
{
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);
	unsigned int blks = be32_to_cpu(ld->ld_length);
	unsigned int revokes = be32_to_cpu(ld->ld_data1);
	struct buffer_head *bh;
	unsigned int offset;
	u64 blkno;
	int first = 1;
	int error;

	if (pass != 0 || be32_to_cpu(ld->ld_type) != GFS2_LOG_DESC_REVOKE)
		return 0;

	offset = sizeof(struct gfs2_log_descriptor);

	for (; blks; gfs2_replay_incr_blk(sdp, &start), blks--) {
		error = gfs2_replay_read_block(jd, start, &bh);
		if (error)
			return error;

		if (!first)
			gfs2_metatype_check(sdp, bh, GFS2_METATYPE_LB);

		while (offset + sizeof(u64) <= sdp->sd_sb.sb_bsize) {
			blkno = be64_to_cpu(*(__be64 *)(bh->b_data + offset));

			error = gfs2_revoke_add(jd, blkno, start);
			if (error < 0) {
				brelse(bh);
				return error;
			}
			else if (error)
				jd->jd_found_revokes++;

			if (!--revokes)
				break;
			offset += sizeof(u64);
		}

		brelse(bh);
		offset = sizeof(struct gfs2_meta_header);
		first = 0;
	}

	return 0;
}

static void revoke_lo_after_scan(struct gfs2_jdesc *jd, int error, int pass)
{
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);

	if (error) {
		gfs2_revoke_clean(jd);
		return;
	}
	if (pass != 1)
		return;

	fs_info(sdp, "jid=%u: Found %u revoke tags\n",
	        jd->jd_jid, jd->jd_found_revokes);

	gfs2_revoke_clean(jd);
}

/**
 * databuf_lo_before_commit - Scan the data buffers, writing as we go
 *
 */

static void databuf_lo_before_commit(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	unsigned int limit = databuf_limit(sdp);
	unsigned int nbuf;
	if (tr == NULL)
		return;
	nbuf = tr->tr_num_databuf_new - tr->tr_num_databuf_rm;
	gfs2_before_commit(sdp, limit, nbuf, &tr->tr_databuf, 1);
}

static int databuf_lo_scan_elements(struct gfs2_jdesc *jd, unsigned int start,
				    struct gfs2_log_descriptor *ld,
				    __be64 *ptr, int pass)
{
	struct gfs2_inode *ip = GFS2_I(jd->jd_inode);
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);
	struct gfs2_glock *gl = ip->i_gl;
	unsigned int blks = be32_to_cpu(ld->ld_data1);
	struct buffer_head *bh_log, *bh_ip;
	u64 blkno;
	u64 esc;
	int error = 0;

	if (pass != 1 || be32_to_cpu(ld->ld_type) != GFS2_LOG_DESC_JDATA)
		return 0;

	gfs2_replay_incr_blk(sdp, &start);
	for (; blks; gfs2_replay_incr_blk(sdp, &start), blks--) {
		blkno = be64_to_cpu(*ptr++);
		esc = be64_to_cpu(*ptr++);

		jd->jd_found_blocks++;

		if (gfs2_revoke_check(jd, blkno, start))
			continue;

		error = gfs2_replay_read_block(jd, start, &bh_log);
		if (error)
			return error;

		bh_ip = gfs2_meta_new(gl, blkno);
		memcpy(bh_ip->b_data, bh_log->b_data, bh_log->b_size);

		/* Unescape */
		if (esc) {
			__be32 *eptr = (__be32 *)bh_ip->b_data;
			*eptr = cpu_to_be32(GFS2_MAGIC);
		}
		mark_buffer_dirty(bh_ip);

		brelse(bh_log);
		brelse(bh_ip);

		jd->jd_replayed_blocks++;
	}

	return error;
}

/* FIXME: sort out accounting for log blocks etc. */

static void databuf_lo_after_scan(struct gfs2_jdesc *jd, int error, int pass)
{
	struct gfs2_inode *ip = GFS2_I(jd->jd_inode);
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);

	if (error) {
		gfs2_meta_sync(ip->i_gl);
		return;
	}
	if (pass != 1)
		return;

	/* data sync? */
	gfs2_meta_sync(ip->i_gl);

	fs_info(sdp, "jid=%u: Replayed %u of %u data blocks\n",
		jd->jd_jid, jd->jd_replayed_blocks, jd->jd_found_blocks);
}

static void databuf_lo_after_commit(struct gfs2_sbd *sdp, struct gfs2_trans *tr)
{
	struct list_head *head;
	struct gfs2_bufdata *bd;

	if (tr == NULL)
		return;

	head = &tr->tr_databuf;
	while (!list_empty(head)) {
		bd = list_entry(head->next, struct gfs2_bufdata, bd_list);
		list_del_init(&bd->bd_list);
		gfs2_unpin(sdp, bd->bd_bh, tr);
	}
}


const struct gfs2_log_operations gfs2_buf_lops = {
	.lo_before_commit = buf_lo_before_commit,
	.lo_after_commit = buf_lo_after_commit,
	.lo_before_scan = buf_lo_before_scan,
	.lo_scan_elements = buf_lo_scan_elements,
	.lo_after_scan = buf_lo_after_scan,
	.lo_name = "buf",
};

const struct gfs2_log_operations gfs2_revoke_lops = {
	.lo_before_commit = revoke_lo_before_commit,
	.lo_after_commit = revoke_lo_after_commit,
	.lo_before_scan = revoke_lo_before_scan,
	.lo_scan_elements = revoke_lo_scan_elements,
	.lo_after_scan = revoke_lo_after_scan,
	.lo_name = "revoke",
};

const struct gfs2_log_operations gfs2_databuf_lops = {
	.lo_before_commit = databuf_lo_before_commit,
	.lo_after_commit = databuf_lo_after_commit,
	.lo_scan_elements = databuf_lo_scan_elements,
	.lo_after_scan = databuf_lo_after_scan,
	.lo_name = "databuf",
};

const struct gfs2_log_operations *gfs2_log_ops[] = {
	&gfs2_databuf_lops,
	&gfs2_buf_lops,
	&gfs2_revoke_lops,
	NULL,
};
/************************************************************/
/* ../linux-3.17/fs/gfs2/main.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/module.h>
#include <linux/init.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/rcupdate.h>
// #include <linux/rculist_bl.h>
#include <linux/atomic.h>
// #include <linux/mempool.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "super.h"
#include "sys.h"
// #include "util.h"
// #include "glock.h"
// #include "quota.h"
// #include "recovery.h"
// #include "dir.h"

struct workqueue_struct *gfs2_control_wq;

static void gfs2_init_inode_once(void *foo)
{
	struct gfs2_inode *ip = foo;

	inode_init_once(&ip->i_inode);
	init_rwsem(&ip->i_rw_mutex);
	INIT_LIST_HEAD(&ip->i_trunc_list);
	ip->i_res = NULL;
	ip->i_hash_cache = NULL;
}

static void gfs2_init_glock_once(void *foo)
{
	struct gfs2_glock *gl = foo;

	INIT_HLIST_BL_NODE(&gl->gl_list);
	spin_lock_init(&gl->gl_spin);
	INIT_LIST_HEAD(&gl->gl_holders);
	INIT_LIST_HEAD(&gl->gl_lru);
	INIT_LIST_HEAD(&gl->gl_ail_list);
	atomic_set(&gl->gl_ail_count, 0);
	atomic_set(&gl->gl_revokes, 0);
}

static void gfs2_init_gl_aspace_once(void *foo)
{
	struct gfs2_glock *gl = foo;
	struct address_space *mapping = (struct address_space *)(gl + 1);

	gfs2_init_glock_once(gl);
	address_space_init_once(mapping);
}

/**
 * init_gfs2_fs - Register GFS2 as a filesystem
 *
 * Returns: 0 on success, error code on failure
 */

static int __init init_gfs2_fs(void)
{
	int error;

	gfs2_str2qstr(&gfs2_qdot, ".");
	gfs2_str2qstr(&gfs2_qdotdot, "..");
	gfs2_quota_hash_init();

	error = gfs2_sys_init();
	if (error)
		return error;

	error = list_lru_init(&gfs2_qd_lru);
	if (error)
		goto fail_lru;

	error = gfs2_glock_init();
	if (error)
		goto fail;

	error = -ENOMEM;
	gfs2_glock_cachep = kmem_cache_create("gfs2_glock",
					      sizeof(struct gfs2_glock),
					      0, 0,
					      gfs2_init_glock_once);
	if (!gfs2_glock_cachep)
		goto fail;

	gfs2_glock_aspace_cachep = kmem_cache_create("gfs2_glock(aspace)",
					sizeof(struct gfs2_glock) +
					sizeof(struct address_space),
					0, 0, gfs2_init_gl_aspace_once);

	if (!gfs2_glock_aspace_cachep)
		goto fail;

	gfs2_inode_cachep = kmem_cache_create("gfs2_inode",
					      sizeof(struct gfs2_inode),
					      0,  SLAB_RECLAIM_ACCOUNT|
					          SLAB_MEM_SPREAD,
					      gfs2_init_inode_once);
	if (!gfs2_inode_cachep)
		goto fail;

	gfs2_bufdata_cachep = kmem_cache_create("gfs2_bufdata",
						sizeof(struct gfs2_bufdata),
					        0, 0, NULL);
	if (!gfs2_bufdata_cachep)
		goto fail;

	gfs2_rgrpd_cachep = kmem_cache_create("gfs2_rgrpd",
					      sizeof(struct gfs2_rgrpd),
					      0, 0, NULL);
	if (!gfs2_rgrpd_cachep)
		goto fail;

	gfs2_quotad_cachep = kmem_cache_create("gfs2_quotad",
					       sizeof(struct gfs2_quota_data),
					       0, 0, NULL);
	if (!gfs2_quotad_cachep)
		goto fail;

	gfs2_rsrv_cachep = kmem_cache_create("gfs2_mblk",
					     sizeof(struct gfs2_blkreserv),
					       0, 0, NULL);
	if (!gfs2_rsrv_cachep)
		goto fail;

	register_shrinker(&gfs2_qd_shrinker);

	error = register_filesystem(&gfs2_fs_type);
	if (error)
		goto fail;

	error = register_filesystem(&gfs2meta_fs_type);
	if (error)
		goto fail_unregister;

	error = -ENOMEM;
	gfs_recovery_wq = alloc_workqueue("gfs_recovery",
					  WQ_MEM_RECLAIM | WQ_FREEZABLE, 0);
	if (!gfs_recovery_wq)
		goto fail_wq;

	gfs2_control_wq = alloc_workqueue("gfs2_control",
					  WQ_UNBOUND | WQ_FREEZABLE, 0);
	if (!gfs2_control_wq)
		goto fail_recovery;

	gfs2_page_pool = mempool_create_page_pool(64, 0);
	if (!gfs2_page_pool)
		goto fail_control;

	gfs2_register_debugfs();

	pr_info("GFS2 installed\n");

	return 0;

fail_control:
	destroy_workqueue(gfs2_control_wq);
fail_recovery:
	destroy_workqueue(gfs_recovery_wq);
fail_wq:
	unregister_filesystem(&gfs2meta_fs_type);
fail_unregister:
	unregister_filesystem(&gfs2_fs_type);
fail:
	list_lru_destroy(&gfs2_qd_lru);
fail_lru:
	unregister_shrinker(&gfs2_qd_shrinker);
	gfs2_glock_exit();

	if (gfs2_rsrv_cachep)
		kmem_cache_destroy(gfs2_rsrv_cachep);

	if (gfs2_quotad_cachep)
		kmem_cache_destroy(gfs2_quotad_cachep);

	if (gfs2_rgrpd_cachep)
		kmem_cache_destroy(gfs2_rgrpd_cachep);

	if (gfs2_bufdata_cachep)
		kmem_cache_destroy(gfs2_bufdata_cachep);

	if (gfs2_inode_cachep)
		kmem_cache_destroy(gfs2_inode_cachep);

	if (gfs2_glock_aspace_cachep)
		kmem_cache_destroy(gfs2_glock_aspace_cachep);

	if (gfs2_glock_cachep)
		kmem_cache_destroy(gfs2_glock_cachep);

	gfs2_sys_uninit();
	return error;
}

/**
 * exit_gfs2_fs - Unregister the file system
 *
 */

static void __exit exit_gfs2_fs(void)
{
	unregister_shrinker(&gfs2_qd_shrinker);
	gfs2_glock_exit();
	gfs2_unregister_debugfs();
	unregister_filesystem(&gfs2_fs_type);
	unregister_filesystem(&gfs2meta_fs_type);
	destroy_workqueue(gfs_recovery_wq);
	destroy_workqueue(gfs2_control_wq);
	list_lru_destroy(&gfs2_qd_lru);

	rcu_barrier();

	mempool_destroy(gfs2_page_pool);
	kmem_cache_destroy(gfs2_rsrv_cachep);
	kmem_cache_destroy(gfs2_quotad_cachep);
	kmem_cache_destroy(gfs2_rgrpd_cachep);
	kmem_cache_destroy(gfs2_bufdata_cachep);
	kmem_cache_destroy(gfs2_inode_cachep);
	kmem_cache_destroy(gfs2_glock_aspace_cachep);
	kmem_cache_destroy(gfs2_glock_cachep);

	gfs2_sys_uninit();
}

MODULE_DESCRIPTION("Global File System");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

module_init(init_gfs2_fs);
module_exit(exit_gfs2_fs);
/************************************************************/
/* ../linux-3.17/fs/gfs2/meta_io.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
// #include <linux/writeback.h>
#include <linux/swap.h>
// #include <linux/delay.h>
// #include <linux/bio.h>
// #include <linux/gfs2_ondisk.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "glock.h"
// #include "glops.h"
// #include "inode.h"
// #include "log.h"
// #include "lops.h"
// #include "meta_io.h"
// #include "rgrp.h"
// #include "trans.h"
// #include "util.h"
// #include "trace_gfs2.h"

static int gfs2_aspace_writepage(struct page *page, struct writeback_control *wbc)
{
	struct buffer_head *bh, *head;
	int nr_underway = 0;
	int write_op = REQ_META | REQ_PRIO |
		(wbc->sync_mode == WB_SYNC_ALL ? WRITE_SYNC : WRITE);

	BUG_ON(!PageLocked(page));
	BUG_ON(!page_has_buffers(page));

	head = page_buffers(page);
	bh = head;

	do {
		if (!buffer_mapped(bh))
			continue;
		/*
		 * If it's a fully non-blocking write attempt and we cannot
		 * lock the buffer then redirty the page.  Note that this can
		 * potentially cause a busy-wait loop from flusher thread and kswapd
		 * activity, but those code paths have their own higher-level
		 * throttling.
		 */
		if (wbc->sync_mode != WB_SYNC_NONE) {
			lock_buffer(bh);
		} else if (!trylock_buffer(bh)) {
			redirty_page_for_writepage(wbc, page);
			continue;
		}
		if (test_clear_buffer_dirty(bh)) {
			mark_buffer_async_write(bh);
		} else {
			unlock_buffer(bh);
		}
	} while ((bh = bh->b_this_page) != head);

	/*
	 * The page and its buffers are protected by PageWriteback(), so we can
	 * drop the bh refcounts early.
	 */
	BUG_ON(PageWriteback(page));
	set_page_writeback(page);

	do {
		struct buffer_head *next = bh->b_this_page;
		if (buffer_async_write(bh)) {
			submit_bh(write_op, bh);
			nr_underway++;
		}
		bh = next;
	} while (bh != head);
	unlock_page(page);

	if (nr_underway == 0)
		end_page_writeback(page);

	return 0;
}

const struct address_space_operations gfs2_meta_aops = {
	.writepage = gfs2_aspace_writepage,
	.releasepage = gfs2_releasepage,
};

const struct address_space_operations gfs2_rgrp_aops = {
	.writepage = gfs2_aspace_writepage,
	.releasepage = gfs2_releasepage,
};

/**
 * gfs2_getbuf - Get a buffer with a given address space
 * @gl: the glock
 * @blkno: the block number (filesystem scope)
 * @create: 1 if the buffer should be created
 *
 * Returns: the buffer
 */

struct buffer_head *gfs2_getbuf(struct gfs2_glock *gl, u64 blkno, int create)
{
	struct address_space *mapping = gfs2_glock2aspace(gl);
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct page *page;
	struct buffer_head *bh;
	unsigned int shift;
	unsigned long index;
	unsigned int bufnum;

	if (mapping == NULL)
		mapping = &sdp->sd_aspace;

	shift = PAGE_CACHE_SHIFT - sdp->sd_sb.sb_bsize_shift;
	index = blkno >> shift;             /* convert block to page */
	bufnum = blkno - (index << shift);  /* block buf index within page */

	if (create) {
		for (;;) {
			page = grab_cache_page(mapping, index);
			if (page)
				break;
			yield();
		}
	} else {
		page = find_get_page_flags(mapping, index,
						FGP_LOCK|FGP_ACCESSED);
		if (!page)
			return NULL;
	}

	if (!page_has_buffers(page))
		create_empty_buffers(page, sdp->sd_sb.sb_bsize, 0);

	/* Locate header for our buffer within our page */
	for (bh = page_buffers(page); bufnum--; bh = bh->b_this_page)
		/* Do nothing */;
	get_bh(bh);

	if (!buffer_mapped(bh))
		map_bh(bh, sdp->sd_vfs, blkno);

	unlock_page(page);
	page_cache_release(page);

	return bh;
}

static void meta_prep_new(struct buffer_head *bh)
{
	struct gfs2_meta_header *mh = (struct gfs2_meta_header *)bh->b_data;

	lock_buffer(bh);
	clear_buffer_dirty(bh);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	mh->mh_magic = cpu_to_be32(GFS2_MAGIC);
}

/**
 * gfs2_meta_new - Get a block
 * @gl: The glock associated with this block
 * @blkno: The block number
 *
 * Returns: The buffer
 */

struct buffer_head *gfs2_meta_new(struct gfs2_glock *gl, u64 blkno)
{
	struct buffer_head *bh;
	bh = gfs2_getbuf(gl, blkno, CREATE);
	meta_prep_new(bh);
	return bh;
}

/**
 * gfs2_meta_read - Read a block from disk
 * @gl: The glock covering the block
 * @blkno: The block number
 * @flags: flags
 * @bhp: the place where the buffer is returned (NULL on failure)
 *
 * Returns: errno
 */

int gfs2_meta_read(struct gfs2_glock *gl, u64 blkno, int flags,
		   struct buffer_head **bhp)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct buffer_head *bh;

	if (unlikely(test_bit(SDF_SHUTDOWN, &sdp->sd_flags))) {
		*bhp = NULL;
		return -EIO;
	}

	*bhp = bh = gfs2_getbuf(gl, blkno, CREATE);

	lock_buffer(bh);
	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return 0;
	}
	bh->b_end_io = end_buffer_read_sync;
	get_bh(bh);
	submit_bh(READ_SYNC | REQ_META | REQ_PRIO, bh);
	if (!(flags & DIO_WAIT))
		return 0;

	wait_on_buffer(bh);
	if (unlikely(!buffer_uptodate(bh))) {
		struct gfs2_trans *tr = current->journal_info;
		if (tr && tr->tr_touched)
			gfs2_io_error_bh(sdp, bh);
		brelse(bh);
		*bhp = NULL;
		return -EIO;
	}

	return 0;
}

/**
 * gfs2_meta_wait - Reread a block from disk
 * @sdp: the filesystem
 * @bh: The block to wait for
 *
 * Returns: errno
 */

int gfs2_meta_wait(struct gfs2_sbd *sdp, struct buffer_head *bh)
{
	if (unlikely(test_bit(SDF_SHUTDOWN, &sdp->sd_flags)))
		return -EIO;

	wait_on_buffer(bh);

	if (!buffer_uptodate(bh)) {
		struct gfs2_trans *tr = current->journal_info;
		if (tr && tr->tr_touched)
			gfs2_io_error_bh(sdp, bh);
		return -EIO;
	}
	if (unlikely(test_bit(SDF_SHUTDOWN, &sdp->sd_flags)))
		return -EIO;

	return 0;
}

void gfs2_remove_from_journal(struct buffer_head *bh, struct gfs2_trans *tr, int meta)
{
	struct address_space *mapping = bh->b_page->mapping;
	struct gfs2_sbd *sdp = gfs2_mapping2sbd(mapping);
	struct gfs2_bufdata *bd = bh->b_private;
	int was_pinned = 0;

	if (test_clear_buffer_pinned(bh)) {
		trace_gfs2_pin(bd, 0);
		atomic_dec(&sdp->sd_log_pinned);
		list_del_init(&bd->bd_list);
		if (meta)
			tr->tr_num_buf_rm++;
		else
			tr->tr_num_databuf_rm++;
		tr->tr_touched = 1;
		was_pinned = 1;
		brelse(bh);
	}
	if (bd) {
		spin_lock(&sdp->sd_ail_lock);
		if (bd->bd_tr) {
			gfs2_trans_add_revoke(sdp, bd);
		} else if (was_pinned) {
			bh->b_private = NULL;
			kmem_cache_free(gfs2_bufdata_cachep, bd);
		}
		spin_unlock(&sdp->sd_ail_lock);
	}
	clear_buffer_dirty(bh);
	clear_buffer_uptodate(bh);
}

/**
 * gfs2_meta_wipe - make inode's buffers so they aren't dirty/pinned anymore
 * @ip: the inode who owns the buffers
 * @bstart: the first buffer in the run
 * @blen: the number of buffers in the run
 *
 */

void gfs2_meta_wipe(struct gfs2_inode *ip, u64 bstart, u32 blen)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head *bh;

	while (blen) {
		bh = gfs2_getbuf(ip->i_gl, bstart, NO_CREATE);
		if (bh) {
			lock_buffer(bh);
			gfs2_log_lock(sdp);
			gfs2_remove_from_journal(bh, current->journal_info, 1);
			gfs2_log_unlock(sdp);
			unlock_buffer(bh);
			brelse(bh);
		}

		bstart++;
		blen--;
	}
}

/**
 * gfs2_meta_indirect_buffer - Get a metadata buffer
 * @ip: The GFS2 inode
 * @height: The level of this buf in the metadata (indir addr) tree (if any)
 * @num: The block number (device relative) of the buffer
 * @bhp: the buffer is returned here
 *
 * Returns: errno
 */

int gfs2_meta_indirect_buffer(struct gfs2_inode *ip, int height, u64 num,
			      struct buffer_head **bhp)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_glock *gl = ip->i_gl;
	struct buffer_head *bh;
	int ret = 0;
	u32 mtype = height ? GFS2_METATYPE_IN : GFS2_METATYPE_DI;

	ret = gfs2_meta_read(gl, num, DIO_WAIT, &bh);
	if (ret == 0 && gfs2_metatype_check(sdp, bh, mtype)) {
		brelse(bh);
		ret = -EIO;
	}
	*bhp = bh;
	return ret;
}

/**
 * gfs2_meta_ra - start readahead on an extent of a file
 * @gl: the glock the blocks belong to
 * @dblock: the starting disk block
 * @extlen: the number of blocks in the extent
 *
 * returns: the first buffer in the extent
 */

struct buffer_head *gfs2_meta_ra(struct gfs2_glock *gl, u64 dblock, u32 extlen)
{
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct buffer_head *first_bh, *bh;
	u32 max_ra = gfs2_tune_get(sdp, gt_max_readahead) >>
			  sdp->sd_sb.sb_bsize_shift;

	BUG_ON(!extlen);

	if (max_ra < 1)
		max_ra = 1;
	if (extlen > max_ra)
		extlen = max_ra;

	first_bh = gfs2_getbuf(gl, dblock, CREATE);

	if (buffer_uptodate(first_bh))
		goto out;
	if (!buffer_locked(first_bh))
		ll_rw_block(READ_SYNC | REQ_META, 1, &first_bh);

	dblock++;
	extlen--;

	while (extlen) {
		bh = gfs2_getbuf(gl, dblock, CREATE);

		if (!buffer_uptodate(bh) && !buffer_locked(bh))
			ll_rw_block(READA | REQ_META, 1, &bh);
		brelse(bh);
		dblock++;
		extlen--;
		if (!buffer_locked(first_bh) && buffer_uptodate(first_bh))
			goto out;
	}

	wait_on_buffer(first_bh);
out:
	return first_bh;
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/aops.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/mpage.h>
// #include <linux/fs.h>
// #include <linux/writeback.h>
// #include <linux/swap.h>
// #include <linux/gfs2_ondisk.h>
#include <linux/backing-dev.h>
#include <linux/aio.h>
#include <trace/events/writeback.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "bmap.h"
// #include "glock.h"
// #include "inode.h"
// #include "log.h"
// #include "meta_io.h"
// #include "quota.h"
// #include "trans.h"
// #include "rgrp.h"
// #include "super.h"
// #include "util.h"
// #include "glops.h"


static void gfs2_page_add_databufs(struct gfs2_inode *ip, struct page *page,
				   unsigned int from, unsigned int to)
{
	struct buffer_head *head = page_buffers(page);
	unsigned int bsize = head->b_size;
	struct buffer_head *bh;
	unsigned int start, end;

	for (bh = head, start = 0; bh != head || !start;
	     bh = bh->b_this_page, start = end) {
		end = start + bsize;
		if (end <= from || start >= to)
			continue;
		if (gfs2_is_jdata(ip))
			set_buffer_uptodate(bh);
		gfs2_trans_add_data(ip->i_gl, bh);
	}
}

/**
 * gfs2_get_block_noalloc - Fills in a buffer head with details about a block
 * @inode: The inode
 * @lblock: The block number to look up
 * @bh_result: The buffer head to return the result in
 * @create: Non-zero if we may add block to the file
 *
 * Returns: errno
 */

static int gfs2_get_block_noalloc(struct inode *inode, sector_t lblock,
				  struct buffer_head *bh_result, int create)
{
	int error;

	error = gfs2_block_map(inode, lblock, bh_result, 0);
	if (error)
		return error;
	if (!buffer_mapped(bh_result))
		return -EIO;
	return 0;
}

static int gfs2_get_block_direct(struct inode *inode, sector_t lblock,
				 struct buffer_head *bh_result, int create)
{
	return gfs2_block_map(inode, lblock, bh_result, 0);
}

/**
 * gfs2_writepage_common - Common bits of writepage
 * @page: The page to be written
 * @wbc: The writeback control
 *
 * Returns: 1 if writepage is ok, otherwise an error code or zero if no error.
 */

static int gfs2_writepage_common(struct page *page,
				 struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	loff_t i_size = i_size_read(inode);
	pgoff_t end_index = i_size >> PAGE_CACHE_SHIFT;
	unsigned offset;

	if (gfs2_assert_withdraw(sdp, gfs2_glock_is_held_excl(ip->i_gl)))
		goto out;
	if (current->journal_info)
		goto redirty;
	/* Is the page fully outside i_size? (truncate in progress) */
	offset = i_size & (PAGE_CACHE_SIZE-1);
	if (page->index > end_index || (page->index == end_index && !offset)) {
		page->mapping->a_ops->invalidatepage(page, 0, PAGE_CACHE_SIZE);
		goto out;
	}
	return 1;
redirty:
	redirty_page_for_writepage(wbc, page);
out:
	unlock_page(page);
	return 0;
}

/**
 * gfs2_writepage - Write page for writeback mappings
 * @page: The page
 * @wbc: The writeback control
 *
 */

static int gfs2_writepage(struct page *page, struct writeback_control *wbc)
{
	int ret;

	ret = gfs2_writepage_common(page, wbc);
	if (ret <= 0)
		return ret;

	return nobh_writepage(page, gfs2_get_block_noalloc, wbc);
}

/**
 * __gfs2_jdata_writepage - The core of jdata writepage
 * @page: The page to write
 * @wbc: The writeback control
 *
 * This is shared between writepage and writepages and implements the
 * core of the writepage operation. If a transaction is required then
 * PageChecked will have been set and the transaction will have
 * already been started before this is called.
 */

static int __gfs2_jdata_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);

	if (PageChecked(page)) {
		ClearPageChecked(page);
		if (!page_has_buffers(page)) {
			create_empty_buffers(page, inode->i_sb->s_blocksize,
					     (1 << BH_Dirty)|(1 << BH_Uptodate));
		}
		gfs2_page_add_databufs(ip, page, 0, sdp->sd_vfs->s_blocksize-1);
	}
	return block_write_full_page(page, gfs2_get_block_noalloc, wbc);
}

/**
 * gfs2_jdata_writepage - Write complete page
 * @page: Page to write
 *
 * Returns: errno
 *
 */

static int gfs2_jdata_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	int ret;
	int done_trans = 0;

	if (PageChecked(page)) {
		if (wbc->sync_mode != WB_SYNC_ALL)
			goto out_ignore;
		ret = gfs2_trans_begin(sdp, RES_DINODE + 1, 0);
		if (ret)
			goto out_ignore;
		done_trans = 1;
	}
	ret = gfs2_writepage_common(page, wbc);
	if (ret > 0)
		ret = __gfs2_jdata_writepage(page, wbc);
	if (done_trans)
		gfs2_trans_end(sdp);
	return ret;

out_ignore:
	redirty_page_for_writepage(wbc, page);
	unlock_page(page);
	return 0;
}

/**
 * gfs2_writepages - Write a bunch of dirty pages back to disk
 * @mapping: The mapping to write
 * @wbc: Write-back control
 *
 * Used for both ordered and writeback modes.
 */
static int gfs2_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, gfs2_get_block_noalloc);
}

/**
 * gfs2_write_jdata_pagevec - Write back a pagevec's worth of pages
 * @mapping: The mapping
 * @wbc: The writeback control
 * @writepage: The writepage function to call for each page
 * @pvec: The vector of pages
 * @nr_pages: The number of pages to write
 *
 * Returns: non-zero if loop should terminate, zero otherwise
 */

static int gfs2_write_jdata_pagevec(struct address_space *mapping,
				    struct writeback_control *wbc,
				    struct pagevec *pvec,
				    int nr_pages, pgoff_t end,
				    pgoff_t *done_index)
{
	struct inode *inode = mapping->host;
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	unsigned nrblocks = nr_pages * (PAGE_CACHE_SIZE/inode->i_sb->s_blocksize);
	int i;
	int ret;

	ret = gfs2_trans_begin(sdp, nrblocks, nrblocks);
	if (ret < 0)
		return ret;

	for(i = 0; i < nr_pages; i++) {
		struct page *page = pvec->pages[i];

		/*
		 * At this point, the page may be truncated or
		 * invalidated (changing page->mapping to NULL), or
		 * even swizzled back from swapper_space to tmpfs file
		 * mapping. However, page->index will not change
		 * because we have a reference on the page.
		 */
		if (page->index > end) {
			/*
			 * can't be range_cyclic (1st pass) because
			 * end == -1 in that case.
			 */
			ret = 1;
			break;
		}

		*done_index = page->index;

		lock_page(page);

		if (unlikely(page->mapping != mapping)) {
continue_unlock:
			unlock_page(page);
			continue;
		}

		if (!PageDirty(page)) {
			/* someone wrote it for us */
			goto continue_unlock;
		}

		if (PageWriteback(page)) {
			if (wbc->sync_mode != WB_SYNC_NONE)
				wait_on_page_writeback(page);
			else
				goto continue_unlock;
		}

		BUG_ON(PageWriteback(page));
		if (!clear_page_dirty_for_io(page))
			goto continue_unlock;

		trace_wbc_writepage(wbc, mapping->backing_dev_info);

		ret = __gfs2_jdata_writepage(page, wbc);
		if (unlikely(ret)) {
			if (ret == AOP_WRITEPAGE_ACTIVATE) {
				unlock_page(page);
				ret = 0;
			} else {

				/*
				 * done_index is set past this page,
				 * so media errors will not choke
				 * background writeout for the entire
				 * file. This has consequences for
				 * range_cyclic semantics (ie. it may
				 * not be suitable for data integrity
				 * writeout).
				 */
				*done_index = page->index + 1;
				ret = 1;
				break;
			}
		}

		/*
		 * We stop writing back only if we are not doing
		 * integrity sync. In case of integrity sync we have to
		 * keep going until we have written all the pages
		 * we tagged for writeback prior to entering this loop.
		 */
		if (--wbc->nr_to_write <= 0 && wbc->sync_mode == WB_SYNC_NONE) {
			ret = 1;
			break;
		}

	}
	gfs2_trans_end(sdp);
	return ret;
}

/**
 * gfs2_write_cache_jdata - Like write_cache_pages but different
 * @mapping: The mapping to write
 * @wbc: The writeback control
 * @writepage: The writepage function to call
 * @data: The data to pass to writepage
 *
 * The reason that we use our own function here is that we need to
 * start transactions before we grab page locks. This allows us
 * to get the ordering right.
 */

static int gfs2_write_cache_jdata(struct address_space *mapping,
				  struct writeback_control *wbc)
{
	int ret = 0;
	int done = 0;
	struct pagevec pvec;
	int nr_pages;
	pgoff_t uninitialized_var(writeback_index);
	pgoff_t index;
	pgoff_t end;
	pgoff_t done_index;
	int cycled;
	int range_whole = 0;
	int tag;

	pagevec_init(&pvec, 0);
	if (wbc->range_cyclic) {
		writeback_index = mapping->writeback_index; /* prev offset */
		index = writeback_index;
		if (index == 0)
			cycled = 1;
		else
			cycled = 0;
		end = -1;
	} else {
		index = wbc->range_start >> PAGE_CACHE_SHIFT;
		end = wbc->range_end >> PAGE_CACHE_SHIFT;
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
		cycled = 1; /* ignore range_cyclic tests */
	}
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag = PAGECACHE_TAG_TOWRITE;
	else
		tag = PAGECACHE_TAG_DIRTY;

retry:
	if (wbc->sync_mode == WB_SYNC_ALL || wbc->tagged_writepages)
		tag_pages_for_writeback(mapping, index, end);
	done_index = index;
	while (!done && (index <= end)) {
		nr_pages = pagevec_lookup_tag(&pvec, mapping, &index, tag,
			      min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1);
		if (nr_pages == 0)
			break;

		ret = gfs2_write_jdata_pagevec(mapping, wbc, &pvec, nr_pages, end, &done_index);
		if (ret)
			done = 1;
		if (ret > 0)
			ret = 0;
		pagevec_release(&pvec);
		cond_resched();
	}

	if (!cycled && !done) {
		/*
		 * range_cyclic:
		 * We hit the last page and there is more work to be done: wrap
		 * back to the start of the file
		 */
		cycled = 1;
		index = 0;
		end = writeback_index - 1;
		goto retry;
	}

	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = done_index;

	return ret;
}


/**
 * gfs2_jdata_writepages - Write a bunch of dirty pages back to disk
 * @mapping: The mapping to write
 * @wbc: The writeback control
 *
 */

static int gfs2_jdata_writepages(struct address_space *mapping,
				 struct writeback_control *wbc)
{
	struct gfs2_inode *ip = GFS2_I(mapping->host);
	struct gfs2_sbd *sdp = GFS2_SB(mapping->host);
	int ret;

	ret = gfs2_write_cache_jdata(mapping, wbc);
	if (ret == 0 && wbc->sync_mode == WB_SYNC_ALL) {
		gfs2_log_flush(sdp, ip->i_gl, NORMAL_FLUSH);
		ret = gfs2_write_cache_jdata(mapping, wbc);
	}
	return ret;
}

/**
 * stuffed_readpage - Fill in a Linux page with stuffed file data
 * @ip: the inode
 * @page: the page
 *
 * Returns: errno
 */

static int stuffed_readpage(struct gfs2_inode *ip, struct page *page)
{
	struct buffer_head *dibh;
	u64 dsize = i_size_read(&ip->i_inode);
	void *kaddr;
	int error;

	/*
	 * Due to the order of unstuffing files and ->fault(), we can be
	 * asked for a zero page in the case of a stuffed file being extended,
	 * so we need to supply one here. It doesn't happen often.
	 */
	if (unlikely(page->index)) {
		zero_user(page, 0, PAGE_CACHE_SIZE);
		SetPageUptodate(page);
		return 0;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		return error;

	kaddr = kmap_atomic(page);
	if (dsize > (dibh->b_size - sizeof(struct gfs2_dinode)))
		dsize = (dibh->b_size - sizeof(struct gfs2_dinode));
	memcpy(kaddr, dibh->b_data + sizeof(struct gfs2_dinode), dsize);
	memset(kaddr + dsize, 0, PAGE_CACHE_SIZE - dsize);
	kunmap_atomic(kaddr);
	flush_dcache_page(page);
	brelse(dibh);
	SetPageUptodate(page);

	return 0;
}


/**
 * __gfs2_readpage - readpage
 * @file: The file to read a page for
 * @page: The page to read
 *
 * This is the core of gfs2's readpage. Its used by the internal file
 * reading code as in that case we already hold the glock. Also its
 * called by gfs2_readpage() once the required lock has been granted.
 *
 */

static int __gfs2_readpage(void *file, struct page *page)
{
	struct gfs2_inode *ip = GFS2_I(page->mapping->host);
	struct gfs2_sbd *sdp = GFS2_SB(page->mapping->host);
	int error;

	if (gfs2_is_stuffed(ip)) {
		error = stuffed_readpage(ip, page);
		unlock_page(page);
	} else {
		error = mpage_readpage(page, gfs2_block_map);
	}

	if (unlikely(test_bit(SDF_SHUTDOWN, &sdp->sd_flags)))
		return -EIO;

	return error;
}

/**
 * gfs2_readpage - read a page of a file
 * @file: The file to read
 * @page: The page of the file
 *
 * This deals with the locking required. We have to unlock and
 * relock the page in order to get the locking in the right
 * order.
 */

static int gfs2_readpage(struct file *file, struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct gfs2_inode *ip = GFS2_I(mapping->host);
	struct gfs2_holder gh;
	int error;

	unlock_page(page);
	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	error = gfs2_glock_nq(&gh);
	if (unlikely(error))
		goto out;
	error = AOP_TRUNCATED_PAGE;
	lock_page(page);
	if (page->mapping == mapping && !PageUptodate(page))
		error = __gfs2_readpage(file, page);
	else
		unlock_page(page);
	gfs2_glock_dq(&gh);
out:
	gfs2_holder_uninit(&gh);
	if (error && error != AOP_TRUNCATED_PAGE)
		lock_page(page);
	return error;
}

/**
 * gfs2_internal_read - read an internal file
 * @ip: The gfs2 inode
 * @buf: The buffer to fill
 * @pos: The file position
 * @size: The amount to read
 *
 */

int gfs2_internal_read(struct gfs2_inode *ip, char *buf, loff_t *pos,
                       unsigned size)
{
	struct address_space *mapping = ip->i_inode.i_mapping;
	unsigned long index = *pos / PAGE_CACHE_SIZE;
	unsigned offset = *pos & (PAGE_CACHE_SIZE - 1);
	unsigned copied = 0;
	unsigned amt;
	struct page *page;
	void *p;

	do {
		amt = size - copied;
		if (offset + size > PAGE_CACHE_SIZE)
			amt = PAGE_CACHE_SIZE - offset;
		page = read_cache_page(mapping, index, __gfs2_readpage, NULL);
		if (IS_ERR(page))
			return PTR_ERR(page);
		p = kmap_atomic(page);
		memcpy(buf + copied, p + offset, amt);
		kunmap_atomic(p);
		page_cache_release(page);
		copied += amt;
		index++;
		offset = 0;
	} while(copied < size);
	(*pos) += size;
	return size;
}

/**
 * gfs2_readpages - Read a bunch of pages at once
 *
 * Some notes:
 * 1. This is only for readahead, so we can simply ignore any things
 *    which are slightly inconvenient (such as locking conflicts between
 *    the page lock and the glock) and return having done no I/O. Its
 *    obviously not something we'd want to do on too regular a basis.
 *    Any I/O we ignore at this time will be done via readpage later.
 * 2. We don't handle stuffed files here we let readpage do the honours.
 * 3. mpage_readpages() does most of the heavy lifting in the common case.
 * 4. gfs2_block_map() is relied upon to set BH_Boundary in the right places.
 */

static int gfs2_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_holder gh;
	int ret;

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	ret = gfs2_glock_nq(&gh);
	if (unlikely(ret))
		goto out_uninit;
	if (!gfs2_is_stuffed(ip))
		ret = mpage_readpages(mapping, pages, nr_pages, gfs2_block_map);
	gfs2_glock_dq(&gh);
out_uninit:
	gfs2_holder_uninit(&gh);
	if (unlikely(test_bit(SDF_SHUTDOWN, &sdp->sd_flags)))
		ret = -EIO;
	return ret;
}

/**
 * gfs2_write_begin - Begin to write to a file
 * @file: The file to write to
 * @mapping: The mapping in which to write
 * @pos: The file offset at which to start writing
 * @len: Length of the write
 * @flags: Various flags
 * @pagep: Pointer to return the page
 * @fsdata: Pointer to return fs data (unused by GFS2)
 *
 * Returns: errno
 */

static int gfs2_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{
	struct gfs2_inode *ip = GFS2_I(mapping->host);
	struct gfs2_sbd *sdp = GFS2_SB(mapping->host);
	struct gfs2_inode *m_ip = GFS2_I(sdp->sd_statfs_inode);
	unsigned int data_blocks = 0, ind_blocks = 0, rblocks;
	unsigned requested = 0;
	int alloc_required;
	int error = 0;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	struct page *page;

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &ip->i_gh);
	error = gfs2_glock_nq(&ip->i_gh);
	if (unlikely(error))
		goto out_uninit;
	if (&ip->i_inode == sdp->sd_rindex) {
		error = gfs2_glock_nq_init(m_ip->i_gl, LM_ST_EXCLUSIVE,
					   GL_NOCACHE, &m_ip->i_gh);
		if (unlikely(error)) {
			gfs2_glock_dq(&ip->i_gh);
			goto out_uninit;
		}
	}

	alloc_required = gfs2_write_alloc_required(ip, pos, len);

	if (alloc_required || gfs2_is_jdata(ip))
		gfs2_write_calc_reserv(ip, len, &data_blocks, &ind_blocks);

	if (alloc_required) {
		struct gfs2_alloc_parms ap = { .aflags = 0, };
		error = gfs2_quota_lock_check(ip);
		if (error)
			goto out_unlock;

		requested = data_blocks + ind_blocks;
		ap.target = requested;
		error = gfs2_inplace_reserve(ip, &ap);
		if (error)
			goto out_qunlock;
	}

	rblocks = RES_DINODE + ind_blocks;
	if (gfs2_is_jdata(ip))
		rblocks += data_blocks ? data_blocks : 1;
	if (ind_blocks || data_blocks)
		rblocks += RES_STATFS + RES_QUOTA;
	if (&ip->i_inode == sdp->sd_rindex)
		rblocks += 2 * RES_STATFS;
	if (alloc_required)
		rblocks += gfs2_rg_blocks(ip, requested);

	error = gfs2_trans_begin(sdp, rblocks,
				 PAGE_CACHE_SIZE/sdp->sd_sb.sb_bsize);
	if (error)
		goto out_trans_fail;

	error = -ENOMEM;
	flags |= AOP_FLAG_NOFS;
	page = grab_cache_page_write_begin(mapping, index, flags);
	*pagep = page;
	if (unlikely(!page))
		goto out_endtrans;

	if (gfs2_is_stuffed(ip)) {
		error = 0;
		if (pos + len > sdp->sd_sb.sb_bsize - sizeof(struct gfs2_dinode)) {
			error = gfs2_unstuff_dinode(ip, page);
			if (error == 0)
				goto prepare_write;
		} else if (!PageUptodate(page)) {
			error = stuffed_readpage(ip, page);
		}
		goto out;
	}

prepare_write:
	error = __block_write_begin(page, from, len, gfs2_block_map);
out:
	if (error == 0)
		return 0;

	unlock_page(page);
	page_cache_release(page);

	gfs2_trans_end(sdp);
	if (pos + len > ip->i_inode.i_size)
		gfs2_trim_blocks(&ip->i_inode);
	goto out_trans_fail;

out_endtrans:
	gfs2_trans_end(sdp);
out_trans_fail:
	if (alloc_required) {
		gfs2_inplace_release(ip);
out_qunlock:
		gfs2_quota_unlock(ip);
	}
out_unlock:
	if (&ip->i_inode == sdp->sd_rindex) {
		gfs2_glock_dq(&m_ip->i_gh);
		gfs2_holder_uninit(&m_ip->i_gh);
	}
	gfs2_glock_dq(&ip->i_gh);
out_uninit:
	gfs2_holder_uninit(&ip->i_gh);
	return error;
}

/**
 * adjust_fs_space - Adjusts the free space available due to gfs2_grow
 * @inode: the rindex inode
 */
static void adjust_fs_space(struct inode *inode)
{
	struct gfs2_sbd *sdp = inode->i_sb->s_fs_info;
	struct gfs2_inode *m_ip = GFS2_I(sdp->sd_statfs_inode);
	struct gfs2_inode *l_ip = GFS2_I(sdp->sd_sc_inode);
	struct gfs2_statfs_change_host *m_sc = &sdp->sd_statfs_master;
	struct gfs2_statfs_change_host *l_sc = &sdp->sd_statfs_local;
	struct buffer_head *m_bh, *l_bh;
	u64 fs_total, new_free;

	/* Total up the file system space, according to the latest rindex. */
	fs_total = gfs2_ri_total(sdp);
	if (gfs2_meta_inode_buffer(m_ip, &m_bh) != 0)
		return;

	spin_lock(&sdp->sd_statfs_spin);
	gfs2_statfs_change_in(m_sc, m_bh->b_data +
			      sizeof(struct gfs2_dinode));
	if (fs_total > (m_sc->sc_total + l_sc->sc_total))
		new_free = fs_total - (m_sc->sc_total + l_sc->sc_total);
	else
		new_free = 0;
	spin_unlock(&sdp->sd_statfs_spin);
	fs_warn(sdp, "File system extended by %llu blocks.\n",
		(unsigned long long)new_free);
	gfs2_statfs_change(sdp, new_free, new_free, 0);

	if (gfs2_meta_inode_buffer(l_ip, &l_bh) != 0)
		goto out;
	update_statfs(sdp, m_bh, l_bh);
	brelse(l_bh);
out:
	brelse(m_bh);
}

/**
 * gfs2_stuffed_write_end - Write end for stuffed files
 * @inode: The inode
 * @dibh: The buffer_head containing the on-disk inode
 * @pos: The file position
 * @len: The length of the write
 * @copied: How much was actually copied by the VFS
 * @page: The page
 *
 * This copies the data from the page into the inode block after
 * the inode data structure itself.
 *
 * Returns: errno
 */
static int gfs2_stuffed_write_end(struct inode *inode, struct buffer_head *dibh,
				  loff_t pos, unsigned len, unsigned copied,
				  struct page *page)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_inode *m_ip = GFS2_I(sdp->sd_statfs_inode);
	u64 to = pos + copied;
	void *kaddr;
	unsigned char *buf = dibh->b_data + sizeof(struct gfs2_dinode);

	BUG_ON((pos + len) > (dibh->b_size - sizeof(struct gfs2_dinode)));
	kaddr = kmap_atomic(page);
	memcpy(buf + pos, kaddr + pos, copied);
	memset(kaddr + pos + copied, 0, len - copied);
	flush_dcache_page(page);
	kunmap_atomic(kaddr);

	if (!PageUptodate(page))
		SetPageUptodate(page);
	unlock_page(page);
	page_cache_release(page);

	if (copied) {
		if (inode->i_size < to)
			i_size_write(inode, to);
		mark_inode_dirty(inode);
	}

	if (inode == sdp->sd_rindex) {
		adjust_fs_space(inode);
		sdp->sd_rindex_uptodate = 0;
	}

	brelse(dibh);
	gfs2_trans_end(sdp);
	if (inode == sdp->sd_rindex) {
		gfs2_glock_dq(&m_ip->i_gh);
		gfs2_holder_uninit(&m_ip->i_gh);
	}
	gfs2_glock_dq(&ip->i_gh);
	gfs2_holder_uninit(&ip->i_gh);
	return copied;
}

/**
 * gfs2_write_end
 * @file: The file to write to
 * @mapping: The address space to write to
 * @pos: The file position
 * @len: The length of the data
 * @copied:
 * @page: The page that has been written
 * @fsdata: The fsdata (unused in GFS2)
 *
 * The main write_end function for GFS2. We have a separate one for
 * stuffed files as they are slightly different, otherwise we just
 * put our locking around the VFS provided functions.
 *
 * Returns: errno
 */

static int gfs2_write_end(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_inode *m_ip = GFS2_I(sdp->sd_statfs_inode);
	struct buffer_head *dibh;
	unsigned int from = pos & (PAGE_CACHE_SIZE - 1);
	unsigned int to = from + len;
	int ret;
	struct gfs2_trans *tr = current->journal_info;
	BUG_ON(!tr);

	BUG_ON(gfs2_glock_is_locked_by_me(ip->i_gl) == NULL);

	ret = gfs2_meta_inode_buffer(ip, &dibh);
	if (unlikely(ret)) {
		unlock_page(page);
		page_cache_release(page);
		goto failed;
	}

	if (gfs2_is_stuffed(ip))
		return gfs2_stuffed_write_end(inode, dibh, pos, len, copied, page);

	if (!gfs2_is_writeback(ip))
		gfs2_page_add_databufs(ip, page, from, to);

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (tr->tr_num_buf_new)
		__mark_inode_dirty(inode, I_DIRTY_DATASYNC);
	else
		gfs2_trans_add_meta(ip->i_gl, dibh);


	if (inode == sdp->sd_rindex) {
		adjust_fs_space(inode);
		sdp->sd_rindex_uptodate = 0;
	}

	brelse(dibh);
failed:
	gfs2_trans_end(sdp);
	gfs2_inplace_release(ip);
	if (ip->i_res->rs_qa_qd_num)
		gfs2_quota_unlock(ip);
	if (inode == sdp->sd_rindex) {
		gfs2_glock_dq(&m_ip->i_gh);
		gfs2_holder_uninit(&m_ip->i_gh);
	}
	gfs2_glock_dq(&ip->i_gh);
	gfs2_holder_uninit(&ip->i_gh);
	return ret;
}

/**
 * gfs2_set_page_dirty - Page dirtying function
 * @page: The page to dirty
 *
 * Returns: 1 if it dirtyed the page, or 0 otherwise
 */

static int gfs2_set_page_dirty(struct page *page)
{
	SetPageChecked(page);
	return __set_page_dirty_buffers(page);
}

/**
 * gfs2_bmap - Block map function
 * @mapping: Address space info
 * @lblock: The block to map
 *
 * Returns: The disk address for the block or 0 on hole or error
 */

static sector_t gfs2_bmap(struct address_space *mapping, sector_t lblock)
{
	struct gfs2_inode *ip = GFS2_I(mapping->host);
	struct gfs2_holder i_gh;
	sector_t dblock = 0;
	int error;

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY, &i_gh);
	if (error)
		return 0;

	if (!gfs2_is_stuffed(ip))
		dblock = generic_block_bmap(mapping, lblock, gfs2_block_map);

	gfs2_glock_dq_uninit(&i_gh);

	return dblock;
}

static void gfs2_discard(struct gfs2_sbd *sdp, struct buffer_head *bh)
{
	struct gfs2_bufdata *bd;

	lock_buffer(bh);
	gfs2_log_lock(sdp);
	clear_buffer_dirty(bh);
	bd = bh->b_private;
	if (bd) {
		if (!list_empty(&bd->bd_list) && !buffer_pinned(bh))
			list_del_init(&bd->bd_list);
		else
			gfs2_remove_from_journal(bh, current->journal_info, 0);
	}
	bh->b_bdev = NULL;
	clear_buffer_mapped(bh);
	clear_buffer_req(bh);
	clear_buffer_new(bh);
	gfs2_log_unlock(sdp);
	unlock_buffer(bh);
}

static void gfs2_invalidatepage(struct page *page, unsigned int offset,
				unsigned int length)
{
	struct gfs2_sbd *sdp = GFS2_SB(page->mapping->host);
	unsigned int stop = offset + length;
	int partial_page = (offset || length < PAGE_CACHE_SIZE);
	struct buffer_head *bh, *head;
	unsigned long pos = 0;

	BUG_ON(!PageLocked(page));
	if (!partial_page)
		ClearPageChecked(page);
	if (!page_has_buffers(page))
		goto out;

	bh = head = page_buffers(page);
	do {
		if (pos + bh->b_size > stop)
			return;

		if (offset <= pos)
			gfs2_discard(sdp, bh);
		pos += bh->b_size;
		bh = bh->b_this_page;
	} while (bh != head);
out:
	if (!partial_page)
		try_to_release_page(page, 0);
}

/**
 * gfs2_ok_for_dio - check that dio is valid on this file
 * @ip: The inode
 * @rw: READ or WRITE
 * @offset: The offset at which we are reading or writing
 *
 * Returns: 0 (to ignore the i/o request and thus fall back to buffered i/o)
 *          1 (to accept the i/o request)
 */
static int gfs2_ok_for_dio(struct gfs2_inode *ip, int rw, loff_t offset)
{
	/*
	 * Should we return an error here? I can't see that O_DIRECT for
	 * a stuffed file makes any sense. For now we'll silently fall
	 * back to buffered I/O
	 */
	if (gfs2_is_stuffed(ip))
		return 0;

	if (offset >= i_size_read(&ip->i_inode))
		return 0;
	return 1;
}



static ssize_t gfs2_direct_IO(int rw, struct kiocb *iocb,
			      struct iov_iter *iter, loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct address_space *mapping = inode->i_mapping;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int rv;

	/*
	 * Deferred lock, even if its a write, since we do no allocation
	 * on this path. All we need change is atime, and this lock mode
	 * ensures that other nodes have flushed their buffered read caches
	 * (i.e. their page cache entries for this inode). We do not,
	 * unfortunately have the option of only flushing a range like
	 * the VFS does.
	 */
	gfs2_holder_init(ip->i_gl, LM_ST_DEFERRED, 0, &gh);
	rv = gfs2_glock_nq(&gh);
	if (rv)
		return rv;
	rv = gfs2_ok_for_dio(ip, rw, offset);
	if (rv != 1)
		goto out; /* dio not valid, fall back to buffered i/o */

	/*
	 * Now since we are holding a deferred (CW) lock at this point, you
	 * might be wondering why this is ever needed. There is a case however
	 * where we've granted a deferred local lock against a cached exclusive
	 * glock. That is ok provided all granted local locks are deferred, but
	 * it also means that it is possible to encounter pages which are
	 * cached and possibly also mapped. So here we check for that and sort
	 * them out ahead of the dio. The glock state machine will take care of
	 * everything else.
	 *
	 * If in fact the cached glock state (gl->gl_state) is deferred (CW) in
	 * the first place, mapping->nr_pages will always be zero.
	 */
	if (mapping->nrpages) {
		loff_t lstart = offset & (PAGE_CACHE_SIZE - 1);
		loff_t len = iov_iter_count(iter);
		loff_t end = PAGE_ALIGN(offset + len) - 1;

		rv = 0;
		if (len == 0)
			goto out;
		if (test_and_clear_bit(GIF_SW_PAGED, &ip->i_flags))
			unmap_shared_mapping_range(ip->i_inode.i_mapping, offset, len);
		rv = filemap_write_and_wait_range(mapping, lstart, end);
		if (rv)
			goto out;
		if (rw == WRITE)
			truncate_inode_pages_range(mapping, lstart, end);
	}

	rv = __blockdev_direct_IO(rw, iocb, inode, inode->i_sb->s_bdev,
				  iter, offset,
				  gfs2_get_block_direct, NULL, NULL, 0);
out:
	gfs2_glock_dq(&gh);
	gfs2_holder_uninit(&gh);
	return rv;
}

/**
 * gfs2_releasepage - free the metadata associated with a page
 * @page: the page that's being released
 * @gfp_mask: passed from Linux VFS, ignored by us
 *
 * Call try_to_free_buffers() if the buffers in this page can be
 * released.
 *
 * Returns: 0
 */

int gfs2_releasepage(struct page *page, gfp_t gfp_mask)
{
	struct address_space *mapping = page->mapping;
	struct gfs2_sbd *sdp = gfs2_mapping2sbd(mapping);
	struct buffer_head *bh, *head;
	struct gfs2_bufdata *bd;

	if (!page_has_buffers(page))
		return 0;

	gfs2_log_lock(sdp);
	spin_lock(&sdp->sd_ail_lock);
	head = bh = page_buffers(page);
	do {
		if (atomic_read(&bh->b_count))
			goto cannot_release;
		bd = bh->b_private;
		if (bd && bd->bd_tr)
			goto cannot_release;
		if (buffer_pinned(bh) || buffer_dirty(bh))
			goto not_possible;
		bh = bh->b_this_page;
	} while(bh != head);
	spin_unlock(&sdp->sd_ail_lock);

	head = bh = page_buffers(page);
	do {
		bd = bh->b_private;
		if (bd) {
			gfs2_assert_warn(sdp, bd->bd_bh == bh);
			if (!list_empty(&bd->bd_list))
				list_del_init(&bd->bd_list);
			bd->bd_bh = NULL;
			bh->b_private = NULL;
			kmem_cache_free(gfs2_bufdata_cachep, bd);
		}

		bh = bh->b_this_page;
	} while (bh != head);
	gfs2_log_unlock(sdp);

	return try_to_free_buffers(page);

not_possible: /* Should never happen */
	WARN_ON(buffer_dirty(bh));
	WARN_ON(buffer_pinned(bh));
cannot_release:
	spin_unlock(&sdp->sd_ail_lock);
	gfs2_log_unlock(sdp);
	return 0;
}

static const struct address_space_operations gfs2_writeback_aops = {
	.writepage = gfs2_writepage,
	.writepages = gfs2_writepages,
	.readpage = gfs2_readpage,
	.readpages = gfs2_readpages,
	.write_begin = gfs2_write_begin,
	.write_end = gfs2_write_end,
	.bmap = gfs2_bmap,
	.invalidatepage = gfs2_invalidatepage,
	.releasepage = gfs2_releasepage,
	.direct_IO = gfs2_direct_IO,
	.migratepage = buffer_migrate_page,
	.is_partially_uptodate = block_is_partially_uptodate,
	.error_remove_page = generic_error_remove_page,
};

static const struct address_space_operations gfs2_ordered_aops = {
	.writepage = gfs2_writepage,
	.writepages = gfs2_writepages,
	.readpage = gfs2_readpage,
	.readpages = gfs2_readpages,
	.write_begin = gfs2_write_begin,
	.write_end = gfs2_write_end,
	.set_page_dirty = gfs2_set_page_dirty,
	.bmap = gfs2_bmap,
	.invalidatepage = gfs2_invalidatepage,
	.releasepage = gfs2_releasepage,
	.direct_IO = gfs2_direct_IO,
	.migratepage = buffer_migrate_page,
	.is_partially_uptodate = block_is_partially_uptodate,
	.error_remove_page = generic_error_remove_page,
};

static const struct address_space_operations gfs2_jdata_aops = {
	.writepage = gfs2_jdata_writepage,
	.writepages = gfs2_jdata_writepages,
	.readpage = gfs2_readpage,
	.readpages = gfs2_readpages,
	.write_begin = gfs2_write_begin,
	.write_end = gfs2_write_end,
	.set_page_dirty = gfs2_set_page_dirty,
	.bmap = gfs2_bmap,
	.invalidatepage = gfs2_invalidatepage,
	.releasepage = gfs2_releasepage,
	.is_partially_uptodate = block_is_partially_uptodate,
	.error_remove_page = generic_error_remove_page,
};

void gfs2_set_aops(struct inode *inode)
{
	struct gfs2_inode *ip = GFS2_I(inode);

	if (gfs2_is_writeback(ip))
		inode->i_mapping->a_ops = &gfs2_writeback_aops;
	else if (gfs2_is_ordered(ip))
		inode->i_mapping->a_ops = &gfs2_ordered_aops;
	else if (gfs2_is_jdata(ip))
		inode->i_mapping->a_ops = &gfs2_jdata_aops;
	else
		BUG();
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/dentry.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/gfs2_ondisk.h>
#include <linux/namei.h>
// #include <linux/crc32.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "dir.h"
// #include "glock.h"
// #include "super.h"
// #include "util.h"
// #include "inode.h"

/**
 * gfs2_drevalidate - Check directory lookup consistency
 * @dentry: the mapping to check
 * @flags: lookup flags
 *
 * Check to make sure the lookup necessary to arrive at this inode from its
 * parent is still good.
 *
 * Returns: 1 if the dentry is ok, 0 if it isn't
 */

static int gfs2_drevalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry *parent;
	struct gfs2_sbd *sdp;
	struct gfs2_inode *dip;
	struct inode *inode;
	struct gfs2_holder d_gh;
	struct gfs2_inode *ip = NULL;
	int error;
	int had_lock = 0;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	parent = dget_parent(dentry);
	sdp = GFS2_SB(parent->d_inode);
	dip = GFS2_I(parent->d_inode);
	inode = dentry->d_inode;

	if (inode) {
		if (is_bad_inode(inode))
			goto invalid;
		ip = GFS2_I(inode);
	}

	if (sdp->sd_lockstruct.ls_ops->lm_mount == NULL)
		goto valid;

	had_lock = (gfs2_glock_is_locked_by_me(dip->i_gl) != NULL);
	if (!had_lock) {
		error = gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED, 0, &d_gh);
		if (error)
			goto fail;
	}

	error = gfs2_dir_check(parent->d_inode, &dentry->d_name, ip);
	switch (error) {
	case 0:
		if (!inode)
			goto invalid_gunlock;
		break;
	case -ENOENT:
		if (!inode)
			goto valid_gunlock;
		goto invalid_gunlock;
	default:
		goto fail_gunlock;
	}

valid_gunlock:
	if (!had_lock)
		gfs2_glock_dq_uninit(&d_gh);
valid:
	dput(parent);
	return 1;

invalid_gunlock:
	if (!had_lock)
		gfs2_glock_dq_uninit(&d_gh);
invalid:
	if (check_submounts_and_drop(dentry) != 0)
		goto valid;

	dput(parent);
	return 0;

fail_gunlock:
	gfs2_glock_dq_uninit(&d_gh);
fail:
	dput(parent);
	return 0;
}

static int gfs2_dhash(const struct dentry *dentry, struct qstr *str)
{
	str->hash = gfs2_disk_hash(str->name, str->len);
	return 0;
}

static int gfs2_dentry_delete(const struct dentry *dentry)
{
	struct gfs2_inode *ginode;

	if (!dentry->d_inode)
		return 0;

	ginode = GFS2_I(dentry->d_inode);
	if (!ginode->i_iopen_gh.gh_gl)
		return 0;

	if (test_bit(GLF_DEMOTE, &ginode->i_iopen_gh.gh_gl->gl_flags))
		return 1;

	return 0;
}

const struct dentry_operations gfs2_dops = {
	.d_revalidate = gfs2_drevalidate,
	.d_hash = gfs2_dhash,
	.d_delete = gfs2_dentry_delete,
};
/************************************************************/
/* ../linux-3.17/fs/gfs2/export.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
#include <linux/exportfs.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/crc32.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "dir.h"
// #include "glock.h"
// #include "glops.h"
// #include "inode.h"
// #include "super.h"
// #include "rgrp.h"
// #include "util.h"

#define GFS2_SMALL_FH_SIZE 4
#define GFS2_LARGE_FH_SIZE 8
#define GFS2_OLD_FH_SIZE 10

static int gfs2_encode_fh(struct inode *inode, __u32 *p, int *len,
			  struct inode *parent)
{
	__be32 *fh = (__force __be32 *)p;
	struct super_block *sb = inode->i_sb;
	struct gfs2_inode *ip = GFS2_I(inode);

	if (parent && (*len < GFS2_LARGE_FH_SIZE)) {
		*len = GFS2_LARGE_FH_SIZE;
		return FILEID_INVALID;
	} else if (*len < GFS2_SMALL_FH_SIZE) {
		*len = GFS2_SMALL_FH_SIZE;
		return FILEID_INVALID;
	}

	fh[0] = cpu_to_be32(ip->i_no_formal_ino >> 32);
	fh[1] = cpu_to_be32(ip->i_no_formal_ino & 0xFFFFFFFF);
	fh[2] = cpu_to_be32(ip->i_no_addr >> 32);
	fh[3] = cpu_to_be32(ip->i_no_addr & 0xFFFFFFFF);
	*len = GFS2_SMALL_FH_SIZE;

	if (!parent || inode == sb->s_root->d_inode)
		return *len;

	ip = GFS2_I(parent);

	fh[4] = cpu_to_be32(ip->i_no_formal_ino >> 32);
	fh[5] = cpu_to_be32(ip->i_no_formal_ino & 0xFFFFFFFF);
	fh[6] = cpu_to_be32(ip->i_no_addr >> 32);
	fh[7] = cpu_to_be32(ip->i_no_addr & 0xFFFFFFFF);
	*len = GFS2_LARGE_FH_SIZE;

	return *len;
}

struct get_name_filldir {
	struct dir_context ctx;
	struct gfs2_inum_host inum;
	char *name;
};

static int get_name_filldir(void *opaque, const char *name, int length,
			    loff_t offset, u64 inum, unsigned int type)
{
	struct get_name_filldir *gnfd = opaque;

	if (inum != gnfd->inum.no_addr)
		return 0;

	memcpy(gnfd->name, name, length);
	gnfd->name[length] = 0;

	return 1;
}

static int gfs2_get_name(struct dentry *parent, char *name,
			 struct dentry *child)
{
	struct inode *dir = parent->d_inode;
	struct inode *inode = child->d_inode;
	struct gfs2_inode *dip, *ip;
	struct get_name_filldir gnfd = {
		.ctx.actor = get_name_filldir,
		.name = name
	};
	struct gfs2_holder gh;
	int error;
	struct file_ra_state f_ra = { .start = 0 };

	if (!dir)
		return -EINVAL;

	if (!S_ISDIR(dir->i_mode) || !inode)
		return -EINVAL;

	dip = GFS2_I(dir);
	ip = GFS2_I(inode);

	*name = 0;
	gnfd.inum.no_addr = ip->i_no_addr;
	gnfd.inum.no_formal_ino = ip->i_no_formal_ino;

	error = gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED, 0, &gh);
	if (error)
		return error;

	error = gfs2_dir_read(dir, &gnfd.ctx, &f_ra);

	gfs2_glock_dq_uninit(&gh);

	if (!error && !*name)
		error = -ENOENT;

	return error;
}

static struct dentry *gfs2_get_parent(struct dentry *child)
{
	return d_obtain_alias(gfs2_lookupi(child->d_inode, &gfs2_qdotdot, 1));
}

static struct dentry *gfs2_get_dentry(struct super_block *sb,
				      struct gfs2_inum_host *inum)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct inode *inode;

	inode = gfs2_ilookup(sb, inum->no_addr, 0);
	if (inode) {
		if (GFS2_I(inode)->i_no_formal_ino != inum->no_formal_ino) {
			iput(inode);
			return ERR_PTR(-ESTALE);
		}
		goto out_inode;
	}

	inode = gfs2_lookup_by_inum(sdp, inum->no_addr, &inum->no_formal_ino,
				    GFS2_BLKST_DINODE);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

out_inode:
	return d_obtain_alias(inode);
}

static struct dentry *gfs2_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	struct gfs2_inum_host this;
	__be32 *fh = (__force __be32 *)fid->raw;

	switch (fh_type) {
	case GFS2_SMALL_FH_SIZE:
	case GFS2_LARGE_FH_SIZE:
	case GFS2_OLD_FH_SIZE:
		if (fh_len < GFS2_SMALL_FH_SIZE)
			return NULL;
		this.no_formal_ino = ((u64)be32_to_cpu(fh[0])) << 32;
		this.no_formal_ino |= be32_to_cpu(fh[1]);
		this.no_addr = ((u64)be32_to_cpu(fh[2])) << 32;
		this.no_addr |= be32_to_cpu(fh[3]);
		return gfs2_get_dentry(sb, &this);
	default:
		return NULL;
	}
}

static struct dentry *gfs2_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	struct gfs2_inum_host parent;
	__be32 *fh = (__force __be32 *)fid->raw;

	switch (fh_type) {
	case GFS2_LARGE_FH_SIZE:
	case GFS2_OLD_FH_SIZE:
		if (fh_len < GFS2_LARGE_FH_SIZE)
			return NULL;
		parent.no_formal_ino = ((u64)be32_to_cpu(fh[4])) << 32;
		parent.no_formal_ino |= be32_to_cpu(fh[5]);
		parent.no_addr = ((u64)be32_to_cpu(fh[6])) << 32;
		parent.no_addr |= be32_to_cpu(fh[7]);
		return gfs2_get_dentry(sb, &parent);
	default:
		return NULL;
	}
}

const struct export_operations gfs2_export_ops = {
	.encode_fh = gfs2_encode_fh,
	.fh_to_dentry = gfs2_fh_to_dentry,
	.fh_to_parent = gfs2_fh_to_parent,
	.get_name = gfs2_get_name,
	.get_parent = gfs2_get_parent,
};
/************************************************************/
/* ../linux-3.17/fs/gfs2/file.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/pagemap.h>
#include <linux/uio.h>
// #include <linux/blkdev.h>
// #include <linux/mm.h>
#include <linux/mount.h>
// #include <linux/fs.h>
// #include <linux/gfs2_ondisk.h>
#include <linux/falloc.h>
// #include <linux/swap.h>
// #include <linux/crc32.h>
// #include <linux/writeback.h>
// #include <asm/uaccess.h>
#include <linux/dlm.h>
#include <linux/dlm_plock.h>
// #include <linux/aio.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "bmap.h"
// #include "dir.h"
// #include "glock.h"
// #include "glops.h"
// #include "inode.h"
// #include "log.h"
// #include "meta_io.h"
// #include "quota.h"
// #include "rgrp.h"
// #include "trans.h"
// #include "util.h"

/**
 * gfs2_llseek - seek to a location in a file
 * @file: the file
 * @offset: the offset
 * @whence: Where to seek from (SEEK_SET, SEEK_CUR, or SEEK_END)
 *
 * SEEK_END requires the glock for the file because it references the
 * file's size.
 *
 * Returns: The new offset, or errno
 */

static loff_t gfs2_llseek(struct file *file, loff_t offset, int whence)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);
	struct gfs2_holder i_gh;
	loff_t error;

	switch (whence) {
	case SEEK_END: /* These reference inode->i_size */
	case SEEK_DATA:
	case SEEK_HOLE:
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY,
					   &i_gh);
		if (!error) {
			error = generic_file_llseek(file, offset, whence);
			gfs2_glock_dq_uninit(&i_gh);
		}
		break;
	case SEEK_CUR:
	case SEEK_SET:
		error = generic_file_llseek(file, offset, whence);
		break;
	default:
		error = -EINVAL;
	}

	return error;
}

/**
 * gfs2_readdir - Iterator for a directory
 * @file: The directory to read from
 * @ctx: What to feed directory entries to
 *
 * Returns: errno
 */

static int gfs2_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file->f_mapping->host;
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_holder d_gh;
	int error;

	error = gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED, 0, &d_gh);
	if (error)
		return error;

	error = gfs2_dir_read(dir, ctx, &file->f_ra);

	gfs2_glock_dq_uninit(&d_gh);

	return error;
}

/**
 * fsflags_cvt
 * @table: A table of 32 u32 flags
 * @val: a 32 bit value to convert
 *
 * This function can be used to convert between fsflags values and
 * GFS2's own flags values.
 *
 * Returns: the converted flags
 */
static u32 fsflags_cvt(const u32 *table, u32 val)
{
	u32 res = 0;
	while(val) {
		if (val & 1)
			res |= *table;
		table++;
		val >>= 1;
	}
	return res;
}

static const u32 fsflags_to_gfs2[32] = {
	[3] = GFS2_DIF_SYNC,
	[4] = GFS2_DIF_IMMUTABLE,
	[5] = GFS2_DIF_APPENDONLY,
	[7] = GFS2_DIF_NOATIME,
	[12] = GFS2_DIF_EXHASH,
	[14] = GFS2_DIF_INHERIT_JDATA,
	[17] = GFS2_DIF_TOPDIR,
};

static const u32 gfs2_to_fsflags[32] = {
	[gfs2fl_Sync] = FS_SYNC_FL,
	[gfs2fl_Immutable] = FS_IMMUTABLE_FL,
	[gfs2fl_AppendOnly] = FS_APPEND_FL,
	[gfs2fl_NoAtime] = FS_NOATIME_FL,
	[gfs2fl_ExHash] = FS_INDEX_FL,
	[gfs2fl_TopLevel] = FS_TOPDIR_FL,
	[gfs2fl_InheritJdata] = FS_JOURNAL_DATA_FL,
};

static int gfs2_get_flags(struct file *filp, u32 __user *ptr)
{
	struct inode *inode = file_inode(filp);
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int error;
	u32 fsflags;

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	error = gfs2_glock_nq(&gh);
	if (error)
		return error;

	fsflags = fsflags_cvt(gfs2_to_fsflags, ip->i_diskflags);
	if (!S_ISDIR(inode->i_mode) && ip->i_diskflags & GFS2_DIF_JDATA)
		fsflags |= FS_JOURNAL_DATA_FL;
	if (put_user(fsflags, ptr))
		error = -EFAULT;

	gfs2_glock_dq(&gh);
	gfs2_holder_uninit(&gh);
	return error;
}

void gfs2_set_inode_flags(struct inode *inode)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	unsigned int flags = inode->i_flags;

	flags &= ~(S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME|S_DIRSYNC|S_NOSEC);
	if ((ip->i_eattr == 0) && !is_sxid(inode->i_mode))
		inode->i_flags |= S_NOSEC;
	if (ip->i_diskflags & GFS2_DIF_IMMUTABLE)
		flags |= S_IMMUTABLE;
	if (ip->i_diskflags & GFS2_DIF_APPENDONLY)
		flags |= S_APPEND;
	if (ip->i_diskflags & GFS2_DIF_NOATIME)
		flags |= S_NOATIME;
	if (ip->i_diskflags & GFS2_DIF_SYNC)
		flags |= S_SYNC;
	inode->i_flags = flags;
}

/* Flags that can be set by user space */
#define GFS2_FLAGS_USER_SET (GFS2_DIF_JDATA|			\
			     GFS2_DIF_IMMUTABLE|		\
			     GFS2_DIF_APPENDONLY|		\
			     GFS2_DIF_NOATIME|			\
			     GFS2_DIF_SYNC|			\
			     GFS2_DIF_SYSTEM|			\
			     GFS2_DIF_TOPDIR|			\
			     GFS2_DIF_INHERIT_JDATA)

/**
 * do_gfs2_set_flags - set flags on an inode
 * @filp: file pointer
 * @reqflags: The flags to set
 * @mask: Indicates which flags are valid
 *
 */
static int do_gfs2_set_flags(struct file *filp, u32 reqflags, u32 mask)
{
	struct inode *inode = file_inode(filp);
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct buffer_head *bh;
	struct gfs2_holder gh;
	int error;
	u32 new_flags, flags;

	error = mnt_want_write_file(filp);
	if (error)
		return error;

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	if (error)
		goto out_drop_write;

	error = -EACCES;
	if (!inode_owner_or_capable(inode))
		goto out;

	error = 0;
	flags = ip->i_diskflags;
	new_flags = (flags & ~mask) | (reqflags & mask);
	if ((new_flags ^ flags) == 0)
		goto out;

	error = -EINVAL;
	if ((new_flags ^ flags) & ~GFS2_FLAGS_USER_SET)
		goto out;

	error = -EPERM;
	if (IS_IMMUTABLE(inode) && (new_flags & GFS2_DIF_IMMUTABLE))
		goto out;
	if (IS_APPEND(inode) && (new_flags & GFS2_DIF_APPENDONLY))
		goto out;
	if (((new_flags ^ flags) & GFS2_DIF_IMMUTABLE) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		goto out;
	if (!IS_IMMUTABLE(inode)) {
		error = gfs2_permission(inode, MAY_WRITE);
		if (error)
			goto out;
	}
	if ((flags ^ new_flags) & GFS2_DIF_JDATA) {
		if (flags & GFS2_DIF_JDATA)
			gfs2_log_flush(sdp, ip->i_gl, NORMAL_FLUSH);
		error = filemap_fdatawrite(inode->i_mapping);
		if (error)
			goto out;
		error = filemap_fdatawait(inode->i_mapping);
		if (error)
			goto out;
	}
	error = gfs2_trans_begin(sdp, RES_DINODE, 0);
	if (error)
		goto out;
	error = gfs2_meta_inode_buffer(ip, &bh);
	if (error)
		goto out_trans_end;
	gfs2_trans_add_meta(ip->i_gl, bh);
	ip->i_diskflags = new_flags;
	gfs2_dinode_out(ip, bh->b_data);
	brelse(bh);
	gfs2_set_inode_flags(inode);
	gfs2_set_aops(inode);
out_trans_end:
	gfs2_trans_end(sdp);
out:
	gfs2_glock_dq_uninit(&gh);
out_drop_write:
	mnt_drop_write_file(filp);
	return error;
}

static int gfs2_set_flags(struct file *filp, u32 __user *ptr)
{
	struct inode *inode = file_inode(filp);
	u32 fsflags, gfsflags;

	if (get_user(fsflags, ptr))
		return -EFAULT;

	gfsflags = fsflags_cvt(fsflags_to_gfs2, fsflags);
	if (!S_ISDIR(inode->i_mode)) {
		gfsflags &= ~GFS2_DIF_TOPDIR;
		if (gfsflags & GFS2_DIF_INHERIT_JDATA)
			gfsflags ^= (GFS2_DIF_JDATA | GFS2_DIF_INHERIT_JDATA);
		return do_gfs2_set_flags(filp, gfsflags, ~0);
	}
	return do_gfs2_set_flags(filp, gfsflags, ~GFS2_DIF_JDATA);
}

static long gfs2_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch(cmd) {
	case FS_IOC_GETFLAGS:
		return gfs2_get_flags(filp, (u32 __user *)arg);
	case FS_IOC_SETFLAGS:
		return gfs2_set_flags(filp, (u32 __user *)arg);
	case FITRIM:
		return gfs2_fitrim(filp, (void __user *)arg);
	}
	return -ENOTTY;
}

/**
 * gfs2_size_hint - Give a hint to the size of a write request
 * @filep: The struct file
 * @offset: The file offset of the write
 * @size: The length of the write
 *
 * When we are about to do a write, this function records the total
 * write size in order to provide a suitable hint to the lower layers
 * about how many blocks will be required.
 *
 */

static void gfs2_size_hint(struct file *filep, loff_t offset, size_t size)
{
	struct inode *inode = file_inode(filep);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_inode *ip = GFS2_I(inode);
	size_t blks = (size + sdp->sd_sb.sb_bsize - 1) >> sdp->sd_sb.sb_bsize_shift;
	int hint = min_t(size_t, INT_MAX, blks);

	atomic_set(&ip->i_res->rs_sizehint, hint);
}

/**
 * gfs2_allocate_page_backing - Use bmap to allocate blocks
 * @page: The (locked) page to allocate backing for
 *
 * We try to allocate all the blocks required for the page in
 * one go. This might fail for various reasons, so we keep
 * trying until all the blocks to back this page are allocated.
 * If some of the blocks are already allocated, thats ok too.
 */

static int gfs2_allocate_page_backing(struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct buffer_head bh;
	unsigned long size = PAGE_CACHE_SIZE;
	u64 lblock = page->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);

	do {
		bh.b_state = 0;
		bh.b_size = size;
		gfs2_block_map(inode, lblock, &bh, 1);
		if (!buffer_mapped(&bh))
			return -EIO;
		size -= bh.b_size;
		lblock += (bh.b_size >> inode->i_blkbits);
	} while(size > 0);
	return 0;
}

/**
 * gfs2_page_mkwrite - Make a shared, mmap()ed, page writable
 * @vma: The virtual memory area
 * @vmf: The virtual memory fault containing the page to become writable
 *
 * When the page becomes writable, we need to ensure that we have
 * blocks allocated on disk to back that page.
 */

static int gfs2_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_alloc_parms ap = { .aflags = 0, };
	unsigned long last_index;
	u64 pos = page->index << PAGE_CACHE_SHIFT;
	unsigned int data_blocks, ind_blocks, rblocks;
	struct gfs2_holder gh;
	loff_t size;
	int ret;

	sb_start_pagefault(inode->i_sb);

	/* Update file times before taking page lock */
	file_update_time(vma->vm_file);

	ret = get_write_access(inode);
	if (ret)
		goto out;

	ret = gfs2_rs_alloc(ip);
	if (ret)
		goto out_write_access;

	gfs2_size_hint(vma->vm_file, pos, PAGE_CACHE_SIZE);

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret)
		goto out_uninit;

	set_bit(GLF_DIRTY, &ip->i_gl->gl_flags);
	set_bit(GIF_SW_PAGED, &ip->i_flags);

	if (!gfs2_write_alloc_required(ip, pos, PAGE_CACHE_SIZE)) {
		lock_page(page);
		if (!PageUptodate(page) || page->mapping != inode->i_mapping) {
			ret = -EAGAIN;
			unlock_page(page);
		}
		goto out_unlock;
	}

	ret = gfs2_rindex_update(sdp);
	if (ret)
		goto out_unlock;

	ret = gfs2_quota_lock_check(ip);
	if (ret)
		goto out_unlock;
	gfs2_write_calc_reserv(ip, PAGE_CACHE_SIZE, &data_blocks, &ind_blocks);
	ap.target = data_blocks + ind_blocks;
	ret = gfs2_inplace_reserve(ip, &ap);
	if (ret)
		goto out_quota_unlock;

	rblocks = RES_DINODE + ind_blocks;
	if (gfs2_is_jdata(ip))
		rblocks += data_blocks ? data_blocks : 1;
	if (ind_blocks || data_blocks) {
		rblocks += RES_STATFS + RES_QUOTA;
		rblocks += gfs2_rg_blocks(ip, data_blocks + ind_blocks);
	}
	ret = gfs2_trans_begin(sdp, rblocks, 0);
	if (ret)
		goto out_trans_fail;

	lock_page(page);
	ret = -EINVAL;
	size = i_size_read(inode);
	last_index = (size - 1) >> PAGE_CACHE_SHIFT;
	/* Check page index against inode size */
	if (size == 0 || (page->index > last_index))
		goto out_trans_end;

	ret = -EAGAIN;
	/* If truncated, we must retry the operation, we may have raced
	 * with the glock demotion code.
	 */
	if (!PageUptodate(page) || page->mapping != inode->i_mapping)
		goto out_trans_end;

	/* Unstuff, if required, and allocate backing blocks for page */
	ret = 0;
	if (gfs2_is_stuffed(ip))
		ret = gfs2_unstuff_dinode(ip, page);
	if (ret == 0)
		ret = gfs2_allocate_page_backing(page);

out_trans_end:
	if (ret)
		unlock_page(page);
	gfs2_trans_end(sdp);
out_trans_fail:
	gfs2_inplace_release(ip);
out_quota_unlock:
	gfs2_quota_unlock(ip);
out_unlock:
	gfs2_glock_dq(&gh);
out_uninit:
	gfs2_holder_uninit(&gh);
	if (ret == 0) {
		set_page_dirty(page);
		wait_for_stable_page(page);
	}
out_write_access:
	put_write_access(inode);
out:
	sb_end_pagefault(inode->i_sb);
	return block_page_mkwrite_return(ret);
}

static const struct vm_operations_struct gfs2_vm_ops = {
	.fault = filemap_fault,
	.map_pages = filemap_map_pages,
	.page_mkwrite = gfs2_page_mkwrite,
	.remap_pages = generic_file_remap_pages,
};

/**
 * gfs2_mmap -
 * @file: The file to map
 * @vma: The VMA which described the mapping
 *
 * There is no need to get a lock here unless we should be updating
 * atime. We ignore any locking errors since the only consequence is
 * a missed atime update (which will just be deferred until later).
 *
 * Returns: 0
 */

static int gfs2_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);

	if (!(file->f_flags & O_NOATIME) &&
	    !IS_NOATIME(&ip->i_inode)) {
		struct gfs2_holder i_gh;
		int error;

		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY,
					   &i_gh);
		if (error)
			return error;
		/* grab lock to update inode */
		gfs2_glock_dq_uninit(&i_gh);
		file_accessed(file);
	}
	vma->vm_ops = &gfs2_vm_ops;

	return 0;
}

/**
 * gfs2_open_common - This is common to open and atomic_open
 * @inode: The inode being opened
 * @file: The file being opened
 *
 * This maybe called under a glock or not depending upon how it has
 * been called. We must always be called under a glock for regular
 * files, however. For other file types, it does not matter whether
 * we hold the glock or not.
 *
 * Returns: Error code or 0 for success
 */

int gfs2_open_common(struct inode *inode, struct file *file)
{
	struct gfs2_file *fp;
	int ret;

	if (S_ISREG(inode->i_mode)) {
		ret = generic_file_open(inode, file);
		if (ret)
			return ret;
	}

	fp = kzalloc(sizeof(struct gfs2_file), GFP_NOFS);
	if (!fp)
		return -ENOMEM;

	mutex_init(&fp->f_fl_mutex);

	gfs2_assert_warn(GFS2_SB(inode), !file->private_data);
	file->private_data = fp;
	return 0;
}

/**
 * gfs2_open - open a file
 * @inode: the inode to open
 * @file: the struct file for this opening
 *
 * After atomic_open, this function is only used for opening files
 * which are already cached. We must still get the glock for regular
 * files to ensure that we have the file size uptodate for the large
 * file check which is in the common code. That is only an issue for
 * regular files though.
 *
 * Returns: errno
 */

static int gfs2_open(struct inode *inode, struct file *file)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder i_gh;
	int error;
	bool need_unlock = false;

	if (S_ISREG(ip->i_inode.i_mode)) {
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY,
					   &i_gh);
		if (error)
			return error;
		need_unlock = true;
	}

	error = gfs2_open_common(inode, file);

	if (need_unlock)
		gfs2_glock_dq_uninit(&i_gh);

	return error;
}

/**
 * gfs2_release - called to close a struct file
 * @inode: the inode the struct file belongs to
 * @file: the struct file being closed
 *
 * Returns: errno
 */

static int gfs2_release(struct inode *inode, struct file *file)
{
	struct gfs2_inode *ip = GFS2_I(inode);

	kfree(file->private_data);
	file->private_data = NULL;

	if (!(file->f_mode & FMODE_WRITE))
		return 0;

	gfs2_rs_delete(ip, &inode->i_writecount);
	return 0;
}

/**
 * gfs2_fsync - sync the dirty data for a file (across the cluster)
 * @file: the file that points to the dentry
 * @start: the start position in the file to sync
 * @end: the end position in the file to sync
 * @datasync: set if we can ignore timestamp changes
 *
 * We split the data flushing here so that we don't wait for the data
 * until after we've also sent the metadata to disk. Note that for
 * data=ordered, we will write & wait for the data at the log flush
 * stage anyway, so this is unlikely to make much of a difference
 * except in the data=writeback case.
 *
 * If the fdatawrite fails due to any reason except -EIO, we will
 * continue the remainder of the fsync, although we'll still report
 * the error at the end. This is to match filemap_write_and_wait_range()
 * behaviour.
 *
 * Returns: errno
 */

static int gfs2_fsync(struct file *file, loff_t start, loff_t end,
		      int datasync)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	int sync_state = inode->i_state & I_DIRTY;
	struct gfs2_inode *ip = GFS2_I(inode);
	int ret = 0, ret1 = 0;

	if (mapping->nrpages) {
		ret1 = filemap_fdatawrite_range(mapping, start, end);
		if (ret1 == -EIO)
			return ret1;
	}

	if (!gfs2_is_jdata(ip))
		sync_state &= ~I_DIRTY_PAGES;
	if (datasync)
		sync_state &= ~I_DIRTY_SYNC;

	if (sync_state) {
		ret = sync_inode_metadata(inode, 1);
		if (ret)
			return ret;
		if (gfs2_is_jdata(ip))
			filemap_write_and_wait(mapping);
		gfs2_ail_flush(ip->i_gl, 1);
	}

	if (mapping->nrpages)
		ret = filemap_fdatawait_range(mapping, start, end);

	return ret ? ret : ret1;
}

/**
 * gfs2_file_write_iter - Perform a write to a file
 * @iocb: The io context
 * @iov: The data to write
 * @nr_segs: Number of @iov segments
 * @pos: The file position
 *
 * We have to do a lock/unlock here to refresh the inode size for
 * O_APPEND writes, otherwise we can land up writing at the wrong
 * offset. There is still a race, but provided the app is using its
 * own file locking, this will make O_APPEND work as expected.
 *
 */

static ssize_t gfs2_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct gfs2_inode *ip = GFS2_I(file_inode(file));
	int ret;

	ret = gfs2_rs_alloc(ip);
	if (ret)
		return ret;

	gfs2_size_hint(file, iocb->ki_pos, iov_iter_count(from));

	if (file->f_flags & O_APPEND) {
		struct gfs2_holder gh;

		ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
		if (ret)
			return ret;
		gfs2_glock_dq_uninit(&gh);
	}

	return generic_file_write_iter(iocb, from);
}

static int fallocate_chunk(struct inode *inode, loff_t offset, loff_t len,
			   int mode)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct buffer_head *dibh;
	int error;
	loff_t size = len;
	unsigned int nr_blks;
	sector_t lblock = offset >> inode->i_blkbits;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (unlikely(error))
		return error;

	gfs2_trans_add_meta(ip->i_gl, dibh);

	if (gfs2_is_stuffed(ip)) {
		error = gfs2_unstuff_dinode(ip, NULL);
		if (unlikely(error))
			goto out;
	}

	while (len) {
		struct buffer_head bh_map = { .b_state = 0, .b_blocknr = 0 };
		bh_map.b_size = len;
		set_buffer_zeronew(&bh_map);

		error = gfs2_block_map(inode, lblock, &bh_map, 1);
		if (unlikely(error))
			goto out;
		len -= bh_map.b_size;
		nr_blks = bh_map.b_size >> inode->i_blkbits;
		lblock += nr_blks;
		if (!buffer_new(&bh_map))
			continue;
		if (unlikely(!buffer_zeronew(&bh_map))) {
			error = -EIO;
			goto out;
		}
	}
	if (offset + size > inode->i_size && !(mode & FALLOC_FL_KEEP_SIZE))
		i_size_write(inode, offset + size);

	mark_inode_dirty(inode);

out:
	brelse(dibh);
	return error;
}

static void calc_max_reserv(struct gfs2_inode *ip, loff_t max, loff_t *len,
			    unsigned int *data_blocks, unsigned int *ind_blocks)
{
	const struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	unsigned int max_blocks = ip->i_rgd->rd_free_clone;
	unsigned int tmp, max_data = max_blocks - 3 * (sdp->sd_max_height - 1);

	for (tmp = max_data; tmp > sdp->sd_diptrs;) {
		tmp = DIV_ROUND_UP(tmp, sdp->sd_inptrs);
		max_data -= tmp;
	}
	/* This calculation isn't the exact reverse of gfs2_write_calc_reserve,
	   so it might end up with fewer data blocks */
	if (max_data <= *data_blocks)
		return;
	*data_blocks = max_data;
	*ind_blocks = max_blocks - max_data;
	*len = ((loff_t)max_data - 3) << sdp->sd_sb.sb_bsize_shift;
	if (*len > max) {
		*len = max;
		gfs2_write_calc_reserv(ip, max, data_blocks, ind_blocks);
	}
}

static long gfs2_fallocate(struct file *file, int mode, loff_t offset,
			   loff_t len)
{
	struct inode *inode = file_inode(file);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_alloc_parms ap = { .aflags = 0, };
	unsigned int data_blocks = 0, ind_blocks = 0, rblocks;
	loff_t bytes, max_bytes;
	int error;
	const loff_t pos = offset;
	const loff_t count = len;
	loff_t bsize_mask = ~((loff_t)sdp->sd_sb.sb_bsize - 1);
	loff_t next = (offset + len - 1) >> sdp->sd_sb.sb_bsize_shift;
	loff_t max_chunk_size = UINT_MAX & bsize_mask;
	struct gfs2_holder gh;

	next = (next + 1) << sdp->sd_sb.sb_bsize_shift;

	/* We only support the FALLOC_FL_KEEP_SIZE mode */
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	offset &= bsize_mask;

	len = next - offset;
	bytes = sdp->sd_max_rg_data * sdp->sd_sb.sb_bsize / 2;
	if (!bytes)
		bytes = UINT_MAX;
	bytes &= bsize_mask;
	if (bytes == 0)
		bytes = sdp->sd_sb.sb_bsize;

	error = gfs2_rs_alloc(ip);
	if (error)
		return error;

	mutex_lock(&inode->i_mutex);

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	error = gfs2_glock_nq(&gh);
	if (unlikely(error))
		goto out_uninit;

	gfs2_size_hint(file, offset, len);

	while (len > 0) {
		if (len < bytes)
			bytes = len;
		if (!gfs2_write_alloc_required(ip, offset, bytes)) {
			len -= bytes;
			offset += bytes;
			continue;
		}
		error = gfs2_quota_lock_check(ip);
		if (error)
			goto out_unlock;

retry:
		gfs2_write_calc_reserv(ip, bytes, &data_blocks, &ind_blocks);

		ap.target = data_blocks + ind_blocks;
		error = gfs2_inplace_reserve(ip, &ap);
		if (error) {
			if (error == -ENOSPC && bytes > sdp->sd_sb.sb_bsize) {
				bytes >>= 1;
				bytes &= bsize_mask;
				if (bytes == 0)
					bytes = sdp->sd_sb.sb_bsize;
				goto retry;
			}
			goto out_qunlock;
		}
		max_bytes = bytes;
		calc_max_reserv(ip, (len > max_chunk_size)? max_chunk_size: len,
				&max_bytes, &data_blocks, &ind_blocks);

		rblocks = RES_DINODE + ind_blocks + RES_STATFS + RES_QUOTA +
			  RES_RG_HDR + gfs2_rg_blocks(ip, data_blocks + ind_blocks);
		if (gfs2_is_jdata(ip))
			rblocks += data_blocks ? data_blocks : 1;

		error = gfs2_trans_begin(sdp, rblocks,
					 PAGE_CACHE_SIZE/sdp->sd_sb.sb_bsize);
		if (error)
			goto out_trans_fail;

		error = fallocate_chunk(inode, offset, max_bytes, mode);
		gfs2_trans_end(sdp);

		if (error)
			goto out_trans_fail;

		len -= max_bytes;
		offset += max_bytes;
		gfs2_inplace_release(ip);
		gfs2_quota_unlock(ip);
	}

	if (error == 0)
		error = generic_write_sync(file, pos, count);
	goto out_unlock;

out_trans_fail:
	gfs2_inplace_release(ip);
out_qunlock:
	gfs2_quota_unlock(ip);
out_unlock:
	gfs2_glock_dq(&gh);
out_uninit:
	gfs2_holder_uninit(&gh);
	mutex_unlock(&inode->i_mutex);
	return error;
}

#ifdef CONFIG_GFS2_FS_LOCKING_DLM

/**
 * gfs2_setlease - acquire/release a file lease
 * @file: the file pointer
 * @arg: lease type
 * @fl: file lock
 *
 * We don't currently have a way to enforce a lease across the whole
 * cluster; until we do, disable leases (by just returning -EINVAL),
 * unless the administrator has requested purely local locking.
 *
 * Locking: called under i_lock
 *
 * Returns: errno
 */

static int gfs2_setlease(struct file *file, long arg, struct file_lock **fl)
{
	return -EINVAL;
}

/**
 * gfs2_lock - acquire/release a posix lock on a file
 * @file: the file pointer
 * @cmd: either modify or retrieve lock state, possibly wait
 * @fl: type and range of lock
 *
 * Returns: errno
 */

static int gfs2_lock(struct file *file, int cmd, struct file_lock *fl)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);
	struct gfs2_sbd *sdp = GFS2_SB(file->f_mapping->host);
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;

	if (!(fl->fl_flags & FL_POSIX))
		return -ENOLCK;
	if (__mandatory_lock(&ip->i_inode) && fl->fl_type != F_UNLCK)
		return -ENOLCK;

	if (cmd == F_CANCELLK) {
		/* Hack: */
		cmd = F_SETLK;
		fl->fl_type = F_UNLCK;
	}
	if (unlikely(test_bit(SDF_SHUTDOWN, &sdp->sd_flags))) {
		if (fl->fl_type == F_UNLCK)
			posix_lock_file_wait(file, fl);
		return -EIO;
	}
	if (IS_GETLK(cmd))
		return dlm_posix_get(ls->ls_dlm, ip->i_no_addr, file, fl);
	else if (fl->fl_type == F_UNLCK)
		return dlm_posix_unlock(ls->ls_dlm, ip->i_no_addr, file, fl);
	else
		return dlm_posix_lock(ls->ls_dlm, ip->i_no_addr, file, cmd, fl);
}

static int do_flock(struct file *file, int cmd, struct file_lock *fl)
{
	struct gfs2_file *fp = file->private_data;
	struct gfs2_holder *fl_gh = &fp->f_fl_gh;
	struct gfs2_inode *ip = GFS2_I(file_inode(file));
	struct gfs2_glock *gl;
	unsigned int state;
	int flags;
	int error = 0;

	state = (fl->fl_type == F_WRLCK) ? LM_ST_EXCLUSIVE : LM_ST_SHARED;
	flags = (IS_SETLKW(cmd) ? 0 : LM_FLAG_TRY) | GL_EXACT;

	mutex_lock(&fp->f_fl_mutex);

	gl = fl_gh->gh_gl;
	if (gl) {
		if (fl_gh->gh_state == state)
			goto out;
		flock_lock_file_wait(file,
				     &(struct file_lock){.fl_type = F_UNLCK});
		gfs2_glock_dq(fl_gh);
		gfs2_holder_reinit(state, flags, fl_gh);
	} else {
		error = gfs2_glock_get(GFS2_SB(&ip->i_inode), ip->i_no_addr,
				       &gfs2_flock_glops, CREATE, &gl);
		if (error)
			goto out;
		gfs2_holder_init(gl, state, flags, fl_gh);
		gfs2_glock_put(gl);
	}
	error = gfs2_glock_nq(fl_gh);
	if (error) {
		gfs2_holder_uninit(fl_gh);
		if (error == GLR_TRYFAILED)
			error = -EAGAIN;
	} else {
		error = flock_lock_file_wait(file, fl);
		gfs2_assert_warn(GFS2_SB(&ip->i_inode), !error);
	}

out:
	mutex_unlock(&fp->f_fl_mutex);
	return error;
}

static void do_unflock(struct file *file, struct file_lock *fl)
{
	struct gfs2_file *fp = file->private_data;
	struct gfs2_holder *fl_gh = &fp->f_fl_gh;

	mutex_lock(&fp->f_fl_mutex);
	flock_lock_file_wait(file, fl);
	if (fl_gh->gh_gl) {
		gfs2_glock_dq_wait(fl_gh);
		gfs2_holder_uninit(fl_gh);
	}
	mutex_unlock(&fp->f_fl_mutex);
}

/**
 * gfs2_flock - acquire/release a flock lock on a file
 * @file: the file pointer
 * @cmd: either modify or retrieve lock state, possibly wait
 * @fl: type and range of lock
 *
 * Returns: errno
 */

static int gfs2_flock(struct file *file, int cmd, struct file_lock *fl)
{
	if (!(fl->fl_flags & FL_FLOCK))
		return -ENOLCK;
	if (fl->fl_type & LOCK_MAND)
		return -EOPNOTSUPP;

	if (fl->fl_type == F_UNLCK) {
		do_unflock(file, fl);
		return 0;
	} else {
		return do_flock(file, cmd, fl);
	}
}

const struct file_operations gfs2_file_fops = {
	.llseek		= gfs2_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= gfs2_file_write_iter,
	.unlocked_ioctl	= gfs2_ioctl,
	.mmap		= gfs2_mmap,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
	.lock		= gfs2_lock,
	.flock		= gfs2_flock,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.setlease	= gfs2_setlease,
	.fallocate	= gfs2_fallocate,
};

const struct file_operations gfs2_dir_fops = {
	.iterate	= gfs2_readdir,
	.unlocked_ioctl	= gfs2_ioctl,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
	.lock		= gfs2_lock,
	.flock		= gfs2_flock,
	.llseek		= default_llseek,
};

#endif /* CONFIG_GFS2_FS_LOCKING_DLM */

const struct file_operations gfs2_file_fops_nolock = {
	.llseek		= gfs2_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= gfs2_file_write_iter,
	.unlocked_ioctl	= gfs2_ioctl,
	.mmap		= gfs2_mmap,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.setlease	= generic_setlease,
	.fallocate	= gfs2_fallocate,
};

const struct file_operations gfs2_dir_fops_nolock = {
	.iterate	= gfs2_readdir,
	.unlocked_ioctl	= gfs2_ioctl,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
	.llseek		= default_llseek,
};
/************************************************************/
/* ../linux-3.17/fs/gfs2/ops_fstype.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/blkdev.h>
// #include <linux/kthread.h>
#include <linux/export.h>
// #include <linux/namei.h>
// #include <linux/mount.h>
// #include <linux/gfs2_ondisk.h>
#include <linux/quotaops.h>
#include <linux/lockdep.h>
// #include <linux/module.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "bmap.h"
// #include "glock.h"
// #include "glops.h"
// #include "inode.h"
// #include "recovery.h"
// #include "rgrp.h"
// #include "super.h"
// #include "sys.h"
// #include "util.h"
// #include "log.h"
// #include "quota.h"
// #include "dir.h"
// #include "meta_io.h"
// #include "trace_gfs2.h"

#define DO 0
#define UNDO 1

/**
 * gfs2_tune_init - Fill a gfs2_tune structure with default values
 * @gt: tune
 *
 */

static void gfs2_tune_init(struct gfs2_tune *gt)
{
	spin_lock_init(&gt->gt_spin);

	gt->gt_quota_warn_period = 10;
	gt->gt_quota_scale_num = 1;
	gt->gt_quota_scale_den = 1;
	gt->gt_new_files_jdata = 0;
	gt->gt_max_readahead = 1 << 18;
	gt->gt_complain_secs = 10;
}

static struct gfs2_sbd *init_sbd(struct super_block *sb)
{
	struct gfs2_sbd *sdp;
	struct address_space *mapping;

	sdp = kzalloc(sizeof(struct gfs2_sbd), GFP_KERNEL);
	if (!sdp)
		return NULL;

	sb->s_fs_info = sdp;
	sdp->sd_vfs = sb;
	sdp->sd_lkstats = alloc_percpu(struct gfs2_pcpu_lkstats);
	if (!sdp->sd_lkstats) {
		kfree(sdp);
		return NULL;
	}

	set_bit(SDF_NOJOURNALID, &sdp->sd_flags);
	gfs2_tune_init(&sdp->sd_tune);

	init_waitqueue_head(&sdp->sd_glock_wait);
	atomic_set(&sdp->sd_glock_disposal, 0);
	init_completion(&sdp->sd_locking_init);
	init_completion(&sdp->sd_wdack);
	spin_lock_init(&sdp->sd_statfs_spin);

	spin_lock_init(&sdp->sd_rindex_spin);
	sdp->sd_rindex_tree.rb_node = NULL;

	INIT_LIST_HEAD(&sdp->sd_jindex_list);
	spin_lock_init(&sdp->sd_jindex_spin);
	mutex_init(&sdp->sd_jindex_mutex);
	init_completion(&sdp->sd_journal_ready);

	INIT_LIST_HEAD(&sdp->sd_quota_list);
	mutex_init(&sdp->sd_quota_mutex);
	mutex_init(&sdp->sd_quota_sync_mutex);
	init_waitqueue_head(&sdp->sd_quota_wait);
	INIT_LIST_HEAD(&sdp->sd_trunc_list);
	spin_lock_init(&sdp->sd_trunc_lock);
	spin_lock_init(&sdp->sd_bitmap_lock);

	mapping = &sdp->sd_aspace;

	address_space_init_once(mapping);
	mapping->a_ops = &gfs2_rgrp_aops;
	mapping->host = sb->s_bdev->bd_inode;
	mapping->flags = 0;
	mapping_set_gfp_mask(mapping, GFP_NOFS);
	mapping->private_data = NULL;
	mapping->backing_dev_info = sb->s_bdi;
	mapping->writeback_index = 0;

	spin_lock_init(&sdp->sd_log_lock);
	atomic_set(&sdp->sd_log_pinned, 0);
	INIT_LIST_HEAD(&sdp->sd_log_le_revoke);
	INIT_LIST_HEAD(&sdp->sd_log_le_ordered);
	spin_lock_init(&sdp->sd_ordered_lock);

	init_waitqueue_head(&sdp->sd_log_waitq);
	init_waitqueue_head(&sdp->sd_logd_waitq);
	spin_lock_init(&sdp->sd_ail_lock);
	INIT_LIST_HEAD(&sdp->sd_ail1_list);
	INIT_LIST_HEAD(&sdp->sd_ail2_list);

	init_rwsem(&sdp->sd_log_flush_lock);
	atomic_set(&sdp->sd_log_in_flight, 0);
	init_waitqueue_head(&sdp->sd_log_flush_wait);
	init_waitqueue_head(&sdp->sd_log_frozen_wait);
	atomic_set(&sdp->sd_log_freeze, 0);
	atomic_set(&sdp->sd_frozen_root, 0);
	init_waitqueue_head(&sdp->sd_frozen_root_wait);

	return sdp;
}


/**
 * gfs2_check_sb - Check superblock
 * @sdp: the filesystem
 * @sb: The superblock
 * @silent: Don't print a message if the check fails
 *
 * Checks the version code of the FS is one that we understand how to
 * read and that the sizes of the various on-disk structures have not
 * changed.
 */

static int gfs2_check_sb(struct gfs2_sbd *sdp, int silent)
{
	struct gfs2_sb_host *sb = &sdp->sd_sb;

	if (sb->sb_magic != GFS2_MAGIC ||
	    sb->sb_type != GFS2_METATYPE_SB) {
		if (!silent)
			pr_warn("not a GFS2 filesystem\n");
		return -EINVAL;
	}

	/*  If format numbers match exactly, we're done.  */

	if (sb->sb_fs_format == GFS2_FORMAT_FS &&
	    sb->sb_multihost_format == GFS2_FORMAT_MULTI)
		return 0;

	fs_warn(sdp, "Unknown on-disk format, unable to mount\n");

	return -EINVAL;
}

static void end_bio_io_page(struct bio *bio, int error)
{
	struct page *page = bio->bi_private;

	if (!error)
		SetPageUptodate(page);
	else
		pr_warn("error %d reading superblock\n", error);
	unlock_page(page);
}

static void gfs2_sb_in(struct gfs2_sbd *sdp, const void *buf)
{
	struct gfs2_sb_host *sb = &sdp->sd_sb;
	struct super_block *s = sdp->sd_vfs;
	const struct gfs2_sb *str = buf;

	sb->sb_magic = be32_to_cpu(str->sb_header.mh_magic);
	sb->sb_type = be32_to_cpu(str->sb_header.mh_type);
	sb->sb_format = be32_to_cpu(str->sb_header.mh_format);
	sb->sb_fs_format = be32_to_cpu(str->sb_fs_format);
	sb->sb_multihost_format = be32_to_cpu(str->sb_multihost_format);
	sb->sb_bsize = be32_to_cpu(str->sb_bsize);
	sb->sb_bsize_shift = be32_to_cpu(str->sb_bsize_shift);
	sb->sb_master_dir.no_addr = be64_to_cpu(str->sb_master_dir.no_addr);
	sb->sb_master_dir.no_formal_ino = be64_to_cpu(str->sb_master_dir.no_formal_ino);
	sb->sb_root_dir.no_addr = be64_to_cpu(str->sb_root_dir.no_addr);
	sb->sb_root_dir.no_formal_ino = be64_to_cpu(str->sb_root_dir.no_formal_ino);

	memcpy(sb->sb_lockproto, str->sb_lockproto, GFS2_LOCKNAME_LEN);
	memcpy(sb->sb_locktable, str->sb_locktable, GFS2_LOCKNAME_LEN);
	memcpy(s->s_uuid, str->sb_uuid, 16);
}

/**
 * gfs2_read_super - Read the gfs2 super block from disk
 * @sdp: The GFS2 super block
 * @sector: The location of the super block
 * @error: The error code to return
 *
 * This uses the bio functions to read the super block from disk
 * because we want to be 100% sure that we never read cached data.
 * A super block is read twice only during each GFS2 mount and is
 * never written to by the filesystem. The first time its read no
 * locks are held, and the only details which are looked at are those
 * relating to the locking protocol. Once locking is up and working,
 * the sb is read again under the lock to establish the location of
 * the master directory (contains pointers to journals etc) and the
 * root directory.
 *
 * Returns: 0 on success or error
 */

static int gfs2_read_super(struct gfs2_sbd *sdp, sector_t sector, int silent)
{
	struct super_block *sb = sdp->sd_vfs;
	struct gfs2_sb *p;
	struct page *page;
	struct bio *bio;

	page = alloc_page(GFP_NOFS);
	if (unlikely(!page))
		return -ENOMEM;

	ClearPageUptodate(page);
	ClearPageDirty(page);
	lock_page(page);

	bio = bio_alloc(GFP_NOFS, 1);
	bio->bi_iter.bi_sector = sector * (sb->s_blocksize >> 9);
	bio->bi_bdev = sb->s_bdev;
	bio_add_page(bio, page, PAGE_SIZE, 0);

	bio->bi_end_io = end_bio_io_page;
	bio->bi_private = page;
	submit_bio(READ_SYNC | REQ_META, bio);
	wait_on_page_locked(page);
	bio_put(bio);
	if (!PageUptodate(page)) {
		__free_page(page);
		return -EIO;
	}
	p = kmap(page);
	gfs2_sb_in(sdp, p);
	kunmap(page);
	__free_page(page);
	return gfs2_check_sb(sdp, silent);
}

/**
 * gfs2_read_sb - Read super block
 * @sdp: The GFS2 superblock
 * @silent: Don't print message if mount fails
 *
 */

static int gfs2_read_sb(struct gfs2_sbd *sdp, int silent)
{
	u32 hash_blocks, ind_blocks, leaf_blocks;
	u32 tmp_blocks;
	unsigned int x;
	int error;

	error = gfs2_read_super(sdp, GFS2_SB_ADDR >> sdp->sd_fsb2bb_shift, silent);
	if (error) {
		if (!silent)
			fs_err(sdp, "can't read superblock\n");
		return error;
	}

	sdp->sd_fsb2bb_shift = sdp->sd_sb.sb_bsize_shift -
			       GFS2_BASIC_BLOCK_SHIFT;
	sdp->sd_fsb2bb = 1 << sdp->sd_fsb2bb_shift;
	sdp->sd_diptrs = (sdp->sd_sb.sb_bsize -
			  sizeof(struct gfs2_dinode)) / sizeof(u64);
	sdp->sd_inptrs = (sdp->sd_sb.sb_bsize -
			  sizeof(struct gfs2_meta_header)) / sizeof(u64);
	sdp->sd_jbsize = sdp->sd_sb.sb_bsize - sizeof(struct gfs2_meta_header);
	sdp->sd_hash_bsize = sdp->sd_sb.sb_bsize / 2;
	sdp->sd_hash_bsize_shift = sdp->sd_sb.sb_bsize_shift - 1;
	sdp->sd_hash_ptrs = sdp->sd_hash_bsize / sizeof(u64);
	sdp->sd_qc_per_block = (sdp->sd_sb.sb_bsize -
				sizeof(struct gfs2_meta_header)) /
			        sizeof(struct gfs2_quota_change);
	sdp->sd_blocks_per_bitmap = (sdp->sd_sb.sb_bsize -
				     sizeof(struct gfs2_meta_header))
		* GFS2_NBBY; /* not the rgrp bitmap, subsequent bitmaps only */

	/* Compute maximum reservation required to add a entry to a directory */

	hash_blocks = DIV_ROUND_UP(sizeof(u64) * (1 << GFS2_DIR_MAX_DEPTH),
			     sdp->sd_jbsize);

	ind_blocks = 0;
	for (tmp_blocks = hash_blocks; tmp_blocks > sdp->sd_diptrs;) {
		tmp_blocks = DIV_ROUND_UP(tmp_blocks, sdp->sd_inptrs);
		ind_blocks += tmp_blocks;
	}

	leaf_blocks = 2 + GFS2_DIR_MAX_DEPTH;

	sdp->sd_max_dirres = hash_blocks + ind_blocks + leaf_blocks;

	sdp->sd_heightsize[0] = sdp->sd_sb.sb_bsize -
				sizeof(struct gfs2_dinode);
	sdp->sd_heightsize[1] = sdp->sd_sb.sb_bsize * sdp->sd_diptrs;
	for (x = 2;; x++) {
		u64 space, d;
		u32 m;

		space = sdp->sd_heightsize[x - 1] * sdp->sd_inptrs;
		d = space;
		m = do_div(d, sdp->sd_inptrs);

		if (d != sdp->sd_heightsize[x - 1] || m)
			break;
		sdp->sd_heightsize[x] = space;
	}
	sdp->sd_max_height = x;
	sdp->sd_heightsize[x] = ~0;
	gfs2_assert(sdp, sdp->sd_max_height <= GFS2_MAX_META_HEIGHT);

	sdp->sd_jheightsize[0] = sdp->sd_sb.sb_bsize -
				 sizeof(struct gfs2_dinode);
	sdp->sd_jheightsize[1] = sdp->sd_jbsize * sdp->sd_diptrs;
	for (x = 2;; x++) {
		u64 space, d;
		u32 m;

		space = sdp->sd_jheightsize[x - 1] * sdp->sd_inptrs;
		d = space;
		m = do_div(d, sdp->sd_inptrs);

		if (d != sdp->sd_jheightsize[x - 1] || m)
			break;
		sdp->sd_jheightsize[x] = space;
	}
	sdp->sd_max_jheight = x;
	sdp->sd_jheightsize[x] = ~0;
	gfs2_assert(sdp, sdp->sd_max_jheight <= GFS2_MAX_META_HEIGHT);

	return 0;
}

static int init_names(struct gfs2_sbd *sdp, int silent)
{
	char *proto, *table;
	int error = 0;

	proto = sdp->sd_args.ar_lockproto;
	table = sdp->sd_args.ar_locktable;

	/*  Try to autodetect  */

	if (!proto[0] || !table[0]) {
		error = gfs2_read_super(sdp, GFS2_SB_ADDR >> sdp->sd_fsb2bb_shift, silent);
		if (error)
			return error;

		if (!proto[0])
			proto = sdp->sd_sb.sb_lockproto;
		if (!table[0])
			table = sdp->sd_sb.sb_locktable;
	}

	if (!table[0])
		table = sdp->sd_vfs->s_id;

	strlcpy(sdp->sd_proto_name, proto, GFS2_FSNAME_LEN);
	strlcpy(sdp->sd_table_name, table, GFS2_FSNAME_LEN);

	table = sdp->sd_table_name;
	while ((table = strchr(table, '/')))
		*table = '_';

	return error;
}

static int init_locking(struct gfs2_sbd *sdp, struct gfs2_holder *mount_gh,
			int undo)
{
	int error = 0;

	if (undo)
		goto fail_trans;

	error = gfs2_glock_nq_num(sdp,
				  GFS2_MOUNT_LOCK, &gfs2_nondisk_glops,
				  LM_ST_EXCLUSIVE, LM_FLAG_NOEXP | GL_NOCACHE,
				  mount_gh);
	if (error) {
		fs_err(sdp, "can't acquire mount glock: %d\n", error);
		goto fail;
	}

	error = gfs2_glock_nq_num(sdp,
				  GFS2_LIVE_LOCK, &gfs2_nondisk_glops,
				  LM_ST_SHARED,
				  LM_FLAG_NOEXP | GL_EXACT,
				  &sdp->sd_live_gh);
	if (error) {
		fs_err(sdp, "can't acquire live glock: %d\n", error);
		goto fail_mount;
	}

	error = gfs2_glock_get(sdp, GFS2_RENAME_LOCK, &gfs2_nondisk_glops,
			       CREATE, &sdp->sd_rename_gl);
	if (error) {
		fs_err(sdp, "can't create rename glock: %d\n", error);
		goto fail_live;
	}

	error = gfs2_glock_get(sdp, GFS2_FREEZE_LOCK, &gfs2_freeze_glops,
			       CREATE, &sdp->sd_freeze_gl);
	if (error) {
		fs_err(sdp, "can't create transaction glock: %d\n", error);
		goto fail_rename;
	}

	return 0;

fail_trans:
	gfs2_glock_put(sdp->sd_freeze_gl);
fail_rename:
	gfs2_glock_put(sdp->sd_rename_gl);
fail_live:
	gfs2_glock_dq_uninit(&sdp->sd_live_gh);
fail_mount:
	gfs2_glock_dq_uninit(mount_gh);
fail:
	return error;
}

static int gfs2_lookup_root(struct super_block *sb, struct dentry **dptr,
			    u64 no_addr, const char *name)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct dentry *dentry;
	struct inode *inode;

	inode = gfs2_inode_lookup(sb, DT_DIR, no_addr, 0, 0);
	if (IS_ERR(inode)) {
		fs_err(sdp, "can't read in %s inode: %ld\n", name, PTR_ERR(inode));
		return PTR_ERR(inode);
	}
	dentry = d_make_root(inode);
	if (!dentry) {
		fs_err(sdp, "can't alloc %s dentry\n", name);
		return -ENOMEM;
	}
	*dptr = dentry;
	return 0;
}

static int init_sb(struct gfs2_sbd *sdp, int silent)
{
	struct super_block *sb = sdp->sd_vfs;
	struct gfs2_holder sb_gh;
	u64 no_addr;
	int ret;

	ret = gfs2_glock_nq_num(sdp, GFS2_SB_LOCK, &gfs2_meta_glops,
				LM_ST_SHARED, 0, &sb_gh);
	if (ret) {
		fs_err(sdp, "can't acquire superblock glock: %d\n", ret);
		return ret;
	}

	ret = gfs2_read_sb(sdp, silent);
	if (ret) {
		fs_err(sdp, "can't read superblock: %d\n", ret);
		goto out;
	}

	/* Set up the buffer cache and SB for real */
	if (sdp->sd_sb.sb_bsize < bdev_logical_block_size(sb->s_bdev)) {
		ret = -EINVAL;
		fs_err(sdp, "FS block size (%u) is too small for device "
		       "block size (%u)\n",
		       sdp->sd_sb.sb_bsize, bdev_logical_block_size(sb->s_bdev));
		goto out;
	}
	if (sdp->sd_sb.sb_bsize > PAGE_SIZE) {
		ret = -EINVAL;
		fs_err(sdp, "FS block size (%u) is too big for machine "
		       "page size (%u)\n",
		       sdp->sd_sb.sb_bsize, (unsigned int)PAGE_SIZE);
		goto out;
	}
	sb_set_blocksize(sb, sdp->sd_sb.sb_bsize);

	/* Get the root inode */
	no_addr = sdp->sd_sb.sb_root_dir.no_addr;
	ret = gfs2_lookup_root(sb, &sdp->sd_root_dir, no_addr, "root");
	if (ret)
		goto out;

	/* Get the master inode */
	no_addr = sdp->sd_sb.sb_master_dir.no_addr;
	ret = gfs2_lookup_root(sb, &sdp->sd_master_dir, no_addr, "master");
	if (ret) {
		dput(sdp->sd_root_dir);
		goto out;
	}
	sb->s_root = dget(sdp->sd_args.ar_meta ? sdp->sd_master_dir : sdp->sd_root_dir);
out:
	gfs2_glock_dq_uninit(&sb_gh);
	return ret;
}

static void gfs2_others_may_mount(struct gfs2_sbd *sdp)
{
	char *message = "FIRSTMOUNT=Done";
	char *envp[] = { message, NULL };

	fs_info(sdp, "first mount done, others may mount\n");

	if (sdp->sd_lockstruct.ls_ops->lm_first_done)
		sdp->sd_lockstruct.ls_ops->lm_first_done(sdp);

	kobject_uevent_env(&sdp->sd_kobj, KOBJ_CHANGE, envp);
}

/**
 * gfs2_jindex_hold - Grab a lock on the jindex
 * @sdp: The GFS2 superblock
 * @ji_gh: the holder for the jindex glock
 *
 * Returns: errno
 */

static int gfs2_jindex_hold(struct gfs2_sbd *sdp, struct gfs2_holder *ji_gh)
{
	struct gfs2_inode *dip = GFS2_I(sdp->sd_jindex);
	struct qstr name;
	char buf[20];
	struct gfs2_jdesc *jd;
	int error;

	name.name = buf;

	mutex_lock(&sdp->sd_jindex_mutex);

	for (;;) {
		error = gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED, 0, ji_gh);
		if (error)
			break;

		name.len = sprintf(buf, "journal%u", sdp->sd_journals);
		name.hash = gfs2_disk_hash(name.name, name.len);

		error = gfs2_dir_check(sdp->sd_jindex, &name, NULL);
		if (error == -ENOENT) {
			error = 0;
			break;
		}

		gfs2_glock_dq_uninit(ji_gh);

		if (error)
			break;

		error = -ENOMEM;
		jd = kzalloc(sizeof(struct gfs2_jdesc), GFP_KERNEL);
		if (!jd)
			break;

		INIT_LIST_HEAD(&jd->extent_list);
		INIT_LIST_HEAD(&jd->jd_revoke_list);

		INIT_WORK(&jd->jd_work, gfs2_recover_func);
		jd->jd_inode = gfs2_lookupi(sdp->sd_jindex, &name, 1);
		if (!jd->jd_inode || IS_ERR(jd->jd_inode)) {
			if (!jd->jd_inode)
				error = -ENOENT;
			else
				error = PTR_ERR(jd->jd_inode);
			kfree(jd);
			break;
		}

		spin_lock(&sdp->sd_jindex_spin);
		jd->jd_jid = sdp->sd_journals++;
		list_add_tail(&jd->jd_list, &sdp->sd_jindex_list);
		spin_unlock(&sdp->sd_jindex_spin);
	}

	mutex_unlock(&sdp->sd_jindex_mutex);

	return error;
}

/**
 * check_journal_clean - Make sure a journal is clean for a spectator mount
 * @sdp: The GFS2 superblock
 * @jd: The journal descriptor
 *
 * Returns: 0 if the journal is clean or locked, else an error
 */
static int check_journal_clean(struct gfs2_sbd *sdp, struct gfs2_jdesc *jd)
{
	int error;
	struct gfs2_holder j_gh;
	struct gfs2_log_header_host head;
	struct gfs2_inode *ip;

	ip = GFS2_I(jd->jd_inode);
	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_NOEXP |
				   GL_EXACT | GL_NOCACHE, &j_gh);
	if (error) {
		fs_err(sdp, "Error locking journal for spectator mount.\n");
		return -EPERM;
	}
	error = gfs2_jdesc_check(jd);
	if (error) {
		fs_err(sdp, "Error checking journal for spectator mount.\n");
		goto out_unlock;
	}
	error = gfs2_find_jhead(jd, &head);
	if (error) {
		fs_err(sdp, "Error parsing journal for spectator mount.\n");
		goto out_unlock;
	}
	if (!(head.lh_flags & GFS2_LOG_HEAD_UNMOUNT)) {
		error = -EPERM;
		fs_err(sdp, "jid=%u: Journal is dirty, so the first mounter "
		       "must not be a spectator.\n", jd->jd_jid);
	}

out_unlock:
	gfs2_glock_dq_uninit(&j_gh);
	return error;
}

static int init_journal(struct gfs2_sbd *sdp, int undo)
{
	struct inode *master = sdp->sd_master_dir->d_inode;
	struct gfs2_holder ji_gh;
	struct gfs2_inode *ip;
	int jindex = 1;
	int error = 0;

	if (undo) {
		jindex = 0;
		goto fail_jinode_gh;
	}

	sdp->sd_jindex = gfs2_lookup_simple(master, "jindex");
	if (IS_ERR(sdp->sd_jindex)) {
		fs_err(sdp, "can't lookup journal index: %d\n", error);
		return PTR_ERR(sdp->sd_jindex);
	}

	/* Load in the journal index special file */

	error = gfs2_jindex_hold(sdp, &ji_gh);
	if (error) {
		fs_err(sdp, "can't read journal index: %d\n", error);
		goto fail;
	}

	error = -EUSERS;
	if (!gfs2_jindex_size(sdp)) {
		fs_err(sdp, "no journals!\n");
		goto fail_jindex;
	}

	if (sdp->sd_args.ar_spectator) {
		sdp->sd_jdesc = gfs2_jdesc_find(sdp, 0);
		atomic_set(&sdp->sd_log_blks_free, sdp->sd_jdesc->jd_blocks);
		atomic_set(&sdp->sd_log_thresh1, 2*sdp->sd_jdesc->jd_blocks/5);
		atomic_set(&sdp->sd_log_thresh2, 4*sdp->sd_jdesc->jd_blocks/5);
	} else {
		if (sdp->sd_lockstruct.ls_jid >= gfs2_jindex_size(sdp)) {
			fs_err(sdp, "can't mount journal #%u\n",
			       sdp->sd_lockstruct.ls_jid);
			fs_err(sdp, "there are only %u journals (0 - %u)\n",
			       gfs2_jindex_size(sdp),
			       gfs2_jindex_size(sdp) - 1);
			goto fail_jindex;
		}
		sdp->sd_jdesc = gfs2_jdesc_find(sdp, sdp->sd_lockstruct.ls_jid);

		error = gfs2_glock_nq_num(sdp, sdp->sd_lockstruct.ls_jid,
					  &gfs2_journal_glops,
					  LM_ST_EXCLUSIVE, LM_FLAG_NOEXP,
					  &sdp->sd_journal_gh);
		if (error) {
			fs_err(sdp, "can't acquire journal glock: %d\n", error);
			goto fail_jindex;
		}

		ip = GFS2_I(sdp->sd_jdesc->jd_inode);
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED,
					   LM_FLAG_NOEXP | GL_EXACT | GL_NOCACHE,
					   &sdp->sd_jinode_gh);
		if (error) {
			fs_err(sdp, "can't acquire journal inode glock: %d\n",
			       error);
			goto fail_journal_gh;
		}

		error = gfs2_jdesc_check(sdp->sd_jdesc);
		if (error) {
			fs_err(sdp, "my journal (%u) is bad: %d\n",
			       sdp->sd_jdesc->jd_jid, error);
			goto fail_jinode_gh;
		}
		atomic_set(&sdp->sd_log_blks_free, sdp->sd_jdesc->jd_blocks);
		atomic_set(&sdp->sd_log_thresh1, 2*sdp->sd_jdesc->jd_blocks/5);
		atomic_set(&sdp->sd_log_thresh2, 4*sdp->sd_jdesc->jd_blocks/5);

		/* Map the extents for this journal's blocks */
		gfs2_map_journal_extents(sdp, sdp->sd_jdesc);
	}
	trace_gfs2_log_blocks(sdp, atomic_read(&sdp->sd_log_blks_free));

	if (sdp->sd_lockstruct.ls_first) {
		unsigned int x;
		for (x = 0; x < sdp->sd_journals; x++) {
			struct gfs2_jdesc *jd = gfs2_jdesc_find(sdp, x);

			if (sdp->sd_args.ar_spectator) {
				error = check_journal_clean(sdp, jd);
				if (error)
					goto fail_jinode_gh;
				continue;
			}
			error = gfs2_recover_journal(jd, true);
			if (error) {
				fs_err(sdp, "error recovering journal %u: %d\n",
				       x, error);
				goto fail_jinode_gh;
			}
		}

		gfs2_others_may_mount(sdp);
	} else if (!sdp->sd_args.ar_spectator) {
		error = gfs2_recover_journal(sdp->sd_jdesc, true);
		if (error) {
			fs_err(sdp, "error recovering my journal: %d\n", error);
			goto fail_jinode_gh;
		}
	}

	set_bit(SDF_JOURNAL_CHECKED, &sdp->sd_flags);
	gfs2_glock_dq_uninit(&ji_gh);
	jindex = 0;
	if (!sdp->sd_args.ar_spectator) {
		error = gfs2_glock_nq_init(sdp->sd_freeze_gl, LM_ST_SHARED, 0,
					   &sdp->sd_thaw_gh);
		if (error) {
			fs_err(sdp, "can't acquire freeze glock: %d\n", error);
			goto fail_jinode_gh;
		}
	}
	gfs2_glock_dq_uninit(&sdp->sd_thaw_gh);
	return 0;

fail_jinode_gh:
	if (!sdp->sd_args.ar_spectator)
		gfs2_glock_dq_uninit(&sdp->sd_jinode_gh);
fail_journal_gh:
	if (!sdp->sd_args.ar_spectator)
		gfs2_glock_dq_uninit(&sdp->sd_journal_gh);
fail_jindex:
	gfs2_jindex_free(sdp);
	if (jindex)
		gfs2_glock_dq_uninit(&ji_gh);
fail:
	iput(sdp->sd_jindex);
	return error;
}

static struct lock_class_key gfs2_quota_imutex_key;

static int init_inodes(struct gfs2_sbd *sdp, int undo)
{
	int error = 0;
	struct inode *master = sdp->sd_master_dir->d_inode;

	if (undo)
		goto fail_qinode;

	error = init_journal(sdp, undo);
	complete_all(&sdp->sd_journal_ready);
	if (error)
		goto fail;

	/* Read in the master statfs inode */
	sdp->sd_statfs_inode = gfs2_lookup_simple(master, "statfs");
	if (IS_ERR(sdp->sd_statfs_inode)) {
		error = PTR_ERR(sdp->sd_statfs_inode);
		fs_err(sdp, "can't read in statfs inode: %d\n", error);
		goto fail_journal;
	}

	/* Read in the resource index inode */
	sdp->sd_rindex = gfs2_lookup_simple(master, "rindex");
	if (IS_ERR(sdp->sd_rindex)) {
		error = PTR_ERR(sdp->sd_rindex);
		fs_err(sdp, "can't get resource index inode: %d\n", error);
		goto fail_statfs;
	}
	sdp->sd_rindex_uptodate = 0;

	/* Read in the quota inode */
	sdp->sd_quota_inode = gfs2_lookup_simple(master, "quota");
	if (IS_ERR(sdp->sd_quota_inode)) {
		error = PTR_ERR(sdp->sd_quota_inode);
		fs_err(sdp, "can't get quota file inode: %d\n", error);
		goto fail_rindex;
	}
	/*
	 * i_mutex on quota files is special. Since this inode is hidden system
	 * file, we are safe to define locking ourselves.
	 */
	lockdep_set_class(&sdp->sd_quota_inode->i_mutex,
			  &gfs2_quota_imutex_key);

	error = gfs2_rindex_update(sdp);
	if (error)
		goto fail_qinode;

	return 0;

fail_qinode:
	iput(sdp->sd_quota_inode);
fail_rindex:
	gfs2_clear_rgrpd(sdp);
	iput(sdp->sd_rindex);
fail_statfs:
	iput(sdp->sd_statfs_inode);
fail_journal:
	init_journal(sdp, UNDO);
fail:
	return error;
}

static int init_per_node(struct gfs2_sbd *sdp, int undo)
{
	struct inode *pn = NULL;
	char buf[30];
	int error = 0;
	struct gfs2_inode *ip;
	struct inode *master = sdp->sd_master_dir->d_inode;

	if (sdp->sd_args.ar_spectator)
		return 0;

	if (undo)
		goto fail_qc_gh;

	pn = gfs2_lookup_simple(master, "per_node");
	if (IS_ERR(pn)) {
		error = PTR_ERR(pn);
		fs_err(sdp, "can't find per_node directory: %d\n", error);
		return error;
	}

	sprintf(buf, "statfs_change%u", sdp->sd_jdesc->jd_jid);
	sdp->sd_sc_inode = gfs2_lookup_simple(pn, buf);
	if (IS_ERR(sdp->sd_sc_inode)) {
		error = PTR_ERR(sdp->sd_sc_inode);
		fs_err(sdp, "can't find local \"sc\" file: %d\n", error);
		goto fail;
	}

	sprintf(buf, "quota_change%u", sdp->sd_jdesc->jd_jid);
	sdp->sd_qc_inode = gfs2_lookup_simple(pn, buf);
	if (IS_ERR(sdp->sd_qc_inode)) {
		error = PTR_ERR(sdp->sd_qc_inode);
		fs_err(sdp, "can't find local \"qc\" file: %d\n", error);
		goto fail_ut_i;
	}

	iput(pn);
	pn = NULL;

	ip = GFS2_I(sdp->sd_sc_inode);
	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0,
				   &sdp->sd_sc_gh);
	if (error) {
		fs_err(sdp, "can't lock local \"sc\" file: %d\n", error);
		goto fail_qc_i;
	}

	ip = GFS2_I(sdp->sd_qc_inode);
	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0,
				   &sdp->sd_qc_gh);
	if (error) {
		fs_err(sdp, "can't lock local \"qc\" file: %d\n", error);
		goto fail_ut_gh;
	}

	return 0;

fail_qc_gh:
	gfs2_glock_dq_uninit(&sdp->sd_qc_gh);
fail_ut_gh:
	gfs2_glock_dq_uninit(&sdp->sd_sc_gh);
fail_qc_i:
	iput(sdp->sd_qc_inode);
fail_ut_i:
	iput(sdp->sd_sc_inode);
fail:
	if (pn)
		iput(pn);
	return error;
}

static const match_table_t nolock_tokens = {
	{ Opt_jid, "jid=%d\n", },
	{ Opt_err, NULL },
};

static const struct lm_lockops nolock_ops = {
	.lm_proto_name = "lock_nolock",
	.lm_put_lock = gfs2_glock_free,
	.lm_tokens = &nolock_tokens,
};

/**
 * gfs2_lm_mount - mount a locking protocol
 * @sdp: the filesystem
 * @args: mount arguments
 * @silent: if 1, don't complain if the FS isn't a GFS2 fs
 *
 * Returns: errno
 */

static int gfs2_lm_mount(struct gfs2_sbd *sdp, int silent)
{
	const struct lm_lockops *lm;
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	struct gfs2_args *args = &sdp->sd_args;
	const char *proto = sdp->sd_proto_name;
	const char *table = sdp->sd_table_name;
	char *o, *options;
	int ret;

	if (!strcmp("lock_nolock", proto)) {
		lm = &nolock_ops;
		sdp->sd_args.ar_localflocks = 1;
#ifdef CONFIG_GFS2_FS_LOCKING_DLM
	} else if (!strcmp("lock_dlm", proto)) {
		lm = &gfs2_dlm_ops;
#endif
	} else {
		pr_info("can't find protocol %s\n", proto);
		return -ENOENT;
	}

	fs_info(sdp, "Trying to join cluster \"%s\", \"%s\"\n", proto, table);

	ls->ls_ops = lm;
	ls->ls_first = 1;

	for (options = args->ar_hostdata; (o = strsep(&options, ":")); ) {
		substring_t tmp[MAX_OPT_ARGS];
		int token, option;

		if (!o || !*o)
			continue;

		token = match_token(o, *lm->lm_tokens, tmp);
		switch (token) {
		case Opt_jid:
			ret = match_int(&tmp[0], &option);
			if (ret || option < 0)
				goto hostdata_error;
			if (test_and_clear_bit(SDF_NOJOURNALID, &sdp->sd_flags))
				ls->ls_jid = option;
			break;
		case Opt_id:
		case Opt_nodir:
			/* Obsolete, but left for backward compat purposes */
			break;
		case Opt_first:
			ret = match_int(&tmp[0], &option);
			if (ret || (option != 0 && option != 1))
				goto hostdata_error;
			ls->ls_first = option;
			break;
		case Opt_err:
		default:
hostdata_error:
			fs_info(sdp, "unknown hostdata (%s)\n", o);
			return -EINVAL;
		}
	}

	if (lm->lm_mount == NULL) {
		fs_info(sdp, "Now mounting FS...\n");
		complete_all(&sdp->sd_locking_init);
		return 0;
	}
	ret = lm->lm_mount(sdp, table);
	if (ret == 0)
		fs_info(sdp, "Joined cluster. Now mounting FS...\n");
	complete_all(&sdp->sd_locking_init);
	return ret;
}

void gfs2_lm_unmount(struct gfs2_sbd *sdp)
{
	const struct lm_lockops *lm = sdp->sd_lockstruct.ls_ops;
	if (likely(!test_bit(SDF_SHUTDOWN, &sdp->sd_flags)) &&
	    lm->lm_unmount)
		lm->lm_unmount(sdp);
}

static int wait_on_journal(struct gfs2_sbd *sdp)
{
	if (sdp->sd_lockstruct.ls_ops->lm_mount == NULL)
		return 0;

	return wait_on_bit(&sdp->sd_flags, SDF_NOJOURNALID, TASK_INTERRUPTIBLE)
		? -EINTR : 0;
}

void gfs2_online_uevent(struct gfs2_sbd *sdp)
{
	struct super_block *sb = sdp->sd_vfs;
	char ro[20];
	char spectator[20];
	char *envp[] = { ro, spectator, NULL };
	sprintf(ro, "RDONLY=%d", (sb->s_flags & MS_RDONLY) ? 1 : 0);
	sprintf(spectator, "SPECTATOR=%d", sdp->sd_args.ar_spectator ? 1 : 0);
	kobject_uevent_env(&sdp->sd_kobj, KOBJ_ONLINE, envp);
}

/**
 * fill_super - Read in superblock
 * @sb: The VFS superblock
 * @data: Mount options
 * @silent: Don't complain if it's not a GFS2 filesystem
 *
 * Returns: errno
 */

static int fill_super(struct super_block *sb, struct gfs2_args *args, int silent)
{
	struct gfs2_sbd *sdp;
	struct gfs2_holder mount_gh;
	int error;

	sdp = init_sbd(sb);
	if (!sdp) {
		pr_warn("can't alloc struct gfs2_sbd\n");
		return -ENOMEM;
	}
	sdp->sd_args = *args;

	if (sdp->sd_args.ar_spectator) {
                sb->s_flags |= MS_RDONLY;
		set_bit(SDF_RORECOVERY, &sdp->sd_flags);
	}
	if (sdp->sd_args.ar_posix_acl)
		sb->s_flags |= MS_POSIXACL;
	if (sdp->sd_args.ar_nobarrier)
		set_bit(SDF_NOBARRIERS, &sdp->sd_flags);

	sb->s_flags |= MS_NOSEC;
	sb->s_magic = GFS2_MAGIC;
	sb->s_op = &gfs2_super_ops;
	sb->s_d_op = &gfs2_dops;
	sb->s_export_op = &gfs2_export_ops;
	sb->s_xattr = gfs2_xattr_handlers;
	sb->s_qcop = &gfs2_quotactl_ops;
	sb_dqopt(sb)->flags |= DQUOT_QUOTA_SYS_FILE;
	sb->s_time_gran = 1;
	sb->s_maxbytes = MAX_LFS_FILESIZE;

	/* Set up the buffer cache and fill in some fake block size values
	   to allow us to read-in the on-disk superblock. */
	sdp->sd_sb.sb_bsize = sb_min_blocksize(sb, GFS2_BASIC_BLOCK);
	sdp->sd_sb.sb_bsize_shift = sb->s_blocksize_bits;
	sdp->sd_fsb2bb_shift = sdp->sd_sb.sb_bsize_shift -
                               GFS2_BASIC_BLOCK_SHIFT;
	sdp->sd_fsb2bb = 1 << sdp->sd_fsb2bb_shift;

	sdp->sd_tune.gt_logd_secs = sdp->sd_args.ar_commit;
	sdp->sd_tune.gt_quota_quantum = sdp->sd_args.ar_quota_quantum;
	if (sdp->sd_args.ar_statfs_quantum) {
		sdp->sd_tune.gt_statfs_slow = 0;
		sdp->sd_tune.gt_statfs_quantum = sdp->sd_args.ar_statfs_quantum;
	} else {
		sdp->sd_tune.gt_statfs_slow = 1;
		sdp->sd_tune.gt_statfs_quantum = 30;
	}

	error = init_names(sdp, silent);
	if (error) {
		/* In this case, we haven't initialized sysfs, so we have to
		   manually free the sdp. */
		free_percpu(sdp->sd_lkstats);
		kfree(sdp);
		sb->s_fs_info = NULL;
		return error;
	}

	snprintf(sdp->sd_fsname, GFS2_FSNAME_LEN, "%s", sdp->sd_table_name);

	error = gfs2_sys_fs_add(sdp);
	/*
	 * If we hit an error here, gfs2_sys_fs_add will have called function
	 * kobject_put which causes the sysfs usage count to go to zero, which
	 * causes sysfs to call function gfs2_sbd_release, which frees sdp.
	 * Subsequent error paths here will call gfs2_sys_fs_del, which also
	 * kobject_put to free sdp.
	 */
	if (error)
		return error;

	gfs2_create_debugfs_file(sdp);

	error = gfs2_lm_mount(sdp, silent);
	if (error)
		goto fail_debug;

	error = init_locking(sdp, &mount_gh, DO);
	if (error)
		goto fail_lm;

	error = init_sb(sdp, silent);
	if (error)
		goto fail_locking;

	error = wait_on_journal(sdp);
	if (error)
		goto fail_sb;

	/*
	 * If user space has failed to join the cluster or some similar
	 * failure has occurred, then the journal id will contain a
	 * negative (error) number. This will then be returned to the
	 * caller (of the mount syscall). We do this even for spectator
	 * mounts (which just write a jid of 0 to indicate "ok" even though
	 * the jid is unused in the spectator case)
	 */
	if (sdp->sd_lockstruct.ls_jid < 0) {
		error = sdp->sd_lockstruct.ls_jid;
		sdp->sd_lockstruct.ls_jid = 0;
		goto fail_sb;
	}

	if (sdp->sd_args.ar_spectator)
		snprintf(sdp->sd_fsname, GFS2_FSNAME_LEN, "%s.s",
			 sdp->sd_table_name);
	else
		snprintf(sdp->sd_fsname, GFS2_FSNAME_LEN, "%s.%u",
			 sdp->sd_table_name, sdp->sd_lockstruct.ls_jid);

	error = init_inodes(sdp, DO);
	if (error)
		goto fail_sb;

	error = init_per_node(sdp, DO);
	if (error)
		goto fail_inodes;

	error = gfs2_statfs_init(sdp);
	if (error) {
		fs_err(sdp, "can't initialize statfs subsystem: %d\n", error);
		goto fail_per_node;
	}

	if (!(sb->s_flags & MS_RDONLY)) {
		error = gfs2_make_fs_rw(sdp);
		if (error) {
			fs_err(sdp, "can't make FS RW: %d\n", error);
			goto fail_per_node;
		}
	}

	gfs2_glock_dq_uninit(&mount_gh);
	gfs2_online_uevent(sdp);
	return 0;

fail_per_node:
	init_per_node(sdp, UNDO);
fail_inodes:
	init_inodes(sdp, UNDO);
fail_sb:
	if (sdp->sd_root_dir)
		dput(sdp->sd_root_dir);
	if (sdp->sd_master_dir)
		dput(sdp->sd_master_dir);
	if (sb->s_root)
		dput(sb->s_root);
	sb->s_root = NULL;
fail_locking:
	init_locking(sdp, &mount_gh, UNDO);
fail_lm:
	complete_all(&sdp->sd_journal_ready);
	gfs2_gl_hash_clear(sdp);
	gfs2_lm_unmount(sdp);
fail_debug:
	gfs2_delete_debugfs_file(sdp);
	free_percpu(sdp->sd_lkstats);
	/* gfs2_sys_fs_del must be the last thing we do, since it causes
	 * sysfs to call function gfs2_sbd_release, which frees sdp. */
	gfs2_sys_fs_del(sdp);
	sb->s_fs_info = NULL;
	return error;
}

static int set_gfs2_super(struct super_block *s, void *data)
{
	s->s_bdev = data;
	s->s_dev = s->s_bdev->bd_dev;

	/*
	 * We set the bdi here to the queue backing, file systems can
	 * overwrite this in ->fill_super()
	 */
	s->s_bdi = &bdev_get_queue(s->s_bdev)->backing_dev_info;
	return 0;
}

static int test_gfs2_super(struct super_block *s, void *ptr)
{
	struct block_device *bdev = ptr;
	return (bdev == s->s_bdev);
}

/**
 * gfs2_mount - Get the GFS2 superblock
 * @fs_type: The GFS2 filesystem type
 * @flags: Mount flags
 * @dev_name: The name of the device
 * @data: The mount arguments
 *
 * Q. Why not use get_sb_bdev() ?
 * A. We need to select one of two root directories to mount, independent
 *    of whether this is the initial, or subsequent, mount of this sb
 *
 * Returns: 0 or -ve on error
 */

static struct dentry *gfs2_mount(struct file_system_type *fs_type, int flags,
		       const char *dev_name, void *data)
{
	struct block_device *bdev;
	struct super_block *s;
	fmode_t mode = FMODE_READ | FMODE_EXCL;
	int error;
	struct gfs2_args args;
	struct gfs2_sbd *sdp;

	if (!(flags & MS_RDONLY))
		mode |= FMODE_WRITE;

	bdev = blkdev_get_by_path(dev_name, mode, fs_type);
	if (IS_ERR(bdev))
		return ERR_CAST(bdev);

	/*
	 * once the super is inserted into the list by sget, s_umount
	 * will protect the lockfs code from trying to start a snapshot
	 * while we are mounting
	 */
	mutex_lock(&bdev->bd_fsfreeze_mutex);
	if (bdev->bd_fsfreeze_count > 0) {
		mutex_unlock(&bdev->bd_fsfreeze_mutex);
		error = -EBUSY;
		goto error_bdev;
	}
	s = sget(fs_type, test_gfs2_super, set_gfs2_super, flags, bdev);
	mutex_unlock(&bdev->bd_fsfreeze_mutex);
	error = PTR_ERR(s);
	if (IS_ERR(s))
		goto error_bdev;

	if (s->s_root) {
		/*
		 * s_umount nests inside bd_mutex during
		 * __invalidate_device().  blkdev_put() acquires
		 * bd_mutex and can't be called under s_umount.  Drop
		 * s_umount temporarily.  This is safe as we're
		 * holding an active reference.
		 */
		up_write(&s->s_umount);
		blkdev_put(bdev, mode);
		down_write(&s->s_umount);
	}

	memset(&args, 0, sizeof(args));
	args.ar_quota = GFS2_QUOTA_DEFAULT;
	args.ar_data = GFS2_DATA_DEFAULT;
	args.ar_commit = 30;
	args.ar_statfs_quantum = 30;
	args.ar_quota_quantum = 60;
	args.ar_errors = GFS2_ERRORS_DEFAULT;

	error = gfs2_mount_args(&args, data);
	if (error) {
		pr_warn("can't parse mount arguments\n");
		goto error_super;
	}

	if (s->s_root) {
		error = -EBUSY;
		if ((flags ^ s->s_flags) & MS_RDONLY)
			goto error_super;
	} else {
		char b[BDEVNAME_SIZE];

		s->s_mode = mode;
		strlcpy(s->s_id, bdevname(bdev, b), sizeof(s->s_id));
		sb_set_blocksize(s, block_size(bdev));
		error = fill_super(s, &args, flags & MS_SILENT ? 1 : 0);
		if (error)
			goto error_super;
		s->s_flags |= MS_ACTIVE;
		bdev->bd_super = s;
	}

	sdp = s->s_fs_info;
	if (args.ar_meta)
		return dget(sdp->sd_master_dir);
	else
		return dget(sdp->sd_root_dir);

error_super:
	deactivate_locked_super(s);
	return ERR_PTR(error);
error_bdev:
	blkdev_put(bdev, mode);
	return ERR_PTR(error);
}

static int set_meta_super(struct super_block *s, void *ptr)
{
	return -EINVAL;
}

static struct dentry *gfs2_mount_meta(struct file_system_type *fs_type,
			int flags, const char *dev_name, void *data)
{
	struct super_block *s;
	struct gfs2_sbd *sdp;
	struct path path;
	int error;

	error = kern_path(dev_name, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_warn("path_lookup on %s returned error %d\n",
			dev_name, error);
		return ERR_PTR(error);
	}
	s = sget(&gfs2_fs_type, test_gfs2_super, set_meta_super, flags,
		 path.dentry->d_inode->i_sb->s_bdev);
	path_put(&path);
	if (IS_ERR(s)) {
		pr_warn("gfs2 mount does not exist\n");
		return ERR_CAST(s);
	}
	if ((flags ^ s->s_flags) & MS_RDONLY) {
		deactivate_locked_super(s);
		return ERR_PTR(-EBUSY);
	}
	sdp = s->s_fs_info;
	return dget(sdp->sd_master_dir);
}

static void gfs2_kill_sb(struct super_block *sb)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;

	if (sdp == NULL) {
		kill_block_super(sb);
		return;
	}

	gfs2_log_flush(sdp, NULL, SYNC_FLUSH);
	dput(sdp->sd_root_dir);
	dput(sdp->sd_master_dir);
	sdp->sd_root_dir = NULL;
	sdp->sd_master_dir = NULL;
	shrink_dcache_sb(sb);
	gfs2_delete_debugfs_file(sdp);
	free_percpu(sdp->sd_lkstats);
	kill_block_super(sb);
}

struct file_system_type gfs2_fs_type = {
	.name = "gfs2",
	.fs_flags = FS_REQUIRES_DEV,
	.mount = gfs2_mount,
	.kill_sb = gfs2_kill_sb,
	.owner = THIS_MODULE,
};
MODULE_ALIAS_FS("gfs2");

struct file_system_type gfs2meta_fs_type = {
	.name = "gfs2meta",
	.fs_flags = FS_REQUIRES_DEV,
	.mount = gfs2_mount_meta,
	.owner = THIS_MODULE,
};
MODULE_ALIAS_FS("gfs2meta");
/************************************************************/
/* ../linux-3.17/fs/gfs2/inode.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/namei.h>
// #include <linux/mm.h>
// #include <linux/xattr.h>
// #include <linux/posix_acl.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/crc32.h>
#include <linux/fiemap.h>
#include <linux/security.h>
// #include <asm/uaccess.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "acl.h"
// #include "bmap.h"
// #include "dir.h"
// #include "xattr.h"
// #include "glock.h"
// #include "inode.h"
// #include "meta_io.h"
// #include "quota.h"
// #include "rgrp.h"
// #include "trans.h"
// #include "util.h"
// #include "super.h"
// #include "glops.h"

struct gfs2_skip_data {
	u64 no_addr;
	int skipped;
	int non_block;
};

static int iget_test(struct inode *inode, void *opaque)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_skip_data *data = opaque;

	if (ip->i_no_addr == data->no_addr) {
		if (data->non_block &&
		    inode->i_state & (I_FREEING|I_CLEAR|I_WILL_FREE)) {
			data->skipped = 1;
			return 0;
		}
		return 1;
	}
	return 0;
}

static int iget_set(struct inode *inode, void *opaque)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_skip_data *data = opaque;

	if (data->skipped)
		return -ENOENT;
	inode->i_ino = (unsigned long)(data->no_addr);
	ip->i_no_addr = data->no_addr;
	return 0;
}

struct inode *gfs2_ilookup(struct super_block *sb, u64 no_addr, int non_block)
{
	unsigned long hash = (unsigned long)no_addr;
	struct gfs2_skip_data data;

	data.no_addr = no_addr;
	data.skipped = 0;
	data.non_block = non_block;
	return ilookup5(sb, hash, iget_test, &data);
}

static struct inode *gfs2_iget(struct super_block *sb, u64 no_addr,
			       int non_block)
{
	struct gfs2_skip_data data;
	unsigned long hash = (unsigned long)no_addr;

	data.no_addr = no_addr;
	data.skipped = 0;
	data.non_block = non_block;
	return iget5_locked(sb, hash, iget_test, iget_set, &data);
}

/**
 * gfs2_set_iop - Sets inode operations
 * @inode: The inode with correct i_mode filled in
 *
 * GFS2 lookup code fills in vfs inode contents based on info obtained
 * from directory entry inside gfs2_inode_lookup().
 */

static void gfs2_set_iop(struct inode *inode)
{
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	umode_t mode = inode->i_mode;

	if (S_ISREG(mode)) {
		inode->i_op = &gfs2_file_iops;
		if (gfs2_localflocks(sdp))
			inode->i_fop = &gfs2_file_fops_nolock;
		else
			inode->i_fop = &gfs2_file_fops;
	} else if (S_ISDIR(mode)) {
		inode->i_op = &gfs2_dir_iops;
		if (gfs2_localflocks(sdp))
			inode->i_fop = &gfs2_dir_fops_nolock;
		else
			inode->i_fop = &gfs2_dir_fops;
	} else if (S_ISLNK(mode)) {
		inode->i_op = &gfs2_symlink_iops;
	} else {
		inode->i_op = &gfs2_file_iops;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	}
}

/**
 * gfs2_inode_lookup - Lookup an inode
 * @sb: The super block
 * @no_addr: The inode number
 * @type: The type of the inode
 * non_block: Can we block on inodes that are being freed?
 *
 * Returns: A VFS inode, or an error
 */

struct inode *gfs2_inode_lookup(struct super_block *sb, unsigned int type,
				u64 no_addr, u64 no_formal_ino, int non_block)
{
	struct inode *inode;
	struct gfs2_inode *ip;
	struct gfs2_glock *io_gl = NULL;
	int error;

	inode = gfs2_iget(sb, no_addr, non_block);
	ip = GFS2_I(inode);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (inode->i_state & I_NEW) {
		struct gfs2_sbd *sdp = GFS2_SB(inode);
		ip->i_no_formal_ino = no_formal_ino;

		error = gfs2_glock_get(sdp, no_addr, &gfs2_inode_glops, CREATE, &ip->i_gl);
		if (unlikely(error))
			goto fail;
		ip->i_gl->gl_object = ip;

		error = gfs2_glock_get(sdp, no_addr, &gfs2_iopen_glops, CREATE, &io_gl);
		if (unlikely(error))
			goto fail_put;

		set_bit(GIF_INVALID, &ip->i_flags);
		error = gfs2_glock_nq_init(io_gl, LM_ST_SHARED, GL_EXACT, &ip->i_iopen_gh);
		if (unlikely(error))
			goto fail_iopen;

		ip->i_iopen_gh.gh_gl->gl_object = ip;
		gfs2_glock_put(io_gl);
		io_gl = NULL;

		if (type == DT_UNKNOWN) {
			/* Inode glock must be locked already */
			error = gfs2_inode_refresh(GFS2_I(inode));
			if (error)
				goto fail_refresh;
		} else {
			inode->i_mode = DT2IF(type);
		}

		gfs2_set_iop(inode);
		unlock_new_inode(inode);
	}

	return inode;

fail_refresh:
	ip->i_iopen_gh.gh_flags |= GL_NOCACHE;
	ip->i_iopen_gh.gh_gl->gl_object = NULL;
	gfs2_glock_dq_uninit(&ip->i_iopen_gh);
fail_iopen:
	if (io_gl)
		gfs2_glock_put(io_gl);
fail_put:
	ip->i_gl->gl_object = NULL;
	gfs2_glock_put(ip->i_gl);
fail:
	iget_failed(inode);
	return ERR_PTR(error);
}

struct inode *gfs2_lookup_by_inum(struct gfs2_sbd *sdp, u64 no_addr,
				  u64 *no_formal_ino, unsigned int blktype)
{
	struct super_block *sb = sdp->sd_vfs;
	struct gfs2_holder i_gh;
	struct inode *inode = NULL;
	int error;

	/* Must not read in block until block type is verified */
	error = gfs2_glock_nq_num(sdp, no_addr, &gfs2_inode_glops,
				  LM_ST_EXCLUSIVE, GL_SKIP, &i_gh);
	if (error)
		return ERR_PTR(error);

	error = gfs2_check_blk_type(sdp, no_addr, blktype);
	if (error)
		goto fail;

	inode = gfs2_inode_lookup(sb, DT_UNKNOWN, no_addr, 0, 1);
	if (IS_ERR(inode))
		goto fail;

	/* Two extra checks for NFS only */
	if (no_formal_ino) {
		error = -ESTALE;
		if (GFS2_I(inode)->i_no_formal_ino != *no_formal_ino)
			goto fail_iput;

		error = -EIO;
		if (GFS2_I(inode)->i_diskflags & GFS2_DIF_SYSTEM)
			goto fail_iput;

		error = 0;
	}

fail:
	gfs2_glock_dq_uninit(&i_gh);
	return error ? ERR_PTR(error) : inode;
fail_iput:
	iput(inode);
	goto fail;
}


struct inode *gfs2_lookup_simple(struct inode *dip, const char *name)
{
	struct qstr qstr;
	struct inode *inode;
	gfs2_str2qstr(&qstr, name);
	inode = gfs2_lookupi(dip, &qstr, 1);
	/* gfs2_lookupi has inconsistent callers: vfs
	 * related routines expect NULL for no entry found,
	 * gfs2_lookup_simple callers expect ENOENT
	 * and do not check for NULL.
	 */
	if (inode == NULL)
		return ERR_PTR(-ENOENT);
	else
		return inode;
}


/**
 * gfs2_lookupi - Look up a filename in a directory and return its inode
 * @d_gh: An initialized holder for the directory glock
 * @name: The name of the inode to look for
 * @is_root: If 1, ignore the caller's permissions
 * @i_gh: An uninitialized holder for the new inode glock
 *
 * This can be called via the VFS filldir function when NFS is doing
 * a readdirplus and the inode which its intending to stat isn't
 * already in cache. In this case we must not take the directory glock
 * again, since the readdir call will have already taken that lock.
 *
 * Returns: errno
 */

struct inode *gfs2_lookupi(struct inode *dir, const struct qstr *name,
			   int is_root)
{
	struct super_block *sb = dir->i_sb;
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_holder d_gh;
	int error = 0;
	struct inode *inode = NULL;
	int unlock = 0;

	if (!name->len || name->len > GFS2_FNAMESIZE)
		return ERR_PTR(-ENAMETOOLONG);

	if ((name->len == 1 && memcmp(name->name, ".", 1) == 0) ||
	    (name->len == 2 && memcmp(name->name, "..", 2) == 0 &&
	     dir == sb->s_root->d_inode)) {
		igrab(dir);
		return dir;
	}

	if (gfs2_glock_is_locked_by_me(dip->i_gl) == NULL) {
		error = gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED, 0, &d_gh);
		if (error)
			return ERR_PTR(error);
		unlock = 1;
	}

	if (!is_root) {
		error = gfs2_permission(dir, MAY_EXEC);
		if (error)
			goto out;
	}

	inode = gfs2_dir_search(dir, name, false);
	if (IS_ERR(inode))
		error = PTR_ERR(inode);
out:
	if (unlock)
		gfs2_glock_dq_uninit(&d_gh);
	if (error == -ENOENT)
		return NULL;
	return inode ? inode : ERR_PTR(error);
}

/**
 * create_ok - OK to create a new on-disk inode here?
 * @dip:  Directory in which dinode is to be created
 * @name:  Name of new dinode
 * @mode:
 *
 * Returns: errno
 */

static int create_ok(struct gfs2_inode *dip, const struct qstr *name,
		     umode_t mode)
{
	int error;

	error = gfs2_permission(&dip->i_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	/*  Don't create entries in an unlinked directory  */
	if (!dip->i_inode.i_nlink)
		return -ENOENT;

	if (dip->i_entries == (u32)-1)
		return -EFBIG;
	if (S_ISDIR(mode) && dip->i_inode.i_nlink == (u32)-1)
		return -EMLINK;

	return 0;
}

static void munge_mode_uid_gid(const struct gfs2_inode *dip,
			       struct inode *inode)
{
	if (GFS2_SB(&dip->i_inode)->sd_args.ar_suiddir &&
	    (dip->i_inode.i_mode & S_ISUID) &&
	    !uid_eq(dip->i_inode.i_uid, GLOBAL_ROOT_UID)) {
		if (S_ISDIR(inode->i_mode))
			inode->i_mode |= S_ISUID;
		else if (!uid_eq(dip->i_inode.i_uid, current_fsuid()))
			inode->i_mode &= ~07111;
		inode->i_uid = dip->i_inode.i_uid;
	} else
		inode->i_uid = current_fsuid();

	if (dip->i_inode.i_mode & S_ISGID) {
		if (S_ISDIR(inode->i_mode))
			inode->i_mode |= S_ISGID;
		inode->i_gid = dip->i_inode.i_gid;
	} else
		inode->i_gid = current_fsgid();
}

static int alloc_dinode(struct gfs2_inode *ip, u32 flags, unsigned *dblocks)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_alloc_parms ap = { .target = *dblocks, .aflags = flags, };
	int error;

	error = gfs2_quota_lock_check(ip);
	if (error)
		goto out;

	error = gfs2_inplace_reserve(ip, &ap);
	if (error)
		goto out_quota;

	error = gfs2_trans_begin(sdp, (*dblocks * RES_RG_BIT) + RES_STATFS + RES_QUOTA, 0);
	if (error)
		goto out_ipreserv;

	error = gfs2_alloc_blocks(ip, &ip->i_no_addr, dblocks, 1, &ip->i_generation);
	ip->i_no_formal_ino = ip->i_generation;
	ip->i_inode.i_ino = ip->i_no_addr;
	ip->i_goal = ip->i_no_addr;

	gfs2_trans_end(sdp);

out_ipreserv:
	gfs2_inplace_release(ip);
out_quota:
	gfs2_quota_unlock(ip);
out:
	return error;
}

static void gfs2_init_dir(struct buffer_head *dibh,
			  const struct gfs2_inode *parent)
{
	struct gfs2_dinode *di = (struct gfs2_dinode *)dibh->b_data;
	struct gfs2_dirent *dent = (struct gfs2_dirent *)(di+1);

	gfs2_qstr2dirent(&gfs2_qdot, GFS2_DIRENT_SIZE(gfs2_qdot.len), dent);
	dent->de_inum = di->di_num; /* already GFS2 endian */
	dent->de_type = cpu_to_be16(DT_DIR);

	dent = (struct gfs2_dirent *)((char*)dent + GFS2_DIRENT_SIZE(1));
	gfs2_qstr2dirent(&gfs2_qdotdot, dibh->b_size - GFS2_DIRENT_SIZE(1) - sizeof(struct gfs2_dinode), dent);
	gfs2_inum_out(parent, dent);
	dent->de_type = cpu_to_be16(DT_DIR);

}

/**
 * gfs2_init_xattr - Initialise an xattr block for a new inode
 * @ip: The inode in question
 *
 * This sets up an empty xattr block for a new inode, ready to
 * take any ACLs, LSM xattrs, etc.
 */

static void gfs2_init_xattr(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head *bh;
	struct gfs2_ea_header *ea;

	bh = gfs2_meta_new(ip->i_gl, ip->i_eattr);
	gfs2_trans_add_meta(ip->i_gl, bh);
	gfs2_metatype_set(bh, GFS2_METATYPE_EA, GFS2_FORMAT_EA);
	gfs2_buffer_clear_tail(bh, sizeof(struct gfs2_meta_header));

	ea = GFS2_EA_BH2FIRST(bh);
	ea->ea_rec_len = cpu_to_be32(sdp->sd_jbsize);
	ea->ea_type = GFS2_EATYPE_UNUSED;
	ea->ea_flags = GFS2_EAFLAG_LAST;

	brelse(bh);
}

/**
 * init_dinode - Fill in a new dinode structure
 * @dip: The directory this inode is being created in
 * @ip: The inode
 * @symname: The symlink destination (if a symlink)
 * @bhp: The buffer head (returned to caller)
 *
 */

static void init_dinode(struct gfs2_inode *dip, struct gfs2_inode *ip,
			const char *symname)
{
	struct gfs2_dinode *di;
	struct buffer_head *dibh;

	dibh = gfs2_meta_new(ip->i_gl, ip->i_no_addr);
	gfs2_trans_add_meta(ip->i_gl, dibh);
	di = (struct gfs2_dinode *)dibh->b_data;
	gfs2_dinode_out(ip, di);

	di->di_major = cpu_to_be32(MAJOR(ip->i_inode.i_rdev));
	di->di_minor = cpu_to_be32(MINOR(ip->i_inode.i_rdev));
	di->__pad1 = 0;
	di->__pad2 = 0;
	di->__pad3 = 0;
	memset(&di->__pad4, 0, sizeof(di->__pad4));
	memset(&di->di_reserved, 0, sizeof(di->di_reserved));
	gfs2_buffer_clear_tail(dibh, sizeof(struct gfs2_dinode));

	switch(ip->i_inode.i_mode & S_IFMT) {
	case S_IFDIR:
		gfs2_init_dir(dibh, dip);
		break;
	case S_IFLNK:
		memcpy(dibh->b_data + sizeof(struct gfs2_dinode), symname, ip->i_inode.i_size);
		break;
	}

	set_buffer_uptodate(dibh);
	brelse(dibh);
}

/**
 * gfs2_trans_da_blocks - Calculate number of blocks to link inode
 * @dip: The directory we are linking into
 * @da: The dir add information
 * @nr_inodes: The number of inodes involved
 *
 * This calculate the number of blocks we need to reserve in a
 * transaction to link @nr_inodes into a directory. In most cases
 * @nr_inodes will be 2 (the directory plus the inode being linked in)
 * but in case of rename, 4 may be required.
 *
 * Returns: Number of blocks
 */

static unsigned gfs2_trans_da_blks(const struct gfs2_inode *dip,
				   const struct gfs2_diradd *da,
				   unsigned nr_inodes)
{
	return da->nr_blocks + gfs2_rg_blocks(dip, da->nr_blocks) +
	       (nr_inodes * RES_DINODE) + RES_QUOTA + RES_STATFS;
}

static int link_dinode(struct gfs2_inode *dip, const struct qstr *name,
		       struct gfs2_inode *ip, struct gfs2_diradd *da)
{
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	struct gfs2_alloc_parms ap = { .target = da->nr_blocks, };
	int error;

	if (da->nr_blocks) {
		error = gfs2_quota_lock_check(dip);
		if (error)
			goto fail_quota_locks;

		error = gfs2_inplace_reserve(dip, &ap);
		if (error)
			goto fail_quota_locks;

		error = gfs2_trans_begin(sdp, gfs2_trans_da_blks(dip, da, 2), 0);
		if (error)
			goto fail_ipreserv;
	} else {
		error = gfs2_trans_begin(sdp, RES_LEAF + 2 * RES_DINODE, 0);
		if (error)
			goto fail_quota_locks;
	}

	error = gfs2_dir_add(&dip->i_inode, name, ip, da);
	if (error)
		goto fail_end_trans;

fail_end_trans:
	gfs2_trans_end(sdp);
fail_ipreserv:
	gfs2_inplace_release(dip);
fail_quota_locks:
	gfs2_quota_unlock(dip);
	return error;
}

static int gfs2_initxattrs(struct inode *inode, const struct xattr *xattr_array,
		    void *fs_info)
{
	const struct xattr *xattr;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = __gfs2_xattr_set(inode, xattr->name, xattr->value,
				       xattr->value_len, 0,
				       GFS2_EATYPE_SECURITY);
		if (err < 0)
			break;
	}
	return err;
}

/**
 * gfs2_create_inode - Create a new inode
 * @dir: The parent directory
 * @dentry: The new dentry
 * @file: If non-NULL, the file which is being opened
 * @mode: The permissions on the new inode
 * @dev: For device nodes, this is the device number
 * @symname: For symlinks, this is the link destination
 * @size: The initial size of the inode (ignored for directories)
 *
 * Returns: 0 on success, or error code
 */

static int gfs2_create_inode(struct inode *dir, struct dentry *dentry,
			     struct file *file,
			     umode_t mode, dev_t dev, const char *symname,
			     unsigned int size, int excl, int *opened)
{
	const struct qstr *name = &dentry->d_name;
	struct posix_acl *default_acl, *acl;
	struct gfs2_holder ghs[2];
	struct inode *inode = NULL;
	struct gfs2_inode *dip = GFS2_I(dir), *ip;
	struct gfs2_sbd *sdp = GFS2_SB(&dip->i_inode);
	struct gfs2_glock *io_gl;
	struct dentry *d;
	int error, free_vfs_inode = 0;
	u32 aflags = 0;
	unsigned blocks = 1;
	struct gfs2_diradd da = { .bh = NULL, };

	if (!name->len || name->len > GFS2_FNAMESIZE)
		return -ENAMETOOLONG;

	error = gfs2_rs_alloc(dip);
	if (error)
		return error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = gfs2_glock_nq_init(dip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	if (error)
		goto fail;

	error = create_ok(dip, name, mode);
	if (error)
		goto fail_gunlock;

	inode = gfs2_dir_search(dir, &dentry->d_name, !S_ISREG(mode) || excl);
	error = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		d = d_splice_alias(inode, dentry);
		error = PTR_ERR(d);
		if (IS_ERR(d))
			goto fail_gunlock;
		error = 0;
		if (file) {
			if (S_ISREG(inode->i_mode)) {
				WARN_ON(d != NULL);
				error = finish_open(file, dentry, gfs2_open_common, opened);
			} else {
				error = finish_no_open(file, d);
			}
		} else {
			dput(d);
		}
		gfs2_glock_dq_uninit(ghs);
		return error;
	} else if (error != -ENOENT) {
		goto fail_gunlock;
	}

	error = gfs2_diradd_alloc_required(dir, name, &da);
	if (error < 0)
		goto fail_gunlock;

	inode = new_inode(sdp->sd_vfs);
	error = -ENOMEM;
	if (!inode)
		goto fail_gunlock;

	error = posix_acl_create(dir, &mode, &default_acl, &acl);
	if (error)
		goto fail_free_vfs_inode;

	ip = GFS2_I(inode);
	error = gfs2_rs_alloc(ip);
	if (error)
		goto fail_free_acls;

	inode->i_mode = mode;
	set_nlink(inode, S_ISDIR(mode) ? 2 : 1);
	inode->i_rdev = dev;
	inode->i_size = size;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	gfs2_set_inode_blocks(inode, 1);
	munge_mode_uid_gid(dip, inode);
	ip->i_goal = dip->i_goal;
	ip->i_diskflags = 0;
	ip->i_eattr = 0;
	ip->i_height = 0;
	ip->i_depth = 0;
	ip->i_entries = 0;

	switch(mode & S_IFMT) {
	case S_IFREG:
		if ((dip->i_diskflags & GFS2_DIF_INHERIT_JDATA) ||
		    gfs2_tune_get(sdp, gt_new_files_jdata))
			ip->i_diskflags |= GFS2_DIF_JDATA;
		gfs2_set_aops(inode);
		break;
	case S_IFDIR:
		ip->i_diskflags |= (dip->i_diskflags & GFS2_DIF_INHERIT_JDATA);
		ip->i_diskflags |= GFS2_DIF_JDATA;
		ip->i_entries = 2;
		break;
	}
	gfs2_set_inode_flags(inode);

	if ((GFS2_I(sdp->sd_root_dir->d_inode) == dip) ||
	    (dip->i_diskflags & GFS2_DIF_TOPDIR))
		aflags |= GFS2_AF_ORLOV;

	if (default_acl || acl)
		blocks++;

	error = alloc_dinode(ip, aflags, &blocks);
	if (error)
		goto fail_free_inode;

	gfs2_set_inode_blocks(inode, blocks);

	error = gfs2_glock_get(sdp, ip->i_no_addr, &gfs2_inode_glops, CREATE, &ip->i_gl);
	if (error)
		goto fail_free_inode;

	ip->i_gl->gl_object = ip;
	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, GL_SKIP, ghs + 1);
	if (error)
		goto fail_free_inode;

	error = gfs2_trans_begin(sdp, blocks, 0);
	if (error)
		goto fail_gunlock2;

	if (blocks > 1) {
		ip->i_eattr = ip->i_no_addr + 1;
		gfs2_init_xattr(ip);
	}
	init_dinode(dip, ip, symname);
	gfs2_trans_end(sdp);

	error = gfs2_glock_get(sdp, ip->i_no_addr, &gfs2_iopen_glops, CREATE, &io_gl);
	if (error)
		goto fail_gunlock2;

	error = gfs2_glock_nq_init(io_gl, LM_ST_SHARED, GL_EXACT, &ip->i_iopen_gh);
	if (error)
		goto fail_gunlock2;

	ip->i_iopen_gh.gh_gl->gl_object = ip;
	gfs2_glock_put(io_gl);
	gfs2_set_iop(inode);
	insert_inode_hash(inode);

	if (default_acl) {
		error = gfs2_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		posix_acl_release(default_acl);
	}
	if (acl) {
		if (!error)
			error = gfs2_set_acl(inode, acl, ACL_TYPE_ACCESS);
		posix_acl_release(acl);
	}

	if (error)
		goto fail_gunlock3;

	error = security_inode_init_security(&ip->i_inode, &dip->i_inode, name,
					     &gfs2_initxattrs, NULL);
	if (error)
		goto fail_gunlock3;

	error = link_dinode(dip, name, ip, &da);
	if (error)
		goto fail_gunlock3;

	mark_inode_dirty(inode);
	d_instantiate(dentry, inode);
	if (file) {
		*opened |= FILE_CREATED;
		error = finish_open(file, dentry, gfs2_open_common, opened);
	}
	gfs2_glock_dq_uninit(ghs);
	gfs2_glock_dq_uninit(ghs + 1);
	return error;

fail_gunlock3:
	gfs2_glock_dq_uninit(ghs + 1);
	if (ip->i_gl)
		gfs2_glock_put(ip->i_gl);
	goto fail_gunlock;

fail_gunlock2:
	gfs2_glock_dq_uninit(ghs + 1);
fail_free_inode:
	if (ip->i_gl)
		gfs2_glock_put(ip->i_gl);
	gfs2_rs_delete(ip, NULL);
fail_free_acls:
	if (default_acl)
		posix_acl_release(default_acl);
	if (acl)
		posix_acl_release(acl);
fail_free_vfs_inode:
	free_vfs_inode = 1;
fail_gunlock:
	gfs2_dir_no_add(&da);
	gfs2_glock_dq_uninit(ghs);
	if (inode && !IS_ERR(inode)) {
		clear_nlink(inode);
		if (!free_vfs_inode)
			mark_inode_dirty(inode);
		set_bit(free_vfs_inode ? GIF_FREE_VFS_INODE : GIF_ALLOC_FAILED,
			&GFS2_I(inode)->i_flags);
		iput(inode);
	}
fail:
	return error;
}

/**
 * gfs2_create - Create a file
 * @dir: The directory in which to create the file
 * @dentry: The dentry of the new file
 * @mode: The mode of the new file
 *
 * Returns: errno
 */

static int gfs2_create(struct inode *dir, struct dentry *dentry,
		       umode_t mode, bool excl)
{
	return gfs2_create_inode(dir, dentry, NULL, S_IFREG | mode, 0, NULL, 0, excl, NULL);
}

/**
 * __gfs2_lookup - Look up a filename in a directory and return its inode
 * @dir: The directory inode
 * @dentry: The dentry of the new inode
 * @file: File to be opened
 * @opened: atomic_open flags
 *
 *
 * Returns: errno
 */

static struct dentry *__gfs2_lookup(struct inode *dir, struct dentry *dentry,
				    struct file *file, int *opened)
{
	struct inode *inode;
	struct dentry *d;
	struct gfs2_holder gh;
	struct gfs2_glock *gl;
	int error;

	inode = gfs2_lookupi(dir, &dentry->d_name, 0);
	if (!inode)
		return NULL;
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	gl = GFS2_I(inode)->i_gl;
	error = gfs2_glock_nq_init(gl, LM_ST_SHARED, LM_FLAG_ANY, &gh);
	if (error) {
		iput(inode);
		return ERR_PTR(error);
	}

	d = d_splice_alias(inode, dentry);
	if (IS_ERR(d)) {
		iput(inode);
		gfs2_glock_dq_uninit(&gh);
		return d;
	}
	if (file && S_ISREG(inode->i_mode))
		error = finish_open(file, dentry, gfs2_open_common, opened);

	gfs2_glock_dq_uninit(&gh);
	if (error) {
		dput(d);
		return ERR_PTR(error);
	}
	return d;
}

static struct dentry *gfs2_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned flags)
{
	return __gfs2_lookup(dir, dentry, NULL, NULL);
}

/**
 * gfs2_link - Link to a file
 * @old_dentry: The inode to link
 * @dir: Add link to this directory
 * @dentry: The name of the link
 *
 * Link the inode in "old_dentry" into the directory "dir" with the
 * name in "dentry".
 *
 * Returns: errno
 */

static int gfs2_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *dentry)
{
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_sbd *sdp = GFS2_SB(dir);
	struct inode *inode = old_dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder ghs[2];
	struct buffer_head *dibh;
	struct gfs2_diradd da = { .bh = NULL, };
	int error;

	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	error = gfs2_rs_alloc(dip);
	if (error)
		return error;

	gfs2_holder_init(dip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + 1);

	error = gfs2_glock_nq(ghs); /* parent */
	if (error)
		goto out_parent;

	error = gfs2_glock_nq(ghs + 1); /* child */
	if (error)
		goto out_child;

	error = -ENOENT;
	if (inode->i_nlink == 0)
		goto out_gunlock;

	error = gfs2_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		goto out_gunlock;

	error = gfs2_dir_check(dir, &dentry->d_name, NULL);
	switch (error) {
	case -ENOENT:
		break;
	case 0:
		error = -EEXIST;
	default:
		goto out_gunlock;
	}

	error = -EINVAL;
	if (!dip->i_inode.i_nlink)
		goto out_gunlock;
	error = -EFBIG;
	if (dip->i_entries == (u32)-1)
		goto out_gunlock;
	error = -EPERM;
	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		goto out_gunlock;
	error = -EINVAL;
	if (!ip->i_inode.i_nlink)
		goto out_gunlock;
	error = -EMLINK;
	if (ip->i_inode.i_nlink == (u32)-1)
		goto out_gunlock;

	error = gfs2_diradd_alloc_required(dir, &dentry->d_name, &da);
	if (error < 0)
		goto out_gunlock;

	if (da.nr_blocks) {
		struct gfs2_alloc_parms ap = { .target = da.nr_blocks, };
		error = gfs2_quota_lock_check(dip);
		if (error)
			goto out_gunlock;

		error = gfs2_inplace_reserve(dip, &ap);
		if (error)
			goto out_gunlock_q;

		error = gfs2_trans_begin(sdp, gfs2_trans_da_blks(dip, &da, 2), 0);
		if (error)
			goto out_ipres;
	} else {
		error = gfs2_trans_begin(sdp, 2 * RES_DINODE + RES_LEAF, 0);
		if (error)
			goto out_ipres;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out_end_trans;

	error = gfs2_dir_add(dir, &dentry->d_name, ip, &da);
	if (error)
		goto out_brelse;

	gfs2_trans_add_meta(ip->i_gl, dibh);
	inc_nlink(&ip->i_inode);
	ip->i_inode.i_ctime = CURRENT_TIME;
	ihold(inode);
	d_instantiate(dentry, inode);
	mark_inode_dirty(inode);

out_brelse:
	brelse(dibh);
out_end_trans:
	gfs2_trans_end(sdp);
out_ipres:
	if (da.nr_blocks)
		gfs2_inplace_release(dip);
out_gunlock_q:
	if (da.nr_blocks)
		gfs2_quota_unlock(dip);
out_gunlock:
	gfs2_dir_no_add(&da);
	gfs2_glock_dq(ghs + 1);
out_child:
	gfs2_glock_dq(ghs);
out_parent:
	gfs2_holder_uninit(ghs);
	gfs2_holder_uninit(ghs + 1);
	return error;
}

/*
 * gfs2_unlink_ok - check to see that a inode is still in a directory
 * @dip: the directory
 * @name: the name of the file
 * @ip: the inode
 *
 * Assumes that the lock on (at least) @dip is held.
 *
 * Returns: 0 if the parent/child relationship is correct, errno if it isn't
 */

static int gfs2_unlink_ok(struct gfs2_inode *dip, const struct qstr *name,
			  const struct gfs2_inode *ip)
{
	int error;

	if (IS_IMMUTABLE(&ip->i_inode) || IS_APPEND(&ip->i_inode))
		return -EPERM;

	if ((dip->i_inode.i_mode & S_ISVTX) &&
	    !uid_eq(dip->i_inode.i_uid, current_fsuid()) &&
	    !uid_eq(ip->i_inode.i_uid, current_fsuid()) && !capable(CAP_FOWNER))
		return -EPERM;

	if (IS_APPEND(&dip->i_inode))
		return -EPERM;

	error = gfs2_permission(&dip->i_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	error = gfs2_dir_check(&dip->i_inode, name, ip);
	if (error)
		return error;

	return 0;
}

/**
 * gfs2_unlink_inode - Removes an inode from its parent dir and unlinks it
 * @dip: The parent directory
 * @name: The name of the entry in the parent directory
 * @inode: The inode to be removed
 *
 * Called with all the locks and in a transaction. This will only be
 * called for a directory after it has been checked to ensure it is empty.
 *
 * Returns: 0 on success, or an error
 */

static int gfs2_unlink_inode(struct gfs2_inode *dip,
			     const struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	int error;

	error = gfs2_dir_del(dip, dentry);
	if (error)
		return error;

	ip->i_entries = 0;
	inode->i_ctime = CURRENT_TIME;
	if (S_ISDIR(inode->i_mode))
		clear_nlink(inode);
	else
		drop_nlink(inode);
	mark_inode_dirty(inode);
	if (inode->i_nlink == 0)
		gfs2_unlink_di(inode);
	return 0;
}


/**
 * gfs2_unlink - Unlink an inode (this does rmdir as well)
 * @dir: The inode of the directory containing the inode to unlink
 * @dentry: The file itself
 *
 * This routine uses the type of the inode as a flag to figure out
 * whether this is an unlink or an rmdir.
 *
 * Returns: errno
 */

static int gfs2_unlink(struct inode *dir, struct dentry *dentry)
{
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_sbd *sdp = GFS2_SB(dir);
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder ghs[3];
	struct gfs2_rgrpd *rgd;
	int error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = -EROFS;

	gfs2_holder_init(dip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	gfs2_holder_init(ip->i_gl,  LM_ST_EXCLUSIVE, 0, ghs + 1);

	rgd = gfs2_blk2rgrpd(sdp, ip->i_no_addr, 1);
	if (!rgd)
		goto out_inodes;

	gfs2_holder_init(rgd->rd_gl, LM_ST_EXCLUSIVE, 0, ghs + 2);


	error = gfs2_glock_nq(ghs); /* parent */
	if (error)
		goto out_parent;

	error = gfs2_glock_nq(ghs + 1); /* child */
	if (error)
		goto out_child;

	error = -ENOENT;
	if (inode->i_nlink == 0)
		goto out_rgrp;

	if (S_ISDIR(inode->i_mode)) {
		error = -ENOTEMPTY;
		if (ip->i_entries > 2 || inode->i_nlink > 2)
			goto out_rgrp;
	}

	error = gfs2_glock_nq(ghs + 2); /* rgrp */
	if (error)
		goto out_rgrp;

	error = gfs2_unlink_ok(dip, &dentry->d_name, ip);
	if (error)
		goto out_gunlock;

	error = gfs2_trans_begin(sdp, 2*RES_DINODE + 3*RES_LEAF + RES_RG_BIT, 0);
	if (error)
		goto out_end_trans;

	error = gfs2_unlink_inode(dip, dentry);

out_end_trans:
	gfs2_trans_end(sdp);
out_gunlock:
	gfs2_glock_dq(ghs + 2);
out_rgrp:
	gfs2_glock_dq(ghs + 1);
out_child:
	gfs2_glock_dq(ghs);
out_parent:
	gfs2_holder_uninit(ghs + 2);
out_inodes:
	gfs2_holder_uninit(ghs + 1);
	gfs2_holder_uninit(ghs);
	return error;
}

/**
 * gfs2_symlink - Create a symlink
 * @dir: The directory to create the symlink in
 * @dentry: The dentry to put the symlink in
 * @symname: The thing which the link points to
 *
 * Returns: errno
 */

static int gfs2_symlink(struct inode *dir, struct dentry *dentry,
			const char *symname)
{
	struct gfs2_sbd *sdp = GFS2_SB(dir);
	unsigned int size;

	size = strlen(symname);
	if (size > sdp->sd_sb.sb_bsize - sizeof(struct gfs2_dinode) - 1)
		return -ENAMETOOLONG;

	return gfs2_create_inode(dir, dentry, NULL, S_IFLNK | S_IRWXUGO, 0, symname, size, 0, NULL);
}

/**
 * gfs2_mkdir - Make a directory
 * @dir: The parent directory of the new one
 * @dentry: The dentry of the new directory
 * @mode: The mode of the new directory
 *
 * Returns: errno
 */

static int gfs2_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct gfs2_sbd *sdp = GFS2_SB(dir);
	unsigned dsize = sdp->sd_sb.sb_bsize - sizeof(struct gfs2_dinode);
	return gfs2_create_inode(dir, dentry, NULL, S_IFDIR | mode, 0, NULL, dsize, 0, NULL);
}

/**
 * gfs2_mknod - Make a special file
 * @dir: The directory in which the special file will reside
 * @dentry: The dentry of the special file
 * @mode: The mode of the special file
 * @dev: The device specification of the special file
 *
 */

static int gfs2_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		      dev_t dev)
{
	return gfs2_create_inode(dir, dentry, NULL, mode, dev, NULL, 0, 0, NULL);
}

/**
 * gfs2_atomic_open - Atomically open a file
 * @dir: The directory
 * @dentry: The proposed new entry
 * @file: The proposed new struct file
 * @flags: open flags
 * @mode: File mode
 * @opened: Flag to say whether the file has been opened or not
 *
 * Returns: error code or 0 for success
 */

static int gfs2_atomic_open(struct inode *dir, struct dentry *dentry,
                            struct file *file, unsigned flags,
                            umode_t mode, int *opened)
{
	struct dentry *d;
	bool excl = !!(flags & O_EXCL);

	d = __gfs2_lookup(dir, dentry, file, opened);
	if (IS_ERR(d))
		return PTR_ERR(d);
	if (d != NULL)
		dentry = d;
	if (dentry->d_inode) {
		if (!(*opened & FILE_OPENED)) {
			if (d == NULL)
				dget(dentry);
			return finish_no_open(file, dentry);
		}
		dput(d);
		return 0;
	}

	BUG_ON(d != NULL);
	if (!(flags & O_CREAT))
		return -ENOENT;

	return gfs2_create_inode(dir, dentry, file, S_IFREG | mode, 0, NULL, 0, excl, opened);
}

/*
 * gfs2_ok_to_move - check if it's ok to move a directory to another directory
 * @this: move this
 * @to: to here
 *
 * Follow @to back to the root and make sure we don't encounter @this
 * Assumes we already hold the rename lock.
 *
 * Returns: errno
 */

static int gfs2_ok_to_move(struct gfs2_inode *this, struct gfs2_inode *to)
{
	struct inode *dir = &to->i_inode;
	struct super_block *sb = dir->i_sb;
	struct inode *tmp;
	int error = 0;

	igrab(dir);

	for (;;) {
		if (dir == &this->i_inode) {
			error = -EINVAL;
			break;
		}
		if (dir == sb->s_root->d_inode) {
			error = 0;
			break;
		}

		tmp = gfs2_lookupi(dir, &gfs2_qdotdot, 1);
		if (!tmp) {
			error = -ENOENT;
			break;
		}
		if (IS_ERR(tmp)) {
			error = PTR_ERR(tmp);
			break;
		}

		iput(dir);
		dir = tmp;
	}

	iput(dir);

	return error;
}

/**
 * gfs2_rename - Rename a file
 * @odir: Parent directory of old file name
 * @odentry: The old dentry of the file
 * @ndir: Parent directory of new file name
 * @ndentry: The new dentry of the file
 *
 * Returns: errno
 */

static int gfs2_rename(struct inode *odir, struct dentry *odentry,
		       struct inode *ndir, struct dentry *ndentry)
{
	struct gfs2_inode *odip = GFS2_I(odir);
	struct gfs2_inode *ndip = GFS2_I(ndir);
	struct gfs2_inode *ip = GFS2_I(odentry->d_inode);
	struct gfs2_inode *nip = NULL;
	struct gfs2_sbd *sdp = GFS2_SB(odir);
	struct gfs2_holder ghs[5], r_gh = { .gh_gl = NULL, };
	struct gfs2_rgrpd *nrgd;
	unsigned int num_gh;
	int dir_rename = 0;
	struct gfs2_diradd da = { .nr_blocks = 0, };
	unsigned int x;
	int error;

	if (ndentry->d_inode) {
		nip = GFS2_I(ndentry->d_inode);
		if (ip == nip)
			return 0;
	}

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = gfs2_rs_alloc(ndip);
	if (error)
		return error;

	if (odip != ndip) {
		error = gfs2_glock_nq_init(sdp->sd_rename_gl, LM_ST_EXCLUSIVE,
					   0, &r_gh);
		if (error)
			goto out;

		if (S_ISDIR(ip->i_inode.i_mode)) {
			dir_rename = 1;
			/* don't move a dirctory into it's subdir */
			error = gfs2_ok_to_move(ip, ndip);
			if (error)
				goto out_gunlock_r;
		}
	}

	num_gh = 1;
	gfs2_holder_init(odip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	if (odip != ndip) {
		gfs2_holder_init(ndip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
		num_gh++;
	}
	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
	num_gh++;

	if (nip) {
		gfs2_holder_init(nip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
		num_gh++;
		/* grab the resource lock for unlink flag twiddling
		 * this is the case of the target file already existing
		 * so we unlink before doing the rename
		 */
		nrgd = gfs2_blk2rgrpd(sdp, nip->i_no_addr, 1);
		if (nrgd)
			gfs2_holder_init(nrgd->rd_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh++);
	}

	for (x = 0; x < num_gh; x++) {
		error = gfs2_glock_nq(ghs + x);
		if (error)
			goto out_gunlock;
	}

	error = -ENOENT;
	if (ip->i_inode.i_nlink == 0)
		goto out_gunlock;

	/* Check out the old directory */

	error = gfs2_unlink_ok(odip, &odentry->d_name, ip);
	if (error)
		goto out_gunlock;

	/* Check out the new directory */

	if (nip) {
		error = gfs2_unlink_ok(ndip, &ndentry->d_name, nip);
		if (error)
			goto out_gunlock;

		if (nip->i_inode.i_nlink == 0) {
			error = -EAGAIN;
			goto out_gunlock;
		}

		if (S_ISDIR(nip->i_inode.i_mode)) {
			if (nip->i_entries < 2) {
				gfs2_consist_inode(nip);
				error = -EIO;
				goto out_gunlock;
			}
			if (nip->i_entries > 2) {
				error = -ENOTEMPTY;
				goto out_gunlock;
			}
		}
	} else {
		error = gfs2_permission(ndir, MAY_WRITE | MAY_EXEC);
		if (error)
			goto out_gunlock;

		error = gfs2_dir_check(ndir, &ndentry->d_name, NULL);
		switch (error) {
		case -ENOENT:
			error = 0;
			break;
		case 0:
			error = -EEXIST;
		default:
			goto out_gunlock;
		};

		if (odip != ndip) {
			if (!ndip->i_inode.i_nlink) {
				error = -ENOENT;
				goto out_gunlock;
			}
			if (ndip->i_entries == (u32)-1) {
				error = -EFBIG;
				goto out_gunlock;
			}
			if (S_ISDIR(ip->i_inode.i_mode) &&
			    ndip->i_inode.i_nlink == (u32)-1) {
				error = -EMLINK;
				goto out_gunlock;
			}
		}
	}

	/* Check out the dir to be renamed */

	if (dir_rename) {
		error = gfs2_permission(odentry->d_inode, MAY_WRITE);
		if (error)
			goto out_gunlock;
	}

	if (nip == NULL) {
		error = gfs2_diradd_alloc_required(ndir, &ndentry->d_name, &da);
		if (error)
			goto out_gunlock;
	}

	if (da.nr_blocks) {
		struct gfs2_alloc_parms ap = { .target = da.nr_blocks, };
		error = gfs2_quota_lock_check(ndip);
		if (error)
			goto out_gunlock;

		error = gfs2_inplace_reserve(ndip, &ap);
		if (error)
			goto out_gunlock_q;

		error = gfs2_trans_begin(sdp, gfs2_trans_da_blks(ndip, &da, 4) +
					 4 * RES_LEAF + 4, 0);
		if (error)
			goto out_ipreserv;
	} else {
		error = gfs2_trans_begin(sdp, 4 * RES_DINODE +
					 5 * RES_LEAF + 4, 0);
		if (error)
			goto out_gunlock;
	}

	/* Remove the target file, if it exists */

	if (nip)
		error = gfs2_unlink_inode(ndip, ndentry);

	if (dir_rename) {
		error = gfs2_dir_mvino(ip, &gfs2_qdotdot, ndip, DT_DIR);
		if (error)
			goto out_end_trans;
	} else {
		struct buffer_head *dibh;
		error = gfs2_meta_inode_buffer(ip, &dibh);
		if (error)
			goto out_end_trans;
		ip->i_inode.i_ctime = CURRENT_TIME;
		gfs2_trans_add_meta(ip->i_gl, dibh);
		gfs2_dinode_out(ip, dibh->b_data);
		brelse(dibh);
	}

	error = gfs2_dir_del(odip, odentry);
	if (error)
		goto out_end_trans;

	error = gfs2_dir_add(ndir, &ndentry->d_name, ip, &da);
	if (error)
		goto out_end_trans;

out_end_trans:
	gfs2_trans_end(sdp);
out_ipreserv:
	if (da.nr_blocks)
		gfs2_inplace_release(ndip);
out_gunlock_q:
	if (da.nr_blocks)
		gfs2_quota_unlock(ndip);
out_gunlock:
	gfs2_dir_no_add(&da);
	while (x--) {
		gfs2_glock_dq(ghs + x);
		gfs2_holder_uninit(ghs + x);
	}
out_gunlock_r:
	if (r_gh.gh_gl)
		gfs2_glock_dq_uninit(&r_gh);
out:
	return error;
}

/**
 * gfs2_follow_link - Follow a symbolic link
 * @dentry: The dentry of the link
 * @nd: Data that we pass to vfs_follow_link()
 *
 * This can handle symlinks of any size.
 *
 * Returns: 0 on success or error code
 */

static void *gfs2_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct gfs2_inode *ip = GFS2_I(dentry->d_inode);
	struct gfs2_holder i_gh;
	struct buffer_head *dibh;
	unsigned int size;
	char *buf;
	int error;

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, 0, &i_gh);
	error = gfs2_glock_nq(&i_gh);
	if (error) {
		gfs2_holder_uninit(&i_gh);
		nd_set_link(nd, ERR_PTR(error));
		return NULL;
	}

	size = (unsigned int)i_size_read(&ip->i_inode);
	if (size == 0) {
		gfs2_consist_inode(ip);
		buf = ERR_PTR(-EIO);
		goto out;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error) {
		buf = ERR_PTR(error);
		goto out;
	}

	buf = kzalloc(size + 1, GFP_NOFS);
	if (!buf)
		buf = ERR_PTR(-ENOMEM);
	else
		memcpy(buf, dibh->b_data + sizeof(struct gfs2_dinode), size);
	brelse(dibh);
out:
	gfs2_glock_dq_uninit(&i_gh);
	nd_set_link(nd, buf);
	return NULL;
}

/**
 * gfs2_permission -
 * @inode: The inode
 * @mask: The mask to be tested
 * @flags: Indicates whether this is an RCU path walk or not
 *
 * This may be called from the VFS directly, or from within GFS2 with the
 * inode locked, so we look to see if the glock is already locked and only
 * lock the glock if its not already been done.
 *
 * Returns: errno
 */

int gfs2_permission(struct inode *inode, int mask)
{
	struct gfs2_inode *ip;
	struct gfs2_holder i_gh;
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	int error;
	int unlock = 0;
	int frozen_root = 0;


	ip = GFS2_I(inode);
	if (gfs2_glock_is_locked_by_me(ip->i_gl) == NULL) {
		if (unlikely(gfs2_glock_is_held_excl(sdp->sd_freeze_gl) &&
			     inode == sdp->sd_root_dir->d_inode &&
			     atomic_inc_not_zero(&sdp->sd_frozen_root)))
			frozen_root = 1;
		else {
			if (mask & MAY_NOT_BLOCK)
				return -ECHILD;
			error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY, &i_gh);
			if (error)
				return error;
			unlock = 1;
		}
	}

	if ((mask & MAY_WRITE) && IS_IMMUTABLE(inode))
		error = -EACCES;
	else
		error = generic_permission(inode, mask);
	if (unlock)
		gfs2_glock_dq_uninit(&i_gh);
	else if (frozen_root && atomic_dec_and_test(&sdp->sd_frozen_root))
		wake_up(&sdp->sd_frozen_root_wait);

	return error;
}

static int __gfs2_setattr_simple(struct inode *inode, struct iattr *attr)
{
	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

/**
 * gfs2_setattr_simple -
 * @ip:
 * @attr:
 *
 * Returns: errno
 */

int gfs2_setattr_simple(struct inode *inode, struct iattr *attr)
{
	int error;

	if (current->journal_info)
		return __gfs2_setattr_simple(inode, attr);

	error = gfs2_trans_begin(GFS2_SB(inode), RES_DINODE, 0);
	if (error)
		return error;

	error = __gfs2_setattr_simple(inode, attr);
	gfs2_trans_end(GFS2_SB(inode));
	return error;
}

static int setattr_chown(struct inode *inode, struct iattr *attr)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	kuid_t ouid, nuid;
	kgid_t ogid, ngid;
	int error;

	ouid = inode->i_uid;
	ogid = inode->i_gid;
	nuid = attr->ia_uid;
	ngid = attr->ia_gid;

	if (!(attr->ia_valid & ATTR_UID) || uid_eq(ouid, nuid))
		ouid = nuid = NO_UID_QUOTA_CHANGE;
	if (!(attr->ia_valid & ATTR_GID) || gid_eq(ogid, ngid))
		ogid = ngid = NO_GID_QUOTA_CHANGE;

	error = get_write_access(inode);
	if (error)
		return error;

	error = gfs2_rs_alloc(ip);
	if (error)
		goto out;

	error = gfs2_rindex_update(sdp);
	if (error)
		goto out;

	error = gfs2_quota_lock(ip, nuid, ngid);
	if (error)
		goto out;

	if (!uid_eq(ouid, NO_UID_QUOTA_CHANGE) ||
	    !gid_eq(ogid, NO_GID_QUOTA_CHANGE)) {
		error = gfs2_quota_check(ip, nuid, ngid);
		if (error)
			goto out_gunlock_q;
	}

	error = gfs2_trans_begin(sdp, RES_DINODE + 2 * RES_QUOTA, 0);
	if (error)
		goto out_gunlock_q;

	error = gfs2_setattr_simple(inode, attr);
	if (error)
		goto out_end_trans;

	if (!uid_eq(ouid, NO_UID_QUOTA_CHANGE) ||
	    !gid_eq(ogid, NO_GID_QUOTA_CHANGE)) {
		u64 blocks = gfs2_get_inode_blocks(&ip->i_inode);
		gfs2_quota_change(ip, -blocks, ouid, ogid);
		gfs2_quota_change(ip, blocks, nuid, ngid);
	}

out_end_trans:
	gfs2_trans_end(sdp);
out_gunlock_q:
	gfs2_quota_unlock(ip);
out:
	put_write_access(inode);
	return error;
}

/**
 * gfs2_setattr - Change attributes on an inode
 * @dentry: The dentry which is changing
 * @attr: The structure describing the change
 *
 * The VFS layer wants to change one or more of an inodes attributes.  Write
 * that change out to disk.
 *
 * Returns: errno
 */

static int gfs2_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder i_gh;
	int error;

	error = gfs2_rs_alloc(ip);
	if (error)
		return error;

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &i_gh);
	if (error)
		return error;

	error = -EPERM;
	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		goto out;

	error = inode_change_ok(inode, attr);
	if (error)
		goto out;

	if (attr->ia_valid & ATTR_SIZE)
		error = gfs2_setattr_size(inode, attr->ia_size);
	else if (attr->ia_valid & (ATTR_UID | ATTR_GID))
		error = setattr_chown(inode, attr);
	else {
		error = gfs2_setattr_simple(inode, attr);
		if (!error && attr->ia_valid & ATTR_MODE)
			error = posix_acl_chmod(inode, inode->i_mode);
	}

out:
	if (!error)
		mark_inode_dirty(inode);
	gfs2_glock_dq_uninit(&i_gh);
	return error;
}

/**
 * gfs2_getattr - Read out an inode's attributes
 * @mnt: The vfsmount the inode is being accessed from
 * @dentry: The dentry to stat
 * @stat: The inode's stats
 *
 * This may be called from the VFS directly, or from within GFS2 with the
 * inode locked, so we look to see if the glock is already locked and only
 * lock the glock if its not already been done. Note that its the NFS
 * readdirplus operation which causes this to be called (from filldir)
 * with the glock already held.
 *
 * Returns: errno
 */

static int gfs2_getattr(struct vfsmount *mnt, struct dentry *dentry,
			struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	int error;
	int unlock = 0;
	int frozen_root = 0;

	if (gfs2_glock_is_locked_by_me(ip->i_gl) == NULL) {
		if (unlikely(gfs2_glock_is_held_excl(sdp->sd_freeze_gl) &&
			     inode == sdp->sd_root_dir->d_inode &&
			     atomic_inc_not_zero(&sdp->sd_frozen_root)))
			frozen_root = 1;
		else {
			error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY, &gh);
			if (error)
				return error;
			unlock = 1;
		}
	}

	generic_fillattr(inode, stat);
	if (unlock)
		gfs2_glock_dq_uninit(&gh);
	else if (frozen_root && atomic_dec_and_test(&sdp->sd_frozen_root))
		wake_up(&sdp->sd_frozen_root_wait);

	return 0;
}

static int gfs2_setxattr(struct dentry *dentry, const char *name,
			 const void *data, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret == 0) {
		ret = gfs2_rs_alloc(ip);
		if (ret == 0)
			ret = generic_setxattr(dentry, name, data, size, flags);
		gfs2_glock_dq(&gh);
	}
	gfs2_holder_uninit(&gh);
	return ret;
}

static ssize_t gfs2_getxattr(struct dentry *dentry, const char *name,
			     void *data, size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	/* For selinux during lookup */
	if (gfs2_glock_is_locked_by_me(ip->i_gl))
		return generic_getxattr(dentry, name, data, size);

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret == 0) {
		ret = generic_getxattr(dentry, name, data, size);
		gfs2_glock_dq(&gh);
	}
	gfs2_holder_uninit(&gh);
	return ret;
}

static int gfs2_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret == 0) {
		ret = gfs2_rs_alloc(ip);
		if (ret == 0)
			ret = generic_removexattr(dentry, name);
		gfs2_glock_dq(&gh);
	}
	gfs2_holder_uninit(&gh);
	return ret;
}

static int gfs2_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		       u64 start, u64 len)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	mutex_lock(&inode->i_mutex);

	ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	if (ret)
		goto out;

	if (gfs2_is_stuffed(ip)) {
		u64 phys = ip->i_no_addr << inode->i_blkbits;
		u64 size = i_size_read(inode);
		u32 flags = FIEMAP_EXTENT_LAST|FIEMAP_EXTENT_NOT_ALIGNED|
			    FIEMAP_EXTENT_DATA_INLINE;
		phys += sizeof(struct gfs2_dinode);
		phys += start;
		if (start + len > size)
			len = size - start;
		if (start < size)
			ret = fiemap_fill_next_extent(fieinfo, start, phys,
						      len, flags);
		if (ret == 1)
			ret = 0;
	} else {
		ret = __generic_block_fiemap(inode, fieinfo, start, len,
					     gfs2_block_map);
	}

	gfs2_glock_dq_uninit(&gh);
out:
	mutex_unlock(&inode->i_mutex);
	return ret;
}

const struct inode_operations gfs2_file_iops = {
	.permission = gfs2_permission,
	.setattr = gfs2_setattr,
	.getattr = gfs2_getattr,
	.setxattr = gfs2_setxattr,
	.getxattr = gfs2_getxattr,
	.listxattr = gfs2_listxattr,
	.removexattr = gfs2_removexattr,
	.fiemap = gfs2_fiemap,
	.get_acl = gfs2_get_acl,
	.set_acl = gfs2_set_acl,
};

const struct inode_operations gfs2_dir_iops = {
	.create = gfs2_create,
	.lookup = gfs2_lookup,
	.link = gfs2_link,
	.unlink = gfs2_unlink,
	.symlink = gfs2_symlink,
	.mkdir = gfs2_mkdir,
	.rmdir = gfs2_unlink,
	.mknod = gfs2_mknod,
	.rename = gfs2_rename,
	.permission = gfs2_permission,
	.setattr = gfs2_setattr,
	.getattr = gfs2_getattr,
	.setxattr = gfs2_setxattr,
	.getxattr = gfs2_getxattr,
	.listxattr = gfs2_listxattr,
	.removexattr = gfs2_removexattr,
	.fiemap = gfs2_fiemap,
	.get_acl = gfs2_get_acl,
	.set_acl = gfs2_set_acl,
	.atomic_open = gfs2_atomic_open,
};

const struct inode_operations gfs2_symlink_iops = {
	.readlink = generic_readlink,
	.follow_link = gfs2_follow_link,
	.put_link = kfree_put_link,
	.permission = gfs2_permission,
	.setattr = gfs2_setattr,
	.getattr = gfs2_getattr,
	.setxattr = gfs2_setxattr,
	.getxattr = gfs2_getxattr,
	.listxattr = gfs2_listxattr,
	.removexattr = gfs2_removexattr,
	.fiemap = gfs2_fiemap,
};
/************************************************************/
/* ../linux-3.17/fs/gfs2/quota.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2007 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

/*
 * Quota change tags are associated with each transaction that allocates or
 * deallocates space.  Those changes are accumulated locally to each node (in a
 * per-node file) and then are periodically synced to the quota file.  This
 * avoids the bottleneck of constantly touching the quota file, but introduces
 * fuzziness in the current usage value of IDs that are being used on different
 * nodes in the cluster simultaneously.  So, it is possible for a user on
 * multiple nodes to overrun their quota, but that overrun is controlable.
 * Since quota tags are part of transactions, there is no need for a quota check
 * program to be run on node crashes or anything like that.
 *
 * There are couple of knobs that let the administrator manage the quota
 * fuzziness.  "quota_quantum" sets the maximum time a quota change can be
 * sitting on one node before being synced to the quota file.  (The default is
 * 60 seconds.)  Another knob, "quota_scale" controls how quickly the frequency
 * of quota file syncs increases as the user moves closer to their limit.  The
 * more frequent the syncs, the more accurate the quota enforcement, but that
 * means that there is more contention between the nodes for the quota file.
 * The default value is one.  This sets the maximum theoretical quota overrun
 * (with infinite node with infinite bandwidth) to twice the user's limit.  (In
 * practice, the maximum overrun you see should be much less.)  A "quota_scale"
 * number greater than one makes quota syncs more frequent and reduces the
 * maximum overrun.  Numbers less than one (but greater than zero) make quota
 * syncs less frequent.
 *
 * GFS quotas also use per-ID Lock Value Blocks (LVBs) to cache the contents of
 * the quota file, so it is not being constantly read.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/mm.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/sort.h>
// #include <linux/fs.h>
// #include <linux/bio.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/kthread.h>
// #include <linux/freezer.h>
#include <linux/quota.h>
#include <linux/dqblk_xfs.h>
// #include <linux/lockref.h>
#include <linux/list_lru.h>
// #include <linux/rcupdate.h>
// #include <linux/rculist_bl.h>
// #include <linux/bit_spinlock.h>
// #include <linux/jhash.h>
// #include <linux/vmalloc.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "bmap.h"
// #include "glock.h"
// #include "glops.h"
// #include "log.h"
// #include "meta_io.h"
// #include "quota.h"
// #include "rgrp.h"
// #include "super.h"
// #include "trans.h"
// #include "inode.h"
// #include "util.h"

#define GFS2_QD_HASH_SHIFT      12
#define GFS2_QD_HASH_SIZE       (1 << GFS2_QD_HASH_SHIFT)
#define GFS2_QD_HASH_MASK       (GFS2_QD_HASH_SIZE - 1)

/* Lock order: qd_lock -> bucket lock -> qd->lockref.lock -> lru lock */
/*                     -> sd_bitmap_lock                              */
static DEFINE_SPINLOCK(qd_lock);
struct list_lru gfs2_qd_lru;

static struct hlist_bl_head qd_hash_table[GFS2_QD_HASH_SIZE];

static unsigned int gfs2_qd_hash(const struct gfs2_sbd *sdp,
				 const struct kqid qid)
{
	unsigned int h;

	h = jhash(&sdp, sizeof(struct gfs2_sbd *), 0);
	h = jhash(&qid, sizeof(struct kqid), h);

	return h & GFS2_QD_HASH_MASK;
}

static inline void spin_lock_bucket(unsigned int hash)
{
        hlist_bl_lock(&qd_hash_table[hash]);
}

static inline void spin_unlock_bucket(unsigned int hash)
{
        hlist_bl_unlock(&qd_hash_table[hash]);
}

static void gfs2_qd_dealloc(struct rcu_head *rcu)
{
	struct gfs2_quota_data *qd = container_of(rcu, struct gfs2_quota_data, qd_rcu);
	kmem_cache_free(gfs2_quotad_cachep, qd);
}

static void gfs2_qd_dispose(struct list_head *list)
{
	struct gfs2_quota_data *qd;
	struct gfs2_sbd *sdp;

	while (!list_empty(list)) {
		qd = list_entry(list->next, struct gfs2_quota_data, qd_lru);
		sdp = qd->qd_gl->gl_sbd;

		list_del(&qd->qd_lru);

		/* Free from the filesystem-specific list */
		spin_lock(&qd_lock);
		list_del(&qd->qd_list);
		spin_unlock(&qd_lock);

		spin_lock_bucket(qd->qd_hash);
		hlist_bl_del_rcu(&qd->qd_hlist);
		spin_unlock_bucket(qd->qd_hash);

		gfs2_assert_warn(sdp, !qd->qd_change);
		gfs2_assert_warn(sdp, !qd->qd_slot_count);
		gfs2_assert_warn(sdp, !qd->qd_bh_count);

		gfs2_glock_put(qd->qd_gl);
		atomic_dec(&sdp->sd_quota_count);

		/* Delete it from the common reclaim list */
		call_rcu(&qd->qd_rcu, gfs2_qd_dealloc);
	}
}


static enum lru_status gfs2_qd_isolate(struct list_head *item, spinlock_t *lock, void *arg)
{
	struct list_head *dispose = arg;
	struct gfs2_quota_data *qd = list_entry(item, struct gfs2_quota_data, qd_lru);

	if (!spin_trylock(&qd->qd_lockref.lock))
		return LRU_SKIP;

	if (qd->qd_lockref.count == 0) {
		lockref_mark_dead(&qd->qd_lockref);
		list_move(&qd->qd_lru, dispose);
	}

	spin_unlock(&qd->qd_lockref.lock);
	return LRU_REMOVED;
}

static unsigned long gfs2_qd_shrink_scan(struct shrinker *shrink,
					 struct shrink_control *sc)
{
	LIST_HEAD(dispose);
	unsigned long freed;

	if (!(sc->gfp_mask & __GFP_FS))
		return SHRINK_STOP;

	freed = list_lru_walk_node(&gfs2_qd_lru, sc->nid, gfs2_qd_isolate,
				   &dispose, &sc->nr_to_scan);

	gfs2_qd_dispose(&dispose);

	return freed;
}

static unsigned long gfs2_qd_shrink_count(struct shrinker *shrink,
					  struct shrink_control *sc)
{
	return vfs_pressure_ratio(list_lru_count_node(&gfs2_qd_lru, sc->nid));
}

struct shrinker gfs2_qd_shrinker = {
	.count_objects = gfs2_qd_shrink_count,
	.scan_objects = gfs2_qd_shrink_scan,
	.seeks = DEFAULT_SEEKS,
	.flags = SHRINKER_NUMA_AWARE,
};


static u64 qd2index(struct gfs2_quota_data *qd)
{
	struct kqid qid = qd->qd_id;
	return (2 * (u64)from_kqid(&init_user_ns, qid)) +
		((qid.type == USRQUOTA) ? 0 : 1);
}

static u64 qd2offset(struct gfs2_quota_data *qd)
{
	u64 offset;

	offset = qd2index(qd);
	offset *= sizeof(struct gfs2_quota);

	return offset;
}

static struct gfs2_quota_data *qd_alloc(unsigned hash, struct gfs2_sbd *sdp, struct kqid qid)
{
	struct gfs2_quota_data *qd;
	int error;

	qd = kmem_cache_zalloc(gfs2_quotad_cachep, GFP_NOFS);
	if (!qd)
		return NULL;

	qd->qd_sbd = sdp;
	qd->qd_lockref.count = 1;
	spin_lock_init(&qd->qd_lockref.lock);
	qd->qd_id = qid;
	qd->qd_slot = -1;
	INIT_LIST_HEAD(&qd->qd_lru);
	qd->qd_hash = hash;

	error = gfs2_glock_get(sdp, qd2index(qd),
			      &gfs2_quota_glops, CREATE, &qd->qd_gl);
	if (error)
		goto fail;

	return qd;

fail:
	kmem_cache_free(gfs2_quotad_cachep, qd);
	return NULL;
}

static struct gfs2_quota_data *gfs2_qd_search_bucket(unsigned int hash,
						     const struct gfs2_sbd *sdp,
						     struct kqid qid)
{
	struct gfs2_quota_data *qd;
	struct hlist_bl_node *h;

	hlist_bl_for_each_entry_rcu(qd, h, &qd_hash_table[hash], qd_hlist) {
		if (!qid_eq(qd->qd_id, qid))
			continue;
		if (qd->qd_sbd != sdp)
			continue;
		if (lockref_get_not_dead(&qd->qd_lockref)) {
			list_lru_del(&gfs2_qd_lru, &qd->qd_lru);
			return qd;
		}
	}

	return NULL;
}


static int qd_get(struct gfs2_sbd *sdp, struct kqid qid,
		  struct gfs2_quota_data **qdp)
{
	struct gfs2_quota_data *qd, *new_qd;
	unsigned int hash = gfs2_qd_hash(sdp, qid);

	rcu_read_lock();
	*qdp = qd = gfs2_qd_search_bucket(hash, sdp, qid);
	rcu_read_unlock();

	if (qd)
		return 0;

	new_qd = qd_alloc(hash, sdp, qid);
	if (!new_qd)
		return -ENOMEM;

	spin_lock(&qd_lock);
	spin_lock_bucket(hash);
	*qdp = qd = gfs2_qd_search_bucket(hash, sdp, qid);
	if (qd == NULL) {
		*qdp = new_qd;
		list_add(&new_qd->qd_list, &sdp->sd_quota_list);
		hlist_bl_add_head_rcu(&new_qd->qd_hlist, &qd_hash_table[hash]);
		atomic_inc(&sdp->sd_quota_count);
	}
	spin_unlock_bucket(hash);
	spin_unlock(&qd_lock);

	if (qd) {
		gfs2_glock_put(new_qd->qd_gl);
		kmem_cache_free(gfs2_quotad_cachep, new_qd);
	}

	return 0;
}


static void qd_hold(struct gfs2_quota_data *qd)
{
	struct gfs2_sbd *sdp = qd->qd_gl->gl_sbd;
	gfs2_assert(sdp, !__lockref_is_dead(&qd->qd_lockref));
	lockref_get(&qd->qd_lockref);
}

static void qd_put(struct gfs2_quota_data *qd)
{
	if (lockref_put_or_lock(&qd->qd_lockref))
		return;

	qd->qd_lockref.count = 0;
	list_lru_add(&gfs2_qd_lru, &qd->qd_lru);
	spin_unlock(&qd->qd_lockref.lock);

}

static int slot_get(struct gfs2_quota_data *qd)
{
	struct gfs2_sbd *sdp = qd->qd_sbd;
	unsigned int bit;
	int error = 0;

	spin_lock(&sdp->sd_bitmap_lock);
	if (qd->qd_slot_count != 0)
		goto out;

	error = -ENOSPC;
	bit = find_first_zero_bit(sdp->sd_quota_bitmap, sdp->sd_quota_slots);
	if (bit < sdp->sd_quota_slots) {
		set_bit(bit, sdp->sd_quota_bitmap);
		qd->qd_slot = bit;
		error = 0;
out:
		qd->qd_slot_count++;
	}
	spin_unlock(&sdp->sd_bitmap_lock);

	return error;
}

static void slot_hold(struct gfs2_quota_data *qd)
{
	struct gfs2_sbd *sdp = qd->qd_sbd;

	spin_lock(&sdp->sd_bitmap_lock);
	gfs2_assert(sdp, qd->qd_slot_count);
	qd->qd_slot_count++;
	spin_unlock(&sdp->sd_bitmap_lock);
}

static void slot_put(struct gfs2_quota_data *qd)
{
	struct gfs2_sbd *sdp = qd->qd_sbd;

	spin_lock(&sdp->sd_bitmap_lock);
	gfs2_assert(sdp, qd->qd_slot_count);
	if (!--qd->qd_slot_count) {
		BUG_ON(!test_and_clear_bit(qd->qd_slot, sdp->sd_quota_bitmap));
		qd->qd_slot = -1;
	}
	spin_unlock(&sdp->sd_bitmap_lock);
}

static int bh_get(struct gfs2_quota_data *qd)
{
	struct gfs2_sbd *sdp = qd->qd_gl->gl_sbd;
	struct gfs2_inode *ip = GFS2_I(sdp->sd_qc_inode);
	unsigned int block, offset;
	struct buffer_head *bh;
	int error;
	struct buffer_head bh_map = { .b_state = 0, .b_blocknr = 0 };

	mutex_lock(&sdp->sd_quota_mutex);

	if (qd->qd_bh_count++) {
		mutex_unlock(&sdp->sd_quota_mutex);
		return 0;
	}

	block = qd->qd_slot / sdp->sd_qc_per_block;
	offset = qd->qd_slot % sdp->sd_qc_per_block;

	bh_map.b_size = 1 << ip->i_inode.i_blkbits;
	error = gfs2_block_map(&ip->i_inode, block, &bh_map, 0);
	if (error)
		goto fail;
	error = gfs2_meta_read(ip->i_gl, bh_map.b_blocknr, DIO_WAIT, &bh);
	if (error)
		goto fail;
	error = -EIO;
	if (gfs2_metatype_check(sdp, bh, GFS2_METATYPE_QC))
		goto fail_brelse;

	qd->qd_bh = bh;
	qd->qd_bh_qc = (struct gfs2_quota_change *)
		(bh->b_data + sizeof(struct gfs2_meta_header) +
		 offset * sizeof(struct gfs2_quota_change));

	mutex_unlock(&sdp->sd_quota_mutex);

	return 0;

fail_brelse:
	brelse(bh);
fail:
	qd->qd_bh_count--;
	mutex_unlock(&sdp->sd_quota_mutex);
	return error;
}

static void bh_put(struct gfs2_quota_data *qd)
{
	struct gfs2_sbd *sdp = qd->qd_gl->gl_sbd;

	mutex_lock(&sdp->sd_quota_mutex);
	gfs2_assert(sdp, qd->qd_bh_count);
	if (!--qd->qd_bh_count) {
		brelse(qd->qd_bh);
		qd->qd_bh = NULL;
		qd->qd_bh_qc = NULL;
	}
	mutex_unlock(&sdp->sd_quota_mutex);
}

static int qd_check_sync(struct gfs2_sbd *sdp, struct gfs2_quota_data *qd,
			 u64 *sync_gen)
{
	if (test_bit(QDF_LOCKED, &qd->qd_flags) ||
	    !test_bit(QDF_CHANGE, &qd->qd_flags) ||
	    (sync_gen && (qd->qd_sync_gen >= *sync_gen)))
		return 0;

	if (!lockref_get_not_dead(&qd->qd_lockref))
		return 0;

	list_move_tail(&qd->qd_list, &sdp->sd_quota_list);
	set_bit(QDF_LOCKED, &qd->qd_flags);
	qd->qd_change_sync = qd->qd_change;
	slot_hold(qd);
	return 1;
}

static int qd_fish(struct gfs2_sbd *sdp, struct gfs2_quota_data **qdp)
{
	struct gfs2_quota_data *qd = NULL;
	int error;
	int found = 0;

	*qdp = NULL;

	if (sdp->sd_vfs->s_flags & MS_RDONLY)
		return 0;

	spin_lock(&qd_lock);

	list_for_each_entry(qd, &sdp->sd_quota_list, qd_list) {
		found = qd_check_sync(sdp, qd, &sdp->sd_quota_sync_gen);
		if (found)
			break;
	}

	if (!found)
		qd = NULL;

	spin_unlock(&qd_lock);

	if (qd) {
		gfs2_assert_warn(sdp, qd->qd_change_sync);
		error = bh_get(qd);
		if (error) {
			clear_bit(QDF_LOCKED, &qd->qd_flags);
			slot_put(qd);
			qd_put(qd);
			return error;
		}
	}

	*qdp = qd;

	return 0;
}

static void qd_unlock(struct gfs2_quota_data *qd)
{
	gfs2_assert_warn(qd->qd_gl->gl_sbd,
			 test_bit(QDF_LOCKED, &qd->qd_flags));
	clear_bit(QDF_LOCKED, &qd->qd_flags);
	bh_put(qd);
	slot_put(qd);
	qd_put(qd);
}

static int qdsb_get(struct gfs2_sbd *sdp, struct kqid qid,
		    struct gfs2_quota_data **qdp)
{
	int error;

	error = qd_get(sdp, qid, qdp);
	if (error)
		return error;

	error = slot_get(*qdp);
	if (error)
		goto fail;

	error = bh_get(*qdp);
	if (error)
		goto fail_slot;

	return 0;

fail_slot:
	slot_put(*qdp);
fail:
	qd_put(*qdp);
	return error;
}

static void qdsb_put(struct gfs2_quota_data *qd)
{
	bh_put(qd);
	slot_put(qd);
	qd_put(qd);
}

int gfs2_quota_hold(struct gfs2_inode *ip, kuid_t uid, kgid_t gid)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_quota_data **qd;
	int error;

	if (ip->i_res == NULL) {
		error = gfs2_rs_alloc(ip);
		if (error)
			return error;
	}

	qd = ip->i_res->rs_qa_qd;

	if (gfs2_assert_warn(sdp, !ip->i_res->rs_qa_qd_num) ||
	    gfs2_assert_warn(sdp, !test_bit(GIF_QD_LOCKED, &ip->i_flags)))
		return -EIO;

	if (sdp->sd_args.ar_quota == GFS2_QUOTA_OFF)
		return 0;

	error = qdsb_get(sdp, make_kqid_uid(ip->i_inode.i_uid), qd);
	if (error)
		goto out;
	ip->i_res->rs_qa_qd_num++;
	qd++;

	error = qdsb_get(sdp, make_kqid_gid(ip->i_inode.i_gid), qd);
	if (error)
		goto out;
	ip->i_res->rs_qa_qd_num++;
	qd++;

	if (!uid_eq(uid, NO_UID_QUOTA_CHANGE) &&
	    !uid_eq(uid, ip->i_inode.i_uid)) {
		error = qdsb_get(sdp, make_kqid_uid(uid), qd);
		if (error)
			goto out;
		ip->i_res->rs_qa_qd_num++;
		qd++;
	}

	if (!gid_eq(gid, NO_GID_QUOTA_CHANGE) &&
	    !gid_eq(gid, ip->i_inode.i_gid)) {
		error = qdsb_get(sdp, make_kqid_gid(gid), qd);
		if (error)
			goto out;
		ip->i_res->rs_qa_qd_num++;
		qd++;
	}

out:
	if (error)
		gfs2_quota_unhold(ip);
	return error;
}

void gfs2_quota_unhold(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	unsigned int x;

	if (ip->i_res == NULL)
		return;
	gfs2_assert_warn(sdp, !test_bit(GIF_QD_LOCKED, &ip->i_flags));

	for (x = 0; x < ip->i_res->rs_qa_qd_num; x++) {
		qdsb_put(ip->i_res->rs_qa_qd[x]);
		ip->i_res->rs_qa_qd[x] = NULL;
	}
	ip->i_res->rs_qa_qd_num = 0;
}

static int sort_qd(const void *a, const void *b)
{
	const struct gfs2_quota_data *qd_a = *(const struct gfs2_quota_data **)a;
	const struct gfs2_quota_data *qd_b = *(const struct gfs2_quota_data **)b;

	if (qid_lt(qd_a->qd_id, qd_b->qd_id))
		return -1;
	if (qid_lt(qd_b->qd_id, qd_a->qd_id))
		return 1;
	return 0;
}

static void do_qc(struct gfs2_quota_data *qd, s64 change)
{
	struct gfs2_sbd *sdp = qd->qd_gl->gl_sbd;
	struct gfs2_inode *ip = GFS2_I(sdp->sd_qc_inode);
	struct gfs2_quota_change *qc = qd->qd_bh_qc;
	s64 x;

	mutex_lock(&sdp->sd_quota_mutex);
	gfs2_trans_add_meta(ip->i_gl, qd->qd_bh);

	if (!test_bit(QDF_CHANGE, &qd->qd_flags)) {
		qc->qc_change = 0;
		qc->qc_flags = 0;
		if (qd->qd_id.type == USRQUOTA)
			qc->qc_flags = cpu_to_be32(GFS2_QCF_USER);
		qc->qc_id = cpu_to_be32(from_kqid(&init_user_ns, qd->qd_id));
	}

	x = be64_to_cpu(qc->qc_change) + change;
	qc->qc_change = cpu_to_be64(x);

	spin_lock(&qd_lock);
	qd->qd_change = x;
	spin_unlock(&qd_lock);

	if (!x) {
		gfs2_assert_warn(sdp, test_bit(QDF_CHANGE, &qd->qd_flags));
		clear_bit(QDF_CHANGE, &qd->qd_flags);
		qc->qc_flags = 0;
		qc->qc_id = 0;
		slot_put(qd);
		qd_put(qd);
	} else if (!test_and_set_bit(QDF_CHANGE, &qd->qd_flags)) {
		qd_hold(qd);
		slot_hold(qd);
	}

	mutex_unlock(&sdp->sd_quota_mutex);
}

/**
 * gfs2_adjust_quota - adjust record of current block usage
 * @ip: The quota inode
 * @loc: Offset of the entry in the quota file
 * @change: The amount of usage change to record
 * @qd: The quota data
 * @fdq: The updated limits to record
 *
 * This function was mostly borrowed from gfs2_block_truncate_page which was
 * in turn mostly borrowed from ext3
 *
 * Returns: 0 or -ve on error
 */

static int gfs2_adjust_quota(struct gfs2_inode *ip, loff_t loc,
			     s64 change, struct gfs2_quota_data *qd,
			     struct fs_disk_quota *fdq)
{
	struct inode *inode = &ip->i_inode;
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct address_space *mapping = inode->i_mapping;
	unsigned long index = loc >> PAGE_CACHE_SHIFT;
	unsigned offset = loc & (PAGE_CACHE_SIZE - 1);
	unsigned blocksize, iblock, pos;
	struct buffer_head *bh;
	struct page *page;
	void *kaddr, *ptr;
	struct gfs2_quota q;
	int err, nbytes;
	u64 size;

	if (gfs2_is_stuffed(ip)) {
		err = gfs2_unstuff_dinode(ip, NULL);
		if (err)
			return err;
	}

	memset(&q, 0, sizeof(struct gfs2_quota));
	err = gfs2_internal_read(ip, (char *)&q, &loc, sizeof(q));
	if (err < 0)
		return err;

	err = -EIO;
	be64_add_cpu(&q.qu_value, change);
	qd->qd_qb.qb_value = q.qu_value;
	if (fdq) {
		if (fdq->d_fieldmask & FS_DQ_BSOFT) {
			q.qu_warn = cpu_to_be64(fdq->d_blk_softlimit >> sdp->sd_fsb2bb_shift);
			qd->qd_qb.qb_warn = q.qu_warn;
		}
		if (fdq->d_fieldmask & FS_DQ_BHARD) {
			q.qu_limit = cpu_to_be64(fdq->d_blk_hardlimit >> sdp->sd_fsb2bb_shift);
			qd->qd_qb.qb_limit = q.qu_limit;
		}
		if (fdq->d_fieldmask & FS_DQ_BCOUNT) {
			q.qu_value = cpu_to_be64(fdq->d_bcount >> sdp->sd_fsb2bb_shift);
			qd->qd_qb.qb_value = q.qu_value;
		}
	}

	/* Write the quota into the quota file on disk */
	ptr = &q;
	nbytes = sizeof(struct gfs2_quota);
get_a_page:
	page = find_or_create_page(mapping, index, GFP_NOFS);
	if (!page)
		return -ENOMEM;

	blocksize = inode->i_sb->s_blocksize;
	iblock = index << (PAGE_CACHE_SHIFT - inode->i_sb->s_blocksize_bits);

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	bh = page_buffers(page);
	pos = blocksize;
	while (offset >= pos) {
		bh = bh->b_this_page;
		iblock++;
		pos += blocksize;
	}

	if (!buffer_mapped(bh)) {
		gfs2_block_map(inode, iblock, bh, 1);
		if (!buffer_mapped(bh))
			goto unlock_out;
		/* If it's a newly allocated disk block for quota, zero it */
		if (buffer_new(bh))
			zero_user(page, pos - blocksize, bh->b_size);
	}

	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!buffer_uptodate(bh)) {
		ll_rw_block(READ | REQ_META, 1, &bh);
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh))
			goto unlock_out;
	}

	gfs2_trans_add_data(ip->i_gl, bh);

	kaddr = kmap_atomic(page);
	if (offset + sizeof(struct gfs2_quota) > PAGE_CACHE_SIZE)
		nbytes = PAGE_CACHE_SIZE - offset;
	memcpy(kaddr + offset, ptr, nbytes);
	flush_dcache_page(page);
	kunmap_atomic(kaddr);
	unlock_page(page);
	page_cache_release(page);

	/* If quota straddles page boundary, we need to update the rest of the
	 * quota at the beginning of the next page */
	if ((offset + sizeof(struct gfs2_quota)) > PAGE_CACHE_SIZE) {
		ptr = ptr + nbytes;
		nbytes = sizeof(struct gfs2_quota) - nbytes;
		offset = 0;
		index++;
		goto get_a_page;
	}

	size = loc + sizeof(struct gfs2_quota);
	if (size > inode->i_size)
		i_size_write(inode, size);
	inode->i_mtime = inode->i_atime = CURRENT_TIME;
	mark_inode_dirty(inode);
	set_bit(QDF_REFRESH, &qd->qd_flags);
	return 0;

unlock_out:
	unlock_page(page);
	page_cache_release(page);
	return err;
}

static int do_sync(unsigned int num_qd, struct gfs2_quota_data **qda)
{
	struct gfs2_sbd *sdp = (*qda)->qd_gl->gl_sbd;
	struct gfs2_inode *ip = GFS2_I(sdp->sd_quota_inode);
	struct gfs2_alloc_parms ap = { .aflags = 0, };
	unsigned int data_blocks, ind_blocks;
	struct gfs2_holder *ghs, i_gh;
	unsigned int qx, x;
	struct gfs2_quota_data *qd;
	unsigned reserved;
	loff_t offset;
	unsigned int nalloc = 0, blocks;
	int error;

	error = gfs2_rs_alloc(ip);
	if (error)
		return error;

	gfs2_write_calc_reserv(ip, sizeof(struct gfs2_quota),
			      &data_blocks, &ind_blocks);

	ghs = kcalloc(num_qd, sizeof(struct gfs2_holder), GFP_NOFS);
	if (!ghs)
		return -ENOMEM;

	sort(qda, num_qd, sizeof(struct gfs2_quota_data *), sort_qd, NULL);
	mutex_lock(&ip->i_inode.i_mutex);
	for (qx = 0; qx < num_qd; qx++) {
		error = gfs2_glock_nq_init(qda[qx]->qd_gl, LM_ST_EXCLUSIVE,
					   GL_NOCACHE, &ghs[qx]);
		if (error)
			goto out;
	}

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &i_gh);
	if (error)
		goto out;

	for (x = 0; x < num_qd; x++) {
		offset = qd2offset(qda[x]);
		if (gfs2_write_alloc_required(ip, offset,
					      sizeof(struct gfs2_quota)))
			nalloc++;
	}

	/*
	 * 1 blk for unstuffing inode if stuffed. We add this extra
	 * block to the reservation unconditionally. If the inode
	 * doesn't need unstuffing, the block will be released to the
	 * rgrp since it won't be allocated during the transaction
	 */
	/* +3 in the end for unstuffing block, inode size update block
	 * and another block in case quota straddles page boundary and
	 * two blocks need to be updated instead of 1 */
	blocks = num_qd * data_blocks + RES_DINODE + num_qd + 3;

	reserved = 1 + (nalloc * (data_blocks + ind_blocks));
	ap.target = reserved;
	error = gfs2_inplace_reserve(ip, &ap);
	if (error)
		goto out_alloc;

	if (nalloc)
		blocks += gfs2_rg_blocks(ip, reserved) + nalloc * ind_blocks + RES_STATFS;

	error = gfs2_trans_begin(sdp, blocks, 0);
	if (error)
		goto out_ipres;

	for (x = 0; x < num_qd; x++) {
		qd = qda[x];
		offset = qd2offset(qd);
		error = gfs2_adjust_quota(ip, offset, qd->qd_change_sync, qd, NULL);
		if (error)
			goto out_end_trans;

		do_qc(qd, -qd->qd_change_sync);
		set_bit(QDF_REFRESH, &qd->qd_flags);
	}

	error = 0;

out_end_trans:
	gfs2_trans_end(sdp);
out_ipres:
	gfs2_inplace_release(ip);
out_alloc:
	gfs2_glock_dq_uninit(&i_gh);
out:
	while (qx--)
		gfs2_glock_dq_uninit(&ghs[qx]);
	mutex_unlock(&ip->i_inode.i_mutex);
	kfree(ghs);
	gfs2_log_flush(ip->i_gl->gl_sbd, ip->i_gl, NORMAL_FLUSH);
	return error;
}

static int update_qd(struct gfs2_sbd *sdp, struct gfs2_quota_data *qd)
{
	struct gfs2_inode *ip = GFS2_I(sdp->sd_quota_inode);
	struct gfs2_quota q;
	struct gfs2_quota_lvb *qlvb;
	loff_t pos;
	int error;

	memset(&q, 0, sizeof(struct gfs2_quota));
	pos = qd2offset(qd);
	error = gfs2_internal_read(ip, (char *)&q, &pos, sizeof(q));
	if (error < 0)
		return error;

	qlvb = (struct gfs2_quota_lvb *)qd->qd_gl->gl_lksb.sb_lvbptr;
	qlvb->qb_magic = cpu_to_be32(GFS2_MAGIC);
	qlvb->__pad = 0;
	qlvb->qb_limit = q.qu_limit;
	qlvb->qb_warn = q.qu_warn;
	qlvb->qb_value = q.qu_value;
	qd->qd_qb = *qlvb;

	return 0;
}

static int do_glock(struct gfs2_quota_data *qd, int force_refresh,
		    struct gfs2_holder *q_gh)
{
	struct gfs2_sbd *sdp = qd->qd_gl->gl_sbd;
	struct gfs2_inode *ip = GFS2_I(sdp->sd_quota_inode);
	struct gfs2_holder i_gh;
	int error;

restart:
	error = gfs2_glock_nq_init(qd->qd_gl, LM_ST_SHARED, 0, q_gh);
	if (error)
		return error;

	qd->qd_qb = *(struct gfs2_quota_lvb *)qd->qd_gl->gl_lksb.sb_lvbptr;

	if (force_refresh || qd->qd_qb.qb_magic != cpu_to_be32(GFS2_MAGIC)) {
		gfs2_glock_dq_uninit(q_gh);
		error = gfs2_glock_nq_init(qd->qd_gl, LM_ST_EXCLUSIVE,
					   GL_NOCACHE, q_gh);
		if (error)
			return error;

		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &i_gh);
		if (error)
			goto fail;

		error = update_qd(sdp, qd);
		if (error)
			goto fail_gunlock;

		gfs2_glock_dq_uninit(&i_gh);
		gfs2_glock_dq_uninit(q_gh);
		force_refresh = 0;
		goto restart;
	}

	return 0;

fail_gunlock:
	gfs2_glock_dq_uninit(&i_gh);
fail:
	gfs2_glock_dq_uninit(q_gh);
	return error;
}

int gfs2_quota_lock(struct gfs2_inode *ip, kuid_t uid, kgid_t gid)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_quota_data *qd;
	unsigned int x;
	int error = 0;

	error = gfs2_quota_hold(ip, uid, gid);
	if (error)
		return error;

	if (capable(CAP_SYS_RESOURCE) ||
	    sdp->sd_args.ar_quota != GFS2_QUOTA_ON)
		return 0;

	sort(ip->i_res->rs_qa_qd, ip->i_res->rs_qa_qd_num,
	     sizeof(struct gfs2_quota_data *), sort_qd, NULL);

	for (x = 0; x < ip->i_res->rs_qa_qd_num; x++) {
		int force = NO_FORCE;
		qd = ip->i_res->rs_qa_qd[x];
		if (test_and_clear_bit(QDF_REFRESH, &qd->qd_flags))
			force = FORCE;
		error = do_glock(qd, force, &ip->i_res->rs_qa_qd_ghs[x]);
		if (error)
			break;
	}

	if (!error)
		set_bit(GIF_QD_LOCKED, &ip->i_flags);
	else {
		while (x--)
			gfs2_glock_dq_uninit(&ip->i_res->rs_qa_qd_ghs[x]);
		gfs2_quota_unhold(ip);
	}

	return error;
}

static int need_sync(struct gfs2_quota_data *qd)
{
	struct gfs2_sbd *sdp = qd->qd_gl->gl_sbd;
	struct gfs2_tune *gt = &sdp->sd_tune;
	s64 value;
	unsigned int num, den;
	int do_sync = 1;

	if (!qd->qd_qb.qb_limit)
		return 0;

	spin_lock(&qd_lock);
	value = qd->qd_change;
	spin_unlock(&qd_lock);

	spin_lock(&gt->gt_spin);
	num = gt->gt_quota_scale_num;
	den = gt->gt_quota_scale_den;
	spin_unlock(&gt->gt_spin);

	if (value < 0)
		do_sync = 0;
	else if ((s64)be64_to_cpu(qd->qd_qb.qb_value) >=
		 (s64)be64_to_cpu(qd->qd_qb.qb_limit))
		do_sync = 0;
	else {
		value *= gfs2_jindex_size(sdp) * num;
		value = div_s64(value, den);
		value += (s64)be64_to_cpu(qd->qd_qb.qb_value);
		if (value < (s64)be64_to_cpu(qd->qd_qb.qb_limit))
			do_sync = 0;
	}

	return do_sync;
}

void gfs2_quota_unlock(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_quota_data *qda[4];
	unsigned int count = 0;
	unsigned int x;
	int found;

	if (!test_and_clear_bit(GIF_QD_LOCKED, &ip->i_flags))
		goto out;

	for (x = 0; x < ip->i_res->rs_qa_qd_num; x++) {
		struct gfs2_quota_data *qd;
		int sync;

		qd = ip->i_res->rs_qa_qd[x];
		sync = need_sync(qd);

		gfs2_glock_dq_uninit(&ip->i_res->rs_qa_qd_ghs[x]);
		if (!sync)
			continue;

		spin_lock(&qd_lock);
		found = qd_check_sync(sdp, qd, NULL);
		spin_unlock(&qd_lock);

		if (!found)
			continue;

		gfs2_assert_warn(sdp, qd->qd_change_sync);
		if (bh_get(qd)) {
			clear_bit(QDF_LOCKED, &qd->qd_flags);
			slot_put(qd);
			qd_put(qd);
			continue;
		}

		qda[count++] = qd;
	}

	if (count) {
		do_sync(count, qda);
		for (x = 0; x < count; x++)
			qd_unlock(qda[x]);
	}

out:
	gfs2_quota_unhold(ip);
}

#define MAX_LINE 256

static int print_message(struct gfs2_quota_data *qd, char *type)
{
	struct gfs2_sbd *sdp = qd->qd_gl->gl_sbd;

	fs_info(sdp, "quota %s for %s %u\n",
		type,
		(qd->qd_id.type == USRQUOTA) ? "user" : "group",
		from_kqid(&init_user_ns, qd->qd_id));

	return 0;
}

int gfs2_quota_check(struct gfs2_inode *ip, kuid_t uid, kgid_t gid)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_quota_data *qd;
	s64 value;
	unsigned int x;
	int error = 0;

	if (!test_bit(GIF_QD_LOCKED, &ip->i_flags))
		return 0;

        if (sdp->sd_args.ar_quota != GFS2_QUOTA_ON)
                return 0;

	for (x = 0; x < ip->i_res->rs_qa_qd_num; x++) {
		qd = ip->i_res->rs_qa_qd[x];

		if (!(qid_eq(qd->qd_id, make_kqid_uid(uid)) ||
		      qid_eq(qd->qd_id, make_kqid_gid(gid))))
			continue;

		value = (s64)be64_to_cpu(qd->qd_qb.qb_value);
		spin_lock(&qd_lock);
		value += qd->qd_change;
		spin_unlock(&qd_lock);

		if (be64_to_cpu(qd->qd_qb.qb_limit) && (s64)be64_to_cpu(qd->qd_qb.qb_limit) < value) {
			print_message(qd, "exceeded");
			quota_send_warning(qd->qd_id,
					   sdp->sd_vfs->s_dev, QUOTA_NL_BHARDWARN);

			error = -EDQUOT;
			break;
		} else if (be64_to_cpu(qd->qd_qb.qb_warn) &&
			   (s64)be64_to_cpu(qd->qd_qb.qb_warn) < value &&
			   time_after_eq(jiffies, qd->qd_last_warn +
					 gfs2_tune_get(sdp,
						gt_quota_warn_period) * HZ)) {
			quota_send_warning(qd->qd_id,
					   sdp->sd_vfs->s_dev, QUOTA_NL_BSOFTWARN);
			error = print_message(qd, "warning");
			qd->qd_last_warn = jiffies;
		}
	}

	return error;
}

void gfs2_quota_change(struct gfs2_inode *ip, s64 change,
		       kuid_t uid, kgid_t gid)
{
	struct gfs2_quota_data *qd;
	unsigned int x;

	if (gfs2_assert_warn(GFS2_SB(&ip->i_inode), change))
		return;
	if (ip->i_diskflags & GFS2_DIF_SYSTEM)
		return;

	for (x = 0; x < ip->i_res->rs_qa_qd_num; x++) {
		qd = ip->i_res->rs_qa_qd[x];

		if (qid_eq(qd->qd_id, make_kqid_uid(uid)) ||
		    qid_eq(qd->qd_id, make_kqid_gid(gid))) {
			do_qc(qd, change);
		}
	}
}

int gfs2_quota_sync(struct super_block *sb, int type)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct gfs2_quota_data **qda;
	unsigned int max_qd = PAGE_SIZE/sizeof(struct gfs2_holder);
	unsigned int num_qd;
	unsigned int x;
	int error = 0;

	qda = kcalloc(max_qd, sizeof(struct gfs2_quota_data *), GFP_KERNEL);
	if (!qda)
		return -ENOMEM;

	mutex_lock(&sdp->sd_quota_sync_mutex);
	sdp->sd_quota_sync_gen++;

	do {
		num_qd = 0;

		for (;;) {
			error = qd_fish(sdp, qda + num_qd);
			if (error || !qda[num_qd])
				break;
			if (++num_qd == max_qd)
				break;
		}

		if (num_qd) {
			if (!error)
				error = do_sync(num_qd, qda);
			if (!error)
				for (x = 0; x < num_qd; x++)
					qda[x]->qd_sync_gen =
						sdp->sd_quota_sync_gen;

			for (x = 0; x < num_qd; x++)
				qd_unlock(qda[x]);
		}
	} while (!error && num_qd == max_qd);

	mutex_unlock(&sdp->sd_quota_sync_mutex);
	kfree(qda);

	return error;
}

int gfs2_quota_refresh(struct gfs2_sbd *sdp, struct kqid qid)
{
	struct gfs2_quota_data *qd;
	struct gfs2_holder q_gh;
	int error;

	error = qd_get(sdp, qid, &qd);
	if (error)
		return error;

	error = do_glock(qd, FORCE, &q_gh);
	if (!error)
		gfs2_glock_dq_uninit(&q_gh);

	qd_put(qd);
	return error;
}

int gfs2_quota_init(struct gfs2_sbd *sdp)
{
	struct gfs2_inode *ip = GFS2_I(sdp->sd_qc_inode);
	u64 size = i_size_read(sdp->sd_qc_inode);
	unsigned int blocks = size >> sdp->sd_sb.sb_bsize_shift;
	unsigned int x, slot = 0;
	unsigned int found = 0;
	unsigned int hash;
	unsigned int bm_size;
	u64 dblock;
	u32 extlen = 0;
	int error;

	if (gfs2_check_internal_file_size(sdp->sd_qc_inode, 1, 64 << 20))
		return -EIO;

	sdp->sd_quota_slots = blocks * sdp->sd_qc_per_block;
	bm_size = DIV_ROUND_UP(sdp->sd_quota_slots, 8 * sizeof(unsigned long));
	bm_size *= sizeof(unsigned long);
	error = -ENOMEM;
	sdp->sd_quota_bitmap = kzalloc(bm_size, GFP_NOFS | __GFP_NOWARN);
	if (sdp->sd_quota_bitmap == NULL)
		sdp->sd_quota_bitmap = __vmalloc(bm_size, GFP_NOFS |
						 __GFP_ZERO, PAGE_KERNEL);
	if (!sdp->sd_quota_bitmap)
		return error;

	for (x = 0; x < blocks; x++) {
		struct buffer_head *bh;
		const struct gfs2_quota_change *qc;
		unsigned int y;

		if (!extlen) {
			int new = 0;
			error = gfs2_extent_map(&ip->i_inode, x, &new, &dblock, &extlen);
			if (error)
				goto fail;
		}
		error = -EIO;
		bh = gfs2_meta_ra(ip->i_gl, dblock, extlen);
		if (!bh)
			goto fail;
		if (gfs2_metatype_check(sdp, bh, GFS2_METATYPE_QC)) {
			brelse(bh);
			goto fail;
		}

		qc = (const struct gfs2_quota_change *)(bh->b_data + sizeof(struct gfs2_meta_header));
		for (y = 0; y < sdp->sd_qc_per_block && slot < sdp->sd_quota_slots;
		     y++, slot++) {
			struct gfs2_quota_data *qd;
			s64 qc_change = be64_to_cpu(qc->qc_change);
			u32 qc_flags = be32_to_cpu(qc->qc_flags);
			enum quota_type qtype = (qc_flags & GFS2_QCF_USER) ?
						USRQUOTA : GRPQUOTA;
			struct kqid qc_id = make_kqid(&init_user_ns, qtype,
						      be32_to_cpu(qc->qc_id));
			qc++;
			if (!qc_change)
				continue;

			hash = gfs2_qd_hash(sdp, qc_id);
			qd = qd_alloc(hash, sdp, qc_id);
			if (qd == NULL) {
				brelse(bh);
				goto fail;
			}

			set_bit(QDF_CHANGE, &qd->qd_flags);
			qd->qd_change = qc_change;
			qd->qd_slot = slot;
			qd->qd_slot_count = 1;

			spin_lock(&qd_lock);
			BUG_ON(test_and_set_bit(slot, sdp->sd_quota_bitmap));
			list_add(&qd->qd_list, &sdp->sd_quota_list);
			atomic_inc(&sdp->sd_quota_count);
			spin_unlock(&qd_lock);

			spin_lock_bucket(hash);
			hlist_bl_add_head_rcu(&qd->qd_hlist, &qd_hash_table[hash]);
			spin_unlock_bucket(hash);

			found++;
		}

		brelse(bh);
		dblock++;
		extlen--;
	}

	if (found)
		fs_info(sdp, "found %u quota changes\n", found);

	return 0;

fail:
	gfs2_quota_cleanup(sdp);
	return error;
}

void gfs2_quota_cleanup(struct gfs2_sbd *sdp)
{
	struct list_head *head = &sdp->sd_quota_list;
	struct gfs2_quota_data *qd;

	spin_lock(&qd_lock);
	while (!list_empty(head)) {
		qd = list_entry(head->prev, struct gfs2_quota_data, qd_list);

		list_del(&qd->qd_list);

		/* Also remove if this qd exists in the reclaim list */
		list_lru_del(&gfs2_qd_lru, &qd->qd_lru);
		atomic_dec(&sdp->sd_quota_count);
		spin_unlock(&qd_lock);

		spin_lock_bucket(qd->qd_hash);
		hlist_bl_del_rcu(&qd->qd_hlist);
		spin_unlock_bucket(qd->qd_hash);

		gfs2_assert_warn(sdp, !qd->qd_change);
		gfs2_assert_warn(sdp, !qd->qd_slot_count);
		gfs2_assert_warn(sdp, !qd->qd_bh_count);

		gfs2_glock_put(qd->qd_gl);
		call_rcu(&qd->qd_rcu, gfs2_qd_dealloc);

		spin_lock(&qd_lock);
	}
	spin_unlock(&qd_lock);

	gfs2_assert_warn(sdp, !atomic_read(&sdp->sd_quota_count));

	if (sdp->sd_quota_bitmap) {
		if (is_vmalloc_addr(sdp->sd_quota_bitmap))
			vfree(sdp->sd_quota_bitmap);
		else
			kfree(sdp->sd_quota_bitmap);
		sdp->sd_quota_bitmap = NULL;
	}
}

static void quotad_error(struct gfs2_sbd *sdp, const char *msg, int error)
{
	if (error == 0 || error == -EROFS)
		return;
	if (!test_bit(SDF_SHUTDOWN, &sdp->sd_flags))
		fs_err(sdp, "gfs2_quotad: %s error %d\n", msg, error);
}

static void quotad_check_timeo(struct gfs2_sbd *sdp, const char *msg,
			       int (*fxn)(struct super_block *sb, int type),
			       unsigned long t, unsigned long *timeo,
			       unsigned int *new_timeo)
{
	if (t >= *timeo) {
		int error = fxn(sdp->sd_vfs, 0);
		quotad_error(sdp, msg, error);
		*timeo = gfs2_tune_get_i(&sdp->sd_tune, new_timeo) * HZ;
	} else {
		*timeo -= t;
	}
}

static void quotad_check_trunc_list(struct gfs2_sbd *sdp)
{
	struct gfs2_inode *ip;

	while(1) {
		ip = NULL;
		spin_lock(&sdp->sd_trunc_lock);
		if (!list_empty(&sdp->sd_trunc_list)) {
			ip = list_entry(sdp->sd_trunc_list.next,
					struct gfs2_inode, i_trunc_list);
			list_del_init(&ip->i_trunc_list);
		}
		spin_unlock(&sdp->sd_trunc_lock);
		if (ip == NULL)
			return;
		gfs2_glock_finish_truncate(ip);
	}
}

void gfs2_wake_up_statfs(struct gfs2_sbd *sdp) {
	if (!sdp->sd_statfs_force_sync) {
		sdp->sd_statfs_force_sync = 1;
		wake_up(&sdp->sd_quota_wait);
	}
}


/**
 * gfs2_quotad - Write cached quota changes into the quota file
 * @sdp: Pointer to GFS2 superblock
 *
 */

int gfs2_quotad(void *data)
{
	struct gfs2_sbd *sdp = data;
	struct gfs2_tune *tune = &sdp->sd_tune;
	unsigned long statfs_timeo = 0;
	unsigned long quotad_timeo = 0;
	unsigned long t = 0;
	DEFINE_WAIT(wait);
	int empty;

	while (!kthread_should_stop()) {

		/* Update the master statfs file */
		if (sdp->sd_statfs_force_sync) {
			int error = gfs2_statfs_sync(sdp->sd_vfs, 0);
			quotad_error(sdp, "statfs", error);
			statfs_timeo = gfs2_tune_get(sdp, gt_statfs_quantum) * HZ;
		}
		else
			quotad_check_timeo(sdp, "statfs", gfs2_statfs_sync, t,
				   	   &statfs_timeo,
					   &tune->gt_statfs_quantum);

		/* Update quota file */
		quotad_check_timeo(sdp, "sync", gfs2_quota_sync, t,
				   &quotad_timeo, &tune->gt_quota_quantum);

		/* Check for & recover partially truncated inodes */
		quotad_check_trunc_list(sdp);

		try_to_freeze();

		t = min(quotad_timeo, statfs_timeo);

		prepare_to_wait(&sdp->sd_quota_wait, &wait, TASK_INTERRUPTIBLE);
		spin_lock(&sdp->sd_trunc_lock);
		empty = list_empty(&sdp->sd_trunc_list);
		spin_unlock(&sdp->sd_trunc_lock);
		if (empty && !sdp->sd_statfs_force_sync)
			t -= schedule_timeout(t);
		else
			t = 0;
		finish_wait(&sdp->sd_quota_wait, &wait);
	}

	return 0;
}

static int gfs2_quota_get_xstate(struct super_block *sb,
				 struct fs_quota_stat *fqs)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;

	memset(fqs, 0, sizeof(struct fs_quota_stat));
	fqs->qs_version = FS_QSTAT_VERSION;

	switch (sdp->sd_args.ar_quota) {
	case GFS2_QUOTA_ON:
		fqs->qs_flags |= (FS_QUOTA_UDQ_ENFD | FS_QUOTA_GDQ_ENFD);
		/*FALLTHRU*/
	case GFS2_QUOTA_ACCOUNT:
		fqs->qs_flags |= (FS_QUOTA_UDQ_ACCT | FS_QUOTA_GDQ_ACCT);
		break;
	case GFS2_QUOTA_OFF:
		break;
	}

	if (sdp->sd_quota_inode) {
		fqs->qs_uquota.qfs_ino = GFS2_I(sdp->sd_quota_inode)->i_no_addr;
		fqs->qs_uquota.qfs_nblks = sdp->sd_quota_inode->i_blocks;
	}
	fqs->qs_uquota.qfs_nextents = 1; /* unsupported */
	fqs->qs_gquota = fqs->qs_uquota; /* its the same inode in both cases */
	fqs->qs_incoredqs = list_lru_count(&gfs2_qd_lru);
	return 0;
}

static int gfs2_get_dqblk(struct super_block *sb, struct kqid qid,
			  struct fs_disk_quota *fdq)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct gfs2_quota_lvb *qlvb;
	struct gfs2_quota_data *qd;
	struct gfs2_holder q_gh;
	int error;

	memset(fdq, 0, sizeof(struct fs_disk_quota));

	if (sdp->sd_args.ar_quota == GFS2_QUOTA_OFF)
		return -ESRCH; /* Crazy XFS error code */

	if ((qid.type != USRQUOTA) &&
	    (qid.type != GRPQUOTA))
		return -EINVAL;

	error = qd_get(sdp, qid, &qd);
	if (error)
		return error;
	error = do_glock(qd, FORCE, &q_gh);
	if (error)
		goto out;

	qlvb = (struct gfs2_quota_lvb *)qd->qd_gl->gl_lksb.sb_lvbptr;
	fdq->d_version = FS_DQUOT_VERSION;
	fdq->d_flags = (qid.type == USRQUOTA) ? FS_USER_QUOTA : FS_GROUP_QUOTA;
	fdq->d_id = from_kqid_munged(current_user_ns(), qid);
	fdq->d_blk_hardlimit = be64_to_cpu(qlvb->qb_limit) << sdp->sd_fsb2bb_shift;
	fdq->d_blk_softlimit = be64_to_cpu(qlvb->qb_warn) << sdp->sd_fsb2bb_shift;
	fdq->d_bcount = be64_to_cpu(qlvb->qb_value) << sdp->sd_fsb2bb_shift;

	gfs2_glock_dq_uninit(&q_gh);
out:
	qd_put(qd);
	return error;
}

/* GFS2 only supports a subset of the XFS fields */
#define GFS2_FIELDMASK (FS_DQ_BSOFT|FS_DQ_BHARD|FS_DQ_BCOUNT)

static int gfs2_set_dqblk(struct super_block *sb, struct kqid qid,
			  struct fs_disk_quota *fdq)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct gfs2_inode *ip = GFS2_I(sdp->sd_quota_inode);
	struct gfs2_quota_data *qd;
	struct gfs2_holder q_gh, i_gh;
	unsigned int data_blocks, ind_blocks;
	unsigned int blocks = 0;
	int alloc_required;
	loff_t offset;
	int error;

	if (sdp->sd_args.ar_quota == GFS2_QUOTA_OFF)
		return -ESRCH; /* Crazy XFS error code */

	if ((qid.type != USRQUOTA) &&
	    (qid.type != GRPQUOTA))
		return -EINVAL;

	if (fdq->d_fieldmask & ~GFS2_FIELDMASK)
		return -EINVAL;

	error = qd_get(sdp, qid, &qd);
	if (error)
		return error;

	error = gfs2_rs_alloc(ip);
	if (error)
		goto out_put;

	mutex_lock(&ip->i_inode.i_mutex);
	error = gfs2_glock_nq_init(qd->qd_gl, LM_ST_EXCLUSIVE, 0, &q_gh);
	if (error)
		goto out_unlockput;
	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &i_gh);
	if (error)
		goto out_q;

	/* Check for existing entry, if none then alloc new blocks */
	error = update_qd(sdp, qd);
	if (error)
		goto out_i;

	/* If nothing has changed, this is a no-op */
	if ((fdq->d_fieldmask & FS_DQ_BSOFT) &&
	    ((fdq->d_blk_softlimit >> sdp->sd_fsb2bb_shift) == be64_to_cpu(qd->qd_qb.qb_warn)))
		fdq->d_fieldmask ^= FS_DQ_BSOFT;

	if ((fdq->d_fieldmask & FS_DQ_BHARD) &&
	    ((fdq->d_blk_hardlimit >> sdp->sd_fsb2bb_shift) == be64_to_cpu(qd->qd_qb.qb_limit)))
		fdq->d_fieldmask ^= FS_DQ_BHARD;

	if ((fdq->d_fieldmask & FS_DQ_BCOUNT) &&
	    ((fdq->d_bcount >> sdp->sd_fsb2bb_shift) == be64_to_cpu(qd->qd_qb.qb_value)))
		fdq->d_fieldmask ^= FS_DQ_BCOUNT;

	if (fdq->d_fieldmask == 0)
		goto out_i;

	offset = qd2offset(qd);
	alloc_required = gfs2_write_alloc_required(ip, offset, sizeof(struct gfs2_quota));
	if (gfs2_is_stuffed(ip))
		alloc_required = 1;
	if (alloc_required) {
		struct gfs2_alloc_parms ap = { .aflags = 0, };
		gfs2_write_calc_reserv(ip, sizeof(struct gfs2_quota),
				       &data_blocks, &ind_blocks);
		blocks = 1 + data_blocks + ind_blocks;
		ap.target = blocks;
		error = gfs2_inplace_reserve(ip, &ap);
		if (error)
			goto out_i;
		blocks += gfs2_rg_blocks(ip, blocks);
	}

	/* Some quotas span block boundaries and can update two blocks,
	   adding an extra block to the transaction to handle such quotas */
	error = gfs2_trans_begin(sdp, blocks + RES_DINODE + 2, 0);
	if (error)
		goto out_release;

	/* Apply changes */
	error = gfs2_adjust_quota(ip, offset, 0, qd, fdq);

	gfs2_trans_end(sdp);
out_release:
	if (alloc_required)
		gfs2_inplace_release(ip);
out_i:
	gfs2_glock_dq_uninit(&i_gh);
out_q:
	gfs2_glock_dq_uninit(&q_gh);
out_unlockput:
	mutex_unlock(&ip->i_inode.i_mutex);
out_put:
	qd_put(qd);
	return error;
}

const struct quotactl_ops gfs2_quotactl_ops = {
	.quota_sync     = gfs2_quota_sync,
	.get_xstate     = gfs2_quota_get_xstate,
	.get_dqblk	= gfs2_get_dqblk,
	.set_dqblk	= gfs2_set_dqblk,
};

void __init gfs2_quota_hash_init(void)
{
	unsigned i;

	for(i = 0; i < GFS2_QD_HASH_SIZE; i++)
		INIT_HLIST_BL_HEAD(&qd_hash_table[i]);
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/recovery.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

// #include <linux/module.h>
// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/crc32.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "bmap.h"
// #include "glock.h"
// #include "glops.h"
// #include "lops.h"
// #include "meta_io.h"
// #include "recovery.h"
// #include "super.h"
// #include "util.h"
// #include "dir.h"

struct workqueue_struct *gfs_recovery_wq;

int gfs2_replay_read_block(struct gfs2_jdesc *jd, unsigned int blk,
			   struct buffer_head **bh)
{
	struct gfs2_inode *ip = GFS2_I(jd->jd_inode);
	struct gfs2_glock *gl = ip->i_gl;
	int new = 0;
	u64 dblock;
	u32 extlen;
	int error;

	error = gfs2_extent_map(&ip->i_inode, blk, &new, &dblock, &extlen);
	if (error)
		return error;
	if (!dblock) {
		gfs2_consist_inode(ip);
		return -EIO;
	}

	*bh = gfs2_meta_ra(gl, dblock, extlen);

	return error;
}

int gfs2_revoke_add(struct gfs2_jdesc *jd, u64 blkno, unsigned int where)
{
	struct list_head *head = &jd->jd_revoke_list;
	struct gfs2_revoke_replay *rr;
	int found = 0;

	list_for_each_entry(rr, head, rr_list) {
		if (rr->rr_blkno == blkno) {
			found = 1;
			break;
		}
	}

	if (found) {
		rr->rr_where = where;
		return 0;
	}

	rr = kmalloc(sizeof(struct gfs2_revoke_replay), GFP_NOFS);
	if (!rr)
		return -ENOMEM;

	rr->rr_blkno = blkno;
	rr->rr_where = where;
	list_add(&rr->rr_list, head);

	return 1;
}

int gfs2_revoke_check(struct gfs2_jdesc *jd, u64 blkno, unsigned int where)
{
	struct gfs2_revoke_replay *rr;
	int wrap, a, b, revoke;
	int found = 0;

	list_for_each_entry(rr, &jd->jd_revoke_list, rr_list) {
		if (rr->rr_blkno == blkno) {
			found = 1;
			break;
		}
	}

	if (!found)
		return 0;

	wrap = (rr->rr_where < jd->jd_replay_tail);
	a = (jd->jd_replay_tail < where);
	b = (where < rr->rr_where);
	revoke = (wrap) ? (a || b) : (a && b);

	return revoke;
}

void gfs2_revoke_clean(struct gfs2_jdesc *jd)
{
	struct list_head *head = &jd->jd_revoke_list;
	struct gfs2_revoke_replay *rr;

	while (!list_empty(head)) {
		rr = list_entry(head->next, struct gfs2_revoke_replay, rr_list);
		list_del(&rr->rr_list);
		kfree(rr);
	}
}

static int gfs2_log_header_in(struct gfs2_log_header_host *lh, const void *buf)
{
	const struct gfs2_log_header *str = buf;

	if (str->lh_header.mh_magic != cpu_to_be32(GFS2_MAGIC) ||
	    str->lh_header.mh_type != cpu_to_be32(GFS2_METATYPE_LH))
		return 1;

	lh->lh_sequence = be64_to_cpu(str->lh_sequence);
	lh->lh_flags = be32_to_cpu(str->lh_flags);
	lh->lh_tail = be32_to_cpu(str->lh_tail);
	lh->lh_blkno = be32_to_cpu(str->lh_blkno);
	lh->lh_hash = be32_to_cpu(str->lh_hash);
	return 0;
}

/**
 * get_log_header - read the log header for a given segment
 * @jd: the journal
 * @blk: the block to look at
 * @lh: the log header to return
 *
 * Read the log header for a given segement in a given journal.  Do a few
 * sanity checks on it.
 *
 * Returns: 0 on success,
 *          1 if the header was invalid or incomplete,
 *          errno on error
 */

static int get_log_header(struct gfs2_jdesc *jd, unsigned int blk,
			  struct gfs2_log_header_host *head)
{
	struct buffer_head *bh;
	struct gfs2_log_header_host uninitialized_var(lh);
	const u32 nothing = 0;
	u32 hash;
	int error;

	error = gfs2_replay_read_block(jd, blk, &bh);
	if (error)
		return error;

	hash = crc32_le((u32)~0, bh->b_data, sizeof(struct gfs2_log_header) -
					     sizeof(u32));
	hash = crc32_le(hash, (unsigned char const *)&nothing, sizeof(nothing));
	hash ^= (u32)~0;
	error = gfs2_log_header_in(&lh, bh->b_data);
	brelse(bh);

	if (error || lh.lh_blkno != blk || lh.lh_hash != hash)
		return 1;

	*head = lh;

	return 0;
}

/**
 * find_good_lh - find a good log header
 * @jd: the journal
 * @blk: the segment to start searching from
 * @lh: the log header to fill in
 * @forward: if true search forward in the log, else search backward
 *
 * Call get_log_header() to get a log header for a segment, but if the
 * segment is bad, either scan forward or backward until we find a good one.
 *
 * Returns: errno
 */

static int find_good_lh(struct gfs2_jdesc *jd, unsigned int *blk,
			struct gfs2_log_header_host *head)
{
	unsigned int orig_blk = *blk;
	int error;

	for (;;) {
		error = get_log_header(jd, *blk, head);
		if (error <= 0)
			return error;

		if (++*blk == jd->jd_blocks)
			*blk = 0;

		if (*blk == orig_blk) {
			gfs2_consist_inode(GFS2_I(jd->jd_inode));
			return -EIO;
		}
	}
}

/**
 * jhead_scan - make sure we've found the head of the log
 * @jd: the journal
 * @head: this is filled in with the log descriptor of the head
 *
 * At this point, seg and lh should be either the head of the log or just
 * before.  Scan forward until we find the head.
 *
 * Returns: errno
 */

static int jhead_scan(struct gfs2_jdesc *jd, struct gfs2_log_header_host *head)
{
	unsigned int blk = head->lh_blkno;
	struct gfs2_log_header_host lh;
	int error;

	for (;;) {
		if (++blk == jd->jd_blocks)
			blk = 0;

		error = get_log_header(jd, blk, &lh);
		if (error < 0)
			return error;
		if (error == 1)
			continue;

		if (lh.lh_sequence == head->lh_sequence) {
			gfs2_consist_inode(GFS2_I(jd->jd_inode));
			return -EIO;
		}
		if (lh.lh_sequence < head->lh_sequence)
			break;

		*head = lh;
	}

	return 0;
}

/**
 * gfs2_find_jhead - find the head of a log
 * @jd: the journal
 * @head: the log descriptor for the head of the log is returned here
 *
 * Do a binary search of a journal and find the valid log entry with the
 * highest sequence number.  (i.e. the log head)
 *
 * Returns: errno
 */

int gfs2_find_jhead(struct gfs2_jdesc *jd, struct gfs2_log_header_host *head)
{
	struct gfs2_log_header_host lh_1, lh_m;
	u32 blk_1, blk_2, blk_m;
	int error;

	blk_1 = 0;
	blk_2 = jd->jd_blocks - 1;

	for (;;) {
		blk_m = (blk_1 + blk_2) / 2;

		error = find_good_lh(jd, &blk_1, &lh_1);
		if (error)
			return error;

		error = find_good_lh(jd, &blk_m, &lh_m);
		if (error)
			return error;

		if (blk_1 == blk_m || blk_m == blk_2)
			break;

		if (lh_1.lh_sequence <= lh_m.lh_sequence)
			blk_1 = blk_m;
		else
			blk_2 = blk_m;
	}

	error = jhead_scan(jd, &lh_1);
	if (error)
		return error;

	*head = lh_1;

	return error;
}

/**
 * foreach_descriptor - go through the active part of the log
 * @jd: the journal
 * @start: the first log header in the active region
 * @end: the last log header (don't process the contents of this entry))
 *
 * Call a given function once for every log descriptor in the active
 * portion of the log.
 *
 * Returns: errno
 */

static int foreach_descriptor(struct gfs2_jdesc *jd, unsigned int start,
			      unsigned int end, int pass)
{
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);
	struct buffer_head *bh;
	struct gfs2_log_descriptor *ld;
	int error = 0;
	u32 length;
	__be64 *ptr;
	unsigned int offset = sizeof(struct gfs2_log_descriptor);
	offset += sizeof(__be64) - 1;
	offset &= ~(sizeof(__be64) - 1);

	while (start != end) {
		error = gfs2_replay_read_block(jd, start, &bh);
		if (error)
			return error;
		if (gfs2_meta_check(sdp, bh)) {
			brelse(bh);
			return -EIO;
		}
		ld = (struct gfs2_log_descriptor *)bh->b_data;
		length = be32_to_cpu(ld->ld_length);

		if (be32_to_cpu(ld->ld_header.mh_type) == GFS2_METATYPE_LH) {
			struct gfs2_log_header_host lh;
			error = get_log_header(jd, start, &lh);
			if (!error) {
				gfs2_replay_incr_blk(sdp, &start);
				brelse(bh);
				continue;
			}
			if (error == 1) {
				gfs2_consist_inode(GFS2_I(jd->jd_inode));
				error = -EIO;
			}
			brelse(bh);
			return error;
		} else if (gfs2_metatype_check(sdp, bh, GFS2_METATYPE_LD)) {
			brelse(bh);
			return -EIO;
		}
		ptr = (__be64 *)(bh->b_data + offset);
		error = lops_scan_elements(jd, start, ld, ptr, pass);
		if (error) {
			brelse(bh);
			return error;
		}

		while (length--)
			gfs2_replay_incr_blk(sdp, &start);

		brelse(bh);
	}

	return 0;
}

/**
 * clean_journal - mark a dirty journal as being clean
 * @sdp: the filesystem
 * @jd: the journal
 * @gl: the journal's glock
 * @head: the head journal to start from
 *
 * Returns: errno
 */

static int clean_journal(struct gfs2_jdesc *jd, struct gfs2_log_header_host *head)
{
	struct gfs2_inode *ip = GFS2_I(jd->jd_inode);
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);
	unsigned int lblock;
	struct gfs2_log_header *lh;
	u32 hash;
	struct buffer_head *bh;
	int error;
	struct buffer_head bh_map = { .b_state = 0, .b_blocknr = 0 };

	lblock = head->lh_blkno;
	gfs2_replay_incr_blk(sdp, &lblock);
	bh_map.b_size = 1 << ip->i_inode.i_blkbits;
	error = gfs2_block_map(&ip->i_inode, lblock, &bh_map, 0);
	if (error)
		return error;
	if (!bh_map.b_blocknr) {
		gfs2_consist_inode(ip);
		return -EIO;
	}

	bh = sb_getblk(sdp->sd_vfs, bh_map.b_blocknr);
	lock_buffer(bh);
	memset(bh->b_data, 0, bh->b_size);
	set_buffer_uptodate(bh);
	clear_buffer_dirty(bh);
	unlock_buffer(bh);

	lh = (struct gfs2_log_header *)bh->b_data;
	memset(lh, 0, sizeof(struct gfs2_log_header));
	lh->lh_header.mh_magic = cpu_to_be32(GFS2_MAGIC);
	lh->lh_header.mh_type = cpu_to_be32(GFS2_METATYPE_LH);
	lh->lh_header.__pad0 = cpu_to_be64(0);
	lh->lh_header.mh_format = cpu_to_be32(GFS2_FORMAT_LH);
	lh->lh_header.mh_jid = cpu_to_be32(sdp->sd_jdesc->jd_jid);
	lh->lh_sequence = cpu_to_be64(head->lh_sequence + 1);
	lh->lh_flags = cpu_to_be32(GFS2_LOG_HEAD_UNMOUNT);
	lh->lh_blkno = cpu_to_be32(lblock);
	hash = gfs2_disk_hash((const char *)lh, sizeof(struct gfs2_log_header));
	lh->lh_hash = cpu_to_be32(hash);

	set_buffer_dirty(bh);
	if (sync_dirty_buffer(bh))
		gfs2_io_error_bh(sdp, bh);
	brelse(bh);

	return error;
}


static void gfs2_recovery_done(struct gfs2_sbd *sdp, unsigned int jid,
                               unsigned int message)
{
	char env_jid[20];
	char env_status[20];
	char *envp[] = { env_jid, env_status, NULL };
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;

        ls->ls_recover_jid_done = jid;
        ls->ls_recover_jid_status = message;
	sprintf(env_jid, "JID=%d", jid);
	sprintf(env_status, "RECOVERY=%s",
		message == LM_RD_SUCCESS ? "Done" : "Failed");
        kobject_uevent_env(&sdp->sd_kobj, KOBJ_CHANGE, envp);

	if (sdp->sd_lockstruct.ls_ops->lm_recovery_result)
		sdp->sd_lockstruct.ls_ops->lm_recovery_result(sdp, jid, message);
}

void gfs2_recover_func(struct work_struct *work)
{
	struct gfs2_jdesc *jd = container_of(work, struct gfs2_jdesc, jd_work);
	struct gfs2_inode *ip = GFS2_I(jd->jd_inode);
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);
	struct gfs2_log_header_host head;
	struct gfs2_holder j_gh, ji_gh, thaw_gh;
	unsigned long t;
	int ro = 0;
	unsigned int pass;
	int error;
	int jlocked = 0;

	if (sdp->sd_args.ar_spectator ||
	    (jd->jd_jid != sdp->sd_lockstruct.ls_jid)) {
		fs_info(sdp, "jid=%u: Trying to acquire journal lock...\n",
			jd->jd_jid);
		jlocked = 1;
		/* Acquire the journal lock so we can do recovery */

		error = gfs2_glock_nq_num(sdp, jd->jd_jid, &gfs2_journal_glops,
					  LM_ST_EXCLUSIVE,
					  LM_FLAG_NOEXP | LM_FLAG_TRY | GL_NOCACHE,
					  &j_gh);
		switch (error) {
		case 0:
			break;

		case GLR_TRYFAILED:
			fs_info(sdp, "jid=%u: Busy\n", jd->jd_jid);
			error = 0;

		default:
			goto fail;
		};

		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED,
					   LM_FLAG_NOEXP | GL_NOCACHE, &ji_gh);
		if (error)
			goto fail_gunlock_j;
	} else {
		fs_info(sdp, "jid=%u, already locked for use\n", jd->jd_jid);
	}

	fs_info(sdp, "jid=%u: Looking at journal...\n", jd->jd_jid);

	error = gfs2_jdesc_check(jd);
	if (error)
		goto fail_gunlock_ji;

	error = gfs2_find_jhead(jd, &head);
	if (error)
		goto fail_gunlock_ji;

	if (!(head.lh_flags & GFS2_LOG_HEAD_UNMOUNT)) {
		fs_info(sdp, "jid=%u: Acquiring the transaction lock...\n",
			jd->jd_jid);

		t = jiffies;

		/* Acquire a shared hold on the freeze lock */

		error = gfs2_glock_nq_init(sdp->sd_freeze_gl, LM_ST_SHARED,
					   LM_FLAG_NOEXP | LM_FLAG_PRIORITY,
					   &thaw_gh);
		if (error)
			goto fail_gunlock_ji;

		if (test_bit(SDF_RORECOVERY, &sdp->sd_flags)) {
			ro = 1;
		} else if (test_bit(SDF_JOURNAL_CHECKED, &sdp->sd_flags)) {
			if (!test_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags))
				ro = 1;
		} else {
			if (sdp->sd_vfs->s_flags & MS_RDONLY) {
				/* check if device itself is read-only */
				ro = bdev_read_only(sdp->sd_vfs->s_bdev);
				if (!ro) {
					fs_info(sdp, "recovery required on "
						"read-only filesystem.\n");
					fs_info(sdp, "write access will be "
						"enabled during recovery.\n");
				}
			}
		}

		if (ro) {
			fs_warn(sdp, "jid=%u: Can't replay: read-only block "
				"device\n", jd->jd_jid);
			error = -EROFS;
			goto fail_gunlock_thaw;
		}

		fs_info(sdp, "jid=%u: Replaying journal...\n", jd->jd_jid);

		for (pass = 0; pass < 2; pass++) {
			lops_before_scan(jd, &head, pass);
			error = foreach_descriptor(jd, head.lh_tail,
						   head.lh_blkno, pass);
			lops_after_scan(jd, error, pass);
			if (error)
				goto fail_gunlock_thaw;
		}

		error = clean_journal(jd, &head);
		if (error)
			goto fail_gunlock_thaw;

		gfs2_glock_dq_uninit(&thaw_gh);
		t = DIV_ROUND_UP(jiffies - t, HZ);
		fs_info(sdp, "jid=%u: Journal replayed in %lus\n",
			jd->jd_jid, t);
	}

	gfs2_recovery_done(sdp, jd->jd_jid, LM_RD_SUCCESS);

	if (jlocked) {
		gfs2_glock_dq_uninit(&ji_gh);
		gfs2_glock_dq_uninit(&j_gh);
	}

	fs_info(sdp, "jid=%u: Done\n", jd->jd_jid);
	goto done;

fail_gunlock_thaw:
	gfs2_glock_dq_uninit(&thaw_gh);
fail_gunlock_ji:
	if (jlocked) {
		gfs2_glock_dq_uninit(&ji_gh);
fail_gunlock_j:
		gfs2_glock_dq_uninit(&j_gh);
	}

	fs_info(sdp, "jid=%u: %s\n", jd->jd_jid, (error) ? "Failed" : "Done");
fail:
	jd->jd_recover_error = error;
	gfs2_recovery_done(sdp, jd->jd_jid, LM_RD_GAVEUP);
done:
	clear_bit(JDF_RECOVERY, &jd->jd_flags);
	smp_mb__after_atomic();
	wake_up_bit(&jd->jd_flags, JDF_RECOVERY);
}

int gfs2_recover_journal(struct gfs2_jdesc *jd, bool wait)
{
	int rv;

	if (test_and_set_bit(JDF_RECOVERY, &jd->jd_flags))
		return -EBUSY;

	/* we have JDF_RECOVERY, queue should always succeed */
	rv = queue_work(gfs_recovery_wq, &jd->jd_work);
	BUG_ON(!rv);

	if (wait)
		wait_on_bit(&jd->jd_flags, JDF_RECOVERY,
			    TASK_UNINTERRUPTIBLE);

	return wait ? jd->jd_recover_error : 0;
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/rgrp.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2008 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/fs.h>
// #include <linux/gfs2_ondisk.h>
#include <linux/prefetch.h>
// #include <linux/blkdev.h>
#include <linux/rbtree.h>
#include <linux/random.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "glock.h"
// #include "glops.h"
// #include "lops.h"
// #include "meta_io.h"
// #include "quota.h"
// #include "rgrp.h"
// #include "super.h"
// #include "trans.h"
// #include "util.h"
// #include "log.h"
// #include "inode.h"
// #include "trace_gfs2.h"

#define BFITNOENT ((u32)~0)
#define NO_BLOCK ((u64)~0)

#if BITS_PER_LONG == 32
#define LBITMASK   (0x55555555UL)
#define LBITSKIP55 (0x55555555UL)
#define LBITSKIP00 (0x00000000UL)
#else
#define LBITMASK   (0x5555555555555555UL)
#define LBITSKIP55 (0x5555555555555555UL)
#define LBITSKIP00 (0x0000000000000000UL)
#endif

/*
 * These routines are used by the resource group routines (rgrp.c)
 * to keep track of block allocation.  Each block is represented by two
 * bits.  So, each byte represents GFS2_NBBY (i.e. 4) blocks.
 *
 * 0 = Free
 * 1 = Used (not metadata)
 * 2 = Unlinked (still in use) inode
 * 3 = Used (metadata)
 */

struct gfs2_extent {
	struct gfs2_rbm rbm;
	u32 len;
};

static const char valid_change[16] = {
	        /* current */
	/* n */ 0, 1, 1, 1,
	/* e */ 1, 0, 0, 0,
	/* w */ 0, 0, 0, 1,
	        1, 0, 0, 0
};

static int gfs2_rbm_find(struct gfs2_rbm *rbm, u8 state, u32 *minext,
			 const struct gfs2_inode *ip, bool nowrap,
			 const struct gfs2_alloc_parms *ap);


/**
 * gfs2_setbit - Set a bit in the bitmaps
 * @rbm: The position of the bit to set
 * @do_clone: Also set the clone bitmap, if it exists
 * @new_state: the new state of the block
 *
 */

static inline void gfs2_setbit(const struct gfs2_rbm *rbm, bool do_clone,
			       unsigned char new_state)
{
	unsigned char *byte1, *byte2, *end, cur_state;
	struct gfs2_bitmap *bi = rbm_bi(rbm);
	unsigned int buflen = bi->bi_len;
	const unsigned int bit = (rbm->offset % GFS2_NBBY) * GFS2_BIT_SIZE;

	byte1 = bi->bi_bh->b_data + bi->bi_offset + (rbm->offset / GFS2_NBBY);
	end = bi->bi_bh->b_data + bi->bi_offset + buflen;

	BUG_ON(byte1 >= end);

	cur_state = (*byte1 >> bit) & GFS2_BIT_MASK;

	if (unlikely(!valid_change[new_state * 4 + cur_state])) {
		pr_warn("buf_blk = 0x%x old_state=%d, new_state=%d\n",
			rbm->offset, cur_state, new_state);
		pr_warn("rgrp=0x%llx bi_start=0x%x\n",
			(unsigned long long)rbm->rgd->rd_addr, bi->bi_start);
		pr_warn("bi_offset=0x%x bi_len=0x%x\n",
			bi->bi_offset, bi->bi_len);
		dump_stack();
		gfs2_consist_rgrpd(rbm->rgd);
		return;
	}
	*byte1 ^= (cur_state ^ new_state) << bit;

	if (do_clone && bi->bi_clone) {
		byte2 = bi->bi_clone + bi->bi_offset + (rbm->offset / GFS2_NBBY);
		cur_state = (*byte2 >> bit) & GFS2_BIT_MASK;
		*byte2 ^= (cur_state ^ new_state) << bit;
	}
}

/**
 * gfs2_testbit - test a bit in the bitmaps
 * @rbm: The bit to test
 *
 * Returns: The two bit block state of the requested bit
 */

static inline u8 gfs2_testbit(const struct gfs2_rbm *rbm)
{
	struct gfs2_bitmap *bi = rbm_bi(rbm);
	const u8 *buffer = bi->bi_bh->b_data + bi->bi_offset;
	const u8 *byte;
	unsigned int bit;

	byte = buffer + (rbm->offset / GFS2_NBBY);
	bit = (rbm->offset % GFS2_NBBY) * GFS2_BIT_SIZE;

	return (*byte >> bit) & GFS2_BIT_MASK;
}

/**
 * gfs2_bit_search
 * @ptr: Pointer to bitmap data
 * @mask: Mask to use (normally 0x55555.... but adjusted for search start)
 * @state: The state we are searching for
 *
 * We xor the bitmap data with a patter which is the bitwise opposite
 * of what we are looking for, this gives rise to a pattern of ones
 * wherever there is a match. Since we have two bits per entry, we
 * take this pattern, shift it down by one place and then and it with
 * the original. All the even bit positions (0,2,4, etc) then represent
 * successful matches, so we mask with 0x55555..... to remove the unwanted
 * odd bit positions.
 *
 * This allows searching of a whole u64 at once (32 blocks) with a
 * single test (on 64 bit arches).
 */

static inline u64 gfs2_bit_search(const __le64 *ptr, u64 mask, u8 state)
{
	u64 tmp;
	static const u64 search[] = {
		[0] = 0xffffffffffffffffULL,
		[1] = 0xaaaaaaaaaaaaaaaaULL,
		[2] = 0x5555555555555555ULL,
		[3] = 0x0000000000000000ULL,
	};
	tmp = le64_to_cpu(*ptr) ^ search[state];
	tmp &= (tmp >> 1);
	tmp &= mask;
	return tmp;
}

/**
 * rs_cmp - multi-block reservation range compare
 * @blk: absolute file system block number of the new reservation
 * @len: number of blocks in the new reservation
 * @rs: existing reservation to compare against
 *
 * returns: 1 if the block range is beyond the reach of the reservation
 *         -1 if the block range is before the start of the reservation
 *          0 if the block range overlaps with the reservation
 */
static inline int rs_cmp(u64 blk, u32 len, struct gfs2_blkreserv *rs)
{
	u64 startblk = gfs2_rbm_to_block(&rs->rs_rbm);

	if (blk >= startblk + rs->rs_free)
		return 1;
	if (blk + len - 1 < startblk)
		return -1;
	return 0;
}

/**
 * gfs2_bitfit - Search an rgrp's bitmap buffer to find a bit-pair representing
 *       a block in a given allocation state.
 * @buf: the buffer that holds the bitmaps
 * @len: the length (in bytes) of the buffer
 * @goal: start search at this block's bit-pair (within @buffer)
 * @state: GFS2_BLKST_XXX the state of the block we're looking for.
 *
 * Scope of @goal and returned block number is only within this bitmap buffer,
 * not entire rgrp or filesystem.  @buffer will be offset from the actual
 * beginning of a bitmap block buffer, skipping any header structures, but
 * headers are always a multiple of 64 bits long so that the buffer is
 * always aligned to a 64 bit boundary.
 *
 * The size of the buffer is in bytes, but is it assumed that it is
 * always ok to read a complete multiple of 64 bits at the end
 * of the block in case the end is no aligned to a natural boundary.
 *
 * Return: the block number (bitmap buffer scope) that was found
 */

static u32 gfs2_bitfit(const u8 *buf, const unsigned int len,
		       u32 goal, u8 state)
{
	u32 spoint = (goal << 1) & ((8*sizeof(u64)) - 1);
	const __le64 *ptr = ((__le64 *)buf) + (goal >> 5);
	const __le64 *end = (__le64 *)(buf + ALIGN(len, sizeof(u64)));
	u64 tmp;
	u64 mask = 0x5555555555555555ULL;
	u32 bit;

	/* Mask off bits we don't care about at the start of the search */
	mask <<= spoint;
	tmp = gfs2_bit_search(ptr, mask, state);
	ptr++;
	while(tmp == 0 && ptr < end) {
		tmp = gfs2_bit_search(ptr, 0x5555555555555555ULL, state);
		ptr++;
	}
	/* Mask off any bits which are more than len bytes from the start */
	if (ptr == end && (len & (sizeof(u64) - 1)))
		tmp &= (((u64)~0) >> (64 - 8*(len & (sizeof(u64) - 1))));
	/* Didn't find anything, so return */
	if (tmp == 0)
		return BFITNOENT;
	ptr--;
	bit = __ffs64(tmp);
	bit /= 2;	/* two bits per entry in the bitmap */
	return (((const unsigned char *)ptr - buf) * GFS2_NBBY) + bit;
}

/**
 * gfs2_rbm_from_block - Set the rbm based upon rgd and block number
 * @rbm: The rbm with rgd already set correctly
 * @block: The block number (filesystem relative)
 *
 * This sets the bi and offset members of an rbm based on a
 * resource group and a filesystem relative block number. The
 * resource group must be set in the rbm on entry, the bi and
 * offset members will be set by this function.
 *
 * Returns: 0 on success, or an error code
 */

static int gfs2_rbm_from_block(struct gfs2_rbm *rbm, u64 block)
{
	u64 rblock = block - rbm->rgd->rd_data0;

	if (WARN_ON_ONCE(rblock > UINT_MAX))
		return -EINVAL;
	if (block >= rbm->rgd->rd_data0 + rbm->rgd->rd_data)
		return -E2BIG;

	rbm->bii = 0;
	rbm->offset = (u32)(rblock);
	/* Check if the block is within the first block */
	if (rbm->offset < rbm_bi(rbm)->bi_blocks)
		return 0;

	/* Adjust for the size diff between gfs2_meta_header and gfs2_rgrp */
	rbm->offset += (sizeof(struct gfs2_rgrp) -
			sizeof(struct gfs2_meta_header)) * GFS2_NBBY;
	rbm->bii = rbm->offset / rbm->rgd->rd_sbd->sd_blocks_per_bitmap;
	rbm->offset -= rbm->bii * rbm->rgd->rd_sbd->sd_blocks_per_bitmap;
	return 0;
}

/**
 * gfs2_rbm_incr - increment an rbm structure
 * @rbm: The rbm with rgd already set correctly
 *
 * This function takes an existing rbm structure and increments it to the next
 * viable block offset.
 *
 * Returns: If incrementing the offset would cause the rbm to go past the
 *          end of the rgrp, true is returned, otherwise false.
 *
 */

static bool gfs2_rbm_incr(struct gfs2_rbm *rbm)
{
	if (rbm->offset + 1 < rbm_bi(rbm)->bi_blocks) { /* in the same bitmap */
		rbm->offset++;
		return false;
	}
	if (rbm->bii == rbm->rgd->rd_length - 1) /* at the last bitmap */
		return true;

	rbm->offset = 0;
	rbm->bii++;
	return false;
}

/**
 * gfs2_unaligned_extlen - Look for free blocks which are not byte aligned
 * @rbm: Position to search (value/result)
 * @n_unaligned: Number of unaligned blocks to check
 * @len: Decremented for each block found (terminate on zero)
 *
 * Returns: true if a non-free block is encountered
 */

static bool gfs2_unaligned_extlen(struct gfs2_rbm *rbm, u32 n_unaligned, u32 *len)
{
	u32 n;
	u8 res;

	for (n = 0; n < n_unaligned; n++) {
		res = gfs2_testbit(rbm);
		if (res != GFS2_BLKST_FREE)
			return true;
		(*len)--;
		if (*len == 0)
			return true;
		if (gfs2_rbm_incr(rbm))
			return true;
	}

	return false;
}

/**
 * gfs2_free_extlen - Return extent length of free blocks
 * @rrbm: Starting position
 * @len: Max length to check
 *
 * Starting at the block specified by the rbm, see how many free blocks
 * there are, not reading more than len blocks ahead. This can be done
 * using memchr_inv when the blocks are byte aligned, but has to be done
 * on a block by block basis in case of unaligned blocks. Also this
 * function can cope with bitmap boundaries (although it must stop on
 * a resource group boundary)
 *
 * Returns: Number of free blocks in the extent
 */

static u32 gfs2_free_extlen(const struct gfs2_rbm *rrbm, u32 len)
{
	struct gfs2_rbm rbm = *rrbm;
	u32 n_unaligned = rbm.offset & 3;
	u32 size = len;
	u32 bytes;
	u32 chunk_size;
	u8 *ptr, *start, *end;
	u64 block;
	struct gfs2_bitmap *bi;

	if (n_unaligned &&
	    gfs2_unaligned_extlen(&rbm, 4 - n_unaligned, &len))
		goto out;

	n_unaligned = len & 3;
	/* Start is now byte aligned */
	while (len > 3) {
		bi = rbm_bi(&rbm);
		start = bi->bi_bh->b_data;
		if (bi->bi_clone)
			start = bi->bi_clone;
		end = start + bi->bi_bh->b_size;
		start += bi->bi_offset;
		BUG_ON(rbm.offset & 3);
		start += (rbm.offset / GFS2_NBBY);
		bytes = min_t(u32, len / GFS2_NBBY, (end - start));
		ptr = memchr_inv(start, 0, bytes);
		chunk_size = ((ptr == NULL) ? bytes : (ptr - start));
		chunk_size *= GFS2_NBBY;
		BUG_ON(len < chunk_size);
		len -= chunk_size;
		block = gfs2_rbm_to_block(&rbm);
		if (gfs2_rbm_from_block(&rbm, block + chunk_size)) {
			n_unaligned = 0;
			break;
		}
		if (ptr) {
			n_unaligned = 3;
			break;
		}
		n_unaligned = len & 3;
	}

	/* Deal with any bits left over at the end */
	if (n_unaligned)
		gfs2_unaligned_extlen(&rbm, n_unaligned, &len);
out:
	return size - len;
}

/**
 * gfs2_bitcount - count the number of bits in a certain state
 * @rgd: the resource group descriptor
 * @buffer: the buffer that holds the bitmaps
 * @buflen: the length (in bytes) of the buffer
 * @state: the state of the block we're looking for
 *
 * Returns: The number of bits
 */

static u32 gfs2_bitcount(struct gfs2_rgrpd *rgd, const u8 *buffer,
			 unsigned int buflen, u8 state)
{
	const u8 *byte = buffer;
	const u8 *end = buffer + buflen;
	const u8 state1 = state << 2;
	const u8 state2 = state << 4;
	const u8 state3 = state << 6;
	u32 count = 0;

	for (; byte < end; byte++) {
		if (((*byte) & 0x03) == state)
			count++;
		if (((*byte) & 0x0C) == state1)
			count++;
		if (((*byte) & 0x30) == state2)
			count++;
		if (((*byte) & 0xC0) == state3)
			count++;
	}

	return count;
}

/**
 * gfs2_rgrp_verify - Verify that a resource group is consistent
 * @rgd: the rgrp
 *
 */

void gfs2_rgrp_verify(struct gfs2_rgrpd *rgd)
{
	struct gfs2_sbd *sdp = rgd->rd_sbd;
	struct gfs2_bitmap *bi = NULL;
	u32 length = rgd->rd_length;
	u32 count[4], tmp;
	int buf, x;

	memset(count, 0, 4 * sizeof(u32));

	/* Count # blocks in each of 4 possible allocation states */
	for (buf = 0; buf < length; buf++) {
		bi = rgd->rd_bits + buf;
		for (x = 0; x < 4; x++)
			count[x] += gfs2_bitcount(rgd,
						  bi->bi_bh->b_data +
						  bi->bi_offset,
						  bi->bi_len, x);
	}

	if (count[0] != rgd->rd_free) {
		if (gfs2_consist_rgrpd(rgd))
			fs_err(sdp, "free data mismatch:  %u != %u\n",
			       count[0], rgd->rd_free);
		return;
	}

	tmp = rgd->rd_data - rgd->rd_free - rgd->rd_dinodes;
	if (count[1] != tmp) {
		if (gfs2_consist_rgrpd(rgd))
			fs_err(sdp, "used data mismatch:  %u != %u\n",
			       count[1], tmp);
		return;
	}

	if (count[2] + count[3] != rgd->rd_dinodes) {
		if (gfs2_consist_rgrpd(rgd))
			fs_err(sdp, "used metadata mismatch:  %u != %u\n",
			       count[2] + count[3], rgd->rd_dinodes);
		return;
	}
}

static inline int rgrp_contains_block(struct gfs2_rgrpd *rgd, u64 block)
{
	u64 first = rgd->rd_data0;
	u64 last = first + rgd->rd_data;
	return first <= block && block < last;
}

/**
 * gfs2_blk2rgrpd - Find resource group for a given data/meta block number
 * @sdp: The GFS2 superblock
 * @blk: The data block number
 * @exact: True if this needs to be an exact match
 *
 * Returns: The resource group, or NULL if not found
 */

struct gfs2_rgrpd *gfs2_blk2rgrpd(struct gfs2_sbd *sdp, u64 blk, bool exact)
{
	struct rb_node *n, *next;
	struct gfs2_rgrpd *cur;

	spin_lock(&sdp->sd_rindex_spin);
	n = sdp->sd_rindex_tree.rb_node;
	while (n) {
		cur = rb_entry(n, struct gfs2_rgrpd, rd_node);
		next = NULL;
		if (blk < cur->rd_addr)
			next = n->rb_left;
		else if (blk >= cur->rd_data0 + cur->rd_data)
			next = n->rb_right;
		if (next == NULL) {
			spin_unlock(&sdp->sd_rindex_spin);
			if (exact) {
				if (blk < cur->rd_addr)
					return NULL;
				if (blk >= cur->rd_data0 + cur->rd_data)
					return NULL;
			}
			return cur;
		}
		n = next;
	}
	spin_unlock(&sdp->sd_rindex_spin);

	return NULL;
}

/**
 * gfs2_rgrpd_get_first - get the first Resource Group in the filesystem
 * @sdp: The GFS2 superblock
 *
 * Returns: The first rgrp in the filesystem
 */

struct gfs2_rgrpd *gfs2_rgrpd_get_first(struct gfs2_sbd *sdp)
{
	const struct rb_node *n;
	struct gfs2_rgrpd *rgd;

	spin_lock(&sdp->sd_rindex_spin);
	n = rb_first(&sdp->sd_rindex_tree);
	rgd = rb_entry(n, struct gfs2_rgrpd, rd_node);
	spin_unlock(&sdp->sd_rindex_spin);

	return rgd;
}

/**
 * gfs2_rgrpd_get_next - get the next RG
 * @rgd: the resource group descriptor
 *
 * Returns: The next rgrp
 */

struct gfs2_rgrpd *gfs2_rgrpd_get_next(struct gfs2_rgrpd *rgd)
{
	struct gfs2_sbd *sdp = rgd->rd_sbd;
	const struct rb_node *n;

	spin_lock(&sdp->sd_rindex_spin);
	n = rb_next(&rgd->rd_node);
	if (n == NULL)
		n = rb_first(&sdp->sd_rindex_tree);

	if (unlikely(&rgd->rd_node == n)) {
		spin_unlock(&sdp->sd_rindex_spin);
		return NULL;
	}
	rgd = rb_entry(n, struct gfs2_rgrpd, rd_node);
	spin_unlock(&sdp->sd_rindex_spin);
	return rgd;
}

void gfs2_free_clones(struct gfs2_rgrpd *rgd)
{
	int x;

	for (x = 0; x < rgd->rd_length; x++) {
		struct gfs2_bitmap *bi = rgd->rd_bits + x;
		kfree(bi->bi_clone);
		bi->bi_clone = NULL;
	}
}

/**
 * gfs2_rs_alloc - make sure we have a reservation assigned to the inode
 * @ip: the inode for this reservation
 */
int gfs2_rs_alloc(struct gfs2_inode *ip)
{
	int error = 0;

	down_write(&ip->i_rw_mutex);
	if (ip->i_res)
		goto out;

	ip->i_res = kmem_cache_zalloc(gfs2_rsrv_cachep, GFP_NOFS);
	if (!ip->i_res) {
		error = -ENOMEM;
		goto out;
	}

	RB_CLEAR_NODE(&ip->i_res->rs_node);
out:
	up_write(&ip->i_rw_mutex);
	return error;
}

static void dump_rs(struct seq_file *seq, const struct gfs2_blkreserv *rs)
{
	gfs2_print_dbg(seq, "  B: n:%llu s:%llu b:%u f:%u\n",
		       (unsigned long long)rs->rs_inum,
		       (unsigned long long)gfs2_rbm_to_block(&rs->rs_rbm),
		       rs->rs_rbm.offset, rs->rs_free);
}

/**
 * __rs_deltree - remove a multi-block reservation from the rgd tree
 * @rs: The reservation to remove
 *
 */
static void __rs_deltree(struct gfs2_blkreserv *rs)
{
	struct gfs2_rgrpd *rgd;

	if (!gfs2_rs_active(rs))
		return;

	rgd = rs->rs_rbm.rgd;
	trace_gfs2_rs(rs, TRACE_RS_TREEDEL);
	rb_erase(&rs->rs_node, &rgd->rd_rstree);
	RB_CLEAR_NODE(&rs->rs_node);

	if (rs->rs_free) {
		struct gfs2_bitmap *bi = rbm_bi(&rs->rs_rbm);

		/* return reserved blocks to the rgrp */
		BUG_ON(rs->rs_rbm.rgd->rd_reserved < rs->rs_free);
		rs->rs_rbm.rgd->rd_reserved -= rs->rs_free;
		/* The rgrp extent failure point is likely not to increase;
		   it will only do so if the freed blocks are somehow
		   contiguous with a span of free blocks that follows. Still,
		   it will force the number to be recalculated later. */
		rgd->rd_extfail_pt += rs->rs_free;
		rs->rs_free = 0;
		clear_bit(GBF_FULL, &bi->bi_flags);
	}
}

/**
 * gfs2_rs_deltree - remove a multi-block reservation from the rgd tree
 * @rs: The reservation to remove
 *
 */
void gfs2_rs_deltree(struct gfs2_blkreserv *rs)
{
	struct gfs2_rgrpd *rgd;

	rgd = rs->rs_rbm.rgd;
	if (rgd) {
		spin_lock(&rgd->rd_rsspin);
		__rs_deltree(rs);
		spin_unlock(&rgd->rd_rsspin);
	}
}

/**
 * gfs2_rs_delete - delete a multi-block reservation
 * @ip: The inode for this reservation
 * @wcount: The inode's write count, or NULL
 *
 */
void gfs2_rs_delete(struct gfs2_inode *ip, atomic_t *wcount)
{
	down_write(&ip->i_rw_mutex);
	if (ip->i_res && ((wcount == NULL) || (atomic_read(wcount) <= 1))) {
		gfs2_rs_deltree(ip->i_res);
		BUG_ON(ip->i_res->rs_free);
		kmem_cache_free(gfs2_rsrv_cachep, ip->i_res);
		ip->i_res = NULL;
	}
	up_write(&ip->i_rw_mutex);
}

/**
 * return_all_reservations - return all reserved blocks back to the rgrp.
 * @rgd: the rgrp that needs its space back
 *
 * We previously reserved a bunch of blocks for allocation. Now we need to
 * give them back. This leave the reservation structures in tact, but removes
 * all of their corresponding "no-fly zones".
 */
static void return_all_reservations(struct gfs2_rgrpd *rgd)
{
	struct rb_node *n;
	struct gfs2_blkreserv *rs;

	spin_lock(&rgd->rd_rsspin);
	while ((n = rb_first(&rgd->rd_rstree))) {
		rs = rb_entry(n, struct gfs2_blkreserv, rs_node);
		__rs_deltree(rs);
	}
	spin_unlock(&rgd->rd_rsspin);
}

void gfs2_clear_rgrpd(struct gfs2_sbd *sdp)
{
	struct rb_node *n;
	struct gfs2_rgrpd *rgd;
	struct gfs2_glock *gl;

	while ((n = rb_first(&sdp->sd_rindex_tree))) {
		rgd = rb_entry(n, struct gfs2_rgrpd, rd_node);
		gl = rgd->rd_gl;

		rb_erase(n, &sdp->sd_rindex_tree);

		if (gl) {
			spin_lock(&gl->gl_spin);
			gl->gl_object = NULL;
			spin_unlock(&gl->gl_spin);
			gfs2_glock_add_to_lru(gl);
			gfs2_glock_put(gl);
		}

		gfs2_free_clones(rgd);
		kfree(rgd->rd_bits);
		return_all_reservations(rgd);
		kmem_cache_free(gfs2_rgrpd_cachep, rgd);
	}
}

static void gfs2_rindex_print(const struct gfs2_rgrpd *rgd)
{
	pr_info("ri_addr = %llu\n", (unsigned long long)rgd->rd_addr);
	pr_info("ri_length = %u\n", rgd->rd_length);
	pr_info("ri_data0 = %llu\n", (unsigned long long)rgd->rd_data0);
	pr_info("ri_data = %u\n", rgd->rd_data);
	pr_info("ri_bitbytes = %u\n", rgd->rd_bitbytes);
}

/**
 * gfs2_compute_bitstructs - Compute the bitmap sizes
 * @rgd: The resource group descriptor
 *
 * Calculates bitmap descriptors, one for each block that contains bitmap data
 *
 * Returns: errno
 */

static int compute_bitstructs(struct gfs2_rgrpd *rgd)
{
	struct gfs2_sbd *sdp = rgd->rd_sbd;
	struct gfs2_bitmap *bi;
	u32 length = rgd->rd_length; /* # blocks in hdr & bitmap */
	u32 bytes_left, bytes;
	int x;

	if (!length)
		return -EINVAL;

	rgd->rd_bits = kcalloc(length, sizeof(struct gfs2_bitmap), GFP_NOFS);
	if (!rgd->rd_bits)
		return -ENOMEM;

	bytes_left = rgd->rd_bitbytes;

	for (x = 0; x < length; x++) {
		bi = rgd->rd_bits + x;

		bi->bi_flags = 0;
		/* small rgrp; bitmap stored completely in header block */
		if (length == 1) {
			bytes = bytes_left;
			bi->bi_offset = sizeof(struct gfs2_rgrp);
			bi->bi_start = 0;
			bi->bi_len = bytes;
			bi->bi_blocks = bytes * GFS2_NBBY;
		/* header block */
		} else if (x == 0) {
			bytes = sdp->sd_sb.sb_bsize - sizeof(struct gfs2_rgrp);
			bi->bi_offset = sizeof(struct gfs2_rgrp);
			bi->bi_start = 0;
			bi->bi_len = bytes;
			bi->bi_blocks = bytes * GFS2_NBBY;
		/* last block */
		} else if (x + 1 == length) {
			bytes = bytes_left;
			bi->bi_offset = sizeof(struct gfs2_meta_header);
			bi->bi_start = rgd->rd_bitbytes - bytes_left;
			bi->bi_len = bytes;
			bi->bi_blocks = bytes * GFS2_NBBY;
		/* other blocks */
		} else {
			bytes = sdp->sd_sb.sb_bsize -
				sizeof(struct gfs2_meta_header);
			bi->bi_offset = sizeof(struct gfs2_meta_header);
			bi->bi_start = rgd->rd_bitbytes - bytes_left;
			bi->bi_len = bytes;
			bi->bi_blocks = bytes * GFS2_NBBY;
		}

		bytes_left -= bytes;
	}

	if (bytes_left) {
		gfs2_consist_rgrpd(rgd);
		return -EIO;
	}
	bi = rgd->rd_bits + (length - 1);
	if ((bi->bi_start + bi->bi_len) * GFS2_NBBY != rgd->rd_data) {
		if (gfs2_consist_rgrpd(rgd)) {
			gfs2_rindex_print(rgd);
			fs_err(sdp, "start=%u len=%u offset=%u\n",
			       bi->bi_start, bi->bi_len, bi->bi_offset);
		}
		return -EIO;
	}

	return 0;
}

/**
 * gfs2_ri_total - Total up the file system space, according to the rindex.
 * @sdp: the filesystem
 *
 */
u64 gfs2_ri_total(struct gfs2_sbd *sdp)
{
	u64 total_data = 0;
	struct inode *inode = sdp->sd_rindex;
	struct gfs2_inode *ip = GFS2_I(inode);
	char buf[sizeof(struct gfs2_rindex)];
	int error, rgrps;

	for (rgrps = 0;; rgrps++) {
		loff_t pos = rgrps * sizeof(struct gfs2_rindex);

		if (pos + sizeof(struct gfs2_rindex) > i_size_read(inode))
			break;
		error = gfs2_internal_read(ip, buf, &pos,
					   sizeof(struct gfs2_rindex));
		if (error != sizeof(struct gfs2_rindex))
			break;
		total_data += be32_to_cpu(((struct gfs2_rindex *)buf)->ri_data);
	}
	return total_data;
}

static int rgd_insert(struct gfs2_rgrpd *rgd)
{
	struct gfs2_sbd *sdp = rgd->rd_sbd;
	struct rb_node **newn = &sdp->sd_rindex_tree.rb_node, *parent = NULL;

	/* Figure out where to put new node */
	while (*newn) {
		struct gfs2_rgrpd *cur = rb_entry(*newn, struct gfs2_rgrpd,
						  rd_node);

		parent = *newn;
		if (rgd->rd_addr < cur->rd_addr)
			newn = &((*newn)->rb_left);
		else if (rgd->rd_addr > cur->rd_addr)
			newn = &((*newn)->rb_right);
		else
			return -EEXIST;
	}

	rb_link_node(&rgd->rd_node, parent, newn);
	rb_insert_color(&rgd->rd_node, &sdp->sd_rindex_tree);
	sdp->sd_rgrps++;
	return 0;
}

/**
 * read_rindex_entry - Pull in a new resource index entry from the disk
 * @ip: Pointer to the rindex inode
 *
 * Returns: 0 on success, > 0 on EOF, error code otherwise
 */

static int read_rindex_entry(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	const unsigned bsize = sdp->sd_sb.sb_bsize;
	loff_t pos = sdp->sd_rgrps * sizeof(struct gfs2_rindex);
	struct gfs2_rindex buf;
	int error;
	struct gfs2_rgrpd *rgd;

	if (pos >= i_size_read(&ip->i_inode))
		return 1;

	error = gfs2_internal_read(ip, (char *)&buf, &pos,
				   sizeof(struct gfs2_rindex));

	if (error != sizeof(struct gfs2_rindex))
		return (error == 0) ? 1 : error;

	rgd = kmem_cache_zalloc(gfs2_rgrpd_cachep, GFP_NOFS);
	error = -ENOMEM;
	if (!rgd)
		return error;

	rgd->rd_sbd = sdp;
	rgd->rd_addr = be64_to_cpu(buf.ri_addr);
	rgd->rd_length = be32_to_cpu(buf.ri_length);
	rgd->rd_data0 = be64_to_cpu(buf.ri_data0);
	rgd->rd_data = be32_to_cpu(buf.ri_data);
	rgd->rd_bitbytes = be32_to_cpu(buf.ri_bitbytes);
	spin_lock_init(&rgd->rd_rsspin);

	error = compute_bitstructs(rgd);
	if (error)
		goto fail;

	error = gfs2_glock_get(sdp, rgd->rd_addr,
			       &gfs2_rgrp_glops, CREATE, &rgd->rd_gl);
	if (error)
		goto fail;

	rgd->rd_gl->gl_object = rgd;
	rgd->rd_gl->gl_vm.start = rgd->rd_addr * bsize;
	rgd->rd_gl->gl_vm.end = rgd->rd_gl->gl_vm.start + (rgd->rd_length * bsize) - 1;
	rgd->rd_rgl = (struct gfs2_rgrp_lvb *)rgd->rd_gl->gl_lksb.sb_lvbptr;
	rgd->rd_flags &= ~GFS2_RDF_UPTODATE;
	if (rgd->rd_data > sdp->sd_max_rg_data)
		sdp->sd_max_rg_data = rgd->rd_data;
	spin_lock(&sdp->sd_rindex_spin);
	error = rgd_insert(rgd);
	spin_unlock(&sdp->sd_rindex_spin);
	if (!error)
		return 0;

	error = 0; /* someone else read in the rgrp; free it and ignore it */
	gfs2_glock_put(rgd->rd_gl);

fail:
	kfree(rgd->rd_bits);
	kmem_cache_free(gfs2_rgrpd_cachep, rgd);
	return error;
}

/**
 * gfs2_ri_update - Pull in a new resource index from the disk
 * @ip: pointer to the rindex inode
 *
 * Returns: 0 on successful update, error code otherwise
 */

static int gfs2_ri_update(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	int error;

	do {
		error = read_rindex_entry(ip);
	} while (error == 0);

	if (error < 0)
		return error;

	sdp->sd_rindex_uptodate = 1;
	return 0;
}

/**
 * gfs2_rindex_update - Update the rindex if required
 * @sdp: The GFS2 superblock
 *
 * We grab a lock on the rindex inode to make sure that it doesn't
 * change whilst we are performing an operation. We keep this lock
 * for quite long periods of time compared to other locks. This
 * doesn't matter, since it is shared and it is very, very rarely
 * accessed in the exclusive mode (i.e. only when expanding the filesystem).
 *
 * This makes sure that we're using the latest copy of the resource index
 * special file, which might have been updated if someone expanded the
 * filesystem (via gfs2_grow utility), which adds new resource groups.
 *
 * Returns: 0 on succeess, error code otherwise
 */

int gfs2_rindex_update(struct gfs2_sbd *sdp)
{
	struct gfs2_inode *ip = GFS2_I(sdp->sd_rindex);
	struct gfs2_glock *gl = ip->i_gl;
	struct gfs2_holder ri_gh;
	int error = 0;
	int unlock_required = 0;

	/* Read new copy from disk if we don't have the latest */
	if (!sdp->sd_rindex_uptodate) {
		if (!gfs2_glock_is_locked_by_me(gl)) {
			error = gfs2_glock_nq_init(gl, LM_ST_SHARED, 0, &ri_gh);
			if (error)
				return error;
			unlock_required = 1;
		}
		if (!sdp->sd_rindex_uptodate)
			error = gfs2_ri_update(ip);
		if (unlock_required)
			gfs2_glock_dq_uninit(&ri_gh);
	}

	return error;
}

static void gfs2_rgrp_in(struct gfs2_rgrpd *rgd, const void *buf)
{
	const struct gfs2_rgrp *str = buf;
	u32 rg_flags;

	rg_flags = be32_to_cpu(str->rg_flags);
	rg_flags &= ~GFS2_RDF_MASK;
	rgd->rd_flags &= GFS2_RDF_MASK;
	rgd->rd_flags |= rg_flags;
	rgd->rd_free = be32_to_cpu(str->rg_free);
	rgd->rd_dinodes = be32_to_cpu(str->rg_dinodes);
	rgd->rd_igeneration = be64_to_cpu(str->rg_igeneration);
}

static void gfs2_rgrp_out(struct gfs2_rgrpd *rgd, void *buf)
{
	struct gfs2_rgrp *str = buf;

	str->rg_flags = cpu_to_be32(rgd->rd_flags & ~GFS2_RDF_MASK);
	str->rg_free = cpu_to_be32(rgd->rd_free);
	str->rg_dinodes = cpu_to_be32(rgd->rd_dinodes);
	str->__pad = cpu_to_be32(0);
	str->rg_igeneration = cpu_to_be64(rgd->rd_igeneration);
	memset(&str->rg_reserved, 0, sizeof(str->rg_reserved));
}

static int gfs2_rgrp_lvb_valid(struct gfs2_rgrpd *rgd)
{
	struct gfs2_rgrp_lvb *rgl = rgd->rd_rgl;
	struct gfs2_rgrp *str = (struct gfs2_rgrp *)rgd->rd_bits[0].bi_bh->b_data;

	if (rgl->rl_flags != str->rg_flags || rgl->rl_free != str->rg_free ||
	    rgl->rl_dinodes != str->rg_dinodes ||
	    rgl->rl_igeneration != str->rg_igeneration)
		return 0;
	return 1;
}

static void gfs2_rgrp_ondisk2lvb(struct gfs2_rgrp_lvb *rgl, const void *buf)
{
	const struct gfs2_rgrp *str = buf;

	rgl->rl_magic = cpu_to_be32(GFS2_MAGIC);
	rgl->rl_flags = str->rg_flags;
	rgl->rl_free = str->rg_free;
	rgl->rl_dinodes = str->rg_dinodes;
	rgl->rl_igeneration = str->rg_igeneration;
	rgl->__pad = 0UL;
}

static void update_rgrp_lvb_unlinked(struct gfs2_rgrpd *rgd, u32 change)
{
	struct gfs2_rgrp_lvb *rgl = rgd->rd_rgl;
	u32 unlinked = be32_to_cpu(rgl->rl_unlinked) + change;
	rgl->rl_unlinked = cpu_to_be32(unlinked);
}

static u32 count_unlinked(struct gfs2_rgrpd *rgd)
{
	struct gfs2_bitmap *bi;
	const u32 length = rgd->rd_length;
	const u8 *buffer = NULL;
	u32 i, goal, count = 0;

	for (i = 0, bi = rgd->rd_bits; i < length; i++, bi++) {
		goal = 0;
		buffer = bi->bi_bh->b_data + bi->bi_offset;
		WARN_ON(!buffer_uptodate(bi->bi_bh));
		while (goal < bi->bi_len * GFS2_NBBY) {
			goal = gfs2_bitfit(buffer, bi->bi_len, goal,
					   GFS2_BLKST_UNLINKED);
			if (goal == BFITNOENT)
				break;
			count++;
			goal++;
		}
	}

	return count;
}


/**
 * gfs2_rgrp_bh_get - Read in a RG's header and bitmaps
 * @rgd: the struct gfs2_rgrpd describing the RG to read in
 *
 * Read in all of a Resource Group's header and bitmap blocks.
 * Caller must eventually call gfs2_rgrp_relse() to free the bitmaps.
 *
 * Returns: errno
 */

static int gfs2_rgrp_bh_get(struct gfs2_rgrpd *rgd)
{
	struct gfs2_sbd *sdp = rgd->rd_sbd;
	struct gfs2_glock *gl = rgd->rd_gl;
	unsigned int length = rgd->rd_length;
	struct gfs2_bitmap *bi;
	unsigned int x, y;
	int error;

	if (rgd->rd_bits[0].bi_bh != NULL)
		return 0;

	for (x = 0; x < length; x++) {
		bi = rgd->rd_bits + x;
		error = gfs2_meta_read(gl, rgd->rd_addr + x, 0, &bi->bi_bh);
		if (error)
			goto fail;
	}

	for (y = length; y--;) {
		bi = rgd->rd_bits + y;
		error = gfs2_meta_wait(sdp, bi->bi_bh);
		if (error)
			goto fail;
		if (gfs2_metatype_check(sdp, bi->bi_bh, y ? GFS2_METATYPE_RB :
					      GFS2_METATYPE_RG)) {
			error = -EIO;
			goto fail;
		}
	}

	if (!(rgd->rd_flags & GFS2_RDF_UPTODATE)) {
		for (x = 0; x < length; x++)
			clear_bit(GBF_FULL, &rgd->rd_bits[x].bi_flags);
		gfs2_rgrp_in(rgd, (rgd->rd_bits[0].bi_bh)->b_data);
		rgd->rd_flags |= (GFS2_RDF_UPTODATE | GFS2_RDF_CHECK);
		rgd->rd_free_clone = rgd->rd_free;
		/* max out the rgrp allocation failure point */
		rgd->rd_extfail_pt = rgd->rd_free;
	}
	if (cpu_to_be32(GFS2_MAGIC) != rgd->rd_rgl->rl_magic) {
		rgd->rd_rgl->rl_unlinked = cpu_to_be32(count_unlinked(rgd));
		gfs2_rgrp_ondisk2lvb(rgd->rd_rgl,
				     rgd->rd_bits[0].bi_bh->b_data);
	}
	else if (sdp->sd_args.ar_rgrplvb) {
		if (!gfs2_rgrp_lvb_valid(rgd)){
			gfs2_consist_rgrpd(rgd);
			error = -EIO;
			goto fail;
		}
		if (rgd->rd_rgl->rl_unlinked == 0)
			rgd->rd_flags &= ~GFS2_RDF_CHECK;
	}
	return 0;

fail:
	while (x--) {
		bi = rgd->rd_bits + x;
		brelse(bi->bi_bh);
		bi->bi_bh = NULL;
		gfs2_assert_warn(sdp, !bi->bi_clone);
	}

	return error;
}

static int update_rgrp_lvb(struct gfs2_rgrpd *rgd)
{
	u32 rl_flags;

	if (rgd->rd_flags & GFS2_RDF_UPTODATE)
		return 0;

	if (cpu_to_be32(GFS2_MAGIC) != rgd->rd_rgl->rl_magic)
		return gfs2_rgrp_bh_get(rgd);

	rl_flags = be32_to_cpu(rgd->rd_rgl->rl_flags);
	rl_flags &= ~GFS2_RDF_MASK;
	rgd->rd_flags &= GFS2_RDF_MASK;
	rgd->rd_flags |= (rl_flags | GFS2_RDF_UPTODATE | GFS2_RDF_CHECK);
	if (rgd->rd_rgl->rl_unlinked == 0)
		rgd->rd_flags &= ~GFS2_RDF_CHECK;
	rgd->rd_free = be32_to_cpu(rgd->rd_rgl->rl_free);
	rgd->rd_free_clone = rgd->rd_free;
	rgd->rd_dinodes = be32_to_cpu(rgd->rd_rgl->rl_dinodes);
	rgd->rd_igeneration = be64_to_cpu(rgd->rd_rgl->rl_igeneration);
	return 0;
}

int gfs2_rgrp_go_lock(struct gfs2_holder *gh)
{
	struct gfs2_rgrpd *rgd = gh->gh_gl->gl_object;
	struct gfs2_sbd *sdp = rgd->rd_sbd;

	if (gh->gh_flags & GL_SKIP && sdp->sd_args.ar_rgrplvb)
		return 0;
	return gfs2_rgrp_bh_get(rgd);
}

/**
 * gfs2_rgrp_go_unlock - Release RG bitmaps read in with gfs2_rgrp_bh_get()
 * @gh: The glock holder for the resource group
 *
 */

void gfs2_rgrp_go_unlock(struct gfs2_holder *gh)
{
	struct gfs2_rgrpd *rgd = gh->gh_gl->gl_object;
	int x, length = rgd->rd_length;

	for (x = 0; x < length; x++) {
		struct gfs2_bitmap *bi = rgd->rd_bits + x;
		if (bi->bi_bh) {
			brelse(bi->bi_bh);
			bi->bi_bh = NULL;
		}
	}

}

int gfs2_rgrp_send_discards(struct gfs2_sbd *sdp, u64 offset,
			     struct buffer_head *bh,
			     const struct gfs2_bitmap *bi, unsigned minlen, u64 *ptrimmed)
{
	struct super_block *sb = sdp->sd_vfs;
	u64 blk;
	sector_t start = 0;
	sector_t nr_blks = 0;
	int rv;
	unsigned int x;
	u32 trimmed = 0;
	u8 diff;

	for (x = 0; x < bi->bi_len; x++) {
		const u8 *clone = bi->bi_clone ? bi->bi_clone : bi->bi_bh->b_data;
		clone += bi->bi_offset;
		clone += x;
		if (bh) {
			const u8 *orig = bh->b_data + bi->bi_offset + x;
			diff = ~(*orig | (*orig >> 1)) & (*clone | (*clone >> 1));
		} else {
			diff = ~(*clone | (*clone >> 1));
		}
		diff &= 0x55;
		if (diff == 0)
			continue;
		blk = offset + ((bi->bi_start + x) * GFS2_NBBY);
		while(diff) {
			if (diff & 1) {
				if (nr_blks == 0)
					goto start_new_extent;
				if ((start + nr_blks) != blk) {
					if (nr_blks >= minlen) {
						rv = sb_issue_discard(sb,
							start, nr_blks,
							GFP_NOFS, 0);
						if (rv)
							goto fail;
						trimmed += nr_blks;
					}
					nr_blks = 0;
start_new_extent:
					start = blk;
				}
				nr_blks++;
			}
			diff >>= 2;
			blk++;
		}
	}
	if (nr_blks >= minlen) {
		rv = sb_issue_discard(sb, start, nr_blks, GFP_NOFS, 0);
		if (rv)
			goto fail;
		trimmed += nr_blks;
	}
	if (ptrimmed)
		*ptrimmed = trimmed;
	return 0;

fail:
	if (sdp->sd_args.ar_discard)
		fs_warn(sdp, "error %d on discard request, turning discards off for this filesystem", rv);
	sdp->sd_args.ar_discard = 0;
	return -EIO;
}

/**
 * gfs2_fitrim - Generate discard requests for unused bits of the filesystem
 * @filp: Any file on the filesystem
 * @argp: Pointer to the arguments (also used to pass result)
 *
 * Returns: 0 on success, otherwise error code
 */

int gfs2_fitrim(struct file *filp, void __user *argp)
{
	struct inode *inode = file_inode(filp);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct request_queue *q = bdev_get_queue(sdp->sd_vfs->s_bdev);
	struct buffer_head *bh;
	struct gfs2_rgrpd *rgd;
	struct gfs2_rgrpd *rgd_end;
	struct gfs2_holder gh;
	struct fstrim_range r;
	int ret = 0;
	u64 amt;
	u64 trimmed = 0;
	u64 start, end, minlen;
	unsigned int x;
	unsigned bs_shift = sdp->sd_sb.sb_bsize_shift;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!blk_queue_discard(q))
		return -EOPNOTSUPP;

	if (copy_from_user(&r, argp, sizeof(r)))
		return -EFAULT;

	ret = gfs2_rindex_update(sdp);
	if (ret)
		return ret;

	start = r.start >> bs_shift;
	end = start + (r.len >> bs_shift);
	minlen = max_t(u64, r.minlen,
		       q->limits.discard_granularity) >> bs_shift;

	if (end <= start || minlen > sdp->sd_max_rg_data)
		return -EINVAL;

	rgd = gfs2_blk2rgrpd(sdp, start, 0);
	rgd_end = gfs2_blk2rgrpd(sdp, end, 0);

	if ((gfs2_rgrpd_get_first(sdp) == gfs2_rgrpd_get_next(rgd_end))
	    && (start > rgd_end->rd_data0 + rgd_end->rd_data))
		return -EINVAL; /* start is beyond the end of the fs */

	while (1) {

		ret = gfs2_glock_nq_init(rgd->rd_gl, LM_ST_EXCLUSIVE, 0, &gh);
		if (ret)
			goto out;

		if (!(rgd->rd_flags & GFS2_RGF_TRIMMED)) {
			/* Trim each bitmap in the rgrp */
			for (x = 0; x < rgd->rd_length; x++) {
				struct gfs2_bitmap *bi = rgd->rd_bits + x;
				ret = gfs2_rgrp_send_discards(sdp,
						rgd->rd_data0, NULL, bi, minlen,
						&amt);
				if (ret) {
					gfs2_glock_dq_uninit(&gh);
					goto out;
				}
				trimmed += amt;
			}

			/* Mark rgrp as having been trimmed */
			ret = gfs2_trans_begin(sdp, RES_RG_HDR, 0);
			if (ret == 0) {
				bh = rgd->rd_bits[0].bi_bh;
				rgd->rd_flags |= GFS2_RGF_TRIMMED;
				gfs2_trans_add_meta(rgd->rd_gl, bh);
				gfs2_rgrp_out(rgd, bh->b_data);
				gfs2_rgrp_ondisk2lvb(rgd->rd_rgl, bh->b_data);
				gfs2_trans_end(sdp);
			}
		}
		gfs2_glock_dq_uninit(&gh);

		if (rgd == rgd_end)
			break;

		rgd = gfs2_rgrpd_get_next(rgd);
	}

out:
	r.len = trimmed << bs_shift;
	if (copy_to_user(argp, &r, sizeof(r)))
		return -EFAULT;

	return ret;
}

/**
 * rs_insert - insert a new multi-block reservation into the rgrp's rb_tree
 * @ip: the inode structure
 *
 */
static void rs_insert(struct gfs2_inode *ip)
{
	struct rb_node **newn, *parent = NULL;
	int rc;
	struct gfs2_blkreserv *rs = ip->i_res;
	struct gfs2_rgrpd *rgd = rs->rs_rbm.rgd;
	u64 fsblock = gfs2_rbm_to_block(&rs->rs_rbm);

	BUG_ON(gfs2_rs_active(rs));

	spin_lock(&rgd->rd_rsspin);
	newn = &rgd->rd_rstree.rb_node;
	while (*newn) {
		struct gfs2_blkreserv *cur =
			rb_entry(*newn, struct gfs2_blkreserv, rs_node);

		parent = *newn;
		rc = rs_cmp(fsblock, rs->rs_free, cur);
		if (rc > 0)
			newn = &((*newn)->rb_right);
		else if (rc < 0)
			newn = &((*newn)->rb_left);
		else {
			spin_unlock(&rgd->rd_rsspin);
			WARN_ON(1);
			return;
		}
	}

	rb_link_node(&rs->rs_node, parent, newn);
	rb_insert_color(&rs->rs_node, &rgd->rd_rstree);

	/* Do our rgrp accounting for the reservation */
	rgd->rd_reserved += rs->rs_free; /* blocks reserved */
	spin_unlock(&rgd->rd_rsspin);
	trace_gfs2_rs(rs, TRACE_RS_INSERT);
}

/**
 * rg_mblk_search - find a group of multiple free blocks to form a reservation
 * @rgd: the resource group descriptor
 * @ip: pointer to the inode for which we're reserving blocks
 * @ap: the allocation parameters
 *
 */

static void rg_mblk_search(struct gfs2_rgrpd *rgd, struct gfs2_inode *ip,
			   const struct gfs2_alloc_parms *ap)
{
	struct gfs2_rbm rbm = { .rgd = rgd, };
	u64 goal;
	struct gfs2_blkreserv *rs = ip->i_res;
	u32 extlen;
	u32 free_blocks = rgd->rd_free_clone - rgd->rd_reserved;
	int ret;
	struct inode *inode = &ip->i_inode;

	if (S_ISDIR(inode->i_mode))
		extlen = 1;
	else {
		extlen = max_t(u32, atomic_read(&rs->rs_sizehint), ap->target);
		extlen = clamp(extlen, RGRP_RSRV_MINBLKS, free_blocks);
	}
	if ((rgd->rd_free_clone < rgd->rd_reserved) || (free_blocks < extlen))
		return;

	/* Find bitmap block that contains bits for goal block */
	if (rgrp_contains_block(rgd, ip->i_goal))
		goal = ip->i_goal;
	else
		goal = rgd->rd_last_alloc + rgd->rd_data0;

	if (WARN_ON(gfs2_rbm_from_block(&rbm, goal)))
		return;

	ret = gfs2_rbm_find(&rbm, GFS2_BLKST_FREE, &extlen, ip, true, ap);
	if (ret == 0) {
		rs->rs_rbm = rbm;
		rs->rs_free = extlen;
		rs->rs_inum = ip->i_no_addr;
		rs_insert(ip);
	} else {
		if (goal == rgd->rd_last_alloc + rgd->rd_data0)
			rgd->rd_last_alloc = 0;
	}
}

/**
 * gfs2_next_unreserved_block - Return next block that is not reserved
 * @rgd: The resource group
 * @block: The starting block
 * @length: The required length
 * @ip: Ignore any reservations for this inode
 *
 * If the block does not appear in any reservation, then return the
 * block number unchanged. If it does appear in the reservation, then
 * keep looking through the tree of reservations in order to find the
 * first block number which is not reserved.
 */

static u64 gfs2_next_unreserved_block(struct gfs2_rgrpd *rgd, u64 block,
				      u32 length,
				      const struct gfs2_inode *ip)
{
	struct gfs2_blkreserv *rs;
	struct rb_node *n;
	int rc;

	spin_lock(&rgd->rd_rsspin);
	n = rgd->rd_rstree.rb_node;
	while (n) {
		rs = rb_entry(n, struct gfs2_blkreserv, rs_node);
		rc = rs_cmp(block, length, rs);
		if (rc < 0)
			n = n->rb_left;
		else if (rc > 0)
			n = n->rb_right;
		else
			break;
	}

	if (n) {
		while ((rs_cmp(block, length, rs) == 0) && (ip->i_res != rs)) {
			block = gfs2_rbm_to_block(&rs->rs_rbm) + rs->rs_free;
			n = n->rb_right;
			if (n == NULL)
				break;
			rs = rb_entry(n, struct gfs2_blkreserv, rs_node);
		}
	}

	spin_unlock(&rgd->rd_rsspin);
	return block;
}

/**
 * gfs2_reservation_check_and_update - Check for reservations during block alloc
 * @rbm: The current position in the resource group
 * @ip: The inode for which we are searching for blocks
 * @minext: The minimum extent length
 * @maxext: A pointer to the maximum extent structure
 *
 * This checks the current position in the rgrp to see whether there is
 * a reservation covering this block. If not then this function is a
 * no-op. If there is, then the position is moved to the end of the
 * contiguous reservation(s) so that we are pointing at the first
 * non-reserved block.
 *
 * Returns: 0 if no reservation, 1 if @rbm has changed, otherwise an error
 */

static int gfs2_reservation_check_and_update(struct gfs2_rbm *rbm,
					     const struct gfs2_inode *ip,
					     u32 minext,
					     struct gfs2_extent *maxext)
{
	u64 block = gfs2_rbm_to_block(rbm);
	u32 extlen = 1;
	u64 nblock;
	int ret;

	/*
	 * If we have a minimum extent length, then skip over any extent
	 * which is less than the min extent length in size.
	 */
	if (minext) {
		extlen = gfs2_free_extlen(rbm, minext);
		if (extlen <= maxext->len)
			goto fail;
	}

	/*
	 * Check the extent which has been found against the reservations
	 * and skip if parts of it are already reserved
	 */
	nblock = gfs2_next_unreserved_block(rbm->rgd, block, extlen, ip);
	if (nblock == block) {
		if (!minext || extlen >= minext)
			return 0;

		if (extlen > maxext->len) {
			maxext->len = extlen;
			maxext->rbm = *rbm;
		}
fail:
		nblock = block + extlen;
	}
	ret = gfs2_rbm_from_block(rbm, nblock);
	if (ret < 0)
		return ret;
	return 1;
}

/**
 * gfs2_rbm_find - Look for blocks of a particular state
 * @rbm: Value/result starting position and final position
 * @state: The state which we want to find
 * @minext: Pointer to the requested extent length (NULL for a single block)
 *          This is updated to be the actual reservation size.
 * @ip: If set, check for reservations
 * @nowrap: Stop looking at the end of the rgrp, rather than wrapping
 *          around until we've reached the starting point.
 * @ap: the allocation parameters
 *
 * Side effects:
 * - If looking for free blocks, we set GBF_FULL on each bitmap which
 *   has no free blocks in it.
 * - If looking for free blocks, we set rd_extfail_pt on each rgrp which
 *   has come up short on a free block search.
 *
 * Returns: 0 on success, -ENOSPC if there is no block of the requested state
 */

static int gfs2_rbm_find(struct gfs2_rbm *rbm, u8 state, u32 *minext,
			 const struct gfs2_inode *ip, bool nowrap,
			 const struct gfs2_alloc_parms *ap)
{
	struct buffer_head *bh;
	int initial_bii;
	u32 initial_offset;
	int first_bii = rbm->bii;
	u32 first_offset = rbm->offset;
	u32 offset;
	u8 *buffer;
	int n = 0;
	int iters = rbm->rgd->rd_length;
	int ret;
	struct gfs2_bitmap *bi;
	struct gfs2_extent maxext = { .rbm.rgd = rbm->rgd, };

	/* If we are not starting at the beginning of a bitmap, then we
	 * need to add one to the bitmap count to ensure that we search
	 * the starting bitmap twice.
	 */
	if (rbm->offset != 0)
		iters++;

	while(1) {
		bi = rbm_bi(rbm);
		if (test_bit(GBF_FULL, &bi->bi_flags) &&
		    (state == GFS2_BLKST_FREE))
			goto next_bitmap;

		bh = bi->bi_bh;
		buffer = bh->b_data + bi->bi_offset;
		WARN_ON(!buffer_uptodate(bh));
		if (state != GFS2_BLKST_UNLINKED && bi->bi_clone)
			buffer = bi->bi_clone + bi->bi_offset;
		initial_offset = rbm->offset;
		offset = gfs2_bitfit(buffer, bi->bi_len, rbm->offset, state);
		if (offset == BFITNOENT)
			goto bitmap_full;
		rbm->offset = offset;
		if (ip == NULL)
			return 0;

		initial_bii = rbm->bii;
		ret = gfs2_reservation_check_and_update(rbm, ip,
							minext ? *minext : 0,
							&maxext);
		if (ret == 0)
			return 0;
		if (ret > 0) {
			n += (rbm->bii - initial_bii);
			goto next_iter;
		}
		if (ret == -E2BIG) {
			rbm->bii = 0;
			rbm->offset = 0;
			n += (rbm->bii - initial_bii);
			goto res_covered_end_of_rgrp;
		}
		return ret;

bitmap_full:	/* Mark bitmap as full and fall through */
		if ((state == GFS2_BLKST_FREE) && initial_offset == 0) {
			struct gfs2_bitmap *bi = rbm_bi(rbm);
			set_bit(GBF_FULL, &bi->bi_flags);
		}

next_bitmap:	/* Find next bitmap in the rgrp */
		rbm->offset = 0;
		rbm->bii++;
		if (rbm->bii == rbm->rgd->rd_length)
			rbm->bii = 0;
res_covered_end_of_rgrp:
		if ((rbm->bii == 0) && nowrap)
			break;
		n++;
next_iter:
		if (n >= iters)
			break;
	}

	if (minext == NULL || state != GFS2_BLKST_FREE)
		return -ENOSPC;

	/* If the extent was too small, and it's smaller than the smallest
	   to have failed before, remember for future reference that it's
	   useless to search this rgrp again for this amount or more. */
	if ((first_offset == 0) && (first_bii == 0) &&
	    (*minext < rbm->rgd->rd_extfail_pt))
		rbm->rgd->rd_extfail_pt = *minext;

	/* If the maximum extent we found is big enough to fulfill the
	   minimum requirements, use it anyway. */
	if (maxext.len) {
		*rbm = maxext.rbm;
		*minext = maxext.len;
		return 0;
	}

	return -ENOSPC;
}

/**
 * try_rgrp_unlink - Look for any unlinked, allocated, but unused inodes
 * @rgd: The rgrp
 * @last_unlinked: block address of the last dinode we unlinked
 * @skip: block address we should explicitly not unlink
 *
 * Returns: 0 if no error
 *          The inode, if one has been found, in inode.
 */

static void try_rgrp_unlink(struct gfs2_rgrpd *rgd, u64 *last_unlinked, u64 skip)
{
	u64 block;
	struct gfs2_sbd *sdp = rgd->rd_sbd;
	struct gfs2_glock *gl;
	struct gfs2_inode *ip;
	int error;
	int found = 0;
	struct gfs2_rbm rbm = { .rgd = rgd, .bii = 0, .offset = 0 };

	while (1) {
		down_write(&sdp->sd_log_flush_lock);
		error = gfs2_rbm_find(&rbm, GFS2_BLKST_UNLINKED, NULL, NULL,
				      true, NULL);
		up_write(&sdp->sd_log_flush_lock);
		if (error == -ENOSPC)
			break;
		if (WARN_ON_ONCE(error))
			break;

		block = gfs2_rbm_to_block(&rbm);
		if (gfs2_rbm_from_block(&rbm, block + 1))
			break;
		if (*last_unlinked != NO_BLOCK && block <= *last_unlinked)
			continue;
		if (block == skip)
			continue;
		*last_unlinked = block;

		error = gfs2_glock_get(sdp, block, &gfs2_inode_glops, CREATE, &gl);
		if (error)
			continue;

		/* If the inode is already in cache, we can ignore it here
		 * because the existing inode disposal code will deal with
		 * it when all refs have gone away. Accessing gl_object like
		 * this is not safe in general. Here it is ok because we do
		 * not dereference the pointer, and we only need an approx
		 * answer to whether it is NULL or not.
		 */
		ip = gl->gl_object;

		if (ip || queue_work(gfs2_delete_workqueue, &gl->gl_delete) == 0)
			gfs2_glock_put(gl);
		else
			found++;

		/* Limit reclaim to sensible number of tasks */
		if (found > NR_CPUS)
			return;
	}

	rgd->rd_flags &= ~GFS2_RDF_CHECK;
	return;
}

/**
 * gfs2_rgrp_congested - Use stats to figure out whether an rgrp is congested
 * @rgd: The rgrp in question
 * @loops: An indication of how picky we can be (0=very, 1=less so)
 *
 * This function uses the recently added glock statistics in order to
 * figure out whether a parciular resource group is suffering from
 * contention from multiple nodes. This is done purely on the basis
 * of timings, since this is the only data we have to work with and
 * our aim here is to reject a resource group which is highly contended
 * but (very important) not to do this too often in order to ensure that
 * we do not land up introducing fragmentation by changing resource
 * groups when not actually required.
 *
 * The calculation is fairly simple, we want to know whether the SRTTB
 * (i.e. smoothed round trip time for blocking operations) to acquire
 * the lock for this rgrp's glock is significantly greater than the
 * time taken for resource groups on average. We introduce a margin in
 * the form of the variable @var which is computed as the sum of the two
 * respective variences, and multiplied by a factor depending on @loops
 * and whether we have a lot of data to base the decision on. This is
 * then tested against the square difference of the means in order to
 * decide whether the result is statistically significant or not.
 *
 * Returns: A boolean verdict on the congestion status
 */

static bool gfs2_rgrp_congested(const struct gfs2_rgrpd *rgd, int loops)
{
	const struct gfs2_glock *gl = rgd->rd_gl;
	const struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_lkstats *st;
	s64 r_dcount, l_dcount;
	s64 r_srttb, l_srttb;
	s64 srttb_diff;
	s64 sqr_diff;
	s64 var;

	preempt_disable();
	st = &this_cpu_ptr(sdp->sd_lkstats)->lkstats[LM_TYPE_RGRP];
	r_srttb = st->stats[GFS2_LKS_SRTTB];
	r_dcount = st->stats[GFS2_LKS_DCOUNT];
	var = st->stats[GFS2_LKS_SRTTVARB] +
	      gl->gl_stats.stats[GFS2_LKS_SRTTVARB];
	preempt_enable();

	l_srttb = gl->gl_stats.stats[GFS2_LKS_SRTTB];
	l_dcount = gl->gl_stats.stats[GFS2_LKS_DCOUNT];

	if ((l_dcount < 1) || (r_dcount < 1) || (r_srttb == 0))
		return false;

	srttb_diff = r_srttb - l_srttb;
	sqr_diff = srttb_diff * srttb_diff;

	var *= 2;
	if (l_dcount < 8 || r_dcount < 8)
		var *= 2;
	if (loops == 1)
		var *= 2;

	return ((srttb_diff < 0) && (sqr_diff > var));
}

/**
 * gfs2_rgrp_used_recently
 * @rs: The block reservation with the rgrp to test
 * @msecs: The time limit in milliseconds
 *
 * Returns: True if the rgrp glock has been used within the time limit
 */
static bool gfs2_rgrp_used_recently(const struct gfs2_blkreserv *rs,
				    u64 msecs)
{
	u64 tdiff;

	tdiff = ktime_to_ns(ktime_sub(ktime_get_real(),
                            rs->rs_rbm.rgd->rd_gl->gl_dstamp));

	return tdiff > (msecs * 1000 * 1000);
}

static u32 gfs2_orlov_skip(const struct gfs2_inode *ip)
{
	const struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	u32 skip;

	get_random_bytes(&skip, sizeof(skip));
	return skip % sdp->sd_rgrps;
}

static bool gfs2_select_rgrp(struct gfs2_rgrpd **pos, const struct gfs2_rgrpd *begin)
{
	struct gfs2_rgrpd *rgd = *pos;
	struct gfs2_sbd *sdp = rgd->rd_sbd;

	rgd = gfs2_rgrpd_get_next(rgd);
	if (rgd == NULL)
		rgd = gfs2_rgrpd_get_first(sdp);
	*pos = rgd;
	if (rgd != begin) /* If we didn't wrap */
		return true;
	return false;
}

/**
 * gfs2_inplace_reserve - Reserve space in the filesystem
 * @ip: the inode to reserve space for
 * @ap: the allocation parameters
 *
 * Returns: errno
 */

int gfs2_inplace_reserve(struct gfs2_inode *ip, const struct gfs2_alloc_parms *ap)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_rgrpd *begin = NULL;
	struct gfs2_blkreserv *rs = ip->i_res;
	int error = 0, rg_locked, flags = 0;
	u64 last_unlinked = NO_BLOCK;
	int loops = 0;
	u32 skip = 0;

	if (sdp->sd_args.ar_rgrplvb)
		flags |= GL_SKIP;
	if (gfs2_assert_warn(sdp, ap->target))
		return -EINVAL;
	if (gfs2_rs_active(rs)) {
		begin = rs->rs_rbm.rgd;
	} else if (ip->i_rgd && rgrp_contains_block(ip->i_rgd, ip->i_goal)) {
		rs->rs_rbm.rgd = begin = ip->i_rgd;
	} else {
		rs->rs_rbm.rgd = begin = gfs2_blk2rgrpd(sdp, ip->i_goal, 1);
	}
	if (S_ISDIR(ip->i_inode.i_mode) && (ap->aflags & GFS2_AF_ORLOV))
		skip = gfs2_orlov_skip(ip);
	if (rs->rs_rbm.rgd == NULL)
		return -EBADSLT;

	while (loops < 3) {
		rg_locked = 1;

		if (!gfs2_glock_is_locked_by_me(rs->rs_rbm.rgd->rd_gl)) {
			rg_locked = 0;
			if (skip && skip--)
				goto next_rgrp;
			if (!gfs2_rs_active(rs) && (loops < 2) &&
			     gfs2_rgrp_used_recently(rs, 1000) &&
			     gfs2_rgrp_congested(rs->rs_rbm.rgd, loops))
				goto next_rgrp;
			error = gfs2_glock_nq_init(rs->rs_rbm.rgd->rd_gl,
						   LM_ST_EXCLUSIVE, flags,
						   &rs->rs_rgd_gh);
			if (unlikely(error))
				return error;
			if (!gfs2_rs_active(rs) && (loops < 2) &&
			    gfs2_rgrp_congested(rs->rs_rbm.rgd, loops))
				goto skip_rgrp;
			if (sdp->sd_args.ar_rgrplvb) {
				error = update_rgrp_lvb(rs->rs_rbm.rgd);
				if (unlikely(error)) {
					gfs2_glock_dq_uninit(&rs->rs_rgd_gh);
					return error;
				}
			}
		}

		/* Skip unuseable resource groups */
		if ((rs->rs_rbm.rgd->rd_flags & (GFS2_RGF_NOALLOC |
						 GFS2_RDF_ERROR)) ||
		    (ap->target > rs->rs_rbm.rgd->rd_extfail_pt))
			goto skip_rgrp;

		if (sdp->sd_args.ar_rgrplvb)
			gfs2_rgrp_bh_get(rs->rs_rbm.rgd);

		/* Get a reservation if we don't already have one */
		if (!gfs2_rs_active(rs))
			rg_mblk_search(rs->rs_rbm.rgd, ip, ap);

		/* Skip rgrps when we can't get a reservation on first pass */
		if (!gfs2_rs_active(rs) && (loops < 1))
			goto check_rgrp;

		/* If rgrp has enough free space, use it */
		if (rs->rs_rbm.rgd->rd_free_clone >= ap->target) {
			ip->i_rgd = rs->rs_rbm.rgd;
			return 0;
		}

check_rgrp:
		/* Check for unlinked inodes which can be reclaimed */
		if (rs->rs_rbm.rgd->rd_flags & GFS2_RDF_CHECK)
			try_rgrp_unlink(rs->rs_rbm.rgd, &last_unlinked,
					ip->i_no_addr);
skip_rgrp:
		/* Drop reservation, if we couldn't use reserved rgrp */
		if (gfs2_rs_active(rs))
			gfs2_rs_deltree(rs);

		/* Unlock rgrp if required */
		if (!rg_locked)
			gfs2_glock_dq_uninit(&rs->rs_rgd_gh);
next_rgrp:
		/* Find the next rgrp, and continue looking */
		if (gfs2_select_rgrp(&rs->rs_rbm.rgd, begin))
			continue;
		if (skip)
			continue;

		/* If we've scanned all the rgrps, but found no free blocks
		 * then this checks for some less likely conditions before
		 * trying again.
		 */
		loops++;
		/* Check that fs hasn't grown if writing to rindex */
		if (ip == GFS2_I(sdp->sd_rindex) && !sdp->sd_rindex_uptodate) {
			error = gfs2_ri_update(ip);
			if (error)
				return error;
		}
		/* Flushing the log may release space */
		if (loops == 2)
			gfs2_log_flush(sdp, NULL, NORMAL_FLUSH);
	}

	return -ENOSPC;
}

/**
 * gfs2_inplace_release - release an inplace reservation
 * @ip: the inode the reservation was taken out on
 *
 * Release a reservation made by gfs2_inplace_reserve().
 */

void gfs2_inplace_release(struct gfs2_inode *ip)
{
	struct gfs2_blkreserv *rs = ip->i_res;

	if (rs->rs_rgd_gh.gh_gl)
		gfs2_glock_dq_uninit(&rs->rs_rgd_gh);
}

/**
 * gfs2_get_block_type - Check a block in a RG is of given type
 * @rgd: the resource group holding the block
 * @block: the block number
 *
 * Returns: The block type (GFS2_BLKST_*)
 */

static unsigned char gfs2_get_block_type(struct gfs2_rgrpd *rgd, u64 block)
{
	struct gfs2_rbm rbm = { .rgd = rgd, };
	int ret;

	ret = gfs2_rbm_from_block(&rbm, block);
	WARN_ON_ONCE(ret != 0);

	return gfs2_testbit(&rbm);
}


/**
 * gfs2_alloc_extent - allocate an extent from a given bitmap
 * @rbm: the resource group information
 * @dinode: TRUE if the first block we allocate is for a dinode
 * @n: The extent length (value/result)
 *
 * Add the bitmap buffer to the transaction.
 * Set the found bits to @new_state to change block's allocation state.
 */
static void gfs2_alloc_extent(const struct gfs2_rbm *rbm, bool dinode,
			     unsigned int *n)
{
	struct gfs2_rbm pos = { .rgd = rbm->rgd, };
	const unsigned int elen = *n;
	u64 block;
	int ret;

	*n = 1;
	block = gfs2_rbm_to_block(rbm);
	gfs2_trans_add_meta(rbm->rgd->rd_gl, rbm_bi(rbm)->bi_bh);
	gfs2_setbit(rbm, true, dinode ? GFS2_BLKST_DINODE : GFS2_BLKST_USED);
	block++;
	while (*n < elen) {
		ret = gfs2_rbm_from_block(&pos, block);
		if (ret || gfs2_testbit(&pos) != GFS2_BLKST_FREE)
			break;
		gfs2_trans_add_meta(pos.rgd->rd_gl, rbm_bi(&pos)->bi_bh);
		gfs2_setbit(&pos, true, GFS2_BLKST_USED);
		(*n)++;
		block++;
	}
}

/**
 * rgblk_free - Change alloc state of given block(s)
 * @sdp: the filesystem
 * @bstart: the start of a run of blocks to free
 * @blen: the length of the block run (all must lie within ONE RG!)
 * @new_state: GFS2_BLKST_XXX the after-allocation block state
 *
 * Returns:  Resource group containing the block(s)
 */

static struct gfs2_rgrpd *rgblk_free(struct gfs2_sbd *sdp, u64 bstart,
				     u32 blen, unsigned char new_state)
{
	struct gfs2_rbm rbm;
	struct gfs2_bitmap *bi;

	rbm.rgd = gfs2_blk2rgrpd(sdp, bstart, 1);
	if (!rbm.rgd) {
		if (gfs2_consist(sdp))
			fs_err(sdp, "block = %llu\n", (unsigned long long)bstart);
		return NULL;
	}

	while (blen--) {
		gfs2_rbm_from_block(&rbm, bstart);
		bi = rbm_bi(&rbm);
		bstart++;
		if (!bi->bi_clone) {
			bi->bi_clone = kmalloc(bi->bi_bh->b_size,
					       GFP_NOFS | __GFP_NOFAIL);
			memcpy(bi->bi_clone + bi->bi_offset,
			       bi->bi_bh->b_data + bi->bi_offset, bi->bi_len);
		}
		gfs2_trans_add_meta(rbm.rgd->rd_gl, bi->bi_bh);
		gfs2_setbit(&rbm, false, new_state);
	}

	return rbm.rgd;
}

/**
 * gfs2_rgrp_dump - print out an rgrp
 * @seq: The iterator
 * @gl: The glock in question
 *
 */

void gfs2_rgrp_dump(struct seq_file *seq, const struct gfs2_glock *gl)
{
	struct gfs2_rgrpd *rgd = gl->gl_object;
	struct gfs2_blkreserv *trs;
	const struct rb_node *n;

	if (rgd == NULL)
		return;
	gfs2_print_dbg(seq, " R: n:%llu f:%02x b:%u/%u i:%u r:%u e:%u\n",
		       (unsigned long long)rgd->rd_addr, rgd->rd_flags,
		       rgd->rd_free, rgd->rd_free_clone, rgd->rd_dinodes,
		       rgd->rd_reserved, rgd->rd_extfail_pt);
	spin_lock(&rgd->rd_rsspin);
	for (n = rb_first(&rgd->rd_rstree); n; n = rb_next(&trs->rs_node)) {
		trs = rb_entry(n, struct gfs2_blkreserv, rs_node);
		dump_rs(seq, trs);
	}
	spin_unlock(&rgd->rd_rsspin);
}

static void gfs2_rgrp_error(struct gfs2_rgrpd *rgd)
{
	struct gfs2_sbd *sdp = rgd->rd_sbd;
	fs_warn(sdp, "rgrp %llu has an error, marking it readonly until umount\n",
		(unsigned long long)rgd->rd_addr);
	fs_warn(sdp, "umount on all nodes and run fsck.gfs2 to fix the error\n");
	gfs2_rgrp_dump(NULL, rgd->rd_gl);
	rgd->rd_flags |= GFS2_RDF_ERROR;
}

/**
 * gfs2_adjust_reservation - Adjust (or remove) a reservation after allocation
 * @ip: The inode we have just allocated blocks for
 * @rbm: The start of the allocated blocks
 * @len: The extent length
 *
 * Adjusts a reservation after an allocation has taken place. If the
 * reservation does not match the allocation, or if it is now empty
 * then it is removed.
 */

static void gfs2_adjust_reservation(struct gfs2_inode *ip,
				    const struct gfs2_rbm *rbm, unsigned len)
{
	struct gfs2_blkreserv *rs = ip->i_res;
	struct gfs2_rgrpd *rgd = rbm->rgd;
	unsigned rlen;
	u64 block;
	int ret;

	spin_lock(&rgd->rd_rsspin);
	if (gfs2_rs_active(rs)) {
		if (gfs2_rbm_eq(&rs->rs_rbm, rbm)) {
			block = gfs2_rbm_to_block(rbm);
			ret = gfs2_rbm_from_block(&rs->rs_rbm, block + len);
			rlen = min(rs->rs_free, len);
			rs->rs_free -= rlen;
			rgd->rd_reserved -= rlen;
			trace_gfs2_rs(rs, TRACE_RS_CLAIM);
			if (rs->rs_free && !ret)
				goto out;
		}
		__rs_deltree(rs);
	}
out:
	spin_unlock(&rgd->rd_rsspin);
}

/**
 * gfs2_set_alloc_start - Set starting point for block allocation
 * @rbm: The rbm which will be set to the required location
 * @ip: The gfs2 inode
 * @dinode: Flag to say if allocation includes a new inode
 *
 * This sets the starting point from the reservation if one is active
 * otherwise it falls back to guessing a start point based on the
 * inode's goal block or the last allocation point in the rgrp.
 */

static void gfs2_set_alloc_start(struct gfs2_rbm *rbm,
				 const struct gfs2_inode *ip, bool dinode)
{
	u64 goal;

	if (gfs2_rs_active(ip->i_res)) {
		*rbm = ip->i_res->rs_rbm;
		return;
	}

	if (!dinode && rgrp_contains_block(rbm->rgd, ip->i_goal))
		goal = ip->i_goal;
	else
		goal = rbm->rgd->rd_last_alloc + rbm->rgd->rd_data0;

	gfs2_rbm_from_block(rbm, goal);
}

/**
 * gfs2_alloc_blocks - Allocate one or more blocks of data and/or a dinode
 * @ip: the inode to allocate the block for
 * @bn: Used to return the starting block number
 * @nblocks: requested number of blocks/extent length (value/result)
 * @dinode: 1 if we're allocating a dinode block, else 0
 * @generation: the generation number of the inode
 *
 * Returns: 0 or error
 */

int gfs2_alloc_blocks(struct gfs2_inode *ip, u64 *bn, unsigned int *nblocks,
		      bool dinode, u64 *generation)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct buffer_head *dibh;
	struct gfs2_rbm rbm = { .rgd = ip->i_rgd, };
	unsigned int ndata;
	u64 block; /* block, within the file system scope */
	int error;

	gfs2_set_alloc_start(&rbm, ip, dinode);
	error = gfs2_rbm_find(&rbm, GFS2_BLKST_FREE, NULL, ip, false, NULL);

	if (error == -ENOSPC) {
		gfs2_set_alloc_start(&rbm, ip, dinode);
		error = gfs2_rbm_find(&rbm, GFS2_BLKST_FREE, NULL, NULL, false,
				      NULL);
	}

	/* Since all blocks are reserved in advance, this shouldn't happen */
	if (error) {
		fs_warn(sdp, "inum=%llu error=%d, nblocks=%u, full=%d fail_pt=%d\n",
			(unsigned long long)ip->i_no_addr, error, *nblocks,
			test_bit(GBF_FULL, &rbm.rgd->rd_bits->bi_flags),
			rbm.rgd->rd_extfail_pt);
		goto rgrp_error;
	}

	gfs2_alloc_extent(&rbm, dinode, nblocks);
	block = gfs2_rbm_to_block(&rbm);
	rbm.rgd->rd_last_alloc = block - rbm.rgd->rd_data0;
	if (gfs2_rs_active(ip->i_res))
		gfs2_adjust_reservation(ip, &rbm, *nblocks);
	ndata = *nblocks;
	if (dinode)
		ndata--;

	if (!dinode) {
		ip->i_goal = block + ndata - 1;
		error = gfs2_meta_inode_buffer(ip, &dibh);
		if (error == 0) {
			struct gfs2_dinode *di =
				(struct gfs2_dinode *)dibh->b_data;
			gfs2_trans_add_meta(ip->i_gl, dibh);
			di->di_goal_meta = di->di_goal_data =
				cpu_to_be64(ip->i_goal);
			brelse(dibh);
		}
	}
	if (rbm.rgd->rd_free < *nblocks) {
		pr_warn("nblocks=%u\n", *nblocks);
		goto rgrp_error;
	}

	rbm.rgd->rd_free -= *nblocks;
	if (dinode) {
		rbm.rgd->rd_dinodes++;
		*generation = rbm.rgd->rd_igeneration++;
		if (*generation == 0)
			*generation = rbm.rgd->rd_igeneration++;
	}

	gfs2_trans_add_meta(rbm.rgd->rd_gl, rbm.rgd->rd_bits[0].bi_bh);
	gfs2_rgrp_out(rbm.rgd, rbm.rgd->rd_bits[0].bi_bh->b_data);
	gfs2_rgrp_ondisk2lvb(rbm.rgd->rd_rgl, rbm.rgd->rd_bits[0].bi_bh->b_data);

	gfs2_statfs_change(sdp, 0, -(s64)*nblocks, dinode ? 1 : 0);
	if (dinode)
		gfs2_trans_add_unrevoke(sdp, block, *nblocks);

	gfs2_quota_change(ip, *nblocks, ip->i_inode.i_uid, ip->i_inode.i_gid);

	rbm.rgd->rd_free_clone -= *nblocks;
	trace_gfs2_block_alloc(ip, rbm.rgd, block, *nblocks,
			       dinode ? GFS2_BLKST_DINODE : GFS2_BLKST_USED);
	*bn = block;
	return 0;

rgrp_error:
	gfs2_rgrp_error(rbm.rgd);
	return -EIO;
}

/**
 * __gfs2_free_blocks - free a contiguous run of block(s)
 * @ip: the inode these blocks are being freed from
 * @bstart: first block of a run of contiguous blocks
 * @blen: the length of the block run
 * @meta: 1 if the blocks represent metadata
 *
 */

void __gfs2_free_blocks(struct gfs2_inode *ip, u64 bstart, u32 blen, int meta)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_rgrpd *rgd;

	rgd = rgblk_free(sdp, bstart, blen, GFS2_BLKST_FREE);
	if (!rgd)
		return;
	trace_gfs2_block_alloc(ip, rgd, bstart, blen, GFS2_BLKST_FREE);
	rgd->rd_free += blen;
	rgd->rd_flags &= ~GFS2_RGF_TRIMMED;
	gfs2_trans_add_meta(rgd->rd_gl, rgd->rd_bits[0].bi_bh);
	gfs2_rgrp_out(rgd, rgd->rd_bits[0].bi_bh->b_data);
	gfs2_rgrp_ondisk2lvb(rgd->rd_rgl, rgd->rd_bits[0].bi_bh->b_data);

	/* Directories keep their data in the metadata address space */
	if (meta || ip->i_depth)
		gfs2_meta_wipe(ip, bstart, blen);
}

/**
 * gfs2_free_meta - free a contiguous run of data block(s)
 * @ip: the inode these blocks are being freed from
 * @bstart: first block of a run of contiguous blocks
 * @blen: the length of the block run
 *
 */

void gfs2_free_meta(struct gfs2_inode *ip, u64 bstart, u32 blen)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);

	__gfs2_free_blocks(ip, bstart, blen, 1);
	gfs2_statfs_change(sdp, 0, +blen, 0);
	gfs2_quota_change(ip, -(s64)blen, ip->i_inode.i_uid, ip->i_inode.i_gid);
}

void gfs2_unlink_di(struct inode *inode)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_rgrpd *rgd;
	u64 blkno = ip->i_no_addr;

	rgd = rgblk_free(sdp, blkno, 1, GFS2_BLKST_UNLINKED);
	if (!rgd)
		return;
	trace_gfs2_block_alloc(ip, rgd, blkno, 1, GFS2_BLKST_UNLINKED);
	gfs2_trans_add_meta(rgd->rd_gl, rgd->rd_bits[0].bi_bh);
	gfs2_rgrp_out(rgd, rgd->rd_bits[0].bi_bh->b_data);
	gfs2_rgrp_ondisk2lvb(rgd->rd_rgl, rgd->rd_bits[0].bi_bh->b_data);
	update_rgrp_lvb_unlinked(rgd, 1);
}

static void gfs2_free_uninit_di(struct gfs2_rgrpd *rgd, u64 blkno)
{
	struct gfs2_sbd *sdp = rgd->rd_sbd;
	struct gfs2_rgrpd *tmp_rgd;

	tmp_rgd = rgblk_free(sdp, blkno, 1, GFS2_BLKST_FREE);
	if (!tmp_rgd)
		return;
	gfs2_assert_withdraw(sdp, rgd == tmp_rgd);

	if (!rgd->rd_dinodes)
		gfs2_consist_rgrpd(rgd);
	rgd->rd_dinodes--;
	rgd->rd_free++;

	gfs2_trans_add_meta(rgd->rd_gl, rgd->rd_bits[0].bi_bh);
	gfs2_rgrp_out(rgd, rgd->rd_bits[0].bi_bh->b_data);
	gfs2_rgrp_ondisk2lvb(rgd->rd_rgl, rgd->rd_bits[0].bi_bh->b_data);
	update_rgrp_lvb_unlinked(rgd, -1);

	gfs2_statfs_change(sdp, 0, +1, -1);
}


void gfs2_free_di(struct gfs2_rgrpd *rgd, struct gfs2_inode *ip)
{
	gfs2_free_uninit_di(rgd, ip->i_no_addr);
	trace_gfs2_block_alloc(ip, rgd, ip->i_no_addr, 1, GFS2_BLKST_FREE);
	gfs2_quota_change(ip, -1, ip->i_inode.i_uid, ip->i_inode.i_gid);
	gfs2_meta_wipe(ip, ip->i_no_addr, 1);
}

/**
 * gfs2_check_blk_type - Check the type of a block
 * @sdp: The superblock
 * @no_addr: The block number to check
 * @type: The block type we are looking for
 *
 * Returns: 0 if the block type matches the expected type
 *          -ESTALE if it doesn't match
 *          or -ve errno if something went wrong while checking
 */

int gfs2_check_blk_type(struct gfs2_sbd *sdp, u64 no_addr, unsigned int type)
{
	struct gfs2_rgrpd *rgd;
	struct gfs2_holder rgd_gh;
	int error = -EINVAL;

	rgd = gfs2_blk2rgrpd(sdp, no_addr, 1);
	if (!rgd)
		goto fail;

	error = gfs2_glock_nq_init(rgd->rd_gl, LM_ST_SHARED, 0, &rgd_gh);
	if (error)
		goto fail;

	if (gfs2_get_block_type(rgd, no_addr) != type)
		error = -ESTALE;

	gfs2_glock_dq_uninit(&rgd_gh);
fail:
	return error;
}

/**
 * gfs2_rlist_add - add a RG to a list of RGs
 * @ip: the inode
 * @rlist: the list of resource groups
 * @block: the block
 *
 * Figure out what RG a block belongs to and add that RG to the list
 *
 * FIXME: Don't use NOFAIL
 *
 */

void gfs2_rlist_add(struct gfs2_inode *ip, struct gfs2_rgrp_list *rlist,
		    u64 block)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_rgrpd *rgd;
	struct gfs2_rgrpd **tmp;
	unsigned int new_space;
	unsigned int x;

	if (gfs2_assert_warn(sdp, !rlist->rl_ghs))
		return;

	if (ip->i_rgd && rgrp_contains_block(ip->i_rgd, block))
		rgd = ip->i_rgd;
	else
		rgd = gfs2_blk2rgrpd(sdp, block, 1);
	if (!rgd) {
		fs_err(sdp, "rlist_add: no rgrp for block %llu\n", (unsigned long long)block);
		return;
	}
	ip->i_rgd = rgd;

	for (x = 0; x < rlist->rl_rgrps; x++)
		if (rlist->rl_rgd[x] == rgd)
			return;

	if (rlist->rl_rgrps == rlist->rl_space) {
		new_space = rlist->rl_space + 10;

		tmp = kcalloc(new_space, sizeof(struct gfs2_rgrpd *),
			      GFP_NOFS | __GFP_NOFAIL);

		if (rlist->rl_rgd) {
			memcpy(tmp, rlist->rl_rgd,
			       rlist->rl_space * sizeof(struct gfs2_rgrpd *));
			kfree(rlist->rl_rgd);
		}

		rlist->rl_space = new_space;
		rlist->rl_rgd = tmp;
	}

	rlist->rl_rgd[rlist->rl_rgrps++] = rgd;
}

/**
 * gfs2_rlist_alloc - all RGs have been added to the rlist, now allocate
 *      and initialize an array of glock holders for them
 * @rlist: the list of resource groups
 * @state: the lock state to acquire the RG lock in
 *
 * FIXME: Don't use NOFAIL
 *
 */

void gfs2_rlist_alloc(struct gfs2_rgrp_list *rlist, unsigned int state)
{
	unsigned int x;

	rlist->rl_ghs = kcalloc(rlist->rl_rgrps, sizeof(struct gfs2_holder),
				GFP_NOFS | __GFP_NOFAIL);
	for (x = 0; x < rlist->rl_rgrps; x++)
		gfs2_holder_init(rlist->rl_rgd[x]->rd_gl,
				state, 0,
				&rlist->rl_ghs[x]);
}

/**
 * gfs2_rlist_free - free a resource group list
 * @rlist: the list of resource groups
 *
 */

void gfs2_rlist_free(struct gfs2_rgrp_list *rlist)
{
	unsigned int x;

	kfree(rlist->rl_rgd);

	if (rlist->rl_ghs) {
		for (x = 0; x < rlist->rl_rgrps; x++)
			gfs2_holder_uninit(&rlist->rl_ghs[x]);
		kfree(rlist->rl_ghs);
		rlist->rl_ghs = NULL;
	}
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/super.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2007 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/bio.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
#include <linux/statfs.h>
// #include <linux/seq_file.h>
// #include <linux/mount.h>
// #include <linux/kthread.h>
// #include <linux/delay.h>
// #include <linux/gfs2_ondisk.h>
// #include <linux/crc32.h>
#include <linux/time.h>
// #include <linux/wait.h>
// #include <linux/writeback.h>
// #include <linux/backing-dev.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "bmap.h"
// #include "dir.h"
// #include "glock.h"
// #include "glops.h"
// #include "inode.h"
// #include "log.h"
// #include "meta_io.h"
// #include "quota.h"
// #include "recovery.h"
// #include "rgrp.h"
// #include "super.h"
// #include "trans.h"
// #include "util.h"
// #include "sys.h"
// #include "xattr.h"

#define args_neq(a1, a2, x) ((a1)->ar_##x != (a2)->ar_##x)

enum {
	Opt_lockproto,
	Opt_locktable,
	Opt_hostdata,
	Opt_spectator,
	Opt_ignore_local_fs,
	Opt_localflocks,
	Opt_localcaching,
	Opt_debug,
	Opt_nodebug,
	Opt_upgrade,
	Opt_acl,
	Opt_noacl,
	Opt_quota_off,
	Opt_quota_account,
	Opt_quota_on,
	Opt_quota,
	Opt_noquota,
	Opt_suiddir,
	Opt_nosuiddir,
	Opt_data_writeback,
	Opt_data_ordered,
	Opt_meta,
	Opt_discard,
	Opt_nodiscard,
	Opt_commit,
	Opt_err_withdraw,
	Opt_err_panic,
	Opt_statfs_quantum,
	Opt_statfs_percent,
	Opt_quota_quantum,
	Opt_barrier,
	Opt_nobarrier,
	Opt_rgrplvb,
	Opt_norgrplvb,
	Opt_error,
};

static const match_table_t tokens = {
	{Opt_lockproto, "lockproto=%s"},
	{Opt_locktable, "locktable=%s"},
	{Opt_hostdata, "hostdata=%s"},
	{Opt_spectator, "spectator"},
	{Opt_spectator, "norecovery"},
	{Opt_ignore_local_fs, "ignore_local_fs"},
	{Opt_localflocks, "localflocks"},
	{Opt_localcaching, "localcaching"},
	{Opt_debug, "debug"},
	{Opt_nodebug, "nodebug"},
	{Opt_upgrade, "upgrade"},
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_quota_off, "quota=off"},
	{Opt_quota_account, "quota=account"},
	{Opt_quota_on, "quota=on"},
	{Opt_quota, "quota"},
	{Opt_noquota, "noquota"},
	{Opt_suiddir, "suiddir"},
	{Opt_nosuiddir, "nosuiddir"},
	{Opt_data_writeback, "data=writeback"},
	{Opt_data_ordered, "data=ordered"},
	{Opt_meta, "meta"},
	{Opt_discard, "discard"},
	{Opt_nodiscard, "nodiscard"},
	{Opt_commit, "commit=%d"},
	{Opt_err_withdraw, "errors=withdraw"},
	{Opt_err_panic, "errors=panic"},
	{Opt_statfs_quantum, "statfs_quantum=%d"},
	{Opt_statfs_percent, "statfs_percent=%d"},
	{Opt_quota_quantum, "quota_quantum=%d"},
	{Opt_barrier, "barrier"},
	{Opt_nobarrier, "nobarrier"},
	{Opt_rgrplvb, "rgrplvb"},
	{Opt_norgrplvb, "norgrplvb"},
	{Opt_error, NULL}
};

/**
 * gfs2_mount_args - Parse mount options
 * @args: The structure into which the parsed options will be written
 * @options: The options to parse
 *
 * Return: errno
 */

int gfs2_mount_args(struct gfs2_args *args, char *options)
{
	char *o;
	int token;
	substring_t tmp[MAX_OPT_ARGS];
	int rv;

	/* Split the options into tokens with the "," character and
	   process them */

	while (1) {
		o = strsep(&options, ",");
		if (o == NULL)
			break;
		if (*o == '\0')
			continue;

		token = match_token(o, tokens, tmp);
		switch (token) {
		case Opt_lockproto:
			match_strlcpy(args->ar_lockproto, &tmp[0],
				      GFS2_LOCKNAME_LEN);
			break;
		case Opt_locktable:
			match_strlcpy(args->ar_locktable, &tmp[0],
				      GFS2_LOCKNAME_LEN);
			break;
		case Opt_hostdata:
			match_strlcpy(args->ar_hostdata, &tmp[0],
				      GFS2_LOCKNAME_LEN);
			break;
		case Opt_spectator:
			args->ar_spectator = 1;
			break;
		case Opt_ignore_local_fs:
			/* Retained for backwards compat only */
			break;
		case Opt_localflocks:
			args->ar_localflocks = 1;
			break;
		case Opt_localcaching:
			/* Retained for backwards compat only */
			break;
		case Opt_debug:
			if (args->ar_errors == GFS2_ERRORS_PANIC) {
				pr_warn("-o debug and -o errors=panic are mutually exclusive\n");
				return -EINVAL;
			}
			args->ar_debug = 1;
			break;
		case Opt_nodebug:
			args->ar_debug = 0;
			break;
		case Opt_upgrade:
			/* Retained for backwards compat only */
			break;
		case Opt_acl:
			args->ar_posix_acl = 1;
			break;
		case Opt_noacl:
			args->ar_posix_acl = 0;
			break;
		case Opt_quota_off:
		case Opt_noquota:
			args->ar_quota = GFS2_QUOTA_OFF;
			break;
		case Opt_quota_account:
			args->ar_quota = GFS2_QUOTA_ACCOUNT;
			break;
		case Opt_quota_on:
		case Opt_quota:
			args->ar_quota = GFS2_QUOTA_ON;
			break;
		case Opt_suiddir:
			args->ar_suiddir = 1;
			break;
		case Opt_nosuiddir:
			args->ar_suiddir = 0;
			break;
		case Opt_data_writeback:
			args->ar_data = GFS2_DATA_WRITEBACK;
			break;
		case Opt_data_ordered:
			args->ar_data = GFS2_DATA_ORDERED;
			break;
		case Opt_meta:
			args->ar_meta = 1;
			break;
		case Opt_discard:
			args->ar_discard = 1;
			break;
		case Opt_nodiscard:
			args->ar_discard = 0;
			break;
		case Opt_commit:
			rv = match_int(&tmp[0], &args->ar_commit);
			if (rv || args->ar_commit <= 0) {
				pr_warn("commit mount option requires a positive numeric argument\n");
				return rv ? rv : -EINVAL;
			}
			break;
		case Opt_statfs_quantum:
			rv = match_int(&tmp[0], &args->ar_statfs_quantum);
			if (rv || args->ar_statfs_quantum < 0) {
				pr_warn("statfs_quantum mount option requires a non-negative numeric argument\n");
				return rv ? rv : -EINVAL;
			}
			break;
		case Opt_quota_quantum:
			rv = match_int(&tmp[0], &args->ar_quota_quantum);
			if (rv || args->ar_quota_quantum <= 0) {
				pr_warn("quota_quantum mount option requires a positive numeric argument\n");
				return rv ? rv : -EINVAL;
			}
			break;
		case Opt_statfs_percent:
			rv = match_int(&tmp[0], &args->ar_statfs_percent);
			if (rv || args->ar_statfs_percent < 0 ||
			    args->ar_statfs_percent > 100) {
				pr_warn("statfs_percent mount option requires a numeric argument between 0 and 100\n");
				return rv ? rv : -EINVAL;
			}
			break;
		case Opt_err_withdraw:
			args->ar_errors = GFS2_ERRORS_WITHDRAW;
			break;
		case Opt_err_panic:
			if (args->ar_debug) {
				pr_warn("-o debug and -o errors=panic are mutually exclusive\n");
				return -EINVAL;
			}
			args->ar_errors = GFS2_ERRORS_PANIC;
			break;
		case Opt_barrier:
			args->ar_nobarrier = 0;
			break;
		case Opt_nobarrier:
			args->ar_nobarrier = 1;
			break;
		case Opt_rgrplvb:
			args->ar_rgrplvb = 1;
			break;
		case Opt_norgrplvb:
			args->ar_rgrplvb = 0;
			break;
		case Opt_error:
		default:
			pr_warn("invalid mount option: %s\n", o);
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * gfs2_jindex_free - Clear all the journal index information
 * @sdp: The GFS2 superblock
 *
 */

void gfs2_jindex_free(struct gfs2_sbd *sdp)
{
	struct list_head list;
	struct gfs2_jdesc *jd;

	spin_lock(&sdp->sd_jindex_spin);
	list_add(&list, &sdp->sd_jindex_list);
	list_del_init(&sdp->sd_jindex_list);
	sdp->sd_journals = 0;
	spin_unlock(&sdp->sd_jindex_spin);

	while (!list_empty(&list)) {
		jd = list_entry(list.next, struct gfs2_jdesc, jd_list);
		gfs2_free_journal_extents(jd);
		list_del(&jd->jd_list);
		iput(jd->jd_inode);
		kfree(jd);
	}
}

static struct gfs2_jdesc *jdesc_find_i(struct list_head *head, unsigned int jid)
{
	struct gfs2_jdesc *jd;
	int found = 0;

	list_for_each_entry(jd, head, jd_list) {
		if (jd->jd_jid == jid) {
			found = 1;
			break;
		}
	}

	if (!found)
		jd = NULL;

	return jd;
}

struct gfs2_jdesc *gfs2_jdesc_find(struct gfs2_sbd *sdp, unsigned int jid)
{
	struct gfs2_jdesc *jd;

	spin_lock(&sdp->sd_jindex_spin);
	jd = jdesc_find_i(&sdp->sd_jindex_list, jid);
	spin_unlock(&sdp->sd_jindex_spin);

	return jd;
}

int gfs2_jdesc_check(struct gfs2_jdesc *jd)
{
	struct gfs2_inode *ip = GFS2_I(jd->jd_inode);
	struct gfs2_sbd *sdp = GFS2_SB(jd->jd_inode);
	u64 size = i_size_read(jd->jd_inode);

	if (gfs2_check_internal_file_size(jd->jd_inode, 8 << 20, 1 << 30))
		return -EIO;

	jd->jd_blocks = size >> sdp->sd_sb.sb_bsize_shift;

	if (gfs2_write_alloc_required(ip, 0, size)) {
		gfs2_consist_inode(ip);
		return -EIO;
	}

	return 0;
}

static int init_threads(struct gfs2_sbd *sdp)
{
	struct task_struct *p;
	int error = 0;

	p = kthread_run(gfs2_logd, sdp, "gfs2_logd");
	if (IS_ERR(p)) {
		error = PTR_ERR(p);
		fs_err(sdp, "can't start logd thread: %d\n", error);
		return error;
	}
	sdp->sd_logd_process = p;

	p = kthread_run(gfs2_quotad, sdp, "gfs2_quotad");
	if (IS_ERR(p)) {
		error = PTR_ERR(p);
		fs_err(sdp, "can't start quotad thread: %d\n", error);
		goto fail;
	}
	sdp->sd_quotad_process = p;
	return 0;

fail:
	kthread_stop(sdp->sd_logd_process);
	return error;
}

/**
 * gfs2_make_fs_rw - Turn a Read-Only FS into a Read-Write one
 * @sdp: the filesystem
 *
 * Returns: errno
 */

int gfs2_make_fs_rw(struct gfs2_sbd *sdp)
{
	struct gfs2_inode *ip = GFS2_I(sdp->sd_jdesc->jd_inode);
	struct gfs2_glock *j_gl = ip->i_gl;
	struct gfs2_holder thaw_gh;
	struct gfs2_log_header_host head;
	int error;

	error = init_threads(sdp);
	if (error)
		return error;

	error = gfs2_glock_nq_init(sdp->sd_freeze_gl, LM_ST_SHARED, 0,
				   &thaw_gh);
	if (error)
		goto fail_threads;

	j_gl->gl_ops->go_inval(j_gl, DIO_METADATA);

	error = gfs2_find_jhead(sdp->sd_jdesc, &head);
	if (error)
		goto fail;

	if (!(head.lh_flags & GFS2_LOG_HEAD_UNMOUNT)) {
		gfs2_consist(sdp);
		error = -EIO;
		goto fail;
	}

	/*  Initialize some head of the log stuff  */
	sdp->sd_log_sequence = head.lh_sequence + 1;
	gfs2_log_pointers_init(sdp, head.lh_blkno);

	error = gfs2_quota_init(sdp);
	if (error)
		goto fail;

	set_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags);

	gfs2_glock_dq_uninit(&thaw_gh);

	return 0;

fail:
	thaw_gh.gh_flags |= GL_NOCACHE;
	gfs2_glock_dq_uninit(&thaw_gh);
fail_threads:
	kthread_stop(sdp->sd_quotad_process);
	kthread_stop(sdp->sd_logd_process);
	return error;
}

void gfs2_statfs_change_in(struct gfs2_statfs_change_host *sc, const void *buf)
{
	const struct gfs2_statfs_change *str = buf;

	sc->sc_total = be64_to_cpu(str->sc_total);
	sc->sc_free = be64_to_cpu(str->sc_free);
	sc->sc_dinodes = be64_to_cpu(str->sc_dinodes);
}

static void gfs2_statfs_change_out(const struct gfs2_statfs_change_host *sc, void *buf)
{
	struct gfs2_statfs_change *str = buf;

	str->sc_total = cpu_to_be64(sc->sc_total);
	str->sc_free = cpu_to_be64(sc->sc_free);
	str->sc_dinodes = cpu_to_be64(sc->sc_dinodes);
}

int gfs2_statfs_init(struct gfs2_sbd *sdp)
{
	struct gfs2_inode *m_ip = GFS2_I(sdp->sd_statfs_inode);
	struct gfs2_statfs_change_host *m_sc = &sdp->sd_statfs_master;
	struct gfs2_inode *l_ip = GFS2_I(sdp->sd_sc_inode);
	struct gfs2_statfs_change_host *l_sc = &sdp->sd_statfs_local;
	struct buffer_head *m_bh, *l_bh;
	struct gfs2_holder gh;
	int error;

	error = gfs2_glock_nq_init(m_ip->i_gl, LM_ST_EXCLUSIVE, GL_NOCACHE,
				   &gh);
	if (error)
		return error;

	error = gfs2_meta_inode_buffer(m_ip, &m_bh);
	if (error)
		goto out;

	if (sdp->sd_args.ar_spectator) {
		spin_lock(&sdp->sd_statfs_spin);
		gfs2_statfs_change_in(m_sc, m_bh->b_data +
				      sizeof(struct gfs2_dinode));
		spin_unlock(&sdp->sd_statfs_spin);
	} else {
		error = gfs2_meta_inode_buffer(l_ip, &l_bh);
		if (error)
			goto out_m_bh;

		spin_lock(&sdp->sd_statfs_spin);
		gfs2_statfs_change_in(m_sc, m_bh->b_data +
				      sizeof(struct gfs2_dinode));
		gfs2_statfs_change_in(l_sc, l_bh->b_data +
				      sizeof(struct gfs2_dinode));
		spin_unlock(&sdp->sd_statfs_spin);

		brelse(l_bh);
	}

out_m_bh:
	brelse(m_bh);
out:
	gfs2_glock_dq_uninit(&gh);
	return 0;
}

void gfs2_statfs_change(struct gfs2_sbd *sdp, s64 total, s64 free,
			s64 dinodes)
{
	struct gfs2_inode *l_ip = GFS2_I(sdp->sd_sc_inode);
	struct gfs2_statfs_change_host *l_sc = &sdp->sd_statfs_local;
	struct gfs2_statfs_change_host *m_sc = &sdp->sd_statfs_master;
	struct buffer_head *l_bh;
	s64 x, y;
	int need_sync = 0;
	int error;

	error = gfs2_meta_inode_buffer(l_ip, &l_bh);
	if (error)
		return;

	gfs2_trans_add_meta(l_ip->i_gl, l_bh);

	spin_lock(&sdp->sd_statfs_spin);
	l_sc->sc_total += total;
	l_sc->sc_free += free;
	l_sc->sc_dinodes += dinodes;
	gfs2_statfs_change_out(l_sc, l_bh->b_data + sizeof(struct gfs2_dinode));
	if (sdp->sd_args.ar_statfs_percent) {
		x = 100 * l_sc->sc_free;
		y = m_sc->sc_free * sdp->sd_args.ar_statfs_percent;
		if (x >= y || x <= -y)
			need_sync = 1;
	}
	spin_unlock(&sdp->sd_statfs_spin);

	brelse(l_bh);
	if (need_sync)
		gfs2_wake_up_statfs(sdp);
}

void update_statfs(struct gfs2_sbd *sdp, struct buffer_head *m_bh,
		   struct buffer_head *l_bh)
{
	struct gfs2_inode *m_ip = GFS2_I(sdp->sd_statfs_inode);
	struct gfs2_inode *l_ip = GFS2_I(sdp->sd_sc_inode);
	struct gfs2_statfs_change_host *m_sc = &sdp->sd_statfs_master;
	struct gfs2_statfs_change_host *l_sc = &sdp->sd_statfs_local;

	gfs2_trans_add_meta(l_ip->i_gl, l_bh);

	spin_lock(&sdp->sd_statfs_spin);
	m_sc->sc_total += l_sc->sc_total;
	m_sc->sc_free += l_sc->sc_free;
	m_sc->sc_dinodes += l_sc->sc_dinodes;
	memset(l_sc, 0, sizeof(struct gfs2_statfs_change));
	memset(l_bh->b_data + sizeof(struct gfs2_dinode),
	       0, sizeof(struct gfs2_statfs_change));
	spin_unlock(&sdp->sd_statfs_spin);

	gfs2_trans_add_meta(m_ip->i_gl, m_bh);
	gfs2_statfs_change_out(m_sc, m_bh->b_data + sizeof(struct gfs2_dinode));
}

int gfs2_statfs_sync(struct super_block *sb, int type)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct gfs2_inode *m_ip = GFS2_I(sdp->sd_statfs_inode);
	struct gfs2_inode *l_ip = GFS2_I(sdp->sd_sc_inode);
	struct gfs2_statfs_change_host *m_sc = &sdp->sd_statfs_master;
	struct gfs2_statfs_change_host *l_sc = &sdp->sd_statfs_local;
	struct gfs2_holder gh;
	struct buffer_head *m_bh, *l_bh;
	int error;

	error = gfs2_glock_nq_init(m_ip->i_gl, LM_ST_EXCLUSIVE, GL_NOCACHE,
				   &gh);
	if (error)
		return error;

	error = gfs2_meta_inode_buffer(m_ip, &m_bh);
	if (error)
		goto out;

	spin_lock(&sdp->sd_statfs_spin);
	gfs2_statfs_change_in(m_sc, m_bh->b_data +
			      sizeof(struct gfs2_dinode));
	if (!l_sc->sc_total && !l_sc->sc_free && !l_sc->sc_dinodes) {
		spin_unlock(&sdp->sd_statfs_spin);
		goto out_bh;
	}
	spin_unlock(&sdp->sd_statfs_spin);

	error = gfs2_meta_inode_buffer(l_ip, &l_bh);
	if (error)
		goto out_bh;

	error = gfs2_trans_begin(sdp, 2 * RES_DINODE, 0);
	if (error)
		goto out_bh2;

	update_statfs(sdp, m_bh, l_bh);
	sdp->sd_statfs_force_sync = 0;

	gfs2_trans_end(sdp);

out_bh2:
	brelse(l_bh);
out_bh:
	brelse(m_bh);
out:
	gfs2_glock_dq_uninit(&gh);
	return error;
}

struct lfcc {
	struct list_head list;
	struct gfs2_holder gh;
};

/**
 * gfs2_lock_fs_check_clean - Stop all writes to the FS and check that all
 *                            journals are clean
 * @sdp: the file system
 * @state: the state to put the transaction lock into
 * @t_gh: the hold on the transaction lock
 *
 * Returns: errno
 */

static int gfs2_lock_fs_check_clean(struct gfs2_sbd *sdp,
				    struct gfs2_holder *freeze_gh)
{
	struct gfs2_inode *ip;
	struct gfs2_jdesc *jd;
	struct lfcc *lfcc;
	LIST_HEAD(list);
	struct gfs2_log_header_host lh;
	struct gfs2_inode *dip = GFS2_I(sdp->sd_root_dir->d_inode);
	int error;

	error = gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED, 0,
				   &sdp->sd_freeze_root_gh);
	if (error)
		return error;
	atomic_set(&sdp->sd_frozen_root, 1);
	list_for_each_entry(jd, &sdp->sd_jindex_list, jd_list) {
		lfcc = kmalloc(sizeof(struct lfcc), GFP_KERNEL);
		if (!lfcc) {
			error = -ENOMEM;
			goto out;
		}
		ip = GFS2_I(jd->jd_inode);
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &lfcc->gh);
		if (error) {
			kfree(lfcc);
			goto out;
		}
		list_add(&lfcc->list, &list);
	}

	error = gfs2_glock_nq_init(sdp->sd_freeze_gl, LM_ST_EXCLUSIVE,
				   GL_NOCACHE, freeze_gh);

	list_for_each_entry(jd, &sdp->sd_jindex_list, jd_list) {
		error = gfs2_jdesc_check(jd);
		if (error)
			break;
		error = gfs2_find_jhead(jd, &lh);
		if (error)
			break;
		if (!(lh.lh_flags & GFS2_LOG_HEAD_UNMOUNT)) {
			error = -EBUSY;
			break;
		}
	}

	if (error)
		gfs2_glock_dq_uninit(freeze_gh);

out:
	while (!list_empty(&list)) {
		lfcc = list_entry(list.next, struct lfcc, list);
		list_del(&lfcc->list);
		gfs2_glock_dq_uninit(&lfcc->gh);
		kfree(lfcc);
	}
	if (error) {
		atomic_dec(&sdp->sd_frozen_root);
		wait_event(sdp->sd_frozen_root_wait, atomic_read(&sdp->sd_frozen_root) == 0);
		gfs2_glock_dq_uninit(&sdp->sd_freeze_root_gh);
	}
	return error;
}

void gfs2_dinode_out(const struct gfs2_inode *ip, void *buf)
{
	struct gfs2_dinode *str = buf;

	str->di_header.mh_magic = cpu_to_be32(GFS2_MAGIC);
	str->di_header.mh_type = cpu_to_be32(GFS2_METATYPE_DI);
	str->di_header.mh_format = cpu_to_be32(GFS2_FORMAT_DI);
	str->di_num.no_addr = cpu_to_be64(ip->i_no_addr);
	str->di_num.no_formal_ino = cpu_to_be64(ip->i_no_formal_ino);
	str->di_mode = cpu_to_be32(ip->i_inode.i_mode);
	str->di_uid = cpu_to_be32(i_uid_read(&ip->i_inode));
	str->di_gid = cpu_to_be32(i_gid_read(&ip->i_inode));
	str->di_nlink = cpu_to_be32(ip->i_inode.i_nlink);
	str->di_size = cpu_to_be64(i_size_read(&ip->i_inode));
	str->di_blocks = cpu_to_be64(gfs2_get_inode_blocks(&ip->i_inode));
	str->di_atime = cpu_to_be64(ip->i_inode.i_atime.tv_sec);
	str->di_mtime = cpu_to_be64(ip->i_inode.i_mtime.tv_sec);
	str->di_ctime = cpu_to_be64(ip->i_inode.i_ctime.tv_sec);

	str->di_goal_meta = cpu_to_be64(ip->i_goal);
	str->di_goal_data = cpu_to_be64(ip->i_goal);
	str->di_generation = cpu_to_be64(ip->i_generation);

	str->di_flags = cpu_to_be32(ip->i_diskflags);
	str->di_height = cpu_to_be16(ip->i_height);
	str->di_payload_format = cpu_to_be32(S_ISDIR(ip->i_inode.i_mode) &&
					     !(ip->i_diskflags & GFS2_DIF_EXHASH) ?
					     GFS2_FORMAT_DE : 0);
	str->di_depth = cpu_to_be16(ip->i_depth);
	str->di_entries = cpu_to_be32(ip->i_entries);

	str->di_eattr = cpu_to_be64(ip->i_eattr);
	str->di_atime_nsec = cpu_to_be32(ip->i_inode.i_atime.tv_nsec);
	str->di_mtime_nsec = cpu_to_be32(ip->i_inode.i_mtime.tv_nsec);
	str->di_ctime_nsec = cpu_to_be32(ip->i_inode.i_ctime.tv_nsec);
}

/**
 * gfs2_write_inode - Make sure the inode is stable on the disk
 * @inode: The inode
 * @wbc: The writeback control structure
 *
 * Returns: errno
 */

static int gfs2_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct address_space *metamapping = gfs2_glock2aspace(ip->i_gl);
	struct backing_dev_info *bdi = metamapping->backing_dev_info;
	int ret = 0;

	if (wbc->sync_mode == WB_SYNC_ALL)
		gfs2_log_flush(GFS2_SB(inode), ip->i_gl, NORMAL_FLUSH);
	if (bdi->dirty_exceeded)
		gfs2_ail1_flush(sdp, wbc);
	else
		filemap_fdatawrite(metamapping);
	if (wbc->sync_mode == WB_SYNC_ALL)
		ret = filemap_fdatawait(metamapping);
	if (ret)
		mark_inode_dirty_sync(inode);
	return ret;
}

/**
 * gfs2_dirty_inode - check for atime updates
 * @inode: The inode in question
 * @flags: The type of dirty
 *
 * Unfortunately it can be called under any combination of inode
 * glock and transaction lock, so we have to check carefully.
 *
 * At the moment this deals only with atime - it should be possible
 * to expand that role in future, once a review of the locking has
 * been carried out.
 */

static void gfs2_dirty_inode(struct inode *inode, int flags)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct buffer_head *bh;
	struct gfs2_holder gh;
	int need_unlock = 0;
	int need_endtrans = 0;
	int ret;

	if (!(flags & (I_DIRTY_DATASYNC|I_DIRTY_SYNC)))
		return;

	if (!gfs2_glock_is_locked_by_me(ip->i_gl)) {
		ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
		if (ret) {
			fs_err(sdp, "dirty_inode: glock %d\n", ret);
			return;
		}
		need_unlock = 1;
	} else if (WARN_ON_ONCE(ip->i_gl->gl_state != LM_ST_EXCLUSIVE))
		return;

	if (current->journal_info == NULL) {
		ret = gfs2_trans_begin(sdp, RES_DINODE, 0);
		if (ret) {
			fs_err(sdp, "dirty_inode: gfs2_trans_begin %d\n", ret);
			goto out;
		}
		need_endtrans = 1;
	}

	ret = gfs2_meta_inode_buffer(ip, &bh);
	if (ret == 0) {
		gfs2_trans_add_meta(ip->i_gl, bh);
		gfs2_dinode_out(ip, bh->b_data);
		brelse(bh);
	}

	if (need_endtrans)
		gfs2_trans_end(sdp);
out:
	if (need_unlock)
		gfs2_glock_dq_uninit(&gh);
}

/**
 * gfs2_make_fs_ro - Turn a Read-Write FS into a Read-Only one
 * @sdp: the filesystem
 *
 * Returns: errno
 */

static int gfs2_make_fs_ro(struct gfs2_sbd *sdp)
{
	struct gfs2_holder thaw_gh;
	int error;

	error = gfs2_glock_nq_init(sdp->sd_freeze_gl, LM_ST_SHARED, GL_NOCACHE,
				   &thaw_gh);
	if (error && !test_bit(SDF_SHUTDOWN, &sdp->sd_flags))
		return error;

	down_write(&sdp->sd_log_flush_lock);
	clear_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags);
	up_write(&sdp->sd_log_flush_lock);

	kthread_stop(sdp->sd_quotad_process);
	kthread_stop(sdp->sd_logd_process);

	flush_workqueue(gfs2_delete_workqueue);
	gfs2_quota_sync(sdp->sd_vfs, 0);
	gfs2_statfs_sync(sdp->sd_vfs, 0);

	gfs2_log_flush(sdp, NULL, SHUTDOWN_FLUSH);
	gfs2_assert_warn(sdp, atomic_read(&sdp->sd_log_blks_free) == sdp->sd_jdesc->jd_blocks);

	if (thaw_gh.gh_gl)
		gfs2_glock_dq_uninit(&thaw_gh);

	gfs2_quota_cleanup(sdp);

	return error;
}

/**
 * gfs2_put_super - Unmount the filesystem
 * @sb: The VFS superblock
 *
 */

static void gfs2_put_super(struct super_block *sb)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	int error;
	struct gfs2_jdesc *jd;

	/* No more recovery requests */
	set_bit(SDF_NORECOVERY, &sdp->sd_flags);
	smp_mb();

	/* Wait on outstanding recovery */
restart:
	spin_lock(&sdp->sd_jindex_spin);
	list_for_each_entry(jd, &sdp->sd_jindex_list, jd_list) {
		if (!test_bit(JDF_RECOVERY, &jd->jd_flags))
			continue;
		spin_unlock(&sdp->sd_jindex_spin);
		wait_on_bit(&jd->jd_flags, JDF_RECOVERY,
			    TASK_UNINTERRUPTIBLE);
		goto restart;
	}
	spin_unlock(&sdp->sd_jindex_spin);

	if (!(sb->s_flags & MS_RDONLY)) {
		error = gfs2_make_fs_ro(sdp);
		if (error)
			gfs2_io_error(sdp);
	}
	/*  At this point, we're through modifying the disk  */

	/*  Release stuff  */

	iput(sdp->sd_jindex);
	iput(sdp->sd_statfs_inode);
	iput(sdp->sd_rindex);
	iput(sdp->sd_quota_inode);

	gfs2_glock_put(sdp->sd_rename_gl);
	gfs2_glock_put(sdp->sd_freeze_gl);

	if (!sdp->sd_args.ar_spectator) {
		gfs2_glock_dq_uninit(&sdp->sd_journal_gh);
		gfs2_glock_dq_uninit(&sdp->sd_jinode_gh);
		gfs2_glock_dq_uninit(&sdp->sd_sc_gh);
		gfs2_glock_dq_uninit(&sdp->sd_qc_gh);
		iput(sdp->sd_sc_inode);
		iput(sdp->sd_qc_inode);
	}

	gfs2_glock_dq_uninit(&sdp->sd_live_gh);
	gfs2_clear_rgrpd(sdp);
	gfs2_jindex_free(sdp);
	/*  Take apart glock structures and buffer lists  */
	gfs2_gl_hash_clear(sdp);
	/*  Unmount the locking protocol  */
	gfs2_lm_unmount(sdp);

	/*  At this point, we're through participating in the lockspace  */
	gfs2_sys_fs_del(sdp);
}

/**
 * gfs2_sync_fs - sync the filesystem
 * @sb: the superblock
 *
 * Flushes the log to disk.
 */

static int gfs2_sync_fs(struct super_block *sb, int wait)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;

	gfs2_quota_sync(sb, -1);
	if (wait && sdp && !atomic_read(&sdp->sd_log_freeze))
		gfs2_log_flush(sdp, NULL, NORMAL_FLUSH);
	return 0;
}

/**
 * gfs2_freeze - prevent further writes to the filesystem
 * @sb: the VFS structure for the filesystem
 *
 */

static int gfs2_freeze(struct super_block *sb)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	int error;

	if (test_bit(SDF_SHUTDOWN, &sdp->sd_flags))
		return -EINVAL;

	for (;;) {
		error = gfs2_lock_fs_check_clean(sdp, &sdp->sd_freeze_gh);
		if (!error)
			break;

		switch (error) {
		case -EBUSY:
			fs_err(sdp, "waiting for recovery before freeze\n");
			break;

		default:
			fs_err(sdp, "error freezing FS: %d\n", error);
			break;
		}

		fs_err(sdp, "retrying...\n");
		msleep(1000);
	}
	return 0;
}

/**
 * gfs2_unfreeze - reallow writes to the filesystem
 * @sb: the VFS structure for the filesystem
 *
 */

static int gfs2_unfreeze(struct super_block *sb)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;

	gfs2_glock_dq_uninit(&sdp->sd_freeze_gh);
	atomic_dec(&sdp->sd_frozen_root);
	wait_event(sdp->sd_frozen_root_wait, atomic_read(&sdp->sd_frozen_root) == 0);
	gfs2_glock_dq_uninit(&sdp->sd_freeze_root_gh);
	return 0;
}

/**
 * statfs_fill - fill in the sg for a given RG
 * @rgd: the RG
 * @sc: the sc structure
 *
 * Returns: 0 on success, -ESTALE if the LVB is invalid
 */

static int statfs_slow_fill(struct gfs2_rgrpd *rgd,
			    struct gfs2_statfs_change_host *sc)
{
	gfs2_rgrp_verify(rgd);
	sc->sc_total += rgd->rd_data;
	sc->sc_free += rgd->rd_free;
	sc->sc_dinodes += rgd->rd_dinodes;
	return 0;
}

/**
 * gfs2_statfs_slow - Stat a filesystem using asynchronous locking
 * @sdp: the filesystem
 * @sc: the sc info that will be returned
 *
 * Any error (other than a signal) will cause this routine to fall back
 * to the synchronous version.
 *
 * FIXME: This really shouldn't busy wait like this.
 *
 * Returns: errno
 */

static int gfs2_statfs_slow(struct gfs2_sbd *sdp, struct gfs2_statfs_change_host *sc)
{
	struct gfs2_rgrpd *rgd_next;
	struct gfs2_holder *gha, *gh;
	unsigned int slots = 64;
	unsigned int x;
	int done;
	int error = 0, err;

	memset(sc, 0, sizeof(struct gfs2_statfs_change_host));
	gha = kcalloc(slots, sizeof(struct gfs2_holder), GFP_KERNEL);
	if (!gha)
		return -ENOMEM;

	rgd_next = gfs2_rgrpd_get_first(sdp);

	for (;;) {
		done = 1;

		for (x = 0; x < slots; x++) {
			gh = gha + x;

			if (gh->gh_gl && gfs2_glock_poll(gh)) {
				err = gfs2_glock_wait(gh);
				if (err) {
					gfs2_holder_uninit(gh);
					error = err;
				} else {
					if (!error)
						error = statfs_slow_fill(
							gh->gh_gl->gl_object, sc);
					gfs2_glock_dq_uninit(gh);
				}
			}

			if (gh->gh_gl)
				done = 0;
			else if (rgd_next && !error) {
				error = gfs2_glock_nq_init(rgd_next->rd_gl,
							   LM_ST_SHARED,
							   GL_ASYNC,
							   gh);
				rgd_next = gfs2_rgrpd_get_next(rgd_next);
				done = 0;
			}

			if (signal_pending(current))
				error = -ERESTARTSYS;
		}

		if (done)
			break;

		yield();
	}

	kfree(gha);
	return error;
}

/**
 * gfs2_statfs_i - Do a statfs
 * @sdp: the filesystem
 * @sg: the sg structure
 *
 * Returns: errno
 */

static int gfs2_statfs_i(struct gfs2_sbd *sdp, struct gfs2_statfs_change_host *sc)
{
	struct gfs2_statfs_change_host *m_sc = &sdp->sd_statfs_master;
	struct gfs2_statfs_change_host *l_sc = &sdp->sd_statfs_local;

	spin_lock(&sdp->sd_statfs_spin);

	*sc = *m_sc;
	sc->sc_total += l_sc->sc_total;
	sc->sc_free += l_sc->sc_free;
	sc->sc_dinodes += l_sc->sc_dinodes;

	spin_unlock(&sdp->sd_statfs_spin);

	if (sc->sc_free < 0)
		sc->sc_free = 0;
	if (sc->sc_free > sc->sc_total)
		sc->sc_free = sc->sc_total;
	if (sc->sc_dinodes < 0)
		sc->sc_dinodes = 0;

	return 0;
}

/**
 * gfs2_statfs - Gather and return stats about the filesystem
 * @sb: The superblock
 * @statfsbuf: The buffer
 *
 * Returns: 0 on success or error code
 */

static int gfs2_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_inode->i_sb;
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct gfs2_statfs_change_host sc;
	int error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	if (gfs2_tune_get(sdp, gt_statfs_slow))
		error = gfs2_statfs_slow(sdp, &sc);
	else
		error = gfs2_statfs_i(sdp, &sc);

	if (error)
		return error;

	buf->f_type = GFS2_MAGIC;
	buf->f_bsize = sdp->sd_sb.sb_bsize;
	buf->f_blocks = sc.sc_total;
	buf->f_bfree = sc.sc_free;
	buf->f_bavail = sc.sc_free;
	buf->f_files = sc.sc_dinodes + sc.sc_free;
	buf->f_ffree = sc.sc_free;
	buf->f_namelen = GFS2_FNAMESIZE;

	return 0;
}

/**
 * gfs2_remount_fs - called when the FS is remounted
 * @sb:  the filesystem
 * @flags:  the remount flags
 * @data:  extra data passed in (not used right now)
 *
 * Returns: errno
 */

static int gfs2_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct gfs2_args args = sdp->sd_args; /* Default to current settings */
	struct gfs2_tune *gt = &sdp->sd_tune;
	int error;

	sync_filesystem(sb);

	spin_lock(&gt->gt_spin);
	args.ar_commit = gt->gt_logd_secs;
	args.ar_quota_quantum = gt->gt_quota_quantum;
	if (gt->gt_statfs_slow)
		args.ar_statfs_quantum = 0;
	else
		args.ar_statfs_quantum = gt->gt_statfs_quantum;
	spin_unlock(&gt->gt_spin);
	error = gfs2_mount_args(&args, data);
	if (error)
		return error;

	/* Not allowed to change locking details */
	if (strcmp(args.ar_lockproto, sdp->sd_args.ar_lockproto) ||
	    strcmp(args.ar_locktable, sdp->sd_args.ar_locktable) ||
	    strcmp(args.ar_hostdata, sdp->sd_args.ar_hostdata))
		return -EINVAL;

	/* Some flags must not be changed */
	if (args_neq(&args, &sdp->sd_args, spectator) ||
	    args_neq(&args, &sdp->sd_args, localflocks) ||
	    args_neq(&args, &sdp->sd_args, meta))
		return -EINVAL;

	if (sdp->sd_args.ar_spectator)
		*flags |= MS_RDONLY;

	if ((sb->s_flags ^ *flags) & MS_RDONLY) {
		if (*flags & MS_RDONLY)
			error = gfs2_make_fs_ro(sdp);
		else
			error = gfs2_make_fs_rw(sdp);
		if (error)
			return error;
	}

	sdp->sd_args = args;
	if (sdp->sd_args.ar_posix_acl)
		sb->s_flags |= MS_POSIXACL;
	else
		sb->s_flags &= ~MS_POSIXACL;
	if (sdp->sd_args.ar_nobarrier)
		set_bit(SDF_NOBARRIERS, &sdp->sd_flags);
	else
		clear_bit(SDF_NOBARRIERS, &sdp->sd_flags);
	spin_lock(&gt->gt_spin);
	gt->gt_logd_secs = args.ar_commit;
	gt->gt_quota_quantum = args.ar_quota_quantum;
	if (args.ar_statfs_quantum) {
		gt->gt_statfs_slow = 0;
		gt->gt_statfs_quantum = args.ar_statfs_quantum;
	}
	else {
		gt->gt_statfs_slow = 1;
		gt->gt_statfs_quantum = 30;
	}
	spin_unlock(&gt->gt_spin);

	gfs2_online_uevent(sdp);
	return 0;
}

/**
 * gfs2_drop_inode - Drop an inode (test for remote unlink)
 * @inode: The inode to drop
 *
 * If we've received a callback on an iopen lock then its because a
 * remote node tried to deallocate the inode but failed due to this node
 * still having the inode open. Here we mark the link count zero
 * since we know that it must have reached zero if the GLF_DEMOTE flag
 * is set on the iopen glock. If we didn't do a disk read since the
 * remote node removed the final link then we might otherwise miss
 * this event. This check ensures that this node will deallocate the
 * inode's blocks, or alternatively pass the baton on to another
 * node for later deallocation.
 */

static int gfs2_drop_inode(struct inode *inode)
{
	struct gfs2_inode *ip = GFS2_I(inode);

	if (!test_bit(GIF_FREE_VFS_INODE, &ip->i_flags) && inode->i_nlink) {
		struct gfs2_glock *gl = ip->i_iopen_gh.gh_gl;
		if (gl && test_bit(GLF_DEMOTE, &gl->gl_flags))
			clear_nlink(inode);
	}
	return generic_drop_inode(inode);
}

static int is_ancestor(const struct dentry *d1, const struct dentry *d2)
{
	do {
		if (d1 == d2)
			return 1;
		d1 = d1->d_parent;
	} while (!IS_ROOT(d1));
	return 0;
}

/**
 * gfs2_show_options - Show mount options for /proc/mounts
 * @s: seq_file structure
 * @root: root of this (sub)tree
 *
 * Returns: 0 on success or error code
 */

static int gfs2_show_options(struct seq_file *s, struct dentry *root)
{
	struct gfs2_sbd *sdp = root->d_sb->s_fs_info;
	struct gfs2_args *args = &sdp->sd_args;
	int val;

	if (is_ancestor(root, sdp->sd_master_dir))
		seq_printf(s, ",meta");
	if (args->ar_lockproto[0])
		seq_printf(s, ",lockproto=%s", args->ar_lockproto);
	if (args->ar_locktable[0])
		seq_printf(s, ",locktable=%s", args->ar_locktable);
	if (args->ar_hostdata[0])
		seq_printf(s, ",hostdata=%s", args->ar_hostdata);
	if (args->ar_spectator)
		seq_printf(s, ",spectator");
	if (args->ar_localflocks)
		seq_printf(s, ",localflocks");
	if (args->ar_debug)
		seq_printf(s, ",debug");
	if (args->ar_posix_acl)
		seq_printf(s, ",acl");
	if (args->ar_quota != GFS2_QUOTA_DEFAULT) {
		char *state;
		switch (args->ar_quota) {
		case GFS2_QUOTA_OFF:
			state = "off";
			break;
		case GFS2_QUOTA_ACCOUNT:
			state = "account";
			break;
		case GFS2_QUOTA_ON:
			state = "on";
			break;
		default:
			state = "unknown";
			break;
		}
		seq_printf(s, ",quota=%s", state);
	}
	if (args->ar_suiddir)
		seq_printf(s, ",suiddir");
	if (args->ar_data != GFS2_DATA_DEFAULT) {
		char *state;
		switch (args->ar_data) {
		case GFS2_DATA_WRITEBACK:
			state = "writeback";
			break;
		case GFS2_DATA_ORDERED:
			state = "ordered";
			break;
		default:
			state = "unknown";
			break;
		}
		seq_printf(s, ",data=%s", state);
	}
	if (args->ar_discard)
		seq_printf(s, ",discard");
	val = sdp->sd_tune.gt_logd_secs;
	if (val != 30)
		seq_printf(s, ",commit=%d", val);
	val = sdp->sd_tune.gt_statfs_quantum;
	if (val != 30)
		seq_printf(s, ",statfs_quantum=%d", val);
	else if (sdp->sd_tune.gt_statfs_slow)
		seq_puts(s, ",statfs_quantum=0");
	val = sdp->sd_tune.gt_quota_quantum;
	if (val != 60)
		seq_printf(s, ",quota_quantum=%d", val);
	if (args->ar_statfs_percent)
		seq_printf(s, ",statfs_percent=%d", args->ar_statfs_percent);
	if (args->ar_errors != GFS2_ERRORS_DEFAULT) {
		const char *state;

		switch (args->ar_errors) {
		case GFS2_ERRORS_WITHDRAW:
			state = "withdraw";
			break;
		case GFS2_ERRORS_PANIC:
			state = "panic";
			break;
		default:
			state = "unknown";
			break;
		}
		seq_printf(s, ",errors=%s", state);
	}
	if (test_bit(SDF_NOBARRIERS, &sdp->sd_flags))
		seq_printf(s, ",nobarrier");
	if (test_bit(SDF_DEMOTE, &sdp->sd_flags))
		seq_printf(s, ",demote_interface_used");
	if (args->ar_rgrplvb)
		seq_printf(s, ",rgrplvb");
	return 0;
}

static void gfs2_final_release_pages(struct gfs2_inode *ip)
{
	struct inode *inode = &ip->i_inode;
	struct gfs2_glock *gl = ip->i_gl;

	truncate_inode_pages(gfs2_glock2aspace(ip->i_gl), 0);
	truncate_inode_pages(&inode->i_data, 0);

	if (atomic_read(&gl->gl_revokes) == 0) {
		clear_bit(GLF_LFLUSH, &gl->gl_flags);
		clear_bit(GLF_DIRTY, &gl->gl_flags);
	}
}

static int gfs2_dinode_dealloc(struct gfs2_inode *ip)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	struct gfs2_rgrpd *rgd;
	struct gfs2_holder gh;
	int error;

	if (gfs2_get_inode_blocks(&ip->i_inode) != 1) {
		gfs2_consist_inode(ip);
		return -EIO;
	}

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = gfs2_quota_hold(ip, NO_UID_QUOTA_CHANGE, NO_GID_QUOTA_CHANGE);
	if (error)
		return error;

	rgd = gfs2_blk2rgrpd(sdp, ip->i_no_addr, 1);
	if (!rgd) {
		gfs2_consist_inode(ip);
		error = -EIO;
		goto out_qs;
	}

	error = gfs2_glock_nq_init(rgd->rd_gl, LM_ST_EXCLUSIVE, 0, &gh);
	if (error)
		goto out_qs;

	error = gfs2_trans_begin(sdp, RES_RG_BIT + RES_STATFS + RES_QUOTA,
				 sdp->sd_jdesc->jd_blocks);
	if (error)
		goto out_rg_gunlock;

	gfs2_free_di(rgd, ip);

	gfs2_final_release_pages(ip);

	gfs2_trans_end(sdp);

out_rg_gunlock:
	gfs2_glock_dq_uninit(&gh);
out_qs:
	gfs2_quota_unhold(ip);
	return error;
}

/**
 * gfs2_evict_inode - Remove an inode from cache
 * @inode: The inode to evict
 *
 * There are three cases to consider:
 * 1. i_nlink == 0, we are final opener (and must deallocate)
 * 2. i_nlink == 0, we are not the final opener (and cannot deallocate)
 * 3. i_nlink > 0
 *
 * If the fs is read only, then we have to treat all cases as per #3
 * since we are unable to do any deallocation. The inode will be
 * deallocated by the next read/write node to attempt an allocation
 * in the same resource group
 *
 * We have to (at the moment) hold the inodes main lock to cover
 * the gap between unlocking the shared lock on the iopen lock and
 * taking the exclusive lock. I'd rather do a shared -> exclusive
 * conversion on the iopen lock, but we can change that later. This
 * is safe, just less efficient.
 */

static void gfs2_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct gfs2_sbd *sdp = sb->s_fs_info;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int error;

	if (test_bit(GIF_FREE_VFS_INODE, &ip->i_flags)) {
		clear_inode(inode);
		return;
	}

	if (inode->i_nlink || (sb->s_flags & MS_RDONLY))
		goto out;

	/* Must not read inode block until block type has been verified */
	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, GL_SKIP, &gh);
	if (unlikely(error)) {
		ip->i_iopen_gh.gh_flags |= GL_NOCACHE;
		gfs2_glock_dq_uninit(&ip->i_iopen_gh);
		goto out;
	}

	if (!test_bit(GIF_ALLOC_FAILED, &ip->i_flags)) {
		error = gfs2_check_blk_type(sdp, ip->i_no_addr, GFS2_BLKST_UNLINKED);
		if (error)
			goto out_truncate;
	}

	if (test_bit(GIF_INVALID, &ip->i_flags)) {
		error = gfs2_inode_refresh(ip);
		if (error)
			goto out_truncate;
	}

	ip->i_iopen_gh.gh_flags |= GL_NOCACHE;
	gfs2_glock_dq_wait(&ip->i_iopen_gh);
	gfs2_holder_reinit(LM_ST_EXCLUSIVE, LM_FLAG_TRY_1CB | GL_NOCACHE, &ip->i_iopen_gh);
	error = gfs2_glock_nq(&ip->i_iopen_gh);
	if (error)
		goto out_truncate;

	/* Case 1 starts here */

	if (S_ISDIR(inode->i_mode) &&
	    (ip->i_diskflags & GFS2_DIF_EXHASH)) {
		error = gfs2_dir_exhash_dealloc(ip);
		if (error)
			goto out_unlock;
	}

	if (ip->i_eattr) {
		error = gfs2_ea_dealloc(ip);
		if (error)
			goto out_unlock;
	}

	if (!gfs2_is_stuffed(ip)) {
		error = gfs2_file_dealloc(ip);
		if (error)
			goto out_unlock;
	}

	error = gfs2_dinode_dealloc(ip);
	goto out_unlock;

out_truncate:
	gfs2_log_flush(sdp, ip->i_gl, NORMAL_FLUSH);
	if (test_bit(GLF_DIRTY, &ip->i_gl->gl_flags)) {
		struct address_space *metamapping = gfs2_glock2aspace(ip->i_gl);
		filemap_fdatawrite(metamapping);
		filemap_fdatawait(metamapping);
	}
	write_inode_now(inode, 1);
	gfs2_ail_flush(ip->i_gl, 0);

	/* Case 2 starts here */
	error = gfs2_trans_begin(sdp, 0, sdp->sd_jdesc->jd_blocks);
	if (error)
		goto out_unlock;
	/* Needs to be done before glock release & also in a transaction */
	truncate_inode_pages(&inode->i_data, 0);
	gfs2_trans_end(sdp);

out_unlock:
	/* Error path for case 1 */
	if (gfs2_rs_active(ip->i_res))
		gfs2_rs_deltree(ip->i_res);

	if (test_bit(HIF_HOLDER, &ip->i_iopen_gh.gh_iflags)) {
		ip->i_iopen_gh.gh_flags |= GL_NOCACHE;
		gfs2_glock_dq(&ip->i_iopen_gh);
	}
	gfs2_holder_uninit(&ip->i_iopen_gh);
	gfs2_glock_dq_uninit(&gh);
	if (error && error != GLR_TRYFAILED && error != -EROFS)
		fs_warn(sdp, "gfs2_evict_inode: %d\n", error);
out:
	/* Case 3 starts here */
	truncate_inode_pages_final(&inode->i_data);
	gfs2_rs_delete(ip, NULL);
	gfs2_ordered_del_inode(ip);
	clear_inode(inode);
	gfs2_dir_hash_inval(ip);
	ip->i_gl->gl_object = NULL;
	flush_delayed_work(&ip->i_gl->gl_work);
	gfs2_glock_add_to_lru(ip->i_gl);
	gfs2_glock_put(ip->i_gl);
	ip->i_gl = NULL;
	if (ip->i_iopen_gh.gh_gl) {
		ip->i_iopen_gh.gh_gl->gl_object = NULL;
		ip->i_iopen_gh.gh_flags |= GL_NOCACHE;
		gfs2_glock_dq_uninit(&ip->i_iopen_gh);
	}
}

static struct inode *gfs2_alloc_inode(struct super_block *sb)
{
	struct gfs2_inode *ip;

	ip = kmem_cache_alloc(gfs2_inode_cachep, GFP_KERNEL);
	if (ip) {
		ip->i_flags = 0;
		ip->i_gl = NULL;
		ip->i_rgd = NULL;
		ip->i_res = NULL;
	}
	return &ip->i_inode;
}

static void gfs2_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(gfs2_inode_cachep, inode);
}

static void gfs2_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, gfs2_i_callback);
}

const struct super_operations gfs2_super_ops = {
	.alloc_inode		= gfs2_alloc_inode,
	.destroy_inode		= gfs2_destroy_inode,
	.write_inode		= gfs2_write_inode,
	.dirty_inode		= gfs2_dirty_inode,
	.evict_inode		= gfs2_evict_inode,
	.put_super		= gfs2_put_super,
	.sync_fs		= gfs2_sync_fs,
	.freeze_fs 		= gfs2_freeze,
	.unfreeze_fs		= gfs2_unfreeze,
	.statfs			= gfs2_statfs,
	.remount_fs		= gfs2_remount_fs,
	.drop_inode		= gfs2_drop_inode,
	.show_options		= gfs2_show_options,
};
/************************************************************/
/* ../linux-3.17/fs/gfs2/sys.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/sched.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/module.h>
#include <linux/kobject.h>
// #include <asm/uaccess.h>
// #include <linux/gfs2_ondisk.h>
#include <linux/genhd.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "sys.h"
// #include "super.h"
// #include "glock.h"
// #include "quota.h"
// #include "util.h"
// #include "glops.h"
// #include "recovery.h"

struct gfs2_attr {
	struct attribute attr;
	ssize_t (*show)(struct gfs2_sbd *, char *);
	ssize_t (*store)(struct gfs2_sbd *, const char *, size_t);
};

static ssize_t gfs2_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct gfs2_sbd *sdp = container_of(kobj, struct gfs2_sbd, sd_kobj);
	struct gfs2_attr *a = container_of(attr, struct gfs2_attr, attr);
	return a->show ? a->show(sdp, buf) : 0;
}

static ssize_t gfs2_attr_store(struct kobject *kobj, struct attribute *attr,
			       const char *buf, size_t len)
{
	struct gfs2_sbd *sdp = container_of(kobj, struct gfs2_sbd, sd_kobj);
	struct gfs2_attr *a = container_of(attr, struct gfs2_attr, attr);
	return a->store ? a->store(sdp, buf, len) : len;
}

static const struct sysfs_ops gfs2_attr_ops = {
	.show  = gfs2_attr_show,
	.store = gfs2_attr_store,
};


static struct kset *gfs2_kset;

static ssize_t id_show(struct gfs2_sbd *sdp, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u:%u\n",
			MAJOR(sdp->sd_vfs->s_dev), MINOR(sdp->sd_vfs->s_dev));
}

static ssize_t fsname_show(struct gfs2_sbd *sdp, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", sdp->sd_fsname);
}

static int gfs2_uuid_valid(const u8 *uuid)
{
	int i;

	for (i = 0; i < 16; i++) {
		if (uuid[i])
			return 1;
	}
	return 0;
}

static ssize_t uuid_show(struct gfs2_sbd *sdp, char *buf)
{
	struct super_block *s = sdp->sd_vfs;
	const u8 *uuid = s->s_uuid;
	buf[0] = '\0';
	if (!gfs2_uuid_valid(uuid))
		return 0;
	return snprintf(buf, PAGE_SIZE, "%pUB\n", uuid);
}

static ssize_t freeze_show(struct gfs2_sbd *sdp, char *buf)
{
	struct super_block *sb = sdp->sd_vfs;
	int frozen = (sb->s_writers.frozen == SB_UNFROZEN) ? 0 : 1;

	return snprintf(buf, PAGE_SIZE, "%u\n", frozen);
}

static ssize_t freeze_store(struct gfs2_sbd *sdp, const char *buf, size_t len)
{
	int error;
	int n = simple_strtol(buf, NULL, 0);

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	switch (n) {
	case 0:
		error = thaw_super(sdp->sd_vfs);
		break;
	case 1:
		error = freeze_super(sdp->sd_vfs);
		break;
	default:
		return -EINVAL;
	}

	if (error) {
		fs_warn(sdp, "freeze %d error %d", n, error);
		return error;
	}

	return len;
}

static ssize_t withdraw_show(struct gfs2_sbd *sdp, char *buf)
{
	unsigned int b = test_bit(SDF_SHUTDOWN, &sdp->sd_flags);
	return snprintf(buf, PAGE_SIZE, "%u\n", b);
}

static ssize_t withdraw_store(struct gfs2_sbd *sdp, const char *buf, size_t len)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (simple_strtol(buf, NULL, 0) != 1)
		return -EINVAL;

	gfs2_lm_withdraw(sdp, "withdrawing from cluster at user's request\n");

	return len;
}

static ssize_t statfs_sync_store(struct gfs2_sbd *sdp, const char *buf,
				 size_t len)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (simple_strtol(buf, NULL, 0) != 1)
		return -EINVAL;

	gfs2_statfs_sync(sdp->sd_vfs, 0);
	return len;
}

static ssize_t quota_sync_store(struct gfs2_sbd *sdp, const char *buf,
				size_t len)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (simple_strtol(buf, NULL, 0) != 1)
		return -EINVAL;

	gfs2_quota_sync(sdp->sd_vfs, 0);
	return len;
}

static ssize_t quota_refresh_user_store(struct gfs2_sbd *sdp, const char *buf,
					size_t len)
{
	struct kqid qid;
	int error;
	u32 id;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	id = simple_strtoul(buf, NULL, 0);

	qid = make_kqid(current_user_ns(), USRQUOTA, id);
	if (!qid_valid(qid))
		return -EINVAL;

	error = gfs2_quota_refresh(sdp, qid);
	return error ? error : len;
}

static ssize_t quota_refresh_group_store(struct gfs2_sbd *sdp, const char *buf,
					 size_t len)
{
	struct kqid qid;
	int error;
	u32 id;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	id = simple_strtoul(buf, NULL, 0);

	qid = make_kqid(current_user_ns(), GRPQUOTA, id);
	if (!qid_valid(qid))
		return -EINVAL;

	error = gfs2_quota_refresh(sdp, qid);
	return error ? error : len;
}

static ssize_t demote_rq_store(struct gfs2_sbd *sdp, const char *buf, size_t len)
{
	struct gfs2_glock *gl;
	const struct gfs2_glock_operations *glops;
	unsigned int glmode;
	unsigned int gltype;
	unsigned long long glnum;
	char mode[16];
	int rv;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	rv = sscanf(buf, "%u:%llu %15s", &gltype, &glnum,
		    mode);
	if (rv != 3)
		return -EINVAL;

	if (strcmp(mode, "EX") == 0)
		glmode = LM_ST_UNLOCKED;
	else if ((strcmp(mode, "CW") == 0) || (strcmp(mode, "DF") == 0))
		glmode = LM_ST_DEFERRED;
	else if ((strcmp(mode, "PR") == 0) || (strcmp(mode, "SH") == 0))
		glmode = LM_ST_SHARED;
	else
		return -EINVAL;

	if (gltype > LM_TYPE_JOURNAL)
		return -EINVAL;
	if (gltype == LM_TYPE_NONDISK && glnum == GFS2_FREEZE_LOCK)
		glops = &gfs2_freeze_glops;
	else
		glops = gfs2_glops_list[gltype];
	if (glops == NULL)
		return -EINVAL;
	if (!test_and_set_bit(SDF_DEMOTE, &sdp->sd_flags))
		fs_info(sdp, "demote interface used\n");
	rv = gfs2_glock_get(sdp, glnum, glops, 0, &gl);
	if (rv)
		return rv;
	gfs2_glock_cb(gl, glmode);
	gfs2_glock_put(gl);
	return len;
}


#define GFS2_ATTR(name, mode, show, store) \
static struct gfs2_attr gfs2_attr_##name = __ATTR(name, mode, show, store)

GFS2_ATTR(id,                  0444, id_show,       NULL);
GFS2_ATTR(fsname,              0444, fsname_show,   NULL);
GFS2_ATTR(uuid,                0444, uuid_show,     NULL);
GFS2_ATTR(freeze,              0644, freeze_show,   freeze_store);
GFS2_ATTR(withdraw,            0644, withdraw_show, withdraw_store);
GFS2_ATTR(statfs_sync,         0200, NULL,          statfs_sync_store);
GFS2_ATTR(quota_sync,          0200, NULL,          quota_sync_store);
GFS2_ATTR(quota_refresh_user,  0200, NULL,          quota_refresh_user_store);
GFS2_ATTR(quota_refresh_group, 0200, NULL,          quota_refresh_group_store);
GFS2_ATTR(demote_rq,           0200, NULL,	    demote_rq_store);

static struct attribute *gfs2_attrs[] = {
	&gfs2_attr_id.attr,
	&gfs2_attr_fsname.attr,
	&gfs2_attr_uuid.attr,
	&gfs2_attr_freeze.attr,
	&gfs2_attr_withdraw.attr,
	&gfs2_attr_statfs_sync.attr,
	&gfs2_attr_quota_sync.attr,
	&gfs2_attr_quota_refresh_user.attr,
	&gfs2_attr_quota_refresh_group.attr,
	&gfs2_attr_demote_rq.attr,
	NULL,
};

static void gfs2_sbd_release(struct kobject *kobj)
{
	struct gfs2_sbd *sdp = container_of(kobj, struct gfs2_sbd, sd_kobj);

	kfree(sdp);
}

static struct kobj_type gfs2_ktype = {
	.release = gfs2_sbd_release,
	.default_attrs = gfs2_attrs,
	.sysfs_ops     = &gfs2_attr_ops,
};


/*
 * lock_module. Originally from lock_dlm
 */

static ssize_t proto_name_show(struct gfs2_sbd *sdp, char *buf)
{
	const struct lm_lockops *ops = sdp->sd_lockstruct.ls_ops;
	return sprintf(buf, "%s\n", ops->lm_proto_name);
}

static ssize_t block_show(struct gfs2_sbd *sdp, char *buf)
{
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	ssize_t ret;
	int val = 0;

	if (test_bit(DFL_BLOCK_LOCKS, &ls->ls_recover_flags))
		val = 1;
	ret = sprintf(buf, "%d\n", val);
	return ret;
}

static ssize_t block_store(struct gfs2_sbd *sdp, const char *buf, size_t len)
{
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	ssize_t ret = len;
	int val;

	val = simple_strtol(buf, NULL, 0);

	if (val == 1)
		set_bit(DFL_BLOCK_LOCKS, &ls->ls_recover_flags);
	else if (val == 0) {
		clear_bit(DFL_BLOCK_LOCKS, &ls->ls_recover_flags);
		smp_mb__after_atomic();
		gfs2_glock_thaw(sdp);
	} else {
		ret = -EINVAL;
	}
	return ret;
}

static ssize_t wdack_show(struct gfs2_sbd *sdp, char *buf)
{
	int val = completion_done(&sdp->sd_wdack) ? 1 : 0;

	return sprintf(buf, "%d\n", val);
}

static ssize_t wdack_store(struct gfs2_sbd *sdp, const char *buf, size_t len)
{
	ssize_t ret = len;
	int val;

	val = simple_strtol(buf, NULL, 0);

	if ((val == 1) &&
	    !strcmp(sdp->sd_lockstruct.ls_ops->lm_proto_name, "lock_dlm"))
		complete(&sdp->sd_wdack);
	else
		ret = -EINVAL;
	return ret;
}

static ssize_t lkfirst_show(struct gfs2_sbd *sdp, char *buf)
{
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	return sprintf(buf, "%d\n", ls->ls_first);
}

static ssize_t lkfirst_store(struct gfs2_sbd *sdp, const char *buf, size_t len)
{
	unsigned first;
	int rv;

	rv = sscanf(buf, "%u", &first);
	if (rv != 1 || first > 1)
		return -EINVAL;
	rv = wait_for_completion_killable(&sdp->sd_locking_init);
	if (rv)
		return rv;
	spin_lock(&sdp->sd_jindex_spin);
	rv = -EBUSY;
	if (test_bit(SDF_NOJOURNALID, &sdp->sd_flags) == 0)
		goto out;
	rv = -EINVAL;
	if (sdp->sd_args.ar_spectator)
		goto out;
	if (sdp->sd_lockstruct.ls_ops->lm_mount == NULL)
		goto out;
	sdp->sd_lockstruct.ls_first = first;
	rv = 0;
out:
        spin_unlock(&sdp->sd_jindex_spin);
        return rv ? rv : len;
}

static ssize_t first_done_show(struct gfs2_sbd *sdp, char *buf)
{
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	return sprintf(buf, "%d\n", !!test_bit(DFL_FIRST_MOUNT_DONE, &ls->ls_recover_flags));
}

int gfs2_recover_set(struct gfs2_sbd *sdp, unsigned jid)
{
	struct gfs2_jdesc *jd;
	int rv;

	/* Wait for our primary journal to be initialized */
	wait_for_completion(&sdp->sd_journal_ready);

	spin_lock(&sdp->sd_jindex_spin);
	rv = -EBUSY;
	if (sdp->sd_jdesc->jd_jid == jid)
		goto out;
	rv = -ENOENT;
	list_for_each_entry(jd, &sdp->sd_jindex_list, jd_list) {
		if (jd->jd_jid != jid)
			continue;
		rv = gfs2_recover_journal(jd, false);
		break;
	}
out:
	spin_unlock(&sdp->sd_jindex_spin);
	return rv;
}

static ssize_t recover_store(struct gfs2_sbd *sdp, const char *buf, size_t len)
{
	unsigned jid;
	int rv;

	rv = sscanf(buf, "%u", &jid);
	if (rv != 1)
		return -EINVAL;

	if (test_bit(SDF_NORECOVERY, &sdp->sd_flags)) {
		rv = -ESHUTDOWN;
		goto out;
	}

	rv = gfs2_recover_set(sdp, jid);
out:
	return rv ? rv : len;
}

static ssize_t recover_done_show(struct gfs2_sbd *sdp, char *buf)
{
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	return sprintf(buf, "%d\n", ls->ls_recover_jid_done);
}

static ssize_t recover_status_show(struct gfs2_sbd *sdp, char *buf)
{
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	return sprintf(buf, "%d\n", ls->ls_recover_jid_status);
}

static ssize_t jid_show(struct gfs2_sbd *sdp, char *buf)
{
	return sprintf(buf, "%d\n", sdp->sd_lockstruct.ls_jid);
}

static ssize_t jid_store(struct gfs2_sbd *sdp, const char *buf, size_t len)
{
        int jid;
	int rv;

	rv = sscanf(buf, "%d", &jid);
	if (rv != 1)
		return -EINVAL;
	rv = wait_for_completion_killable(&sdp->sd_locking_init);
	if (rv)
		return rv;
	spin_lock(&sdp->sd_jindex_spin);
	rv = -EINVAL;
	if (sdp->sd_lockstruct.ls_ops->lm_mount == NULL)
		goto out;
	rv = -EBUSY;
	if (test_bit(SDF_NOJOURNALID, &sdp->sd_flags) == 0)
		goto out;
	rv = 0;
	if (sdp->sd_args.ar_spectator && jid > 0)
		rv = jid = -EINVAL;
	sdp->sd_lockstruct.ls_jid = jid;
	clear_bit(SDF_NOJOURNALID, &sdp->sd_flags);
	smp_mb__after_atomic();
	wake_up_bit(&sdp->sd_flags, SDF_NOJOURNALID);
out:
	spin_unlock(&sdp->sd_jindex_spin);
	return rv ? rv : len;
}

#define GDLM_ATTR(_name,_mode,_show,_store) \
static struct gfs2_attr gdlm_attr_##_name = __ATTR(_name,_mode,_show,_store)

GDLM_ATTR(proto_name,		0444, proto_name_show,		NULL);
GDLM_ATTR(block,		0644, block_show,		block_store);
GDLM_ATTR(withdraw,		0644, wdack_show,		wdack_store);
GDLM_ATTR(jid,			0644, jid_show,			jid_store);
GDLM_ATTR(first,		0644, lkfirst_show,		lkfirst_store);
GDLM_ATTR(first_done,		0444, first_done_show,		NULL);
GDLM_ATTR(recover,		0600, NULL,			recover_store);
GDLM_ATTR(recover_done,		0444, recover_done_show,	NULL);
GDLM_ATTR(recover_status,	0444, recover_status_show,	NULL);

static struct attribute *lock_module_attrs[] = {
	&gdlm_attr_proto_name.attr,
	&gdlm_attr_block.attr,
	&gdlm_attr_withdraw.attr,
	&gdlm_attr_jid.attr,
	&gdlm_attr_first.attr,
	&gdlm_attr_first_done.attr,
	&gdlm_attr_recover.attr,
	&gdlm_attr_recover_done.attr,
	&gdlm_attr_recover_status.attr,
	NULL,
};

/*
 * get and set struct gfs2_tune fields
 */

static ssize_t quota_scale_show(struct gfs2_sbd *sdp, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u %u\n",
			sdp->sd_tune.gt_quota_scale_num,
			sdp->sd_tune.gt_quota_scale_den);
}

static ssize_t quota_scale_store(struct gfs2_sbd *sdp, const char *buf,
				 size_t len)
{
	struct gfs2_tune *gt = &sdp->sd_tune;
	unsigned int x, y;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (sscanf(buf, "%u %u", &x, &y) != 2 || !y)
		return -EINVAL;

	spin_lock(&gt->gt_spin);
	gt->gt_quota_scale_num = x;
	gt->gt_quota_scale_den = y;
	spin_unlock(&gt->gt_spin);
	return len;
}

static ssize_t tune_set(struct gfs2_sbd *sdp, unsigned int *field,
			int check_zero, const char *buf, size_t len)
{
	struct gfs2_tune *gt = &sdp->sd_tune;
	unsigned int x;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	x = simple_strtoul(buf, NULL, 0);

	if (check_zero && !x)
		return -EINVAL;

	spin_lock(&gt->gt_spin);
	*field = x;
	spin_unlock(&gt->gt_spin);
	return len;
}

#define TUNE_ATTR_3(name, show, store)                                        \
static struct gfs2_attr tune_attr_##name = __ATTR(name, 0644, show, store)

#define TUNE_ATTR_2(name, store)                                              \
static ssize_t name##_show(struct gfs2_sbd *sdp, char *buf)                   \
{                                                                             \
	return snprintf(buf, PAGE_SIZE, "%u\n", sdp->sd_tune.gt_##name);      \
}                                                                             \
TUNE_ATTR_3(name, name##_show, store)

#define TUNE_ATTR(name, check_zero)                                           \
static ssize_t name##_store(struct gfs2_sbd *sdp, const char *buf, size_t len)\
{                                                                             \
	return tune_set(sdp, &sdp->sd_tune.gt_##name, check_zero, buf, len);  \
}                                                                             \
TUNE_ATTR_2(name, name##_store)

TUNE_ATTR(quota_warn_period, 0);
TUNE_ATTR(quota_quantum, 0);
TUNE_ATTR(max_readahead, 0);
TUNE_ATTR(complain_secs, 0);
TUNE_ATTR(statfs_slow, 0);
TUNE_ATTR(new_files_jdata, 0);
TUNE_ATTR(statfs_quantum, 1);
TUNE_ATTR_3(quota_scale, quota_scale_show, quota_scale_store);

static struct attribute *tune_attrs[] = {
	&tune_attr_quota_warn_period.attr,
	&tune_attr_quota_quantum.attr,
	&tune_attr_max_readahead.attr,
	&tune_attr_complain_secs.attr,
	&tune_attr_statfs_slow.attr,
	&tune_attr_statfs_quantum.attr,
	&tune_attr_quota_scale.attr,
	&tune_attr_new_files_jdata.attr,
	NULL,
};

static struct attribute_group tune_group = {
	.name = "tune",
	.attrs = tune_attrs,
};

static struct attribute_group lock_module_group = {
	.name = "lock_module",
	.attrs = lock_module_attrs,
};

int gfs2_sys_fs_add(struct gfs2_sbd *sdp)
{
	struct super_block *sb = sdp->sd_vfs;
	int error;
	char ro[20];
	char spectator[20];
	char *envp[] = { ro, spectator, NULL };
	int sysfs_frees_sdp = 0;

	sprintf(ro, "RDONLY=%d", (sb->s_flags & MS_RDONLY) ? 1 : 0);
	sprintf(spectator, "SPECTATOR=%d", sdp->sd_args.ar_spectator ? 1 : 0);

	sdp->sd_kobj.kset = gfs2_kset;
	error = kobject_init_and_add(&sdp->sd_kobj, &gfs2_ktype, NULL,
				     "%s", sdp->sd_table_name);
	if (error)
		goto fail_reg;

	sysfs_frees_sdp = 1; /* Freeing sdp is now done by sysfs calling
				function gfs2_sbd_release. */
	error = sysfs_create_group(&sdp->sd_kobj, &tune_group);
	if (error)
		goto fail_reg;

	error = sysfs_create_group(&sdp->sd_kobj, &lock_module_group);
	if (error)
		goto fail_tune;

	error = sysfs_create_link(&sdp->sd_kobj,
				  &disk_to_dev(sb->s_bdev->bd_disk)->kobj,
				  "device");
	if (error)
		goto fail_lock_module;

	kobject_uevent_env(&sdp->sd_kobj, KOBJ_ADD, envp);
	return 0;

fail_lock_module:
	sysfs_remove_group(&sdp->sd_kobj, &lock_module_group);
fail_tune:
	sysfs_remove_group(&sdp->sd_kobj, &tune_group);
fail_reg:
	free_percpu(sdp->sd_lkstats);
	fs_err(sdp, "error %d adding sysfs files", error);
	if (sysfs_frees_sdp)
		kobject_put(&sdp->sd_kobj);
	else
		kfree(sdp);
	sb->s_fs_info = NULL;
	return error;
}

void gfs2_sys_fs_del(struct gfs2_sbd *sdp)
{
	sysfs_remove_link(&sdp->sd_kobj, "device");
	sysfs_remove_group(&sdp->sd_kobj, &tune_group);
	sysfs_remove_group(&sdp->sd_kobj, &lock_module_group);
	kobject_put(&sdp->sd_kobj);
}

static int gfs2_uevent(struct kset *kset, struct kobject *kobj,
		       struct kobj_uevent_env *env)
{
	struct gfs2_sbd *sdp = container_of(kobj, struct gfs2_sbd, sd_kobj);
	struct super_block *s = sdp->sd_vfs;
	const u8 *uuid = s->s_uuid;

	add_uevent_var(env, "LOCKTABLE=%s", sdp->sd_table_name);
	add_uevent_var(env, "LOCKPROTO=%s", sdp->sd_proto_name);
	if (!test_bit(SDF_NOJOURNALID, &sdp->sd_flags))
		add_uevent_var(env, "JOURNALID=%d", sdp->sd_lockstruct.ls_jid);
	if (gfs2_uuid_valid(uuid))
		add_uevent_var(env, "UUID=%pUB", uuid);
	return 0;
}

static const struct kset_uevent_ops gfs2_uevent_ops = {
	.uevent = gfs2_uevent,
};

int gfs2_sys_init(void)
{
	gfs2_kset = kset_create_and_add("gfs2", &gfs2_uevent_ops, fs_kobj);
	if (!gfs2_kset)
		return -ENOMEM;
	return 0;
}

void gfs2_sys_uninit(void)
{
	kset_unregister(gfs2_kset);
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/trans.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/kallsyms.h>
// #include <linux/gfs2_ondisk.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "glock.h"
// #include "inode.h"
// #include "log.h"
// #include "lops.h"
// #include "meta_io.h"
// #include "trans.h"
// #include "util.h"
// #include "trace_gfs2.h"

int gfs2_trans_begin(struct gfs2_sbd *sdp, unsigned int blocks,
		     unsigned int revokes)
{
	struct gfs2_trans *tr;
	int error;

	BUG_ON(current->journal_info);
	BUG_ON(blocks == 0 && revokes == 0);

	if (!test_bit(SDF_JOURNAL_LIVE, &sdp->sd_flags))
		return -EROFS;

	tr = kzalloc(sizeof(struct gfs2_trans), GFP_NOFS);
	if (!tr)
		return -ENOMEM;

	tr->tr_ip = (unsigned long)__builtin_return_address(0);
	tr->tr_blocks = blocks;
	tr->tr_revokes = revokes;
	tr->tr_reserved = 1;
	tr->tr_alloced = 1;
	if (blocks)
		tr->tr_reserved += 6 + blocks;
	if (revokes)
		tr->tr_reserved += gfs2_struct2blk(sdp, revokes,
						   sizeof(u64));
	INIT_LIST_HEAD(&tr->tr_databuf);
	INIT_LIST_HEAD(&tr->tr_buf);

	sb_start_intwrite(sdp->sd_vfs);

	error = gfs2_log_reserve(sdp, tr->tr_reserved);
	if (error)
		goto fail;

	current->journal_info = tr;

	return 0;

fail:
	sb_end_intwrite(sdp->sd_vfs);
	kfree(tr);

	return error;
}

static void gfs2_print_trans(const struct gfs2_trans *tr)
{
	pr_warn("Transaction created at: %pSR\n", (void *)tr->tr_ip);
	pr_warn("blocks=%u revokes=%u reserved=%u touched=%u\n",
		tr->tr_blocks, tr->tr_revokes, tr->tr_reserved, tr->tr_touched);
	pr_warn("Buf %u/%u Databuf %u/%u Revoke %u/%u\n",
		tr->tr_num_buf_new, tr->tr_num_buf_rm,
		tr->tr_num_databuf_new, tr->tr_num_databuf_rm,
		tr->tr_num_revoke, tr->tr_num_revoke_rm);
}

void gfs2_trans_end(struct gfs2_sbd *sdp)
{
	struct gfs2_trans *tr = current->journal_info;
	s64 nbuf;
	BUG_ON(!tr);
	current->journal_info = NULL;

	if (!tr->tr_touched) {
		gfs2_log_release(sdp, tr->tr_reserved);
		if (tr->tr_alloced)
			kfree(tr);
		sb_end_intwrite(sdp->sd_vfs);
		return;
	}

	nbuf = tr->tr_num_buf_new + tr->tr_num_databuf_new;
	nbuf -= tr->tr_num_buf_rm;
	nbuf -= tr->tr_num_databuf_rm;

	if (gfs2_assert_withdraw(sdp, (nbuf <= tr->tr_blocks) &&
				       (tr->tr_num_revoke <= tr->tr_revokes)))
		gfs2_print_trans(tr);

	gfs2_log_commit(sdp, tr);
	if (tr->tr_alloced && !tr->tr_attached)
			kfree(tr);
	up_read(&sdp->sd_log_flush_lock);

	if (sdp->sd_vfs->s_flags & MS_SYNCHRONOUS)
		gfs2_log_flush(sdp, NULL, NORMAL_FLUSH);
	sb_end_intwrite(sdp->sd_vfs);
}

static struct gfs2_bufdata *gfs2_alloc_bufdata(struct gfs2_glock *gl,
					       struct buffer_head *bh,
					       const struct gfs2_log_operations *lops)
{
	struct gfs2_bufdata *bd;

	bd = kmem_cache_zalloc(gfs2_bufdata_cachep, GFP_NOFS | __GFP_NOFAIL);
	bd->bd_bh = bh;
	bd->bd_gl = gl;
	bd->bd_ops = lops;
	INIT_LIST_HEAD(&bd->bd_list);
	bh->b_private = bd;
	return bd;
}

/**
 * gfs2_trans_add_data - Add a databuf to the transaction.
 * @gl: The inode glock associated with the buffer
 * @bh: The buffer to add
 *
 * This is used in two distinct cases:
 * i) In ordered write mode
 *    We put the data buffer on a list so that we can ensure that its
 *    synced to disk at the right time
 * ii) In journaled data mode
 *    We need to journal the data block in the same way as metadata in
 *    the functions above. The difference is that here we have a tag
 *    which is two __be64's being the block number (as per meta data)
 *    and a flag which says whether the data block needs escaping or
 *    not. This means we need a new log entry for each 251 or so data
 *    blocks, which isn't an enormous overhead but twice as much as
 *    for normal metadata blocks.
 */
void gfs2_trans_add_data(struct gfs2_glock *gl, struct buffer_head *bh)
{
	struct gfs2_trans *tr = current->journal_info;
	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct address_space *mapping = bh->b_page->mapping;
	struct gfs2_inode *ip = GFS2_I(mapping->host);
	struct gfs2_bufdata *bd;

	if (!gfs2_is_jdata(ip)) {
		gfs2_ordered_add_inode(ip);
		return;
	}

	lock_buffer(bh);
	gfs2_log_lock(sdp);
	bd = bh->b_private;
	if (bd == NULL) {
		gfs2_log_unlock(sdp);
		unlock_buffer(bh);
		if (bh->b_private == NULL)
			bd = gfs2_alloc_bufdata(gl, bh, &gfs2_databuf_lops);
		lock_buffer(bh);
		gfs2_log_lock(sdp);
	}
	gfs2_assert(sdp, bd->bd_gl == gl);
	tr->tr_touched = 1;
	if (list_empty(&bd->bd_list)) {
		set_bit(GLF_LFLUSH, &bd->bd_gl->gl_flags);
		set_bit(GLF_DIRTY, &bd->bd_gl->gl_flags);
		gfs2_pin(sdp, bd->bd_bh);
		tr->tr_num_databuf_new++;
		list_add_tail(&bd->bd_list, &tr->tr_databuf);
	}
	gfs2_log_unlock(sdp);
	unlock_buffer(bh);
}

static void meta_lo_add(struct gfs2_sbd *sdp, struct gfs2_bufdata *bd)
{
	struct gfs2_meta_header *mh;
	struct gfs2_trans *tr;

	tr = current->journal_info;
	tr->tr_touched = 1;
	if (!list_empty(&bd->bd_list))
		return;
	set_bit(GLF_LFLUSH, &bd->bd_gl->gl_flags);
	set_bit(GLF_DIRTY, &bd->bd_gl->gl_flags);
	mh = (struct gfs2_meta_header *)bd->bd_bh->b_data;
	if (unlikely(mh->mh_magic != cpu_to_be32(GFS2_MAGIC))) {
		pr_err("Attempting to add uninitialised block to journal (inplace block=%lld)\n",
		       (unsigned long long)bd->bd_bh->b_blocknr);
		BUG();
	}
	gfs2_pin(sdp, bd->bd_bh);
	mh->__pad0 = cpu_to_be64(0);
	mh->mh_jid = cpu_to_be32(sdp->sd_jdesc->jd_jid);
	list_add(&bd->bd_list, &tr->tr_buf);
	tr->tr_num_buf_new++;
}

void gfs2_trans_add_meta(struct gfs2_glock *gl, struct buffer_head *bh)
{

	struct gfs2_sbd *sdp = gl->gl_sbd;
	struct gfs2_bufdata *bd;

	lock_buffer(bh);
	gfs2_log_lock(sdp);
	bd = bh->b_private;
	if (bd == NULL) {
		gfs2_log_unlock(sdp);
		unlock_buffer(bh);
		lock_page(bh->b_page);
		if (bh->b_private == NULL)
			bd = gfs2_alloc_bufdata(gl, bh, &gfs2_buf_lops);
		unlock_page(bh->b_page);
		lock_buffer(bh);
		gfs2_log_lock(sdp);
	}
	gfs2_assert(sdp, bd->bd_gl == gl);
	meta_lo_add(sdp, bd);
	gfs2_log_unlock(sdp);
	unlock_buffer(bh);
}

void gfs2_trans_add_revoke(struct gfs2_sbd *sdp, struct gfs2_bufdata *bd)
{
	struct gfs2_trans *tr = current->journal_info;

	BUG_ON(!list_empty(&bd->bd_list));
	gfs2_add_revoke(sdp, bd);
	tr->tr_touched = 1;
	tr->tr_num_revoke++;
}

void gfs2_trans_add_unrevoke(struct gfs2_sbd *sdp, u64 blkno, unsigned int len)
{
	struct gfs2_bufdata *bd, *tmp;
	struct gfs2_trans *tr = current->journal_info;
	unsigned int n = len;

	gfs2_log_lock(sdp);
	list_for_each_entry_safe(bd, tmp, &sdp->sd_log_le_revoke, bd_list) {
		if ((bd->bd_blkno >= blkno) && (bd->bd_blkno < (blkno + len))) {
			list_del_init(&bd->bd_list);
			gfs2_assert_withdraw(sdp, sdp->sd_log_num_revoke);
			sdp->sd_log_num_revoke--;
			kmem_cache_free(gfs2_bufdata_cachep, bd);
			tr->tr_num_revoke_rm++;
			if (--n == 0)
				break;
		}
	}
	gfs2_log_unlock(sdp);
}
/************************************************************/
/* ../linux-3.17/fs/gfs2/util.c */
/************************************************************/
/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/spinlock.h>
// #include <linux/completion.h>
// #include <linux/buffer_head.h>
// #include <linux/crc32.h>
// #include <linux/gfs2_ondisk.h>
// #include <asm/uaccess.h>

// #include "gfs2.h"
// #include "incore.h"
// #include "glock.h"
// #include "util.h"

struct kmem_cache *gfs2_glock_cachep __read_mostly;
struct kmem_cache *gfs2_glock_aspace_cachep __read_mostly;
struct kmem_cache *gfs2_inode_cachep __read_mostly;
struct kmem_cache *gfs2_bufdata_cachep __read_mostly;
struct kmem_cache *gfs2_rgrpd_cachep __read_mostly;
struct kmem_cache *gfs2_quotad_cachep __read_mostly;
struct kmem_cache *gfs2_rsrv_cachep __read_mostly;
mempool_t *gfs2_page_pool __read_mostly;

void gfs2_assert_i(struct gfs2_sbd *sdp)
{
	fs_emerg(sdp, "fatal assertion failed\n");
}

int gfs2_lm_withdraw(struct gfs2_sbd *sdp, const char *fmt, ...)
{
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;
	const struct lm_lockops *lm = ls->ls_ops;
	va_list args;
	struct va_format vaf;

	if (sdp->sd_args.ar_errors == GFS2_ERRORS_WITHDRAW &&
	    test_and_set_bit(SDF_SHUTDOWN, &sdp->sd_flags))
		return 0;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	fs_err(sdp, "%pV", &vaf);

	va_end(args);

	if (sdp->sd_args.ar_errors == GFS2_ERRORS_WITHDRAW) {
		fs_err(sdp, "about to withdraw this file system\n");
		BUG_ON(sdp->sd_args.ar_debug);

		kobject_uevent(&sdp->sd_kobj, KOBJ_OFFLINE);

		if (!strcmp(sdp->sd_lockstruct.ls_ops->lm_proto_name, "lock_dlm"))
			wait_for_completion(&sdp->sd_wdack);

		if (lm->lm_unmount) {
			fs_err(sdp, "telling LM to unmount\n");
			lm->lm_unmount(sdp);
		}
		fs_err(sdp, "withdrawn\n");
		dump_stack();
	}

	if (sdp->sd_args.ar_errors == GFS2_ERRORS_PANIC)
		panic("GFS2: fsid=%s: panic requested\n", sdp->sd_fsname);

	return -1;
}

/**
 * gfs2_assert_withdraw_i - Cause the machine to withdraw if @assertion is false
 * Returns: -1 if this call withdrew the machine,
 *          -2 if it was already withdrawn
 */

int gfs2_assert_withdraw_i(struct gfs2_sbd *sdp, char *assertion,
			   const char *function, char *file, unsigned int line)
{
	int me;
	me = gfs2_lm_withdraw(sdp,
			      "fatal: assertion \"%s\" failed\n"
			      "   function = %s, file = %s, line = %u\n",
			      assertion, function, file, line);
	dump_stack();
	return (me) ? -1 : -2;
}

/**
 * gfs2_assert_warn_i - Print a message to the console if @assertion is false
 * Returns: -1 if we printed something
 *          -2 if we didn't
 */

int gfs2_assert_warn_i(struct gfs2_sbd *sdp, char *assertion,
		       const char *function, char *file, unsigned int line)
{
	if (time_before(jiffies,
			sdp->sd_last_warning +
			gfs2_tune_get(sdp, gt_complain_secs) * HZ))
		return -2;

	if (sdp->sd_args.ar_errors == GFS2_ERRORS_WITHDRAW)
		fs_warn(sdp, "warning: assertion \"%s\" failed at function = %s, file = %s, line = %u\n",
			assertion, function, file, line);

	if (sdp->sd_args.ar_debug)
		BUG();
	else
		dump_stack();

	if (sdp->sd_args.ar_errors == GFS2_ERRORS_PANIC)
		panic("GFS2: fsid=%s: warning: assertion \"%s\" failed\n"
		      "GFS2: fsid=%s:   function = %s, file = %s, line = %u\n",
		      sdp->sd_fsname, assertion,
		      sdp->sd_fsname, function, file, line);

	sdp->sd_last_warning = jiffies;

	return -1;
}

/**
 * gfs2_consist_i - Flag a filesystem consistency error and withdraw
 * Returns: -1 if this call withdrew the machine,
 *          0 if it was already withdrawn
 */

int gfs2_consist_i(struct gfs2_sbd *sdp, int cluster_wide, const char *function,
		   char *file, unsigned int line)
{
	int rv;
	rv = gfs2_lm_withdraw(sdp,
			      "fatal: filesystem consistency error - function = %s, file = %s, line = %u\n",
			      function, file, line);
	return rv;
}

/**
 * gfs2_consist_inode_i - Flag an inode consistency error and withdraw
 * Returns: -1 if this call withdrew the machine,
 *          0 if it was already withdrawn
 */

int gfs2_consist_inode_i(struct gfs2_inode *ip, int cluster_wide,
			 const char *function, char *file, unsigned int line)
{
	struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	int rv;
	rv = gfs2_lm_withdraw(sdp,
			      "fatal: filesystem consistency error\n"
			      "  inode = %llu %llu\n"
			      "  function = %s, file = %s, line = %u\n",
			      (unsigned long long)ip->i_no_formal_ino,
			      (unsigned long long)ip->i_no_addr,
			      function, file, line);
	return rv;
}

/**
 * gfs2_consist_rgrpd_i - Flag a RG consistency error and withdraw
 * Returns: -1 if this call withdrew the machine,
 *          0 if it was already withdrawn
 */

int gfs2_consist_rgrpd_i(struct gfs2_rgrpd *rgd, int cluster_wide,
			 const char *function, char *file, unsigned int line)
{
	struct gfs2_sbd *sdp = rgd->rd_sbd;
	int rv;
	rv = gfs2_lm_withdraw(sdp,
			      "fatal: filesystem consistency error\n"
			      "  RG = %llu\n"
			      "  function = %s, file = %s, line = %u\n",
			      (unsigned long long)rgd->rd_addr,
			      function, file, line);
	return rv;
}

/**
 * gfs2_meta_check_ii - Flag a magic number consistency error and withdraw
 * Returns: -1 if this call withdrew the machine,
 *          -2 if it was already withdrawn
 */

int gfs2_meta_check_ii(struct gfs2_sbd *sdp, struct buffer_head *bh,
		       const char *type, const char *function, char *file,
		       unsigned int line)
{
	int me;
	me = gfs2_lm_withdraw(sdp,
			      "fatal: invalid metadata block\n"
			      "  bh = %llu (%s)\n"
			      "  function = %s, file = %s, line = %u\n",
			      (unsigned long long)bh->b_blocknr, type,
			      function, file, line);
	return (me) ? -1 : -2;
}

/**
 * gfs2_metatype_check_ii - Flag a metadata type consistency error and withdraw
 * Returns: -1 if this call withdrew the machine,
 *          -2 if it was already withdrawn
 */

int gfs2_metatype_check_ii(struct gfs2_sbd *sdp, struct buffer_head *bh,
			   u16 type, u16 t, const char *function,
			   char *file, unsigned int line)
{
	int me;
	me = gfs2_lm_withdraw(sdp,
			      "fatal: invalid metadata block\n"
			      "  bh = %llu (type: exp=%u, found=%u)\n"
			      "  function = %s, file = %s, line = %u\n",
			      (unsigned long long)bh->b_blocknr, type, t,
			      function, file, line);
	return (me) ? -1 : -2;
}

/**
 * gfs2_io_error_i - Flag an I/O error and withdraw
 * Returns: -1 if this call withdrew the machine,
 *          0 if it was already withdrawn
 */

int gfs2_io_error_i(struct gfs2_sbd *sdp, const char *function, char *file,
		    unsigned int line)
{
	int rv;
	rv = gfs2_lm_withdraw(sdp,
			      "fatal: I/O error\n"
			      "  function = %s, file = %s, line = %u\n",
			      function, file, line);
	return rv;
}

/**
 * gfs2_io_error_bh_i - Flag a buffer I/O error and withdraw
 * Returns: -1 if this call withdrew the machine,
 *          0 if it was already withdrawn
 */

int gfs2_io_error_bh_i(struct gfs2_sbd *sdp, struct buffer_head *bh,
		       const char *function, char *file, unsigned int line)
{
	int rv;
	rv = gfs2_lm_withdraw(sdp,
			      "fatal: I/O error\n"
			      "  block = %llu\n"
			      "  function = %s, file = %s, line = %u\n",
			      (unsigned long long)bh->b_blocknr,
			      function, file, line);
	return rv;
}
