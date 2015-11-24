/*
 *  linux/fs/ext3/balloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  Enhanced block allocation by Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/quotaops.h>
#include <linux/blkdev.h>
#include "ext3.h"
#include "../../inc/__fss.h"

/*
 * balloc.c contains the blocks allocation and deallocation routines
 */

/*
 * The free blocks are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.  The descriptors are loaded in memory
 * when a file system is mounted (see ext3_fill_super).
 */


#define in_range(b, first, len)	((b) >= (first) && (b) <= (first) + (len) - 1)

/*
 * Calculate the block group number and offset, given a block number
 */
static void ext3_get_group_no_and_offset(struct super_block *sb,
	ext3_fsblk_t blocknr, unsigned long *blockgrpp, ext3_grpblk_t *offsetp)
{
	struct ext3_super_block *es = EXT3_SB(sb)->s_es;

	blocknr = blocknr - le32_to_cpu(es->s_first_data_block);
	if (offsetp)
		*offsetp = blocknr % EXT3_BLOCKS_PER_GROUP(sb);
	if (blockgrpp)
		*blockgrpp = blocknr / EXT3_BLOCKS_PER_GROUP(sb);
}

/**
 * ext3_get_group_desc() -- load group descriptor from disk
 * @sb:			super block
 * @block_group:	given block group
 * @bh:			pointer to the buffer head to store the block
 *			group descriptor
 */
struct ext3_group_desc * ext3_get_group_desc(struct super_block * sb,
					     unsigned int block_group,
					     struct buffer_head ** bh)
{
	unsigned long group_desc;
	unsigned long offset;
	struct ext3_group_desc * desc;
	struct ext3_sb_info *sbi = EXT3_SB(sb);

	if (block_group >= sbi->s_groups_count) {
		ext3_error (sb, "ext3_get_group_desc",
			    "block_group >= groups_count - "
			    "block_group = %d, groups_count = %lu",
			    block_group, sbi->s_groups_count);

		return NULL;
	}
	smp_rmb();

	group_desc = block_group >> EXT3_DESC_PER_BLOCK_BITS(sb);
	offset = block_group & (EXT3_DESC_PER_BLOCK(sb) - 1);
	if (!sbi->s_group_desc[group_desc]) {
		ext3_error (sb, "ext3_get_group_desc",
			    "Group descriptor not loaded - "
			    "block_group = %d, group_desc = %lu, desc = %lu",
			     block_group, group_desc, offset);
		return NULL;
	}

	desc = (struct ext3_group_desc *) sbi->s_group_desc[group_desc]->b_data;
	if (bh)
		*bh = sbi->s_group_desc[group_desc];
	return desc + offset;
}

static int ext3_valid_block_bitmap(struct super_block *sb,
					struct ext3_group_desc *desc,
					unsigned int block_group,
					struct buffer_head *bh)
{
	ext3_grpblk_t offset;
	ext3_grpblk_t next_zero_bit;
	ext3_fsblk_t bitmap_blk;
	ext3_fsblk_t group_first_block;

	group_first_block = ext3_group_first_block_no(sb, block_group);

	/* check whether block bitmap block number is set */
	bitmap_blk = le32_to_cpu(desc->bg_block_bitmap);
	offset = bitmap_blk - group_first_block;
	if (!ext3_test_bit(offset, bh->b_data))
		/* bad block bitmap */
		goto err_out;

	/* check whether the inode bitmap block number is set */
	bitmap_blk = le32_to_cpu(desc->bg_inode_bitmap);
	offset = bitmap_blk - group_first_block;
	if (!ext3_test_bit(offset, bh->b_data))
		/* bad block bitmap */
		goto err_out;

	/* check whether the inode table block number is set */
	bitmap_blk = le32_to_cpu(desc->bg_inode_table);
	offset = bitmap_blk - group_first_block;
	next_zero_bit = ext3_find_next_zero_bit(bh->b_data,
				offset + EXT3_SB(sb)->s_itb_per_group,
				offset);
	if (next_zero_bit >= offset + EXT3_SB(sb)->s_itb_per_group)
		/* good bitmap for inode tables */
		return 1;

err_out:
	ext3_error(sb, __func__,
			"Invalid block bitmap - "
			"block_group = %d, block = %lu",
			block_group, bitmap_blk);
	return 0;
}

/**
 * read_block_bitmap()
 * @sb:			super block
 * @block_group:	given block group
 *
 * Read the bitmap for a given block_group,and validate the
 * bits for block/inode/inode tables are set in the bitmaps
 *
 * Return buffer_head on success or NULL in case of failure.
 */
static struct buffer_head *
read_block_bitmap(struct super_block *sb, unsigned int block_group)
{
	struct ext3_group_desc * desc;
	struct buffer_head * bh = NULL;
	ext3_fsblk_t bitmap_blk;

	desc = ext3_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return NULL;
	trace_ext3_read_block_bitmap(sb, block_group);
	bitmap_blk = le32_to_cpu(desc->bg_block_bitmap);
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ext3_error(sb, __func__,
			    "Cannot read block bitmap - "
			    "block_group = %d, block_bitmap = %u",
			    block_group, le32_to_cpu(desc->bg_block_bitmap));
		return NULL;
	}
	if (likely(bh_uptodate_or_lock(bh)))
		return bh;

	if (bh_submit_read(bh) < 0) {
		brelse(bh);
		ext3_error(sb, __func__,
			    "Cannot read block bitmap - "
			    "block_group = %d, block_bitmap = %u",
			    block_group, le32_to_cpu(desc->bg_block_bitmap));
		return NULL;
	}
	ext3_valid_block_bitmap(sb, desc, block_group, bh);
	/*
	 * file system mounted not to panic on error, continue with corrupt
	 * bitmap
	 */
	return bh;
}
/*
 * The reservation window structure operations
 * --------------------------------------------
 * Operations include:
 * dump, find, add, remove, is_empty, find_next_reservable_window, etc.
 *
 * We use a red-black tree to represent per-filesystem reservation
 * windows.
 *
 */

/**
 * __rsv_window_dump() -- Dump the filesystem block allocation reservation map
 * @rb_root:		root of per-filesystem reservation rb tree
 * @verbose:		verbose mode
 * @fn:			function which wishes to dump the reservation map
 *
 * If verbose is turned on, it will print the whole block reservation
 * windows(start, end).	Otherwise, it will only print out the "bad" windows,
 * those windows that overlap with their immediate neighbors.
 */
#if 1
static void __rsv_window_dump(struct rb_root *root, int verbose,
			      const char *fn)
{
	struct rb_node *n;
	struct ext3_reserve_window_node *rsv, *prev;
	int bad;

restart:
	n = rb_first(root);
	bad = 0;
	prev = NULL;

	printk("Block Allocation Reservation Windows Map (%s):\n", fn);
	while (n) {
		rsv = rb_entry(n, struct ext3_reserve_window_node, rsv_node);
		if (verbose)
			printk("reservation window 0x%p "
			       "start:  %lu, end:  %lu\n",
			       rsv, rsv->rsv_start, rsv->rsv_end);
		if (rsv->rsv_start && rsv->rsv_start >= rsv->rsv_end) {
			printk("Bad reservation %p (start >= end)\n",
			       rsv);
			bad = 1;
		}
		if (prev && prev->rsv_end >= rsv->rsv_start) {
			printk("Bad reservation %p (prev->end >= start)\n",
			       rsv);
			bad = 1;
		}
		if (bad) {
			if (!verbose) {
				printk("Restarting reservation walk in verbose mode\n");
				verbose = 1;
				goto restart;
			}
		}
		n = rb_next(n);
		prev = rsv;
	}
	printk("Window map complete.\n");
	BUG_ON(bad);
}
#define rsv_window_dump(root, verbose) \
	__rsv_window_dump((root), (verbose), __func__)
#else
#define rsv_window_dump(root, verbose) do {} while (0)
#endif

/**
 * goal_in_my_reservation()
 * @rsv:		inode's reservation window
 * @grp_goal:		given goal block relative to the allocation block group
 * @group:		the current allocation block group
 * @sb:			filesystem super block
 *
 * Test if the given goal block (group relative) is within the file's
 * own block reservation window range.
 *
 * If the reservation window is outside the goal allocation group, return 0;
 * grp_goal (given goal block) could be -1, which means no specific
 * goal block. In this case, always return 1.
 * If the goal block is within the reservation window, return 1;
 * otherwise, return 0;
 */
static int
goal_in_my_reservation(struct ext3_reserve_window *rsv, ext3_grpblk_t grp_goal,
			unsigned int group, struct super_block * sb)
{
	ext3_fsblk_t group_first_block, group_last_block;

	group_first_block = ext3_group_first_block_no(sb, group);
	group_last_block = group_first_block + (EXT3_BLOCKS_PER_GROUP(sb) - 1);

	if ((rsv->_rsv_start > group_last_block) ||
	    (rsv->_rsv_end < group_first_block))
		return 0;
	if ((grp_goal >= 0) && ((grp_goal + group_first_block < rsv->_rsv_start)
		|| (grp_goal + group_first_block > rsv->_rsv_end)))
		return 0;
	return 1;
}

/**
 * search_reserve_window()
 * @rb_root:		root of reservation tree
 * @goal:		target allocation block
 *
 * Find the reserved window which includes the goal, or the previous one
 * if the goal is not in any window.
 * Returns NULL if there are no windows or if all windows start after the goal.
 */
static struct ext3_reserve_window_node *
search_reserve_window(struct rb_root *root, ext3_fsblk_t goal)
{
	struct rb_node *n = root->rb_node;
	struct ext3_reserve_window_node *rsv;

	if (!n)
		return NULL;

	do {
		rsv = rb_entry(n, struct ext3_reserve_window_node, rsv_node);

		if (goal < rsv->rsv_start)
			n = n->rb_left;
		else if (goal > rsv->rsv_end)
			n = n->rb_right;
		else
			return rsv;
	} while (n);
	/*
	 * We've fallen off the end of the tree: the goal wasn't inside
	 * any particular node.  OK, the previous node must be to one
	 * side of the interval containing the goal.  If it's the RHS,
	 * we need to back up one.
	 */
	if (rsv->rsv_start > goal) {
		n = rb_prev(&rsv->rsv_node);
		rsv = rb_entry(n, struct ext3_reserve_window_node, rsv_node);
	}
	return rsv;
}

/**
 * ext3_rsv_window_add() -- Insert a window to the block reservation rb tree.
 * @sb:			super block
 * @rsv:		reservation window to add
 *
 * Must be called with rsv_lock hold.
 */
void ext3_rsv_window_add(struct super_block *sb,
		    struct ext3_reserve_window_node *rsv)
{
	struct rb_root *root = &EXT3_SB(sb)->s_rsv_window_root;
	struct rb_node *node = &rsv->rsv_node;
	ext3_fsblk_t start = rsv->rsv_start;

	struct rb_node ** p = &root->rb_node;
	struct rb_node * parent = NULL;
	struct ext3_reserve_window_node *this;

	trace_ext3_rsv_window_add(sb, rsv);
	while (*p)
	{
		parent = *p;
		this = rb_entry(parent, struct ext3_reserve_window_node, rsv_node);

		if (start < this->rsv_start)
			p = &(*p)->rb_left;
		else if (start > this->rsv_end)
			p = &(*p)->rb_right;
		else {
			rsv_window_dump(root, 1);
			BUG();
		}
	}

	rb_link_node(node, parent, p);
	rb_insert_color(node, root);
}

/**
 * ext3_rsv_window_remove() -- unlink a window from the reservation rb tree
 * @sb:			super block
 * @rsv:		reservation window to remove
 *
 * Mark the block reservation window as not allocated, and unlink it
 * from the filesystem reservation window rb tree. Must be called with
 * rsv_lock hold.
 */
static void rsv_window_remove(struct super_block *sb,
			      struct ext3_reserve_window_node *rsv)
{
	rsv->rsv_start = EXT3_RESERVE_WINDOW_NOT_ALLOCATED;
	rsv->rsv_end = EXT3_RESERVE_WINDOW_NOT_ALLOCATED;
	rsv->rsv_alloc_hit = 0;
	rb_erase(&rsv->rsv_node, &EXT3_SB(sb)->s_rsv_window_root);
}

/*
 * rsv_is_empty() -- Check if the reservation window is allocated.
 * @rsv:		given reservation window to check
 *
 * returns 1 if the end block is EXT3_RESERVE_WINDOW_NOT_ALLOCATED.
 */
static inline int rsv_is_empty(struct ext3_reserve_window *rsv)
{
	/* a valid reservation end block could not be 0 */
	return rsv->_rsv_end == EXT3_RESERVE_WINDOW_NOT_ALLOCATED;
}

/**
 * ext3_init_block_alloc_info()
 * @inode:		file inode structure
 *
 * Allocate and initialize the	reservation window structure, and
 * link the window to the ext3 inode structure at last
 *
 * The reservation window structure is only dynamically allocated
 * and linked to ext3 inode the first time the open file
 * needs a new block. So, before every ext3_new_block(s) call, for
 * regular files, we should check whether the reservation window
 * structure exists or not. In the latter case, this function is called.
 * Fail to do so will result in block reservation being turned off for that
 * open file.
 *
 * This function is called from ext3_get_blocks_handle(), also called
 * when setting the reservation window size through ioctl before the file
 * is open for write (needs block allocation).
 *
 * Needs truncate_mutex protection prior to call this function.
 */
void ext3_init_block_alloc_info(struct inode *inode)
{
	struct ext3_inode_info *ei = EXT3_I(inode);
	struct ext3_block_alloc_info *block_i;
	struct super_block *sb = inode->i_sb;

	block_i = kmalloc(sizeof(*block_i), GFP_NOFS);
	if (block_i) {
		struct ext3_reserve_window_node *rsv = &block_i->rsv_window_node;

		rsv->rsv_start = EXT3_RESERVE_WINDOW_NOT_ALLOCATED;
		rsv->rsv_end = EXT3_RESERVE_WINDOW_NOT_ALLOCATED;

		/*
		 * if filesystem is mounted with NORESERVATION, the goal
		 * reservation window size is set to zero to indicate
		 * block reservation is off
		 */
		if (!test_opt(sb, RESERVATION))
			rsv->rsv_goal_size = 0;
		else
			rsv->rsv_goal_size = EXT3_DEFAULT_RESERVE_BLOCKS;
		rsv->rsv_alloc_hit = 0;
		block_i->last_alloc_logical_block = 0;
		block_i->last_alloc_physical_block = 0;
	}
	ei->i_block_alloc_info = block_i;
}

/**
 * ext3_discard_reservation()
 * @inode:		inode
 *
 * Discard(free) block reservation window on last file close, or truncate
 * or at last iput().
 *
 * It is being called in three cases:
 *	ext3_release_file(): last writer close the file
 *	ext3_clear_inode(): last iput(), when nobody link to this file.
 *	ext3_truncate(): when the block indirect map is about to change.
 *
 */
void ext3_discard_reservation(struct inode *inode)
{
	struct ext3_inode_info *ei = EXT3_I(inode);
	struct ext3_block_alloc_info *block_i = ei->i_block_alloc_info;
	struct ext3_reserve_window_node *rsv;
	spinlock_t *rsv_lock = &EXT3_SB(inode->i_sb)->s_rsv_window_lock;

	if (!block_i)
		return;

	rsv = &block_i->rsv_window_node;
	if (!rsv_is_empty(&rsv->rsv_window)) {
		spin_lock(rsv_lock);
		if (!rsv_is_empty(&rsv->rsv_window)) {
			trace_ext3_discard_reservation(inode, rsv);
			rsv_window_remove(inode->i_sb, rsv);
		}
		spin_unlock(rsv_lock);
	}
}

/**
 * ext3_free_blocks_sb() -- Free given blocks and update quota
 * @handle:			handle to this transaction
 * @sb:				super block
 * @block:			start physical block to free
 * @count:			number of blocks to free
 * @pdquot_freed_blocks:	pointer to quota
 */
void ext3_free_blocks_sb(handle_t *handle, struct super_block *sb,
			 ext3_fsblk_t block, unsigned long count,
			 unsigned long *pdquot_freed_blocks)
{
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *gd_bh;
	unsigned long block_group;
	ext3_grpblk_t bit;
	unsigned long i;
	unsigned long overflow;
	struct ext3_group_desc * desc;
	struct ext3_super_block * es;
	struct ext3_sb_info *sbi;
	int err = 0, ret;
	ext3_grpblk_t group_freed;

	*pdquot_freed_blocks = 0;
	sbi = EXT3_SB(sb);
	es = sbi->s_es;
	if (block < le32_to_cpu(es->s_first_data_block) ||
	    block + count < block ||
	    block + count > le32_to_cpu(es->s_blocks_count)) {
		ext3_error (sb, "ext3_free_blocks",
			    "Freeing blocks not in datazone - "
			    "block = "E3FSBLK", count = %lu", block, count);
		goto error_return;
	}

	ext3_debug ("freeing block(s) %lu-%lu\n", block, block + count - 1);

do_more:
	overflow = 0;
	block_group = (block - le32_to_cpu(es->s_first_data_block)) /
		      EXT3_BLOCKS_PER_GROUP(sb);
	bit = (block - le32_to_cpu(es->s_first_data_block)) %
		      EXT3_BLOCKS_PER_GROUP(sb);
	/*
	 * Check to see if we are freeing blocks across a group
	 * boundary.
	 */
	if (bit + count > EXT3_BLOCKS_PER_GROUP(sb)) {
		overflow = bit + count - EXT3_BLOCKS_PER_GROUP(sb);
		count -= overflow;
	}
	brelse(bitmap_bh);
	bitmap_bh = read_block_bitmap(sb, block_group);
	if (!bitmap_bh)
		goto error_return;
	desc = ext3_get_group_desc (sb, block_group, &gd_bh);
	if (!desc)
		goto error_return;

	if (in_range (le32_to_cpu(desc->bg_block_bitmap), block, count) ||
	    in_range (le32_to_cpu(desc->bg_inode_bitmap), block, count) ||
	    in_range (block, le32_to_cpu(desc->bg_inode_table),
		      sbi->s_itb_per_group) ||
	    in_range (block + count - 1, le32_to_cpu(desc->bg_inode_table),
		      sbi->s_itb_per_group)) {
		ext3_error (sb, "ext3_free_blocks",
			    "Freeing blocks in system zones - "
			    "Block = "E3FSBLK", count = %lu",
			    block, count);
		goto error_return;
	}

	/*
	 * We are about to start releasing blocks in the bitmap,
	 * so we need undo access.
	 */
	/* @@@ check errors */
	BUFFER_TRACE(bitmap_bh, "getting undo access");
	err = ext3_journal_get_undo_access(handle, bitmap_bh);
	if (err)
		goto error_return;

	/*
	 * We are about to modify some metadata.  Call the journal APIs
	 * to unshare ->b_data if a currently-committing transaction is
	 * using it
	 */
	BUFFER_TRACE(gd_bh, "get_write_access");
	err = ext3_journal_get_write_access(handle, gd_bh);
	if (err)
		goto error_return;

	jbd_lock_bh_state(bitmap_bh);

	for (i = 0, group_freed = 0; i < count; i++) {
		/*
		 * An HJ special.  This is expensive...
		 */
#ifdef CONFIG_JBD_DEBUG
		jbd_unlock_bh_state(bitmap_bh);
		{
			struct buffer_head *debug_bh;
			debug_bh = sb_find_get_block(sb, block + i);
			if (debug_bh) {
				BUFFER_TRACE(debug_bh, "Deleted!");
				if (!bh2jh(bitmap_bh)->b_committed_data)
					BUFFER_TRACE(debug_bh,
						"No committed data in bitmap");
				BUFFER_TRACE2(debug_bh, bitmap_bh, "bitmap");
				__brelse(debug_bh);
			}
		}
		jbd_lock_bh_state(bitmap_bh);
#endif
		if (need_resched()) {
			jbd_unlock_bh_state(bitmap_bh);
			cond_resched();
			jbd_lock_bh_state(bitmap_bh);
		}
		/* @@@ This prevents newly-allocated data from being
		 * freed and then reallocated within the same
		 * transaction.
		 *
		 * Ideally we would want to allow that to happen, but to
		 * do so requires making journal_forget() capable of
		 * revoking the queued write of a data block, which
		 * implies blocking on the journal lock.  *forget()
		 * cannot block due to truncate races.
		 *
		 * Eventually we can fix this by making journal_forget()
		 * return a status indicating whether or not it was able
		 * to revoke the buffer.  On successful revoke, it is
		 * safe not to set the allocation bit in the committed
		 * bitmap, because we know that there is no outstanding
		 * activity on the buffer any more and so it is safe to
		 * reallocate it.
		 */
		BUFFER_TRACE(bitmap_bh, "set in b_committed_data");
		J_ASSERT_BH(bitmap_bh,
				bh2jh(bitmap_bh)->b_committed_data != NULL);
		ext3_set_bit_atomic(sb_bgl_lock(sbi, block_group), bit + i,
				bh2jh(bitmap_bh)->b_committed_data);

		/*
		 * We clear the bit in the bitmap after setting the committed
		 * data bit, because this is the reverse order to that which
		 * the allocator uses.
		 */
		BUFFER_TRACE(bitmap_bh, "clear bit");
		if (!ext3_clear_bit_atomic(sb_bgl_lock(sbi, block_group),
						bit + i, bitmap_bh->b_data)) {
			jbd_unlock_bh_state(bitmap_bh);
			ext3_error(sb, __func__,
				"bit already cleared for block "E3FSBLK,
				 block + i);
			jbd_lock_bh_state(bitmap_bh);
			BUFFER_TRACE(bitmap_bh, "bit already cleared");
		} else {
			group_freed++;
		}
	}
	jbd_unlock_bh_state(bitmap_bh);

	spin_lock(sb_bgl_lock(sbi, block_group));
	le16_add_cpu(&desc->bg_free_blocks_count, group_freed);
	spin_unlock(sb_bgl_lock(sbi, block_group));
	percpu_counter_add(&sbi->s_freeblocks_counter, count);

	/* We dirtied the bitmap block */
	BUFFER_TRACE(bitmap_bh, "dirtied bitmap block");
	err = ext3_journal_dirty_metadata(handle, bitmap_bh);

	/* And the group descriptor block */
	BUFFER_TRACE(gd_bh, "dirtied group descriptor block");
	ret = ext3_journal_dirty_metadata(handle, gd_bh);
	if (!err) err = ret;
	*pdquot_freed_blocks += group_freed;

	if (overflow && !err) {
		block += count;
		count = overflow;
		goto do_more;
	}

error_return:
	brelse(bitmap_bh);
	ext3_std_error(sb, err);
	return;
}

/**
 * ext3_free_blocks() -- Free given blocks and update quota
 * @handle:		handle for this transaction
 * @inode:		inode
 * @block:		start physical block to free
 * @count:		number of blocks to count
 */
void ext3_free_blocks(handle_t *handle, struct inode *inode,
			ext3_fsblk_t block, unsigned long count)
{
	struct super_block *sb = inode->i_sb;
	unsigned long dquot_freed_blocks;

	trace_ext3_free_blocks(inode, block, count);
	ext3_free_blocks_sb(handle, sb, block, count, &dquot_freed_blocks);
	if (dquot_freed_blocks)
		dquot_free_block(inode, dquot_freed_blocks);
	return;
}

/**
 * ext3_test_allocatable()
 * @nr:			given allocation block group
 * @bh:			bufferhead contains the bitmap of the given block group
 *
 * For ext3 allocations, we must not reuse any blocks which are
 * allocated in the bitmap buffer's "last committed data" copy.  This
 * prevents deletes from freeing up the page for reuse until we have
 * committed the delete transaction.
 *
 * If we didn't do this, then deleting something and reallocating it as
 * data would allow the old block to be overwritten before the
 * transaction committed (because we force data to disk before commit).
 * This would lead to corruption if we crashed between overwriting the
 * data and committing the delete.
 *
 * @@@ We may want to make this allocation behaviour conditional on
 * data-writes at some point, and disable it for metadata allocations or
 * sync-data inodes.
 */
static int ext3_test_allocatable(ext3_grpblk_t nr, struct buffer_head *bh)
{
	int ret;
	struct journal_head *jh = bh2jh(bh);

	if (ext3_test_bit(nr, bh->b_data))
		return 0;

	jbd_lock_bh_state(bh);
	if (!jh->b_committed_data)
		ret = 1;
	else
		ret = !ext3_test_bit(nr, jh->b_committed_data);
	jbd_unlock_bh_state(bh);
	return ret;
}

/**
 * bitmap_search_next_usable_block()
 * @start:		the starting block (group relative) of the search
 * @bh:			bufferhead contains the block group bitmap
 * @maxblocks:		the ending block (group relative) of the reservation
 *
 * The bitmap search --- search forward alternately through the actual
 * bitmap on disk and the last-committed copy in journal, until we find a
 * bit free in both bitmaps.
 */
static ext3_grpblk_t
bitmap_search_next_usable_block(ext3_grpblk_t start, struct buffer_head *bh,
					ext3_grpblk_t maxblocks)
{
	ext3_grpblk_t next;
	struct journal_head *jh = bh2jh(bh);

	while (start < maxblocks) {
		next = ext3_find_next_zero_bit(bh->b_data, maxblocks, start);
		if (next >= maxblocks)
			return -1;
		if (ext3_test_allocatable(next, bh))
			return next;
		jbd_lock_bh_state(bh);
		if (jh->b_committed_data)
			start = ext3_find_next_zero_bit(jh->b_committed_data,
							maxblocks, next);
		jbd_unlock_bh_state(bh);
	}
	return -1;
}

/**
 * find_next_usable_block()
 * @start:		the starting block (group relative) to find next
 *			allocatable block in bitmap.
 * @bh:			bufferhead contains the block group bitmap
 * @maxblocks:		the ending block (group relative) for the search
 *
 * Find an allocatable block in a bitmap.  We honor both the bitmap and
 * its last-committed copy (if that exists), and perform the "most
 * appropriate allocation" algorithm of looking for a free block near
 * the initial goal; then for a free byte somewhere in the bitmap; then
 * for any free bit in the bitmap.
 */
static ext3_grpblk_t
find_next_usable_block(ext3_grpblk_t start, struct buffer_head *bh,
			ext3_grpblk_t maxblocks)
{
	ext3_grpblk_t here, next;
	char *p, *r;

	if (start > 0) {
		/*
		 * The goal was occupied; search forward for a free
		 * block within the next XX blocks.
		 *
		 * end_goal is more or less random, but it has to be
		 * less than EXT3_BLOCKS_PER_GROUP. Aligning up to the
		 * next 64-bit boundary is simple..
		 */
		ext3_grpblk_t end_goal = (start + 63) & ~63;
		if (end_goal > maxblocks)
			end_goal = maxblocks;
		here = ext3_find_next_zero_bit(bh->b_data, end_goal, start);
		if (here < end_goal && ext3_test_allocatable(here, bh))
			return here;
		ext3_debug("Bit not found near goal\n");
	}

	here = start;
	if (here < 0)
		here = 0;

	p = bh->b_data + (here >> 3);
	r = memscan(p, 0, ((maxblocks + 7) >> 3) - (here >> 3));
	next = (r - bh->b_data) << 3;

	if (next < maxblocks && next >= start && ext3_test_allocatable(next, bh))
		return next;

	/*
	 * The bitmap search --- search forward alternately through the actual
	 * bitmap and the last-committed copy until we find a bit free in
	 * both
	 */
	here = bitmap_search_next_usable_block(here, bh, maxblocks);
	return here;
}

/**
 * claim_block()
 * @lock:		the spin lock for this block group
 * @block:		the free block (group relative) to allocate
 * @bh:			the buffer_head contains the block group bitmap
 *
 * We think we can allocate this block in this bitmap.  Try to set the bit.
 * If that succeeds then check that nobody has allocated and then freed the
 * block since we saw that is was not marked in b_committed_data.  If it _was_
 * allocated and freed then clear the bit in the bitmap again and return
 * zero (failure).
 */
static inline int
claim_block(spinlock_t *lock, ext3_grpblk_t block, struct buffer_head *bh)
{
	struct journal_head *jh = bh2jh(bh);
	int ret;

	if (ext3_set_bit_atomic(lock, block, bh->b_data))
		return 0;
	jbd_lock_bh_state(bh);
	if (jh->b_committed_data && ext3_test_bit(block,jh->b_committed_data)) {
		ext3_clear_bit_atomic(lock, block, bh->b_data);
		ret = 0;
	} else {
		ret = 1;
	}
	jbd_unlock_bh_state(bh);
	return ret;
}

/**
 * ext3_try_to_allocate()
 * @sb:			superblock
 * @handle:		handle to this transaction
 * @group:		given allocation block group
 * @bitmap_bh:		bufferhead holds the block bitmap
 * @grp_goal:		given target block within the group
 * @count:		target number of blocks to allocate
 * @my_rsv:		reservation window
 *
 * Attempt to allocate blocks within a give range. Set the range of allocation
 * first, then find the first free bit(s) from the bitmap (within the range),
 * and at last, allocate the blocks by claiming the found free bit as allocated.
 *
 * To set the range of this allocation:
 *	if there is a reservation window, only try to allocate block(s) from the
 *	file's own reservation window;
 *	Otherwise, the allocation range starts from the give goal block, ends at
 *	the block group's last block.
 *
 * If we failed to allocate the desired block then we may end up crossing to a
 * new bitmap.  In that case we must release write access to the old one via
 * ext3_journal_release_buffer(), else we'll run out of credits.
 */
static ext3_grpblk_t
ext3_try_to_allocate(struct super_block *sb, handle_t *handle, int group,
			struct buffer_head *bitmap_bh, ext3_grpblk_t grp_goal,
			unsigned long *count, struct ext3_reserve_window *my_rsv)
{
	ext3_fsblk_t group_first_block;
	ext3_grpblk_t start, end;
	unsigned long num = 0;

	/* we do allocation within the reservation window if we have a window */
	if (my_rsv) {
		group_first_block = ext3_group_first_block_no(sb, group);
		if (my_rsv->_rsv_start >= group_first_block)
			start = my_rsv->_rsv_start - group_first_block;
		else
			/* reservation window cross group boundary */
			start = 0;
		end = my_rsv->_rsv_end - group_first_block + 1;
		if (end > EXT3_BLOCKS_PER_GROUP(sb))
			/* reservation window crosses group boundary */
			end = EXT3_BLOCKS_PER_GROUP(sb);
		if ((start <= grp_goal) && (grp_goal < end))
			start = grp_goal;
		else
			grp_goal = -1;
	} else {
		if (grp_goal > 0)
			start = grp_goal;
		else
			start = 0;
		end = EXT3_BLOCKS_PER_GROUP(sb);
	}

	BUG_ON(start > EXT3_BLOCKS_PER_GROUP(sb));

repeat:
	if (grp_goal < 0 || !ext3_test_allocatable(grp_goal, bitmap_bh)) {
		grp_goal = find_next_usable_block(start, bitmap_bh, end);
		if (grp_goal < 0)
			goto fail_access;
		if (!my_rsv) {
			int i;

			for (i = 0; i < 7 && grp_goal > start &&
					ext3_test_allocatable(grp_goal - 1,
								bitmap_bh);
					i++, grp_goal--)
				;
		}
	}
	start = grp_goal;

	if (!claim_block(sb_bgl_lock(EXT3_SB(sb), group),
		grp_goal, bitmap_bh)) {
		/*
		 * The block was allocated by another thread, or it was
		 * allocated and then freed by another thread
		 */
		start++;
		grp_goal++;
		if (start >= end)
			goto fail_access;
		goto repeat;
	}
	num++;
	grp_goal++;
	while (num < *count && grp_goal < end
		&& ext3_test_allocatable(grp_goal, bitmap_bh)
		&& claim_block(sb_bgl_lock(EXT3_SB(sb), group),
				grp_goal, bitmap_bh)) {
		num++;
		grp_goal++;
	}
	*count = num;
	return grp_goal - num;
fail_access:
	*count = num;
	return -1;
}

/**
 *	find_next_reservable_window():
 *		find a reservable space within the given range.
 *		It does not allocate the reservation window for now:
 *		alloc_new_reservation() will do the work later.
 *
 *	@search_head: the head of the searching list;
 *		This is not necessarily the list head of the whole filesystem
 *
 *		We have both head and start_block to assist the search
 *		for the reservable space. The list starts from head,
 *		but we will shift to the place where start_block is,
 *		then start from there, when looking for a reservable space.
 *
 *	@my_rsv: the reservation window
 *
 *	@sb: the super block
 *
 *	@start_block: the first block we consider to start
 *			the real search from
 *
 *	@last_block:
 *		the maximum block number that our goal reservable space
 *		could start from. This is normally the last block in this
 *		group. The search will end when we found the start of next
 *		possible reservable space is out of this boundary.
 *		This could handle the cross boundary reservation window
 *		request.
 *
 *	basically we search from the given range, rather than the whole
 *	reservation double linked list, (start_block, last_block)
 *	to find a free region that is of my size and has not
 *	been reserved.
 *
 */
static int find_next_reservable_window(
				struct ext3_reserve_window_node *search_head,
				struct ext3_reserve_window_node *my_rsv,
				struct super_block * sb,
				ext3_fsblk_t start_block,
				ext3_fsblk_t last_block)
{
	struct rb_node *next;
	struct ext3_reserve_window_node *rsv, *prev;
	ext3_fsblk_t cur;
	int size = my_rsv->rsv_goal_size;

	/* TODO: make the start of the reservation window byte-aligned */
	/* cur = *start_block & ~7;*/
	cur = start_block;
	rsv = search_head;
	if (!rsv)
		return -1;

	while (1) {
		if (cur <= rsv->rsv_end)
			cur = rsv->rsv_end + 1;

		/* TODO?
		 * in the case we could not find a reservable space
		 * that is what is expected, during the re-search, we could
		 * remember what's the largest reservable space we could have
		 * and return that one.
		 *
		 * For now it will fail if we could not find the reservable
		 * space with expected-size (or more)...
		 */
		if (cur > last_block)
			return -1;		/* fail */

		prev = rsv;
		next = rb_next(&rsv->rsv_node);
		rsv = rb_entry(next,struct ext3_reserve_window_node,rsv_node);

		/*
		 * Reached the last reservation, we can just append to the
		 * previous one.
		 */
		if (!next)
			break;

		if (cur + size <= rsv->rsv_start) {
			/*
			 * Found a reserveable space big enough.  We could
			 * have a reservation across the group boundary here
			 */
			break;
		}
	}
	/*
	 * we come here either :
	 * when we reach the end of the whole list,
	 * and there is empty reservable space after last entry in the list.
	 * append it to the end of the list.
	 *
	 * or we found one reservable space in the middle of the list,
	 * return the reservation window that we could append to.
	 * succeed.
	 */

	if ((prev != my_rsv) && (!rsv_is_empty(&my_rsv->rsv_window)))
		rsv_window_remove(sb, my_rsv);

	/*
	 * Let's book the whole available window for now.  We will check the
	 * disk bitmap later and then, if there are free blocks then we adjust
	 * the window size if it's larger than requested.
	 * Otherwise, we will remove this node from the tree next time
	 * call find_next_reservable_window.
	 */
	my_rsv->rsv_start = cur;
	my_rsv->rsv_end = cur + size - 1;
	my_rsv->rsv_alloc_hit = 0;

	if (prev != my_rsv)
		ext3_rsv_window_add(sb, my_rsv);

	return 0;
}

/**
 *	alloc_new_reservation()--allocate a new reservation window
 *
 *		To make a new reservation, we search part of the filesystem
 *		reservation list (the list that inside the group). We try to
 *		allocate a new reservation window near the allocation goal,
 *		or the beginning of the group, if there is no goal.
 *
 *		We first find a reservable space after the goal, then from
 *		there, we check the bitmap for the first free block after
 *		it. If there is no free block until the end of group, then the
 *		whole group is full, we failed. Otherwise, check if the free
 *		block is inside the expected reservable space, if so, we
 *		succeed.
 *		If the first free block is outside the reservable space, then
 *		start from the first free block, we search for next available
 *		space, and go on.
 *
 *	on succeed, a new reservation will be found and inserted into the list
 *	It contains at least one free block, and it does not overlap with other
 *	reservation windows.
 *
 *	failed: we failed to find a reservation window in this group
 *
 *	@my_rsv: the reservation window
 *
 *	@grp_goal: The goal (group-relative).  It is where the search for a
 *		free reservable space should start from.
 *		if we have a grp_goal(grp_goal >0 ), then start from there,
 *		no grp_goal(grp_goal = -1), we start from the first block
 *		of the group.
 *
 *	@sb: the super block
 *	@group: the group we are trying to allocate in
 *	@bitmap_bh: the block group block bitmap
 *
 */
static int alloc_new_reservation(struct ext3_reserve_window_node *my_rsv,
		ext3_grpblk_t grp_goal, struct super_block *sb,
		unsigned int group, struct buffer_head *bitmap_bh)
{
	struct ext3_reserve_window_node *search_head;
	ext3_fsblk_t group_first_block, group_end_block, start_block;
	ext3_grpblk_t first_free_block;
	struct rb_root *fs_rsv_root = &EXT3_SB(sb)->s_rsv_window_root;
	unsigned long size;
	int ret;
	spinlock_t *rsv_lock = &EXT3_SB(sb)->s_rsv_window_lock;

	group_first_block = ext3_group_first_block_no(sb, group);
	group_end_block = group_first_block + (EXT3_BLOCKS_PER_GROUP(sb) - 1);

	if (grp_goal < 0)
		start_block = group_first_block;
	else
		start_block = grp_goal + group_first_block;

	trace_ext3_alloc_new_reservation(sb, start_block);
	size = my_rsv->rsv_goal_size;

	if (!rsv_is_empty(&my_rsv->rsv_window)) {
		/*
		 * if the old reservation is cross group boundary
		 * and if the goal is inside the old reservation window,
		 * we will come here when we just failed to allocate from
		 * the first part of the window. We still have another part
		 * that belongs to the next group. In this case, there is no
		 * point to discard our window and try to allocate a new one
		 * in this group(which will fail). we should
		 * keep the reservation window, just simply move on.
		 *
		 * Maybe we could shift the start block of the reservation
		 * window to the first block of next group.
		 */

		if ((my_rsv->rsv_start <= group_end_block) &&
				(my_rsv->rsv_end > group_end_block) &&
				(start_block >= my_rsv->rsv_start))
			return -1;

		if ((my_rsv->rsv_alloc_hit >
		     (my_rsv->rsv_end - my_rsv->rsv_start + 1) / 2)) {
			/*
			 * if the previously allocation hit ratio is
			 * greater than 1/2, then we double the size of
			 * the reservation window the next time,
			 * otherwise we keep the same size window
			 */
			size = size * 2;
			if (size > EXT3_MAX_RESERVE_BLOCKS)
				size = EXT3_MAX_RESERVE_BLOCKS;
			my_rsv->rsv_goal_size= size;
		}
	}

	spin_lock(rsv_lock);
	/*
	 * shift the search start to the window near the goal block
	 */
	search_head = search_reserve_window(fs_rsv_root, start_block);

	/*
	 * find_next_reservable_window() simply finds a reservable window
	 * inside the given range(start_block, group_end_block).
	 *
	 * To make sure the reservation window has a free bit inside it, we
	 * need to check the bitmap after we found a reservable window.
	 */
retry:
	ret = find_next_reservable_window(search_head, my_rsv, sb,
						start_block, group_end_block);

	if (ret == -1) {
		if (!rsv_is_empty(&my_rsv->rsv_window))
			rsv_window_remove(sb, my_rsv);
		spin_unlock(rsv_lock);
		return -1;
	}

	/*
	 * On success, find_next_reservable_window() returns the
	 * reservation window where there is a reservable space after it.
	 * Before we reserve this reservable space, we need
	 * to make sure there is at least a free block inside this region.
	 *
	 * searching the first free bit on the block bitmap and copy of
	 * last committed bitmap alternatively, until we found a allocatable
	 * block. Search start from the start block of the reservable space
	 * we just found.
	 */
	spin_unlock(rsv_lock);
	first_free_block = bitmap_search_next_usable_block(
			my_rsv->rsv_start - group_first_block,
			bitmap_bh, group_end_block - group_first_block + 1);

	if (first_free_block < 0) {
		/*
		 * no free block left on the bitmap, no point
		 * to reserve the space. return failed.
		 */
		spin_lock(rsv_lock);
		if (!rsv_is_empty(&my_rsv->rsv_window))
			rsv_window_remove(sb, my_rsv);
		spin_unlock(rsv_lock);
		return -1;		/* failed */
	}

	start_block = first_free_block + group_first_block;
	/*
	 * check if the first free block is within the
	 * free space we just reserved
	 */
	if (start_block >= my_rsv->rsv_start &&
	    start_block <= my_rsv->rsv_end) {
		trace_ext3_reserved(sb, start_block, my_rsv);
		return 0;		/* success */
	}
	/*
	 * if the first free bit we found is out of the reservable space
	 * continue search for next reservable space,
	 * start from where the free block is,
	 * we also shift the list head to where we stopped last time
	 */
	search_head = my_rsv;
	spin_lock(rsv_lock);
	goto retry;
}

/**
 * try_to_extend_reservation()
 * @my_rsv:		given reservation window
 * @sb:			super block
 * @size:		the delta to extend
 *
 * Attempt to expand the reservation window large enough to have
 * required number of free blocks
 *
 * Since ext3_try_to_allocate() will always allocate blocks within
 * the reservation window range, if the window size is too small,
 * multiple blocks allocation has to stop at the end of the reservation
 * window. To make this more efficient, given the total number of
 * blocks needed and the current size of the window, we try to
 * expand the reservation window size if necessary on a best-effort
 * basis before ext3_new_blocks() tries to allocate blocks,
 */
static void try_to_extend_reservation(struct ext3_reserve_window_node *my_rsv,
			struct super_block *sb, int size)
{
	struct ext3_reserve_window_node *next_rsv;
	struct rb_node *next;
	spinlock_t *rsv_lock = &EXT3_SB(sb)->s_rsv_window_lock;

	if (!spin_trylock(rsv_lock))
		return;

	next = rb_next(&my_rsv->rsv_node);

	if (!next)
		my_rsv->rsv_end += size;
	else {
		next_rsv = rb_entry(next, struct ext3_reserve_window_node, rsv_node);

		if ((next_rsv->rsv_start - my_rsv->rsv_end - 1) >= size)
			my_rsv->rsv_end += size;
		else
			my_rsv->rsv_end = next_rsv->rsv_start - 1;
	}
	spin_unlock(rsv_lock);
}

/**
 * ext3_try_to_allocate_with_rsv()
 * @sb:			superblock
 * @handle:		handle to this transaction
 * @group:		given allocation block group
 * @bitmap_bh:		bufferhead holds the block bitmap
 * @grp_goal:		given target block within the group
 * @my_rsv:		reservation window
 * @count:		target number of blocks to allocate
 * @errp:		pointer to store the error code
 *
 * This is the main function used to allocate a new block and its reservation
 * window.
 *
 * Each time when a new block allocation is need, first try to allocate from
 * its own reservation.  If it does not have a reservation window, instead of
 * looking for a free bit on bitmap first, then look up the reservation list to
 * see if it is inside somebody else's reservation window, we try to allocate a
 * reservation window for it starting from the goal first. Then do the block
 * allocation within the reservation window.
 *
 * This will avoid keeping on searching the reservation list again and
 * again when somebody is looking for a free block (without
 * reservation), and there are lots of free blocks, but they are all
 * being reserved.
 *
 * We use a red-black tree for the per-filesystem reservation list.
 *
 */
static ext3_grpblk_t
ext3_try_to_allocate_with_rsv(struct super_block *sb, handle_t *handle,
			unsigned int group, struct buffer_head *bitmap_bh,
			ext3_grpblk_t grp_goal,
			struct ext3_reserve_window_node * my_rsv,
			unsigned long *count, int *errp)
{
	ext3_fsblk_t group_first_block, group_last_block;
	ext3_grpblk_t ret = 0;
	int fatal;
	unsigned long num = *count;

	*errp = 0;

	/*
	 * Make sure we use undo access for the bitmap, because it is critical
	 * that we do the frozen_data COW on bitmap buffers in all cases even
	 * if the buffer is in BJ_Forget state in the committing transaction.
	 */
	BUFFER_TRACE(bitmap_bh, "get undo access for new block");
	fatal = ext3_journal_get_undo_access(handle, bitmap_bh);
	if (fatal) {
		*errp = fatal;
		return -1;
	}

	/*
	 * we don't deal with reservation when
	 * filesystem is mounted without reservation
	 * or the file is not a regular file
	 * or last attempt to allocate a block with reservation turned on failed
	 */
	if (my_rsv == NULL ) {
		ret = ext3_try_to_allocate(sb, handle, group, bitmap_bh,
						grp_goal, count, NULL);
		goto out;
	}
	/*
	 * grp_goal is a group relative block number (if there is a goal)
	 * 0 <= grp_goal < EXT3_BLOCKS_PER_GROUP(sb)
	 * first block is a filesystem wide block number
	 * first block is the block number of the first block in this group
	 */
	group_first_block = ext3_group_first_block_no(sb, group);
	group_last_block = group_first_block + (EXT3_BLOCKS_PER_GROUP(sb) - 1);

	/*
	 * Basically we will allocate a new block from inode's reservation
	 * window.
	 *
	 * We need to allocate a new reservation window, if:
	 * a) inode does not have a reservation window; or
	 * b) last attempt to allocate a block from existing reservation
	 *    failed; or
	 * c) we come here with a goal and with a reservation window
	 *
	 * We do not need to allocate a new reservation window if we come here
	 * at the beginning with a goal and the goal is inside the window, or
	 * we don't have a goal but already have a reservation window.
	 * then we could go to allocate from the reservation window directly.
	 */
	while (1) {
		if (rsv_is_empty(&my_rsv->rsv_window) || (ret < 0) ||
			!goal_in_my_reservation(&my_rsv->rsv_window,
						grp_goal, group, sb)) {
			if (my_rsv->rsv_goal_size < *count)
				my_rsv->rsv_goal_size = *count;
			ret = alloc_new_reservation(my_rsv, grp_goal, sb,
							group, bitmap_bh);
			if (ret < 0)
				break;			/* failed */

			if (!goal_in_my_reservation(&my_rsv->rsv_window,
							grp_goal, group, sb))
				grp_goal = -1;
		} else if (grp_goal >= 0) {
			int curr = my_rsv->rsv_end -
					(grp_goal + group_first_block) + 1;

			if (curr < *count)
				try_to_extend_reservation(my_rsv, sb,
							*count - curr);
		}

		if ((my_rsv->rsv_start > group_last_block) ||
				(my_rsv->rsv_end < group_first_block)) {
			rsv_window_dump(&EXT3_SB(sb)->s_rsv_window_root, 1);
			BUG();
		}
		ret = ext3_try_to_allocate(sb, handle, group, bitmap_bh,
					   grp_goal, &num, &my_rsv->rsv_window);
		if (ret >= 0) {
			my_rsv->rsv_alloc_hit += num;
			*count = num;
			break;				/* succeed */
		}
		num = *count;
	}
out:
	if (ret >= 0) {
		BUFFER_TRACE(bitmap_bh, "journal_dirty_metadata for "
					"bitmap block");
		fatal = ext3_journal_dirty_metadata(handle, bitmap_bh);
		if (fatal) {
			*errp = fatal;
			return -1;
		}
		return ret;
	}

	BUFFER_TRACE(bitmap_bh, "journal_release_buffer");
	ext3_journal_release_buffer(handle, bitmap_bh);
	return ret;
}

/**
 * ext3_has_free_blocks()
 * @sbi:		in-core super block structure.
 *
 * Check if filesystem has at least 1 free block available for allocation.
 */
static int ext3_has_free_blocks(struct ext3_sb_info *sbi, int use_reservation)
{
	ext3_fsblk_t free_blocks, root_blocks;

	free_blocks = percpu_counter_read_positive(&sbi->s_freeblocks_counter);
	root_blocks = le32_to_cpu(sbi->s_es->s_r_blocks_count);
	if (free_blocks < root_blocks + 1 && !capable(CAP_SYS_RESOURCE) &&
		!use_reservation && !uid_eq(sbi->s_resuid, current_fsuid()) &&
		(gid_eq(sbi->s_resgid, GLOBAL_ROOT_GID) ||
		 !in_group_p (sbi->s_resgid))) {
		return 0;
	}
	return 1;
}

/**
 * ext3_should_retry_alloc()
 * @sb:			super block
 * @retries		number of attemps has been made
 *
 * ext3_should_retry_alloc() is called when ENOSPC is returned, and if
 * it is profitable to retry the operation, this function will wait
 * for the current or committing transaction to complete, and then
 * return TRUE.
 *
 * if the total number of retries exceed three times, return FALSE.
 */
int ext3_should_retry_alloc(struct super_block *sb, int *retries)
{
	if (!ext3_has_free_blocks(EXT3_SB(sb), 0) || (*retries)++ > 3)
		return 0;

	jbd_debug(1, "%s: retrying operation after ENOSPC\n", sb->s_id);

	return journal_force_commit_nested(EXT3_SB(sb)->s_journal);
}

/**
 * ext3_new_blocks() -- core block(s) allocation function
 * @handle:		handle to this transaction
 * @inode:		file inode
 * @goal:		given target block(filesystem wide)
 * @count:		target number of blocks to allocate
 * @errp:		error code
 *
 * ext3_new_blocks uses a goal block to assist allocation.  It tries to
 * allocate block(s) from the block group contains the goal block first. If that
 * fails, it will try to allocate block(s) from other block groups without
 * any specific goal block.
 *
 */
ext3_fsblk_t ext3_new_blocks(handle_t *handle, struct inode *inode,
			ext3_fsblk_t goal, unsigned long *count, int *errp)
{
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *gdp_bh;
	int group_no;
	int goal_group;
	ext3_grpblk_t grp_target_blk;	/* blockgroup relative goal block */
	ext3_grpblk_t grp_alloc_blk;	/* blockgroup-relative allocated block*/
	ext3_fsblk_t ret_block;		/* filesyetem-wide allocated block */
	int bgi;			/* blockgroup iteration index */
	int fatal = 0, err;
	int performed_allocation = 0;
	ext3_grpblk_t free_blocks;	/* number of free blocks in a group */
	struct super_block *sb;
	struct ext3_group_desc *gdp;
	struct ext3_super_block *es;
	struct ext3_sb_info *sbi;
	struct ext3_reserve_window_node *my_rsv = NULL;
	struct ext3_block_alloc_info *block_i;
	unsigned short windowsz = 0;
#ifdef EXT3FS_DEBUG
	static int goal_hits, goal_attempts;
#endif
	unsigned long ngroups;
	unsigned long num = *count;

	*errp = -ENOSPC;
	sb = inode->i_sb;

	/*
	 * Check quota for allocation of this block.
	 */
	err = dquot_alloc_block(inode, num);
	if (err) {
		*errp = err;
		return 0;
	}

	trace_ext3_request_blocks(inode, goal, num);

	sbi = EXT3_SB(sb);
	es = sbi->s_es;
	ext3_debug("goal=%lu.\n", goal);
	/*
	 * Allocate a block from reservation only when
	 * filesystem is mounted with reservation(default,-o reservation), and
	 * it's a regular file, and
	 * the desired window size is greater than 0 (One could use ioctl
	 * command EXT3_IOC_SETRSVSZ to set the window size to 0 to turn off
	 * reservation on that particular file)
	 */
	block_i = EXT3_I(inode)->i_block_alloc_info;
	if (block_i && ((windowsz = block_i->rsv_window_node.rsv_goal_size) > 0))
		my_rsv = &block_i->rsv_window_node;

	if (!ext3_has_free_blocks(sbi, IS_NOQUOTA(inode))) {
		*errp = -ENOSPC;
		goto out;
	}

	/*
	 * First, test whether the goal block is free.
	 */
	if (goal < le32_to_cpu(es->s_first_data_block) ||
	    goal >= le32_to_cpu(es->s_blocks_count))
		goal = le32_to_cpu(es->s_first_data_block);
	group_no = (goal - le32_to_cpu(es->s_first_data_block)) /
			EXT3_BLOCKS_PER_GROUP(sb);
	goal_group = group_no;
retry_alloc:
	gdp = ext3_get_group_desc(sb, group_no, &gdp_bh);
	if (!gdp)
		goto io_error;

	free_blocks = le16_to_cpu(gdp->bg_free_blocks_count);
	/*
	 * if there is not enough free blocks to make a new resevation
	 * turn off reservation for this allocation
	 */
	if (my_rsv && (free_blocks < windowsz)
		&& (free_blocks > 0)
		&& (rsv_is_empty(&my_rsv->rsv_window)))
		my_rsv = NULL;

	if (free_blocks > 0) {
		grp_target_blk = ((goal - le32_to_cpu(es->s_first_data_block)) %
				EXT3_BLOCKS_PER_GROUP(sb));
		bitmap_bh = read_block_bitmap(sb, group_no);
		if (!bitmap_bh)
			goto io_error;
		grp_alloc_blk = ext3_try_to_allocate_with_rsv(sb, handle,
					group_no, bitmap_bh, grp_target_blk,
					my_rsv,	&num, &fatal);
		if (fatal)
			goto out;
		if (grp_alloc_blk >= 0)
			goto allocated;
	}

	ngroups = EXT3_SB(sb)->s_groups_count;
	smp_rmb();

	/*
	 * Now search the rest of the groups.  We assume that
	 * group_no and gdp correctly point to the last group visited.
	 */
	for (bgi = 0; bgi < ngroups; bgi++) {
		group_no++;
		if (group_no >= ngroups)
			group_no = 0;
		gdp = ext3_get_group_desc(sb, group_no, &gdp_bh);
		if (!gdp)
			goto io_error;
		free_blocks = le16_to_cpu(gdp->bg_free_blocks_count);
		/*
		 * skip this group (and avoid loading bitmap) if there
		 * are no free blocks
		 */
		if (!free_blocks)
			continue;
		/*
		 * skip this group if the number of
		 * free blocks is less than half of the reservation
		 * window size.
		 */
		if (my_rsv && (free_blocks <= (windowsz/2)))
			continue;

		brelse(bitmap_bh);
		bitmap_bh = read_block_bitmap(sb, group_no);
		if (!bitmap_bh)
			goto io_error;
		/*
		 * try to allocate block(s) from this group, without a goal(-1).
		 */
		grp_alloc_blk = ext3_try_to_allocate_with_rsv(sb, handle,
					group_no, bitmap_bh, -1, my_rsv,
					&num, &fatal);
		if (fatal)
			goto out;
		if (grp_alloc_blk >= 0)
			goto allocated;
	}
	/*
	 * We may end up a bogus earlier ENOSPC error due to
	 * filesystem is "full" of reservations, but
	 * there maybe indeed free blocks available on disk
	 * In this case, we just forget about the reservations
	 * just do block allocation as without reservations.
	 */
	if (my_rsv) {
		my_rsv = NULL;
		windowsz = 0;
		group_no = goal_group;
		goto retry_alloc;
	}
	/* No space left on the device */
	*errp = -ENOSPC;
	goto out;

allocated:

	ext3_debug("using block group %d(%d)\n",
			group_no, gdp->bg_free_blocks_count);

	BUFFER_TRACE(gdp_bh, "get_write_access");
	fatal = ext3_journal_get_write_access(handle, gdp_bh);
	if (fatal)
		goto out;

	ret_block = grp_alloc_blk + ext3_group_first_block_no(sb, group_no);

	if (in_range(le32_to_cpu(gdp->bg_block_bitmap), ret_block, num) ||
	    in_range(le32_to_cpu(gdp->bg_inode_bitmap), ret_block, num) ||
	    in_range(ret_block, le32_to_cpu(gdp->bg_inode_table),
		      EXT3_SB(sb)->s_itb_per_group) ||
	    in_range(ret_block + num - 1, le32_to_cpu(gdp->bg_inode_table),
		      EXT3_SB(sb)->s_itb_per_group)) {
		ext3_error(sb, "ext3_new_block",
			    "Allocating block in system zone - "
			    "blocks from "E3FSBLK", length %lu",
			     ret_block, num);
		/*
		 * claim_block() marked the blocks we allocated as in use. So we
		 * may want to selectively mark some of the blocks as free.
		 */
		goto retry_alloc;
	}

	performed_allocation = 1;

#ifdef CONFIG_JBD_DEBUG
	{
		struct buffer_head *debug_bh;

		/* Record bitmap buffer state in the newly allocated block */
		debug_bh = sb_find_get_block(sb, ret_block);
		if (debug_bh) {
			BUFFER_TRACE(debug_bh, "state when allocated");
			BUFFER_TRACE2(debug_bh, bitmap_bh, "bitmap state");
			brelse(debug_bh);
		}
	}
	jbd_lock_bh_state(bitmap_bh);
	spin_lock(sb_bgl_lock(sbi, group_no));
	if (buffer_jbd(bitmap_bh) && bh2jh(bitmap_bh)->b_committed_data) {
		int i;

		for (i = 0; i < num; i++) {
			if (ext3_test_bit(grp_alloc_blk+i,
					bh2jh(bitmap_bh)->b_committed_data)) {
				printk("%s: block was unexpectedly set in "
					"b_committed_data\n", __func__);
			}
		}
	}
	ext3_debug("found bit %d\n", grp_alloc_blk);
	spin_unlock(sb_bgl_lock(sbi, group_no));
	jbd_unlock_bh_state(bitmap_bh);
#endif

	if (ret_block + num - 1 >= le32_to_cpu(es->s_blocks_count)) {
		ext3_error(sb, "ext3_new_block",
			    "block("E3FSBLK") >= blocks count(%d) - "
			    "block_group = %d, es == %p ", ret_block,
			le32_to_cpu(es->s_blocks_count), group_no, es);
		goto out;
	}

	/*
	 * It is up to the caller to add the new buffer to a journal
	 * list of some description.  We don't know in advance whether
	 * the caller wants to use it as metadata or data.
	 */
	ext3_debug("allocating block %lu. Goal hits %d of %d.\n",
			ret_block, goal_hits, goal_attempts);

	spin_lock(sb_bgl_lock(sbi, group_no));
	le16_add_cpu(&gdp->bg_free_blocks_count, -num);
	spin_unlock(sb_bgl_lock(sbi, group_no));
	percpu_counter_sub(&sbi->s_freeblocks_counter, num);

	BUFFER_TRACE(gdp_bh, "journal_dirty_metadata for group descriptor");
	fatal = ext3_journal_dirty_metadata(handle, gdp_bh);
	if (fatal)
		goto out;

	*errp = 0;
	brelse(bitmap_bh);

	if (num < *count) {
		dquot_free_block(inode, *count-num);
		*count = num;
	}

	trace_ext3_allocate_blocks(inode, goal, num,
				   (unsigned long long)ret_block);

	return ret_block;

io_error:
	*errp = -EIO;
out:
	if (fatal) {
		*errp = fatal;
		ext3_std_error(sb, fatal);
	}
	/*
	 * Undo the block allocation
	 */
	if (!performed_allocation)
		dquot_free_block(inode, *count);
	brelse(bitmap_bh);
	return 0;
}

ext3_fsblk_t ext3_new_block(handle_t *handle, struct inode *inode,
			ext3_fsblk_t goal, int *errp)
{
	unsigned long count = 1;

	return ext3_new_blocks(handle, inode, goal, &count, errp);
}

/**
 * ext3_count_free_blocks() -- count filesystem free blocks
 * @sb:		superblock
 *
 * Adds up the number of free blocks from each block group.
 */
ext3_fsblk_t ext3_count_free_blocks(struct super_block *sb)
{
	ext3_fsblk_t desc_count;
	struct ext3_group_desc *gdp;
	int i;
	unsigned long ngroups = EXT3_SB(sb)->s_groups_count;
#ifdef EXT3FS_DEBUG
	struct ext3_super_block *es;
	ext3_fsblk_t bitmap_count;
	unsigned long x;
	struct buffer_head *bitmap_bh = NULL;

	es = EXT3_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;

	smp_rmb();
	for (i = 0; i < ngroups; i++) {
		gdp = ext3_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += le16_to_cpu(gdp->bg_free_blocks_count);
		brelse(bitmap_bh);
		bitmap_bh = read_block_bitmap(sb, i);
		if (bitmap_bh == NULL)
			continue;

		x = ext3_count_free(bitmap_bh, sb->s_blocksize);
		printk("group %d: stored = %d, counted = %lu\n",
			i, le16_to_cpu(gdp->bg_free_blocks_count), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk("ext3_count_free_blocks: stored = "E3FSBLK
		", computed = "E3FSBLK", "E3FSBLK"\n",
	       (ext3_fsblk_t)le32_to_cpu(es->s_free_blocks_count),
		desc_count, bitmap_count);
	return bitmap_count;
#else
	desc_count = 0;
	smp_rmb();
	for (i = 0; i < ngroups; i++) {
		gdp = ext3_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += le16_to_cpu(gdp->bg_free_blocks_count);
	}

	return desc_count;
#endif
}

static inline int test_root(int a, int b)
{
	int num = b;

	while (a > num)
		num *= b;
	return num == a;
}

static int ext3_group_sparse(int group)
{
	if (group <= 1)
		return 1;
	if (!(group & 1))
		return 0;
	return (test_root(group, 7) || test_root(group, 5) ||
		test_root(group, 3));
}

/**
 *	ext3_bg_has_super - number of blocks used by the superblock in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the superblock (primary or backup)
 *	in this group.  Currently this will be only 0 or 1.
 */
int ext3_bg_has_super(struct super_block *sb, int group)
{
	if (EXT3_HAS_RO_COMPAT_FEATURE(sb,
				EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER) &&
			!ext3_group_sparse(group))
		return 0;
	return 1;
}

static unsigned long ext3_bg_num_gdb_meta(struct super_block *sb, int group)
{
	unsigned long metagroup = group / EXT3_DESC_PER_BLOCK(sb);
	unsigned long first = metagroup * EXT3_DESC_PER_BLOCK(sb);
	unsigned long last = first + EXT3_DESC_PER_BLOCK(sb) - 1;

	if (group == first || group == first + 1 || group == last)
		return 1;
	return 0;
}

static unsigned long ext3_bg_num_gdb_nometa(struct super_block *sb, int group)
{
	return ext3_bg_has_super(sb, group) ? EXT3_SB(sb)->s_gdb_count : 0;
}

/**
 *	ext3_bg_num_gdb - number of blocks used by the group table in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the group descriptor table
 *	(primary or backup) in this group.  In the future there may be a
 *	different number of descriptor blocks in each group.
 */
unsigned long ext3_bg_num_gdb(struct super_block *sb, int group)
{
	unsigned long first_meta_bg =
			le32_to_cpu(EXT3_SB(sb)->s_es->s_first_meta_bg);
	unsigned long metagroup = group / EXT3_DESC_PER_BLOCK(sb);

	if (!EXT3_HAS_INCOMPAT_FEATURE(sb,EXT3_FEATURE_INCOMPAT_META_BG) ||
			metagroup < first_meta_bg)
		return ext3_bg_num_gdb_nometa(sb,group);

	return ext3_bg_num_gdb_meta(sb,group);

}

/**
 * ext3_trim_all_free -- function to trim all free space in alloc. group
 * @sb:			super block for file system
 * @group:		allocation group to trim
 * @start:		first group block to examine
 * @max:		last group block to examine
 * @gdp:		allocation group description structure
 * @minblocks:		minimum extent block count
 *
 * ext3_trim_all_free walks through group's block bitmap searching for free
 * blocks. When the free block is found, it tries to allocate this block and
 * consequent free block to get the biggest free extent possible, until it
 * reaches any used block. Then issue a TRIM command on this extent and free
 * the extent in the block bitmap. This is done until whole group is scanned.
 */
static ext3_grpblk_t ext3_trim_all_free(struct super_block *sb,
					unsigned int group,
					ext3_grpblk_t start, ext3_grpblk_t max,
					ext3_grpblk_t minblocks)
{
	handle_t *handle;
	ext3_grpblk_t next, free_blocks, bit, freed, count = 0;
	ext3_fsblk_t discard_block;
	struct ext3_sb_info *sbi;
	struct buffer_head *gdp_bh, *bitmap_bh = NULL;
	struct ext3_group_desc *gdp;
	int err = 0, ret = 0;

	/*
	 * We will update one block bitmap, and one group descriptor
	 */
	handle = ext3_journal_start_sb(sb, 2);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	bitmap_bh = read_block_bitmap(sb, group);
	if (!bitmap_bh) {
		err = -EIO;
		goto err_out;
	}

	BUFFER_TRACE(bitmap_bh, "getting undo access");
	err = ext3_journal_get_undo_access(handle, bitmap_bh);
	if (err)
		goto err_out;

	gdp = ext3_get_group_desc(sb, group, &gdp_bh);
	if (!gdp) {
		err = -EIO;
		goto err_out;
	}

	BUFFER_TRACE(gdp_bh, "get_write_access");
	err = ext3_journal_get_write_access(handle, gdp_bh);
	if (err)
		goto err_out;

	free_blocks = le16_to_cpu(gdp->bg_free_blocks_count);
	sbi = EXT3_SB(sb);

	 /* Walk through the whole group */
	while (start <= max) {
		start = bitmap_search_next_usable_block(start, bitmap_bh, max);
		if (start < 0)
			break;
		next = start;

		/*
		 * Allocate contiguous free extents by setting bits in the
		 * block bitmap
		 */
		while (next <= max
			&& claim_block(sb_bgl_lock(sbi, group),
					next, bitmap_bh)) {
			next++;
		}

		 /* We did not claim any blocks */
		if (next == start)
			continue;

		discard_block = (ext3_fsblk_t)start +
				ext3_group_first_block_no(sb, group);

		/* Update counters */
		spin_lock(sb_bgl_lock(sbi, group));
		le16_add_cpu(&gdp->bg_free_blocks_count, start - next);
		spin_unlock(sb_bgl_lock(sbi, group));
		percpu_counter_sub(&sbi->s_freeblocks_counter, next - start);

		free_blocks -= next - start;
		/* Do not issue a TRIM on extents smaller than minblocks */
		if ((next - start) < minblocks)
			goto free_extent;

		trace_ext3_discard_blocks(sb, discard_block, next - start);
		 /* Send the TRIM command down to the device */
		err = sb_issue_discard(sb, discard_block, next - start,
				       GFP_NOFS, 0);
		count += (next - start);
free_extent:
		freed = 0;

		/*
		 * Clear bits in the bitmap
		 */
		for (bit = start; bit < next; bit++) {
			BUFFER_TRACE(bitmap_bh, "clear bit");
			if (!ext3_clear_bit_atomic(sb_bgl_lock(sbi, group),
						bit, bitmap_bh->b_data)) {
				ext3_error(sb, __func__,
					"bit already cleared for block "E3FSBLK,
					 (unsigned long)bit);
				BUFFER_TRACE(bitmap_bh, "bit already cleared");
			} else {
				freed++;
			}
		}

		/* Update couters */
		spin_lock(sb_bgl_lock(sbi, group));
		le16_add_cpu(&gdp->bg_free_blocks_count, freed);
		spin_unlock(sb_bgl_lock(sbi, group));
		percpu_counter_add(&sbi->s_freeblocks_counter, freed);

		start = next;
		if (err < 0) {
			if (err != -EOPNOTSUPP)
				ext3_warning(sb, __func__, "Discard command "
					     "returned error %d\n", err);
			break;
		}

		if (fatal_signal_pending(current)) {
			err = -ERESTARTSYS;
			break;
		}

		cond_resched();

		/* No more suitable extents */
		if (free_blocks < minblocks)
			break;
	}

	/* We dirtied the bitmap block */
	BUFFER_TRACE(bitmap_bh, "dirtied bitmap block");
	ret = ext3_journal_dirty_metadata(handle, bitmap_bh);
	if (!err)
		err = ret;

	/* And the group descriptor block */
	BUFFER_TRACE(gdp_bh, "dirtied group descriptor block");
	ret = ext3_journal_dirty_metadata(handle, gdp_bh);
	if (!err)
		err = ret;

	ext3_debug("trimmed %d blocks in the group %d\n",
		count, group);

err_out:
	if (err)
		count = err;
	ext3_journal_stop(handle);
	brelse(bitmap_bh);

	return count;
}

/**
 * ext3_trim_fs() -- trim ioctl handle function
 * @sb:			superblock for filesystem
 * @start:		First Byte to trim
 * @len:		number of Bytes to trim from start
 * @minlen:		minimum extent length in Bytes
 *
 * ext3_trim_fs goes through all allocation groups containing Bytes from
 * start to start+len. For each such a group ext3_trim_all_free function
 * is invoked to trim all free space.
 */
int ext3_trim_fs(struct super_block *sb, struct fstrim_range *range)
{
	ext3_grpblk_t last_block, first_block;
	unsigned long group, first_group, last_group;
	struct ext3_group_desc *gdp;
	struct ext3_super_block *es = EXT3_SB(sb)->s_es;
	uint64_t start, minlen, end, trimmed = 0;
	ext3_fsblk_t first_data_blk =
			le32_to_cpu(EXT3_SB(sb)->s_es->s_first_data_block);
	ext3_fsblk_t max_blks = le32_to_cpu(es->s_blocks_count);
	int ret = 0;

	start = range->start >> sb->s_blocksize_bits;
	end = start + (range->len >> sb->s_blocksize_bits) - 1;
	minlen = range->minlen >> sb->s_blocksize_bits;

	if (minlen > EXT3_BLOCKS_PER_GROUP(sb) ||
	    start >= max_blks ||
	    range->len < sb->s_blocksize)
		return -EINVAL;
	if (end >= max_blks)
		end = max_blks - 1;
	if (end <= first_data_blk)
		goto out;
	if (start < first_data_blk)
		start = first_data_blk;

	smp_rmb();

	/* Determine first and last group to examine based on start and len */
	ext3_get_group_no_and_offset(sb, (ext3_fsblk_t) start,
				     &first_group, &first_block);
	ext3_get_group_no_and_offset(sb, (ext3_fsblk_t) end,
				     &last_group, &last_block);

	/* end now represents the last block to discard in this group */
	end = EXT3_BLOCKS_PER_GROUP(sb) - 1;

	for (group = first_group; group <= last_group; group++) {
		gdp = ext3_get_group_desc(sb, group, NULL);
		if (!gdp)
			break;

		/*
		 * For all the groups except the last one, last block will
		 * always be EXT3_BLOCKS_PER_GROUP(sb)-1, so we only need to
		 * change it for the last group, note that last_block is
		 * already computed earlier by ext3_get_group_no_and_offset()
		 */
		if (group == last_group)
			end = last_block;

		if (le16_to_cpu(gdp->bg_free_blocks_count) >= minlen) {
			ret = ext3_trim_all_free(sb, group, first_block,
						 end, minlen);
			if (ret < 0)
				break;
			trimmed += ret;
		}

		/*
		 * For every group except the first one, we are sure
		 * that the first block to discard will be block #0.
		 */
		first_block = 0;
	}

	if (ret > 0)
		ret = 0;

out:
	range->len = trimmed * sb->s_blocksize;
	return ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/balloc.c */
/************************************************************/
/*
 *  linux/fs/ext3/bitmap.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

// #include "ext3.h"

#ifdef EXT3FS_DEBUG

unsigned long ext3_count_free (struct buffer_head * map, unsigned int numchars)
{
	return numchars * BITS_PER_BYTE - memweight(map->b_data, numchars);
}

#endif  /*  EXT3FS_DEBUG  */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/bitmap.c */
/************************************************************/
/*
 *  linux/fs/ext3/dir.c
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
 *  ext3 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * Hash Tree Directory indexing (c) 2001  Daniel Phillips
 *
 */

#include <linux/compat.h>
// #include "ext3.h"
#include "../../inc/__fss.h"

static unsigned char ext3_filetype_table[] = {
	DT_UNKNOWN, DT_REG, DT_DIR, DT_CHR, DT_BLK, DT_FIFO, DT_SOCK, DT_LNK
};

static int ext3_dx_readdir(struct file *, struct dir_context *);

static unsigned char get_dtype(struct super_block *sb, int filetype)
{
	if (!EXT3_HAS_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_FILETYPE) ||
	    (filetype >= EXT3_FT_MAX))
		return DT_UNKNOWN;

	return (ext3_filetype_table[filetype]);
}

/**
 * Check if the given dir-inode refers to an htree-indexed directory
 * (or a directory which could potentially get converted to use htree
 * indexing).
 *
 * Return 1 if it is a dx dir, 0 if not
 */
static int is_dx_dir(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	if (EXT3_HAS_COMPAT_FEATURE(inode->i_sb,
		     EXT3_FEATURE_COMPAT_DIR_INDEX) &&
	    ((EXT3_I(inode)->i_flags & EXT3_INDEX_FL) ||
	     ((inode->i_size >> sb->s_blocksize_bits) == 1)))
		return 1;

	return 0;
}

int ext3_check_dir_entry (const char * function, struct inode * dir,
			  struct ext3_dir_entry_2 * de,
			  struct buffer_head * bh,
			  unsigned long offset)
{
	const char * error_msg = NULL;
	const int rlen = ext3_rec_len_from_disk(de->rec_len);

	if (unlikely(rlen < EXT3_DIR_REC_LEN(1)))
		error_msg = "rec_len is smaller than minimal";
	else if (unlikely(rlen % 4 != 0))
		error_msg = "rec_len % 4 != 0";
	else if (unlikely(rlen < EXT3_DIR_REC_LEN(de->name_len)))
		error_msg = "rec_len is too small for name_len";
	else if (unlikely((((char *) de - bh->b_data) + rlen > dir->i_sb->s_blocksize)))
		error_msg = "directory entry across blocks";
	else if (unlikely(le32_to_cpu(de->inode) >
			le32_to_cpu(EXT3_SB(dir->i_sb)->s_es->s_inodes_count)))
		error_msg = "inode out of bounds";

	if (unlikely(error_msg != NULL))
		ext3_error (dir->i_sb, function,
			"bad entry in directory #%lu: %s - "
			"offset=%lu, inode=%lu, rec_len=%d, name_len=%d",
			dir->i_ino, error_msg, offset,
			(unsigned long) le32_to_cpu(de->inode),
			rlen, de->name_len);

	return error_msg == NULL ? 1 : 0;
}

static int ext3_readdir(struct file *file, struct dir_context *ctx)
{
	unsigned long offset;
	int i;
	struct ext3_dir_entry_2 *de;
	int err;
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	int dir_has_error = 0;

	if (is_dx_dir(inode)) {
		err = ext3_dx_readdir(file, ctx);
		if (err != ERR_BAD_DX_DIR)
			return err;
		/*
		 * We don't set the inode dirty flag since it's not
		 * critical that it get flushed back to the disk.
		 */
		EXT3_I(inode)->i_flags &= ~EXT3_INDEX_FL;
	}
	offset = ctx->pos & (sb->s_blocksize - 1);

	while (ctx->pos < inode->i_size) {
		unsigned long blk = ctx->pos >> EXT3_BLOCK_SIZE_BITS(sb);
		struct buffer_head map_bh;
		struct buffer_head *bh = NULL;

		map_bh.b_state = 0;
		err = ext3_get_blocks_handle(NULL, inode, blk, 1, &map_bh, 0);
		if (err > 0) {
			pgoff_t index = map_bh.b_blocknr >>
					(PAGE_CACHE_SHIFT - inode->i_blkbits);
			if (!ra_has_index(&file->f_ra, index))
				page_cache_sync_readahead(
					sb->s_bdev->bd_inode->i_mapping,
					&file->f_ra, file,
					index, 1);
			file->f_ra.prev_pos = (loff_t)index << PAGE_CACHE_SHIFT;
			bh = ext3_bread(NULL, inode, blk, 0, &err);
		}

		/*
		 * We ignore I/O errors on directories so users have a chance
		 * of recovering data when there's a bad sector
		 */
		if (!bh) {
			if (!dir_has_error) {
				ext3_error(sb, __func__, "directory #%lu "
					"contains a hole at offset %lld",
					inode->i_ino, ctx->pos);
				dir_has_error = 1;
			}
			/* corrupt size?  Maybe no more blocks to read */
			if (ctx->pos > inode->i_blocks << 9)
				break;
			ctx->pos += sb->s_blocksize - offset;
			continue;
		}

		/* If the dir block has changed since the last call to
		 * readdir(2), then we might be pointing to an invalid
		 * dirent right now.  Scan from the start of the block
		 * to make sure. */
		if (offset && file->f_version != inode->i_version) {
			for (i = 0; i < sb->s_blocksize && i < offset; ) {
				de = (struct ext3_dir_entry_2 *)
					(bh->b_data + i);
				/* It's too expensive to do a full
				 * dirent test each time round this
				 * loop, but we do have to test at
				 * least that it is non-zero.  A
				 * failure will be detected in the
				 * dirent test below. */
				if (ext3_rec_len_from_disk(de->rec_len) <
						EXT3_DIR_REC_LEN(1))
					break;
				i += ext3_rec_len_from_disk(de->rec_len);
			}
			offset = i;
			ctx->pos = (ctx->pos & ~(sb->s_blocksize - 1))
				| offset;
			file->f_version = inode->i_version;
		}

		while (ctx->pos < inode->i_size
		       && offset < sb->s_blocksize) {
			de = (struct ext3_dir_entry_2 *) (bh->b_data + offset);
			if (!ext3_check_dir_entry ("ext3_readdir", inode, de,
						   bh, offset)) {
				/* On error, skip the to the
                                   next block. */
				ctx->pos = (ctx->pos |
						(sb->s_blocksize - 1)) + 1;
				break;
			}
			offset += ext3_rec_len_from_disk(de->rec_len);
			if (le32_to_cpu(de->inode)) {
				if (!dir_emit(ctx, de->name, de->name_len,
					      le32_to_cpu(de->inode),
					      get_dtype(sb, de->file_type))) {
					brelse(bh);
					return 0;
				}
			}
			ctx->pos += ext3_rec_len_from_disk(de->rec_len);
		}
		offset = 0;
		brelse (bh);
		if (ctx->pos < inode->i_size)
			if (!dir_relax(inode))
				return 0;
	}
	return 0;
}

static inline int is_32bit_api(void)
{
#ifdef CONFIG_COMPAT
	return is_compat_task();
#else
	return (BITS_PER_LONG == 32);
#endif
}

/*
 * These functions convert from the major/minor hash to an f_pos
 * value for dx directories
 *
 * Upper layer (for example NFS) should specify FMODE_32BITHASH or
 * FMODE_64BITHASH explicitly. On the other hand, we allow ext3 to be mounted
 * directly on both 32-bit and 64-bit nodes, under such case, neither
 * FMODE_32BITHASH nor FMODE_64BITHASH is specified.
 */
static inline loff_t hash2pos(struct file *filp, __u32 major, __u32 minor)
{
	if ((filp->f_mode & FMODE_32BITHASH) ||
	    (!(filp->f_mode & FMODE_64BITHASH) && is_32bit_api()))
		return major >> 1;
	else
		return ((__u64)(major >> 1) << 32) | (__u64)minor;
}

static inline __u32 pos2maj_hash(struct file *filp, loff_t pos)
{
	if ((filp->f_mode & FMODE_32BITHASH) ||
	    (!(filp->f_mode & FMODE_64BITHASH) && is_32bit_api()))
		return (pos << 1) & 0xffffffff;
	else
		return ((pos >> 32) << 1) & 0xffffffff;
}

static inline __u32 pos2min_hash(struct file *filp, loff_t pos)
{
	if ((filp->f_mode & FMODE_32BITHASH) ||
	    (!(filp->f_mode & FMODE_64BITHASH) && is_32bit_api()))
		return 0;
	else
		return pos & 0xffffffff;
}

/*
 * Return 32- or 64-bit end-of-file for dx directories
 */
static inline loff_t ext3_get_htree_eof(struct file *filp)
{
	if ((filp->f_mode & FMODE_32BITHASH) ||
	    (!(filp->f_mode & FMODE_64BITHASH) && is_32bit_api()))
		return EXT3_HTREE_EOF_32BIT;
	else
		return EXT3_HTREE_EOF_64BIT;
}


/*
 * ext3_dir_llseek() calls generic_file_llseek[_size]() to handle both
 * non-htree and htree directories, where the "offset" is in terms
 * of the filename hash value instead of the byte offset.
 *
 * Because we may return a 64-bit hash that is well beyond s_maxbytes,
 * we need to pass the max hash as the maximum allowable offset in
 * the htree directory case.
 *
 * NOTE: offsets obtained *before* ext3_set_inode_flag(dir, EXT3_INODE_INDEX)
 *       will be invalid once the directory was converted into a dx directory
 */
static loff_t ext3_dir_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	int dx_dir = is_dx_dir(inode);
	loff_t htree_max = ext3_get_htree_eof(file);

	if (likely(dx_dir))
		return generic_file_llseek_size(file, offset, whence,
					        htree_max, htree_max);
	else
		return generic_file_llseek(file, offset, whence);
}

/*
 * This structure holds the nodes of the red-black tree used to store
 * the directory entry in hash order.
 */
struct fname {
	__u32		hash;
	__u32		minor_hash;
	struct rb_node	rb_hash;
	struct fname	*next;
	__u32		inode;
	__u8		name_len;
	__u8		file_type;
	char		name[0];
};

/*
 * This functoin implements a non-recursive way of freeing all of the
 * nodes in the red-black tree.
 */
static void free_rb_tree_fname(struct rb_root *root)
{
	struct fname *fname, *next;

	rbtree_postorder_for_each_entry_safe(fname, next, root, rb_hash)
		do {
			struct fname *old = fname;
			fname = fname->next;
			kfree(old);
		} while (fname);

	*root = RB_ROOT;
}

static struct dir_private_info *ext3_htree_create_dir_info(struct file *filp,
							   loff_t pos)
{
	struct dir_private_info *p;

	p = kzalloc(sizeof(struct dir_private_info), GFP_KERNEL);
	if (!p)
		return NULL;
	p->curr_hash = pos2maj_hash(filp, pos);
	p->curr_minor_hash = pos2min_hash(filp, pos);
	return p;
}

void ext3_htree_free_dir_info(struct dir_private_info *p)
{
	free_rb_tree_fname(&p->root);
	kfree(p);
}

/*
 * Given a directory entry, enter it into the fname rb tree.
 */
int ext3_htree_store_dirent(struct file *dir_file, __u32 hash,
			     __u32 minor_hash,
			     struct ext3_dir_entry_2 *dirent)
{
	struct rb_node **p, *parent = NULL;
	struct fname * fname, *new_fn;
	struct dir_private_info *info;
	int len;

	info = (struct dir_private_info *) dir_file->private_data;
	p = &info->root.rb_node;

	/* Create and allocate the fname structure */
	len = sizeof(struct fname) + dirent->name_len + 1;
	new_fn = kzalloc(len, GFP_KERNEL);
	if (!new_fn)
		return -ENOMEM;
	new_fn->hash = hash;
	new_fn->minor_hash = minor_hash;
	new_fn->inode = le32_to_cpu(dirent->inode);
	new_fn->name_len = dirent->name_len;
	new_fn->file_type = dirent->file_type;
	memcpy(new_fn->name, dirent->name, dirent->name_len);
	new_fn->name[dirent->name_len] = 0;

	while (*p) {
		parent = *p;
		fname = rb_entry(parent, struct fname, rb_hash);

		/*
		 * If the hash and minor hash match up, then we put
		 * them on a linked list.  This rarely happens...
		 */
		if ((new_fn->hash == fname->hash) &&
		    (new_fn->minor_hash == fname->minor_hash)) {
			new_fn->next = fname->next;
			fname->next = new_fn;
			return 0;
		}

		if (new_fn->hash < fname->hash)
			p = &(*p)->rb_left;
		else if (new_fn->hash > fname->hash)
			p = &(*p)->rb_right;
		else if (new_fn->minor_hash < fname->minor_hash)
			p = &(*p)->rb_left;
		else /* if (new_fn->minor_hash > fname->minor_hash) */
			p = &(*p)->rb_right;
	}

	rb_link_node(&new_fn->rb_hash, parent, p);
	rb_insert_color(&new_fn->rb_hash, &info->root);
	return 0;
}



/*
 * This is a helper function for ext3_dx_readdir.  It calls filldir
 * for all entres on the fname linked list.  (Normally there is only
 * one entry on the linked list, unless there are 62 bit hash collisions.)
 */
static bool call_filldir(struct file *file, struct dir_context *ctx,
			struct fname *fname)
{
	struct dir_private_info *info = file->private_data;
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;

	if (!fname) {
		printk("call_filldir: called with null fname?!?\n");
		return true;
	}
	ctx->pos = hash2pos(file, fname->hash, fname->minor_hash);
	while (fname) {
		if (!dir_emit(ctx, fname->name, fname->name_len,
				fname->inode,
				get_dtype(sb, fname->file_type))) {
			info->extra_fname = fname;
			return false;
		}
		fname = fname->next;
	}
	return true;
}

static int ext3_dx_readdir(struct file *file, struct dir_context *ctx)
{
	struct dir_private_info *info = file->private_data;
	struct inode *inode = file_inode(file);
	struct fname *fname;
	int	ret;

	if (!info) {
		info = ext3_htree_create_dir_info(file, ctx->pos);
		if (!info)
			return -ENOMEM;
		file->private_data = info;
	}

	if (ctx->pos == ext3_get_htree_eof(file))
		return 0;	/* EOF */

	/* Some one has messed with f_pos; reset the world */
	if (info->last_pos != ctx->pos) {
		free_rb_tree_fname(&info->root);
		info->curr_node = NULL;
		info->extra_fname = NULL;
		info->curr_hash = pos2maj_hash(file, ctx->pos);
		info->curr_minor_hash = pos2min_hash(file, ctx->pos);
	}

	/*
	 * If there are any leftover names on the hash collision
	 * chain, return them first.
	 */
	if (info->extra_fname) {
		if (!call_filldir(file, ctx, info->extra_fname))
			goto finished;
		info->extra_fname = NULL;
		goto next_node;
	} else if (!info->curr_node)
		info->curr_node = rb_first(&info->root);

	while (1) {
		/*
		 * Fill the rbtree if we have no more entries,
		 * or the inode has changed since we last read in the
		 * cached entries.
		 */
		if ((!info->curr_node) ||
		    (file->f_version != inode->i_version)) {
			info->curr_node = NULL;
			free_rb_tree_fname(&info->root);
			file->f_version = inode->i_version;
			ret = ext3_htree_fill_tree(file, info->curr_hash,
						   info->curr_minor_hash,
						   &info->next_hash);
			if (ret < 0)
				return ret;
			if (ret == 0) {
				ctx->pos = ext3_get_htree_eof(file);
				break;
			}
			info->curr_node = rb_first(&info->root);
		}

		fname = rb_entry(info->curr_node, struct fname, rb_hash);
		info->curr_hash = fname->hash;
		info->curr_minor_hash = fname->minor_hash;
		if (!call_filldir(file, ctx, fname))
			break;
	next_node:
		info->curr_node = rb_next(info->curr_node);
		if (info->curr_node) {
			fname = rb_entry(info->curr_node, struct fname,
					 rb_hash);
			info->curr_hash = fname->hash;
			info->curr_minor_hash = fname->minor_hash;
		} else {
			if (info->next_hash == ~0) {
				ctx->pos = ext3_get_htree_eof(file);
				break;
			}
			info->curr_hash = info->next_hash;
			info->curr_minor_hash = 0;
		}
	}
finished:
	info->last_pos = ctx->pos;
	return 0;
}

static int ext3_release_dir (struct inode * inode, struct file * filp)
{
       if (filp->private_data)
		ext3_htree_free_dir_info(filp->private_data);

	return 0;
}

const struct file_operations ext3_dir_operations = {
	.llseek		= ext3_dir_llseek,
	.read		= generic_read_dir,
	.iterate	= ext3_readdir,
	.unlocked_ioctl = ext3_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext3_compat_ioctl,
#endif
	.fsync		= ext3_sync_file,
	.release	= ext3_release_dir,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/dir.c */
/************************************************************/
/*
 *  linux/fs/ext3/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext3 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 */

// #include <linux/quotaops.h>
// #include "ext3.h"
#include "xattr.h"
#include "acl.h"
#include "../../inc/__fss.h"

/*
 * Called when an inode is released. Note that this is different
 * from ext3_file_open: open gets called at every open, but release
 * gets called only when /all/ the files are closed.
 */
static int ext3_release_file (struct inode * inode, struct file * filp)
{
	if (ext3_test_inode_state(inode, EXT3_STATE_FLUSH_ON_CLOSE)) {
		filemap_flush(inode->i_mapping);
		ext3_clear_inode_state(inode, EXT3_STATE_FLUSH_ON_CLOSE);
	}
	/* if we are the last writer on the inode, drop the block reservation */
	if ((filp->f_mode & FMODE_WRITE) &&
			(atomic_read(&inode->i_writecount) == 1))
	{
		mutex_lock(&EXT3_I(inode)->truncate_mutex);
		ext3_discard_reservation(inode);
		mutex_unlock(&EXT3_I(inode)->truncate_mutex);
	}
	if (is_dx(inode) && filp->private_data)
		ext3_htree_free_dir_info(filp->private_data);

	return 0;
}

const struct file_operations ext3_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.write		= new_sync_write,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.unlocked_ioctl	= ext3_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext3_compat_ioctl,
#endif
	.mmap		= generic_file_mmap,
	.open		= dquot_file_open,
	.release	= ext3_release_file,
	.fsync		= ext3_sync_file,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
};

const struct inode_operations ext3_file_inode_operations = {
	.setattr	= ext3_setattr,
#ifdef CONFIG_EXT3_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext3_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.get_acl	= ext3_get_acl,
	.set_acl	= ext3_set_acl,
	.fiemap		= ext3_fiemap,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/file.c */
/************************************************************/
/*
 *  linux/fs/ext3/fsync.c
 *
 *  Copyright (C) 1993  Stephen Tweedie (sct@redhat.com)
 *  from
 *  Copyright (C) 1992  Remy Card (card@masi.ibp.fr)
 *                      Laboratoire MASI - Institut Blaise Pascal
 *                      Universite Pierre et Marie Curie (Paris VI)
 *  from
 *  linux/fs/minix/truncate.c   Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext3fs fsync primitive
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 *  Removed unnecessary code duplication for little endian machines
 *  and excessive __inline__s.
 *        Andi Kleen, 1997
 *
 * Major simplications and cleanup - we only need to do the metadata, because
 * we can depend on generic_block_fdatasync() to sync the data blocks.
 */

// #include <linux/blkdev.h>
#include <linux/writeback.h>
// #include "ext3.h"
#include "../../inc/__fss.h"

/*
 * akpm: A new design for ext3_sync_file().
 *
 * This is only called from sys_fsync(), sys_fdatasync() and sys_msync().
 * There cannot be a transaction open by this task.
 * Another task could have dirtied this inode.  Its data can be in any
 * state in the journalling system.
 *
 * What we do is just kick off a commit and wait on it.  This will snapshot the
 * inode to disk.
 */

int ext3_sync_file(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct ext3_inode_info *ei = EXT3_I(inode);
	journal_t *journal = EXT3_SB(inode->i_sb)->s_journal;
	int ret, needs_barrier = 0;
	tid_t commit_tid;

	trace_ext3_sync_file_enter(file, datasync);

	if (inode->i_sb->s_flags & MS_RDONLY) {
		/* Make sure that we read updated state */
		smp_rmb();
		if (EXT3_SB(inode->i_sb)->s_mount_state & EXT3_ERROR_FS)
			return -EROFS;
		return 0;
	}
	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		goto out;

	J_ASSERT(ext3_journal_current_handle() == NULL);

	/*
	 * data=writeback,ordered:
	 *  The caller's filemap_fdatawrite()/wait will sync the data.
	 *  Metadata is in the journal, we wait for a proper transaction
	 *  to commit here.
	 *
	 * data=journal:
	 *  filemap_fdatawrite won't do anything (the buffers are clean).
	 *  ext3_force_commit will write the file data into the journal and
	 *  will wait on that.
	 *  filemap_fdatawait() will encounter a ton of newly-dirtied pages
	 *  (they were dirtied by commit).  But that's OK - the blocks are
	 *  safe in-journal, which is all fsync() needs to ensure.
	 */
	if (ext3_should_journal_data(inode)) {
		ret = ext3_force_commit(inode->i_sb);
		goto out;
	}

	if (datasync)
		commit_tid = atomic_read(&ei->i_datasync_tid);
	else
		commit_tid = atomic_read(&ei->i_sync_tid);

	if (test_opt(inode->i_sb, BARRIER) &&
	    !journal_trans_will_send_data_barrier(journal, commit_tid))
		needs_barrier = 1;
	log_start_commit(journal, commit_tid);
	ret = log_wait_commit(journal, commit_tid);

	/*
	 * In case we didn't commit a transaction, we have to flush
	 * disk caches manually so that data really is on persistent
	 * storage
	 */
	if (needs_barrier) {
		int err;

		err = blkdev_issue_flush(inode->i_sb->s_bdev, GFP_KERNEL, NULL);
		if (!ret)
			ret = err;
	}
out:
	trace_ext3_sync_file_exit(inode, ret);
	return ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/fsync.c */
/************************************************************/
/*
 *  linux/fs/ext3/ialloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  BSD ufs-inspired inode and directory allocation by
 *  Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

// #include <linux/quotaops.h>
#include <linux/random.h>
#include "../../inc/__fss.h"

// #include "ext3.h"
// #include "xattr.h"
// #include "acl.h"

/*
 * ialloc.c contains the inodes allocation and deallocation routines
 */

/*
 * The free inodes are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.
 */


/*
 * Read the inode allocation bitmap for a given block_group, reading
 * into the specified slot in the superblock's bitmap cache.
 *
 * Return buffer_head of bitmap on success or NULL.
 */
static struct buffer_head *
read_inode_bitmap(struct super_block * sb, unsigned long block_group)
{
	struct ext3_group_desc *desc;
	struct buffer_head *bh = NULL;

	desc = ext3_get_group_desc(sb, block_group, NULL);
	if (!desc)
		goto error_out;

	bh = sb_bread(sb, le32_to_cpu(desc->bg_inode_bitmap));
	if (!bh)
		ext3_error(sb, "read_inode_bitmap",
			    "Cannot read inode bitmap - "
			    "block_group = %lu, inode_bitmap = %u",
			    block_group, le32_to_cpu(desc->bg_inode_bitmap));
error_out:
	return bh;
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 *
 * HOWEVER: we must make sure that we get no aliases,
 * which means that we have to call "clear_inode()"
 * _before_ we mark the inode not in use in the inode
 * bitmaps. Otherwise a newly created file might use
 * the same inode number (not actually the same pointer
 * though), and then we'd have two inodes sharing the
 * same inode number and space on the harddisk.
 */
void ext3_free_inode (handle_t *handle, struct inode * inode)
{
	struct super_block * sb = inode->i_sb;
	int is_directory;
	unsigned long ino;
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *bh2;
	unsigned long block_group;
	unsigned long bit;
	struct ext3_group_desc * gdp;
	struct ext3_super_block * es;
	struct ext3_sb_info *sbi;
	int fatal = 0, err;

	if (atomic_read(&inode->i_count) > 1) {
		printk ("ext3_free_inode: inode has count=%d\n",
					atomic_read(&inode->i_count));
		return;
	}
	if (inode->i_nlink) {
		printk ("ext3_free_inode: inode has nlink=%d\n",
			inode->i_nlink);
		return;
	}
	if (!sb) {
		printk("ext3_free_inode: inode on nonexistent device\n");
		return;
	}
	sbi = EXT3_SB(sb);

	ino = inode->i_ino;
	ext3_debug ("freeing inode %lu\n", ino);
	trace_ext3_free_inode(inode);

	is_directory = S_ISDIR(inode->i_mode);

	es = EXT3_SB(sb)->s_es;
	if (ino < EXT3_FIRST_INO(sb) || ino > le32_to_cpu(es->s_inodes_count)) {
		ext3_error (sb, "ext3_free_inode",
			    "reserved or nonexistent inode %lu", ino);
		goto error_return;
	}
	block_group = (ino - 1) / EXT3_INODES_PER_GROUP(sb);
	bit = (ino - 1) % EXT3_INODES_PER_GROUP(sb);
	bitmap_bh = read_inode_bitmap(sb, block_group);
	if (!bitmap_bh)
		goto error_return;

	BUFFER_TRACE(bitmap_bh, "get_write_access");
	fatal = ext3_journal_get_write_access(handle, bitmap_bh);
	if (fatal)
		goto error_return;

	/* Ok, now we can actually update the inode bitmaps.. */
	if (!ext3_clear_bit_atomic(sb_bgl_lock(sbi, block_group),
					bit, bitmap_bh->b_data))
		ext3_error (sb, "ext3_free_inode",
			      "bit already cleared for inode %lu", ino);
	else {
		gdp = ext3_get_group_desc (sb, block_group, &bh2);

		BUFFER_TRACE(bh2, "get_write_access");
		fatal = ext3_journal_get_write_access(handle, bh2);
		if (fatal) goto error_return;

		if (gdp) {
			spin_lock(sb_bgl_lock(sbi, block_group));
			le16_add_cpu(&gdp->bg_free_inodes_count, 1);
			if (is_directory)
				le16_add_cpu(&gdp->bg_used_dirs_count, -1);
			spin_unlock(sb_bgl_lock(sbi, block_group));
			percpu_counter_inc(&sbi->s_freeinodes_counter);
			if (is_directory)
				percpu_counter_dec(&sbi->s_dirs_counter);

		}
		BUFFER_TRACE(bh2, "call ext3_journal_dirty_metadata");
		err = ext3_journal_dirty_metadata(handle, bh2);
		if (!fatal) fatal = err;
	}
	BUFFER_TRACE(bitmap_bh, "call ext3_journal_dirty_metadata");
	err = ext3_journal_dirty_metadata(handle, bitmap_bh);
	if (!fatal)
		fatal = err;

error_return:
	brelse(bitmap_bh);
	ext3_std_error(sb, fatal);
}

/*
 * Orlov's allocator for directories.
 *
 * We always try to spread first-level directories.
 *
 * If there are blockgroups with both free inodes and free blocks counts
 * not worse than average we return one with smallest directory count.
 * Otherwise we simply return a random group.
 *
 * For the rest rules look so:
 *
 * It's OK to put directory into a group unless
 * it has too many directories already (max_dirs) or
 * it has too few free inodes left (min_inodes) or
 * it has too few free blocks left (min_blocks).
 * Parent's group is preferred, if it doesn't satisfy these
 * conditions we search cyclically through the rest. If none
 * of the groups look good we just look for a group with more
 * free inodes than average (starting at parent's group).
 *
 * Debt is incremented each time we allocate a directory and decremented
 * when we allocate an inode, within 0--255.
 */

static int find_group_orlov(struct super_block *sb, struct inode *parent)
{
	int parent_group = EXT3_I(parent)->i_block_group;
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	int ngroups = sbi->s_groups_count;
	int inodes_per_group = EXT3_INODES_PER_GROUP(sb);
	unsigned int freei, avefreei;
	ext3_fsblk_t freeb, avefreeb;
	unsigned int ndirs;
	int max_dirs, min_inodes;
	ext3_grpblk_t min_blocks;
	int group = -1, i;
	struct ext3_group_desc *desc;

	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
	avefreei = freei / ngroups;
	freeb = percpu_counter_read_positive(&sbi->s_freeblocks_counter);
	avefreeb = freeb / ngroups;
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);

	if ((parent == sb->s_root->d_inode) ||
	    (EXT3_I(parent)->i_flags & EXT3_TOPDIR_FL)) {
		int best_ndir = inodes_per_group;
		int best_group = -1;

		group = prandom_u32();
		parent_group = (unsigned)group % ngroups;
		for (i = 0; i < ngroups; i++) {
			group = (parent_group + i) % ngroups;
			desc = ext3_get_group_desc (sb, group, NULL);
			if (!desc || !desc->bg_free_inodes_count)
				continue;
			if (le16_to_cpu(desc->bg_used_dirs_count) >= best_ndir)
				continue;
			if (le16_to_cpu(desc->bg_free_inodes_count) < avefreei)
				continue;
			if (le16_to_cpu(desc->bg_free_blocks_count) < avefreeb)
				continue;
			best_group = group;
			best_ndir = le16_to_cpu(desc->bg_used_dirs_count);
		}
		if (best_group >= 0)
			return best_group;
		goto fallback;
	}

	max_dirs = ndirs / ngroups + inodes_per_group / 16;
	min_inodes = avefreei - inodes_per_group / 4;
	min_blocks = avefreeb - EXT3_BLOCKS_PER_GROUP(sb) / 4;

	for (i = 0; i < ngroups; i++) {
		group = (parent_group + i) % ngroups;
		desc = ext3_get_group_desc (sb, group, NULL);
		if (!desc || !desc->bg_free_inodes_count)
			continue;
		if (le16_to_cpu(desc->bg_used_dirs_count) >= max_dirs)
			continue;
		if (le16_to_cpu(desc->bg_free_inodes_count) < min_inodes)
			continue;
		if (le16_to_cpu(desc->bg_free_blocks_count) < min_blocks)
			continue;
		return group;
	}

fallback:
	for (i = 0; i < ngroups; i++) {
		group = (parent_group + i) % ngroups;
		desc = ext3_get_group_desc (sb, group, NULL);
		if (!desc || !desc->bg_free_inodes_count)
			continue;
		if (le16_to_cpu(desc->bg_free_inodes_count) >= avefreei)
			return group;
	}

	if (avefreei) {
		/*
		 * The free-inodes counter is approximate, and for really small
		 * filesystems the above test can fail to find any blockgroups
		 */
		avefreei = 0;
		goto fallback;
	}

	return -1;
}

static int find_group_other(struct super_block *sb, struct inode *parent)
{
	int parent_group = EXT3_I(parent)->i_block_group;
	int ngroups = EXT3_SB(sb)->s_groups_count;
	struct ext3_group_desc *desc;
	int group, i;

	/*
	 * Try to place the inode in its parent directory
	 */
	group = parent_group;
	desc = ext3_get_group_desc (sb, group, NULL);
	if (desc && le16_to_cpu(desc->bg_free_inodes_count) &&
			le16_to_cpu(desc->bg_free_blocks_count))
		return group;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */
	group = (group + parent->i_ino) % ngroups;

	/*
	 * Use a quadratic hash to find a group with a free inode and some free
	 * blocks.
	 */
	for (i = 1; i < ngroups; i <<= 1) {
		group += i;
		if (group >= ngroups)
			group -= ngroups;
		desc = ext3_get_group_desc (sb, group, NULL);
		if (desc && le16_to_cpu(desc->bg_free_inodes_count) &&
				le16_to_cpu(desc->bg_free_blocks_count))
			return group;
	}

	/*
	 * That failed: try linear search for a free inode, even if that group
	 * has no free blocks.
	 */
	group = parent_group;
	for (i = 0; i < ngroups; i++) {
		if (++group >= ngroups)
			group = 0;
		desc = ext3_get_group_desc (sb, group, NULL);
		if (desc && le16_to_cpu(desc->bg_free_inodes_count))
			return group;
	}

	return -1;
}

/*
 * There are two policies for allocating an inode.  If the new inode is
 * a directory, then a forward search is made for a block group with both
 * free space and a low directory-to-inode ratio; if that fails, then of
 * the groups with above-average free space, that group with the fewest
 * directories already is chosen.
 *
 * For other inodes, search forward from the parent directory's block
 * group to find a free inode.
 */
struct inode *ext3_new_inode(handle_t *handle, struct inode * dir,
			     const struct qstr *qstr, umode_t mode)
{
	struct super_block *sb;
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *bh2;
	int group;
	unsigned long ino = 0;
	struct inode * inode;
	struct ext3_group_desc * gdp = NULL;
	struct ext3_super_block * es;
	struct ext3_inode_info *ei;
	struct ext3_sb_info *sbi;
	int err = 0;
	struct inode *ret;
	int i;

	/* Cannot create files in a deleted directory */
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);

	sb = dir->i_sb;
	trace_ext3_request_inode(dir, mode);
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	ei = EXT3_I(inode);

	sbi = EXT3_SB(sb);
	es = sbi->s_es;
	if (S_ISDIR(mode))
		group = find_group_orlov(sb, dir);
	else
		group = find_group_other(sb, dir);

	err = -ENOSPC;
	if (group == -1)
		goto out;

	for (i = 0; i < sbi->s_groups_count; i++) {
		err = -EIO;

		gdp = ext3_get_group_desc(sb, group, &bh2);
		if (!gdp)
			goto fail;

		brelse(bitmap_bh);
		bitmap_bh = read_inode_bitmap(sb, group);
		if (!bitmap_bh)
			goto fail;

		ino = 0;

repeat_in_this_group:
		ino = ext3_find_next_zero_bit((unsigned long *)
				bitmap_bh->b_data, EXT3_INODES_PER_GROUP(sb), ino);
		if (ino < EXT3_INODES_PER_GROUP(sb)) {

			BUFFER_TRACE(bitmap_bh, "get_write_access");
			err = ext3_journal_get_write_access(handle, bitmap_bh);
			if (err)
				goto fail;

			if (!ext3_set_bit_atomic(sb_bgl_lock(sbi, group),
						ino, bitmap_bh->b_data)) {
				/* we won it */
				BUFFER_TRACE(bitmap_bh,
					"call ext3_journal_dirty_metadata");
				err = ext3_journal_dirty_metadata(handle,
								bitmap_bh);
				if (err)
					goto fail;
				goto got;
			}
			/* we lost it */
			journal_release_buffer(handle, bitmap_bh);

			if (++ino < EXT3_INODES_PER_GROUP(sb))
				goto repeat_in_this_group;
		}

		/*
		 * This case is possible in concurrent environment.  It is very
		 * rare.  We cannot repeat the find_group_xxx() call because
		 * that will simply return the same blockgroup, because the
		 * group descriptor metadata has not yet been updated.
		 * So we just go onto the next blockgroup.
		 */
		if (++group == sbi->s_groups_count)
			group = 0;
	}
	err = -ENOSPC;
	goto out;

got:
	ino += group * EXT3_INODES_PER_GROUP(sb) + 1;
	if (ino < EXT3_FIRST_INO(sb) || ino > le32_to_cpu(es->s_inodes_count)) {
		ext3_error (sb, "ext3_new_inode",
			    "reserved inode or inode > inodes count - "
			    "block_group = %d, inode=%lu", group, ino);
		err = -EIO;
		goto fail;
	}

	BUFFER_TRACE(bh2, "get_write_access");
	err = ext3_journal_get_write_access(handle, bh2);
	if (err) goto fail;
	spin_lock(sb_bgl_lock(sbi, group));
	le16_add_cpu(&gdp->bg_free_inodes_count, -1);
	if (S_ISDIR(mode)) {
		le16_add_cpu(&gdp->bg_used_dirs_count, 1);
	}
	spin_unlock(sb_bgl_lock(sbi, group));
	BUFFER_TRACE(bh2, "call ext3_journal_dirty_metadata");
	err = ext3_journal_dirty_metadata(handle, bh2);
	if (err) goto fail;

	percpu_counter_dec(&sbi->s_freeinodes_counter);
	if (S_ISDIR(mode))
		percpu_counter_inc(&sbi->s_dirs_counter);


	if (test_opt(sb, GRPID)) {
		inode->i_mode = mode;
		inode->i_uid = current_fsuid();
		inode->i_gid = dir->i_gid;
	} else
		inode_init_owner(inode, dir, mode);

	inode->i_ino = ino;
	/* This is the optimal IO size (for stat), not the fs block size */
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME_SEC;

	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_dir_start_lookup = 0;
	ei->i_disksize = 0;

	ei->i_flags =
		ext3_mask_flags(mode, EXT3_I(dir)->i_flags & EXT3_FL_INHERITED);
#ifdef EXT3_FRAGMENTS
	ei->i_faddr = 0;
	ei->i_frag_no = 0;
	ei->i_frag_size = 0;
#endif
	ei->i_file_acl = 0;
	ei->i_dir_acl = 0;
	ei->i_dtime = 0;
	ei->i_block_alloc_info = NULL;
	ei->i_block_group = group;

	ext3_set_inode_flags(inode);
	if (IS_DIRSYNC(inode))
		handle->h_sync = 1;
	if (insert_inode_locked(inode) < 0) {
		/*
		 * Likely a bitmap corruption causing inode to be allocated
		 * twice.
		 */
		err = -EIO;
		goto fail;
	}
	spin_lock(&sbi->s_next_gen_lock);
	inode->i_generation = sbi->s_next_generation++;
	spin_unlock(&sbi->s_next_gen_lock);

	ei->i_state_flags = 0;
	ext3_set_inode_state(inode, EXT3_STATE_NEW);

	/* See comment in ext3_iget for explanation */
	if (ino >= EXT3_FIRST_INO(sb) + 1 &&
	    EXT3_INODE_SIZE(sb) > EXT3_GOOD_OLD_INODE_SIZE) {
		ei->i_extra_isize =
			sizeof(struct ext3_inode) - EXT3_GOOD_OLD_INODE_SIZE;
	} else {
		ei->i_extra_isize = 0;
	}

	ret = inode;
	dquot_initialize(inode);
	err = dquot_alloc_inode(inode);
	if (err)
		goto fail_drop;

	err = ext3_init_acl(handle, inode, dir);
	if (err)
		goto fail_free_drop;

	err = ext3_init_security(handle, inode, dir, qstr);
	if (err)
		goto fail_free_drop;

	err = ext3_mark_inode_dirty(handle, inode);
	if (err) {
		ext3_std_error(sb, err);
		goto fail_free_drop;
	}

	ext3_debug("allocating inode %lu\n", inode->i_ino);
	trace_ext3_allocate_inode(inode, dir, mode);
	goto really_out;
fail:
	ext3_std_error(sb, err);
out:
	iput(inode);
	ret = ERR_PTR(err);
really_out:
	brelse(bitmap_bh);
	return ret;

fail_free_drop:
	dquot_free_inode(inode);

fail_drop:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	clear_nlink(inode);
	unlock_new_inode(inode);
	iput(inode);
	brelse(bitmap_bh);
	return ERR_PTR(err);
}

/* Verify that we are loading a valid orphan from disk */
struct inode *ext3_orphan_get(struct super_block *sb, unsigned long ino)
{
	unsigned long max_ino = le32_to_cpu(EXT3_SB(sb)->s_es->s_inodes_count);
	unsigned long block_group;
	int bit;
	struct buffer_head *bitmap_bh;
	struct inode *inode = NULL;
	long err = -EIO;

	/* Error cases - e2fsck has already cleaned up for us */
	if (ino > max_ino) {
		ext3_warning(sb, __func__,
			     "bad orphan ino %lu!  e2fsck was run?", ino);
		goto error;
	}

	block_group = (ino - 1) / EXT3_INODES_PER_GROUP(sb);
	bit = (ino - 1) % EXT3_INODES_PER_GROUP(sb);
	bitmap_bh = read_inode_bitmap(sb, block_group);
	if (!bitmap_bh) {
		ext3_warning(sb, __func__,
			     "inode bitmap error for orphan %lu", ino);
		goto error;
	}

	/* Having the inode bit set should be a 100% indicator that this
	 * is a valid orphan (no e2fsck run on fs).  Orphans also include
	 * inodes that were being truncated, so we can't check i_nlink==0.
	 */
	if (!ext3_test_bit(bit, bitmap_bh->b_data))
		goto bad_orphan;

	inode = ext3_iget(sb, ino);
	if (IS_ERR(inode))
		goto iget_failed;

	/*
	 * If the orphans has i_nlinks > 0 then it should be able to be
	 * truncated, otherwise it won't be removed from the orphan list
	 * during processing and an infinite loop will result.
	 */
	if (inode->i_nlink && !ext3_can_truncate(inode))
		goto bad_orphan;

	if (NEXT_ORPHAN(inode) > max_ino)
		goto bad_orphan;
	brelse(bitmap_bh);
	return inode;

iget_failed:
	err = PTR_ERR(inode);
	inode = NULL;
bad_orphan:
	ext3_warning(sb, __func__,
		     "bad orphan inode %lu!  e2fsck was run?", ino);
	printk(KERN_NOTICE "ext3_test_bit(bit=%d, block=%llu) = %d\n",
	       bit, (unsigned long long)bitmap_bh->b_blocknr,
	       ext3_test_bit(bit, bitmap_bh->b_data));
	printk(KERN_NOTICE "inode=%p\n", inode);
	if (inode) {
		printk(KERN_NOTICE "is_bad_inode(inode)=%d\n",
		       is_bad_inode(inode));
		printk(KERN_NOTICE "NEXT_ORPHAN(inode)=%u\n",
		       NEXT_ORPHAN(inode));
		printk(KERN_NOTICE "max_ino=%lu\n", max_ino);
		printk(KERN_NOTICE "i_nlink=%u\n", inode->i_nlink);
		/* Avoid freeing blocks if we got a bad deleted inode */
		if (inode->i_nlink == 0)
			inode->i_blocks = 0;
		iput(inode);
	}
	brelse(bitmap_bh);
error:
	return ERR_PTR(err);
}

unsigned long ext3_count_free_inodes (struct super_block * sb)
{
	unsigned long desc_count;
	struct ext3_group_desc *gdp;
	int i;
#ifdef EXT3FS_DEBUG
	struct ext3_super_block *es;
	unsigned long bitmap_count, x;
	struct buffer_head *bitmap_bh = NULL;

	es = EXT3_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;
	for (i = 0; i < EXT3_SB(sb)->s_groups_count; i++) {
		gdp = ext3_get_group_desc (sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += le16_to_cpu(gdp->bg_free_inodes_count);
		brelse(bitmap_bh);
		bitmap_bh = read_inode_bitmap(sb, i);
		if (!bitmap_bh)
			continue;

		x = ext3_count_free(bitmap_bh, EXT3_INODES_PER_GROUP(sb) / 8);
		printk("group %d: stored = %d, counted = %lu\n",
			i, le16_to_cpu(gdp->bg_free_inodes_count), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk("ext3_count_free_inodes: stored = %u, computed = %lu, %lu\n",
		le32_to_cpu(es->s_free_inodes_count), desc_count, bitmap_count);
	return desc_count;
#else
	desc_count = 0;
	for (i = 0; i < EXT3_SB(sb)->s_groups_count; i++) {
		gdp = ext3_get_group_desc (sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += le16_to_cpu(gdp->bg_free_inodes_count);
		cond_resched();
	}
	return desc_count;
#endif
}

/* Called at mount-time, super-block is locked */
unsigned long ext3_count_dirs (struct super_block * sb)
{
	unsigned long count = 0;
	int i;

	for (i = 0; i < EXT3_SB(sb)->s_groups_count; i++) {
		struct ext3_group_desc *gdp = ext3_get_group_desc (sb, i, NULL);
		if (!gdp)
			continue;
		count += le16_to_cpu(gdp->bg_used_dirs_count);
	}
	return count;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/ialloc.c */
/************************************************************/
/*
 *  linux/fs/ext3/inode.c
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
 *  Goal-directed block allocation by Stephen Tweedie
 *	(sct@redhat.com), 1993, 1998
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 *
 *  Assorted race fixes, rewrite of ext3_get_block() by Al Viro, 2000
 */

#include <linux/highuid.h>
// #include <linux/quotaops.h>
// #include <linux/writeback.h>
#include <linux/mpage.h>
#include <linux/namei.h>
#include <linux/aio.h>
// #include "ext3.h"
// #include "xattr.h"
// #include "acl.h"
#include "../../inc/__fss.h"

static int ext3_writepage_trans_blocks(struct inode *inode);
static int ext3_block_truncate_page(struct inode *inode, loff_t from);

/*
 * Test whether an inode is a fast symlink.
 */
static int ext3_inode_is_fast_symlink(struct inode *inode)
{
	int ea_blocks = EXT3_I(inode)->i_file_acl ?
		(inode->i_sb->s_blocksize >> 9) : 0;

	return (S_ISLNK(inode->i_mode) && inode->i_blocks - ea_blocks == 0);
}

/*
 * The ext3 forget function must perform a revoke if we are freeing data
 * which has been journaled.  Metadata (eg. indirect blocks) must be
 * revoked in all cases.
 *
 * "bh" may be NULL: a metadata block may have been freed from memory
 * but there may still be a record of it in the journal, and that record
 * still needs to be revoked.
 */
int ext3_forget(handle_t *handle, int is_metadata, struct inode *inode,
			struct buffer_head *bh, ext3_fsblk_t blocknr)
{
	int err;

	might_sleep();

	trace_ext3_forget(inode, is_metadata, blocknr);
	BUFFER_TRACE(bh, "enter");

	jbd_debug(4, "forgetting bh %p: is_metadata = %d, mode %o, "
		  "data mode %lx\n",
		  bh, is_metadata, inode->i_mode,
		  test_opt(inode->i_sb, DATA_FLAGS));

	/* Never use the revoke function if we are doing full data
	 * journaling: there is no need to, and a V1 superblock won't
	 * support it.  Otherwise, only skip the revoke on un-journaled
	 * data blocks. */

	if (test_opt(inode->i_sb, DATA_FLAGS) == EXT3_MOUNT_JOURNAL_DATA ||
	    (!is_metadata && !ext3_should_journal_data(inode))) {
		if (bh) {
			BUFFER_TRACE(bh, "call journal_forget");
			return ext3_journal_forget(handle, bh);
		}
		return 0;
	}

	/*
	 * data!=journal && (is_metadata || should_journal_data(inode))
	 */
	BUFFER_TRACE(bh, "call ext3_journal_revoke");
	err = ext3_journal_revoke(handle, blocknr, bh);
	if (err)
		ext3_abort(inode->i_sb, __func__,
			   "error %d when attempting revoke", err);
	BUFFER_TRACE(bh, "exit");
	return err;
}

/*
 * Work out how many blocks we need to proceed with the next chunk of a
 * truncate transaction.
 */
static unsigned long blocks_for_truncate(struct inode *inode)
{
	unsigned long needed;

	needed = inode->i_blocks >> (inode->i_sb->s_blocksize_bits - 9);

	/* Give ourselves just enough room to cope with inodes in which
	 * i_blocks is corrupt: we've seen disk corruptions in the past
	 * which resulted in random data in an inode which looked enough
	 * like a regular file for ext3 to try to delete it.  Things
	 * will go a bit crazy if that happens, but at least we should
	 * try not to panic the whole kernel. */
	if (needed < 2)
		needed = 2;

	/* But we need to bound the transaction so we don't overflow the
	 * journal. */
	if (needed > EXT3_MAX_TRANS_DATA)
		needed = EXT3_MAX_TRANS_DATA;

	return EXT3_DATA_TRANS_BLOCKS(inode->i_sb) + needed;
}

/*
 * Truncate transactions can be complex and absolutely huge.  So we need to
 * be able to restart the transaction at a conventient checkpoint to make
 * sure we don't overflow the journal.
 *
 * start_transaction gets us a new handle for a truncate transaction,
 * and extend_transaction tries to extend the existing one a bit.  If
 * extend fails, we need to propagate the failure up and restart the
 * transaction in the top-level truncate loop. --sct
 */
static handle_t *start_transaction(struct inode *inode)
{
	handle_t *result;

	result = ext3_journal_start(inode, blocks_for_truncate(inode));
	if (!IS_ERR(result))
		return result;

	ext3_std_error(inode->i_sb, PTR_ERR(result));
	return result;
}

/*
 * Try to extend this transaction for the purposes of truncation.
 *
 * Returns 0 if we managed to create more room.  If we can't create more
 * room, and the transaction must be restarted we return 1.
 */
static int try_to_extend_transaction(handle_t *handle, struct inode *inode)
{
	if (handle->h_buffer_credits > EXT3_RESERVE_TRANS_BLOCKS)
		return 0;
	if (!ext3_journal_extend(handle, blocks_for_truncate(inode)))
		return 0;
	return 1;
}

/*
 * Restart the transaction associated with *handle.  This does a commit,
 * so before we call here everything must be consistently dirtied against
 * this transaction.
 */
static int truncate_restart_transaction(handle_t *handle, struct inode *inode)
{
	int ret;

	jbd_debug(2, "restarting handle %p\n", handle);
	/*
	 * Drop truncate_mutex to avoid deadlock with ext3_get_blocks_handle
	 * At this moment, get_block can be called only for blocks inside
	 * i_size since page cache has been already dropped and writes are
	 * blocked by i_mutex. So we can safely drop the truncate_mutex.
	 */
	mutex_unlock(&EXT3_I(inode)->truncate_mutex);
	ret = ext3_journal_restart(handle, blocks_for_truncate(inode));
	mutex_lock(&EXT3_I(inode)->truncate_mutex);
	return ret;
}

/*
 * Called at inode eviction from icache
 */
void ext3_evict_inode (struct inode *inode)
{
	struct ext3_inode_info *ei = EXT3_I(inode);
	struct ext3_block_alloc_info *rsv;
	handle_t *handle;
	int want_delete = 0;

	trace_ext3_evict_inode(inode);
	if (!inode->i_nlink && !is_bad_inode(inode)) {
		dquot_initialize(inode);
		want_delete = 1;
	}

	/*
	 * When journalling data dirty buffers are tracked only in the journal.
	 * So although mm thinks everything is clean and ready for reaping the
	 * inode might still have some pages to write in the running
	 * transaction or waiting to be checkpointed. Thus calling
	 * journal_invalidatepage() (via truncate_inode_pages()) to discard
	 * these buffers can cause data loss. Also even if we did not discard
	 * these buffers, we would have no way to find them after the inode
	 * is reaped and thus user could see stale data if he tries to read
	 * them before the transaction is checkpointed. So be careful and
	 * force everything to disk here... We use ei->i_datasync_tid to
	 * store the newest transaction containing inode's data.
	 *
	 * Note that directories do not have this problem because they don't
	 * use page cache.
	 *
	 * The s_journal check handles the case when ext3_get_journal() fails
	 * and puts the journal inode.
	 */
	if (inode->i_nlink && ext3_should_journal_data(inode) &&
	    EXT3_SB(inode->i_sb)->s_journal &&
	    (S_ISLNK(inode->i_mode) || S_ISREG(inode->i_mode)) &&
	    inode->i_ino != EXT3_JOURNAL_INO) {
		tid_t commit_tid = atomic_read(&ei->i_datasync_tid);
		journal_t *journal = EXT3_SB(inode->i_sb)->s_journal;

		log_start_commit(journal, commit_tid);
		log_wait_commit(journal, commit_tid);
		filemap_write_and_wait(&inode->i_data);
	}
	truncate_inode_pages_final(&inode->i_data);

	ext3_discard_reservation(inode);
	rsv = ei->i_block_alloc_info;
	ei->i_block_alloc_info = NULL;
	if (unlikely(rsv))
		kfree(rsv);

	if (!want_delete)
		goto no_delete;

	handle = start_transaction(inode);
	if (IS_ERR(handle)) {
		/*
		 * If we're going to skip the normal cleanup, we still need to
		 * make sure that the in-core orphan linked list is properly
		 * cleaned up.
		 */
		ext3_orphan_del(NULL, inode);
		goto no_delete;
	}

	if (IS_SYNC(inode))
		handle->h_sync = 1;
	inode->i_size = 0;
	if (inode->i_blocks)
		ext3_truncate(inode);
	/*
	 * Kill off the orphan record created when the inode lost the last
	 * link.  Note that ext3_orphan_del() has to be able to cope with the
	 * deletion of a non-existent orphan - ext3_truncate() could
	 * have removed the record.
	 */
	ext3_orphan_del(handle, inode);
	ei->i_dtime = get_seconds();

	/*
	 * One subtle ordering requirement: if anything has gone wrong
	 * (transaction abort, IO errors, whatever), then we can still
	 * do these next steps (the fs will already have been marked as
	 * having errors), but we can't free the inode if the mark_dirty
	 * fails.
	 */
	if (ext3_mark_inode_dirty(handle, inode)) {
		/* If that failed, just dquot_drop() and be done with that */
		dquot_drop(inode);
		clear_inode(inode);
	} else {
		ext3_xattr_delete_inode(handle, inode);
		dquot_free_inode(inode);
		dquot_drop(inode);
		clear_inode(inode);
		ext3_free_inode(handle, inode);
	}
	ext3_journal_stop(handle);
	return;
no_delete:
	clear_inode(inode);
	dquot_drop(inode);
}

typedef struct {
	__le32	*p;
	__le32	key;
	struct buffer_head *bh;
} Indirect;

static inline void add_chain(Indirect *p, struct buffer_head *bh, __le32 *v)
{
	p->key = *(p->p = v);
	p->bh = bh;
}

static int verify_chain(Indirect *from, Indirect *to)
{
	while (from <= to && from->key == *from->p)
		from++;
	return (from > to);
}

/**
 *	ext3_block_to_path - parse the block number into array of offsets
 *	@inode: inode in question (we are only interested in its superblock)
 *	@i_block: block number to be parsed
 *	@offsets: array to store the offsets in
 *      @boundary: set this non-zero if the referred-to block is likely to be
 *             followed (on disk) by an indirect block.
 *
 *	To store the locations of file's data ext3 uses a data structure common
 *	for UNIX filesystems - tree of pointers anchored in the inode, with
 *	data blocks at leaves and indirect blocks in intermediate nodes.
 *	This function translates the block number into path in that tree -
 *	return value is the path length and @offsets[n] is the offset of
 *	pointer to (n+1)th node in the nth one. If @block is out of range
 *	(negative or too large) warning is printed and zero returned.
 *
 *	Note: function doesn't find node addresses, so no IO is needed. All
 *	we need to know is the capacity of indirect blocks (taken from the
 *	inode->i_sb).
 */

/*
 * Portability note: the last comparison (check that we fit into triple
 * indirect block) is spelled differently, because otherwise on an
 * architecture with 32-bit longs and 8Kb pages we might get into trouble
 * if our filesystem had 8Kb blocks. We might use long long, but that would
 * kill us on x86. Oh, well, at least the sign propagation does not matter -
 * i_block would have to be negative in the very beginning, so we would not
 * get there at all.
 */

static int ext3_block_to_path(struct inode *inode,
			long i_block, int offsets[4], int *boundary)
{
	int ptrs = EXT3_ADDR_PER_BLOCK(inode->i_sb);
	int ptrs_bits = EXT3_ADDR_PER_BLOCK_BITS(inode->i_sb);
	const long direct_blocks = EXT3_NDIR_BLOCKS,
		indirect_blocks = ptrs,
		double_blocks = (1 << (ptrs_bits * 2));
	int n = 0;
	int final = 0;

	if (i_block < 0) {
		ext3_warning (inode->i_sb, "ext3_block_to_path", "block < 0");
	} else if (i_block < direct_blocks) {
		offsets[n++] = i_block;
		final = direct_blocks;
	} else if ( (i_block -= direct_blocks) < indirect_blocks) {
		offsets[n++] = EXT3_IND_BLOCK;
		offsets[n++] = i_block;
		final = ptrs;
	} else if ((i_block -= indirect_blocks) < double_blocks) {
		offsets[n++] = EXT3_DIND_BLOCK;
		offsets[n++] = i_block >> ptrs_bits;
		offsets[n++] = i_block & (ptrs - 1);
		final = ptrs;
	} else if (((i_block -= double_blocks) >> (ptrs_bits * 2)) < ptrs) {
		offsets[n++] = EXT3_TIND_BLOCK;
		offsets[n++] = i_block >> (ptrs_bits * 2);
		offsets[n++] = (i_block >> ptrs_bits) & (ptrs - 1);
		offsets[n++] = i_block & (ptrs - 1);
		final = ptrs;
	} else {
		ext3_warning(inode->i_sb, "ext3_block_to_path", "block > big");
	}
	if (boundary)
		*boundary = final - 1 - (i_block & (ptrs - 1));
	return n;
}

/**
 *	ext3_get_branch - read the chain of indirect blocks leading to data
 *	@inode: inode in question
 *	@depth: depth of the chain (1 - direct pointer, etc.)
 *	@offsets: offsets of pointers in inode/indirect blocks
 *	@chain: place to store the result
 *	@err: here we store the error value
 *
 *	Function fills the array of triples <key, p, bh> and returns %NULL
 *	if everything went OK or the pointer to the last filled triple
 *	(incomplete one) otherwise. Upon the return chain[i].key contains
 *	the number of (i+1)-th block in the chain (as it is stored in memory,
 *	i.e. little-endian 32-bit), chain[i].p contains the address of that
 *	number (it points into struct inode for i==0 and into the bh->b_data
 *	for i>0) and chain[i].bh points to the buffer_head of i-th indirect
 *	block for i>0 and NULL for i==0. In other words, it holds the block
 *	numbers of the chain, addresses they were taken from (and where we can
 *	verify that chain did not change) and buffer_heads hosting these
 *	numbers.
 *
 *	Function stops when it stumbles upon zero pointer (absent block)
 *		(pointer to last triple returned, *@err == 0)
 *	or when it gets an IO error reading an indirect block
 *		(ditto, *@err == -EIO)
 *	or when it notices that chain had been changed while it was reading
 *		(ditto, *@err == -EAGAIN)
 *	or when it reads all @depth-1 indirect blocks successfully and finds
 *	the whole chain, all way to the data (returns %NULL, *err == 0).
 */
static Indirect *ext3_get_branch(struct inode *inode, int depth, int *offsets,
				 Indirect chain[4], int *err)
{
	struct super_block *sb = inode->i_sb;
	Indirect *p = chain;
	struct buffer_head *bh;

	*err = 0;
	/* i_data is not going away, no lock needed */
	add_chain (chain, NULL, EXT3_I(inode)->i_data + *offsets);
	if (!p->key)
		goto no_block;
	while (--depth) {
		bh = sb_bread(sb, le32_to_cpu(p->key));
		if (!bh)
			goto failure;
		/* Reader: pointers */
		if (!verify_chain(chain, p))
			goto changed;
		add_chain(++p, bh, (__le32*)bh->b_data + *++offsets);
		/* Reader: end */
		if (!p->key)
			goto no_block;
	}
	return NULL;

changed:
	brelse(bh);
	*err = -EAGAIN;
	goto no_block;
failure:
	*err = -EIO;
no_block:
	return p;
}

/**
 *	ext3_find_near - find a place for allocation with sufficient locality
 *	@inode: owner
 *	@ind: descriptor of indirect block.
 *
 *	This function returns the preferred place for block allocation.
 *	It is used when heuristic for sequential allocation fails.
 *	Rules are:
 *	  + if there is a block to the left of our position - allocate near it.
 *	  + if pointer will live in indirect block - allocate near that block.
 *	  + if pointer will live in inode - allocate in the same
 *	    cylinder group.
 *
 * In the latter case we colour the starting block by the callers PID to
 * prevent it from clashing with concurrent allocations for a different inode
 * in the same block group.   The PID is used here so that functionally related
 * files will be close-by on-disk.
 *
 *	Caller must make sure that @ind is valid and will stay that way.
 */
static ext3_fsblk_t ext3_find_near(struct inode *inode, Indirect *ind)
{
	struct ext3_inode_info *ei = EXT3_I(inode);
	__le32 *start = ind->bh ? (__le32*) ind->bh->b_data : ei->i_data;
	__le32 *p;
	ext3_fsblk_t bg_start;
	ext3_grpblk_t colour;

	/* Try to find previous block */
	for (p = ind->p - 1; p >= start; p--) {
		if (*p)
			return le32_to_cpu(*p);
	}

	/* No such thing, so let's try location of indirect block */
	if (ind->bh)
		return ind->bh->b_blocknr;

	/*
	 * It is going to be referred to from the inode itself? OK, just put it
	 * into the same cylinder group then.
	 */
	bg_start = ext3_group_first_block_no(inode->i_sb, ei->i_block_group);
	colour = (current->pid % 16) *
			(EXT3_BLOCKS_PER_GROUP(inode->i_sb) / 16);
	return bg_start + colour;
}

/**
 *	ext3_find_goal - find a preferred place for allocation.
 *	@inode: owner
 *	@block:  block we want
 *	@partial: pointer to the last triple within a chain
 *
 *	Normally this function find the preferred place for block allocation,
 *	returns it.
 */

static ext3_fsblk_t ext3_find_goal(struct inode *inode, long block,
				   Indirect *partial)
{
	struct ext3_block_alloc_info *block_i;

	block_i =  EXT3_I(inode)->i_block_alloc_info;

	/*
	 * try the heuristic for sequential allocation,
	 * failing that at least try to get decent locality.
	 */
	if (block_i && (block == block_i->last_alloc_logical_block + 1)
		&& (block_i->last_alloc_physical_block != 0)) {
		return block_i->last_alloc_physical_block + 1;
	}

	return ext3_find_near(inode, partial);
}

/**
 *	ext3_blks_to_allocate - Look up the block map and count the number
 *	of direct blocks need to be allocated for the given branch.
 *
 *	@branch: chain of indirect blocks
 *	@k: number of blocks need for indirect blocks
 *	@blks: number of data blocks to be mapped.
 *	@blocks_to_boundary:  the offset in the indirect block
 *
 *	return the total number of blocks to be allocate, including the
 *	direct and indirect blocks.
 */
static int ext3_blks_to_allocate(Indirect *branch, int k, unsigned long blks,
		int blocks_to_boundary)
{
	unsigned long count = 0;

	/*
	 * Simple case, [t,d]Indirect block(s) has not allocated yet
	 * then it's clear blocks on that path have not allocated
	 */
	if (k > 0) {
		/* right now we don't handle cross boundary allocation */
		if (blks < blocks_to_boundary + 1)
			count += blks;
		else
			count += blocks_to_boundary + 1;
		return count;
	}

	count++;
	while (count < blks && count <= blocks_to_boundary &&
		le32_to_cpu(*(branch[0].p + count)) == 0) {
		count++;
	}
	return count;
}

/**
 *	ext3_alloc_blocks - multiple allocate blocks needed for a branch
 *	@handle: handle for this transaction
 *	@inode: owner
 *	@goal: preferred place for allocation
 *	@indirect_blks: the number of blocks need to allocate for indirect
 *			blocks
 *	@blks:	number of blocks need to allocated for direct blocks
 *	@new_blocks: on return it will store the new block numbers for
 *	the indirect blocks(if needed) and the first direct block,
 *	@err: here we store the error value
 *
 *	return the number of direct blocks allocated
 */
static int ext3_alloc_blocks(handle_t *handle, struct inode *inode,
			ext3_fsblk_t goal, int indirect_blks, int blks,
			ext3_fsblk_t new_blocks[4], int *err)
{
	int target, i;
	unsigned long count = 0;
	int index = 0;
	ext3_fsblk_t current_block = 0;
	int ret = 0;

	/*
	 * Here we try to allocate the requested multiple blocks at once,
	 * on a best-effort basis.
	 * To build a branch, we should allocate blocks for
	 * the indirect blocks(if not allocated yet), and at least
	 * the first direct block of this branch.  That's the
	 * minimum number of blocks need to allocate(required)
	 */
	target = blks + indirect_blks;

	while (1) {
		count = target;
		/* allocating blocks for indirect blocks and direct blocks */
		current_block = ext3_new_blocks(handle,inode,goal,&count,err);
		if (*err)
			goto failed_out;

		target -= count;
		/* allocate blocks for indirect blocks */
		while (index < indirect_blks && count) {
			new_blocks[index++] = current_block++;
			count--;
		}

		if (count > 0)
			break;
	}

	/* save the new block number for the first direct block */
	new_blocks[index] = current_block;

	/* total number of blocks allocated for direct blocks */
	ret = count;
	*err = 0;
	return ret;
failed_out:
	for (i = 0; i <index; i++)
		ext3_free_blocks(handle, inode, new_blocks[i], 1);
	return ret;
}

/**
 *	ext3_alloc_branch - allocate and set up a chain of blocks.
 *	@handle: handle for this transaction
 *	@inode: owner
 *	@indirect_blks: number of allocated indirect blocks
 *	@blks: number of allocated direct blocks
 *	@goal: preferred place for allocation
 *	@offsets: offsets (in the blocks) to store the pointers to next.
 *	@branch: place to store the chain in.
 *
 *	This function allocates blocks, zeroes out all but the last one,
 *	links them into chain and (if we are synchronous) writes them to disk.
 *	In other words, it prepares a branch that can be spliced onto the
 *	inode. It stores the information about that chain in the branch[], in
 *	the same format as ext3_get_branch() would do. We are calling it after
 *	we had read the existing part of chain and partial points to the last
 *	triple of that (one with zero ->key). Upon the exit we have the same
 *	picture as after the successful ext3_get_block(), except that in one
 *	place chain is disconnected - *branch->p is still zero (we did not
 *	set the last link), but branch->key contains the number that should
 *	be placed into *branch->p to fill that gap.
 *
 *	If allocation fails we free all blocks we've allocated (and forget
 *	their buffer_heads) and return the error value the from failed
 *	ext3_alloc_block() (normally -ENOSPC). Otherwise we set the chain
 *	as described above and return 0.
 */
static int ext3_alloc_branch(handle_t *handle, struct inode *inode,
			int indirect_blks, int *blks, ext3_fsblk_t goal,
			int *offsets, Indirect *branch)
{
	int blocksize = inode->i_sb->s_blocksize;
	int i, n = 0;
	int err = 0;
	struct buffer_head *bh;
	int num;
	ext3_fsblk_t new_blocks[4];
	ext3_fsblk_t current_block;

	num = ext3_alloc_blocks(handle, inode, goal, indirect_blks,
				*blks, new_blocks, &err);
	if (err)
		return err;

	branch[0].key = cpu_to_le32(new_blocks[0]);
	/*
	 * metadata blocks and data blocks are allocated.
	 */
	for (n = 1; n <= indirect_blks;  n++) {
		/*
		 * Get buffer_head for parent block, zero it out
		 * and set the pointer to new one, then send
		 * parent to disk.
		 */
		bh = sb_getblk(inode->i_sb, new_blocks[n-1]);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			goto failed;
		}
		branch[n].bh = bh;
		lock_buffer(bh);
		BUFFER_TRACE(bh, "call get_create_access");
		err = ext3_journal_get_create_access(handle, bh);
		if (err) {
			unlock_buffer(bh);
			brelse(bh);
			goto failed;
		}

		memset(bh->b_data, 0, blocksize);
		branch[n].p = (__le32 *) bh->b_data + offsets[n];
		branch[n].key = cpu_to_le32(new_blocks[n]);
		*branch[n].p = branch[n].key;
		if ( n == indirect_blks) {
			current_block = new_blocks[n];
			/*
			 * End of chain, update the last new metablock of
			 * the chain to point to the new allocated
			 * data blocks numbers
			 */
			for (i=1; i < num; i++)
				*(branch[n].p + i) = cpu_to_le32(++current_block);
		}
		BUFFER_TRACE(bh, "marking uptodate");
		set_buffer_uptodate(bh);
		unlock_buffer(bh);

		BUFFER_TRACE(bh, "call ext3_journal_dirty_metadata");
		err = ext3_journal_dirty_metadata(handle, bh);
		if (err)
			goto failed;
	}
	*blks = num;
	return err;
failed:
	/* Allocation failed, free what we already allocated */
	for (i = 1; i <= n ; i++) {
		BUFFER_TRACE(branch[i].bh, "call journal_forget");
		ext3_journal_forget(handle, branch[i].bh);
	}
	for (i = 0; i < indirect_blks; i++)
		ext3_free_blocks(handle, inode, new_blocks[i], 1);

	ext3_free_blocks(handle, inode, new_blocks[i], num);

	return err;
}

/**
 * ext3_splice_branch - splice the allocated branch onto inode.
 * @handle: handle for this transaction
 * @inode: owner
 * @block: (logical) number of block we are adding
 * @where: location of missing link
 * @num:   number of indirect blocks we are adding
 * @blks:  number of direct blocks we are adding
 *
 * This function fills the missing link and does all housekeeping needed in
 * inode (->i_blocks, etc.). In case of success we end up with the full
 * chain to new block and return 0.
 */
static int ext3_splice_branch(handle_t *handle, struct inode *inode,
			long block, Indirect *where, int num, int blks)
{
	int i;
	int err = 0;
	struct ext3_block_alloc_info *block_i;
	ext3_fsblk_t current_block;
	struct ext3_inode_info *ei = EXT3_I(inode);
	struct timespec now;

	block_i = ei->i_block_alloc_info;
	/*
	 * If we're splicing into a [td]indirect block (as opposed to the
	 * inode) then we need to get write access to the [td]indirect block
	 * before the splice.
	 */
	if (where->bh) {
		BUFFER_TRACE(where->bh, "get_write_access");
		err = ext3_journal_get_write_access(handle, where->bh);
		if (err)
			goto err_out;
	}
	/* That's it */

	*where->p = where->key;

	/*
	 * Update the host buffer_head or inode to point to more just allocated
	 * direct blocks blocks
	 */
	if (num == 0 && blks > 1) {
		current_block = le32_to_cpu(where->key) + 1;
		for (i = 1; i < blks; i++)
			*(where->p + i ) = cpu_to_le32(current_block++);
	}

	/*
	 * update the most recently allocated logical & physical block
	 * in i_block_alloc_info, to assist find the proper goal block for next
	 * allocation
	 */
	if (block_i) {
		block_i->last_alloc_logical_block = block + blks - 1;
		block_i->last_alloc_physical_block =
				le32_to_cpu(where[num].key) + blks - 1;
	}

	/* We are done with atomic stuff, now do the rest of housekeeping */
	now = CURRENT_TIME_SEC;
	if (!timespec_equal(&inode->i_ctime, &now) || !where->bh) {
		inode->i_ctime = now;
		ext3_mark_inode_dirty(handle, inode);
	}
	/* ext3_mark_inode_dirty already updated i_sync_tid */
	atomic_set(&ei->i_datasync_tid, handle->h_transaction->t_tid);

	/* had we spliced it onto indirect block? */
	if (where->bh) {
		/*
		 * If we spliced it onto an indirect block, we haven't
		 * altered the inode.  Note however that if it is being spliced
		 * onto an indirect block at the very end of the file (the
		 * file is growing) then we *will* alter the inode to reflect
		 * the new i_size.  But that is not done here - it is done in
		 * generic_commit_write->__mark_inode_dirty->ext3_dirty_inode.
		 */
		jbd_debug(5, "splicing indirect only\n");
		BUFFER_TRACE(where->bh, "call ext3_journal_dirty_metadata");
		err = ext3_journal_dirty_metadata(handle, where->bh);
		if (err)
			goto err_out;
	} else {
		/*
		 * OK, we spliced it into the inode itself on a direct block.
		 * Inode was dirtied above.
		 */
		jbd_debug(5, "splicing direct\n");
	}
	return err;

err_out:
	for (i = 1; i <= num; i++) {
		BUFFER_TRACE(where[i].bh, "call journal_forget");
		ext3_journal_forget(handle, where[i].bh);
		ext3_free_blocks(handle,inode,le32_to_cpu(where[i-1].key),1);
	}
	ext3_free_blocks(handle, inode, le32_to_cpu(where[num].key), blks);

	return err;
}

/*
 * Allocation strategy is simple: if we have to allocate something, we will
 * have to go the whole way to leaf. So let's do it before attaching anything
 * to tree, set linkage between the newborn blocks, write them if sync is
 * required, recheck the path, free and repeat if check fails, otherwise
 * set the last missing link (that will protect us from any truncate-generated
 * removals - all blocks on the path are immune now) and possibly force the
 * write on the parent block.
 * That has a nice additional property: no special recovery from the failed
 * allocations is needed - we simply release blocks and do not touch anything
 * reachable from inode.
 *
 * `handle' can be NULL if create == 0.
 *
 * The BKL may not be held on entry here.  Be sure to take it early.
 * return > 0, # of blocks mapped or allocated.
 * return = 0, if plain lookup failed.
 * return < 0, error case.
 */
int ext3_get_blocks_handle(handle_t *handle, struct inode *inode,
		sector_t iblock, unsigned long maxblocks,
		struct buffer_head *bh_result,
		int create)
{
	int err = -EIO;
	int offsets[4];
	Indirect chain[4];
	Indirect *partial;
	ext3_fsblk_t goal;
	int indirect_blks;
	int blocks_to_boundary = 0;
	int depth;
	struct ext3_inode_info *ei = EXT3_I(inode);
	int count = 0;
	ext3_fsblk_t first_block = 0;


	trace_ext3_get_blocks_enter(inode, iblock, maxblocks, create);
	J_ASSERT(handle != NULL || create == 0);
	depth = ext3_block_to_path(inode,iblock,offsets,&blocks_to_boundary);

	if (depth == 0)
		goto out;

	partial = ext3_get_branch(inode, depth, offsets, chain, &err);

	/* Simplest case - block found, no allocation needed */
	if (!partial) {
		first_block = le32_to_cpu(chain[depth - 1].key);
		clear_buffer_new(bh_result);
		count++;
		/*map more blocks*/
		while (count < maxblocks && count <= blocks_to_boundary) {
			ext3_fsblk_t blk;

			if (!verify_chain(chain, chain + depth - 1)) {
				/*
				 * Indirect block might be removed by
				 * truncate while we were reading it.
				 * Handling of that case: forget what we've
				 * got now. Flag the err as EAGAIN, so it
				 * will reread.
				 */
				err = -EAGAIN;
				count = 0;
				break;
			}
			blk = le32_to_cpu(*(chain[depth-1].p + count));

			if (blk == first_block + count)
				count++;
			else
				break;
		}
		if (err != -EAGAIN)
			goto got_it;
	}

	/* Next simple case - plain lookup or failed read of indirect block */
	if (!create || err == -EIO)
		goto cleanup;

	/*
	 * Block out ext3_truncate while we alter the tree
	 */
	mutex_lock(&ei->truncate_mutex);

	/*
	 * If the indirect block is missing while we are reading
	 * the chain(ext3_get_branch() returns -EAGAIN err), or
	 * if the chain has been changed after we grab the semaphore,
	 * (either because another process truncated this branch, or
	 * another get_block allocated this branch) re-grab the chain to see if
	 * the request block has been allocated or not.
	 *
	 * Since we already block the truncate/other get_block
	 * at this point, we will have the current copy of the chain when we
	 * splice the branch into the tree.
	 */
	if (err == -EAGAIN || !verify_chain(chain, partial)) {
		while (partial > chain) {
			brelse(partial->bh);
			partial--;
		}
		partial = ext3_get_branch(inode, depth, offsets, chain, &err);
		if (!partial) {
			count++;
			mutex_unlock(&ei->truncate_mutex);
			if (err)
				goto cleanup;
			clear_buffer_new(bh_result);
			goto got_it;
		}
	}

	/*
	 * Okay, we need to do block allocation.  Lazily initialize the block
	 * allocation info here if necessary
	*/
	if (S_ISREG(inode->i_mode) && (!ei->i_block_alloc_info))
		ext3_init_block_alloc_info(inode);

	goal = ext3_find_goal(inode, iblock, partial);

	/* the number of blocks need to allocate for [d,t]indirect blocks */
	indirect_blks = (chain + depth) - partial - 1;

	/*
	 * Next look up the indirect map to count the totoal number of
	 * direct blocks to allocate for this branch.
	 */
	count = ext3_blks_to_allocate(partial, indirect_blks,
					maxblocks, blocks_to_boundary);
	err = ext3_alloc_branch(handle, inode, indirect_blks, &count, goal,
				offsets + (partial - chain), partial);

	/*
	 * The ext3_splice_branch call will free and forget any buffers
	 * on the new chain if there is a failure, but that risks using
	 * up transaction credits, especially for bitmaps where the
	 * credits cannot be returned.  Can we handle this somehow?  We
	 * may need to return -EAGAIN upwards in the worst case.  --sct
	 */
	if (!err)
		err = ext3_splice_branch(handle, inode, iblock,
					partial, indirect_blks, count);
	mutex_unlock(&ei->truncate_mutex);
	if (err)
		goto cleanup;

	set_buffer_new(bh_result);
got_it:
	map_bh(bh_result, inode->i_sb, le32_to_cpu(chain[depth-1].key));
	if (count > blocks_to_boundary)
		set_buffer_boundary(bh_result);
	err = count;
	/* Clean up and exit */
	partial = chain + depth - 1;	/* the whole chain */
cleanup:
	while (partial > chain) {
		BUFFER_TRACE(partial->bh, "call brelse");
		brelse(partial->bh);
		partial--;
	}
	BUFFER_TRACE(bh_result, "returned");
out:
	trace_ext3_get_blocks_exit(inode, iblock,
				   depth ? le32_to_cpu(chain[depth-1].key) : 0,
				   count, err);
	return err;
}

/* Maximum number of blocks we map for direct IO at once. */
#define DIO_MAX_BLOCKS 4096
/*
 * Number of credits we need for writing DIO_MAX_BLOCKS:
 * We need sb + group descriptor + bitmap + inode -> 4
 * For B blocks with A block pointers per block we need:
 * 1 (triple ind.) + (B/A/A + 2) (doubly ind.) + (B/A + 2) (indirect).
 * If we plug in 4096 for B and 256 for A (for 1KB block size), we get 25.
 */
#define DIO_CREDITS 25

static int ext3_get_block(struct inode *inode, sector_t iblock,
			struct buffer_head *bh_result, int create)
{
	handle_t *handle = ext3_journal_current_handle();
	int ret = 0, started = 0;
	unsigned max_blocks = bh_result->b_size >> inode->i_blkbits;

	if (create && !handle) {	/* Direct IO write... */
		if (max_blocks > DIO_MAX_BLOCKS)
			max_blocks = DIO_MAX_BLOCKS;
		handle = ext3_journal_start(inode, DIO_CREDITS +
				EXT3_MAXQUOTAS_TRANS_BLOCKS(inode->i_sb));
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto out;
		}
		started = 1;
	}

	ret = ext3_get_blocks_handle(handle, inode, iblock,
					max_blocks, bh_result, create);
	if (ret > 0) {
		bh_result->b_size = (ret << inode->i_blkbits);
		ret = 0;
	}
	if (started)
		ext3_journal_stop(handle);
out:
	return ret;
}

int ext3_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 len)
{
	return generic_block_fiemap(inode, fieinfo, start, len,
				    ext3_get_block);
}

/*
 * `handle' can be NULL if create is zero
 */
struct buffer_head *ext3_getblk(handle_t *handle, struct inode *inode,
				long block, int create, int *errp)
{
	struct buffer_head dummy;
	int fatal = 0, err;

	J_ASSERT(handle != NULL || create == 0);

	dummy.b_state = 0;
	dummy.b_blocknr = -1000;
	buffer_trace_init(&dummy.b_history);
	err = ext3_get_blocks_handle(handle, inode, block, 1,
					&dummy, create);
	/*
	 * ext3_get_blocks_handle() returns number of blocks
	 * mapped. 0 in case of a HOLE.
	 */
	if (err > 0) {
		WARN_ON(err > 1);
		err = 0;
	}
	*errp = err;
	if (!err && buffer_mapped(&dummy)) {
		struct buffer_head *bh;
		bh = sb_getblk(inode->i_sb, dummy.b_blocknr);
		if (unlikely(!bh)) {
			*errp = -ENOMEM;
			goto err;
		}
		if (buffer_new(&dummy)) {
			J_ASSERT(create != 0);
			J_ASSERT(handle != NULL);

			/*
			 * Now that we do not always journal data, we should
			 * keep in mind whether this should always journal the
			 * new buffer as metadata.  For now, regular file
			 * writes use ext3_get_block instead, so it's not a
			 * problem.
			 */
			lock_buffer(bh);
			BUFFER_TRACE(bh, "call get_create_access");
			fatal = ext3_journal_get_create_access(handle, bh);
			if (!fatal && !buffer_uptodate(bh)) {
				memset(bh->b_data,0,inode->i_sb->s_blocksize);
				set_buffer_uptodate(bh);
			}
			unlock_buffer(bh);
			BUFFER_TRACE(bh, "call ext3_journal_dirty_metadata");
			err = ext3_journal_dirty_metadata(handle, bh);
			if (!fatal)
				fatal = err;
		} else {
			BUFFER_TRACE(bh, "not a new buffer");
		}
		if (fatal) {
			*errp = fatal;
			brelse(bh);
			bh = NULL;
		}
		return bh;
	}
err:
	return NULL;
}

struct buffer_head *ext3_bread(handle_t *handle, struct inode *inode,
			       int block, int create, int *err)
{
	struct buffer_head * bh;

	bh = ext3_getblk(handle, inode, block, create, err);
	if (!bh)
		return bh;
	if (bh_uptodate_or_lock(bh))
		return bh;
	get_bh(bh);
	bh->b_end_io = end_buffer_read_sync;
	submit_bh(READ | REQ_META | REQ_PRIO, bh);
	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		return bh;
	put_bh(bh);
	*err = -EIO;
	return NULL;
}

static int walk_page_buffers(	handle_t *handle,
				struct buffer_head *head,
				unsigned from,
				unsigned to,
				int *partial,
				int (*fn)(	handle_t *handle,
						struct buffer_head *bh))
{
	struct buffer_head *bh;
	unsigned block_start, block_end;
	unsigned blocksize = head->b_size;
	int err, ret = 0;
	struct buffer_head *next;

	for (	bh = head, block_start = 0;
		ret == 0 && (bh != head || !block_start);
		block_start = block_end, bh = next)
	{
		next = bh->b_this_page;
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (partial && !buffer_uptodate(bh))
				*partial = 1;
			continue;
		}
		err = (*fn)(handle, bh);
		if (!ret)
			ret = err;
	}
	return ret;
}

/*
 * To preserve ordering, it is essential that the hole instantiation and
 * the data write be encapsulated in a single transaction.  We cannot
 * close off a transaction and start a new one between the ext3_get_block()
 * and the commit_write().  So doing the journal_start at the start of
 * prepare_write() is the right place.
 *
 * Also, this function can nest inside ext3_writepage() ->
 * block_write_full_page(). In that case, we *know* that ext3_writepage()
 * has generated enough buffer credits to do the whole page.  So we won't
 * block on the journal in that case, which is good, because the caller may
 * be PF_MEMALLOC.
 *
 * By accident, ext3 can be reentered when a transaction is open via
 * quota file writes.  If we were to commit the transaction while thus
 * reentered, there can be a deadlock - we would be holding a quota
 * lock, and the commit would never complete if another thread had a
 * transaction open and was blocking on the quota lock - a ranking
 * violation.
 *
 * So what we do is to rely on the fact that journal_stop/journal_start
 * will _not_ run commit under these circumstances because handle->h_ref
 * is elevated.  We'll still have enough credits for the tiny quotafile
 * write.
 */
static int do_journal_get_write_access(handle_t *handle,
					struct buffer_head *bh)
{
	int dirty = buffer_dirty(bh);
	int ret;

	if (!buffer_mapped(bh) || buffer_freed(bh))
		return 0;
	/*
	 * __block_prepare_write() could have dirtied some buffers. Clean
	 * the dirty bit as jbd2_journal_get_write_access() could complain
	 * otherwise about fs integrity issues. Setting of the dirty bit
	 * by __block_prepare_write() isn't a real problem here as we clear
	 * the bit before releasing a page lock and thus writeback cannot
	 * ever write the buffer.
	 */
	if (dirty)
		clear_buffer_dirty(bh);
	ret = ext3_journal_get_write_access(handle, bh);
	if (!ret && dirty)
		ret = ext3_journal_dirty_metadata(handle, bh);
	return ret;
}

/*
 * Truncate blocks that were not used by write. We have to truncate the
 * pagecache as well so that corresponding buffers get properly unmapped.
 */
static void ext3_truncate_failed_write(struct inode *inode)
{
	truncate_inode_pages(inode->i_mapping, inode->i_size);
	ext3_truncate(inode);
}

/*
 * Truncate blocks that were not used by direct IO write. We have to zero out
 * the last file block as well because direct IO might have written to it.
 */
static void ext3_truncate_failed_direct_write(struct inode *inode)
{
	ext3_block_truncate_page(inode, inode->i_size);
	ext3_truncate(inode);
}

static int ext3_write_begin(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	int ret;
	handle_t *handle;
	int retries = 0;
	struct page *page;
	pgoff_t index;
	unsigned from, to;
	/* Reserve one block more for addition to orphan list in case
	 * we allocate blocks but write fails for some reason */
	int needed_blocks = ext3_writepage_trans_blocks(inode) + 1;

	trace_ext3_write_begin(inode, pos, len, flags);

	index = pos >> PAGE_CACHE_SHIFT;
	from = pos & (PAGE_CACHE_SIZE - 1);
	to = from + len;

retry:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	handle = ext3_journal_start(inode, needed_blocks);
	if (IS_ERR(handle)) {
		unlock_page(page);
		page_cache_release(page);
		ret = PTR_ERR(handle);
		goto out;
	}
	ret = __block_write_begin(page, pos, len, ext3_get_block);
	if (ret)
		goto write_begin_failed;

	if (ext3_should_journal_data(inode)) {
		ret = walk_page_buffers(handle, page_buffers(page),
				from, to, NULL, do_journal_get_write_access);
	}
write_begin_failed:
	if (ret) {
		/*
		 * block_write_begin may have instantiated a few blocks
		 * outside i_size.  Trim these off again. Don't need
		 * i_size_read because we hold i_mutex.
		 *
		 * Add inode to orphan list in case we crash before truncate
		 * finishes. Do this only if ext3_can_truncate() agrees so
		 * that orphan processing code is happy.
		 */
		if (pos + len > inode->i_size && ext3_can_truncate(inode))
			ext3_orphan_add(handle, inode);
		ext3_journal_stop(handle);
		unlock_page(page);
		page_cache_release(page);
		if (pos + len > inode->i_size)
			ext3_truncate_failed_write(inode);
	}
	if (ret == -ENOSPC && ext3_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
out:
	return ret;
}


int ext3_journal_dirty_data(handle_t *handle, struct buffer_head *bh)
{
	int err = journal_dirty_data(handle, bh);
	if (err)
		ext3_journal_abort_handle(__func__, __func__,
						bh, handle, err);
	return err;
}

/* For ordered writepage and write_end functions */
static int journal_dirty_data_fn(handle_t *handle, struct buffer_head *bh)
{
	/*
	 * Write could have mapped the buffer but it didn't copy the data in
	 * yet. So avoid filing such buffer into a transaction.
	 */
	if (buffer_mapped(bh) && buffer_uptodate(bh))
		return ext3_journal_dirty_data(handle, bh);
	return 0;
}

/* For write_end() in data=journal mode */
static int write_end_fn(handle_t *handle, struct buffer_head *bh)
{
	if (!buffer_mapped(bh) || buffer_freed(bh))
		return 0;
	set_buffer_uptodate(bh);
	return ext3_journal_dirty_metadata(handle, bh);
}

/*
 * This is nasty and subtle: ext3_write_begin() could have allocated blocks
 * for the whole page but later we failed to copy the data in. Update inode
 * size according to what we managed to copy. The rest is going to be
 * truncated in write_end function.
 */
static void update_file_sizes(struct inode *inode, loff_t pos, unsigned copied)
{
	/* What matters to us is i_disksize. We don't write i_size anywhere */
	if (pos + copied > inode->i_size)
		i_size_write(inode, pos + copied);
	if (pos + copied > EXT3_I(inode)->i_disksize) {
		EXT3_I(inode)->i_disksize = pos + copied;
		mark_inode_dirty(inode);
	}
}

/*
 * We need to pick up the new inode size which generic_commit_write gave us
 * `file' can be NULL - eg, when called from page_symlink().
 *
 * ext3 never places buffers on inode->i_mapping->private_list.  metadata
 * buffers are managed internally.
 */
static int ext3_ordered_write_end(struct file *file,
				struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata)
{
	handle_t *handle = ext3_journal_current_handle();
	struct inode *inode = file->f_mapping->host;
	unsigned from, to;
	int ret = 0, ret2;

	trace_ext3_ordered_write_end(inode, pos, len, copied);
	copied = block_write_end(file, mapping, pos, len, copied, page, fsdata);

	from = pos & (PAGE_CACHE_SIZE - 1);
	to = from + copied;
	ret = walk_page_buffers(handle, page_buffers(page),
		from, to, NULL, journal_dirty_data_fn);

	if (ret == 0)
		update_file_sizes(inode, pos, copied);
	/*
	 * There may be allocated blocks outside of i_size because
	 * we failed to copy some data. Prepare for truncate.
	 */
	if (pos + len > inode->i_size && ext3_can_truncate(inode))
		ext3_orphan_add(handle, inode);
	ret2 = ext3_journal_stop(handle);
	if (!ret)
		ret = ret2;
	unlock_page(page);
	page_cache_release(page);

	if (pos + len > inode->i_size)
		ext3_truncate_failed_write(inode);
	return ret ? ret : copied;
}

static int ext3_writeback_write_end(struct file *file,
				struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata)
{
	handle_t *handle = ext3_journal_current_handle();
	struct inode *inode = file->f_mapping->host;
	int ret;

	trace_ext3_writeback_write_end(inode, pos, len, copied);
	copied = block_write_end(file, mapping, pos, len, copied, page, fsdata);
	update_file_sizes(inode, pos, copied);
	/*
	 * There may be allocated blocks outside of i_size because
	 * we failed to copy some data. Prepare for truncate.
	 */
	if (pos + len > inode->i_size && ext3_can_truncate(inode))
		ext3_orphan_add(handle, inode);
	ret = ext3_journal_stop(handle);
	unlock_page(page);
	page_cache_release(page);

	if (pos + len > inode->i_size)
		ext3_truncate_failed_write(inode);
	return ret ? ret : copied;
}

static int ext3_journalled_write_end(struct file *file,
				struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata)
{
	handle_t *handle = ext3_journal_current_handle();
	struct inode *inode = mapping->host;
	struct ext3_inode_info *ei = EXT3_I(inode);
	int ret = 0, ret2;
	int partial = 0;
	unsigned from, to;

	trace_ext3_journalled_write_end(inode, pos, len, copied);
	from = pos & (PAGE_CACHE_SIZE - 1);
	to = from + len;

	if (copied < len) {
		if (!PageUptodate(page))
			copied = 0;
		page_zero_new_buffers(page, from + copied, to);
		to = from + copied;
	}

	ret = walk_page_buffers(handle, page_buffers(page), from,
				to, &partial, write_end_fn);
	if (!partial)
		SetPageUptodate(page);

	if (pos + copied > inode->i_size)
		i_size_write(inode, pos + copied);
	/*
	 * There may be allocated blocks outside of i_size because
	 * we failed to copy some data. Prepare for truncate.
	 */
	if (pos + len > inode->i_size && ext3_can_truncate(inode))
		ext3_orphan_add(handle, inode);
	ext3_set_inode_state(inode, EXT3_STATE_JDATA);
	atomic_set(&ei->i_datasync_tid, handle->h_transaction->t_tid);
	if (inode->i_size > ei->i_disksize) {
		ei->i_disksize = inode->i_size;
		ret2 = ext3_mark_inode_dirty(handle, inode);
		if (!ret)
			ret = ret2;
	}

	ret2 = ext3_journal_stop(handle);
	if (!ret)
		ret = ret2;
	unlock_page(page);
	page_cache_release(page);

	if (pos + len > inode->i_size)
		ext3_truncate_failed_write(inode);
	return ret ? ret : copied;
}

/*
 * bmap() is special.  It gets used by applications such as lilo and by
 * the swapper to find the on-disk block of a specific piece of data.
 *
 * Naturally, this is dangerous if the block concerned is still in the
 * journal.  If somebody makes a swapfile on an ext3 data-journaling
 * filesystem and enables swap, then they may get a nasty shock when the
 * data getting swapped to that swapfile suddenly gets overwritten by
 * the original zero's written out previously to the journal and
 * awaiting writeback in the kernel's buffer cache.
 *
 * So, if we see any bmap calls here on a modified, data-journaled file,
 * take extra steps to flush any blocks which might be in the cache.
 */
static sector_t ext3_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;
	journal_t *journal;
	int err;

	if (ext3_test_inode_state(inode, EXT3_STATE_JDATA)) {
		/*
		 * This is a REALLY heavyweight approach, but the use of
		 * bmap on dirty files is expected to be extremely rare:
		 * only if we run lilo or swapon on a freshly made file
		 * do we expect this to happen.
		 *
		 * (bmap requires CAP_SYS_RAWIO so this does not
		 * represent an unprivileged user DOS attack --- we'd be
		 * in trouble if mortal users could trigger this path at
		 * will.)
		 *
		 * NB. EXT3_STATE_JDATA is not set on files other than
		 * regular files.  If somebody wants to bmap a directory
		 * or symlink and gets confused because the buffer
		 * hasn't yet been flushed to disk, they deserve
		 * everything they get.
		 */

		ext3_clear_inode_state(inode, EXT3_STATE_JDATA);
		journal = EXT3_JOURNAL(inode);
		journal_lock_updates(journal);
		err = journal_flush(journal);
		journal_unlock_updates(journal);

		if (err)
			return 0;
	}

	return generic_block_bmap(mapping,block,ext3_get_block);
}

static int bget_one(handle_t *handle, struct buffer_head *bh)
{
	get_bh(bh);
	return 0;
}

static int bput_one(handle_t *handle, struct buffer_head *bh)
{
	put_bh(bh);
	return 0;
}

static int buffer_unmapped(handle_t *handle, struct buffer_head *bh)
{
	return !buffer_mapped(bh);
}

/*
 * Note that whenever we need to map blocks we start a transaction even if
 * we're not journalling data.  This is to preserve ordering: any hole
 * instantiation within __block_write_full_page -> ext3_get_block() should be
 * journalled along with the data so we don't crash and then get metadata which
 * refers to old data.
 *
 * In all journalling modes block_write_full_page() will start the I/O.
 *
 * We don't honour synchronous mounts for writepage().  That would be
 * disastrous.  Any write() or metadata operation will sync the fs for
 * us.
 */
static int ext3_ordered_writepage(struct page *page,
				struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *page_bufs;
	handle_t *handle = NULL;
	int ret = 0;
	int err;

	J_ASSERT(PageLocked(page));
	/*
	 * We don't want to warn for emergency remount. The condition is
	 * ordered to avoid dereferencing inode->i_sb in non-error case to
	 * avoid slow-downs.
	 */
	WARN_ON_ONCE(IS_RDONLY(inode) &&
		     !(EXT3_SB(inode->i_sb)->s_mount_state & EXT3_ERROR_FS));

	/*
	 * We give up here if we're reentered, because it might be for a
	 * different filesystem.
	 */
	if (ext3_journal_current_handle())
		goto out_fail;

	trace_ext3_ordered_writepage(page);
	if (!page_has_buffers(page)) {
		create_empty_buffers(page, inode->i_sb->s_blocksize,
				(1 << BH_Dirty)|(1 << BH_Uptodate));
		page_bufs = page_buffers(page);
	} else {
		page_bufs = page_buffers(page);
		if (!walk_page_buffers(NULL, page_bufs, 0, PAGE_CACHE_SIZE,
				       NULL, buffer_unmapped)) {
			/* Provide NULL get_block() to catch bugs if buffers
			 * weren't really mapped */
			return block_write_full_page(page, NULL, wbc);
		}
	}
	handle = ext3_journal_start(inode, ext3_writepage_trans_blocks(inode));

	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out_fail;
	}

	walk_page_buffers(handle, page_bufs, 0,
			PAGE_CACHE_SIZE, NULL, bget_one);

	ret = block_write_full_page(page, ext3_get_block, wbc);

	/*
	 * The page can become unlocked at any point now, and
	 * truncate can then come in and change things.  So we
	 * can't touch *page from now on.  But *page_bufs is
	 * safe due to elevated refcount.
	 */

	/*
	 * And attach them to the current transaction.  But only if
	 * block_write_full_page() succeeded.  Otherwise they are unmapped,
	 * and generally junk.
	 */
	if (ret == 0)
		ret = walk_page_buffers(handle, page_bufs, 0, PAGE_CACHE_SIZE,
					NULL, journal_dirty_data_fn);
	walk_page_buffers(handle, page_bufs, 0,
			PAGE_CACHE_SIZE, NULL, bput_one);
	err = ext3_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;

out_fail:
	redirty_page_for_writepage(wbc, page);
	unlock_page(page);
	return ret;
}

static int ext3_writeback_writepage(struct page *page,
				struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	handle_t *handle = NULL;
	int ret = 0;
	int err;

	J_ASSERT(PageLocked(page));
	/*
	 * We don't want to warn for emergency remount. The condition is
	 * ordered to avoid dereferencing inode->i_sb in non-error case to
	 * avoid slow-downs.
	 */
	WARN_ON_ONCE(IS_RDONLY(inode) &&
		     !(EXT3_SB(inode->i_sb)->s_mount_state & EXT3_ERROR_FS));

	if (ext3_journal_current_handle())
		goto out_fail;

	trace_ext3_writeback_writepage(page);
	if (page_has_buffers(page)) {
		if (!walk_page_buffers(NULL, page_buffers(page), 0,
				      PAGE_CACHE_SIZE, NULL, buffer_unmapped)) {
			/* Provide NULL get_block() to catch bugs if buffers
			 * weren't really mapped */
			return block_write_full_page(page, NULL, wbc);
		}
	}

	handle = ext3_journal_start(inode, ext3_writepage_trans_blocks(inode));
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		goto out_fail;
	}

	ret = block_write_full_page(page, ext3_get_block, wbc);

	err = ext3_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;

out_fail:
	redirty_page_for_writepage(wbc, page);
	unlock_page(page);
	return ret;
}

static int ext3_journalled_writepage(struct page *page,
				struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	handle_t *handle = NULL;
	int ret = 0;
	int err;

	J_ASSERT(PageLocked(page));
	/*
	 * We don't want to warn for emergency remount. The condition is
	 * ordered to avoid dereferencing inode->i_sb in non-error case to
	 * avoid slow-downs.
	 */
	WARN_ON_ONCE(IS_RDONLY(inode) &&
		     !(EXT3_SB(inode->i_sb)->s_mount_state & EXT3_ERROR_FS));

	trace_ext3_journalled_writepage(page);
	if (!page_has_buffers(page) || PageChecked(page)) {
		if (ext3_journal_current_handle())
			goto no_write;

		handle = ext3_journal_start(inode,
					    ext3_writepage_trans_blocks(inode));
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			goto no_write;
		}
		/*
		 * It's mmapped pagecache.  Add buffers and journal it.  There
		 * doesn't seem much point in redirtying the page here.
		 */
		ClearPageChecked(page);
		ret = __block_write_begin(page, 0, PAGE_CACHE_SIZE,
					  ext3_get_block);
		if (ret != 0) {
			ext3_journal_stop(handle);
			goto out_unlock;
		}
		ret = walk_page_buffers(handle, page_buffers(page), 0,
			PAGE_CACHE_SIZE, NULL, do_journal_get_write_access);

		err = walk_page_buffers(handle, page_buffers(page), 0,
				PAGE_CACHE_SIZE, NULL, write_end_fn);
		if (ret == 0)
			ret = err;
		ext3_set_inode_state(inode, EXT3_STATE_JDATA);
		atomic_set(&EXT3_I(inode)->i_datasync_tid,
			   handle->h_transaction->t_tid);
		unlock_page(page);
		err = ext3_journal_stop(handle);
		if (!ret)
			ret = err;
	} else {
		/*
		 * It is a page full of checkpoint-mode buffers. Go and write
		 * them. They should have been already mapped when they went
		 * to the journal so provide NULL get_block function to catch
		 * errors.
		 */
		ret = block_write_full_page(page, NULL, wbc);
	}
out:
	return ret;

no_write:
	redirty_page_for_writepage(wbc, page);
out_unlock:
	unlock_page(page);
	goto out;
}

static int ext3_readpage(struct file *file, struct page *page)
{
	trace_ext3_readpage(page);
	return mpage_readpage(page, ext3_get_block);
}

static int
ext3_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, ext3_get_block);
}

static void ext3_invalidatepage(struct page *page, unsigned int offset,
				unsigned int length)
{
	journal_t *journal = EXT3_JOURNAL(page->mapping->host);

	trace_ext3_invalidatepage(page, offset, length);

	/*
	 * If it's a full truncate we just forget about the pending dirtying
	 */
	if (offset == 0 && length == PAGE_CACHE_SIZE)
		ClearPageChecked(page);

	journal_invalidatepage(journal, page, offset, length);
}

static int ext3_releasepage(struct page *page, gfp_t wait)
{
	journal_t *journal = EXT3_JOURNAL(page->mapping->host);

	trace_ext3_releasepage(page);
	WARN_ON(PageChecked(page));
	if (!page_has_buffers(page))
		return 0;
	return journal_try_to_free_buffers(journal, page, wait);
}

/*
 * If the O_DIRECT write will extend the file then add this inode to the
 * orphan list.  So recovery will truncate it back to the original size
 * if the machine crashes during the write.
 *
 * If the O_DIRECT write is intantiating holes inside i_size and the machine
 * crashes then stale disk data _may_ be exposed inside the file. But current
 * VFS code falls back into buffered path in that case so we are safe.
 */
static ssize_t ext3_direct_IO(int rw, struct kiocb *iocb,
			struct iov_iter *iter, loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct ext3_inode_info *ei = EXT3_I(inode);
	handle_t *handle;
	ssize_t ret;
	int orphan = 0;
	size_t count = iov_iter_count(iter);
	int retries = 0;

	trace_ext3_direct_IO_enter(inode, offset, count, rw);

	if (rw == WRITE) {
		loff_t final_size = offset + count;

		if (final_size > inode->i_size) {
			/* Credits for sb + inode write */
			handle = ext3_journal_start(inode, 2);
			if (IS_ERR(handle)) {
				ret = PTR_ERR(handle);
				goto out;
			}
			ret = ext3_orphan_add(handle, inode);
			if (ret) {
				ext3_journal_stop(handle);
				goto out;
			}
			orphan = 1;
			ei->i_disksize = inode->i_size;
			ext3_journal_stop(handle);
		}
	}

retry:
	ret = blockdev_direct_IO(rw, iocb, inode, iter, offset, ext3_get_block);
	/*
	 * In case of error extending write may have instantiated a few
	 * blocks outside i_size. Trim these off again.
	 */
	if (unlikely((rw & WRITE) && ret < 0)) {
		loff_t isize = i_size_read(inode);
		loff_t end = offset + count;

		if (end > isize)
			ext3_truncate_failed_direct_write(inode);
	}
	if (ret == -ENOSPC && ext3_should_retry_alloc(inode->i_sb, &retries))
		goto retry;

	if (orphan) {
		int err;

		/* Credits for sb + inode write */
		handle = ext3_journal_start(inode, 2);
		if (IS_ERR(handle)) {
			/* This is really bad luck. We've written the data
			 * but cannot extend i_size. Truncate allocated blocks
			 * and pretend the write failed... */
			ext3_truncate_failed_direct_write(inode);
			ret = PTR_ERR(handle);
			if (inode->i_nlink)
				ext3_orphan_del(NULL, inode);
			goto out;
		}
		if (inode->i_nlink)
			ext3_orphan_del(handle, inode);
		if (ret > 0) {
			loff_t end = offset + ret;
			if (end > inode->i_size) {
				ei->i_disksize = end;
				i_size_write(inode, end);
				/*
				 * We're going to return a positive `ret'
				 * here due to non-zero-length I/O, so there's
				 * no way of reporting error returns from
				 * ext3_mark_inode_dirty() to userspace.  So
				 * ignore it.
				 */
				ext3_mark_inode_dirty(handle, inode);
			}
		}
		err = ext3_journal_stop(handle);
		if (ret == 0)
			ret = err;
	}
out:
	trace_ext3_direct_IO_exit(inode, offset, count, rw, ret);
	return ret;
}

/*
 * Pages can be marked dirty completely asynchronously from ext3's journalling
 * activity.  By filemap_sync_pte(), try_to_unmap_one(), etc.  We cannot do
 * much here because ->set_page_dirty is called under VFS locks.  The page is
 * not necessarily locked.
 *
 * We cannot just dirty the page and leave attached buffers clean, because the
 * buffers' dirty state is "definitive".  We cannot just set the buffers dirty
 * or jbddirty because all the journalling code will explode.
 *
 * So what we do is to mark the page "pending dirty" and next time writepage
 * is called, propagate that into the buffers appropriately.
 */
static int ext3_journalled_set_page_dirty(struct page *page)
{
	SetPageChecked(page);
	return __set_page_dirty_nobuffers(page);
}

static const struct address_space_operations ext3_ordered_aops = {
	.readpage		= ext3_readpage,
	.readpages		= ext3_readpages,
	.writepage		= ext3_ordered_writepage,
	.write_begin		= ext3_write_begin,
	.write_end		= ext3_ordered_write_end,
	.bmap			= ext3_bmap,
	.invalidatepage		= ext3_invalidatepage,
	.releasepage		= ext3_releasepage,
	.direct_IO		= ext3_direct_IO,
	.migratepage		= buffer_migrate_page,
	.is_partially_uptodate  = block_is_partially_uptodate,
	.is_dirty_writeback	= buffer_check_dirty_writeback,
	.error_remove_page	= generic_error_remove_page,
};

static const struct address_space_operations ext3_writeback_aops = {
	.readpage		= ext3_readpage,
	.readpages		= ext3_readpages,
	.writepage		= ext3_writeback_writepage,
	.write_begin		= ext3_write_begin,
	.write_end		= ext3_writeback_write_end,
	.bmap			= ext3_bmap,
	.invalidatepage		= ext3_invalidatepage,
	.releasepage		= ext3_releasepage,
	.direct_IO		= ext3_direct_IO,
	.migratepage		= buffer_migrate_page,
	.is_partially_uptodate  = block_is_partially_uptodate,
	.error_remove_page	= generic_error_remove_page,
};

static const struct address_space_operations ext3_journalled_aops = {
	.readpage		= ext3_readpage,
	.readpages		= ext3_readpages,
	.writepage		= ext3_journalled_writepage,
	.write_begin		= ext3_write_begin,
	.write_end		= ext3_journalled_write_end,
	.set_page_dirty		= ext3_journalled_set_page_dirty,
	.bmap			= ext3_bmap,
	.invalidatepage		= ext3_invalidatepage,
	.releasepage		= ext3_releasepage,
	.is_partially_uptodate  = block_is_partially_uptodate,
	.error_remove_page	= generic_error_remove_page,
};

void ext3_set_aops(struct inode *inode)
{
	if (ext3_should_order_data(inode))
		inode->i_mapping->a_ops = &ext3_ordered_aops;
	else if (ext3_should_writeback_data(inode))
		inode->i_mapping->a_ops = &ext3_writeback_aops;
	else
		inode->i_mapping->a_ops = &ext3_journalled_aops;
}

/*
 * ext3_block_truncate_page() zeroes out a mapping from file offset `from'
 * up to the end of the block which corresponds to `from'.
 * This required during truncate. We need to physically zero the tail end
 * of that block so it doesn't yield old data if the file is later grown.
 */
static int ext3_block_truncate_page(struct inode *inode, loff_t from)
{
	ext3_fsblk_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE - 1);
	unsigned blocksize, iblock, length, pos;
	struct page *page;
	handle_t *handle = NULL;
	struct buffer_head *bh;
	int err = 0;

	/* Truncated on block boundary - nothing to do */
	blocksize = inode->i_sb->s_blocksize;
	if ((from & (blocksize - 1)) == 0)
		return 0;

	page = grab_cache_page(inode->i_mapping, index);
	if (!page)
		return -ENOMEM;
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
	if (buffer_freed(bh)) {
		BUFFER_TRACE(bh, "freed: skip");
		goto unlock;
	}

	if (!buffer_mapped(bh)) {
		BUFFER_TRACE(bh, "unmapped");
		ext3_get_block(inode, iblock, bh, 0);
		/* unmapped? It's a hole - nothing to do */
		if (!buffer_mapped(bh)) {
			BUFFER_TRACE(bh, "still unmapped");
			goto unlock;
		}
	}

	/* Ok, it's mapped. Make sure it's up-to-date */
	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!bh_uptodate_or_lock(bh)) {
		err = bh_submit_read(bh);
		/* Uhhuh. Read error. Complain and punt. */
		if (err)
			goto unlock;
	}

	/* data=writeback mode doesn't need transaction to zero-out data */
	if (!ext3_should_writeback_data(inode)) {
		/* We journal at most one block */
		handle = ext3_journal_start(inode, 1);
		if (IS_ERR(handle)) {
			clear_highpage(page);
			flush_dcache_page(page);
			err = PTR_ERR(handle);
			goto unlock;
		}
	}

	if (ext3_should_journal_data(inode)) {
		BUFFER_TRACE(bh, "get write access");
		err = ext3_journal_get_write_access(handle, bh);
		if (err)
			goto stop;
	}

	zero_user(page, offset, length);
	BUFFER_TRACE(bh, "zeroed end of block");

	err = 0;
	if (ext3_should_journal_data(inode)) {
		err = ext3_journal_dirty_metadata(handle, bh);
	} else {
		if (ext3_should_order_data(inode))
			err = ext3_journal_dirty_data(handle, bh);
		mark_buffer_dirty(bh);
	}
stop:
	if (handle)
		ext3_journal_stop(handle);

unlock:
	unlock_page(page);
	page_cache_release(page);
	return err;
}

/*
 * Probably it should be a library function... search for first non-zero word
 * or memcmp with zero_page, whatever is better for particular architecture.
 * Linus?
 */
static inline int all_zeroes(__le32 *p, __le32 *q)
{
	while (p < q)
		if (*p++)
			return 0;
	return 1;
}

/**
 *	ext3_find_shared - find the indirect blocks for partial truncation.
 *	@inode:	  inode in question
 *	@depth:	  depth of the affected branch
 *	@offsets: offsets of pointers in that branch (see ext3_block_to_path)
 *	@chain:	  place to store the pointers to partial indirect blocks
 *	@top:	  place to the (detached) top of branch
 *
 *	This is a helper function used by ext3_truncate().
 *
 *	When we do truncate() we may have to clean the ends of several
 *	indirect blocks but leave the blocks themselves alive. Block is
 *	partially truncated if some data below the new i_size is referred
 *	from it (and it is on the path to the first completely truncated
 *	data block, indeed).  We have to free the top of that path along
 *	with everything to the right of the path. Since no allocation
 *	past the truncation point is possible until ext3_truncate()
 *	finishes, we may safely do the latter, but top of branch may
 *	require special attention - pageout below the truncation point
 *	might try to populate it.
 *
 *	We atomically detach the top of branch from the tree, store the
 *	block number of its root in *@top, pointers to buffer_heads of
 *	partially truncated blocks - in @chain[].bh and pointers to
 *	their last elements that should not be removed - in
 *	@chain[].p. Return value is the pointer to last filled element
 *	of @chain.
 *
 *	The work left to caller to do the actual freeing of subtrees:
 *		a) free the subtree starting from *@top
 *		b) free the subtrees whose roots are stored in
 *			(@chain[i].p+1 .. end of @chain[i].bh->b_data)
 *		c) free the subtrees growing from the inode past the @chain[0].
 *			(no partially truncated stuff there).  */

static Indirect *ext3_find_shared(struct inode *inode, int depth,
			int offsets[4], Indirect chain[4], __le32 *top)
{
	Indirect *partial, *p;
	int k, err;

	*top = 0;
	/* Make k index the deepest non-null offset + 1 */
	for (k = depth; k > 1 && !offsets[k-1]; k--)
		;
	partial = ext3_get_branch(inode, k, offsets, chain, &err);
	/* Writer: pointers */
	if (!partial)
		partial = chain + k-1;
	/*
	 * If the branch acquired continuation since we've looked at it -
	 * fine, it should all survive and (new) top doesn't belong to us.
	 */
	if (!partial->key && *partial->p)
		/* Writer: end */
		goto no_top;
	for (p=partial; p>chain && all_zeroes((__le32*)p->bh->b_data,p->p); p--)
		;
	/*
	 * OK, we've found the last block that must survive. The rest of our
	 * branch should be detached before unlocking. However, if that rest
	 * of branch is all ours and does not grow immediately from the inode
	 * it's easier to cheat and just decrement partial->p.
	 */
	if (p == chain + k - 1 && p > chain) {
		p->p--;
	} else {
		*top = *p->p;
		/* Nope, don't do this in ext3.  Must leave the tree intact */
#if 0
		*p->p = 0;
#endif
	}
	/* Writer: end */

	while(partial > p) {
		brelse(partial->bh);
		partial--;
	}
no_top:
	return partial;
}

/*
 * Zero a number of block pointers in either an inode or an indirect block.
 * If we restart the transaction we must again get write access to the
 * indirect block for further modification.
 *
 * We release `count' blocks on disk, but (last - first) may be greater
 * than `count' because there can be holes in there.
 */
static void ext3_clear_blocks(handle_t *handle, struct inode *inode,
		struct buffer_head *bh, ext3_fsblk_t block_to_free,
		unsigned long count, __le32 *first, __le32 *last)
{
	__le32 *p;
	if (try_to_extend_transaction(handle, inode)) {
		if (bh) {
			BUFFER_TRACE(bh, "call ext3_journal_dirty_metadata");
			if (ext3_journal_dirty_metadata(handle, bh))
				return;
		}
		ext3_mark_inode_dirty(handle, inode);
		truncate_restart_transaction(handle, inode);
		if (bh) {
			BUFFER_TRACE(bh, "retaking write access");
			if (ext3_journal_get_write_access(handle, bh))
				return;
		}
	}

	/*
	 * Any buffers which are on the journal will be in memory. We find
	 * them on the hash table so journal_revoke() will run journal_forget()
	 * on them.  We've already detached each block from the file, so
	 * bforget() in journal_forget() should be safe.
	 *
	 * AKPM: turn on bforget in journal_forget()!!!
	 */
	for (p = first; p < last; p++) {
		u32 nr = le32_to_cpu(*p);
		if (nr) {
			struct buffer_head *bh;

			*p = 0;
			bh = sb_find_get_block(inode->i_sb, nr);
			ext3_forget(handle, 0, inode, bh, nr);
		}
	}

	ext3_free_blocks(handle, inode, block_to_free, count);
}

/**
 * ext3_free_data - free a list of data blocks
 * @handle:	handle for this transaction
 * @inode:	inode we are dealing with
 * @this_bh:	indirect buffer_head which contains *@first and *@last
 * @first:	array of block numbers
 * @last:	points immediately past the end of array
 *
 * We are freeing all blocks referred from that array (numbers are stored as
 * little-endian 32-bit) and updating @inode->i_blocks appropriately.
 *
 * We accumulate contiguous runs of blocks to free.  Conveniently, if these
 * blocks are contiguous then releasing them at one time will only affect one
 * or two bitmap blocks (+ group descriptor(s) and superblock) and we won't
 * actually use a lot of journal space.
 *
 * @this_bh will be %NULL if @first and @last point into the inode's direct
 * block pointers.
 */
static void ext3_free_data(handle_t *handle, struct inode *inode,
			   struct buffer_head *this_bh,
			   __le32 *first, __le32 *last)
{
	ext3_fsblk_t block_to_free = 0;    /* Starting block # of a run */
	unsigned long count = 0;	    /* Number of blocks in the run */
	__le32 *block_to_free_p = NULL;	    /* Pointer into inode/ind
					       corresponding to
					       block_to_free */
	ext3_fsblk_t nr;		    /* Current block # */
	__le32 *p;			    /* Pointer into inode/ind
					       for current block */
	int err;

	if (this_bh) {				/* For indirect block */
		BUFFER_TRACE(this_bh, "get_write_access");
		err = ext3_journal_get_write_access(handle, this_bh);
		/* Important: if we can't update the indirect pointers
		 * to the blocks, we can't free them. */
		if (err)
			return;
	}

	for (p = first; p < last; p++) {
		nr = le32_to_cpu(*p);
		if (nr) {
			/* accumulate blocks to free if they're contiguous */
			if (count == 0) {
				block_to_free = nr;
				block_to_free_p = p;
				count = 1;
			} else if (nr == block_to_free + count) {
				count++;
			} else {
				ext3_clear_blocks(handle, inode, this_bh,
						  block_to_free,
						  count, block_to_free_p, p);
				block_to_free = nr;
				block_to_free_p = p;
				count = 1;
			}
		}
	}

	if (count > 0)
		ext3_clear_blocks(handle, inode, this_bh, block_to_free,
				  count, block_to_free_p, p);

	if (this_bh) {
		BUFFER_TRACE(this_bh, "call ext3_journal_dirty_metadata");

		/*
		 * The buffer head should have an attached journal head at this
		 * point. However, if the data is corrupted and an indirect
		 * block pointed to itself, it would have been detached when
		 * the block was cleared. Check for this instead of OOPSing.
		 */
		if (bh2jh(this_bh))
			ext3_journal_dirty_metadata(handle, this_bh);
		else
			ext3_error(inode->i_sb, "ext3_free_data",
				   "circular indirect block detected, "
				   "inode=%lu, block=%llu",
				   inode->i_ino,
				   (unsigned long long)this_bh->b_blocknr);
	}
}

/**
 *	ext3_free_branches - free an array of branches
 *	@handle: JBD handle for this transaction
 *	@inode:	inode we are dealing with
 *	@parent_bh: the buffer_head which contains *@first and *@last
 *	@first:	array of block numbers
 *	@last:	pointer immediately past the end of array
 *	@depth:	depth of the branches to free
 *
 *	We are freeing all blocks referred from these branches (numbers are
 *	stored as little-endian 32-bit) and updating @inode->i_blocks
 *	appropriately.
 */
static void ext3_free_branches(handle_t *handle, struct inode *inode,
			       struct buffer_head *parent_bh,
			       __le32 *first, __le32 *last, int depth)
{
	ext3_fsblk_t nr;
	__le32 *p;

	if (is_handle_aborted(handle))
		return;

	if (depth--) {
		struct buffer_head *bh;
		int addr_per_block = EXT3_ADDR_PER_BLOCK(inode->i_sb);
		p = last;
		while (--p >= first) {
			nr = le32_to_cpu(*p);
			if (!nr)
				continue;		/* A hole */

			/* Go read the buffer for the next level down */
			bh = sb_bread(inode->i_sb, nr);

			/*
			 * A read failure? Report error and clear slot
			 * (should be rare).
			 */
			if (!bh) {
				ext3_error(inode->i_sb, "ext3_free_branches",
					   "Read failure, inode=%lu, block="E3FSBLK,
					   inode->i_ino, nr);
				continue;
			}

			/* This zaps the entire block.  Bottom up. */
			BUFFER_TRACE(bh, "free child branches");
			ext3_free_branches(handle, inode, bh,
					   (__le32*)bh->b_data,
					   (__le32*)bh->b_data + addr_per_block,
					   depth);

			/*
			 * Everything below this this pointer has been
			 * released.  Now let this top-of-subtree go.
			 *
			 * We want the freeing of this indirect block to be
			 * atomic in the journal with the updating of the
			 * bitmap block which owns it.  So make some room in
			 * the journal.
			 *
			 * We zero the parent pointer *after* freeing its
			 * pointee in the bitmaps, so if extend_transaction()
			 * for some reason fails to put the bitmap changes and
			 * the release into the same transaction, recovery
			 * will merely complain about releasing a free block,
			 * rather than leaking blocks.
			 */
			if (is_handle_aborted(handle))
				return;
			if (try_to_extend_transaction(handle, inode)) {
				ext3_mark_inode_dirty(handle, inode);
				truncate_restart_transaction(handle, inode);
			}

			/*
			 * We've probably journalled the indirect block several
			 * times during the truncate.  But it's no longer
			 * needed and we now drop it from the transaction via
			 * journal_revoke().
			 *
			 * That's easy if it's exclusively part of this
			 * transaction.  But if it's part of the committing
			 * transaction then journal_forget() will simply
			 * brelse() it.  That means that if the underlying
			 * block is reallocated in ext3_get_block(),
			 * unmap_underlying_metadata() will find this block
			 * and will try to get rid of it.  damn, damn. Thus
			 * we don't allow a block to be reallocated until
			 * a transaction freeing it has fully committed.
			 *
			 * We also have to make sure journal replay after a
			 * crash does not overwrite non-journaled data blocks
			 * with old metadata when the block got reallocated for
			 * data.  Thus we have to store a revoke record for a
			 * block in the same transaction in which we free the
			 * block.
			 */
			ext3_forget(handle, 1, inode, bh, bh->b_blocknr);

			ext3_free_blocks(handle, inode, nr, 1);

			if (parent_bh) {
				/*
				 * The block which we have just freed is
				 * pointed to by an indirect block: journal it
				 */
				BUFFER_TRACE(parent_bh, "get_write_access");
				if (!ext3_journal_get_write_access(handle,
								   parent_bh)){
					*p = 0;
					BUFFER_TRACE(parent_bh,
					"call ext3_journal_dirty_metadata");
					ext3_journal_dirty_metadata(handle,
								    parent_bh);
				}
			}
		}
	} else {
		/* We have reached the bottom of the tree. */
		BUFFER_TRACE(parent_bh, "free data blocks");
		ext3_free_data(handle, inode, parent_bh, first, last);
	}
}

int ext3_can_truncate(struct inode *inode)
{
	if (S_ISREG(inode->i_mode))
		return 1;
	if (S_ISDIR(inode->i_mode))
		return 1;
	if (S_ISLNK(inode->i_mode))
		return !ext3_inode_is_fast_symlink(inode);
	return 0;
}

/*
 * ext3_truncate()
 *
 * We block out ext3_get_block() block instantiations across the entire
 * transaction, and VFS/VM ensures that ext3_truncate() cannot run
 * simultaneously on behalf of the same inode.
 *
 * As we work through the truncate and commit bits of it to the journal there
 * is one core, guiding principle: the file's tree must always be consistent on
 * disk.  We must be able to restart the truncate after a crash.
 *
 * The file's tree may be transiently inconsistent in memory (although it
 * probably isn't), but whenever we close off and commit a journal transaction,
 * the contents of (the filesystem + the journal) must be consistent and
 * restartable.  It's pretty simple, really: bottom up, right to left (although
 * left-to-right works OK too).
 *
 * Note that at recovery time, journal replay occurs *before* the restart of
 * truncate against the orphan inode list.
 *
 * The committed inode has the new, desired i_size (which is the same as
 * i_disksize in this case).  After a crash, ext3_orphan_cleanup() will see
 * that this inode's truncate did not complete and it will again call
 * ext3_truncate() to have another go.  So there will be instantiated blocks
 * to the right of the truncation point in a crashed ext3 filesystem.  But
 * that's fine - as long as they are linked from the inode, the post-crash
 * ext3_truncate() run will find them and release them.
 */
void ext3_truncate(struct inode *inode)
{
	handle_t *handle;
	struct ext3_inode_info *ei = EXT3_I(inode);
	__le32 *i_data = ei->i_data;
	int addr_per_block = EXT3_ADDR_PER_BLOCK(inode->i_sb);
	int offsets[4];
	Indirect chain[4];
	Indirect *partial;
	__le32 nr = 0;
	int n;
	long last_block;
	unsigned blocksize = inode->i_sb->s_blocksize;

	trace_ext3_truncate_enter(inode);

	if (!ext3_can_truncate(inode))
		goto out_notrans;

	if (inode->i_size == 0 && ext3_should_writeback_data(inode))
		ext3_set_inode_state(inode, EXT3_STATE_FLUSH_ON_CLOSE);

	handle = start_transaction(inode);
	if (IS_ERR(handle))
		goto out_notrans;

	last_block = (inode->i_size + blocksize-1)
					>> EXT3_BLOCK_SIZE_BITS(inode->i_sb);
	n = ext3_block_to_path(inode, last_block, offsets, NULL);
	if (n == 0)
		goto out_stop;	/* error */

	/*
	 * OK.  This truncate is going to happen.  We add the inode to the
	 * orphan list, so that if this truncate spans multiple transactions,
	 * and we crash, we will resume the truncate when the filesystem
	 * recovers.  It also marks the inode dirty, to catch the new size.
	 *
	 * Implication: the file must always be in a sane, consistent
	 * truncatable state while each transaction commits.
	 */
	if (ext3_orphan_add(handle, inode))
		goto out_stop;

	/*
	 * The orphan list entry will now protect us from any crash which
	 * occurs before the truncate completes, so it is now safe to propagate
	 * the new, shorter inode size (held for now in i_size) into the
	 * on-disk inode. We do this via i_disksize, which is the value which
	 * ext3 *really* writes onto the disk inode.
	 */
	ei->i_disksize = inode->i_size;

	/*
	 * From here we block out all ext3_get_block() callers who want to
	 * modify the block allocation tree.
	 */
	mutex_lock(&ei->truncate_mutex);

	if (n == 1) {		/* direct blocks */
		ext3_free_data(handle, inode, NULL, i_data+offsets[0],
			       i_data + EXT3_NDIR_BLOCKS);
		goto do_indirects;
	}

	partial = ext3_find_shared(inode, n, offsets, chain, &nr);
	/* Kill the top of shared branch (not detached) */
	if (nr) {
		if (partial == chain) {
			/* Shared branch grows from the inode */
			ext3_free_branches(handle, inode, NULL,
					   &nr, &nr+1, (chain+n-1) - partial);
			*partial->p = 0;
			/*
			 * We mark the inode dirty prior to restart,
			 * and prior to stop.  No need for it here.
			 */
		} else {
			/* Shared branch grows from an indirect block */
			ext3_free_branches(handle, inode, partial->bh,
					partial->p,
					partial->p+1, (chain+n-1) - partial);
		}
	}
	/* Clear the ends of indirect blocks on the shared branch */
	while (partial > chain) {
		ext3_free_branches(handle, inode, partial->bh, partial->p + 1,
				   (__le32*)partial->bh->b_data+addr_per_block,
				   (chain+n-1) - partial);
		BUFFER_TRACE(partial->bh, "call brelse");
		brelse (partial->bh);
		partial--;
	}
do_indirects:
	/* Kill the remaining (whole) subtrees */
	switch (offsets[0]) {
	default:
		nr = i_data[EXT3_IND_BLOCK];
		if (nr) {
			ext3_free_branches(handle, inode, NULL, &nr, &nr+1, 1);
			i_data[EXT3_IND_BLOCK] = 0;
		}
	case EXT3_IND_BLOCK:
		nr = i_data[EXT3_DIND_BLOCK];
		if (nr) {
			ext3_free_branches(handle, inode, NULL, &nr, &nr+1, 2);
			i_data[EXT3_DIND_BLOCK] = 0;
		}
	case EXT3_DIND_BLOCK:
		nr = i_data[EXT3_TIND_BLOCK];
		if (nr) {
			ext3_free_branches(handle, inode, NULL, &nr, &nr+1, 3);
			i_data[EXT3_TIND_BLOCK] = 0;
		}
	case EXT3_TIND_BLOCK:
		;
	}

	ext3_discard_reservation(inode);

	mutex_unlock(&ei->truncate_mutex);
	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
	ext3_mark_inode_dirty(handle, inode);

	/*
	 * In a multi-transaction truncate, we only make the final transaction
	 * synchronous
	 */
	if (IS_SYNC(inode))
		handle->h_sync = 1;
out_stop:
	/*
	 * If this was a simple ftruncate(), and the file will remain alive
	 * then we need to clear up the orphan record which we created above.
	 * However, if this was a real unlink then we were called by
	 * ext3_evict_inode(), and we allow that function to clean up the
	 * orphan info for us.
	 */
	if (inode->i_nlink)
		ext3_orphan_del(handle, inode);

	ext3_journal_stop(handle);
	trace_ext3_truncate_exit(inode);
	return;
out_notrans:
	/*
	 * Delete the inode from orphan list so that it doesn't stay there
	 * forever and trigger assertion on umount.
	 */
	if (inode->i_nlink)
		ext3_orphan_del(NULL, inode);
	trace_ext3_truncate_exit(inode);
}

static ext3_fsblk_t ext3_get_inode_block(struct super_block *sb,
		unsigned long ino, struct ext3_iloc *iloc)
{
	unsigned long block_group;
	unsigned long offset;
	ext3_fsblk_t block;
	struct ext3_group_desc *gdp;

	if (!ext3_valid_inum(sb, ino)) {
		/*
		 * This error is already checked for in namei.c unless we are
		 * looking at an NFS filehandle, in which case no error
		 * report is needed
		 */
		return 0;
	}

	block_group = (ino - 1) / EXT3_INODES_PER_GROUP(sb);
	gdp = ext3_get_group_desc(sb, block_group, NULL);
	if (!gdp)
		return 0;
	/*
	 * Figure out the offset within the block group inode table
	 */
	offset = ((ino - 1) % EXT3_INODES_PER_GROUP(sb)) *
		EXT3_INODE_SIZE(sb);
	block = le32_to_cpu(gdp->bg_inode_table) +
		(offset >> EXT3_BLOCK_SIZE_BITS(sb));

	iloc->block_group = block_group;
	iloc->offset = offset & (EXT3_BLOCK_SIZE(sb) - 1);
	return block;
}

/*
 * ext3_get_inode_loc returns with an extra refcount against the inode's
 * underlying buffer_head on success. If 'in_mem' is true, we have all
 * data in memory that is needed to recreate the on-disk version of this
 * inode.
 */
static int __ext3_get_inode_loc(struct inode *inode,
				struct ext3_iloc *iloc, int in_mem)
{
	ext3_fsblk_t block;
	struct buffer_head *bh;

	block = ext3_get_inode_block(inode->i_sb, inode->i_ino, iloc);
	if (!block)
		return -EIO;

	bh = sb_getblk(inode->i_sb, block);
	if (unlikely(!bh)) {
		ext3_error (inode->i_sb, "ext3_get_inode_loc",
				"unable to read inode block - "
				"inode=%lu, block="E3FSBLK,
				 inode->i_ino, block);
		return -ENOMEM;
	}
	if (!buffer_uptodate(bh)) {
		lock_buffer(bh);

		/*
		 * If the buffer has the write error flag, we have failed
		 * to write out another inode in the same block.  In this
		 * case, we don't have to read the block because we may
		 * read the old inode data successfully.
		 */
		if (buffer_write_io_error(bh) && !buffer_uptodate(bh))
			set_buffer_uptodate(bh);

		if (buffer_uptodate(bh)) {
			/* someone brought it uptodate while we waited */
			unlock_buffer(bh);
			goto has_buffer;
		}

		/*
		 * If we have all information of the inode in memory and this
		 * is the only valid inode in the block, we need not read the
		 * block.
		 */
		if (in_mem) {
			struct buffer_head *bitmap_bh;
			struct ext3_group_desc *desc;
			int inodes_per_buffer;
			int inode_offset, i;
			int block_group;
			int start;

			block_group = (inode->i_ino - 1) /
					EXT3_INODES_PER_GROUP(inode->i_sb);
			inodes_per_buffer = bh->b_size /
				EXT3_INODE_SIZE(inode->i_sb);
			inode_offset = ((inode->i_ino - 1) %
					EXT3_INODES_PER_GROUP(inode->i_sb));
			start = inode_offset & ~(inodes_per_buffer - 1);

			/* Is the inode bitmap in cache? */
			desc = ext3_get_group_desc(inode->i_sb,
						block_group, NULL);
			if (!desc)
				goto make_io;

			bitmap_bh = sb_getblk(inode->i_sb,
					le32_to_cpu(desc->bg_inode_bitmap));
			if (unlikely(!bitmap_bh))
				goto make_io;

			/*
			 * If the inode bitmap isn't in cache then the
			 * optimisation may end up performing two reads instead
			 * of one, so skip it.
			 */
			if (!buffer_uptodate(bitmap_bh)) {
				brelse(bitmap_bh);
				goto make_io;
			}
			for (i = start; i < start + inodes_per_buffer; i++) {
				if (i == inode_offset)
					continue;
				if (ext3_test_bit(i, bitmap_bh->b_data))
					break;
			}
			brelse(bitmap_bh);
			if (i == start + inodes_per_buffer) {
				/* all other inodes are free, so skip I/O */
				memset(bh->b_data, 0, bh->b_size);
				set_buffer_uptodate(bh);
				unlock_buffer(bh);
				goto has_buffer;
			}
		}

make_io:
		/*
		 * There are other valid inodes in the buffer, this inode
		 * has in-inode xattrs, or we don't have this inode in memory.
		 * Read the block from disk.
		 */
		trace_ext3_load_inode(inode);
		get_bh(bh);
		bh->b_end_io = end_buffer_read_sync;
		submit_bh(READ | REQ_META | REQ_PRIO, bh);
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh)) {
			ext3_error(inode->i_sb, "ext3_get_inode_loc",
					"unable to read inode block - "
					"inode=%lu, block="E3FSBLK,
					inode->i_ino, block);
			brelse(bh);
			return -EIO;
		}
	}
has_buffer:
	iloc->bh = bh;
	return 0;
}

int ext3_get_inode_loc(struct inode *inode, struct ext3_iloc *iloc)
{
	/* We have all inode data except xattrs in memory here. */
	return __ext3_get_inode_loc(inode, iloc,
		!ext3_test_inode_state(inode, EXT3_STATE_XATTR));
}

void ext3_set_inode_flags(struct inode *inode)
{
	unsigned int flags = EXT3_I(inode)->i_flags;

	inode->i_flags &= ~(S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME|S_DIRSYNC);
	if (flags & EXT3_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & EXT3_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & EXT3_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & EXT3_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & EXT3_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
}

/* Propagate flags from i_flags to EXT3_I(inode)->i_flags */
void ext3_get_inode_flags(struct ext3_inode_info *ei)
{
	unsigned int flags = ei->vfs_inode.i_flags;

	ei->i_flags &= ~(EXT3_SYNC_FL|EXT3_APPEND_FL|
			EXT3_IMMUTABLE_FL|EXT3_NOATIME_FL|EXT3_DIRSYNC_FL);
	if (flags & S_SYNC)
		ei->i_flags |= EXT3_SYNC_FL;
	if (flags & S_APPEND)
		ei->i_flags |= EXT3_APPEND_FL;
	if (flags & S_IMMUTABLE)
		ei->i_flags |= EXT3_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		ei->i_flags |= EXT3_NOATIME_FL;
	if (flags & S_DIRSYNC)
		ei->i_flags |= EXT3_DIRSYNC_FL;
}

struct inode *ext3_iget(struct super_block *sb, unsigned long ino)
{
	struct ext3_iloc iloc;
	struct ext3_inode *raw_inode;
	struct ext3_inode_info *ei;
	struct buffer_head *bh;
	struct inode *inode;
	journal_t *journal = EXT3_SB(sb)->s_journal;
	transaction_t *transaction;
	long ret;
	int block;
	uid_t i_uid;
	gid_t i_gid;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ei = EXT3_I(inode);
	ei->i_block_alloc_info = NULL;

	ret = __ext3_get_inode_loc(inode, &iloc, 0);
	if (ret < 0)
		goto bad_inode;
	bh = iloc.bh;
	raw_inode = ext3_raw_inode(&iloc);
	inode->i_mode = le16_to_cpu(raw_inode->i_mode);
	i_uid = (uid_t)le16_to_cpu(raw_inode->i_uid_low);
	i_gid = (gid_t)le16_to_cpu(raw_inode->i_gid_low);
	if(!(test_opt (inode->i_sb, NO_UID32))) {
		i_uid |= le16_to_cpu(raw_inode->i_uid_high) << 16;
		i_gid |= le16_to_cpu(raw_inode->i_gid_high) << 16;
	}
	i_uid_write(inode, i_uid);
	i_gid_write(inode, i_gid);
	set_nlink(inode, le16_to_cpu(raw_inode->i_links_count));
	inode->i_size = le32_to_cpu(raw_inode->i_size);
	inode->i_atime.tv_sec = (signed)le32_to_cpu(raw_inode->i_atime);
	inode->i_ctime.tv_sec = (signed)le32_to_cpu(raw_inode->i_ctime);
	inode->i_mtime.tv_sec = (signed)le32_to_cpu(raw_inode->i_mtime);
	inode->i_atime.tv_nsec = inode->i_ctime.tv_nsec = inode->i_mtime.tv_nsec = 0;

	ei->i_state_flags = 0;
	ei->i_dir_start_lookup = 0;
	ei->i_dtime = le32_to_cpu(raw_inode->i_dtime);
	/* We now have enough fields to check if the inode was active or not.
	 * This is needed because nfsd might try to access dead inodes
	 * the test is that same one that e2fsck uses
	 * NeilBrown 1999oct15
	 */
	if (inode->i_nlink == 0) {
		if (inode->i_mode == 0 ||
		    !(EXT3_SB(inode->i_sb)->s_mount_state & EXT3_ORPHAN_FS)) {
			/* this inode is deleted */
			brelse (bh);
			ret = -ESTALE;
			goto bad_inode;
		}
		/* The only unlinked inodes we let through here have
		 * valid i_mode and are being read by the orphan
		 * recovery code: that's fine, we're about to complete
		 * the process of deleting those. */
	}
	inode->i_blocks = le32_to_cpu(raw_inode->i_blocks);
	ei->i_flags = le32_to_cpu(raw_inode->i_flags);
#ifdef EXT3_FRAGMENTS
	ei->i_faddr = le32_to_cpu(raw_inode->i_faddr);
	ei->i_frag_no = raw_inode->i_frag;
	ei->i_frag_size = raw_inode->i_fsize;
#endif
	ei->i_file_acl = le32_to_cpu(raw_inode->i_file_acl);
	if (!S_ISREG(inode->i_mode)) {
		ei->i_dir_acl = le32_to_cpu(raw_inode->i_dir_acl);
	} else {
		inode->i_size |=
			((__u64)le32_to_cpu(raw_inode->i_size_high)) << 32;
	}
	ei->i_disksize = inode->i_size;
	inode->i_generation = le32_to_cpu(raw_inode->i_generation);
	ei->i_block_group = iloc.block_group;
	/*
	 * NOTE! The in-memory inode i_data array is in little-endian order
	 * even on big-endian machines: we do NOT byteswap the block numbers!
	 */
	for (block = 0; block < EXT3_N_BLOCKS; block++)
		ei->i_data[block] = raw_inode->i_block[block];
	INIT_LIST_HEAD(&ei->i_orphan);

	/*
	 * Set transaction id's of transactions that have to be committed
	 * to finish f[data]sync. We set them to currently running transaction
	 * as we cannot be sure that the inode or some of its metadata isn't
	 * part of the transaction - the inode could have been reclaimed and
	 * now it is reread from disk.
	 */
	if (journal) {
		tid_t tid;

		spin_lock(&journal->j_state_lock);
		if (journal->j_running_transaction)
			transaction = journal->j_running_transaction;
		else
			transaction = journal->j_committing_transaction;
		if (transaction)
			tid = transaction->t_tid;
		else
			tid = journal->j_commit_sequence;
		spin_unlock(&journal->j_state_lock);
		atomic_set(&ei->i_sync_tid, tid);
		atomic_set(&ei->i_datasync_tid, tid);
	}

	if (inode->i_ino >= EXT3_FIRST_INO(inode->i_sb) + 1 &&
	    EXT3_INODE_SIZE(inode->i_sb) > EXT3_GOOD_OLD_INODE_SIZE) {
		/*
		 * When mke2fs creates big inodes it does not zero out
		 * the unused bytes above EXT3_GOOD_OLD_INODE_SIZE,
		 * so ignore those first few inodes.
		 */
		ei->i_extra_isize = le16_to_cpu(raw_inode->i_extra_isize);
		if (EXT3_GOOD_OLD_INODE_SIZE + ei->i_extra_isize >
		    EXT3_INODE_SIZE(inode->i_sb)) {
			brelse (bh);
			ret = -EIO;
			goto bad_inode;
		}
		if (ei->i_extra_isize == 0) {
			/* The extra space is currently unused. Use it. */
			ei->i_extra_isize = sizeof(struct ext3_inode) -
					    EXT3_GOOD_OLD_INODE_SIZE;
		} else {
			__le32 *magic = (void *)raw_inode +
					EXT3_GOOD_OLD_INODE_SIZE +
					ei->i_extra_isize;
			if (*magic == cpu_to_le32(EXT3_XATTR_MAGIC))
				 ext3_set_inode_state(inode, EXT3_STATE_XATTR);
		}
	} else
		ei->i_extra_isize = 0;

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &ext3_file_inode_operations;
		inode->i_fop = &ext3_file_operations;
		ext3_set_aops(inode);
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ext3_dir_inode_operations;
		inode->i_fop = &ext3_dir_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		if (ext3_inode_is_fast_symlink(inode)) {
			inode->i_op = &ext3_fast_symlink_inode_operations;
			nd_terminate_link(ei->i_data, inode->i_size,
				sizeof(ei->i_data) - 1);
		} else {
			inode->i_op = &ext3_symlink_inode_operations;
			ext3_set_aops(inode);
		}
	} else {
		inode->i_op = &ext3_special_inode_operations;
		if (raw_inode->i_block[0])
			init_special_inode(inode, inode->i_mode,
			   old_decode_dev(le32_to_cpu(raw_inode->i_block[0])));
		else
			init_special_inode(inode, inode->i_mode,
			   new_decode_dev(le32_to_cpu(raw_inode->i_block[1])));
	}
	brelse (iloc.bh);
	ext3_set_inode_flags(inode);
	unlock_new_inode(inode);
	return inode;

bad_inode:
	iget_failed(inode);
	return ERR_PTR(ret);
}

/*
 * Post the struct inode info into an on-disk inode location in the
 * buffer-cache.  This gobbles the caller's reference to the
 * buffer_head in the inode location struct.
 *
 * The caller must have write access to iloc->bh.
 */
static int ext3_do_update_inode(handle_t *handle,
				struct inode *inode,
				struct ext3_iloc *iloc)
{
	struct ext3_inode *raw_inode = ext3_raw_inode(iloc);
	struct ext3_inode_info *ei = EXT3_I(inode);
	struct buffer_head *bh = iloc->bh;
	int err = 0, rc, block;
	int need_datasync = 0;
	__le32 disksize;
	uid_t i_uid;
	gid_t i_gid;

again:
	/* we can't allow multiple procs in here at once, its a bit racey */
	lock_buffer(bh);

	/* For fields not not tracking in the in-memory inode,
	 * initialise them to zero for new inodes. */
	if (ext3_test_inode_state(inode, EXT3_STATE_NEW))
		memset(raw_inode, 0, EXT3_SB(inode->i_sb)->s_inode_size);

	ext3_get_inode_flags(ei);
	raw_inode->i_mode = cpu_to_le16(inode->i_mode);
	i_uid = i_uid_read(inode);
	i_gid = i_gid_read(inode);
	if(!(test_opt(inode->i_sb, NO_UID32))) {
		raw_inode->i_uid_low = cpu_to_le16(low_16_bits(i_uid));
		raw_inode->i_gid_low = cpu_to_le16(low_16_bits(i_gid));
/*
 * Fix up interoperability with old kernels. Otherwise, old inodes get
 * re-used with the upper 16 bits of the uid/gid intact
 */
		if(!ei->i_dtime) {
			raw_inode->i_uid_high =
				cpu_to_le16(high_16_bits(i_uid));
			raw_inode->i_gid_high =
				cpu_to_le16(high_16_bits(i_gid));
		} else {
			raw_inode->i_uid_high = 0;
			raw_inode->i_gid_high = 0;
		}
	} else {
		raw_inode->i_uid_low =
			cpu_to_le16(fs_high2lowuid(i_uid));
		raw_inode->i_gid_low =
			cpu_to_le16(fs_high2lowgid(i_gid));
		raw_inode->i_uid_high = 0;
		raw_inode->i_gid_high = 0;
	}
	raw_inode->i_links_count = cpu_to_le16(inode->i_nlink);
	disksize = cpu_to_le32(ei->i_disksize);
	if (disksize != raw_inode->i_size) {
		need_datasync = 1;
		raw_inode->i_size = disksize;
	}
	raw_inode->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	raw_inode->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	raw_inode->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	raw_inode->i_blocks = cpu_to_le32(inode->i_blocks);
	raw_inode->i_dtime = cpu_to_le32(ei->i_dtime);
	raw_inode->i_flags = cpu_to_le32(ei->i_flags);
#ifdef EXT3_FRAGMENTS
	raw_inode->i_faddr = cpu_to_le32(ei->i_faddr);
	raw_inode->i_frag = ei->i_frag_no;
	raw_inode->i_fsize = ei->i_frag_size;
#endif
	raw_inode->i_file_acl = cpu_to_le32(ei->i_file_acl);
	if (!S_ISREG(inode->i_mode)) {
		raw_inode->i_dir_acl = cpu_to_le32(ei->i_dir_acl);
	} else {
		disksize = cpu_to_le32(ei->i_disksize >> 32);
		if (disksize != raw_inode->i_size_high) {
			raw_inode->i_size_high = disksize;
			need_datasync = 1;
		}
		if (ei->i_disksize > 0x7fffffffULL) {
			struct super_block *sb = inode->i_sb;
			if (!EXT3_HAS_RO_COMPAT_FEATURE(sb,
					EXT3_FEATURE_RO_COMPAT_LARGE_FILE) ||
			    EXT3_SB(sb)->s_es->s_rev_level ==
					cpu_to_le32(EXT3_GOOD_OLD_REV)) {
			       /* If this is the first large file
				* created, add a flag to the superblock.
				*/
				unlock_buffer(bh);
				err = ext3_journal_get_write_access(handle,
						EXT3_SB(sb)->s_sbh);
				if (err)
					goto out_brelse;

				ext3_update_dynamic_rev(sb);
				EXT3_SET_RO_COMPAT_FEATURE(sb,
					EXT3_FEATURE_RO_COMPAT_LARGE_FILE);
				handle->h_sync = 1;
				err = ext3_journal_dirty_metadata(handle,
						EXT3_SB(sb)->s_sbh);
				/* get our lock and start over */
				goto again;
			}
		}
	}
	raw_inode->i_generation = cpu_to_le32(inode->i_generation);
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		if (old_valid_dev(inode->i_rdev)) {
			raw_inode->i_block[0] =
				cpu_to_le32(old_encode_dev(inode->i_rdev));
			raw_inode->i_block[1] = 0;
		} else {
			raw_inode->i_block[0] = 0;
			raw_inode->i_block[1] =
				cpu_to_le32(new_encode_dev(inode->i_rdev));
			raw_inode->i_block[2] = 0;
		}
	} else for (block = 0; block < EXT3_N_BLOCKS; block++)
		raw_inode->i_block[block] = ei->i_data[block];

	if (ei->i_extra_isize)
		raw_inode->i_extra_isize = cpu_to_le16(ei->i_extra_isize);

	BUFFER_TRACE(bh, "call ext3_journal_dirty_metadata");
	unlock_buffer(bh);
	rc = ext3_journal_dirty_metadata(handle, bh);
	if (!err)
		err = rc;
	ext3_clear_inode_state(inode, EXT3_STATE_NEW);

	atomic_set(&ei->i_sync_tid, handle->h_transaction->t_tid);
	if (need_datasync)
		atomic_set(&ei->i_datasync_tid, handle->h_transaction->t_tid);
out_brelse:
	brelse (bh);
	ext3_std_error(inode->i_sb, err);
	return err;
}

/*
 * ext3_write_inode()
 *
 * We are called from a few places:
 *
 * - Within generic_file_aio_write() -> generic_write_sync() for O_SYNC files.
 *   Here, there will be no transaction running. We wait for any running
 *   transaction to commit.
 *
 * - Within flush work (for sys_sync(), kupdate and such).
 *   We wait on commit, if told to.
 *
 * - Within iput_final() -> write_inode_now()
 *   We wait on commit, if told to.
 *
 * In all cases it is actually safe for us to return without doing anything,
 * because the inode has been copied into a raw inode buffer in
 * ext3_mark_inode_dirty().  This is a correctness thing for WB_SYNC_ALL
 * writeback.
 *
 * Note that we are absolutely dependent upon all inode dirtiers doing the
 * right thing: they *must* call mark_inode_dirty() after dirtying info in
 * which we are interested.
 *
 * It would be a bug for them to not do this.  The code:
 *
 *	mark_inode_dirty(inode)
 *	stuff();
 *	inode->i_size = expr;
 *
 * is in error because write_inode() could occur while `stuff()' is running,
 * and the new i_size will be lost.  Plus the inode will no longer be on the
 * superblock's dirty inode list.
 */
int ext3_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	if (WARN_ON_ONCE(current->flags & PF_MEMALLOC))
		return 0;

	if (ext3_journal_current_handle()) {
		jbd_debug(1, "called recursively, non-PF_MEMALLOC!\n");
		dump_stack();
		return -EIO;
	}

	/*
	 * No need to force transaction in WB_SYNC_NONE mode. Also
	 * ext3_sync_fs() will force the commit after everything is
	 * written.
	 */
	if (wbc->sync_mode != WB_SYNC_ALL || wbc->for_sync)
		return 0;

	return ext3_force_commit(inode->i_sb);
}

/*
 * ext3_setattr()
 *
 * Called from notify_change.
 *
 * We want to trap VFS attempts to truncate the file as soon as
 * possible.  In particular, we want to make sure that when the VFS
 * shrinks i_size, we put the inode on the orphan list and modify
 * i_disksize immediately, so that during the subsequent flushing of
 * dirty pages and freeing of disk blocks, we can guarantee that any
 * commit will leave the blocks being flushed in an unused state on
 * disk.  (On recovery, the inode will get truncated and the blocks will
 * be freed, so we have a strong guarantee that no future commit will
 * leave these blocks visible to the user.)
 *
 * Called with inode->sem down.
 */
int ext3_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error, rc = 0;
	const unsigned int ia_valid = attr->ia_valid;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if (is_quota_modification(inode, attr))
		dquot_initialize(inode);
	if ((ia_valid & ATTR_UID && !uid_eq(attr->ia_uid, inode->i_uid)) ||
	    (ia_valid & ATTR_GID && !gid_eq(attr->ia_gid, inode->i_gid))) {
		handle_t *handle;

		/* (user+group)*(old+new) structure, inode write (sb,
		 * inode block, ? - but truncate inode update has it) */
		handle = ext3_journal_start(inode, EXT3_MAXQUOTAS_INIT_BLOCKS(inode->i_sb)+
					EXT3_MAXQUOTAS_DEL_BLOCKS(inode->i_sb)+3);
		if (IS_ERR(handle)) {
			error = PTR_ERR(handle);
			goto err_out;
		}
		error = dquot_transfer(inode, attr);
		if (error) {
			ext3_journal_stop(handle);
			return error;
		}
		/* Update corresponding info in inode so that everything is in
		 * one transaction */
		if (attr->ia_valid & ATTR_UID)
			inode->i_uid = attr->ia_uid;
		if (attr->ia_valid & ATTR_GID)
			inode->i_gid = attr->ia_gid;
		error = ext3_mark_inode_dirty(handle, inode);
		ext3_journal_stop(handle);
	}

	if (attr->ia_valid & ATTR_SIZE)
		inode_dio_wait(inode);

	if (S_ISREG(inode->i_mode) &&
	    attr->ia_valid & ATTR_SIZE && attr->ia_size < inode->i_size) {
		handle_t *handle;

		handle = ext3_journal_start(inode, 3);
		if (IS_ERR(handle)) {
			error = PTR_ERR(handle);
			goto err_out;
		}

		error = ext3_orphan_add(handle, inode);
		if (error) {
			ext3_journal_stop(handle);
			goto err_out;
		}
		EXT3_I(inode)->i_disksize = attr->ia_size;
		error = ext3_mark_inode_dirty(handle, inode);
		ext3_journal_stop(handle);
		if (error) {
			/* Some hard fs error must have happened. Bail out. */
			ext3_orphan_del(NULL, inode);
			goto err_out;
		}
		rc = ext3_block_truncate_page(inode, attr->ia_size);
		if (rc) {
			/* Cleanup orphan list and exit */
			handle = ext3_journal_start(inode, 3);
			if (IS_ERR(handle)) {
				ext3_orphan_del(NULL, inode);
				goto err_out;
			}
			ext3_orphan_del(handle, inode);
			ext3_journal_stop(handle);
			goto err_out;
		}
	}

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		truncate_setsize(inode, attr->ia_size);
		ext3_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);

	if (ia_valid & ATTR_MODE)
		rc = posix_acl_chmod(inode, inode->i_mode);

err_out:
	ext3_std_error(inode->i_sb, error);
	if (!error)
		error = rc;
	return error;
}


/*
 * How many blocks doth make a writepage()?
 *
 * With N blocks per page, it may be:
 * N data blocks
 * 2 indirect block
 * 2 dindirect
 * 1 tindirect
 * N+5 bitmap blocks (from the above)
 * N+5 group descriptor summary blocks
 * 1 inode block
 * 1 superblock.
 * 2 * EXT3_SINGLEDATA_TRANS_BLOCKS for the quote files
 *
 * 3 * (N + 5) + 2 + 2 * EXT3_SINGLEDATA_TRANS_BLOCKS
 *
 * With ordered or writeback data it's the same, less the N data blocks.
 *
 * If the inode's direct blocks can hold an integral number of pages then a
 * page cannot straddle two indirect blocks, and we can only touch one indirect
 * and dindirect block, and the "5" above becomes "3".
 *
 * This still overestimates under most circumstances.  If we were to pass the
 * start and end offsets in here as well we could do block_to_path() on each
 * block and work out the exact number of indirects which are touched.  Pah.
 */

static int ext3_writepage_trans_blocks(struct inode *inode)
{
	int bpp = ext3_journal_blocks_per_page(inode);
	int indirects = (EXT3_NDIR_BLOCKS % bpp) ? 5 : 3;
	int ret;

	if (ext3_should_journal_data(inode))
		ret = 3 * (bpp + indirects) + 2;
	else
		ret = 2 * (bpp + indirects) + indirects + 2;

#ifdef CONFIG_QUOTA
	/* We know that structure was already allocated during dquot_initialize so
	 * we will be updating only the data blocks + inodes */
	ret += EXT3_MAXQUOTAS_TRANS_BLOCKS(inode->i_sb);
#endif

	return ret;
}

/*
 * The caller must have previously called ext3_reserve_inode_write().
 * Give this, we know that the caller already has write access to iloc->bh.
 */
int ext3_mark_iloc_dirty(handle_t *handle,
		struct inode *inode, struct ext3_iloc *iloc)
{
	int err = 0;

	/* the do_update_inode consumes one bh->b_count */
	get_bh(iloc->bh);

	/* ext3_do_update_inode() does journal_dirty_metadata */
	err = ext3_do_update_inode(handle, inode, iloc);
	put_bh(iloc->bh);
	return err;
}

/*
 * On success, We end up with an outstanding reference count against
 * iloc->bh.  This _must_ be cleaned up later.
 */

int
ext3_reserve_inode_write(handle_t *handle, struct inode *inode,
			 struct ext3_iloc *iloc)
{
	int err = 0;
	if (handle) {
		err = ext3_get_inode_loc(inode, iloc);
		if (!err) {
			BUFFER_TRACE(iloc->bh, "get_write_access");
			err = ext3_journal_get_write_access(handle, iloc->bh);
			if (err) {
				brelse(iloc->bh);
				iloc->bh = NULL;
			}
		}
	}
	ext3_std_error(inode->i_sb, err);
	return err;
}

/*
 * What we do here is to mark the in-core inode as clean with respect to inode
 * dirtiness (it may still be data-dirty).
 * This means that the in-core inode may be reaped by prune_icache
 * without having to perform any I/O.  This is a very good thing,
 * because *any* task may call prune_icache - even ones which
 * have a transaction open against a different journal.
 *
 * Is this cheating?  Not really.  Sure, we haven't written the
 * inode out, but prune_icache isn't a user-visible syncing function.
 * Whenever the user wants stuff synced (sys_sync, sys_msync, sys_fsync)
 * we start and wait on commits.
 */
int ext3_mark_inode_dirty(handle_t *handle, struct inode *inode)
{
	struct ext3_iloc iloc;
	int err;

	might_sleep();
	trace_ext3_mark_inode_dirty(inode, _RET_IP_);
	err = ext3_reserve_inode_write(handle, inode, &iloc);
	if (!err)
		err = ext3_mark_iloc_dirty(handle, inode, &iloc);
	return err;
}

/*
 * ext3_dirty_inode() is called from __mark_inode_dirty()
 *
 * We're really interested in the case where a file is being extended.
 * i_size has been changed by generic_commit_write() and we thus need
 * to include the updated inode in the current transaction.
 *
 * Also, dquot_alloc_space() will always dirty the inode when blocks
 * are allocated to the file.
 *
 * If the inode is marked synchronous, we don't honour that here - doing
 * so would cause a commit on atime updates, which we don't bother doing.
 * We handle synchronous inodes at the highest possible level.
 */
void ext3_dirty_inode(struct inode *inode, int flags)
{
	handle_t *current_handle = ext3_journal_current_handle();
	handle_t *handle;

	handle = ext3_journal_start(inode, 2);
	if (IS_ERR(handle))
		goto out;
	if (current_handle &&
		current_handle->h_transaction != handle->h_transaction) {
		/* This task has a transaction open against a different fs */
		printk(KERN_EMERG "%s: transactions do not match!\n",
		       __func__);
	} else {
		jbd_debug(5, "marking dirty.  outer handle=%p\n",
				current_handle);
		ext3_mark_inode_dirty(handle, inode);
	}
	ext3_journal_stop(handle);
out:
	return;
}

#if 0
/*
 * Bind an inode's backing buffer_head into this transaction, to prevent
 * it from being flushed to disk early.  Unlike
 * ext3_reserve_inode_write, this leaves behind no bh reference and
 * returns no iloc structure, so the caller needs to repeat the iloc
 * lookup to mark the inode dirty later.
 */
static int ext3_pin_inode(handle_t *handle, struct inode *inode)
{
	struct ext3_iloc iloc;

	int err = 0;
	if (handle) {
		err = ext3_get_inode_loc(inode, &iloc);
		if (!err) {
			BUFFER_TRACE(iloc.bh, "get_write_access");
			err = journal_get_write_access(handle, iloc.bh);
			if (!err)
				err = ext3_journal_dirty_metadata(handle,
								  iloc.bh);
			brelse(iloc.bh);
		}
	}
	ext3_std_error(inode->i_sb, err);
	return err;
}
#endif

int ext3_change_inode_journal_flag(struct inode *inode, int val)
{
	journal_t *journal;
	handle_t *handle;
	int err;

	/*
	 * We have to be very careful here: changing a data block's
	 * journaling status dynamically is dangerous.  If we write a
	 * data block to the journal, change the status and then delete
	 * that block, we risk forgetting to revoke the old log record
	 * from the journal and so a subsequent replay can corrupt data.
	 * So, first we make sure that the journal is empty and that
	 * nobody is changing anything.
	 */

	journal = EXT3_JOURNAL(inode);
	if (is_journal_aborted(journal))
		return -EROFS;

	journal_lock_updates(journal);
	journal_flush(journal);

	/*
	 * OK, there are no updates running now, and all cached data is
	 * synced to disk.  We are now in a completely consistent state
	 * which doesn't have anything in the journal, and we know that
	 * no filesystem updates are running, so it is safe to modify
	 * the inode's in-core data-journaling state flag now.
	 */

	if (val)
		EXT3_I(inode)->i_flags |= EXT3_JOURNAL_DATA_FL;
	else
		EXT3_I(inode)->i_flags &= ~EXT3_JOURNAL_DATA_FL;
	ext3_set_aops(inode);

	journal_unlock_updates(journal);

	/* Finally we can mark the inode as dirty. */

	handle = ext3_journal_start(inode, 1);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	err = ext3_mark_inode_dirty(handle, inode);
	handle->h_sync = 1;
	ext3_journal_stop(handle);
	ext3_std_error(inode->i_sb, err);

	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/inode.c */
/************************************************************/
/*
 * linux/fs/ext3/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/mount.h>
// #include <linux/compat.h>
#include <asm/uaccess.h>
// #include "ext3.h"
#include "../../inc/__fss.h"

long ext3_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct ext3_inode_info *ei = EXT3_I(inode);
	unsigned int flags;
	unsigned short rsv_window_size;

	ext3_debug ("cmd = %u, arg = %lu\n", cmd, arg);

	switch (cmd) {
	case EXT3_IOC_GETFLAGS:
		ext3_get_inode_flags(ei);
		flags = ei->i_flags & EXT3_FL_USER_VISIBLE;
		return put_user(flags, (int __user *) arg);
	case EXT3_IOC_SETFLAGS: {
		handle_t *handle = NULL;
		int err;
		struct ext3_iloc iloc;
		unsigned int oldflags;
		unsigned int jflag;

		if (!inode_owner_or_capable(inode))
			return -EACCES;

		if (get_user(flags, (int __user *) arg))
			return -EFAULT;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		flags = ext3_mask_flags(inode->i_mode, flags);

		mutex_lock(&inode->i_mutex);

		/* Is it quota file? Do not allow user to mess with it */
		err = -EPERM;
		if (IS_NOQUOTA(inode))
			goto flags_out;

		oldflags = ei->i_flags;

		/* The JOURNAL_DATA flag is modifiable only by root */
		jflag = flags & EXT3_JOURNAL_DATA_FL;

		/*
		 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
		 * the relevant capability.
		 *
		 * This test looks nicer. Thanks to Pauline Middelink
		 */
		if ((flags ^ oldflags) & (EXT3_APPEND_FL | EXT3_IMMUTABLE_FL)) {
			if (!capable(CAP_LINUX_IMMUTABLE))
				goto flags_out;
		}

		/*
		 * The JOURNAL_DATA flag can only be changed by
		 * the relevant capability.
		 */
		if ((jflag ^ oldflags) & (EXT3_JOURNAL_DATA_FL)) {
			if (!capable(CAP_SYS_RESOURCE))
				goto flags_out;
		}

		handle = ext3_journal_start(inode, 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto flags_out;
		}
		if (IS_SYNC(inode))
			handle->h_sync = 1;
		err = ext3_reserve_inode_write(handle, inode, &iloc);
		if (err)
			goto flags_err;

		flags = flags & EXT3_FL_USER_MODIFIABLE;
		flags |= oldflags & ~EXT3_FL_USER_MODIFIABLE;
		ei->i_flags = flags;

		ext3_set_inode_flags(inode);
		inode->i_ctime = CURRENT_TIME_SEC;

		err = ext3_mark_iloc_dirty(handle, inode, &iloc);
flags_err:
		ext3_journal_stop(handle);
		if (err)
			goto flags_out;

		if ((jflag ^ oldflags) & (EXT3_JOURNAL_DATA_FL))
			err = ext3_change_inode_journal_flag(inode, jflag);
flags_out:
		mutex_unlock(&inode->i_mutex);
		mnt_drop_write_file(filp);
		return err;
	}
	case EXT3_IOC_GETVERSION:
	case EXT3_IOC_GETVERSION_OLD:
		return put_user(inode->i_generation, (int __user *) arg);
	case EXT3_IOC_SETVERSION:
	case EXT3_IOC_SETVERSION_OLD: {
		handle_t *handle;
		struct ext3_iloc iloc;
		__u32 generation;
		int err;

		if (!inode_owner_or_capable(inode))
			return -EPERM;

		err = mnt_want_write_file(filp);
		if (err)
			return err;
		if (get_user(generation, (int __user *) arg)) {
			err = -EFAULT;
			goto setversion_out;
		}

		mutex_lock(&inode->i_mutex);
		handle = ext3_journal_start(inode, 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto unlock_out;
		}
		err = ext3_reserve_inode_write(handle, inode, &iloc);
		if (err == 0) {
			inode->i_ctime = CURRENT_TIME_SEC;
			inode->i_generation = generation;
			err = ext3_mark_iloc_dirty(handle, inode, &iloc);
		}
		ext3_journal_stop(handle);

unlock_out:
		mutex_unlock(&inode->i_mutex);
setversion_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case EXT3_IOC_GETRSVSZ:
		if (test_opt(inode->i_sb, RESERVATION)
			&& S_ISREG(inode->i_mode)
			&& ei->i_block_alloc_info) {
			rsv_window_size = ei->i_block_alloc_info->rsv_window_node.rsv_goal_size;
			return put_user(rsv_window_size, (int __user *)arg);
		}
		return -ENOTTY;
	case EXT3_IOC_SETRSVSZ: {
		int err;

		if (!test_opt(inode->i_sb, RESERVATION) ||!S_ISREG(inode->i_mode))
			return -ENOTTY;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		if (!inode_owner_or_capable(inode)) {
			err = -EACCES;
			goto setrsvsz_out;
		}

		if (get_user(rsv_window_size, (int __user *)arg)) {
			err = -EFAULT;
			goto setrsvsz_out;
		}

		if (rsv_window_size > EXT3_MAX_RESERVE_BLOCKS)
			rsv_window_size = EXT3_MAX_RESERVE_BLOCKS;

		/*
		 * need to allocate reservation structure for this inode
		 * before set the window size
		 */
		mutex_lock(&ei->truncate_mutex);
		if (!ei->i_block_alloc_info)
			ext3_init_block_alloc_info(inode);

		if (ei->i_block_alloc_info){
			struct ext3_reserve_window_node *rsv = &ei->i_block_alloc_info->rsv_window_node;
			rsv->rsv_goal_size = rsv_window_size;
		}
		mutex_unlock(&ei->truncate_mutex);
setrsvsz_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case EXT3_IOC_GROUP_EXTEND: {
		ext3_fsblk_t n_blocks_count;
		struct super_block *sb = inode->i_sb;
		int err, err2;

		if (!capable(CAP_SYS_RESOURCE))
			return -EPERM;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		if (get_user(n_blocks_count, (__u32 __user *)arg)) {
			err = -EFAULT;
			goto group_extend_out;
		}
		err = ext3_group_extend(sb, EXT3_SB(sb)->s_es, n_blocks_count);
		journal_lock_updates(EXT3_SB(sb)->s_journal);
		err2 = journal_flush(EXT3_SB(sb)->s_journal);
		journal_unlock_updates(EXT3_SB(sb)->s_journal);
		if (err == 0)
			err = err2;
group_extend_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case EXT3_IOC_GROUP_ADD: {
		struct ext3_new_group_data input;
		struct super_block *sb = inode->i_sb;
		int err, err2;

		if (!capable(CAP_SYS_RESOURCE))
			return -EPERM;

		err = mnt_want_write_file(filp);
		if (err)
			return err;

		if (copy_from_user(&input, (struct ext3_new_group_input __user *)arg,
				sizeof(input))) {
			err = -EFAULT;
			goto group_add_out;
		}

		err = ext3_group_add(sb, &input);
		journal_lock_updates(EXT3_SB(sb)->s_journal);
		err2 = journal_flush(EXT3_SB(sb)->s_journal);
		journal_unlock_updates(EXT3_SB(sb)->s_journal);
		if (err == 0)
			err = err2;
group_add_out:
		mnt_drop_write_file(filp);
		return err;
	}
	case FITRIM: {

		struct super_block *sb = inode->i_sb;
		struct fstrim_range range;
		int ret = 0;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&range, (struct fstrim_range __user *)arg,
				   sizeof(range)))
			return -EFAULT;

		ret = ext3_trim_fs(sb, &range);
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
long ext3_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case EXT3_IOC32_GETFLAGS:
		cmd = EXT3_IOC_GETFLAGS;
		break;
	case EXT3_IOC32_SETFLAGS:
		cmd = EXT3_IOC_SETFLAGS;
		break;
	case EXT3_IOC32_GETVERSION:
		cmd = EXT3_IOC_GETVERSION;
		break;
	case EXT3_IOC32_SETVERSION:
		cmd = EXT3_IOC_SETVERSION;
		break;
	case EXT3_IOC32_GROUP_EXTEND:
		cmd = EXT3_IOC_GROUP_EXTEND;
		break;
	case EXT3_IOC32_GETVERSION_OLD:
		cmd = EXT3_IOC_GETVERSION_OLD;
		break;
	case EXT3_IOC32_SETVERSION_OLD:
		cmd = EXT3_IOC_SETVERSION_OLD;
		break;
#ifdef CONFIG_JBD_DEBUG
	case EXT3_IOC32_WAIT_FOR_READONLY:
		cmd = EXT3_IOC_WAIT_FOR_READONLY;
		break;
#endif
	case EXT3_IOC32_GETRSVSZ:
		cmd = EXT3_IOC_GETRSVSZ;
		break;
	case EXT3_IOC32_SETRSVSZ:
		cmd = EXT3_IOC_SETRSVSZ;
		break;
	case EXT3_IOC_GROUP_ADD:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return ext3_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/ioctl.c */
/************************************************************/
/*
 *  linux/fs/ext3/namei.c
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
 *  Directory entry file type support and forward compatibility hooks
 *	for B-tree directories by Theodore Ts'o (tytso@mit.edu), 1998
 *  Hash Tree Directory indexing (c)
 *	Daniel Phillips, 2001
 *  Hash Tree Directory indexing porting
 *	Christopher Li, 2002
 *  Hash Tree Directory indexing cleanup
 *	Theodore Ts'o, 2002
 */

// #include <linux/quotaops.h>
// #include "ext3.h"
#include "namei.h"
// #include "xattr.h"
// #include "acl.h"
#include "../../inc/__fss.h"

/*
 * define how far ahead to read directories while searching them.
 */
#define NAMEI_RA_CHUNKS  2
#define NAMEI_RA_BLOCKS  4
#define NAMEI_RA_SIZE        (NAMEI_RA_CHUNKS * NAMEI_RA_BLOCKS)

static struct buffer_head *ext3_append(handle_t *handle,
					struct inode *inode,
					u32 *block, int *err)
{
	struct buffer_head *bh;

	*block = inode->i_size >> inode->i_sb->s_blocksize_bits;

	if ((bh = ext3_dir_bread(handle, inode, *block, 1, err))) {
		inode->i_size += inode->i_sb->s_blocksize;
		EXT3_I(inode)->i_disksize = inode->i_size;
		*err = ext3_journal_get_write_access(handle, bh);
		if (*err) {
			brelse(bh);
			bh = NULL;
		}
	}
	return bh;
}

#ifndef assert
#define assert(test) J_ASSERT(test)
#endif

#ifdef DX_DEBUG
#define dxtrace(command) command
#else
#define dxtrace(command)
#endif

struct fake_dirent
{
	__le32 inode;
	__le16 rec_len;
	u8 name_len;
	u8 file_type;
};

struct dx_countlimit
{
	__le16 limit;
	__le16 count;
};

struct dx_entry
{
	__le32 hash;
	__le32 block;
};

/*
 * dx_root_info is laid out so that if it should somehow get overlaid by a
 * dirent the two low bits of the hash version will be zero.  Therefore, the
 * hash version mod 4 should never be 0.  Sincerely, the paranoia department.
 */

struct dx_root
{
	struct fake_dirent dot;
	char dot_name[4];
	struct fake_dirent dotdot;
	char dotdot_name[4];
	struct dx_root_info
	{
		__le32 reserved_zero;
		u8 hash_version;
		u8 info_length; /* 8 */
		u8 indirect_levels;
		u8 unused_flags;
	}
	info;
	struct dx_entry	entries[0];
};

struct dx_node
{
	struct fake_dirent fake;
	struct dx_entry	entries[0];
};


struct dx_frame
{
	struct buffer_head *bh;
	struct dx_entry *entries;
	struct dx_entry *at;
};

struct dx_map_entry
{
	u32 hash;
	u16 offs;
	u16 size;
};

static inline unsigned dx_get_block (struct dx_entry *entry);
static void dx_set_block (struct dx_entry *entry, unsigned value);
static inline unsigned dx_get_hash (struct dx_entry *entry);
static void dx_set_hash (struct dx_entry *entry, unsigned value);
static unsigned dx_get_count (struct dx_entry *entries);
static unsigned dx_get_limit (struct dx_entry *entries);
static void dx_set_count (struct dx_entry *entries, unsigned value);
static void dx_set_limit (struct dx_entry *entries, unsigned value);
static unsigned dx_root_limit (struct inode *dir, unsigned infosize);
static unsigned dx_node_limit (struct inode *dir);
static struct dx_frame *dx_probe(struct qstr *entry,
				 struct inode *dir,
				 struct dx_hash_info *hinfo,
				 struct dx_frame *frame,
				 int *err);
static void dx_release (struct dx_frame *frames);
static int dx_make_map(struct ext3_dir_entry_2 *de, unsigned blocksize,
			struct dx_hash_info *hinfo, struct dx_map_entry map[]);
static void dx_sort_map(struct dx_map_entry *map, unsigned count);
static struct ext3_dir_entry_2 *dx_move_dirents (char *from, char *to,
		struct dx_map_entry *offsets, int count);
static struct ext3_dir_entry_2 *dx_pack_dirents(char *base, unsigned blocksize);
static void dx_insert_block (struct dx_frame *frame, u32 hash, u32 block);
static int ext3_htree_next_block(struct inode *dir, __u32 hash,
				 struct dx_frame *frame,
				 struct dx_frame *frames,
				 __u32 *start_hash);
static struct buffer_head * ext3_dx_find_entry(struct inode *dir,
			struct qstr *entry, struct ext3_dir_entry_2 **res_dir,
			int *err);
static int ext3_dx_add_entry(handle_t *handle, struct dentry *dentry,
			     struct inode *inode);

/*
 * p is at least 6 bytes before the end of page
 */
static inline struct ext3_dir_entry_2 *
ext3_next_entry(struct ext3_dir_entry_2 *p)
{
	return (struct ext3_dir_entry_2 *)((char *)p +
		ext3_rec_len_from_disk(p->rec_len));
}

/*
 * Future: use high four bits of block for coalesce-on-delete flags
 * Mask them off for now.
 */

static inline unsigned dx_get_block (struct dx_entry *entry)
{
	return le32_to_cpu(entry->block) & 0x00ffffff;
}

static inline void dx_set_block (struct dx_entry *entry, unsigned value)
{
	entry->block = cpu_to_le32(value);
}

static inline unsigned dx_get_hash (struct dx_entry *entry)
{
	return le32_to_cpu(entry->hash);
}

static inline void dx_set_hash (struct dx_entry *entry, unsigned value)
{
	entry->hash = cpu_to_le32(value);
}

static inline unsigned dx_get_count (struct dx_entry *entries)
{
	return le16_to_cpu(((struct dx_countlimit *) entries)->count);
}

static inline unsigned dx_get_limit (struct dx_entry *entries)
{
	return le16_to_cpu(((struct dx_countlimit *) entries)->limit);
}

static inline void dx_set_count (struct dx_entry *entries, unsigned value)
{
	((struct dx_countlimit *) entries)->count = cpu_to_le16(value);
}

static inline void dx_set_limit (struct dx_entry *entries, unsigned value)
{
	((struct dx_countlimit *) entries)->limit = cpu_to_le16(value);
}

static inline unsigned dx_root_limit (struct inode *dir, unsigned infosize)
{
	unsigned entry_space = dir->i_sb->s_blocksize - EXT3_DIR_REC_LEN(1) -
		EXT3_DIR_REC_LEN(2) - infosize;
	return entry_space / sizeof(struct dx_entry);
}

static inline unsigned dx_node_limit (struct inode *dir)
{
	unsigned entry_space = dir->i_sb->s_blocksize - EXT3_DIR_REC_LEN(0);
	return entry_space / sizeof(struct dx_entry);
}

/*
 * Debug
 */
#ifdef DX_DEBUG
static void dx_show_index (char * label, struct dx_entry *entries)
{
        int i, n = dx_get_count (entries);
        printk("%s index ", label);
        for (i = 0; i < n; i++)
        {
                printk("%x->%u ", i? dx_get_hash(entries + i): 0, dx_get_block(entries + i));
        }
        printk("\n");
}

struct stats
{
	unsigned names;
	unsigned space;
	unsigned bcount;
};

static struct stats dx_show_leaf(struct dx_hash_info *hinfo, struct ext3_dir_entry_2 *de,
				 int size, int show_names)
{
	unsigned names = 0, space = 0;
	char *base = (char *) de;
	struct dx_hash_info h = *hinfo;

	printk("names: ");
	while ((char *) de < base + size)
	{
		if (de->inode)
		{
			if (show_names)
			{
				int len = de->name_len;
				char *name = de->name;
				while (len--) printk("%c", *name++);
				ext3fs_dirhash(de->name, de->name_len, &h);
				printk(":%x.%u ", h.hash,
				       (unsigned) ((char *) de - base));
			}
			space += EXT3_DIR_REC_LEN(de->name_len);
			names++;
		}
		de = ext3_next_entry(de);
	}
	printk("(%i)\n", names);
	return (struct stats) { names, space, 1 };
}

struct stats dx_show_entries(struct dx_hash_info *hinfo, struct inode *dir,
			     struct dx_entry *entries, int levels)
{
	unsigned blocksize = dir->i_sb->s_blocksize;
	unsigned count = dx_get_count (entries), names = 0, space = 0, i;
	unsigned bcount = 0;
	struct buffer_head *bh;
	int err;
	printk("%i indexed blocks...\n", count);
	for (i = 0; i < count; i++, entries++)
	{
		u32 block = dx_get_block(entries), hash = i? dx_get_hash(entries): 0;
		u32 range = i < count - 1? (dx_get_hash(entries + 1) - hash): ~hash;
		struct stats stats;
		printk("%s%3u:%03u hash %8x/%8x ",levels?"":"   ", i, block, hash, range);
		if (!(bh = ext3_bread (NULL,dir, block, 0,&err))) continue;
		stats = levels?
		   dx_show_entries(hinfo, dir, ((struct dx_node *) bh->b_data)->entries, levels - 1):
		   dx_show_leaf(hinfo, (struct ext3_dir_entry_2 *) bh->b_data, blocksize, 0);
		names += stats.names;
		space += stats.space;
		bcount += stats.bcount;
		brelse (bh);
	}
	if (bcount)
		printk("%snames %u, fullness %u (%u%%)\n", levels?"":"   ",
			names, space/bcount,(space/bcount)*100/blocksize);
	return (struct stats) { names, space, bcount};
}
#endif /* DX_DEBUG */

/*
 * Probe for a directory leaf block to search.
 *
 * dx_probe can return ERR_BAD_DX_DIR, which means there was a format
 * error in the directory index, and the caller should fall back to
 * searching the directory normally.  The callers of dx_probe **MUST**
 * check for this error code, and make sure it never gets reflected
 * back to userspace.
 */
static struct dx_frame *
dx_probe(struct qstr *entry, struct inode *dir,
	 struct dx_hash_info *hinfo, struct dx_frame *frame_in, int *err)
{
	unsigned count, indirect;
	struct dx_entry *at, *entries, *p, *q, *m;
	struct dx_root *root;
	struct buffer_head *bh;
	struct dx_frame *frame = frame_in;
	u32 hash;

	frame->bh = NULL;
	if (!(bh = ext3_dir_bread(NULL, dir, 0, 0, err))) {
		*err = ERR_BAD_DX_DIR;
		goto fail;
	}
	root = (struct dx_root *) bh->b_data;
	if (root->info.hash_version != DX_HASH_TEA &&
	    root->info.hash_version != DX_HASH_HALF_MD4 &&
	    root->info.hash_version != DX_HASH_LEGACY) {
		ext3_warning(dir->i_sb, __func__,
			     "Unrecognised inode hash code %d",
			     root->info.hash_version);
		brelse(bh);
		*err = ERR_BAD_DX_DIR;
		goto fail;
	}
	hinfo->hash_version = root->info.hash_version;
	if (hinfo->hash_version <= DX_HASH_TEA)
		hinfo->hash_version += EXT3_SB(dir->i_sb)->s_hash_unsigned;
	hinfo->seed = EXT3_SB(dir->i_sb)->s_hash_seed;
	if (entry)
		ext3fs_dirhash(entry->name, entry->len, hinfo);
	hash = hinfo->hash;

	if (root->info.unused_flags & 1) {
		ext3_warning(dir->i_sb, __func__,
			     "Unimplemented inode hash flags: %#06x",
			     root->info.unused_flags);
		brelse(bh);
		*err = ERR_BAD_DX_DIR;
		goto fail;
	}

	if ((indirect = root->info.indirect_levels) > 1) {
		ext3_warning(dir->i_sb, __func__,
			     "Unimplemented inode hash depth: %#06x",
			     root->info.indirect_levels);
		brelse(bh);
		*err = ERR_BAD_DX_DIR;
		goto fail;
	}

	entries = (struct dx_entry *) (((char *)&root->info) +
				       root->info.info_length);

	if (dx_get_limit(entries) != dx_root_limit(dir,
						   root->info.info_length)) {
		ext3_warning(dir->i_sb, __func__,
			     "dx entry: limit != root limit");
		brelse(bh);
		*err = ERR_BAD_DX_DIR;
		goto fail;
	}

	dxtrace (printk("Look up %x", hash));
	while (1)
	{
		count = dx_get_count(entries);
		if (!count || count > dx_get_limit(entries)) {
			ext3_warning(dir->i_sb, __func__,
				     "dx entry: no count or count > limit");
			brelse(bh);
			*err = ERR_BAD_DX_DIR;
			goto fail2;
		}

		p = entries + 1;
		q = entries + count - 1;
		while (p <= q)
		{
			m = p + (q - p)/2;
			dxtrace(printk("."));
			if (dx_get_hash(m) > hash)
				q = m - 1;
			else
				p = m + 1;
		}

		if (0) // linear search cross check
		{
			unsigned n = count - 1;
			at = entries;
			while (n--)
			{
				dxtrace(printk(","));
				if (dx_get_hash(++at) > hash)
				{
					at--;
					break;
				}
			}
			assert (at == p - 1);
		}

		at = p - 1;
		dxtrace(printk(" %x->%u\n", at == entries? 0: dx_get_hash(at), dx_get_block(at)));
		frame->bh = bh;
		frame->entries = entries;
		frame->at = at;
		if (!indirect--) return frame;
		if (!(bh = ext3_dir_bread(NULL, dir, dx_get_block(at), 0, err))) {
			*err = ERR_BAD_DX_DIR;
			goto fail2;
		}
		at = entries = ((struct dx_node *) bh->b_data)->entries;
		if (dx_get_limit(entries) != dx_node_limit (dir)) {
			ext3_warning(dir->i_sb, __func__,
				     "dx entry: limit != node limit");
			brelse(bh);
			*err = ERR_BAD_DX_DIR;
			goto fail2;
		}
		frame++;
		frame->bh = NULL;
	}
fail2:
	while (frame >= frame_in) {
		brelse(frame->bh);
		frame--;
	}
fail:
	if (*err == ERR_BAD_DX_DIR)
		ext3_warning(dir->i_sb, __func__,
			     "Corrupt dir inode %ld, running e2fsck is "
			     "recommended.", dir->i_ino);
	return NULL;
}

static void dx_release (struct dx_frame *frames)
{
	if (frames[0].bh == NULL)
		return;

	if (((struct dx_root *) frames[0].bh->b_data)->info.indirect_levels)
		brelse(frames[1].bh);
	brelse(frames[0].bh);
}

/*
 * This function increments the frame pointer to search the next leaf
 * block, and reads in the necessary intervening nodes if the search
 * should be necessary.  Whether or not the search is necessary is
 * controlled by the hash parameter.  If the hash value is even, then
 * the search is only continued if the next block starts with that
 * hash value.  This is used if we are searching for a specific file.
 *
 * If the hash value is HASH_NB_ALWAYS, then always go to the next block.
 *
 * This function returns 1 if the caller should continue to search,
 * or 0 if it should not.  If there is an error reading one of the
 * index blocks, it will a negative error code.
 *
 * If start_hash is non-null, it will be filled in with the starting
 * hash of the next page.
 */
static int ext3_htree_next_block(struct inode *dir, __u32 hash,
				 struct dx_frame *frame,
				 struct dx_frame *frames,
				 __u32 *start_hash)
{
	struct dx_frame *p;
	struct buffer_head *bh;
	int err, num_frames = 0;
	__u32 bhash;

	p = frame;
	/*
	 * Find the next leaf page by incrementing the frame pointer.
	 * If we run out of entries in the interior node, loop around and
	 * increment pointer in the parent node.  When we break out of
	 * this loop, num_frames indicates the number of interior
	 * nodes need to be read.
	 */
	while (1) {
		if (++(p->at) < p->entries + dx_get_count(p->entries))
			break;
		if (p == frames)
			return 0;
		num_frames++;
		p--;
	}

	/*
	 * If the hash is 1, then continue only if the next page has a
	 * continuation hash of any value.  This is used for readdir
	 * handling.  Otherwise, check to see if the hash matches the
	 * desired contiuation hash.  If it doesn't, return since
	 * there's no point to read in the successive index pages.
	 */
	bhash = dx_get_hash(p->at);
	if (start_hash)
		*start_hash = bhash;
	if ((hash & 1) == 0) {
		if ((bhash & ~1) != hash)
			return 0;
	}
	/*
	 * If the hash is HASH_NB_ALWAYS, we always go to the next
	 * block so no check is necessary
	 */
	while (num_frames--) {
		if (!(bh = ext3_dir_bread(NULL, dir, dx_get_block(p->at),
					  0, &err)))
			return err; /* Failure */
		p++;
		brelse (p->bh);
		p->bh = bh;
		p->at = p->entries = ((struct dx_node *) bh->b_data)->entries;
	}
	return 1;
}


/*
 * This function fills a red-black tree with information from a
 * directory block.  It returns the number directory entries loaded
 * into the tree.  If there is an error it is returned in err.
 */
static int htree_dirblock_to_tree(struct file *dir_file,
				  struct inode *dir, int block,
				  struct dx_hash_info *hinfo,
				  __u32 start_hash, __u32 start_minor_hash)
{
	struct buffer_head *bh;
	struct ext3_dir_entry_2 *de, *top;
	int err = 0, count = 0;

	dxtrace(printk("In htree dirblock_to_tree: block %d\n", block));

	if (!(bh = ext3_dir_bread(NULL, dir, block, 0, &err)))
		return err;

	de = (struct ext3_dir_entry_2 *) bh->b_data;
	top = (struct ext3_dir_entry_2 *) ((char *) de +
					   dir->i_sb->s_blocksize -
					   EXT3_DIR_REC_LEN(0));
	for (; de < top; de = ext3_next_entry(de)) {
		if (!ext3_check_dir_entry("htree_dirblock_to_tree", dir, de, bh,
					(block<<EXT3_BLOCK_SIZE_BITS(dir->i_sb))
						+((char *)de - bh->b_data))) {
			/* silently ignore the rest of the block */
			break;
		}
		ext3fs_dirhash(de->name, de->name_len, hinfo);
		if ((hinfo->hash < start_hash) ||
		    ((hinfo->hash == start_hash) &&
		     (hinfo->minor_hash < start_minor_hash)))
			continue;
		if (de->inode == 0)
			continue;
		if ((err = ext3_htree_store_dirent(dir_file,
				   hinfo->hash, hinfo->minor_hash, de)) != 0) {
			brelse(bh);
			return err;
		}
		count++;
	}
	brelse(bh);
	return count;
}


/*
 * This function fills a red-black tree with information from a
 * directory.  We start scanning the directory in hash order, starting
 * at start_hash and start_minor_hash.
 *
 * This function returns the number of entries inserted into the tree,
 * or a negative error code.
 */
int ext3_htree_fill_tree(struct file *dir_file, __u32 start_hash,
			 __u32 start_minor_hash, __u32 *next_hash)
{
	struct dx_hash_info hinfo;
	struct ext3_dir_entry_2 *de;
	struct dx_frame frames[2], *frame;
	struct inode *dir;
	int block, err;
	int count = 0;
	int ret;
	__u32 hashval;

	dxtrace(printk("In htree_fill_tree, start hash: %x:%x\n", start_hash,
		       start_minor_hash));
	dir = file_inode(dir_file);
	if (!(EXT3_I(dir)->i_flags & EXT3_INDEX_FL)) {
		hinfo.hash_version = EXT3_SB(dir->i_sb)->s_def_hash_version;
		if (hinfo.hash_version <= DX_HASH_TEA)
			hinfo.hash_version +=
				EXT3_SB(dir->i_sb)->s_hash_unsigned;
		hinfo.seed = EXT3_SB(dir->i_sb)->s_hash_seed;
		count = htree_dirblock_to_tree(dir_file, dir, 0, &hinfo,
					       start_hash, start_minor_hash);
		*next_hash = ~0;
		return count;
	}
	hinfo.hash = start_hash;
	hinfo.minor_hash = 0;
	frame = dx_probe(NULL, file_inode(dir_file), &hinfo, frames, &err);
	if (!frame)
		return err;

	/* Add '.' and '..' from the htree header */
	if (!start_hash && !start_minor_hash) {
		de = (struct ext3_dir_entry_2 *) frames[0].bh->b_data;
		if ((err = ext3_htree_store_dirent(dir_file, 0, 0, de)) != 0)
			goto errout;
		count++;
	}
	if (start_hash < 2 || (start_hash ==2 && start_minor_hash==0)) {
		de = (struct ext3_dir_entry_2 *) frames[0].bh->b_data;
		de = ext3_next_entry(de);
		if ((err = ext3_htree_store_dirent(dir_file, 2, 0, de)) != 0)
			goto errout;
		count++;
	}

	while (1) {
		block = dx_get_block(frame->at);
		ret = htree_dirblock_to_tree(dir_file, dir, block, &hinfo,
					     start_hash, start_minor_hash);
		if (ret < 0) {
			err = ret;
			goto errout;
		}
		count += ret;
		hashval = ~0;
		ret = ext3_htree_next_block(dir, HASH_NB_ALWAYS,
					    frame, frames, &hashval);
		*next_hash = hashval;
		if (ret < 0) {
			err = ret;
			goto errout;
		}
		/*
		 * Stop if:  (a) there are no more entries, or
		 * (b) we have inserted at least one entry and the
		 * next hash value is not a continuation
		 */
		if ((ret == 0) ||
		    (count && ((hashval & 1) == 0)))
			break;
	}
	dx_release(frames);
	dxtrace(printk("Fill tree: returned %d entries, next hash: %x\n",
		       count, *next_hash));
	return count;
errout:
	dx_release(frames);
	return (err);
}


/*
 * Directory block splitting, compacting
 */

/*
 * Create map of hash values, offsets, and sizes, stored at end of block.
 * Returns number of entries mapped.
 */
static int dx_make_map(struct ext3_dir_entry_2 *de, unsigned blocksize,
		struct dx_hash_info *hinfo, struct dx_map_entry *map_tail)
{
	int count = 0;
	char *base = (char *) de;
	struct dx_hash_info h = *hinfo;

	while ((char *) de < base + blocksize)
	{
		if (de->name_len && de->inode) {
			ext3fs_dirhash(de->name, de->name_len, &h);
			map_tail--;
			map_tail->hash = h.hash;
			map_tail->offs = (u16) ((char *) de - base);
			map_tail->size = le16_to_cpu(de->rec_len);
			count++;
			cond_resched();
		}
		/* XXX: do we need to check rec_len == 0 case? -Chris */
		de = ext3_next_entry(de);
	}
	return count;
}

/* Sort map by hash value */
static void dx_sort_map (struct dx_map_entry *map, unsigned count)
{
        struct dx_map_entry *p, *q, *top = map + count - 1;
        int more;
        /* Combsort until bubble sort doesn't suck */
        while (count > 2)
	{
                count = count*10/13;
                if (count - 9 < 2) /* 9, 10 -> 11 */
                        count = 11;
                for (p = top, q = p - count; q >= map; p--, q--)
                        if (p->hash < q->hash)
                                swap(*p, *q);
        }
        /* Garden variety bubble sort */
        do {
                more = 0;
                q = top;
                while (q-- > map)
		{
                        if (q[1].hash >= q[0].hash)
				continue;
                        swap(*(q+1), *q);
                        more = 1;
		}
	} while(more);
}

static void dx_insert_block(struct dx_frame *frame, u32 hash, u32 block)
{
	struct dx_entry *entries = frame->entries;
	struct dx_entry *old = frame->at, *new = old + 1;
	int count = dx_get_count(entries);

	assert(count < dx_get_limit(entries));
	assert(old < entries + count);
	memmove(new + 1, new, (char *)(entries + count) - (char *)(new));
	dx_set_hash(new, hash);
	dx_set_block(new, block);
	dx_set_count(entries, count + 1);
}

static void ext3_update_dx_flag(struct inode *inode)
{
	if (!EXT3_HAS_COMPAT_FEATURE(inode->i_sb,
				     EXT3_FEATURE_COMPAT_DIR_INDEX))
		EXT3_I(inode)->i_flags &= ~EXT3_INDEX_FL;
}

/*
 * NOTE! unlike strncmp, ext3_match returns 1 for success, 0 for failure.
 *
 * `len <= EXT3_NAME_LEN' is guaranteed by caller.
 * `de != NULL' is guaranteed by caller.
 */
static inline int ext3_match (int len, const char * const name,
			      struct ext3_dir_entry_2 * de)
{
	if (len != de->name_len)
		return 0;
	if (!de->inode)
		return 0;
	return !memcmp(name, de->name, len);
}

/*
 * Returns 0 if not found, -1 on failure, and 1 on success
 */
static inline int search_dirblock(struct buffer_head * bh,
				  struct inode *dir,
				  struct qstr *child,
				  unsigned long offset,
				  struct ext3_dir_entry_2 ** res_dir)
{
	struct ext3_dir_entry_2 * de;
	char * dlimit;
	int de_len;
	const char *name = child->name;
	int namelen = child->len;

	de = (struct ext3_dir_entry_2 *) bh->b_data;
	dlimit = bh->b_data + dir->i_sb->s_blocksize;
	while ((char *) de < dlimit) {
		/* this code is executed quadratically often */
		/* do minimal checking `by hand' */

		if ((char *) de + namelen <= dlimit &&
		    ext3_match (namelen, name, de)) {
			/* found a match - just to be sure, do a full check */
			if (!ext3_check_dir_entry("ext3_find_entry",
						  dir, de, bh, offset))
				return -1;
			*res_dir = de;
			return 1;
		}
		/* prevent looping on a bad block */
		de_len = ext3_rec_len_from_disk(de->rec_len);
		if (de_len <= 0)
			return -1;
		offset += de_len;
		de = (struct ext3_dir_entry_2 *) ((char *) de + de_len);
	}
	return 0;
}


/*
 *	ext3_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the cache buffer in which the entry was found, and the entry
 * itself (as a parameter - res_dir). It does NOT read the inode of the
 * entry - you'll have to do that yourself if you want to.
 *
 * The returned buffer_head has ->b_count elevated.  The caller is expected
 * to brelse() it when appropriate.
 */
static struct buffer_head *ext3_find_entry(struct inode *dir,
					struct qstr *entry,
					struct ext3_dir_entry_2 **res_dir)
{
	struct super_block * sb;
	struct buffer_head * bh_use[NAMEI_RA_SIZE];
	struct buffer_head * bh, *ret = NULL;
	unsigned long start, block, b;
	const u8 *name = entry->name;
	int ra_max = 0;		/* Number of bh's in the readahead
				   buffer, bh_use[] */
	int ra_ptr = 0;		/* Current index into readahead
				   buffer */
	int num = 0;
	int nblocks, i, err;
	int namelen;

	*res_dir = NULL;
	sb = dir->i_sb;
	namelen = entry->len;
	if (namelen > EXT3_NAME_LEN)
		return NULL;
	if ((namelen <= 2) && (name[0] == '.') &&
	    (name[1] == '.' || name[1] == 0)) {
		/*
		 * "." or ".." will only be in the first block
		 * NFS may look up ".."; "." should be handled by the VFS
		 */
		block = start = 0;
		nblocks = 1;
		goto restart;
	}
	if (is_dx(dir)) {
		bh = ext3_dx_find_entry(dir, entry, res_dir, &err);
		/*
		 * On success, or if the error was file not found,
		 * return.  Otherwise, fall back to doing a search the
		 * old fashioned way.
		 */
		if (bh || (err != ERR_BAD_DX_DIR))
			return bh;
		dxtrace(printk("ext3_find_entry: dx failed, falling back\n"));
	}
	nblocks = dir->i_size >> EXT3_BLOCK_SIZE_BITS(sb);
	start = EXT3_I(dir)->i_dir_start_lookup;
	if (start >= nblocks)
		start = 0;
	block = start;
restart:
	do {
		/*
		 * We deal with the read-ahead logic here.
		 */
		if (ra_ptr >= ra_max) {
			/* Refill the readahead buffer */
			ra_ptr = 0;
			b = block;
			for (ra_max = 0; ra_max < NAMEI_RA_SIZE; ra_max++) {
				/*
				 * Terminate if we reach the end of the
				 * directory and must wrap, or if our
				 * search has finished at this block.
				 */
				if (b >= nblocks || (num && block == start)) {
					bh_use[ra_max] = NULL;
					break;
				}
				num++;
				bh = ext3_getblk(NULL, dir, b++, 0, &err);
				bh_use[ra_max] = bh;
				if (bh && !bh_uptodate_or_lock(bh)) {
					get_bh(bh);
					bh->b_end_io = end_buffer_read_sync;
					submit_bh(READ | REQ_META | REQ_PRIO,
						  bh);
				}
			}
		}
		if ((bh = bh_use[ra_ptr++]) == NULL)
			goto next;
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh)) {
			/* read error, skip block & hope for the best */
			ext3_error(sb, __func__, "reading directory #%lu "
				   "offset %lu", dir->i_ino, block);
			brelse(bh);
			goto next;
		}
		i = search_dirblock(bh, dir, entry,
			    block << EXT3_BLOCK_SIZE_BITS(sb), res_dir);
		if (i == 1) {
			EXT3_I(dir)->i_dir_start_lookup = block;
			ret = bh;
			goto cleanup_and_exit;
		} else {
			brelse(bh);
			if (i < 0)
				goto cleanup_and_exit;
		}
	next:
		if (++block >= nblocks)
			block = 0;
	} while (block != start);

	/*
	 * If the directory has grown while we were searching, then
	 * search the last part of the directory before giving up.
	 */
	block = nblocks;
	nblocks = dir->i_size >> EXT3_BLOCK_SIZE_BITS(sb);
	if (block < nblocks) {
		start = 0;
		goto restart;
	}

cleanup_and_exit:
	/* Clean up the read-ahead blocks */
	for (; ra_ptr < ra_max; ra_ptr++)
		brelse (bh_use[ra_ptr]);
	return ret;
}

static struct buffer_head * ext3_dx_find_entry(struct inode *dir,
			struct qstr *entry, struct ext3_dir_entry_2 **res_dir,
			int *err)
{
	struct super_block *sb = dir->i_sb;
	struct dx_hash_info	hinfo;
	struct dx_frame frames[2], *frame;
	struct buffer_head *bh;
	unsigned long block;
	int retval;

	if (!(frame = dx_probe(entry, dir, &hinfo, frames, err)))
		return NULL;
	do {
		block = dx_get_block(frame->at);
		if (!(bh = ext3_dir_bread (NULL, dir, block, 0, err)))
			goto errout;

		retval = search_dirblock(bh, dir, entry,
					 block << EXT3_BLOCK_SIZE_BITS(sb),
					 res_dir);
		if (retval == 1) {
			dx_release(frames);
			return bh;
		}
		brelse(bh);
		if (retval == -1) {
			*err = ERR_BAD_DX_DIR;
			goto errout;
		}

		/* Check to see if we should continue to search */
		retval = ext3_htree_next_block(dir, hinfo.hash, frame,
					       frames, NULL);
		if (retval < 0) {
			ext3_warning(sb, __func__,
			     "error reading index page in directory #%lu",
			     dir->i_ino);
			*err = retval;
			goto errout;
		}
	} while (retval == 1);

	*err = -ENOENT;
errout:
	dxtrace(printk("%s not found\n", entry->name));
	dx_release (frames);
	return NULL;
}

static struct dentry *ext3_lookup(struct inode * dir, struct dentry *dentry, unsigned int flags)
{
	struct inode * inode;
	struct ext3_dir_entry_2 * de;
	struct buffer_head * bh;

	if (dentry->d_name.len > EXT3_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	bh = ext3_find_entry(dir, &dentry->d_name, &de);
	inode = NULL;
	if (bh) {
		unsigned long ino = le32_to_cpu(de->inode);
		brelse (bh);
		if (!ext3_valid_inum(dir->i_sb, ino)) {
			ext3_error(dir->i_sb, "ext3_lookup",
				   "bad inode number: %lu", ino);
			return ERR_PTR(-EIO);
		}
		inode = ext3_iget(dir->i_sb, ino);
		if (inode == ERR_PTR(-ESTALE)) {
			ext3_error(dir->i_sb, __func__,
					"deleted inode referenced: %lu",
					ino);
			return ERR_PTR(-EIO);
		}
	}
	return d_splice_alias(inode, dentry);
}


struct dentry *ext3_get_parent(struct dentry *child)
{
	unsigned long ino;
	struct qstr dotdot = QSTR_INIT("..", 2);
	struct ext3_dir_entry_2 * de;
	struct buffer_head *bh;

	bh = ext3_find_entry(child->d_inode, &dotdot, &de);
	if (!bh)
		return ERR_PTR(-ENOENT);
	ino = le32_to_cpu(de->inode);
	brelse(bh);

	if (!ext3_valid_inum(child->d_inode->i_sb, ino)) {
		ext3_error(child->d_inode->i_sb, "ext3_get_parent",
			   "bad inode number: %lu", ino);
		return ERR_PTR(-EIO);
	}

	return d_obtain_alias(ext3_iget(child->d_inode->i_sb, ino));
}

#define S_SHIFT 12
static unsigned char ext3_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= EXT3_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= EXT3_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= EXT3_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= EXT3_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= EXT3_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= EXT3_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= EXT3_FT_SYMLINK,
};

static inline void ext3_set_de_type(struct super_block *sb,
				struct ext3_dir_entry_2 *de,
				umode_t mode) {
	if (EXT3_HAS_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_FILETYPE))
		de->file_type = ext3_type_by_mode[(mode & S_IFMT)>>S_SHIFT];
}

/*
 * Move count entries from end of map between two memory locations.
 * Returns pointer to last entry moved.
 */
static struct ext3_dir_entry_2 *
dx_move_dirents(char *from, char *to, struct dx_map_entry *map, int count)
{
	unsigned rec_len = 0;

	while (count--) {
		struct ext3_dir_entry_2 *de = (struct ext3_dir_entry_2 *) (from + map->offs);
		rec_len = EXT3_DIR_REC_LEN(de->name_len);
		memcpy (to, de, rec_len);
		((struct ext3_dir_entry_2 *) to)->rec_len =
				ext3_rec_len_to_disk(rec_len);
		de->inode = 0;
		map++;
		to += rec_len;
	}
	return (struct ext3_dir_entry_2 *) (to - rec_len);
}

/*
 * Compact each dir entry in the range to the minimal rec_len.
 * Returns pointer to last entry in range.
 */
static struct ext3_dir_entry_2 *dx_pack_dirents(char *base, unsigned blocksize)
{
	struct ext3_dir_entry_2 *next, *to, *prev;
	struct ext3_dir_entry_2 *de = (struct ext3_dir_entry_2 *)base;
	unsigned rec_len = 0;

	prev = to = de;
	while ((char *)de < base + blocksize) {
		next = ext3_next_entry(de);
		if (de->inode && de->name_len) {
			rec_len = EXT3_DIR_REC_LEN(de->name_len);
			if (de > to)
				memmove(to, de, rec_len);
			to->rec_len = ext3_rec_len_to_disk(rec_len);
			prev = to;
			to = (struct ext3_dir_entry_2 *) (((char *) to) + rec_len);
		}
		de = next;
	}
	return prev;
}

/*
 * Split a full leaf block to make room for a new dir entry.
 * Allocate a new block, and move entries so that they are approx. equally full.
 * Returns pointer to de in block into which the new entry will be inserted.
 */
static struct ext3_dir_entry_2 *do_split(handle_t *handle, struct inode *dir,
			struct buffer_head **bh,struct dx_frame *frame,
			struct dx_hash_info *hinfo, int *error)
{
	unsigned blocksize = dir->i_sb->s_blocksize;
	unsigned count, continued;
	struct buffer_head *bh2;
	u32 newblock;
	u32 hash2;
	struct dx_map_entry *map;
	char *data1 = (*bh)->b_data, *data2;
	unsigned split, move, size;
	struct ext3_dir_entry_2 *de = NULL, *de2;
	int	err = 0, i;

	bh2 = ext3_append (handle, dir, &newblock, &err);
	if (!(bh2)) {
		brelse(*bh);
		*bh = NULL;
		goto errout;
	}

	BUFFER_TRACE(*bh, "get_write_access");
	err = ext3_journal_get_write_access(handle, *bh);
	if (err)
		goto journal_error;

	BUFFER_TRACE(frame->bh, "get_write_access");
	err = ext3_journal_get_write_access(handle, frame->bh);
	if (err)
		goto journal_error;

	data2 = bh2->b_data;

	/* create map in the end of data2 block */
	map = (struct dx_map_entry *) (data2 + blocksize);
	count = dx_make_map ((struct ext3_dir_entry_2 *) data1,
			     blocksize, hinfo, map);
	map -= count;
	dx_sort_map (map, count);
	/* Split the existing block in the middle, size-wise */
	size = 0;
	move = 0;
	for (i = count-1; i >= 0; i--) {
		/* is more than half of this entry in 2nd half of the block? */
		if (size + map[i].size/2 > blocksize/2)
			break;
		size += map[i].size;
		move++;
	}
	/* map index at which we will split */
	split = count - move;
	hash2 = map[split].hash;
	continued = hash2 == map[split - 1].hash;
	dxtrace(printk("Split block %i at %x, %i/%i\n",
		dx_get_block(frame->at), hash2, split, count-split));

	/* Fancy dance to stay within two buffers */
	de2 = dx_move_dirents(data1, data2, map + split, count - split);
	de = dx_pack_dirents(data1,blocksize);
	de->rec_len = ext3_rec_len_to_disk(data1 + blocksize - (char *) de);
	de2->rec_len = ext3_rec_len_to_disk(data2 + blocksize - (char *) de2);
	dxtrace(dx_show_leaf (hinfo, (struct ext3_dir_entry_2 *) data1, blocksize, 1));
	dxtrace(dx_show_leaf (hinfo, (struct ext3_dir_entry_2 *) data2, blocksize, 1));

	/* Which block gets the new entry? */
	if (hinfo->hash >= hash2)
	{
		swap(*bh, bh2);
		de = de2;
	}
	dx_insert_block (frame, hash2 + continued, newblock);
	err = ext3_journal_dirty_metadata (handle, bh2);
	if (err)
		goto journal_error;
	err = ext3_journal_dirty_metadata (handle, frame->bh);
	if (err)
		goto journal_error;
	brelse (bh2);
	dxtrace(dx_show_index ("frame", frame->entries));
	return de;

journal_error:
	brelse(*bh);
	brelse(bh2);
	*bh = NULL;
	ext3_std_error(dir->i_sb, err);
errout:
	*error = err;
	return NULL;
}


/*
 * Add a new entry into a directory (leaf) block.  If de is non-NULL,
 * it points to a directory entry which is guaranteed to be large
 * enough for new directory entry.  If de is NULL, then
 * add_dirent_to_buf will attempt search the directory block for
 * space.  It will return -ENOSPC if no space is available, and -EIO
 * and -EEXIST if directory entry already exists.
 *
 * NOTE!  bh is NOT released in the case where ENOSPC is returned.  In
 * all other cases bh is released.
 */
static int add_dirent_to_buf(handle_t *handle, struct dentry *dentry,
			     struct inode *inode, struct ext3_dir_entry_2 *de,
			     struct buffer_head * bh)
{
	struct inode	*dir = dentry->d_parent->d_inode;
	const char	*name = dentry->d_name.name;
	int		namelen = dentry->d_name.len;
	unsigned long	offset = 0;
	unsigned short	reclen;
	int		nlen, rlen, err;
	char		*top;

	reclen = EXT3_DIR_REC_LEN(namelen);
	if (!de) {
		de = (struct ext3_dir_entry_2 *)bh->b_data;
		top = bh->b_data + dir->i_sb->s_blocksize - reclen;
		while ((char *) de <= top) {
			if (!ext3_check_dir_entry("ext3_add_entry", dir, de,
						  bh, offset)) {
				brelse (bh);
				return -EIO;
			}
			if (ext3_match (namelen, name, de)) {
				brelse (bh);
				return -EEXIST;
			}
			nlen = EXT3_DIR_REC_LEN(de->name_len);
			rlen = ext3_rec_len_from_disk(de->rec_len);
			if ((de->inode? rlen - nlen: rlen) >= reclen)
				break;
			de = (struct ext3_dir_entry_2 *)((char *)de + rlen);
			offset += rlen;
		}
		if ((char *) de > top)
			return -ENOSPC;
	}
	BUFFER_TRACE(bh, "get_write_access");
	err = ext3_journal_get_write_access(handle, bh);
	if (err) {
		ext3_std_error(dir->i_sb, err);
		brelse(bh);
		return err;
	}

	/* By now the buffer is marked for journaling */
	nlen = EXT3_DIR_REC_LEN(de->name_len);
	rlen = ext3_rec_len_from_disk(de->rec_len);
	if (de->inode) {
		struct ext3_dir_entry_2 *de1 = (struct ext3_dir_entry_2 *)((char *)de + nlen);
		de1->rec_len = ext3_rec_len_to_disk(rlen - nlen);
		de->rec_len = ext3_rec_len_to_disk(nlen);
		de = de1;
	}
	de->file_type = EXT3_FT_UNKNOWN;
	if (inode) {
		de->inode = cpu_to_le32(inode->i_ino);
		ext3_set_de_type(dir->i_sb, de, inode->i_mode);
	} else
		de->inode = 0;
	de->name_len = namelen;
	memcpy (de->name, name, namelen);
	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 *
	 * XXX similarly, too many callers depend on
	 * ext3_new_inode() setting the times, but error
	 * recovery deletes the inode, so the worst that can
	 * happen is that the times are slightly out of date
	 * and/or different from the directory change time.
	 */
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	ext3_update_dx_flag(dir);
	dir->i_version++;
	ext3_mark_inode_dirty(handle, dir);
	BUFFER_TRACE(bh, "call ext3_journal_dirty_metadata");
	err = ext3_journal_dirty_metadata(handle, bh);
	if (err)
		ext3_std_error(dir->i_sb, err);
	brelse(bh);
	return 0;
}

/*
 * This converts a one block unindexed directory to a 3 block indexed
 * directory, and adds the dentry to the indexed directory.
 */
static int make_indexed_dir(handle_t *handle, struct dentry *dentry,
			    struct inode *inode, struct buffer_head *bh)
{
	struct inode	*dir = dentry->d_parent->d_inode;
	const char	*name = dentry->d_name.name;
	int		namelen = dentry->d_name.len;
	struct buffer_head *bh2;
	struct dx_root	*root;
	struct dx_frame	frames[2], *frame;
	struct dx_entry *entries;
	struct ext3_dir_entry_2	*de, *de2;
	char		*data1, *top;
	unsigned	len;
	int		retval;
	unsigned	blocksize;
	struct dx_hash_info hinfo;
	u32		block;
	struct fake_dirent *fde;

	blocksize =  dir->i_sb->s_blocksize;
	dxtrace(printk(KERN_DEBUG "Creating index: inode %lu\n", dir->i_ino));
	retval = ext3_journal_get_write_access(handle, bh);
	if (retval) {
		ext3_std_error(dir->i_sb, retval);
		brelse(bh);
		return retval;
	}
	root = (struct dx_root *) bh->b_data;

	/* The 0th block becomes the root, move the dirents out */
	fde = &root->dotdot;
	de = (struct ext3_dir_entry_2 *)((char *)fde +
			ext3_rec_len_from_disk(fde->rec_len));
	if ((char *) de >= (((char *) root) + blocksize)) {
		ext3_error(dir->i_sb, __func__,
			   "invalid rec_len for '..' in inode %lu",
			   dir->i_ino);
		brelse(bh);
		return -EIO;
	}
	len = ((char *) root) + blocksize - (char *) de;

	bh2 = ext3_append (handle, dir, &block, &retval);
	if (!(bh2)) {
		brelse(bh);
		return retval;
	}
	EXT3_I(dir)->i_flags |= EXT3_INDEX_FL;
	data1 = bh2->b_data;

	memcpy (data1, de, len);
	de = (struct ext3_dir_entry_2 *) data1;
	top = data1 + len;
	while ((char *)(de2 = ext3_next_entry(de)) < top)
		de = de2;
	de->rec_len = ext3_rec_len_to_disk(data1 + blocksize - (char *) de);
	/* Initialize the root; the dot dirents already exist */
	de = (struct ext3_dir_entry_2 *) (&root->dotdot);
	de->rec_len = ext3_rec_len_to_disk(blocksize - EXT3_DIR_REC_LEN(2));
	memset (&root->info, 0, sizeof(root->info));
	root->info.info_length = sizeof(root->info);
	root->info.hash_version = EXT3_SB(dir->i_sb)->s_def_hash_version;
	entries = root->entries;
	dx_set_block (entries, 1);
	dx_set_count (entries, 1);
	dx_set_limit (entries, dx_root_limit(dir, sizeof(root->info)));

	/* Initialize as for dx_probe */
	hinfo.hash_version = root->info.hash_version;
	if (hinfo.hash_version <= DX_HASH_TEA)
		hinfo.hash_version += EXT3_SB(dir->i_sb)->s_hash_unsigned;
	hinfo.seed = EXT3_SB(dir->i_sb)->s_hash_seed;
	ext3fs_dirhash(name, namelen, &hinfo);
	frame = frames;
	frame->entries = entries;
	frame->at = entries;
	frame->bh = bh;
	bh = bh2;
	/*
	 * Mark buffers dirty here so that if do_split() fails we write a
	 * consistent set of buffers to disk.
	 */
	ext3_journal_dirty_metadata(handle, frame->bh);
	ext3_journal_dirty_metadata(handle, bh);
	de = do_split(handle,dir, &bh, frame, &hinfo, &retval);
	if (!de) {
		ext3_mark_inode_dirty(handle, dir);
		dx_release(frames);
		return retval;
	}
	dx_release(frames);

	return add_dirent_to_buf(handle, dentry, inode, de, bh);
}

/*
 *	ext3_add_entry()
 *
 * adds a file entry to the specified directory, using the same
 * semantics as ext3_find_entry(). It returns NULL if it failed.
 *
 * NOTE!! The inode part of 'de' is left at 0 - which means you
 * may not sleep between calling this and putting something into
 * the entry, as someone else might have used it while you slept.
 */
static int ext3_add_entry (handle_t *handle, struct dentry *dentry,
	struct inode *inode)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct buffer_head * bh;
	struct ext3_dir_entry_2 *de;
	struct super_block * sb;
	int	retval;
	int	dx_fallback=0;
	unsigned blocksize;
	u32 block, blocks;

	sb = dir->i_sb;
	blocksize = sb->s_blocksize;
	if (!dentry->d_name.len)
		return -EINVAL;
	if (is_dx(dir)) {
		retval = ext3_dx_add_entry(handle, dentry, inode);
		if (!retval || (retval != ERR_BAD_DX_DIR))
			return retval;
		EXT3_I(dir)->i_flags &= ~EXT3_INDEX_FL;
		dx_fallback++;
		ext3_mark_inode_dirty(handle, dir);
	}
	blocks = dir->i_size >> sb->s_blocksize_bits;
	for (block = 0; block < blocks; block++) {
		if (!(bh = ext3_dir_bread(handle, dir, block, 0, &retval)))
			return retval;

		retval = add_dirent_to_buf(handle, dentry, inode, NULL, bh);
		if (retval != -ENOSPC)
			return retval;

		if (blocks == 1 && !dx_fallback &&
		    EXT3_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_DIR_INDEX))
			return make_indexed_dir(handle, dentry, inode, bh);
		brelse(bh);
	}
	bh = ext3_append(handle, dir, &block, &retval);
	if (!bh)
		return retval;
	de = (struct ext3_dir_entry_2 *) bh->b_data;
	de->inode = 0;
	de->rec_len = ext3_rec_len_to_disk(blocksize);
	return add_dirent_to_buf(handle, dentry, inode, de, bh);
}

/*
 * Returns 0 for success, or a negative error value
 */
static int ext3_dx_add_entry(handle_t *handle, struct dentry *dentry,
			     struct inode *inode)
{
	struct dx_frame frames[2], *frame;
	struct dx_entry *entries, *at;
	struct dx_hash_info hinfo;
	struct buffer_head * bh;
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block * sb = dir->i_sb;
	struct ext3_dir_entry_2 *de;
	int err;

	frame = dx_probe(&dentry->d_name, dir, &hinfo, frames, &err);
	if (!frame)
		return err;
	entries = frame->entries;
	at = frame->at;

	if (!(bh = ext3_dir_bread(handle, dir, dx_get_block(frame->at), 0, &err)))
		goto cleanup;

	BUFFER_TRACE(bh, "get_write_access");
	err = ext3_journal_get_write_access(handle, bh);
	if (err)
		goto journal_error;

	err = add_dirent_to_buf(handle, dentry, inode, NULL, bh);
	if (err != -ENOSPC) {
		bh = NULL;
		goto cleanup;
	}

	/* Block full, should compress but for now just split */
	dxtrace(printk("using %u of %u node entries\n",
		       dx_get_count(entries), dx_get_limit(entries)));
	/* Need to split index? */
	if (dx_get_count(entries) == dx_get_limit(entries)) {
		u32 newblock;
		unsigned icount = dx_get_count(entries);
		int levels = frame - frames;
		struct dx_entry *entries2;
		struct dx_node *node2;
		struct buffer_head *bh2;

		if (levels && (dx_get_count(frames->entries) ==
			       dx_get_limit(frames->entries))) {
			ext3_warning(sb, __func__,
				     "Directory index full!");
			err = -ENOSPC;
			goto cleanup;
		}
		bh2 = ext3_append (handle, dir, &newblock, &err);
		if (!(bh2))
			goto cleanup;
		node2 = (struct dx_node *)(bh2->b_data);
		entries2 = node2->entries;
		memset(&node2->fake, 0, sizeof(struct fake_dirent));
		node2->fake.rec_len = ext3_rec_len_to_disk(sb->s_blocksize);
		BUFFER_TRACE(frame->bh, "get_write_access");
		err = ext3_journal_get_write_access(handle, frame->bh);
		if (err)
			goto journal_error;
		if (levels) {
			unsigned icount1 = icount/2, icount2 = icount - icount1;
			unsigned hash2 = dx_get_hash(entries + icount1);
			dxtrace(printk("Split index %i/%i\n", icount1, icount2));

			BUFFER_TRACE(frame->bh, "get_write_access"); /* index root */
			err = ext3_journal_get_write_access(handle,
							     frames[0].bh);
			if (err)
				goto journal_error;

			memcpy ((char *) entries2, (char *) (entries + icount1),
				icount2 * sizeof(struct dx_entry));
			dx_set_count (entries, icount1);
			dx_set_count (entries2, icount2);
			dx_set_limit (entries2, dx_node_limit(dir));

			/* Which index block gets the new entry? */
			if (at - entries >= icount1) {
				frame->at = at = at - entries - icount1 + entries2;
				frame->entries = entries = entries2;
				swap(frame->bh, bh2);
			}
			dx_insert_block (frames + 0, hash2, newblock);
			dxtrace(dx_show_index ("node", frames[1].entries));
			dxtrace(dx_show_index ("node",
			       ((struct dx_node *) bh2->b_data)->entries));
			err = ext3_journal_dirty_metadata(handle, bh2);
			if (err)
				goto journal_error;
			brelse (bh2);
		} else {
			dxtrace(printk("Creating second level index...\n"));
			memcpy((char *) entries2, (char *) entries,
			       icount * sizeof(struct dx_entry));
			dx_set_limit(entries2, dx_node_limit(dir));

			/* Set up root */
			dx_set_count(entries, 1);
			dx_set_block(entries + 0, newblock);
			((struct dx_root *) frames[0].bh->b_data)->info.indirect_levels = 1;

			/* Add new access path frame */
			frame = frames + 1;
			frame->at = at = at - entries + entries2;
			frame->entries = entries = entries2;
			frame->bh = bh2;
			err = ext3_journal_get_write_access(handle,
							     frame->bh);
			if (err)
				goto journal_error;
		}
		err = ext3_journal_dirty_metadata(handle, frames[0].bh);
		if (err)
			goto journal_error;
	}
	de = do_split(handle, dir, &bh, frame, &hinfo, &err);
	if (!de)
		goto cleanup;
	err = add_dirent_to_buf(handle, dentry, inode, de, bh);
	bh = NULL;
	goto cleanup;

journal_error:
	ext3_std_error(dir->i_sb, err);
cleanup:
	if (bh)
		brelse(bh);
	dx_release(frames);
	return err;
}

/*
 * ext3_delete_entry deletes a directory entry by merging it with the
 * previous entry
 */
static int ext3_delete_entry (handle_t *handle,
			      struct inode * dir,
			      struct ext3_dir_entry_2 * de_del,
			      struct buffer_head * bh)
{
	struct ext3_dir_entry_2 * de, * pde;
	int i;

	i = 0;
	pde = NULL;
	de = (struct ext3_dir_entry_2 *) bh->b_data;
	while (i < bh->b_size) {
		if (!ext3_check_dir_entry("ext3_delete_entry", dir, de, bh, i))
			return -EIO;
		if (de == de_del)  {
			int err;

			BUFFER_TRACE(bh, "get_write_access");
			err = ext3_journal_get_write_access(handle, bh);
			if (err)
				goto journal_error;

			if (pde)
				pde->rec_len = ext3_rec_len_to_disk(
					ext3_rec_len_from_disk(pde->rec_len) +
					ext3_rec_len_from_disk(de->rec_len));
			else
				de->inode = 0;
			dir->i_version++;
			BUFFER_TRACE(bh, "call ext3_journal_dirty_metadata");
			err = ext3_journal_dirty_metadata(handle, bh);
			if (err) {
journal_error:
				ext3_std_error(dir->i_sb, err);
				return err;
			}
			return 0;
		}
		i += ext3_rec_len_from_disk(de->rec_len);
		pde = de;
		de = ext3_next_entry(de);
	}
	return -ENOENT;
}

static int ext3_add_nondir(handle_t *handle,
		struct dentry *dentry, struct inode *inode)
{
	int err = ext3_add_entry(handle, dentry, inode);
	if (!err) {
		ext3_mark_inode_dirty(handle, inode);
		unlock_new_inode(inode);
		d_instantiate(dentry, inode);
		return 0;
	}
	drop_nlink(inode);
	unlock_new_inode(inode);
	iput(inode);
	return err;
}

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int ext3_create (struct inode * dir, struct dentry * dentry, umode_t mode,
		bool excl)
{
	handle_t *handle;
	struct inode * inode;
	int err, retries = 0;

	dquot_initialize(dir);

retry:
	handle = ext3_journal_start(dir, EXT3_DATA_TRANS_BLOCKS(dir->i_sb) +
					EXT3_INDEX_EXTRA_TRANS_BLOCKS + 3 +
					EXT3_MAXQUOTAS_INIT_BLOCKS(dir->i_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (IS_DIRSYNC(dir))
		handle->h_sync = 1;

	inode = ext3_new_inode (handle, dir, &dentry->d_name, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		inode->i_op = &ext3_file_inode_operations;
		inode->i_fop = &ext3_file_operations;
		ext3_set_aops(inode);
		err = ext3_add_nondir(handle, dentry, inode);
	}
	ext3_journal_stop(handle);
	if (err == -ENOSPC && ext3_should_retry_alloc(dir->i_sb, &retries))
		goto retry;
	return err;
}

static int ext3_mknod (struct inode * dir, struct dentry *dentry,
			umode_t mode, dev_t rdev)
{
	handle_t *handle;
	struct inode *inode;
	int err, retries = 0;

	if (!new_valid_dev(rdev))
		return -EINVAL;

	dquot_initialize(dir);

retry:
	handle = ext3_journal_start(dir, EXT3_DATA_TRANS_BLOCKS(dir->i_sb) +
					EXT3_INDEX_EXTRA_TRANS_BLOCKS + 3 +
					EXT3_MAXQUOTAS_INIT_BLOCKS(dir->i_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (IS_DIRSYNC(dir))
		handle->h_sync = 1;

	inode = ext3_new_inode (handle, dir, &dentry->d_name, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		init_special_inode(inode, inode->i_mode, rdev);
#ifdef CONFIG_EXT3_FS_XATTR
		inode->i_op = &ext3_special_inode_operations;
#endif
		err = ext3_add_nondir(handle, dentry, inode);
	}
	ext3_journal_stop(handle);
	if (err == -ENOSPC && ext3_should_retry_alloc(dir->i_sb, &retries))
		goto retry;
	return err;
}

static int ext3_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	handle_t *handle;
	struct inode *inode;
	int err, retries = 0;

	dquot_initialize(dir);

retry:
	handle = ext3_journal_start(dir, EXT3_MAXQUOTAS_INIT_BLOCKS(dir->i_sb) +
			  4 + EXT3_XATTR_TRANS_BLOCKS);

	if (IS_ERR(handle))
		return PTR_ERR(handle);

	inode = ext3_new_inode (handle, dir, NULL, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		inode->i_op = &ext3_file_inode_operations;
		inode->i_fop = &ext3_file_operations;
		ext3_set_aops(inode);
		d_tmpfile(dentry, inode);
		err = ext3_orphan_add(handle, inode);
		if (err)
			goto err_unlock_inode;
		mark_inode_dirty(inode);
		unlock_new_inode(inode);
	}
	ext3_journal_stop(handle);
	if (err == -ENOSPC && ext3_should_retry_alloc(dir->i_sb, &retries))
		goto retry;
	return err;
err_unlock_inode:
	ext3_journal_stop(handle);
	unlock_new_inode(inode);
	return err;
}

static int ext3_mkdir(struct inode * dir, struct dentry * dentry, umode_t mode)
{
	handle_t *handle;
	struct inode * inode;
	struct buffer_head * dir_block = NULL;
	struct ext3_dir_entry_2 * de;
	int err, retries = 0;

	if (dir->i_nlink >= EXT3_LINK_MAX)
		return -EMLINK;

	dquot_initialize(dir);

retry:
	handle = ext3_journal_start(dir, EXT3_DATA_TRANS_BLOCKS(dir->i_sb) +
					EXT3_INDEX_EXTRA_TRANS_BLOCKS + 3 +
					EXT3_MAXQUOTAS_INIT_BLOCKS(dir->i_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (IS_DIRSYNC(dir))
		handle->h_sync = 1;

	inode = ext3_new_inode (handle, dir, &dentry->d_name, S_IFDIR | mode);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_stop;

	inode->i_op = &ext3_dir_inode_operations;
	inode->i_fop = &ext3_dir_operations;
	inode->i_size = EXT3_I(inode)->i_disksize = inode->i_sb->s_blocksize;
	if (!(dir_block = ext3_dir_bread(handle, inode, 0, 1, &err)))
		goto out_clear_inode;

	BUFFER_TRACE(dir_block, "get_write_access");
	err = ext3_journal_get_write_access(handle, dir_block);
	if (err)
		goto out_clear_inode;

	de = (struct ext3_dir_entry_2 *) dir_block->b_data;
	de->inode = cpu_to_le32(inode->i_ino);
	de->name_len = 1;
	de->rec_len = ext3_rec_len_to_disk(EXT3_DIR_REC_LEN(de->name_len));
	strcpy (de->name, ".");
	ext3_set_de_type(dir->i_sb, de, S_IFDIR);
	de = ext3_next_entry(de);
	de->inode = cpu_to_le32(dir->i_ino);
	de->rec_len = ext3_rec_len_to_disk(inode->i_sb->s_blocksize -
					EXT3_DIR_REC_LEN(1));
	de->name_len = 2;
	strcpy (de->name, "..");
	ext3_set_de_type(dir->i_sb, de, S_IFDIR);
	set_nlink(inode, 2);
	BUFFER_TRACE(dir_block, "call ext3_journal_dirty_metadata");
	err = ext3_journal_dirty_metadata(handle, dir_block);
	if (err)
		goto out_clear_inode;

	err = ext3_mark_inode_dirty(handle, inode);
	if (!err)
		err = ext3_add_entry (handle, dentry, inode);

	if (err) {
out_clear_inode:
		clear_nlink(inode);
		unlock_new_inode(inode);
		ext3_mark_inode_dirty(handle, inode);
		iput (inode);
		goto out_stop;
	}
	inc_nlink(dir);
	ext3_update_dx_flag(dir);
	err = ext3_mark_inode_dirty(handle, dir);
	if (err)
		goto out_clear_inode;

	unlock_new_inode(inode);
	d_instantiate(dentry, inode);
out_stop:
	brelse(dir_block);
	ext3_journal_stop(handle);
	if (err == -ENOSPC && ext3_should_retry_alloc(dir->i_sb, &retries))
		goto retry;
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
static int empty_dir (struct inode * inode)
{
	unsigned long offset;
	struct buffer_head * bh;
	struct ext3_dir_entry_2 * de, * de1;
	struct super_block * sb;
	int err = 0;

	sb = inode->i_sb;
	if (inode->i_size < EXT3_DIR_REC_LEN(1) + EXT3_DIR_REC_LEN(2) ||
	    !(bh = ext3_dir_bread(NULL, inode, 0, 0, &err))) {
		if (err)
			ext3_error(inode->i_sb, __func__,
				   "error %d reading directory #%lu offset 0",
				   err, inode->i_ino);
		else
			ext3_warning(inode->i_sb, __func__,
				     "bad directory (dir #%lu) - no data block",
				     inode->i_ino);
		return 1;
	}
	de = (struct ext3_dir_entry_2 *) bh->b_data;
	de1 = ext3_next_entry(de);
	if (le32_to_cpu(de->inode) != inode->i_ino ||
			!le32_to_cpu(de1->inode) ||
			strcmp (".", de->name) ||
			strcmp ("..", de1->name)) {
		ext3_warning (inode->i_sb, "empty_dir",
			      "bad directory (dir #%lu) - no `.' or `..'",
			      inode->i_ino);
		brelse (bh);
		return 1;
	}
	offset = ext3_rec_len_from_disk(de->rec_len) +
			ext3_rec_len_from_disk(de1->rec_len);
	de = ext3_next_entry(de1);
	while (offset < inode->i_size ) {
		if (!bh ||
			(void *) de >= (void *) (bh->b_data+sb->s_blocksize)) {
			err = 0;
			brelse (bh);
			if (!(bh = ext3_dir_bread (NULL, inode,
				offset >> EXT3_BLOCK_SIZE_BITS(sb), 0, &err))) {
				if (err)
					ext3_error(sb, __func__,
						   "error %d reading directory"
						   " #%lu offset %lu",
						   err, inode->i_ino, offset);
				offset += sb->s_blocksize;
				continue;
			}
			de = (struct ext3_dir_entry_2 *) bh->b_data;
		}
		if (!ext3_check_dir_entry("empty_dir", inode, de, bh, offset)) {
			de = (struct ext3_dir_entry_2 *)(bh->b_data +
							 sb->s_blocksize);
			offset = (offset | (sb->s_blocksize - 1)) + 1;
			continue;
		}
		if (le32_to_cpu(de->inode)) {
			brelse (bh);
			return 0;
		}
		offset += ext3_rec_len_from_disk(de->rec_len);
		de = ext3_next_entry(de);
	}
	brelse (bh);
	return 1;
}

/* ext3_orphan_add() links an unlinked or truncated inode into a list of
 * such inodes, starting at the superblock, in case we crash before the
 * file is closed/deleted, or in case the inode truncate spans multiple
 * transactions and the last transaction is not recovered after a crash.
 *
 * At filesystem recovery time, we walk this list deleting unlinked
 * inodes and truncating linked inodes in ext3_orphan_cleanup().
 */
int ext3_orphan_add(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct ext3_iloc iloc;
	int err = 0, rc;

	mutex_lock(&EXT3_SB(sb)->s_orphan_lock);
	if (!list_empty(&EXT3_I(inode)->i_orphan))
		goto out_unlock;

	/* Orphan handling is only valid for files with data blocks
	 * being truncated, or files being unlinked. */

	/* @@@ FIXME: Observation from aviro:
	 * I think I can trigger J_ASSERT in ext3_orphan_add().  We block
	 * here (on s_orphan_lock), so race with ext3_link() which might bump
	 * ->i_nlink. For, say it, character device. Not a regular file,
	 * not a directory, not a symlink and ->i_nlink > 0.
	 *
	 * tytso, 4/25/2009: I'm not sure how that could happen;
	 * shouldn't the fs core protect us from these sort of
	 * unlink()/link() races?
	 */
	J_ASSERT ((S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
		S_ISLNK(inode->i_mode)) || inode->i_nlink == 0);

	BUFFER_TRACE(EXT3_SB(sb)->s_sbh, "get_write_access");
	err = ext3_journal_get_write_access(handle, EXT3_SB(sb)->s_sbh);
	if (err)
		goto out_unlock;

	err = ext3_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto out_unlock;

	/* Insert this inode at the head of the on-disk orphan list... */
	NEXT_ORPHAN(inode) = le32_to_cpu(EXT3_SB(sb)->s_es->s_last_orphan);
	EXT3_SB(sb)->s_es->s_last_orphan = cpu_to_le32(inode->i_ino);
	err = ext3_journal_dirty_metadata(handle, EXT3_SB(sb)->s_sbh);
	rc = ext3_mark_iloc_dirty(handle, inode, &iloc);
	if (!err)
		err = rc;

	/* Only add to the head of the in-memory list if all the
	 * previous operations succeeded.  If the orphan_add is going to
	 * fail (possibly taking the journal offline), we can't risk
	 * leaving the inode on the orphan list: stray orphan-list
	 * entries can cause panics at unmount time.
	 *
	 * This is safe: on error we're going to ignore the orphan list
	 * anyway on the next recovery. */
	if (!err)
		list_add(&EXT3_I(inode)->i_orphan, &EXT3_SB(sb)->s_orphan);

	jbd_debug(4, "superblock will point to %lu\n", inode->i_ino);
	jbd_debug(4, "orphan inode %lu will point to %d\n",
			inode->i_ino, NEXT_ORPHAN(inode));
out_unlock:
	mutex_unlock(&EXT3_SB(sb)->s_orphan_lock);
	ext3_std_error(inode->i_sb, err);
	return err;
}

/*
 * ext3_orphan_del() removes an unlinked or truncated inode from the list
 * of such inodes stored on disk, because it is finally being cleaned up.
 */
int ext3_orphan_del(handle_t *handle, struct inode *inode)
{
	struct list_head *prev;
	struct ext3_inode_info *ei = EXT3_I(inode);
	struct ext3_sb_info *sbi;
	unsigned long ino_next;
	struct ext3_iloc iloc;
	int err = 0;

	mutex_lock(&EXT3_SB(inode->i_sb)->s_orphan_lock);
	if (list_empty(&ei->i_orphan))
		goto out;

	ino_next = NEXT_ORPHAN(inode);
	prev = ei->i_orphan.prev;
	sbi = EXT3_SB(inode->i_sb);

	jbd_debug(4, "remove inode %lu from orphan list\n", inode->i_ino);

	list_del_init(&ei->i_orphan);

	/* If we're on an error path, we may not have a valid
	 * transaction handle with which to update the orphan list on
	 * disk, but we still need to remove the inode from the linked
	 * list in memory. */
	if (!handle)
		goto out;

	err = ext3_reserve_inode_write(handle, inode, &iloc);
	if (err)
		goto out_err;

	if (prev == &sbi->s_orphan) {
		jbd_debug(4, "superblock will point to %lu\n", ino_next);
		BUFFER_TRACE(sbi->s_sbh, "get_write_access");
		err = ext3_journal_get_write_access(handle, sbi->s_sbh);
		if (err)
			goto out_brelse;
		sbi->s_es->s_last_orphan = cpu_to_le32(ino_next);
		err = ext3_journal_dirty_metadata(handle, sbi->s_sbh);
	} else {
		struct ext3_iloc iloc2;
		struct inode *i_prev =
			&list_entry(prev, struct ext3_inode_info, i_orphan)->vfs_inode;

		jbd_debug(4, "orphan inode %lu will point to %lu\n",
			  i_prev->i_ino, ino_next);
		err = ext3_reserve_inode_write(handle, i_prev, &iloc2);
		if (err)
			goto out_brelse;
		NEXT_ORPHAN(i_prev) = ino_next;
		err = ext3_mark_iloc_dirty(handle, i_prev, &iloc2);
	}
	if (err)
		goto out_brelse;
	NEXT_ORPHAN(inode) = 0;
	err = ext3_mark_iloc_dirty(handle, inode, &iloc);

out_err:
	ext3_std_error(inode->i_sb, err);
out:
	mutex_unlock(&EXT3_SB(inode->i_sb)->s_orphan_lock);
	return err;

out_brelse:
	brelse(iloc.bh);
	goto out_err;
}

static int ext3_rmdir (struct inode * dir, struct dentry *dentry)
{
	int retval;
	struct inode * inode;
	struct buffer_head * bh;
	struct ext3_dir_entry_2 * de;
	handle_t *handle;

	/* Initialize quotas before so that eventual writes go in
	 * separate transaction */
	dquot_initialize(dir);
	dquot_initialize(dentry->d_inode);

	handle = ext3_journal_start(dir, EXT3_DELETE_TRANS_BLOCKS(dir->i_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	retval = -ENOENT;
	bh = ext3_find_entry(dir, &dentry->d_name, &de);
	if (!bh)
		goto end_rmdir;

	if (IS_DIRSYNC(dir))
		handle->h_sync = 1;

	inode = dentry->d_inode;

	retval = -EIO;
	if (le32_to_cpu(de->inode) != inode->i_ino)
		goto end_rmdir;

	retval = -ENOTEMPTY;
	if (!empty_dir (inode))
		goto end_rmdir;

	retval = ext3_delete_entry(handle, dir, de, bh);
	if (retval)
		goto end_rmdir;
	if (inode->i_nlink != 2)
		ext3_warning (inode->i_sb, "ext3_rmdir",
			      "empty directory has nlink!=2 (%d)",
			      inode->i_nlink);
	inode->i_version++;
	clear_nlink(inode);
	/* There's no need to set i_disksize: the fact that i_nlink is
	 * zero will ensure that the right thing happens during any
	 * recovery. */
	inode->i_size = 0;
	ext3_orphan_add(handle, inode);
	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME_SEC;
	ext3_mark_inode_dirty(handle, inode);
	drop_nlink(dir);
	ext3_update_dx_flag(dir);
	ext3_mark_inode_dirty(handle, dir);

end_rmdir:
	ext3_journal_stop(handle);
	brelse (bh);
	return retval;
}

static int ext3_unlink(struct inode * dir, struct dentry *dentry)
{
	int retval;
	struct inode * inode;
	struct buffer_head * bh;
	struct ext3_dir_entry_2 * de;
	handle_t *handle;

	trace_ext3_unlink_enter(dir, dentry);
	/* Initialize quotas before so that eventual writes go
	 * in separate transaction */
	dquot_initialize(dir);
	dquot_initialize(dentry->d_inode);

	handle = ext3_journal_start(dir, EXT3_DELETE_TRANS_BLOCKS(dir->i_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (IS_DIRSYNC(dir))
		handle->h_sync = 1;

	retval = -ENOENT;
	bh = ext3_find_entry(dir, &dentry->d_name, &de);
	if (!bh)
		goto end_unlink;

	inode = dentry->d_inode;

	retval = -EIO;
	if (le32_to_cpu(de->inode) != inode->i_ino)
		goto end_unlink;

	if (!inode->i_nlink) {
		ext3_warning (inode->i_sb, "ext3_unlink",
			      "Deleting nonexistent file (%lu), %d",
			      inode->i_ino, inode->i_nlink);
		set_nlink(inode, 1);
	}
	retval = ext3_delete_entry(handle, dir, de, bh);
	if (retval)
		goto end_unlink;
	dir->i_ctime = dir->i_mtime = CURRENT_TIME_SEC;
	ext3_update_dx_flag(dir);
	ext3_mark_inode_dirty(handle, dir);
	drop_nlink(inode);
	if (!inode->i_nlink)
		ext3_orphan_add(handle, inode);
	inode->i_ctime = dir->i_ctime;
	ext3_mark_inode_dirty(handle, inode);
	retval = 0;

end_unlink:
	ext3_journal_stop(handle);
	brelse (bh);
	trace_ext3_unlink_exit(dentry, retval);
	return retval;
}

static int ext3_symlink (struct inode * dir,
		struct dentry *dentry, const char * symname)
{
	handle_t *handle;
	struct inode * inode;
	int l, err, retries = 0;
	int credits;

	l = strlen(symname)+1;
	if (l > dir->i_sb->s_blocksize)
		return -ENAMETOOLONG;

	dquot_initialize(dir);

	if (l > EXT3_N_BLOCKS * 4) {
		/*
		 * For non-fast symlinks, we just allocate inode and put it on
		 * orphan list in the first transaction => we need bitmap,
		 * group descriptor, sb, inode block, quota blocks, and
		 * possibly selinux xattr blocks.
		 */
		credits = 4 + EXT3_MAXQUOTAS_INIT_BLOCKS(dir->i_sb) +
			  EXT3_XATTR_TRANS_BLOCKS;
	} else {
		/*
		 * Fast symlink. We have to add entry to directory
		 * (EXT3_DATA_TRANS_BLOCKS + EXT3_INDEX_EXTRA_TRANS_BLOCKS),
		 * allocate new inode (bitmap, group descriptor, inode block,
		 * quota blocks, sb is already counted in previous macros).
		 */
		credits = EXT3_DATA_TRANS_BLOCKS(dir->i_sb) +
			  EXT3_INDEX_EXTRA_TRANS_BLOCKS + 3 +
			  EXT3_MAXQUOTAS_INIT_BLOCKS(dir->i_sb);
	}
retry:
	handle = ext3_journal_start(dir, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (IS_DIRSYNC(dir))
		handle->h_sync = 1;

	inode = ext3_new_inode (handle, dir, &dentry->d_name, S_IFLNK|S_IRWXUGO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_stop;

	if (l > EXT3_N_BLOCKS * 4) {
		inode->i_op = &ext3_symlink_inode_operations;
		ext3_set_aops(inode);
		/*
		 * We cannot call page_symlink() with transaction started
		 * because it calls into ext3_write_begin() which acquires page
		 * lock which ranks below transaction start (and it can also
		 * wait for journal commit if we are running out of space). So
		 * we have to stop transaction now and restart it when symlink
		 * contents is written. 
		 *
		 * To keep fs consistent in case of crash, we have to put inode
		 * to orphan list in the mean time.
		 */
		drop_nlink(inode);
		err = ext3_orphan_add(handle, inode);
		ext3_journal_stop(handle);
		if (err)
			goto err_drop_inode;
		err = __page_symlink(inode, symname, l, 1);
		if (err)
			goto err_drop_inode;
		/*
		 * Now inode is being linked into dir (EXT3_DATA_TRANS_BLOCKS
		 * + EXT3_INDEX_EXTRA_TRANS_BLOCKS), inode is also modified
		 */
		handle = ext3_journal_start(dir,
				EXT3_DATA_TRANS_BLOCKS(dir->i_sb) +
				EXT3_INDEX_EXTRA_TRANS_BLOCKS + 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto err_drop_inode;
		}
		set_nlink(inode, 1);
		err = ext3_orphan_del(handle, inode);
		if (err) {
			ext3_journal_stop(handle);
			drop_nlink(inode);
			goto err_drop_inode;
		}
	} else {
		inode->i_op = &ext3_fast_symlink_inode_operations;
		memcpy((char*)&EXT3_I(inode)->i_data,symname,l);
		inode->i_size = l-1;
	}
	EXT3_I(inode)->i_disksize = inode->i_size;
	err = ext3_add_nondir(handle, dentry, inode);
out_stop:
	ext3_journal_stop(handle);
	if (err == -ENOSPC && ext3_should_retry_alloc(dir->i_sb, &retries))
		goto retry;
	return err;
err_drop_inode:
	unlock_new_inode(inode);
	iput(inode);
	return err;
}

static int ext3_link (struct dentry * old_dentry,
		struct inode * dir, struct dentry *dentry)
{
	handle_t *handle;
	struct inode *inode = old_dentry->d_inode;
	int err, retries = 0;

	if (inode->i_nlink >= EXT3_LINK_MAX)
		return -EMLINK;

	dquot_initialize(dir);

retry:
	handle = ext3_journal_start(dir, EXT3_DATA_TRANS_BLOCKS(dir->i_sb) +
					EXT3_INDEX_EXTRA_TRANS_BLOCKS + 1);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (IS_DIRSYNC(dir))
		handle->h_sync = 1;

	inode->i_ctime = CURRENT_TIME_SEC;
	inc_nlink(inode);
	ihold(inode);

	err = ext3_add_entry(handle, dentry, inode);
	if (!err) {
		ext3_mark_inode_dirty(handle, inode);
		/* this can happen only for tmpfile being
		 * linked the first time
		 */
		if (inode->i_nlink == 1)
			ext3_orphan_del(handle, inode);
		d_instantiate(dentry, inode);
	} else {
		drop_nlink(inode);
		iput(inode);
	}
	ext3_journal_stop(handle);
	if (err == -ENOSPC && ext3_should_retry_alloc(dir->i_sb, &retries))
		goto retry;
	return err;
}

#define PARENT_INO(buffer) \
	(ext3_next_entry((struct ext3_dir_entry_2 *)(buffer))->inode)

/*
 * Anybody can rename anything with this: the permission checks are left to the
 * higher-level routines.
 */
static int ext3_rename (struct inode * old_dir, struct dentry *old_dentry,
			   struct inode * new_dir,struct dentry *new_dentry)
{
	handle_t *handle;
	struct inode * old_inode, * new_inode;
	struct buffer_head * old_bh, * new_bh, * dir_bh;
	struct ext3_dir_entry_2 * old_de, * new_de;
	int retval, flush_file = 0;

	dquot_initialize(old_dir);
	dquot_initialize(new_dir);

	old_bh = new_bh = dir_bh = NULL;

	/* Initialize quotas before so that eventual writes go
	 * in separate transaction */
	if (new_dentry->d_inode)
		dquot_initialize(new_dentry->d_inode);
	handle = ext3_journal_start(old_dir, 2 *
					EXT3_DATA_TRANS_BLOCKS(old_dir->i_sb) +
					EXT3_INDEX_EXTRA_TRANS_BLOCKS + 2);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (IS_DIRSYNC(old_dir) || IS_DIRSYNC(new_dir))
		handle->h_sync = 1;

	old_bh = ext3_find_entry(old_dir, &old_dentry->d_name, &old_de);
	/*
	 *  Check for inode number is _not_ due to possible IO errors.
	 *  We might rmdir the source, keep it as pwd of some process
	 *  and merrily kill the link to whatever was created under the
	 *  same name. Goodbye sticky bit ;-<
	 */
	old_inode = old_dentry->d_inode;
	retval = -ENOENT;
	if (!old_bh || le32_to_cpu(old_de->inode) != old_inode->i_ino)
		goto end_rename;

	new_inode = new_dentry->d_inode;
	new_bh = ext3_find_entry(new_dir, &new_dentry->d_name, &new_de);
	if (new_bh) {
		if (!new_inode) {
			brelse (new_bh);
			new_bh = NULL;
		}
	}
	if (S_ISDIR(old_inode->i_mode)) {
		if (new_inode) {
			retval = -ENOTEMPTY;
			if (!empty_dir (new_inode))
				goto end_rename;
		}
		retval = -EIO;
		dir_bh = ext3_dir_bread(handle, old_inode, 0, 0, &retval);
		if (!dir_bh)
			goto end_rename;
		if (le32_to_cpu(PARENT_INO(dir_bh->b_data)) != old_dir->i_ino)
			goto end_rename;
		retval = -EMLINK;
		if (!new_inode && new_dir!=old_dir &&
				new_dir->i_nlink >= EXT3_LINK_MAX)
			goto end_rename;
	}
	if (!new_bh) {
		retval = ext3_add_entry (handle, new_dentry, old_inode);
		if (retval)
			goto end_rename;
	} else {
		BUFFER_TRACE(new_bh, "get write access");
		retval = ext3_journal_get_write_access(handle, new_bh);
		if (retval)
			goto journal_error;
		new_de->inode = cpu_to_le32(old_inode->i_ino);
		if (EXT3_HAS_INCOMPAT_FEATURE(new_dir->i_sb,
					      EXT3_FEATURE_INCOMPAT_FILETYPE))
			new_de->file_type = old_de->file_type;
		new_dir->i_version++;
		new_dir->i_ctime = new_dir->i_mtime = CURRENT_TIME_SEC;
		ext3_mark_inode_dirty(handle, new_dir);
		BUFFER_TRACE(new_bh, "call ext3_journal_dirty_metadata");
		retval = ext3_journal_dirty_metadata(handle, new_bh);
		if (retval)
			goto journal_error;
		brelse(new_bh);
		new_bh = NULL;
	}

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
	 * rename.
	 */
	old_inode->i_ctime = CURRENT_TIME_SEC;
	ext3_mark_inode_dirty(handle, old_inode);

	/*
	 * ok, that's it
	 */
	if (le32_to_cpu(old_de->inode) != old_inode->i_ino ||
	    old_de->name_len != old_dentry->d_name.len ||
	    strncmp(old_de->name, old_dentry->d_name.name, old_de->name_len) ||
	    (retval = ext3_delete_entry(handle, old_dir,
					old_de, old_bh)) == -ENOENT) {
		/* old_de could have moved from under us during htree split, so
		 * make sure that we are deleting the right entry.  We might
		 * also be pointing to a stale entry in the unused part of
		 * old_bh so just checking inum and the name isn't enough. */
		struct buffer_head *old_bh2;
		struct ext3_dir_entry_2 *old_de2;

		old_bh2 = ext3_find_entry(old_dir, &old_dentry->d_name,
					  &old_de2);
		if (old_bh2) {
			retval = ext3_delete_entry(handle, old_dir,
						   old_de2, old_bh2);
			brelse(old_bh2);
		}
	}
	if (retval) {
		ext3_warning(old_dir->i_sb, "ext3_rename",
				"Deleting old file (%lu), %d, error=%d",
				old_dir->i_ino, old_dir->i_nlink, retval);
	}

	if (new_inode) {
		drop_nlink(new_inode);
		new_inode->i_ctime = CURRENT_TIME_SEC;
	}
	old_dir->i_ctime = old_dir->i_mtime = CURRENT_TIME_SEC;
	ext3_update_dx_flag(old_dir);
	if (dir_bh) {
		BUFFER_TRACE(dir_bh, "get_write_access");
		retval = ext3_journal_get_write_access(handle, dir_bh);
		if (retval)
			goto journal_error;
		PARENT_INO(dir_bh->b_data) = cpu_to_le32(new_dir->i_ino);
		BUFFER_TRACE(dir_bh, "call ext3_journal_dirty_metadata");
		retval = ext3_journal_dirty_metadata(handle, dir_bh);
		if (retval) {
journal_error:
			ext3_std_error(new_dir->i_sb, retval);
			goto end_rename;
		}
		drop_nlink(old_dir);
		if (new_inode) {
			drop_nlink(new_inode);
		} else {
			inc_nlink(new_dir);
			ext3_update_dx_flag(new_dir);
			ext3_mark_inode_dirty(handle, new_dir);
		}
	}
	ext3_mark_inode_dirty(handle, old_dir);
	if (new_inode) {
		ext3_mark_inode_dirty(handle, new_inode);
		if (!new_inode->i_nlink)
			ext3_orphan_add(handle, new_inode);
		if (ext3_should_writeback_data(new_inode))
			flush_file = 1;
	}
	retval = 0;

end_rename:
	brelse (dir_bh);
	brelse (old_bh);
	brelse (new_bh);
	ext3_journal_stop(handle);
	if (retval == 0 && flush_file)
		filemap_flush(old_inode->i_mapping);
	return retval;
}

/*
 * directories can handle most operations...
 */
const struct inode_operations ext3_dir_inode_operations = {
	.create		= ext3_create,
	.lookup		= ext3_lookup,
	.link		= ext3_link,
	.unlink		= ext3_unlink,
	.symlink	= ext3_symlink,
	.mkdir		= ext3_mkdir,
	.rmdir		= ext3_rmdir,
	.mknod		= ext3_mknod,
	.tmpfile	= ext3_tmpfile,
	.rename		= ext3_rename,
	.setattr	= ext3_setattr,
#ifdef CONFIG_EXT3_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext3_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.get_acl	= ext3_get_acl,
	.set_acl	= ext3_set_acl,
};

const struct inode_operations ext3_special_inode_operations = {
	.setattr	= ext3_setattr,
#ifdef CONFIG_EXT3_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext3_listxattr,
	.removexattr	= generic_removexattr,
#endif
	.get_acl	= ext3_get_acl,
	.set_acl	= ext3_set_acl,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/namei.c */
/************************************************************/
/*
 *  linux/fs/ext3/super.c
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
// #include <linux/blkdev.h>
#include <linux/parser.h>
#include <linux/exportfs.h>
#include <linux/statfs.h>
// #include <linux/random.h>
// #include <linux/mount.h>
// #include <linux/quotaops.h>
#include <linux/seq_file.h>
#include <linux/log2.h>
#include <linux/cleancache.h>
// #include <linux/namei.h>
#include "../../inc/__fss.h"

// #include <asm/uaccess.h>

#define CREATE_TRACE_POINTS

// #include "ext3.h"
// #include "xattr.h"
// #include "acl.h"
// #include "namei.h"

#ifdef CONFIG_EXT3_DEFAULTS_TO_ORDERED
  #define EXT3_MOUNT_DEFAULT_DATA_MODE EXT3_MOUNT_ORDERED_DATA
#else
  #define EXT3_MOUNT_DEFAULT_DATA_MODE EXT3_MOUNT_WRITEBACK_DATA
#endif

static int ext3_load_journal(struct super_block *, struct ext3_super_block *,
			     unsigned long journal_devnum);
static int ext3_create_journal(struct super_block *, struct ext3_super_block *,
			       unsigned int);
static int ext3_commit_super(struct super_block *sb,
			       struct ext3_super_block *es,
			       int sync);
static void ext3_mark_recovery_complete(struct super_block * sb,
					struct ext3_super_block * es);
static void ext3_clear_journal_err(struct super_block * sb,
				   struct ext3_super_block * es);
static int ext3_sync_fs(struct super_block *sb, int wait);
static const char *ext3_decode_error(struct super_block * sb, int errno,
				     char nbuf[16]);
static int ext3_remount (struct super_block * sb, int * flags, char * data);
static int ext3_statfs (struct dentry * dentry, struct kstatfs * buf);
static int ext3_unfreeze(struct super_block *sb);
static int ext3_freeze(struct super_block *sb);

/*
 * Wrappers for journal_start/end.
 */
handle_t *ext3_journal_start_sb(struct super_block *sb, int nblocks)
{
	journal_t *journal;

	if (sb->s_flags & MS_RDONLY)
		return ERR_PTR(-EROFS);

	/* Special case here: if the journal has aborted behind our
	 * backs (eg. EIO in the commit thread), then we still need to
	 * take the FS itself readonly cleanly. */
	journal = EXT3_SB(sb)->s_journal;
	if (is_journal_aborted(journal)) {
		ext3_abort(sb, __func__,
			   "Detected aborted journal");
		return ERR_PTR(-EROFS);
	}

	return journal_start(journal, nblocks);
}

int __ext3_journal_stop(const char *where, handle_t *handle)
{
	struct super_block *sb;
	int err;
	int rc;

	sb = handle->h_transaction->t_journal->j_private;
	err = handle->h_err;
	rc = journal_stop(handle);

	if (!err)
		err = rc;
	if (err)
		__ext3_std_error(sb, where, err);
	return err;
}

void ext3_journal_abort_handle(const char *caller, const char *err_fn,
		struct buffer_head *bh, handle_t *handle, int err)
{
	char nbuf[16];
	const char *errstr = ext3_decode_error(NULL, err, nbuf);

	if (bh)
		BUFFER_TRACE(bh, "abort");

	if (!handle->h_err)
		handle->h_err = err;

	if (is_handle_aborted(handle))
		return;

	printk(KERN_ERR "EXT3-fs: %s: aborting transaction: %s in %s\n",
		caller, errstr, err_fn);

	journal_abort_handle(handle);
}

void ext3_msg(struct super_block *sb, const char *prefix,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	printk("%sEXT3-fs (%s): %pV\n", prefix, sb->s_id, &vaf);

	va_end(args);
}

/* Deal with the reporting of failure conditions on a filesystem such as
 * inconsistencies detected or read IO failures.
 *
 * On ext2, we can store the error state of the filesystem in the
 * superblock.  That is not possible on ext3, because we may have other
 * write ordering constraints on the superblock which prevent us from
 * writing it out straight away; and given that the journal is about to
 * be aborted, we can't rely on the current, or future, transactions to
 * write out the superblock safely.
 *
 * We'll just use the journal_abort() error code to record an error in
 * the journal instead.  On recovery, the journal will complain about
 * that error until we've noted it down and cleared it.
 */

static void ext3_handle_error(struct super_block *sb)
{
	struct ext3_super_block *es = EXT3_SB(sb)->s_es;

	EXT3_SB(sb)->s_mount_state |= EXT3_ERROR_FS;
	es->s_state |= cpu_to_le16(EXT3_ERROR_FS);

	if (sb->s_flags & MS_RDONLY)
		return;

	if (!test_opt (sb, ERRORS_CONT)) {
		journal_t *journal = EXT3_SB(sb)->s_journal;

		set_opt(EXT3_SB(sb)->s_mount_opt, ABORT);
		if (journal)
			journal_abort(journal, -EIO);
	}
	if (test_opt (sb, ERRORS_RO)) {
		ext3_msg(sb, KERN_CRIT,
			"error: remounting filesystem read-only");
		/*
		 * Make sure updated value of ->s_mount_state will be visible
		 * before ->s_flags update.
		 */
		smp_wmb();
		sb->s_flags |= MS_RDONLY;
	}
	ext3_commit_super(sb, es, 1);
	if (test_opt(sb, ERRORS_PANIC))
		panic("EXT3-fs (%s): panic forced after error\n",
			sb->s_id);
}

void ext3_error(struct super_block *sb, const char *function,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	printk(KERN_CRIT "EXT3-fs error (device %s): %s: %pV\n",
	       sb->s_id, function, &vaf);

	va_end(args);

	ext3_handle_error(sb);
}

static const char *ext3_decode_error(struct super_block * sb, int errno,
				     char nbuf[16])
{
	char *errstr = NULL;

	switch (errno) {
	case -EIO:
		errstr = "IO failure";
		break;
	case -ENOMEM:
		errstr = "Out of memory";
		break;
	case -EROFS:
		if (!sb || EXT3_SB(sb)->s_journal->j_flags & JFS_ABORT)
			errstr = "Journal has aborted";
		else
			errstr = "Readonly filesystem";
		break;
	default:
		/* If the caller passed in an extra buffer for unknown
		 * errors, textualise them now.  Else we just return
		 * NULL. */
		if (nbuf) {
			/* Check for truncated error codes... */
			if (snprintf(nbuf, 16, "error %d", -errno) >= 0)
				errstr = nbuf;
		}
		break;
	}

	return errstr;
}

/* __ext3_std_error decodes expected errors from journaling functions
 * automatically and invokes the appropriate error response.  */

void __ext3_std_error (struct super_block * sb, const char * function,
		       int errno)
{
	char nbuf[16];
	const char *errstr;

	/* Special case: if the error is EROFS, and we're not already
	 * inside a transaction, then there's really no point in logging
	 * an error. */
	if (errno == -EROFS && journal_current_handle() == NULL &&
	    (sb->s_flags & MS_RDONLY))
		return;

	errstr = ext3_decode_error(sb, errno, nbuf);
	ext3_msg(sb, KERN_CRIT, "error in %s: %s", function, errstr);

	ext3_handle_error(sb);
}

/*
 * ext3_abort is a much stronger failure handler than ext3_error.  The
 * abort function may be used to deal with unrecoverable failures such
 * as journal IO errors or ENOMEM at a critical moment in log management.
 *
 * We unconditionally force the filesystem into an ABORT|READONLY state,
 * unless the error response on the fs has been set to panic in which
 * case we take the easy way out and panic immediately.
 */

void ext3_abort(struct super_block *sb, const char *function,
		 const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	printk(KERN_CRIT "EXT3-fs (%s): error: %s: %pV\n",
	       sb->s_id, function, &vaf);

	va_end(args);

	if (test_opt(sb, ERRORS_PANIC))
		panic("EXT3-fs: panic from previous error\n");

	if (sb->s_flags & MS_RDONLY)
		return;

	ext3_msg(sb, KERN_CRIT,
		"error: remounting filesystem read-only");
	EXT3_SB(sb)->s_mount_state |= EXT3_ERROR_FS;
	set_opt(EXT3_SB(sb)->s_mount_opt, ABORT);
	/*
	 * Make sure updated value of ->s_mount_state will be visible
	 * before ->s_flags update.
	 */
	smp_wmb();
	sb->s_flags |= MS_RDONLY;

	if (EXT3_SB(sb)->s_journal)
		journal_abort(EXT3_SB(sb)->s_journal, -EIO);
}

void ext3_warning(struct super_block *sb, const char *function,
		  const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	printk(KERN_WARNING "EXT3-fs (%s): warning: %s: %pV\n",
	       sb->s_id, function, &vaf);

	va_end(args);
}

void ext3_update_dynamic_rev(struct super_block *sb)
{
	struct ext3_super_block *es = EXT3_SB(sb)->s_es;

	if (le32_to_cpu(es->s_rev_level) > EXT3_GOOD_OLD_REV)
		return;

	ext3_msg(sb, KERN_WARNING,
		"warning: updating to rev %d because of "
		"new feature flag, running e2fsck is recommended",
		EXT3_DYNAMIC_REV);

	es->s_first_ino = cpu_to_le32(EXT3_GOOD_OLD_FIRST_INO);
	es->s_inode_size = cpu_to_le16(EXT3_GOOD_OLD_INODE_SIZE);
	es->s_rev_level = cpu_to_le32(EXT3_DYNAMIC_REV);
	/* leave es->s_feature_*compat flags alone */
	/* es->s_uuid will be set by e2fsck if empty */

	/*
	 * The rest of the superblock fields should be zero, and if not it
	 * means they are likely already in use, so leave them alone.  We
	 * can leave it up to e2fsck to clean up any inconsistencies there.
	 */
}

/*
 * Open the external journal device
 */
static struct block_device *ext3_blkdev_get(dev_t dev, struct super_block *sb)
{
	struct block_device *bdev;
	char b[BDEVNAME_SIZE];

	bdev = blkdev_get_by_dev(dev, FMODE_READ|FMODE_WRITE|FMODE_EXCL, sb);
	if (IS_ERR(bdev))
		goto fail;
	return bdev;

fail:
	ext3_msg(sb, KERN_ERR, "error: failed to open journal device %s: %ld",
		__bdevname(dev, b), PTR_ERR(bdev));

	return NULL;
}

/*
 * Release the journal device
 */
static void ext3_blkdev_put(struct block_device *bdev)
{
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
}

static void ext3_blkdev_remove(struct ext3_sb_info *sbi)
{
	struct block_device *bdev;
	bdev = sbi->journal_bdev;
	if (bdev) {
		ext3_blkdev_put(bdev);
		sbi->journal_bdev = NULL;
	}
}

static inline struct inode *orphan_list_entry(struct list_head *l)
{
	return &list_entry(l, struct ext3_inode_info, i_orphan)->vfs_inode;
}

static void dump_orphan_list(struct super_block *sb, struct ext3_sb_info *sbi)
{
	struct list_head *l;

	ext3_msg(sb, KERN_ERR, "error: sb orphan head is %d",
	       le32_to_cpu(sbi->s_es->s_last_orphan));

	ext3_msg(sb, KERN_ERR, "sb_info orphan list:");
	list_for_each(l, &sbi->s_orphan) {
		struct inode *inode = orphan_list_entry(l);
		ext3_msg(sb, KERN_ERR, "  "
		       "inode %s:%lu at %p: mode %o, nlink %d, next %d\n",
		       inode->i_sb->s_id, inode->i_ino, inode,
		       inode->i_mode, inode->i_nlink,
		       NEXT_ORPHAN(inode));
	}
}

static void ext3_put_super (struct super_block * sb)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	struct ext3_super_block *es = sbi->s_es;
	int i, err;

	dquot_disable(sb, -1, DQUOT_USAGE_ENABLED | DQUOT_LIMITS_ENABLED);
	ext3_xattr_put_super(sb);
	err = journal_destroy(sbi->s_journal);
	sbi->s_journal = NULL;
	if (err < 0)
		ext3_abort(sb, __func__, "Couldn't clean up the journal");

	if (!(sb->s_flags & MS_RDONLY)) {
		EXT3_CLEAR_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_RECOVER);
		es->s_state = cpu_to_le16(sbi->s_mount_state);
		BUFFER_TRACE(sbi->s_sbh, "marking dirty");
		mark_buffer_dirty(sbi->s_sbh);
		ext3_commit_super(sb, es, 1);
	}

	for (i = 0; i < sbi->s_gdb_count; i++)
		brelse(sbi->s_group_desc[i]);
	kfree(sbi->s_group_desc);
	percpu_counter_destroy(&sbi->s_freeblocks_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	brelse(sbi->s_sbh);
#ifdef CONFIG_QUOTA
	for (i = 0; i < EXT3_MAXQUOTAS; i++)
		kfree(sbi->s_qf_names[i]);
#endif

	/* Debugging code just in case the in-memory inode orphan list
	 * isn't empty.  The on-disk one can be non-empty if we've
	 * detected an error and taken the fs readonly, but the
	 * in-memory list had better be clean by this point. */
	if (!list_empty(&sbi->s_orphan))
		dump_orphan_list(sb, sbi);
	J_ASSERT(list_empty(&sbi->s_orphan));

	invalidate_bdev(sb->s_bdev);
	if (sbi->journal_bdev && sbi->journal_bdev != sb->s_bdev) {
		/*
		 * Invalidate the journal device's buffers.  We don't want them
		 * floating about in memory - the physical journal device may
		 * hotswapped, and it breaks the `ro-after' testing code.
		 */
		sync_blockdev(sbi->journal_bdev);
		invalidate_bdev(sbi->journal_bdev);
		ext3_blkdev_remove(sbi);
	}
	sb->s_fs_info = NULL;
	kfree(sbi->s_blockgroup_lock);
	mutex_destroy(&sbi->s_orphan_lock);
	mutex_destroy(&sbi->s_resize_lock);
	kfree(sbi);
}

static struct kmem_cache *ext3_inode_cachep;

/*
 * Called inside transaction, so use GFP_NOFS
 */
static struct inode *ext3_alloc_inode(struct super_block *sb)
{
	struct ext3_inode_info *ei;

	ei = kmem_cache_alloc(ext3_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;
	ei->i_block_alloc_info = NULL;
	ei->vfs_inode.i_version = 1;
	atomic_set(&ei->i_datasync_tid, 0);
	atomic_set(&ei->i_sync_tid, 0);
#ifdef CONFIG_QUOTA
	memset(&ei->i_dquot, 0, sizeof(ei->i_dquot));
#endif

	return &ei->vfs_inode;
}

static int ext3_drop_inode(struct inode *inode)
{
	int drop = generic_drop_inode(inode);

	trace_ext3_drop_inode(inode, drop);
	return drop;
}

static void ext3_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(ext3_inode_cachep, EXT3_I(inode));
}

static void ext3_destroy_inode(struct inode *inode)
{
	if (!list_empty(&(EXT3_I(inode)->i_orphan))) {
		printk("EXT3 Inode %p: orphan list check failed!\n",
			EXT3_I(inode));
		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_ADDRESS, 16, 4,
				EXT3_I(inode), sizeof(struct ext3_inode_info),
				false);
		dump_stack();
	}
	call_rcu(&inode->i_rcu, ext3_i_callback);
}

static void init_once(void *foo)
{
	struct ext3_inode_info *ei = (struct ext3_inode_info *) foo;

	INIT_LIST_HEAD(&ei->i_orphan);
#ifdef CONFIG_EXT3_FS_XATTR
	init_rwsem(&ei->xattr_sem);
#endif
	mutex_init(&ei->truncate_mutex);
	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	ext3_inode_cachep = kmem_cache_create("ext3_inode_cache",
					     sizeof(struct ext3_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (ext3_inode_cachep == NULL)
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
	kmem_cache_destroy(ext3_inode_cachep);
}

static inline void ext3_show_quota_options(struct seq_file *seq, struct super_block *sb)
{
#if defined(CONFIG_QUOTA)
	struct ext3_sb_info *sbi = EXT3_SB(sb);

	if (sbi->s_jquota_fmt) {
		char *fmtname = "";

		switch (sbi->s_jquota_fmt) {
		case QFMT_VFS_OLD:
			fmtname = "vfsold";
			break;
		case QFMT_VFS_V0:
			fmtname = "vfsv0";
			break;
		case QFMT_VFS_V1:
			fmtname = "vfsv1";
			break;
		}
		seq_printf(seq, ",jqfmt=%s", fmtname);
	}

	if (sbi->s_qf_names[USRQUOTA])
		seq_printf(seq, ",usrjquota=%s", sbi->s_qf_names[USRQUOTA]);

	if (sbi->s_qf_names[GRPQUOTA])
		seq_printf(seq, ",grpjquota=%s", sbi->s_qf_names[GRPQUOTA]);

	if (test_opt(sb, USRQUOTA))
		seq_puts(seq, ",usrquota");

	if (test_opt(sb, GRPQUOTA))
		seq_puts(seq, ",grpquota");
#endif
}

static char *data_mode_string(unsigned long mode)
{
	switch (mode) {
	case EXT3_MOUNT_JOURNAL_DATA:
		return "journal";
	case EXT3_MOUNT_ORDERED_DATA:
		return "ordered";
	case EXT3_MOUNT_WRITEBACK_DATA:
		return "writeback";
	}
	return "unknown";
}

/*
 * Show an option if
 *  - it's set to a non-default value OR
 *  - if the per-sb default is different from the global default
 */
static int ext3_show_options(struct seq_file *seq, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	struct ext3_super_block *es = sbi->s_es;
	unsigned long def_mount_opts;

	def_mount_opts = le32_to_cpu(es->s_default_mount_opts);

	if (sbi->s_sb_block != 1)
		seq_printf(seq, ",sb=%lu", sbi->s_sb_block);
	if (test_opt(sb, MINIX_DF))
		seq_puts(seq, ",minixdf");
	if (test_opt(sb, GRPID))
		seq_puts(seq, ",grpid");
	if (!test_opt(sb, GRPID) && (def_mount_opts & EXT3_DEFM_BSDGROUPS))
		seq_puts(seq, ",nogrpid");
	if (!uid_eq(sbi->s_resuid, make_kuid(&init_user_ns, EXT3_DEF_RESUID)) ||
	    le16_to_cpu(es->s_def_resuid) != EXT3_DEF_RESUID) {
		seq_printf(seq, ",resuid=%u",
				from_kuid_munged(&init_user_ns, sbi->s_resuid));
	}
	if (!gid_eq(sbi->s_resgid, make_kgid(&init_user_ns, EXT3_DEF_RESGID)) ||
	    le16_to_cpu(es->s_def_resgid) != EXT3_DEF_RESGID) {
		seq_printf(seq, ",resgid=%u",
				from_kgid_munged(&init_user_ns, sbi->s_resgid));
	}
	if (test_opt(sb, ERRORS_RO)) {
		int def_errors = le16_to_cpu(es->s_errors);

		if (def_errors == EXT3_ERRORS_PANIC ||
		    def_errors == EXT3_ERRORS_CONTINUE) {
			seq_puts(seq, ",errors=remount-ro");
		}
	}
	if (test_opt(sb, ERRORS_CONT))
		seq_puts(seq, ",errors=continue");
	if (test_opt(sb, ERRORS_PANIC))
		seq_puts(seq, ",errors=panic");
	if (test_opt(sb, NO_UID32))
		seq_puts(seq, ",nouid32");
	if (test_opt(sb, DEBUG))
		seq_puts(seq, ",debug");
#ifdef CONFIG_EXT3_FS_XATTR
	if (test_opt(sb, XATTR_USER))
		seq_puts(seq, ",user_xattr");
	if (!test_opt(sb, XATTR_USER) &&
	    (def_mount_opts & EXT3_DEFM_XATTR_USER)) {
		seq_puts(seq, ",nouser_xattr");
	}
#endif
#ifdef CONFIG_EXT3_FS_POSIX_ACL
	if (test_opt(sb, POSIX_ACL))
		seq_puts(seq, ",acl");
	if (!test_opt(sb, POSIX_ACL) && (def_mount_opts & EXT3_DEFM_ACL))
		seq_puts(seq, ",noacl");
#endif
	if (!test_opt(sb, RESERVATION))
		seq_puts(seq, ",noreservation");
	if (sbi->s_commit_interval) {
		seq_printf(seq, ",commit=%u",
			   (unsigned) (sbi->s_commit_interval / HZ));
	}

	/*
	 * Always display barrier state so it's clear what the status is.
	 */
	seq_puts(seq, ",barrier=");
	seq_puts(seq, test_opt(sb, BARRIER) ? "1" : "0");
	seq_printf(seq, ",data=%s", data_mode_string(test_opt(sb, DATA_FLAGS)));
	if (test_opt(sb, DATA_ERR_ABORT))
		seq_puts(seq, ",data_err=abort");

	if (test_opt(sb, NOLOAD))
		seq_puts(seq, ",norecovery");

	ext3_show_quota_options(seq, sb);

	return 0;
}


static struct inode *ext3_nfs_get_inode(struct super_block *sb,
		u64 ino, u32 generation)
{
	struct inode *inode;

	if (ino < EXT3_FIRST_INO(sb) && ino != EXT3_ROOT_INO)
		return ERR_PTR(-ESTALE);
	if (ino > le32_to_cpu(EXT3_SB(sb)->s_es->s_inodes_count))
		return ERR_PTR(-ESTALE);

	/* iget isn't really right if the inode is currently unallocated!!
	 *
	 * ext3_read_inode will return a bad_inode if the inode had been
	 * deleted, so we should be safe.
	 *
	 * Currently we don't know the generation for parent directory, so
	 * a generation of 0 means "accept any"
	 */
	inode = ext3_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

static struct dentry *ext3_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    ext3_nfs_get_inode);
}

static struct dentry *ext3_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    ext3_nfs_get_inode);
}

/*
 * Try to release metadata pages (indirect blocks, directories) which are
 * mapped via the block device.  Since these pages could have journal heads
 * which would prevent try_to_free_buffers() from freeing them, we must use
 * jbd layer's try_to_free_buffers() function to release them.
 */
static int bdev_try_to_free_page(struct super_block *sb, struct page *page,
				 gfp_t wait)
{
	journal_t *journal = EXT3_SB(sb)->s_journal;

	WARN_ON(PageChecked(page));
	if (!page_has_buffers(page))
		return 0;
	if (journal)
		return journal_try_to_free_buffers(journal, page, 
						   wait & ~__GFP_WAIT);
	return try_to_free_buffers(page);
}

#ifdef CONFIG_QUOTA
#define QTYPE2NAME(t) ((t)==USRQUOTA?"user":"group")
#define QTYPE2MOPT(on, t) ((t)==USRQUOTA?((on)##USRJQUOTA):((on)##GRPJQUOTA))

static int ext3_write_dquot(struct dquot *dquot);
static int ext3_acquire_dquot(struct dquot *dquot);
static int ext3_release_dquot(struct dquot *dquot);
static int ext3_mark_dquot_dirty(struct dquot *dquot);
static int ext3_write_info(struct super_block *sb, int type);
static int ext3_quota_on(struct super_block *sb, int type, int format_id,
			 struct path *path);
static int ext3_quota_on_mount(struct super_block *sb, int type);
static ssize_t ext3_quota_read(struct super_block *sb, int type, char *data,
			       size_t len, loff_t off);
static ssize_t ext3_quota_write(struct super_block *sb, int type,
				const char *data, size_t len, loff_t off);
static struct dquot **ext3_get_dquots(struct inode *inode)
{
	return EXT3_I(inode)->i_dquot;
}

static const struct dquot_operations ext3_quota_operations = {
	.write_dquot	= ext3_write_dquot,
	.acquire_dquot	= ext3_acquire_dquot,
	.release_dquot	= ext3_release_dquot,
	.mark_dirty	= ext3_mark_dquot_dirty,
	.write_info	= ext3_write_info,
	.alloc_dquot	= dquot_alloc,
	.destroy_dquot	= dquot_destroy,
};

static const struct quotactl_ops ext3_qctl_operations = {
	.quota_on	= ext3_quota_on,
	.quota_off	= dquot_quota_off,
	.quota_sync	= dquot_quota_sync,
	.get_info	= dquot_get_dqinfo,
	.set_info	= dquot_set_dqinfo,
	.get_dqblk	= dquot_get_dqblk,
	.set_dqblk	= dquot_set_dqblk
};
#endif

static const struct super_operations ext3_sops = {
	.alloc_inode	= ext3_alloc_inode,
	.destroy_inode	= ext3_destroy_inode,
	.write_inode	= ext3_write_inode,
	.dirty_inode	= ext3_dirty_inode,
	.drop_inode	= ext3_drop_inode,
	.evict_inode	= ext3_evict_inode,
	.put_super	= ext3_put_super,
	.sync_fs	= ext3_sync_fs,
	.freeze_fs	= ext3_freeze,
	.unfreeze_fs	= ext3_unfreeze,
	.statfs		= ext3_statfs,
	.remount_fs	= ext3_remount,
	.show_options	= ext3_show_options,
#ifdef CONFIG_QUOTA
	.quota_read	= ext3_quota_read,
	.quota_write	= ext3_quota_write,
	.get_dquots	= ext3_get_dquots,
#endif
	.bdev_try_to_free_page = bdev_try_to_free_page,
};

static const struct export_operations ext3_export_ops = {
	.fh_to_dentry = ext3_fh_to_dentry,
	.fh_to_parent = ext3_fh_to_parent,
	.get_parent = ext3_get_parent,
};

enum {
	Opt_bsd_df, Opt_minix_df, Opt_grpid, Opt_nogrpid,
	Opt_resgid, Opt_resuid, Opt_sb, Opt_err_cont, Opt_err_panic, Opt_err_ro,
	Opt_nouid32, Opt_nocheck, Opt_debug, Opt_oldalloc, Opt_orlov,
	Opt_user_xattr, Opt_nouser_xattr, Opt_acl, Opt_noacl,
	Opt_reservation, Opt_noreservation, Opt_noload, Opt_nobh, Opt_bh,
	Opt_commit, Opt_journal_update, Opt_journal_inum, Opt_journal_dev,
	Opt_journal_path,
	Opt_abort, Opt_data_journal, Opt_data_ordered, Opt_data_writeback,
	Opt_data_err_abort, Opt_data_err_ignore,
	Opt_usrjquota, Opt_grpjquota, Opt_offusrjquota, Opt_offgrpjquota,
	Opt_jqfmt_vfsold, Opt_jqfmt_vfsv0, Opt_jqfmt_vfsv1, Opt_quota,
	Opt_noquota, Opt_ignore, Opt_barrier, Opt_nobarrier, Opt_err,
	Opt_resize, Opt_usrquota, Opt_grpquota
};

static const match_table_t tokens = {
	{Opt_bsd_df, "bsddf"},
	{Opt_minix_df, "minixdf"},
	{Opt_grpid, "grpid"},
	{Opt_grpid, "bsdgroups"},
	{Opt_nogrpid, "nogrpid"},
	{Opt_nogrpid, "sysvgroups"},
	{Opt_resgid, "resgid=%u"},
	{Opt_resuid, "resuid=%u"},
	{Opt_sb, "sb=%u"},
	{Opt_err_cont, "errors=continue"},
	{Opt_err_panic, "errors=panic"},
	{Opt_err_ro, "errors=remount-ro"},
	{Opt_nouid32, "nouid32"},
	{Opt_nocheck, "nocheck"},
	{Opt_nocheck, "check=none"},
	{Opt_debug, "debug"},
	{Opt_oldalloc, "oldalloc"},
	{Opt_orlov, "orlov"},
	{Opt_user_xattr, "user_xattr"},
	{Opt_nouser_xattr, "nouser_xattr"},
	{Opt_acl, "acl"},
	{Opt_noacl, "noacl"},
	{Opt_reservation, "reservation"},
	{Opt_noreservation, "noreservation"},
	{Opt_noload, "noload"},
	{Opt_noload, "norecovery"},
	{Opt_nobh, "nobh"},
	{Opt_bh, "bh"},
	{Opt_commit, "commit=%u"},
	{Opt_journal_update, "journal=update"},
	{Opt_journal_inum, "journal=%u"},
	{Opt_journal_dev, "journal_dev=%u"},
	{Opt_journal_path, "journal_path=%s"},
	{Opt_abort, "abort"},
	{Opt_data_journal, "data=journal"},
	{Opt_data_ordered, "data=ordered"},
	{Opt_data_writeback, "data=writeback"},
	{Opt_data_err_abort, "data_err=abort"},
	{Opt_data_err_ignore, "data_err=ignore"},
	{Opt_offusrjquota, "usrjquota="},
	{Opt_usrjquota, "usrjquota=%s"},
	{Opt_offgrpjquota, "grpjquota="},
	{Opt_grpjquota, "grpjquota=%s"},
	{Opt_jqfmt_vfsold, "jqfmt=vfsold"},
	{Opt_jqfmt_vfsv0, "jqfmt=vfsv0"},
	{Opt_jqfmt_vfsv1, "jqfmt=vfsv1"},
	{Opt_grpquota, "grpquota"},
	{Opt_noquota, "noquota"},
	{Opt_quota, "quota"},
	{Opt_usrquota, "usrquota"},
	{Opt_barrier, "barrier=%u"},
	{Opt_barrier, "barrier"},
	{Opt_nobarrier, "nobarrier"},
	{Opt_resize, "resize"},
	{Opt_err, NULL},
};

static ext3_fsblk_t get_sb_block(void **data, struct super_block *sb)
{
	ext3_fsblk_t	sb_block;
	char		*options = (char *) *data;

	if (!options || strncmp(options, "sb=", 3) != 0)
		return 1;	/* Default location */
	options += 3;
	/*todo: use simple_strtoll with >32bit ext3 */
	sb_block = simple_strtoul(options, &options, 0);
	if (*options && *options != ',') {
		ext3_msg(sb, KERN_ERR, "error: invalid sb specification: %s",
		       (char *) *data);
		return 1;
	}
	if (*options == ',')
		options++;
	*data = (void *) options;
	return sb_block;
}

#ifdef CONFIG_QUOTA
static int set_qf_name(struct super_block *sb, int qtype, substring_t *args)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	char *qname;

	if (sb_any_quota_loaded(sb) &&
		!sbi->s_qf_names[qtype]) {
		ext3_msg(sb, KERN_ERR,
			"Cannot change journaled "
			"quota options when quota turned on");
		return 0;
	}
	qname = match_strdup(args);
	if (!qname) {
		ext3_msg(sb, KERN_ERR,
			"Not enough memory for storing quotafile name");
		return 0;
	}
	if (sbi->s_qf_names[qtype]) {
		int same = !strcmp(sbi->s_qf_names[qtype], qname);

		kfree(qname);
		if (!same) {
			ext3_msg(sb, KERN_ERR,
				 "%s quota file already specified",
				 QTYPE2NAME(qtype));
		}
		return same;
	}
	if (strchr(qname, '/')) {
		ext3_msg(sb, KERN_ERR,
			"quotafile must be on filesystem root");
		kfree(qname);
		return 0;
	}
	sbi->s_qf_names[qtype] = qname;
	set_opt(sbi->s_mount_opt, QUOTA);
	return 1;
}

static int clear_qf_name(struct super_block *sb, int qtype) {

	struct ext3_sb_info *sbi = EXT3_SB(sb);

	if (sb_any_quota_loaded(sb) &&
		sbi->s_qf_names[qtype]) {
		ext3_msg(sb, KERN_ERR, "Cannot change journaled quota options"
			" when quota turned on");
		return 0;
	}
	if (sbi->s_qf_names[qtype]) {
		kfree(sbi->s_qf_names[qtype]);
		sbi->s_qf_names[qtype] = NULL;
	}
	return 1;
}
#endif

static int parse_options (char *options, struct super_block *sb,
			  unsigned int *inum, unsigned long *journal_devnum,
			  ext3_fsblk_t *n_blocks_count, int is_remount)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	char * p;
	substring_t args[MAX_OPT_ARGS];
	int data_opt = 0;
	int option;
	kuid_t uid;
	kgid_t gid;
	char *journal_path;
	struct inode *journal_inode;
	struct path path;
	int error;

#ifdef CONFIG_QUOTA
	int qfmt;
#endif

	if (!options)
		return 1;

	while ((p = strsep (&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;
		/*
		 * Initialize args struct so we know whether arg was
		 * found; some options take optional arguments.
		 */
		args[0].to = args[0].from = NULL;
		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_bsd_df:
			clear_opt (sbi->s_mount_opt, MINIX_DF);
			break;
		case Opt_minix_df:
			set_opt (sbi->s_mount_opt, MINIX_DF);
			break;
		case Opt_grpid:
			set_opt (sbi->s_mount_opt, GRPID);
			break;
		case Opt_nogrpid:
			clear_opt (sbi->s_mount_opt, GRPID);
			break;
		case Opt_resuid:
			if (match_int(&args[0], &option))
				return 0;
			uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(uid)) {
				ext3_msg(sb, KERN_ERR, "Invalid uid value %d", option);
				return 0;

			}
			sbi->s_resuid = uid;
			break;
		case Opt_resgid:
			if (match_int(&args[0], &option))
				return 0;
			gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(gid)) {
				ext3_msg(sb, KERN_ERR, "Invalid gid value %d", option);
				return 0;
			}
			sbi->s_resgid = gid;
			break;
		case Opt_sb:
			/* handled by get_sb_block() instead of here */
			/* *sb_block = match_int(&args[0]); */
			break;
		case Opt_err_panic:
			clear_opt (sbi->s_mount_opt, ERRORS_CONT);
			clear_opt (sbi->s_mount_opt, ERRORS_RO);
			set_opt (sbi->s_mount_opt, ERRORS_PANIC);
			break;
		case Opt_err_ro:
			clear_opt (sbi->s_mount_opt, ERRORS_CONT);
			clear_opt (sbi->s_mount_opt, ERRORS_PANIC);
			set_opt (sbi->s_mount_opt, ERRORS_RO);
			break;
		case Opt_err_cont:
			clear_opt (sbi->s_mount_opt, ERRORS_RO);
			clear_opt (sbi->s_mount_opt, ERRORS_PANIC);
			set_opt (sbi->s_mount_opt, ERRORS_CONT);
			break;
		case Opt_nouid32:
			set_opt (sbi->s_mount_opt, NO_UID32);
			break;
		case Opt_nocheck:
			clear_opt (sbi->s_mount_opt, CHECK);
			break;
		case Opt_debug:
			set_opt (sbi->s_mount_opt, DEBUG);
			break;
		case Opt_oldalloc:
			ext3_msg(sb, KERN_WARNING,
				"Ignoring deprecated oldalloc option");
			break;
		case Opt_orlov:
			ext3_msg(sb, KERN_WARNING,
				"Ignoring deprecated orlov option");
			break;
#ifdef CONFIG_EXT3_FS_XATTR
		case Opt_user_xattr:
			set_opt (sbi->s_mount_opt, XATTR_USER);
			break;
		case Opt_nouser_xattr:
			clear_opt (sbi->s_mount_opt, XATTR_USER);
			break;
#else
		case Opt_user_xattr:
		case Opt_nouser_xattr:
			ext3_msg(sb, KERN_INFO,
				"(no)user_xattr options not supported");
			break;
#endif
#ifdef CONFIG_EXT3_FS_POSIX_ACL
		case Opt_acl:
			set_opt(sbi->s_mount_opt, POSIX_ACL);
			break;
		case Opt_noacl:
			clear_opt(sbi->s_mount_opt, POSIX_ACL);
			break;
#else
		case Opt_acl:
		case Opt_noacl:
			ext3_msg(sb, KERN_INFO,
				"(no)acl options not supported");
			break;
#endif
		case Opt_reservation:
			set_opt(sbi->s_mount_opt, RESERVATION);
			break;
		case Opt_noreservation:
			clear_opt(sbi->s_mount_opt, RESERVATION);
			break;
		case Opt_journal_update:
			/* @@@ FIXME */
			/* Eventually we will want to be able to create
			   a journal file here.  For now, only allow the
			   user to specify an existing inode to be the
			   journal file. */
			if (is_remount) {
				ext3_msg(sb, KERN_ERR, "error: cannot specify "
					"journal on remount");
				return 0;
			}
			set_opt (sbi->s_mount_opt, UPDATE_JOURNAL);
			break;
		case Opt_journal_inum:
			if (is_remount) {
				ext3_msg(sb, KERN_ERR, "error: cannot specify "
				       "journal on remount");
				return 0;
			}
			if (match_int(&args[0], &option))
				return 0;
			*inum = option;
			break;
		case Opt_journal_dev:
			if (is_remount) {
				ext3_msg(sb, KERN_ERR, "error: cannot specify "
				       "journal on remount");
				return 0;
			}
			if (match_int(&args[0], &option))
				return 0;
			*journal_devnum = option;
			break;
		case Opt_journal_path:
			if (is_remount) {
				ext3_msg(sb, KERN_ERR, "error: cannot specify "
				       "journal on remount");
				return 0;
			}

			journal_path = match_strdup(&args[0]);
			if (!journal_path) {
				ext3_msg(sb, KERN_ERR, "error: could not dup "
					"journal device string");
				return 0;
			}

			error = kern_path(journal_path, LOOKUP_FOLLOW, &path);
			if (error) {
				ext3_msg(sb, KERN_ERR, "error: could not find "
					"journal device path: error %d", error);
				kfree(journal_path);
				return 0;
			}

			journal_inode = path.dentry->d_inode;
			if (!S_ISBLK(journal_inode->i_mode)) {
				ext3_msg(sb, KERN_ERR, "error: journal path %s "
					"is not a block device", journal_path);
				path_put(&path);
				kfree(journal_path);
				return 0;
			}

			*journal_devnum = new_encode_dev(journal_inode->i_rdev);
			path_put(&path);
			kfree(journal_path);
			break;
		case Opt_noload:
			set_opt (sbi->s_mount_opt, NOLOAD);
			break;
		case Opt_commit:
			if (match_int(&args[0], &option))
				return 0;
			if (option < 0)
				return 0;
			if (option == 0)
				option = JBD_DEFAULT_MAX_COMMIT_AGE;
			sbi->s_commit_interval = HZ * option;
			break;
		case Opt_data_journal:
			data_opt = EXT3_MOUNT_JOURNAL_DATA;
			goto datacheck;
		case Opt_data_ordered:
			data_opt = EXT3_MOUNT_ORDERED_DATA;
			goto datacheck;
		case Opt_data_writeback:
			data_opt = EXT3_MOUNT_WRITEBACK_DATA;
		datacheck:
			if (is_remount) {
				if (test_opt(sb, DATA_FLAGS) == data_opt)
					break;
				ext3_msg(sb, KERN_ERR,
					"error: cannot change "
					"data mode on remount. The filesystem "
					"is mounted in data=%s mode and you "
					"try to remount it in data=%s mode.",
					data_mode_string(test_opt(sb,
							DATA_FLAGS)),
					data_mode_string(data_opt));
				return 0;
			} else {
				clear_opt(sbi->s_mount_opt, DATA_FLAGS);
				sbi->s_mount_opt |= data_opt;
			}
			break;
		case Opt_data_err_abort:
			set_opt(sbi->s_mount_opt, DATA_ERR_ABORT);
			break;
		case Opt_data_err_ignore:
			clear_opt(sbi->s_mount_opt, DATA_ERR_ABORT);
			break;
#ifdef CONFIG_QUOTA
		case Opt_usrjquota:
			if (!set_qf_name(sb, USRQUOTA, &args[0]))
				return 0;
			break;
		case Opt_grpjquota:
			if (!set_qf_name(sb, GRPQUOTA, &args[0]))
				return 0;
			break;
		case Opt_offusrjquota:
			if (!clear_qf_name(sb, USRQUOTA))
				return 0;
			break;
		case Opt_offgrpjquota:
			if (!clear_qf_name(sb, GRPQUOTA))
				return 0;
			break;
		case Opt_jqfmt_vfsold:
			qfmt = QFMT_VFS_OLD;
			goto set_qf_format;
		case Opt_jqfmt_vfsv0:
			qfmt = QFMT_VFS_V0;
			goto set_qf_format;
		case Opt_jqfmt_vfsv1:
			qfmt = QFMT_VFS_V1;
set_qf_format:
			if (sb_any_quota_loaded(sb) &&
			    sbi->s_jquota_fmt != qfmt) {
				ext3_msg(sb, KERN_ERR, "error: cannot change "
					"journaled quota options when "
					"quota turned on.");
				return 0;
			}
			sbi->s_jquota_fmt = qfmt;
			break;
		case Opt_quota:
		case Opt_usrquota:
			set_opt(sbi->s_mount_opt, QUOTA);
			set_opt(sbi->s_mount_opt, USRQUOTA);
			break;
		case Opt_grpquota:
			set_opt(sbi->s_mount_opt, QUOTA);
			set_opt(sbi->s_mount_opt, GRPQUOTA);
			break;
		case Opt_noquota:
			if (sb_any_quota_loaded(sb)) {
				ext3_msg(sb, KERN_ERR, "error: cannot change "
					"quota options when quota turned on.");
				return 0;
			}
			clear_opt(sbi->s_mount_opt, QUOTA);
			clear_opt(sbi->s_mount_opt, USRQUOTA);
			clear_opt(sbi->s_mount_opt, GRPQUOTA);
			break;
#else
		case Opt_quota:
		case Opt_usrquota:
		case Opt_grpquota:
			ext3_msg(sb, KERN_ERR,
				"error: quota options not supported.");
			break;
		case Opt_usrjquota:
		case Opt_grpjquota:
		case Opt_offusrjquota:
		case Opt_offgrpjquota:
		case Opt_jqfmt_vfsold:
		case Opt_jqfmt_vfsv0:
		case Opt_jqfmt_vfsv1:
			ext3_msg(sb, KERN_ERR,
				"error: journaled quota options not "
				"supported.");
			break;
		case Opt_noquota:
			break;
#endif
		case Opt_abort:
			set_opt(sbi->s_mount_opt, ABORT);
			break;
		case Opt_nobarrier:
			clear_opt(sbi->s_mount_opt, BARRIER);
			break;
		case Opt_barrier:
			if (args[0].from) {
				if (match_int(&args[0], &option))
					return 0;
			} else
				option = 1;	/* No argument, default to 1 */
			if (option)
				set_opt(sbi->s_mount_opt, BARRIER);
			else
				clear_opt(sbi->s_mount_opt, BARRIER);
			break;
		case Opt_ignore:
			break;
		case Opt_resize:
			if (!is_remount) {
				ext3_msg(sb, KERN_ERR,
					"error: resize option only available "
					"for remount");
				return 0;
			}
			if (match_int(&args[0], &option) != 0)
				return 0;
			*n_blocks_count = option;
			break;
		case Opt_nobh:
			ext3_msg(sb, KERN_WARNING,
				"warning: ignoring deprecated nobh option");
			break;
		case Opt_bh:
			ext3_msg(sb, KERN_WARNING,
				"warning: ignoring deprecated bh option");
			break;
		default:
			ext3_msg(sb, KERN_ERR,
				"error: unrecognized mount option \"%s\" "
				"or missing value", p);
			return 0;
		}
	}
#ifdef CONFIG_QUOTA
	if (sbi->s_qf_names[USRQUOTA] || sbi->s_qf_names[GRPQUOTA]) {
		if (test_opt(sb, USRQUOTA) && sbi->s_qf_names[USRQUOTA])
			clear_opt(sbi->s_mount_opt, USRQUOTA);
		if (test_opt(sb, GRPQUOTA) && sbi->s_qf_names[GRPQUOTA])
			clear_opt(sbi->s_mount_opt, GRPQUOTA);

		if (test_opt(sb, GRPQUOTA) || test_opt(sb, USRQUOTA)) {
			ext3_msg(sb, KERN_ERR, "error: old and new quota "
					"format mixing.");
			return 0;
		}

		if (!sbi->s_jquota_fmt) {
			ext3_msg(sb, KERN_ERR, "error: journaled quota format "
					"not specified.");
			return 0;
		}
	}
#endif
	return 1;
}

static int ext3_setup_super(struct super_block *sb, struct ext3_super_block *es,
			    int read_only)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	int res = 0;

	if (le32_to_cpu(es->s_rev_level) > EXT3_MAX_SUPP_REV) {
		ext3_msg(sb, KERN_ERR,
			"error: revision level too high, "
			"forcing read-only mode");
		res = MS_RDONLY;
	}
	if (read_only)
		return res;
	if (!(sbi->s_mount_state & EXT3_VALID_FS))
		ext3_msg(sb, KERN_WARNING,
			"warning: mounting unchecked fs, "
			"running e2fsck is recommended");
	else if ((sbi->s_mount_state & EXT3_ERROR_FS))
		ext3_msg(sb, KERN_WARNING,
			"warning: mounting fs with errors, "
			"running e2fsck is recommended");
	else if ((__s16) le16_to_cpu(es->s_max_mnt_count) > 0 &&
		 le16_to_cpu(es->s_mnt_count) >=
			le16_to_cpu(es->s_max_mnt_count))
		ext3_msg(sb, KERN_WARNING,
			"warning: maximal mount count reached, "
			"running e2fsck is recommended");
	else if (le32_to_cpu(es->s_checkinterval) &&
		(le32_to_cpu(es->s_lastcheck) +
			le32_to_cpu(es->s_checkinterval) <= get_seconds()))
		ext3_msg(sb, KERN_WARNING,
			"warning: checktime reached, "
			"running e2fsck is recommended");
#if 0
		/* @@@ We _will_ want to clear the valid bit if we find
                   inconsistencies, to force a fsck at reboot.  But for
                   a plain journaled filesystem we can keep it set as
                   valid forever! :) */
	es->s_state &= cpu_to_le16(~EXT3_VALID_FS);
#endif
	if (!le16_to_cpu(es->s_max_mnt_count))
		es->s_max_mnt_count = cpu_to_le16(EXT3_DFL_MAX_MNT_COUNT);
	le16_add_cpu(&es->s_mnt_count, 1);
	es->s_mtime = cpu_to_le32(get_seconds());
	ext3_update_dynamic_rev(sb);
	EXT3_SET_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_RECOVER);

	ext3_commit_super(sb, es, 1);
	if (test_opt(sb, DEBUG))
		ext3_msg(sb, KERN_INFO, "[bs=%lu, gc=%lu, "
				"bpg=%lu, ipg=%lu, mo=%04lx]",
			sb->s_blocksize,
			sbi->s_groups_count,
			EXT3_BLOCKS_PER_GROUP(sb),
			EXT3_INODES_PER_GROUP(sb),
			sbi->s_mount_opt);

	if (EXT3_SB(sb)->s_journal->j_inode == NULL) {
		char b[BDEVNAME_SIZE];
		ext3_msg(sb, KERN_INFO, "using external journal on %s",
			bdevname(EXT3_SB(sb)->s_journal->j_dev, b));
	} else {
		ext3_msg(sb, KERN_INFO, "using internal journal");
	}
	cleancache_init_fs(sb);
	return res;
}

/* Called at mount-time, super-block is locked */
static int ext3_check_descriptors(struct super_block *sb)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	int i;

	ext3_debug ("Checking group descriptors");

	for (i = 0; i < sbi->s_groups_count; i++) {
		struct ext3_group_desc *gdp = ext3_get_group_desc(sb, i, NULL);
		ext3_fsblk_t first_block = ext3_group_first_block_no(sb, i);
		ext3_fsblk_t last_block;

		if (i == sbi->s_groups_count - 1)
			last_block = le32_to_cpu(sbi->s_es->s_blocks_count) - 1;
		else
			last_block = first_block +
				(EXT3_BLOCKS_PER_GROUP(sb) - 1);

		if (le32_to_cpu(gdp->bg_block_bitmap) < first_block ||
		    le32_to_cpu(gdp->bg_block_bitmap) > last_block)
		{
			ext3_error (sb, "ext3_check_descriptors",
				    "Block bitmap for group %d"
				    " not in group (block %lu)!",
				    i, (unsigned long)
					le32_to_cpu(gdp->bg_block_bitmap));
			return 0;
		}
		if (le32_to_cpu(gdp->bg_inode_bitmap) < first_block ||
		    le32_to_cpu(gdp->bg_inode_bitmap) > last_block)
		{
			ext3_error (sb, "ext3_check_descriptors",
				    "Inode bitmap for group %d"
				    " not in group (block %lu)!",
				    i, (unsigned long)
					le32_to_cpu(gdp->bg_inode_bitmap));
			return 0;
		}
		if (le32_to_cpu(gdp->bg_inode_table) < first_block ||
		    le32_to_cpu(gdp->bg_inode_table) + sbi->s_itb_per_group - 1 >
		    last_block)
		{
			ext3_error (sb, "ext3_check_descriptors",
				    "Inode table for group %d"
				    " not in group (block %lu)!",
				    i, (unsigned long)
					le32_to_cpu(gdp->bg_inode_table));
			return 0;
		}
	}

	sbi->s_es->s_free_blocks_count=cpu_to_le32(ext3_count_free_blocks(sb));
	sbi->s_es->s_free_inodes_count=cpu_to_le32(ext3_count_free_inodes(sb));
	return 1;
}


/* ext3_orphan_cleanup() walks a singly-linked list of inodes (starting at
 * the superblock) which were deleted from all directories, but held open by
 * a process at the time of a crash.  We walk the list and try to delete these
 * inodes at recovery time (only with a read-write filesystem).
 *
 * In order to keep the orphan inode chain consistent during traversal (in
 * case of crash during recovery), we link each inode into the superblock
 * orphan list_head and handle it the same way as an inode deletion during
 * normal operation (which journals the operations for us).
 *
 * We only do an iget() and an iput() on each inode, which is very safe if we
 * accidentally point at an in-use or already deleted inode.  The worst that
 * can happen in this case is that we get a "bit already cleared" message from
 * ext3_free_inode().  The only reason we would point at a wrong inode is if
 * e2fsck was run on this filesystem, and it must have already done the orphan
 * inode cleanup for us, so we can safely abort without any further action.
 */
static void ext3_orphan_cleanup (struct super_block * sb,
				 struct ext3_super_block * es)
{
	unsigned int s_flags = sb->s_flags;
	int nr_orphans = 0, nr_truncates = 0;
#ifdef CONFIG_QUOTA
	int i;
#endif
	if (!es->s_last_orphan) {
		jbd_debug(4, "no orphan inodes to clean up\n");
		return;
	}

	if (bdev_read_only(sb->s_bdev)) {
		ext3_msg(sb, KERN_ERR, "error: write access "
			"unavailable, skipping orphan cleanup.");
		return;
	}

	/* Check if feature set allows readwrite operations */
	if (EXT3_HAS_RO_COMPAT_FEATURE(sb, ~EXT3_FEATURE_RO_COMPAT_SUPP)) {
		ext3_msg(sb, KERN_INFO, "Skipping orphan cleanup due to "
			 "unknown ROCOMPAT features");
		return;
	}

	if (EXT3_SB(sb)->s_mount_state & EXT3_ERROR_FS) {
		/* don't clear list on RO mount w/ errors */
		if (es->s_last_orphan && !(s_flags & MS_RDONLY)) {
			jbd_debug(1, "Errors on filesystem, "
				  "clearing orphan list.\n");
			es->s_last_orphan = 0;
		}
		jbd_debug(1, "Skipping orphan recovery on fs with errors.\n");
		return;
	}

	if (s_flags & MS_RDONLY) {
		ext3_msg(sb, KERN_INFO, "orphan cleanup on readonly fs");
		sb->s_flags &= ~MS_RDONLY;
	}
#ifdef CONFIG_QUOTA
	/* Needed for iput() to work correctly and not trash data */
	sb->s_flags |= MS_ACTIVE;
	/* Turn on quotas so that they are updated correctly */
	for (i = 0; i < EXT3_MAXQUOTAS; i++) {
		if (EXT3_SB(sb)->s_qf_names[i]) {
			int ret = ext3_quota_on_mount(sb, i);
			if (ret < 0)
				ext3_msg(sb, KERN_ERR,
					"error: cannot turn on journaled "
					"quota: %d", ret);
		}
	}
#endif

	while (es->s_last_orphan) {
		struct inode *inode;

		inode = ext3_orphan_get(sb, le32_to_cpu(es->s_last_orphan));
		if (IS_ERR(inode)) {
			es->s_last_orphan = 0;
			break;
		}

		list_add(&EXT3_I(inode)->i_orphan, &EXT3_SB(sb)->s_orphan);
		dquot_initialize(inode);
		if (inode->i_nlink) {
			printk(KERN_DEBUG
				"%s: truncating inode %lu to %Ld bytes\n",
				__func__, inode->i_ino, inode->i_size);
			jbd_debug(2, "truncating inode %lu to %Ld bytes\n",
				  inode->i_ino, inode->i_size);
			ext3_truncate(inode);
			nr_truncates++;
		} else {
			printk(KERN_DEBUG
				"%s: deleting unreferenced inode %lu\n",
				__func__, inode->i_ino);
			jbd_debug(2, "deleting unreferenced inode %lu\n",
				  inode->i_ino);
			nr_orphans++;
		}
		iput(inode);  /* The delete magic happens here! */
	}

#define PLURAL(x) (x), ((x)==1) ? "" : "s"

	if (nr_orphans)
		ext3_msg(sb, KERN_INFO, "%d orphan inode%s deleted",
		       PLURAL(nr_orphans));
	if (nr_truncates)
		ext3_msg(sb, KERN_INFO, "%d truncate%s cleaned up",
		       PLURAL(nr_truncates));
#ifdef CONFIG_QUOTA
	/* Turn quotas off */
	for (i = 0; i < EXT3_MAXQUOTAS; i++) {
		if (sb_dqopt(sb)->files[i])
			dquot_quota_off(sb, i);
	}
#endif
	sb->s_flags = s_flags; /* Restore MS_RDONLY status */
}

/*
 * Maximal file size.  There is a direct, and {,double-,triple-}indirect
 * block limit, and also a limit of (2^32 - 1) 512-byte sectors in i_blocks.
 * We need to be 1 filesystem block less than the 2^32 sector limit.
 */
static loff_t ext3_max_size(int bits)
{
	loff_t res = EXT3_NDIR_BLOCKS;
	int meta_blocks;
	loff_t upper_limit;

	/* This is calculated to be the largest file size for a
	 * dense, file such that the total number of
	 * sectors in the file, including data and all indirect blocks,
	 * does not exceed 2^32 -1
	 * __u32 i_blocks representing the total number of
	 * 512 bytes blocks of the file
	 */
	upper_limit = (1LL << 32) - 1;

	/* total blocks in file system block size */
	upper_limit >>= (bits - 9);


	/* indirect blocks */
	meta_blocks = 1;
	/* double indirect blocks */
	meta_blocks += 1 + (1LL << (bits-2));
	/* tripple indirect blocks */
	meta_blocks += 1 + (1LL << (bits-2)) + (1LL << (2*(bits-2)));

	upper_limit -= meta_blocks;
	upper_limit <<= bits;

	res += 1LL << (bits-2);
	res += 1LL << (2*(bits-2));
	res += 1LL << (3*(bits-2));
	res <<= bits;
	if (res > upper_limit)
		res = upper_limit;

	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;

	return res;
}

static ext3_fsblk_t descriptor_loc(struct super_block *sb,
				    ext3_fsblk_t logic_sb_block,
				    int nr)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	unsigned long bg, first_meta_bg;
	int has_super = 0;

	first_meta_bg = le32_to_cpu(sbi->s_es->s_first_meta_bg);

	if (!EXT3_HAS_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_META_BG) ||
	    nr < first_meta_bg)
		return (logic_sb_block + nr + 1);
	bg = sbi->s_desc_per_block * nr;
	if (ext3_bg_has_super(sb, bg))
		has_super = 1;
	return (has_super + ext3_group_first_block_no(sb, bg));
}


static int ext3_fill_super (struct super_block *sb, void *data, int silent)
{
	struct buffer_head * bh;
	struct ext3_super_block *es = NULL;
	struct ext3_sb_info *sbi;
	ext3_fsblk_t block;
	ext3_fsblk_t sb_block = get_sb_block(&data, sb);
	ext3_fsblk_t logic_sb_block;
	unsigned long offset = 0;
	unsigned int journal_inum = 0;
	unsigned long journal_devnum = 0;
	unsigned long def_mount_opts;
	struct inode *root;
	int blocksize;
	int hblock;
	int db_count;
	int i;
	int needs_recovery;
	int ret = -EINVAL;
	__le32 features;
	int err;

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->s_blockgroup_lock =
		kzalloc(sizeof(struct blockgroup_lock), GFP_KERNEL);
	if (!sbi->s_blockgroup_lock) {
		kfree(sbi);
		return -ENOMEM;
	}
	sb->s_fs_info = sbi;
	sbi->s_sb_block = sb_block;

	blocksize = sb_min_blocksize(sb, EXT3_MIN_BLOCK_SIZE);
	if (!blocksize) {
		ext3_msg(sb, KERN_ERR, "error: unable to set blocksize");
		goto out_fail;
	}

	/*
	 * The ext3 superblock will not be buffer aligned for other than 1kB
	 * block sizes.  We need to calculate the offset from buffer start.
	 */
	if (blocksize != EXT3_MIN_BLOCK_SIZE) {
		logic_sb_block = (sb_block * EXT3_MIN_BLOCK_SIZE) / blocksize;
		offset = (sb_block * EXT3_MIN_BLOCK_SIZE) % blocksize;
	} else {
		logic_sb_block = sb_block;
	}

	if (!(bh = sb_bread(sb, logic_sb_block))) {
		ext3_msg(sb, KERN_ERR, "error: unable to read superblock");
		goto out_fail;
	}
	/*
	 * Note: s_es must be initialized as soon as possible because
	 *       some ext3 macro-instructions depend on its value
	 */
	es = (struct ext3_super_block *) (bh->b_data + offset);
	sbi->s_es = es;
	sb->s_magic = le16_to_cpu(es->s_magic);
	if (sb->s_magic != EXT3_SUPER_MAGIC)
		goto cantfind_ext3;

	/* Set defaults before we parse the mount options */
	def_mount_opts = le32_to_cpu(es->s_default_mount_opts);
	if (def_mount_opts & EXT3_DEFM_DEBUG)
		set_opt(sbi->s_mount_opt, DEBUG);
	if (def_mount_opts & EXT3_DEFM_BSDGROUPS)
		set_opt(sbi->s_mount_opt, GRPID);
	if (def_mount_opts & EXT3_DEFM_UID16)
		set_opt(sbi->s_mount_opt, NO_UID32);
#ifdef CONFIG_EXT3_FS_XATTR
	if (def_mount_opts & EXT3_DEFM_XATTR_USER)
		set_opt(sbi->s_mount_opt, XATTR_USER);
#endif
#ifdef CONFIG_EXT3_FS_POSIX_ACL
	if (def_mount_opts & EXT3_DEFM_ACL)
		set_opt(sbi->s_mount_opt, POSIX_ACL);
#endif
	if ((def_mount_opts & EXT3_DEFM_JMODE) == EXT3_DEFM_JMODE_DATA)
		set_opt(sbi->s_mount_opt, JOURNAL_DATA);
	else if ((def_mount_opts & EXT3_DEFM_JMODE) == EXT3_DEFM_JMODE_ORDERED)
		set_opt(sbi->s_mount_opt, ORDERED_DATA);
	else if ((def_mount_opts & EXT3_DEFM_JMODE) == EXT3_DEFM_JMODE_WBACK)
		set_opt(sbi->s_mount_opt, WRITEBACK_DATA);

	if (le16_to_cpu(sbi->s_es->s_errors) == EXT3_ERRORS_PANIC)
		set_opt(sbi->s_mount_opt, ERRORS_PANIC);
	else if (le16_to_cpu(sbi->s_es->s_errors) == EXT3_ERRORS_CONTINUE)
		set_opt(sbi->s_mount_opt, ERRORS_CONT);
	else
		set_opt(sbi->s_mount_opt, ERRORS_RO);

	sbi->s_resuid = make_kuid(&init_user_ns, le16_to_cpu(es->s_def_resuid));
	sbi->s_resgid = make_kgid(&init_user_ns, le16_to_cpu(es->s_def_resgid));

	/* enable barriers by default */
	set_opt(sbi->s_mount_opt, BARRIER);
	set_opt(sbi->s_mount_opt, RESERVATION);

	if (!parse_options ((char *) data, sb, &journal_inum, &journal_devnum,
			    NULL, 0))
		goto failed_mount;

	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		(test_opt(sb, POSIX_ACL) ? MS_POSIXACL : 0);

	if (le32_to_cpu(es->s_rev_level) == EXT3_GOOD_OLD_REV &&
	    (EXT3_HAS_COMPAT_FEATURE(sb, ~0U) ||
	     EXT3_HAS_RO_COMPAT_FEATURE(sb, ~0U) ||
	     EXT3_HAS_INCOMPAT_FEATURE(sb, ~0U)))
		ext3_msg(sb, KERN_WARNING,
			"warning: feature flags set on rev 0 fs, "
			"running e2fsck is recommended");
	/*
	 * Check feature flags regardless of the revision level, since we
	 * previously didn't change the revision level when setting the flags,
	 * so there is a chance incompat flags are set on a rev 0 filesystem.
	 */
	features = EXT3_HAS_INCOMPAT_FEATURE(sb, ~EXT3_FEATURE_INCOMPAT_SUPP);
	if (features) {
		ext3_msg(sb, KERN_ERR,
			"error: couldn't mount because of unsupported "
			"optional features (%x)", le32_to_cpu(features));
		goto failed_mount;
	}
	features = EXT3_HAS_RO_COMPAT_FEATURE(sb, ~EXT3_FEATURE_RO_COMPAT_SUPP);
	if (!(sb->s_flags & MS_RDONLY) && features) {
		ext3_msg(sb, KERN_ERR,
			"error: couldn't mount RDWR because of unsupported "
			"optional features (%x)", le32_to_cpu(features));
		goto failed_mount;
	}
	blocksize = BLOCK_SIZE << le32_to_cpu(es->s_log_block_size);

	if (blocksize < EXT3_MIN_BLOCK_SIZE ||
	    blocksize > EXT3_MAX_BLOCK_SIZE) {
		ext3_msg(sb, KERN_ERR,
			"error: couldn't mount because of unsupported "
			"filesystem blocksize %d", blocksize);
		goto failed_mount;
	}

	hblock = bdev_logical_block_size(sb->s_bdev);
	if (sb->s_blocksize != blocksize) {
		/*
		 * Make sure the blocksize for the filesystem is larger
		 * than the hardware sectorsize for the machine.
		 */
		if (blocksize < hblock) {
			ext3_msg(sb, KERN_ERR,
				"error: fsblocksize %d too small for "
				"hardware sectorsize %d", blocksize, hblock);
			goto failed_mount;
		}

		brelse (bh);
		if (!sb_set_blocksize(sb, blocksize)) {
			ext3_msg(sb, KERN_ERR,
				"error: bad blocksize %d", blocksize);
			goto out_fail;
		}
		logic_sb_block = (sb_block * EXT3_MIN_BLOCK_SIZE) / blocksize;
		offset = (sb_block * EXT3_MIN_BLOCK_SIZE) % blocksize;
		bh = sb_bread(sb, logic_sb_block);
		if (!bh) {
			ext3_msg(sb, KERN_ERR,
			       "error: can't read superblock on 2nd try");
			goto failed_mount;
		}
		es = (struct ext3_super_block *)(bh->b_data + offset);
		sbi->s_es = es;
		if (es->s_magic != cpu_to_le16(EXT3_SUPER_MAGIC)) {
			ext3_msg(sb, KERN_ERR,
				"error: magic mismatch");
			goto failed_mount;
		}
	}

	sb->s_maxbytes = ext3_max_size(sb->s_blocksize_bits);

	if (le32_to_cpu(es->s_rev_level) == EXT3_GOOD_OLD_REV) {
		sbi->s_inode_size = EXT3_GOOD_OLD_INODE_SIZE;
		sbi->s_first_ino = EXT3_GOOD_OLD_FIRST_INO;
	} else {
		sbi->s_inode_size = le16_to_cpu(es->s_inode_size);
		sbi->s_first_ino = le32_to_cpu(es->s_first_ino);
		if ((sbi->s_inode_size < EXT3_GOOD_OLD_INODE_SIZE) ||
		    (!is_power_of_2(sbi->s_inode_size)) ||
		    (sbi->s_inode_size > blocksize)) {
			ext3_msg(sb, KERN_ERR,
				"error: unsupported inode size: %d",
				sbi->s_inode_size);
			goto failed_mount;
		}
	}
	sbi->s_frag_size = EXT3_MIN_FRAG_SIZE <<
				   le32_to_cpu(es->s_log_frag_size);
	if (blocksize != sbi->s_frag_size) {
		ext3_msg(sb, KERN_ERR,
		       "error: fragsize %lu != blocksize %u (unsupported)",
		       sbi->s_frag_size, blocksize);
		goto failed_mount;
	}
	sbi->s_frags_per_block = 1;
	sbi->s_blocks_per_group = le32_to_cpu(es->s_blocks_per_group);
	sbi->s_frags_per_group = le32_to_cpu(es->s_frags_per_group);
	sbi->s_inodes_per_group = le32_to_cpu(es->s_inodes_per_group);
	if (EXT3_INODE_SIZE(sb) == 0 || EXT3_INODES_PER_GROUP(sb) == 0)
		goto cantfind_ext3;
	sbi->s_inodes_per_block = blocksize / EXT3_INODE_SIZE(sb);
	if (sbi->s_inodes_per_block == 0)
		goto cantfind_ext3;
	sbi->s_itb_per_group = sbi->s_inodes_per_group /
					sbi->s_inodes_per_block;
	sbi->s_desc_per_block = blocksize / sizeof(struct ext3_group_desc);
	sbi->s_sbh = bh;
	sbi->s_mount_state = le16_to_cpu(es->s_state);
	sbi->s_addr_per_block_bits = ilog2(EXT3_ADDR_PER_BLOCK(sb));
	sbi->s_desc_per_block_bits = ilog2(EXT3_DESC_PER_BLOCK(sb));
	for (i=0; i < 4; i++)
		sbi->s_hash_seed[i] = le32_to_cpu(es->s_hash_seed[i]);
	sbi->s_def_hash_version = es->s_def_hash_version;
	i = le32_to_cpu(es->s_flags);
	if (i & EXT2_FLAGS_UNSIGNED_HASH)
		sbi->s_hash_unsigned = 3;
	else if ((i & EXT2_FLAGS_SIGNED_HASH) == 0) {
#ifdef __CHAR_UNSIGNED__
		es->s_flags |= cpu_to_le32(EXT2_FLAGS_UNSIGNED_HASH);
		sbi->s_hash_unsigned = 3;
#else
		es->s_flags |= cpu_to_le32(EXT2_FLAGS_SIGNED_HASH);
#endif
	}

	if (sbi->s_blocks_per_group > blocksize * 8) {
		ext3_msg(sb, KERN_ERR,
			"#blocks per group too big: %lu",
			sbi->s_blocks_per_group);
		goto failed_mount;
	}
	if (sbi->s_frags_per_group > blocksize * 8) {
		ext3_msg(sb, KERN_ERR,
			"error: #fragments per group too big: %lu",
			sbi->s_frags_per_group);
		goto failed_mount;
	}
	if (sbi->s_inodes_per_group > blocksize * 8) {
		ext3_msg(sb, KERN_ERR,
			"error: #inodes per group too big: %lu",
			sbi->s_inodes_per_group);
		goto failed_mount;
	}

	err = generic_check_addressable(sb->s_blocksize_bits,
					le32_to_cpu(es->s_blocks_count));
	if (err) {
		ext3_msg(sb, KERN_ERR,
			"error: filesystem is too large to mount safely");
		if (sizeof(sector_t) < 8)
			ext3_msg(sb, KERN_ERR,
				"error: CONFIG_LBDAF not enabled");
		ret = err;
		goto failed_mount;
	}

	if (EXT3_BLOCKS_PER_GROUP(sb) == 0)
		goto cantfind_ext3;
	sbi->s_groups_count = ((le32_to_cpu(es->s_blocks_count) -
			       le32_to_cpu(es->s_first_data_block) - 1)
				       / EXT3_BLOCKS_PER_GROUP(sb)) + 1;
	db_count = DIV_ROUND_UP(sbi->s_groups_count, EXT3_DESC_PER_BLOCK(sb));
	sbi->s_group_desc = kmalloc(db_count * sizeof (struct buffer_head *),
				    GFP_KERNEL);
	if (sbi->s_group_desc == NULL) {
		ext3_msg(sb, KERN_ERR,
			"error: not enough memory");
		ret = -ENOMEM;
		goto failed_mount;
	}

	bgl_lock_init(sbi->s_blockgroup_lock);

	for (i = 0; i < db_count; i++) {
		block = descriptor_loc(sb, logic_sb_block, i);
		sbi->s_group_desc[i] = sb_bread(sb, block);
		if (!sbi->s_group_desc[i]) {
			ext3_msg(sb, KERN_ERR,
				"error: can't read group descriptor %d", i);
			db_count = i;
			goto failed_mount2;
		}
	}
	if (!ext3_check_descriptors (sb)) {
		ext3_msg(sb, KERN_ERR,
			"error: group descriptors corrupted");
		goto failed_mount2;
	}
	sbi->s_gdb_count = db_count;
	get_random_bytes(&sbi->s_next_generation, sizeof(u32));
	spin_lock_init(&sbi->s_next_gen_lock);

	/* per fileystem reservation list head & lock */
	spin_lock_init(&sbi->s_rsv_window_lock);
	sbi->s_rsv_window_root = RB_ROOT;
	/* Add a single, static dummy reservation to the start of the
	 * reservation window list --- it gives us a placeholder for
	 * append-at-start-of-list which makes the allocation logic
	 * _much_ simpler. */
	sbi->s_rsv_window_head.rsv_start = EXT3_RESERVE_WINDOW_NOT_ALLOCATED;
	sbi->s_rsv_window_head.rsv_end = EXT3_RESERVE_WINDOW_NOT_ALLOCATED;
	sbi->s_rsv_window_head.rsv_alloc_hit = 0;
	sbi->s_rsv_window_head.rsv_goal_size = 0;
	ext3_rsv_window_add(sb, &sbi->s_rsv_window_head);

	/*
	 * set up enough so that it can read an inode
	 */
	sb->s_op = &ext3_sops;
	sb->s_export_op = &ext3_export_ops;
	sb->s_xattr = ext3_xattr_handlers;
#ifdef CONFIG_QUOTA
	sb->s_qcop = &ext3_qctl_operations;
	sb->dq_op = &ext3_quota_operations;
	sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP;
#endif
	memcpy(sb->s_uuid, es->s_uuid, sizeof(es->s_uuid));
	INIT_LIST_HEAD(&sbi->s_orphan); /* unlinked but open files */
	mutex_init(&sbi->s_orphan_lock);
	mutex_init(&sbi->s_resize_lock);

	sb->s_root = NULL;

	needs_recovery = (es->s_last_orphan != 0 ||
			  EXT3_HAS_INCOMPAT_FEATURE(sb,
				    EXT3_FEATURE_INCOMPAT_RECOVER));

	/*
	 * The first inode we look at is the journal inode.  Don't try
	 * root first: it may be modified in the journal!
	 */
	if (!test_opt(sb, NOLOAD) &&
	    EXT3_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_HAS_JOURNAL)) {
		if (ext3_load_journal(sb, es, journal_devnum))
			goto failed_mount2;
	} else if (journal_inum) {
		if (ext3_create_journal(sb, es, journal_inum))
			goto failed_mount2;
	} else {
		if (!silent)
			ext3_msg(sb, KERN_ERR,
				"error: no journal found. "
				"mounting ext3 over ext2?");
		goto failed_mount2;
	}
	err = percpu_counter_init(&sbi->s_freeblocks_counter,
			ext3_count_free_blocks(sb), GFP_KERNEL);
	if (!err) {
		err = percpu_counter_init(&sbi->s_freeinodes_counter,
				ext3_count_free_inodes(sb), GFP_KERNEL);
	}
	if (!err) {
		err = percpu_counter_init(&sbi->s_dirs_counter,
				ext3_count_dirs(sb), GFP_KERNEL);
	}
	if (err) {
		ext3_msg(sb, KERN_ERR, "error: insufficient memory");
		ret = err;
		goto failed_mount3;
	}

	/* We have now updated the journal if required, so we can
	 * validate the data journaling mode. */
	switch (test_opt(sb, DATA_FLAGS)) {
	case 0:
		/* No mode set, assume a default based on the journal
                   capabilities: ORDERED_DATA if the journal can
                   cope, else JOURNAL_DATA */
		if (journal_check_available_features
		    (sbi->s_journal, 0, 0, JFS_FEATURE_INCOMPAT_REVOKE))
			set_opt(sbi->s_mount_opt, DEFAULT_DATA_MODE);
		else
			set_opt(sbi->s_mount_opt, JOURNAL_DATA);
		break;

	case EXT3_MOUNT_ORDERED_DATA:
	case EXT3_MOUNT_WRITEBACK_DATA:
		if (!journal_check_available_features
		    (sbi->s_journal, 0, 0, JFS_FEATURE_INCOMPAT_REVOKE)) {
			ext3_msg(sb, KERN_ERR,
				"error: journal does not support "
				"requested data journaling mode");
			goto failed_mount3;
		}
	default:
		break;
	}

	/*
	 * The journal_load will have done any necessary log recovery,
	 * so we can safely mount the rest of the filesystem now.
	 */

	root = ext3_iget(sb, EXT3_ROOT_INO);
	if (IS_ERR(root)) {
		ext3_msg(sb, KERN_ERR, "error: get root inode failed");
		ret = PTR_ERR(root);
		goto failed_mount3;
	}
	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		iput(root);
		ext3_msg(sb, KERN_ERR, "error: corrupt root inode, run e2fsck");
		goto failed_mount3;
	}
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		ext3_msg(sb, KERN_ERR, "error: get root dentry failed");
		ret = -ENOMEM;
		goto failed_mount3;
	}

	if (ext3_setup_super(sb, es, sb->s_flags & MS_RDONLY))
		sb->s_flags |= MS_RDONLY;

	EXT3_SB(sb)->s_mount_state |= EXT3_ORPHAN_FS;
	ext3_orphan_cleanup(sb, es);
	EXT3_SB(sb)->s_mount_state &= ~EXT3_ORPHAN_FS;
	if (needs_recovery) {
		ext3_mark_recovery_complete(sb, es);
		ext3_msg(sb, KERN_INFO, "recovery complete");
	}
	ext3_msg(sb, KERN_INFO, "mounted filesystem with %s data mode",
		test_opt(sb,DATA_FLAGS) == EXT3_MOUNT_JOURNAL_DATA ? "journal":
		test_opt(sb,DATA_FLAGS) == EXT3_MOUNT_ORDERED_DATA ? "ordered":
		"writeback");

	return 0;

cantfind_ext3:
	if (!silent)
		ext3_msg(sb, KERN_INFO,
			"error: can't find ext3 filesystem on dev %s.",
		       sb->s_id);
	goto failed_mount;

failed_mount3:
	percpu_counter_destroy(&sbi->s_freeblocks_counter);
	percpu_counter_destroy(&sbi->s_freeinodes_counter);
	percpu_counter_destroy(&sbi->s_dirs_counter);
	journal_destroy(sbi->s_journal);
failed_mount2:
	for (i = 0; i < db_count; i++)
		brelse(sbi->s_group_desc[i]);
	kfree(sbi->s_group_desc);
failed_mount:
#ifdef CONFIG_QUOTA
	for (i = 0; i < EXT3_MAXQUOTAS; i++)
		kfree(sbi->s_qf_names[i]);
#endif
	ext3_blkdev_remove(sbi);
	brelse(bh);
out_fail:
	sb->s_fs_info = NULL;
	kfree(sbi->s_blockgroup_lock);
	kfree(sbi);
	return ret;
}

/*
 * Setup any per-fs journal parameters now.  We'll do this both on
 * initial mount, once the journal has been initialised but before we've
 * done any recovery; and again on any subsequent remount.
 */
static void ext3_init_journal_params(struct super_block *sb, journal_t *journal)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);

	if (sbi->s_commit_interval)
		journal->j_commit_interval = sbi->s_commit_interval;
	/* We could also set up an ext3-specific default for the commit
	 * interval here, but for now we'll just fall back to the jbd
	 * default. */

	spin_lock(&journal->j_state_lock);
	if (test_opt(sb, BARRIER))
		journal->j_flags |= JFS_BARRIER;
	else
		journal->j_flags &= ~JFS_BARRIER;
	if (test_opt(sb, DATA_ERR_ABORT))
		journal->j_flags |= JFS_ABORT_ON_SYNCDATA_ERR;
	else
		journal->j_flags &= ~JFS_ABORT_ON_SYNCDATA_ERR;
	spin_unlock(&journal->j_state_lock);
}

static journal_t *ext3_get_journal(struct super_block *sb,
				   unsigned int journal_inum)
{
	struct inode *journal_inode;
	journal_t *journal;

	/* First, test for the existence of a valid inode on disk.  Bad
	 * things happen if we iget() an unused inode, as the subsequent
	 * iput() will try to delete it. */

	journal_inode = ext3_iget(sb, journal_inum);
	if (IS_ERR(journal_inode)) {
		ext3_msg(sb, KERN_ERR, "error: no journal found");
		return NULL;
	}
	if (!journal_inode->i_nlink) {
		make_bad_inode(journal_inode);
		iput(journal_inode);
		ext3_msg(sb, KERN_ERR, "error: journal inode is deleted");
		return NULL;
	}

	jbd_debug(2, "Journal inode found at %p: %Ld bytes\n",
		  journal_inode, journal_inode->i_size);
	if (!S_ISREG(journal_inode->i_mode)) {
		ext3_msg(sb, KERN_ERR, "error: invalid journal inode");
		iput(journal_inode);
		return NULL;
	}

	journal = journal_init_inode(journal_inode);
	if (!journal) {
		ext3_msg(sb, KERN_ERR, "error: could not load journal inode");
		iput(journal_inode);
		return NULL;
	}
	journal->j_private = sb;
	ext3_init_journal_params(sb, journal);
	return journal;
}

static journal_t *ext3_get_dev_journal(struct super_block *sb,
				       dev_t j_dev)
{
	struct buffer_head * bh;
	journal_t *journal;
	ext3_fsblk_t start;
	ext3_fsblk_t len;
	int hblock, blocksize;
	ext3_fsblk_t sb_block;
	unsigned long offset;
	struct ext3_super_block * es;
	struct block_device *bdev;

	bdev = ext3_blkdev_get(j_dev, sb);
	if (bdev == NULL)
		return NULL;

	blocksize = sb->s_blocksize;
	hblock = bdev_logical_block_size(bdev);
	if (blocksize < hblock) {
		ext3_msg(sb, KERN_ERR,
			"error: blocksize too small for journal device");
		goto out_bdev;
	}

	sb_block = EXT3_MIN_BLOCK_SIZE / blocksize;
	offset = EXT3_MIN_BLOCK_SIZE % blocksize;
	set_blocksize(bdev, blocksize);
	if (!(bh = __bread(bdev, sb_block, blocksize))) {
		ext3_msg(sb, KERN_ERR, "error: couldn't read superblock of "
			"external journal");
		goto out_bdev;
	}

	es = (struct ext3_super_block *) (bh->b_data + offset);
	if ((le16_to_cpu(es->s_magic) != EXT3_SUPER_MAGIC) ||
	    !(le32_to_cpu(es->s_feature_incompat) &
	      EXT3_FEATURE_INCOMPAT_JOURNAL_DEV)) {
		ext3_msg(sb, KERN_ERR, "error: external journal has "
			"bad superblock");
		brelse(bh);
		goto out_bdev;
	}

	if (memcmp(EXT3_SB(sb)->s_es->s_journal_uuid, es->s_uuid, 16)) {
		ext3_msg(sb, KERN_ERR, "error: journal UUID does not match");
		brelse(bh);
		goto out_bdev;
	}

	len = le32_to_cpu(es->s_blocks_count);
	start = sb_block + 1;
	brelse(bh);	/* we're done with the superblock */

	journal = journal_init_dev(bdev, sb->s_bdev,
					start, len, blocksize);
	if (!journal) {
		ext3_msg(sb, KERN_ERR,
			"error: failed to create device journal");
		goto out_bdev;
	}
	journal->j_private = sb;
	if (!bh_uptodate_or_lock(journal->j_sb_buffer)) {
		if (bh_submit_read(journal->j_sb_buffer)) {
			ext3_msg(sb, KERN_ERR, "I/O error on journal device");
			goto out_journal;
		}
	}
	if (be32_to_cpu(journal->j_superblock->s_nr_users) != 1) {
		ext3_msg(sb, KERN_ERR,
			"error: external journal has more than one "
			"user (unsupported) - %d",
			be32_to_cpu(journal->j_superblock->s_nr_users));
		goto out_journal;
	}
	EXT3_SB(sb)->journal_bdev = bdev;
	ext3_init_journal_params(sb, journal);
	return journal;
out_journal:
	journal_destroy(journal);
out_bdev:
	ext3_blkdev_put(bdev);
	return NULL;
}

static int ext3_load_journal(struct super_block *sb,
			     struct ext3_super_block *es,
			     unsigned long journal_devnum)
{
	journal_t *journal;
	unsigned int journal_inum = le32_to_cpu(es->s_journal_inum);
	dev_t journal_dev;
	int err = 0;
	int really_read_only;

	if (journal_devnum &&
	    journal_devnum != le32_to_cpu(es->s_journal_dev)) {
		ext3_msg(sb, KERN_INFO, "external journal device major/minor "
			"numbers have changed");
		journal_dev = new_decode_dev(journal_devnum);
	} else
		journal_dev = new_decode_dev(le32_to_cpu(es->s_journal_dev));

	really_read_only = bdev_read_only(sb->s_bdev);

	/*
	 * Are we loading a blank journal or performing recovery after a
	 * crash?  For recovery, we need to check in advance whether we
	 * can get read-write access to the device.
	 */

	if (EXT3_HAS_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_RECOVER)) {
		if (sb->s_flags & MS_RDONLY) {
			ext3_msg(sb, KERN_INFO,
				"recovery required on readonly filesystem");
			if (really_read_only) {
				ext3_msg(sb, KERN_ERR, "error: write access "
					"unavailable, cannot proceed");
				return -EROFS;
			}
			ext3_msg(sb, KERN_INFO,
				"write access will be enabled during recovery");
		}
	}

	if (journal_inum && journal_dev) {
		ext3_msg(sb, KERN_ERR, "error: filesystem has both journal "
		       "and inode journals");
		return -EINVAL;
	}

	if (journal_inum) {
		if (!(journal = ext3_get_journal(sb, journal_inum)))
			return -EINVAL;
	} else {
		if (!(journal = ext3_get_dev_journal(sb, journal_dev)))
			return -EINVAL;
	}

	if (!(journal->j_flags & JFS_BARRIER))
		printk(KERN_INFO "EXT3-fs: barriers not enabled\n");

	if (!really_read_only && test_opt(sb, UPDATE_JOURNAL)) {
		err = journal_update_format(journal);
		if (err)  {
			ext3_msg(sb, KERN_ERR, "error updating journal");
			journal_destroy(journal);
			return err;
		}
	}

	if (!EXT3_HAS_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_RECOVER))
		err = journal_wipe(journal, !really_read_only);
	if (!err)
		err = journal_load(journal);

	if (err) {
		ext3_msg(sb, KERN_ERR, "error loading journal");
		journal_destroy(journal);
		return err;
	}

	EXT3_SB(sb)->s_journal = journal;
	ext3_clear_journal_err(sb, es);

	if (!really_read_only && journal_devnum &&
	    journal_devnum != le32_to_cpu(es->s_journal_dev)) {
		es->s_journal_dev = cpu_to_le32(journal_devnum);

		/* Make sure we flush the recovery flag to disk. */
		ext3_commit_super(sb, es, 1);
	}

	return 0;
}

static int ext3_create_journal(struct super_block *sb,
			       struct ext3_super_block *es,
			       unsigned int journal_inum)
{
	journal_t *journal;
	int err;

	if (sb->s_flags & MS_RDONLY) {
		ext3_msg(sb, KERN_ERR,
			"error: readonly filesystem when trying to "
			"create journal");
		return -EROFS;
	}

	journal = ext3_get_journal(sb, journal_inum);
	if (!journal)
		return -EINVAL;

	ext3_msg(sb, KERN_INFO, "creating new journal on inode %u",
	       journal_inum);

	err = journal_create(journal);
	if (err) {
		ext3_msg(sb, KERN_ERR, "error creating journal");
		journal_destroy(journal);
		return -EIO;
	}

	EXT3_SB(sb)->s_journal = journal;

	ext3_update_dynamic_rev(sb);
	EXT3_SET_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_RECOVER);
	EXT3_SET_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_HAS_JOURNAL);

	es->s_journal_inum = cpu_to_le32(journal_inum);

	/* Make sure we flush the recovery flag to disk. */
	ext3_commit_super(sb, es, 1);

	return 0;
}

static int ext3_commit_super(struct super_block *sb,
			       struct ext3_super_block *es,
			       int sync)
{
	struct buffer_head *sbh = EXT3_SB(sb)->s_sbh;
	int error = 0;

	if (!sbh)
		return error;

	if (buffer_write_io_error(sbh)) {
		/*
		 * Oh, dear.  A previous attempt to write the
		 * superblock failed.  This could happen because the
		 * USB device was yanked out.  Or it could happen to
		 * be a transient write error and maybe the block will
		 * be remapped.  Nothing we can do but to retry the
		 * write and hope for the best.
		 */
		ext3_msg(sb, KERN_ERR, "previous I/O error to "
		       "superblock detected");
		clear_buffer_write_io_error(sbh);
		set_buffer_uptodate(sbh);
	}
	/*
	 * If the file system is mounted read-only, don't update the
	 * superblock write time.  This avoids updating the superblock
	 * write time when we are mounting the root file system
	 * read/only but we need to replay the journal; at that point,
	 * for people who are east of GMT and who make their clock
	 * tick in localtime for Windows bug-for-bug compatibility,
	 * the clock is set in the future, and this will cause e2fsck
	 * to complain and force a full file system check.
	 */
	if (!(sb->s_flags & MS_RDONLY))
		es->s_wtime = cpu_to_le32(get_seconds());
	es->s_free_blocks_count = cpu_to_le32(ext3_count_free_blocks(sb));
	es->s_free_inodes_count = cpu_to_le32(ext3_count_free_inodes(sb));
	BUFFER_TRACE(sbh, "marking dirty");
	mark_buffer_dirty(sbh);
	if (sync) {
		error = sync_dirty_buffer(sbh);
		if (buffer_write_io_error(sbh)) {
			ext3_msg(sb, KERN_ERR, "I/O error while writing "
			       "superblock");
			clear_buffer_write_io_error(sbh);
			set_buffer_uptodate(sbh);
		}
	}
	return error;
}


/*
 * Have we just finished recovery?  If so, and if we are mounting (or
 * remounting) the filesystem readonly, then we will end up with a
 * consistent fs on disk.  Record that fact.
 */
static void ext3_mark_recovery_complete(struct super_block * sb,
					struct ext3_super_block * es)
{
	journal_t *journal = EXT3_SB(sb)->s_journal;

	journal_lock_updates(journal);
	if (journal_flush(journal) < 0)
		goto out;

	if (EXT3_HAS_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_RECOVER) &&
	    sb->s_flags & MS_RDONLY) {
		EXT3_CLEAR_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_RECOVER);
		ext3_commit_super(sb, es, 1);
	}

out:
	journal_unlock_updates(journal);
}

/*
 * If we are mounting (or read-write remounting) a filesystem whose journal
 * has recorded an error from a previous lifetime, move that error to the
 * main filesystem now.
 */
static void ext3_clear_journal_err(struct super_block *sb,
				   struct ext3_super_block *es)
{
	journal_t *journal;
	int j_errno;
	const char *errstr;

	journal = EXT3_SB(sb)->s_journal;

	/*
	 * Now check for any error status which may have been recorded in the
	 * journal by a prior ext3_error() or ext3_abort()
	 */

	j_errno = journal_errno(journal);
	if (j_errno) {
		char nbuf[16];

		errstr = ext3_decode_error(sb, j_errno, nbuf);
		ext3_warning(sb, __func__, "Filesystem error recorded "
			     "from previous mount: %s", errstr);
		ext3_warning(sb, __func__, "Marking fs in need of "
			     "filesystem check.");

		EXT3_SB(sb)->s_mount_state |= EXT3_ERROR_FS;
		es->s_state |= cpu_to_le16(EXT3_ERROR_FS);
		ext3_commit_super (sb, es, 1);

		journal_clear_err(journal);
	}
}

/*
 * Force the running and committing transactions to commit,
 * and wait on the commit.
 */
int ext3_force_commit(struct super_block *sb)
{
	journal_t *journal;
	int ret;

	if (sb->s_flags & MS_RDONLY)
		return 0;

	journal = EXT3_SB(sb)->s_journal;
	ret = ext3_journal_force_commit(journal);
	return ret;
}

static int ext3_sync_fs(struct super_block *sb, int wait)
{
	tid_t target;

	trace_ext3_sync_fs(sb, wait);
	/*
	 * Writeback quota in non-journalled quota case - journalled quota has
	 * no dirty dquots
	 */
	dquot_writeback_dquots(sb, -1);
	if (journal_start_commit(EXT3_SB(sb)->s_journal, &target)) {
		if (wait)
			log_wait_commit(EXT3_SB(sb)->s_journal, target);
	}
	return 0;
}

/*
 * LVM calls this function before a (read-only) snapshot is created.  This
 * gives us a chance to flush the journal completely and mark the fs clean.
 */
static int ext3_freeze(struct super_block *sb)
{
	int error = 0;
	journal_t *journal;

	if (!(sb->s_flags & MS_RDONLY)) {
		journal = EXT3_SB(sb)->s_journal;

		/* Now we set up the journal barrier. */
		journal_lock_updates(journal);

		/*
		 * We don't want to clear needs_recovery flag when we failed
		 * to flush the journal.
		 */
		error = journal_flush(journal);
		if (error < 0)
			goto out;

		/* Journal blocked and flushed, clear needs_recovery flag. */
		EXT3_CLEAR_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_RECOVER);
		error = ext3_commit_super(sb, EXT3_SB(sb)->s_es, 1);
		if (error)
			goto out;
	}
	return 0;

out:
	journal_unlock_updates(journal);
	return error;
}

/*
 * Called by LVM after the snapshot is done.  We need to reset the RECOVER
 * flag here, even though the filesystem is not technically dirty yet.
 */
static int ext3_unfreeze(struct super_block *sb)
{
	if (!(sb->s_flags & MS_RDONLY)) {
		/* Reser the needs_recovery flag before the fs is unlocked. */
		EXT3_SET_INCOMPAT_FEATURE(sb, EXT3_FEATURE_INCOMPAT_RECOVER);
		ext3_commit_super(sb, EXT3_SB(sb)->s_es, 1);
		journal_unlock_updates(EXT3_SB(sb)->s_journal);
	}
	return 0;
}

static int ext3_remount (struct super_block * sb, int * flags, char * data)
{
	struct ext3_super_block * es;
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	ext3_fsblk_t n_blocks_count = 0;
	unsigned long old_sb_flags;
	struct ext3_mount_options old_opts;
	int enable_quota = 0;
	int err;
#ifdef CONFIG_QUOTA
	int i;
#endif

	sync_filesystem(sb);

	/* Store the original options */
	old_sb_flags = sb->s_flags;
	old_opts.s_mount_opt = sbi->s_mount_opt;
	old_opts.s_resuid = sbi->s_resuid;
	old_opts.s_resgid = sbi->s_resgid;
	old_opts.s_commit_interval = sbi->s_commit_interval;
#ifdef CONFIG_QUOTA
	old_opts.s_jquota_fmt = sbi->s_jquota_fmt;
	for (i = 0; i < EXT3_MAXQUOTAS; i++)
		if (sbi->s_qf_names[i]) {
			old_opts.s_qf_names[i] = kstrdup(sbi->s_qf_names[i],
							 GFP_KERNEL);
			if (!old_opts.s_qf_names[i]) {
				int j;

				for (j = 0; j < i; j++)
					kfree(old_opts.s_qf_names[j]);
				return -ENOMEM;
			}
		} else
			old_opts.s_qf_names[i] = NULL;
#endif

	/*
	 * Allow the "check" option to be passed as a remount option.
	 */
	if (!parse_options(data, sb, NULL, NULL, &n_blocks_count, 1)) {
		err = -EINVAL;
		goto restore_opts;
	}

	if (test_opt(sb, ABORT))
		ext3_abort(sb, __func__, "Abort forced by user");

	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		(test_opt(sb, POSIX_ACL) ? MS_POSIXACL : 0);

	es = sbi->s_es;

	ext3_init_journal_params(sb, sbi->s_journal);

	if ((*flags & MS_RDONLY) != (sb->s_flags & MS_RDONLY) ||
		n_blocks_count > le32_to_cpu(es->s_blocks_count)) {
		if (test_opt(sb, ABORT)) {
			err = -EROFS;
			goto restore_opts;
		}

		if (*flags & MS_RDONLY) {
			err = dquot_suspend(sb, -1);
			if (err < 0)
				goto restore_opts;

			/*
			 * First of all, the unconditional stuff we have to do
			 * to disable replay of the journal when we next remount
			 */
			sb->s_flags |= MS_RDONLY;

			/*
			 * OK, test if we are remounting a valid rw partition
			 * readonly, and if so set the rdonly flag and then
			 * mark the partition as valid again.
			 */
			if (!(es->s_state & cpu_to_le16(EXT3_VALID_FS)) &&
			    (sbi->s_mount_state & EXT3_VALID_FS))
				es->s_state = cpu_to_le16(sbi->s_mount_state);

			ext3_mark_recovery_complete(sb, es);
		} else {
			__le32 ret;
			if ((ret = EXT3_HAS_RO_COMPAT_FEATURE(sb,
					~EXT3_FEATURE_RO_COMPAT_SUPP))) {
				ext3_msg(sb, KERN_WARNING,
					"warning: couldn't remount RDWR "
					"because of unsupported optional "
					"features (%x)", le32_to_cpu(ret));
				err = -EROFS;
				goto restore_opts;
			}

			/*
			 * If we have an unprocessed orphan list hanging
			 * around from a previously readonly bdev mount,
			 * require a full umount & mount for now.
			 */
			if (es->s_last_orphan) {
				ext3_msg(sb, KERN_WARNING, "warning: couldn't "
				       "remount RDWR because of unprocessed "
				       "orphan inode list.  Please "
				       "umount & mount instead.");
				err = -EINVAL;
				goto restore_opts;
			}

			/*
			 * Mounting a RDONLY partition read-write, so reread
			 * and store the current valid flag.  (It may have
			 * been changed by e2fsck since we originally mounted
			 * the partition.)
			 */
			ext3_clear_journal_err(sb, es);
			sbi->s_mount_state = le16_to_cpu(es->s_state);
			if ((err = ext3_group_extend(sb, es, n_blocks_count)))
				goto restore_opts;
			if (!ext3_setup_super (sb, es, 0))
				sb->s_flags &= ~MS_RDONLY;
			enable_quota = 1;
		}
	}
#ifdef CONFIG_QUOTA
	/* Release old quota file names */
	for (i = 0; i < EXT3_MAXQUOTAS; i++)
		kfree(old_opts.s_qf_names[i]);
#endif
	if (enable_quota)
		dquot_resume(sb, -1);
	return 0;
restore_opts:
	sb->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_opts.s_mount_opt;
	sbi->s_resuid = old_opts.s_resuid;
	sbi->s_resgid = old_opts.s_resgid;
	sbi->s_commit_interval = old_opts.s_commit_interval;
#ifdef CONFIG_QUOTA
	sbi->s_jquota_fmt = old_opts.s_jquota_fmt;
	for (i = 0; i < EXT3_MAXQUOTAS; i++) {
		kfree(sbi->s_qf_names[i]);
		sbi->s_qf_names[i] = old_opts.s_qf_names[i];
	}
#endif
	return err;
}

static int ext3_statfs (struct dentry * dentry, struct kstatfs * buf)
{
	struct super_block *sb = dentry->d_sb;
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	struct ext3_super_block *es = sbi->s_es;
	u64 fsid;

	if (test_opt(sb, MINIX_DF)) {
		sbi->s_overhead_last = 0;
	} else if (sbi->s_blocks_last != le32_to_cpu(es->s_blocks_count)) {
		unsigned long ngroups = sbi->s_groups_count, i;
		ext3_fsblk_t overhead = 0;
		smp_rmb();

		/*
		 * Compute the overhead (FS structures).  This is constant
		 * for a given filesystem unless the number of block groups
		 * changes so we cache the previous value until it does.
		 */

		/*
		 * All of the blocks before first_data_block are
		 * overhead
		 */
		overhead = le32_to_cpu(es->s_first_data_block);

		/*
		 * Add the overhead attributed to the superblock and
		 * block group descriptors.  If the sparse superblocks
		 * feature is turned on, then not all groups have this.
		 */
		for (i = 0; i < ngroups; i++) {
			overhead += ext3_bg_has_super(sb, i) +
				ext3_bg_num_gdb(sb, i);
			cond_resched();
		}

		/*
		 * Every block group has an inode bitmap, a block
		 * bitmap, and an inode table.
		 */
		overhead += ngroups * (2 + sbi->s_itb_per_group);

		/* Add the internal journal blocks as well */
		if (sbi->s_journal && !sbi->journal_bdev)
			overhead += sbi->s_journal->j_maxlen;

		sbi->s_overhead_last = overhead;
		smp_wmb();
		sbi->s_blocks_last = le32_to_cpu(es->s_blocks_count);
	}

	buf->f_type = EXT3_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = le32_to_cpu(es->s_blocks_count) - sbi->s_overhead_last;
	buf->f_bfree = percpu_counter_sum_positive(&sbi->s_freeblocks_counter);
	buf->f_bavail = buf->f_bfree - le32_to_cpu(es->s_r_blocks_count);
	if (buf->f_bfree < le32_to_cpu(es->s_r_blocks_count))
		buf->f_bavail = 0;
	buf->f_files = le32_to_cpu(es->s_inodes_count);
	buf->f_ffree = percpu_counter_sum_positive(&sbi->s_freeinodes_counter);
	buf->f_namelen = EXT3_NAME_LEN;
	fsid = le64_to_cpup((void *)es->s_uuid) ^
	       le64_to_cpup((void *)es->s_uuid + sizeof(u64));
	buf->f_fsid.val[0] = fsid & 0xFFFFFFFFUL;
	buf->f_fsid.val[1] = (fsid >> 32) & 0xFFFFFFFFUL;
	return 0;
}

/* Helper function for writing quotas on sync - we need to start transaction before quota file
 * is locked for write. Otherwise the are possible deadlocks:
 * Process 1                         Process 2
 * ext3_create()                     quota_sync()
 *   journal_start()                   write_dquot()
 *   dquot_initialize()                       down(dqio_mutex)
 *     down(dqio_mutex)                    journal_start()
 *
 */

#ifdef CONFIG_QUOTA

static inline struct inode *dquot_to_inode(struct dquot *dquot)
{
	return sb_dqopt(dquot->dq_sb)->files[dquot->dq_id.type];
}

static int ext3_write_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;
	struct inode *inode;

	inode = dquot_to_inode(dquot);
	handle = ext3_journal_start(inode,
					EXT3_QUOTA_TRANS_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_commit(dquot);
	err = ext3_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int ext3_acquire_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;

	handle = ext3_journal_start(dquot_to_inode(dquot),
					EXT3_QUOTA_INIT_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_acquire(dquot);
	err = ext3_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int ext3_release_dquot(struct dquot *dquot)
{
	int ret, err;
	handle_t *handle;

	handle = ext3_journal_start(dquot_to_inode(dquot),
					EXT3_QUOTA_DEL_BLOCKS(dquot->dq_sb));
	if (IS_ERR(handle)) {
		/* Release dquot anyway to avoid endless cycle in dqput() */
		dquot_release(dquot);
		return PTR_ERR(handle);
	}
	ret = dquot_release(dquot);
	err = ext3_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

static int ext3_mark_dquot_dirty(struct dquot *dquot)
{
	/* Are we journaling quotas? */
	if (EXT3_SB(dquot->dq_sb)->s_qf_names[USRQUOTA] ||
	    EXT3_SB(dquot->dq_sb)->s_qf_names[GRPQUOTA]) {
		dquot_mark_dquot_dirty(dquot);
		return ext3_write_dquot(dquot);
	} else {
		return dquot_mark_dquot_dirty(dquot);
	}
}

static int ext3_write_info(struct super_block *sb, int type)
{
	int ret, err;
	handle_t *handle;

	/* Data block + inode block */
	handle = ext3_journal_start(sb->s_root->d_inode, 2);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = dquot_commit_info(sb, type);
	err = ext3_journal_stop(handle);
	if (!ret)
		ret = err;
	return ret;
}

/*
 * Turn on quotas during mount time - we need to find
 * the quota file and such...
 */
static int ext3_quota_on_mount(struct super_block *sb, int type)
{
	return dquot_quota_on_mount(sb, EXT3_SB(sb)->s_qf_names[type],
					EXT3_SB(sb)->s_jquota_fmt, type);
}

/*
 * Standard function to be called on quota_on
 */
static int ext3_quota_on(struct super_block *sb, int type, int format_id,
			 struct path *path)
{
	int err;

	if (!test_opt(sb, QUOTA))
		return -EINVAL;

	/* Quotafile not on the same filesystem? */
	if (path->dentry->d_sb != sb)
		return -EXDEV;
	/* Journaling quota? */
	if (EXT3_SB(sb)->s_qf_names[type]) {
		/* Quotafile not of fs root? */
		if (path->dentry->d_parent != sb->s_root)
			ext3_msg(sb, KERN_WARNING,
				"warning: Quota file not on filesystem root. "
				"Journaled quota will not work.");
	}

	/*
	 * When we journal data on quota file, we have to flush journal to see
	 * all updates to the file when we bypass pagecache...
	 */
	if (ext3_should_journal_data(path->dentry->d_inode)) {
		/*
		 * We don't need to lock updates but journal_flush() could
		 * otherwise be livelocked...
		 */
		journal_lock_updates(EXT3_SB(sb)->s_journal);
		err = journal_flush(EXT3_SB(sb)->s_journal);
		journal_unlock_updates(EXT3_SB(sb)->s_journal);
		if (err)
			return err;
	}

	return dquot_quota_on(sb, type, format_id, path);
}

/* Read data from quotafile - avoid pagecache and such because we cannot afford
 * acquiring the locks... As quota files are never truncated and quota code
 * itself serializes the operations (and no one else should touch the files)
 * we don't have to be afraid of races */
static ssize_t ext3_quota_read(struct super_block *sb, int type, char *data,
			       size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	sector_t blk = off >> EXT3_BLOCK_SIZE_BITS(sb);
	int err = 0;
	int offset = off & (sb->s_blocksize - 1);
	int tocopy;
	size_t toread;
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
		bh = ext3_bread(NULL, inode, blk, 0, &err);
		if (err)
			return err;
		if (!bh)	/* A hole? */
			memset(data, 0, tocopy);
		else
			memcpy(data, bh->b_data+offset, tocopy);
		brelse(bh);
		offset = 0;
		toread -= tocopy;
		data += tocopy;
		blk++;
	}
	return len;
}

/* Write to quotafile (we know the transaction is already started and has
 * enough credits) */
static ssize_t ext3_quota_write(struct super_block *sb, int type,
				const char *data, size_t len, loff_t off)
{
	struct inode *inode = sb_dqopt(sb)->files[type];
	sector_t blk = off >> EXT3_BLOCK_SIZE_BITS(sb);
	int err = 0;
	int offset = off & (sb->s_blocksize - 1);
	int journal_quota = EXT3_SB(sb)->s_qf_names[type] != NULL;
	struct buffer_head *bh;
	handle_t *handle = journal_current_handle();

	if (!handle) {
		ext3_msg(sb, KERN_WARNING,
			"warning: quota write (off=%llu, len=%llu)"
			" cancelled because transaction is not started.",
			(unsigned long long)off, (unsigned long long)len);
		return -EIO;
	}

	/*
	 * Since we account only one data block in transaction credits,
	 * then it is impossible to cross a block boundary.
	 */
	if (sb->s_blocksize - offset < len) {
		ext3_msg(sb, KERN_WARNING, "Quota write (off=%llu, len=%llu)"
			" cancelled because not block aligned",
			(unsigned long long)off, (unsigned long long)len);
		return -EIO;
	}
	bh = ext3_bread(handle, inode, blk, 1, &err);
	if (!bh)
		goto out;
	if (journal_quota) {
		err = ext3_journal_get_write_access(handle, bh);
		if (err) {
			brelse(bh);
			goto out;
		}
	}
	lock_buffer(bh);
	memcpy(bh->b_data+offset, data, len);
	flush_dcache_page(bh->b_page);
	unlock_buffer(bh);
	if (journal_quota)
		err = ext3_journal_dirty_metadata(handle, bh);
	else {
		/* Always do at least ordered writes for quotas */
		err = ext3_journal_dirty_data(handle, bh);
		mark_buffer_dirty(bh);
	}
	brelse(bh);
out:
	if (err)
		return err;
	if (inode->i_size < off + len) {
		i_size_write(inode, off + len);
		EXT3_I(inode)->i_disksize = inode->i_size;
	}
	inode->i_version++;
	inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	ext3_mark_inode_dirty(handle, inode);
	return len;
}

#endif

static struct dentry *ext3_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, ext3_fill_super);
}

static struct file_system_type ext3_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ext3",
	.mount		= ext3_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("ext3");

static int __init init_ext3_fs(void)
{
	int err = init_ext3_xattr();
	if (err)
		return err;
	err = init_inodecache();
	if (err)
		goto out1;
        err = register_filesystem(&ext3_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	exit_ext3_xattr();
	return err;
}

static void __exit exit_ext3_fs(void)
{
	unregister_filesystem(&ext3_fs_type);
	destroy_inodecache();
	exit_ext3_xattr();
}

MODULE_AUTHOR("Remy Card, Stephen Tweedie, Andrew Morton, Andreas Dilger, Theodore Ts'o and others");
MODULE_DESCRIPTION("Second Extended Filesystem with journaling extensions");
MODULE_LICENSE("GPL");
module_init(init_ext3_fs)
module_exit(exit_ext3_fs)
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/super.c */
/************************************************************/
/*
 *  linux/fs/ext3/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext3 symlink handling code
 */

// #include <linux/namei.h>
// #include "ext3.h"
// #include "xattr.h"

static void * ext3_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct ext3_inode_info *ei = EXT3_I(dentry->d_inode);
	nd_set_link(nd, (char*)ei->i_data);
	return NULL;
}

const struct inode_operations ext3_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.setattr	= ext3_setattr,
#ifdef CONFIG_EXT3_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext3_listxattr,
	.removexattr	= generic_removexattr,
#endif
};

const struct inode_operations ext3_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= ext3_follow_link,
	.setattr	= ext3_setattr,
#ifdef CONFIG_EXT3_FS_XATTR
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext3_listxattr,
	.removexattr	= generic_removexattr,
#endif
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/symlink.c */
/************************************************************/
/*
 *  linux/fs/ext3/hash.c
 *
 * Copyright (C) 2002 by Theodore Ts'o
 *
 * This file is released under the GPL v2.
 *
 * This file may be redistributed under the terms of the GNU Public
 * License.
 */

// #include "ext3.h"
#include <linux/cryptohash.h>
#include "../../inc/__fss.h"

#define DELTA 0x9E3779B9

static void TEA_transform(__u32 buf[4], __u32 const in[])
{
	__u32	sum = 0;
	__u32	b0 = buf[0], b1 = buf[1];
	__u32	a = in[0], b = in[1], c = in[2], d = in[3];
	int	n = 16;

	do {
		sum += DELTA;
		b0 += ((b1 << 4)+a) ^ (b1+sum) ^ ((b1 >> 5)+b);
		b1 += ((b0 << 4)+c) ^ (b0+sum) ^ ((b0 >> 5)+d);
	} while(--n);

	buf[0] += b0;
	buf[1] += b1;
}


/* The old legacy hash */
static __u32 dx_hack_hash_unsigned(const char *name, int len)
{
	__u32 hash, hash0 = 0x12a3fe2d, hash1 = 0x37abe8f9;
	const unsigned char *ucp = (const unsigned char *) name;

	while (len--) {
		hash = hash1 + (hash0 ^ (((int) *ucp++) * 7152373));

		if (hash & 0x80000000)
			hash -= 0x7fffffff;
		hash1 = hash0;
		hash0 = hash;
	}
	return hash0 << 1;
}

static __u32 dx_hack_hash_signed(const char *name, int len)
{
	__u32 hash, hash0 = 0x12a3fe2d, hash1 = 0x37abe8f9;
	const signed char *scp = (const signed char *) name;

	while (len--) {
		hash = hash1 + (hash0 ^ (((int) *scp++) * 7152373));

		if (hash & 0x80000000)
			hash -= 0x7fffffff;
		hash1 = hash0;
		hash0 = hash;
	}
	return hash0 << 1;
}

static void str2hashbuf_signed(const char *msg, int len, __u32 *buf, int num)
{
	__u32	pad, val;
	int	i;
	const signed char *scp = (const signed char *) msg;

	pad = (__u32)len | ((__u32)len << 8);
	pad |= pad << 16;

	val = pad;
	if (len > num*4)
		len = num * 4;
	for (i = 0; i < len; i++) {
		if ((i % 4) == 0)
			val = pad;
		val = ((int) scp[i]) + (val << 8);
		if ((i % 4) == 3) {
			*buf++ = val;
			val = pad;
			num--;
		}
	}
	if (--num >= 0)
		*buf++ = val;
	while (--num >= 0)
		*buf++ = pad;
}

static void str2hashbuf_unsigned(const char *msg, int len, __u32 *buf, int num)
{
	__u32	pad, val;
	int	i;
	const unsigned char *ucp = (const unsigned char *) msg;

	pad = (__u32)len | ((__u32)len << 8);
	pad |= pad << 16;

	val = pad;
	if (len > num*4)
		len = num * 4;
	for (i=0; i < len; i++) {
		if ((i % 4) == 0)
			val = pad;
		val = ((int) ucp[i]) + (val << 8);
		if ((i % 4) == 3) {
			*buf++ = val;
			val = pad;
			num--;
		}
	}
	if (--num >= 0)
		*buf++ = val;
	while (--num >= 0)
		*buf++ = pad;
}

/*
 * Returns the hash of a filename.  If len is 0 and name is NULL, then
 * this function can be used to test whether or not a hash version is
 * supported.
 *
 * The seed is an 4 longword (32 bits) "secret" which can be used to
 * uniquify a hash.  If the seed is all zero's, then some default seed
 * may be used.
 *
 * A particular hash version specifies whether or not the seed is
 * represented, and whether or not the returned hash is 32 bits or 64
 * bits.  32 bit hashes will return 0 for the minor hash.
 */
int ext3fs_dirhash(const char *name, int len, struct dx_hash_info *hinfo)
{
	__u32	hash;
	__u32	minor_hash = 0;
	const char	*p;
	int		i;
	__u32		in[8], buf[4];
	void		(*str2hashbuf)(const char *, int, __u32 *, int) =
				str2hashbuf_signed;

	/* Initialize the default seed for the hash checksum functions */
	buf[0] = 0x67452301;
	buf[1] = 0xefcdab89;
	buf[2] = 0x98badcfe;
	buf[3] = 0x10325476;

	/* Check to see if the seed is all zero's */
	if (hinfo->seed) {
		for (i=0; i < 4; i++) {
			if (hinfo->seed[i])
				break;
		}
		if (i < 4)
			memcpy(buf, hinfo->seed, sizeof(buf));
	}

	switch (hinfo->hash_version) {
	case DX_HASH_LEGACY_UNSIGNED:
		hash = dx_hack_hash_unsigned(name, len);
		break;
	case DX_HASH_LEGACY:
		hash = dx_hack_hash_signed(name, len);
		break;
	case DX_HASH_HALF_MD4_UNSIGNED:
		str2hashbuf = str2hashbuf_unsigned;
	case DX_HASH_HALF_MD4:
		p = name;
		while (len > 0) {
			(*str2hashbuf)(p, len, in, 8);
			half_md4_transform(buf, in);
			len -= 32;
			p += 32;
		}
		minor_hash = buf[2];
		hash = buf[1];
		break;
	case DX_HASH_TEA_UNSIGNED:
		str2hashbuf = str2hashbuf_unsigned;
	case DX_HASH_TEA:
		p = name;
		while (len > 0) {
			(*str2hashbuf)(p, len, in, 4);
			TEA_transform(buf, in);
			len -= 16;
			p += 16;
		}
		hash = buf[0];
		minor_hash = buf[1];
		break;
	default:
		hinfo->hash = 0;
		return -1;
	}
	hash = hash & ~1;
	if (hash == (EXT3_HTREE_EOF_32BIT << 1))
		hash = (EXT3_HTREE_EOF_32BIT - 1) << 1;
	hinfo->hash = hash;
	hinfo->minor_hash = minor_hash;
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/hash.c */
/************************************************************/
/*
 *  linux/fs/ext3/resize.c
 *
 * Support for resizing an ext3 filesystem while it is mounted.
 *
 * Copyright (C) 2001, 2002 Andreas Dilger <adilger@clusterfs.com>
 *
 * This could probably be made into a module, because it is not often in use.
 */


#define EXT3FS_DEBUG

// #include "ext3.h"


#define outside(b, first, last)	((b) < (first) || (b) >= (last))
#define inside(b, first, last)	((b) >= (first) && (b) < (last))

static int verify_group_input(struct super_block *sb,
			      struct ext3_new_group_data *input)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	struct ext3_super_block *es = sbi->s_es;
	ext3_fsblk_t start = le32_to_cpu(es->s_blocks_count);
	ext3_fsblk_t end = start + input->blocks_count;
	unsigned group = input->group;
	ext3_fsblk_t itend = input->inode_table + sbi->s_itb_per_group;
	unsigned overhead = ext3_bg_has_super(sb, group) ?
		(1 + ext3_bg_num_gdb(sb, group) +
		 le16_to_cpu(es->s_reserved_gdt_blocks)) : 0;
	ext3_fsblk_t metaend = start + overhead;
	struct buffer_head *bh = NULL;
	ext3_grpblk_t free_blocks_count;
	int err = -EINVAL;

	input->free_blocks_count = free_blocks_count =
		input->blocks_count - 2 - overhead - sbi->s_itb_per_group;

	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG "EXT3-fs: adding %s group %u: %u blocks "
		       "(%d free, %u reserved)\n",
		       ext3_bg_has_super(sb, input->group) ? "normal" :
		       "no-super", input->group, input->blocks_count,
		       free_blocks_count, input->reserved_blocks);

	if (group != sbi->s_groups_count)
		ext3_warning(sb, __func__,
			     "Cannot add at group %u (only %lu groups)",
			     input->group, sbi->s_groups_count);
	else if ((start - le32_to_cpu(es->s_first_data_block)) %
		 EXT3_BLOCKS_PER_GROUP(sb))
		ext3_warning(sb, __func__, "Last group not full");
	else if (input->reserved_blocks > input->blocks_count / 5)
		ext3_warning(sb, __func__, "Reserved blocks too high (%u)",
			     input->reserved_blocks);
	else if (free_blocks_count < 0)
		ext3_warning(sb, __func__, "Bad blocks count %u",
			     input->blocks_count);
	else if (!(bh = sb_bread(sb, end - 1)))
		ext3_warning(sb, __func__,
			     "Cannot read last block ("E3FSBLK")",
			     end - 1);
	else if (outside(input->block_bitmap, start, end))
		ext3_warning(sb, __func__,
			     "Block bitmap not in group (block %u)",
			     input->block_bitmap);
	else if (outside(input->inode_bitmap, start, end))
		ext3_warning(sb, __func__,
			     "Inode bitmap not in group (block %u)",
			     input->inode_bitmap);
	else if (outside(input->inode_table, start, end) ||
	         outside(itend - 1, start, end))
		ext3_warning(sb, __func__,
			     "Inode table not in group (blocks %u-"E3FSBLK")",
			     input->inode_table, itend - 1);
	else if (input->inode_bitmap == input->block_bitmap)
		ext3_warning(sb, __func__,
			     "Block bitmap same as inode bitmap (%u)",
			     input->block_bitmap);
	else if (inside(input->block_bitmap, input->inode_table, itend))
		ext3_warning(sb, __func__,
			     "Block bitmap (%u) in inode table (%u-"E3FSBLK")",
			     input->block_bitmap, input->inode_table, itend-1);
	else if (inside(input->inode_bitmap, input->inode_table, itend))
		ext3_warning(sb, __func__,
			     "Inode bitmap (%u) in inode table (%u-"E3FSBLK")",
			     input->inode_bitmap, input->inode_table, itend-1);
	else if (inside(input->block_bitmap, start, metaend))
		ext3_warning(sb, __func__,
			     "Block bitmap (%u) in GDT table"
			     " ("E3FSBLK"-"E3FSBLK")",
			     input->block_bitmap, start, metaend - 1);
	else if (inside(input->inode_bitmap, start, metaend))
		ext3_warning(sb, __func__,
			     "Inode bitmap (%u) in GDT table"
			     " ("E3FSBLK"-"E3FSBLK")",
			     input->inode_bitmap, start, metaend - 1);
	else if (inside(input->inode_table, start, metaend) ||
	         inside(itend - 1, start, metaend))
		ext3_warning(sb, __func__,
			     "Inode table (%u-"E3FSBLK") overlaps"
			     "GDT table ("E3FSBLK"-"E3FSBLK")",
			     input->inode_table, itend - 1, start, metaend - 1);
	else
		err = 0;
	brelse(bh);

	return err;
}

static struct buffer_head *bclean(handle_t *handle, struct super_block *sb,
				  ext3_fsblk_t blk)
{
	struct buffer_head *bh;
	int err;

	bh = sb_getblk(sb, blk);
	if (unlikely(!bh))
		return ERR_PTR(-ENOMEM);
	if ((err = ext3_journal_get_write_access(handle, bh))) {
		brelse(bh);
		bh = ERR_PTR(err);
	} else {
		lock_buffer(bh);
		memset(bh->b_data, 0, sb->s_blocksize);
		set_buffer_uptodate(bh);
		unlock_buffer(bh);
	}

	return bh;
}

/*
 * To avoid calling the atomic setbit hundreds or thousands of times, we only
 * need to use it within a single byte (to ensure we get endianness right).
 * We can use memset for the rest of the bitmap as there are no other users.
 */
static void mark_bitmap_end(int start_bit, int end_bit, char *bitmap)
{
	int i;

	if (start_bit >= end_bit)
		return;

	ext3_debug("mark end bits +%d through +%d used\n", start_bit, end_bit);
	for (i = start_bit; i < ((start_bit + 7) & ~7UL); i++)
		ext3_set_bit(i, bitmap);
	if (i < end_bit)
		memset(bitmap + (i >> 3), 0xff, (end_bit - i) >> 3);
}

/*
 * If we have fewer than thresh credits, extend by EXT3_MAX_TRANS_DATA.
 * If that fails, restart the transaction & regain write access for the
 * buffer head which is used for block_bitmap modifications.
 */
static int extend_or_restart_transaction(handle_t *handle, int thresh,
					 struct buffer_head *bh)
{
	int err;

	if (handle->h_buffer_credits >= thresh)
		return 0;

	err = ext3_journal_extend(handle, EXT3_MAX_TRANS_DATA);
	if (err < 0)
		return err;
	if (err) {
		err = ext3_journal_restart(handle, EXT3_MAX_TRANS_DATA);
		if (err)
			return err;
		err = ext3_journal_get_write_access(handle, bh);
		if (err)
			return err;
	}

	return 0;
}

/*
 * Set up the block and inode bitmaps, and the inode table for the new group.
 * This doesn't need to be part of the main transaction, since we are only
 * changing blocks outside the actual filesystem.  We still do journaling to
 * ensure the recovery is correct in case of a failure just after resize.
 * If any part of this fails, we simply abort the resize.
 */
static int setup_new_group_blocks(struct super_block *sb,
				  struct ext3_new_group_data *input)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	ext3_fsblk_t start = ext3_group_first_block_no(sb, input->group);
	int reserved_gdb = ext3_bg_has_super(sb, input->group) ?
		le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks) : 0;
	unsigned long gdblocks = ext3_bg_num_gdb(sb, input->group);
	struct buffer_head *bh;
	handle_t *handle;
	ext3_fsblk_t block;
	ext3_grpblk_t bit;
	int i;
	int err = 0, err2;

	/* This transaction may be extended/restarted along the way */
	handle = ext3_journal_start_sb(sb, EXT3_MAX_TRANS_DATA);

	if (IS_ERR(handle))
		return PTR_ERR(handle);

	mutex_lock(&sbi->s_resize_lock);
	if (input->group != sbi->s_groups_count) {
		err = -EBUSY;
		goto exit_journal;
	}

	if (IS_ERR(bh = bclean(handle, sb, input->block_bitmap))) {
		err = PTR_ERR(bh);
		goto exit_journal;
	}

	if (ext3_bg_has_super(sb, input->group)) {
		ext3_debug("mark backup superblock %#04lx (+0)\n", start);
		ext3_set_bit(0, bh->b_data);
	}

	/* Copy all of the GDT blocks into the backup in this group */
	for (i = 0, bit = 1, block = start + 1;
	     i < gdblocks; i++, block++, bit++) {
		struct buffer_head *gdb;

		ext3_debug("update backup group %#04lx (+%d)\n", block, bit);

		err = extend_or_restart_transaction(handle, 1, bh);
		if (err)
			goto exit_bh;

		gdb = sb_getblk(sb, block);
		if (unlikely(!gdb)) {
			err = -ENOMEM;
			goto exit_bh;
		}
		if ((err = ext3_journal_get_write_access(handle, gdb))) {
			brelse(gdb);
			goto exit_bh;
		}
		lock_buffer(gdb);
		memcpy(gdb->b_data, sbi->s_group_desc[i]->b_data, gdb->b_size);
		set_buffer_uptodate(gdb);
		unlock_buffer(gdb);
		err = ext3_journal_dirty_metadata(handle, gdb);
		if (err) {
			brelse(gdb);
			goto exit_bh;
		}
		ext3_set_bit(bit, bh->b_data);
		brelse(gdb);
	}

	/* Zero out all of the reserved backup group descriptor table blocks */
	for (i = 0, bit = gdblocks + 1, block = start + bit;
	     i < reserved_gdb; i++, block++, bit++) {
		struct buffer_head *gdb;

		ext3_debug("clear reserved block %#04lx (+%d)\n", block, bit);

		err = extend_or_restart_transaction(handle, 1, bh);
		if (err)
			goto exit_bh;

		if (IS_ERR(gdb = bclean(handle, sb, block))) {
			err = PTR_ERR(gdb);
			goto exit_bh;
		}
		err = ext3_journal_dirty_metadata(handle, gdb);
		if (err) {
			brelse(gdb);
			goto exit_bh;
		}
		ext3_set_bit(bit, bh->b_data);
		brelse(gdb);
	}
	ext3_debug("mark block bitmap %#04x (+%ld)\n", input->block_bitmap,
		   input->block_bitmap - start);
	ext3_set_bit(input->block_bitmap - start, bh->b_data);
	ext3_debug("mark inode bitmap %#04x (+%ld)\n", input->inode_bitmap,
		   input->inode_bitmap - start);
	ext3_set_bit(input->inode_bitmap - start, bh->b_data);

	/* Zero out all of the inode table blocks */
	for (i = 0, block = input->inode_table, bit = block - start;
	     i < sbi->s_itb_per_group; i++, bit++, block++) {
		struct buffer_head *it;

		ext3_debug("clear inode block %#04lx (+%d)\n", block, bit);

		err = extend_or_restart_transaction(handle, 1, bh);
		if (err)
			goto exit_bh;

		if (IS_ERR(it = bclean(handle, sb, block))) {
			err = PTR_ERR(it);
			goto exit_bh;
		}
		err = ext3_journal_dirty_metadata(handle, it);
		if (err) {
			brelse(it);
			goto exit_bh;
		}
		brelse(it);
		ext3_set_bit(bit, bh->b_data);
	}

	err = extend_or_restart_transaction(handle, 2, bh);
	if (err)
		goto exit_bh;

	mark_bitmap_end(input->blocks_count, EXT3_BLOCKS_PER_GROUP(sb),
			bh->b_data);
	err = ext3_journal_dirty_metadata(handle, bh);
	if (err)
		goto exit_bh;
	brelse(bh);

	/* Mark unused entries in inode bitmap used */
	ext3_debug("clear inode bitmap %#04x (+%ld)\n",
		   input->inode_bitmap, input->inode_bitmap - start);
	if (IS_ERR(bh = bclean(handle, sb, input->inode_bitmap))) {
		err = PTR_ERR(bh);
		goto exit_journal;
	}

	mark_bitmap_end(EXT3_INODES_PER_GROUP(sb), EXT3_BLOCKS_PER_GROUP(sb),
			bh->b_data);
	err = ext3_journal_dirty_metadata(handle, bh);
exit_bh:
	brelse(bh);

exit_journal:
	mutex_unlock(&sbi->s_resize_lock);
	if ((err2 = ext3_journal_stop(handle)) && !err)
		err = err2;

	return err;
}

/*
 * Iterate through the groups which hold BACKUP superblock/GDT copies in an
 * ext3 filesystem.  The counters should be initialized to 1, 5, and 7 before
 * calling this for the first time.  In a sparse filesystem it will be the
 * sequence of powers of 3, 5, and 7: 1, 3, 5, 7, 9, 25, 27, 49, 81, ...
 * For a non-sparse filesystem it will be every group: 1, 2, 3, 4, ...
 */
static unsigned ext3_list_backups(struct super_block *sb, unsigned *three,
				  unsigned *five, unsigned *seven)
{
	unsigned *min = three;
	int mult = 3;
	unsigned ret;

	if (!EXT3_HAS_RO_COMPAT_FEATURE(sb,
					EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER)) {
		ret = *min;
		*min += 1;
		return ret;
	}

	if (*five < *min) {
		min = five;
		mult = 5;
	}
	if (*seven < *min) {
		min = seven;
		mult = 7;
	}

	ret = *min;
	*min *= mult;

	return ret;
}

/*
 * Check that all of the backup GDT blocks are held in the primary GDT block.
 * It is assumed that they are stored in group order.  Returns the number of
 * groups in current filesystem that have BACKUPS, or -ve error code.
 */
static int verify_reserved_gdb(struct super_block *sb,
			       struct buffer_head *primary)
{
	const ext3_fsblk_t blk = primary->b_blocknr;
	const unsigned long end = EXT3_SB(sb)->s_groups_count;
	unsigned three = 1;
	unsigned five = 5;
	unsigned seven = 7;
	unsigned grp;
	__le32 *p = (__le32 *)primary->b_data;
	int gdbackups = 0;

	while ((grp = ext3_list_backups(sb, &three, &five, &seven)) < end) {
		if (le32_to_cpu(*p++) != grp * EXT3_BLOCKS_PER_GROUP(sb) + blk){
			ext3_warning(sb, __func__,
				     "reserved GDT "E3FSBLK
				     " missing grp %d ("E3FSBLK")",
				     blk, grp,
				     grp * EXT3_BLOCKS_PER_GROUP(sb) + blk);
			return -EINVAL;
		}
		if (++gdbackups > EXT3_ADDR_PER_BLOCK(sb))
			return -EFBIG;
	}

	return gdbackups;
}

/*
 * Called when we need to bring a reserved group descriptor table block into
 * use from the resize inode.  The primary copy of the new GDT block currently
 * is an indirect block (under the double indirect block in the resize inode).
 * The new backup GDT blocks will be stored as leaf blocks in this indirect
 * block, in group order.  Even though we know all the block numbers we need,
 * we check to ensure that the resize inode has actually reserved these blocks.
 *
 * Don't need to update the block bitmaps because the blocks are still in use.
 *
 * We get all of the error cases out of the way, so that we are sure to not
 * fail once we start modifying the data on disk, because JBD has no rollback.
 */
static int add_new_gdb(handle_t *handle, struct inode *inode,
		       struct ext3_new_group_data *input,
		       struct buffer_head **primary)
{
	struct super_block *sb = inode->i_sb;
	struct ext3_super_block *es = EXT3_SB(sb)->s_es;
	unsigned long gdb_num = input->group / EXT3_DESC_PER_BLOCK(sb);
	ext3_fsblk_t gdblock = EXT3_SB(sb)->s_sbh->b_blocknr + 1 + gdb_num;
	struct buffer_head **o_group_desc, **n_group_desc;
	struct buffer_head *dind;
	int gdbackups;
	struct ext3_iloc iloc;
	__le32 *data;
	int err;

	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG
		       "EXT3-fs: ext3_add_new_gdb: adding group block %lu\n",
		       gdb_num);

	/*
	 * If we are not using the primary superblock/GDT copy don't resize,
	 * because the user tools have no way of handling this.  Probably a
	 * bad time to do it anyways.
	 */
	if (EXT3_SB(sb)->s_sbh->b_blocknr !=
	    le32_to_cpu(EXT3_SB(sb)->s_es->s_first_data_block)) {
		ext3_warning(sb, __func__,
			"won't resize using backup superblock at %llu",
			(unsigned long long)EXT3_SB(sb)->s_sbh->b_blocknr);
		return -EPERM;
	}

	*primary = sb_bread(sb, gdblock);
	if (!*primary)
		return -EIO;

	if ((gdbackups = verify_reserved_gdb(sb, *primary)) < 0) {
		err = gdbackups;
		goto exit_bh;
	}

	data = EXT3_I(inode)->i_data + EXT3_DIND_BLOCK;
	dind = sb_bread(sb, le32_to_cpu(*data));
	if (!dind) {
		err = -EIO;
		goto exit_bh;
	}

	data = (__le32 *)dind->b_data;
	if (le32_to_cpu(data[gdb_num % EXT3_ADDR_PER_BLOCK(sb)]) != gdblock) {
		ext3_warning(sb, __func__,
			     "new group %u GDT block "E3FSBLK" not reserved",
			     input->group, gdblock);
		err = -EINVAL;
		goto exit_dind;
	}

	if ((err = ext3_journal_get_write_access(handle, EXT3_SB(sb)->s_sbh)))
		goto exit_dind;

	if ((err = ext3_journal_get_write_access(handle, *primary)))
		goto exit_sbh;

	if ((err = ext3_journal_get_write_access(handle, dind)))
		goto exit_primary;

	/* ext3_reserve_inode_write() gets a reference on the iloc */
	if ((err = ext3_reserve_inode_write(handle, inode, &iloc)))
		goto exit_dindj;

	n_group_desc = kmalloc((gdb_num + 1) * sizeof(struct buffer_head *),
			GFP_NOFS);
	if (!n_group_desc) {
		err = -ENOMEM;
		ext3_warning (sb, __func__,
			      "not enough memory for %lu groups", gdb_num + 1);
		goto exit_inode;
	}

	/*
	 * Finally, we have all of the possible failures behind us...
	 *
	 * Remove new GDT block from inode double-indirect block and clear out
	 * the new GDT block for use (which also "frees" the backup GDT blocks
	 * from the reserved inode).  We don't need to change the bitmaps for
	 * these blocks, because they are marked as in-use from being in the
	 * reserved inode, and will become GDT blocks (primary and backup).
	 */
	data[gdb_num % EXT3_ADDR_PER_BLOCK(sb)] = 0;
	err = ext3_journal_dirty_metadata(handle, dind);
	if (err)
		goto exit_group_desc;
	brelse(dind);
	dind = NULL;
	inode->i_blocks -= (gdbackups + 1) * sb->s_blocksize >> 9;
	err = ext3_mark_iloc_dirty(handle, inode, &iloc);
	if (err)
		goto exit_group_desc;
	memset((*primary)->b_data, 0, sb->s_blocksize);
	err = ext3_journal_dirty_metadata(handle, *primary);
	if (err)
		goto exit_group_desc;

	o_group_desc = EXT3_SB(sb)->s_group_desc;
	memcpy(n_group_desc, o_group_desc,
	       EXT3_SB(sb)->s_gdb_count * sizeof(struct buffer_head *));
	n_group_desc[gdb_num] = *primary;
	EXT3_SB(sb)->s_group_desc = n_group_desc;
	EXT3_SB(sb)->s_gdb_count++;
	kfree(o_group_desc);

	le16_add_cpu(&es->s_reserved_gdt_blocks, -1);
	err = ext3_journal_dirty_metadata(handle, EXT3_SB(sb)->s_sbh);
	if (err)
		goto exit_inode;

	return 0;

exit_group_desc:
	kfree(n_group_desc);
exit_inode:
	//ext3_journal_release_buffer(handle, iloc.bh);
	brelse(iloc.bh);
exit_dindj:
	//ext3_journal_release_buffer(handle, dind);
exit_primary:
	//ext3_journal_release_buffer(handle, *primary);
exit_sbh:
	//ext3_journal_release_buffer(handle, *primary);
exit_dind:
	brelse(dind);
exit_bh:
	brelse(*primary);

	ext3_debug("leaving with error %d\n", err);
	return err;
}

/*
 * Called when we are adding a new group which has a backup copy of each of
 * the GDT blocks (i.e. sparse group) and there are reserved GDT blocks.
 * We need to add these reserved backup GDT blocks to the resize inode, so
 * that they are kept for future resizing and not allocated to files.
 *
 * Each reserved backup GDT block will go into a different indirect block.
 * The indirect blocks are actually the primary reserved GDT blocks,
 * so we know in advance what their block numbers are.  We only get the
 * double-indirect block to verify it is pointing to the primary reserved
 * GDT blocks so we don't overwrite a data block by accident.  The reserved
 * backup GDT blocks are stored in their reserved primary GDT block.
 */
static int reserve_backup_gdb(handle_t *handle, struct inode *inode,
			      struct ext3_new_group_data *input)
{
	struct super_block *sb = inode->i_sb;
	int reserved_gdb =le16_to_cpu(EXT3_SB(sb)->s_es->s_reserved_gdt_blocks);
	struct buffer_head **primary;
	struct buffer_head *dind;
	struct ext3_iloc iloc;
	ext3_fsblk_t blk;
	__le32 *data, *end;
	int gdbackups = 0;
	int res, i;
	int err;

	primary = kmalloc(reserved_gdb * sizeof(*primary), GFP_NOFS);
	if (!primary)
		return -ENOMEM;

	data = EXT3_I(inode)->i_data + EXT3_DIND_BLOCK;
	dind = sb_bread(sb, le32_to_cpu(*data));
	if (!dind) {
		err = -EIO;
		goto exit_free;
	}

	blk = EXT3_SB(sb)->s_sbh->b_blocknr + 1 + EXT3_SB(sb)->s_gdb_count;
	data = (__le32 *)dind->b_data + (EXT3_SB(sb)->s_gdb_count %
					 EXT3_ADDR_PER_BLOCK(sb));
	end = (__le32 *)dind->b_data + EXT3_ADDR_PER_BLOCK(sb);

	/* Get each reserved primary GDT block and verify it holds backups */
	for (res = 0; res < reserved_gdb; res++, blk++) {
		if (le32_to_cpu(*data) != blk) {
			ext3_warning(sb, __func__,
				     "reserved block "E3FSBLK
				     " not at offset %ld",
				     blk,
				     (long)(data - (__le32 *)dind->b_data));
			err = -EINVAL;
			goto exit_bh;
		}
		primary[res] = sb_bread(sb, blk);
		if (!primary[res]) {
			err = -EIO;
			goto exit_bh;
		}
		if ((gdbackups = verify_reserved_gdb(sb, primary[res])) < 0) {
			brelse(primary[res]);
			err = gdbackups;
			goto exit_bh;
		}
		if (++data >= end)
			data = (__le32 *)dind->b_data;
	}

	for (i = 0; i < reserved_gdb; i++) {
		if ((err = ext3_journal_get_write_access(handle, primary[i]))) {
			/*
			int j;
			for (j = 0; j < i; j++)
				ext3_journal_release_buffer(handle, primary[j]);
			 */
			goto exit_bh;
		}
	}

	if ((err = ext3_reserve_inode_write(handle, inode, &iloc)))
		goto exit_bh;

	/*
	 * Finally we can add each of the reserved backup GDT blocks from
	 * the new group to its reserved primary GDT block.
	 */
	blk = input->group * EXT3_BLOCKS_PER_GROUP(sb);
	for (i = 0; i < reserved_gdb; i++) {
		int err2;
		data = (__le32 *)primary[i]->b_data;
		/* printk("reserving backup %lu[%u] = %lu\n",
		       primary[i]->b_blocknr, gdbackups,
		       blk + primary[i]->b_blocknr); */
		data[gdbackups] = cpu_to_le32(blk + primary[i]->b_blocknr);
		err2 = ext3_journal_dirty_metadata(handle, primary[i]);
		if (!err)
			err = err2;
	}
	inode->i_blocks += reserved_gdb * sb->s_blocksize >> 9;
	ext3_mark_iloc_dirty(handle, inode, &iloc);

exit_bh:
	while (--res >= 0)
		brelse(primary[res]);
	brelse(dind);

exit_free:
	kfree(primary);

	return err;
}

/*
 * Update the backup copies of the ext3 metadata.  These don't need to be part
 * of the main resize transaction, because e2fsck will re-write them if there
 * is a problem (basically only OOM will cause a problem).  However, we
 * _should_ update the backups if possible, in case the primary gets trashed
 * for some reason and we need to run e2fsck from a backup superblock.  The
 * important part is that the new block and inode counts are in the backup
 * superblocks, and the location of the new group metadata in the GDT backups.
 *
 * We do not need take the s_resize_lock for this, because these
 * blocks are not otherwise touched by the filesystem code when it is
 * mounted.  We don't need to worry about last changing from
 * sbi->s_groups_count, because the worst that can happen is that we
 * do not copy the full number of backups at this time.  The resize
 * which changed s_groups_count will backup again.
 */
static void update_backups(struct super_block *sb,
			   int blk_off, char *data, int size)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	const unsigned long last = sbi->s_groups_count;
	const int bpg = EXT3_BLOCKS_PER_GROUP(sb);
	unsigned three = 1;
	unsigned five = 5;
	unsigned seven = 7;
	unsigned group;
	int rest = sb->s_blocksize - size;
	handle_t *handle;
	int err = 0, err2;

	handle = ext3_journal_start_sb(sb, EXT3_MAX_TRANS_DATA);
	if (IS_ERR(handle)) {
		group = 1;
		err = PTR_ERR(handle);
		goto exit_err;
	}

	while ((group = ext3_list_backups(sb, &three, &five, &seven)) < last) {
		struct buffer_head *bh;

		/* Out of journal space, and can't get more - abort - so sad */
		if (handle->h_buffer_credits == 0 &&
		    ext3_journal_extend(handle, EXT3_MAX_TRANS_DATA) &&
		    (err = ext3_journal_restart(handle, EXT3_MAX_TRANS_DATA)))
			break;

		bh = sb_getblk(sb, group * bpg + blk_off);
		if (unlikely(!bh)) {
			err = -ENOMEM;
			break;
		}
		ext3_debug("update metadata backup %#04lx\n",
			  (unsigned long)bh->b_blocknr);
		if ((err = ext3_journal_get_write_access(handle, bh))) {
			brelse(bh);
			break;
		}
		lock_buffer(bh);
		memcpy(bh->b_data, data, size);
		if (rest)
			memset(bh->b_data + size, 0, rest);
		set_buffer_uptodate(bh);
		unlock_buffer(bh);
		err = ext3_journal_dirty_metadata(handle, bh);
		brelse(bh);
		if (err)
			break;
	}
	if ((err2 = ext3_journal_stop(handle)) && !err)
		err = err2;

	/*
	 * Ugh! Need to have e2fsck write the backup copies.  It is too
	 * late to revert the resize, we shouldn't fail just because of
	 * the backup copies (they are only needed in case of corruption).
	 *
	 * However, if we got here we have a journal problem too, so we
	 * can't really start a transaction to mark the superblock.
	 * Chicken out and just set the flag on the hope it will be written
	 * to disk, and if not - we will simply wait until next fsck.
	 */
exit_err:
	if (err) {
		ext3_warning(sb, __func__,
			     "can't update backup for group %d (err %d), "
			     "forcing fsck on next reboot", group, err);
		sbi->s_mount_state &= ~EXT3_VALID_FS;
		sbi->s_es->s_state &= cpu_to_le16(~EXT3_VALID_FS);
		mark_buffer_dirty(sbi->s_sbh);
	}
}

/* Add group descriptor data to an existing or new group descriptor block.
 * Ensure we handle all possible error conditions _before_ we start modifying
 * the filesystem, because we cannot abort the transaction and not have it
 * write the data to disk.
 *
 * If we are on a GDT block boundary, we need to get the reserved GDT block.
 * Otherwise, we may need to add backup GDT blocks for a sparse group.
 *
 * We only need to hold the superblock lock while we are actually adding
 * in the new group's counts to the superblock.  Prior to that we have
 * not really "added" the group at all.  We re-check that we are still
 * adding in the last group in case things have changed since verifying.
 */
int ext3_group_add(struct super_block *sb, struct ext3_new_group_data *input)
{
	struct ext3_sb_info *sbi = EXT3_SB(sb);
	struct ext3_super_block *es = sbi->s_es;
	int reserved_gdb = ext3_bg_has_super(sb, input->group) ?
		le16_to_cpu(es->s_reserved_gdt_blocks) : 0;
	struct buffer_head *primary = NULL;
	struct ext3_group_desc *gdp;
	struct inode *inode = NULL;
	handle_t *handle;
	int gdb_off, gdb_num;
	int err, err2;

	gdb_num = input->group / EXT3_DESC_PER_BLOCK(sb);
	gdb_off = input->group % EXT3_DESC_PER_BLOCK(sb);

	if (gdb_off == 0 && !EXT3_HAS_RO_COMPAT_FEATURE(sb,
					EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER)) {
		ext3_warning(sb, __func__,
			     "Can't resize non-sparse filesystem further");
		return -EPERM;
	}

	if (le32_to_cpu(es->s_blocks_count) + input->blocks_count <
	    le32_to_cpu(es->s_blocks_count)) {
		ext3_warning(sb, __func__, "blocks_count overflow\n");
		return -EINVAL;
	}

	if (le32_to_cpu(es->s_inodes_count) + EXT3_INODES_PER_GROUP(sb) <
	    le32_to_cpu(es->s_inodes_count)) {
		ext3_warning(sb, __func__, "inodes_count overflow\n");
		return -EINVAL;
	}

	if (reserved_gdb || gdb_off == 0) {
		if (!EXT3_HAS_COMPAT_FEATURE(sb,
					     EXT3_FEATURE_COMPAT_RESIZE_INODE)
		    || !le16_to_cpu(es->s_reserved_gdt_blocks)) {
			ext3_warning(sb, __func__,
				     "No reserved GDT blocks, can't resize");
			return -EPERM;
		}
		inode = ext3_iget(sb, EXT3_RESIZE_INO);
		if (IS_ERR(inode)) {
			ext3_warning(sb, __func__,
				     "Error opening resize inode");
			return PTR_ERR(inode);
		}
	}

	if ((err = verify_group_input(sb, input)))
		goto exit_put;

	if ((err = setup_new_group_blocks(sb, input)))
		goto exit_put;

	/*
	 * We will always be modifying at least the superblock and a GDT
	 * block.  If we are adding a group past the last current GDT block,
	 * we will also modify the inode and the dindirect block.  If we
	 * are adding a group with superblock/GDT backups  we will also
	 * modify each of the reserved GDT dindirect blocks.
	 */
	handle = ext3_journal_start_sb(sb,
				       ext3_bg_has_super(sb, input->group) ?
				       3 + reserved_gdb : 4);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto exit_put;
	}

	mutex_lock(&sbi->s_resize_lock);
	if (input->group != sbi->s_groups_count) {
		ext3_warning(sb, __func__,
			     "multiple resizers run on filesystem!");
		err = -EBUSY;
		goto exit_journal;
	}

	if ((err = ext3_journal_get_write_access(handle, sbi->s_sbh)))
		goto exit_journal;

	/*
	 * We will only either add reserved group blocks to a backup group
	 * or remove reserved blocks for the first group in a new group block.
	 * Doing both would be mean more complex code, and sane people don't
	 * use non-sparse filesystems anymore.  This is already checked above.
	 */
	if (gdb_off) {
		primary = sbi->s_group_desc[gdb_num];
		if ((err = ext3_journal_get_write_access(handle, primary)))
			goto exit_journal;

		if (reserved_gdb && ext3_bg_num_gdb(sb, input->group) &&
		    (err = reserve_backup_gdb(handle, inode, input)))
			goto exit_journal;
	} else if ((err = add_new_gdb(handle, inode, input, &primary)))
		goto exit_journal;

	/*
	 * OK, now we've set up the new group.  Time to make it active.
	 *
	 * We do not lock all allocations via s_resize_lock
	 * so we have to be safe wrt. concurrent accesses the group
	 * data.  So we need to be careful to set all of the relevant
	 * group descriptor data etc. *before* we enable the group.
	 *
	 * The key field here is sbi->s_groups_count: as long as
	 * that retains its old value, nobody is going to access the new
	 * group.
	 *
	 * So first we update all the descriptor metadata for the new
	 * group; then we update the total disk blocks count; then we
	 * update the groups count to enable the group; then finally we
	 * update the free space counts so that the system can start
	 * using the new disk blocks.
	 */

	/* Update group descriptor block for new group */
	gdp = (struct ext3_group_desc *)primary->b_data + gdb_off;

	gdp->bg_block_bitmap = cpu_to_le32(input->block_bitmap);
	gdp->bg_inode_bitmap = cpu_to_le32(input->inode_bitmap);
	gdp->bg_inode_table = cpu_to_le32(input->inode_table);
	gdp->bg_free_blocks_count = cpu_to_le16(input->free_blocks_count);
	gdp->bg_free_inodes_count = cpu_to_le16(EXT3_INODES_PER_GROUP(sb));

	/*
	 * Make the new blocks and inodes valid next.  We do this before
	 * increasing the group count so that once the group is enabled,
	 * all of its blocks and inodes are already valid.
	 *
	 * We always allocate group-by-group, then block-by-block or
	 * inode-by-inode within a group, so enabling these
	 * blocks/inodes before the group is live won't actually let us
	 * allocate the new space yet.
	 */
	le32_add_cpu(&es->s_blocks_count, input->blocks_count);
	le32_add_cpu(&es->s_inodes_count, EXT3_INODES_PER_GROUP(sb));

	/*
	 * We need to protect s_groups_count against other CPUs seeing
	 * inconsistent state in the superblock.
	 *
	 * The precise rules we use are:
	 *
	 * * Writers of s_groups_count *must* hold s_resize_lock
	 * AND
	 * * Writers must perform a smp_wmb() after updating all dependent
	 *   data and before modifying the groups count
	 *
	 * * Readers must hold s_resize_lock over the access
	 * OR
	 * * Readers must perform an smp_rmb() after reading the groups count
	 *   and before reading any dependent data.
	 *
	 * NB. These rules can be relaxed when checking the group count
	 * while freeing data, as we can only allocate from a block
	 * group after serialising against the group count, and we can
	 * only then free after serialising in turn against that
	 * allocation.
	 */
	smp_wmb();

	/* Update the global fs size fields */
	sbi->s_groups_count++;

	err = ext3_journal_dirty_metadata(handle, primary);
	if (err)
		goto exit_journal;

	/* Update the reserved block counts only once the new group is
	 * active. */
	le32_add_cpu(&es->s_r_blocks_count, input->reserved_blocks);

	/* Update the free space counts */
	percpu_counter_add(&sbi->s_freeblocks_counter,
			   input->free_blocks_count);
	percpu_counter_add(&sbi->s_freeinodes_counter,
			   EXT3_INODES_PER_GROUP(sb));

	err = ext3_journal_dirty_metadata(handle, sbi->s_sbh);

exit_journal:
	mutex_unlock(&sbi->s_resize_lock);
	if ((err2 = ext3_journal_stop(handle)) && !err)
		err = err2;
	if (!err) {
		update_backups(sb, sbi->s_sbh->b_blocknr, (char *)es,
			       sizeof(struct ext3_super_block));
		update_backups(sb, primary->b_blocknr, primary->b_data,
			       primary->b_size);
	}
exit_put:
	iput(inode);
	return err;
} /* ext3_group_add */

/* Extend the filesystem to the new number of blocks specified.  This entry
 * point is only used to extend the current filesystem to the end of the last
 * existing group.  It can be accessed via ioctl, or by "remount,resize=<size>"
 * for emergencies (because it has no dependencies on reserved blocks).
 *
 * If we _really_ wanted, we could use default values to call ext3_group_add()
 * allow the "remount" trick to work for arbitrary resizing, assuming enough
 * GDT blocks are reserved to grow to the desired size.
 */
int ext3_group_extend(struct super_block *sb, struct ext3_super_block *es,
		      ext3_fsblk_t n_blocks_count)
{
	ext3_fsblk_t o_blocks_count;
	ext3_grpblk_t last;
	ext3_grpblk_t add;
	struct buffer_head * bh;
	handle_t *handle;
	int err;
	unsigned long freed_blocks;

	/* We don't need to worry about locking wrt other resizers just
	 * yet: we're going to revalidate es->s_blocks_count after
	 * taking the s_resize_lock below. */
	o_blocks_count = le32_to_cpu(es->s_blocks_count);

	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG "EXT3-fs: extending last group from "E3FSBLK
		       " up to "E3FSBLK" blocks\n",
		       o_blocks_count, n_blocks_count);

	if (n_blocks_count == 0 || n_blocks_count == o_blocks_count)
		return 0;

	if (n_blocks_count > (sector_t)(~0ULL) >> (sb->s_blocksize_bits - 9)) {
		printk(KERN_ERR "EXT3-fs: filesystem on %s:"
			" too large to resize to "E3FSBLK" blocks safely\n",
			sb->s_id, n_blocks_count);
		if (sizeof(sector_t) < 8)
			ext3_warning(sb, __func__,
			"CONFIG_LBDAF not enabled\n");
		return -EINVAL;
	}

	if (n_blocks_count < o_blocks_count) {
		ext3_warning(sb, __func__,
			     "can't shrink FS - resize aborted");
		return -EBUSY;
	}

	/* Handle the remaining blocks in the last group only. */
	last = (o_blocks_count - le32_to_cpu(es->s_first_data_block)) %
		EXT3_BLOCKS_PER_GROUP(sb);

	if (last == 0) {
		ext3_warning(sb, __func__,
			     "need to use ext2online to resize further");
		return -EPERM;
	}

	add = EXT3_BLOCKS_PER_GROUP(sb) - last;

	if (o_blocks_count + add < o_blocks_count) {
		ext3_warning(sb, __func__, "blocks_count overflow");
		return -EINVAL;
	}

	if (o_blocks_count + add > n_blocks_count)
		add = n_blocks_count - o_blocks_count;

	if (o_blocks_count + add < n_blocks_count)
		ext3_warning(sb, __func__,
			     "will only finish group ("E3FSBLK
			     " blocks, %u new)",
			     o_blocks_count + add, add);

	/* See if the device is actually as big as what was requested */
	bh = sb_bread(sb, o_blocks_count + add -1);
	if (!bh) {
		ext3_warning(sb, __func__,
			     "can't read last block, resize aborted");
		return -ENOSPC;
	}
	brelse(bh);

	/* We will update the superblock, one block bitmap, and
	 * one group descriptor via ext3_free_blocks().
	 */
	handle = ext3_journal_start_sb(sb, 3);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		ext3_warning(sb, __func__, "error %d on journal start",err);
		goto exit_put;
	}

	mutex_lock(&EXT3_SB(sb)->s_resize_lock);
	if (o_blocks_count != le32_to_cpu(es->s_blocks_count)) {
		ext3_warning(sb, __func__,
			     "multiple resizers run on filesystem!");
		mutex_unlock(&EXT3_SB(sb)->s_resize_lock);
		ext3_journal_stop(handle);
		err = -EBUSY;
		goto exit_put;
	}

	if ((err = ext3_journal_get_write_access(handle,
						 EXT3_SB(sb)->s_sbh))) {
		ext3_warning(sb, __func__,
			     "error %d on journal write access", err);
		mutex_unlock(&EXT3_SB(sb)->s_resize_lock);
		ext3_journal_stop(handle);
		goto exit_put;
	}
	es->s_blocks_count = cpu_to_le32(o_blocks_count + add);
	err = ext3_journal_dirty_metadata(handle, EXT3_SB(sb)->s_sbh);
	mutex_unlock(&EXT3_SB(sb)->s_resize_lock);
	if (err) {
		ext3_warning(sb, __func__,
			     "error %d on journal dirty metadata", err);
		ext3_journal_stop(handle);
		goto exit_put;
	}
	ext3_debug("freeing blocks "E3FSBLK" through "E3FSBLK"\n",
		   o_blocks_count, o_blocks_count + add);
	ext3_free_blocks_sb(handle, sb, o_blocks_count, add, &freed_blocks);
	ext3_debug("freed blocks "E3FSBLK" through "E3FSBLK"\n",
		   o_blocks_count, o_blocks_count + add);
	if ((err = ext3_journal_stop(handle)))
		goto exit_put;
	if (test_opt(sb, DEBUG))
		printk(KERN_DEBUG "EXT3-fs: extended group to %u blocks\n",
		       le32_to_cpu(es->s_blocks_count));
	update_backups(sb, EXT3_SB(sb)->s_sbh->b_blocknr, (char *)es,
		       sizeof(struct ext3_super_block));
exit_put:
	return err;
} /* ext3_group_extend */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/resize.c */
/************************************************************/
/*
 * Interface between ext3 and JBD
 */

// #include "ext3.h"

int __ext3_journal_get_undo_access(const char *where, handle_t *handle,
				struct buffer_head *bh)
{
	int err = journal_get_undo_access(handle, bh);
	if (err)
		ext3_journal_abort_handle(where, __func__, bh, handle,err);
	return err;
}

int __ext3_journal_get_write_access(const char *where, handle_t *handle,
				struct buffer_head *bh)
{
	int err = journal_get_write_access(handle, bh);
	if (err)
		ext3_journal_abort_handle(where, __func__, bh, handle,err);
	return err;
}

int __ext3_journal_forget(const char *where, handle_t *handle,
				struct buffer_head *bh)
{
	int err = journal_forget(handle, bh);
	if (err)
		ext3_journal_abort_handle(where, __func__, bh, handle,err);
	return err;
}

int __ext3_journal_revoke(const char *where, handle_t *handle,
				unsigned long blocknr, struct buffer_head *bh)
{
	int err = journal_revoke(handle, blocknr, bh);
	if (err)
		ext3_journal_abort_handle(where, __func__, bh, handle,err);
	return err;
}

int __ext3_journal_get_create_access(const char *where,
				handle_t *handle, struct buffer_head *bh)
{
	int err = journal_get_create_access(handle, bh);
	if (err)
		ext3_journal_abort_handle(where, __func__, bh, handle,err);
	return err;
}

int __ext3_journal_dirty_metadata(const char *where,
				handle_t *handle, struct buffer_head *bh)
{
	int err = journal_dirty_metadata(handle, bh);
	if (err)
		ext3_journal_abort_handle(where, __func__, bh, handle,err);
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/ext3_jbd.c */
/************************************************************/
/*
 * linux/fs/ext3/xattr.c
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher, <agruen@suse.de>
 *
 * Fix by Harrison Xing <harrison@mountainviewdata.com>.
 * Ext3 code with a lot of help from Eric Jarman <ejarman@acm.org>.
 * Extended attributes for symlinks and special files added per
 *  suggestion of Luka Renko <luka.renko@hermes.si>.
 * xattr consolidation Copyright (c) 2004 James Morris <jmorris@redhat.com>,
 *  Red Hat Inc.
 * ea-in-inode support by Alex Tomas <alex@clusterfs.com> aka bzzz
 *  and Andreas Gruenbacher <agruen@suse.de>.
 */

/*
 * Extended attributes are stored directly in inodes (on file systems with
 * inodes bigger than 128 bytes) and on additional disk blocks. The i_file_acl
 * field contains the block number if an inode uses an additional block. All
 * attributes must fit in the inode and one additional block. Blocks that
 * contain the identical set of attributes may be shared among several inodes.
 * Identical blocks are detected by keeping a cache of blocks that have
 * recently been accessed.
 *
 * The attributes in inodes and on blocks have a different header; the entries
 * are stored in the same format:
 *
 *   +------------------+
 *   | header           |
 *   | entry 1          | |
 *   | entry 2          | | growing downwards
 *   | entry 3          | v
 *   | four null bytes  |
 *   | . . .            |
 *   | value 1          | ^
 *   | value 3          | | growing upwards
 *   | value 2          | |
 *   +------------------+
 *
 * The header is followed by multiple entry descriptors. In disk blocks, the
 * entry descriptors are kept sorted. In inodes, they are unsorted. The
 * attribute values are aligned to the end of the block in no specific order.
 *
 * Locking strategy
 * ----------------
 * EXT3_I(inode)->i_file_acl is protected by EXT3_I(inode)->xattr_sem.
 * EA blocks are only changed if they are exclusive to an inode, so
 * holding xattr_sem also means that nothing but the EA block's reference
 * count can change. Multiple writers to the same block are synchronized
 * by the buffer lock.
 */

// #include "ext3.h"
#include <linux/mbcache.h>
// #include <linux/quotaops.h>
// #include "xattr.h"
// #include "acl.h"
#include "../../inc/__fss.h"

#define BHDR(bh) ((struct ext3_xattr_header *)((bh)->b_data))
#define ENTRY(ptr) ((struct ext3_xattr_entry *)(ptr))
#define BFIRST(bh) ENTRY(BHDR(bh)+1)
#define IS_LAST_ENTRY(entry) (*(__u32 *)(entry) == 0)

#define IHDR(inode, raw_inode) \
	((struct ext3_xattr_ibody_header *) \
		((void *)raw_inode + \
		 EXT3_GOOD_OLD_INODE_SIZE + \
		 EXT3_I(inode)->i_extra_isize))
#define IFIRST(hdr) ((struct ext3_xattr_entry *)((hdr)+1))

#ifdef EXT3_XATTR_DEBUG
# define ea_idebug(inode, f...) do { \
		printk(KERN_DEBUG "inode %s:%lu: ", \
			inode->i_sb->s_id, inode->i_ino); \
		printk(f); \
		printk("\n"); \
	} while (0)
# define ea_bdebug(bh, f...) do { \
		char b[BDEVNAME_SIZE]; \
		printk(KERN_DEBUG "block %s:%lu: ", \
			bdevname(bh->b_bdev, b), \
			(unsigned long) bh->b_blocknr); \
		printk(f); \
		printk("\n"); \
	} while (0)
#else
# define ea_idebug(f...)
# define ea_bdebug(f...)
#endif

static void ext3_xattr_cache_insert(struct buffer_head *);
static struct buffer_head *ext3_xattr_cache_find(struct inode *,
						 struct ext3_xattr_header *,
						 struct mb_cache_entry **);
static void ext3_xattr_rehash(struct ext3_xattr_header *,
			      struct ext3_xattr_entry *);
static int ext3_xattr_list(struct dentry *dentry, char *buffer,
			   size_t buffer_size);

static struct mb_cache *ext3_xattr_cache;

static const struct xattr_handler *ext3_xattr_handler_map[] = {
	[EXT3_XATTR_INDEX_USER]		     = &ext3_xattr_user_handler,
#ifdef CONFIG_EXT3_FS_POSIX_ACL
	[EXT3_XATTR_INDEX_POSIX_ACL_ACCESS]  = &posix_acl_access_xattr_handler,
	[EXT3_XATTR_INDEX_POSIX_ACL_DEFAULT] = &posix_acl_default_xattr_handler,
#endif
	[EXT3_XATTR_INDEX_TRUSTED]	     = &ext3_xattr_trusted_handler,
#ifdef CONFIG_EXT3_FS_SECURITY
	[EXT3_XATTR_INDEX_SECURITY]	     = &ext3_xattr_security_handler,
#endif
};

const struct xattr_handler *ext3_xattr_handlers[] = {
	&ext3_xattr_user_handler,
	&ext3_xattr_trusted_handler,
#ifdef CONFIG_EXT3_FS_POSIX_ACL
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
#ifdef CONFIG_EXT3_FS_SECURITY
	&ext3_xattr_security_handler,
#endif
	NULL
};

static inline const struct xattr_handler *
ext3_xattr_handler(int name_index)
{
	const struct xattr_handler *handler = NULL;

	if (name_index > 0 && name_index < ARRAY_SIZE(ext3_xattr_handler_map))
		handler = ext3_xattr_handler_map[name_index];
	return handler;
}

/*
 * Inode operation listxattr()
 *
 * dentry->d_inode->i_mutex: don't care
 */
ssize_t
ext3_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	return ext3_xattr_list(dentry, buffer, size);
}

static int
ext3_xattr_check_names(struct ext3_xattr_entry *entry, void *end)
{
	while (!IS_LAST_ENTRY(entry)) {
		struct ext3_xattr_entry *next = EXT3_XATTR_NEXT(entry);
		if ((void *)next >= end)
			return -EIO;
		entry = next;
	}
	return 0;
}

static inline int
ext3_xattr_check_block(struct buffer_head *bh)
{
	int error;

	if (BHDR(bh)->h_magic != cpu_to_le32(EXT3_XATTR_MAGIC) ||
	    BHDR(bh)->h_blocks != cpu_to_le32(1))
		return -EIO;
	error = ext3_xattr_check_names(BFIRST(bh), bh->b_data + bh->b_size);
	return error;
}

static inline int
ext3_xattr_check_entry(struct ext3_xattr_entry *entry, size_t size)
{
	size_t value_size = le32_to_cpu(entry->e_value_size);

	if (entry->e_value_block != 0 || value_size > size ||
	    le16_to_cpu(entry->e_value_offs) + value_size > size)
		return -EIO;
	return 0;
}

static int
ext3_xattr_find_entry(struct ext3_xattr_entry **pentry, int name_index,
		      const char *name, size_t size, int sorted)
{
	struct ext3_xattr_entry *entry;
	size_t name_len;
	int cmp = 1;

	if (name == NULL)
		return -EINVAL;
	name_len = strlen(name);
	entry = *pentry;
	for (; !IS_LAST_ENTRY(entry); entry = EXT3_XATTR_NEXT(entry)) {
		cmp = name_index - entry->e_name_index;
		if (!cmp)
			cmp = name_len - entry->e_name_len;
		if (!cmp)
			cmp = memcmp(name, entry->e_name, name_len);
		if (cmp <= 0 && (sorted || cmp == 0))
			break;
	}
	*pentry = entry;
	if (!cmp && ext3_xattr_check_entry(entry, size))
			return -EIO;
	return cmp ? -ENODATA : 0;
}

static int
ext3_xattr_block_get(struct inode *inode, int name_index, const char *name,
		     void *buffer, size_t buffer_size)
{
	struct buffer_head *bh = NULL;
	struct ext3_xattr_entry *entry;
	size_t size;
	int error;

	ea_idebug(inode, "name=%d.%s, buffer=%p, buffer_size=%ld",
		  name_index, name, buffer, (long)buffer_size);

	error = -ENODATA;
	if (!EXT3_I(inode)->i_file_acl)
		goto cleanup;
	ea_idebug(inode, "reading block %u", EXT3_I(inode)->i_file_acl);
	bh = sb_bread(inode->i_sb, EXT3_I(inode)->i_file_acl);
	if (!bh)
		goto cleanup;
	ea_bdebug(bh, "b_count=%d, refcount=%d",
		atomic_read(&(bh->b_count)), le32_to_cpu(BHDR(bh)->h_refcount));
	if (ext3_xattr_check_block(bh)) {
bad_block:	ext3_error(inode->i_sb, __func__,
			   "inode %lu: bad block "E3FSBLK, inode->i_ino,
			   EXT3_I(inode)->i_file_acl);
		error = -EIO;
		goto cleanup;
	}
	ext3_xattr_cache_insert(bh);
	entry = BFIRST(bh);
	error = ext3_xattr_find_entry(&entry, name_index, name, bh->b_size, 1);
	if (error == -EIO)
		goto bad_block;
	if (error)
		goto cleanup;
	size = le32_to_cpu(entry->e_value_size);
	if (buffer) {
		error = -ERANGE;
		if (size > buffer_size)
			goto cleanup;
		memcpy(buffer, bh->b_data + le16_to_cpu(entry->e_value_offs),
		       size);
	}
	error = size;

cleanup:
	brelse(bh);
	return error;
}

static int
ext3_xattr_ibody_get(struct inode *inode, int name_index, const char *name,
		     void *buffer, size_t buffer_size)
{
	struct ext3_xattr_ibody_header *header;
	struct ext3_xattr_entry *entry;
	struct ext3_inode *raw_inode;
	struct ext3_iloc iloc;
	size_t size;
	void *end;
	int error;

	if (!ext3_test_inode_state(inode, EXT3_STATE_XATTR))
		return -ENODATA;
	error = ext3_get_inode_loc(inode, &iloc);
	if (error)
		return error;
	raw_inode = ext3_raw_inode(&iloc);
	header = IHDR(inode, raw_inode);
	entry = IFIRST(header);
	end = (void *)raw_inode + EXT3_SB(inode->i_sb)->s_inode_size;
	error = ext3_xattr_check_names(entry, end);
	if (error)
		goto cleanup;
	error = ext3_xattr_find_entry(&entry, name_index, name,
				      end - (void *)entry, 0);
	if (error)
		goto cleanup;
	size = le32_to_cpu(entry->e_value_size);
	if (buffer) {
		error = -ERANGE;
		if (size > buffer_size)
			goto cleanup;
		memcpy(buffer, (void *)IFIRST(header) +
		       le16_to_cpu(entry->e_value_offs), size);
	}
	error = size;

cleanup:
	brelse(iloc.bh);
	return error;
}

/*
 * ext3_xattr_get()
 *
 * Copy an extended attribute into the buffer
 * provided, or compute the buffer size required.
 * Buffer is NULL to compute the size of the buffer required.
 *
 * Returns a negative error number on failure, or the number of bytes
 * used / required on success.
 */
int
ext3_xattr_get(struct inode *inode, int name_index, const char *name,
	       void *buffer, size_t buffer_size)
{
	int error;

	down_read(&EXT3_I(inode)->xattr_sem);
	error = ext3_xattr_ibody_get(inode, name_index, name, buffer,
				     buffer_size);
	if (error == -ENODATA)
		error = ext3_xattr_block_get(inode, name_index, name, buffer,
					     buffer_size);
	up_read(&EXT3_I(inode)->xattr_sem);
	return error;
}

static int
ext3_xattr_list_entries(struct dentry *dentry, struct ext3_xattr_entry *entry,
			char *buffer, size_t buffer_size)
{
	size_t rest = buffer_size;

	for (; !IS_LAST_ENTRY(entry); entry = EXT3_XATTR_NEXT(entry)) {
		const struct xattr_handler *handler =
			ext3_xattr_handler(entry->e_name_index);

		if (handler) {
			size_t size = handler->list(dentry, buffer, rest,
						    entry->e_name,
						    entry->e_name_len,
						    handler->flags);
			if (buffer) {
				if (size > rest)
					return -ERANGE;
				buffer += size;
			}
			rest -= size;
		}
	}
	return buffer_size - rest;
}

static int
ext3_xattr_block_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct inode *inode = dentry->d_inode;
	struct buffer_head *bh = NULL;
	int error;

	ea_idebug(inode, "buffer=%p, buffer_size=%ld",
		  buffer, (long)buffer_size);

	error = 0;
	if (!EXT3_I(inode)->i_file_acl)
		goto cleanup;
	ea_idebug(inode, "reading block %u", EXT3_I(inode)->i_file_acl);
	bh = sb_bread(inode->i_sb, EXT3_I(inode)->i_file_acl);
	error = -EIO;
	if (!bh)
		goto cleanup;
	ea_bdebug(bh, "b_count=%d, refcount=%d",
		atomic_read(&(bh->b_count)), le32_to_cpu(BHDR(bh)->h_refcount));
	if (ext3_xattr_check_block(bh)) {
		ext3_error(inode->i_sb, __func__,
			   "inode %lu: bad block "E3FSBLK, inode->i_ino,
			   EXT3_I(inode)->i_file_acl);
		error = -EIO;
		goto cleanup;
	}
	ext3_xattr_cache_insert(bh);
	error = ext3_xattr_list_entries(dentry, BFIRST(bh), buffer, buffer_size);

cleanup:
	brelse(bh);

	return error;
}

static int
ext3_xattr_ibody_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct inode *inode = dentry->d_inode;
	struct ext3_xattr_ibody_header *header;
	struct ext3_inode *raw_inode;
	struct ext3_iloc iloc;
	void *end;
	int error;

	if (!ext3_test_inode_state(inode, EXT3_STATE_XATTR))
		return 0;
	error = ext3_get_inode_loc(inode, &iloc);
	if (error)
		return error;
	raw_inode = ext3_raw_inode(&iloc);
	header = IHDR(inode, raw_inode);
	end = (void *)raw_inode + EXT3_SB(inode->i_sb)->s_inode_size;
	error = ext3_xattr_check_names(IFIRST(header), end);
	if (error)
		goto cleanup;
	error = ext3_xattr_list_entries(dentry, IFIRST(header),
					buffer, buffer_size);

cleanup:
	brelse(iloc.bh);
	return error;
}

/*
 * ext3_xattr_list()
 *
 * Copy a list of attribute names into the buffer
 * provided, or compute the buffer size required.
 * Buffer is NULL to compute the size of the buffer required.
 *
 * Returns a negative error number on failure, or the number of bytes
 * used / required on success.
 */
static int
ext3_xattr_list(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int i_error, b_error;

	down_read(&EXT3_I(dentry->d_inode)->xattr_sem);
	i_error = ext3_xattr_ibody_list(dentry, buffer, buffer_size);
	if (i_error < 0) {
		b_error = 0;
	} else {
		if (buffer) {
			buffer += i_error;
			buffer_size -= i_error;
		}
		b_error = ext3_xattr_block_list(dentry, buffer, buffer_size);
		if (b_error < 0)
			i_error = 0;
	}
	up_read(&EXT3_I(dentry->d_inode)->xattr_sem);
	return i_error + b_error;
}

/*
 * If the EXT3_FEATURE_COMPAT_EXT_ATTR feature of this file system is
 * not set, set it.
 */
static void ext3_xattr_update_super_block(handle_t *handle,
					  struct super_block *sb)
{
	if (EXT3_HAS_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_EXT_ATTR))
		return;

	if (ext3_journal_get_write_access(handle, EXT3_SB(sb)->s_sbh) == 0) {
		EXT3_SET_COMPAT_FEATURE(sb, EXT3_FEATURE_COMPAT_EXT_ATTR);
		ext3_journal_dirty_metadata(handle, EXT3_SB(sb)->s_sbh);
	}
}

/*
 * Release the xattr block BH: If the reference count is > 1, decrement
 * it; otherwise free the block.
 */
static void
ext3_xattr_release_block(handle_t *handle, struct inode *inode,
			 struct buffer_head *bh)
{
	struct mb_cache_entry *ce = NULL;
	int error = 0;

	ce = mb_cache_entry_get(ext3_xattr_cache, bh->b_bdev, bh->b_blocknr);
	error = ext3_journal_get_write_access(handle, bh);
	if (error)
		 goto out;

	lock_buffer(bh);

	if (BHDR(bh)->h_refcount == cpu_to_le32(1)) {
		ea_bdebug(bh, "refcount now=0; freeing");
		if (ce)
			mb_cache_entry_free(ce);
		ext3_free_blocks(handle, inode, bh->b_blocknr, 1);
		get_bh(bh);
		ext3_forget(handle, 1, inode, bh, bh->b_blocknr);
	} else {
		le32_add_cpu(&BHDR(bh)->h_refcount, -1);
		error = ext3_journal_dirty_metadata(handle, bh);
		if (IS_SYNC(inode))
			handle->h_sync = 1;
		dquot_free_block(inode, 1);
		ea_bdebug(bh, "refcount now=%d; releasing",
			  le32_to_cpu(BHDR(bh)->h_refcount));
		if (ce)
			mb_cache_entry_release(ce);
	}
	unlock_buffer(bh);
out:
	ext3_std_error(inode->i_sb, error);
	return;
}

struct ext3_xattr_info {
	int name_index;
	const char *name;
	const void *value;
	size_t value_len;
};

struct ext3_xattr_search {
	struct ext3_xattr_entry *first;
	void *base;
	void *end;
	struct ext3_xattr_entry *here;
	int not_found;
};

static int
ext3_xattr_set_entry(struct ext3_xattr_info *i, struct ext3_xattr_search *s)
{
	struct ext3_xattr_entry *last;
	size_t free, min_offs = s->end - s->base, name_len = strlen(i->name);

	/* Compute min_offs and last. */
	last = s->first;
	for (; !IS_LAST_ENTRY(last); last = EXT3_XATTR_NEXT(last)) {
		if (!last->e_value_block && last->e_value_size) {
			size_t offs = le16_to_cpu(last->e_value_offs);
			if (offs < min_offs)
				min_offs = offs;
		}
	}
	free = min_offs - ((void *)last - s->base) - sizeof(__u32);
	if (!s->not_found) {
		if (!s->here->e_value_block && s->here->e_value_size) {
			size_t size = le32_to_cpu(s->here->e_value_size);
			free += EXT3_XATTR_SIZE(size);
		}
		free += EXT3_XATTR_LEN(name_len);
	}
	if (i->value) {
		if (free < EXT3_XATTR_SIZE(i->value_len) ||
		    free < EXT3_XATTR_LEN(name_len) +
			   EXT3_XATTR_SIZE(i->value_len))
			return -ENOSPC;
	}

	if (i->value && s->not_found) {
		/* Insert the new name. */
		size_t size = EXT3_XATTR_LEN(name_len);
		size_t rest = (void *)last - (void *)s->here + sizeof(__u32);
		memmove((void *)s->here + size, s->here, rest);
		memset(s->here, 0, size);
		s->here->e_name_index = i->name_index;
		s->here->e_name_len = name_len;
		memcpy(s->here->e_name, i->name, name_len);
	} else {
		if (!s->here->e_value_block && s->here->e_value_size) {
			void *first_val = s->base + min_offs;
			size_t offs = le16_to_cpu(s->here->e_value_offs);
			void *val = s->base + offs;
			size_t size = EXT3_XATTR_SIZE(
				le32_to_cpu(s->here->e_value_size));

			if (i->value && size == EXT3_XATTR_SIZE(i->value_len)) {
				/* The old and the new value have the same
				   size. Just replace. */
				s->here->e_value_size =
					cpu_to_le32(i->value_len);
				memset(val + size - EXT3_XATTR_PAD, 0,
				       EXT3_XATTR_PAD); /* Clear pad bytes. */
				memcpy(val, i->value, i->value_len);
				return 0;
			}

			/* Remove the old value. */
			memmove(first_val + size, first_val, val - first_val);
			memset(first_val, 0, size);
			s->here->e_value_size = 0;
			s->here->e_value_offs = 0;
			min_offs += size;

			/* Adjust all value offsets. */
			last = s->first;
			while (!IS_LAST_ENTRY(last)) {
				size_t o = le16_to_cpu(last->e_value_offs);
				if (!last->e_value_block &&
				    last->e_value_size && o < offs)
					last->e_value_offs =
						cpu_to_le16(o + size);
				last = EXT3_XATTR_NEXT(last);
			}
		}
		if (!i->value) {
			/* Remove the old name. */
			size_t size = EXT3_XATTR_LEN(name_len);
			last = ENTRY((void *)last - size);
			memmove(s->here, (void *)s->here + size,
				(void *)last - (void *)s->here + sizeof(__u32));
			memset(last, 0, size);
		}
	}

	if (i->value) {
		/* Insert the new value. */
		s->here->e_value_size = cpu_to_le32(i->value_len);
		if (i->value_len) {
			size_t size = EXT3_XATTR_SIZE(i->value_len);
			void *val = s->base + min_offs - size;
			s->here->e_value_offs = cpu_to_le16(min_offs - size);
			memset(val + size - EXT3_XATTR_PAD, 0,
			       EXT3_XATTR_PAD); /* Clear the pad bytes. */
			memcpy(val, i->value, i->value_len);
		}
	}
	return 0;
}

struct ext3_xattr_block_find {
	struct ext3_xattr_search s;
	struct buffer_head *bh;
};

static int
ext3_xattr_block_find(struct inode *inode, struct ext3_xattr_info *i,
		      struct ext3_xattr_block_find *bs)
{
	struct super_block *sb = inode->i_sb;
	int error;

	ea_idebug(inode, "name=%d.%s, value=%p, value_len=%ld",
		  i->name_index, i->name, i->value, (long)i->value_len);

	if (EXT3_I(inode)->i_file_acl) {
		/* The inode already has an extended attribute block. */
		bs->bh = sb_bread(sb, EXT3_I(inode)->i_file_acl);
		error = -EIO;
		if (!bs->bh)
			goto cleanup;
		ea_bdebug(bs->bh, "b_count=%d, refcount=%d",
			atomic_read(&(bs->bh->b_count)),
			le32_to_cpu(BHDR(bs->bh)->h_refcount));
		if (ext3_xattr_check_block(bs->bh)) {
			ext3_error(sb, __func__,
				"inode %lu: bad block "E3FSBLK, inode->i_ino,
				EXT3_I(inode)->i_file_acl);
			error = -EIO;
			goto cleanup;
		}
		/* Find the named attribute. */
		bs->s.base = BHDR(bs->bh);
		bs->s.first = BFIRST(bs->bh);
		bs->s.end = bs->bh->b_data + bs->bh->b_size;
		bs->s.here = bs->s.first;
		error = ext3_xattr_find_entry(&bs->s.here, i->name_index,
					      i->name, bs->bh->b_size, 1);
		if (error && error != -ENODATA)
			goto cleanup;
		bs->s.not_found = error;
	}
	error = 0;

cleanup:
	return error;
}

static int
ext3_xattr_block_set(handle_t *handle, struct inode *inode,
		     struct ext3_xattr_info *i,
		     struct ext3_xattr_block_find *bs)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *new_bh = NULL;
	struct ext3_xattr_search *s = &bs->s;
	struct mb_cache_entry *ce = NULL;
	int error = 0;

#define header(x) ((struct ext3_xattr_header *)(x))

	if (i->value && i->value_len > sb->s_blocksize)
		return -ENOSPC;
	if (s->base) {
		ce = mb_cache_entry_get(ext3_xattr_cache, bs->bh->b_bdev,
					bs->bh->b_blocknr);
		error = ext3_journal_get_write_access(handle, bs->bh);
		if (error)
			goto cleanup;
		lock_buffer(bs->bh);

		if (header(s->base)->h_refcount == cpu_to_le32(1)) {
			if (ce) {
				mb_cache_entry_free(ce);
				ce = NULL;
			}
			ea_bdebug(bs->bh, "modifying in-place");
			error = ext3_xattr_set_entry(i, s);
			if (!error) {
				if (!IS_LAST_ENTRY(s->first))
					ext3_xattr_rehash(header(s->base),
							  s->here);
				ext3_xattr_cache_insert(bs->bh);
			}
			unlock_buffer(bs->bh);
			if (error == -EIO)
				goto bad_block;
			if (!error)
				error = ext3_journal_dirty_metadata(handle,
								    bs->bh);
			if (error)
				goto cleanup;
			goto inserted;
		} else {
			int offset = (char *)s->here - bs->bh->b_data;

			unlock_buffer(bs->bh);
			journal_release_buffer(handle, bs->bh);

			if (ce) {
				mb_cache_entry_release(ce);
				ce = NULL;
			}
			ea_bdebug(bs->bh, "cloning");
			s->base = kmalloc(bs->bh->b_size, GFP_NOFS);
			error = -ENOMEM;
			if (s->base == NULL)
				goto cleanup;
			memcpy(s->base, BHDR(bs->bh), bs->bh->b_size);
			s->first = ENTRY(header(s->base)+1);
			header(s->base)->h_refcount = cpu_to_le32(1);
			s->here = ENTRY(s->base + offset);
			s->end = s->base + bs->bh->b_size;
		}
	} else {
		/* Allocate a buffer where we construct the new block. */
		s->base = kzalloc(sb->s_blocksize, GFP_NOFS);
		/* assert(header == s->base) */
		error = -ENOMEM;
		if (s->base == NULL)
			goto cleanup;
		header(s->base)->h_magic = cpu_to_le32(EXT3_XATTR_MAGIC);
		header(s->base)->h_blocks = cpu_to_le32(1);
		header(s->base)->h_refcount = cpu_to_le32(1);
		s->first = ENTRY(header(s->base)+1);
		s->here = ENTRY(header(s->base)+1);
		s->end = s->base + sb->s_blocksize;
	}

	error = ext3_xattr_set_entry(i, s);
	if (error == -EIO)
		goto bad_block;
	if (error)
		goto cleanup;
	if (!IS_LAST_ENTRY(s->first))
		ext3_xattr_rehash(header(s->base), s->here);

inserted:
	if (!IS_LAST_ENTRY(s->first)) {
		new_bh = ext3_xattr_cache_find(inode, header(s->base), &ce);
		if (new_bh) {
			/* We found an identical block in the cache. */
			if (new_bh == bs->bh)
				ea_bdebug(new_bh, "keeping");
			else {
				/* The old block is released after updating
				   the inode. */
				error = dquot_alloc_block(inode, 1);
				if (error)
					goto cleanup;
				error = ext3_journal_get_write_access(handle,
								      new_bh);
				if (error)
					goto cleanup_dquot;
				lock_buffer(new_bh);
				le32_add_cpu(&BHDR(new_bh)->h_refcount, 1);
				ea_bdebug(new_bh, "reusing; refcount now=%d",
					le32_to_cpu(BHDR(new_bh)->h_refcount));
				unlock_buffer(new_bh);
				error = ext3_journal_dirty_metadata(handle,
								    new_bh);
				if (error)
					goto cleanup_dquot;
			}
			mb_cache_entry_release(ce);
			ce = NULL;
		} else if (bs->bh && s->base == bs->bh->b_data) {
			/* We were modifying this block in-place. */
			ea_bdebug(bs->bh, "keeping this block");
			new_bh = bs->bh;
			get_bh(new_bh);
		} else {
			/* We need to allocate a new block */
			ext3_fsblk_t goal = ext3_group_first_block_no(sb,
						EXT3_I(inode)->i_block_group);
			ext3_fsblk_t block;

			/*
			 * Protect us agaist concurrent allocations to the
			 * same inode from ext3_..._writepage(). Reservation
			 * code does not expect racing allocations.
			 */
			mutex_lock(&EXT3_I(inode)->truncate_mutex);
			block = ext3_new_block(handle, inode, goal, &error);
			mutex_unlock(&EXT3_I(inode)->truncate_mutex);
			if (error)
				goto cleanup;
			ea_idebug(inode, "creating block %d", block);

			new_bh = sb_getblk(sb, block);
			if (unlikely(!new_bh)) {
getblk_failed:
				ext3_free_blocks(handle, inode, block, 1);
				error = -ENOMEM;
				goto cleanup;
			}
			lock_buffer(new_bh);
			error = ext3_journal_get_create_access(handle, new_bh);
			if (error) {
				unlock_buffer(new_bh);
				goto getblk_failed;
			}
			memcpy(new_bh->b_data, s->base, new_bh->b_size);
			set_buffer_uptodate(new_bh);
			unlock_buffer(new_bh);
			ext3_xattr_cache_insert(new_bh);
			error = ext3_journal_dirty_metadata(handle, new_bh);
			if (error)
				goto cleanup;
		}
	}

	/* Update the inode. */
	EXT3_I(inode)->i_file_acl = new_bh ? new_bh->b_blocknr : 0;

	/* Drop the previous xattr block. */
	if (bs->bh && bs->bh != new_bh)
		ext3_xattr_release_block(handle, inode, bs->bh);
	error = 0;

cleanup:
	if (ce)
		mb_cache_entry_release(ce);
	brelse(new_bh);
	if (!(bs->bh && s->base == bs->bh->b_data))
		kfree(s->base);

	return error;

cleanup_dquot:
	dquot_free_block(inode, 1);
	goto cleanup;

bad_block:
	ext3_error(inode->i_sb, __func__,
		   "inode %lu: bad block "E3FSBLK, inode->i_ino,
		   EXT3_I(inode)->i_file_acl);
	goto cleanup;

#undef header
}

struct ext3_xattr_ibody_find {
	struct ext3_xattr_search s;
	struct ext3_iloc iloc;
};

static int
ext3_xattr_ibody_find(struct inode *inode, struct ext3_xattr_info *i,
		      struct ext3_xattr_ibody_find *is)
{
	struct ext3_xattr_ibody_header *header;
	struct ext3_inode *raw_inode;
	int error;

	if (EXT3_I(inode)->i_extra_isize == 0)
		return 0;
	raw_inode = ext3_raw_inode(&is->iloc);
	header = IHDR(inode, raw_inode);
	is->s.base = is->s.first = IFIRST(header);
	is->s.here = is->s.first;
	is->s.end = (void *)raw_inode + EXT3_SB(inode->i_sb)->s_inode_size;
	if (ext3_test_inode_state(inode, EXT3_STATE_XATTR)) {
		error = ext3_xattr_check_names(IFIRST(header), is->s.end);
		if (error)
			return error;
		/* Find the named attribute. */
		error = ext3_xattr_find_entry(&is->s.here, i->name_index,
					      i->name, is->s.end -
					      (void *)is->s.base, 0);
		if (error && error != -ENODATA)
			return error;
		is->s.not_found = error;
	}
	return 0;
}

static int
ext3_xattr_ibody_set(handle_t *handle, struct inode *inode,
		     struct ext3_xattr_info *i,
		     struct ext3_xattr_ibody_find *is)
{
	struct ext3_xattr_ibody_header *header;
	struct ext3_xattr_search *s = &is->s;
	int error;

	if (EXT3_I(inode)->i_extra_isize == 0)
		return -ENOSPC;
	error = ext3_xattr_set_entry(i, s);
	if (error)
		return error;
	header = IHDR(inode, ext3_raw_inode(&is->iloc));
	if (!IS_LAST_ENTRY(s->first)) {
		header->h_magic = cpu_to_le32(EXT3_XATTR_MAGIC);
		ext3_set_inode_state(inode, EXT3_STATE_XATTR);
	} else {
		header->h_magic = cpu_to_le32(0);
		ext3_clear_inode_state(inode, EXT3_STATE_XATTR);
	}
	return 0;
}

/*
 * ext3_xattr_set_handle()
 *
 * Create, replace or remove an extended attribute for this inode.  Value
 * is NULL to remove an existing extended attribute, and non-NULL to
 * either replace an existing extended attribute, or create a new extended
 * attribute. The flags XATTR_REPLACE and XATTR_CREATE
 * specify that an extended attribute must exist and must not exist
 * previous to the call, respectively.
 *
 * Returns 0, or a negative error number on failure.
 */
int
ext3_xattr_set_handle(handle_t *handle, struct inode *inode, int name_index,
		      const char *name, const void *value, size_t value_len,
		      int flags)
{
	struct ext3_xattr_info i = {
		.name_index = name_index,
		.name = name,
		.value = value,
		.value_len = value_len,

	};
	struct ext3_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ext3_xattr_block_find bs = {
		.s = { .not_found = -ENODATA, },
	};
	int error;

	if (!name)
		return -EINVAL;
	if (strlen(name) > 255)
		return -ERANGE;
	down_write(&EXT3_I(inode)->xattr_sem);
	error = ext3_get_inode_loc(inode, &is.iloc);
	if (error)
		goto cleanup;

	error = ext3_journal_get_write_access(handle, is.iloc.bh);
	if (error)
		goto cleanup;

	if (ext3_test_inode_state(inode, EXT3_STATE_NEW)) {
		struct ext3_inode *raw_inode = ext3_raw_inode(&is.iloc);
		memset(raw_inode, 0, EXT3_SB(inode->i_sb)->s_inode_size);
		ext3_clear_inode_state(inode, EXT3_STATE_NEW);
	}

	error = ext3_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto cleanup;
	if (is.s.not_found)
		error = ext3_xattr_block_find(inode, &i, &bs);
	if (error)
		goto cleanup;
	if (is.s.not_found && bs.s.not_found) {
		error = -ENODATA;
		if (flags & XATTR_REPLACE)
			goto cleanup;
		error = 0;
		if (!value)
			goto cleanup;
	} else {
		error = -EEXIST;
		if (flags & XATTR_CREATE)
			goto cleanup;
	}
	if (!value) {
		if (!is.s.not_found)
			error = ext3_xattr_ibody_set(handle, inode, &i, &is);
		else if (!bs.s.not_found)
			error = ext3_xattr_block_set(handle, inode, &i, &bs);
	} else {
		error = ext3_xattr_ibody_set(handle, inode, &i, &is);
		if (!error && !bs.s.not_found) {
			i.value = NULL;
			error = ext3_xattr_block_set(handle, inode, &i, &bs);
		} else if (error == -ENOSPC) {
			if (EXT3_I(inode)->i_file_acl && !bs.s.base) {
				error = ext3_xattr_block_find(inode, &i, &bs);
				if (error)
					goto cleanup;
			}
			error = ext3_xattr_block_set(handle, inode, &i, &bs);
			if (error)
				goto cleanup;
			if (!is.s.not_found) {
				i.value = NULL;
				error = ext3_xattr_ibody_set(handle, inode, &i,
							     &is);
			}
		}
	}
	if (!error) {
		ext3_xattr_update_super_block(handle, inode->i_sb);
		inode->i_ctime = CURRENT_TIME_SEC;
		error = ext3_mark_iloc_dirty(handle, inode, &is.iloc);
		/*
		 * The bh is consumed by ext3_mark_iloc_dirty, even with
		 * error != 0.
		 */
		is.iloc.bh = NULL;
		if (IS_SYNC(inode))
			handle->h_sync = 1;
	}

cleanup:
	brelse(is.iloc.bh);
	brelse(bs.bh);
	up_write(&EXT3_I(inode)->xattr_sem);
	return error;
}

/*
 * ext3_xattr_set()
 *
 * Like ext3_xattr_set_handle, but start from an inode. This extended
 * attribute modification is a filesystem transaction by itself.
 *
 * Returns 0, or a negative error number on failure.
 */
int
ext3_xattr_set(struct inode *inode, int name_index, const char *name,
	       const void *value, size_t value_len, int flags)
{
	handle_t *handle;
	int error, retries = 0;

retry:
	handle = ext3_journal_start(inode, EXT3_DATA_TRANS_BLOCKS(inode->i_sb));
	if (IS_ERR(handle)) {
		error = PTR_ERR(handle);
	} else {
		int error2;

		error = ext3_xattr_set_handle(handle, inode, name_index, name,
					      value, value_len, flags);
		error2 = ext3_journal_stop(handle);
		if (error == -ENOSPC &&
		    ext3_should_retry_alloc(inode->i_sb, &retries))
			goto retry;
		if (error == 0)
			error = error2;
	}

	return error;
}

/*
 * ext3_xattr_delete_inode()
 *
 * Free extended attribute resources associated with this inode. This
 * is called immediately before an inode is freed. We have exclusive
 * access to the inode.
 */
void
ext3_xattr_delete_inode(handle_t *handle, struct inode *inode)
{
	struct buffer_head *bh = NULL;

	if (!EXT3_I(inode)->i_file_acl)
		goto cleanup;
	bh = sb_bread(inode->i_sb, EXT3_I(inode)->i_file_acl);
	if (!bh) {
		ext3_error(inode->i_sb, __func__,
			"inode %lu: block "E3FSBLK" read error", inode->i_ino,
			EXT3_I(inode)->i_file_acl);
		goto cleanup;
	}
	if (BHDR(bh)->h_magic != cpu_to_le32(EXT3_XATTR_MAGIC) ||
	    BHDR(bh)->h_blocks != cpu_to_le32(1)) {
		ext3_error(inode->i_sb, __func__,
			"inode %lu: bad block "E3FSBLK, inode->i_ino,
			EXT3_I(inode)->i_file_acl);
		goto cleanup;
	}
	ext3_xattr_release_block(handle, inode, bh);
	EXT3_I(inode)->i_file_acl = 0;

cleanup:
	brelse(bh);
}

/*
 * ext3_xattr_put_super()
 *
 * This is called when a file system is unmounted.
 */
void
ext3_xattr_put_super(struct super_block *sb)
{
	mb_cache_shrink(sb->s_bdev);
}

/*
 * ext3_xattr_cache_insert()
 *
 * Create a new entry in the extended attribute cache, and insert
 * it unless such an entry is already in the cache.
 *
 * Returns 0, or a negative error number on failure.
 */
static void
ext3_xattr_cache_insert(struct buffer_head *bh)
{
	__u32 hash = le32_to_cpu(BHDR(bh)->h_hash);
	struct mb_cache_entry *ce;
	int error;

	ce = mb_cache_entry_alloc(ext3_xattr_cache, GFP_NOFS);
	if (!ce) {
		ea_bdebug(bh, "out of memory");
		return;
	}
	error = mb_cache_entry_insert(ce, bh->b_bdev, bh->b_blocknr, hash);
	if (error) {
		mb_cache_entry_free(ce);
		if (error == -EBUSY) {
			ea_bdebug(bh, "already in cache");
			error = 0;
		}
	} else {
		ea_bdebug(bh, "inserting [%x]", (int)hash);
		mb_cache_entry_release(ce);
	}
}

/*
 * ext3_xattr_cmp()
 *
 * Compare two extended attribute blocks for equality.
 *
 * Returns 0 if the blocks are equal, 1 if they differ, and
 * a negative error number on errors.
 */
static int
ext3_xattr_cmp(struct ext3_xattr_header *header1,
	       struct ext3_xattr_header *header2)
{
	struct ext3_xattr_entry *entry1, *entry2;

	entry1 = ENTRY(header1+1);
	entry2 = ENTRY(header2+1);
	while (!IS_LAST_ENTRY(entry1)) {
		if (IS_LAST_ENTRY(entry2))
			return 1;
		if (entry1->e_hash != entry2->e_hash ||
		    entry1->e_name_index != entry2->e_name_index ||
		    entry1->e_name_len != entry2->e_name_len ||
		    entry1->e_value_size != entry2->e_value_size ||
		    memcmp(entry1->e_name, entry2->e_name, entry1->e_name_len))
			return 1;
		if (entry1->e_value_block != 0 || entry2->e_value_block != 0)
			return -EIO;
		if (memcmp((char *)header1 + le16_to_cpu(entry1->e_value_offs),
			   (char *)header2 + le16_to_cpu(entry2->e_value_offs),
			   le32_to_cpu(entry1->e_value_size)))
			return 1;

		entry1 = EXT3_XATTR_NEXT(entry1);
		entry2 = EXT3_XATTR_NEXT(entry2);
	}
	if (!IS_LAST_ENTRY(entry2))
		return 1;
	return 0;
}

/*
 * ext3_xattr_cache_find()
 *
 * Find an identical extended attribute block.
 *
 * Returns a pointer to the block found, or NULL if such a block was
 * not found or an error occurred.
 */
static struct buffer_head *
ext3_xattr_cache_find(struct inode *inode, struct ext3_xattr_header *header,
		      struct mb_cache_entry **pce)
{
	__u32 hash = le32_to_cpu(header->h_hash);
	struct mb_cache_entry *ce;

	if (!header->h_hash)
		return NULL;  /* never share */
	ea_idebug(inode, "looking for cached blocks [%x]", (int)hash);
again:
	ce = mb_cache_entry_find_first(ext3_xattr_cache, inode->i_sb->s_bdev,
				       hash);
	while (ce) {
		struct buffer_head *bh;

		if (IS_ERR(ce)) {
			if (PTR_ERR(ce) == -EAGAIN)
				goto again;
			break;
		}
		bh = sb_bread(inode->i_sb, ce->e_block);
		if (!bh) {
			ext3_error(inode->i_sb, __func__,
				"inode %lu: block %lu read error",
				inode->i_ino, (unsigned long) ce->e_block);
		} else if (le32_to_cpu(BHDR(bh)->h_refcount) >=
				EXT3_XATTR_REFCOUNT_MAX) {
			ea_idebug(inode, "block %lu refcount %d>=%d",
				  (unsigned long) ce->e_block,
				  le32_to_cpu(BHDR(bh)->h_refcount),
					  EXT3_XATTR_REFCOUNT_MAX);
		} else if (ext3_xattr_cmp(header, BHDR(bh)) == 0) {
			*pce = ce;
			return bh;
		}
		brelse(bh);
		ce = mb_cache_entry_find_next(ce, inode->i_sb->s_bdev, hash);
	}
	return NULL;
}

#define NAME_HASH_SHIFT 5
#define VALUE_HASH_SHIFT 16

/*
 * ext3_xattr_hash_entry()
 *
 * Compute the hash of an extended attribute.
 */
static inline void ext3_xattr_hash_entry(struct ext3_xattr_header *header,
					 struct ext3_xattr_entry *entry)
{
	__u32 hash = 0;
	char *name = entry->e_name;
	int n;

	for (n=0; n < entry->e_name_len; n++) {
		hash = (hash << NAME_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - NAME_HASH_SHIFT)) ^
		       *name++;
	}

	if (entry->e_value_block == 0 && entry->e_value_size != 0) {
		__le32 *value = (__le32 *)((char *)header +
			le16_to_cpu(entry->e_value_offs));
		for (n = (le32_to_cpu(entry->e_value_size) +
		     EXT3_XATTR_ROUND) >> EXT3_XATTR_PAD_BITS; n; n--) {
			hash = (hash << VALUE_HASH_SHIFT) ^
			       (hash >> (8*sizeof(hash) - VALUE_HASH_SHIFT)) ^
			       le32_to_cpu(*value++);
		}
	}
	entry->e_hash = cpu_to_le32(hash);
}

#undef NAME_HASH_SHIFT
#undef VALUE_HASH_SHIFT

#define BLOCK_HASH_SHIFT 16

/*
 * ext3_xattr_rehash()
 *
 * Re-compute the extended attribute hash value after an entry has changed.
 */
static void ext3_xattr_rehash(struct ext3_xattr_header *header,
			      struct ext3_xattr_entry *entry)
{
	struct ext3_xattr_entry *here;
	__u32 hash = 0;

	ext3_xattr_hash_entry(header, entry);
	here = ENTRY(header+1);
	while (!IS_LAST_ENTRY(here)) {
		if (!here->e_hash) {
			/* Block is not shared if an entry's hash value == 0 */
			hash = 0;
			break;
		}
		hash = (hash << BLOCK_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - BLOCK_HASH_SHIFT)) ^
		       le32_to_cpu(here->e_hash);
		here = EXT3_XATTR_NEXT(here);
	}
	header->h_hash = cpu_to_le32(hash);
}

#undef BLOCK_HASH_SHIFT

int __init
init_ext3_xattr(void)
{
	ext3_xattr_cache = mb_cache_create("ext3_xattr", 6);
	if (!ext3_xattr_cache)
		return -ENOMEM;
	return 0;
}

void
exit_ext3_xattr(void)
{
	if (ext3_xattr_cache)
		mb_cache_destroy(ext3_xattr_cache);
	ext3_xattr_cache = NULL;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/xattr.c */
/************************************************************/
/*
 * linux/fs/ext3/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

// #include "ext3.h"
// #include "xattr.h"

static size_t
ext3_xattr_user_list(struct dentry *dentry, char *list, size_t list_size,
		const char *name, size_t name_len, int type)
{
	const size_t prefix_len = XATTR_USER_PREFIX_LEN;
	const size_t total_len = prefix_len + name_len + 1;

	if (!test_opt(dentry->d_sb, XATTR_USER))
		return 0;

	if (list && total_len <= list_size) {
		memcpy(list, XATTR_USER_PREFIX, prefix_len);
		memcpy(list+prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}
	return total_len;
}

static int
ext3_xattr_user_get(struct dentry *dentry, const char *name, void *buffer,
		size_t size, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext3_xattr_get(dentry->d_inode, EXT3_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int
ext3_xattr_user_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext3_xattr_set(dentry->d_inode, EXT3_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler ext3_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= ext3_xattr_user_list,
	.get	= ext3_xattr_user_get,
	.set	= ext3_xattr_user_set,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/xattr_user.c */
/************************************************************/
/*
 * linux/fs/ext3/xattr_trusted.c
 * Handler for trusted extended attributes.
 *
 * Copyright (C) 2003 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

// #include "ext3.h"
// #include "xattr.h"

static size_t
ext3_xattr_trusted_list(struct dentry *dentry, char *list, size_t list_size,
		const char *name, size_t name_len, int type)
{
	const size_t prefix_len = XATTR_TRUSTED_PREFIX_LEN;
	const size_t total_len = prefix_len + name_len + 1;

	if (!capable(CAP_SYS_ADMIN))
		return 0;

	if (list && total_len <= list_size) {
		memcpy(list, XATTR_TRUSTED_PREFIX, prefix_len);
		memcpy(list+prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}
	return total_len;
}

static int
ext3_xattr_trusted_get(struct dentry *dentry, const char *name,
		       void *buffer, size_t size, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext3_xattr_get(dentry->d_inode, EXT3_XATTR_INDEX_TRUSTED,
			      name, buffer, size);
}

static int
ext3_xattr_trusted_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext3_xattr_set(dentry->d_inode, EXT3_XATTR_INDEX_TRUSTED, name,
			      value, size, flags);
}

const struct xattr_handler ext3_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= ext3_xattr_trusted_list,
	.get	= ext3_xattr_trusted_get,
	.set	= ext3_xattr_trusted_set,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/xattr_trusted.c */
/************************************************************/
/*
 * linux/fs/ext3/acl.c
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher, <agruen@suse.de>
 */

// #include "ext3.h"
// #include "xattr.h"
// #include "acl.h"

/*
 * Convert from filesystem to in-memory representation.
 */
static struct posix_acl *
ext3_acl_from_disk(const void *value, size_t size)
{
	const char *end = (char *)value + size;
	int n, count;
	struct posix_acl *acl;

	if (!value)
		return NULL;
	if (size < sizeof(ext3_acl_header))
		 return ERR_PTR(-EINVAL);
	if (((ext3_acl_header *)value)->a_version !=
	    cpu_to_le32(EXT3_ACL_VERSION))
		return ERR_PTR(-EINVAL);
	value = (char *)value + sizeof(ext3_acl_header);
	count = ext3_acl_count(size);
	if (count < 0)
		return ERR_PTR(-EINVAL);
	if (count == 0)
		return NULL;
	acl = posix_acl_alloc(count, GFP_NOFS);
	if (!acl)
		return ERR_PTR(-ENOMEM);
	for (n=0; n < count; n++) {
		ext3_acl_entry *entry =
			(ext3_acl_entry *)value;
		if ((char *)value + sizeof(ext3_acl_entry_short) > end)
			goto fail;
		acl->a_entries[n].e_tag  = le16_to_cpu(entry->e_tag);
		acl->a_entries[n].e_perm = le16_to_cpu(entry->e_perm);
		switch(acl->a_entries[n].e_tag) {
			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				value = (char *)value +
					sizeof(ext3_acl_entry_short);
				break;

			case ACL_USER:
				value = (char *)value + sizeof(ext3_acl_entry);
				if ((char *)value > end)
					goto fail;
				acl->a_entries[n].e_uid =
					make_kuid(&init_user_ns,
						  le32_to_cpu(entry->e_id));
				break;
			case ACL_GROUP:
				value = (char *)value + sizeof(ext3_acl_entry);
				if ((char *)value > end)
					goto fail;
				acl->a_entries[n].e_gid =
					make_kgid(&init_user_ns,
						  le32_to_cpu(entry->e_id));
				break;

			default:
				goto fail;
		}
	}
	if (value != end)
		goto fail;
	return acl;

fail:
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Convert from in-memory to filesystem representation.
 */
static void *
ext3_acl_to_disk(const struct posix_acl *acl, size_t *size)
{
	ext3_acl_header *ext_acl;
	char *e;
	size_t n;

	*size = ext3_acl_size(acl->a_count);
	ext_acl = kmalloc(sizeof(ext3_acl_header) + acl->a_count *
			sizeof(ext3_acl_entry), GFP_NOFS);
	if (!ext_acl)
		return ERR_PTR(-ENOMEM);
	ext_acl->a_version = cpu_to_le32(EXT3_ACL_VERSION);
	e = (char *)ext_acl + sizeof(ext3_acl_header);
	for (n=0; n < acl->a_count; n++) {
		const struct posix_acl_entry *acl_e = &acl->a_entries[n];
		ext3_acl_entry *entry = (ext3_acl_entry *)e;
		entry->e_tag  = cpu_to_le16(acl_e->e_tag);
		entry->e_perm = cpu_to_le16(acl_e->e_perm);
		switch(acl_e->e_tag) {
			case ACL_USER:
				entry->e_id = cpu_to_le32(
					from_kuid(&init_user_ns, acl_e->e_uid));
				e += sizeof(ext3_acl_entry);
				break;
			case ACL_GROUP:
				entry->e_id = cpu_to_le32(
					from_kgid(&init_user_ns, acl_e->e_gid));
				e += sizeof(ext3_acl_entry);
				break;

			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				e += sizeof(ext3_acl_entry_short);
				break;

			default:
				goto fail;
		}
	}
	return (char *)ext_acl;

fail:
	kfree(ext_acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Inode operation get_posix_acl().
 *
 * inode->i_mutex: don't care
 */
struct posix_acl *
ext3_get_acl(struct inode *inode, int type)
{
	int name_index;
	char *value = NULL;
	struct posix_acl *acl;
	int retval;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = EXT3_XATTR_INDEX_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name_index = EXT3_XATTR_INDEX_POSIX_ACL_DEFAULT;
		break;
	default:
		BUG();
	}

	retval = ext3_xattr_get(inode, name_index, "", NULL, 0);
	if (retval > 0) {
		value = kmalloc(retval, GFP_NOFS);
		if (!value)
			return ERR_PTR(-ENOMEM);
		retval = ext3_xattr_get(inode, name_index, "", value, retval);
	}
	if (retval > 0)
		acl = ext3_acl_from_disk(value, retval);
	else if (retval == -ENODATA || retval == -ENOSYS)
		acl = NULL;
	else
		acl = ERR_PTR(retval);
	kfree(value);

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	return acl;
}

/*
 * Set the access or default ACL of an inode.
 *
 * inode->i_mutex: down unless called from ext3_new_inode
 */
static int
__ext3_set_acl(handle_t *handle, struct inode *inode, int type,
	     struct posix_acl *acl)
{
	int name_index;
	void *value = NULL;
	size_t size = 0;
	int error;

	switch(type) {
		case ACL_TYPE_ACCESS:
			name_index = EXT3_XATTR_INDEX_POSIX_ACL_ACCESS;
			if (acl) {
				error = posix_acl_equiv_mode(acl, &inode->i_mode);
				if (error < 0)
					return error;
				else {
					inode->i_ctime = CURRENT_TIME_SEC;
					ext3_mark_inode_dirty(handle, inode);
					if (error == 0)
						acl = NULL;
				}
			}
			break;

		case ACL_TYPE_DEFAULT:
			name_index = EXT3_XATTR_INDEX_POSIX_ACL_DEFAULT;
			if (!S_ISDIR(inode->i_mode))
				return acl ? -EACCES : 0;
			break;

		default:
			return -EINVAL;
	}
	if (acl) {
		value = ext3_acl_to_disk(acl, &size);
		if (IS_ERR(value))
			return (int)PTR_ERR(value);
	}

	error = ext3_xattr_set_handle(handle, inode, name_index, "",
				      value, size, 0);

	kfree(value);

	if (!error)
		set_cached_acl(inode, type, acl);

	return error;
}

int
ext3_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	handle_t *handle;
	int error, retries = 0;

retry:
	handle = ext3_journal_start(inode, EXT3_DATA_TRANS_BLOCKS(inode->i_sb));
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	error = __ext3_set_acl(handle, inode, type, acl);
	ext3_journal_stop(handle);
	if (error == -ENOSPC && ext3_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
	return error;
}

/*
 * Initialize the ACLs of a new inode. Called from ext3_new_inode.
 *
 * dir->i_mutex: down
 * inode->i_mutex: up (access to inode is still exclusive)
 */
int
ext3_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int error;

	error = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (error)
		return error;

	if (default_acl) {
		error = __ext3_set_acl(handle, inode, ACL_TYPE_DEFAULT,
				       default_acl);
		posix_acl_release(default_acl);
	}
	if (acl) {
		if (!error)
			error = __ext3_set_acl(handle, inode, ACL_TYPE_ACCESS,
					       acl);
		posix_acl_release(acl);
	}
	return error;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/acl.c */
/************************************************************/
/*
 * linux/fs/ext3/xattr_security.c
 * Handler for storing security labels as extended attributes.
 */

#include <linux/security.h>
// #include "ext3.h"
// #include "xattr.h"
#include "../../inc/__fss.h"

static size_t
ext3_xattr_security_list(struct dentry *dentry, char *list, size_t list_size,
			 const char *name, size_t name_len, int type)
{
	const size_t prefix_len = XATTR_SECURITY_PREFIX_LEN;
	const size_t total_len = prefix_len + name_len + 1;


	if (list && total_len <= list_size) {
		memcpy(list, XATTR_SECURITY_PREFIX, prefix_len);
		memcpy(list+prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}
	return total_len;
}

static int
ext3_xattr_security_get(struct dentry *dentry, const char *name,
		void *buffer, size_t size, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext3_xattr_get(dentry->d_inode, EXT3_XATTR_INDEX_SECURITY,
			      name, buffer, size);
}

static int
ext3_xattr_security_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return ext3_xattr_set(dentry->d_inode, EXT3_XATTR_INDEX_SECURITY,
			      name, value, size, flags);
}

static int ext3_initxattrs(struct inode *inode,
			   const struct xattr *xattr_array,
			   void *fs_info)
{
	const struct xattr *xattr;
	handle_t *handle = fs_info;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = ext3_xattr_set_handle(handle, inode,
					    EXT3_XATTR_INDEX_SECURITY,
					    xattr->name, xattr->value,
					    xattr->value_len, 0);
		if (err < 0)
			break;
	}
	return err;
}

int
ext3_init_security(handle_t *handle, struct inode *inode, struct inode *dir,
		   const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					    &ext3_initxattrs, handle);
}

const struct xattr_handler ext3_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.list	= ext3_xattr_security_list,
	.get	= ext3_xattr_security_get,
	.set	= ext3_xattr_security_set,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ext3/xattr_security.c */
/************************************************************/
