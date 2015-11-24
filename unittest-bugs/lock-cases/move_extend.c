#else
/***
 * file: fs/ext4/move_extent.c
 * patch id: 6e2631463f3a2ce430a295c68aead3ff228ca3cf
 * Description:
 * If we have to copy data we must drop i_data_sem because of
 * get_blocks() will be called inside mext_page_mkuptodate(), but later we must
 * reacquire it again because we are about to change extent's tree
 ***/


/**
 *  * ext4_double_down_write_data_sem - Acquire two inodes' write lock
 *   *                                   of i_data_sem
 *    *
 *     * Acquire write lock of i_data_sem of the two inodes
 *      */
void
ext4_double_down_write_data_sem(struct inode *first, struct inode *second)
{
	if (first < second) {
		down_write(&EXT4_I(first)->i_data_sem);
		down_write_nested(&EXT4_I(second)->i_data_sem, SINGLE_DEPTH_NESTING);
	} else {
		down_write(&EXT4_I(second)->i_data_sem);
		down_write_nested(&EXT4_I(first)->i_data_sem, SINGLE_DEPTH_NESTING);

	}
}

/**
 *  * ext4_double_up_write_data_sem - Release two inodes' write lock of i_data_sem
 *   *
 *    * @orig_inode:		original inode structure to be released its lock first
 *     * @donor_inode:	donor inode structure to be released its lock second
 *      * Release write lock of i_data_sem of two inodes (orig and donor).
 *       */
void
ext4_double_up_write_data_sem(struct inode *orig_inode,
			      struct inode *donor_inode)
{
	up_write(&EXT4_I(orig_inode)->i_data_sem);
	up_write(&EXT4_I(donor_inode)->i_data_sem);
}


/**
 *  * move_extent_per_page - Move extent data per page
 *   *
 *    * @o_filp:			file structure of original file
 *     * @donor_inode:		donor inode
 *      * @orig_page_offset:		page index on original file
 *       * @data_offset_in_page:	block index where data swapping starts
 *        * @block_len_in_page:		the number of blocks to be swapped
 *         * @unwritten:			orig extent is unwritten or not
 *          * @err:			pointer to save return value
 *           *
 *            * Save the data in original inode blocks and replace original inode extents
 *             * with donor inode extents by calling mext_replace_branches().
 *              * Finally, write out the saved data in new original inode blocks. Return
 *               * replaced block count.
 *                */
static int
move_extent_per_page(struct file *o_filp, struct inode *donor_inode,
		  pgoff_t orig_page_offset, int data_offset_in_page,
		  int block_len_in_page, int unwritten, int *err)
{
	struct inode *orig_inode = file_inode(o_filp);
	struct page *pagep[2] = {NULL, NULL};
	handle_t *handle;
	ext4_lblk_t orig_blk_offset;
	unsigned long blocksize = orig_inode->i_sb->s_blocksize;
	unsigned int w_flags = 0;
	unsigned int tmp_data_size, data_size, replaced_size;
	int err2, jblocks, retries = 0;
	int replaced_count = 0;
	int from = data_offset_in_page << orig_inode->i_blkbits;
	int blocks_per_page = PAGE_CACHE_SIZE >> orig_inode->i_blkbits;

	/*
 * 	 * It needs twice the amount of ordinary journal buffers because
 * 	 	 * inode and donor_inode may change each different metadata blocks.
 * 	 	 	 */
again:
	*err = 0;
	jblocks = ext4_writepage_trans_blocks(orig_inode) * 2;
	handle = ext4_journal_start(orig_inode, EXT4_HT_MOVE_EXTENTS, jblocks);
	if (IS_ERR(handle)) {
		*err = PTR_ERR(handle);
		return 0;
	}

	if (segment_eq(get_fs(), KERNEL_DS))
		w_flags |= AOP_FLAG_UNINTERRUPTIBLE;

	orig_blk_offset = orig_page_offset * blocks_per_page +
		data_offset_in_page;

	/* Calculate data_size */
	if ((orig_blk_offset + block_len_in_page - 1) ==
	    ((orig_inode->i_size - 1) >> orig_inode->i_blkbits)) {
		/* Replace the last block */
		tmp_data_size = orig_inode->i_size & (blocksize - 1);
		/*
 * 		 * If data_size equal zero, it shows data_size is multiples of
 * 		 		 * blocksize. So we set appropriate value.
 * 		 		 		 */
		if (tmp_data_size == 0)
			tmp_data_size = blocksize;

		data_size = tmp_data_size +
			((block_len_in_page - 1) << orig_inode->i_blkbits);
	} else
		data_size = block_len_in_page << orig_inode->i_blkbits;

	replaced_size = data_size;

	*err = mext_page_double_lock(orig_inode, donor_inode, orig_page_offset,
				     pagep);
	if (unlikely(*err < 0))
		goto stop_journal;
	/*
 * 	 * If orig extent was unwritten it can become initialized
 * 	 	 * at any time after i_data_sem was dropped, in order to
 * 	 	 	 * serialize with delalloc we have recheck extent while we
 * 	 	 	 	 * hold page's lock, if it is still the case data copy is not
 * 	 	 	 	 	 * necessary, just swap data blocks between orig and donor.
 * 	 	 	 	 	 	 */
	if (unwritten) {
		ext4_double_down_write_data_sem(orig_inode, donor_inode);
		/* If any of extents in range became initialized we have to
 * 		 * fallback to data copying */
		unwritten = mext_check_coverage(orig_inode, orig_blk_offset,
						block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		unwritten &= mext_check_coverage(donor_inode, orig_blk_offset,
						 block_len_in_page, 1, err);
		if (*err)
			goto drop_data_sem;

		if (!unwritten) {
			ext4_double_up_write_data_sem(orig_inode, donor_inode);
			goto data_copy;
		}
		if ((page_has_private(pagep[0]) &&
		     !try_to_release_page(pagep[0], 0)) ||
		    (page_has_private(pagep[1]) &&
		     !try_to_release_page(pagep[1], 0))) {
			*err = -EBUSY;
			goto drop_data_sem;
		}
		replaced_count = mext_replace_branches(handle, orig_inode,
						donor_inode, orig_blk_offset,
						block_len_in_page, err);
	drop_data_sem:
		ext4_double_up_write_data_sem(orig_inode, donor_inode);
		goto unlock_pages;
	}
data_copy:
	*err = mext_page_mkuptodate(pagep[0], from, from + replaced_size);
	if (*err)
		goto unlock_pages;

	/* At this point all buffers in range are uptodate, old mapping layout
 * 	 * is no longer required, try to drop it now. */
	if ((page_has_private(pagep[0]) && !try_to_release_page(pagep[0], 0)) ||
	    (page_has_private(pagep[1]) && !try_to_release_page(pagep[1], 0))) {
		*err = -EBUSY;
		goto unlock_pages;
	}

#ifndef __PATCH__
	replaced_count = mext_replace_branches(handle, orig_inode, donor_inode,
					       orig_blk_offset,
					       block_len_in_page, err);
#else
	ext4_double_down_write_data_sem(orig_inode, donor_inode);
	replaced_count = mext_replace_branches(handle, orig_inode, donor_inode,
					       orig_blk_offset,
					       block_len_in_page, err);
	ext4_double_up_write_data_sem(orig_inode, donor_inode);

#endif

	if (*err) {
		if (replaced_count) {
			block_len_in_page = replaced_count;
			replaced_size =
				block_len_in_page << orig_inode->i_blkbits;
		} else
			goto unlock_pages;
	}
	/* Perform all necessary steps similar write_begin()/write_end()
 * 	 * but keeping in mind that i_size will not change */
	*err = __block_write_begin(pagep[0], from, replaced_size,
				   ext4_get_block);
	if (!*err)
		*err = block_commit_write(pagep[0], from, from + replaced_size);

	if (unlikely(*err < 0))
		goto repair_branches;

	/* Even in case of data=writeback it is reasonable to pin
 * 	 * inode to transaction, to prevent unexpected data loss */
	*err = ext4_jbd2_file_inode(handle, orig_inode);

unlock_pages:
	unlock_page(pagep[0]);
	page_cache_release(pagep[0]);
	unlock_page(pagep[1]);
	page_cache_release(pagep[1]);
stop_journal:
	ext4_journal_stop(handle);
	/* Buffer was busy because probably is pinned to journal transaction,
 * 	 * force transaction commit may help to free it. */
	if (*err == -EBUSY && ext4_should_retry_alloc(orig_inode->i_sb,
						      &retries))
		goto again;
	return replaced_count;

repair_branches:
	/*
 * 	 * This should never ever happen!
 * 	 	 * Extents are swapped already, but we are not able to copy data.
 * 	 	 	 * Try to swap extents to it's original places
 * 	 	 	 	 */
	ext4_double_down_write_data_sem(orig_inode, donor_inode);
	replaced_count = mext_replace_branches(handle, donor_inode, orig_inode,
					       orig_blk_offset,
					       block_len_in_page, &err2);
	ext4_double_up_write_data_sem(orig_inode, donor_inode);
	if (replaced_count != block_len_in_page) {
		EXT4_ERROR_INODE_BLOCK(orig_inode, (sector_t)(orig_blk_offset),
				       "Unable to copy data block,"
				       " data will be lost.");
		*err = -EIO;
	}
	replaced_count = 0;
	goto unlock_pages;
}


