#include "common.h"

/***
 * fs/ext3/inode.c
 *
 **/
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


void unlock_page(struct page *page)
{
         //VM_BUG_ON_PAGE(!PageLocked(page), page);
         //clear_bit_unlock(PG_locked, &page->flags);
         //smp_mb__after_atomic();
         //wake_up_page(page, PG_locked);
}



/*
 *  * We need to pick up the new inode size which generic_commit_write gave us
 *   * `file' can be NULL - eg, when called from page_symlink().
 *    *
 *     * ext3 never places buffers on inode->i_mapping->private_list.  metadata
 *      * buffers are managed internally.
 *       */
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
 * 	 * There may be allocated blocks outside of i_size because
 * 	 	 * we failed to copy some data. Prepare for truncate.
 * 	 	 	 */
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
