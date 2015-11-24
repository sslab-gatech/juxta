/***
 * file fs/ext4/inode.c
 * patch id: 09e0834fb0ce1ea2a63885177015bd5d7d2bc22d
 * description:
 * 	If ext4_jbd2_file_inode() in ext4_ordered_write_end() fails for some
 * 	reasons, this function returns to caller without unlocking the page.
 * 	It leads to the deadlock, and the patch fixes this issue.
 ***/

#define page_cache_release(page)        put_page(page)

 void put_page(struct page *page)
 {
         if (unlikely(PageCompound(page)))
                 put_compound_page(page);
         else if (put_page_testzero(page))
                 __put_single_page(page);
 }
 EXPORT_SYMBOL(put_page);
 



 /**
  * unlock_page - unlock a locked page
  * @page: the page
  *
  * Unlocks the page and wakes up sleepers in ___wait_on_page_locked().
  * Also wakes sleepers in wait_on_page_writeback() because the wakeup
  * mechanism between PageLocked pages and PageWriteback pages is shared.
  * But that's OK - sleepers in wait_on_page_writeback() just go back to sleep.
  *
  * The mb is necessary to enforce ordering between the clear_bit and the read
  * of the waitqueue (to avoid SMP races with a parallel wait_on_page_locked()).
  */
 void unlock_page(struct page *page)
 {
         VM_BUG_ON_PAGE(!PageLocked(page), page);
         clear_bit_unlock(PG_locked, &page->flags);
         smp_mb__after_atomic();
         wake_up_page(page, PG_locked);
 }
 EXPORT_SYMBOL(unlock_page);
 



/*
 *  * We need to pick up the new inode size which generic_commit_write gave us
 *   * `file' can be NULL - eg, when called from page_symlink().
 *    *
 *     * ext4 never places buffers on inode->i_mapping->private_list.  metadata
 *      * buffers are managed internally.
 *       */
static int ext4_ordered_write_end(struct file *file,
				  struct address_space *mapping,
				  loff_t pos, unsigned len, unsigned copied,
				  struct page *page, void *fsdata)
{
	handle_t *handle = ext4_journal_current_handle();
	struct inode *inode = mapping->host;
	int ret = 0, ret2;

	trace_ext4_ordered_write_end(inode, pos, len, copied);
	ret = ext4_jbd2_file_inode(handle, inode);

	if (ret == 0) {
		ret2 = ext4_generic_write_end(file, mapping, pos, len, copied,
							page, fsdata);
		copied = ret2;
		if (pos + len > inode->i_size && ext4_can_truncate(inode))
			/* if we have allocated more blocks and copied
 * 			 * less. We will have blocks allocated outside
 * 			 			 * inode->i_size. So truncate them
 * 			 			 			 */
			ext4_orphan_add(handle, inode);
		if (ret2 < 0)
			ret = ret2;
#ifndef __PATCH__

#else
	} else {
		unlock_page(page);
		page_cache_release(page);
#endif
	}

	ret2 = ext4_journal_stop(handle);
	if (!ret)
		ret = ret2;

	if (pos + len > inode->i_size) {
		ext4_truncate_failed_write(inode);
		/*
 * 		 * If truncate failed early the inode might still be
 * 		 		 * on the orphan list; we need to make sure the inode
 * 		 		 		 * is removed from the orphan list in that case.
 * 		 		 		 		 */
		if (inode->i_nlink)
			ext4_orphan_del(NULL, inode);
	}


	return ret ? ret : copied;
}

