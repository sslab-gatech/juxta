#include "common.h"

/***
 * file fs/ext4/inode.c
 * patch id: 09e0834fb0ce1ea2a63885177015bd5d7d2bc22d
 * description:
 * 	If ext4_jbd2_file_inode() in ext4_ordered_write_end() fails for some
 * 	reasons, this function returns to caller without unlocking the page.
 * 	It leads to the deadlock, and the patch fixes this issue.
 ***/


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

