#include "common.h"
/***
 * fs/9p/vfs_addr.c
 *
 **/

static int v9fs_write_end(struct file *filp, struct address_space *mapping,
                          loff_t pos, unsigned len, unsigned copied,
                          struct page *page, void *fsdata)
{
        loff_t last_pos = pos + copied;
        struct inode *inode = page->mapping->host;

        //p9_debug(P9_DEBUG_VFS, "filp %p, mapping %p\n", filp, mapping);

        if (unlikely(copied < len)) {
                /*
                 * zero out the rest of the area
                 */
                unsigned from = pos & (PAGE_CACHE_SIZE - 1);

                zero_user(page, from + copied, len - copied);
                flush_dcache_page(page);
        }

        if (!PageUptodate(page))
                SetPageUptodate(page);
        /*
         * No need to use i_size_read() here, the i_size
         * cannot change under us because we hold the i_mutex.
         */
        if (last_pos > inode->i_size) {
                inode_add_bytes(inode, last_pos - inode->i_size);
                i_size_write(inode, last_pos);
        }
        set_page_dirty(page);
        unlock_page(page);
        page_cache_release(page);

        return copied;
}
