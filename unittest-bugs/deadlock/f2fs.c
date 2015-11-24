#include "common.h"

/***
 * f2fs/data.c
 *
 ***/

static inline void f2fs_put_page(struct page *page, int unlock)
{
        if (!page)
                return;

        if (unlock) {
                f2fs_bug_on(F2FS_P_SB(page), !PageLocked(page));
                unlock_page(page);
        }
        page_cache_release(page);
}


static int f2fs_write_end(struct file *file,
                        struct address_space *mapping,
                        loff_t pos, unsigned len, unsigned copied,
                        struct page *page, void *fsdata)
{
        struct inode *inode = page->mapping->host;

        trace_f2fs_write_end(inode, pos, len, copied);

        set_page_dirty(page);

        if (pos + copied > i_size_read(inode)) {
                i_size_write(inode, pos + copied);
                mark_inode_dirty(inode);
                update_inode_page(inode);
        }

        f2fs_put_page(page, 1);
        return copied;
}
