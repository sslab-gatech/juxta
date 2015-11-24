#include "common.h"

/**
 * generic_write_end in fs/buffer.c
 *
 */

#define page_cache_release(page)        put_page(page)
void put_page(struct page *page){}

static inline void mark_inode_dirty(struct inode *inode){}
static inline void i_size_write(struct inode *inode, loff_t i_size){}
void pagecache_isize_extended(struct inode *inode, loff_t from, loff_t to) {}

int block_write_end(struct file *file, struct address_space *mapping,
                        loff_t pos, unsigned len, unsigned copied,
                        struct page *page, void *fsdata) {}



int generic_write_end(struct file *file, struct address_space *mapping,
                        loff_t pos, unsigned len, unsigned copied,
                        struct page *page, void *fsdata)
{
        struct inode *inode = mapping->host;
        loff_t old_size = inode->i_size;
        int i_size_changed = 0;

        copied = block_write_end(file, mapping, pos, len, copied, page, fsdata);

        /*
         * No need to use i_size_read() here, the i_size
         * cannot change under us because we hold i_mutex.
         *
         * But it's important to update i_size while still holding page lock:
         * page writeout could otherwise come in and zero beyond i_size.
         */
        if (pos+copied > inode->i_size) {
                i_size_write(inode, pos+copied);
                i_size_changed = 1;
        }

        unlock_page(page);
        page_cache_release(page);

        if (old_size < pos)
                pagecache_isize_extended(inode, old_size, pos);
        /*
         * Don't mark the inode dirty under page lock. First, it unnecessarily
         * makes the holding time of page lock longer. Second, it forces lock
         * ordering of page lock and transaction start for journaling
         * filesystems.
         */
        if (i_size_changed)
                mark_inode_dirty(inode);

        return copied;
}
//EXPORT_SYMBOL(generic_write_end);



static int ext2_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	int ret;

	ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
	if (ret < len)
		ext2_write_failed(mapping, pos + len);
	return ret;
}
