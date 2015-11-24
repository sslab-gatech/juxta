/***
 * xfs/xfs_aops.c
 *
 **/
#include "common.h"

static inline void mark_inode_dirty(struct inode *inode){}

static inline void i_size_write(struct inode *inode, loff_t i_size){}


/*
 * On failure, we only need to kill delalloc blocks beyond EOF in the range of
 * this specific write because they will never be written. Previous writes
 * beyond EOF where block allocation succeeded do not need to be trashed, so
 * only new blocks from this write should be trashed. For blocks within
 * EOF, generic_write_end() zeros them so they are safe to leave alone and be
 * written with all the other valid data.
 */
static int
xfs_vm_write_end(
        struct file             *file,
        struct address_space    *mapping,
        loff_t                  pos,
        unsigned                len,
        unsigned                copied,
        struct page             *page,
        void                    *fsdata)
{
        int                     ret;

        ASSERT(len <= PAGE_CACHE_SIZE);

        ret = generic_write_end(file, mapping, pos, len, copied, page, fsdata);
        if (unlikely(ret < len)) {
                struct inode    *inode = mapping->host;
                size_t          isize = i_size_read(inode);
                loff_t          to = pos + len;

                if (to > isize) {
                        /* only kill blocks in this write beyond EOF */
                        if (pos > isize)
                                isize = pos;
                        xfs_vm_kill_delalloc_range(inode, isize, to);
                        truncate_pagecache_range(inode, isize, to);
                }
        }
        return ret;
}
