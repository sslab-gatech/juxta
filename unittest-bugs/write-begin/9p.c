#include "common.h"

struct v9fs_inode *V9FS_I(const struct inode *inode)
{
	struct v9fs_inode *v9fs = (struct v9fs_inode *)inode;
	return v9fs;
}

static int v9fs_write_begin(struct file *filp, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{
	int retval = 0;
	struct page *page;
	struct v9fs_inode *v9inode;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct inode *inode = mapping->host;


	v9inode = V9FS_I(inode);
start:
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		retval = -ENOMEM;
		goto out;
	}
	BUG_ON(!v9inode->writeback_fid);

	if (len == PAGE_CACHE_SIZE)
		goto out;

out:
	*pagep = page;
	return retval;
}


