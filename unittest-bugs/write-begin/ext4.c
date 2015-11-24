#include "common.h"

static int ext4_da_write_begin(struct file *file, struct address_space *mapping,
			       loff_t pos, unsigned len, unsigned flags,
			       struct page **pagep, void **fsdata)
{
	int ret, retries = 0;
	struct page *page;
	pgoff_t index;
	struct inode *inode = mapping->host;
	handle_t *handle;

	index = pos >> PAGE_CACHE_SHIFT;


	page = grab_cache_page_write_begin(mapping, index, flags);
#ifdef __PATCH__
	if (!page)
		return -ENOMEM;
#endif
	unlock_page(page);
	*pagep = page;
	return ret;
}


