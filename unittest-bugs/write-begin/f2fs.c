#include "common.h"

static int f2fs_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct page *page, *ipage;
	pgoff_t index = ((unsigned long long) pos) >> PAGE_CACHE_SHIFT;
	struct dnode_of_data dn;
	int err = 0;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page) {
		err = -ENOMEM;
		goto fail;
	}

	*pagep = page;

	set_new_dnode(&dn, inode, ipage, ipage, 0);

	err = f2fs_reserve_block(&dn, index);
	if (err)
		goto put_fail;
out:
	return 0;

put_fail:
unlock_fail:
fail:
	return err;
}


