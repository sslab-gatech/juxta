#include "common.h"

#define EXT3_ROOT_INO		 2	/* Root inode */
#define EXT3_RESIZE_INO		 7	/* Reserved group descriptors inode */
#define EXT3_JOURNAL_INO	 8	/* Journal inode */


int ext3_valid_inum(struct super_block *sb, unsigned long ino)
{
	return ino == EXT3_ROOT_INO ||
		ino == EXT3_JOURNAL_INO ||
		ino == EXT3_RESIZE_INO;
}

struct buffer_head *bh;
struct buffer_head *ext3_find_entry(struct inode *dir, void *child, struct page **res_page)
{
	return bh;
}

struct dentry *ext3_get_parent(struct dentry *child)
{
	unsigned long ino;
	struct ext_dir_entry_2 * de;
	struct buffer_head *bh;

	bh = ext3_find_entry(child->d_inode, NULL, &de);
#ifdef __PATCH__
	if (!bh)
		return ERR_PTR(-ENOENT);
#endif
	brelse(bh);

	if (!ext3_valid_inum(child->d_inode->i_sb, ino)) {
		return ERR_PTR(-EIO);
	}

	return d_obtain_alias(ext_iget(child->d_inode->i_sb, ino));
}

