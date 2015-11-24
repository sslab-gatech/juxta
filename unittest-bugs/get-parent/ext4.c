/* commit is artificial, but it is similar to a6c15c2b0fbfd5c0a84f5f0e1e3f20f85d2b8692 */

#include "common.h"


#define EXT4_ROOT_INO		 2	/* Root inode */
#define EXT4_RESIZE_INO		 7	/* Reserved group descriptors inode */
#define EXT4_JOURNAL_INO	 8	/* Journal inode */

int ext4_valid_inum(struct super_block *sb, unsigned long ino)
{
	return ino == EXT4_ROOT_INO ||
		ino == EXT4_JOURNAL_INO ||
		ino == EXT4_RESIZE_INO;
}

struct buffer_head *bh;
struct buffer_head *ext4_find_entry(struct inode *dir, void *child, struct page **res_page)
{
	return bh;
}


struct dentry *ext4_get_parent(struct dentry *child)
{
	__u32 ino;
	struct ext_dir_entry_2 * de;
	struct buffer_head *bh;

	bh = ext4_find_entry(child->d_inode, NULL, &de);
	if (IS_ERR(bh))
		return (struct dentry *) bh;
#ifdef __PATCH__
	if (!bh)
		return ERR_PTR(-ENOENT);
#endif
	brelse(bh);

	if (!ext4_valid_inum(child->d_inode->i_sb, ino)) {
		return ERR_PTR(-EIO);
	}

	return d_obtain_alias(ext_iget(child->d_inode->i_sb, ino));
}


