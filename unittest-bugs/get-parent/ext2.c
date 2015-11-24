#include "common.h"

struct dentry *ext2_get_parent(struct dentry *child)
{
	unsigned long ino = ext_inode_by_name(child->d_inode, NULL);
	if (!ino)
		return ERR_PTR(-ENOENT);
	return d_obtain_alias(ext_iget(child->d_inode->i_sb, ino));
}
