#include "common.h"

struct f2fs_inode_info {
	struct inode vfs_inode;		/* serve a vfs inode */
	unsigned char i_advise;		/* use to give file attribute hints */
};

struct f2fs_inode_info *F2FS_I(struct inode* inode)
{
	struct f2fs_inode_info *f = (struct f2fs_inode_info *)inode;
	return f;
}

static int f2fs_xattr_advise_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	struct inode *inode = dentry->d_inode;

	if (strcmp(name, "") != 0)
		return -EINVAL;
	if (!inode_owner_or_capable(inode))
		return -EPERM;
	if (value == NULL)
		return -EINVAL;

	F2FS_I(inode)->i_advise |= *(char *)value;
	return 0;
}
