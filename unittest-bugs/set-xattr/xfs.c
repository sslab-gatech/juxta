#include "common.h"

static int
xfs_xattr_set(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags, int xflags)
{
	struct xfs_inode *ip = XFS_I(dentry->d_inode);

	if (strcmp(name, "") == 0)
		return -EINVAL;

	/* Convert Linux syscall to XFS internal ATTR flags */
	if (flags & XATTR_CREATE)
		xflags |= ATTR_CREATE;
	if (flags & XATTR_REPLACE)
		xflags |= ATTR_REPLACE;

	if (!value)
		return xfs_attr_remove(ip, (unsigned char *)name, xflags);
	return xfs_attr_set(ip, (unsigned char *)name,
				(void *)value, size, xflags);
}


