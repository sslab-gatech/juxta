#include "common.h"

#define	V9FS_ACCESS_ANY (V9FS_ACCESS_SINGLE | \
			 V9FS_ACCESS_USER |   \
			 V9FS_ACCESS_CLIENT)
#define V9FS_ACCESS_MASK V9FS_ACCESS_ANY
#define V9FS_ACL_MASK V9FS_POSIX_ACL

enum p9_session_flags {
	V9FS_PROTO_2000U	= 0x01,
	V9FS_PROTO_2000L	= 0x02,
	V9FS_ACCESS_SINGLE	= 0x04,
	V9FS_ACCESS_USER	= 0x08,
	V9FS_ACCESS_CLIENT	= 0x10,
	V9FS_POSIX_ACL		= 0x20
};

struct v9fs_session_info {
	/* options */
	unsigned char flags;
	unsigned char nodev;
	unsigned short debug;
	unsigned int afid;
	unsigned int cache;
	char *cachetag;

	char *uname;		/* user name to mount as */
	char *aname;		/* name of remote hierarchy being mounted */
	unsigned int maxdata;	/* max data for client interface */
};

static int v9fs_xattr_set_acl(struct dentry *dentry, const char *name,
			      const void *value, size_t size,
			      int flags, int type)
{
	int retval;
	struct posix_acl *acl;
	struct v9fs_session_info *v9ses;
	struct inode *inode = dentry->d_inode;

	if (strcmp(name, "") != 0)
		return -EINVAL;

	v9ses = v9fs_dentry2v9ses(dentry);
	/*
	 * set the attribute on the remote. Without even looking at the
	 * xattr value. We leave it to the server to validate
	 */
	if ((v9ses->flags & V9FS_ACCESS_MASK) != V9FS_ACCESS_CLIENT)
		return v9fs_remote_set_acl(dentry, name,
					   value, size, flags, type);

	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
	/* artifical bug! */
#ifdef __PATCH__
	if (!inode_owner_or_capable(inode))
		return -EPERM;
#endif
	if (value) {
		/* update the cached acl value */
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		else if (acl) {
			retval = posix_acl_valid(acl);
			if (retval)
				goto err_out;
		}
	} else
		acl = NULL;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = POSIX_ACL_XATTR_ACCESS;
		if (acl) {
			umode_t mode = inode->i_mode;
			retval = posix_acl_equiv_mode(acl, &mode);
			if (retval < 0)
				goto err_out;
			else {
				struct iattr iattr;
				if (retval == 0) {
					/*
					 * ACL can be represented
					 * by the mode bits. So don't
					 * update ACL.
					 */
					acl = NULL;
					value = NULL;
					size = 0;
				}
				/* Updte the mode bits */
				iattr.ia_mode = ((mode & S_IALLUGO) |
						 (inode->i_mode & ~S_IALLUGO));
				iattr.ia_valid = ATTR_MODE;
				/* FIXME should we update ctime ?
				 * What is the following setxattr update the
				 * mode ?
				 */
				v9fs_vfs_setattr_dotl(dentry, &iattr);
			}
		}
		break;
	case ACL_TYPE_DEFAULT:
		name = POSIX_ACL_XATTR_DEFAULT;
		if (!S_ISDIR(inode->i_mode)) {
			retval = acl ? -EINVAL : 0;
			goto err_out;
		}
		break;
	default:
		BUG();
	}
	retval = v9fs_xattr_set(dentry, name, value, size, flags);
	if (!retval)
		set_cached_acl(inode, type, acl);
err_out:
	posix_acl_release(acl);
	return retval;
}


