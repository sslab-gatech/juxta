#include "common.h"

#define EXT4_XATTR_INDEX_USER	1
#define EXT4_HT_XATTR			10

int ext4_should_retry_alloc(struct super_block *sb, int *retries)
{
	if ((*retries)++ > 3)
		return 0;

	return 1;
}

handle_t *ext4_journal_start(struct inode *inode, int type, int nblocks)
{
	handle_t *h;
	return h;
}

int ext4_journal_stop(handle_t *handle)
{
	return 0;
}
int
ext4_xattr_set_handle(handle_t *handle, struct inode *inode, int name_index,
		      const char *name, const void *value, size_t value_len,
		      int flags)
{
	return 0;
}

int ext4_jbd2_credits_xattr(struct inode *inode)
{
	return 0;
}

int
ext4_xattr_set(struct inode *inode, int name_index, const char *name,
	       const void *value, size_t value_len, int flags)
{
	handle_t *handle;
	int error, retries = 0;
	int credits = ext4_jbd2_credits_xattr(inode);

retry:
	handle = ext4_journal_start(inode, EXT4_HT_XATTR, credits);
	if (IS_ERR(handle)) {
		error = PTR_ERR(handle);
	} else {
		int error2;

		error = ext4_xattr_set_handle(handle, inode, name_index, name,
					      value, value_len, flags);
		error2 = ext4_journal_stop(handle);
		if (error == -ENOSPC &&
		    ext4_should_retry_alloc(inode->i_sb, &retries))
			goto retry;
		if (error == 0)
			error = error2;
	}

	return error;
}




static int
ext4_xattr_user_set(struct dentry *dentry, const char *name,
		    const void *value, size_t size, int flags, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext4_xattr_set(dentry->d_inode, EXT4_XATTR_INDEX_USER,
			      name, value, size, flags);
}


