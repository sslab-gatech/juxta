#include "common.h"

#define EXT3_XATTR_INDEX_USER			1
#define EXT3_DATA_TRANS_BLOCKS(sb)		((8U) + (6U) - 2)

handle_t *ext3_journal_start(struct inode *inode, int nblocks)
{
	handle_t *h;
	return h;
}

int ext3_journal_stop(handle_t *handle)
{
	return 0;
}

int ext3_should_retry_alloc(struct super_block *sb, int *retries)
{
	if ((*retries)++ > 3)
		return 0;

	return 1;
}

int ext3_xattr_set_handle(handle_t *handle, struct inode *inode,
						  int name_index, const char *name, const void *value,
						  size_t value_len, int flags)
{
	return 0;
}

unsigned long IS_ERR(void *ptr)
{
	return (unsigned long)ptr >= 4095;
}

long PTR_ERR(void *ptr)
{
	return (long)ptr;
}

int
ext3_xattr_set(struct inode *inode, int name_index, const char *name,
	       const void *value, size_t value_len, int flags)
{
	handle_t *handle;
	int error, retries = 0;

retry:
	handle = ext3_journal_start(inode, EXT3_DATA_TRANS_BLOCKS(inode->i_sb));
	if (IS_ERR(handle)) {
		error = PTR_ERR(handle);
	} else {
		int error2;

		error = ext3_xattr_set_handle(handle, inode, name_index, name,
					      value, value_len, flags);
		error2 = ext3_journal_stop(handle);
		if (error == -ENOSPC &&
		    ext3_should_retry_alloc(inode->i_sb, &retries))
			goto retry;
		if (error == 0)
			error = error2;
	}

	return error;
}



static int
ext3_xattr_user_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return ext3_xattr_set(dentry->d_inode, EXT3_XATTR_INDEX_USER,
			      name, value, size, flags);
}


