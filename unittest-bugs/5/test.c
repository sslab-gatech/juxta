/* commit 3153495d8ed6a9bb9f00aea42c18dc488a885dd6 */

/*
 * This test is about the incorrect placement of
 * inc_nlink function and update of the i_ctime.
 */

#include "../fs.h"

#include <malloc.h>

#define ENOMEM		12
#define EINVAL		22
#define EMLINK		31
#define S_ISUID 0004000
#define S_ISGID	0002000


#define CURRENT_TIME_SEC	((struct timespec) {4,5})
#define BTRFS_LINK_MAX		65535U

typedef unsigned long long u64;

volatile struct dentry *old_dentry, *dentry;
volatile struct inode *dir;

void inc_nlink(struct inode *inode)
{
	inode->__i_nink++;
}

int btrfs_set_inode_index(struct inode *dir, u64 *index)
{
	if (dir)
		return -EINVAL;
	else {
		dir = malloc(sizeof(struct inode));
		if (!dir)
			return -ENOMEM;
	}
	return 0;
}

int btrfs_link(struct dentry *old_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	u64 index;
	int err;
	struct inode *inode = old_dentry->d_inode;

	if (inode->i_nlink >= BTRFS_LINK_MAX)
		return -EMLINK;

#ifndef __PATCH__
	inc_nlink(inode);
	inode->i_ctime = CURRENT_TIME_SEC;
#endif

	err = btrfs_set_inode_index(dir, &index);
	if (err)
		goto fail;

#ifdef __PATCH__
	inc_nlink(inode);
	inode->i_ctime = CURRENT_TIME_SEC;
#endif

     fail:
	return err;
}

int main(int argc, char *argv[])
{
	int v;
	v = btrfs_link(old_dentry, dir, dentry);
	return 0;
}
