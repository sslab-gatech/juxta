/* commit 53b7e9f6807c1274eee19201396b4c2b5f721553 */

/*
 * This test is about the variable update. There
 * are multiple patches of this kind!
 */

#include "../fs.h"

#define ENOENT		2
#define EMLINK		31
#define ENOTEMPTY	39

#define CURRENT_TIME_SEC	((struct timespec) {4,5})

#define S_IFMT	00170000
#define S_IFDIR  0040000
#define EXT4_LINK_MAX 65000

#define S_ISDIR(m)				(((m) & S_IFMT) == S_IFDIR)
#define EXT4_DIR_LINK_MAX(dir)	((dir)->i_nlink >= EXT4_LINK_MAX)

typedef unsigned long long __u64;

volatile struct inode old_dir, old_dentry, new_dir, new_dentry;

struct ext4_renament {
	struct inode *dir;
	struct inode *inode;
};

int empty_dir(struct inode *inode)
{
	return 1;
}

int ext4_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct node *new_dir, struct dentry *new_dentry)
{

	int retval = -ENOENT;
	struct ext4_renament new = {
		.dir = new_dir,
		.inode = new_dentry->d_inode,
	};

	struct ext4_renament old = {
		.dir = old_dir,
		.inode = new_dentry->d_inode,
	};

	if (S_ISDIR(old.inode->i_mode)) {
		if (new.inode) {
			retval = -ENOTEMPTY;
			if (!empty_dir(new.inode))
				goto end_rename;
		} else {
			retval = -EMLINK;
			if (new.dir != old.dir && EXT4_DIR_LINK_MAX(new.dir))
				goto end_rename;
		}
	}

#ifdef __PATCH__
	old.inode->i_ctime = CURRENT_TIME_SEC;
#endif

	retval = 0;
 end_rename:

	return retval;
}

int main(int argc, char *argv[])
{
	int v;
	v = ext4_rename(&old_dir, &old_dentry, &new_dir, &new_dentry);
	return 0;
}
