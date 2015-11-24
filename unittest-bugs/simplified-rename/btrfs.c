#include "common.h"

#define RENAME_NOREPLACE	(1 << 0)	/* Don't overwrite target */
// #define CURRENT_TIME		(current_kernel_time())

#define BTRFS_FIRST_FREE_OBJECTID 256ULL
#define BTRFS_EMPTY_SUBVOL_DIR_OBJECTID 2
#define BTRFS_EMPTY_DIR_SIZE 0

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

struct btrfs_fs_info {};
struct btrfs_key {};
struct btrfs_root {
  struct btrfs_fs_info *fs_info;
  struct btrfs_key root_key;
};

struct btrfs_inode {
  struct btrfs_root *root;
  struct inode vfs_inode;
};
  
static inline struct btrfs_inode *BTRFS_I(struct inode *inode)
{
  struct btrfs_inode *bi = (struct btrfs_inode*)inode;
  return bi;
}

static int btrfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = BTRFS_I(old_dir)->root;
	struct btrfs_root *dest = BTRFS_I(new_dir)->root;
	struct inode *new_inode = new_dentry->d_inode;
	struct inode *old_inode = old_dentry->d_inode;
	struct timespec ctime = CURRENT_TIME_SEC;
	u64 index = 0;
	u64 root_objectid;
	int ret;
	u64 old_ino = btrfs_ino(old_inode);

	if (S_ISDIR(old_inode->i_mode) && new_inode &&
	    new_inode->i_size > BTRFS_EMPTY_DIR_SIZE)
		return -ENOTEMPTY;

	if (ret) {
		if (ret == -EEXIST) {
			if (WARN_ON(!new_inode)) {
				return ret;
			}
		} else {
			return ret;
		}
	}
	ret = 0;

	inode_inc_iversion(old_dir);
	inode_inc_iversion(new_dir);
	inode_inc_iversion(old_inode);
	old_dir->i_ctime = old_dir->i_mtime = ctime;
	new_dir->i_ctime = new_dir->i_mtime = ctime;
	old_inode->i_ctime = ctime;

	if (old_dentry->d_parent != new_dentry->d_parent)
		btrfs_record_unlink_dir(trans, old_dir, old_inode, 1);

	ret = btrfs_add_link(trans, new_dir, old_inode,
			     new_dentry->d_name.name,
			     new_dentry->d_name.len, 0, index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_fail;
	}

out_fail:
	return ret;
}

// NOTE : btrfs_rename2() is the entry point.
static int btrfs_rename2(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry,
			 unsigned int flags)
{
	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	return btrfs_rename(old_dir, old_dentry, new_dir, new_dentry);
}

