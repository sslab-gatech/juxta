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

	if (btrfs_ino(new_dir) == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)
		return -EPERM;

	/* we only allow rename subvolume link between subvolumes */
	if (old_ino != BTRFS_FIRST_FREE_OBJECTID && root != dest)
		return -EXDEV;

	if (old_ino == BTRFS_EMPTY_SUBVOL_DIR_OBJECTID ||
	    (new_inode && btrfs_ino(new_inode) == BTRFS_FIRST_FREE_OBJECTID))
		return -ENOTEMPTY;

	if (S_ISDIR(old_inode->i_mode) && new_inode &&
	    new_inode->i_size > BTRFS_EMPTY_DIR_SIZE)
		return -ENOTEMPTY;


	/* check for collisions, even if the  name isn't there */
	ret = btrfs_check_dir_item_collision(dest, new_dir->i_ino,
			     new_dentry->d_name.name,
			     new_dentry->d_name.len);

	if (ret) {
		if (ret == -EEXIST) {
			/* we shouldn't get
			 * eexist without a new_inode */
			if (WARN_ON(!new_inode)) {
				return ret;
			}
		} else {
			/* maybe -EOVERFLOW */
			return ret;
		}
	}
	ret = 0;

	/*
	 * we're using rename to replace one file with another.  Start IO on it
	 * now so  we don't add too much work to the end of the transaction
	 */
	if (new_inode && S_ISREG(old_inode->i_mode) && new_inode->i_size)
		filemap_flush(old_inode->i_mapping);

	/* close the racy window with snapshot create/destroy ioctl */
	/* if (old_ino == BTRFS_FIRST_FREE_OBJECTID) */
	/* 	down_read(&root->fs_info->subvol_sem); */
	/*
	 * We want to reserve the absolute worst case amount of items.  So if
	 * both inodes are subvols and we need to unlink them then that would
	 * require 4 item modifications, but if they are both normal inodes it
	 * would require 5 item modifications, so we'll assume their normal
	 * inodes.  So 5 * 2 is 10, plus 1 for the new link, so 11 total items
	 * should cover the worst case number of items we'll modify.
	 */
	trans = btrfs_start_transaction(root, 11);
	if (IS_ERR(trans)) {
                ret = PTR_ERR(trans);
                goto out_notrans;
        }

	if (dest != root)
		btrfs_record_root_in_trans(trans, dest);

	ret = btrfs_set_inode_index(new_dir, &index);
	if (ret)
		goto out_fail;

	/* BTRFS_I(old_inode)->dir_index = 0ULL; */
	if (unlikely(old_ino == BTRFS_FIRST_FREE_OBJECTID)) {
		/* force full log commit if subvolume involved. */
		btrfs_set_log_full_commit(root->fs_info, trans);
	} else {
		ret = btrfs_insert_inode_ref(trans, dest,
					     new_dentry->d_name.name,
					     new_dentry->d_name.len,
					     old_ino,
					     btrfs_ino(new_dir), index);
		if (ret)
			goto out_fail;
		/*
		 * this is an ugly little race, but the rename is required
		 * to make sure that if we crash, the inode is either at the
		 * old name or the new one.  pinning the log transaction lets
		 * us make sure we don't allow a log commit to come in after
		 * we unlink the name but before we add the new name back in.
		 */
		btrfs_pin_log_trans(root);
	}

	inode_inc_iversion(old_dir);
	inode_inc_iversion(new_dir);
	inode_inc_iversion(old_inode);
	old_dir->i_ctime = old_dir->i_mtime = ctime;
	new_dir->i_ctime = new_dir->i_mtime = ctime;
	old_inode->i_ctime = ctime;

	if (old_dentry->d_parent != new_dentry->d_parent)
		btrfs_record_unlink_dir(trans, old_dir, old_inode, 1);

	/* if (unlikely(old_ino == BTRFS_FIRST_FREE_OBJECTID)) { */
	/* 	root_objectid = BTRFS_I(old_inode)->root->root_key.objectid; */
	/* 	ret = btrfs_unlink_subvol(trans, root, old_dir, root_objectid, */
	/* 				old_dentry->d_name.name, */
	/* 				old_dentry->d_name.len); */
	/* } else { */
	/* 	ret = __btrfs_unlink_inode(trans, root, old_dir, */
	/* 				old_dentry->d_inode, */
	/* 				old_dentry->d_name.name, */
	/* 				old_dentry->d_name.len); */
	/* 	if (!ret) */
	/* 		ret = btrfs_update_inode(trans, root, old_inode); */
	/* } */
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_fail;
	}

	if (new_inode) {
		inode_inc_iversion(new_inode);
		new_inode->i_ctime = CURRENT_TIME_SEC;
		if (unlikely(btrfs_ino(new_inode) ==
			     BTRFS_EMPTY_SUBVOL_DIR_OBJECTID)) {
			/* root_objectid = BTRFS_I(new_inode)->location.objectid; */
			ret = btrfs_unlink_subvol(trans, dest, new_dir,
						root_objectid,
						new_dentry->d_name.name,
						new_dentry->d_name.len);
			BUG_ON(new_inode->i_nlink == 0);
		} else {
			ret = btrfs_unlink_inode(trans, dest, new_dir,
						 new_dentry->d_inode,
						 new_dentry->d_name.name,
						 new_dentry->d_name.len);
		}
		if (!ret && new_inode->i_nlink == 0)
			ret = btrfs_orphan_add(trans, new_dentry->d_inode);
		if (ret) {
			btrfs_abort_transaction(trans, root, ret);
			goto out_fail;
		}
	}

	ret = btrfs_add_link(trans, new_dir, old_inode,
			     new_dentry->d_name.name,
			     new_dentry->d_name.len, 0, index);
	if (ret) {
		btrfs_abort_transaction(trans, root, ret);
		goto out_fail;
	}

	/* if (old_inode->i_nlink == 1) */
	/* 	BTRFS_I(old_inode)->dir_index = index; */

	if (old_ino != BTRFS_FIRST_FREE_OBJECTID) {
		struct dentry *parent = new_dentry->d_parent;
		btrfs_log_new_name(trans, old_inode, old_dir, parent);
		btrfs_end_log_trans(root);
	}
out_fail:
	btrfs_end_transaction(trans, root);
out_notrans:
	/* if (old_ino == BTRFS_FIRST_FREE_OBJECTID) */
	/* 	up_read(&root->fs_info->subvol_sem); */

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

