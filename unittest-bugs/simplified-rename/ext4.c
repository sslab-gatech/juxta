#include "common.h"

struct ext4_renament {
	struct inode *dir;
	struct dentry *dentry;
	struct inode *inode;
	bool is_dir;
	int dir_nlink_delta;

	/* entry for "dentry" */
	struct buffer_head *bh;
	struct ext4_dir_entry_2 *de;
	int inlined;

	/* entry for ".." in inode if it's a directory */
	struct buffer_head *dir_bh;
	struct ext4_dir_entry_2 *parent_de;
	int dir_inlined;
};


# define NSEC_PER_SEC			1000000000ULL

static inline struct timespec ext4_current_time(struct inode *inode)
{
	return (inode->i_sb->s_time_gran < NSEC_PER_SEC) ?
        // current_fs_time(inode->i_sb) : CURRENT_TIME_SEC;
		CURRENT_TIME_SEC : CURRENT_TIME_SEC;
}

#define NO_AUTO_DA_ALLOC	0x10000	/* No auto delalloc mapping */
#define RENAME_WHITEOUT		(1 << 2)	/* Whiteout source */
#define EXT4_HT_DIR              4
#define EXT4_INODE_INLINE_DATA	28	/* Data in inode. */
#define EXT4_FT_CHRDEV		3
#define EXT4_INDEX_EXTRA_TRANS_BLOCKS	8

static int ext4_rename2(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned int flags)
{
	handle_t *handle = NULL;
	struct ext4_renament old = {
		.dir = old_dir,
		.dentry = old_dentry,
		.inode = old_dentry->d_inode,
	};
	struct ext4_renament new = {
		.dir = new_dir,
		.dentry = new_dentry,
		.inode = new_dentry->d_inode,
	};
	int retval;

	/* Initialize quotas before so that eventual writes go
	 * in separate transaction */
	if (new.inode)
		dquot_initialize(new.inode);

	new.bh = ext4_find_entry(new.dir, &new.dentry->d_name,
				 &new.de, &new.inlined);
    if (new.bh) {
        if (!new.inode) {
            brelse(new.bh);
            new.bh = NULL;
        }
    }
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
		retval = ext4_rename_dir_prepare(handle, &old);
		if (retval)
			goto end_rename;
	}
	old.inode->i_ctime = ext4_current_time(old.inode);
	ext4_mark_inode_dirty(handle, old.inode);

	if (new.inode) {
		ext4_dec_count(handle, new.inode);
		new.inode->i_ctime = ext4_current_time(new.inode);
	}
	old.dir->i_ctime = old.dir->i_mtime = ext4_current_time(old.dir);
	ext4_update_dx_flag(old.dir);
	if (old.dir_bh) {
		retval = ext4_rename_dir_finish(handle, &old, new.dir->i_ino);
		if (retval)
			goto end_rename;
	}
	ext4_mark_inode_dirty(handle, old.dir);
	if (new.inode) {
		ext4_mark_inode_dirty(handle, new.inode);
		if (!new.inode->i_nlink)
			ext4_orphan_add(handle, new.inode);
	}
	retval = 0;

end_rename:
	return retval;
}
