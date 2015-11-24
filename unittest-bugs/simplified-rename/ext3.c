#include "common.h"

#define EXT3_INDEX_EXTRA_TRANS_BLOCKS	8
#define EXT3_NAME_LEN 255
#define EXT3_LINK_MAX		32000
#define EXT3_FEATURE_INCOMPAT_FILETYPE		0x0002
struct ext3_dir_entry_2 {
	__le32	inode;			/* Inode number */
	__le16	rec_len;		/* Directory entry length */
	__u8	name_len;		/* Name length */
	__u8	file_type;
	char	name[EXT3_NAME_LEN];	/* File name */
};

static int ext3_rename (struct inode * old_dir, struct dentry *old_dentry,
			struct inode * new_dir,struct dentry *new_dentry)
{
	handle_t *handle;
	struct inode * old_inode, * new_inode;
	struct buffer_head * new_bh, * dir_bh;
	struct ext3_dir_entry_2 * old_de, * new_de;
	int retval, flush_file = 0;

	new_bh = dir_bh = NULL;

	old_inode = old_dentry->d_inode;
	retval = -ENOENT;
	new_inode = new_dentry->d_inode;
	new_bh = ext3_find_entry(new_dir, &new_dentry->d_name, &new_de);
	if (new_bh) {
		if (!new_inode) {
			brelse (new_bh);
			new_bh = NULL;
		}
	}
	if (!new_bh) {
		retval = ext3_add_entry (handle, new_dentry, old_inode);
		if (retval)
			goto end_rename;
	} else {
#ifdef __PATCH__
		// !! NOTE!! Below two lines are the patch!
		new_dir->i_ctime = new_dir->i_mtime = CURRENT_TIME_SEC;
		ext3_mark_inode_dirty(handle, new_dir);
#endif
	}

	old_inode->i_ctime = CURRENT_TIME_SEC;
	ext3_mark_inode_dirty(handle, old_inode);

	/*
	 * ok, that's it
	 */
	if (new_inode) {
		drop_nlink(new_inode);
		new_inode->i_ctime = CURRENT_TIME_SEC;
	}
	old_dir->i_ctime = old_dir->i_mtime = CURRENT_TIME_SEC;
	ext3_update_dx_flag(old_dir);
	retval = 0;

end_rename:
	return retval;
}
