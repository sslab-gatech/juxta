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
	struct buffer_head * old_bh, * new_bh, * dir_bh;
	struct ext3_dir_entry_2 * old_de, * new_de;
	int retval, flush_file = 0;

	dquot_initialize(old_dir);
	dquot_initialize(new_dir);

	old_bh = new_bh = dir_bh = NULL;

	/* Initialize quotas before so that eventual writes go
	 * in separate transaction */
	if (new_dentry->d_inode)
		dquot_initialize(new_dentry->d_inode);
	/* handle = (handle_t*)ext3_journal_start(old_dir, 2 * */
	/* 				/\* EXT3_DATA_TRANS_BLOCKS(old_dir->i_sb) + *\/ */
	/* 				EXT3_INDEX_EXTRA_TRANS_BLOCKS + 2); */
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (IS_DIRSYNC(old_dir) || IS_DIRSYNC(new_dir))
                handle = (handle_t*)1;

	/* old_bh = ext3_find_entry(old_dir, &old_dentry->d_name, &old_de); */
	/*
	 *  Check for inode number is _not_ due to possible IO errors.
	 *  We might rmdir the source, keep it as pwd of some process
	 *  and merrily kill the link to whatever was created under the
	 *  same name. Goodbye sticky bit ;-<
	 */
	old_inode = old_dentry->d_inode;
	retval = -ENOENT;
	if (!old_bh || le32_to_cpu(old_de->inode) != old_inode->i_ino)
		goto end_rename;

	new_inode = new_dentry->d_inode;
	new_bh = ext3_find_entry(new_dir, &new_dentry->d_name, &new_de);
	if (new_bh) {
		if (!new_inode) {
			brelse (new_bh);
			new_bh = NULL;
		}
	}
	if (S_ISDIR(old_inode->i_mode)) {
		if (new_inode) {
			retval = -ENOTEMPTY;
			if (!empty_dir (new_inode))
				goto end_rename;
		}
		retval = -EIO;
		dir_bh = ext3_dir_bread(handle, old_inode, 0, 0, &retval);
		if (!dir_bh)
			goto end_rename;
		/* if (le32_to_cpu(PARENT_INO(dir_bh->b_data)) != old_dir->i_ino) */
		/* 	goto end_rename; */
		retval = -EMLINK;
		if (!new_inode && new_dir!=old_dir &&
				new_dir->i_nlink >= EXT3_LINK_MAX)
			goto end_rename;
	}
	if (!new_bh) {
		retval = ext3_add_entry (handle, new_dentry, old_inode);
		if (retval)
			goto end_rename;
	} else {
		BUFFER_TRACE(new_bh, "get write access");
		retval = ext3_journal_get_write_access(handle, new_bh);
		if (retval)
			goto journal_error;
		new_de->inode = cpu_to_le32(old_inode->i_ino);
		if (EXT3_HAS_INCOMPAT_FEATURE(new_dir->i_sb,
					      EXT3_FEATURE_INCOMPAT_FILETYPE))
			new_de->file_type = old_de->file_type;
		new_dir->i_version++;

		// !! NOTE!! Below two lines are the patch!
#ifdef __PATCH__
		new_dir->i_ctime = new_dir->i_mtime = CURRENT_TIME_SEC;
		ext3_mark_inode_dirty(handle, new_dir);
#endif

		BUFFER_TRACE(new_bh, "call ext3_journal_dirty_metadata");
		retval = ext3_journal_dirty_metadata(handle, new_bh);
		if (retval)
			goto journal_error;
		brelse(new_bh);
		new_bh = NULL;
	}

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
	 * rename.
	 */

	old_inode->i_ctime = CURRENT_TIME_SEC;
	ext3_mark_inode_dirty(handle, old_inode);

	/*
	 * ok, that's it
	 */
	if (le32_to_cpu(old_de->inode) != old_inode->i_ino ||
	    old_de->name_len != old_dentry->d_name.len ||
	    strncmp(old_de->name, old_dentry->d_name.name, old_de->name_len) ||
	    (retval = ext3_delete_entry(handle, old_dir,
					old_de, old_bh)) == -ENOENT) {
		/* old_de could have moved from under us during htree split, so
		 * make sure that we are deleting the right entry.  We might
		 * also be pointing to a stale entry in the unused part of
		 * old_bh so just checking inum and the name isn't enough. */
		struct buffer_head *old_bh2;
		struct ext3_dir_entry_2 *old_de2;

		old_bh2 = ext3_find_entry(old_dir, &old_dentry->d_name,
					  &old_de2);
		if (old_bh2) {
			retval = ext3_delete_entry(handle, old_dir,
						   old_de2, old_bh2);
			brelse(old_bh2);
		}
	}
	if (retval) {
		ext3_warning(old_dir->i_sb, "ext3_rename",
				"Deleting old file (%lu), %d, error=%d",
				old_dir->i_ino, old_dir->i_nlink, retval);
	}

	if (new_inode) {
		drop_nlink(new_inode);
		new_inode->i_ctime = CURRENT_TIME_SEC;
	}
	old_dir->i_ctime = old_dir->i_mtime = CURRENT_TIME_SEC;
	ext3_update_dx_flag(old_dir);
	if (dir_bh) {
		BUFFER_TRACE(dir_bh, "get_write_access");
		retval = ext3_journal_get_write_access(handle, dir_bh);
		if (retval)
			goto journal_error;
		/* PARENT_INO(dir_bh->b_data) = cpu_to_le32(new_dir->i_ino); */
		BUFFER_TRACE(dir_bh, "call ext3_journal_dirty_metadata");
		retval = ext3_journal_dirty_metadata(handle, dir_bh);
		if (retval) {
journal_error:
			ext3_std_error(new_dir->i_sb, retval);
			goto end_rename;
		}
		drop_nlink(old_dir);
		if (new_inode) {
			drop_nlink(new_inode);
		} else {
			inc_nlink(new_dir);
			ext3_update_dx_flag(new_dir);
			ext3_mark_inode_dirty(handle, new_dir);
		}
	}
	ext3_mark_inode_dirty(handle, old_dir);
	if (new_inode) {
		ext3_mark_inode_dirty(handle, new_inode);
		if (!new_inode->i_nlink)
			ext3_orphan_add(handle, new_inode);
		if (ext3_should_writeback_data(new_inode))
			flush_file = 1;
	}
	retval = 0;

end_rename:
	brelse (dir_bh);
	brelse (old_bh);
	brelse (new_bh);
	ext3_journal_stop(handle);
	if (retval == 0 && flush_file)
		filemap_flush(old_inode->i_mapping);
	return retval;
}
