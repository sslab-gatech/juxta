/* commit: 4143179218960a70d821a425e3c23ce44aa93dee */

#include "common.h"

#define EXT4_XATTR_INDEX_USER	1
#define EXT4_HT_XATTR			10

struct ext4_inode_info {
	__le32	i_data[15];
	__u32	i_flags;
	__u32	i_faddr;
	__u8	i_frag_no;
	__u8	i_frag_size;
	__u16	i_state;
	__u32	i_file_acl;
	__u32	i_dir_acl;
	__u32	i_dtime;

	/*
	 * i_block_group is the number of the block group which contains
	 * this file's inode.  Constant across the lifetime of the inode,
	 * it is used for making block allocation decisions - we try to
	 * place a file's data blocks near its inode block, and new inodes
	 * near to their parent directory's inode.
	 */
	__u32	i_block_group;

	/* block reservation info */
	__u32	i_dir_start_lookup;
	struct inode	vfs_inode;
};


static inline struct ext4_inode_info *EXT4_I(struct inode *inode)
{
	struct ext4_inode_info *i = (struct inode *)inode;
	return i;
}

int ext4_trim_fs(struct super_block *sb, struct fstrim_range *range)
{
	int ret;
	if (ret > 0)
		ret = 0;

out:
	return ret;
}

long ext4_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct ext4_inode_info *ei = EXT4_I(inode);
	unsigned int flags;

	switch (cmd) {
	case FITRIM:
		{
			struct request_queue *q = bdev_get_queue(sb->s_bdev);
			struct fstrim_range range;
			int ret = 0;

			if (!capable(CAP_SYS_ADMIN))
				return -EPERM;
#ifdef __PATCH__
			if (!blk_queue_discard(q))
				return -EOPNOTSUPP;
#endif

			if (copy_from_user(&range, (struct fstrim_range *)arg,
							   sizeof(range)))
				return -EFAULT;

			range.minlen = (unsigned int)range.minlen;
			ret = ext4_trim_fs(sb, &range);
			if (ret < 0)
				return ret;

			if (copy_to_user((struct fstrim_range *)arg, &range,
							 sizeof(range)))
				return -EFAULT;

			return 0;
		}
	default:
		return -ENOTTY;
	}
}
