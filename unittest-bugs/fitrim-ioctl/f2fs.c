#include "common.h"

int f2fs_trim_fs(struct f2fs_sb_info *sbi, struct fstrim_range *range)
{
	return 0;
}

static int f2fs_ioc_fitrim(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct request_queue *q = bdev_get_queue(sb->s_bdev);
	struct fstrim_range range;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!blk_queue_discard(q))
		return -EOPNOTSUPP;

	if (copy_from_user(&range, (struct fstrim_range *)arg,
					   sizeof(range)))
		return -EFAULT;

	range.minlen = (unsigned int)range.minlen;
	ret = f2fs_trim_fs(F2FS_SB(sb), &range);
	if (ret < 0)
		return ret;

	if (copy_to_user((struct fstrim_range *)arg, &range,
					 sizeof(range)))
		return -EFAULT;
	return 0;
}

long f2fs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FITRIM:
		return f2fs_ioc_fitrim(filp, arg);
	default:
		return -ENOTTY;
	}
}

