#include "common.h"

int btrfs_trim_fs(struct btrfs_root *root, struct fstrim_range *range)
{
	return 0;
}

static int btrfs_ioctl_fitrim(struct file *file, void *arg)
{
	struct btrfs_fs_info *fs_info;// = btrfs_sb(file_inode(file)->i_sb);
	struct btrfs_device *device;
	struct request_queue *q;
	unsigned long total_bytes;
	struct fstrim_range range;
	u64 minlen = ULLONG_MAX;
	u64 num_devices = 0;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	//rcu_read_lock();
	//list_for_each_entry_rcu(device, &fs_info->fs_devices->devices,
	//						dev_list) {
		if (!device->bdev);
			//continue;
		q = bdev_get_queue(device->bdev);
		if (blk_queue_discard(q)) {
			num_devices++;
		}
	//}
	//rcu_read_unlock();

	if (!num_devices)
		return -EOPNOTSUPP;
	if (copy_from_user(&range, arg, sizeof(range)))
		return -EFAULT;
	if (range.start > total_bytes ||
		range.len < fs_info->sb->s_blocksize)
		return -EINVAL;

	range.minlen = range.minlen;
	ret = btrfs_trim_fs(fs_info->tree_root, &range);
	if (ret < 0)
		return ret;

	if (copy_to_user(arg, &range, sizeof(range)))
		return -EFAULT;

	return 0;
}



static inline struct btrfs_inode *BTRFS_I(struct inode *inode)
{
	struct btrfs_inode *i = (struct inode *)inode;
	return i;
}

long btrfs_ioctl(struct file *file, unsigned int
				 cmd, unsigned long arg)
{
	struct btrfs_root *root = BTRFS_I(file_inode(file))->root;
	void *argp = (void *)arg;

	switch (cmd) {

	case FITRIM:
		return btrfs_ioctl_fitrim(file, argp);

	}
	return -ENOTTY;
}

