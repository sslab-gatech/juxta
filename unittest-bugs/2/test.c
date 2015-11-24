/* commit 4a58579b9e4e2a35d57e6c9c8483e52f6f1b7fd6 */

/*
 * This test is missing a return value which is already
 * going to be a part of the set
 */

#include "../fs.h"

#define S_ISUID 0004000
#define S_ISGID	0002000
#define EINVAL	22

typedef unsigned long long __u64;

volatile struct inode orig_inode, donor_inode;
volatile __u64 orig_start, donor_start, len;

int mext_check_arguments(struct inode *orig_inode,
		     struct inode *donor_inode, __u64 orig_start,
		     __u64 donor_start, __u64 *len)
{

	unsigned int blkbits = orig_inode->i_blkbits;
	unsigned int blocksize = 1 << blkbits;

#ifdef __PATCH__
	if (donor_inode->i_mode & (S_ISUID|S_ISGID))
		return -EINVAL;
#endif

	if ((!orig_inode->i_size) || (!donor_inode->i_size))
		return -EINVAL;

	if (!*len)
		return -EINVAL;

	return 0;
}

int main(int argc, char *argv[])
{
	int v;
	v = mext_check_arguments(&orig_inode, &donor_inode, orig_start, donor_start, &len);
	return 0;
}
