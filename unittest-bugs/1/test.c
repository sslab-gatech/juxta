/* commit ed9b3e3379731e9f9d2f73f3d7fd9e7d2ce3df4a */

/*
 * This test misses one return value which is not repeated
 */

#include "../fs.h"

#define EPERM	1
#define EINVAL	22

#define S_IMMUTABLE 8   /* Immutable file */
#define S_APPEND    4   /* Append-only file */

#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)

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
	if (IS_IMMUTABLE(donor_inode) || IS_APPEND(donor_inode))
		return -EPERM;
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
