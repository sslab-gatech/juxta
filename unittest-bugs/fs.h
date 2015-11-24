#include <stdio.h>
#include <time.h>

typedef long long loff_t;

struct super_block {
};

struct posix_acl {
};

struct dentry_operations {
};

struct dentry {
	struct inode *d_inode;
};

struct inode_operations {
};

struct inode {
	unsigned int	i_flags;
	unsigned int	i_blkbits;
	loff_t		i_size;
	unsigned short	i_mode;
	struct timespec i_ctime;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nink;
	};
};
