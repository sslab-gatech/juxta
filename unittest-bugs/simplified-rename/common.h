#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <time.h>
#include <stdbool.h>

typedef long long loff_t;
typedef unsigned int u32;
typedef unsigned int __u32;
typedef unsigned long u64;
typedef unsigned long __u64;
typedef u64 atomic_t;
typedef u64 umode_t;
typedef u64 blkcnt_t;


typedef u64 handle_t;
typedef u32 __le32;
typedef unsigned short __le16;
typedef unsigned char __u8;
typedef unsigned char u8;

struct super_block {
	u32		   s_time_gran;
};

struct posix_acl {
};

struct dentry_operations {
};

#define CURRENT_TIME_SEC	((struct timespec) { 0, 0 })

#define HASH_LEN_DECLARE u32 hash; u32 len;

struct qstr {
	union {
		struct {
			HASH_LEN_DECLARE;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

#define DNAME_INLINE_LEN 32 /* 192 bytes */

struct dentry {
	/* RCU lookup touched fields */
	unsigned int d_flags;		/* protected by d_lock */
	// seqcount_t d_seq;		/* per dentry seqlock */
	// struct hlist_bl_node d_hash;	/* lookup hash list */
	struct dentry *d_parent;	/* parent directory */
	struct qstr d_name;
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */

	/* Ref lookup also touches following */
	// struct lockref d_lockref;	/* per-dentry lock and refcount */
	// const struct dentry_operations *d_op;
	// struct super_block *d_sb;	/* The root of the dentry tree */
	// unsigned long d_time;		/* used by d_revalidate */
	// void *d_fsdata;			/* fs-specific data */

	// struct list_head d_lru;		/* LRU list */
	// struct list_head d_child;	/* child of parent list */
	// struct list_head d_subdirs;	/* our children */
	// /*
	//  * d_alias and d_rcu can share memory
	//  */
	// union {
	// 	struct hlist_node d_alias;	/* inode alias list */
	//  	struct rcu_head d_rcu;
	// } d_u;
};

struct inode_operations {
};

struct inode {
	umode_t			i_mode;
	unsigned short		i_opflags;
	// kuid_t			i_uid;
	// kgid_t			i_gid;
	unsigned int		i_flags;

	const struct inode_operations	*i_op;
	struct super_block	*i_sb;
	struct address_space	*i_mapping;
	unsigned long		i_ino;

	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	// dev_t			i_rdev;
	loff_t			i_size;
	struct timespec		i_atime;
	struct timespec		i_mtime;
	struct timespec		i_ctime;
	// spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
	unsigned short          i_bytes;
	unsigned int		i_blkbits;
	blkcnt_t		i_blocks;

	/* Misc */
	unsigned long		i_state;
	// struct mutex		i_mutex;

	unsigned long		dirtied_when;	/* jiffies of first dirtying */

	// struct hlist_node	i_hash;
	// struct list_head	i_wb_list;	/* backing dev IO list */
	// struct list_head	i_lru;		/* inode LRU list */
	// struct list_head	i_sb_list;
	// union {
	// 	struct hlist_head	i_dentry;
	// 	struct rcu_head		i_rcu;
	// };
	u64			i_version;
	atomic_t		i_count;
	atomic_t		i_dio_count;
	atomic_t		i_writecount;

	// const struct file_operations	*i_fop;	/* former ->i_op->default_file_ops */
	// struct file_lock_context	*i_flctx;
	// struct address_space	i_data;
	// struct list_head	i_devices;
	// union {
	// 	struct pipe_inode_info	*i_pipe;
	// 	struct block_device	*i_bdev;
	// 	struct cdev		*i_cdev;
	// };

	__u32			i_generation;

	void			*i_private; /* fs or device private pointer */
};

#define	EPERM		 1	/* Operation not permitted */
#define	ENOENT		 2	/* No such file or directory */
#define	ESRCH		 3	/* No such process */
#define	EINTR		 4	/* Interrupted system call */
#define	EIO		 5	/* I/O error */
#define	ENXIO		 6	/* No such device or address */
#define	E2BIG		 7	/* Argument list too long */
#define	ENOEXEC		 8	/* Exec format error */
#define	EBADF		 9	/* Bad file number */
#define	ECHILD		10	/* No child processes */
#define	EAGAIN		11	/* Try again */
#define	ENOMEM		12	/* Out of memory */
#define	EACCES		13	/* Permission denied */
#define	EFAULT		14	/* Bad address */
#define	ENOTBLK		15	/* Block device required */
#define	EBUSY		16	/* Device or resource busy */
#define	EEXIST		17	/* File exists */
#define	EXDEV		18	/* Cross-device link */
#define	ENODEV		19	/* No such device */
#define	ENOTDIR		20	/* Not a directory */
#define	EISDIR		21	/* Is a directory */
#define	EINVAL		22	/* Invalid argument */
#define	ENFILE		23	/* File table overflow */
#define	EMFILE		24	/* Too many open files */
#define	ENOTTY		25	/* Not a typewriter */
#define	ETXTBSY		26	/* Text file busy */
#define	EFBIG		27	/* File too large */
#define	ENOSPC		28	/* No space left on device */
#define	ESPIPE		29	/* Illegal seek */
#define	EROFS		30	/* Read-only file system */
#define	EMLINK		31	/* Too many links */
#define	EPIPE		32	/* Broken pipe */
#define	EDOM		33	/* Math argument out of domain of func */
#define	ERANGE		34	/* Math result not representable */

#define	ENOTEMPTY	247	/* Directory not empty */

#endif // __COMMON_H__
