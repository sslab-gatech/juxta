/*
 *  linux/fs/sysv/ialloc.c
 *
 *  minix/bitmap.c
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext/freelists.c
 *  Copyright (C) 1992  Remy Card (card@masi.ibp.fr)
 *
 *  xenix/alloc.c
 *  Copyright (C) 1992  Doug Evans
 *
 *  coh/alloc.c
 *  Copyright (C) 1993  Pascal Haible, Bruno Haible
 *
 *  sysv/ialloc.c
 *  Copyright (C) 1993  Bruno Haible
 *
 *  This file contains code for allocating/freeing inodes.
 */

#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include "sysv.h"

/* We don't trust the value of
   sb->sv_sbd2->s_tinode = *sb->sv_sb_total_free_inodes
   but we nevertheless keep it up to date. */

/* An inode on disk is considered free if both i_mode == 0 and i_nlink == 0. */

/* return &sb->sv_sb_fic_inodes[i] = &sbd->s_inode[i]; */
static inline sysv_ino_t *
sv_sb_fic_inode(struct super_block * sb, unsigned int i)
{
	struct sysv_sb_info *sbi = SYSV_SB(sb);

	if (sbi->s_bh1 == sbi->s_bh2)
		return &sbi->s_sb_fic_inodes[i];
	else {
		/* 512 byte Xenix FS */
		unsigned int offset = offsetof(struct xenix_super_block, s_inode[i]);
		if (offset < 512)
			return (sysv_ino_t*)(sbi->s_sbd1 + offset);
		else
			return (sysv_ino_t*)(sbi->s_sbd2 + offset);
	}
}

struct sysv_inode *
sysv_raw_inode(struct super_block *sb, unsigned ino, struct buffer_head **bh)
{
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	struct sysv_inode *res;
	int block = sbi->s_firstinodezone + sbi->s_block_base;

	block += (ino-1) >> sbi->s_inodes_per_block_bits;
	*bh = sb_bread(sb, block);
	if (!*bh)
		return NULL;
	res = (struct sysv_inode *)(*bh)->b_data;
	return res + ((ino-1) & sbi->s_inodes_per_block_1);
}

static int refill_free_cache(struct super_block *sb)
{
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	struct buffer_head * bh;
	struct sysv_inode * raw_inode;
	int i = 0, ino;

	ino = SYSV_ROOT_INO+1;
	raw_inode = sysv_raw_inode(sb, ino, &bh);
	if (!raw_inode)
		goto out;
	while (ino <= sbi->s_ninodes) {
		if (raw_inode->i_mode == 0 && raw_inode->i_nlink == 0) {
			*sv_sb_fic_inode(sb,i++) = cpu_to_fs16(SYSV_SB(sb), ino);
			if (i == sbi->s_fic_size)
				break;
		}
		if ((ino++ & sbi->s_inodes_per_block_1) == 0) {
			brelse(bh);
			raw_inode = sysv_raw_inode(sb, ino, &bh);
			if (!raw_inode)
				goto out;
		} else
			raw_inode++;
	}
	brelse(bh);
out:
	return i;
}

void sysv_free_inode(struct inode * inode)
{
	struct super_block *sb = inode->i_sb;
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	unsigned int ino;
	struct buffer_head * bh;
	struct sysv_inode * raw_inode;
	unsigned count;

	sb = inode->i_sb;
	ino = inode->i_ino;
	if (ino <= SYSV_ROOT_INO || ino > sbi->s_ninodes) {
		printk("sysv_free_inode: inode 0,1,2 or nonexistent inode\n");
		return;
	}
	raw_inode = sysv_raw_inode(sb, ino, &bh);
	if (!raw_inode) {
		printk("sysv_free_inode: unable to read inode block on device "
		       "%s\n", inode->i_sb->s_id);
		return;
	}
	mutex_lock(&sbi->s_lock);
	count = fs16_to_cpu(sbi, *sbi->s_sb_fic_count);
	if (count < sbi->s_fic_size) {
		*sv_sb_fic_inode(sb,count++) = cpu_to_fs16(sbi, ino);
		*sbi->s_sb_fic_count = cpu_to_fs16(sbi, count);
	}
	fs16_add(sbi, sbi->s_sb_total_free_inodes, 1);
	dirty_sb(sb);
	memset(raw_inode, 0, sizeof(struct sysv_inode));
	mark_buffer_dirty(bh);
	mutex_unlock(&sbi->s_lock);
	brelse(bh);
}

struct inode * sysv_new_inode(const struct inode * dir, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	struct inode *inode;
	sysv_ino_t ino;
	unsigned count;
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_NONE
	};

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&sbi->s_lock);
	count = fs16_to_cpu(sbi, *sbi->s_sb_fic_count);
	if (count == 0 || (*sv_sb_fic_inode(sb,count-1) == 0)) {
		count = refill_free_cache(sb);
		if (count == 0) {
			iput(inode);
			mutex_unlock(&sbi->s_lock);
			return ERR_PTR(-ENOSPC);
		}
	}
	/* Now count > 0. */
	ino = *sv_sb_fic_inode(sb,--count);
	*sbi->s_sb_fic_count = cpu_to_fs16(sbi, count);
	fs16_add(sbi, sbi->s_sb_total_free_inodes, -1);
	dirty_sb(sb);
	inode_init_owner(inode, dir, mode);
	inode->i_ino = fs16_to_cpu(sbi, ino);
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME_SEC;
	inode->i_blocks = 0;
	memset(SYSV_I(inode)->i_data, 0, sizeof(SYSV_I(inode)->i_data));
	SYSV_I(inode)->i_dir_start_lookup = 0;
	insert_inode_hash(inode);
	mark_inode_dirty(inode);

	sysv_write_inode(inode, &wbc);	/* ensure inode not allocated again */
	mark_inode_dirty(inode);	/* cleared by sysv_write_inode() */
	/* That's it. */
	mutex_unlock(&sbi->s_lock);
	return inode;
}

unsigned long sysv_count_free_inodes(struct super_block * sb)
{
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	struct buffer_head * bh;
	struct sysv_inode * raw_inode;
	int ino, count, sb_count;

	mutex_lock(&sbi->s_lock);

	sb_count = fs16_to_cpu(sbi, *sbi->s_sb_total_free_inodes);

	if (0)
		goto trust_sb;

	/* this causes a lot of disk traffic ... */
	count = 0;
	ino = SYSV_ROOT_INO+1;
	raw_inode = sysv_raw_inode(sb, ino, &bh);
	if (!raw_inode)
		goto Eio;
	while (ino <= sbi->s_ninodes) {
		if (raw_inode->i_mode == 0 && raw_inode->i_nlink == 0)
			count++;
		if ((ino++ & sbi->s_inodes_per_block_1) == 0) {
			brelse(bh);
			raw_inode = sysv_raw_inode(sb, ino, &bh);
			if (!raw_inode)
				goto Eio;
		} else
			raw_inode++;
	}
	brelse(bh);
	if (count != sb_count)
		goto Einval;
out:
	mutex_unlock(&sbi->s_lock);
	return count;

Einval:
	printk("sysv_count_free_inodes: "
		"free inode count was %d, correcting to %d\n",
		sb_count, count);
	if (!(sb->s_flags & MS_RDONLY)) {
		*sbi->s_sb_total_free_inodes = cpu_to_fs16(SYSV_SB(sb), count);
		dirty_sb(sb);
	}
	goto out;

Eio:
	printk("sysv_count_free_inodes: unable to read inode table\n");
trust_sb:
	count = sb_count;
	goto out;
}
/************************************************************/
/* ../linux-3.17/fs/sysv/ialloc.c */
/************************************************************/
/*
 *  linux/fs/sysv/balloc.c
 *
 *  minix/bitmap.c
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext/freelists.c
 *  Copyright (C) 1992  Remy Card (card@masi.ibp.fr)
 *
 *  xenix/alloc.c
 *  Copyright (C) 1992  Doug Evans
 *
 *  coh/alloc.c
 *  Copyright (C) 1993  Pascal Haible, Bruno Haible
 *
 *  sysv/balloc.c
 *  Copyright (C) 1993  Bruno Haible
 *
 *  This file contains code for allocating/freeing blocks.
 */

// #include <linux/buffer_head.h>
// #include <linux/string.h>
// #include "sysv.h"

/* We don't trust the value of
   sb->sv_sbd2->s_tfree = *sb->sv_free_blocks
   but we nevertheless keep it up to date. */

static inline sysv_zone_t *get_chunk(struct super_block *sb, struct buffer_head *bh)
{
	char *bh_data = bh->b_data;

	if (SYSV_SB(sb)->s_type == FSTYPE_SYSV4)
		return (sysv_zone_t*)(bh_data+4);
	else
		return (sysv_zone_t*)(bh_data+2);
}

/* NOTE NOTE NOTE: nr is a block number _as_ _stored_ _on_ _disk_ */

void sysv_free_block(struct super_block * sb, sysv_zone_t nr)
{
	struct sysv_sb_info * sbi = SYSV_SB(sb);
	struct buffer_head * bh;
	sysv_zone_t *blocks = sbi->s_bcache;
	unsigned count;
	unsigned block = fs32_to_cpu(sbi, nr);

	/*
	 * This code does not work at all for AFS (it has a bitmap
	 * free list).  As AFS is supposed to be read-only no one
	 * should call this for an AFS filesystem anyway...
	 */
	if (sbi->s_type == FSTYPE_AFS)
		return;

	if (block < sbi->s_firstdatazone || block >= sbi->s_nzones) {
		printk("sysv_free_block: trying to free block not in datazone\n");
		return;
	}

	mutex_lock(&sbi->s_lock);
	count = fs16_to_cpu(sbi, *sbi->s_bcache_count);

	if (count > sbi->s_flc_size) {
		printk("sysv_free_block: flc_count > flc_size\n");
		mutex_unlock(&sbi->s_lock);
		return;
	}
	/* If the free list head in super-block is full, it is copied
	 * into this block being freed, ditto if it's completely empty
	 * (applies only on Coherent).
	 */
	if (count == sbi->s_flc_size || count == 0) {
		block += sbi->s_block_base;
		bh = sb_getblk(sb, block);
		if (!bh) {
			printk("sysv_free_block: getblk() failed\n");
			mutex_unlock(&sbi->s_lock);
			return;
		}
		memset(bh->b_data, 0, sb->s_blocksize);
		*(__fs16*)bh->b_data = cpu_to_fs16(sbi, count);
		memcpy(get_chunk(sb,bh), blocks, count * sizeof(sysv_zone_t));
		mark_buffer_dirty(bh);
		set_buffer_uptodate(bh);
		brelse(bh);
		count = 0;
	}
	sbi->s_bcache[count++] = nr;

	*sbi->s_bcache_count = cpu_to_fs16(sbi, count);
	fs32_add(sbi, sbi->s_free_blocks, 1);
	dirty_sb(sb);
	mutex_unlock(&sbi->s_lock);
}

sysv_zone_t sysv_new_block(struct super_block * sb)
{
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	unsigned int block;
	sysv_zone_t nr;
	struct buffer_head * bh;
	unsigned count;

	mutex_lock(&sbi->s_lock);
	count = fs16_to_cpu(sbi, *sbi->s_bcache_count);

	if (count == 0) /* Applies only to Coherent FS */
		goto Enospc;
	nr = sbi->s_bcache[--count];
	if (nr == 0)  /* Applies only to Xenix FS, SystemV FS */
		goto Enospc;

	block = fs32_to_cpu(sbi, nr);

	*sbi->s_bcache_count = cpu_to_fs16(sbi, count);

	if (block < sbi->s_firstdatazone || block >= sbi->s_nzones) {
		printk("sysv_new_block: new block %d is not in data zone\n",
			block);
		goto Enospc;
	}

	if (count == 0) { /* the last block continues the free list */
		unsigned count;

		block += sbi->s_block_base;
		if (!(bh = sb_bread(sb, block))) {
			printk("sysv_new_block: cannot read free-list block\n");
			/* retry this same block next time */
			*sbi->s_bcache_count = cpu_to_fs16(sbi, 1);
			goto Enospc;
		}
		count = fs16_to_cpu(sbi, *(__fs16*)bh->b_data);
		if (count > sbi->s_flc_size) {
			printk("sysv_new_block: free-list block with >flc_size entries\n");
			brelse(bh);
			goto Enospc;
		}
		*sbi->s_bcache_count = cpu_to_fs16(sbi, count);
		memcpy(sbi->s_bcache, get_chunk(sb, bh),
				count * sizeof(sysv_zone_t));
		brelse(bh);
	}
	/* Now the free list head in the superblock is valid again. */
	fs32_add(sbi, sbi->s_free_blocks, -1);
	dirty_sb(sb);
	mutex_unlock(&sbi->s_lock);
	return nr;

Enospc:
	mutex_unlock(&sbi->s_lock);
	return 0;
}

unsigned long sysv_count_free_blocks(struct super_block * sb)
{
	struct sysv_sb_info * sbi = SYSV_SB(sb);
	int sb_count;
	int count;
	struct buffer_head * bh = NULL;
	sysv_zone_t *blocks;
	unsigned block;
	int n;

	/*
	 * This code does not work at all for AFS (it has a bitmap
	 * free list).  As AFS is supposed to be read-only we just
	 * lie and say it has no free block at all.
	 */
	if (sbi->s_type == FSTYPE_AFS)
		return 0;

	mutex_lock(&sbi->s_lock);
	sb_count = fs32_to_cpu(sbi, *sbi->s_free_blocks);

	if (0)
		goto trust_sb;

	/* this causes a lot of disk traffic ... */
	count = 0;
	n = fs16_to_cpu(sbi, *sbi->s_bcache_count);
	blocks = sbi->s_bcache;
	while (1) {
		sysv_zone_t zone;
		if (n > sbi->s_flc_size)
			goto E2big;
		zone = 0;
		while (n && (zone = blocks[--n]) != 0)
			count++;
		if (zone == 0)
			break;

		block = fs32_to_cpu(sbi, zone);
		if (bh)
			brelse(bh);

		if (block < sbi->s_firstdatazone || block >= sbi->s_nzones)
			goto Einval;
		block += sbi->s_block_base;
		bh = sb_bread(sb, block);
		if (!bh)
			goto Eio;
		n = fs16_to_cpu(sbi, *(__fs16*)bh->b_data);
		blocks = get_chunk(sb, bh);
	}
	if (bh)
		brelse(bh);
	if (count != sb_count)
		goto Ecount;
done:
	mutex_unlock(&sbi->s_lock);
	return count;

Einval:
	printk("sysv_count_free_blocks: new block %d is not in data zone\n",
		block);
	goto trust_sb;
Eio:
	printk("sysv_count_free_blocks: cannot read free-list block\n");
	goto trust_sb;
E2big:
	printk("sysv_count_free_blocks: >flc_size entries in free-list block\n");
	if (bh)
		brelse(bh);
trust_sb:
	count = sb_count;
	goto done;
Ecount:
	printk("sysv_count_free_blocks: free block count was %d, "
		"correcting to %d\n", sb_count, count);
	if (!(sb->s_flags & MS_RDONLY)) {
		*sbi->s_free_blocks = cpu_to_fs32(sbi, count);
		dirty_sb(sb);
	}
	goto done;
}
/************************************************************/
/* ../linux-3.17/fs/sysv/balloc.c */
/************************************************************/
/*
 *  linux/fs/sysv/inode.c
 *
 *  minix/inode.c
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  xenix/inode.c
 *  Copyright (C) 1992  Doug Evans
 *
 *  coh/inode.c
 *  Copyright (C) 1993  Pascal Haible, Bruno Haible
 *
 *  sysv/inode.c
 *  Copyright (C) 1993  Paul B. Monday
 *
 *  sysv/inode.c
 *  Copyright (C) 1993  Bruno Haible
 *  Copyright (C) 1997, 1998  Krzysztof G. Baranowski
 *
 *  This file contains code for allocating/freeing inodes and for read/writing
 *  the superblock.
 */

#include <linux/highuid.h>
#include <linux/slab.h>
#include <linux/init.h>
// #include <linux/buffer_head.h>
#include <linux/vfs.h>
// #include <linux/writeback.h>
#include <linux/namei.h>
#include <asm/byteorder.h>
// #include "sysv.h"

static int sysv_sync_fs(struct super_block *sb, int wait)
{
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	unsigned long time = get_seconds(), old_time;

	mutex_lock(&sbi->s_lock);

	/*
	 * If we are going to write out the super block,
	 * then attach current time stamp.
	 * But if the filesystem was marked clean, keep it clean.
	 */
	old_time = fs32_to_cpu(sbi, *sbi->s_sb_time);
	if (sbi->s_type == FSTYPE_SYSV4) {
		if (*sbi->s_sb_state == cpu_to_fs32(sbi, 0x7c269d38 - old_time))
			*sbi->s_sb_state = cpu_to_fs32(sbi, 0x7c269d38 - time);
		*sbi->s_sb_time = cpu_to_fs32(sbi, time);
		mark_buffer_dirty(sbi->s_bh2);
	}

	mutex_unlock(&sbi->s_lock);

	return 0;
}

static int sysv_remount(struct super_block *sb, int *flags, char *data)
{
	struct sysv_sb_info *sbi = SYSV_SB(sb);

	sync_filesystem(sb);
	if (sbi->s_forced_ro)
		*flags |= MS_RDONLY;
	return 0;
}

static void sysv_put_super(struct super_block *sb)
{
	struct sysv_sb_info *sbi = SYSV_SB(sb);

	if (!(sb->s_flags & MS_RDONLY)) {
		/* XXX ext2 also updates the state here */
		mark_buffer_dirty(sbi->s_bh1);
		if (sbi->s_bh1 != sbi->s_bh2)
			mark_buffer_dirty(sbi->s_bh2);
	}

	brelse(sbi->s_bh1);
	if (sbi->s_bh1 != sbi->s_bh2)
		brelse(sbi->s_bh2);

	kfree(sbi);
}

static int sysv_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type = sb->s_magic;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = sbi->s_ndatazones;
	buf->f_bavail = buf->f_bfree = sysv_count_free_blocks(sb);
	buf->f_files = sbi->s_ninodes;
	buf->f_ffree = sysv_count_free_inodes(sb);
	buf->f_namelen = SYSV_NAMELEN;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	return 0;
}

/*
 * NXI <-> N0XI for PDP, XIN <-> XIN0 for le32, NIX <-> 0NIX for be32
 */
static inline void read3byte(struct sysv_sb_info *sbi,
	unsigned char * from, unsigned char * to)
{
	if (sbi->s_bytesex == BYTESEX_PDP) {
		to[0] = from[0];
		to[1] = 0;
		to[2] = from[1];
		to[3] = from[2];
	} else if (sbi->s_bytesex == BYTESEX_LE) {
		to[0] = from[0];
		to[1] = from[1];
		to[2] = from[2];
		to[3] = 0;
	} else {
		to[0] = 0;
		to[1] = from[0];
		to[2] = from[1];
		to[3] = from[2];
	}
}

static inline void write3byte(struct sysv_sb_info *sbi,
	unsigned char * from, unsigned char * to)
{
	if (sbi->s_bytesex == BYTESEX_PDP) {
		to[0] = from[0];
		to[1] = from[2];
		to[2] = from[3];
	} else if (sbi->s_bytesex == BYTESEX_LE) {
		to[0] = from[0];
		to[1] = from[1];
		to[2] = from[2];
	} else {
		to[0] = from[1];
		to[1] = from[2];
		to[2] = from[3];
	}
}

static const struct inode_operations sysv_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.getattr	= sysv_getattr,
};

void sysv_set_inode(struct inode *inode, dev_t rdev)
{
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &sysv_file_inode_operations;
		inode->i_fop = &sysv_file_operations;
		inode->i_mapping->a_ops = &sysv_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &sysv_dir_inode_operations;
		inode->i_fop = &sysv_dir_operations;
		inode->i_mapping->a_ops = &sysv_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		if (inode->i_blocks) {
			inode->i_op = &sysv_symlink_inode_operations;
			inode->i_mapping->a_ops = &sysv_aops;
		} else {
			inode->i_op = &sysv_fast_symlink_inode_operations;
			nd_terminate_link(SYSV_I(inode)->i_data, inode->i_size,
				sizeof(SYSV_I(inode)->i_data) - 1);
		}
	} else
		init_special_inode(inode, inode->i_mode, rdev);
}

struct inode *sysv_iget(struct super_block *sb, unsigned int ino)
{
	struct sysv_sb_info * sbi = SYSV_SB(sb);
	struct buffer_head * bh;
	struct sysv_inode * raw_inode;
	struct sysv_inode_info * si;
	struct inode *inode;
	unsigned int block;

	if (!ino || ino > sbi->s_ninodes) {
		printk("Bad inode number on dev %s: %d is out of range\n",
		       sb->s_id, ino);
		return ERR_PTR(-EIO);
	}

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	raw_inode = sysv_raw_inode(sb, ino, &bh);
	if (!raw_inode) {
		printk("Major problem: unable to read inode from dev %s\n",
		       inode->i_sb->s_id);
		goto bad_inode;
	}
	/* SystemV FS: kludge permissions if ino==SYSV_ROOT_INO ?? */
	inode->i_mode = fs16_to_cpu(sbi, raw_inode->i_mode);
	i_uid_write(inode, (uid_t)fs16_to_cpu(sbi, raw_inode->i_uid));
	i_gid_write(inode, (gid_t)fs16_to_cpu(sbi, raw_inode->i_gid));
	set_nlink(inode, fs16_to_cpu(sbi, raw_inode->i_nlink));
	inode->i_size = fs32_to_cpu(sbi, raw_inode->i_size);
	inode->i_atime.tv_sec = fs32_to_cpu(sbi, raw_inode->i_atime);
	inode->i_mtime.tv_sec = fs32_to_cpu(sbi, raw_inode->i_mtime);
	inode->i_ctime.tv_sec = fs32_to_cpu(sbi, raw_inode->i_ctime);
	inode->i_ctime.tv_nsec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_blocks = 0;

	si = SYSV_I(inode);
	for (block = 0; block < 10+1+1+1; block++)
		read3byte(sbi, &raw_inode->i_data[3*block],
				(u8 *)&si->i_data[block]);
	brelse(bh);
	si->i_dir_start_lookup = 0;
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		sysv_set_inode(inode,
			       old_decode_dev(fs32_to_cpu(sbi, si->i_data[0])));
	else
		sysv_set_inode(inode, 0);
	unlock_new_inode(inode);
	return inode;

bad_inode:
	iget_failed(inode);
	return ERR_PTR(-EIO);
}

static int __sysv_write_inode(struct inode *inode, int wait)
{
	struct super_block * sb = inode->i_sb;
	struct sysv_sb_info * sbi = SYSV_SB(sb);
	struct buffer_head * bh;
	struct sysv_inode * raw_inode;
	struct sysv_inode_info * si;
	unsigned int ino, block;
	int err = 0;

	ino = inode->i_ino;
	if (!ino || ino > sbi->s_ninodes) {
		printk("Bad inode number on dev %s: %d is out of range\n",
		       inode->i_sb->s_id, ino);
		return -EIO;
	}
	raw_inode = sysv_raw_inode(sb, ino, &bh);
	if (!raw_inode) {
		printk("unable to read i-node block\n");
		return -EIO;
	}

	raw_inode->i_mode = cpu_to_fs16(sbi, inode->i_mode);
	raw_inode->i_uid = cpu_to_fs16(sbi, fs_high2lowuid(i_uid_read(inode)));
	raw_inode->i_gid = cpu_to_fs16(sbi, fs_high2lowgid(i_gid_read(inode)));
	raw_inode->i_nlink = cpu_to_fs16(sbi, inode->i_nlink);
	raw_inode->i_size = cpu_to_fs32(sbi, inode->i_size);
	raw_inode->i_atime = cpu_to_fs32(sbi, inode->i_atime.tv_sec);
	raw_inode->i_mtime = cpu_to_fs32(sbi, inode->i_mtime.tv_sec);
	raw_inode->i_ctime = cpu_to_fs32(sbi, inode->i_ctime.tv_sec);

	si = SYSV_I(inode);
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		si->i_data[0] = cpu_to_fs32(sbi, old_encode_dev(inode->i_rdev));
	for (block = 0; block < 10+1+1+1; block++)
		write3byte(sbi, (u8 *)&si->i_data[block],
			&raw_inode->i_data[3*block]);
	mark_buffer_dirty(bh);
	if (wait) {
                sync_dirty_buffer(bh);
                if (buffer_req(bh) && !buffer_uptodate(bh)) {
                        printk ("IO error syncing sysv inode [%s:%08x]\n",
                                sb->s_id, ino);
                        err = -EIO;
                }
        }
	brelse(bh);
	return 0;
}

int sysv_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return __sysv_write_inode(inode, wbc->sync_mode == WB_SYNC_ALL);
}

int sysv_sync_inode(struct inode *inode)
{
	return __sysv_write_inode(inode, 1);
}

static void sysv_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	if (!inode->i_nlink) {
		inode->i_size = 0;
		sysv_truncate(inode);
	}
	invalidate_inode_buffers(inode);
	clear_inode(inode);
	if (!inode->i_nlink)
		sysv_free_inode(inode);
}

static struct kmem_cache *sysv_inode_cachep;

static struct inode *sysv_alloc_inode(struct super_block *sb)
{
	struct sysv_inode_info *si;

	si = kmem_cache_alloc(sysv_inode_cachep, GFP_KERNEL);
	if (!si)
		return NULL;
	return &si->vfs_inode;
}

static void sysv_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(sysv_inode_cachep, SYSV_I(inode));
}

static void sysv_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, sysv_i_callback);
}

static void init_once(void *p)
{
	struct sysv_inode_info *si = (struct sysv_inode_info *)p;

	inode_init_once(&si->vfs_inode);
}

const struct super_operations sysv_sops = {
	.alloc_inode	= sysv_alloc_inode,
	.destroy_inode	= sysv_destroy_inode,
	.write_inode	= sysv_write_inode,
	.evict_inode	= sysv_evict_inode,
	.put_super	= sysv_put_super,
	.sync_fs	= sysv_sync_fs,
	.remount_fs	= sysv_remount,
	.statfs		= sysv_statfs,
};

int __init sysv_init_icache(void)
{
	sysv_inode_cachep = kmem_cache_create("sysv_inode_cache",
			sizeof(struct sysv_inode_info), 0,
			SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD,
			init_once);
	if (!sysv_inode_cachep)
		return -ENOMEM;
	return 0;
}

void sysv_destroy_icache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(sysv_inode_cachep);
}
/************************************************************/
/* ../linux-3.17/fs/sysv/inode.c */
/************************************************************/
/*
 *  linux/fs/sysv/itree.c
 *
 *  Handling of indirect blocks' trees.
 *  AV, Sep--Dec 2000
 */

// #include <linux/buffer_head.h>
#include <linux/mount.h>
// #include <linux/string.h>
// #include "sysv.h"

enum {DIRECT = 10, DEPTH = 4};	/* Have triple indirect */

static inline void dirty_indirect(struct buffer_head *bh, struct inode *inode)
{
	mark_buffer_dirty_inode(bh, inode);
	if (IS_SYNC(inode))
		sync_dirty_buffer(bh);
}

static int block_to_path(struct inode *inode, long block, int offsets[DEPTH])
{
	struct super_block *sb = inode->i_sb;
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	int ptrs_bits = sbi->s_ind_per_block_bits;
	unsigned long	indirect_blocks = sbi->s_ind_per_block,
			double_blocks = sbi->s_ind_per_block_2;
	int n = 0;

	if (block < 0) {
		printk("sysv_block_map: block < 0\n");
	} else if (block < DIRECT) {
		offsets[n++] = block;
	} else if ( (block -= DIRECT) < indirect_blocks) {
		offsets[n++] = DIRECT;
		offsets[n++] = block;
	} else if ((block -= indirect_blocks) < double_blocks) {
		offsets[n++] = DIRECT+1;
		offsets[n++] = block >> ptrs_bits;
		offsets[n++] = block & (indirect_blocks - 1);
	} else if (((block -= double_blocks) >> (ptrs_bits * 2)) < indirect_blocks) {
		offsets[n++] = DIRECT+2;
		offsets[n++] = block >> (ptrs_bits * 2);
		offsets[n++] = (block >> ptrs_bits) & (indirect_blocks - 1);
		offsets[n++] = block & (indirect_blocks - 1);
	} else {
		/* nothing */;
	}
	return n;
}

static inline int block_to_cpu(struct sysv_sb_info *sbi, sysv_zone_t nr)
{
	return sbi->s_block_base + fs32_to_cpu(sbi, nr);
}

typedef struct {
	sysv_zone_t     *p;
	sysv_zone_t     key;
	struct buffer_head *bh;
} Indirect;

static DEFINE_RWLOCK(pointers_lock);

static inline void add_chain(Indirect *p, struct buffer_head *bh, sysv_zone_t *v)
{
	p->key = *(p->p = v);
	p->bh = bh;
}

static inline int verify_chain(Indirect *from, Indirect *to)
{
	while (from <= to && from->key == *from->p)
		from++;
	return (from > to);
}

static inline sysv_zone_t *block_end(struct buffer_head *bh)
{
	return (sysv_zone_t*)((char*)bh->b_data + bh->b_size);
}

/*
 * Requires read_lock(&pointers_lock) or write_lock(&pointers_lock)
 */
static Indirect *get_branch(struct inode *inode,
			    int depth,
			    int offsets[],
			    Indirect chain[],
			    int *err)
{
	struct super_block *sb = inode->i_sb;
	Indirect *p = chain;
	struct buffer_head *bh;

	*err = 0;
	add_chain(chain, NULL, SYSV_I(inode)->i_data + *offsets);
	if (!p->key)
		goto no_block;
	while (--depth) {
		int block = block_to_cpu(SYSV_SB(sb), p->key);
		bh = sb_bread(sb, block);
		if (!bh)
			goto failure;
		if (!verify_chain(chain, p))
			goto changed;
		add_chain(++p, bh, (sysv_zone_t*)bh->b_data + *++offsets);
		if (!p->key)
			goto no_block;
	}
	return NULL;

changed:
	brelse(bh);
	*err = -EAGAIN;
	goto no_block;
failure:
	*err = -EIO;
no_block:
	return p;
}

static int alloc_branch(struct inode *inode,
			int num,
			int *offsets,
			Indirect *branch)
{
	int blocksize = inode->i_sb->s_blocksize;
	int n = 0;
	int i;

	branch[0].key = sysv_new_block(inode->i_sb);
	if (branch[0].key) for (n = 1; n < num; n++) {
		struct buffer_head *bh;
		int parent;
		/* Allocate the next block */
		branch[n].key = sysv_new_block(inode->i_sb);
		if (!branch[n].key)
			break;
		/*
		 * Get buffer_head for parent block, zero it out and set
		 * the pointer to new one, then send parent to disk.
		 */
		parent = block_to_cpu(SYSV_SB(inode->i_sb), branch[n-1].key);
		bh = sb_getblk(inode->i_sb, parent);
		lock_buffer(bh);
		memset(bh->b_data, 0, blocksize);
		branch[n].bh = bh;
		branch[n].p = (sysv_zone_t*) bh->b_data + offsets[n];
		*branch[n].p = branch[n].key;
		set_buffer_uptodate(bh);
		unlock_buffer(bh);
		dirty_indirect(bh, inode);
	}
	if (n == num)
		return 0;

	/* Allocation failed, free what we already allocated */
	for (i = 1; i < n; i++)
		bforget(branch[i].bh);
	for (i = 0; i < n; i++)
		sysv_free_block(inode->i_sb, branch[i].key);
	return -ENOSPC;
}

static inline int splice_branch(struct inode *inode,
				Indirect chain[],
				Indirect *where,
				int num)
{
	int i;

	/* Verify that place we are splicing to is still there and vacant */
	write_lock(&pointers_lock);
	if (!verify_chain(chain, where-1) || *where->p)
		goto changed;
	*where->p = where->key;
	write_unlock(&pointers_lock);

	inode->i_ctime = CURRENT_TIME_SEC;

	/* had we spliced it onto indirect block? */
	if (where->bh)
		dirty_indirect(where->bh, inode);

	if (IS_SYNC(inode))
		sysv_sync_inode(inode);
	else
		mark_inode_dirty(inode);
	return 0;

changed:
	write_unlock(&pointers_lock);
	for (i = 1; i < num; i++)
		bforget(where[i].bh);
	for (i = 0; i < num; i++)
		sysv_free_block(inode->i_sb, where[i].key);
	return -EAGAIN;
}

static int get_block(struct inode *inode, sector_t iblock, struct buffer_head *bh_result, int create)
{
	int err = -EIO;
	int offsets[DEPTH];
	Indirect chain[DEPTH];
	struct super_block *sb = inode->i_sb;
	Indirect *partial;
	int left;
	int depth = block_to_path(inode, iblock, offsets);

	if (depth == 0)
		goto out;

reread:
	read_lock(&pointers_lock);
	partial = get_branch(inode, depth, offsets, chain, &err);
	read_unlock(&pointers_lock);

	/* Simplest case - block found, no allocation needed */
	if (!partial) {
got_it:
		map_bh(bh_result, sb, block_to_cpu(SYSV_SB(sb),
					chain[depth-1].key));
		/* Clean up and exit */
		partial = chain+depth-1; /* the whole chain */
		goto cleanup;
	}

	/* Next simple case - plain lookup or failed read of indirect block */
	if (!create || err == -EIO) {
cleanup:
		while (partial > chain) {
			brelse(partial->bh);
			partial--;
		}
out:
		return err;
	}

	/*
	 * Indirect block might be removed by truncate while we were
	 * reading it. Handling of that case (forget what we've got and
	 * reread) is taken out of the main path.
	 */
	if (err == -EAGAIN)
		goto changed;

	left = (chain + depth) - partial;
	err = alloc_branch(inode, left, offsets+(partial-chain), partial);
	if (err)
		goto cleanup;

	if (splice_branch(inode, chain, partial, left) < 0)
		goto changed;

	set_buffer_new(bh_result);
	goto got_it;

changed:
	while (partial > chain) {
		brelse(partial->bh);
		partial--;
	}
	goto reread;
}

static inline int all_zeroes(sysv_zone_t *p, sysv_zone_t *q)
{
	while (p < q)
		if (*p++)
			return 0;
	return 1;
}

static Indirect *find_shared(struct inode *inode,
				int depth,
				int offsets[],
				Indirect chain[],
				sysv_zone_t *top)
{
	Indirect *partial, *p;
	int k, err;

	*top = 0;
	for (k = depth; k > 1 && !offsets[k-1]; k--)
		;

	write_lock(&pointers_lock);
	partial = get_branch(inode, k, offsets, chain, &err);
	if (!partial)
		partial = chain + k-1;
	/*
	 * If the branch acquired continuation since we've looked at it -
	 * fine, it should all survive and (new) top doesn't belong to us.
	 */
	if (!partial->key && *partial->p) {
		write_unlock(&pointers_lock);
		goto no_top;
	}
	for (p=partial; p>chain && all_zeroes((sysv_zone_t*)p->bh->b_data,p->p); p--)
		;
	/*
	 * OK, we've found the last block that must survive. The rest of our
	 * branch should be detached before unlocking. However, if that rest
	 * of branch is all ours and does not grow immediately from the inode
	 * it's easier to cheat and just decrement partial->p.
	 */
	if (p == chain + k - 1 && p > chain) {
		p->p--;
	} else {
		*top = *p->p;
		*p->p = 0;
	}
	write_unlock(&pointers_lock);

	while (partial > p) {
		brelse(partial->bh);
		partial--;
	}
no_top:
	return partial;
}

static inline void free_data(struct inode *inode, sysv_zone_t *p, sysv_zone_t *q)
{
	for ( ; p < q ; p++) {
		sysv_zone_t nr = *p;
		if (nr) {
			*p = 0;
			sysv_free_block(inode->i_sb, nr);
			mark_inode_dirty(inode);
		}
	}
}

static void free_branches(struct inode *inode, sysv_zone_t *p, sysv_zone_t *q, int depth)
{
	struct buffer_head * bh;
	struct super_block *sb = inode->i_sb;

	if (depth--) {
		for ( ; p < q ; p++) {
			int block;
			sysv_zone_t nr = *p;
			if (!nr)
				continue;
			*p = 0;
			block = block_to_cpu(SYSV_SB(sb), nr);
			bh = sb_bread(sb, block);
			if (!bh)
				continue;
			free_branches(inode, (sysv_zone_t*)bh->b_data,
					block_end(bh), depth);
			bforget(bh);
			sysv_free_block(sb, nr);
			mark_inode_dirty(inode);
		}
	} else
		free_data(inode, p, q);
}

void sysv_truncate (struct inode * inode)
{
	sysv_zone_t *i_data = SYSV_I(inode)->i_data;
	int offsets[DEPTH];
	Indirect chain[DEPTH];
	Indirect *partial;
	sysv_zone_t nr = 0;
	int n;
	long iblock;
	unsigned blocksize;

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	    S_ISLNK(inode->i_mode)))
		return;

	blocksize = inode->i_sb->s_blocksize;
	iblock = (inode->i_size + blocksize-1)
					>> inode->i_sb->s_blocksize_bits;

	block_truncate_page(inode->i_mapping, inode->i_size, get_block);

	n = block_to_path(inode, iblock, offsets);
	if (n == 0)
		return;

	if (n == 1) {
		free_data(inode, i_data+offsets[0], i_data + DIRECT);
		goto do_indirects;
	}

	partial = find_shared(inode, n, offsets, chain, &nr);
	/* Kill the top of shared branch (already detached) */
	if (nr) {
		if (partial == chain)
			mark_inode_dirty(inode);
		else
			dirty_indirect(partial->bh, inode);
		free_branches(inode, &nr, &nr+1, (chain+n-1) - partial);
	}
	/* Clear the ends of indirect blocks on the shared branch */
	while (partial > chain) {
		free_branches(inode, partial->p + 1, block_end(partial->bh),
				(chain+n-1) - partial);
		dirty_indirect(partial->bh, inode);
		brelse (partial->bh);
		partial--;
	}
do_indirects:
	/* Kill the remaining (whole) subtrees (== subtrees deeper than...) */
	while (n < DEPTH) {
		nr = i_data[DIRECT + n - 1];
		if (nr) {
			i_data[DIRECT + n - 1] = 0;
			mark_inode_dirty(inode);
			free_branches(inode, &nr, &nr+1, n);
		}
		n++;
	}
	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
	if (IS_SYNC(inode))
		sysv_sync_inode (inode);
	else
		mark_inode_dirty(inode);
}

static unsigned sysv_nblocks(struct super_block *s, loff_t size)
{
	struct sysv_sb_info *sbi = SYSV_SB(s);
	int ptrs_bits = sbi->s_ind_per_block_bits;
	unsigned blocks, res, direct = DIRECT, i = DEPTH;
	blocks = (size + s->s_blocksize - 1) >> s->s_blocksize_bits;
	res = blocks;
	while (--i && blocks > direct) {
		blocks = ((blocks - direct - 1) >> ptrs_bits) + 1;
		res += blocks;
		direct = 1;
	}
	return blocks;
}

int sysv_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct super_block *s = dentry->d_sb;
	generic_fillattr(dentry->d_inode, stat);
	stat->blocks = (s->s_blocksize / 512) * sysv_nblocks(s, stat->size);
	stat->blksize = s->s_blocksize;
	return 0;
}

static int sysv_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page,get_block,wbc);
}

static int sysv_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page,get_block);
}

int sysv_prepare_chunk(struct page *page, loff_t pos, unsigned len)
{
	return __block_write_begin(page, pos, len, get_block);
}

static void sysv_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		sysv_truncate(inode);
	}
}

static int sysv_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep, get_block);
	if (unlikely(ret))
		sysv_write_failed(mapping, pos + len);

	return ret;
}

static sector_t sysv_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,get_block);
}

const struct address_space_operations sysv_aops = {
	.readpage = sysv_readpage,
	.writepage = sysv_writepage,
	.write_begin = sysv_write_begin,
	.write_end = generic_write_end,
	.bmap = sysv_bmap
};
/************************************************************/
/* ../linux-3.17/fs/sysv/itree.c */
/************************************************************/
/*
 *  linux/fs/sysv/file.c
 *
 *  minix/file.c
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  coh/file.c
 *  Copyright (C) 1993  Pascal Haible, Bruno Haible
 *
 *  sysv/file.c
 *  Copyright (C) 1993  Bruno Haible
 *
 *  SystemV/Coherent regular file handling primitives
 */

// #include "sysv.h"

/*
 * We have mostly NULLs here: the current defaults are OK for
 * the coh filesystem.
 */
const struct file_operations sysv_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

static int sysv_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;
		truncate_setsize(inode, attr->ia_size);
		sysv_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations sysv_file_inode_operations = {
	.setattr	= sysv_setattr,
	.getattr	= sysv_getattr,
};
/************************************************************/
/* ../linux-3.17/fs/sysv/file.c */
/************************************************************/
/*
 *  linux/fs/sysv/dir.c
 *
 *  minix/dir.c
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  coh/dir.c
 *  Copyright (C) 1993  Pascal Haible, Bruno Haible
 *
 *  sysv/dir.c
 *  Copyright (C) 1993  Bruno Haible
 *
 *  SystemV/Coherent directory handling functions
 */

#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/swap.h>
// #include "sysv.h"

static int sysv_readdir(struct file *, struct dir_context *);

const struct file_operations sysv_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sysv_readdir,
	.fsync		= generic_file_fsync,
};

static inline void dir_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

static inline unsigned long dir_pages(struct inode *inode)
{
	return (inode->i_size+PAGE_CACHE_SIZE-1)>>PAGE_CACHE_SHIFT;
}

static int dir_commit_chunk(struct page *page, loff_t pos, unsigned len)
{
	struct address_space *mapping = page->mapping;
	struct inode *dir = mapping->host;
	int err = 0;

	block_write_end(NULL, mapping, pos, len, len, page, NULL);
	if (pos+len > dir->i_size) {
		i_size_write(dir, pos+len);
		mark_inode_dirty(dir);
	}
	if (IS_DIRSYNC(dir))
		err = write_one_page(page, 1);
	else
		unlock_page(page);
	return err;
}

static struct page * dir_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);
	if (!IS_ERR(page))
		kmap(page);
	return page;
}

static int sysv_readdir(struct file *file, struct dir_context *ctx)
{
	unsigned long pos = ctx->pos;
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	unsigned long npages = dir_pages(inode);
	unsigned offset;
	unsigned long n;

	ctx->pos = pos = (pos + SYSV_DIRSIZE-1) & ~(SYSV_DIRSIZE-1);
	if (pos >= inode->i_size)
		return 0;

	offset = pos & ~PAGE_CACHE_MASK;
	n = pos >> PAGE_CACHE_SHIFT;

	for ( ; n < npages; n++, offset = 0) {
		char *kaddr, *limit;
		struct sysv_dir_entry *de;
		struct page *page = dir_get_page(inode, n);

		if (IS_ERR(page))
			continue;
		kaddr = (char *)page_address(page);
		de = (struct sysv_dir_entry *)(kaddr+offset);
		limit = kaddr + PAGE_CACHE_SIZE - SYSV_DIRSIZE;
		for ( ;(char*)de <= limit; de++, ctx->pos += sizeof(*de)) {
			char *name = de->name;

			if (!de->inode)
				continue;

			if (!dir_emit(ctx, name, strnlen(name,SYSV_NAMELEN),
					fs16_to_cpu(SYSV_SB(sb), de->inode),
					DT_UNKNOWN)) {
				dir_put_page(page);
				return 0;
			}
		}
		dir_put_page(page);
	}
	return 0;
}

/* compare strings: name[0..len-1] (not zero-terminated) and
 * buffer[0..] (filled with zeroes up to buffer[0..maxlen-1])
 */
static inline int namecompare(int len, int maxlen,
	const char * name, const char * buffer)
{
	if (len < maxlen && buffer[len])
		return 0;
	return !memcmp(name, buffer, len);
}

/*
 *	sysv_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the cache buffer in which the entry was found, and the entry
 * itself (as a parameter - res_dir). It does NOT read the inode of the
 * entry - you'll have to do that yourself if you want to.
 */
struct sysv_dir_entry *sysv_find_entry(struct dentry *dentry, struct page **res_page)
{
	const char * name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct inode * dir = dentry->d_parent->d_inode;
	unsigned long start, n;
	unsigned long npages = dir_pages(dir);
	struct page *page = NULL;
	struct sysv_dir_entry *de;

	*res_page = NULL;

	start = SYSV_I(dir)->i_dir_start_lookup;
	if (start >= npages)
		start = 0;
	n = start;

	do {
		char *kaddr;
		page = dir_get_page(dir, n);
		if (!IS_ERR(page)) {
			kaddr = (char*)page_address(page);
			de = (struct sysv_dir_entry *) kaddr;
			kaddr += PAGE_CACHE_SIZE - SYSV_DIRSIZE;
			for ( ; (char *) de <= kaddr ; de++) {
				if (!de->inode)
					continue;
				if (namecompare(namelen, SYSV_NAMELEN,
							name, de->name))
					goto found;
			}
			dir_put_page(page);
		}

		if (++n >= npages)
			n = 0;
	} while (n != start);

	return NULL;

found:
	SYSV_I(dir)->i_dir_start_lookup = n;
	*res_page = page;
	return de;
}

int sysv_add_link(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = dentry->d_parent->d_inode;
	const char * name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct page *page = NULL;
	struct sysv_dir_entry * de;
	unsigned long npages = dir_pages(dir);
	unsigned long n;
	char *kaddr;
	loff_t pos;
	int err;

	/* We take care of directory expansion in the same loop */
	for (n = 0; n <= npages; n++) {
		page = dir_get_page(dir, n);
		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto out;
		kaddr = (char*)page_address(page);
		de = (struct sysv_dir_entry *)kaddr;
		kaddr += PAGE_CACHE_SIZE - SYSV_DIRSIZE;
		while ((char *)de <= kaddr) {
			if (!de->inode)
				goto got_it;
			err = -EEXIST;
			if (namecompare(namelen, SYSV_NAMELEN, name, de->name))
				goto out_page;
			de++;
		}
		dir_put_page(page);
	}
	BUG();
	return -EINVAL;

got_it:
	pos = page_offset(page) +
			(char*)de - (char*)page_address(page);
	lock_page(page);
	err = sysv_prepare_chunk(page, pos, SYSV_DIRSIZE);
	if (err)
		goto out_unlock;
	memcpy (de->name, name, namelen);
	memset (de->name + namelen, 0, SYSV_DIRSIZE - namelen - 2);
	de->inode = cpu_to_fs16(SYSV_SB(inode->i_sb), inode->i_ino);
	err = dir_commit_chunk(page, pos, SYSV_DIRSIZE);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(dir);
out_page:
	dir_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_page;
}

int sysv_delete_entry(struct sysv_dir_entry *de, struct page *page)
{
	struct inode *inode = page->mapping->host;
	char *kaddr = (char*)page_address(page);
	loff_t pos = page_offset(page) + (char *)de - kaddr;
	int err;

	lock_page(page);
	err = sysv_prepare_chunk(page, pos, SYSV_DIRSIZE);
	BUG_ON(err);
	de->inode = 0;
	err = dir_commit_chunk(page, pos, SYSV_DIRSIZE);
	dir_put_page(page);
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	mark_inode_dirty(inode);
	return err;
}

int sysv_make_empty(struct inode *inode, struct inode *dir)
{
	struct page *page = grab_cache_page(inode->i_mapping, 0);
	struct sysv_dir_entry * de;
	char *base;
	int err;

	if (!page)
		return -ENOMEM;
	err = sysv_prepare_chunk(page, 0, 2 * SYSV_DIRSIZE);
	if (err) {
		unlock_page(page);
		goto fail;
	}
	kmap(page);

	base = (char*)page_address(page);
	memset(base, 0, PAGE_CACHE_SIZE);

	de = (struct sysv_dir_entry *) base;
	de->inode = cpu_to_fs16(SYSV_SB(inode->i_sb), inode->i_ino);
	strcpy(de->name,".");
	de++;
	de->inode = cpu_to_fs16(SYSV_SB(inode->i_sb), dir->i_ino);
	strcpy(de->name,"..");

	kunmap(page);
	err = dir_commit_chunk(page, 0, 2 * SYSV_DIRSIZE);
fail:
	page_cache_release(page);
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
int sysv_empty_dir(struct inode * inode)
{
	struct super_block *sb = inode->i_sb;
	struct page *page = NULL;
	unsigned long i, npages = dir_pages(inode);

	for (i = 0; i < npages; i++) {
		char *kaddr;
		struct sysv_dir_entry * de;
		page = dir_get_page(inode, i);

		if (IS_ERR(page))
			continue;

		kaddr = (char *)page_address(page);
		de = (struct sysv_dir_entry *)kaddr;
		kaddr += PAGE_CACHE_SIZE-SYSV_DIRSIZE;

		for ( ;(char *)de <= kaddr; de++) {
			if (!de->inode)
				continue;
			/* check for . and .. */
			if (de->name[0] != '.')
				goto not_empty;
			if (!de->name[1]) {
				if (de->inode == cpu_to_fs16(SYSV_SB(sb),
							inode->i_ino))
					continue;
				goto not_empty;
			}
			if (de->name[1] != '.' || de->name[2])
				goto not_empty;
		}
		dir_put_page(page);
	}
	return 1;

not_empty:
	dir_put_page(page);
	return 0;
}

/* Releases the page */
void sysv_set_link(struct sysv_dir_entry *de, struct page *page,
	struct inode *inode)
{
	struct inode *dir = page->mapping->host;
	loff_t pos = page_offset(page) +
			(char *)de-(char*)page_address(page);
	int err;

	lock_page(page);
	err = sysv_prepare_chunk(page, pos, SYSV_DIRSIZE);
	BUG_ON(err);
	de->inode = cpu_to_fs16(SYSV_SB(inode->i_sb), inode->i_ino);
	err = dir_commit_chunk(page, pos, SYSV_DIRSIZE);
	dir_put_page(page);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(dir);
}

struct sysv_dir_entry * sysv_dotdot (struct inode *dir, struct page **p)
{
	struct page *page = dir_get_page(dir, 0);
	struct sysv_dir_entry *de = NULL;

	if (!IS_ERR(page)) {
		de = (struct sysv_dir_entry*) page_address(page) + 1;
		*p = page;
	}
	return de;
}

ino_t sysv_inode_by_name(struct dentry *dentry)
{
	struct page *page;
	struct sysv_dir_entry *de = sysv_find_entry (dentry, &page);
	ino_t res = 0;

	if (de) {
		res = fs16_to_cpu(SYSV_SB(dentry->d_sb), de->inode);
		dir_put_page(page);
	}
	return res;
}
/************************************************************/
/* ../linux-3.17/fs/sysv/dir.c */
/************************************************************/
/*
 *  linux/fs/sysv/namei.c
 *
 *  minix/namei.c
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  coh/namei.c
 *  Copyright (C) 1993  Pascal Haible, Bruno Haible
 *
 *  sysv/namei.c
 *  Copyright (C) 1993  Bruno Haible
 *  Copyright (C) 1997, 1998  Krzysztof G. Baranowski
 */

// #include <linux/pagemap.h>
// #include "sysv.h"

static int add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err = sysv_add_link(dentry, inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(inode);
	return err;
}

static int sysv_hash(const struct dentry *dentry, struct qstr *qstr)
{
	/* Truncate the name in place, avoids having to define a compare
	   function. */
	if (qstr->len > SYSV_NAMELEN) {
		qstr->len = SYSV_NAMELEN;
		qstr->hash = full_name_hash(qstr->name, qstr->len);
	}
	return 0;
}

const struct dentry_operations sysv_dentry_operations = {
	.d_hash		= sysv_hash,
};

static struct dentry *sysv_lookup(struct inode * dir, struct dentry * dentry, unsigned int flags)
{
	struct inode * inode = NULL;
	ino_t ino;

	if (dentry->d_name.len > SYSV_NAMELEN)
		return ERR_PTR(-ENAMETOOLONG);
	ino = sysv_inode_by_name(dentry);

	if (ino) {
		inode = sysv_iget(dir->i_sb, ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}
	d_add(dentry, inode);
	return NULL;
}

static int sysv_mknod(struct inode * dir, struct dentry * dentry, umode_t mode, dev_t rdev)
{
	struct inode * inode;
	int err;

	if (!old_valid_dev(rdev))
		return -EINVAL;

	inode = sysv_new_inode(dir, mode);
	err = PTR_ERR(inode);

	if (!IS_ERR(inode)) {
		sysv_set_inode(inode, rdev);
		mark_inode_dirty(inode);
		err = add_nondir(dentry, inode);
	}
	return err;
}

static int sysv_create(struct inode * dir, struct dentry * dentry, umode_t mode, bool excl)
{
	return sysv_mknod(dir, dentry, mode, 0);
}

static int sysv_symlink(struct inode * dir, struct dentry * dentry,
	const char * symname)
{
	int err = -ENAMETOOLONG;
	int l = strlen(symname)+1;
	struct inode * inode;

	if (l > dir->i_sb->s_blocksize)
		goto out;

	inode = sysv_new_inode(dir, S_IFLNK|0777);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

	sysv_set_inode(inode, 0);
	err = page_symlink(inode, symname, l);
	if (err)
		goto out_fail;

	mark_inode_dirty(inode);
	err = add_nondir(dentry, inode);
out:
	return err;

out_fail:
	inode_dec_link_count(inode);
	iput(inode);
	goto out;
}

static int sysv_link(struct dentry * old_dentry, struct inode * dir,
	struct dentry * dentry)
{
	struct inode *inode = old_dentry->d_inode;

	inode->i_ctime = CURRENT_TIME_SEC;
	inode_inc_link_count(inode);
	ihold(inode);

	return add_nondir(dentry, inode);
}

static int sysv_mkdir(struct inode * dir, struct dentry *dentry, umode_t mode)
{
	struct inode * inode;
	int err;

	inode_inc_link_count(dir);

	inode = sysv_new_inode(dir, S_IFDIR|mode);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	sysv_set_inode(inode, 0);

	inode_inc_link_count(inode);

	err = sysv_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = sysv_add_link(dentry, inode);
	if (err)
		goto out_fail;

        d_instantiate(dentry, inode);
out:
	return err;

out_fail:
	inode_dec_link_count(inode);
	inode_dec_link_count(inode);
	iput(inode);
out_dir:
	inode_dec_link_count(dir);
	goto out;
}

static int sysv_unlink(struct inode * dir, struct dentry * dentry)
{
	struct inode * inode = dentry->d_inode;
	struct page * page;
	struct sysv_dir_entry * de;
	int err = -ENOENT;

	de = sysv_find_entry(dentry, &page);
	if (!de)
		goto out;

	err = sysv_delete_entry (de, page);
	if (err)
		goto out;

	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);
out:
	return err;
}

static int sysv_rmdir(struct inode * dir, struct dentry * dentry)
{
	struct inode *inode = dentry->d_inode;
	int err = -ENOTEMPTY;

	if (sysv_empty_dir(inode)) {
		err = sysv_unlink(dir, dentry);
		if (!err) {
			inode->i_size = 0;
			inode_dec_link_count(inode);
			inode_dec_link_count(dir);
		}
	}
	return err;
}

/*
 * Anybody can rename anything with this: the permission checks are left to the
 * higher-level routines.
 */
static int sysv_rename(struct inode * old_dir, struct dentry * old_dentry,
		  struct inode * new_dir, struct dentry * new_dentry)
{
	struct inode * old_inode = old_dentry->d_inode;
	struct inode * new_inode = new_dentry->d_inode;
	struct page * dir_page = NULL;
	struct sysv_dir_entry * dir_de = NULL;
	struct page * old_page;
	struct sysv_dir_entry * old_de;
	int err = -ENOENT;

	old_de = sysv_find_entry(old_dentry, &old_page);
	if (!old_de)
		goto out;

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_de = sysv_dotdot(old_inode, &dir_page);
		if (!dir_de)
			goto out_old;
	}

	if (new_inode) {
		struct page * new_page;
		struct sysv_dir_entry * new_de;

		err = -ENOTEMPTY;
		if (dir_de && !sysv_empty_dir(new_inode))
			goto out_dir;

		err = -ENOENT;
		new_de = sysv_find_entry(new_dentry, &new_page);
		if (!new_de)
			goto out_dir;
		sysv_set_link(new_de, new_page, old_inode);
		new_inode->i_ctime = CURRENT_TIME_SEC;
		if (dir_de)
			drop_nlink(new_inode);
		inode_dec_link_count(new_inode);
	} else {
		err = sysv_add_link(new_dentry, old_inode);
		if (err)
			goto out_dir;
		if (dir_de)
			inode_inc_link_count(new_dir);
	}

	sysv_delete_entry(old_de, old_page);
	mark_inode_dirty(old_inode);

	if (dir_de) {
		sysv_set_link(dir_de, dir_page, new_dir);
		inode_dec_link_count(old_dir);
	}
	return 0;

out_dir:
	if (dir_de) {
		kunmap(dir_page);
		page_cache_release(dir_page);
	}
out_old:
	kunmap(old_page);
	page_cache_release(old_page);
out:
	return err;
}

/*
 * directories can handle most operations...
 */
const struct inode_operations sysv_dir_inode_operations = {
	.create		= sysv_create,
	.lookup		= sysv_lookup,
	.link		= sysv_link,
	.unlink		= sysv_unlink,
	.symlink	= sysv_symlink,
	.mkdir		= sysv_mkdir,
	.rmdir		= sysv_rmdir,
	.mknod		= sysv_mknod,
	.rename		= sysv_rename,
	.getattr	= sysv_getattr,
};
/************************************************************/
/* ../linux-3.17/fs/sysv/namei.c */
/************************************************************/
/*
 *  linux/fs/sysv/inode.c
 *
 *  minix/inode.c
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  xenix/inode.c
 *  Copyright (C) 1992  Doug Evans
 *
 *  coh/inode.c
 *  Copyright (C) 1993  Pascal Haible, Bruno Haible
 *
 *  sysv/inode.c
 *  Copyright (C) 1993  Paul B. Monday
 *
 *  sysv/inode.c
 *  Copyright (C) 1993  Bruno Haible
 *  Copyright (C) 1997, 1998  Krzysztof G. Baranowski
 *
 *  This file contains code for read/parsing the superblock.
 */

#include <linux/module.h>
// #include <linux/init.h>
// #include <linux/slab.h>
// #include <linux/buffer_head.h>
// #include "sysv.h"

/*
 * The following functions try to recognize specific filesystems.
 *
 * We recognize:
 * - Xenix FS by its magic number.
 * - SystemV FS by its magic number.
 * - Coherent FS by its funny fname/fpack field.
 * - SCO AFS by s_nfree == 0xffff
 * - V7 FS has no distinguishing features.
 *
 * We discriminate among SystemV4 and SystemV2 FS by the assumption that
 * the time stamp is not < 01-01-1980.
 */

enum {
	JAN_1_1980 = (10*365 + 2) * 24 * 60 * 60
};

static void detected_xenix(struct sysv_sb_info *sbi, unsigned *max_links)
{
	struct buffer_head *bh1 = sbi->s_bh1;
	struct buffer_head *bh2 = sbi->s_bh2;
	struct xenix_super_block * sbd1;
	struct xenix_super_block * sbd2;

	if (bh1 != bh2)
		sbd1 = sbd2 = (struct xenix_super_block *) bh1->b_data;
	else {
		/* block size = 512, so bh1 != bh2 */
		sbd1 = (struct xenix_super_block *) bh1->b_data;
		sbd2 = (struct xenix_super_block *) (bh2->b_data - 512);
	}

	*max_links = XENIX_LINK_MAX;
	sbi->s_fic_size = XENIX_NICINOD;
	sbi->s_flc_size = XENIX_NICFREE;
	sbi->s_sbd1 = (char *)sbd1;
	sbi->s_sbd2 = (char *)sbd2;
	sbi->s_sb_fic_count = &sbd1->s_ninode;
	sbi->s_sb_fic_inodes = &sbd1->s_inode[0];
	sbi->s_sb_total_free_inodes = &sbd2->s_tinode;
	sbi->s_bcache_count = &sbd1->s_nfree;
	sbi->s_bcache = &sbd1->s_free[0];
	sbi->s_free_blocks = &sbd2->s_tfree;
	sbi->s_sb_time = &sbd2->s_time;
	sbi->s_firstdatazone = fs16_to_cpu(sbi, sbd1->s_isize);
	sbi->s_nzones = fs32_to_cpu(sbi, sbd1->s_fsize);
}

static void detected_sysv4(struct sysv_sb_info *sbi, unsigned *max_links)
{
	struct sysv4_super_block * sbd;
	struct buffer_head *bh1 = sbi->s_bh1;
	struct buffer_head *bh2 = sbi->s_bh2;

	if (bh1 == bh2)
		sbd = (struct sysv4_super_block *) (bh1->b_data + BLOCK_SIZE/2);
	else
		sbd = (struct sysv4_super_block *) bh2->b_data;

	*max_links = SYSV_LINK_MAX;
	sbi->s_fic_size = SYSV_NICINOD;
	sbi->s_flc_size = SYSV_NICFREE;
	sbi->s_sbd1 = (char *)sbd;
	sbi->s_sbd2 = (char *)sbd;
	sbi->s_sb_fic_count = &sbd->s_ninode;
	sbi->s_sb_fic_inodes = &sbd->s_inode[0];
	sbi->s_sb_total_free_inodes = &sbd->s_tinode;
	sbi->s_bcache_count = &sbd->s_nfree;
	sbi->s_bcache = &sbd->s_free[0];
	sbi->s_free_blocks = &sbd->s_tfree;
	sbi->s_sb_time = &sbd->s_time;
	sbi->s_sb_state = &sbd->s_state;
	sbi->s_firstdatazone = fs16_to_cpu(sbi, sbd->s_isize);
	sbi->s_nzones = fs32_to_cpu(sbi, sbd->s_fsize);
}

static void detected_sysv2(struct sysv_sb_info *sbi, unsigned *max_links)
{
	struct sysv2_super_block *sbd;
	struct buffer_head *bh1 = sbi->s_bh1;
	struct buffer_head *bh2 = sbi->s_bh2;

	if (bh1 == bh2)
		sbd = (struct sysv2_super_block *) (bh1->b_data + BLOCK_SIZE/2);
	else
		sbd = (struct sysv2_super_block *) bh2->b_data;

	*max_links = SYSV_LINK_MAX;
	sbi->s_fic_size = SYSV_NICINOD;
	sbi->s_flc_size = SYSV_NICFREE;
	sbi->s_sbd1 = (char *)sbd;
	sbi->s_sbd2 = (char *)sbd;
	sbi->s_sb_fic_count = &sbd->s_ninode;
	sbi->s_sb_fic_inodes = &sbd->s_inode[0];
	sbi->s_sb_total_free_inodes = &sbd->s_tinode;
	sbi->s_bcache_count = &sbd->s_nfree;
	sbi->s_bcache = &sbd->s_free[0];
	sbi->s_free_blocks = &sbd->s_tfree;
	sbi->s_sb_time = &sbd->s_time;
	sbi->s_sb_state = &sbd->s_state;
	sbi->s_firstdatazone = fs16_to_cpu(sbi, sbd->s_isize);
	sbi->s_nzones = fs32_to_cpu(sbi, sbd->s_fsize);
}

static void detected_coherent(struct sysv_sb_info *sbi, unsigned *max_links)
{
	struct coh_super_block * sbd;
	struct buffer_head *bh1 = sbi->s_bh1;

	sbd = (struct coh_super_block *) bh1->b_data;

	*max_links = COH_LINK_MAX;
	sbi->s_fic_size = COH_NICINOD;
	sbi->s_flc_size = COH_NICFREE;
	sbi->s_sbd1 = (char *)sbd;
	sbi->s_sbd2 = (char *)sbd;
	sbi->s_sb_fic_count = &sbd->s_ninode;
	sbi->s_sb_fic_inodes = &sbd->s_inode[0];
	sbi->s_sb_total_free_inodes = &sbd->s_tinode;
	sbi->s_bcache_count = &sbd->s_nfree;
	sbi->s_bcache = &sbd->s_free[0];
	sbi->s_free_blocks = &sbd->s_tfree;
	sbi->s_sb_time = &sbd->s_time;
	sbi->s_firstdatazone = fs16_to_cpu(sbi, sbd->s_isize);
	sbi->s_nzones = fs32_to_cpu(sbi, sbd->s_fsize);
}

static void detected_v7(struct sysv_sb_info *sbi, unsigned *max_links)
{
	struct buffer_head *bh2 = sbi->s_bh2;
	struct v7_super_block *sbd = (struct v7_super_block *)bh2->b_data;

	*max_links = V7_LINK_MAX;
	sbi->s_fic_size = V7_NICINOD;
	sbi->s_flc_size = V7_NICFREE;
	sbi->s_sbd1 = (char *)sbd;
	sbi->s_sbd2 = (char *)sbd;
	sbi->s_sb_fic_count = &sbd->s_ninode;
	sbi->s_sb_fic_inodes = &sbd->s_inode[0];
	sbi->s_sb_total_free_inodes = &sbd->s_tinode;
	sbi->s_bcache_count = &sbd->s_nfree;
	sbi->s_bcache = &sbd->s_free[0];
	sbi->s_free_blocks = &sbd->s_tfree;
	sbi->s_sb_time = &sbd->s_time;
	sbi->s_firstdatazone = fs16_to_cpu(sbi, sbd->s_isize);
	sbi->s_nzones = fs32_to_cpu(sbi, sbd->s_fsize);
}

static int detect_xenix(struct sysv_sb_info *sbi, struct buffer_head *bh)
{
	struct xenix_super_block *sbd = (struct xenix_super_block *)bh->b_data;
	if (*(__le32 *)&sbd->s_magic == cpu_to_le32(0x2b5544))
		sbi->s_bytesex = BYTESEX_LE;
	else if (*(__be32 *)&sbd->s_magic == cpu_to_be32(0x2b5544))
		sbi->s_bytesex = BYTESEX_BE;
	else
		return 0;
	switch (fs32_to_cpu(sbi, sbd->s_type)) {
	case 1:
		sbi->s_type = FSTYPE_XENIX;
		return 1;
	case 2:
		sbi->s_type = FSTYPE_XENIX;
		return 2;
	default:
		return 0;
	}
}

static int detect_sysv(struct sysv_sb_info *sbi, struct buffer_head *bh)
{
	struct super_block *sb = sbi->s_sb;
	/* All relevant fields are at the same offsets in R2 and R4 */
	struct sysv4_super_block * sbd;
	u32 type;

	sbd = (struct sysv4_super_block *) (bh->b_data + BLOCK_SIZE/2);
	if (*(__le32 *)&sbd->s_magic == cpu_to_le32(0xfd187e20))
		sbi->s_bytesex = BYTESEX_LE;
	else if (*(__be32 *)&sbd->s_magic == cpu_to_be32(0xfd187e20))
		sbi->s_bytesex = BYTESEX_BE;
	else
		return 0;

	type = fs32_to_cpu(sbi, sbd->s_type);

 	if (fs16_to_cpu(sbi, sbd->s_nfree) == 0xffff) {
 		sbi->s_type = FSTYPE_AFS;
		sbi->s_forced_ro = 1;
 		if (!(sb->s_flags & MS_RDONLY)) {
 			printk("SysV FS: SCO EAFS on %s detected, "
 				"forcing read-only mode.\n",
 				sb->s_id);
 		}
 		return type;
 	}

	if (fs32_to_cpu(sbi, sbd->s_time) < JAN_1_1980) {
		/* this is likely to happen on SystemV2 FS */
		if (type > 3 || type < 1)
			return 0;
		sbi->s_type = FSTYPE_SYSV2;
		return type;
	}
	if ((type > 3 || type < 1) && (type > 0x30 || type < 0x10))
		return 0;

	/* On Interactive Unix (ISC) Version 4.0/3.x s_type field = 0x10,
	   0x20 or 0x30 indicates that symbolic links and the 14-character
	   filename limit is gone. Due to lack of information about this
           feature read-only mode seems to be a reasonable approach... -KGB */

	if (type >= 0x10) {
		printk("SysV FS: can't handle long file names on %s, "
		       "forcing read-only mode.\n", sb->s_id);
		sbi->s_forced_ro = 1;
	}

	sbi->s_type = FSTYPE_SYSV4;
	return type >= 0x10 ? type >> 4 : type;
}

static int detect_coherent(struct sysv_sb_info *sbi, struct buffer_head *bh)
{
	struct coh_super_block * sbd;

	sbd = (struct coh_super_block *) (bh->b_data + BLOCK_SIZE/2);
	if ((memcmp(sbd->s_fname,"noname",6) && memcmp(sbd->s_fname,"xxxxx ",6))
	    || (memcmp(sbd->s_fpack,"nopack",6) && memcmp(sbd->s_fpack,"xxxxx\n",6)))
		return 0;
	sbi->s_bytesex = BYTESEX_PDP;
	sbi->s_type = FSTYPE_COH;
	return 1;
}

static int detect_sysv_odd(struct sysv_sb_info *sbi, struct buffer_head *bh)
{
	int size = detect_sysv(sbi, bh);

	return size>2 ? 0 : size;
}

static struct {
	int block;
	int (*test)(struct sysv_sb_info *, struct buffer_head *);
} flavours[] = {
	{1, detect_xenix},
	{0, detect_sysv},
	{0, detect_coherent},
	{9, detect_sysv_odd},
	{15,detect_sysv_odd},
	{18,detect_sysv},
};

static char *flavour_names[] = {
	[FSTYPE_XENIX]	= "Xenix",
	[FSTYPE_SYSV4]	= "SystemV",
	[FSTYPE_SYSV2]	= "SystemV Release 2",
	[FSTYPE_COH]	= "Coherent",
	[FSTYPE_V7]	= "V7",
	[FSTYPE_AFS]	= "AFS",
};

static void (*flavour_setup[])(struct sysv_sb_info *, unsigned *) = {
	[FSTYPE_XENIX]	= detected_xenix,
	[FSTYPE_SYSV4]	= detected_sysv4,
	[FSTYPE_SYSV2]	= detected_sysv2,
	[FSTYPE_COH]	= detected_coherent,
	[FSTYPE_V7]	= detected_v7,
	[FSTYPE_AFS]	= detected_sysv4,
};

static int complete_read_super(struct super_block *sb, int silent, int size)
{
	struct sysv_sb_info *sbi = SYSV_SB(sb);
	struct inode *root_inode;
	char *found = flavour_names[sbi->s_type];
	u_char n_bits = size+8;
	int bsize = 1 << n_bits;
	int bsize_4 = bsize >> 2;

	sbi->s_firstinodezone = 2;

	flavour_setup[sbi->s_type](sbi, &sb->s_max_links);

	sbi->s_truncate = 1;
	sbi->s_ndatazones = sbi->s_nzones - sbi->s_firstdatazone;
	sbi->s_inodes_per_block = bsize >> 6;
	sbi->s_inodes_per_block_1 = (bsize >> 6)-1;
	sbi->s_inodes_per_block_bits = n_bits-6;
	sbi->s_ind_per_block = bsize_4;
	sbi->s_ind_per_block_2 = bsize_4*bsize_4;
	sbi->s_toobig_block = 10 + bsize_4 * (1 + bsize_4 * (1 + bsize_4));
	sbi->s_ind_per_block_bits = n_bits-2;

	sbi->s_ninodes = (sbi->s_firstdatazone - sbi->s_firstinodezone)
		<< sbi->s_inodes_per_block_bits;

	if (!silent)
		printk("VFS: Found a %s FS (block size = %ld) on device %s\n",
		       found, sb->s_blocksize, sb->s_id);

	sb->s_magic = SYSV_MAGIC_BASE + sbi->s_type;
	/* set up enough so that it can read an inode */
	sb->s_op = &sysv_sops;
	if (sbi->s_forced_ro)
		sb->s_flags |= MS_RDONLY;
	if (sbi->s_truncate)
		sb->s_d_op = &sysv_dentry_operations;
	root_inode = sysv_iget(sb, SYSV_ROOT_INO);
	if (IS_ERR(root_inode)) {
		printk("SysV FS: get root inode failed\n");
		return 0;
	}
	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		printk("SysV FS: get root dentry failed\n");
		return 0;
	}
	return 1;
}

static int sysv_fill_super(struct super_block *sb, void *data, int silent)
{
	struct buffer_head *bh1, *bh = NULL;
	struct sysv_sb_info *sbi;
	unsigned long blocknr;
	int size = 0, i;

	BUILD_BUG_ON(1024 != sizeof (struct xenix_super_block));
	BUILD_BUG_ON(512 != sizeof (struct sysv4_super_block));
	BUILD_BUG_ON(512 != sizeof (struct sysv2_super_block));
	BUILD_BUG_ON(500 != sizeof (struct coh_super_block));
	BUILD_BUG_ON(64 != sizeof (struct sysv_inode));

	sbi = kzalloc(sizeof(struct sysv_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->s_sb = sb;
	sbi->s_block_base = 0;
	mutex_init(&sbi->s_lock);
	sb->s_fs_info = sbi;

	sb_set_blocksize(sb, BLOCK_SIZE);

	for (i = 0; i < ARRAY_SIZE(flavours) && !size; i++) {
		brelse(bh);
		bh = sb_bread(sb, flavours[i].block);
		if (!bh)
			continue;
		size = flavours[i].test(SYSV_SB(sb), bh);
	}

	if (!size)
		goto Eunknown;

	switch (size) {
		case 1:
			blocknr = bh->b_blocknr << 1;
			brelse(bh);
			sb_set_blocksize(sb, 512);
			bh1 = sb_bread(sb, blocknr);
			bh = sb_bread(sb, blocknr + 1);
			break;
		case 2:
			bh1 = bh;
			break;
		case 3:
			blocknr = bh->b_blocknr >> 1;
			brelse(bh);
			sb_set_blocksize(sb, 2048);
			bh1 = bh = sb_bread(sb, blocknr);
			break;
		default:
			goto Ebadsize;
	}

	if (bh && bh1) {
		sbi->s_bh1 = bh1;
		sbi->s_bh2 = bh;
		if (complete_read_super(sb, silent, size))
			return 0;
	}

	brelse(bh1);
	brelse(bh);
	sb_set_blocksize(sb, BLOCK_SIZE);
	printk("oldfs: cannot read superblock\n");
failed:
	kfree(sbi);
	return -EINVAL;

Eunknown:
	brelse(bh);
	if (!silent)
		printk("VFS: unable to find oldfs superblock on device %s\n",
			sb->s_id);
	goto failed;
Ebadsize:
	brelse(bh);
	if (!silent)
		printk("VFS: oldfs: unsupported block size (%dKb)\n",
			1<<(size-2));
	goto failed;
}

static int v7_sanity_check(struct super_block *sb, struct buffer_head *bh)
{
	struct v7_super_block *v7sb;
	struct sysv_inode *v7i;
	struct buffer_head *bh2;
	struct sysv_sb_info *sbi;

	sbi = sb->s_fs_info;

	/* plausibility check on superblock */
	v7sb = (struct v7_super_block *) bh->b_data;
	if (fs16_to_cpu(sbi, v7sb->s_nfree) > V7_NICFREE ||
	    fs16_to_cpu(sbi, v7sb->s_ninode) > V7_NICINOD ||
	    fs32_to_cpu(sbi, v7sb->s_fsize) > V7_MAXSIZE)
		return 0;

	/* plausibility check on root inode: it is a directory,
	   with a nonzero size that is a multiple of 16 */
	bh2 = sb_bread(sb, 2);
	if (bh2 == NULL)
		return 0;

	v7i = (struct sysv_inode *)(bh2->b_data + 64);
	if ((fs16_to_cpu(sbi, v7i->i_mode) & ~0777) != S_IFDIR ||
	    (fs32_to_cpu(sbi, v7i->i_size) == 0) ||
	    (fs32_to_cpu(sbi, v7i->i_size) & 017) ||
	    (fs32_to_cpu(sbi, v7i->i_size) > V7_NFILES *
	     sizeof(struct sysv_dir_entry))) {
		brelse(bh2);
		return 0;
	}

	brelse(bh2);
	return 1;
}

static int v7_fill_super(struct super_block *sb, void *data, int silent)
{
	struct sysv_sb_info *sbi;
	struct buffer_head *bh;

	if (440 != sizeof (struct v7_super_block))
		panic("V7 FS: bad super-block size");
	if (64 != sizeof (struct sysv_inode))
		panic("sysv fs: bad i-node size");

	sbi = kzalloc(sizeof(struct sysv_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->s_sb = sb;
	sbi->s_block_base = 0;
	sbi->s_type = FSTYPE_V7;
	mutex_init(&sbi->s_lock);
	sb->s_fs_info = sbi;

	sb_set_blocksize(sb, 512);

	if ((bh = sb_bread(sb, 1)) == NULL) {
		if (!silent)
			printk("VFS: unable to read V7 FS superblock on "
			       "device %s.\n", sb->s_id);
		goto failed;
	}

	/* Try PDP-11 UNIX */
	sbi->s_bytesex = BYTESEX_PDP;
	if (v7_sanity_check(sb, bh))
		goto detected;

	/* Try PC/IX, v7/x86 */
	sbi->s_bytesex = BYTESEX_LE;
	if (v7_sanity_check(sb, bh))
		goto detected;

	goto failed;

detected:
	sbi->s_bh1 = bh;
	sbi->s_bh2 = bh;
	if (complete_read_super(sb, silent, 1))
		return 0;

failed:
	printk(KERN_ERR "VFS: could not find a valid V7 on %s.\n",
		sb->s_id);
	brelse(bh);
	kfree(sbi);
	return -EINVAL;
}

/* Every kernel module contains stuff like this. */

static struct dentry *sysv_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, sysv_fill_super);
}

static struct dentry *v7_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, v7_fill_super);
}

static struct file_system_type sysv_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "sysv",
	.mount		= sysv_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("sysv");

static struct file_system_type v7_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "v7",
	.mount		= v7_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("v7");
MODULE_ALIAS("v7");

static int __init init_sysv_fs(void)
{
	int error;

	error = sysv_init_icache();
	if (error)
		goto out;
	error = register_filesystem(&sysv_fs_type);
	if (error)
		goto destroy_icache;
	error = register_filesystem(&v7_fs_type);
	if (error)
		goto unregister;
	return 0;

unregister:
	unregister_filesystem(&sysv_fs_type);
destroy_icache:
	sysv_destroy_icache();
out:
	return error;
}

static void __exit exit_sysv_fs(void)
{
	unregister_filesystem(&sysv_fs_type);
	unregister_filesystem(&v7_fs_type);
	sysv_destroy_icache();
}

module_init(init_sysv_fs)
module_exit(exit_sysv_fs)
MODULE_LICENSE("GPL");
/************************************************************/
/* ../linux-3.17/fs/sysv/super.c */
/************************************************************/
/*
 *  linux/fs/sysv/symlink.c
 *
 *  Handling of System V filesystem fast symlinks extensions.
 *  Aug 2001, Christoph Hellwig (hch@infradead.org)
 */

// #include "sysv.h"
// #include <linux/namei.h>

static void *sysv_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, (char *)SYSV_I(dentry->d_inode)->i_data);
	return NULL;
}

const struct inode_operations sysv_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= sysv_follow_link,
};
/************************************************************/
/* ../linux-3.17/fs/sysv/symlink.c */
/************************************************************/
