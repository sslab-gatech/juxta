#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <asm/div64.h>
#include "omfs.h"
#include "../../inc/__fss.h"

unsigned long omfs_count_free(struct super_block *sb)
{
	unsigned int i;
	unsigned long sum = 0;
	struct omfs_sb_info *sbi = OMFS_SB(sb);
	int nbits = sb->s_blocksize * 8;

	for (i = 0; i < sbi->s_imap_size; i++)
		sum += nbits - bitmap_weight(sbi->s_imap[i], nbits);

	return sum;
}

/*
 *  Counts the run of zero bits starting at bit up to max.
 *  It handles the case where a run might spill over a buffer.
 *  Called with bitmap lock.
 */
static int count_run(unsigned long **addr, int nbits,
		int addrlen, int bit, int max)
{
	int count = 0;
	int x;

	for (; addrlen > 0; addrlen--, addr++) {
		x = find_next_bit(*addr, nbits, bit);
		count += x - bit;

		if (x < nbits || count > max)
			return min(count, max);

		bit = 0;
	}
	return min(count, max);
}

/*
 * Sets or clears the run of count bits starting with bit.
 * Called with bitmap lock.
 */
static int set_run(struct super_block *sb, int map,
		int nbits, int bit, int count, int set)
{
	int i;
	int err;
	struct buffer_head *bh;
	struct omfs_sb_info *sbi = OMFS_SB(sb);

 	err = -ENOMEM;
	bh = sb_bread(sb, clus_to_blk(sbi, sbi->s_bitmap_ino) + map);
	if (!bh)
		goto out;

	for (i = 0; i < count; i++, bit++) {
		if (bit >= nbits) {
			bit = 0;
			map++;

			mark_buffer_dirty(bh);
			brelse(bh);
			bh = sb_bread(sb,
				clus_to_blk(sbi, sbi->s_bitmap_ino) + map);
			if (!bh)
				goto out;
		}
		if (set) {
			set_bit(bit, sbi->s_imap[map]);
			set_bit(bit, (unsigned long *)bh->b_data);
		} else {
			clear_bit(bit, sbi->s_imap[map]);
			clear_bit(bit, (unsigned long *)bh->b_data);
		}
	}
	mark_buffer_dirty(bh);
	brelse(bh);
	err = 0;
out:
	return err;
}

/*
 * Tries to allocate exactly one block.  Returns true if successful.
 */
int omfs_allocate_block(struct super_block *sb, u64 block)
{
	struct buffer_head *bh;
	struct omfs_sb_info *sbi = OMFS_SB(sb);
	int bits_per_entry = 8 * sb->s_blocksize;
	unsigned int map, bit;
	int ret = 0;
	u64 tmp;

	tmp = block;
	bit = do_div(tmp, bits_per_entry);
	map = tmp;

	mutex_lock(&sbi->s_bitmap_lock);
	if (map >= sbi->s_imap_size || test_and_set_bit(bit, sbi->s_imap[map]))
		goto out;

	if (sbi->s_bitmap_ino > 0) {
		bh = sb_bread(sb, clus_to_blk(sbi, sbi->s_bitmap_ino) + map);
		if (!bh)
			goto out;

		set_bit(bit, (unsigned long *)bh->b_data);
		mark_buffer_dirty(bh);
		brelse(bh);
	}
	ret = 1;
out:
	mutex_unlock(&sbi->s_bitmap_lock);
	return ret;
}


/*
 *  Tries to allocate a set of blocks.	The request size depends on the
 *  type: for inodes, we must allocate sbi->s_mirrors blocks, and for file
 *  blocks, we try to allocate sbi->s_clustersize, but can always get away
 *  with just one block.
 */
int omfs_allocate_range(struct super_block *sb,
			int min_request,
			int max_request,
			u64 *return_block,
			int *return_size)
{
	struct omfs_sb_info *sbi = OMFS_SB(sb);
	int bits_per_entry = 8 * sb->s_blocksize;
	int ret = 0;
	int i, run, bit;

	mutex_lock(&sbi->s_bitmap_lock);
	for (i = 0; i < sbi->s_imap_size; i++) {
		bit = 0;
		while (bit < bits_per_entry) {
			bit = find_next_zero_bit(sbi->s_imap[i], bits_per_entry,
				bit);

			if (bit == bits_per_entry)
				break;

			run = count_run(&sbi->s_imap[i], bits_per_entry,
				sbi->s_imap_size-i, bit, max_request);

			if (run >= min_request)
				goto found;
			bit += run;
		}
	}
	ret = -ENOSPC;
	goto out;

found:
	*return_block = i * bits_per_entry + bit;
	*return_size = run;
	ret = set_run(sb, i, bits_per_entry, bit, run, 1);

out:
	mutex_unlock(&sbi->s_bitmap_lock);
	return ret;
}

/*
 * Clears count bits starting at a given block.
 */
int omfs_clear_range(struct super_block *sb, u64 block, int count)
{
	struct omfs_sb_info *sbi = OMFS_SB(sb);
	int bits_per_entry = 8 * sb->s_blocksize;
	u64 tmp;
	unsigned int map, bit;
	int ret;

	tmp = block;
	bit = do_div(tmp, bits_per_entry);
	map = tmp;

	if (map >= sbi->s_imap_size)
		return 0;

	mutex_lock(&sbi->s_bitmap_lock);
	ret = set_run(sb, map, bits_per_entry, bit, count, 0);
	mutex_unlock(&sbi->s_bitmap_lock);
	return ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/omfs/bitmap.c */
/************************************************************/
/*
 * OMFS (as used by RIO Karma) directory operations.
 * Copyright (C) 2005 Bob Copeland <me@bobcopeland.com>
 * Released under GPL v2.
 */

// #include <linux/fs.h>
#include <linux/ctype.h>
// #include <linux/buffer_head.h>
// #include "omfs.h"
#include "../../inc/__fss.h"

static int omfs_hash(const char *name, int namelen, int mod)
{
	int i, hash = 0;
	for (i = 0; i < namelen; i++)
		hash ^= tolower(name[i]) << (i % 24);
	return hash % mod;
}

/*
 * Finds the bucket for a given name and reads the containing block;
 * *ofs is set to the offset of the first list entry.
 */
static struct buffer_head *omfs_get_bucket(struct inode *dir,
		const char *name, int namelen, int *ofs)
{
	int nbuckets = (dir->i_size - OMFS_DIR_START)/8;
	int bucket = omfs_hash(name, namelen, nbuckets);

	*ofs = OMFS_DIR_START + bucket * 8;
	return omfs_bread(dir->i_sb, dir->i_ino);
}

static struct buffer_head *omfs_scan_list(struct inode *dir, u64 block,
				const char *name, int namelen,
				u64 *prev_block)
{
	struct buffer_head *bh;
	struct omfs_inode *oi;
	int err = -ENOENT;
	*prev_block = ~0;

	while (block != ~0) {
		bh = omfs_bread(dir->i_sb, block);
		if (!bh) {
			err = -EIO;
			goto err;
		}

		oi = (struct omfs_inode *) bh->b_data;
		if (omfs_is_bad(OMFS_SB(dir->i_sb), &oi->i_head, block)) {
			brelse(bh);
			goto err;
		}

		if (strncmp(oi->i_name, name, namelen) == 0)
			return bh;

		*prev_block = block;
		block = be64_to_cpu(oi->i_sibling);
		brelse(bh);
	}
err:
	return ERR_PTR(err);
}

static struct buffer_head *omfs_find_entry(struct inode *dir,
					   const char *name, int namelen)
{
	struct buffer_head *bh;
	int ofs;
	u64 block, dummy;

	bh = omfs_get_bucket(dir, name, namelen, &ofs);
	if (!bh)
		return ERR_PTR(-EIO);

	block = be64_to_cpu(*((__be64 *) &bh->b_data[ofs]));
	brelse(bh);

	return omfs_scan_list(dir, block, name, namelen, &dummy);
}

int omfs_make_empty(struct inode *inode, struct super_block *sb)
{
	struct omfs_sb_info *sbi = OMFS_SB(sb);
	struct buffer_head *bh;
	struct omfs_inode *oi;

	bh = omfs_bread(sb, inode->i_ino);
	if (!bh)
		return -ENOMEM;

	memset(bh->b_data, 0, sizeof(struct omfs_inode));

	if (S_ISDIR(inode->i_mode)) {
		memset(&bh->b_data[OMFS_DIR_START], 0xff,
			sbi->s_sys_blocksize - OMFS_DIR_START);
	} else
		omfs_make_empty_table(bh, OMFS_EXTENT_START);

	oi = (struct omfs_inode *) bh->b_data;
	oi->i_head.h_self = cpu_to_be64(inode->i_ino);
	oi->i_sibling = ~cpu_to_be64(0ULL);

	mark_buffer_dirty(bh);
	brelse(bh);
	return 0;
}

static int omfs_add_link(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = dentry->d_parent->d_inode;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct omfs_inode *oi;
	struct buffer_head *bh;
	u64 block;
	__be64 *entry;
	int ofs;

	/* just prepend to head of queue in proper bucket */
	bh = omfs_get_bucket(dir, name, namelen, &ofs);
	if (!bh)
		goto out;

	entry = (__be64 *) &bh->b_data[ofs];
	block = be64_to_cpu(*entry);
	*entry = cpu_to_be64(inode->i_ino);
	mark_buffer_dirty(bh);
	brelse(bh);

	/* now set the sibling and parent pointers on the new inode */
	bh = omfs_bread(dir->i_sb, inode->i_ino);
	if (!bh)
		goto out;

	oi = (struct omfs_inode *) bh->b_data;
	memcpy(oi->i_name, name, namelen);
	memset(oi->i_name + namelen, 0, OMFS_NAMELEN - namelen);
	oi->i_sibling = cpu_to_be64(block);
	oi->i_parent = cpu_to_be64(dir->i_ino);
	mark_buffer_dirty(bh);
	brelse(bh);

	dir->i_ctime = CURRENT_TIME_SEC;

	/* mark affected inodes dirty to rebuild checksums */
	mark_inode_dirty(dir);
	mark_inode_dirty(inode);
	return 0;
out:
	return -ENOMEM;
}

static int omfs_delete_entry(struct dentry *dentry)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct inode *dirty;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct omfs_inode *oi;
	struct buffer_head *bh, *bh2;
	__be64 *entry, next;
	u64 block, prev;
	int ofs;
	int err = -ENOMEM;

	/* delete the proper node in the bucket's linked list */
	bh = omfs_get_bucket(dir, name, namelen, &ofs);
	if (!bh)
		goto out;

	entry = (__be64 *) &bh->b_data[ofs];
	block = be64_to_cpu(*entry);

	bh2 = omfs_scan_list(dir, block, name, namelen, &prev);
	if (IS_ERR(bh2)) {
		err = PTR_ERR(bh2);
		goto out_free_bh;
	}

	oi = (struct omfs_inode *) bh2->b_data;
	next = oi->i_sibling;
	brelse(bh2);

	if (prev != ~0) {
		/* found in middle of list, get list ptr */
		brelse(bh);
		bh = omfs_bread(dir->i_sb, prev);
		if (!bh)
			goto out;

		oi = (struct omfs_inode *) bh->b_data;
		entry = &oi->i_sibling;
	}

	*entry = next;
	mark_buffer_dirty(bh);

	if (prev != ~0) {
		dirty = omfs_iget(dir->i_sb, prev);
		if (!IS_ERR(dirty)) {
			mark_inode_dirty(dirty);
			iput(dirty);
		}
	}

	err = 0;
out_free_bh:
	brelse(bh);
out:
	return err;
}

static int omfs_dir_is_empty(struct inode *inode)
{
	int nbuckets = (inode->i_size - OMFS_DIR_START) / 8;
	struct buffer_head *bh;
	u64 *ptr;
	int i;

	bh = omfs_bread(inode->i_sb, inode->i_ino);

	if (!bh)
		return 0;

	ptr = (u64 *) &bh->b_data[OMFS_DIR_START];

	for (i = 0; i < nbuckets; i++, ptr++)
		if (*ptr != ~0)
			break;

	brelse(bh);
	return *ptr != ~0;
}

static int omfs_remove(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int ret;


	if (S_ISDIR(inode->i_mode) &&
	    !omfs_dir_is_empty(inode))
		return -ENOTEMPTY;

	ret = omfs_delete_entry(dentry);
	if (ret)
		return ret;
	
	clear_nlink(inode);
	mark_inode_dirty(inode);
	mark_inode_dirty(dir);
	return 0;
}

static int omfs_add_node(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct inode *inode = omfs_new_inode(dir, mode);

	if (IS_ERR(inode))
		return PTR_ERR(inode);

	err = omfs_make_empty(inode, dir->i_sb);
	if (err)
		goto out_free_inode;

	err = omfs_add_link(dentry, inode);
	if (err)
		goto out_free_inode;

	d_instantiate(dentry, inode);
	return 0;

out_free_inode:
	iput(inode);
	return err;
}

static int omfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return omfs_add_node(dir, dentry, mode | S_IFDIR);
}

static int omfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	return omfs_add_node(dir, dentry, mode | S_IFREG);
}

static struct dentry *omfs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct buffer_head *bh;
	struct inode *inode = NULL;

	if (dentry->d_name.len > OMFS_NAMELEN)
		return ERR_PTR(-ENAMETOOLONG);

	bh = omfs_find_entry(dir, dentry->d_name.name, dentry->d_name.len);
	if (!IS_ERR(bh)) {
		struct omfs_inode *oi = (struct omfs_inode *)bh->b_data;
		ino_t ino = be64_to_cpu(oi->i_head.h_self);
		brelse(bh);
		inode = omfs_iget(dir->i_sb, ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}
	d_add(dentry, inode);
	return NULL;
}

/* sanity check block's self pointer */
int omfs_is_bad(struct omfs_sb_info *sbi, struct omfs_header *header,
	u64 fsblock)
{
	int is_bad;
	u64 ino = be64_to_cpu(header->h_self);
	is_bad = ((ino != fsblock) || (ino < sbi->s_root_ino) ||
		(ino > sbi->s_num_blocks));

	if (is_bad)
		printk(KERN_WARNING "omfs: bad hash chain detected\n");

	return is_bad;
}

static bool omfs_fill_chain(struct inode *dir, struct dir_context *ctx,
		u64 fsblock, int hindex)
{
	/* follow chain in this bucket */
	while (fsblock != ~0) {
		struct buffer_head *bh = omfs_bread(dir->i_sb, fsblock);
		struct omfs_inode *oi;
		u64 self;
		unsigned char d_type;

		if (!bh)
			return true;

		oi = (struct omfs_inode *) bh->b_data;
		if (omfs_is_bad(OMFS_SB(dir->i_sb), &oi->i_head, fsblock)) {
			brelse(bh);
			return true;
		}

		self = fsblock;
		fsblock = be64_to_cpu(oi->i_sibling);

		/* skip visited nodes */
		if (hindex) {
			hindex--;
			brelse(bh);
			continue;
		}

		d_type = (oi->i_type == OMFS_DIR) ? DT_DIR : DT_REG;

		if (!dir_emit(ctx, oi->i_name,
			      strnlen(oi->i_name, OMFS_NAMELEN),
			      self, d_type)) {
			brelse(bh);
			return false;
		}
		brelse(bh);
		ctx->pos++;
	}
	return true;
}

static int omfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *new_inode = new_dentry->d_inode;
	struct inode *old_inode = old_dentry->d_inode;
	int err;

	if (new_inode) {
		/* overwriting existing file/dir */
		err = omfs_remove(new_dir, new_dentry);
		if (err)
			goto out;
	}

	/* since omfs locates files by name, we need to unlink _before_
	 * adding the new link or we won't find the old one */
	err = omfs_delete_entry(old_dentry);
	if (err)
		goto out;

	mark_inode_dirty(old_dir);
	err = omfs_add_link(new_dentry, old_inode);
	if (err)
		goto out;

	old_inode->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(old_inode);
out:
	return err;
}

static int omfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file_inode(file);
	struct buffer_head *bh;
	__be64 *p;
	unsigned int hchain, hindex;
	int nbuckets;

	if (ctx->pos >> 32)
		return -EINVAL;

	if (ctx->pos < 1 << 20) {
		if (!dir_emit_dots(file, ctx))
			return 0;
		ctx->pos = 1 << 20;
	}

	nbuckets = (dir->i_size - OMFS_DIR_START) / 8;

	/* high 12 bits store bucket + 1 and low 20 bits store hash index */
	hchain = (ctx->pos >> 20) - 1;
	hindex = ctx->pos & 0xfffff;

	bh = omfs_bread(dir->i_sb, dir->i_ino);
	if (!bh)
		return -EINVAL;

	p = (__be64 *)(bh->b_data + OMFS_DIR_START) + hchain;

	for (; hchain < nbuckets; hchain++) {
		__u64 fsblock = be64_to_cpu(*p++);
		if (!omfs_fill_chain(dir, ctx, fsblock, hindex))
			break;
		hindex = 0;
		ctx->pos = (hchain+2) << 20;
	}
	brelse(bh);
	return 0;
}

const struct inode_operations omfs_dir_inops = {
	.lookup = omfs_lookup,
	.mkdir = omfs_mkdir,
	.rename = omfs_rename,
	.create = omfs_create,
	.unlink = omfs_remove,
	.rmdir = omfs_remove,
};

const struct file_operations omfs_dir_operations = {
	.read = generic_read_dir,
	.iterate = omfs_readdir,
	.llseek = generic_file_llseek,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/omfs/dir.c */
/************************************************************/
/*
 * OMFS (as used by RIO Karma) file operations.
 * Copyright (C) 2005 Bob Copeland <me@bobcopeland.com>
 * Released under GPL v2.
 */

#include <linux/module.h>
// #include <linux/fs.h>
// #include <linux/buffer_head.h>
#include <linux/mpage.h>
// #include "omfs.h"
#include "../../inc/__fss.h"

static u32 omfs_max_extents(struct omfs_sb_info *sbi, int offset)
{
	return (sbi->s_sys_blocksize - offset -
		sizeof(struct omfs_extent)) /
		sizeof(struct omfs_extent_entry) + 1;
}

void omfs_make_empty_table(struct buffer_head *bh, int offset)
{
	struct omfs_extent *oe = (struct omfs_extent *) &bh->b_data[offset];

	oe->e_next = ~cpu_to_be64(0ULL);
	oe->e_extent_count = cpu_to_be32(1),
	oe->e_fill = cpu_to_be32(0x22),
	oe->e_entry.e_cluster = ~cpu_to_be64(0ULL);
	oe->e_entry.e_blocks = ~cpu_to_be64(0ULL);
}

int omfs_shrink_inode(struct inode *inode)
{
	struct omfs_sb_info *sbi = OMFS_SB(inode->i_sb);
	struct omfs_extent *oe;
	struct omfs_extent_entry *entry;
	struct buffer_head *bh;
	u64 next, last;
	u32 extent_count;
	u32 max_extents;
	int ret;

	/* traverse extent table, freeing each entry that is greater
	 * than inode->i_size;
	 */
	next = inode->i_ino;

	/* only support truncate -> 0 for now */
	ret = -EIO;
	if (inode->i_size != 0)
		goto out;

	bh = omfs_bread(inode->i_sb, next);
	if (!bh)
		goto out;

	oe = (struct omfs_extent *)(&bh->b_data[OMFS_EXTENT_START]);
	max_extents = omfs_max_extents(sbi, OMFS_EXTENT_START);

	for (;;) {

		if (omfs_is_bad(sbi, (struct omfs_header *) bh->b_data, next))
			goto out_brelse;

		extent_count = be32_to_cpu(oe->e_extent_count);

		if (extent_count > max_extents)
			goto out_brelse;

		last = next;
		next = be64_to_cpu(oe->e_next);
		entry = &oe->e_entry;

		/* ignore last entry as it is the terminator */
		for (; extent_count > 1; extent_count--) {
			u64 start, count;
			start = be64_to_cpu(entry->e_cluster);
			count = be64_to_cpu(entry->e_blocks);

			omfs_clear_range(inode->i_sb, start, (int) count);
			entry++;
		}
		omfs_make_empty_table(bh, (char *) oe - bh->b_data);
		mark_buffer_dirty(bh);
		brelse(bh);

		if (last != inode->i_ino)
			omfs_clear_range(inode->i_sb, last, sbi->s_mirrors);

		if (next == ~0)
			break;

		bh = omfs_bread(inode->i_sb, next);
		if (!bh)
			goto out;
		oe = (struct omfs_extent *) (&bh->b_data[OMFS_EXTENT_CONT]);
		max_extents = omfs_max_extents(sbi, OMFS_EXTENT_CONT);
	}
	ret = 0;
out:
	return ret;
out_brelse:
	brelse(bh);
	return ret;
}

static void omfs_truncate(struct inode *inode)
{
	omfs_shrink_inode(inode);
	mark_inode_dirty(inode);
}

/*
 * Add new blocks to the current extent, or create new entries/continuations
 * as necessary.
 */
static int omfs_grow_extent(struct inode *inode, struct omfs_extent *oe,
			u64 *ret_block)
{
	struct omfs_extent_entry *terminator;
	struct omfs_extent_entry *entry = &oe->e_entry;
	struct omfs_sb_info *sbi = OMFS_SB(inode->i_sb);
	u32 extent_count = be32_to_cpu(oe->e_extent_count);
	u64 new_block = 0;
	u32 max_count;
	int new_count;
	int ret = 0;

	/* reached the end of the extent table with no blocks mapped.
	 * there are three possibilities for adding: grow last extent,
	 * add a new extent to the current extent table, and add a
	 * continuation inode.  in last two cases need an allocator for
	 * sbi->s_cluster_size
	 */

	/* TODO: handle holes */

	/* should always have a terminator */
	if (extent_count < 1)
		return -EIO;

	/* trivially grow current extent, if next block is not taken */
	terminator = entry + extent_count - 1;
	if (extent_count > 1) {
		entry = terminator-1;
		new_block = be64_to_cpu(entry->e_cluster) +
			be64_to_cpu(entry->e_blocks);

		if (omfs_allocate_block(inode->i_sb, new_block)) {
			be64_add_cpu(&entry->e_blocks, 1);
			terminator->e_blocks = ~(cpu_to_be64(
				be64_to_cpu(~terminator->e_blocks) + 1));
			goto out;
		}
	}
	max_count = omfs_max_extents(sbi, OMFS_EXTENT_START);

	/* TODO: add a continuation block here */
	if (be32_to_cpu(oe->e_extent_count) > max_count-1)
		return -EIO;

	/* try to allocate a new cluster */
	ret = omfs_allocate_range(inode->i_sb, 1, sbi->s_clustersize,
		&new_block, &new_count);
	if (ret)
		goto out_fail;

	/* copy terminator down an entry */
	entry = terminator;
	terminator++;
	memcpy(terminator, entry, sizeof(struct omfs_extent_entry));

	entry->e_cluster = cpu_to_be64(new_block);
	entry->e_blocks = cpu_to_be64((u64) new_count);

	terminator->e_blocks = ~(cpu_to_be64(
		be64_to_cpu(~terminator->e_blocks) + (u64) new_count));

	/* write in new entry */
	be32_add_cpu(&oe->e_extent_count, 1);

out:
	*ret_block = new_block;
out_fail:
	return ret;
}

/*
 * Scans across the directory table for a given file block number.
 * If block not found, return 0.
 */
static sector_t find_block(struct inode *inode, struct omfs_extent_entry *ent,
			sector_t block, int count, int *left)
{
	/* count > 1 because of terminator */
	sector_t searched = 0;
	for (; count > 1; count--) {
		int numblocks = clus_to_blk(OMFS_SB(inode->i_sb),
			be64_to_cpu(ent->e_blocks));

		if (block >= searched  &&
		    block < searched + numblocks) {
			/*
			 * found it at cluster + (block - searched)
			 * numblocks - (block - searched) is remainder
			 */
			*left = numblocks - (block - searched);
			return clus_to_blk(OMFS_SB(inode->i_sb),
				be64_to_cpu(ent->e_cluster)) +
				block - searched;
		}
		searched += numblocks;
		ent++;
	}
	return 0;
}

static int omfs_get_block(struct inode *inode, sector_t block,
			  struct buffer_head *bh_result, int create)
{
	struct buffer_head *bh;
	sector_t next, offset;
	int ret;
	u64 uninitialized_var(new_block);
	u32 max_extents;
	int extent_count;
	struct omfs_extent *oe;
	struct omfs_extent_entry *entry;
	struct omfs_sb_info *sbi = OMFS_SB(inode->i_sb);
	int max_blocks = bh_result->b_size >> inode->i_blkbits;
	int remain;

	ret = -EIO;
	bh = omfs_bread(inode->i_sb, inode->i_ino);
	if (!bh)
		goto out;

	oe = (struct omfs_extent *)(&bh->b_data[OMFS_EXTENT_START]);
	max_extents = omfs_max_extents(sbi, OMFS_EXTENT_START);
	next = inode->i_ino;

	for (;;) {

		if (omfs_is_bad(sbi, (struct omfs_header *) bh->b_data, next))
			goto out_brelse;

		extent_count = be32_to_cpu(oe->e_extent_count);
		next = be64_to_cpu(oe->e_next);
		entry = &oe->e_entry;

		if (extent_count > max_extents)
			goto out_brelse;

		offset = find_block(inode, entry, block, extent_count, &remain);
		if (offset > 0) {
			ret = 0;
			map_bh(bh_result, inode->i_sb, offset);
			if (remain > max_blocks)
				remain = max_blocks;
			bh_result->b_size = (remain << inode->i_blkbits);
			goto out_brelse;
		}
		if (next == ~0)
			break;

		brelse(bh);
		bh = omfs_bread(inode->i_sb, next);
		if (!bh)
			goto out;
		oe = (struct omfs_extent *) (&bh->b_data[OMFS_EXTENT_CONT]);
		max_extents = omfs_max_extents(sbi, OMFS_EXTENT_CONT);
	}
	if (create) {
		ret = omfs_grow_extent(inode, oe, &new_block);
		if (ret == 0) {
			mark_buffer_dirty(bh);
			mark_inode_dirty(inode);
			map_bh(bh_result, inode->i_sb,
					clus_to_blk(sbi, new_block));
		}
	}
out_brelse:
	brelse(bh);
out:
	return ret;
}

static int omfs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, omfs_get_block);
}

static int omfs_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, omfs_get_block);
}

static int omfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, omfs_get_block, wbc);
}

static int
omfs_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, omfs_get_block);
}

static void omfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		omfs_truncate(inode);
	}
}

static int omfs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep,
				omfs_get_block);
	if (unlikely(ret))
		omfs_write_failed(mapping, pos + len);

	return ret;
}

static sector_t omfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, omfs_get_block);
}

const struct file_operations omfs_file_operations = {
	.llseek = generic_file_llseek,
	.read = new_sync_read,
	.write = new_sync_write,
	.read_iter = generic_file_read_iter,
	.write_iter = generic_file_write_iter,
	.mmap = generic_file_mmap,
	.fsync = generic_file_fsync,
	.splice_read = generic_file_splice_read,
};

static int omfs_setattr(struct dentry *dentry, struct iattr *attr)
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
		omfs_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations omfs_file_inops = {
	.setattr = omfs_setattr,
};

const struct address_space_operations omfs_aops = {
	.readpage = omfs_readpage,
	.readpages = omfs_readpages,
	.writepage = omfs_writepage,
	.writepages = omfs_writepages,
	.write_begin = omfs_write_begin,
	.write_end = generic_write_end,
	.bmap = omfs_bmap,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/omfs/file.c */
/************************************************************/
/*
 * Optimized MPEG FS - inode and super operations.
 * Copyright (C) 2006 Bob Copeland <me@bobcopeland.com>
 * Released under GPL v2.
 */
// #include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
// #include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/parser.h>
// #include <linux/buffer_head.h>
#include <linux/vmalloc.h>
#include <linux/writeback.h>
#include <linux/crc-itu-t.h>
// #include "omfs.h"
#include "../../inc/__fss.h"

MODULE_AUTHOR("Bob Copeland <me@bobcopeland.com>");
MODULE_DESCRIPTION("OMFS (ReplayTV/Karma) Filesystem for Linux");
MODULE_LICENSE("GPL");

struct buffer_head *omfs_bread(struct super_block *sb, sector_t block)
{
	struct omfs_sb_info *sbi = OMFS_SB(sb);
	if (block >= sbi->s_num_blocks)
		return NULL;

	return sb_bread(sb, clus_to_blk(sbi, block));
}

struct inode *omfs_new_inode(struct inode *dir, umode_t mode)
{
	struct inode *inode;
	u64 new_block;
	int err;
	int len;
	struct omfs_sb_info *sbi = OMFS_SB(dir->i_sb);

	inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	err = omfs_allocate_range(dir->i_sb, sbi->s_mirrors, sbi->s_mirrors,
			&new_block, &len);
	if (err)
		goto fail;

	inode->i_ino = new_block;
	inode_init_owner(inode, NULL, mode);
	inode->i_mapping->a_ops = &omfs_aops;

	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	switch (mode & S_IFMT) {
	case S_IFDIR:
		inode->i_op = &omfs_dir_inops;
		inode->i_fop = &omfs_dir_operations;
		inode->i_size = sbi->s_sys_blocksize;
		inc_nlink(inode);
		break;
	case S_IFREG:
		inode->i_op = &omfs_file_inops;
		inode->i_fop = &omfs_file_operations;
		inode->i_size = 0;
		break;
	}

	insert_inode_hash(inode);
	mark_inode_dirty(inode);
	return inode;
fail:
	make_bad_inode(inode);
	iput(inode);
	return ERR_PTR(err);
}

/*
 * Update the header checksums for a dirty inode based on its contents.
 * Caller is expected to hold the buffer head underlying oi and mark it
 * dirty.
 */
static void omfs_update_checksums(struct omfs_inode *oi)
{
	int xor, i, ofs = 0, count;
	u16 crc = 0;
	unsigned char *ptr = (unsigned char *) oi;

	count = be32_to_cpu(oi->i_head.h_body_size);
	ofs = sizeof(struct omfs_header);

	crc = crc_itu_t(crc, ptr + ofs, count);
	oi->i_head.h_crc = cpu_to_be16(crc);

	xor = ptr[0];
	for (i = 1; i < OMFS_XOR_COUNT; i++)
		xor ^= ptr[i];

	oi->i_head.h_check_xor = xor;
}

static int __omfs_write_inode(struct inode *inode, int wait)
{
	struct omfs_inode *oi;
	struct omfs_sb_info *sbi = OMFS_SB(inode->i_sb);
	struct buffer_head *bh, *bh2;
	u64 ctime;
	int i;
	int ret = -EIO;
	int sync_failed = 0;

	/* get current inode since we may have written sibling ptrs etc. */
	bh = omfs_bread(inode->i_sb, inode->i_ino);
	if (!bh)
		goto out;

	oi = (struct omfs_inode *) bh->b_data;

	oi->i_head.h_self = cpu_to_be64(inode->i_ino);
	if (S_ISDIR(inode->i_mode))
		oi->i_type = OMFS_DIR;
	else if (S_ISREG(inode->i_mode))
		oi->i_type = OMFS_FILE;
	else {
		printk(KERN_WARNING "omfs: unknown file type: %d\n",
			inode->i_mode);
		goto out_brelse;
	}

	oi->i_head.h_body_size = cpu_to_be32(sbi->s_sys_blocksize -
		sizeof(struct omfs_header));
	oi->i_head.h_version = 1;
	oi->i_head.h_type = OMFS_INODE_NORMAL;
	oi->i_head.h_magic = OMFS_IMAGIC;
	oi->i_size = cpu_to_be64(inode->i_size);

	ctime = inode->i_ctime.tv_sec * 1000LL +
		((inode->i_ctime.tv_nsec + 999)/1000);
	oi->i_ctime = cpu_to_be64(ctime);

	omfs_update_checksums(oi);

	mark_buffer_dirty(bh);
	if (wait) {
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh))
			sync_failed = 1;
	}

	/* if mirroring writes, copy to next fsblock */
	for (i = 1; i < sbi->s_mirrors; i++) {
		bh2 = omfs_bread(inode->i_sb, inode->i_ino + i);
		if (!bh2)
			goto out_brelse;

		memcpy(bh2->b_data, bh->b_data, bh->b_size);
		mark_buffer_dirty(bh2);
		if (wait) {
			sync_dirty_buffer(bh2);
			if (buffer_req(bh2) && !buffer_uptodate(bh2))
				sync_failed = 1;
		}
		brelse(bh2);
	}
	ret = (sync_failed) ? -EIO : 0;
out_brelse:
	brelse(bh);
out:
	return ret;
}

static int omfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return __omfs_write_inode(inode, wbc->sync_mode == WB_SYNC_ALL);
}

int omfs_sync_inode(struct inode *inode)
{
	return __omfs_write_inode(inode, 1);
}

/*
 * called when an entry is deleted, need to clear the bits in the
 * bitmaps.
 */
static void omfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	if (inode->i_nlink)
		return;

	if (S_ISREG(inode->i_mode)) {
		inode->i_size = 0;
		omfs_shrink_inode(inode);
	}

	omfs_clear_range(inode->i_sb, inode->i_ino, 2);
}

struct inode *omfs_iget(struct super_block *sb, ino_t ino)
{
	struct omfs_sb_info *sbi = OMFS_SB(sb);
	struct omfs_inode *oi;
	struct buffer_head *bh;
	u64 ctime;
	unsigned long nsecs;
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	bh = omfs_bread(inode->i_sb, ino);
	if (!bh)
		goto iget_failed;

	oi = (struct omfs_inode *)bh->b_data;

	/* check self */
	if (ino != be64_to_cpu(oi->i_head.h_self))
		goto fail_bh;

	inode->i_uid = sbi->s_uid;
	inode->i_gid = sbi->s_gid;

	ctime = be64_to_cpu(oi->i_ctime);
	nsecs = do_div(ctime, 1000) * 1000L;

	inode->i_atime.tv_sec = ctime;
	inode->i_mtime.tv_sec = ctime;
	inode->i_ctime.tv_sec = ctime;
	inode->i_atime.tv_nsec = nsecs;
	inode->i_mtime.tv_nsec = nsecs;
	inode->i_ctime.tv_nsec = nsecs;

	inode->i_mapping->a_ops = &omfs_aops;

	switch (oi->i_type) {
	case OMFS_DIR:
		inode->i_mode = S_IFDIR | (S_IRWXUGO & ~sbi->s_dmask);
		inode->i_op = &omfs_dir_inops;
		inode->i_fop = &omfs_dir_operations;
		inode->i_size = sbi->s_sys_blocksize;
		inc_nlink(inode);
		break;
	case OMFS_FILE:
		inode->i_mode = S_IFREG | (S_IRWXUGO & ~sbi->s_fmask);
		inode->i_fop = &omfs_file_operations;
		inode->i_size = be64_to_cpu(oi->i_size);
		break;
	}
	brelse(bh);
	unlock_new_inode(inode);
	return inode;
fail_bh:
	brelse(bh);
iget_failed:
	iget_failed(inode);
	return ERR_PTR(-EIO);
}

static void omfs_put_super(struct super_block *sb)
{
	struct omfs_sb_info *sbi = OMFS_SB(sb);
	kfree(sbi->s_imap);
	kfree(sbi);
	sb->s_fs_info = NULL;
}

static int omfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *s = dentry->d_sb;
	struct omfs_sb_info *sbi = OMFS_SB(s);
	u64 id = huge_encode_dev(s->s_bdev->bd_dev);

	buf->f_type = OMFS_MAGIC;
	buf->f_bsize = sbi->s_blocksize;
	buf->f_blocks = sbi->s_num_blocks;
	buf->f_files = sbi->s_num_blocks;
	buf->f_namelen = OMFS_NAMELEN;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	buf->f_bfree = buf->f_bavail = buf->f_ffree =
		omfs_count_free(s);

	return 0;
}

static const struct super_operations omfs_sops = {
	.write_inode	= omfs_write_inode,
	.evict_inode	= omfs_evict_inode,
	.put_super	= omfs_put_super,
	.statfs		= omfs_statfs,
	.show_options	= generic_show_options,
};

/*
 * For Rio Karma, there is an on-disk free bitmap whose location is
 * stored in the root block.  For ReplayTV, there is no such free bitmap
 * so we have to walk the tree.  Both inodes and file data are allocated
 * from the same map.  This array can be big (300k) so we allocate
 * in units of the blocksize.
 */
static int omfs_get_imap(struct super_block *sb)
{
	unsigned int bitmap_size, count, array_size;
	struct omfs_sb_info *sbi = OMFS_SB(sb);
	struct buffer_head *bh;
	unsigned long **ptr;
	sector_t block;

	bitmap_size = DIV_ROUND_UP(sbi->s_num_blocks, 8);
	array_size = DIV_ROUND_UP(bitmap_size, sb->s_blocksize);

	if (sbi->s_bitmap_ino == ~0ULL)
		goto out;

	sbi->s_imap_size = array_size;
	sbi->s_imap = kcalloc(array_size, sizeof(unsigned long *), GFP_KERNEL);
	if (!sbi->s_imap)
		goto nomem;

	block = clus_to_blk(sbi, sbi->s_bitmap_ino);
	if (block >= sbi->s_num_blocks)
		goto nomem;

	ptr = sbi->s_imap;
	for (count = bitmap_size; count > 0; count -= sb->s_blocksize) {
		bh = sb_bread(sb, block++);
		if (!bh)
			goto nomem_free;
		*ptr = kmalloc(sb->s_blocksize, GFP_KERNEL);
		if (!*ptr) {
			brelse(bh);
			goto nomem_free;
		}
		memcpy(*ptr, bh->b_data, sb->s_blocksize);
		if (count < sb->s_blocksize)
			memset((void *)*ptr + count, 0xff,
				sb->s_blocksize - count);
		brelse(bh);
		ptr++;
	}
out:
	return 0;

nomem_free:
	for (count = 0; count < array_size; count++)
		kfree(sbi->s_imap[count]);

	kfree(sbi->s_imap);
nomem:
	sbi->s_imap = NULL;
	sbi->s_imap_size = 0;
	return -ENOMEM;
}

enum {
	Opt_uid, Opt_gid, Opt_umask, Opt_dmask, Opt_fmask
};

static const match_table_t tokens = {
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_umask, "umask=%o"},
	{Opt_dmask, "dmask=%o"},
	{Opt_fmask, "fmask=%o"},
};

static int parse_options(char *options, struct omfs_sb_info *sbi)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_uid:
			if (match_int(&args[0], &option))
				return 0;
			sbi->s_uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(sbi->s_uid))
				return 0;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return 0;
			sbi->s_gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(sbi->s_gid))
				return 0;
			break;
		case Opt_umask:
			if (match_octal(&args[0], &option))
				return 0;
			sbi->s_fmask = sbi->s_dmask = option;
			break;
		case Opt_dmask:
			if (match_octal(&args[0], &option))
				return 0;
			sbi->s_dmask = option;
			break;
		case Opt_fmask:
			if (match_octal(&args[0], &option))
				return 0;
			sbi->s_fmask = option;
			break;
		default:
			return 0;
		}
	}
	return 1;
}

static int omfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct buffer_head *bh, *bh2;
	struct omfs_super_block *omfs_sb;
	struct omfs_root_block *omfs_rb;
	struct omfs_sb_info *sbi;
	struct inode *root;
	int ret = -EINVAL;

	save_mount_options(sb, (char *) data);

	sbi = kzalloc(sizeof(struct omfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;

	sbi->s_uid = current_uid();
	sbi->s_gid = current_gid();
	sbi->s_dmask = sbi->s_fmask = current_umask();

	if (!parse_options((char *) data, sbi))
		goto end;

	sb->s_maxbytes = 0xffffffff;

	sb_set_blocksize(sb, 0x200);

	bh = sb_bread(sb, 0);
	if (!bh)
		goto end;

	omfs_sb = (struct omfs_super_block *)bh->b_data;

	if (omfs_sb->s_magic != cpu_to_be32(OMFS_MAGIC)) {
		if (!silent)
			printk(KERN_ERR "omfs: Invalid superblock (%x)\n",
				   omfs_sb->s_magic);
		goto out_brelse_bh;
	}
	sb->s_magic = OMFS_MAGIC;

	sbi->s_num_blocks = be64_to_cpu(omfs_sb->s_num_blocks);
	sbi->s_blocksize = be32_to_cpu(omfs_sb->s_blocksize);
	sbi->s_mirrors = be32_to_cpu(omfs_sb->s_mirrors);
	sbi->s_root_ino = be64_to_cpu(omfs_sb->s_root_block);
	sbi->s_sys_blocksize = be32_to_cpu(omfs_sb->s_sys_blocksize);
	mutex_init(&sbi->s_bitmap_lock);

	if (sbi->s_num_blocks > OMFS_MAX_BLOCKS) {
		printk(KERN_ERR "omfs: sysblock number (%llx) is out of range\n",
		       (unsigned long long)sbi->s_num_blocks);
		goto out_brelse_bh;
	}

	if (sbi->s_sys_blocksize > PAGE_SIZE) {
		printk(KERN_ERR "omfs: sysblock size (%d) is out of range\n",
			sbi->s_sys_blocksize);
		goto out_brelse_bh;
	}

	if (sbi->s_blocksize < sbi->s_sys_blocksize ||
	    sbi->s_blocksize > OMFS_MAX_BLOCK_SIZE) {
		printk(KERN_ERR "omfs: block size (%d) is out of range\n",
			sbi->s_blocksize);
		goto out_brelse_bh;
	}

	/*
	 * Use sys_blocksize as the fs block since it is smaller than a
	 * page while the fs blocksize can be larger.
	 */
	sb_set_blocksize(sb, sbi->s_sys_blocksize);

	/*
	 * ...and the difference goes into a shift.  sys_blocksize is always
	 * a power of two factor of blocksize.
	 */
	sbi->s_block_shift = get_bitmask_order(sbi->s_blocksize) -
		get_bitmask_order(sbi->s_sys_blocksize);

	bh2 = omfs_bread(sb, be64_to_cpu(omfs_sb->s_root_block));
	if (!bh2)
		goto out_brelse_bh;

	omfs_rb = (struct omfs_root_block *)bh2->b_data;

	sbi->s_bitmap_ino = be64_to_cpu(omfs_rb->r_bitmap);
	sbi->s_clustersize = be32_to_cpu(omfs_rb->r_clustersize);

	if (sbi->s_num_blocks != be64_to_cpu(omfs_rb->r_num_blocks)) {
		printk(KERN_ERR "omfs: block count discrepancy between "
			"super and root blocks (%llx, %llx)\n",
			(unsigned long long)sbi->s_num_blocks,
			(unsigned long long)be64_to_cpu(omfs_rb->r_num_blocks));
		goto out_brelse_bh2;
	}

	if (sbi->s_bitmap_ino != ~0ULL &&
	    sbi->s_bitmap_ino > sbi->s_num_blocks) {
		printk(KERN_ERR "omfs: free space bitmap location is corrupt "
			"(%llx, total blocks %llx)\n",
			(unsigned long long) sbi->s_bitmap_ino,
			(unsigned long long) sbi->s_num_blocks);
		goto out_brelse_bh2;
	}
	if (sbi->s_clustersize < 1 ||
	    sbi->s_clustersize > OMFS_MAX_CLUSTER_SIZE) {
		printk(KERN_ERR "omfs: cluster size out of range (%d)",
			sbi->s_clustersize);
		goto out_brelse_bh2;
	}

	ret = omfs_get_imap(sb);
	if (ret)
		goto out_brelse_bh2;

	sb->s_op = &omfs_sops;

	root = omfs_iget(sb, be64_to_cpu(omfs_rb->r_root_dir));
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto out_brelse_bh2;
	}

	sb->s_root = d_make_root(root);
	if (!sb->s_root)
		goto out_brelse_bh2;
	printk(KERN_DEBUG "omfs: Mounted volume %s\n", omfs_rb->r_name);

	ret = 0;
out_brelse_bh2:
	brelse(bh2);
out_brelse_bh:
	brelse(bh);
end:
	if (ret)
		kfree(sbi);
	return ret;
}

static struct dentry *omfs_mount(struct file_system_type *fs_type,
			int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, omfs_fill_super);
}

static struct file_system_type omfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "omfs",
	.mount = omfs_mount,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("omfs");

static int __init init_omfs_fs(void)
{
	return register_filesystem(&omfs_fs_type);
}

static void __exit exit_omfs_fs(void)
{
	unregister_filesystem(&omfs_fs_type);
}

module_init(init_omfs_fs);
module_exit(exit_omfs_fs);
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/omfs/inode.c */
/************************************************************/
