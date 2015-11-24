/*
 *  linux/fs/adfs/dir.c
 *
 *  Copyright (C) 1999-2000 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Common directory handling for ADFS
 */
#include "adfs.h"
#include "../../inc/__fss.h"

/*
 * For future.  This should probably be per-directory.
 */
static DEFINE_RWLOCK(adfs_dir_lock);

static int
adfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct adfs_dir_ops *ops = ADFS_SB(sb)->s_dir;
	struct object_info obj;
	struct adfs_dir dir;
	int ret = 0;

	if (ctx->pos >> 32)
		return 0;

	ret = ops->read(sb, inode->i_ino, inode->i_size, &dir);
	if (ret)
		return ret;

	if (ctx->pos == 0) {
		if (!dir_emit_dot(file, ctx))
			goto free_out;
		ctx->pos = 1;
	}
	if (ctx->pos == 1) {
		if (!dir_emit(ctx, "..", 2, dir.parent_id, DT_DIR))
			goto free_out;
		ctx->pos = 2;
	}

	read_lock(&adfs_dir_lock);

	ret = ops->setpos(&dir, ctx->pos - 2);
	if (ret)
		goto unlock_out;
	while (ops->getnext(&dir, &obj) == 0) {
		if (!dir_emit(ctx, obj.name, obj.name_len,
			    obj.file_id, DT_UNKNOWN))
			break;
		ctx->pos++;
	}

unlock_out:
	read_unlock(&adfs_dir_lock);

free_out:
	ops->free(&dir);
	return ret;
}

int
adfs_dir_update(struct super_block *sb, struct object_info *obj, int wait)
{
	int ret = -EINVAL;
#ifdef CONFIG_ADFS_FS_RW
	struct adfs_dir_ops *ops = ADFS_SB(sb)->s_dir;
	struct adfs_dir dir;

	printk(KERN_INFO "adfs_dir_update: object %06X in dir %06X\n",
		 obj->file_id, obj->parent_id);

	if (!ops->update) {
		ret = -EINVAL;
		goto out;
	}

	ret = ops->read(sb, obj->parent_id, 0, &dir);
	if (ret)
		goto out;

	write_lock(&adfs_dir_lock);
	ret = ops->update(&dir, obj);
	write_unlock(&adfs_dir_lock);

	if (wait) {
		int err = ops->sync(&dir);
		if (!ret)
			ret = err;
	}

	ops->free(&dir);
out:
#endif
	return ret;
}

static int
adfs_match(struct qstr *name, struct object_info *obj)
{
	int i;

	if (name->len != obj->name_len)
		return 0;

	for (i = 0; i < name->len; i++) {
		char c1, c2;

		c1 = name->name[i];
		c2 = obj->name[i];

		if (c1 >= 'A' && c1 <= 'Z')
			c1 += 'a' - 'A';
		if (c2 >= 'A' && c2 <= 'Z')
			c2 += 'a' - 'A';

		if (c1 != c2)
			return 0;
	}
	return 1;
}

static int
adfs_dir_lookup_byname(struct inode *inode, struct qstr *name, struct object_info *obj)
{
	struct super_block *sb = inode->i_sb;
	struct adfs_dir_ops *ops = ADFS_SB(sb)->s_dir;
	struct adfs_dir dir;
	int ret;

	ret = ops->read(sb, inode->i_ino, inode->i_size, &dir);
	if (ret)
		goto out;

	if (ADFS_I(inode)->parent_id != dir.parent_id) {
		adfs_error(sb, "parent directory changed under me! (%lx but got %x)\n",
			   ADFS_I(inode)->parent_id, dir.parent_id);
		ret = -EIO;
		goto free_out;
	}

	obj->parent_id = inode->i_ino;

	/*
	 * '.' is handled by reserved_lookup() in fs/namei.c
	 */
	if (name->len == 2 && name->name[0] == '.' && name->name[1] == '.') {
		/*
		 * Currently unable to fill in the rest of 'obj',
		 * but this is better than nothing.  We need to
		 * ascend one level to find it's parent.
		 */
		obj->name_len = 0;
		obj->file_id  = obj->parent_id;
		goto free_out;
	}

	read_lock(&adfs_dir_lock);

	ret = ops->setpos(&dir, 0);
	if (ret)
		goto unlock_out;

	ret = -ENOENT;
	while (ops->getnext(&dir, obj) == 0) {
		if (adfs_match(name, obj)) {
			ret = 0;
			break;
		}
	}

unlock_out:
	read_unlock(&adfs_dir_lock);

free_out:
	ops->free(&dir);
out:
	return ret;
}

const struct file_operations adfs_dir_operations = {
	.read		= generic_read_dir,
	.llseek		= generic_file_llseek,
	.iterate	= adfs_readdir,
	.fsync		= generic_file_fsync,
};

static int
adfs_hash(const struct dentry *parent, struct qstr *qstr)
{
	const unsigned int name_len = ADFS_SB(parent->d_sb)->s_namelen;
	const unsigned char *name;
	unsigned long hash;
	int i;

	if (qstr->len < name_len)
		return 0;

	/*
	 * Truncate the name in place, avoids
	 * having to define a compare function.
	 */
	qstr->len = i = name_len;
	name = qstr->name;
	hash = init_name_hash();
	while (i--) {
		char c;

		c = *name++;
		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';

		hash = partial_name_hash(c, hash);
	}
	qstr->hash = end_name_hash(hash);

	return 0;
}

/*
 * Compare two names, taking note of the name length
 * requirements of the underlying filesystem.
 */
static int
adfs_compare(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	int i;

	if (len != name->len)
		return 1;

	for (i = 0; i < name->len; i++) {
		char a, b;

		a = str[i];
		b = name->name[i];

		if (a >= 'A' && a <= 'Z')
			a += 'a' - 'A';
		if (b >= 'A' && b <= 'Z')
			b += 'a' - 'A';

		if (a != b)
			return 1;
	}
	return 0;
}

const struct dentry_operations adfs_dentry_operations = {
	.d_hash		= adfs_hash,
	.d_compare	= adfs_compare,
};

static struct dentry *
adfs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct inode *inode = NULL;
	struct object_info obj;
	int error;

	error = adfs_dir_lookup_byname(dir, &dentry->d_name, &obj);
	if (error == 0) {
		error = -EACCES;
		/*
		 * This only returns NULL if get_empty_inode
		 * fails.
		 */
		inode = adfs_iget(dir->i_sb, &obj);
		if (inode)
			error = 0;
	}
	d_add(dentry, inode);
	return ERR_PTR(error);
}

/*
 * directories can handle most operations...
 */
const struct inode_operations adfs_dir_inode_operations = {
	.lookup		= adfs_lookup,
	.setattr	= adfs_notify_change,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/adfs/dir.c */
/************************************************************/
/*
 *  linux/fs/adfs/dir_f.c
 *
 * Copyright (C) 1997-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  E and F format directory handling
 */
#include <linux/buffer_head.h>
// #include "adfs.h"
#include "dir_f.h"
#include "../../inc/__fss.h"

static void adfs_f_free(struct adfs_dir *dir);

/*
 * Read an (unaligned) value of length 1..4 bytes
 */
static inline unsigned int adfs_readval(unsigned char *p, int len)
{
	unsigned int val = 0;

	switch (len) {
	case 4:		val |= p[3] << 24;
	case 3:		val |= p[2] << 16;
	case 2:		val |= p[1] << 8;
	default:	val |= p[0];
	}
	return val;
}

static inline void adfs_writeval(unsigned char *p, int len, unsigned int val)
{
	switch (len) {
	case 4:		p[3] = val >> 24;
	case 3:		p[2] = val >> 16;
	case 2:		p[1] = val >> 8;
	default:	p[0] = val;
	}
}

static inline int adfs_readname(char *buf, char *ptr, int maxlen)
{
	char *old_buf = buf;

	while ((unsigned char)*ptr >= ' ' && maxlen--) {
		if (*ptr == '/')
			*buf++ = '.';
		else
			*buf++ = *ptr;
		ptr++;
	}

	return buf - old_buf;
}

#define ror13(v) ((v >> 13) | (v << 19))

#define dir_u8(idx)				\
	({ int _buf = idx >> blocksize_bits;	\
	   int _off = idx - (_buf << blocksize_bits);\
	  *(u8 *)(bh[_buf]->b_data + _off);	\
	})

#define dir_u32(idx)				\
	({ int _buf = idx >> blocksize_bits;	\
	   int _off = idx - (_buf << blocksize_bits);\
	  *(__le32 *)(bh[_buf]->b_data + _off);	\
	})

#define bufoff(_bh,_idx)			\
	({ int _buf = _idx >> blocksize_bits;	\
	   int _off = _idx - (_buf << blocksize_bits);\
	  (u8 *)(_bh[_buf]->b_data + _off);	\
	})

/*
 * There are some algorithms that are nice in
 * assembler, but a bitch in C...  This is one
 * of them.
 */
static u8
adfs_dir_checkbyte(const struct adfs_dir *dir)
{
	struct buffer_head * const *bh = dir->bh;
	const int blocksize_bits = dir->sb->s_blocksize_bits;
	union { __le32 *ptr32; u8 *ptr8; } ptr, end;
	u32 dircheck = 0;
	int last = 5 - 26;
	int i = 0;

	/*
	 * Accumulate each word up to the last whole
	 * word of the last directory entry.  This
	 * can spread across several buffer heads.
	 */
	do {
		last += 26;
		do {
			dircheck = le32_to_cpu(dir_u32(i)) ^ ror13(dircheck);

			i += sizeof(u32);
		} while (i < (last & ~3));
	} while (dir_u8(last) != 0);

	/*
	 * Accumulate the last few bytes.  These
	 * bytes will be within the same bh.
	 */
	if (i != last) {
		ptr.ptr8 = bufoff(bh, i);
		end.ptr8 = ptr.ptr8 + last - i;

		do {
			dircheck = *ptr.ptr8++ ^ ror13(dircheck);
		} while (ptr.ptr8 < end.ptr8);
	}

	/*
	 * The directory tail is in the final bh
	 * Note that contary to the RISC OS PRMs,
	 * the first few bytes are NOT included
	 * in the check.  All bytes are in the
	 * same bh.
	 */
	ptr.ptr8 = bufoff(bh, 2008);
	end.ptr8 = ptr.ptr8 + 36;

	do {
		__le32 v = *ptr.ptr32++;
		dircheck = le32_to_cpu(v) ^ ror13(dircheck);
	} while (ptr.ptr32 < end.ptr32);

	return (dircheck ^ (dircheck >> 8) ^ (dircheck >> 16) ^ (dircheck >> 24)) & 0xff;
}

/*
 * Read and check that a directory is valid
 */
static int
adfs_dir_read(struct super_block *sb, unsigned long object_id,
	      unsigned int size, struct adfs_dir *dir)
{
	const unsigned int blocksize_bits = sb->s_blocksize_bits;
	int blk = 0;

	/*
	 * Directories which are not a multiple of 2048 bytes
	 * are considered bad v2 [3.6]
	 */
	if (size & 2047)
		goto bad_dir;

	size >>= blocksize_bits;

	dir->nr_buffers = 0;
	dir->sb = sb;

	for (blk = 0; blk < size; blk++) {
		int phys;

		phys = __adfs_block_map(sb, object_id, blk);
		if (!phys) {
			adfs_error(sb, "dir object %lX has a hole at offset %d",
				   object_id, blk);
			goto release_buffers;
		}

		dir->bh[blk] = sb_bread(sb, phys);
		if (!dir->bh[blk])
			goto release_buffers;
	}

	memcpy(&dir->dirhead, bufoff(dir->bh, 0), sizeof(dir->dirhead));
	memcpy(&dir->dirtail, bufoff(dir->bh, 2007), sizeof(dir->dirtail));

	if (dir->dirhead.startmasseq != dir->dirtail.new.endmasseq ||
	    memcmp(&dir->dirhead.startname, &dir->dirtail.new.endname, 4))
		goto bad_dir;

	if (memcmp(&dir->dirhead.startname, "Nick", 4) &&
	    memcmp(&dir->dirhead.startname, "Hugo", 4))
		goto bad_dir;

	if (adfs_dir_checkbyte(dir) != dir->dirtail.new.dircheckbyte)
		goto bad_dir;

	dir->nr_buffers = blk;

	return 0;

bad_dir:
	adfs_error(sb, "corrupted directory fragment %lX",
		   object_id);
release_buffers:
	for (blk -= 1; blk >= 0; blk -= 1)
		brelse(dir->bh[blk]);

	dir->sb = NULL;

	return -EIO;
}

/*
 * convert a disk-based directory entry to a Linux ADFS directory entry
 */
static inline void
adfs_dir2obj(struct adfs_dir *dir, struct object_info *obj,
	struct adfs_direntry *de)
{
	obj->name_len =	adfs_readname(obj->name, de->dirobname, ADFS_F_NAME_LEN);
	obj->file_id  = adfs_readval(de->dirinddiscadd, 3);
	obj->loadaddr = adfs_readval(de->dirload, 4);
	obj->execaddr = adfs_readval(de->direxec, 4);
	obj->size     = adfs_readval(de->dirlen,  4);
	obj->attr     = de->newdiratts;
	obj->filetype = -1;

	/*
	 * object is a file and is filetyped and timestamped?
	 * RISC OS 12-bit filetype is stored in load_address[19:8]
	 */
	if ((0 == (obj->attr & ADFS_NDA_DIRECTORY)) &&
		(0xfff00000 == (0xfff00000 & obj->loadaddr))) {
		obj->filetype = (__u16) ((0x000fff00 & obj->loadaddr) >> 8);

		/* optionally append the ,xyz hex filetype suffix */
		if (ADFS_SB(dir->sb)->s_ftsuffix)
			obj->name_len +=
				append_filetype_suffix(
					&obj->name[obj->name_len],
					obj->filetype);
	}
}

/*
 * convert a Linux ADFS directory entry to a disk-based directory entry
 */
static inline void
adfs_obj2dir(struct adfs_direntry *de, struct object_info *obj)
{
	adfs_writeval(de->dirinddiscadd, 3, obj->file_id);
	adfs_writeval(de->dirload, 4, obj->loadaddr);
	adfs_writeval(de->direxec, 4, obj->execaddr);
	adfs_writeval(de->dirlen,  4, obj->size);
	de->newdiratts = obj->attr;
}

/*
 * get a directory entry.  Note that the caller is responsible
 * for holding the relevant locks.
 */
static int
__adfs_dir_get(struct adfs_dir *dir, int pos, struct object_info *obj)
{
	struct super_block *sb = dir->sb;
	struct adfs_direntry de;
	int thissize, buffer, offset;

	buffer = pos >> sb->s_blocksize_bits;

	if (buffer > dir->nr_buffers)
		return -EINVAL;

	offset = pos & (sb->s_blocksize - 1);
	thissize = sb->s_blocksize - offset;
	if (thissize > 26)
		thissize = 26;

	memcpy(&de, dir->bh[buffer]->b_data + offset, thissize);
	if (thissize != 26)
		memcpy(((char *)&de) + thissize, dir->bh[buffer + 1]->b_data,
		       26 - thissize);

	if (!de.dirobname[0])
		return -ENOENT;

	adfs_dir2obj(dir, obj, &de);

	return 0;
}

static int
__adfs_dir_put(struct adfs_dir *dir, int pos, struct object_info *obj)
{
	struct super_block *sb = dir->sb;
	struct adfs_direntry de;
	int thissize, buffer, offset;

	buffer = pos >> sb->s_blocksize_bits;

	if (buffer > dir->nr_buffers)
		return -EINVAL;

	offset = pos & (sb->s_blocksize - 1);
	thissize = sb->s_blocksize - offset;
	if (thissize > 26)
		thissize = 26;

	/*
	 * Get the entry in total
	 */
	memcpy(&de, dir->bh[buffer]->b_data + offset, thissize);
	if (thissize != 26)
		memcpy(((char *)&de) + thissize, dir->bh[buffer + 1]->b_data,
		       26 - thissize);

	/*
	 * update it
	 */
	adfs_obj2dir(&de, obj);

	/*
	 * Put the new entry back
	 */
	memcpy(dir->bh[buffer]->b_data + offset, &de, thissize);
	if (thissize != 26)
		memcpy(dir->bh[buffer + 1]->b_data, ((char *)&de) + thissize,
		       26 - thissize);

	return 0;
}

/*
 * the caller is responsible for holding the necessary
 * locks.
 */
static int
adfs_dir_find_entry(struct adfs_dir *dir, unsigned long object_id)
{
	int pos, ret;

	ret = -ENOENT;

	for (pos = 5; pos < ADFS_NUM_DIR_ENTRIES * 26 + 5; pos += 26) {
		struct object_info obj;

		if (!__adfs_dir_get(dir, pos, &obj))
			break;

		if (obj.file_id == object_id) {
			ret = pos;
			break;
		}
	}

	return ret;
}

static int
adfs_f_read(struct super_block *sb, unsigned int id, unsigned int sz, struct adfs_dir *dir)
{
	int ret;

	if (sz != ADFS_NEWDIR_SIZE)
		return -EIO;

	ret = adfs_dir_read(sb, id, sz, dir);
	if (ret)
		adfs_error(sb, "unable to read directory");
	else
		dir->parent_id = adfs_readval(dir->dirtail.new.dirparent, 3);

	return ret;
}

static int
adfs_f_setpos(struct adfs_dir *dir, unsigned int fpos)
{
	if (fpos >= ADFS_NUM_DIR_ENTRIES)
		return -ENOENT;

	dir->pos = 5 + fpos * 26;
	return 0;
}

static int
adfs_f_getnext(struct adfs_dir *dir, struct object_info *obj)
{
	unsigned int ret;

	ret = __adfs_dir_get(dir, dir->pos, obj);
	if (ret == 0)
		dir->pos += 26;

	return ret;
}

static int
adfs_f_update(struct adfs_dir *dir, struct object_info *obj)
{
	struct super_block *sb = dir->sb;
	int ret, i;

	ret = adfs_dir_find_entry(dir, obj->file_id);
	if (ret < 0) {
		adfs_error(dir->sb, "unable to locate entry to update");
		goto out;
	}

	__adfs_dir_put(dir, ret, obj);
 
	/*
	 * Increment directory sequence number
	 */
	dir->bh[0]->b_data[0] += 1;
	dir->bh[dir->nr_buffers - 1]->b_data[sb->s_blocksize - 6] += 1;

	ret = adfs_dir_checkbyte(dir);
	/*
	 * Update directory check byte
	 */
	dir->bh[dir->nr_buffers - 1]->b_data[sb->s_blocksize - 1] = ret;

#if 1
	{
	const unsigned int blocksize_bits = sb->s_blocksize_bits;

	memcpy(&dir->dirhead, bufoff(dir->bh, 0), sizeof(dir->dirhead));
	memcpy(&dir->dirtail, bufoff(dir->bh, 2007), sizeof(dir->dirtail));

	if (dir->dirhead.startmasseq != dir->dirtail.new.endmasseq ||
	    memcmp(&dir->dirhead.startname, &dir->dirtail.new.endname, 4))
		goto bad_dir;

	if (memcmp(&dir->dirhead.startname, "Nick", 4) &&
	    memcmp(&dir->dirhead.startname, "Hugo", 4))
		goto bad_dir;

	if (adfs_dir_checkbyte(dir) != dir->dirtail.new.dircheckbyte)
		goto bad_dir;
	}
#endif
	for (i = dir->nr_buffers - 1; i >= 0; i--)
		mark_buffer_dirty(dir->bh[i]);

	ret = 0;
out:
	return ret;
#if 1
bad_dir:
	adfs_error(dir->sb, "whoops!  I broke a directory!");
	return -EIO;
#endif
}

static int
adfs_f_sync(struct adfs_dir *dir)
{
	int err = 0;
	int i;

	for (i = dir->nr_buffers - 1; i >= 0; i--) {
		struct buffer_head *bh = dir->bh[i];
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh))
			err = -EIO;
	}

	return err;
}

static void
adfs_f_free(struct adfs_dir *dir)
{
	int i;

	for (i = dir->nr_buffers - 1; i >= 0; i--) {
		brelse(dir->bh[i]);
		dir->bh[i] = NULL;
	}

	dir->nr_buffers = 0;
	dir->sb = NULL;
}

struct adfs_dir_ops adfs_f_dir_ops = {
	.read		= adfs_f_read,
	.setpos		= adfs_f_setpos,
	.getnext	= adfs_f_getnext,
	.update		= adfs_f_update,
	.sync		= adfs_f_sync,
	.free		= adfs_f_free
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/adfs/dir_f.c */
/************************************************************/
/*
 *  linux/fs/adfs/dir_fplus.c
 *
 *  Copyright (C) 1997-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
// #include <linux/buffer_head.h>
#include <linux/slab.h>
// #include "adfs.h"
#include "dir_fplus.h"
#include "../../inc/__fss.h"

static int
adfs_fplus_read(struct super_block *sb, unsigned int id, unsigned int sz, struct adfs_dir *dir)
{
	struct adfs_bigdirheader *h;
	struct adfs_bigdirtail *t;
	unsigned long block;
	unsigned int blk, size;
	int i, ret = -EIO;

	dir->nr_buffers = 0;

	/* start off using fixed bh set - only alloc for big dirs */
	dir->bh_fplus = &dir->bh[0];

	block = __adfs_block_map(sb, id, 0);
	if (!block) {
		adfs_error(sb, "dir object %X has a hole at offset 0", id);
		goto out;
	}

	dir->bh_fplus[0] = sb_bread(sb, block);
	if (!dir->bh_fplus[0])
		goto out;
	dir->nr_buffers += 1;

	h = (struct adfs_bigdirheader *)dir->bh_fplus[0]->b_data;
	size = le32_to_cpu(h->bigdirsize);
	if (size != sz) {
		printk(KERN_WARNING "adfs: adfs_fplus_read:"
					" directory header size %X\n"
					" does not match directory size %X\n",
					size, sz);
	}

	if (h->bigdirversion[0] != 0 || h->bigdirversion[1] != 0 ||
	    h->bigdirversion[2] != 0 || size & 2047 ||
	    h->bigdirstartname != cpu_to_le32(BIGDIRSTARTNAME)) {
		printk(KERN_WARNING "adfs: dir object %X has"
					" malformed dir header\n", id);
		goto out;
	}

	size >>= sb->s_blocksize_bits;
	if (size > ARRAY_SIZE(dir->bh)) {
		/* this directory is too big for fixed bh set, must allocate */
		struct buffer_head **bh_fplus =
			kcalloc(size, sizeof(struct buffer_head *),
				GFP_KERNEL);
		if (!bh_fplus) {
			adfs_error(sb, "not enough memory for"
					" dir object %X (%d blocks)", id, size);
			goto out;
		}
		dir->bh_fplus = bh_fplus;
		/* copy over the pointer to the block that we've already read */
		dir->bh_fplus[0] = dir->bh[0];
	}

	for (blk = 1; blk < size; blk++) {
		block = __adfs_block_map(sb, id, blk);
		if (!block) {
			adfs_error(sb, "dir object %X has a hole at offset %d", id, blk);
			goto out;
		}

		dir->bh_fplus[blk] = sb_bread(sb, block);
		if (!dir->bh_fplus[blk]) {
			adfs_error(sb,	"dir object %x failed read for offset %d, mapped block %lX",
				   id, blk, block);
			goto out;
		}

		dir->nr_buffers += 1;
	}

	t = (struct adfs_bigdirtail *)
		(dir->bh_fplus[size - 1]->b_data + (sb->s_blocksize - 8));

	if (t->bigdirendname != cpu_to_le32(BIGDIRENDNAME) ||
	    t->bigdirendmasseq != h->startmasseq ||
	    t->reserved[0] != 0 || t->reserved[1] != 0) {
		printk(KERN_WARNING "adfs: dir object %X has "
					"malformed dir end\n", id);
		goto out;
	}

	dir->parent_id = le32_to_cpu(h->bigdirparent);
	dir->sb = sb;
	return 0;

out:
	if (dir->bh_fplus) {
		for (i = 0; i < dir->nr_buffers; i++)
			brelse(dir->bh_fplus[i]);

		if (&dir->bh[0] != dir->bh_fplus)
			kfree(dir->bh_fplus);

		dir->bh_fplus = NULL;
	}

	dir->nr_buffers = 0;
	dir->sb = NULL;
	return ret;
}

static int
adfs_fplus_setpos(struct adfs_dir *dir, unsigned int fpos)
{
	struct adfs_bigdirheader *h =
		(struct adfs_bigdirheader *) dir->bh_fplus[0]->b_data;
	int ret = -ENOENT;

	if (fpos <= le32_to_cpu(h->bigdirentries)) {
		dir->pos = fpos;
		ret = 0;
	}

	return ret;
}

static void
dir_memcpy(struct adfs_dir *dir, unsigned int offset, void *to, int len)
{
	struct super_block *sb = dir->sb;
	unsigned int buffer, partial, remainder;

	buffer = offset >> sb->s_blocksize_bits;
	offset &= sb->s_blocksize - 1;

	partial = sb->s_blocksize - offset;

	if (partial >= len)
		memcpy(to, dir->bh_fplus[buffer]->b_data + offset, len);
	else {
		char *c = (char *)to;

		remainder = len - partial;

		memcpy(c,
			dir->bh_fplus[buffer]->b_data + offset,
			partial);

		memcpy(c + partial,
			dir->bh_fplus[buffer + 1]->b_data,
			remainder);
	}
}

static int
adfs_fplus_getnext(struct adfs_dir *dir, struct object_info *obj)
{
	struct adfs_bigdirheader *h =
		(struct adfs_bigdirheader *) dir->bh_fplus[0]->b_data;
	struct adfs_bigdirentry bde;
	unsigned int offset;
	int i, ret = -ENOENT;

	if (dir->pos >= le32_to_cpu(h->bigdirentries))
		goto out;

	offset = offsetof(struct adfs_bigdirheader, bigdirname);
	offset += ((le32_to_cpu(h->bigdirnamelen) + 4) & ~3);
	offset += dir->pos * sizeof(struct adfs_bigdirentry);

	dir_memcpy(dir, offset, &bde, sizeof(struct adfs_bigdirentry));

	obj->loadaddr = le32_to_cpu(bde.bigdirload);
	obj->execaddr = le32_to_cpu(bde.bigdirexec);
	obj->size     = le32_to_cpu(bde.bigdirlen);
	obj->file_id  = le32_to_cpu(bde.bigdirindaddr);
	obj->attr     = le32_to_cpu(bde.bigdirattr);
	obj->name_len = le32_to_cpu(bde.bigdirobnamelen);

	offset = offsetof(struct adfs_bigdirheader, bigdirname);
	offset += ((le32_to_cpu(h->bigdirnamelen) + 4) & ~3);
	offset += le32_to_cpu(h->bigdirentries) * sizeof(struct adfs_bigdirentry);
	offset += le32_to_cpu(bde.bigdirobnameptr);

	dir_memcpy(dir, offset, obj->name, obj->name_len);
	for (i = 0; i < obj->name_len; i++)
		if (obj->name[i] == '/')
			obj->name[i] = '.';

	obj->filetype = -1;

	/*
	 * object is a file and is filetyped and timestamped?
	 * RISC OS 12-bit filetype is stored in load_address[19:8]
	 */
	if ((0 == (obj->attr & ADFS_NDA_DIRECTORY)) &&
		(0xfff00000 == (0xfff00000 & obj->loadaddr))) {
		obj->filetype = (__u16) ((0x000fff00 & obj->loadaddr) >> 8);

		/* optionally append the ,xyz hex filetype suffix */
		if (ADFS_SB(dir->sb)->s_ftsuffix)
			obj->name_len +=
				append_filetype_suffix(
					&obj->name[obj->name_len],
					obj->filetype);
	}

	dir->pos += 1;
	ret = 0;
out:
	return ret;
}

static int
adfs_fplus_sync(struct adfs_dir *dir)
{
	int err = 0;
	int i;

	for (i = dir->nr_buffers - 1; i >= 0; i--) {
		struct buffer_head *bh = dir->bh_fplus[i];
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh))
			err = -EIO;
	}

	return err;
}

static void
adfs_fplus_free(struct adfs_dir *dir)
{
	int i;

	if (dir->bh_fplus) {
		for (i = 0; i < dir->nr_buffers; i++)
			brelse(dir->bh_fplus[i]);

		if (&dir->bh[0] != dir->bh_fplus)
			kfree(dir->bh_fplus);

		dir->bh_fplus = NULL;
	}

	dir->nr_buffers = 0;
	dir->sb = NULL;
}

struct adfs_dir_ops adfs_fplus_dir_ops = {
	.read		= adfs_fplus_read,
	.setpos		= adfs_fplus_setpos,
	.getnext	= adfs_fplus_getnext,
	.sync		= adfs_fplus_sync,
	.free		= adfs_fplus_free
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/adfs/dir_fplus.c */
/************************************************************/
/*
 *  linux/fs/adfs/file.c
 *
 * Copyright (C) 1997-1999 Russell King
 * from:
 *
 *  linux/fs/ext2/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  adfs regular file handling primitives           
 */
// #include "adfs.h"

const struct file_operations adfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.write		= new_sync_write,
	.write_iter	= generic_file_write_iter,
	.splice_read	= generic_file_splice_read,
};

const struct inode_operations adfs_file_inode_operations = {
	.setattr	= adfs_notify_change,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/adfs/file.c */
/************************************************************/
/*
 *  linux/fs/adfs/inode.c
 *
 *  Copyright (C) 1997-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
// #include <linux/buffer_head.h>
#include <linux/writeback.h>
// #include "adfs.h"
#include "../../inc/__fss.h"

/*
 * Lookup/Create a block at offset 'block' into 'inode'.  We currently do
 * not support creation of new blocks, so we return -EIO for this case.
 */
static int
adfs_get_block(struct inode *inode, sector_t block, struct buffer_head *bh,
	       int create)
{
	if (!create) {
		if (block >= inode->i_blocks)
			goto abort_toobig;

		block = __adfs_block_map(inode->i_sb, inode->i_ino, block);
		if (block)
			map_bh(bh, inode->i_sb, block);
		return 0;
	}
	/* don't support allocation of blocks yet */
	return -EIO;

abort_toobig:
	return 0;
}

static int adfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, adfs_get_block, wbc);
}

static int adfs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, adfs_get_block);
}

static void adfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size)
		truncate_pagecache(inode, inode->i_size);
}

static int adfs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	*pagep = NULL;
	ret = cont_write_begin(file, mapping, pos, len, flags, pagep, fsdata,
				adfs_get_block,
				&ADFS_I(mapping->host)->mmu_private);
	if (unlikely(ret))
		adfs_write_failed(mapping, pos + len);

	return ret;
}

static sector_t _adfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, adfs_get_block);
}

static const struct address_space_operations adfs_aops = {
	.readpage	= adfs_readpage,
	.writepage	= adfs_writepage,
	.write_begin	= adfs_write_begin,
	.write_end	= generic_write_end,
	.bmap		= _adfs_bmap
};

/*
 * Convert ADFS attributes and filetype to Linux permission.
 */
static umode_t
adfs_atts2mode(struct super_block *sb, struct inode *inode)
{
	unsigned int attr = ADFS_I(inode)->attr;
	umode_t mode, rmask;
	struct adfs_sb_info *asb = ADFS_SB(sb);

	if (attr & ADFS_NDA_DIRECTORY) {
		mode = S_IRUGO & asb->s_owner_mask;
		return S_IFDIR | S_IXUGO | mode;
	}

	switch (ADFS_I(inode)->filetype) {
	case 0xfc0:	/* LinkFS */
		return S_IFLNK|S_IRWXUGO;

	case 0xfe6:	/* UnixExec */
		rmask = S_IRUGO | S_IXUGO;
		break;

	default:
		rmask = S_IRUGO;
	}

	mode = S_IFREG;

	if (attr & ADFS_NDA_OWNER_READ)
		mode |= rmask & asb->s_owner_mask;

	if (attr & ADFS_NDA_OWNER_WRITE)
		mode |= S_IWUGO & asb->s_owner_mask;

	if (attr & ADFS_NDA_PUBLIC_READ)
		mode |= rmask & asb->s_other_mask;

	if (attr & ADFS_NDA_PUBLIC_WRITE)
		mode |= S_IWUGO & asb->s_other_mask;
	return mode;
}

/*
 * Convert Linux permission to ADFS attribute.  We try to do the reverse
 * of atts2mode, but there is not a 1:1 translation.
 */
static int
adfs_mode2atts(struct super_block *sb, struct inode *inode)
{
	umode_t mode;
	int attr;
	struct adfs_sb_info *asb = ADFS_SB(sb);

	/* FIXME: should we be able to alter a link? */
	if (S_ISLNK(inode->i_mode))
		return ADFS_I(inode)->attr;

	if (S_ISDIR(inode->i_mode))
		attr = ADFS_NDA_DIRECTORY;
	else
		attr = 0;

	mode = inode->i_mode & asb->s_owner_mask;
	if (mode & S_IRUGO)
		attr |= ADFS_NDA_OWNER_READ;
	if (mode & S_IWUGO)
		attr |= ADFS_NDA_OWNER_WRITE;

	mode = inode->i_mode & asb->s_other_mask;
	mode &= ~asb->s_owner_mask;
	if (mode & S_IRUGO)
		attr |= ADFS_NDA_PUBLIC_READ;
	if (mode & S_IWUGO)
		attr |= ADFS_NDA_PUBLIC_WRITE;

	return attr;
}

/*
 * Convert an ADFS time to Unix time.  ADFS has a 40-bit centi-second time
 * referenced to 1 Jan 1900 (til 2248) so we need to discard 2208988800 seconds
 * of time to convert from RISC OS epoch to Unix epoch.
 */
static void
adfs_adfs2unix_time(struct timespec *tv, struct inode *inode)
{
	unsigned int high, low;
	/* 01 Jan 1970 00:00:00 (Unix epoch) as nanoseconds since
	 * 01 Jan 1900 00:00:00 (RISC OS epoch)
	 */
	static const s64 nsec_unix_epoch_diff_risc_os_epoch =
							2208988800000000000LL;
	s64 nsec;

	if (ADFS_I(inode)->stamped == 0)
		goto cur_time;

	high = ADFS_I(inode)->loadaddr & 0xFF; /* top 8 bits of timestamp */
	low  = ADFS_I(inode)->execaddr;    /* bottom 32 bits of timestamp */

	/* convert 40-bit centi-seconds to 32-bit seconds
	 * going via nanoseconds to retain precision
	 */
	nsec = (((s64) high << 32) | (s64) low) * 10000000; /* cs to ns */

	/* Files dated pre  01 Jan 1970 00:00:00. */
	if (nsec < nsec_unix_epoch_diff_risc_os_epoch)
		goto too_early;

	/* convert from RISC OS to Unix epoch */
	nsec -= nsec_unix_epoch_diff_risc_os_epoch;

	*tv = ns_to_timespec(nsec);
	return;

 cur_time:
	*tv = CURRENT_TIME;
	return;

 too_early:
	tv->tv_sec = tv->tv_nsec = 0;
	return;
}

/*
 * Convert an Unix time to ADFS time.  We only do this if the entry has a
 * time/date stamp already.
 */
static void
adfs_unix2adfs_time(struct inode *inode, unsigned int secs)
{
	unsigned int high, low;

	if (ADFS_I(inode)->stamped) {
		/* convert 32-bit seconds to 40-bit centi-seconds */
		low  = (secs & 255) * 100;
		high = (secs / 256) * 100 + (low >> 8) + 0x336e996a;

		ADFS_I(inode)->loadaddr = (high >> 24) |
				(ADFS_I(inode)->loadaddr & ~0xff);
		ADFS_I(inode)->execaddr = (low & 255) | (high << 8);
	}
}

/*
 * Fill in the inode information from the object information.
 *
 * Note that this is an inode-less filesystem, so we can't use the inode
 * number to reference the metadata on the media.  Instead, we use the
 * inode number to hold the object ID, which in turn will tell us where
 * the data is held.  We also save the parent object ID, and with these
 * two, we can locate the metadata.
 *
 * This does mean that we rely on an objects parent remaining the same at
 * all times - we cannot cope with a cross-directory rename (yet).
 */
struct inode *
adfs_iget(struct super_block *sb, struct object_info *obj)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		goto out;

	inode->i_uid	 = ADFS_SB(sb)->s_uid;
	inode->i_gid	 = ADFS_SB(sb)->s_gid;
	inode->i_ino	 = obj->file_id;
	inode->i_size	 = obj->size;
	set_nlink(inode, 2);
	inode->i_blocks	 = (inode->i_size + sb->s_blocksize - 1) >>
			    sb->s_blocksize_bits;

	/*
	 * we need to save the parent directory ID so that
	 * write_inode can update the directory information
	 * for this file.  This will need special handling
	 * for cross-directory renames.
	 */
	ADFS_I(inode)->parent_id = obj->parent_id;
	ADFS_I(inode)->loadaddr  = obj->loadaddr;
	ADFS_I(inode)->execaddr  = obj->execaddr;
	ADFS_I(inode)->attr      = obj->attr;
	ADFS_I(inode)->filetype  = obj->filetype;
	ADFS_I(inode)->stamped   = ((obj->loadaddr & 0xfff00000) == 0xfff00000);

	inode->i_mode	 = adfs_atts2mode(sb, inode);
	adfs_adfs2unix_time(&inode->i_mtime, inode);
	inode->i_atime = inode->i_mtime;
	inode->i_ctime = inode->i_mtime;

	if (S_ISDIR(inode->i_mode)) {
		inode->i_op	= &adfs_dir_inode_operations;
		inode->i_fop	= &adfs_dir_operations;
	} else if (S_ISREG(inode->i_mode)) {
		inode->i_op	= &adfs_file_inode_operations;
		inode->i_fop	= &adfs_file_operations;
		inode->i_mapping->a_ops = &adfs_aops;
		ADFS_I(inode)->mmu_private = inode->i_size;
	}

	insert_inode_hash(inode);

out:
	return inode;
}

/*
 * Validate and convert a changed access mode/time to their ADFS equivalents.
 * adfs_write_inode will actually write the information back to the directory
 * later.
 */
int
adfs_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	unsigned int ia_valid = attr->ia_valid;
	int error;
	
	error = inode_change_ok(inode, attr);

	/*
	 * we can't change the UID or GID of any file -
	 * we have a global UID/GID in the superblock
	 */
	if ((ia_valid & ATTR_UID && !uid_eq(attr->ia_uid, ADFS_SB(sb)->s_uid)) ||
	    (ia_valid & ATTR_GID && !gid_eq(attr->ia_gid, ADFS_SB(sb)->s_gid)))
		error = -EPERM;

	if (error)
		goto out;

	/* XXX: this is missing some actual on-disk truncation.. */
	if (ia_valid & ATTR_SIZE)
		truncate_setsize(inode, attr->ia_size);

	if (ia_valid & ATTR_MTIME) {
		inode->i_mtime = attr->ia_mtime;
		adfs_unix2adfs_time(inode, attr->ia_mtime.tv_sec);
	}
	/*
	 * FIXME: should we make these == to i_mtime since we don't
	 * have the ability to represent them in our filesystem?
	 */
	if (ia_valid & ATTR_ATIME)
		inode->i_atime = attr->ia_atime;
	if (ia_valid & ATTR_CTIME)
		inode->i_ctime = attr->ia_ctime;
	if (ia_valid & ATTR_MODE) {
		ADFS_I(inode)->attr = adfs_mode2atts(sb, inode);
		inode->i_mode = adfs_atts2mode(sb, inode);
	}

	/*
	 * FIXME: should we be marking this inode dirty even if
	 * we don't have any metadata to write back?
	 */
	if (ia_valid & (ATTR_SIZE | ATTR_MTIME | ATTR_MODE))
		mark_inode_dirty(inode);
out:
	return error;
}

/*
 * write an existing inode back to the directory, and therefore the disk.
 * The adfs-specific inode data has already been updated by
 * adfs_notify_change()
 */
int adfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct super_block *sb = inode->i_sb;
	struct object_info obj;
	int ret;

	obj.file_id	= inode->i_ino;
	obj.name_len	= 0;
	obj.parent_id	= ADFS_I(inode)->parent_id;
	obj.loadaddr	= ADFS_I(inode)->loadaddr;
	obj.execaddr	= ADFS_I(inode)->execaddr;
	obj.attr	= ADFS_I(inode)->attr;
	obj.size	= inode->i_size;

	ret = adfs_dir_update(sb, &obj, wbc->sync_mode == WB_SYNC_ALL);
	return ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/adfs/inode.c */
/************************************************************/
/*
 *  linux/fs/adfs/map.c
 *
 *  Copyright (C) 1997-2002 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
// #include <linux/buffer_head.h>
#include <asm/unaligned.h>
// #include "adfs.h"
#include "../../inc/__fss.h"

/*
 * The ADFS map is basically a set of sectors.  Each sector is called a
 * zone which contains a bitstream made up of variable sized fragments.
 * Each bit refers to a set of bytes in the filesystem, defined by
 * log2bpmb.  This may be larger or smaller than the sector size, but
 * the overall size it describes will always be a round number of
 * sectors.  A fragment id is always idlen bits long.
 *
 *  < idlen > <       n        > <1>
 * +---------+-------//---------+---+
 * | frag id |  0000....000000  | 1 |
 * +---------+-------//---------+---+
 *
 * The physical disk space used by a fragment is taken from the start of
 * the fragment id up to and including the '1' bit - ie, idlen + n + 1
 * bits.
 *
 * A fragment id can be repeated multiple times in the whole map for
 * large or fragmented files.  The first map zone a fragment starts in
 * is given by fragment id / ids_per_zone - this allows objects to start
 * from any zone on the disk.
 *
 * Free space is described by a linked list of fragments.  Each free
 * fragment describes free space in the same way as the other fragments,
 * however, the frag id specifies an offset (in map bits) from the end
 * of this fragment to the start of the next free fragment.
 *
 * Objects stored on the disk are allocated object ids (we use these as
 * our inode numbers.)  Object ids contain a fragment id and an optional
 * offset.  This allows a directory fragment to contain small files
 * associated with that directory.
 */

/*
 * For the future...
 */
static DEFINE_RWLOCK(adfs_map_lock);

/*
 * This is fun.  We need to load up to 19 bits from the map at an
 * arbitrary bit alignment.  (We're limited to 19 bits by F+ version 2).
 */
#define GET_FRAG_ID(_map,_start,_idmask)				\
	({								\
		unsigned char *_m = _map + (_start >> 3);		\
		u32 _frag = get_unaligned_le32(_m);			\
		_frag >>= (_start & 7);					\
		_frag & _idmask;					\
	})

/*
 * return the map bit offset of the fragment frag_id in the zone dm.
 * Note that the loop is optimised for best asm code - look at the
 * output of:
 *  gcc -D__KERNEL__ -O2 -I../../include -o - -S map.c
 */
static int
lookup_zone(const struct adfs_discmap *dm, const unsigned int idlen,
	    const unsigned int frag_id, unsigned int *offset)
{
	const unsigned int mapsize = dm->dm_endbit;
	const u32 idmask = (1 << idlen) - 1;
	unsigned char *map = dm->dm_bh->b_data + 4;
	unsigned int start = dm->dm_startbit;
	unsigned int mapptr;
	u32 frag;

	do {
		frag = GET_FRAG_ID(map, start, idmask);
		mapptr = start + idlen;

		/*
		 * find end of fragment
		 */
		{
			__le32 *_map = (__le32 *)map;
			u32 v = le32_to_cpu(_map[mapptr >> 5]) >> (mapptr & 31);
			while (v == 0) {
				mapptr = (mapptr & ~31) + 32;
				if (mapptr >= mapsize)
					goto error;
				v = le32_to_cpu(_map[mapptr >> 5]);
			}

			mapptr += 1 + ffz(~v);
		}

		if (frag == frag_id)
			goto found;
again:
		start = mapptr;
	} while (mapptr < mapsize);
	return -1;

error:
	printk(KERN_ERR "adfs: oversized fragment 0x%x at 0x%x-0x%x\n",
		frag, start, mapptr);
	return -1;

found:
	{
		int length = mapptr - start;
		if (*offset >= length) {
			*offset -= length;
			goto again;
		}
	}
	return start + *offset;
}

/*
 * Scan the free space map, for this zone, calculating the total
 * number of map bits in each free space fragment.
 *
 * Note: idmask is limited to 15 bits [3.2]
 */
static unsigned int
scan_free_map(struct adfs_sb_info *asb, struct adfs_discmap *dm)
{
	const unsigned int mapsize = dm->dm_endbit + 32;
	const unsigned int idlen  = asb->s_idlen;
	const unsigned int frag_idlen = idlen <= 15 ? idlen : 15;
	const u32 idmask = (1 << frag_idlen) - 1;
	unsigned char *map = dm->dm_bh->b_data;
	unsigned int start = 8, mapptr;
	u32 frag;
	unsigned long total = 0;

	/*
	 * get fragment id
	 */
	frag = GET_FRAG_ID(map, start, idmask);

	/*
	 * If the freelink is null, then no free fragments
	 * exist in this zone.
	 */
	if (frag == 0)
		return 0;

	do {
		start += frag;

		/*
		 * get fragment id
		 */
		frag = GET_FRAG_ID(map, start, idmask);
		mapptr = start + idlen;

		/*
		 * find end of fragment
		 */
		{
			__le32 *_map = (__le32 *)map;
			u32 v = le32_to_cpu(_map[mapptr >> 5]) >> (mapptr & 31);
			while (v == 0) {
				mapptr = (mapptr & ~31) + 32;
				if (mapptr >= mapsize)
					goto error;
				v = le32_to_cpu(_map[mapptr >> 5]);
			}

			mapptr += 1 + ffz(~v);
		}

		total += mapptr - start;
	} while (frag >= idlen + 1);

	if (frag != 0)
		printk(KERN_ERR "adfs: undersized free fragment\n");

	return total;
error:
	printk(KERN_ERR "adfs: oversized free fragment\n");
	return 0;
}

static int
scan_map(struct adfs_sb_info *asb, unsigned int zone,
	 const unsigned int frag_id, unsigned int mapoff)
{
	const unsigned int idlen = asb->s_idlen;
	struct adfs_discmap *dm, *dm_end;
	int result;

	dm	= asb->s_map + zone;
	zone	= asb->s_map_size;
	dm_end	= asb->s_map + zone;

	do {
		result = lookup_zone(dm, idlen, frag_id, &mapoff);

		if (result != -1)
			goto found;

		dm ++;
		if (dm == dm_end)
			dm = asb->s_map;
	} while (--zone > 0);

	return -1;
found:
	result -= dm->dm_startbit;
	result += dm->dm_startblk;

	return result;
}

/*
 * calculate the amount of free blocks in the map.
 *
 *              n=1
 *  total_free = E(free_in_zone_n)
 *              nzones
 */
unsigned int
adfs_map_free(struct super_block *sb)
{
	struct adfs_sb_info *asb = ADFS_SB(sb);
	struct adfs_discmap *dm;
	unsigned int total = 0;
	unsigned int zone;

	dm   = asb->s_map;
	zone = asb->s_map_size;

	do {
		total += scan_free_map(asb, dm++);
	} while (--zone > 0);

	return signed_asl(total, asb->s_map2blk);
}

int
adfs_map_lookup(struct super_block *sb, unsigned int frag_id,
		unsigned int offset)
{
	struct adfs_sb_info *asb = ADFS_SB(sb);
	unsigned int zone, mapoff;
	int result;

	/*
	 * map & root fragment is special - it starts in the center of the
	 * disk.  The other fragments start at zone (frag / ids_per_zone)
	 */
	if (frag_id == ADFS_ROOT_FRAG)
		zone = asb->s_map_size >> 1;
	else
		zone = frag_id / asb->s_ids_per_zone;

	if (zone >= asb->s_map_size)
		goto bad_fragment;

	/* Convert sector offset to map offset */
	mapoff = signed_asl(offset, -asb->s_map2blk);

	read_lock(&adfs_map_lock);
	result = scan_map(asb, zone, frag_id, mapoff);
	read_unlock(&adfs_map_lock);

	if (result > 0) {
		unsigned int secoff;

		/* Calculate sector offset into map block */
		secoff = offset - signed_asl(mapoff, asb->s_map2blk);
		return secoff + signed_asl(result, asb->s_map2blk);
	}

	adfs_error(sb, "fragment 0x%04x at offset %d not found in map",
		   frag_id, offset);
	return 0;

bad_fragment:
	adfs_error(sb, "invalid fragment 0x%04x (zone = %d, max = %d)",
		   frag_id, zone, asb->s_map_size);
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/adfs/map.c */
/************************************************************/
/*
 *  linux/fs/adfs/super.c
 *
 *  Copyright (C) 1997-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/init.h>
// #include <linux/buffer_head.h>
#include <linux/parser.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
// #include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/user_namespace.h>
// #include "adfs.h"
// #include "dir_f.h"
// #include "dir_fplus.h"
#include "../../inc/__fss.h"

#define ADFS_DEFAULT_OWNER_MASK S_IRWXU
#define ADFS_DEFAULT_OTHER_MASK (S_IRWXG | S_IRWXO)

void __adfs_error(struct super_block *sb, const char *function, const char *fmt, ...)
{
	char error_buf[128];
	va_list args;

	va_start(args, fmt);
	vsnprintf(error_buf, sizeof(error_buf), fmt, args);
	va_end(args);

	printk(KERN_CRIT "ADFS-fs error (device %s)%s%s: %s\n",
		sb->s_id, function ? ": " : "",
		function ? function : "", error_buf);
}

static int adfs_checkdiscrecord(struct adfs_discrecord *dr)
{
	int i;

	/* sector size must be 256, 512 or 1024 bytes */
	if (dr->log2secsize != 8 &&
	    dr->log2secsize != 9 &&
	    dr->log2secsize != 10)
		return 1;

	/* idlen must be at least log2secsize + 3 */
	if (dr->idlen < dr->log2secsize + 3)
		return 1;

	/* we cannot have such a large disc that we
	 * are unable to represent sector offsets in
	 * 32 bits.  This works out at 2.0 TB.
	 */
	if (le32_to_cpu(dr->disc_size_high) >> dr->log2secsize)
		return 1;

	/* idlen must be no greater than 19 v2 [1.0] */
	if (dr->idlen > 19)
		return 1;

	/* reserved bytes should be zero */
	for (i = 0; i < sizeof(dr->unused52); i++)
		if (dr->unused52[i] != 0)
			return 1;

	return 0;
}

static unsigned char adfs_calczonecheck(struct super_block *sb, unsigned char *map)
{
	unsigned int v0, v1, v2, v3;
	int i;

	v0 = v1 = v2 = v3 = 0;
	for (i = sb->s_blocksize - 4; i; i -= 4) {
		v0 += map[i]     + (v3 >> 8);
		v3 &= 0xff;
		v1 += map[i + 1] + (v0 >> 8);
		v0 &= 0xff;
		v2 += map[i + 2] + (v1 >> 8);
		v1 &= 0xff;
		v3 += map[i + 3] + (v2 >> 8);
		v2 &= 0xff;
	}
	v0 +=           v3 >> 8;
	v1 += map[1] + (v0 >> 8);
	v2 += map[2] + (v1 >> 8);
	v3 += map[3] + (v2 >> 8);

	return v0 ^ v1 ^ v2 ^ v3;
}

static int adfs_checkmap(struct super_block *sb, struct adfs_discmap *dm)
{
	unsigned char crosscheck = 0, zonecheck = 1;
	int i;

	for (i = 0; i < ADFS_SB(sb)->s_map_size; i++) {
		unsigned char *map;

		map = dm[i].dm_bh->b_data;

		if (adfs_calczonecheck(sb, map) != map[0]) {
			adfs_error(sb, "zone %d fails zonecheck", i);
			zonecheck = 0;
		}
		crosscheck ^= map[3];
	}
	if (crosscheck != 0xff)
		adfs_error(sb, "crosscheck != 0xff");
	return crosscheck == 0xff && zonecheck;
}

static void adfs_put_super(struct super_block *sb)
{
	int i;
	struct adfs_sb_info *asb = ADFS_SB(sb);

	for (i = 0; i < asb->s_map_size; i++)
		brelse(asb->s_map[i].dm_bh);
	kfree(asb->s_map);
	kfree_rcu(asb, rcu);
}

static int adfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct adfs_sb_info *asb = ADFS_SB(root->d_sb);

	if (!uid_eq(asb->s_uid, GLOBAL_ROOT_UID))
		seq_printf(seq, ",uid=%u", from_kuid_munged(&init_user_ns, asb->s_uid));
	if (!gid_eq(asb->s_gid, GLOBAL_ROOT_GID))
		seq_printf(seq, ",gid=%u", from_kgid_munged(&init_user_ns, asb->s_gid));
	if (asb->s_owner_mask != ADFS_DEFAULT_OWNER_MASK)
		seq_printf(seq, ",ownmask=%o", asb->s_owner_mask);
	if (asb->s_other_mask != ADFS_DEFAULT_OTHER_MASK)
		seq_printf(seq, ",othmask=%o", asb->s_other_mask);
	if (asb->s_ftsuffix != 0)
		seq_printf(seq, ",ftsuffix=%u", asb->s_ftsuffix);

	return 0;
}

enum {Opt_uid, Opt_gid, Opt_ownmask, Opt_othmask, Opt_ftsuffix, Opt_err};

static const match_table_t tokens = {
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_ownmask, "ownmask=%o"},
	{Opt_othmask, "othmask=%o"},
	{Opt_ftsuffix, "ftsuffix=%u"},
	{Opt_err, NULL}
};

static int parse_options(struct super_block *sb, char *options)
{
	char *p;
	struct adfs_sb_info *asb = ADFS_SB(sb);
	int option;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_uid:
			if (match_int(args, &option))
				return -EINVAL;
			asb->s_uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(asb->s_uid))
				return -EINVAL;
			break;
		case Opt_gid:
			if (match_int(args, &option))
				return -EINVAL;
			asb->s_gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(asb->s_gid))
				return -EINVAL;
			break;
		case Opt_ownmask:
			if (match_octal(args, &option))
				return -EINVAL;
			asb->s_owner_mask = option;
			break;
		case Opt_othmask:
			if (match_octal(args, &option))
				return -EINVAL;
			asb->s_other_mask = option;
			break;
		case Opt_ftsuffix:
			if (match_int(args, &option))
				return -EINVAL;
			asb->s_ftsuffix = option;
			break;
		default:
			printk("ADFS-fs: unrecognised mount option \"%s\" "
					"or missing value\n", p);
			return -EINVAL;
		}
	}
	return 0;
}

static int adfs_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	*flags |= MS_NODIRATIME;
	return parse_options(sb, data);
}

static int adfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct adfs_sb_info *sbi = ADFS_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type    = ADFS_SUPER_MAGIC;
	buf->f_namelen = sbi->s_namelen;
	buf->f_bsize   = sb->s_blocksize;
	buf->f_blocks  = sbi->s_size;
	buf->f_files   = sbi->s_ids_per_zone * sbi->s_map_size;
	buf->f_bavail  =
	buf->f_bfree   = adfs_map_free(sb);
	buf->f_ffree   = (long)(buf->f_bfree * buf->f_files) / (long)buf->f_blocks;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}

static struct kmem_cache *adfs_inode_cachep;

static struct inode *adfs_alloc_inode(struct super_block *sb)
{
	struct adfs_inode_info *ei;
	ei = (struct adfs_inode_info *)kmem_cache_alloc(adfs_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void adfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(adfs_inode_cachep, ADFS_I(inode));
}

static void adfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, adfs_i_callback);
}

static void init_once(void *foo)
{
	struct adfs_inode_info *ei = (struct adfs_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	adfs_inode_cachep = kmem_cache_create("adfs_inode_cache",
					     sizeof(struct adfs_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (adfs_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(adfs_inode_cachep);
}

static const struct super_operations adfs_sops = {
	.alloc_inode	= adfs_alloc_inode,
	.destroy_inode	= adfs_destroy_inode,
	.write_inode	= adfs_write_inode,
	.put_super	= adfs_put_super,
	.statfs		= adfs_statfs,
	.remount_fs	= adfs_remount,
	.show_options	= adfs_show_options,
};

static struct adfs_discmap *adfs_read_map(struct super_block *sb, struct adfs_discrecord *dr)
{
	struct adfs_discmap *dm;
	unsigned int map_addr, zone_size, nzones;
	int i, zone;
	struct adfs_sb_info *asb = ADFS_SB(sb);

	nzones    = asb->s_map_size;
	zone_size = (8 << dr->log2secsize) - le16_to_cpu(dr->zone_spare);
	map_addr  = (nzones >> 1) * zone_size -
		     ((nzones > 1) ? ADFS_DR_SIZE_BITS : 0);
	map_addr  = signed_asl(map_addr, asb->s_map2blk);

	asb->s_ids_per_zone = zone_size / (asb->s_idlen + 1);

	dm = kmalloc(nzones * sizeof(*dm), GFP_KERNEL);
	if (dm == NULL) {
		adfs_error(sb, "not enough memory");
		return NULL;
	}

	for (zone = 0; zone < nzones; zone++, map_addr++) {
		dm[zone].dm_startbit = 0;
		dm[zone].dm_endbit   = zone_size;
		dm[zone].dm_startblk = zone * zone_size - ADFS_DR_SIZE_BITS;
		dm[zone].dm_bh       = sb_bread(sb, map_addr);

		if (!dm[zone].dm_bh) {
			adfs_error(sb, "unable to read map");
			goto error_free;
		}
	}

	/* adjust the limits for the first and last map zones */
	i = zone - 1;
	dm[0].dm_startblk = 0;
	dm[0].dm_startbit = ADFS_DR_SIZE_BITS;
	dm[i].dm_endbit   = (le32_to_cpu(dr->disc_size_high) << (32 - dr->log2bpmb)) +
			    (le32_to_cpu(dr->disc_size) >> dr->log2bpmb) +
			    (ADFS_DR_SIZE_BITS - i * zone_size);

	if (adfs_checkmap(sb, dm))
		return dm;

	adfs_error(sb, "map corrupted");

error_free:
	while (--zone >= 0)
		brelse(dm[zone].dm_bh);

	kfree(dm);
	return NULL;
}

static inline unsigned long adfs_discsize(struct adfs_discrecord *dr, int block_bits)
{
	unsigned long discsize;

	discsize  = le32_to_cpu(dr->disc_size_high) << (32 - block_bits);
	discsize |= le32_to_cpu(dr->disc_size) >> block_bits;

	return discsize;
}

static int adfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct adfs_discrecord *dr;
	struct buffer_head *bh;
	struct object_info root_obj;
	unsigned char *b_data;
	struct adfs_sb_info *asb;
	struct inode *root;

	sb->s_flags |= MS_NODIRATIME;

	asb = kzalloc(sizeof(*asb), GFP_KERNEL);
	if (!asb)
		return -ENOMEM;
	sb->s_fs_info = asb;

	/* set default options */
	asb->s_uid = GLOBAL_ROOT_UID;
	asb->s_gid = GLOBAL_ROOT_GID;
	asb->s_owner_mask = ADFS_DEFAULT_OWNER_MASK;
	asb->s_other_mask = ADFS_DEFAULT_OTHER_MASK;
	asb->s_ftsuffix = 0;

	if (parse_options(sb, data))
		goto error;

	sb_set_blocksize(sb, BLOCK_SIZE);
	if (!(bh = sb_bread(sb, ADFS_DISCRECORD / BLOCK_SIZE))) {
		adfs_error(sb, "unable to read superblock");
		goto error;
	}

	b_data = bh->b_data + (ADFS_DISCRECORD % BLOCK_SIZE);

	if (adfs_checkbblk(b_data)) {
		if (!silent)
			printk("VFS: Can't find an adfs filesystem on dev "
				"%s.\n", sb->s_id);
		goto error_free_bh;
	}

	dr = (struct adfs_discrecord *)(b_data + ADFS_DR_OFFSET);

	/*
	 * Do some sanity checks on the ADFS disc record
	 */
	if (adfs_checkdiscrecord(dr)) {
		if (!silent)
			printk("VPS: Can't find an adfs filesystem on dev "
				"%s.\n", sb->s_id);
		goto error_free_bh;
	}

	brelse(bh);
	if (sb_set_blocksize(sb, 1 << dr->log2secsize)) {
		bh = sb_bread(sb, ADFS_DISCRECORD / sb->s_blocksize);
		if (!bh) {
			adfs_error(sb, "couldn't read superblock on "
				"2nd try.");
			goto error;
		}
		b_data = bh->b_data + (ADFS_DISCRECORD % sb->s_blocksize);
		if (adfs_checkbblk(b_data)) {
			adfs_error(sb, "disc record mismatch, very weird!");
			goto error_free_bh;
		}
		dr = (struct adfs_discrecord *)(b_data + ADFS_DR_OFFSET);
	} else {
		if (!silent)
			printk(KERN_ERR "VFS: Unsupported blocksize on dev "
				"%s.\n", sb->s_id);
		goto error;
	}

	/*
	 * blocksize on this device should now be set to the ADFS log2secsize
	 */

	sb->s_magic		= ADFS_SUPER_MAGIC;
	asb->s_idlen		= dr->idlen;
	asb->s_map_size		= dr->nzones | (dr->nzones_high << 8);
	asb->s_map2blk		= dr->log2bpmb - dr->log2secsize;
	asb->s_size    		= adfs_discsize(dr, sb->s_blocksize_bits);
	asb->s_version 		= dr->format_version;
	asb->s_log2sharesize	= dr->log2sharesize;
	
	asb->s_map = adfs_read_map(sb, dr);
	if (!asb->s_map)
		goto error_free_bh;

	brelse(bh);

	/*
	 * set up enough so that we can read an inode
	 */
	sb->s_op = &adfs_sops;

	dr = (struct adfs_discrecord *)(asb->s_map[0].dm_bh->b_data + 4);

	root_obj.parent_id = root_obj.file_id = le32_to_cpu(dr->root);
	root_obj.name_len  = 0;
	/* Set root object date as 01 Jan 1987 00:00:00 */
	root_obj.loadaddr  = 0xfff0003f;
	root_obj.execaddr  = 0xec22c000;
	root_obj.size	   = ADFS_NEWDIR_SIZE;
	root_obj.attr	   = ADFS_NDA_DIRECTORY   | ADFS_NDA_OWNER_READ |
			     ADFS_NDA_OWNER_WRITE | ADFS_NDA_PUBLIC_READ;
	root_obj.filetype  = -1;

	/*
	 * If this is a F+ disk with variable length directories,
	 * get the root_size from the disc record.
	 */
	if (asb->s_version) {
		root_obj.size = le32_to_cpu(dr->root_size);
		asb->s_dir     = &adfs_fplus_dir_ops;
		asb->s_namelen = ADFS_FPLUS_NAME_LEN;
	} else {
		asb->s_dir     = &adfs_f_dir_ops;
		asb->s_namelen = ADFS_F_NAME_LEN;
	}
	/*
	 * ,xyz hex filetype suffix may be added by driver
	 * to files that have valid RISC OS filetype
	 */
	if (asb->s_ftsuffix)
		asb->s_namelen += 4;

	sb->s_d_op = &adfs_dentry_operations;
	root = adfs_iget(sb, &root_obj);
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		int i;
		for (i = 0; i < asb->s_map_size; i++)
			brelse(asb->s_map[i].dm_bh);
		kfree(asb->s_map);
		adfs_error(sb, "get root inode failed\n");
		goto error;
	}
	return 0;

error_free_bh:
	brelse(bh);
error:
	sb->s_fs_info = NULL;
	kfree(asb);
	return -EINVAL;
}

static struct dentry *adfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, adfs_fill_super);
}

static struct file_system_type adfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "adfs",
	.mount		= adfs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("adfs");

static int __init init_adfs_fs(void)
{
	int err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&adfs_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_adfs_fs(void)
{
	unregister_filesystem(&adfs_fs_type);
	destroy_inodecache();
}

module_init(init_adfs_fs)
module_exit(exit_adfs_fs)
MODULE_LICENSE("GPL");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/adfs/super.c */
/************************************************************/
